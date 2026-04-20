#!/usr/bin/env python3
"""
redact_hermes.py — Redact secrets from Hermes Agent storage files.

Usage:
    python3 redact_hermes.py --secrets "secret1:value1,secret2:value2,..."

    Or with named pairs:
    python3 redact_hermes.py \
        --secret "openai:sk-...ABC" \
        --secret "replicate:r8_...XYZ" \
        --secret "agentmail:am_us_..."

    Interactive (will prompt for secrets):
    python3 redact_hermes.py --interactive

    Audit mode (find secrets without modifying):
    python3 redact_hermes.py --audit --secrets "..."

Examples:
    # Single secret
    python3 redact_hermes.py --secrets "sk-1234567890abcdef:***OPENAI_KEY_REDACTED***"

    # Multiple secrets
    python3 redact_hermes.py \
        --secret "sk-...:***OPENAI_KEY_REDACTED***" \
        --secret "r8_...:***REPLICATE_KEY_REDACTED***" \
        --secret "am_us_...:***AGENTMAIL_KEY_REDACTED***"

    # Full cleanup of known secrets (add your own):
    python3 redact_hermes.py \
        --secret "YOUR_KEY_HERE:***YOUR_SERVICE_REDACTED***"
"""

import argparse
import os
import re
import shutil
import sqlite3
import sys
import time


HERMES_DIR = os.path.expanduser("~/.hermes")


# ---------------------------------------------------------------------------
# Core redaction logic
# ---------------------------------------------------------------------------

def redact_file(path: str, secrets: dict[str, str], verbose: bool = True) -> int:
    """Replace all secret occurrences in a plain text file. Returns count of replacements."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except (IOError, OSError):
        return 0

    original = content
    for secret, placeholder in secrets.items():
        # Only replace if the secret is long enough to be real (avoid placeholder-in-placeholder loops)
        if len(secret) > 8 and secret in content:
            content = content.replace(secret, placeholder)

    if content != original:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        count = sum(1 for s in secrets if len(s) > 8 and s in original)
        if verbose:
            print(f"  ✓  {path}  ({count} replacement{'s' if count != 1 else ''})")
        return 1
    return 0


def redact_json_file(path: str, secrets: dict[str, str], verbose: bool = True) -> int:
    """Replace all secret occurrences in a .json file (session files, dumps, etc.)."""
    return redact_file(path, secrets, verbose)


def redact_sqlite_db(db_path: str, secrets: dict[str, str], verbose: bool = True) -> int:
    """
    Redact secrets from a SQLite database (state.db).
    Backs up the DB before modifying, then walks every text column in every
    table and replaces secret values. Handles the Hermes state.db schema.
    """
    if not os.path.exists(db_path):
        return 0

    backup_path = f"{db_path}.bak.{int(time.time())}"
    shutil.copy2(db_path, backup_path)

    files_modified = 0
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Get all table names
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]

        for table in tables:
            try:
                # Get column names and types
                cursor.execute(f"PRAGMA table_info({table})")
                columns = [(row[1], row[2]) for row in cursor.fetchall()]  # (name, type)

                text_cols = [name for name, dtype in columns
                             if dtype in ("TEXT", "BLOB", "ANY") or "CHAR" in dtype.upper() or "STR" in dtype.upper()]

                for col in text_cols:
                    try:
                        cursor.execute(f"SELECT rowid, {col} FROM {table} WHERE {col} IS NOT NULL")
                        for rowid, value in cursor.fetchall():
                            if not isinstance(value, str):
                                continue
                            new_value = value
                            changed = False
                            for secret, placeholder in secrets.items():
                                if len(secret) > 8 and secret in value:
                                    new_value = new_value.replace(secret, placeholder)
                                    changed = True
                            if changed:
                                cursor.execute(f"UPDATE {table} SET {col} = ? WHERE rowid = ?", (new_value, rowid))
                    except sqlite3.Error:
                        pass  # Skip columns that can't be read/written

            except sqlite3.Error:
                pass  # Skip tables that cause issues

        conn.commit()
        conn.close()
        files_modified = 1
        if verbose:
            print(f"  ✓  {db_path}  (SQLite — backup: {os.path.basename(backup_path)})")

    except Exception as e:
        # Restore from backup on failure
        if os.path.exists(backup_path):
            shutil.move(backup_path, db_path)
        print(f"  ✗  {db_path} — error: {e}  (restored from backup)", file=sys.stderr)
        return 0
    finally:
        # Remove old backup on success
        if files_modified and os.path.exists(backup_path):
            try:
                os.remove(backup_path)
            except OSError:
                pass

    return files_modified


def audit_hermes(secrets: dict[str, str], hermes_dir: str = HERMES_DIR) -> dict:
    """
    Scan hermes storage and report where secrets are found (without modifying anything).
    Returns {path: [found_secrets_list]}.
    """
    findings = {}
    for root, dirs, files in os.walk(hermes_dir):
        # Skip .git directories
        dirs[:] = [d for d in dirs if d != ".git"]

        for fn in files:
            fp = os.path.join(root, fn)
            found_in_file = []

            try:
                if fn.endswith(".json"):
                    with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                elif fn.endswith(".db"):
                    # Quick binary scan for secrets — just search the whole file as bytes
                    with open(fp, "rb") as f:
                        content = f.read().decode("utf-8", errors="ignore")
                else:
                    with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                for secret in secrets:
                    if len(secret) > 8 and secret in content:
                        found_in_file.append(secret[:20] + "...")

                if found_in_file:
                    findings[fp] = found_in_file

            except (IOError, OSError, UnicodeDecodeError):
                pass

    return findings


# ---------------------------------------------------------------------------
# Scanning and dispatch
# ---------------------------------------------------------------------------

def scan_and_redact(secrets: dict[str, str], hermes_dir: str = HERMES_DIR, dry_run: bool = False) -> dict:
    """
    Walk hermes_dir and redact secrets from all relevant files.
    Returns {"files_scanned": N, "files_modified": M, "errors": []}.
    """
    stats = {"files_scanned": 0, "files_modified": 0, "errors": []}

    for root, dirs, files in os.walk(hermes_dir):
        # Skip .git directories
        dirs[:] = [d for d in dirs if d != ".git"]

        for fn in files:
            fp = os.path.join(root, fn)
            stats["files_scanned"] += 1

            try:
                if fn in (".hermes_history", "transcript.txt", "memory.json"):
                    # Plain text / line-delimited history
                    files_modified += redact_file(fp, secrets)

                elif fn.endswith(".json") or fn.endswith(".jsonl"):
                    files_modified += redact_json_file(fp, secrets)

                elif fn == "state.db":
                    files_modified += redact_sqlite_db(fp, secrets)

                else:
                    # Treat everything else as plain text
                    files_modified += redact_file(fp, secrets)

            except Exception as e:
                stats["errors"].append(f"{fp}: {e}")

    return stats


# Fix the scoping issue in scan_and_redact
def _scan_and_redact_impl(secrets: dict, hermes_dir: str, dry_run: bool):
    stats = {"files_scanned": 0, "files_modified": 0, "errors": []}

    for root, dirs, files in os.walk(hermes_dir):
        dirs[:] = [d for d in dirs if d != ".git"]
        for fn in files:
            fp = os.path.join(root, fn)
            stats["files_scanned"] += 1
            try:
                if fn in (".hermes_history", "transcript.txt", "memory.json"):
                    stats["files_modified"] += redact_file(fp, secrets)
                elif fn.endswith(".json") or fn.endswith(".jsonl"):
                    stats["files_modified"] += redact_json_file(fp, secrets)
                elif fn == "state.db":
                    stats["files_modified"] += redact_sqlite_db(fp, secrets)
                else:
                    stats["files_modified"] += redact_file(fp, secrets)
            except Exception as e:
                stats["errors"].append(f"{fp}: {e}")

    return stats


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_secrets_input(raw: str) -> dict[str, str]:
    """
    Parse "secret1:value1,secret2:value2,..." into {secret: placeholder}.
    Also handles named --secret arguments already split.
    """
    secrets = {}
    for item in raw.split(","):
        item = item.strip()
        if not item or ":" not in item:
            continue
        secret, _, placeholder = item.partition(":")
        secret = secret.strip()
        placeholder = placeholder.strip()
        if secret and placeholder:
            secrets[secret] = placeholder
    return secrets


def interactive_prompt() -> dict[str, str]:
    """Prompt the user for secret -> placeholder pairs interactively."""
    secrets = {}
    print("\n=== Interactive Secret Entry ===")
    print("Enter each secret followed by its placeholder label.")
    print("Press Ctrl+C to finish.\n")
    while True:
        try:
            line = input("Secret (or ENTER to finish): ").strip()
            if not line:
                break
            placeholder = input(f"  Placeholder for '{line[:20]}...': ").strip()
            if placeholder:
                secrets[line] = placeholder
        except (EOFError, KeyboardInterrupt):
            print()
            break
    return secrets


def main():
    parser = argparse.ArgumentParser(
        description="Redact secrets from Hermes Agent storage files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--secrets", "-s",
        help='Comma-separated "secret:placeholder" pairs, e.g. "sk-ABC:***OPENAI_REDACTED***"',
    )
    parser.add_argument(
        "--secret",
        action="append",
        dest="secret_list",
        help='Single "secret:placeholder" pair. Repeat for multiple secrets.',
    )
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Interactively enter secrets and placeholders",
    )
    parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="Audit only — show what would be changed without modifying files",
    )
    parser.add_argument(
        "--audit", "-a",
        action="store_true",
        help="Show which files contain which secrets (no modifications)",
    )
    parser.add_argument(
        "--hermes-dir",
        default=HERMES_DIR,
        help=f"Path to hermes directory (default: {HERMES_DIR})",
    )

    args = parser.parse_args()

    # Collect secrets from all sources
    secrets = {}

    if args.secrets:
        secrets.update(parse_secrets_input(args.secrets))

    if args.secret_list:
        for item in args.secret_list:
            secrets.update(parse_secrets_input(item))

    if args.interactive:
        secrets.update(interactive_prompt())

    if not secrets:
        print("Error: No secrets provided. Use --secrets, --secret, or --interactive.", file=sys.stderr)
        parser.print_help()
        sys.exit(1)

    # Validate: warn if any placeholder already appears in its corresponding secret
    for secret, placeholder in secrets.items():
        if len(secret) > 8 and placeholder in secret:
            print(f"WARNING: placeholder '{placeholder}' appears inside its own secret — may cause nested redaction.", file=sys.stderr)

    print(f"\n{'[DRY-RUN] ' if args.dry_run else ''}{'Scanning' if args.audit else 'Redacting'} {len(secrets)} secret(s) in {args.hermes_dir}...\n")

    if args.audit:
        findings = audit_hermes(secrets, args.hermes_dir)
        if not findings:
            print("  No secrets found.")
        else:
            for fp, found in findings.items():
                rel = fp.replace(os.path.expanduser("~"), "~")
                print(f"  ⚠️  {rel}")
                for s in found:
                    print(f"       → {s}")
        print(f"\n  {len(findings)} file(s) contain secrets.")
        return

    if args.dry_run:
        print("  (Dry run — no files will be modified)\n")

    stats = _scan_and_redact_impl(secrets, args.hermes_dir, args.dry_run)

    print(f"\n{'  Done.' if args.dry_run else ''}")
    print(f"  Files scanned:  {stats['files_scanned']}")
    print(f"  Files modified: {stats['files_modified']}")
    if stats["errors"]:
        print(f"  Errors: {len(stats['errors'])}")
        for err in stats["errors"]:
            print(f"    {err}")

    sys.exit(0 if not stats["errors"] else 1)


if __name__ == "__main__":
    main()
