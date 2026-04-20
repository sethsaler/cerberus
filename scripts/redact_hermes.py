#!/usr/bin/env python3
"""
redact_hermes.py — Redact secrets from Hermes Agent storage files.

Usage:
    python3 redact_hermes.py --secrets "secret1:value1,secret2:value2,..."

    Or with named pairs:
    python3 redact_hermes.py \
        --secret "openai:sk-...ABC" \
        --secret "replicate:r8_...XYZ"

    Interactive (will prompt for secrets):
        python3 redact_hermes.py --interactive

    Recommended (avoids shell history / argv exposure):
        printf '%s\n' 'sk-abc...:***OPENAI_REDACTED***' | python3 redact_hermes.py --from-stdin
        python3 redact_hermes.py --secrets-file /path/to/pairs.txt

    Audit mode (find secrets without modifying):
        python3 redact_hermes.py --audit --secrets "..."

    Verify mode (exit 1 if any secret still present — CI / post-session checks):
        python3 redact_hermes.py --verify --secrets "..."

Examples:
    # Single secret
    python3 redact_hermes.py --secrets "sk-1234567890abcdef:***OPENAI_KEY_REDACTED***"

    # Multiple secrets
    python3 redact_hermes.py \
        --secret "sk-...:***OPENAI_KEY_REDACTED***" \
        --secret "r8_...:***REPLICATE_KEY_REDACTED***"

    # Full cleanup of known secrets (add your own):
    python3 redact_hermes.py \
        --secret "YOUR_KEY_HERE:***YOUR_SERVICE_REDACTED***"
"""

from __future__ import annotations

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

def redact_file(
    path: str,
    secrets: dict[str, str],
    verbose: bool = True,
    dry_run: bool = False,
) -> int:
    """Replace all secret occurrences in a plain text file. Returns 1 if modified (or would be)."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except (IOError, OSError):
        return 0

    original = content
    for secret, placeholder in secrets.items():
        if len(secret) > 8 and secret in content:
            content = content.replace(secret, placeholder)

    if content != original:
        if not dry_run:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
        if verbose:
            tag = "would update" if dry_run else "✓"
            print(f"  {tag}  {path}")
        return 1
    return 0


def redact_json_file(
    path: str,
    secrets: dict[str, str],
    verbose: bool = True,
    dry_run: bool = False,
) -> int:
    """Replace all secret occurrences in a .json file (session files, dumps, etc.)."""
    return redact_file(path, secrets, verbose, dry_run)


def redact_sqlite_db(
    db_path: str,
    secrets: dict[str, str],
    verbose: bool = True,
    dry_run: bool = False,
) -> int:
    """
    Redact secrets from a SQLite database (state.db).
    Backs up the DB before modifying, then walks every text column in every
    table and replaces secret values. Handles the Hermes state.db schema.
    """
    if not os.path.exists(db_path):
        return 0

    backup_path = f"{db_path}.bak.{int(time.time())}"

    if dry_run:
        return _sqlite_redact_dry_run(db_path, secrets, verbose)

    shutil.copy2(db_path, backup_path)

    files_modified = 0
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]

        for table in tables:
            try:
                cursor.execute(f"PRAGMA table_info({table})")
                columns = [(row[1], row[2]) for row in cursor.fetchall()]

                text_cols = [
                    name
                    for name, dtype in columns
                    if dtype in ("TEXT", "BLOB", "ANY")
                    or "CHAR" in dtype.upper()
                    or "STR" in dtype.upper()
                ]

                for col in text_cols:
                    try:
                        cursor.execute(
                            f"SELECT rowid, {col} FROM {table} WHERE {col} IS NOT NULL"
                        )
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
                                cursor.execute(
                                    f"UPDATE {table} SET {col} = ? WHERE rowid = ?",
                                    (new_value, rowid),
                                )
                    except sqlite3.Error:
                        pass

            except sqlite3.Error:
                pass

        conn.commit()
        conn.close()
        files_modified = 1
        if verbose:
            print(f"  ✓  {db_path}  (SQLite — backup: {os.path.basename(backup_path)})")

    except Exception as e:
        if os.path.exists(backup_path):
            shutil.move(backup_path, db_path)
        print(
            f"  ✗  {db_path} — error: {e}  (restored from backup)",
            file=sys.stderr,
        )
        return 0
    finally:
        if files_modified and os.path.exists(backup_path):
            try:
                os.remove(backup_path)
            except OSError:
                pass

    return files_modified


def _sqlite_redact_dry_run(db_path: str, secrets: dict[str, str], verbose: bool) -> int:
    """Count whether any secret appears in the DB without writing."""
    uri = f"file:{db_path}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error:
        return 0
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    found = False
    for table in tables:
        try:
            cursor.execute(f"PRAGMA table_info({table})")
            columns = [(row[1], row[2]) for row in cursor.fetchall()]
            text_cols = [
                name
                for name, dtype in columns
                if dtype in ("TEXT", "BLOB", "ANY")
                or "CHAR" in dtype.upper()
                or "STR" in dtype.upper()
            ]
            for col in text_cols:
                try:
                    cursor.execute(
                        f"SELECT {col} FROM {table} WHERE {col} IS NOT NULL"
                    )
                    for (value,) in cursor.fetchall():
                        if not isinstance(value, str):
                            continue
                        for secret in secrets:
                            if len(secret) > 8 and secret in value:
                                found = True
                                break
                        if found:
                            break
                except sqlite3.Error:
                    pass
            if found:
                break
        except sqlite3.Error:
            pass
    conn.close()
    if found and verbose:
        print(f"  [dry-run] would update  {db_path}  (SQLite)")
    return 1 if found else 0


def audit_hermes(secrets: dict[str, str], hermes_dir: str = HERMES_DIR) -> dict:
    """
    Scan hermes storage and report where secrets are found (without modifying anything).
    Returns {path: [found_secrets_list]}.
    """
    findings: dict[str, list[str]] = {}
    for root, dirs, files in os.walk(hermes_dir):
        dirs[:] = [d for d in dirs if d != ".git"]

        for fn in files:
            fp = os.path.join(root, fn)
            found_in_file: list[str] = []

            try:
                if fn.endswith(".json"):
                    with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                elif fn.endswith(".db"):
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


def scan_and_redact(
    secrets: dict[str, str],
    hermes_dir: str = HERMES_DIR,
    dry_run: bool = False,
) -> dict:
    """Walk hermes_dir and redact secrets from all relevant files."""
    stats: dict = {"files_scanned": 0, "files_modified": 0, "errors": []}

    for root, dirs, files in os.walk(hermes_dir):
        dirs[:] = [d for d in dirs if d != ".git"]
        for fn in files:
            fp = os.path.join(root, fn)
            stats["files_scanned"] += 1
            try:
                if fn in (".hermes_history", "transcript.txt", "memory.json"):
                    stats["files_modified"] += redact_file(fp, secrets, dry_run=dry_run)
                elif fn.endswith(".json") or fn.endswith(".jsonl"):
                    stats["files_modified"] += redact_json_file(
                        fp, secrets, dry_run=dry_run
                    )
                elif fn == "state.db":
                    stats["files_modified"] += redact_sqlite_db(
                        fp, secrets, dry_run=dry_run
                    )
                else:
                    stats["files_modified"] += redact_file(fp, secrets, dry_run=dry_run)
            except Exception as e:
                stats["errors"].append(f"{fp}: {e}")

    return stats


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_secrets_input(raw: str) -> dict[str, str]:
    """
    Parse "secret1:value1,secret2:value2,..." or line-based pairs into {secret: placeholder}.
    """
    secrets: dict[str, str] = {}
    for item in re.split(r"[\n,]+", raw.strip()):
        item = item.strip()
        if not item or ":" not in item:
            continue
        secret, _, placeholder = item.partition(":")
        secret = secret.strip()
        placeholder = placeholder.strip()
        if secret and placeholder:
            secrets[secret] = placeholder
    return secrets


def load_secrets_file(path: str) -> dict[str, str]:
    """Load secret:placeholder pairs from a UTF-8 file (one pair per line; # comments OK)."""
    secrets: dict[str, str] = {}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            secrets.update(parse_secrets_input(line))
    return secrets


def interactive_prompt() -> dict[str, str]:
    """Prompt the user for secret -> placeholder pairs interactively."""
    secrets: dict[str, str] = {}
    print("\n=== Interactive Secret Entry ===")
    print("Enter each secret followed by its placeholder label.")
    print("Press Ctrl+C or ENTER on empty secret to finish.\n")
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


def merge_secrets(base: dict[str, str], extra: dict[str, str]) -> None:
    """Merge extra into base (extra overwrites duplicate keys)."""
    base.update(extra)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Redact secrets from Hermes Agent storage files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--secrets",
        "-s",
        help='Comma- or newline-separated "secret:placeholder" pairs',
    )
    parser.add_argument(
        "--secret",
        action="append",
        dest="secret_list",
        help='Single "secret:placeholder" pair. Repeat for multiple secrets.',
    )
    parser.add_argument(
        "--secrets-file",
        "-f",
        metavar="PATH",
        help="Read pairs from a file (one secret:placeholder per line; avoids argv exposure).",
    )
    parser.add_argument(
        "--from-stdin",
        action="store_true",
        help="Read pairs from stdin (recommended for piping; same format as --secrets-file).",
    )
    parser.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="Interactively enter secrets and placeholders",
    )
    parser.add_argument(
        "--dry-run",
        "-n",
        action="store_true",
        help="Show what would be changed without modifying files",
    )
    parser.add_argument(
        "--audit",
        "-a",
        action="store_true",
        help="Show which files contain which secrets (no modifications)",
    )
    parser.add_argument(
        "--verify",
        "-V",
        action="store_true",
        help="Exit with status 1 if any secret is still present (audit-only)",
    )
    parser.add_argument(
        "--hermes-dir",
        default=HERMES_DIR,
        help=f"Path to hermes directory (default: {HERMES_DIR})",
    )

    args = parser.parse_args()

    secrets: dict[str, str] = {}

    if args.secrets_file:
        merge_secrets(secrets, load_secrets_file(args.secrets_file))

    if args.from_stdin:
        stdin_text = sys.stdin.read()
        merge_secrets(secrets, parse_secrets_input(stdin_text))

    if args.secrets:
        merge_secrets(secrets, parse_secrets_input(args.secrets))

    if args.secret_list:
        for item in args.secret_list:
            merge_secrets(secrets, parse_secrets_input(item))

    if args.interactive:
        merge_secrets(secrets, interactive_prompt())

    if not secrets:
        print(
            "Error: No secrets provided. Use --secrets-file, --from-stdin, --secrets, --secret, or --interactive.",
            file=sys.stderr,
        )
        parser.print_help()
        sys.exit(1)

    for secret, placeholder in secrets.items():
        if len(secret) > 8 and placeholder in secret:
            print(
                f"WARNING: placeholder '{placeholder}' appears inside its own secret — may cause nested redaction.",
                file=sys.stderr,
            )

    if args.verify:
        print(f"\nVerifying {len(secrets)} secret(s) in {args.hermes_dir}...\n")
        findings = audit_hermes(secrets, args.hermes_dir)
        if not findings:
            print("  OK — no tracked secrets found in Hermes storage.")
            sys.exit(0)
        for fp, found in findings.items():
            rel = fp.replace(os.path.expanduser("~"), "~")
            print(f"  FAIL  {rel}")
            for s in found:
                print(f"        → {s}")
        print(f"\n  {len(findings)} file(s) still contain secret material.")
        sys.exit(1)

    if args.audit:
        print(f"\nScanning {len(secrets)} secret(s) in {args.hermes_dir}...\n")
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
        sys.exit(0)

    prefix = "[DRY-RUN] " if args.dry_run else ""
    print(
        f"\n{prefix}Redacting {len(secrets)} secret(s) in {args.hermes_dir}...\n"
    )

    if args.dry_run:
        print("  (Dry run — no files will be modified)\n")

    stats = scan_and_redact(secrets, args.hermes_dir, dry_run=args.dry_run)

    print(f"\n  {'Planned changes (dry run).' if args.dry_run else 'Done.'}")
    print(f"  Files scanned:  {stats['files_scanned']}")
    print(f"  Files modified: {stats['files_modified']}")
    if stats["errors"]:
        print(f"  Errors: {len(stats['errors'])}")
        for err in stats["errors"]:
            print(f"    {err}")

    sys.exit(0 if not stats["errors"] else 1)


if __name__ == "__main__":
    main()
