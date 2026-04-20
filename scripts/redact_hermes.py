#!/usr/bin/env python3
"""
redact_hermes.py — Redact known secrets from Hermes storage and optional paths.

Primary target: ~/.hermes (session JSON, history, state.db).

Also supports extra directories (e.g. project .env.local), shell history files,
and any explicit file path — use --dry-run first outside ~/.hermes.

Usage:
    python3 redact_hermes.py --secrets "secret1:value1,secret2:value2,..."

    Recommended (avoids shell history / argv exposure):
        printf '%s\n' 'sk-abc...:***OPENAI_REDACTED***' | python3 redact_hermes.py --from-stdin
        python3 redact_hermes.py --secrets-file /path/to/pairs.txt

    Scan only a project directory (Hermes unchanged):
        python3 redact_hermes.py --skip-hermes --extra-root ./myapp --dry-run --from-stdin < pairs.txt

    Include shell history (~/.bash_history, ~/.zsh_history if present):
        python3 redact_hermes.py --include-shell-history --from-stdin < pairs.txt

    Verify (exit 1 if any secret still present):
        python3 redact_hermes.py --verify --secrets-file pairs.txt
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
# Path collection
# ---------------------------------------------------------------------------


def default_shell_history_files() -> list[str]:
    """Common shell history paths (only those that exist)."""
    candidates = [
        os.path.expanduser("~/.bash_history"),
        os.path.expanduser("~/.zsh_history"),
    ]
    return [p for p in candidates if os.path.isfile(p)]


def collect_files_under_roots(roots: list[str]) -> list[str]:
    """
    Expand roots into a list of file paths. Roots may be files or directories.
    Skips .git directories when walking.
    """
    out: list[str] = []
    seen: set[str] = set()

    for raw in roots:
        root = os.path.expanduser(os.path.normpath(raw))
        if not os.path.exists(root):
            continue

        if os.path.isfile(root):
            ap = os.path.abspath(root)
            if ap not in seen:
                seen.add(ap)
                out.append(ap)
            continue

        for dirpath, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d != ".git"]
            for fn in files:
                fp = os.path.join(dirpath, fn)
                ap = os.path.abspath(fp)
                if ap not in seen:
                    seen.add(ap)
                    out.append(ap)

    return out


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
    table and replaces secret values.
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


def redact_one_path(
    fp: str,
    secrets: dict[str, str],
    dry_run: bool,
) -> int:
    """Apply redaction to a single file using the same rules as Hermes storage."""
    fn = os.path.basename(fp)
    if fn in (".hermes_history", "transcript.txt", "memory.json"):
        return redact_file(fp, secrets, dry_run=dry_run)
    if fn.endswith(".json") or fn.endswith(".jsonl"):
        return redact_json_file(fp, secrets, dry_run=dry_run)
    if fn == "state.db":
        return redact_sqlite_db(fp, secrets, dry_run=dry_run)
    return redact_file(fp, secrets, dry_run=dry_run)


def audit_files(secrets: dict[str, str], file_paths: list[str]) -> dict[str, list[str]]:
    """
    Scan files and report where secrets are found (no modifications).
    Returns {path: [found_secrets_list]}.
    """
    findings: dict[str, list[str]] = {}

    for fp in file_paths:
        found_in_file: list[str] = []
        try:
            if fp.endswith(".db"):
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


def scan_and_redact_paths(
    secrets: dict[str, str],
    file_paths: list[str],
    dry_run: bool = False,
) -> dict:
    """Redact secrets from each file path."""
    stats: dict = {"files_scanned": 0, "files_modified": 0, "errors": []}

    for fp in file_paths:
        stats["files_scanned"] += 1
        try:
            stats["files_modified"] += redact_one_path(fp, secrets, dry_run=dry_run)
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


def build_scan_roots(
    hermes_dir: str,
    skip_hermes: bool,
    extra_roots: list[str] | None,
    include_shell_history: bool,
) -> list[str]:
    """Assemble list of roots (dirs or files) to scan."""
    roots: list[str] = []
    if not skip_hermes:
        roots.append(hermes_dir)
    if extra_roots:
        roots.extend(extra_roots)
    if include_shell_history:
        roots.extend(default_shell_history_files())
    return roots


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Redact secrets from Hermes storage and optional paths.",
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
        help=f"Path to Hermes data directory (default: {HERMES_DIR})",
    )
    parser.add_argument(
        "--skip-hermes",
        action="store_true",
        help="Do not scan ~/.hermes (or --hermes-dir); only --extra-root paths are used",
    )
    parser.add_argument(
        "--extra-root",
        action="append",
        metavar="PATH",
        help="Additional file or directory to scan (repeatable). Use for .env.local, project dirs, etc.",
    )
    parser.add_argument(
        "--include-shell-history",
        action="store_true",
        help="Include ~/.bash_history and ~/.zsh_history if they exist (destructive — prefer --dry-run first)",
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

    roots = build_scan_roots(
        args.hermes_dir,
        args.skip_hermes,
        args.extra_root,
        args.include_shell_history,
    )

    if not roots:
        print(
            "Error: No scan roots. Remove --skip-hermes or add --extra-root / --include-shell-history.",
            file=sys.stderr,
        )
        sys.exit(1)

    file_paths = collect_files_under_roots(roots)
    root_summary = ", ".join(
        r.replace(os.path.expanduser("~"), "~") for r in roots
    )

    if args.verify:
        print(
            f"\nVerifying {len(secrets)} secret(s) across {len(file_paths)} file(s)...\n"
            f"  Roots: {root_summary}\n"
        )
        findings = audit_files(secrets, file_paths)
        if not findings:
            print("  OK — no tracked secrets found.")
            sys.exit(0)
        for fp, found in findings.items():
            rel = fp.replace(os.path.expanduser("~"), "~")
            print(f"  FAIL  {rel}")
            for s in found:
                print(f"        → {s}")
        print(f"\n  {len(findings)} file(s) still contain secret material.")
        sys.exit(1)

    if args.audit:
        print(
            f"\nScanning {len(secrets)} secret(s) in {len(file_paths)} file(s)...\n"
            f"  Roots: {root_summary}\n"
        )
        findings = audit_files(secrets, file_paths)
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
        f"\n{prefix}Redacting {len(secrets)} secret(s) in {len(file_paths)} file(s)...\n"
        f"  Roots: {root_summary}\n"
    )

    if args.dry_run:
        print("  (Dry run — no files will be modified)\n")

    stats = scan_and_redact_paths(secrets, file_paths, dry_run=args.dry_run)

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
