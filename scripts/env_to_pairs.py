#!/usr/bin/env python3
"""
env_to_pairs.py — Build a redact_hermes pairs file from a dotenv-style file.

Reads KEY=value lines from --env-file and writes secret:placeholder pairs to
--pairs-out. Does not print secret values to stdout (only a short summary).

Skips empty values, REPLACE_ME placeholders, and lines already marked redacted.
"""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys


def parse_env_lines(content: str) -> dict[str, str]:
    """Parse simple KEY=value / export KEY=value lines (no multiline values)."""
    out: dict[str, str] = {}
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip("'").strip('"')
        if not key:
            continue
        out[key] = val
    return out


def placeholder_for(key: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_]+", "_", key).strip("_") or "SECRET"
    return f"***{safe}_REDACTED***"


def should_skip_value(val: str) -> bool:
    v = val.strip()
    if not v:
        return True
    if v.upper() == "REPLACE_ME":
        return True
    if "REDACTED" in v:
        return True
    return False


def main() -> None:
    p = argparse.ArgumentParser(
        description="Write secret:placeholder pairs from an env file for redact_hermes.py.",
    )
    p.add_argument(
        "--env-file",
        required=True,
        help="Path to dotenv-style file (e.g. .cerberus/env.local)",
    )
    p.add_argument(
        "--pairs-out",
        required=True,
        help="Output path for pairs (one secret:placeholder per line).",
    )
    p.add_argument(
        "--append",
        action="store_true",
        help="Append to pairs file instead of overwriting",
    )
    args = p.parse_args()

    path = os.path.abspath(os.path.expanduser(args.env_file))
    if not os.path.isfile(path):
        print(f"Error: env file not found: {path}", file=sys.stderr)
        sys.exit(1)

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    pairs: dict[str, str] = {}
    for key, val in parse_env_lines(content).items():
        if should_skip_value(val):
            continue
        pairs[val] = placeholder_for(key)

    out_path = os.path.abspath(os.path.expanduser(args.pairs_out))
    parent = os.path.dirname(out_path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    mode = "a" if args.append else "w"
    with open(out_path, mode, encoding="utf-8") as f:
        if mode == "a" and os.path.isfile(out_path) and os.path.getsize(out_path) > 0:
            f.write("\n")
        for secret, ph in pairs.items():
            f.write(f"{secret}:{ph}\n")

    os.chmod(out_path, stat.S_IRUSR | stat.S_IWUSR)

    print(
        f"Wrote {len(pairs)} pair(s) to {out_path} (mode 600). "
        "Do not cat this file in chat."
    )
    if not pairs:
        print(
            "No non-placeholder values found — fill REPLACE_ME in the env file first.",
            file=sys.stderr,
        )
        sys.exit(2)


if __name__ == "__main__":
    main()
