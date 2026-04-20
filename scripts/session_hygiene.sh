#!/usr/bin/env bash
# session_hygiene.sh — Run after a sensitive Hermes session (or on a timer).
#
# Requires CERBERUS_PAIRS_FILE: a chmod 600 file with lines of secret:placeholder
# (same format as redact_hermes.py --secrets-file).
#
# Usage:
#   export CERBERUS_PAIRS_FILE="$HOME/.config/cerberus/pairs.txt"
#   bash scripts/session_hygiene.sh
#   bash scripts/session_hygiene.sh --dry-run
#   bash scripts/session_hygiene.sh --include-shell-history
#
# Extra args are passed through to redact_hermes.py (e.g. --extra-root ./myapp).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REDACT="${SCRIPT_DIR}/redact_hermes.py"
PAIRS="${CERBERUS_PAIRS_FILE:-}"

if [[ ! -f "$REDACT" ]]; then
  echo "redact_hermes.py not found at $REDACT" >&2
  exit 1
fi

if [[ -z "$PAIRS" ]]; then
  echo "Set CERBERUS_PAIRS_FILE to a file containing secret:placeholder pairs (chmod 600)." >&2
  echo "Example: export CERBERUS_PAIRS_FILE=\"\$HOME/.config/cerberus/pairs.txt\"" >&2
  exit 1
fi

if [[ ! -f "$PAIRS" ]]; then
  echo "CERBERUS_PAIRS_FILE does not exist: $PAIRS" >&2
  exit 1
fi

MODE=$(stat -c '%a' "$PAIRS" 2>/dev/null || stat -f '%OLp' "$PAIRS" 2>/dev/null || echo "")
if [[ -n "$MODE" && "$MODE" != "600" && "$MODE" != "400" ]]; then
  echo "Warning: $PAIRS should be chmod 600 or 400 (current: $MODE)" >&2
fi

exec python3 "$REDACT" --secrets-file "$PAIRS" "$@"
