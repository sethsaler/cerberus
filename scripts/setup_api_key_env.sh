#!/usr/bin/env bash
# setup_api_key_env.sh — Scaffold a local env file for manual API key entry (cerberus).
#
# Default layout: <project>/.cerberus/env.local (chmod 600), project .gitignore updated.
# Opens the file in EDITOR, cursor, or code when available.
#
# Usage:
#   bash scripts/setup_api_key_env.sh --project /path/to/repo --var OPENAI_API_KEY
#   bash scripts/setup_api_key_env.sh --project . --var ANTHROPIC_API_KEY --var OPENAI_API_KEY
#   bash scripts/setup_api_key_env.sh --project . --no-open
#
# After the user saves real values, run (does not print secrets):
#   python3 scripts/env_to_pairs.py --env-file .cerberus/env.local --pairs-out ~/.config/cerberus/pairs.txt
#   python3 scripts/redact_hermes.py --secrets-file ~/.config/cerberus/pairs.txt --extra-root .

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="."
VARS=()
NO_OPEN=false

info() { echo "cerberus: $*"; }

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project)
      PROJECT="${2:?}"
      shift 2
      ;;
    --var)
      VARS+=("${2:?}")
      shift 2
      ;;
    --no-open)
      NO_OPEN=true
      shift
      ;;
    -h|--help)
      usage
      ;;
    *)
      info "unknown arg: $1" >&2
      usage
      ;;
  esac
done

PROJECT="$(cd "$PROJECT" && pwd)"
CERB_DIR="$PROJECT/.cerberus"
ENV_FILE="$CERB_DIR/env.local"

mkdir -p "$CERB_DIR"
chmod 700 "$CERB_DIR"

if [[ ${#VARS[@]} -eq 0 ]]; then
  VARS=("OPENAI_API_KEY")
  info "no --var given; defaulting to OPENAI_API_KEY (add more with repeated --var)"
fi

if [[ ! -f "$ENV_FILE" ]]; then
  cat > "$ENV_FILE" << 'EOF'
# Cerberus — local secrets only. Do not commit. Replace REPLACE_ME with your key.
# Docs: see your provider's dashboard to create a key.

EOF
fi

for v in "${VARS[@]}"; do
  if grep -qE "^${v}=" "$ENV_FILE" 2>/dev/null; then
    info "variable already present: $v"
  else
    echo "${v}=REPLACE_ME" >> "$ENV_FILE"
    info "appended ${v}=REPLACE_ME"
  fi
done

chmod 600 "$ENV_FILE"

GITIGNORE="$PROJECT/.gitignore"
LINE=".cerberus/"
if [[ -f "$GITIGNORE" ]]; then
  if ! grep -qxF "$LINE" "$GITIGNORE" 2>/dev/null; then
    echo "" >> "$GITIGNORE"
    echo "# Cerberus local secrets (env files)" >> "$GITIGNORE"
    echo "$LINE" >> "$GITIGNORE"
    info "appended $LINE to .gitignore"
  fi
else
  printf '%s\n' "# Cerberus local secrets (env files)" "$LINE" > "$GITIGNORE"
  info "created .gitignore with $LINE"
fi

info "env file: $ENV_FILE"

if [[ "$NO_OPEN" == true ]]; then
  info "skipping editor (--no-open). Open the file above and replace REPLACE_ME."
  exit 0
fi

if [[ -n "${EDITOR:-}" ]]; then
  # shellcheck disable=SC2086
  $EDITOR "$ENV_FILE"
elif command -v cursor >/dev/null 2>&1; then
  cursor "$ENV_FILE"
elif command -v code >/dev/null 2>&1; then
  code "$ENV_FILE"
else
  info "set EDITOR or install cursor/code; open manually: $ENV_FILE"
  exit 0
fi

info "when finished saving keys, seal with env_to_pairs.py + redact_hermes.py (see SKILL.md)"
