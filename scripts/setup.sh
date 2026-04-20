#!/usr/bin/env bash
# =============================================================================
# cerberus/setup.sh
# =============================================================================
# One-command installer for the cerberus skill.
# Run this from the repo root:
#   bash scripts/setup.sh
#
# What it does:
#   1. Finds your Hermes Agent skills directory (~/.hermes/skills by default)
#   2. Prompts for the install path if non-standard
#   3. Copies this skill into a gitignored subdirectory
#   4. Creates SECRETS.md (gitignored) for the secrets inventory
#   5. Prints a quick sanity check
#
# Requirements: bash 4+, cp, mkdir, echo, cat
# =============================================================================

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILL_DIR="$REPO_DIR"
SKILL_NAME="cerberus"
SKILL_SUBDIR="security/$SKILL_NAME"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

info()  { echo "ℹ️   $*"; }
warn()  { echo "⚠️   $*" >&2; }
ok()    { echo "✅   $*"; }
error() { echo "❌   $*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || error "Required command '$1' not found. Please install it first."
}

confirm() {
  local prompt="${1:-Continue?}"
  local reply
  read -rp "$prompt [y/N] " reply || true
  case "$reply" in
    [yY]|[yY][eE][sS]) return 0 ;;
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# Step 0: prerequisites
# ---------------------------------------------------------------------------

need "bash"
need "cp"
need "mkdir"

# ---------------------------------------------------------------------------
# Step 1: detect hermes directory
# ---------------------------------------------------------------------------

HERMES_DIR="${HERMES_DIR:-}"
if [[ -z "$HERMES_DIR" ]]; then
  if [[ -d "$HOME/.hermes/skills" ]]; then
    HERMES_DIR="$HOME/.hermes/skills"
  elif [[ -d "$HOME/.hermes" ]]; then
    HERMES_DIR="$HOME/.hermes/skills"
    info "Detected Hermes dir: $HERMES_DIR"
  else
    read -rp "Enter your Hermes Agent skills directory: " HERMES_DIR
    HERMES_DIR="${HERMES_DIR:-$HOME/.hermes/skills}"
  fi
fi

# Resolve ~ and relative paths
HERMES_DIR="$(eval echo "$HERMES_DIR")"

if [[ ! -d "$HERMES_DIR" ]]; then
  warn "Skills directory does not exist: $HERMES_DIR"
  if confirm "Create it?"; then
    mkdir -p "$HERMES_DIR"
    ok "Created $HERMES_DIR"
  else
    error "Aborted."
  fi
fi

# ---------------------------------------------------------------------------
# Step 2: target install path
# ---------------------------------------------------------------------------

TARGET_DIR="$HERMES_DIR/$SKILL_SUBDIR"

if [[ -d "$TARGET_DIR" ]]; then
  warn "Skill already exists at $TARGET_DIR"
  if confirm "Overwrite it?"; then
    info "Removing existing installation..."
    rm -rf "$TARGET_DIR"
  else
    error "Aborted. Remove the existing skill first if you want a fresh install."
  fi
fi

# ---------------------------------------------------------------------------
# Step 3: create gitignored subdirectory structure
# ---------------------------------------------------------------------------

info "Creating skill directory at $TARGET_DIR..."
mkdir -p "$TARGET_DIR"

# ---------------------------------------------------------------------------
# Step 4: copy skill files (but NOT SECRETS.md if it exists in repo)
# ---------------------------------------------------------------------------

info "Copying SKILL.md..."
cp "$SKILL_DIR/SKILL.md" "$TARGET_DIR/SKILL.md"

info "Copying scripts..."
mkdir -p "$TARGET_DIR/scripts"
if [[ -f "$SKILL_DIR/scripts/redact_hermes.py" ]]; then
  cp "$SKILL_DIR/scripts/redact_hermes.py" "$TARGET_DIR/scripts/redact_hermes.py"
fi

# ---------------------------------------------------------------------------
# Step 5: create local SECRETS.md (gitignored, stores secret inventory)
# ---------------------------------------------------------------------------

if [[ ! -f "$TARGET_DIR/SECRETS.md" ]]; then
  info "Creating SECRETS.md (gitignored — store your secrets inventory here)..."
  cat > "$TARGET_DIR/SECRETS.md" << 'EOF'
---
# This file is .gitignored — use it for labels and placeholders only.
# Do NOT store live secret values here (or anywhere the agent can sync to git).
#
# | Service       | Redacted Placeholder              | Notes        |
# |---------------|------------------------------------|--------------|
# | myservice.com | ***MYSERVICE_API_KEY_REDACTED***   | Added 2026-XX |
#
# To redact a leaked value from Hermes storage, prefer piping pairs into the script
# so secrets never appear in shell history or `ps`:
#   printf '%s\n' 'sk-...:***OPENAI_REDACTED***' | python3 scripts/redact_hermes.py --from-stdin
#
EOF
  # Ensure it's .gitignored so the user's global gitignore covers it
  # (we'll also add it to the repo's .gitignore below)
fi

# ---------------------------------------------------------------------------
# Step 6: verify .gitignore covers SECRETS.md
# ---------------------------------------------------------------------------

if [[ -f "$REPO_DIR/.gitignore" ]]; then
  if ! grep -qx "SECRETS.md" "$REPO_DIR/.gitignore"; then
    info "Adding SECRETS.md to .gitignore..."
    echo -e "\n# Secrets inventory (contains real values — never commit)" >> "$REPO_DIR/.gitignore"
    echo "SECRETS.md" >> "$REPO_DIR/.gitignore"
  fi
fi

# ---------------------------------------------------------------------------
# Step 7: make redact script executable
# ---------------------------------------------------------------------------

if [[ -f "$TARGET_DIR/scripts/redact_hermes.py" ]]; then
  chmod +x "$TARGET_DIR/scripts/redact_hermes.py"
fi

# ---------------------------------------------------------------------------
# Step 8: sanity check
# ---------------------------------------------------------------------------

echo ""
echo "============================================"
ok "cerberus installed successfully!"
echo "============================================"
echo ""
echo "  Skill location:  $TARGET_DIR"
echo "  Secrets file:    $TARGET_DIR/SECRETS.md"
echo "  Redact script:   $TARGET_DIR/scripts/redact_hermes.py"
echo ""
echo "Next steps:"
echo "  1. Optional: edit $TARGET_DIR/SECRETS.md with placeholder labels only"
echo "     (never store live secrets in that file)"
echo ""
echo "  2. To clean plaintext from Hermes storage, prefer stdin or a chmod 600 file:"
echo "     printf '%s\\n' 'YOUR_KEY:***YOUR_SERVICE_REDACTED***' | \\"
echo "       python3 $TARGET_DIR/scripts/redact_hermes.py --from-stdin"
echo ""
echo "  3. After a session ends, re-run redaction; use --verify in CI if needed."
echo ""
echo "  4. The skill loads automatically — Hermes will use it when you share credentials."
echo ""
