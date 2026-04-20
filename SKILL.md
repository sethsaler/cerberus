---
name: cerberus
description: Automatically detect, redact, and safely handle API keys, tokens, passwords, and other sensitive data shared by the user. Prevents plaintext secrets from ever being stored in session files, skills, or disk.
category: security
---

## Trigger

Load this skill **automatically** whenever the user shares any of the following:

- API keys, API tokens, bearer tokens
- Passwords or passphrases
- Private keys (SSH, GPG, etc.)
- Any string that matches a known secret pattern (see Patterns below)
- Requests to "save", "store", or "remember" a credential
- **You need an API key or other secret to proceed** (build, test, deploy, call an API)

---

## Key intake protocol (DEFAULT when an API key is needed)

When the task requires a secret the agent does not already have, **do not ask the user to paste the key in chat** unless they insist. Default flow:

1. **Scaffold** — Run the setup script from the **project root** (or pass `--project`):

   ```bash
   bash scripts/setup_api_key_env.sh --project . --var OPENAI_API_KEY
   ```

   Repeat `--var NAME` for each key (e.g. `--var ANTHROPIC_API_KEY`). This creates `.cerberus/env.local` with `NAME=REPLACE_ME`, sets **chmod 600** on the file and **chmod 700** on `.cerberus/`, and appends `.cerberus/` to the project **`.gitignore`** if present.

2. **Open for manual entry** — The script opens the file in `$EDITOR`, or `cursor`, or `code` when available. If none apply, tell the user the path and ask them to open it locally. Use `--no-open` only in headless environments.

3. **Wait** — Tell the user: replace each `REPLACE_ME` with their real key and save the file. **Do not** ask them to paste the value in the chat.

4. **Seal (after they save)** — Build the redaction pairs file and scrub Hermes + project (never print secret values or `cat` the env file):

   ```bash
   python3 scripts/env_to_pairs.py --env-file .cerberus/env.local --pairs-out ~/.config/cerberus/pairs.txt
   python3 scripts/redact_hermes.py --secrets-file ~/.config/cerberus/pairs.txt --extra-root .
   ```

   Point `--pairs-out` at a user-private path (chmod 600). If `env_to_pairs.py` exits **2** (no real values yet), remind the user to save real keys in `.cerberus/env.local` and re-run.

   The redactor **skips** `.cerberus/env.local` so your on-disk key is not replaced by placeholders (you still need `chmod 600` and `.gitignore`). It **does** remove the same values from Hermes logs, session JSON, and other files under `--extra-root`.

5. **Use the key without echoing it** — Load via the environment in later commands, e.g. `set -a && source .cerberus/env.local && set +a && your-command`, or export only the variable names your tooling needs. Never paste file contents into chat or tool args.

6. **Ongoing** — Keep `CERBERUS_PAIRS_FILE` or the same pairs path for `session_hygiene.sh` after sessions. If the user **did** paste a key in chat, fall through to **Redact from Disk** below immediately.

---

## Threat model (what this skill does and does not do)

**In scope:** Limit exposure of **plaintext secrets in local Hermes storage** (history, session JSON, SQLite `state.db`, transcripts) by redacting known values and guiding safer handling.

**Out of scope / not guaranteed:**

- **Breach recovery:** If a secret was ever written to disk, backups, sync folders, IDE local history, or logs, **assume it may still exist somewhere**. Redaction reduces risk on the primary paths; it does not prove erasure everywhere.
- **Platform security:** "Agent memory" or vendor encryption is a **trust boundary**, not a substitute for a secrets manager. If the threat includes compromised accounts or hosts, prefer **vaults, OIDC/workload identity, and short-lived tokens**.
- **Perfect detection:** Regex patterns miss novel formats; treat pattern lists as **best-effort** and extend them as your stack changes.

---

## Default stance (prefer this order)

1. **Manual entry file first** — use **Key intake protocol** (`.cerberus/env.local` + `env_to_pairs.py` + `redact_hermes.py`) whenever you need a new API key.
2. **No raw secrets in chat** — use env files, `op run`, cloud IAM, or files outside the repo that tools read at runtime.
3. **If a secret was pasted** — redact from Hermes storage immediately, then **rotate** the credential at the provider if exposure is plausible (see checklist below).
4. **Inventory** — `SECRETS.md` should list **labels and placeholders only**, not live values. Never commit it.

---

## Sensitive Patterns to Guard

```python
SENSITIVE_PATTERNS = [
    # OpenAI / Anthropic
    (r'sk-[A-Za-z0-9_-]{20,}',                        'OPENAI_API_KEY'),
    (r'sk-ant-[A-Za-z0-9_-]{30,}',                    'ANTHROPIC_API_KEY'),
    # Replicate
    (r'r8_[A-Za-z0-9_-]{40,}',                        'REPLICATE_API_KEY'),
    # Krea.ai / inference.sh (UUID:secret format)
    (r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[A-Za-z0-9_-]+', 'API_KEY'),
    # AgentMail
    (r'am_us_[a-f0-9]{48}',                           'AGENTMAIL_API_KEY'),
    # GLM / Zhipu (32-hex.secret format)
    (r'[0-9a-f]{32}\.[A-Za-z0-9_-]+',                 'GLM_API_KEY'),
    # Generic long hex/string tokens (must be handled carefully — high false-positive risk)
    (r'(?i)(api[_-]?key|apikey|auth[_-]?token|access[_-]?token|secret[_-]?key|bearer)\s*[:=]\s*["\']?[A-Za-z0-9_-]{20,}["\']?', 'SENSITIVE_TOKEN'),
    # SSH private keys
    (r'-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----', 'PRIVATE_KEY'),
    # Credentials embedded in URLs
    (r'[a-zA-Z0-9.+-]+://[^:]+:[^@]+@[a-zA-Z0-9./-]+', 'CREDENTIALS_IN_URL'),
]
```

---

## Handling Protocol

### Step 1 — Detect

When a sensitive value is detected in the user's message, extract it and identify its type using the patterns above.

### Step 2 — Redact from Disk (IMMEDIATE)

Run the redaction script against all Hermes storage locations.

**Prefer inputs that avoid shell history and process listings:**

```bash
# Recommended: pipe pairs (stdin), or use --secrets-file with chmod 600
printf '%s\n' 'sk-abc...:***OPENAI_KEY_REDACTED***' | python3 scripts/redact_hermes.py --from-stdin
```

```bash
python3 scripts/redact_hermes.py --secrets-file /path/to/pairs.txt
```

Avoid putting live secrets in argv when possible (`--secrets "..."` is visible in `/proc` and may be logged).

```bash
# Fallback (less ideal): comma-separated on the command line
python3 scripts/redact_hermes.py --secrets "key1:value1,key2:value2,..."
```

Known labels can be tracked in `~/.hermes/skills/security/cerberus/SECRETS.md` (**placeholders only**, gitignored). The script replaces each plaintext value with `***{TYPE}_REDACTED***`.

**Never leave the plaintext value in any file.**

### Step 2b — Other locations (optional)

Secrets sometimes land in **project env files**, **shell history**, or other trees. The same redactor can scan extra roots:

```bash
# Project only (no Hermes) — dry-run first
python3 scripts/redact_hermes.py --skip-hermes --extra-root ./myapp --dry-run --secrets-file /path/to/pairs.txt
```

```bash
# Hermes + a project directory
python3 scripts/redact_hermes.py --extra-root ./myapp --secrets-file /path/to/pairs.txt
```

**Shell history** (`~/.bash_history`, `~/.zsh_history`) — only with explicit opt-in; this **rewrites** those files. Prefer `--dry-run` first:

```bash
python3 scripts/redact_hermes.py --include-shell-history --dry-run --from-stdin < /path/to/pairs.txt
```

`--verify` and `--audit` apply to **all** selected roots (Hermes, extra paths, and shell history when included).

### Step 2c — Session end (automation)

After a sensitive session, run redaction again (active session files may still have contained plaintext until closed). Optional wrapper:

```bash
export CERBERUS_PAIRS_FILE="$HOME/.config/cerberus/pairs.txt"   # chmod 600
bash scripts/session_hygiene.sh
bash scripts/session_hygiene.sh --verify
```

Pass through flags such as `--extra-root ./myapp` or `--include-shell-history` as needed.

### Step 3 — Memory: metadata only

Do **not** store the real secret value in agent memory. If the user needs a reminder, store only:

- Service name / purpose
- Placeholder label (e.g. `***OPENAI_KEY_REDACTED***`)
- Optional: last 4 characters for confirmation (`...xyz1`)

If the user says "remember this key for later use", explain that **remembering the actual key in memory is unsafe**; they should use a secrets manager or env injection and only share non-secret handles with the agent.

### Step 4 — Warn on Risky Patterns

If the user pastes a raw key into chat without any context or warning, respond with:

> "I see you've shared an API key. I'll redact it from Hermes storage immediately. For future use, inject secrets via env vars or a vault (`op run`, cloud IAM) so they never hit session history. If this key may have been exposed, rotate it at the provider."

### Step 5 — Never Log or Print Keys

- When acknowledging receipt of a key, print only the **last 4 characters** (e.g., `...xyz1`)
- Never echo back the full value
- Never include keys in tool call arguments that appear in logs

### Step 6 — After exposure (incident checklist)

If a real secret touched chat, disk, or CI logs:

1. **Redact** Hermes storage (this skill).
2. **Rotate** the credential at the provider; treat the old one as compromised if there was any realistic exposure.
3. **Update** consumers (env, deployment secrets, local files).
4. **Verify** old credential no longer works; run `python3 scripts/redact_hermes.py --verify --secrets-file ...` (optionally with `--extra-root` / `--include-shell-history`) so automation fails if plaintext remains anywhere you scan.

### Step 7 — Active session caveat

The current session file may still receive plaintext until the session ends. **Re-run redaction after the session closes** or on a schedule. Pair with disk encryption and minimal retention for `~/.hermes` where possible.

---

## Defense in depth (outside this skill)

- **Git history:** use [Gitleaks](https://github.com/gitleaks/gitleaks) locally via **pre-commit** (`.pre-commit-config.yaml` in this repo) and in **CI** (`.github/workflows/gitleaks.yml`). That catches accidental commits of keys; it does **not** replace rotating a key that was already pushed.
- Keep `.env*` and similar out of version control; block commits that add them.
- Short-lived tokens and workload identity instead of long-lived API keys.
- Filesystem permissions on any file that lists `secret:placeholder` pairs (e.g. `chmod 600`).
- **Tooling logs:** avoid passing secrets in tool arguments that get logged; prefer env var **names** or paths to unread-by-default files.

---

## Secrets inventory

Add **placeholder labels and notes only** — not live values. The inventory lives in `SECRETS.md` (gitignored).

| Service | Redacted Form | Added |
|---------|---------------|-------|
| *(none yet — add your own)* | | |

---

## Pitfalls

- **Do NOT** write plaintext keys to skill SKILL.md files — use `***REDACTED***` placeholders
- **Do NOT** pass live secrets through shell history — prefer `--from-stdin` or `--secrets-file`
- **Do NOT** include keys in terminal command history — use env vars or prompt at runtime
- **Do NOT** save keys to `.env` files inside project repos — use ignored paths or OS keychain-backed tooling
- If a skill needs a key at runtime, accept it via environment or parameters supplied outside chat, not as a stored value in the session
- Regex detection is incomplete; when in doubt, treat ambiguous high-entropy strings as sensitive
- When piping pairs into the redactor, put **`--from-stdin` before `--verify`** — stdin can only be read once
