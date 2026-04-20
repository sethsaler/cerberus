# 🔒 cerberus

> Automatically detect, redact, and safely handle API keys and other sensitive data in Hermes Agent — forever.

**Problem:** When you share an API key with Hermes Agent, it gets embedded in session transcripts, history files, and database records in plaintext. If those files are ever compromised, your keys go with them.

**Solution:** `cerberus` is a Hermes Agent skill that automatically intercepts any sensitive value you share, redacts it from disk immediately, and stores only a safe placeholder in agent memory.

**Limits:** Redaction cleans the primary Hermes storage paths; it does not prove a secret never existed in backups, sync, or logs. If a real key may have leaked, **rotate it at the provider** — see Threat model in `SKILL.md`.

---

## ✨ Features

- **Automatic detection** — regex patterns for OpenAI, Anthropic, Replicate, AgentMail, GLM, SSH keys, and more
- **Immediate redaction** — secrets are purged from `.hermes_history`, session JSON files, and `state.db` within seconds of being shared
- **Safer CLI inputs** — `--from-stdin` and `--secrets-file` avoid putting live secrets in argv/shell history
- **Dry-run** — preview changes without writing
- **Verify mode** — exit non-zero if secrets still appear (CI / post-session checks)
- **Audit mode** — scan without modifying to see exactly where your secrets leaked
- **SQLite-aware** — properly handles Hermes's `state.db` with backup-and-restore safety
- **Zero false-positive noise** — uses full-value matching, not just pattern scanning
- **Manual API key setup** — scaffold `.cerberus/env.local`, open it for the user, then seal with `env_to_pairs.py` + `redact_hermes.py` (see below)

---

## 🔑 Default: need an API key (no pasting in chat)

Hermes agents should follow `SKILL.md` **Key intake protocol**. Short version:

```bash
# From the project that needs the key
bash scripts/setup_api_key_env.sh --project . --var OPENAI_API_KEY
# User replaces REPLACE_ME in .cerberus/env.local and saves

python3 scripts/env_to_pairs.py --env-file .cerberus/env.local --pairs-out ~/.config/cerberus/pairs.txt
python3 scripts/redact_hermes.py --secrets-file ~/.config/cerberus/pairs.txt --extra-root .
```

Then run tools with the file sourced (do not print the file):

```bash
set -a && source .cerberus/env.local && set +a && your-command
```

`env_to_pairs.py` exits **2** if every value is still `REPLACE_ME` (nothing to redact yet).

`redact_hermes.py` **does not rewrite** `.cerberus/env.local` (so sourcing keeps working); it still scrubs those values elsewhere.

---

## 🚀 Quick Start

### 1. Install the skill

```bash
git clone https://github.com/YOUR_USERNAME/cerberus.git
cd cerberus
bash scripts/setup.sh
```

That's it. The setup script detects your Hermes skills directory, copies the skill in, and creates a `SECRETS.md` for your inventory (placeholders only — not live secrets).

---

### 2. Track placeholders in the inventory (optional)

Edit `~/.hermes/skills/security/cerberus/SECRETS.md`:

```markdown
| Service       | Redacted Placeholder               | Notes       |
|---------------|------------------------------------|-------------|
| OpenAI        | ***OPENAI_API_KEY_REDACTED***      | Added 2026-04-19 |
| My Service    | ***MYSERVICE_KEY_REDACTED***       | Added 2026-04-19 |
```

Do **not** store live secret values in this file — only labels and placeholders.

---

### 3. Redact existing plaintext secrets (one-time cleanup)

**Recommended** — pipe pairs or use a file so secrets are not visible in `ps` / shell history:

```bash
printf '%s\n' 'sk-1234567890abcdef:***OPENAI_KEY_REDACTED***' 'r8_abcdef123456:***REPLICATE_KEY_REDACTED***' \
  | python3 ~/.hermes/skills/security/cerberus/scripts/redact_hermes.py --from-stdin
```

Or:

```bash
chmod 600 ./pairs.txt   # one secret:placeholder per line
python3 ~/.hermes/skills/security/cerberus/scripts/redact_hermes.py --secrets-file ./pairs.txt
```

Or use **audit mode** first to see exactly where your secrets are before touching anything:

```bash
python3 scripts/redact_hermes.py --audit \
  --secrets "sk-1234567890abcdef:***OPENAI_KEY_REDACTED***"
```

**After a session ends**, re-run redaction (the active session file may still contain plaintext until it is closed). Use `--verify` in scripts to fail if anything remains:

```bash
python3 scripts/redact_hermes.py --verify --secrets-file ./pairs.txt
```

---

### 4. Done

From now on, whenever you share a key or credential with Hermes Agent, the skill:

1. Detects it automatically
2. Redacts it from all Hermes storage files (prefer stdin/file for the redactor CLI)
3. Stores only metadata and placeholders — **not** the real value in memory
4. Shows you only the last 4 characters when confirming receipt

If a key may have been exposed, **rotate it at the provider** after redacting locally.

---

## 📁 Repo Structure

```
cerberus/
├── SKILL.md                          # The Hermes Agent skill (what gets loaded)
├── scripts/
│   ├── redact_hermes.py              # Redact known values from Hermes + optional paths
│   ├── setup_api_key_env.sh          # Scaffold .cerberus/env.local + gitignore + open editor
│   ├── env_to_pairs.py               # Build pairs file from env (for redactor; chmod 600)
│   ├── session_hygiene.sh            # Optional: CERBERUS_PAIRS_FILE + redact wrapper
│   └── setup.sh                      # One-command installer into ~/.hermes/skills/...
├── README.md                         # This file
├── LICENSE                           # MIT
└── .gitignore                        # SECRETS.md, .cerberus/
```

---

## 🔧 CLI Reference

```bash
# Recommended: stdin (no secrets in argv)
printf '%s\n' 'sk-ABC:***OPENAI_REDACTED***' | python3 redact_hermes.py --from-stdin

# Recommended: secrets file (chmod 600)
python3 redact_hermes.py --secrets-file ./pairs.txt

# Basic redaction (less ideal — secret visible in process list)
python3 redact_hermes.py --secrets "secret:placeholder"

# Multiple secrets via repeated flags
python3 redact_hermes.py \
  --secret "sk-ABC123:***OPENAI_REDACTED***" \
  --secret "r8_XYZ789:***REPLICATE_REDACTED***"

# Audit mode (find without modifying)
python3 redact_hermes.py --audit --secrets "sk-ABC123:***REDACTED***"

# Dry run (preview without writing)
python3 redact_hermes.py --dry-run --secrets-file ./pairs.txt

# Verify — exit 1 if any secret still present (CI / hooks)
python3 redact_hermes.py --verify --secrets-file ./pairs.txt

# Interactive entry
python3 redact_hermes.py --interactive

# Custom hermes directory
python3 redact_hermes.py --hermes-dir /path/to/.hermes --from-stdin < pairs.txt
```

---

## 🛡️ Detection Patterns

The skill (and script) detect these patterns automatically:

| Pattern | Type |
|---------|------|
| `sk-[A-Za-z0-9_-]{20,}` | OpenAI API key |
| `sk-ant-[A-Za-z0-9_-]{30,}` | Anthropic API key |
| `r8_[A-Za-z0-9_-]{40,}` | Replicate API key |
| `{uuid}:[A-Za-z0-9_-]+` | Krea.ai / inference.sh style |
| `am_us_[a-f0-9]{48}` | AgentMail API key |
| `{32hex}.[A-Za-z0-9_-]+` | GLM / Zhipu AI |
| `-----BEGIN ... PRIVATE KEY-----` | SSH/GPG private keys |
| `protocol://user:pass@host/` | Credentials in URLs |

You can add custom patterns in `SKILL.md` under `SENSITIVE_PATTERNS`.

---

## ⚠️ Known Limitation: Active Session

The **current active session file** (`session_YYYYMMDD_*.json`) is written in real-time as the conversation happens. Secrets mentioned in tool calls or reasoning during the current session will appear in it until the session resets. This is a fundamental architectural constraint — the skill redacts as fast as possible, but can't retroactively clean a file that's still being actively appended to.

**Mitigation:** Re-run the redaction script after the session ends. Use `--verify` in automation to catch stragglers.

---

## 🤝 Contributing

1. Fork the repo
2. Add your patterns or improvements to `SKILL.md` / `redact_hermes.py`
3. Test with `--dry-run` or `--audit` first
4. Submit a PR

---

## 📜 License

MIT — do whatever you want with it, but be kind and don't use it to harvest other people's secrets.
