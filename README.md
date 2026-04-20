# 🔒 secret-guardian

> Automatically detect, redact, and safely handle API keys and other sensitive data in Hermes Agent — forever.

**Problem:** When you share an API key with Hermes Agent, it gets embedded in session transcripts, history files, and database records in plaintext. If those files are ever compromised, your keys go with them.

**Solution:** `secret-guardian` is a Hermes Agent skill that automatically intercepts any sensitive value you share, redacts it from disk immediately, and stores only a safe placeholder in agent memory.

---

## ✨ Features

- **Automatic detection** — regex patterns for OpenAI, Anthropic, Replicate, AgentMail, GLM, SSH keys, and more
- **Immediate redaction** — secrets are purged from `.hermes_history`, session JSON files, and `state.db` within seconds of being shared
- **Memory-only storage** — real key values stay in encrypted agent memory, never on disk
- **Audit mode** — scan without modifying to see exactly where your secrets leaked
- **SQLite-aware** — properly handles Hermes's `state.db` with backup-and-restore safety
- **Zero false-positive noise** — uses full-value matching, not just pattern scanning

---

## 🚀 Quick Start

### 1. Install the skill

```bash
git clone https://github.com/YOUR_USERNAME/secret-guardian.git
cd secret-guardian
bash scripts/setup.sh
```

That's it. The setup script detects your Hermes skills directory, copies the skill in, and creates a `SECRETS.md` for your inventory.

---

### 2. Add your secrets to the inventory

Edit `~/.hermes/skills/security/secret-guardian/SECRETS.md`:

```markdown
| Service       | Redacted Placeholder               | Notes       |
|---------------|------------------------------------|-------------|
| OpenAI        | ***OPENAI_API_KEY_REDACTED***      | Added 2026-04-19 |
| My Service    | ***MYSERVICE_KEY_REDACTED***       | Added 2026-04-19 |
```

---

### 3. Redact existing plaintext secrets (one-time cleanup)

```bash
python3 ~/.hermes/skills/security/secret-guardian/scripts/redact_hermes.py \
  --secrets "sk-1234567890abcdef:***OPENAI_KEY_REDACTED***,r8_abcdef123456:***REPLICATE_KEY_REDACTED***"
```

Or use **audit mode** first to see exactly where your secrets are before touching anything:

```bash
python3 scripts/redact_hermes.py --audit \
  --secrets "sk-1234567890abcdef:***OPENAI_KEY_REDACTED***"
```

---

### 4. Done

From now on, whenever you share a key or credential with Hermes Agent, the skill:

1. Detects it automatically
2. Redacts it from all hermes storage files
3. Stores only a `***SERVICE_KEY_REDACTED***` placeholder in memory
4. Shows you only the last 4 characters when confirming receipt

---

## 📁 Repo Structure

```
secret-guardian/
├── SKILL.md                          # The Hermes Agent skill (what gets loaded)
├── scripts/
│   ├── redact_hermes.py              # Core redaction CLI tool
│   └── setup.sh                      # One-command installer
├── README.md                         # This file
├── LICENSE                           # MIT
└── .gitignore                        # Ignores SECRETS.md
```

---

## 🔧 CLI Reference

```bash
# Basic redaction
python3 redact_hermes.py --secrets "secret:placeholder"

# Multiple secrets
python3 redact_hermes.py \
  --secret "sk-ABC123:***OPENAI_REDACTED***" \
  --secret "r8_XYZ789:***REPLICATE_REDACTED***"

# Audit mode (find without modifying)
python3 redact_hermes.py --audit --secrets "sk-ABC123:***REDACTED***"

# Dry run
python3 redact_hermes.py --dry-run --secrets "sk-ABC123:***REDACTED***"

# Interactive entry
python3 redact_hermes.py --interactive

# Custom hermes directory
python3 redact_hermes.py --hermes-dir /path/to/.hermes --secrets "..."
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

**Fix:** Simply re-run the redaction script after a session reset.

---

## 🤝 Contributing

1. Fork the repo
2. Add your patterns or improvements to `SKILL.md` / `redact_hermes.py`
3. Test with `--dry-run` or `--audit` first
4. Submit a PR

---

## 📜 License

MIT — do whatever you want with it, but be kind and don't use it to harvest other people's secrets.
