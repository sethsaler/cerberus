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

Run the redaction script against all hermes storage locations:

```bash
python3 scripts/redact_hermes.py --secrets "key1:value1,key2:value2,..."
```

Known secrets can be found in `~/.hermes/skills/security/cerberus/SECRETS.md` (gitignored). The script replaces each plaintext value with `***{TYPE}_REDACTED***`.

**Never leave the plaintext value in any file.**

### Step 3 — Memory Only

Save the credential to **agent memory only** (using the `memory` tool under `target=memory`). Do NOT save to skill files, config files, session transcripts, or any disk location.

If the user says "I need you to remember this key for later use":
1. Confirm the key was received
2. Immediately redact from wherever it was shared
3. Store label + `***REDACTED***` placeholder in memory (not the real value)

### Step 4 — Warn on Risky Patterns

If the user pastes a raw key into chat without any context or warning, respond with:

> "I see you've shared an API key. I'll redact it from disk immediately and only store it in encrypted memory. For future use, you can share it via a secrets manager or direct file — just say the word and I'll handle it securely without it touching session history."

### Step 5 — Never Log or Print Keys

- When acknowledging receipt of a key, print only the **last 4 characters** (e.g., `...xyz1`)
- Never echo back the full value
- Never include keys in tool call arguments that appear in logs

---

## Secrets Inventory

Add new secrets here as they are discovered. The inventory lives in `SECRETS.md` (gitignored).

| Service | Redacted Form | Added |
|---------|---------------|-------|
| *(none yet — add your own)* | | |

---

## Pitfalls

- **Do NOT** write plaintext keys to skill SKILL.md files — use `***REDACTED***` placeholders
- **Do NOT** include keys in terminal command history — use env vars or prompt for them at runtime
- **Do NOT** save keys to `.env` files in project repos — use `~/.env` outside of version control
- If a skill needs a key at runtime, accept it as a parameter, not as a stored value
- The agent's own memory is encrypted by the platform — keys stored there are safe; session/transcript files need manual redaction
