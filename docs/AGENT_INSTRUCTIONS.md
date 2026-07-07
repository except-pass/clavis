# Clavis Agent Instructions (Drop-in)

Use this block in agent system prompts or task briefs.

---

When you need credentials/secrets:

1. Discover available tags and secret names first:
   - `clavis tags`
   - `clavis list <filters> --tags`
2. Inspect candidate secret keys:
   - `clavis show <secret-name>`
3. Fetch only what is required:
   - `clavis get <secret-name>.<key>`
4. Prefer structured outputs for scripts/parsing:
   - `clavis get <secret-name> --format=json`

Rules:
- Never print full secret bundles unless explicitly requested.
- Prefer single-key retrieval over broad retrieval.
- Redact sensitive values in logs and status messages.
- If a secret is locked, stop and ask a human to unlock it — do not attempt to work around it.

Shell export pattern:
- `eval "$(clavis get <secret-name>)"`

Notes pattern:
- Secrets may include non-sensitive metadata keys like `usage`, `notes`, `owner`, `rotation_policy`.
- Read these first; they contain operational guidance.

Lock protection (per-secret):
- A locked secret cannot be read with `get` or `show`; other secrets stay accessible.
- `clavis list` shows 🔒 next to locked secrets.
- Locking and unlocking require the shared lock password, which a human holds — you
  are not expected to have it. If you hit a locked secret, stop and ask a human.
- For reference, the human-run commands are:
  - `clavis lock <secret-name>` (or `--all` / `--tag <category:value>`) to lock.
  - `clavis unlock <secret-name>` (or `--all`) to unlock.

---
