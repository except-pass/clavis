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
- If a secret is lockable+locked, stop and ask for human unlock.

Shell export pattern:
- `eval "$(clavis get <secret-name>)"`

Notes pattern:
- Secrets may include non-sensitive metadata keys like `usage`, `notes`, `owner`, `rotation_policy`.
- Read these first; they contain operational guidance.

Lock protection:
- `clavis lockable <secret-name>` toggles lockable mode.
- `clavis lock` blocks access to lockable secrets.
- `clavis unlock` requires human password.

---
