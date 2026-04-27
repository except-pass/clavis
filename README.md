# Clavis

Encrypted secrets manager using [age](https://age-encryption.org/).  
Clavis stores secrets as tagged key-value bundles in a single encrypted vault.

## Motivation

Clavis is an **agent-first secrets manager**.

I built it because it felt clunky to give agents the right secrets at the right time with the right context. I wanted a command-line workflow where agents can safely discover, fetch, and use only what they need — while still honoring progressive disclosure.

With Clavis, secrets and usage context can live together (for example: `usage`, `notes`, `owner`, `rotation_policy`), so agents get not just a token, but the operational intent around it.

## Install

```bash
go install github.com/except-pass/clavis@latest
```

Or build from source:

```bash
go build -o clavis ./cmd/clavis/
```

## Quick Start

```bash
# Initialize vault + identity
clavis init

# Add a secret
clavis add prod/mydb host=db.example.com user=admin password=secret \
  --tag env:prod --tag service:mydb --tag type:database

# Get one value
clavis get prod/mydb.password

# List by tags
clavis list env:prod type:database
```

## Access Patterns (Human + Agent Friendly)

### 1) Discover first, then fetch

```bash
clavis tags
clavis list env:prod --tags
clavis show prod/mydb
clavis get prod/mydb.password
```

### 2) Shell export pattern (`$(...)`)

This is the common “prepend dollar-sign command substitution” pattern:

```bash
eval "$(clavis get prod/mydb)"
```

That expands exported environment variables from the secret bundle into your shell.

### 3) Structured output for automation

```bash
clavis get prod/mydb --format=json
clavis get prod/mydb --format=yaml
clavis get prod/mydb --format=docker
clavis get prod/mydb --format=files -o /run/secrets/
```

## Agent Usage Pattern

If you’re instructing an AI coding agent, this works well:

1. `clavis tags` to discover categories
2. `clavis list <tag filters> --tags` to narrow candidates
3. `clavis show <name>` to inspect available keys
4. `clavis get <name>.key` for single values
5. `clavis get <name> --format=json` when structured parsing is needed

You can also keep usage notes inside the secret itself (for example `notes`, `usage`, `owner`, `rotation_policy`) so agents read the operational context alongside credentials.

## Lockable Secrets (Human-in-the-loop protection)

Clavis supports per-secret lockability and vault lock/unlock flow:

```bash
# Mark a secret as lockable (toggle)
clavis lockable prod/high-risk/mysql

# Lock lockable secrets
clavis lock

# Unlock requires human password
clavis unlock
```

When locked, lockable secrets cannot be retrieved by `get`/`show` until unlocked.  
This is useful when agents can use Clavis for routine secrets, while sensitive secrets remain human-gated.

## Documentation

```bash
clavis --help          # command overview
clavis <cmd> --help    # command-specific help
clavis manual          # full manual + workflow patterns
```

## Files

```text
~/.secrets/
  vault.age       # encrypted vault
  identity.txt    # age private key (NEVER share)
```
