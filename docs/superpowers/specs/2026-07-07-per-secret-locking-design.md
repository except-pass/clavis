# Per-secret locking — design

**Date:** 2026-07-07
**Status:** Approved, ready for implementation
**Author:** brainstormed with Claude

## Motivation

Clavis is agent-first: you hand a vault to an autonomous agent so it can discover
and fetch the creds it needs. Sometimes you want to hand over the vault but keep a
few credentials out of reach — production database passwords, a payment key —
while the rest stay usable.

Today's lock is all-or-nothing: you mark secrets `lockable`, then a single
`clavis lock` freezes *all* lockable secrets at once behind one password, and
`clavis unlock` releases *all* of them. This design makes lock state **per-secret**:
lock and unlock individual credentials independently.

## Threat model (decided)

**Soft / advisory lock**, consistent with the existing implementation. The lock is a
bcrypt password check that the clavis CLI honors — it is *not* additional
cryptographic protection. The secret's value still sits in the vault, encrypted only
by the age identity. An agent that can run `clavis get` at all holds that identity and
could decrypt the vault file directly, bypassing the lock.

The lock therefore guards against **accidental and casual access by a well-behaved
agent**, not a determined adversary. Real cryptographic per-secret encryption is
explicitly out of scope (see below).

## Password model (decided)

**One shared lock password.** Set on the first lock (like today's vault password),
verified for every subsequent per-secret lock and unlock. The same password opens any
locked secret. The human holds it; the agent does not.

**Tradeoff:** simplicity over compartmentalization. Gains a dead-simple mental model
and a tiny diff. Costs the ability to guard different creds with different passwords.
If that's ever needed, the deferred "per-secret passwords" path covers it.

## Data model

`internal/secret/secret.go`:

- **Add `Locked bool`** (`json:"locked,omitempty"`) — the single source of truth for
  whether a secret is currently locked.
- **Remove `Lockable bool`** — the separate "eligible to be locked" flag goes away.
  You lock a secret directly; there is no pre-marking step.

`internal/vault/vault.go`:

- **Keep `LockHash string`** — the one shared password (bcrypt). Set on the first lock;
  cleared when the last locked secret is unlocked.
- `IsLocked()` stays as "does the vault have a lock password set" (i.e. `LockHash != ""`),
  used to decide whether to prompt-to-set vs verify.
- New helpers:
  - `LockSecret(name, password) error` — sets password on first use (validates confirm
    at the command layer), else verifies; sets `s.Locked = true`.
  - `UnlockSecret(name, password) error` — verifies password; sets `s.Locked = false`;
    if no secrets remain locked, clears `LockHash`.
  - `AnyLocked() bool` — true if any secret has `Locked == true`.

## Command surface

- `clavis lock <name>` — lock one secret. If the vault has no password yet, prompt for
  password + confirm and set it; otherwise verify against the existing hash. Error if
  the secret is already locked or not found.
- `clavis unlock <name>` — verify the password, unlock that one secret. Error if it is
  not locked or not found.
- `clavis lock --all` — lock every secret.
- `clavis lock --tag <k:v>` — lock every secret matching the tag. Primary agent-handoff
  ergonomic: `clavis lock --tag sensitive`.
- `clavis unlock --all` — unlock every locked secret with the password.
- `--password <pw>` flag stays on both `lock` and `unlock` for scripting (prompts if
  absent), matching today.
- **Remove `clavis lockable`** and its wiring.

`lock` / `unlock` now require exactly one of: a `<name>` argument, `--all`, or (for
`lock`) `--tag`. A bare `clavis lock` with no selector errors with a hint pointing at
`--all` / `<name>`. This is the one small breaking change versus v1.0.0.

`--all` and `--tag` are mutually exclusive and both are mutually exclusive with a
positional `<name>`.

## Enforcement (read paths)

- `cmd/clavis/get.go` and `cmd/clavis/show.go`: refuse a secret when `s.Locked` is true,
  returning `secret %q is locked`. This replaces today's compound
  `v.IsLocked() && s.Lockable` check with a simple `s.Locked`.
- `cmd/clavis/list.go`: show 🔒 (U+1F512) next to locked secrets; no icon otherwise.
  (Drop the 🔓 unlocked-padlock indicator — an absent icon already means "not locked",
  and the previous 🔓 only existed to distinguish lockable-but-unlocked from ordinary,
  a distinction this design removes.)

## Migration / backward compatibility

- **Bump `VaultVersion` to 3** in `internal/config/config.go` to mark the schema-semantics
  change.
- On load of a pre-v3 vault, for each secret set:
  `Locked = (vault had LockHash set) AND (old Lockable was true)`.
  So a vault that was globally locked comes back with exactly those secrets locked; an
  unlocked vault comes back with nothing locked. No data loss, no manual step. The old
  `lockable` JSON key is simply ignored on load once `Lockable` is removed; the migration
  reads it during the load step before it is dropped. (Implementation note: read the raw
  `lockable` value during version-3 migration, since the struct field no longer exists —
  a small `map[string]json.RawMessage` or transitional struct in the loader.)
- If a v2 vault had `LockHash` set but no secrets were `Lockable`, `LockHash` is cleared
  on migration (nothing is locked, so no shared password should linger).

## Agent-facing docs

Update `docs/AGENT_INSTRUCTIONS.md`:

- Remove the `clavis lockable <secret-name>` line.
- Replace the lock-protection section with per-secret semantics: `clavis lock <name>` /
  `clavis unlock <name>`, `--all` / `--tag` bulk forms.
- Keep the guidance: "If a secret is locked, stop and ask a human to unlock it."

Also update the README lock section and `clavis-completion.bash` (drop `lockable`, keep
`lock`/`unlock`, add `--all`/`--tag` completions).

## Testing

Unit — `internal/secret/secret_test.go`, `internal/vault/vault_test.go`:

- Lock one secret leaves the others readable.
- Unlock one secret; others stay in their prior state.
- Wrong password on lock/unlock is a no-op and returns an error.
- Unlocking the last locked secret clears `LockHash`.
- First lock sets `LockHash`; second lock with the same password succeeds; with a
  different password fails.
- Migration: a v2 vault with `LockHash` set and two `Lockable` secrets loads as v3 with
  exactly those two `Locked`; a v2 unlocked vault loads with nothing locked; a v2 vault
  with `LockHash` but no lockable secrets loads with `LockHash` cleared.

Integration — `scripts/integration-test.sh`:

- Lock A, confirm `get A` fails and `get B` works, unlock A, confirm both work.
- `lock --tag <k:v>` locks the tagged set; a non-tagged secret stays readable.
- `unlock --all` releases everything.

## Out of scope

- Real cryptographic per-secret encryption (locked value unreadable without the password).
- Per-secret passwords.
- Session tokens / time-based auto-unlock.
- Per-tier passwords (unlock a whole tag with a tier-specific password).
