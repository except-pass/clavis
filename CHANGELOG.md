# Changelog

## v2.0.0 (unreleased)

### Breaking changes

Per-secret locking replaces the previous all-or-nothing vault lock. Because the CLI
surface and the on-disk vault format changed, this is a major version bump.

- **`clavis lockable` is removed.** You no longer mark a secret as "lockable" and then
  lock the whole set. Lock secrets directly instead.
- **`clavis lock` / `clavis unlock` now require a selector.** The bare, global forms
  are gone. Use one of:
  - `clavis lock <name>` / `clavis unlock <name>` — a single secret.
  - `clavis lock --all` / `clavis unlock --all` — every secret.
  - `clavis lock --tag <category:value>` — every secret matching a tag.
- **Vault format is now version 3.** Existing vaults migrate automatically on first
  load: a secret is locked if the old vault had a lock password *and* the secret was
  marked lockable. No manual step is needed. The upgrade is one-way — an older (v2)
  `clavis` binary will not understand a v3 vault, so upgrade all machines that share a
  vault together.

### Added

- Per-secret lock state: lock and unlock individual credentials independently behind one
  shared password (set on the first lock, cleared when the last secret is unlocked).
- `clavis list` shows 🔒 next to locked secrets.
- The lock is now enforced on every read path that would expose a value — `get`, `show`,
  `search --reveal`, and `edit` all refuse a locked secret.

### Notes

The lock is a convenience guardrail, not additional cryptography: secret values are
protected by the vault's age encryption, and the lock stops routine CLI access to a
locked secret rather than someone who can already decrypt the vault.
