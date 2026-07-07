# Concepts

Shared domain vocabulary for this project — entities, named processes, and status concepts with project-specific meaning. Seeded with core domain vocabulary, then accretes as ce-compound and ce-compound-refresh process learnings; direct edits are fine. Glossary only, not a spec or catch-all.

## Vault

The single encrypted store holding all of a user's secrets. There is one vault per identity, encrypted at rest with an age keypair; reading anything from it requires the age identity.

## Secret

A named bundle of key-value pairs plus tags and metadata, addressed by name (e.g. `prod/mysql`) and optionally by a single key within it (`prod/mysql.password`). A secret is the unit of storage, retrieval, and locking — not an individual value.

## Tag

A `category:value` label attached to a secret (e.g. `env:prod`). Tags drive filtering in list and search and bulk selection for locking; a secret may carry many, one value per category.

## Soft Lock

The lock mechanism: an advisory access gate, not additional cryptography. It is a password check the CLI honors before exposing a secret's value — the value itself stays protected only by the vault's age encryption. Anyone who can already decrypt the vault can bypass the lock, so it guards against routine and accidental access by a well-behaved caller, not a determined one.

*Avoid:* Lockable (see Flagged ambiguities).

Locking is per-secret and gated on every value-exposing read path, not only the primary getter.

## Locked

The status of a secret whose value the CLI refuses to reveal until it is unlocked. A locked secret still appears in listings (marked with a padlock) and remains discoverable by name and tag; only its values are withheld.

## Shared Lock Password

The one password that protects every locked secret in a vault. It is established when the first secret is locked, reused to lock or unlock any secret thereafter, and cleared once no secret remains locked — so a password is set exactly when something is locked.

## Flagged ambiguities

- *Lockable* was an earlier concept: a secret was first *marked lockable*, then a single global lock froze all lockable secrets at once. It has been retired in favor of per-secret **Locked** state — secrets are now locked directly, with no separate "lockable" marking step.
