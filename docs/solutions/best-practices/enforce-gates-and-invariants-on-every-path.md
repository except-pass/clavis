---
title: Enforce a new access gate or state invariant on every path, not just the obvious one
date: 2026-07-07
category: best-practices
module: secret-locking
problem_type: best_practice
component: authentication
severity: high
applies_when:
  - Adding a permission, lock, visibility, or feature-flag gate that hides or protects a resource
  - Introducing a cross-field invariant such as "X is set if and only if Y is true"
  - Reviewing a change that gates reads or writes of sensitive data
tags: [access-control, invariants, code-review, defense-in-depth, secrets, go]
---

# Enforce a new access gate or state invariant on every path, not just the obvious one

## Context

Clavis added per-secret locking: a soft/advisory gate that lets a human lock
individual credentials before handing a vault to an autonomous agent. The
implementation gated the two obvious read paths — `get` and `show` — and shipped
with green unit and integration tests. A multi-persona code review then found
three places where the gate or its supporting invariant was silently *not*
maintained:

1. `search --reveal` printed a locked secret's plaintext value.
2. `edit` dumped a locked secret's values into `$EDITOR` (a read bypass) and let
   them be overwritten.
3. `rm` of the last locked secret left the shared lock password (`LockHash`) set
   with nothing locked, breaking the "password set iff something is locked"
   invariant and stranding the vault in a stuck "ghost password" state.

Each was individually small; together they defeated the feature's stated purpose
(an agent could read a "locked" secret through `search`/`edit`) and introduced a
real correctness bug. The lesson generalizes well beyond this feature.

## Guidance

When you add a gate over a resource, or an invariant over state, treat "which
code paths touch this" as a first-class part of the change — not an afterthought.

1. **Enumerate every path that exposes the guarded resource, then gate all of
   them.** For a read gate, that means every command/endpoint that can print,
   export, edit, or search the value — not only the canonical getter. A gate on
   2 of 4 read paths is not a gate.

2. **Maintain a cross-field invariant in the data-layer mutator, not at each call
   site.** If the feature establishes "field A is set iff condition B holds," put
   the enforcement inside the shared mutation method so *every* caller inherits
   it. Enforcing it only where you happen to be looking guarantees drift the day
   a different caller mutates the same state.

3. **Give an adversarial review pass one explicit job: find the un-gated path.**
   The paths you forget are exactly the ones your own tests won't cover, because
   you write tests for the paths you thought about. A reviewer prompted to hunt
   for the bypass finds them cheaply.

## Why This Matters

A protection is only as strong as its leakiest path. The vault's soft lock was
correct everywhere it was applied and worthless on the paths where it was
missing — and those gaps lived precisely where the author wasn't looking, so
they passed review-by-author and passed a green test suite. Invariants have the
same property: an "A iff B" rule enforced at three of four mutation sites is not
an invariant, it is a latent stuck state waiting for the fourth caller.

The cost asymmetry is stark: enumerating paths and centralizing the invariant is
minutes of work at authoring time; the missed path is a security leak or a
data-integrity bug found later (or never).

## When to Apply

- Adding any gate that hides or protects data: permissions, locks, visibility
  flags, feature flags controlling exposure.
- Introducing a "set iff" or "present iff" invariant across two or more fields.
- Reviewing a diff that adds such a gate — check the non-obvious exposure paths
  (search, export, edit, bulk, admin) and every mutator of the invariant's state.

## Examples

**Gate every read path (search, edit — not just get/show).** Before, the lock
check lived only in `get`/`show`. After, it guards each value-exposing path:

```go
// cmd/clavis/edit.go — refuse a locked secret (it revealed values to $EDITOR)
if s.Locked {
    return fmt.Errorf("secret %q is locked", name)
}

// cmd/clavis/search.go — don't match/reveal values of a locked secret;
// names and tags stay searchable (already visible via list)
if s.Locked {
    continue
}
```

**Maintain the invariant in the mutator, not the caller.** The rule is "the
shared lock password is set iff some secret is locked." `UnlockSecret` already
cleared it on the last unlock; `rm` did not. The fix lives in the data-layer
`Remove`, so *any* caller that deletes a secret keeps the invariant:

```go
// internal/vault/vault.go
func (v *Vault) Remove(name string) bool {
    for i, s := range v.Secrets {
        if s.Name == name {
            v.Secrets = append(v.Secrets[:i], v.Secrets[i+1:]...)
            // Removing the last locked secret would orphan the shared lock
            // password; keep IsLocked() consistent with AnyLocked().
            if !v.AnyLocked() {
                v.LockHash = ""
            }
            return true
        }
    }
    return false
}
```

**Test the forgotten paths explicitly.** Coverage followed the same blind spot as
the code, so the added tests target the previously un-gated paths: an integration
check that `search --reveal` prints nothing for a locked secret and `edit`
refuses it, plus a unit test that removing the last locked secret clears the
shared password.

## Related

- Design spec: `docs/superpowers/specs/2026-07-07-per-secret-locking-design.md`
- Implementation plan: `docs/plans/2026-07-07-001-feat-per-secret-locking-plan.md`
