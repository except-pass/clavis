# Recipient-scoped managed vaults

Managed snapshots give each machine an encrypted local copy of only the bundles
approved for it. Normal `clavis get NAME.key` uses local files, including when the
publisher, network, or controller is unavailable. There are no leases, expiration
checks, network reads, or downstream credential tests. Delivery is eventual;
external providers can reject an old credential until the next successful sync.

## Files and local reads

Run all target commands as the account that normally runs Clavis. Paths use that
account's home:

```text
~/.secrets/
  vault.age                 # optional, existing user-managed vault
  identity.txt              # optional, existing user identity
  identity.txt.pub
  managed/                  # 0700
    identity.txt            # 0600, machine-local private identity
    identity.txt.pub        # 0600, public recipient
    vault.age               # 0600, complete managed snapshot
    .lock                   # serializes key creation and installation
```

`get`, `list`, `show`, `search`, and `tags` combine the two local vaults. A user
bundle wins a collision **as a whole**; missing user keys do not fall through to
the managed bundle, and locked user bundles stay locked. `list` adds
`[managed shadowed by user]` to a name with an underlying managed bundle. Filters
apply to the winning bundle's tags. A machine with only a managed snapshot needs
neither `clavis init` nor a user identity/vault.

All existing bundle write commands continue to address only the user vault:
add, set, rm, edit, tag, lock, unlock, and migration do not write the managed
snapshot. Generic file encryption/decryption commands keep their existing
explicit input/output path behavior. A same-name local addition can intentionally shadow
managed data; removing it exposes the managed bundle again. No command saves a
merged view back to either file. Managed is a CLI ownership convention, not an
OS security boundary against someone acting as the owning account.

## Machine identity and inventory approval

On an existing target, through the established authenticated SSH transport:

```sh
clavis managed keygen
```

Stdout contains only one public `age1...` recipient and a newline. Repeated or
concurrent invocations reuse the identity. The public file can be reconstructed
from the private identity. A malformed existing identity is never overwritten;
a missing identity with an existing managed vault requires explicit recovery.
The private identity never leaves the target, and must never be copied from the
publisher or another machine.

Bind the public recipient to the authoritative inventory host identity using
trusted SSH and ordinary inventory/review policy. A worker's requested names are
inputs to approval, not approval themselves. The delivery layer must intersect
requests with explicit host/group permissions and report rejected requests.
Clavis export accepts the resulting **approved** names; it does not implement
inventory membership or an authorization service. Replacing a machine identity
requires verifying the replacement through that same trusted transport.

## Controller export contract

On the trusted publisher, create a names file containing one exact approved
bundle name per line. Blank lines are ignored; duplicates are removed; there is
no comment syntax. Export selects complete bundles, including their metadata and
all keys, rather than individual keys. The publisher reads only its ordinary
user vault, never its own managed overlay.

```sh
clavis export --recipient /protected/path/machine-recipient.pub \
  --names-file /protected/path/approved.names \
  --out /protected/path/snapshot.age
```

`--recipient` also accepts the public `age1...` string directly. Recipient files
must contain exactly one X25519 public recipient, optionally with surrounding
whitespace. No private key or secret value belongs in command arguments.

Any missing or locked name refuses the **entire** export, reports the affected
names/reasons, and leaves an existing output untouched. Legacy vault lock state
is migrated in memory before selection. No lock hash or publisher identity is
included. The publisher must unlock selected locked bundles through the existing
human-controlled flow before a later export; export has no bypass option.

Output is age ciphertext for exactly that recipient. Export writes a 0600 file
using a temporary file in the destination directory, fsync, and atomic rename.
The parent directory must exist; use a protected staging directory. Stdout is
one JSON object (also used by target verification and installation):

```json
{"count":2,"names":["example/one","example/two"],"fingerprint":"64 lowercase hexadecimal characters"}
```

The fingerprint is an HMAC-SHA256 over the sorted selected content and recipient,
keyed by the publisher identity with a managed-snapshot domain separator. It is
stable across repeated exports even though age ciphertext is randomized. Value
changes are detected even if modification timestamps were not updated. Unrelated
source changes do not affect it; changes to included metadata, recipient, or
publisher identity do. A keyed fingerprint avoids publishing a guessable hash of
low-entropy secret values. It is a generation identifier, not a timestamp or
freshness rule. Targets cannot recompute the publisher's HMAC.

## Verify, install, retry, and withdraw

Copy ciphertext using existing authenticated SSH delivery to a protected staging
file owned by the target Clavis account. Use restrictive permissions on staging
files as well. Then run as that account:

```sh
clavis managed verify /protected/path/staged.age
clavis managed install /protected/path/staged.age
```

`verify` can be used as an Ansible copy `validate:` command such as
`clavis managed verify %s`; it decrypts, authenticates, checks the target recipient
and snapshot schema, and changes no managed files. `install` independently
validates the exact bytes it commits; it does not trust an earlier verification.
Wrong-recipient, truncated, malformed, locked, duplicate-name, and unsupported
version snapshots are refused. Reports and diagnostics contain no values/private
keys. Keep automation's credential-bearing task output protected with its normal
`no_log` conventions; never display decrypted payloads or raw private files.

Installation serializes concurrent writers. Readers see one complete file via
atomic rename. Until that rename, the active file is the last-good snapshot;
interruption or validation failure leaves it intact. A successful install of the
same content/fingerprint leaves the active file unchanged. Repeated delivery is
safe. A filesystem error after rename may report failure even though the complete
new file is visible; retrying reconciles it. Protect the directory itself and use
a local filesystem with atomic rename and fsync support.

Snapshots are complete replacements. After withdrawing approval, exporting the
reduced names file and successfully installing removes those managed bundles.
An **empty** names file exports a valid empty snapshot to withdraw everything.
Unrelated user secrets are preserved. Successful installs retain no historical
`.previous` archive that would keep withdrawn credentials around. Remove staging
and export-cache files using the delivery layer's normal cleanup, including
failed/interrupted staging remnants; they may contain old encrypted values.

Withdrawal removes the managed copy at the next successful sync. It cannot
revoke an already disclosed value, erase backups/copies elsewhere, or override a
user-owned colliding bundle. Revoke/rotate the actual credential at its upstream
provider separately when required. A rotated value can fail normally at that
provider while an offline target waits for synchronization.

The delivery layer should compare fingerprint reports, record host, requested and
approved counts, delivered fingerprint, last success, and errors, and retry
offline/failed targets in its existing reconciliation cycle. Never replace a
working local snapshot with an empty or partial file to represent failure. There
is no anti-rollback counter or distributed ordering guarantee: overlapping runs
can deliver an older complete snapshot last; the next reconciliation converges.
The orchestrator should serialize reconciliations for a host when ordering is
needed. No daemon or new coordinating service is required.

## Recovery and proof checklist

Back up the encrypted source vault and its publisher identity through existing
protected backup conventions. Store the decryption authority separately from the
ciphertext with access limited to authorized controllers/operators. Encrypted
source backup alone is insufficient for recovery. A second **existing authorized
controller** can restore the source vault and identity into its protected Clavis
account, restore/reuse authoritative inventory and SSH authority, verify target
public recipients through trusted SSH, and run the same export/delivery workflow.
Using the same source identity preserves fingerprints. Never distribute that
source identity to workers. Targets keep using their local copies throughout the
controller outage and recovery; ordinary credential reads need no controller.

If a target loses its private managed identity, restore a protected machine-local
backup according to existing policy, or explicitly remove its unusable managed
vault and identity and regenerate locally, then approve the new public recipient
through trusted inventory policy and deliver a new snapshot. Do not silently
rekey a deployed target, or restore another target's identity onto it.

Before deployment, run fixture tests with `go test ./...` and
`go test -race ./...`. They cover two-recipient isolation, unknown/locked names
(including legacy lock migration), no management-output value/key leakage,
managed-only reads, shadowing and user locks, rotation without timestamp changes,
last-good offline use, retry, complete/empty revocation, user-data preservation,
concurrent writers/readers, and killing a writer after fsync before rename.

Then use an already existing small authorized host subset: record public
recipients, deliver different approved selections, confirm rejection of an
unapproved request, rotate a fixture/approved source, temporarily make a target
unreachable for delivery, retry, and withdraw approval. Confirm local `get`
while controller transport is unavailable using output redirected into the
intended consumer; never include values in proof logs. Compare only the safe
JSON reports. Fleet-wide convergence and PR merge follow the owner's explicit
approval and existing deployment/review controls. Clavis fixture tests do not
claim that this live-host proof has run.
