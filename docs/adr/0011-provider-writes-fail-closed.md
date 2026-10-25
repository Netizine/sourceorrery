# ADR 0011: Provider writes fail closed, and say when they may have happened

**Status:** accepted · **Date:** 2026-10-25 · **Changes:** ADR 0008 (how a
provider adapter publishes a value with its policy) and ADR 0009 (what the
router records about a call at a connection)

## Context

The security review of 2026-10-25 found two problems at the boundary
between a vault and the providers its connections reach.

**SR02.** A new version with a restrictive policy (disabled, not yet
valid, expired) is published before its policy:

* **HashiCorp Vault** keeps the policy per version in the secret's
  `custom_metadata`, and a version without an entry there is enabled with
  no time window. The adapter writes the data, then the metadata. If the
  second request fails, or while it is in flight, the new version is
  readable. The review reproduced it with a loopback fake Vault.
* **AWS Secrets Manager** keeps the policy in the secret's tags, which
  apply to every version. For an existing secret the adapter sends
  `PutSecretValue`, then the tags. A failed tag write leaves the new
  current version under the old policy.

**SR03**, its second half. B06 made the vault check itself before every
call at a connection. A call that was sent is still recorded only
afterwards, and when recording fails (the vault was blocked in between,
the disk is full), or the provider's answer is lost, the caller gets an
error that reads as if nothing happened, although the provider may have
acted. A local SQLite transaction cannot undo a remote change.

## Decision

### 1. Every outcome of a call at a connection is one of three

| Outcome | When | Recorded as | Returned |
|---|---|---|---|
| refused | the vault's gate refused it (B06), or the provider answered with a definite refusal (`invalid_argument`, `not_found`, `deleted_conflict`, `permission_denied`, `unauthenticated`, `unsupported`, …) | `failure` or `denied`, as now | that error |
| done | the provider answered with success and the vault recorded it | `success`, as now | the value |
| **unknown** | the provider may have acted: its answer was lost or it failed in a way that does not prove nothing happened (`provider_unavailable` on a change), an adapter knows it acted in part, or the provider acted but the vault could not record it | **`unknown`** when the vault can still write; otherwise only the attempt below stays | **`outcome_unknown`**, a new error code |

Reads are not changes: a read whose answer is lost is simply an error, and
a value read but not recorded is not returned.

### 2. A change at a connection is recorded before it is sent

Before a change (set, update, delete, recover, purge) is sent, once the
vault's gate has passed (B06) and the connection's client is open, the
router records the **attempt**: an event of the change's operation with
the new outcome **`pending`** and the detail `at connection <id>: sent`,
committed before the provider is called. The event that records the
result names it: `at connection <id>[: <code>] (attempt <event id>)`, with
`success`, `failure`, `denied` or `unknown`. An attempt is **unresolved**
while nothing but an `unknown` completes it (the answer was lost, the
process stopped, or the vault could not record the answer), until a later
change of the same secret through the same connection succeeds
(`forget_missing` included): that change was made after the secret was
looked at again. `SqliteVault::unresolved_attempts` lists them, and
`sourceorrery audit` names them with what to do.

Nothing is retried automatically. The procedure for an unresolved attempt
or an `outcome_unknown` (`docs/providers/index.md`):

| Change | Safe to repeat? | Check first |
|---|---|---|
| `secret set` | yes: at worst a second version | `secret versions NAME` |
| `secret update` | yes: it sets the same properties | `secret get NAME` (metadata) |
| `secret delete` | check: a second delete is refused | `secret list --deleted` |
| `secret recover` | check: a second recover is refused | `secret get NAME` |
| `secret purge` | check: the catalog may still list it | `Routed::missing` / `forget_missing` |

A pending attempt stays in the log for good, like every event: the log
records that the vault did not learn the result, never a result it does
not know.

### 3. Publishing a value never makes a restricted version readable

**The invariant.** At every moment, after any failure (a refused request,
a lost answer, a process that stops between two requests), and with any
number of SourceOrrery writers on HashiCorp Vault, the policy a
SourceOrrery reader applies to a version is at least as restrictive as
the one its writer asked for: disabled if it asked for disabled, a
`not_before` no earlier and an `expires_on` no later. Nothing relies on a
cleanup after a failure; whatever a failure leaves behind only restricts.
"Reader" means every SourceOrrery read, metadata-only ones included
(properties, version lists, listings) as well as value reads with or
without an explicit version.

The policy binds what SourceOrrery returns. A client with its own Vault
token or AWS credentials reads any version regardless; against those the
control is the provider's own: a Vault ACL policy on `<mount>/data/*`, an
IAM policy (or tag-based ABAC) on `secretsmanager:GetSecretValue`.

**HashiCorp Vault** keeps the policy per version in `custom_metadata`.

* *Representation.* A version's **committed** properties are the document
  `sourceorrery.v<N>`, as before (one an earlier release wrote is a
  committed one). An **intent** `sourceorrery.v<N>~<nonce>` (16 random hex
  digits) is what one writer asked for version `N` before `N` existed. A
  reader applies to version `N` its committed document, or the defaults
  without one, **restricted by every intent for `N`**: disabled if any is,
  the latest `not_before`, the earliest `expires_on`; the content type, the
  tags and `updated_on` come from the committed document, or else from the
  first intent in key order. A version with neither, written by another
  client, is enabled with no window, as before. Releases before this one
  apply committed documents only.
* *Writes.* Every change to `custom_metadata` is a JSON merge patch of the
  keys it concerns (`PATCH <mount>/metadata/<name>`, which needs the
  `patch` capability), so two writers never drop each other's keys. A new
  secret's metadata is first created by a `POST` that sets only
  `max_versions: 0` and leaves `custom_metadata` alone. (Verified against
  Vault 2.2.1: a merge patch with `null` removes a key, a patch of missing
  metadata is 404, a `POST` without `custom_metadata` keeps it, and a data
  write whose `cas` is not the current version is refused with 400.)
* *`set_secret`.* Read the metadata (current version `N`). When the
  properties asked for are not the defaults, patch an intent for `N+1`.
  Write the data with `options.cas = N`. Then one patch commits: the
  committed document for `N+1` (none at the defaults), this writer's intent
  removed, and every intent for `N+1` that the first read found removed
  (left by an attempt that stopped; any writer still in flight for `N+1`
  has lost its check-and-set). With default properties and nothing to
  remove, the write is the only change, as before.
* *Failures of `set_secret`.* Refused before the data write, or the data
  write refused (another writer took `N+1`: Vault's check-and-set answers
  400): nothing was written; the intent is removed if one was patched, and
  the refusal is returned (`invalid_argument` for the check-and-set,
  naming the other writer). The data write's answer lost: the intent stays,
  which binds `N+1` if the write landed, and the result is
  `outcome_unknown`. The commit failed: the version exists, held by its
  intent at least as restrictive as asked, and the result is
  `outcome_unknown`. A leftover intent restricts the version it names once
  someone writes it, until a later `set_secret` of that version commits or
  `update_secret_properties` of it decides.
* *`update_secret_properties`* is one patch: the version's committed
  document, and its intents removed; the owner's explicit decision
  supersedes them.
* *Delete* patches the deletion marker in first, then asks KV's delete;
  *recover* asks KV's undelete first, then patches the marker away. A
  failure of the second step leaves the marker, so SourceOrrery still
  treats the secret as deleted and it can be recovered or purged; the
  result is `outcome_unknown`.
* *Limits.* Vault's `custom_metadata` limits (64 keys, 512 bytes a value)
  count an intent too; an intent that does not fit is refused before any
  data is written.

**AWS Secrets Manager** keeps the policy per secret, in tags that apply to
every version (`Capability::PerVersionProperties` is not claimed).

* *Policy tags* are `sourceorrery:disabled`, `sourceorrery:not_before` and
  `sourceorrery:expires_on`; the content type, `updated_on` and user tags
  are the others. `TagResource` adds or overwrites keys; `UntagResource`
  removes them.
* *`set_secret` of an existing secret.* Describe it (the old policy and
  tags) and validate the request (B09). When the **meet** of the old and
  new policy (disabled if either is, the later `not_before`, the earlier
  `expires_on`) is stricter than the old, tag the secret with the meet's
  policy tags: only additions and overwrites. Then `PutSecretValue`. Then
  the target, in an order that never loosens below it: remove stale
  non-policy tags, tag every wanted tag, remove stale policy tags last.
  The new version is never current under a policy looser than the target,
  and the old one is never under a policy looser than the meet until the
  new one is current; afterwards the policy of the secret is the new one,
  for every version, as the contract for per-secret properties says.
* *`update_secret_properties`* runs the same three target steps. (They
  replace an order that removed stale tags first and could loosen the
  policy for a moment: from disabled to a future `not_before`, the secret
  was enabled with no window in between.)
* *Failures.* The narrowing refused: nothing changed, the refusal is
  returned. Its answer lost: no value was sent, the policy may be narrowed,
  `outcome_unknown`. `PutSecretValue` refused: the narrowing is undone (old
  values tagged back, keys the meet added removed) and the refusal
  returned, or `outcome_unknown` when the undo fails. `PutSecretValue`'s
  answer lost, or any target step failing: `outcome_unknown`, with the
  secret held at least as strict as asked. A new secret gets its value and
  tags in one `CreateSecret`.
* *Concurrent writers.* Secrets Manager has no conditional write for tags
  or `PutSecretValue`. Two SourceOrrery writers changing one secret at the
  same moment can interleave their tag steps, and a version can be under
  the other writer's policy until the last step lands. The invariant holds
  on AWS for one writer at a time per secret; a policy that must hold
  against concurrent writers or other clients belongs in IAM.

**Azure Key Vault** sets a version's value, attributes and tags in one
request: unchanged, and the invariant holds as it is.

Input a provider would refuse after publication is refused before the
first request: user tags, content types and the provider's limits (B09 for
AWS, the existing checks for Azure, Vault's own limits at the intent).

### 4. Error code `outcome_unknown`

`SecretError::OutcomeUnknown { at, reason }`, code `outcome_unknown`,
appended (codes are append-only). `at` names the connection, or the
provider when an adapter reports it. Not transient: a blind retry is the
wrong reaction. `SecretError::is_refusal` is the list of codes that show a
provider made no change, and `SecretError::after_change_sent` turns any
other failure of a sent change into `outcome_unknown`; an adapter that
sends more than one request for a change returns a refusal only while it
has changed nothing.

The Rust client's `ErrorKind` names it, as it names `rotation`. No SDK and
no C ABI function changes a secret (ADR 0005), so none can meet it: the
bindings type the codes a read returns, and report any other, this one
included, as their base error with the code kept. `CONTRACT_VERSION` stays
`"2"`: no existing scenario changes its outcome.

## Consequences

* `AuditOutcome` gains `pending` and `unknown` (appended). They are part of
  the audit row as any outcome is; schema 5 is unreleased, so no format
  change follows.
* A change at a connection writes two audit events instead of one.
* A Vault write with properties that are not the defaults makes four
  requests instead of three (read, intent, data, commit), and needs the
  `patch` capability on `<mount>/metadata/*`; a token without it is
  refused with `permission_denied` before any data is written.
* An AWS write with a policy change makes up to five requests; the old
  current version is restricted for the moment between them when the new
  policy is stricter.
* On AWS, the invariant needs one writer at a time per secret (above).

## Alternatives considered

* **Swap the two requests** (Vault metadata first, AWS tags first).
  Correct for a stricter new policy, wrong for a looser one (AWS: the old
  version would be loosened early), and silent about lost answers.
* **Vault: write the committed document for `N+1` before the data,
  replacing the whole `custom_metadata` map.** Correct for one writer, but
  a second writer's read-modify-write of the map (a property update of
  another version, a deletion marker, its own pre-write) can drop the
  entry, and the version is then enabled when its data lands. Per-writer
  intents patched key by key cannot be dropped that way.
* **Vault: treat a version without properties as disabled.** Fails closed
  without intents, but every version another client writes would become
  unreadable through SourceOrrery.
* **Keep the policy inside the Vault data** (one atomic write per
  version). Metadata listings would have to read values, and property
  updates still need `custom_metadata`.
* **Clean up after a failed second request.** The version is readable
  until the cleanup lands, and the cleanup can fail too.
* **A distributed transaction or a write-ahead log replayed on open.**
  The providers offer no transaction with SQLite, and replaying a change
  whose outcome is unknown could repeat it.
