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

An adapter publishes a value so that, at every moment and under every
failure (a refused request, a lost answer, a concurrent reader), the policy
that applies to any version SourceOrrery returns is at least as
restrictive as both the policy before and the one asked for. Cleanup after
a failure is not relied on.

* **HashiCorp Vault** (policy per version). The adapter reads the
  metadata (current version `N`), writes the new version's properties for
  `N+1` into `custom_metadata` (an entry at its default is removed, so an
  earlier attempt's entry cannot apply to it), and only then writes the
  data with `options.cas = N`. A concurrent writer makes the data write
  fail rather than land as another number. Afterwards the adapter reads
  the metadata back; an entry that another writer changed in between is
  written again and the call returns `outcome_unknown`. A version that
  another client writes without an entry is enabled, as before:
  SourceOrrery's policy binds what SourceOrrery returns, not a client
  with its own Vault token.
* **AWS Secrets Manager** (policy per secret). For an existing secret the
  adapter first narrows the tags to the **meet** of the old and new
  policy: disabled if either is, the later `not_before`, the earlier
  `expires_on`. It then sends `PutSecretValue`, and finally writes the new
  policy and user tags. A failure before the value is sent puts the old
  tags back when the narrowing is known not to have applied; anything
  else leaves the secret at the meet, which restricts and never exposes,
  and returns `outcome_unknown` saying which step failed. A new secret
  gets its value and tags in one `CreateSecret`.
* **Azure Key Vault** sets a version's value, attributes and tags in one
  request: unchanged.

User tags, content types and their limits are validated before the first
request (B09 for AWS): nothing is sent for input the provider would
refuse after publication.

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
* An AWS write with a policy change makes up to three requests; the old
  current version is restricted for the moment between them when the new
  policy is stricter.
* Two SourceOrrery writers changing one Vault secret at the same moment
  can still see each other's properties for the short time before the
  read-back; the read-back turns that into an `outcome_unknown` instead of
  silence.

## Alternatives considered

* **Swap the two requests** (Vault metadata first, AWS tags first).
  Correct for a stricter new policy, wrong for a looser one (AWS: the old
  version would be loosened early), and silent about lost answers.
* **Keep the policy inside the Vault data** (one atomic write per
  version). Metadata listings would have to read values, and property
  updates still need `custom_metadata`.
* **Clean up after a failed second request.** The version is readable
  until the cleanup lands, and the cleanup can fail too.
* **A distributed transaction or a write-ahead log replayed on open.**
  The providers offer no transaction with SQLite, and replaying a change
  whose outcome is unknown could repeat it.
