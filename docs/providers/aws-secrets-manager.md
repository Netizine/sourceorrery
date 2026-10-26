# AWS Secrets Manager

A vault's `aws-secrets-manager` [connection](index.md) keeps secrets under
one prefix in one region of
[AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/). The
crate is `sourceorrery-provider-aws`, on by default in the CLI, the
`sourceorrery` crate, the C ABI and every SDK (Cargo feature
`provider-aws`, part of `remote`).

```bash
sourceorrery vault create production --recovery-key-out production.recovery-key \
  --aws-secrets-manager eu-west-1 \
  --aws-secrets-manager-prefix myapp/ \
  --aws-secrets-manager-endpoint http://localhost:4566 \
  --aws-access-key-id AKIA... --aws-secret-access-key-file key.txt   # optional: store an access key
```

The prefix is optional: every secret name is placed under it. The endpoint
is optional too, for a private endpoint or an emulator (`https://`, or
`http://` for this machine). Without a stored access key the connection
uses the AWS default credential chain.

A prefix should end in a separator (`myapp/`): names never start with a
hyphen, but `myapp` alone would place `myapp` and `myapp-other` under one
roof.

## What the service's tags decide

A version's `enabled` flag, its time window and content type, and the
rotation state live in the secret's tags, which Secrets Manager does not
authenticate: an identity allowed `secretsmanager:TagResource` can
re-enable a disabled version, clear a window or mark a retired version as
a validated rotation candidate, and the client cannot tell. Treat
`TagResource` and `UntagResource` on these secrets as policy
administration; the local vault's tags and checkpoints have no
counterpart here ([threat model](../threat-model.md), known gap 14).
SourceOrrery's policy binds what SourceOrrery returns; an identity with
`secretsmanager:GetSecretValue` reads any version through AWS's own tools,
so deny it in IAM (or with tag-based conditions) where that matters.

### How a version is published

A new version is never current under a looser policy than it was written
with, and before it is current the old one is never under a looser policy
than it had ([ADR 0011](../adr/0011-provider-writes-fail-closed.md)):

1. The secret is described (its tags) and the request is checked:
   nothing is sent for tags, a content type or a value the service would
   refuse (below).
2. When the stricter of the old and new policy (disabled if either is,
   the later `not_before`, the earlier `expires_on`) is stricter than the
   old one, the secret is tagged with it.
3. `PutSecretValue` makes the new version current.
4. The tags reach the new properties: stale tags that are not policy are
   removed, every wanted tag is written, and stale policy tags are removed
   last, so the policy never passes below the new one.

A refused `PutSecretValue` puts the old policy back and returns the
refusal. A lost answer, or a failure in step 4, is `outcome_unknown`, with
the secret held at least as strict as asked. The SDK's automatic retries
are off (also over `AWS_MAX_ATTEMPTS` and a profile's `max_attempts`): a
request whose answer was lost is never sent again, so the refusal of a
repeat is never taken for a change that did not happen. `update_secret_properties`
runs step 4 alone. A new secret gets its value and tags in one
`CreateSecret`. Secrets Manager has no conditional write, so this holds
for one writer at a time per secret: two writers changing one secret's
policy at the same moment can see each other's tags until the last step
lands.

## Credentials

An access key stored in the connection is used when there is one.
Otherwise the official AWS SDK's default credential chain supplies the
credentials, in its usual order: the environment (`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`,
`AWS_SESSION_TOKEN`), the shared config and credentials files with
`AWS_PROFILE`, SSO, web identity (`AWS_WEB_IDENTITY_TOKEN_FILE` and
`AWS_ROLE_ARN`, the path GitHub Actions and Kubernetes use), the ECS task
role and the EC2 instance role. Credentials are resolved once when the
connection is first used: a process the chain finds nothing for fails there with
`unauthenticated`, before any request. Credentials the service rejects
(`UnrecognizedClientException`, an expired token) are `unauthenticated`
too; a policy that denies the call is `permission_denied`.

## Mapping

| SourceOrrery | Secrets Manager |
|--------------|-----------------|
| secret `name` | the secret `<prefix><name>` |
| version id | the `VersionId`. Versions this provider writes get a time-ordered 32-hex-digit id (the `ClientRequestToken`), so they sort without relying on timestamps; versions other tools wrote keep their ids and sort by creation time |
| newest version | the version staged `AWSCURRENT` |
| value | `SecretString` when the bytes are UTF-8 without NUL, `SecretBinary` otherwise. Nothing is wrapped around the value |
| `enabled`, `content_type`, `not_before`, `expires_on`, `updated_on` | tags `sourceorrery:disabled`, `sourceorrery:content_type`, `sourceorrery:not_before`, `sourceorrery:expires_on`, `sourceorrery:updated_on` on the **secret** |
| `tags` | every other tag of the secret, except AWS's own (`aws:`), which are left alone |
| `created_on` | the version's `CreatedDate` |
| `set_secret` | `CreateSecret` the first time; after that the tags narrowed to the stricter policy, `PutSecretValue`, then the tags (above). The options' properties become the secret's tags (user tags are replaced only when the options carry some) |
| `get_secret(name, None)` | `DescribeSecret` and `ListSecretVersionIds`, then the core's policy over the versions, then `GetSecretValue` by version id |
| `update_secret_properties` | `UntagResource` of stale tags that are not policy, `TagResource`, then `UntagResource` of stale policy tags; the newest version only (below) |
| `delete_secret` | `DeleteSecret` with a 30-day recovery window |
| `recover_deleted_secret` | `RestoreSecret` |
| `purge_deleted_secret` | `DeleteSecret` with `ForceDeleteWithoutRecovery` |
| `list_*` | `ListSecrets` filtered by the name prefix, planned deletions included, then `ListSecretVersionIds` per secret |
| `audit_events` | `unsupported`: AWS CloudTrail holds the trail |
| descriptor | `backend` `aws-secrets-manager`, `id` `<region>:<prefix>`, `created` unknown (shown as `-`), recovery `recoverable`, retention 30 days |

Every policy decision is made by the core from the properties above,
exactly as for a local vault.

## What differs from a local vault

* **Properties belong to the secret, not to a version.** Secrets Manager
  has no per-version metadata, so `enabled`, `content_type`, `not_before`
  and `expires_on` apply to every version at once: disabling the newest
  version disables the secret, with no fall-back to an older version, and
  a `set` with new options redefines the secret's properties. For that
  reason `update_secret_properties` accepts only the newest version and
  answers `unsupported` for any other, saying so. The lifecycle
  conformance suite runs without the `PerVersionProperties` capability
  (ADR 0008), skipping the one scenario that needs it; the provider's own
  test covers what happens instead.
* **No rotation workflow.** `sourceorrery secret rotate` needs a disabled
  candidate next to the enabled current version, which per-secret
  properties cannot hold; the provider reports no `PerVersionProperties`
  capability and the workflow answers `unsupported` before writing anything
  ([rotation](../rotation.md)). Secrets Manager's own rotation (Lambda
  rotation functions) is the mechanism there.
* **Tags are bounded, and checked first.** A secret carries at most 50
  tags (AWS's own `aws:` tags not counted), keys of 1 to 128 and values of
  at most 256 characters, made of letters, digits, spaces and
  `_ . : / = + - @` (AWS's tagging rules); the properties above take up to
  five of them, and a write counts every tag the secret holds at once while
  it runs. A key starting with `aws:` or `sourceorrery:` (in any case) is
  refused, as is a content type with another character (`text/plain;
  charset=utf-8`), since it is stored as a tag, and a value over 64 KiB.
  All of this is `invalid_argument` before any request that writes.
* **Unlabelled versions age out.** A version that is neither `AWSCURRENT`
  nor `AWSPREVIOUS` is deprecated; Secrets Manager keeps up to 100 of them
  and removes the oldest beyond that, after which the version is
  `version_not_found`.
* **Recovery is 30 days.** `delete_secret` schedules deletion with the
  longest window the service offers. `scheduled_purge_on` is AWS's recovery
  deadline. Permanent deletion is asynchronous and can happen later; a name
  is reusable after deletion completes, including after `purge_deleted_secret`. See
  [AWS's deletion semantics](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DeleteSecret.html).
* **The deletion start is unknown.** AWS returns the recovery deadline,
  not the original deletion-request time. The provider uses the Unix
  epoch (`1970-01-01T00:00:00Z`) as the unknown sentinel for `deleted_on`;
  consult CloudTrail for the actual request time. It does not subtract
  30 days, because another tool may have requested a shorter recovery window.
* **Timestamps come from the service** except `updated_on`, which the
  provider writes into a tag when it changes properties, and the unknown
  `deleted_on` sentinel above.
* **Listing costs one request per secret**, after the `ListSecrets` pages.
  The paged methods cut pages out of that listing.
* **Two audit trails.** The vault's own log records every call
  SourceOrrery makes at the connection, with its outcome and, for a
  change, the attempt recorded before it was sent
  ([providers](index.md#when-a-changes-result-is-not-known)):
  `sourceorrery audit` shows it and `audit export` sends it on, like any
  local event. The provider's own trail (below) records what it served,
  including to clients other than SourceOrrery. The provider client itself
  keeps no log (`audit_events` is `unsupported` on it).
* **Two writers can race.** Nothing locks a secret between the describe
  and the writes that follow it, and the service has no conditional write:
  the publication above holds for one writer at a time per secret.

## Audit trail

AWS CloudTrail holds the provider's trail, beside the vault's own log of
each call (above); `sourceorrery audit` prints this pointer for every
connection that stores a secret.
Secrets Manager's API calls are management events, recorded by default
with the identity the process authenticated as: a read is
`GetSecretValue` (preceded by `DescribeSecret` and `ListSecretVersionIds`
for the policy decision), a write `CreateSecret` or `PutSecretValue`,
property changes `TagResource` and `UntagResource`, soft delete
`DeleteSecret`, recovery `RestoreSecret`. One query shows SourceOrrery's
operations on the vault's prefix:

```sh
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=secretsmanager.amazonaws.com \
  --start-time 2026-10-01T00:00:00Z --query 'Events[].CloudTrailEvent' --output text \
  | jq -c 'select(.requestParameters.secretId | startswith("myapp/"))
           | {eventTime, eventName, who: .userIdentity.arn, secret: .requestParameters.secretId, errorCode}'
```

A CloudTrail Lake event data store, or a trail delivered to S3 and read by
a collector, gives the same records continuously; route them where
`sourceorrery audit export` from the local vaults goes
([enterprise.md](../enterprise.md#collecting-the-audit-trail)).

## Errors

| Situation | Code |
|-----------|------|
| the default chain finds no credentials; the service rejects them | `unauthenticated` |
| the policy denies the call (`AccessDeniedException`) | `permission_denied` |
| the service cannot be reached, times out, throttles or fails internally | `provider_unavailable` (transient) |
| a tag, content type or value the service would refuse (checked before any write) | `invalid_argument` |
| `InvalidRequestException`, `InvalidParameterException`, `LimitExceededException` and other rejections | `invalid_argument` with the service's message |
| a write's answer was lost, or the value was published and its tags were not all written | `outcome_unknown` ([providers](index.md#when-a-changes-result-is-not-known)) |
| a version that does not exist, or that was removed | `version_not_found` |

No error message repeats a value: the SDK's messages carry the service's
error code and text, which name secrets and parameters only.

## Testing

`cargo test -p sourceorrery-provider-aws` runs the mapping and error
classification tests. With `SOURCEORRERY_AWS_TEST_ENDPOINT` naming an
emulator (and `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` set to
anything), the `live` test runs the lifecycle conformance suite without
`PerVersionProperties`, one fresh prefix per scenario, plus the
per-secret behaviour above:

```bash
npm ci --ignore-scripts --prefix scripts/ci/lstk     # the pinned LocalStack CLI
# From the repository root, with LOCALSTACK_AUTH_TOKEN set:
scripts/ci/lstk/node_modules/.bin/lstk start
SOURCEORRERY_AWS_TEST_ENDPOINT=http://127.0.0.1:4566 AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
  cargo test -p sourceorrery-provider-aws --test live -- --show-output
```

The `provider-aws` CI job does the same against LocalStack, started by
lstk with the image pinned in `.lstk/config.toml` and the
`LOCALSTACK_AUTH_TOKEN` repository secret (a LocalStack CI auth token),
then writes secrets into a Secrets-Manager-backed vault with the CLI and
reads them back through the Rust and C conformance runners with the SDK
harness's `--remote` scenarios (without `--remote-per-version`). Pull
requests from forks do not receive the secret: their emulator tests are
skipped with a warning and run after merge.

LocalStack refuses `ListSecretVersionIds` for a secret scheduled for
deletion, which AWS allows, and gives version creation times in whole
seconds. The provider then falls back to the secret's own creation time,
so the two deletion tests compare everything except the times and report
the divergence as a workflow warning. Against an endpoint that lists those
versions, they compare the times too.
