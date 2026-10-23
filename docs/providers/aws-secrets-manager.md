# AWS Secrets Manager

`provider = "aws-secrets-manager"` serves the secrets under one prefix in
one region of [AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/)
as a SourceOrrery vault. The crate is `sourceorrery-provider-aws`, on by
default in the CLI, the `sourceorrery` crate, the C ABI and every SDK
(Cargo feature `provider-aws`, part of `remote`).

```toml
[vaults.production]
provider = "aws-secrets-manager"
region = "eu-west-1"
prefix = "myapp/"                          # optional: every secret name is placed under it
endpoint_url = "http://localhost:4566"     # optional: a private endpoint or an emulator
```

## Credentials

The manifest holds the region, prefix and endpoint only. The official AWS
SDK's default credential chain supplies the credentials, in its usual
order: the environment (`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`,
`AWS_SESSION_TOKEN`), the shared config and credentials files with
`AWS_PROFILE`, SSO, web identity (`AWS_WEB_IDENTITY_TOKEN_FILE` and
`AWS_ROLE_ARN`, the path GitHub Actions and Kubernetes use), the ECS task
role and the EC2 instance role. Credentials are resolved once when the
vault is opened: a process the chain finds nothing for fails there with
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
| `tags` | every other tag of the secret |
| `created_on` | the version's `CreatedDate` |
| `set_secret` | `CreateSecret` the first time, `PutSecretValue` after; the options' properties become the secret's tags (user tags are replaced only when the options carry some) |
| `get_secret(name, None)` | `DescribeSecret` and `ListSecretVersionIds`, then the core's policy over the versions, then `GetSecretValue` by version id |
| `update_secret_properties` | `TagResource` and `UntagResource` on the secret; the newest version only (below) |
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
* **Tags are bounded.** A secret carries at most 50 tags, keys of at most
  128 and values of at most 256 characters; the properties above take up to
  five of them. Secrets Manager rejects a `set` or `update` beyond that
  with `invalid_argument` and its own message.
* **Unlabelled versions age out.** A version that is neither `AWSCURRENT`
  nor `AWSPREVIOUS` is deprecated; Secrets Manager keeps up to 100 of them
  and removes the oldest beyond that, after which the version is
  `version_not_found`.
* **Recovery is 30 days.** `delete_secret` schedules deletion with the
  longest window the service offers; `scheduled_purge_on` is that date, and
  Secrets Manager really does purge the secret then. A name is reusable
  only after the purge, or at once after `purge_deleted_secret`.
* **Timestamps come from the service** except `updated_on`, which the
  provider writes into a tag when it changes properties.
* **Listing costs one request per secret**, after the `ListSecrets` pages.
  The paged methods cut pages out of that listing.
* **No audit log.** `audit_events` is `unsupported`; `sourceorrery audit`
  refuses a remote vault by name.
* **Two writers can race.** Nothing locks a secret between the describe
  and the write that follows it.

## Errors

| Situation | Code |
|-----------|------|
| the default chain finds no credentials; the service rejects them | `unauthenticated` |
| the policy denies the call (`AccessDeniedException`) | `permission_denied` |
| the service cannot be reached, times out, throttles or fails internally | `provider_unavailable` (transient) |
| `InvalidRequestException`, `InvalidParameterException`, `LimitExceededException` and other rejections | `invalid_argument` with the service's message |
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
pip install 'moto[server]' && moto_server -p 4566 &     # or: docker run -p 4566:5000 motoserver/moto
SOURCEORRERY_AWS_TEST_ENDPOINT=http://127.0.0.1:4566 AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
  cargo test -p sourceorrery-provider-aws --test live
```

The `provider-aws` CI job does the same against the `motoserver/moto`
container (the LocalStack image needs a licence token since its 2026
releases), then writes secrets into a Secrets-Manager-backed vault with
the CLI and
reads them back through the Rust and C conformance runners with the SDK
harness's `--remote` scenarios (without `--remote-per-version`).
