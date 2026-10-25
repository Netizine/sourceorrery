# Azure Key Vault

A vault's `azure-key-vault` [connection](index.md) keeps secrets in one
[Azure Key Vault](https://learn.microsoft.com/azure/key-vault/secrets/).
The crate is `sourceorrery-provider-azure`, on by default in the CLI, the
`sourceorrery` crate, the C ABI and every SDK (Cargo feature
`provider-azure`, part of `remote`).

```bash
sourceorrery vault create production --recovery-key-out production.recovery-key \
  --azure-key-vault https://myapp-kv.vault.azure.net \
  --azure-tenant-id TENANT --azure-client-id CLIENT --azure-client-secret-file secret.txt   # optional
```

The URL must use `https://`: Key Vault, and its emulator, speak TLS only
(another cloud's suffix, or an emulator's, works the same way). Key Vault
has no prefixes, so vaults that share a Key Vault share its names.

## Credentials

With a stored service principal (the three flags above) the connection
uses it. Otherwise the provider signs in with the first identity the
process's environment provides, through the official Azure SDK for
Rust:

1. a service principal: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and
   `AZURE_CLIENT_SECRET`;
2. workload identity federation: `AZURE_FEDERATED_TOKEN_FILE` with
   `AZURE_TENANT_ID` and `AZURE_CLIENT_ID` (the path AKS and a GitHub
   Actions OIDC token written to a file take);
3. the Azure CLI (`az login`), then the Azure Developer CLI;
4. a managed identity: App Service, Functions and Container Apps name their
   endpoint; on a virtual machine the instance metadata endpoint is used when
   it accepts a connection within a second. `AZURE_CLIENT_ID` names a
   user-assigned identity.

The developer tools come before the managed identity so a workstation never
waits on the metadata endpoint. `AZURE_AUTHORITY_HOST` names another cloud's
sign-in authority (or an emulator's). A token is fetched once when the vault
is opened, for the scope of the vault's cloud (`https://vault.azure.net/.default`
for `*.vault.azure.net`): a process with no identity fails there with
`unauthenticated`, before any request reaches the vault, and the message
lists why each source did not sign in.

The identity needs, on the vault, the role **Key Vault Secrets User** to
read and **Key Vault Secrets Officer** to write, delete, recover and purge;
for a vault that uses access policies, the matching secret permissions.
[enterprise.md](../enterprise.md) covers the workload identity set-up per
platform.

## Mapping

| SourceOrrery | Key Vault |
|--------------|-----------|
| secret `name` | the secret of the same name (the name rules are the same) |
| version id | the version id Key Vault assigns (32 hex digits) |
| `enabled`, `not_before`, `expires_on`, `content_type` | the version's own attributes `enabled`, `nbf`, `exp` and `contentType` |
| `tags` | the version's tags, except the reserved `sourceorrery:` ones |
| `created_on` | the reserved tag `sourceorrery:created_on`, written with the version at full precision; Key Vault's `created` (whole seconds) for versions other tools wrote |
| `updated_on` | the reserved tag `sourceorrery:updated_on` written by an update, or Key Vault's `updated` when another tool changed the version |
| value | the version's value when the bytes are UTF-8; otherwise base64, marked with the reserved tag `sourceorrery:encoding = base64` |
| newest version | the version with the latest `created_on` (then the higher id) |
| `set_secret` | `SetSecret`, with the options as the new version's attributes and tags |
| `get_secret(name, None)` | `GetSecretVersions`, then the core's policy over the versions, then `GetSecret` by version id |
| `update_secret_properties` | `UpdateSecret` on the chosen version |
| `delete_secret` | `DeleteSecret` (every vault has soft delete) |
| `recover_deleted_secret` | `RecoverDeletedSecret`, then a wait until the secret reads as live |
| `purge_deleted_secret` | `PurgeDeletedSecret` |
| `list_*` | `GetSecrets` or `GetDeletedSecrets`, then the versions (or the deleted secret) per name |
| `audit_events` | `unsupported`: Azure Monitor holds the trail |
| descriptor | `backend` `azure-key-vault`, `id` the vault URL, `created` unknown (shown as `-`), recovery `recoverable`, retention the vault's soft-delete days as a secret reports them (Key Vault's default of 90 when the vault holds no secret, or the identity cannot list them) |

Every policy decision is made by the core from the properties above,
exactly as for a local vault. Properties belong to one version, as in the
contract, so disabling the newest version falls back to the one before and
the rotation workflow works ([rotation](../rotation.md)); the lifecycle
conformance suite runs with `PerVersionProperties`.

## What differs from a local vault

* **A time window can be replaced but not removed.** Key Vault's
  `UpdateSecret` leaves an attribute it is not given unchanged and has no
  way to remove `nbf` or `exp`, so `update_secret_properties` with
  `not_before: Some(None)` or `expires_on: Some(None)` on a version that has
  one answers `unsupported`, saying so; write a new version without the
  window. The provider reports no `ClearableTimeWindow` capability and the
  conformance suite skips the scenario that needs it. A later expiry, or an
  earlier activation, replaces the old one as usual.
* **Values are text.** Bytes that are not UTF-8 are stored as base64, a
  third larger, which other tools see as such. Key Vault holds values of up
  to 25 KiB; a larger one is refused before anything is sent.
* **Tags are bounded.** A version carries at most 15 tags with values of
  at most 256 characters; SourceOrrery keeps three of them, so at most 12
  user tags can be given, and none under the `sourceorrery:` prefix. Beyond
  that a `set` or `update` is `invalid_argument` before any request.
* **Version order trusts a tag.** Key Vault's times are whole seconds, so
  versions written within one second are ordered by `sourceorrery:created_on`.
  An identity allowed to update a version's tags can reorder versions; in
  Key Vault that is the same permission as writing a new version
  (`secrets/set`), so it grants nothing that identity could not already do.
* **Recovery follows the vault.** Soft delete is always on in Key Vault;
  the retention (7 to 90 days) and purge protection are the vault's
  settings. `deleted_on` and `scheduled_purge_on` are Key Vault's own. With
  purge protection on, `purge_deleted_secret` is refused by the service.
* **Deletion, recovery and purge finish in the background.** A request that
  meets a secret still being deleted, recovered or purged is retried for up
  to a minute before it fails as `provider_unavailable`.
* **Listing costs one request per secret**, after the listing pages, because
  a listing names a secret but not its newest version. The paged methods cut
  pages out of that listing.
* **Two audit trails.** The vault's own log records every call
  SourceOrrery makes at the connection, with its outcome and, for a
  change, the attempt recorded before it was sent
  ([providers](index.md#when-a-changes-result-is-not-known)):
  `sourceorrery audit` shows it and `audit export` sends it on, like any
  local event. The provider's own trail (below) records what it served,
  including to clients other than SourceOrrery. The provider client itself
  keeps no log (`audit_events` is `unsupported` on it).
* **Two writers can race.** Nothing locks a secret between the version
  listing and the write that follows it.

## Audit trail

Azure Monitor holds the trail, once the vault has a diagnostic setting that
sends the `AuditEvent` category to a Log Analytics workspace; that is the
provider's trail, beside the vault's own log of each call (above), and
`sourceorrery audit` prints this pointer for every connection that stores a
secret. Every data-plane call is an event with the
identity that made it: a read is `SecretGet` (preceded by `SecretListVersions`
for the policy decision), a write `SecretSet`, property changes
`SecretUpdate`, soft delete `SecretDelete`, recovery `SecretRecover`, purge
`SecretPurge`. One query shows SourceOrrery's operations on the vault:

```sh
az monitor log-analytics query --workspace <workspace-id> --analytics-query \
  "AzureDiagnostics | where ResourceProvider == 'MICROSOFT.KEYVAULT' and Resource == 'MYAPP-KV'
   and OperationName startswith 'Secret'
   | project TimeGenerated, OperationName, id_s, identity_claim_appid_g, ResultSignature"
```

A data export rule or an Event Hub in the diagnostic setting gives the same
records continuously; route them where `sourceorrery audit export` from the
local vaults goes ([enterprise.md](../enterprise.md#collecting-the-audit-trail)).

## Errors

| Situation | Code |
|-----------|------|
| no identity signs in; the service rejects the token (401) | `unauthenticated` |
| the identity has no role or access policy for the operation (403) | `permission_denied` |
| a version disabled by another client between the listing and the read | `disabled` |
| the service cannot be reached, times out, throttles (429) or fails (5xx); a secret still being deleted, recovered or purged | `provider_unavailable` (transient) |
| a name that is soft-deleted (409) | `deleted_conflict` |
| `BadParameter` and other rejections (400) | `invalid_argument` with the service's message |
| a version that does not exist | `version_not_found` |

No error message repeats a value: messages carry Key Vault's error code and
text, which name secrets and versions only, and a response body is never
formatted.

## Testing

`cargo test -p sourceorrery-provider-azure` runs the mapping, credential and
error classification tests. With `SOURCEORRERY_AZURE_TEST_ENDPOINT` naming
an Azure emulator's management and sign-in endpoint, the `live` test creates
a vault per scenario through the emulator's Resource Manager and runs the
lifecycle conformance suite with `PerVersionProperties`, plus the
differences above. It does not run against Azure itself.

```bash
npm ci --ignore-scripts --prefix scripts/ci/lstk     # the pinned LocalStack CLI
# From the repository root, with a LocalStack for Azure token in LOCALSTACK_AUTH_TOKEN:
scripts/ci/lstk/node_modules/.bin/lstk --config .lstk/azure.toml start
export SOURCEORRERY_AZURE_TEST_ENDPOINT=https://azure.localhost.localstack.cloud:4567
export AZURE_AUTHORITY_HOST=$SOURCEORRERY_AZURE_TEST_ENDPOINT AZURE_TENANT_ID=00000000-0000-0000-0000-000000000000
export AZURE_CLIENT_ID=any-app AZURE_CLIENT_SECRET=emulator-placeholder
cargo test -p sourceorrery-provider-azure --test live
```

The emulator accepts any client and secret in its one tenant; `any-app` is
the principal its documentation uses and the one that may create vaults.
`.lstk/azure.toml` pins the image by digest (it publishes no version tags),
puts it on port 4567 and enforces role-based access, so a principal without
a role is refused as on Azure. The AWS and Azure emulators bind the same
ports and cannot run at once.

The `provider-azure` CI job does the same with the
`LOCALSTACK_AZURE_AUTH_TOKEN` repository secret (a LocalStack CI auth
token), then writes secrets into a Key-Vault-backed vault with the CLI and
reads them back through the Rust and C conformance runners with the SDK
harness's `--remote --remote-per-version` scenarios, and
`scripts/ci/azure-federation.sh` checks that a service principal from the
environment reads, a principal without a role is `permission_denied` and a
process with no identity is `unauthenticated`. The emulator does not
exchange federated tokens for a managed identity, so workload identity is
not exercised end to end. Pull requests from forks do not receive the
secret: their emulator tests are skipped with a warning and run after
merge.
