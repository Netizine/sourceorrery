# HashiCorp Vault

`provider = "hashicorp-vault"` serves a [KV version 2](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2)
secrets engine of a Vault server as a SourceOrrery vault. The crate is
`sourceorrery-provider-vault`, on by default in the CLI, the `sourceorrery`
crate, the C ABI and every SDK (Cargo feature `provider-vault`, part of
`remote`).

```toml
[vaults.production]
provider = "hashicorp-vault"
address = "https://vault.example.com:8200"   # http:// or https://, no user info
mount = "secret"                              # the KV v2 engine's mount path
namespace = "platform"                        # optional; Vault Enterprise
```

`VAULT_NAMESPACE` supplies the namespace when the table has none, and
`VAULT_CACERT` a PEM root certificate for a private CA. TLS verification is
never disabled.

## Credentials

The manifest holds the address only. The provider takes the first
credential it finds, in this order:

| Source | What it uses |
|--------|--------------|
| `VAULT_TOKEN` | the token |
| `~/.vault-token` | the token `vault login` stored |
| `VAULT_ROLE_ID` and `VAULT_SECRET_ID` | AppRole login at `auth/approle/login` |
| `VAULT_AUTH_ROLE` with `VAULT_JWT_FILE` or `VAULT_JWT` | JWT login at `auth/jwt/login` (OIDC and workload identity tokens) |
| `VAULT_AUTH_ROLE` in a pod | Kubernetes login at `auth/kubernetes/login` with the service account token at `/var/run/secrets/kubernetes.io/serviceaccount/token` |

`VAULT_AUTH_MOUNT` names the auth method's mount when it is not the
default. A login happens once, when the vault is opened; the token it
returns is used for the life of the client and is not renewed. No
credential found is `unauthenticated` before any request is made; a token
the server refuses is `unauthenticated` too (the provider asks
`auth/token/lookup-self` to tell it from a missing capability, which is
`permission_denied`).

## Mapping

| SourceOrrery | KV version 2 |
|--------------|--------------|
| secret `name` | path `<mount>/data/<name>`, directly under the mount (no folders) |
| version id | the KV version number, as a decimal string (`"1"`, `"2"`) |
| value | the `value` field of the KV data (`value_base64` when the bytes are not UTF-8). A secret written by other tools, with other fields, is read whole as the JSON object with content type `application/json` |
| `enabled`, `content_type`, `tags`, `not_before`, `expires_on`, `updated_on` | one `custom_metadata` key per version, `sourceorrery.v<N>`, holding a compact JSON document; a version with default properties has none. KV v2 has no per-version metadata of its own, and `custom_metadata` is the one thing that can change without a new version |
| `created_on` | the version's `created_time` |
| `set_secret` | `POST data/<name>` (a new version), then the properties into `custom_metadata` when any is not the default |
| `get_secret(name, None)` | metadata, then the core's policy picks the newest accessible live version, then `GET data/<name>?version=N` |
| `update_secret_properties` | metadata read-modify-write of the version's `sourceorrery.v<N>` key; never a new version |
| `delete_secret` | `POST delete/<name>` for every live version, plus a `sourceorrery.deleted` marker (`deleted_on`, the versions) in `custom_metadata` |
| `recover_deleted_secret` | `POST undelete/<name>` for the marker's versions, marker removed |
| `purge_deleted_secret` | `DELETE metadata/<name>`: every version and the metadata go |
| `list_*` | `LIST metadata/` then the metadata of each name (folders and names that are not secret names are skipped) |
| `audit_events` | `unsupported`: the Vault server's audit devices hold the trail |
| descriptor | `backend` `hashicorp-vault`, `id` the mount accessor, `created` unknown (shown as `-`), recovery `recoverable`, retention 90 days |

Every policy decision (`disabled`, `not_yet_valid`, `expired`, the newest
accessible version) is made by the core from the properties above, exactly
as for a local vault.

## What differs from a local vault

* **Version history is bounded by the mount.** KV v2 keeps `max_versions`
  versions per secret (10 unless the mount or the secret's metadata says
  otherwise) and destroys the oldest beyond that; a destroyed version is
  `version_not_found`. The provider never changes mount configuration. The
  conformance job configures its mounts with a higher limit.
* **Properties have a size limit.** `custom_metadata` allows 64 keys of at
  most 128 bytes with values of at most 512 bytes by default. A version's
  properties document (tags included) that exceeds it is refused by Vault,
  which the provider reports as `invalid_argument` with Vault's message.
* **Soft delete is a marker.** A version deleted with `vault kv delete`
  outside SourceOrrery is simply not live: it is skipped in listings and
  `version_not_found` when asked for. A secret is *deleted* in the
  SourceOrrery sense only through `delete_secret`, which marks it.
  `scheduled_purge_on` is informational (`deleted_on` + 90 days); Vault does
  not purge a deleted secret by itself.
* **Timestamps come from the server.** `created_on` is Vault's clock;
  `updated_on` of a changed version is the client's.
* **Listing costs one request per secret**, after one `LIST`. The paged
  methods cut pages out of that listing.
* **No audit log of SourceOrrery's own.** `audit_events` is `unsupported`;
  `sourceorrery audit --vault <name>` points at the server's audit devices
  (below) and `audit export` refuses.
* **Two writers can race.** Nothing locks a secret between the metadata
  read and the write that follows it; Vault's own check-and-set is not used.

`sourceorrery secret rotate` works against a Vault-backed vault like
against a local one: the candidate, its state and the grace period are
per-version properties in `custom_metadata` ([rotation](../rotation.md)).

## Audit trail

The Vault server's audit devices hold the trail; SourceOrrery writes no log
of its own for a remote vault, and `sourceorrery audit --vault <name>`
prints this pointer. With a file audit device enabled on the server (`vault
audit enable file file_path=/var/log/vault/audit.log`), every operation
SourceOrrery performs is a request against the mount, under the identity
the process logged in as: a read is `read` on `<mount>/data/<name>` (with
a `version` parameter when one was asked for), metadata and listings are
requests under `<mount>/metadata/`, a write is `update` on
`<mount>/data/<name>`, soft delete and recovery `update` on
`<mount>/delete/<name>` and `<mount>/undelete/<name>`, purge `delete` on
`<mount>/metadata/<name>`. One query shows them all (Vault hashes the
values in its audit log itself):

```sh
jq -c 'select(.type == "response" and (.request.path | startswith("secret/data/") or startswith("secret/metadata/")))
       | {time, op: .request.operation, path: .request.path, who: .auth.display_name, error}' /var/log/vault/audit.log
```

Route the device to the collector that receives `sourceorrery audit
export` from the local vaults, and the two trails meet there
([enterprise.md](../enterprise.md#collecting-the-audit-trail)).

## Errors

| Situation | Code |
|-----------|------|
| no credential in the environment; a token the server refuses | `unauthenticated` |
| the token lacks a capability on the path | `permission_denied` |
| the server cannot be reached, times out, or answers 5xx or 429 | `provider_unavailable` (transient) |
| the mount is not a KV version 2 engine | `invalid_argument` at open |
| no such mount | `vault_not_found` at open |
| Vault rejects a write (a `custom_metadata` limit, a bad body) | `invalid_argument` with Vault's diagnostic |

No error message repeats a response body; Vault's own `errors` strings
(`permission denied`, a limit that was hit) are the only server text that
appears, and they never hold a value.

## Testing

`cargo test -p sourceorrery-provider-vault` runs the mapping tests and
recorded-response tests of the status mapping against an in-process HTTP
server. With `SOURCEORRERY_VAULT_TEST_ADDR` (and `VAULT_TOKEN`) naming a
server, the `live` test runs the whole lifecycle conformance suite through
the `Blocking` adapter, one fresh KV v2 mount per scenario:

```bash
vault server -dev -dev-root-token-id=root &
SOURCEORRERY_VAULT_TEST_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root \
  cargo test -p sourceorrery-provider-vault --test live
```

The `provider-vault` CI job does the same against the `hashicorp/vault`
container, then writes secrets into a Vault-backed vault with the CLI and
reads them back through the Rust and C conformance runners with the SDK
harness's `--remote` scenarios.
