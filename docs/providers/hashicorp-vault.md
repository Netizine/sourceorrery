# HashiCorp Vault

A vault's `hashicorp-vault` [connection](index.md) keeps secrets in a
[KV version 2](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2)
secrets engine of a Vault server. The crate is
`sourceorrery-provider-vault`, on by default in the CLI, the `sourceorrery`
crate, the C ABI and every SDK (Cargo feature `provider-vault`, part of
`remote`).

```bash
sourceorrery vault create production --recovery-key-out production.recovery-key \
  --hashicorp-vault https://vault.example.com:8200 \
  --hashicorp-vault-mount secret \
  --hashicorp-vault-namespace platform \
  --hashicorp-vault-token-file token.txt     # optional: store the token in the vault
```

The address is `https://`, or `http://` only for this machine, with no
user information; the mount is the KV v2 engine's path (default
`secret`); the namespace is Vault Enterprise's. Without a stored token the
connection signs in as the Vault CLI does (`VAULT_TOKEN`, `~/.vault-token`).

`VAULT_NAMESPACE` supplies the namespace when the connection has none, and
`VAULT_CACERT` a PEM root certificate for a private CA, trusted in addition
to the operating system's certificate store, which the server's certificate
is verified against otherwise. TLS verification is never disabled. The token travels with every request, so `http://` is
accepted only for `localhost`, `127.0.0.0/8` or `::1` (a dev server), no
redirect is ever followed (a 3xx answer is `provider_unavailable`), and a
proxy named by `HTTP_PROXY` / `HTTPS_PROXY` is honoured as the Vault CLI
honours it, except for a loopback address.

## What the server's metadata decides

SourceOrrery keeps a version's `enabled` flag, its time window, its
content type and tags, the deletion marker and the rotation state in the
secret's `custom_metadata`. Vault authenticates nothing there: whoever may
`update` or `patch` `<mount>/metadata/<name>` can re-enable a disabled
version, clear a window, undelete a secret or mark an old version as a
validated rotation candidate, and the client cannot tell. Grant those on
the `metadata` path as you would grant policy administration, and keep
them off the identities that only read (`read` on `data` and `metadata`).
SourceOrrery's policy binds what SourceOrrery returns; a client with its
own token reads any version its Vault policy allows. The local vault's
tags and checkpoints have no counterpart here; see the
[threat model](../threat-model.md), known gap 14.

A token that writes needs, on the mount's paths:

| Path | Capabilities |
|------|--------------|
| `<mount>/data/*` | `create`, `update`, `read` |
| `<mount>/metadata/*` | `create`, `update`, `patch`, `read`, `list`, `delete` |
| `<mount>/delete/*`, `<mount>/undelete/*` | `update` |

Without `patch`, a write whose properties are not the defaults, an update,
a delete and a recovery are refused with `permission_denied` before
anything changes; the message says that properties are written with
`patch`.

### How a version is published

A new version is never readable through SourceOrrery under a looser
policy than it was written with, whichever request fails and with any
number of SourceOrrery writers ([ADR 0011](../adr/0011-provider-writes-fail-closed.md)):

1. The metadata is read: the current version `N`.
2. When the properties asked for are not the defaults, this writer's
   **intent** for `N+1` is patched in: `sourceorrery.v<N+1>~<nonce>`, the
   same document a committed version has. (A new secret's metadata is
   created first, with a `POST` that sets only `max_versions: 0`.)
3. The data is written with `options.cas = N`: if another writer took
   `N+1` in between, nothing is written and the write is refused with
   `invalid_argument` ("another writer added version …"); the intent is
   removed.
4. One merge patch commits: `sourceorrery.v<N+1>` written (none at the
   defaults), the intent removed, and any intent for `N+1` an earlier
   attempt left removed.

A reader applies to a version its committed document restricted by every
intent for it: disabled if any is, the latest `not_before`, the earliest
`expires_on`. So between steps 3 and 4, and if step 4 never happens, the
version is held at least as restricted as asked. A lost answer in step 3
or a failed step 4 is `outcome_unknown`. Every change to `custom_metadata`
is a merge patch of its own keys, so writers never drop each other's.
Releases before 0.3.0 read committed documents only, and do not honour an
intent.

## Credentials

A token stored in the connection is used when there is one. Otherwise the
provider takes the first credential it finds, in this order:

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
| `enabled`, `content_type`, `tags`, `not_before`, `expires_on`, `updated_on` | one `custom_metadata` key per version, `sourceorrery.v<N>`, holding a compact JSON document; a version with default properties has none. While a version is being written, a writer's intent `sourceorrery.v<N>~<nonce>` restricts it (above). KV v2 has no per-version metadata of its own, and `custom_metadata` is the one thing that can change without a new version |
| `created_on` | the version's `created_time` |
| `set_secret` | metadata read; the intent patched in when a property is not the default; `POST data/<name>` with check-and-set (a new version); one patch that commits the properties (above) |
| `get_secret(name, None)` | metadata, then the core's policy picks the newest accessible live version, then `GET data/<name>?version=N` |
| `update_secret_properties` | one merge patch of the version's `sourceorrery.v<N>` key, its intents removed; never a new version |
| `delete_secret` | a `sourceorrery.deleted` marker (`deleted_on`, the versions) patched into `custom_metadata`, then `POST delete/<name>` for every live version |
| `recover_deleted_secret` | `POST undelete/<name>` for the marker's versions, then the marker patched away; either cut short leaves the secret deleted for SourceOrrery (`outcome_unknown`), and it can be recovered or purged |
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
  most 128 bytes with values of at most 512 bytes. A version's properties
  document (tags included) that exceeds it is refused by Vault, which the
  provider reports as `invalid_argument` with Vault's message, at the
  intent, before any data is written. An intent takes one key while a
  version is being written.
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
* **Two writers are told apart.** A data write uses Vault's
  check-and-set, so two writers never write the same version number; the
  one that loses is refused with `invalid_argument` and writes nothing.

`sourceorrery secret rotate` works against a Vault-backed vault like
against a local one: the candidate, its state and the grace period are
per-version properties in `custom_metadata` ([rotation](../rotation.md)).

## Audit trail

The Vault server's audit devices hold the trail; SourceOrrery writes no log
of its own for a provider's secrets, and `sourceorrery audit --vault <name>`
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
| the server cannot be reached, times out, or answers 5xx or 429; a reply cut off part way | `provider_unavailable` (transient) |
| a reply over 8 MiB, declared or not (read chunk by chunk and stopped there, never buffered whole) | `storage` |
| the mount is not a KV version 2 engine | `invalid_argument` at open |
| no such mount | `vault_not_found` at open |
| Vault rejects a write (a `custom_metadata` limit, a bad body) | `invalid_argument` with Vault's diagnostic |
| another writer wrote the same version number first (check-and-set) | `invalid_argument`; nothing was written |
| a write's answer was lost, or it was written and its properties could not be committed; a delete or recovery cut short | `outcome_unknown` ([providers](index.md#when-a-changes-result-is-not-known)) |

No error message repeats a response body; Vault's own `errors` strings
(`permission denied`, a limit that was hit) are the only server text that
appears, and they never hold a value.

## Testing

`cargo test -p sourceorrery-provider-vault` runs the mapping tests,
recorded-response tests of the status mapping against an in-process HTTP
server, and the publication tests (`tests/publication.rs`): a model of KV
v2 that fails, or applies and loses the answer to, each request of a
write, and interleaves two writers, checking after every request it
applies that no version is readable under a looser policy than asked. With `SOURCEORRERY_VAULT_TEST_ADDR` (and `VAULT_TOKEN`) naming a
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
