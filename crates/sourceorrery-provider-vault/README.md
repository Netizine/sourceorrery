# sourceorrery-provider-vault

[HashiCorp Vault](https://developer.hashicorp.com/vault)'s KV version 2
secrets engine behind the [SourceOrrery](https://sourceorrery.ai) secret
contract: the same `get`, `set`, versions, policy, soft delete and recover
as a local vault, served by a Vault server.

**You probably want another crate.** Applications read secrets through
[`sourceorrery`](https://crates.io/crates/sourceorrery) (feature
`provider-vault`, on by default) and name the Vault server in
`sourceorrery.toml`:

```toml
[vaults.production]
provider = "hashicorp-vault"
address = "https://vault.example.com:8200"
mount = "secret"
```

Credentials never live in the manifest: the provider takes `VAULT_TOKEN`
(or `~/.vault-token`), an AppRole (`VAULT_ROLE_ID`, `VAULT_SECRET_ID`), a
JWT (`VAULT_AUTH_ROLE`, `VAULT_JWT_FILE`) or the Kubernetes service account
token (`VAULT_AUTH_ROLE`), in that order.

The mapping of SourceOrrery semantics onto KV v2 (versions, per-version
properties in `custom_metadata`, soft delete as `delete`/`undelete`/
metadata deletion, the limits that follow) is documented in
`docs/providers/hashicorp-vault.md` of the repository. The crate is a small
hand-written client over `reqwest` with `rustls`; no response body is ever
logged, and a secret value crosses it only as `SecretBytes`.
