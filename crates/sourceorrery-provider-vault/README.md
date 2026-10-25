# sourceorrery-provider-vault

[HashiCorp Vault](https://developer.hashicorp.com/vault)'s KV version 2
secrets engine behind the [SourceOrrery](https://sourceorrery.ai) secret
contract: the same `get`, `set`, versions, policy, soft delete and recover
as a local vault, served by a Vault server.

**You probably want another crate.** A SourceOrrery vault keeps a
secret at a Vault server through a connection it holds, made with the CLI
(`sourceorrery setup`, or `vault create --hashicorp-vault ADDRESS`), and
applications read it through
[`sourceorrery`](https://crates.io/crates/sourceorrery) (feature
`provider-vault`, on by default) like any other secret; the manifest never
names the server.

Use the CLI to create vaults and set secret values; application SDKs are
read-only. See the [CLI installation guide](https://sourceorrery.ai/getting-started/#install).

The connection signs in with a token it stores, sealed in the vault, or
else as Vault's own tools do: `VAULT_TOKEN` (or `~/.vault-token`), an
AppRole (`VAULT_ROLE_ID`, `VAULT_SECRET_ID`), a JWT (`VAULT_AUTH_ROLE`,
`VAULT_JWT_FILE`) or the Kubernetes service account token
(`VAULT_AUTH_ROLE`), in that order.

The mapping of SourceOrrery semantics onto KV v2 (versions, per-version
properties in `custom_metadata`, soft delete as `delete`/`undelete`/
metadata deletion, the limits that follow) is documented in
the [provider guide](https://sourceorrery.ai/providers/hashicorp-vault/). The crate is a small
hand-written client over `reqwest` with `rustls`; no response body is ever
logged, and a secret value crosses it only as `SecretBytes`.

## Project setup options

1. **Option 1: Set up with the CLI.** Follow the [CLI installation guide](https://sourceorrery.ai/getting-started/#install),
   then create the vault and set its secret values in your own terminal.
2. **Option 2: Set up with an AI coding agent.** Run
   `sourceorrery init --integration all`, then ask your agent to set up
   SourceOrrery for the project without showing values. You keep vault
   keys and new values private. [The agent setup guide](https://sourceorrery.ai/guides/ai-agents/)
   works with an existing CLI installation.
