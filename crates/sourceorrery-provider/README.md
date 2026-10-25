# sourceorrery-provider

The bridge between the two shapes of the
[SourceOrrery](https://sourceorrery.ai) secret contract: `SecretClient`
(synchronous, the local encrypted vault) and `AsyncSecretClient`
(asynchronous, the remote providers). Both are defined in
[`sourceorrery-core`](https://crates.io/crates/sourceorrery-core); this
crate makes every backend serve both.

**You probably want another crate.** To read secrets from an application,
use [`sourceorrery`](https://crates.io/crates/sourceorrery), the read-only
client. Use the separately installed CLI to create vaults and set secret
values: [CLI installation guide](https://sourceorrery.ai/getting-started/#install).

## Project setup options

1. **Option 1: Set up with the CLI.** Follow the [CLI installation guide](https://sourceorrery.ai/getting-started/#install),
   then create the vault and set its secret values in your own terminal.
2. **Option 2: Set up with an AI coding agent.** Run
   `sourceorrery init --integration all`, then ask your agent to set up
   SourceOrrery for the project without showing values. You keep vault
   keys and new values private. [The agent setup guide](https://sourceorrery.ai/guides/ai-agents/)
   works with an existing CLI installation.

## What is in it

* `Blocking<A>`: a `SecretClient` over any `AsyncSecretClient`, driven on a
  Tokio runtime the adapter owns (or a handle you give it). The CLI, the C
  ABI, every SDK and the conformance suite run unchanged against a remote
  provider through it.
* `AsyncLocal<C>`: an `AsyncSecretClient` over any `Send + Sync`
  `SecretClient`, each call run on Tokio's blocking pool, so async
  applications reach the local vault without blocking their executor.

* `open_connection`: opens the provider a connection reaches (its
  `ConnectionSettings` from `sourceorrery-core`, with its stored
  `Credentials` or else the provider's own credential chain), wrapping it
  in `Blocking`.
* `Routed`: a `SecretClient` over a local vault and the providers its
  connections reach. Each call goes to where the secret is kept; what a
  provider did is recorded in the vault's audit log and the vault's
  catalog follows.

Both adapters pass every operation and every error through untouched: the
error code an application sees is the backend's, whichever shape it called.
HashiCorp Vault, AWS Secrets Manager and Azure Key Vault are implemented
providers. Their mappings and capability limits are documented in the
[provider guides](https://sourceorrery.ai/providers/).
