# sourceorrery-provider

The bridge between the two shapes of the
[SourceOrrery](https://sourceorrery.ai) secret contract: `SecretClient`
(synchronous, the local encrypted vault) and `AsyncSecretClient`
(asynchronous, the remote providers). Both are defined in
[`sourceorrery-core`](https://crates.io/crates/sourceorrery-core); this
crate makes every backend serve both.

**You probably want another crate.** To read secrets from an application,
use [`sourceorrery`](https://crates.io/crates/sourceorrery), the read-only
client. To create vaults and store secrets, install the CLI:
`cargo install --locked sourceorrery-cli`.

## What is in it

* `Blocking<A>`: a `SecretClient` over any `AsyncSecretClient`, driven on a
  Tokio runtime the adapter owns (or a handle you give it). The CLI, the C
  ABI, every SDK and the conformance suite run unchanged against a remote
  provider through it.
* `AsyncLocal<C>`: an `AsyncSecretClient` over any `Send + Sync`
  `SecretClient`, each call run on Tokio's blocking pool, so async
  applications reach the local vault without blocking their executor.

Both adapters pass every operation and every error through untouched: the
error code an application sees is the backend's, whichever shape it called.
The remote providers themselves (HashiCorp Vault, AWS Secrets Manager,
Azure Key Vault) are the next items of
[milestone 4](https://github.com/Netizine/sourceorrery/blob/main/docs/roadmap.md).
