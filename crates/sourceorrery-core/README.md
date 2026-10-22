# sourceorrery-core

The contracts and semantics of [SourceOrrery](https://sourceorrery.ai), the
encrypted local secrets vault with an Azure Key Vault–style lifecycle.
Secrets belong to the runtime, not the repository.

**You probably want another crate.** To read secrets from an application,
use [`sourceorrery`](https://crates.io/crates/sourceorrery), the read-only
client. To create vaults and store secrets, install the CLI:
`cargo install --locked sourceorrery-cli`
([`sourceorrery-cli`](https://crates.io/crates/sourceorrery-cli)). This
crate is the shared foundation they are both built on.

## What is in it

* The `SecretClient` trait: set (always a new immutable version), get the
  newest accessible version or an exact one, metadata-only listing,
  property updates, soft delete, recover, purge and audit, with the
  semantics every backend must honour, including enforced `not_before` and
  `expires_on`.
* `SecretError` with stable, append-only error codes
  ([the list](https://sourceorrery.ai/reference/error-codes/)).
* `SecretBytes`, the only carrier of a secret value: zeroised on drop,
  redacted in `Debug`, with no `Serialize`.
* Secret and vault naming rules, `sourceorrery://` references, audit event
  types, and the `sourceorrery.toml` manifest, which cannot hold a value.

It contains no cryptography and no storage; those are
[`sourceorrery-crypto`](https://crates.io/crates/sourceorrery-crypto) and
[`sourceorrery-storage`](https://crates.io/crates/sourceorrery-storage).
How the crates fit together:
[architecture](https://sourceorrery.ai/architecture/).

## Stability

Pre-1.0. The SourceOrrery crates are released together with one version
number; this crate's API may change in any 0.x release. The error codes
are the stable part: they are never renamed or reused.

## Licence

MIT or Apache-2.0, at your option. Source:
<https://github.com/Netizine/sourceorrery/tree/main/crates/sourceorrery-core>.
