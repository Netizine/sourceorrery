# sourceorrery-crypto

The cryptography wrappers of [SourceOrrery](https://sourceorrery.ai), the
encrypted local secrets vault. Secrets belong to the runtime, not the
repository.

**You probably want another crate.** To read secrets from an application,
use [`sourceorrery`](https://crates.io/crates/sourceorrery), the read-only
client. To create vaults and store secrets, install the CLI:
`cargo install --locked sourceorrery-cli`
([`sourceorrery-cli`](https://crates.io/crates/sourceorrery-cli)). This
crate is an internal building block of both.

## What is in it

No algorithm is implemented here. The crate wraps RustCrypto primitives
behind the narrow API the vault needs, with key and plaintext buffers
zeroised when dropped:

| Purpose | Primitive | Crate |
|---------|-----------|-------|
| Value and key encryption, with additional authenticated data | XChaCha20-Poly1305, random 24-byte nonce | `chacha20poly1305` |
| Password to key | Argon2id, caller-owned working memory that is zeroised; parameters read from a vault are capped | `argon2` |
| Envelope key wrapping | XChaCha20-Poly1305 under a key-encryption key | `chacha20poly1305` |
| Sub-keys and integrity tags | HKDF-SHA256, HMAC-SHA256 | `hkdf`, `hmac`, `sha2` |
| Randomness | the OS CSPRNG | `getrandom` |

How the vault uses them:
[vault format](https://sourceorrery.ai/reference/vault-format/).

## Stability

Pre-1.0. The SourceOrrery crates are released together with one version
number; this crate's API may change in any 0.x release.

## Licence

MIT or Apache-2.0, at your option. Source:
<https://github.com/Netizine/sourceorrery/tree/main/crates/sourceorrery-crypto>.
