# sourceorrery-storage

The encrypted vault of [SourceOrrery](https://sourceorrery.ai): one SQLite
file per vault, its key protectors and the OS credential store. Secrets
belong to the runtime, not the repository.

**You probably want another crate.** To read secrets from an application,
use [`sourceorrery`](https://crates.io/crates/sourceorrery), the read-only
client. To create vaults and store secrets, install the CLI:
`cargo install --locked sourceorrery-cli`
([`sourceorrery-cli`](https://crates.io/crates/sourceorrery-cli)). This
crate is the storage backend both of them use.

## What is in it

* The `SecretClient` implementation over one SQLite file per vault
  (`<home>/vaults/<name>.sorvault`): every value encrypted on its own and
  bound to its vault, name and version; soft delete with retention and
  automatic purge.
* Integrity: every mutable row carries an HMAC under a key derived from the
  vault key, the audit log is a keyed hash chain, and every change records
  the row's new state in that chain, so an older copy of a row is refused.
* Key protectors: the OS credential store (Windows Credential Manager,
  macOS Keychain, Secret Service) and Argon2id passphrases, several per
  vault, each wrapping the same vault key.
* The vault registry: where vaults live (`SOURCEORRERY_HOME` or the
  platform data directory) and how they are opened.

The on-disk format is documented in full:
[vault format](https://sourceorrery.ai/reference/vault-format/).

## Features

`os-keyring` (default) enables the OS credential store. Without it
(`--no-default-features`) only passphrase protectors are available, and on
Linux the D-Bus headers are not needed.

## Stability

Pre-1.0. The SourceOrrery crates are released together with one version
number; this crate's API may change in any 0.x release. Vault files are
versioned separately: a newer file format is adopted only through
`sourceorrery vault migrate`.

## Licence

MIT or Apache-2.0, at your option. Source:
<https://github.com/Netizine/sourceorrery/tree/main/crates/sourceorrery-storage>.
