# sourceorrery-storage

The encrypted vault of [SourceOrrery](https://sourceorrery.ai): one SQLite
file per vault, the keys that open it and the OS credential store.
Secrets belong to the runtime, not the repository.

**You probably want another crate.** To read secrets from an application,
use [`sourceorrery`](https://crates.io/crates/sourceorrery), the read-only
client. Use the separately installed CLI to create vaults and set secret
values: [CLI installation guide](https://sourceorrery.ai/getting-started/#install). This
crate is the storage backend both of them use.

## Project setup options

1. **Option 1: Set up with the CLI.** Follow the [CLI installation guide](https://sourceorrery.ai/getting-started/#install),
   then create the vault and set its secret values in your own terminal.
2. **Option 2: Set up with an AI coding agent.** Run
   `sourceorrery init --integration all`, then ask your agent to set up
   SourceOrrery for the project without showing values. You keep vault
   keys and new values private. [The agent setup guide](https://sourceorrery.ai/guides/ai-agents/)
   works with an existing CLI installation.

## What is in it

* The `SecretClient` implementation over one SQLite file per vault
  (`<home>/vaults/<name>.sorvault`): every value encrypted on its own and
  bound to its vault, name and version; soft delete with retention and
  automatic purge.
* Integrity: every mutable row carries an HMAC under a key derived from the
  vault key, the audit log is a keyed hash chain, and every change records
  the row's new state in that chain, so an older copy of a row is refused.
* The keys that open a vault, each wrapping the same vault key: this
  machine's key in the OS credential store (Windows Credential Manager,
  macOS Keychain, Secret Service) and one recovery key, shown once.
* The view check (an optional password with an authenticator on top),
  the vault's connections to providers with their credentials sealed
  under the vault key, the catalog of secrets a connection stores, and
  the project folders built from the vault; export and import of a whole
  vault.
* The vault registry: where vaults live (`SOURCEORRERY_HOME` or the
  platform data directory) and how they are opened.

The on-disk format is documented in full:
[vault format](https://sourceorrery.ai/reference/vault-format/).

## Features

`os-keyring` (default) enables the OS credential store. Without it
(`--no-default-features`) vaults open with their recovery keys only, and on
Linux the D-Bus headers are not needed.

## Stability

Pre-1.0. The SourceOrrery crates are released together with one version
number; this crate's API may change in any 0.x release. Vault files are
versioned separately: a file from an earlier format is refused with
`migration_required`, never rewritten.

## Licence

MIT or Apache-2.0, at your option. Source:
<https://github.com/Netizine/sourceorrery/tree/main/crates/sourceorrery-storage>.
