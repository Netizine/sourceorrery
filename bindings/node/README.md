# @sourceorreryai/sdk

**Read secrets from [SourceOrrery](https://sourceorrery.ai) vaults in
Node.js, with TypeScript types included.** Secrets belong to the runtime,
not the repository.

```ts
import { SecretReader } from '@sourceorreryai/sdk';

using reader = new SecretReader('development');
using secret = reader.get('database-password');
connect({ password: secret.value.exposeText() });
// `using` closes the reader and zeroises the value at the end of the block
```

SourceOrrery replaces the plaintext `.env` file with an encrypted local
vault. This package is its read-only JavaScript and TypeScript SDK: it
opens a vault, reads the newest accessible version of a secret (or an
exact version), its properties and `sourceorrery://` references, and loads
every secret a project's `sourceorrery.toml` declares. It cannot create,
change or delete a secret: an application that only reads cannot be
tricked into writing.

Documentation: [the JavaScript guide](https://sourceorrery.ai/sdks/javascript/) ·
[Getting started](https://sourceorrery.ai/getting-started/) ·
[Threat model](https://sourceorrery.ai/security/threat-model/)

## Before you start: the CLI

This package only reads. Vaults are created, and secrets stored, with the
`sourceorrery` command-line tool, which npm does not install. Install it
once on the machine where you manage secrets, from the
[GitHub release](https://github.com/Netizine/sourceorrery/releases/latest)
(Windows, macOS and Linux, x64 and arm64) or with
`cargo install --locked sourceorrery-cli --version 0.1.4`
([step by step](https://sourceorrery.ai/getting-started/#install)), then:

```bash
sourceorrery vault create development
sourceorrery secret set database-password --vault development   # typed at a hidden prompt
```

The CLI does not have to be installed where your application runs: this
package opens the vault file itself.

## Install

```bash
npm install @sourceorreryai/sdk
```

A napi-rs native addon for Node.js 20+. The addon itself is in one
platform package per operating system and CPU, which this package lists
as optional dependencies; npm installs only the one that matches the
machine, so nothing is compiled on install:

| Platform package | For |
|------------------|-----|
| `@sourceorreryai/sdk-win32-x64-msvc` | Windows x64 |
| `@sourceorreryai/sdk-win32-arm64-msvc` | Windows on Arm (arm64) |
| `@sourceorreryai/sdk-darwin-x64` | macOS on Intel (x64) |
| `@sourceorreryai/sdk-darwin-arm64` | macOS on Apple silicon (arm64) |
| `@sourceorreryai/sdk-linux-x64-gnu` | Linux x64 (glibc) |
| `@sourceorreryai/sdk-linux-arm64-gnu` | Linux arm64 (glibc) |

Every package is published by trusted publishing with provenance;
`npm audit signatures` checks it
([Supply chain](https://sourceorrery.ai/security/supply-chain/)).

## Unlocking

`new SecretReader('development')` finds the vault under `SOURCEORRERY_HOME`
(or the platform data directory) and unlocks it like the CLI: the OS
credential store first, then `SOURCEORRERY_PASSPHRASE`, then the file named
by `SOURCEORRERY_PASSPHRASE_FILE`; never an interactive prompt. On servers,
in containers and in CI, give the vault a passphrase protector and pass the
passphrase as a file
([Headless](https://sourceorrery.ai/guides/headless/)).

A vault that the project's `sourceorrery.toml` declares in a
`[vaults.<name>]` table is remote: `SecretReader` opens it at its provider
instead of as a local file. Pass `{ manifest }` to name the manifest; the
default is the nearest `sourceorrery.toml` above the current directory.
Credentials come from the provider's own environment, never from the
manifest.

## Errors and values

Every failure is a `SourceOrreryError` subclass (`SecretNotFoundError`,
`VaultLockedError`, `SecretExpiredError`, …) with a stable `code` and a
`hint` that says what to do, such as the `sourceorrery secret set` command
that would store a missing secret. A value is a `SecretValue`: it prints
and serialises as `[REDACTED]`, hands out its bytes only through
`expose()` or `exposeText()`, and is zeroised by `close()` or at the end of
a `using` block.

## Building from source

From a clone of the repository, with Rust 1.88+, a C compiler and Node.js
20+. The tests read a vault that the CLI creates, so build that too; in
Bash (Git Bash on Windows):

```bash
cargo build --release -p sourceorrery-cli
eval "$(bash scripts/ci/fixture-vault.sh)"
cd bindings/node
npm ci
npm run build            # napi build --platform --release
npm test
```

Every step, with the prerequisites for each platform:
<https://sourceorrery.ai/sdks/javascript/#building-from-source>.

`npm run build` generates `index.js` (the loader) and `index.d.ts` next to
the addon; both are in `.gitignore` and both ship in the package. The
`npm/<platform>` directories are the platform packages' manifests: the
release workflow regenerates them with `npx napi create-npm-dirs` from the
stamped `package.json`, then `scripts/release/npm-platform-packages.py`
writes each one's README and description. In the repository
`package.json` depends on them as `file:npm/<platform>` links so that
`npm ci` resolves without the registry; the release stamps the version in
place of the links.

## Licence

MIT or Apache-2.0, at your option. Source:
<https://github.com/Netizine/sourceorrery/tree/main/bindings/node>.
