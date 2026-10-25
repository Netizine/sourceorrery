# @sourceorreryai/sdk-win32-arm64-msvc

The Windows on Arm (arm64) native addon of [`@sourceorreryai/sdk`](https://www.npmjs.com/package/@sourceorreryai/sdk),
the read-only JavaScript and TypeScript SDK for
[SourceOrrery](https://sourceorrery.ai) vaults. Secrets belong to the
runtime, not the repository.

**Do not install this package directly.** Install the SDK:

```bash
npm install @sourceorreryai/sdk
```

`@sourceorreryai/sdk` lists one platform package per operating system and CPU as an
optional dependency, and npm installs only the one that matches the
machine, so nothing is compiled on install. This package holds a single
file, `sourceorrery.win32-arm64-msvc.node`, compiled from the SourceOrrery Rust core by the release
workflow and published with provenance.

| Platform package | For |
|------------------|-----|
| `@sourceorreryai/sdk-darwin-arm64` | macOS on Apple silicon (arm64) |
| `@sourceorreryai/sdk-darwin-x64` | macOS on Intel (x64) |
| `@sourceorreryai/sdk-linux-arm64-gnu` | Linux arm64 (glibc) |
| `@sourceorreryai/sdk-linux-x64-gnu` | Linux x64 (glibc) |
| `@sourceorreryai/sdk-win32-arm64-msvc` | Windows on Arm (arm64) |
| `@sourceorreryai/sdk-win32-x64-msvc` | Windows x64 |

## The CLI

The SDK only reads secrets. Vaults are created, and secrets stored, with
the `sourceorrery` command-line tool, which npm does not install: get it
from the [GitHub release](https://github.com/Netizine/sourceorrery/releases/latest)
or with `cargo install --locked sourceorrery-cli --version 0.3.0`
([Getting started](https://sourceorrery.ai/getting-started/)). It does not
have to be installed where your application runs.

Documentation: <https://sourceorrery.ai/sdks/javascript/>. Source:
<https://github.com/Netizine/sourceorrery/tree/main/bindings/node>.
Licence: MIT or Apache-2.0, at your option.
