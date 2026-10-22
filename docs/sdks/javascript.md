# JavaScript and TypeScript

## Install

### From npm

```bash
npm install @sourceorreryai/sdk
```

[`@sourceorreryai/sdk` on npm](https://www.npmjs.com/package/@sourceorreryai/sdk)
is a napi-rs native addon for Node.js 20+ with TypeScript types included.
The main package pulls in the matching one of six platform packages
(`@sourceorreryai/sdk-<platform>` for Windows x64 and arm64, macOS x64 and
arm64, Linux glibc x64 and arm64) as an optional dependency, so nothing is
compiled on install. Every package is published by trusted publishing
with provenance, which `npm audit signatures` checks
([Supply chain](../supply-chain.md#npm)).

### From the GitHub release

The [v0.1.3 release](https://github.com/Netizine/sourceorrery/releases/tag/v0.1.3)
carries the same packages as tarballs: `sourceorreryai-sdk-0.1.3.tgz` is
the main package, and `sourceorreryai-sdk-<platform>-0.1.3.tgz` (one each
for `win32-x64-msvc`, `win32-arm64-msvc`, `darwin-x64`, `darwin-arm64`,
`linux-x64-gnu` and `linux-arm64-gnu`) carries the native addon for that
platform. Install the main tarball and your platform's together:

<!-- tabs: os -->

#### Windows

```powershell
npm install https://github.com/Netizine/sourceorrery/releases/download/v0.1.3/sourceorreryai-sdk-0.1.3.tgz https://github.com/Netizine/sourceorrery/releases/download/v0.1.3/sourceorreryai-sdk-win32-x64-msvc-0.1.3.tgz   # win32-arm64-msvc on Arm
```

#### macOS

```bash
npm install https://github.com/Netizine/sourceorrery/releases/download/v0.1.3/sourceorreryai-sdk-0.1.3.tgz https://github.com/Netizine/sourceorrery/releases/download/v0.1.3/sourceorreryai-sdk-darwin-arm64-0.1.3.tgz   # darwin-x64 on Intel
```

#### Linux

```bash
npm install https://github.com/Netizine/sourceorrery/releases/download/v0.1.3/sourceorreryai-sdk-0.1.3.tgz https://github.com/Netizine/sourceorrery/releases/download/v0.1.3/sourceorreryai-sdk-linux-x64-gnu-0.1.3.tgz   # linux-arm64-gnu on arm64
```

<!-- /tabs -->

### From source

See [Building from source](#building-from-source) below.

## Get a secret

```ts
import { SecretReader } from '@sourceorreryai/sdk';

using reader = new SecretReader('development');
using secret = reader.get('database-password');
connect({ password: secret.value.exposeText() });
// `using` closes the reader and zeroises the value at the end of the block
```

`using` needs Node 24+ or TypeScript 5.2+ with a target that supports
explicit resource management; otherwise call `close()` in a `finally`:

```js
const { SecretReader } = require('@sourceorreryai/sdk');

const reader = new SecretReader('development');
try {
  const secret = reader.get('database-password');
  try {
    connect({ password: secret.value.exposeText() });
  } finally {
    secret.close();
  }
} finally {
  reader.close();
}
```

`new SecretReader(vault, { home, passphrase, passphraseFile, environment })`
opens the vault; with no options it behaves like the CLI (`SOURCEORRERY_HOME`,
then the OS credential store, `SOURCEORRERY_PASSPHRASE`,
`SOURCEORRERY_PASSPHRASE_FILE`). `environment: false` ignores the two
passphrase variables.

| Call | Returns |
|------|---------|
| `reader.get(name)` | `Secret` for the newest accessible version |
| `reader.get(name, version)` | `Secret` for exactly that version |
| `reader.properties(name, version?)` | `SecretProperties` (policy not applied) |
| `reader.resolve('sourceorrery://development/database-password')` | `Secret` |
| `reader.descriptor()` | the vault descriptor (no values) |
| `reader.close()` | releases the vault; also `Symbol.dispose` |

`secret.properties` is a frozen object (`vault`, `name`, `version`,
`enabled`, `contentType`, `tags`, `notBefore`, `expiresOn`, `createdOn`,
`updatedOn` as `Date`, `recoveryLevel`, `reference`). `secret.value` is a
`SecretValue`:

```js
value.expose();       // Buffer (a copy)
value.exposeText();   // string
value.length;
value.close();        // zeroise; expose() throws afterwards
String(value);        // '[REDACTED]'
JSON.stringify({ value });   // '{"value":"[REDACTED]"}'
util.inspect(value);  // 'SecretValue([REDACTED])'
```

## Errors

Every failure is a `SourceOrreryError` subclass with `code`, `detail`,
`hint` and `message` (`detail` plus `hint`):

```ts
import { SecretReader, SecretNotFoundError, VaultLockedError, SourceOrreryError } from '@sourceorreryai/sdk';

try {
  using reader = new SecretReader('development');
  using secret = reader.get('database-password');
} catch (err) {
  if (err instanceof VaultLockedError) console.error(err.hint);
  else if (err instanceof SecretNotFoundError) console.error(err.hint);
  else if (err instanceof SourceOrreryError) console.error(err.code, err.message);
  else throw err;
}
```

Classes: `VaultNotFoundError`, `VaultLockedError`, `MigrationRequiredError`,
`SecretNotFoundError`, `VersionNotFoundError`, `SecretDeletedError`,
`PolicyError` with `SecretDisabledError`, `SecretNotYetValidError`
(`transient` is true), `SecretExpiredError`, `IntegrityError`,
`UnsupportedError`, `InvalidArgumentError`, `InvalidNameError`,
`ManifestError`, `PermissionDeniedError`, `StorageError`. See
[the SDK overview](index.md#errors).

## Load a project

```ts
import { Project } from '@sourceorreryai/sdk';

using project = Project.load('sourceorrery.toml');   // or Project.load() to discover it
for (const secret of project) process.env[secret.env] = secret.value.exposeText();
```

`Project.load` resolves every `[secrets.*]` entry the way `sourceorrery run`
does and throws the first required secret's error if one cannot be read.

## Building from source

You need Git, Rust 1.88 or newer installed with rustup, and a C compiler
(on Linux also `pkg-config` and `libdbus-1-dev`);
[Building from source](../building.md#what-you-need) has the commands for
each platform. For this SDK, also Node.js 20 or newer with npm.

Get the code and build the addon for this machine:

```bash
git clone https://github.com/Netizine/sourceorrery
cd sourceorrery
git checkout v0.1.3              # or stay on main for the newest changes
cd bindings/node
npm ci                           # the napi-rs CLI and TypeScript
npm run build                    # napi build --platform --release
```

`npm run build` compiles the addon as `sourceorrery.<platform>.node` (for
example `sourceorrery.linux-x64-gnu.node`) and generates the loader
`index.js` and the types `index.d.ts` next to it; the first build takes a
few minutes. To use it from your own project on the same machine, install
the directory:

```bash
cd /path/to/your-project
npm install /path/to/sourceorrery/bindings/node
```

npm links the directory rather than copying it, so a rebuild is picked up
without installing again. The version is the one committed in the
repository, not the release's.

To run the tests, the example and the conformance harness, build the CLI,
which creates the test vault, and run the rest in Bash (Git Bash on
Windows) from the repository root:

```bash
cargo build --release -p sourceorrery-cli
eval "$(bash scripts/ci/fixture-vault.sh)"       # a throwaway vault and the variables the tests read
cd bindings/node
npm test
npm run typecheck
node examples/get-secret.mjs "$SOURCEORRERY_TEST_VAULT" database-password
cd ../..
python tests/conformance/sdk/harness.py --runner node
```

What the fixture script creates: [The SDK test vault](../building.md#the-sdk-test-vault).
Source: [`bindings/node`](../../bindings/node/README.md).
