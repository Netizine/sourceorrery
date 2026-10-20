# JavaScript and TypeScript

```bash
npm install @sourceorrery/sdk
```

A napi-rs native addon for Node.js 20+ with TypeScript types included.
The main package pulls in one of `@sourceorrery/sdk-win32-x64-msvc`,
`-win32-arm64-msvc`, `-darwin-x64`, `-darwin-arm64`, `-linux-x64-gnu` or
`-linux-arm64-gnu` as an optional dependency; nothing is compiled on
install.

## Get a secret

```ts
import { SecretReader } from '@sourceorrery/sdk';

using reader = new SecretReader('development');
using secret = reader.get('database-password');
connect({ password: secret.value.exposeText() });
// `using` closes the reader and zeroises the value at the end of the block
```

`using` needs Node 24+ or TypeScript 5.2+ with a target that supports
explicit resource management; otherwise call `close()` in a `finally`:

```js
const { SecretReader } = require('@sourceorrery/sdk');

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
import { SecretReader, SecretNotFoundError, VaultLockedError, SourceOrreryError } from '@sourceorrery/sdk';

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
import { Project } from '@sourceorrery/sdk';

using project = Project.load('sourceorrery.toml');   // or Project.load() to discover it
for (const secret of project) process.env[secret.env] = secret.value.exposeText();
```

`Project.load` resolves every `[secrets.*]` entry the way `sourceorrery run`
does and throws the first required secret's error if one cannot be read.

## Building from source

```bash
cd bindings/node && npm ci && npm run build        # napi build --platform --release
eval "$(bash ../../scripts/ci/fixture-vault.sh)" && npm test && npm run typecheck
```

Source: [`bindings/node`](../../bindings/node/README.md).
