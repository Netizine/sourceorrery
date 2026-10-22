# @sourceorreryai/sdk

Read secrets from a [SourceOrrery](https://sourceorrery.ai) vault from
Node.js, with TypeScript types included. Secrets belong to the runtime, not
the repository.

```ts
import { SecretReader } from '@sourceorreryai/sdk';

using reader = new SecretReader('development');
using secret = reader.get('database-password');
connect({ password: secret.value.exposeText() });
```

The package only reads. The vault is unlocked the way the `sourceorrery`
CLI unlocks it: OS credential store first, then `SOURCEORRERY_PASSPHRASE`,
then `SOURCEORRERY_PASSPHRASE_FILE`. Every failure is a typed error with a
stable `code` and a `hint` that says what to do.

Documentation: <https://sourceorrery.ai/sdks/javascript/>. Source:
`bindings/node` in the repository. Native builds are published for Windows
(x64, arm64), macOS (x64, arm64) and Linux glibc (x64, arm64).

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
`npm/<platform>` directories are the platform packages' manifests
(`npx napi create-npm-dirs` regenerates them from `package.json`), and
`package.json` depends on them as `file:npm/<platform>` links so that
`npm ci` resolves without the platform packages being on the registry.
The release workflow stamps the version in place of the links.
