# Converting JavaScript and TypeScript code

SDK: `npm install @sourceorreryai/sdk` (Node.js 20+, a native addon with
TypeScript types; prebuilt for Windows, macOS and Linux glibc, x64 and
arm64). The supported runtime is Node.js. Browser bundles must not contain
secrets. Edge and managed runtimes use their platform's secret store;
`sourceorrery run --` can wrap a local process, not a remotely hosted
runtime or browser. Keep those deployment boundaries intact.

## One module for every read

```ts
// src/secrets.ts
import { Project } from '@sourceorreryai/sdk';

const project = Project.load(); // nearest sourceorrery.toml, unlocked like the CLI

/** The value delivered as environment variable `name`. */
export function secret(name: string): string {
  const value = project.env(name);
  if (!value) throw new Error(`${name} is not available from sourceorrery.toml`);
  return value.exposeText();
}

export function optionalSecret(name: string, fallback?: string): string | undefined {
  return project.env(name)?.exposeText() ?? fallback;
}
```

CommonJS: `const { Project } = require('@sourceorreryai/sdk');` and
`module.exports = { secret, optionalSecret };`.

## Replacements

| Before | After |
|--------|-------|
| `process.env.DATABASE_URL` | `secret('DATABASE_URL')` |
| `process.env.TIMEOUT ?? '30'` | `optionalSecret('TIMEOUT', '30')` |
| `require('dotenv').config()`, `import 'dotenv/config'` | delete, once every key is covered |
| `node --env-file=.env app.js` | `node app.js`, or `sourceorrery run -- node app.js` |

Remove `dotenv`, `dotenv-expand`, `env-cmd` or `cross-env` usage that
only served the `.env` file from `package.json`.

## Frameworks and build tools

- **Express, Fastify, NestJS, workers, scripts**: use `secret()` where the
  value is read; for `@nestjs/config`, load secrets in the config factory
  with `secret()`.
- **Next.js, Vite, Nuxt, Remix**: variables read at build time
  (`NEXT_PUBLIC_*`, `VITE_*`, `import.meta.env`) end up in the bundle and
  must never be secrets; leave them. Server-side secrets: read them with
  `secret()` in server code (route handlers, server actions, API routes),
  or run the dev and start scripts under `sourceorrery run --`.
- **Prisma and other CLIs reading `DATABASE_URL`**: change the script, for
  example `"migrate": "sourceorrery run -- prisma migrate deploy"`.

## Tests

Jest, Vitest and Mocha: run them as `sourceorrery run -- npm test` or let
the code load the project. Never write a real value into a test file.
