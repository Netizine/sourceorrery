---
name: sourceorrery-migrate-env
description: Migrate a project from .env files to SourceOrrery without exposing a single value. Imports the keys of .env, .env.local, .env.production and similar files into an encrypted vault, declares them in sourceorrery.toml, finds every place the code, scripts, Docker and CI files read those variables (process.env, os.environ, os.Getenv, System.getenv, Environment.GetEnvironmentVariable, std::env::var, getenv, $_ENV, dotenv loaders) and converts them to SourceOrrery, then removes the plaintext files. Use when the user wants to get rid of .env files, move environment variables or secrets into SourceOrrery, or stop sharing or committing .env files.
license: MIT OR Apache-2.0
metadata:
  homepage: https://sourceorrery.ai
  managed-by: sourceorrery
---

# Migrate a project from .env files to SourceOrrery

Done means: no plaintext `.env` file with values left in the working tree,
every value in a vault, the code reading the same variables through
SourceOrrery, and nothing you saw or wrote containing a value.

## Rules

- **Never look at a value.** Do not open, print, search or summarise a
  `.env` file. Read its key names only through
  `sourceorrery import <file> --dry-run`. Searching the *code* for key
  names is fine; searching inside `.env` files is not.
- Never run `sourceorrery secret get --reveal`, never print environment
  variables, never write a value into code, configuration, tests,
  fixtures or a commit message.
- **Ask the user** before deleting files, before importing production or
  staging values on this machine, and before rewriting git history.

## Checklist

Copy this into your notes and tick it off:

```
- [ ] 1. CLI installed, vault exists
- [ ] 2. Env files found and planned
- [ ] 3. Values imported, `sourceorrery check` passes
- [ ] 4. Code converted
- [ ] 5. Scripts, containers, CI and docs updated
- [ ] 6. Plaintext removed and ignored
- [ ] 7. Verified and reported
```

### 1. CLI and vault

Run `sourceorrery --version`; if it is missing, install it
([references/install.md](references/install.md)). Then
`sourceorrery vault list`. If there is no `development` vault, run
`sourceorrery vault create development`; if it asks for a passphrase,
stop and ask the user to run it themselves.

### 2. Find and plan the env files

List the files by name only (they are usually git-ignored, so search the
disk rather than the index):

```bash
find . -name '.env*' -type f -not -path '*/node_modules/*' -not -path '*/.git/*'
```

```powershell
Get-ChildItem -Recurse -Force -File -Filter '.env*' | Where-Object FullName -notmatch '\\(node_modules|\.git)\\' | ForEach-Object FullName
```

For each file, see its keys and what would happen, without values:

```bash
sourceorrery import .env --dry-run
sourceorrery -o json import .env --dry-run      # the same, for parsing
```

Plan one vault per environment:

| File | Vault | Action |
|------|-------|--------|
| `.env`, `.env.local`, `.env.development` | `development` | `sourceorrery import .env` |
| `.env.test` | `test` (create it) | `sourceorrery --vault test import .env.test` |
| `.env.staging`, `.env.production` | `staging`, `production` | **ask first**: these values belong on the machines that run that environment |
| `.env.example`, `.env.sample`, `.env.template` | none: they hold no real values | `sourceorrery import .env.example --manifest-only` |
| `.env.vault`, `*.env.enc` or other encrypted files | none | stop and ask the user |

The dry run marks keys it cannot import: an invalid variable name, an
empty value, a `SOURCEORRERY_` name, a key assigned twice. Tell the user;
they rename the key or set the value by hand with
`sourceorrery secret set <name>`. In a monorepo each app gets its own
`sourceorrery.toml`; run the commands from that app's directory.

### 3. Import

```bash
sourceorrery import .env
sourceorrery check
```

`import` stores each non-empty value as a secret (`DATABASE_URL` becomes
`database-url`) and declares it in `sourceorrery.toml`, creating the file
if needed. Secrets already in the vault are left alone, so it is safe to
run again. If `sourceorrery.toml` still has the `database-password`
example from `sourceorrery init` and the project has no such secret,
delete that entry. `check` must report every secret `ok`.

### 4. Convert the code

1. Find every read of every imported key:
   [references/find-usages.md](references/find-usages.md).
2. Convert with the reference for each language:

   | Language | Reference |
   |----------|-----------|
   | Python | [references/convert-python.md](references/convert-python.md) |
   | JavaScript, TypeScript | [references/convert-javascript.md](references/convert-javascript.md) |
   | Java, Kotlin | [references/convert-java.md](references/convert-java.md) |
   | C#, F#, .NET | [references/convert-dotnet.md](references/convert-dotnet.md) |
   | Go | [references/convert-go.md](references/convert-go.md) |
   | Rust | [references/convert-rust.md](references/convert-rust.md) |
   | PHP | [references/convert-php.md](references/convert-php.md) |
   | C, C++ | [references/convert-c-cpp.md](references/convert-c-cpp.md) |
   | Anything else: Ruby, shell, Make, Docker, CI, Terraform | [references/convert-other.md](references/convert-other.md) |

How to choose, per variable:

- **Use the SDK** where the language has one: load the project once at
  start-up with `Project.load()` and replace each environment read with
  `env("NAME")` on it, which returns the same variable's value. Put this
  in one small module (`secrets.py`, `secrets.ts`, `Secrets.java`, ...)
  and route every read through it.
- **Keep the environment variable and start the program with
  `sourceorrery run --`** where something you do not control reads it:
  framework configuration placeholders, build tools, Docker Compose
  interpolation, shell scripts, Makefiles, runtimes without native
  modules. Then change how the program is started instead of the code.
- Remove the dotenv loader and its dependency only when every key it
  supplied is covered.
- Values that are configuration rather than secrets (ports, log levels)
  were imported too and keep working. If the user wants them in a
  committed config file instead, they have to move the values
  themselves: you cannot see them.

### 5. Scripts, containers, CI and docs

[references/convert-other.md](references/convert-other.md) covers
`package.json` scripts, Makefiles, Docker and Compose, CI workflows and
the README. In short: start programs with `sourceorrery run --`, replace
`env_file: .env` with variables passed through from the host, leave CI's
own secret store alone unless the user asks, and replace "copy
`.env.example` to `.env`" in the setup instructions with SourceOrrery
steps.

### 6. Remove the plaintext

- Make sure `.gitignore` contains `.env`, `.env.*`, `!.env.example` and
  `*.sorvault`.
- Ask the user, then delete each imported `.env` file. Keep
  `.env.example` if the project uses it as documentation.
- Check whether a file with values was ever committed
  (`git log --all --oneline -- .env`). If so, tell the user those
  credentials are in the repository's history and should be rotated: new
  values set with `sourceorrery secret set`. Do not rewrite history
  unless asked.

### 7. Verify and report

- `sourceorrery check` passes.
- The build and tests pass, through the SDK or
  `sourceorrery run -- <test command>`.
- Searching the code for `dotenv` finds no loader left behind.
- `git status` shows no `.env` file or `*.sorvault` staged.
- Tell the user which keys were migrated, which were skipped and why,
  which files changed, which were deleted, and what is left for them:
  rotating leaked values, and how teammates set up their own vault (each
  machine has its own; they run `sourceorrery vault create` and
  `sourceorrery secret set` or import their own `.env`).
