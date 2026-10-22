---
name: sourceorrery
description: Set up and use SourceOrrery, the encrypted local secrets vault that replaces .env files. Use when installing the sourceorrery CLI, creating a vault, storing or rotating a secret, declaring secrets in sourceorrery.toml, running an app or its tests with `sourceorrery run`, reading secrets from code with a SourceOrrery SDK (Python, JavaScript/TypeScript, Rust, Java, .NET, Go, C, C++, PHP), giving CI or a container access without a credential store, or fixing a SourceOrrery error. To move an existing project off .env files, use the sourceorrery-migrate-env skill.
license: MIT OR Apache-2.0
metadata:
  homepage: https://sourceorrery.ai
  managed-by: sourceorrery
---

# SourceOrrery

SourceOrrery keeps a project's secrets in an encrypted vault on the
developer's machine and hands them to the application at run time. The
repository holds `sourceorrery.toml`, which names the secrets a project
needs and can never hold a value. Documentation: https://sourceorrery.ai

## Rules

These keep secret values out of your context, the terminal and the
repository. Follow them even when a shortcut looks easier.

- **Never read a secret value.** Do not open, print, search or summarise
  the values in `.env` files. Do not run `sourceorrery secret get --reveal`.
  Do not print environment variables (`env`, `printenv`, `echo $VAR`,
  `Get-ChildItem Env:`) or add code that logs them. Key names are fine.
- **Never write a value** on a command line, in a file, in a test fixture
  or in a commit. The CLI has no option that takes a value. When a secret
  needs a new value, ask the user to run `sourceorrery secret set <name>`
  in their own terminal; it reads the value at a hidden prompt.
- **Values already in a `.env` file** move with `sourceorrery import`,
  which stores them without showing them (the sourceorrery-migrate-env
  skill has the whole procedure).
- **Do not create or store vault passphrases.** Prefer the OS credential
  store; where a passphrase is needed, the user chooses and types it.
- **Ask first** before `secret delete`, `secret purge`, `vault destroy`,
  `vault protector remove` or `audit --acknowledge`.
- **Never commit** `.env` files with values or `*.sorvault` vault files.

You run as the user, so you could unlock the vault; these rules are the
boundary. SourceOrrery's threat model says so plainly:
https://sourceorrery.ai/security/threat-model/

## 1. Make sure the CLI is installed

```bash
sourceorrery --version
```

If the command is missing, install it: [references/install.md](references/install.md).

## 2. Set up the project

```bash
sourceorrery vault list                  # vaults on this machine
sourceorrery vault create development    # key kept in the OS credential store: nothing to type
sourceorrery init                        # writes sourceorrery.toml in the current directory
```

Where there is no credential store (headless Linux, containers, CI),
`vault create` asks for a passphrase twice: ask the user to run it, and
see [references/install.md#headless](references/install.md#headless).

`sourceorrery.toml` declares the secrets; commit it:

```toml
[project]
name = "my-app"
vault = "development"            # vault the secrets come from

[secrets.database-url]           # secret name: letters, digits, hyphens
purpose = "Primary database"     # documentation only

[secrets.stripe-key]
env = "STRIPE_SECRET_KEY"        # delivered as this variable (default: STRIPE_KEY)
required = false                 # the program still starts without it
```

A `value` key is a parse error. The template `init` writes declares
`database-password` as an example: remove it if the project has no such
secret.

## 3. Store and inspect secrets

| Task | Command |
|------|---------|
| A new value, typed by the user | the user runs `sourceorrery secret set <name>` |
| Values from a `.env` file | `sourceorrery import .env` |
| A value from a file (certificate, key) | `sourceorrery secret set tls-key --from-file ./server.key` |
| What exists, without values | `sourceorrery secret list`, `secret versions <name>`, `secret get <name>` |
| Everything the manifest needs is present | `sourceorrery check` |
| Disable or expire a version | `sourceorrery secret update <name> --disable`, `--expires 2027-01-01T00:00:00Z` |
| Who read what | `sourceorrery audit` |

Every `set` adds an immutable version; a read takes the newest enabled
version inside its time window. Add `-o json` to any command for
machine-readable output. Secret names map to environment variables in
`UPPER_SNAKE_CASE`: `database-url` is `DATABASE_URL`.

## 4. Deliver secrets to the program

1. **As environment variables, no code change:** start the program with
   `sourceorrery run -- <command>`, for example `sourceorrery run -- npm start`
   or `sourceorrery run -- pytest`. Each secret in the manifest arrives as
   its variable in that process only. Change the scripts that start it
   (`package.json`, `Makefile`, `Procfile`, IDE launch configurations).
2. **Through an SDK:** the program reads the vault itself, so the values
   never sit in its environment. In every SDK `Project.load()` resolves
   the manifest the way `run` does and `env("NAME")` returns one
   variable's value: [references/sdks.md](references/sdks.md).

`--vault <name>` or `SOURCEORRERY_VAULT` selects another vault, for
example `sourceorrery --vault staging run -- ./deploy.sh`.

## 5. Errors

Every error has a stable code and a hint saying what to do; the common
ones are in [references/troubleshooting.md](references/troubleshooting.md).
