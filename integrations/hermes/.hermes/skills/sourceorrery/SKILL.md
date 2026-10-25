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
- **Never see a recovery key or a view-check password.** A vault's
  recovery key opens it anywhere and is shown once, when the vault is
  made: the user creates vaults themselves (`sourceorrery setup`, in their
  own terminal). If they ask you to create one, run
  `sourceorrery vault create <name> --recovery-key-out <file>` with a path
  they choose outside the repository, never print the file, and tell them
  where it is. Never set `SOURCEORRERY_PASSWORD`, `--password-file` or
  `--code`: when the vault's view check refuses a command
  (`permission_denied`), ask the user to run it.
- **Ask first** before `secret delete`, `secret purge`, `vault destroy` or
  `audit --acknowledge`.
- **Never commit** `.env` files with values or `*.sorvault` vault files.

These instructions keep values out of a cooperative setup workflow. They
do not isolate a process running as the user. See the threat model:
https://sourceorrery.ai/security/threat-model/

## 1. Make sure the CLI is installed

```bash
sourceorrery --version
```

If the command is missing, install it: [references/install.md](references/install.md).
An existing installation can be used as it is; do not require a source
build or reinstall just to configure a project.

## 2. Set up the project

```bash
sourceorrery vault list                  # vaults on this machine
```

If there is no vault, ask the user to run `sourceorrery setup` in their
own terminal and wait: it creates the vault on screens and shows its
recovery key once, for them alone. Where there is no credential store
(headless Linux, containers, CI) the vault opens with that key from a
file: [references/install.md#headless](references/install.md#headless).

Choose the vault the user wants, keeping an existing manifest's vault.
Then write the manifest from its secrets, by name:

```bash
sourceorrery init development --all                                      # every secret it holds
sourceorrery init development --secret database-url --secret stripe-key  # or just these
```

`init` adds to an existing `sourceorrery.toml` in place and records the
folder in the vault. A secret the vault does not have yet is stored first
(the user runs `sourceorrery secret set <name>`, or `sourceorrery import`
moves a `.env` file in). `sourceorrery.toml` declares the secrets; commit
it:

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

A `value` key is a parse error, and so is a provider: where a secret is
kept (the vault file, or a provider such as AWS Secrets Manager through a
connection the vault holds) is the vault's record, never the manifest's.

## 3. Store and inspect secrets

| Task | Command |
|------|---------|
| A new value, typed by the user | the user runs `sourceorrery secret set <name>` (`--storage aws-secrets-manager`, `hashicorp-vault` or `azure-key-vault` keeps it at a provider the vault connects to) |
| Values from a `.env` file | `sourceorrery import .env` |
| A value from a file (certificate, key) | `sourceorrery secret set tls-key --from-file ./server.key` |
| Everything the manifest needs is present | `sourceorrery check` (no view check) |
| What exists, without values | `sourceorrery secret list`, `secret versions <name>`, `secret get <name>` (they ask the vault's view check, when it has one: then the user runs them) |
| Disable or expire a version | `sourceorrery secret update <name> --disable`, `--expires 2027-01-01T00:00:00Z` |
| Rotate a credential | `sourceorrery secret rotate <name>` (the new value comes from the manifest's `[rotation.<name>]` issue command, or the user types it) |
| Who read what | `sourceorrery audit` (asks the view check too) |

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

When writing setup documentation, make manual CLI setup option 1 and
AI-assisted setup option 2. Link the current CLI installation page rather
than duplicating installation commands or package availability:
https://sourceorrery.ai/getting-started/#install.
Option 2 installs the agent skills with `sourceorrery init --integration
<agent>` and asks the agent to configure the project, while the user keeps
recovery keys, passwords and new secret values in their own terminal.
