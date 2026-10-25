# SourceOrrery overview

SourceOrrery keeps development and application secrets out of project files.
A local encrypted SQLite vault owns the catalog, keys, provider connections,
project records and audit history. Each secret's values live in that file
or at HashiCorp Vault KV v2, AWS Secrets Manager or Azure Key Vault. A local
vault is required for every project, including projects whose values are
all remote.

The CLI manages vaults and secret values. Its terminal browser shows
metadata only. Applications can receive values in a child process's
environment through `sourceorrery run`, or read them with an SDK.
SourceOrrery has no background daemon or local broker in this version.

## Install

Follow the [CLI installation guide](https://sourceorrery.ai/getting-started/#install).
It lists ready-to-run installation choices before source builds; Rust is
needed only if you choose to build from source. Install the CLI before
provisioning a vault or setting values. Installing an SDK alone does not
provide those management commands.

## Option 1: Set up with the CLI

Run these commands yourself in the project's directory. Create a vault
named `development` on the setup screens, store the recovery key privately,
then enter the new secret at its hidden prompt:

```bash
sourceorrery setup
sourceorrery secret set database-password --vault development
sourceorrery init --vault development --secret database-password
sourceorrery check
sourceorrery run -- npm start
```

Replace `npm start` with your application's start command. `check` reads
metadata; `run` resolves the declared secrets and delivers them to the
child process. A required secret that cannot resolve stops the launch.

The manifest is safe to commit because it contains references, not values:

```toml
[project]
name = "my-app"
vault = "development"

[secrets.database-password]
env = "DATABASE_PASSWORD"
required = true
```

The manifest names one local vault. Provider settings and credentials
belong in the vault's connections, not in the manifest. See the
[CLI reference](https://sourceorrery.ai/reference/cli/) for non-interactive
setup, import, connection configuration and lifecycle commands.

## Option 2: Set up with an AI coding agent

```bash
sourceorrery init --integration all
```

Ask your existing agent: "Set up SourceOrrery for this project without
showing secret values." The command installs SourceOrrery skills for
agents already on your machine; it does not install the agent applications.
It works before a vault or project manifest exists. Without a secret
selection it keeps an existing manifest and creates no new one.

The `sourceorrery` skill covers setup, SDKs, launch commands and diagnostics.
The `sourceorrery-migrate-env` skill covers migration through the CLI,
application changes and verification. You create vaults, enter new values
and retain recovery keys and view-check credentials privately. Agents
handle manifests, application code, launch scripts and metadata checks.

Supported agents are Claude Code, Gemini CLI, GitHub Copilot, Google
Antigravity, Cline, OpenAI Codex, Cursor, Hermes Agent, Kilo Code, Kimi Code
CLI, Kiro and OpenCode. The
[agent guide](https://sourceorrery.ai/guides/ai-agents/) lists their exact
integration names, directories, user scopes and the Claude Code plugin.

The installed CLI writes its embedded skill snapshot without downloading
anything. Maintained repository integration folders and the Claude Code
plugin can update skill text independently of CLI package releases;
[current repository skills](https://sourceorrery.ai/guides/ai-agents/#current-repository-skills)
explains how to preserve local customisations.

## Application languages

Read-only SDKs support Python, JavaScript and TypeScript, Rust, Java,
.NET, Go, C, C++ and PHP. The [SDK index](https://sourceorrery.ai/sdks/)
links each package, runtime requirements, examples and native library
requirements. Browser JavaScript, static sites and edge runtimes cannot
open a local vault with the native Node.js SDK.

Applications open existing vaults directly; they do not need a CLI process
running alongside them. Their public APIs open vaults, read values and
properties, resolve references and load projects. They cannot create a
vault or set secret values. Reads append audit events, so the vault
directory must be writable. The lower-level C tooling API has separate
write-capable entry points; use the documented reader/project APIs in
application code.

## Provider differences

Local storage, HashiCorp Vault and Azure Key Vault have per-version
properties. AWS Secrets Manager has per-secret properties and does not
support SourceOrrery's staged rotation workflow. Azure time windows can
be replaced but cannot be cleared. Check the
[provider mappings](https://sourceorrery.ai/providers/) before choosing a
lifecycle or rotation operation. An `outcome_unknown` error needs metadata
and provider-audit inspection before deciding whether to retry a mutation.

## Safe use and boundaries

Secret values are never command-line arguments. Use hidden prompts, stdin
or files through the CLI. Agents should not read `.env` contents, reveal
values, dump environment variables, read recovery keys or answer view
checks. `sourceorrery import .env --dry-run` can discover names without
showing values. Import leaves the original file in place; review skipped
or failed entries, check the application and ask before deleting it.

The machine key in the OS credential store and the recovery key unlock
the same vault encryption key. The optional view check controls interactive
browsing and explicit reveal; it is separate from encryption. SDKs,
`run`, `check` and `init` do not ask it. Processes with the same user's
access are not isolated by SourceOrrery. See the
[threat model](https://sourceorrery.ai/security/threat-model/) for the full
guarantees and limits.

Vault export copies local encrypted state, not the remote providers'
secret values. Only the supported vault format can be opened or imported;
there is no legacy-format conversion. Follow the
[export and import guide](https://sourceorrery.ai/guides/upgrading/).
