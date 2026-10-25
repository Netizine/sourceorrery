# Everything without an SDK: scripts, containers, CI, docs

Where the variable is read by something you do not change (a shell
script, a Makefile, a framework, a Ruby program), keep the variable and
change how the program starts: `sourceorrery run -- <command>` resolves
`sourceorrery.toml` and starts the command with each secret in its
environment, and only there.

## Scripts and task runners

| Before | After |
|--------|-------|
| `"start": "node -r dotenv/config server.js"` | `"start": "sourceorrery run -- node server.js"` |
| `"dev": "env-cmd -f .env next dev"` | `"dev": "sourceorrery run -- next dev"` |
| `set -a; source .env; set +a` in a script | delete; run the script as `sourceorrery run -- ./script.sh` |
| `include .env` / `export` in a Makefile | delete; prefix the recipe's command, or run `sourceorrery run -- make <target>` |
| Procfile `web: gunicorn app:app` | `web: sourceorrery run -- gunicorn app:app` |
| `.vscode/launch.json` `"envFile": "${workspaceFolder}/.env"` | remove `envFile`; launch through the SDK, or set `"program"`/`"runtimeExecutable"` to run under `sourceorrery run --` |

**Ruby**: there is no Ruby SDK. Remove the `dotenv` gem's
`Dotenv.load` / `require 'dotenv/load'` and start the app with
`sourceorrery run -- bundle exec rails server` (or `rake`, `rspec`).

## Docker and Compose

Vault files stay on the developer's machine; images never contain them.

- `docker-compose.yml` with `env_file: .env`: replace it with an
  `environment:` list of the variable names, which Compose copies from
  its own environment, and start Compose under SourceOrrery:

  ```yaml
  services:
    web:
      environment:
        - DATABASE_URL
        - STRIPE_KEY
  ```

  ```bash
  sourceorrery run -- docker compose up
  ```

  `${NAME}` interpolation in the Compose file works the same way.
- `docker run --env-file .env ...`: `sourceorrery run -- docker run -e DATABASE_URL -e STRIPE_KEY ...`.
- `ARG`/`ENV` holding a secret in a `Dockerfile` bakes it into the image:
  remove it and pass the value at run time as above.
- A container that should read the vault itself needs the vault (an
  exported copy, `vault export`, or the home mounted) and its recovery
  key as a file (`SOURCEORRERY_RECOVERY_KEY_FILE`): see the headless
  section of install.md.

## CI

CI runners have no developer vault. Leave the CI system's own secret
store (GitHub Actions secrets, GitLab CI variables) as it is unless the
user asks to change it; just stop CI from creating or reading `.env`
files. A pipeline that should use SourceOrrery gets its own vault, opened
with its recovery key from the CI system's secret store:
https://sourceorrery.ai/guides/headless/#ci

## Kubernetes, Terraform, serverless

These read from their own secret stores at deploy time. Do not move
production secrets into a developer vault; tell the user which
deployment files reference the migrated variables.

## Documentation

Replace "copy `.env.example` to `.env` and fill it in" in the README or
CONTRIBUTING with:

```bash
# Install SourceOrrery: https://sourceorrery.ai/getting-started/
sourceorrery setup                       # a vault, on screens; keep the recovery key it shows
sourceorrery secret set database-url     # once per secret in sourceorrery.toml; values are typed at a hidden prompt
sourceorrery check
sourceorrery run -- npm start            # or the project's own start command
```

A teammate who still has a `.env` file can run `sourceorrery import .env`
instead of setting each secret by hand, then delete it.
