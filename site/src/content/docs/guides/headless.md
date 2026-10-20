---
title: "Headless: WSL, Docker, CI"
description: How to unlock a SourceOrrery vault where there is no OS credential store or no terminal, using a passphrase protector, a passphrase file and the SOURCEORRERY_HOME directory.
---

On a desktop the vault key sits in the OS credential store and unlocking is
silent. WSL cannot reach Windows Credential Manager, a container has no
Secret Service daemon, and a CI runner has neither a credential store nor a
person at a terminal. For all three the answer is the same: give the vault a
**passphrase protector** and supply the passphrase from a file.

## How unlocking works

A vault is unlocked by trying, in order:

1. every **OS-keyring protector** (Windows Credential Manager, macOS
   Keychain, Secret Service), with no prompt;
2. the `SOURCEORRERY_PASSPHRASE` environment variable;
3. the file named by `--passphrase-file` or `SOURCEORRERY_PASSPHRASE_FILE`;
4. an interactive prompt on stderr (up to three attempts), only when stdin is
   a terminal.

Each passphrase is tried against every passphrase protector on the vault.
Failed attempts are recorded in the audit log as `vault_open` / `denied`;
giving up is recorded as `vault_open` / `failure`. Nothing ever falls back to
an unprotected vault.

A vault can carry several protectors because each one wraps the same vault
key (see [Vault format](/reference/vault-format/#key-hierarchy)). A vault
created on Windows with Credential Manager can therefore also be unlocked with
a passphrase from WSL, Docker or CI. The last protector cannot be removed.

## Add a passphrase protector

Run this where the vault can already be unlocked, for example on the Windows
desktop that created it. You are prompted for the new passphrase twice.

```bash
sourceorrery vault protector add --kind passphrase --vault development
sourceorrery vault protector list --vault development
```

To create a vault that only ever uses a passphrase, for instance one dedicated
to a pipeline:

```bash
sourceorrery vault create ci --protector passphrase
```

Choose a passphrase you can provision independently of the vault file. Argon2id
(64 MiB, 3 passes) slows offline guessing against a stolen file; it does not
rescue a weak passphrase.

## WSL

The Windows home directory is reachable from WSL, so point `SOURCEORRERY_HOME`
at it and unlock with the passphrase protector added above:

```bash
export SOURCEORRERY_HOME=/mnt/c/Users/me/AppData/Local/sourceorrery
sourceorrery secret list --vault development         # prompts for the passphrase
sourceorrery run --vault development -- ./app         # same
```

To avoid the prompt, keep the passphrase in a file that only you can read:

```bash
install -m 600 /dev/null ~/.config/sourceorrery-pass
# write the passphrase into it with your editor, then
export SOURCEORRERY_PASSPHRASE_FILE=~/.config/sourceorrery-pass
sourceorrery check
```

You need a Linux build of `sourceorrery` inside WSL; the Windows binary cannot
talk to Credential Manager from there anyway, so a build with
`--no-default-features` is enough.

## Docker

Build the CLI without OS-keyring support, since a container has no Secret
Service, and give the container two things: the home directory that holds the
vault file, and the passphrase as a file.

```dockerfile
FROM rust:1.88 AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p sourceorrery-cli --no-default-features

FROM debian:bookworm-slim
COPY --from=build /src/target/release/sourceorrery /usr/local/bin/sourceorrery
ENV SOURCEORRERY_HOME=/var/lib/sourceorrery
```

Mount the vault directory read-write (every access appends an audit row) and
pass the passphrase through a file rather than an environment variable:

```bash
docker run --rm \
  -v "$HOME/.local/share/sourceorrery:/var/lib/sourceorrery" \
  -v "$PWD/sourceorrery.toml:/app/sourceorrery.toml:ro" \
  -v "$HOME/.config/sourceorrery-pass:/run/secrets/sopass:ro" \
  -w /app my-image \
  sourceorrery --passphrase-file /run/secrets/sopass run -- ./app
```

With Docker Compose or Swarm, declare the passphrase under `secrets:` and it
appears at `/run/secrets/<name>` in the container, which is exactly what
`--passphrase-file` expects.

## CI

`SOURCEORRERY_PASSPHRASE` works but environment variables are visible to
process inspection, so prefer a file. In GitHub Actions, store the passphrase
as a repository secret and write it to the runner's temporary directory for
the length of the job:

```yaml
- name: Provide the vault passphrase
  run: echo "$VAULT_PASSPHRASE" > "$RUNNER_TEMP/sopass"
  env:
    VAULT_PASSPHRASE: ${{ secrets.VAULT_PASSPHRASE }}

- name: Check the manifest resolves
  run: sourceorrery --passphrase-file "$RUNNER_TEMP/sopass" check

- name: Deploy with secrets in the environment
  run: sourceorrery --passphrase-file "$RUNNER_TEMP/sopass" run -- ./deploy.sh
```

`check` reads metadata only and writes no `secret_get` audit rows, so it is
safe to run on every pipeline. `run` resolves every entry and starts the
command with the values in its environment; a missing required secret aborts
before the command starts.

The vault file itself has to reach the runner. Milestone 1 vaults are local
files and `*.sorvault` is gitignored on purpose; do not commit one. Use a
self-hosted runner with a persistent home directory, or a container image or
volume provisioned with the vault, and provide the passphrase separately.
Encrypted `backup` / `restore` and remote providers are on the
[roadmap](/roadmap/).

## What a passphrase does not change

Whoever holds the passphrase, or runs as the user that can read the passphrase
file, can unlock the vault and reveal any secret in it. That is the
[access-control guarantee](/security/threat-model/#the-three-guarantees) of
milestone 1: local only. Headless setups make it easier to forget, so keep the
passphrase file out of images, out of logs and out of the repository, and
treat a CI runner that holds it as able to read every secret in that vault.
