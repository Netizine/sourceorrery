---
title: "Headless: WSL, Docker, CI"
description: How to unlock a SourceOrrery vault where there is no OS credential store or no terminal, using a passphrase protector, a passphrase file and the SOURCEORRERY_HOME directory.
---

On a desktop, an OS credential store can protect the vault key and unlock it
without a prompt. Linux programs in WSL cannot use Windows Credential
Manager, and containers and CI runners usually have no usable credential
store. Give the vault a **passphrase protector** and supply the passphrase
from a restricted file.

> [!IMPORTANT]
> Keep the passphrase separate from the vault. The vault directory needs
> write access because even metadata reads append audit events. A read-only
> volume is not sufficient for a read-only SDK or for `sourceorrery check`.

## How unlocking works

The CLI unlocks a vault using:

1. every **OS-keyring protector** (Windows Credential Manager, macOS
   Keychain, Secret Service), with no prompt;
2. the first configured passphrase source: non-empty
   `SOURCEORRERY_PASSPHRASE`, otherwise the file named by `--passphrase-file`
   or `SOURCEORRERY_PASSPHRASE_FILE`;
3. an interactive prompt on stderr if needed and stdin is a terminal, up to
   the vault's three-attempt limit.

> [!TIP]
> An incorrect `SOURCEORRERY_PASSPHRASE` prevents the CLI from trying a
> configured passphrase file. Unset that variable before using a file.
> SDKs never prompt and try their configured candidates in sequence; see
> [SDK setup](/sdks/#setting-up).

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
desktop that created it. Without a configured passphrase source, you are
prompted for the new passphrase twice. If an environment variable or file is
configured, that source supplies the new protector's passphrase instead.

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
mkdir -p ~/.config
install -m 600 /dev/null ~/.config/sourceorrery-pass
# write the passphrase into it with your editor, then
export SOURCEORRERY_PASSPHRASE_FILE=~/.config/sourceorrery-pass
sourceorrery check
```

Use a Linux build of `sourceorrery` to launch Linux applications inside WSL.
A build with `--no-default-features` is enough for passphrase-based CLI
commands; it omits both OS-keyring support and the interactive `ui`.

## Docker

Build the CLI without OS-keyring support, since a container has no Secret
Service, and give the container two things: the home directory that holds the
vault file, and the passphrase as a file.

```dockerfile
FROM rust:1.88-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p sourceorrery-cli --no-default-features

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
  sourceorrery --passphrase-file /run/secrets/sopass check
```

Build `my-image` from the Dockerfile above in the SourceOrrery repository.
The final image contains the CLI only. To run an application, add that
application and its runtime to the image, then replace `check` with
`run -- <your application's command>`. Keep build and runtime images on the
same Debian release so the compiled binary has compatible system libraries.

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
  shell: bash
  run: |
    umask 077
    printf '%s' "$VAULT_PASSPHRASE" > "$RUNNER_TEMP/sopass"
  env:
    VAULT_PASSPHRASE: ${{ secrets.VAULT_PASSPHRASE }}

- name: Check the manifest resolves
  shell: bash
  run: sourceorrery --passphrase-file "$RUNNER_TEMP/sopass" check

- name: Deploy with secrets in the environment
  shell: bash
  run: sourceorrery --passphrase-file "$RUNNER_TEMP/sopass" run -- ./deploy.sh

- name: Remove the passphrase file
  if: always()
  shell: bash
  run: rm -f -- "$RUNNER_TEMP/sopass"
```

These steps assume the CLI is installed, the repository is checked out and
the runner can access a provisioned vault. `check` reads metadata only and
writes no `secret_get` audit rows, but its unlock and inspection operations
are still audited. `run` resolves every entry and starts the
command with the values in its environment; a missing required secret aborts
before the command starts.

The vault file itself has to reach the runner. Vaults are local files and
`*.sorvault` is gitignored on purpose; do not commit one. Use a
self-hosted runner with a persistent home directory, or a container image or
volume provisioned with the vault, and provide the passphrase separately.
Encrypted `backup` / `restore` and remote providers are on the
[roadmap](/roadmap/).

## What a passphrase does not change

> [!WARNING]
> Whoever holds the passphrase, or runs as the user that can read the
> passphrase file, can unlock the vault and reveal any accessible secret in
> it. Keep the file out of images, logs and the repository. Treat a runner
> that holds it as having access to the vault, and use a separate vault with
> credentials scoped to that pipeline. See the
> [threat model](/security/threat-model/#the-three-guarantees).
