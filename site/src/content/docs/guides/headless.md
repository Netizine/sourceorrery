---
title: "Headless: WSL, Docker, CI"
description: How to open a SourceOrrery vault where this machine's key is not available or there is no terminal, using the vault's recovery key from a file and the SOURCEORRERY_HOME directory.
---

On a desktop, the OS credential store keeps this machine's key to the vault
and opens it without a prompt. Linux programs in WSL cannot use Windows
Credential Manager, and containers and CI runners usually have no usable
credential store, or not the one that holds this machine's key. There the
vault opens with its **recovery key**, shown once when the vault was made,
supplied from a restricted file.

> [!IMPORTANT]
> Keep the recovery key separate from the vault. The vault directory needs
> write access because even metadata reads append audit events. A read-only
> volume is not sufficient for a read-only SDK or for `sourceorrery check`.

## How a vault opens

The CLI opens a vault with:

1. **this machine's key** in the OS credential store (Windows Credential
   Manager, macOS Keychain, Secret Service), with no prompt;
2. otherwise the **recovery key**: `SOURCEORRERY_RECOVERY_KEY` if set,
   else the file named by `--recovery-key-file` or
   `SOURCEORRERY_RECOVERY_KEY_FILE`;
3. otherwise a hidden prompt on stderr when stdin is a terminal, up to
   three attempts.

> [!TIP]
> A recovery key from the environment or a file is tried once; a wrong one
> is not retried. `SOURCEORRERY_KEYRING=off` skips the credential store
> altogether. SDKs never prompt and try the same sources; see
> [SDK setup](/sdks/#setting-up).

Failed attempts are recorded in the audit log as `vault_open` / `denied`;
giving up is recorded as `vault_open` / `failure`. Nothing ever falls back to
an unprotected vault.

Both keys wrap the same vault key (see
[Vault format](/reference/vault-format/#key-hierarchy)), so a vault made on
Windows opens with its recovery key from WSL, Docker or CI. The vault's
**view check** (a password, perhaps with an authenticator code) is asked
only when a person views the vault or reveals a value; `run`, `check` and
the SDKs never ask it, and a vault opened with its recovery key has passed
it.

## The recovery key

`sourceorrery setup` shows the recovery key once, behind a "written down"
tick; `vault create` prints it once, or writes it to a new file readable by
you only:

```bash
sourceorrery vault create development --recovery-key-out ~/.config/development.recovery-key
```

A vault for a pipeline only, with no key for this machine:

```bash
sourceorrery vault create ci --no-keyring --recovery-key-out ci.recovery-key
```

A lost recovery key is replaced on a machine that still opens the vault,
on the setup screens (`sourceorrery vault create development`, or `c` in
`sourceorrery ui`); the old one stops working at once.

## WSL

The Windows home directory is reachable from WSL, so point `SOURCEORRERY_HOME`
at it and give the recovery key from a file only you can read:

```bash
mkdir -p ~/.config
install -m 600 /dev/null ~/.config/development.recovery-key
# write the recovery key into it with your editor, then
export SOURCEORRERY_HOME=/mnt/c/Users/me/AppData/Local/sourceorrery
export SOURCEORRERY_RECOVERY_KEY_FILE=~/.config/development.recovery-key
sourceorrery check
sourceorrery run --vault development -- ./app
```

Without the variable, each command prompts for the recovery key. Use a
Linux build of `sourceorrery` to launch Linux applications inside WSL. A
build with `--no-default-features` is enough for that; it omits the OS
credential store, the screens (`ui`, `setup`, `init`'s) and the providers.

## Docker

Build the CLI without the credential store, since a container has no
Secret Service, and give the container two things: the home directory that
holds the vault file, and the recovery key as a file.

```dockerfile
FROM rust:1.91.1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p sourceorrery-cli --no-default-features

FROM debian:bookworm-slim
COPY --from=build /src/target/release/sourceorrery /usr/local/bin/sourceorrery
ENV SOURCEORRERY_HOME=/var/lib/sourceorrery
```

For secrets the vault keeps at HashiCorp Vault, AWS Secrets Manager or
Azure Key Vault, build with `--no-default-features --features remote`
instead.

Mount the vault directory read-write (every access appends an audit row) and
pass the recovery key through a file rather than an environment variable:

```bash
docker run --rm \
  -v "$HOME/.local/share/sourceorrery:/var/lib/sourceorrery" \
  -v "$PWD/sourceorrery.toml:/app/sourceorrery.toml:ro" \
  -v "$HOME/.config/development.recovery-key:/run/secrets/recovery-key:ro" \
  -w /app my-image \
  sourceorrery --recovery-key-file /run/secrets/recovery-key check
```

Build `my-image` from the Dockerfile above in the SourceOrrery repository.
The final image contains the CLI only. To run an application, add that
application and its runtime to the image, then replace `check` with
`run -- <your application's command>`. Keep build and runtime images on the
same Debian release so the compiled binary has compatible system libraries.

With Docker Compose or Swarm, declare the recovery key under `secrets:` and
it appears at `/run/secrets/<name>` in the container, which is exactly what
`--recovery-key-file` expects.

## CI

`SOURCEORRERY_RECOVERY_KEY` works but environment variables are visible to
process inspection, so prefer a file. In GitHub Actions, store the recovery
key as a repository secret and write it to the runner's temporary directory
for the length of the job:

```yaml
- name: Provide the vault's recovery key
  shell: bash
  run: |
    umask 077
    printf '%s' "$VAULT_RECOVERY_KEY" > "$RUNNER_TEMP/recovery-key"
  env:
    VAULT_RECOVERY_KEY: ${{ secrets.VAULT_RECOVERY_KEY }}

- name: Check the manifest resolves
  shell: bash
  run: sourceorrery --recovery-key-file "$RUNNER_TEMP/recovery-key" check

- name: Deploy with secrets in the environment
  shell: bash
  run: sourceorrery --recovery-key-file "$RUNNER_TEMP/recovery-key" run -- ./deploy.sh

- name: Remove the recovery key file
  if: always()
  shell: bash
  run: rm -f -- "$RUNNER_TEMP/recovery-key"
```

These steps assume the CLI is installed, the repository is checked out and
the runner can access a provisioned vault. `check` reads metadata only and
writes no `secret_get` audit rows, but its open and inspection operations
are still audited. `run` resolves every entry and starts the command with
the values in its environment; a missing required secret aborts before the
command starts.

For a local vault, the file itself has to reach the runner. `*.sorvault`
is gitignored on purpose; do not commit one. Use a self-hosted runner with
a persistent home directory, or a container image or volume provisioned
with a copy of the vault: `sourceorrery vault export --out FILE` writes
one that opens with the recovery key only, and `vault import FILE` brings
it onto a machine. A secret the vault keeps at a provider
([providers](/providers/)) is read there through the vault's connection,
with the credentials the connection stores or the provider's own sign-in
on the runner, so only the vault's catalog travels with the file.

## What a recovery key does not change

> [!WARNING]
> Whoever holds the recovery key, or runs as the user that can read the
> file, can open the vault and reveal any accessible secret in it, with
> no view check. Keep the file out of images, logs and the repository.
> Treat a runner that holds it as having access to the vault, and use a
> separate vault for that pipeline. See the
> [threat model](/security/threat-model/#the-three-guarantees).
