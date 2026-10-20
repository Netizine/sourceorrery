# CLI reference

```
sourceorrery [--vault NAME] [--home DIR] [-o table|json] [--passphrase-file FILE] [-v] <command>
```

| Global option | Env | Meaning |
|---------------|-----|---------|
| `--vault NAME` | `SOURCEORRERY_VAULT` | Vault to use. Default: `[project].vault` from the nearest `sourceorrery.toml`. |
| `--home DIR` | `SOURCEORRERY_HOME` | Directory holding vault files. |
| `-o, --output table\|json` | | Output format. Errors in JSON mode are `{"error":{"code","message"}}` on stderr. |
| `--passphrase-file FILE` | `SOURCEORRERY_PASSPHRASE_FILE` | Read the vault passphrase from a file (automation). |
| | `SOURCEORRERY_PASSPHRASE` | Passphrase from the environment. CI only; environment variables are visible to process inspection. |
| `-v` | `SOURCEORRERY_LOG` | Diagnostics on stderr. Never prints values. |

Exit status: `0` success, `1` any error (code in JSON mode), `2` usage error.
`run` exits with the child's status.

## Unlocking

A vault is unlocked, in order, by: its OS-keyring protector (Windows
Credential Manager, macOS Keychain, Secret Service — no prompt), then
`SOURCEORRERY_PASSPHRASE`, then `--passphrase-file`, then an interactive
prompt on stderr (up to three attempts) when stdin is a terminal. Failed
attempts are audited.

## `vault`

| Command | Description |
|---------|-------------|
| `vault create NAME [--protector os-keyring\|passphrase] [--retention-days 7-90] [--purgeable]` | Create a vault. Default protector: OS keyring when available, otherwise passphrase (prompted twice). `--purgeable` disables soft delete. |
| `vault list` | Vaults in the home directory. |
| `vault info` | Metadata and protectors of the selected vault. |
| `vault protector list` | Installed protectors. |
| `vault protector add --kind passphrase\|os-keyring [--label L]` | Add another way to unlock (e.g. a passphrase for WSL/Docker/CI). |
| `vault protector remove ID_OR_LABEL` | Remove a protector. The last one cannot be removed. |
| `vault destroy NAME [--yes]` | Delete the vault file and its OS-keyring entries. Irreversible. |

## `secret`

| Command | Description |
|---------|-------------|
| `secret set NAME [--stdin \| --from-file FILE] [--confirm] [--allow-empty] [--keep-trailing-newline] [--content-type T] [--tag K=V]... [--not-before T] [--expires T] [--disabled]` | Store a **new version**. Value source: `--from-file`, else stdin when piped (`--stdin` to force), else a hidden prompt. One trailing newline from stdin is stripped. There is no `--value` option. |
| `secret get NAME [--version ID] [--reveal] [--raw]` | Metadata (default). `--reveal` prints the value + newline; `--raw` omits the newline. `-o json --reveal` adds `value` (or `value_hex` for non-UTF-8). Without `--version`, the newest *accessible* version is used. |
| `secret list [--deleted]` | Live secrets (newest version each), or soft-deleted ones. Metadata only. |
| `secret versions NAME` | Every version, newest first, with status. |
| `secret update NAME [--version ID] [--enable\|--disable] [--content-type T\|--clear-content-type] [--tag K=V...\|--clear-tags] [--not-before T\|--clear-not-before] [--expires T\|--clear-expires]` | Change metadata of one version. Never the value. |
| `secret delete NAME` | Soft-delete all versions (recoverable until retention ends). Immediate in a purgeable vault. |
| `secret recover NAME` | Undo a soft delete. |
| `secret purge NAME [--yes]` | Permanently remove a soft-deleted secret. |

Status column values: `enabled`, `disabled`, `pending` (before `not_before`),
`expired`.

Timestamps are RFC 3339, e.g. `2026-12-31T00:00:00Z`.

## `audit`

```
sourceorrery audit [--secret NAME] [--operation OP] [--since TIME] [--limit N]
```

Newest first. Operations: `vault_create`, `vault_open`, `protector_add`,
`protector_remove`, `secret_set`, `secret_get`, `secret_list`,
`secret_update`, `secret_delete`, `secret_recover`, `secret_purge`.
Outcomes: `success`, `denied` (policy), `failure`. Detail holds the error
code — never a value.

## Project manifest: `init`, `check`, `run`

`sourceorrery.toml` is the committed, value-free replacement for `.env`:

```toml
[project]
name = "my-application"
vault = "development"

[secrets.database-password]
required = true
purpose = "Database authentication"          # documentation only

[secrets.payment-api-key]
required = false
env = "STRIPE_KEY"                           # default: PAYMENT_API_KEY
version = "0123456789abcdef0123456789abcdef" # pin a version (optional)
vault = "payments-sandbox"                   # different vault (optional)
```

Any other key — in particular `value` — is a parse error.

| Command | Description |
|---------|-------------|
| `init [--project-name N] [--vault-name V] [--path FILE] [--force]` | Write a starter manifest. |
| `check [--manifest FILE]` | Verify every entry resolves to an accessible version. Reads **metadata only**; writes no `secret_get` audit rows. Fails if a required secret is missing. |
| `run [--manifest FILE] -- COMMAND [ARGS...]` | Resolve every entry and start `COMMAND` with the values in its environment (plus `SOURCEORRERY_PROJECT`). Missing required secrets abort before the child starts. `--vault` overrides the manifest's default vault. |

The parent process never prints the values; they exist only in the child's
environment (which other processes running as you can read — see the threat
model).

## `completions`

```
sourceorrery completions bash|zsh|fish|powershell|elvish
```

## Examples

```bash
# Windows PowerShell, OS keyring
sourceorrery vault create development
"s3cr3t" | sourceorrery secret set database-password --vault development
sourceorrery secret list --vault development

# Same vault from WSL: add a passphrase protector once (on Windows), then
sourceorrery vault protector add --kind passphrase --vault development
# in WSL, pointing at the same home directory
export SOURCEORRERY_HOME=/mnt/c/Users/me/AppData/Local/sourceorrery
sourceorrery secret get database-password --vault development --reveal

# CI
echo "$VAULT_PASSPHRASE" > /run/secrets/sopass
sourceorrery --passphrase-file /run/secrets/sopass check
sourceorrery --passphrase-file /run/secrets/sopass run -- ./deploy.sh
```
