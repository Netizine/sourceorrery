# CLI reference

```
sourceorrery [--vault NAME] [--home DIR] [-o table|json] [--passphrase-file FILE] [-v] <command>
```

| Global option | Env | Meaning |
|---------------|-----|---------|
| `--vault NAME` | `SOURCEORRERY_VAULT` | Vault to use. Default: `[project].vault` from the nearest `sourceorrery.toml`. |
| `--home DIR` | `SOURCEORRERY_HOME` | Directory holding vault files. |
| `-o, --output table\|json` | | Output format. Errors in JSON mode are `{"error":{"code","message"}}` on stderr. In table mode, control and bidi formatting characters in stored text (labels, audit actors and details) are shown as `\u{..}` escapes. |
| `--passphrase-file FILE` | `SOURCEORRERY_PASSPHRASE_FILE` | Read the vault passphrase from a file (automation). |
| | `SOURCEORRERY_PASSPHRASE` | Passphrase from the environment. CI only; environment variables are visible to process inspection. |
| `-v` | `SOURCEORRERY_LOG` | Diagnostics on stderr. Never prints values. |

Exit status: `0` success, `1` any error (code in JSON mode), `2` usage error.
`run` exits with the child's status, whole: a Windows status above 255
(such as `3010`) is passed through unchanged, and a Unix child killed by a
signal exits `128 + signal`, as a shell would.

Running `sourceorrery` with no arguments prints the text logo, a link to
sourceorrery.ai and a quick start. On a terminal the logo is drawn with
Unicode half blocks in colours chosen to read on dark and light
backgrounds; when piped it is plain text. `SOURCEORRERY_BANNER=unicode|plain`
forces a style.

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
| `vault protector add --kind passphrase\|os-keyring [--label L]` | Add another way to unlock (e.g. a passphrase for WSL/Docker/CI). At most 8 passphrase protectors: unlock tries no more than that, so a ninth is refused rather than installed and never tried. |
| `vault protector remove ID_OR_LABEL` | Remove a protector. The last one cannot be removed. The OS-keyring entry is deleted after the change is committed, and only if it is provably this vault's. |
| `vault destroy NAME [--yes] [--keep-os-key]` | Delete the vault file and the OS-keyring entries it provably owns (entries another vault file references are kept and reported). Irreversible. |
| `vault migrate NAME` | Upgrade a vault written by an older release (schema 1 or 2) to the current format. Explicit on purpose: the rows it finds are taken on trust once, so only migrate a file you trust. A file that was already in the current format, or whose audit log was truncated, is refused; a migrated vault with a recorded, unacknowledged truncation stays blocked until `audit --acknowledge`. |

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
sourceorrery audit --verify
sourceorrery audit --acknowledge [--yes]
```

Newest first, with each event's id. Operations: `vault_create`,
`vault_open`, `vault_migrate`, `secret_inspect` (metadata reads: properties,
versions, deleted-secret details), `protector_add`, `protector_remove`,
`secret_set`, `secret_get`, `secret_list`, `secret_update`,
`secret_delete`, `secret_recover`, `secret_purge`, `audit_verify`
(a detected truncation with outcome `failure`, its acknowledgement with
outcome `success`). Outcomes: `success`, `denied` (policy), `failure`.
Detail holds the error code or a short note — never a value.

`--verify` checks the log's keyed hash chain instead of listing it (see
[vault-format.md](vault-format.md#audit-chain)) and prints:

| field | meaning |
|-------|---------|
| `rows` | audit rows examined |
| `keyed` | rows authenticated with the vault key |
| `unkeyed` | rows written before the vault was unlocked (failed unlock attempts); chained with a public key, so forgeable but not silently removable |
| `first_broken` | id of the first row whose link or hash does not verify, else `-` / `null` |
| `truncations` | times a write found rows removed from the end of the log (each is an `audit_verify` / `failure` event); acknowledged ones still count |
| `unacknowledged` | truncations not yet acknowledged with `--acknowledge`; while this is not 0 the vault refuses every other command |
| `head_valid` | the recorded chain head names the newest keyed row |
| `result` | `intact` or `BROKEN` |

The result is always printed (as JSON with `-o json`); when the chain is not
intact the command also fails with exit status 1. Verification is read-only,
but opening the vault to run it writes the usual `vault_open` row.

### A truncated log blocks the vault

If rows were removed from the end of the log since the last write, the
first command that unlocks the vault fails with `crypto` ("audit log
integrity: rows removed after event N …"): the vault judges every row
against the newest checkpoint in the log, so a shortened log is not
consulted. That refusal records the truncation (`audit_verify` /
`failure`), and from then on **every** command that unlocks the vault, and
every operation, fails with `crypto` naming that event ("… the truncation
detected at event 42 (…) is unacknowledged; the vault is blocked until
…"). Each refusal is recorded too.

The one exception is `audit` itself, which unlocks a blocked vault for
inspection: `audit` lists the log (and warns on stderr that the vault is
blocked), `audit --verify` reports the chain, and `audit --acknowledge`
lifts the block. Such an unlock writes `vault_open` / `success` with detail
`inspection (truncation unacknowledged)`, skips the retention purge, and
still refuses every secret and protector operation; nothing else opens
the vault. `vault migrate` is no way round it either.

Treat a truncation as evidence that the file was edited. Whatever the
missing events recorded — a change of policy, a deletion, a new version
— is gone, and an attacker who removed them may also have put back older
copies of the rows they covered, which the surviving history can no longer
tell from the truth. Compare the log and the secrets with a backup, then:

```
sourceorrery audit --acknowledge --vault development
```

prints the truncation events, asks for confirmation (`--yes` answers it,
for automation; in a non-interactive session without `--yes` the command
aborts and the vault stays blocked) and appends one keyed `audit_verify` /
`success` event, `truncation acknowledged (event 42)`. After that the
vault accepts commands again, with the surviving history as its record;
`audit --verify` keeps reporting the truncation (`truncations` stays 1,
`unacknowledged` becomes 0, the result stays `BROKEN`). The acknowledgement
covers every truncation detected before it and nothing after: a truncation
detected by another process between listing and acknowledging is refused
with `invalid_argument`, and a log found shortened again at that moment is
recorded and refused. With nothing to acknowledge the command says so and
exits 0.

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

Any other key — in particular `value` — is a parse error, reported by key
name and position without repeating the offending text. `env` names must be
unique ignoring case (Windows environments are case-insensitive) and may not
start with `SOURCEORRERY_`.

| Command | Description |
|---------|-------------|
| `init [--project-name N] [--vault-name V] [--path FILE] [--force]` | Write a starter manifest. |
| `check [--manifest FILE]` | Verify every entry resolves to an accessible version. Reads **metadata only**; writes no `secret_get` audit rows. Fails if a required secret is missing. |
| `run [--manifest FILE] -- COMMAND [ARGS...]` | Resolve every entry and start `COMMAND` with the values in its environment (plus `SOURCEORRERY_PROJECT`). Missing required secrets abort before the child starts; an optional secret whose vault does not exist is skipped. The child never inherits `SOURCEORRERY_PASSPHRASE` or `SOURCEORRERY_PASSPHRASE_FILE`. `--vault` overrides the manifest's default vault. |

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
