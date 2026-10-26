# CLI reference

> [!NOTE]
> This reference describes the 0.3.0 source tree. Check your installed
> version with `sourceorrery --version`.

```
sourceorrery [--vault NAME] [--home DIR] [-o table|json] [--recovery-key-file FILE] [--password-file FILE] [--code CODE] [-v] <command>
```

| Global option | Env | Meaning |
|---------------|-----|---------|
| `--vault NAME` | `SOURCEORRERY_VAULT` | Vault to use. Default: `[project].vault` from the nearest `sourceorrery.toml`. |
| `--home DIR` | `SOURCEORRERY_HOME` | Directory holding vault files. |
| `-o, --output table\|json` | | Output format. Errors in JSON mode are `{"error":{"code","message"}}` on stderr. In table mode, control and bidi formatting characters in stored text (labels, audit actors and details) are shown as `\u{..}` escapes. |
| `--recovery-key-file FILE` | `SOURCEORRERY_RECOVERY_KEY_FILE` | The vault's recovery key, read from a file, where this machine cannot open the vault by itself (WSL, a container, CI, another machine). |
| | `SOURCEORRERY_RECOVERY_KEY` | The recovery key from the environment. CI only; environment variables are visible to process inspection. |
| `--password-file FILE` | `SOURCEORRERY_PASSWORD_FILE` | The [view check](#the-view-check)'s password, read from a file (scripts); with `vault create` and `vault import`, the password the vault's check is set to. |
| | `SOURCEORRERY_PASSWORD` | The view check's password from the environment. |
| `--code CODE` | `SOURCEORRERY_TOTP` | A six-digit code from the authenticator app, for a vault whose view check asks for one. Without it the code is asked for on the terminal; a code is never read from a pipe. |
| `-v` | `SOURCEORRERY_LOG` | Diagnostics on stderr. Never prints values. |
| | `SOURCEORRERY_KEYRING=off` | Use no OS credential store: every vault opens with its recovery key. |

Exit status: `0` success, `1` any error (code in JSON mode), `2` usage error.
`run` exits with the child's status, whole: a Windows status above 255
(such as `3010`) is passed through unchanged, and a Unix child killed by a
signal exits `128 + signal`, as a shell would.

Running `sourceorrery` with no arguments prints the text logo, a link to
sourceorrery.ai and a quick start. On a terminal the logo is drawn with
Unicode half blocks in colours chosen to read on dark and light
backgrounds; when piped it is plain text. `SOURCEORRERY_BANNER=unicode|plain`
forces a style.

## Project setup options

1. **Option 1: Set up with the CLI.** Follow the [CLI installation guide](https://sourceorrery.ai/getting-started/#install),
   then create the vault and set its secret values in your own terminal.
2. **Option 2: Set up with an AI coding agent.** Run
   `sourceorrery init --integration all`, then ask your agent to set up
   SourceOrrery for the project without showing values. You keep vault
   keys and new values private. [The agent setup guide](https://sourceorrery.ai/guides/ai-agents/)
   works with an existing CLI installation.

## `setup`: a vault on screens

```
sourceorrery setup [--guide] [--theme dark|light|terminal]
sourceorrery vault create [NAME]
```

`setup` and `vault create [NAME]` show the same screens on a terminal. With
no vault on this machine they create one; with vaults they list them, to
change one or create another. `vault create NAME` starts with the name
filled in, and the name of a vault that exists opens it for changes.

| Screen | What it does |
|--------|--------------|
| Start | The vaults on this machine, **Create a new vault**, and whether this machine's credential store keeps a vault's key. |
| Name | The new vault's name, checked as it is typed (letters, digits, hyphens, underscores, up to 64, unique ignoring case). |
| View check | Whether viewing the vault asks for a password, and an authenticator code on top of it ([below](#the-view-check)). |
| Password | Typed twice with a strength meter (it must rate "good"), or generated and shown once behind a "written down" tick; an optional hint, refused if it gives the password away. |
| Authenticator | A complete QR code when it fits, with the manual enrolment key available on compact screens; the code field and controls remain reachable. A code from the app is checked before moving on; three wrong ones make a new key. |
| Recovery key | Shown once, behind a "written down" tick. When changing a vault it is kept unless a new one is asked for, and the old one then stops working in this file. A new recovery key is not a new vault key: an old copy of the vault still opens with the old key. After a compromise, rotate the exposed credentials and move to a new vault instead ([threat model](threat-model.md), gap 10). |
| Storage | The SourceOrrery vault (always) and HashiCorp Vault, AWS Secrets Manager and Azure Key Vault; a provider not built into this binary is shown as unavailable. |
| Connections | One form per provider ticked: its address, region or URL, and its credentials, either this machine's sign-in (the provider's own environment, CLI login or workload identity) or stored in the vault, sealed. **Test connection** makes one metadata call. |
| Review | Everything above. **Create vault** or **Save changes** makes it all in one transaction: nothing is written before it, and a part the vault refuses leaves everything as it was. |
| Done | The vault, its file, view check and storage, and what to run next: `sourceorrery ui` and `sourceorrery init`. |

<!-- walkthrough: setup -->

Changing a vault never prompts: this machine's key opens it, else its
recovery key is typed on the screen (which passes the view check by
itself), else its view check is asked there, with the hint. The review
commits only against the view check the screens passed, or found absent,
when they opened the vault: one set or changed elsewhere in the meantime
refuses the commit (`permission_denied`), and the vault is opened again.
Hidden fields are drawn as dots from their length; what is typed lives in
a buffer that is wiped, and goes to the vault at the review. The screens
are the Cargo feature `ui`.

`setup --guide`, or `setup` without a terminal or with `-o json`, prints
the one command that does the same without the screens:

```
sourceorrery vault create development --recovery-key-out development.recovery-key \
  [--password-file FILE] \
  [--hashicorp-vault ADDRESS [--hashicorp-vault-mount MOUNT] [--hashicorp-vault-token-file FILE]] \
  [--aws-secrets-manager REGION [--aws-access-key-id ID --aws-secret-access-key-file FILE]] \
  [--azure-key-vault URL [--azure-tenant-id ID --azure-client-id ID --azure-client-secret-file FILE]]
```

The authenticator is set up on the screens only: it needs a code from the
app.

## Opening a vault

A vault's key is kept twice: once for this machine, in its OS credential
store (Windows Credential Manager, macOS Keychain, Secret Service on
Linux), and once under the vault's **recovery key**, shown when the vault
is made. The CLI tries this machine's key first, without prompting. Where
that is not possible (WSL, a container, CI, another machine, an exported
copy, `SOURCEORRERY_KEYRING=off`) it takes the recovery key from
`SOURCEORRERY_RECOVERY_KEY`, else `--recovery-key-file` /
`SOURCEORRERY_RECOVERY_KEY_FILE`, else a hidden prompt when stdin is a
terminal, up to three attempts. A key from the environment or a file is
tried once; a wrong one is not retried. Failed attempts are audited.

`run` never passes any of these variables, or the password and code
variables below, to the program it starts.

### The view check

Opening a vault lets a process read its values. The **view check** is a
second question for the moments a person views the vault or reveals a
value: a password, and optionally a code from an authenticator app on top
of it, set on the [setup screens](#setup-a-vault-on-screens). It is a
check, not encryption: the vault key does not depend on it.

It is asked by `ui`, `secret list`, `secret get` (with or without
`--reveal`), `secret versions`, `audit` and `audit export`, and before the
setup screens change a vault. `run`, `check`, `init`, `import`, the other
`secret` commands and every SDK never ask it, so an application keeps
starting without a prompt while an API key read out at the keyboard, by
you or by an agent, asks for more.

The password comes from `SOURCEORRERY_PASSWORD`, else `--password-file`,
else a hidden prompt (after the hint, if one is set). The code comes from
`--code` / `SOURCEORRERY_TOTP`, else a prompt on the terminal; it is never
read from a pipe, so a script that has neither is refused rather than
hung. A code is accepted once, for the current 30-second step or the one
either side of it. A vault opened with its recovery key has passed the
check: the recovery key opens it anywhere and is the stronger secret.

A refusal is `permission_denied`, audited under `guard`. After five wrong
answers in a row each further attempt waits, 30 seconds at first, doubling
to at most 15 minutes. The check is not a boundary against code running as
you with the vault key in reach; see the [threat model](threat-model.md).

```
sourceorrery secret get database-password --vault development --reveal
Hint: the long one
Password of vault 'development':
Code from the authenticator app: 123456
```

## `vault`

> [!WARNING]
> `vault destroy` removes the vault permanently. A purgeable vault also
> makes `secret delete` immediate and irreversible. Use the default
> recoverable vault unless you deliberately need permanent deletion.

| Command | Description |
|---------|-------------|
| `vault create [NAME]` | On a terminal, without the flags below: the [setup screens](#setup-a-vault-on-screens) (`--theme` as for `ui`). |
| `vault create NAME [--recovery-key-out FILE] [--password-file FILE] [--no-keyring] [--retention-days 7-90] [--purgeable] [connection flags]` | Create the vault at once (scripts, CI, any of these flags, or no terminal). Its recovery key is printed once on stdout, or written to `--recovery-key-out`: a new file, created before the vault with permissions only you have (on Windows restricted to your account and Windows SYSTEM, read back and checked; on Unix mode `0600`), and synced to disk; an existing file is never written over, and a volume that cannot keep permissions is refused. A key that cannot be delivered, to the file or to stdout, leaves no vault behind: the create is undone. `--password-file` sets the view check's password (a weak one is warned about); `--no-keyring` keeps no key for this machine. The connection flags add one connection per provider, the credentials read from files only (below). The vault, its password and its connections are made in one transaction: a part refused creates nothing. `-o json`: `vault`, `this_machine`, `keys` (kind and id of each key that opens it), `view_check`, `connections`, and `recovery_key` or `recovery_key_file`. |
| `vault list` | The vault files in the home directory. It opens none of them. |
| `vault export [NAME] --out FILE` | A copy of the vault for another machine: a consistent snapshot of the file (settings, connections with their credentials still sealed, the catalog, the values it keeps, project folders and the audit log). This machine's key and the view check stay behind, so the copy opens only with the recovery key; the copy's own log records the export. `--out` must not exist. Not asked the view check: the copy is no more open than the file. |
| `vault import FILE [--name NAME]` | Bring an exported vault onto this machine: it is opened with its recovery key (the environment, `--recovery-key-file` or the prompt), its name, settings and audit chain are verified, this machine's key is added and it is registered under its name or `--name` (a name that exists, ignoring case, is refused). It comes with no view check; `--password-file` sets one at once, and otherwise the output says how (`vault create NAME` on a terminal). |
| `vault destroy NAME [--yes] [--keep-os-key]` | Delete the vault file and the credential-store entries it provably owns (entries another vault file references are kept and reported). Irreversible. |

The connection flags of `vault create`:

| Provider | Flags |
|----------|-------|
| HashiCorp Vault | `--hashicorp-vault ADDRESS` (`https://`, or `http://` to this machine), `--hashicorp-vault-mount MOUNT` (default `secret`), `--hashicorp-vault-namespace NAMESPACE`, `--hashicorp-vault-token-file FILE` (store the token in the vault instead of using `VAULT_TOKEN` and Vault's other sign-in sources) |
| AWS Secrets Manager | `--aws-secrets-manager REGION`, `--aws-secrets-manager-prefix PREFIX`, `--aws-secrets-manager-endpoint URL`, `--aws-access-key-id ID` with `--aws-secret-access-key-file FILE` (store an access key) |
| Azure Key Vault | `--azure-key-vault URL`, `--azure-tenant-id ID` with `--azure-client-id ID` and `--azure-client-secret-file FILE` (store a service principal) |

Without stored credentials a connection signs in the way the provider's
own tools do on that machine. The providers, what each maps and what it
cannot express are in [providers](providers/index.md).

## `secret`

| Command | Description |
|---------|-------------|
| `secret set NAME [--stdin \| --from-file FILE] [--confirm] [--allow-empty] [--keep-trailing-newline] [--content-type T] [--tag K=V]... [--not-before T] [--expires T] [--disabled] [--storage STORAGE] [--description TEXT]` | Store a **new version**. Value source: `--from-file`, else stdin when piped (`--stdin` to force), else a hidden prompt. One trailing newline from stdin is stripped. There is no `--value` option. `--storage` says where a new secret is kept: `sourceorrery` (the vault file, the default), or a provider the vault has a connection to (`hashicorp-vault`, `aws-secrets-manager`, `azure-key-vault`, or the connection's id); a new version of an existing secret goes where the secret is. `--description` is one line of what the secret is for (at most 200 characters), kept in the vault's catalog and written into a manifest as `purpose` by `init`. Tag keys under `sourceorrery.` are SourceOrrery's own (rotation state) and refused. |
| `secret get NAME [--version ID] [--reveal] [--raw]` | Metadata (default). `--reveal` prints the value + newline; `--raw` omits the newline. `-o json --reveal` adds `value` (or `value_hex` for non-UTF-8). Without `--version`, the newest *accessible* version is used. Asks the [view check](#the-view-check). |
| `secret list [--deleted] [--limit N] [--after NAME]` | Live secrets (newest version each), or soft-deleted ones, in name order, from wherever each is kept. Metadata only. `--limit N` shows one page of up to N and, while names follow, the `--after NAME` that continues it; `-o json` then prints `{"items": [...], "continuation": "NAME"}` instead of the plain array. Each page is one `secret_list` audit event. Asks the view check. |
| `secret versions NAME` | Every version, newest first, with status. Asks the view check. |
| `secret update NAME [--version ID] [--enable\|--disable] [--content-type T\|--clear-content-type] [--tag K=V...\|--clear-tags] [--not-before T\|--clear-not-before] [--expires T\|--clear-expires]` | Change metadata of one version. Never the value. A provider that keeps these properties per secret, or cannot remove a time window, refuses what it cannot express (`unsupported`). |
| `secret delete NAME` | Soft-delete all versions (recoverable until retention ends). Immediate in a purgeable vault. |
| `secret recover NAME` | Undo a soft delete. |
| `secret purge NAME [--yes]` | Permanently remove a soft-deleted secret. |
| `secret rotate NAME [--manifest FILE] [--step rotate\|activate\|retire\|status] [--no-activate] [--retire-after D] [--now] [--stdin \| --from-file FILE] [--keep-trailing-newline] [--allow-empty]` | Rotate a credential: issue a new value (the manifest's `[rotation.NAME]` `issue` command, else stdin, a file or a prompt), validate it with the `validate` command, activate it (enable the new version, then disable the previous one), and retire the previous one with the `retire` command once `retire_after` (or `--retire-after`) has passed, in a later `--step retire` run; without a grace period, in the same run. State lives in `sourceorrery.rotation.*` tags; refusals carry the code `rotation`. A secret kept at AWS Secrets Manager cannot be rotated (`unsupported`: its properties are per secret). See [rotation](rotation.md). |

A secret kept at a provider is read and changed there through the vault's
connection, and the vault records each call in its own audit log.

Status column values: `enabled`, `disabled`, `pending` (before `not_before`),
`expired`.

Timestamps are RFC 3339, e.g. `2026-12-31T00:00:00Z`.

## `audit`

```
sourceorrery audit [--secret NAME] [--operation OP] [--since TIME] [--limit N]
sourceorrery audit --verify
sourceorrery audit --acknowledge [--yes]
sourceorrery audit export [--format jsonl|otlp] [--since TIME] [--follow] [--interval S] [--endpoint URL] [--header K=V]... [--batch N]
```

Newest first, with each event's id. `audit` and `audit export` ask the
[view check](#the-view-check). Operations:

| Operation | Recorded for |
|-----------|--------------|
| `vault_create`, `vault_open` | Creating the vault; each open (a failed one with outcome `failure`, detail `locked`). |
| `secret_set`, `secret_get`, `secret_list`, `secret_inspect`, `secret_update`, `secret_delete`, `secret_recover`, `secret_purge` | The secret operations; `secret_inspect` is a metadata read (properties, versions, a deleted secret's details). A call to a provider is recorded the same way, by the vault, with the provider's outcome. |
| `guard` | The view check: an answer passed or refused (`denied`), each change to it (password set or changed, check cleared, authenticator enrolled and verified or removed), and each change refused (`failure`, the error code only: never the password or hint it was given). |
| `protector_add` | The recovery key replaced, or this machine's key added. Its event checkpoints the new set of key wraps. |
| `vault_change` | A connection added, changed or removed, and a change of settings refused as a whole (`failure`). |
| `connection_test` | A connection tested (`success`, or `failure` with the error code). |
| `vault_export`, `vault_import` | The vault exported (in the copy's own log) or imported. |
| `project_link`, `project_unlink` | A project folder recorded by `init`, or forgotten in the `ui`. |
| `audit_verify` | A detected truncation (`failure`) and its acknowledgement (`success`). |

Older releases also recorded `protector_remove`, `vault_migrate`,
`vault_backup` and `secret_restore`; they are kept as names, never
recorded now. Outcomes: `success`, `denied` (policy), `failure`,
`pending` and `unknown`. A change at a connection is recorded as a
`pending` attempt before it is sent (`at connection <id>: sent`), and the
event with its result names it (`(attempt <id>)`); `unknown` is a change
the provider may have made (`outcome_unknown`). After the events, `audit`
names every attempt whose result the vault never learned and what to do
([providers](providers/index.md#when-a-changes-result-is-not-known)).
Detail holds the error code or a short note — never a value, a code, a
password, a credential or the hint.

`--verify` checks the log's keyed hash chain instead of listing it (see
[vault-format.md](vault-format.md#audit-chain)) and prints:

| field | meaning |
|-------|---------|
| `rows` | audit rows examined |
| `keyed` | rows authenticated with the vault key |
| `unkeyed` | rows written before the vault was opened (failed attempts); chained with a public key, so forgeable but not silently removable |
| `first_broken` | id of the first row whose link or hash does not verify, else `-` / `null` |
| `truncations` | times a write found rows removed from the end of the log (each is an `audit_verify` / `failure` event); acknowledged ones still count |
| `unacknowledged` | truncations not yet acknowledged with `--acknowledge`; while this is not 0 the vault refuses every other command |
| `head_valid` | the recorded chain head names the newest keyed row |
| `result` | `intact` or `BROKEN` |

The result is always printed (as JSON with `-o json`); when the chain is not
intact the command also fails with exit status 1. Verification is read-only,
but opening the vault to run it writes the usual `vault_open` row.

### `audit export`: the log for a collector

`audit export` writes the whole log, **oldest first**, for the place the
organisation already collects logs, and ends with the chain verification
so a collector can tell a complete export from a truncated log:

* `--format jsonl` (default): one JSON object per line on stdout, the
  event as `audit -o json` shows it plus `"vault"`, then one trailer line
  `{"vault", "events", "last_id", "intact", "verification": {…}}` with
  the fields of `audit --verify`. Vector, Fluent Bit and their kind read
  it without help (`sourceorrery audit export --vault production |
  vector --config …`, or a `file` source on a redirected file).
* `--format otlp --endpoint URL`: the same records as OTLP/HTTP log records
  (JSON encoding, `POST …/v1/logs`) in batches of `--batch` (500), for a
  collector that speaks OTLP directly. Each event is a log record whose body
  is `<operation> <outcome> [<secret>]`, severity `INFO`, `WARN` (denied) or
  `ERROR` (failure), with the fields as attributes (`sourceorrery.vault`,
  `sourceorrery.event.id`, `sourceorrery.operation`, `sourceorrery.outcome`,
  `sourceorrery.actor`, `sourceorrery.secret`, `sourceorrery.version`,
  `sourceorrery.detail`); the verification is the last record, body `audit
  chain verification: intact|broken`, with `sourceorrery.audit.*`
  attributes. The endpoint defaults to `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`,
  else `OTEL_EXPORTER_OTLP_ENDPOINT` with `/v1/logs` appended; headers come
  from `--header KEY=VALUE` and `OTEL_EXPORTER_OTLP_HEADERS`. An `https://`
  collector's certificate is verified against the operating system's
  certificate store. A collector that answers anything but 2xx fails the
  export, with the status in the error. Built with the Cargo feature `otlp`
  (on by default); without it the command says so and JSON Lines remains.
* `--since TIME` starts from that time; `--follow` keeps the vault open and,
  after the backlog and its trailer, exports each new event as it is
  recorded (looking every `--interval` seconds, default 2) until stdout
  closes or the process is stopped. Reading the log is not itself audited,
  so following adds nothing to it.

Exported records are the metadata the log holds, never a value. A secret
kept at a provider also appears in that provider's own trail; `audit`
says where to look for each provider the vault's secrets are kept at
([providers](providers/index.md)).

### A truncated log blocks the vault

If rows were removed from the end of the log since the last write, the
first command that opens the vault fails with `crypto` ("audit log
integrity: rows removed after event N …"): the vault judges every row
against the newest checkpoint in the log, so a shortened log is not
consulted. That refusal records the truncation (`audit_verify` /
`failure`), and from then on **every** command that opens the vault, and
every operation, fails with `crypto` naming that event ("… the truncation
detected at event 42 (…) is unacknowledged; the vault is blocked until
…"). Each refusal is recorded too.

The one exception is `audit` itself, which opens a blocked vault for
inspection: `audit` lists the log (and warns on stderr that the vault is
blocked), `audit --verify` reports the chain, and `audit --acknowledge`
lifts the block. Such an open writes `vault_open` / `success` with detail
`inspection (truncation unacknowledged)`, skips the retention purge, and
still refuses every secret operation. `ui` opens vaults the same way so
that its audit log view works on a blocked vault; it shows nothing else
there and cannot acknowledge.

Treat a truncation as evidence that the file was edited. Whatever the
missing events recorded — a change of settings, a deletion, a new version
— is gone, and an attacker who removed them may also have put back older
copies of the rows they covered, or of the vault's settings (the view
check, the connections), which the surviving history can no longer tell
from the truth. Compare the log, the secrets and the settings with an
exported copy ([`vault export`](#vault)), then:

```
sourceorrery audit --acknowledge --vault development
```

prints the truncation events, asks for confirmation (`--yes` answers it,
for automation; in a non-interactive session without `--yes` the command
aborts and the vault stays blocked) and appends one keyed `audit_verify` /
`success` event, `truncation acknowledged (event 42)`, which also records
the vault's settings as they are now. After that the vault accepts
commands again, with the surviving history and those settings as its record;
`audit --verify` keeps reporting the truncation (`truncations` stays 1,
`unacknowledged` becomes 0, the result stays `BROKEN`). The acknowledgement
covers every truncation detected before it and nothing after: a truncation
detected by another process between listing and acknowledging is refused
with `invalid_argument`, and a log found shortened again at that moment is
recorded and refused. With nothing to acknowledge the command says so and
exits 0.

## Project manifest: `init`, `import`, `check`, `run`

Without `--manifest`, the commands look for `sourceorrery.toml` in the
current directory and its parents, no further than the repository (the
first directory with a `.git` entry), the home directory, and, on Unix,
directories and files owned by the home directory's owner: a manifest
decides which vault a name means, so one planted in `/tmp` or a shared
parent is never picked up. `--manifest FILE` uses the file it names.

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
```

Any other key — in particular `value`, a per-secret `vault` or a
`[vaults.*]` table — is a parse error, reported by key name and position
without repeating the offending text. Where a secret is kept is the
vault's business: the vault file, or a provider through one of its
connections; the manifest names the vault and the secrets. `env` names
must be unique ignoring case (Windows environments are case-insensitive)
and may not start with `SOURCEORRERY_`.

How a secret is rotated is a `[rotation.<name>]` table naming the commands
`secret rotate` runs (each the program and its arguments, no shell) and the
grace period; it cannot hold a value either:

```toml
[rotation.database-password]
issue = ["./scripts/db-rotate.sh", "issue"]        # stdout is the new value
validate = ["./scripts/db-rotate.sh", "validate"]  # exit 0 accepts the candidate
retire = ["./scripts/db-rotate.sh", "retire"]      # revokes the previous credential
retire_after = "7d"
```

See [rotation](rotation.md) for what each command receives.

| Command | Description |
|---------|-------------|
| `init [VAULT] [--project-name NAME] [--all \| --secret NAME...] [--path FILE] [--theme T]` | Write the project's `sourceorrery.toml` from the vault's secrets, by name, or add to the one there, and record the folder in the vault (below). |
| `init --integration AGENT[,AGENT...] [--scope project\|user] [--skills-dir DIR]` | Install the SourceOrrery skills for AI coding agents (below). |
| `import FILE [--dry-run] [--manifest-only] [--only KEY]... [--exclude KEY]... [--overwrite] [--storage STORAGE] [--manifest FILE \| --no-manifest]` | Move a `.env` file into the vault and declare its keys (below). |
| `check [--manifest FILE] [--access]` | Verify every entry resolves to an accessible version. Reads **metadata only**; writes no `secret_get` audit rows. Fails if a required secret is missing. `--access` also reads each value and discards it, so the status says whether this identity may read the secret and not only inspect it (a provider can allow metadata and deny values); that is an audited read. |
| `run [--manifest FILE] -- COMMAND [ARGS...]` | Resolve every entry and start `COMMAND` with the values in its environment (plus `SOURCEORRERY_PROJECT`). Missing required secrets abort before the child starts. Every variable the manifest names is the vault's to set: an optional secret that does not resolve (missing, disabled, outside its window, deleted) leaves its variable absent in the child, never a value of that name inherited from this environment (on Windows matched in any case). Other variables pass through. The child never inherits the recovery-key, password or code variables. `--vault` overrides the manifest's vault. |

The parent resolves values in memory without printing them, then passes
them to the child through its environment. Processes with permission to
inspect the child can read that environment; the child and its dependencies
can also log or copy values. See the [threat model](threat-model.md).

### `init`: the manifest from the vault

`init` needs a vault on this machine and reads its catalog (names, where
each is kept, descriptions) without the view check: it never needs a
value. The vault is the one an existing manifest names (another one asked
for is refused; a missing one points at `vault import` and `vault
create`), else `VAULT` or `--vault`, else the only vault on this machine.

On a terminal, with no secret picked by a flag, `init` shows its own
screens:

| Screen | What it does |
|--------|--------------|
| Vault | Which vault, when there is more than one. |
| Project | The project's name (default: the folder's) and where the manifest goes. |
| Secrets | The vault's secrets as a checkbox list with **All**, a filter (`/`), and each secret's storage, environment variable and description. With a manifest already there, its secrets are ticked, and one the vault lacks is marked: Enter gives it a value. |
| New secrets | A loop: "Add a new secret to the vault for this project?" A new one has a name (checked as typed), its value twice in hidden fields, its storage when the vault has connections, a description and its variable; **Store** puts it in the vault at once. |
| Review | What the manifest will declare, each with a `required` tick, what is taken out, and what was stored on this run. Nothing is written before **Write sourceorrery.toml**; leaving earlier says which secrets stayed in the vault. |
| Done | The manifest, and next: `sourceorrery run -- <your command>`, `sourceorrery check`. |

<!-- walkthrough: init -->

Without a terminal, `--all` declares every secret the vault holds and
`--secret NAME` (repeatable) the ones named; there is no way to store a
value from here, so a script stores new secrets first (`secret set NAME
--stdin`). Each pick is declared as `[secrets.<name>]` with `required =
true` and `purpose` from its description. An existing manifest is edited
in place: new entries land after its other secrets and every other byte
(comments, `env` overrides, `version` pins, `[rotation.*]` tables) stays.
Writing records the folder in the vault (`project_link`), which the `ui`
lists under Projects.

### `import`: moving a `.env` file into a vault

> [!NOTE]
> Create the destination vault first. `--dry-run` stores no
> secret values and does not edit the manifest, but opening an existing
> vault and inspecting metadata still appends audit events.

```bash
sourceorrery import .env --dry-run      # preview key names and planned changes
sourceorrery import .env                # store the values, declare the keys
sourceorrery --vault test import .env.test --storage aws-secrets-manager
sourceorrery import .env.example --manifest-only
```

Each `KEY=value` becomes a secret named after the key in lower case with
hyphens (`DATABASE_URL` → `database-url`), stored as a new version in the
vault (`--vault`, else the manifest's vault, else `development`), where
`--storage` says (the vault file by default), and tagged
`imported-from=<file name>`. Each key is declared in the nearest
`sourceorrery.toml` (created if there is none) by appending
`[secrets.<name>]` entries, so the file's comments and existing entries are
kept; an `env` line is added when the default name would not deliver the
original variable (`apiKey` → `env = "apiKey"`).

Nothing the command prints contains a value: the table (or `-o json`)
lists each key, its secret name, what happened in the vault and in the
manifest, and a note. A "key" is file text, and on a line that is not
really an assignment (a connection string or the end of wrapped base64 on
a line of its own) the text before `=` can be part of a value, so a key
that is not shaped like a variable name, or whose value is only `=`
padding, is shown as `(not shown)`, in the table, in JSON and in errors,
and skipped. A secret the vault already holds is left as it is
(`--overwrite` stores a new version), so the command can be run again.
Keys that cannot become manifest entries are reported and skipped: an
invalid environment variable name, a name starting with `SOURCEORRERY_`,
an empty value. A key assigned twice, two keys that would map to the same
secret, a syntax error (reported by line number only) or a manifest that
would become invalid stops the command before anything is stored.
`--manifest-only` declares the keys without opening a vault, for
`.env.example` files.

> [!IMPORTANT]
> The input file is never deleted or rewritten. Inspect the per-key report,
> run `sourceorrery check`, and test the application before removing the
> plaintext file. Imports are not one transaction across the vault and the
> manifest: a later storage or file-write failure can leave earlier secrets
> imported. Correct the reported problem and rerun; existing secrets are
> preserved unless you explicitly use `--overwrite`.

The syntax is what python-dotenv, dotenv for Node and godotenv share:
`KEY=value` with optional `export`, `#` comments, single quotes and
backticks literal, double quotes with `\n`, `\r`, `\t`, `\"` and `\\`
escapes, multi-line quoted values. Nothing is expanded: a value containing
`${...}` is stored as written and noted.

### `init --integration`: skills for AI coding agents

> [!NOTE]
> These skills guide an agent's workflow; they do not prevent
> a process running with your credentials from opening the vault.

```bash
sourceorrery init --integration claude
sourceorrery init --integration cursor,codex --scope user
sourceorrery init --integration all
```

Writes two skills, `sourceorrery` and `sourceorrery-migrate-env`, in the
Agent Skills format to the directory the agent reads: `claude` (and a
subagent), `gemini`, `copilot`, `antigravity`, `cline`, `codex`, `cursor`,
`hermes`, `kilocode`, `kimi`, `kiro`, `opencode`, or `all`. The skills are
compiled into the binary; nothing is downloaded. `--scope user` installs
them for every project on this machine, and `--skills-dir DIR` anywhere
else; neither writes a manifest. In a project, the manifest is written
too when `--all` or `--secret` picks secrets. Running it again updates the
files SourceOrrery wrote and leaves alone a skill of the same name that it
did not. Paths per agent, the Claude Code plugin and what the skills do:
[AI coding agents](ai-agents.md).

## `ui`

```
sourceorrery ui [--vault NAME] [--theme dark|light|terminal] [--lock-after MINUTES] [--read-only]
```

An interactive browser for the vaults in the home directory, which can
also change their secrets' metadata. It shows **metadata only**. Its
browsing interface has no operation returning a stored value, so screen
buffers and metadata snapshots do not contain secret values. The process
still holds the opened vault key and briefly handles a new value entered
at the hidden prompt. Stored text is escaped as in every other table (see
`--output` above), so metadata in the file cannot drive the terminal.
Times are UTC.

| View | Shows |
|------|-------|
| `1` Overview | The vault at a glance. The header says what the view check asks for and where the vault keeps secrets. Panels: secrets by status and by storage, by expiry, and what expires or activates next; the audit chain as `audit --verify` would report it (`v` checks it again); 14 days of activity, denials and failures marked, with the last value read and the last failed open; the vault (created, file, deletion, how it opens); the view check (password, hint, authenticator, when the recovery key was issued; `c` changes it); storage (each connection's secrets, sign-in, last test and target, or that its provider could not be reached); projects (found and missing). |
| `2` Secrets | Every live secret: status, storage, short version id, last update, expiry, the projects whose manifest declares it, tags. `Enter` opens its details: every field, where it is kept, the projects that use it, the `sourceorrery://` reference, every version (newest first), and the secret's recent audit events. |
| `3` Projects | The project folders the vault records (by `init`): path, name, the number of secrets their manifest declares, and whether the folder's `sourceorrery.toml` is there (✓) or gone (✗), as found when the vault was read. `Enter` shows the manifest's secrets and whether each resolves in the vault, as `check` would say from metadata. |
| `4` Deleted | Soft-deleted secrets, their purge date and the days left. `Enter` shows the fields and recent activity; a deleted secret's versions cannot be listed until it is recovered. |
| `5` Audit log | The newest 1000 events, denials and failures marked. |
| `6` Vaults | The vault files in the home directory with size and modification time. Listing them needs no opening; `Enter` opens one, `n` creates one and `c` changes the selected one on the [setup screens](#setup-a-vault-on-screens). |

<!-- walkthrough: browser -->

**Opening a vault.** The vault named by `--vault` or the manifest is
opened, and its view check asked, **before** the screen is taken over,
with the usual order and prompts; if that fails, the command fails as any
other would. With no vault named, `ui` starts on Vaults. Opening a vault
from there suspends the screen for the same prompts (if any are needed)
and comes back to the browser. `ui` needs a terminal on stdin and stdout
and has no JSON output; both are checked before anything is opened, so a
refused start prompts for nothing and records nothing. Secrets a
connection stores are listed at its provider, one listing per connection;
a provider that cannot be reached is shown on the Overview, and the rest
of the vault is shown.

**Locking.** After `--lock-after` minutes without a key (default 10,
`SOURCEORRERY_UI_LOCK_AFTER`; `0` never locks), and at once on `L`, the
browser drops the open vault: its handle goes, and with it the vault key,
which is zeroised; everything read from it goes too. `Enter` opens it
again, asking what opening it asks, view check included.

The last 30 seconds show a countdown. Display ticks do not refresh metadata
or extend the session. Synchronous provider work must return before input
or locking can resume; the operation message makes that limit explicit.

**Actions and complete details.** `F2` opens a contextual menu with the
same commands as the keyboard shortcuts. Unavailable actions explain why;
moving through the menu performs no write or provider read. `i` opens the
complete cached metadata, and `!` opens a complete message. Both scroll
without fetching more data and return to the same underlying view.

Tables retain name/status first and hide lower-priority columns on narrow
screens. An ellipsis marks clipped metadata; use `i` or explicit details
for the full field. Counts distinguish matching rows from the visible row
range. Help, project declarations, overview panels and form reviews scroll
at compact sizes. Non-secret text fields support cursor movement and
mid-string edits; hidden secret prompts retain their own input handling.

**Changes**, unless `--read-only` is given:

| Key | Change | The vault records |
|-----|--------|-------------------|
| `space` | Enable or disable the selected version (in details: the version selected there; in the list: the newest) | `secret_update` |
| `e` | Change that version's metadata: enabled, content type, tags, not before, expires | `secret_update` |
| `n` | A new version of the secret, starting from the newest version's content type and tags | `secret_set` |
| `a` | A new secret, in the storage picked (the vault file or one of its connections); a new version if a live secret has the name | `secret_set` |
| `d` | Delete the secret: soft in a recoverable vault, for good in a purgeable one | `secret_delete` |
| `u` | Recover a deleted secret (Deleted view) | `secret_recover` |
| `x` | Forget a project whose folder or manifest is gone (Projects view); the disk is not touched | `project_unlink` |
| `c` | Change the vault's settings (view check, recovery key, storage) on the setup screens, in place of the browser | what the screens change |
| `n` (Vaults) | Create a vault on the setup screens | `vault_create` and the rest |

Every change is checked first with the vault's own rules (names, tags,
time windows) and what the secret's storage can express (a provider that
keeps properties per secret changes only the newest version; Azure Key
Vault cannot remove a time window), so one the vault or its provider would
refuse is never sent, and then shown for confirmation; `Enter` makes it,
`Esc` drops it. Deleting for good must be confirmed by typing the
secret's name. Afterwards the browser reads the vault again. A value is
never typed into the browser: for `n` and `a`, confirming leaves the
screen and asks for it twice at the same hidden prompt as `secret set`,
then stores it and comes back; an empty value, or two that differ, store
nothing. Purging, destroying and acknowledging a truncation are not
available in the browser; nothing can be changed in a blocked vault.

**A blocked vault.** Vaults are opened for inspection, as `audit` opens
them. One blocked by an unacknowledged audit-log truncation (see `audit`
above) shows its audit log and a callout naming the truncation, and
nothing else: the browser never asks it for secrets, since each refusal
would be recorded. Acknowledge with `sourceorrery audit --acknowledge`.

**Search.** `/` filters the current view; each view keeps its own filter.
Words match anywhere in a row (all of them, in any order, case ignored).
Qualifiers narrow by one field; several of one kind mean any of them:

| View | Qualifiers |
|------|------------|
| Secrets, Deleted | `tag:KEY`, `tag:KEY=VALUE`, `status:enabled\|disabled\|pending\|expired`, `type:TEXT` (content type), `expires:<30d` (expires within that many days, or has expired) |
| Audit log | `op:TEXT`, `outcome:success\|denied\|failure`, `secret:TEXT`, `actor:TEXT` |

A qualifier for the other kind of view matches nothing. `Enter` keeps the
filter; `Esc` clears it.

`f` opens filter categories with counts computed from cached metadata.
Selecting another facet of the same kind replaces that qualifier; typed
queries still support same-kind OR alternatives. Matching words are
highlighted. `s` offers Secrets name/updated/expiry and Audit timestamp
sorting; missing dates stay last. Sorting and refresh retain the selected
object by its full identity, or clear selection if it disappears.

| Key | Action |
|-----|--------|
| `↑` `↓` / `k` `j` | Move the selection (in details: the versions) |
| `PgUp` `PgDn` | Move by a screenful |
| `Home` `End` / `g` `G` | First / last |
| `Tab` `Shift-Tab` / `←` `→` / `1`–`6` | Switch view |
| `Enter` | Details of the selected secret or project; open the selected vault |
| `Esc` | Back: close the help, the search box, the details; clear the filter |
| `/` | Search |
| `F2` | Contextual Actions and unavailable reasons |
| `f` / `s` | Cached filters / sorting |
| `i` / `!` | Complete cached metadata / message details |
| `t` | Preview Dark, Light or Terminal; Enter applies, Esc restores |
| `r` | Read the vault again (on Vaults: list the files again) |
| `v` | Check the audit chain again |
| `L` | Lock now: drop the vault and wipe its key |
| `space` `e` `n` `a` `d` `u` `x` `c` | Changes (see above) |
| `?` | Keys and search syntax |
| `q` / `Ctrl-C` | Quit |

What the vault records: metadata is read when first shown and retained
until explicit refresh or a confirmed change needs a reload. Navigation,
sorting, filtering, menus, theme changes and cached inspection do not
introduce vault/provider reads.

| Browser action | Audit events |
|----------------|--------------|
| Opening a vault | one `vault_open`, and a `guard` when its view check is asked |
| The secret list: on opening, and on each `r` | one `secret_list`, and one for each connection that stores secrets (its provider's listing) |
| The deleted list: the first time the Overview or the Deleted view is shown after opening or `r` | the same |
| A secret's details: the first time they open after opening or `r` | one `secret_inspect` |
| The audit log, verifying the chain, the vault's keys, connections, view check and projects, a project's manifest on disk, the vault list, searching, moving, redrawing, locking | none |

What is shown is a snapshot: a change made from another terminal appears
after `r`. The successful-load time remains visible. A failed refresh
keeps its failure state and last successful time; complete error details
remain available. Refresh and uncached detail opening display an operation
message before blocking work; neither promises cancellation while blocked.

| Theme | Env | Look |
|-------|-----|------|
| `dark` (default) | `SOURCEORRERY_THEME` | The documentation site's dark palette: warm charcoal, navy ink, callout colours for status and messages. Painted over the whole screen. |
| `light` | | The site's light "paper" palette, painted the same way. |
| `terminal` | | The terminal's own background and named colours, as the banner uses. |

`dark` and `light` use 24-bit colour on Windows and wherever `COLORTERM`
says `truecolor`, and the nearest xterm 256 colours elsewhere (macOS
Terminal, for one). `NO_COLOR` turns colour off in every theme. The same
themes draw the setup screens and `init`'s.

The browser, `init`'s screens and the setup screens are the `ui` cargo
feature of `sourceorrery-cli`, on by default. A build without it
(`--no-default-features --features os-keyring`) has no `ui` command, and
`setup` and `init` print and take flags instead.

## `completions`

```
sourceorrery completions bash|zsh|fish|powershell|elvish
```

## Examples

```bash
# On a terminal: a vault on the setup screens, then a project
sourceorrery setup
sourceorrery ui              # add secrets (a), browse
sourceorrery init            # in the project's folder

# A script: the vault, its password, a secret, the manifest
sourceorrery vault create development --recovery-key-out development.recovery-key \
  --password-file password.txt
printf '%s' "$DB_PASSWORD" | sourceorrery secret set database-password --vault development --stdin
sourceorrery init development --secret database-password

# The same vault from WSL, a container or CI: its recovery key from a file
export SOURCEORRERY_HOME=/mnt/c/Users/me/AppData/Local/sourceorrery
export SOURCEORRERY_RECOVERY_KEY_FILE=/run/secrets/development.recovery-key
sourceorrery check
sourceorrery run -- ./deploy.sh
```
