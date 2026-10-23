# CLI reference

> [!NOTE]
> This reference targets **0.1.4**, including `import` and
> `init --integration`. Check your installed version with
> `sourceorrery --version`.

```
sourceorrery [--vault NAME] [--home DIR] [-o table|json] [--passphrase-file FILE] [--code CODE] [-v] <command>
```

| Global option | Env | Meaning |
|---------------|-----|---------|
| `--vault NAME` | `SOURCEORRERY_VAULT` | Vault to use. Default: `[project].vault` from the nearest `sourceorrery.toml`. |
| `--home DIR` | `SOURCEORRERY_HOME` | Directory holding vault files. |
| `-o, --output table\|json` | | Output format. Errors in JSON mode are `{"error":{"code","message"}}` on stderr. In table mode, control and bidi formatting characters in stored text (labels, audit actors and details) are shown as `\u{..}` escapes. |
| `--passphrase-file FILE` | `SOURCEORRERY_PASSPHRASE_FILE` | Read the vault passphrase from a file (automation). |
| | `SOURCEORRERY_PASSPHRASE` | Passphrase from the environment. CI only; environment variables are visible to process inspection. |
| `--code CODE` | `SOURCEORRERY_TOTP` | A six-digit code from the authenticator app, for a command the [reveal guard](#the-reveal-guard) asks one of (automation). Without it the code is asked for on the terminal; a code is never read from a pipe. |
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

## `setup`: the guided first run

```
sourceorrery setup [--secret NAME] [--project-name NAME] [--path FILE] [--guide] [--theme dark|light|terminal]
```

Six screens on the terminal, from the first vault to the first `run`: the
vault (a passphrase typed with a live strength meter, or generated and
shown once; the OS credential store as a second key where it exists, or
an existing vault used as it is), the first secret (`database-password` by
default, typed against the same meter or generated and stored unseen),
recovery (five recovery codes shown once behind a "written down" tick box,
an optional hint), the second factor (a QR code to scan, kept once a code
matched), the [reveal guard](#the-reveal-guard), and the project (the
manifest written unless one exists, checked, and the `run` line). Every
step is an ordinary command, which the last screen and
[First run](getting-started.md) list; `--guide`, or no terminal, prints
those steps instead (`-o json`: `vault`, `steps`). `--vault` names the
vault (default `development`). Hidden fields are drawn as dots from their
length; nothing typed as a secret is kept by the screens. Cargo feature
`ui`; without it only the guide is printed.

## Unlocking

The CLI tries OS-keyring protectors first (Windows Credential Manager,
macOS Keychain or Secret Service, without prompting). For passphrase
protectors it selects the non-empty `SOURCEORRERY_PASSPHRASE` variable,
otherwise `--passphrase-file` / `SOURCEORRERY_PASSPHRASE_FILE`. If needed,
it prompts on stderr when stdin is a terminal, up to the three-attempt
limit. Failed attempts are audited.

A **recovery code** (`vault recovery codes`) unlocks a vault in place of
its passphrase, wherever a passphrase is accepted: typed at the prompt or
supplied through `SOURCEORRERY_PASSPHRASE` or a file. Case, hyphens and
the look-alike letters (`I`/`L` for `1`, `O` for `0`) do not matter. If the
vault has a **passphrase hint** (`vault passphrase hint`) the prompt shows
it first; the hint is stored in clear and is not authenticated, so it is
only ever a reminder for the person reading it.

> [!TIP]
> The CLI does not fall back from an incorrect environment passphrase to a
> configured file. Unset `SOURCEORRERY_PASSPHRASE` when using a file. SDKs
> try their configured passphrase candidates in sequence and never prompt.

## `vault`

> [!WARNING]
> `vault destroy` removes the vault permanently. A purgeable vault also
> makes `secret delete` immediate and irreversible. Use the default
> recoverable vault unless you deliberately need permanent deletion.

`setup`, `vault create`, `vault protector`, `vault destroy`, `vault migrate`,
`audit --verify`, `audit --acknowledge`, `audit export`, `backup`,
`restore` and `ui` are about the vault file and refuse a
[remote vault](providers/index.md) by name; plain `audit` on one prints
where the provider keeps its trail; the `secret` commands, `check`, `run`
and `import` work against either kind.

| Command | Description |
|---------|-------------|
| `vault create NAME [--protector os-keyring\|passphrase] [--retention-days 7-90] [--purgeable] [--allow-weak]` | Create a vault. Default protector: OS keyring when available, otherwise passphrase (prompted twice). A passphrase typed at the prompt must rate at least "good" on the strength estimate (below) unless `--allow-weak`; one from `SOURCEORRERY_PASSPHRASE` or `--passphrase-file` is accepted with a warning on stderr when it rates lower. `--purgeable` disables soft delete. |
| `vault list` | Vaults in the home directory, and the remote vaults the nearest `sourceorrery.toml` declares with their provider and location. JSON output is one object per vault (`name`, `kind`, and `path` or `provider` and `location`). |
| `vault info` | Metadata and protectors of the selected vault, what the [reveal guard](#the-reveal-guard) asks for, whether a second factor is enrolled and verified (never its secret), the recovery codes installed (by label) and the passphrase hint; for a remote vault, what its provider reports. |
| `vault protector list` | Installed protectors. |
| `vault protector add --kind passphrase\|os-keyring [--label L] [--allow-weak]` | Add another way to unlock (e.g. a passphrase for WSL/Docker/CI). At most 8 passphrase protectors: unlock tries no more than that, so a ninth is refused rather than installed and never tried. The strength rule of `vault create` applies. |
| `vault passphrase generate [--length N]` | Print a random passphrase (letters, digits and symbols from the OS random source; 20 characters, about 125 bits, by default; at least 12) to stdout, once. It is not stored: pipe it where it is needed or write it down. `-o json` gives `passphrase`, `length`, `bits`. |
| `vault passphrase check` | Read a passphrase from stdin or a hidden prompt and print the strength estimate: a score 0 (guessable) to 4 (strong), the estimated bits of guessing work and what weakened it (a common password, a dictionary word with the usual substitutions, repeated characters, a keyboard or alphabet sequence, a year, a short length, a capital first letter with a digit or symbol last). It is an estimate from those rules, not a dictionary; nothing is stored or echoed. "good" (score 3) is what a vault passphrase needs. |
| `vault protector remove ID_OR_LABEL` | Remove a protector. The last one cannot be removed. The OS-keyring entry is deleted after the change is committed, and only if it is provably this vault's. |
| `vault passphrase set [--new-from-file FILE] [--allow-weak]` | Replace the vault passphrase: the current one is taken from `SOURCEORRERY_PASSPHRASE`, `--passphrase-file` or a hidden prompt and checked, a code too when the guard asks for one, then the new one is prompted twice (strength rule of `vault create`) or read from `--new-from-file`. The protector keeps its label; recovery codes are unchanged. |
| `vault passphrase hint [TEXT \| --clear]` | Set, show or clear the hint shown at the passphrase prompt. At most 120 characters, no control characters, and never something that itself unlocks the vault. It is stored in clear in the vault file: a reminder, not a secret. |
| `vault recovery codes [--count N]` | Print N (default 5, at most 7) new recovery codes to stdout, once, and install them as passphrase protectors labelled `recovery-1..N`, replacing every earlier recovery code. Each is 25 characters in five groups (125 bits) from an alphabet without look-alikes and unlocks the vault in place of the passphrase. Guarded. `-o json`: `vault`, `codes`, `labels`, `replaced`. |
| `vault 2fa enable [--show-uri] [--no-verify]` | Enrol an authenticator app as the second factor: a QR code is drawn on stderr (the `otpauth://` URI itself only with `--show-uri`, for a user who cannot scan), then one code from the app is asked for (`--code`, or on the terminal, three attempts) and the enrolment is kept only when it matches. `--no-verify` keeps it unverified for `vault 2fa verify` later; until verified it counts for nothing and the guard cannot ask for it. Guarded; a verified enrolment must be disabled before another is made. `-o json` prints the base32 `key` and the `uri` once instead of the QR code. |
| `vault 2fa verify` | Prove an enrolment made with `--no-verify` by entering one code. |
| `vault 2fa disable` | Remove the second factor. The passphrase is asked for when the guard asks for it, and one code while the enrolment is verified; the guard then stops asking for a code. |
| `vault 2fa status` | Enrolled or not, verified or not, when, and what the guard asks for. Never the secret. |
| `vault guard [--reveal passphrase,second-factor\|none]` | Show or set what a reveal or export must present again (below). `passphrase`, `second-factor` (needs a verified enrolment) or both; `none` turns it off. Changing the guard passes the current guard first. |
| `vault destroy NAME [--yes] [--keep-os-key]` | Delete the vault file and the OS-keyring entries it provably owns (entries another vault file references are kept and reported). Irreversible. |
| `vault migrate NAME` | Upgrade a vault written by an older release (schema 1 or 2) to the current format. Explicit on purpose: the rows it finds are taken on trust once, so only migrate a file you trust. A file that was already in the current format, or whose audit log was truncated, is refused; a migrated vault with a recorded, unacknowledged truncation stays blocked until `audit --acknowledge`. |

### The reveal guard

Unlocking a vault lets a process read values; the **reveal guard** is a
second check for the moments a person asks to *see* one. When it is on
(`vault guard --reveal ...`), these commands ask for the vault passphrase
again, a code from the authenticator app, or both, before they go on:
`secret get --reveal`, `backup`, `vault protector add` and `remove`,
`vault recovery codes`, `vault 2fa enable`, `vault guard` itself and (for
the code) `vault passphrase set` and `vault 2fa disable`. The passphrase
is taken from where an unlock takes it (`SOURCEORRERY_PASSPHRASE`,
`--passphrase-file`, else a hidden prompt) and a recovery code counts;
the code comes from `--code` / `SOURCEORRERY_TOTP` or a visible prompt on
the terminal, never from a pipe, so a script that has neither is refused
rather than hung. A code is accepted once, for the current step or the
one either side of it (30 seconds each), and never for a step at or
before the last accepted one.

A refusal is `permission_denied`, prints nothing of the value, and is
audited under `guard` with what was checked and the outcome. The guard
is deliberately narrow: `run`, `check`, the `ui` browser (which never
shows a value) and every SDK are untouched, so an application keeps
starting with its vault unlocked by the OS keyring while a person at the
keyboard, or an agent driving the CLI, must present the passphrase and
the phone to read an API key out. It is not a boundary against code
running as you with the same credentials in its environment; see the
[threat model](threat-model.md).

```
sourceorrery vault 2fa enable --vault development          # scan, then type one code
sourceorrery vault guard --reveal passphrase,second-factor --vault development
sourceorrery secret get database-password --vault development --reveal
Passphrase of vault 'development' to reveal a secret:
Code from the app: 123456
```

## `secret`

| Command | Description |
|---------|-------------|
| `secret set NAME [--stdin \| --from-file FILE] [--confirm] [--allow-empty] [--keep-trailing-newline] [--content-type T] [--tag K=V]... [--not-before T] [--expires T] [--disabled]` | Store a **new version**. Value source: `--from-file`, else stdin when piped (`--stdin` to force), else a hidden prompt. One trailing newline from stdin is stripped. There is no `--value` option. |
| `secret get NAME [--version ID] [--reveal] [--raw]` | Metadata (default). `--reveal` prints the value + newline; `--raw` omits the newline. `-o json --reveal` adds `value` (or `value_hex` for non-UTF-8). Without `--version`, the newest *accessible* version is used. `--reveal` is subject to the [reveal guard](#the-reveal-guard). |
| `secret list [--deleted] [--limit N] [--after NAME]` | Live secrets (newest version each), or soft-deleted ones, in name order. Metadata only. `--limit N` shows one page of up to N and, while names follow, the `--after NAME` that continues it (the last page can be empty when the names left were deleted ones, or live ones under `--deleted`); `-o json` then prints `{"items": [...], "continuation": "NAME"}` instead of the plain array. Each page is one `secret_list` audit event. |
| `secret versions NAME` | Every version, newest first, with status. |
| `secret update NAME [--version ID] [--enable\|--disable] [--content-type T\|--clear-content-type] [--tag K=V...\|--clear-tags] [--not-before T\|--clear-not-before] [--expires T\|--clear-expires]` | Change metadata of one version. Never the value. |
| `secret delete NAME` | Soft-delete all versions (recoverable until retention ends). Immediate in a purgeable vault. |
| `secret recover NAME` | Undo a soft delete. |
| `secret purge NAME [--yes]` | Permanently remove a soft-deleted secret. |
| `secret rotate NAME [--manifest FILE] [--step rotate\|activate\|retire\|status] [--no-activate] [--retire-after D] [--now] [--stdin \| --from-file FILE] [--keep-trailing-newline] [--allow-empty]` | Rotate a credential: issue a new value (the manifest's `[rotation.NAME]` `issue` command, else stdin, a file or a prompt), validate it with the `validate` command, activate it (enable the new version, then disable the previous one), and retire the previous one with the `retire` command once `retire_after` (or `--retire-after`) has passed, in a later `--step retire` run; without a grace period, in the same run. State lives in `sourceorrery.rotation.*` tags; refusals carry the code `rotation`. `unsupported` on AWS Secrets Manager. See [rotation](rotation.md). |

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

Newest first, with each event's id. Operations: `vault_create`,
`vault_open`, `vault_migrate`, `secret_inspect` (metadata reads: properties,
versions, deleted-secret details), `protector_add`, `protector_remove`,
`secret_set`, `secret_get`, `secret_list`, `secret_update`,
`secret_delete`, `secret_recover`, `secret_purge`, `vault_backup` (one
per secret exported, with the version count), `secret_restore` (one per
version written from a backup), `audit_verify`
(a detected truncation with outcome `failure`, its acknowledgement with
outcome `success`), `guard` (the reveal guard: a passphrase re-check or a
second-factor code with outcome `success` or `denied`, the second factor
enrolled, verified or disabled, the guard or the passphrase hint changed;
the detail names which). Outcomes: `success`, `denied` (policy), `failure`.
Detail holds the error code or a short note — never a value, a code, a
secret or the hint.

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
  from `--header KEY=VALUE` and `OTEL_EXPORTER_OTLP_HEADERS`. A collector
  that answers anything but 2xx fails the export, with the status in the
  error. Built with the Cargo feature `otlp` (on by default); without it the
  command says so and JSON Lines remains.
* `--since TIME` starts from that time; `--follow` keeps the vault open and,
  after the backlog and its trailer, exports each new event as it is
  recorded (looking every `--interval` seconds, default 2) until stdout
  closes or the process is stopped. Reading the log is not itself audited,
  so following adds nothing to it.

Exported records are the metadata the log holds, never a value. A remote
vault has no local log: `audit --vault <remote>` prints where the
provider keeps its trail and the query that shows SourceOrrery's
operations there ([providers](providers/index.md); `-o json` gives
`provider`, `audit_trail`, `query` and `docs`), and `audit export` on one
is `unsupported` with the same pointer.

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
still refuses every secret and protector operation. `ui` opens vaults
the same way so that its audit log view works on a blocked vault; it
shows nothing else there and cannot acknowledge. Nothing else opens the
vault, and `vault migrate` is no way round it either.

Treat a truncation as evidence that the file was edited. Whatever the
missing events recorded — a change of policy, a deletion, a new version
— is gone, and an attacker who removed them may also have put back older
copies of the rows they covered, which the surviving history can no longer
tell from the truth. Compare the log and the secrets with a backup
([`backup` and `restore`](#backup-and-restore)), then:

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

## Project manifest: `init`, `import`, `check`, `run`

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

A vault that is not a local file is a `[vaults.<name>]` table naming its
provider and how to reach it, and nothing else; `payments-sandbox` above
could be:

```toml
[vaults.payments-sandbox]
provider = "hashicorp-vault"                 # or aws-secrets-manager
address = "https://vault.example.com:8200"
mount = "secret"
```

There is no key for a credential, so `token = "..."` is a parse error like
`value`; credentials come from the provider's own environment. A vault
name without a table is a local vault file, as before. The providers, their
keys and the commands that work against a remote vault are in
[providers](providers/index.md).

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
| `init [--project-name N] [--vault-name V] [--path FILE] [--force]` | Write a starter manifest. |
| `init --integration AGENT[,AGENT...] [--scope project\|user] [--skills-dir DIR]` | Install the SourceOrrery skills for AI coding agents (below). An existing manifest is kept. |
| `import FILE [--dry-run] [--manifest-only] [--only KEY]... [--exclude KEY]... [--overwrite] [--manifest FILE \| --no-manifest]` | Move a `.env` file into the vault and declare its keys (below). |
| `check [--manifest FILE] [--access]` | Verify every entry resolves to an accessible version. Reads **metadata only**; writes no `secret_get` audit rows. Fails if a required secret is missing. `--access` also reads each value and discards it, so the status says whether this identity may read the secret and not only inspect it (a remote provider can allow metadata and deny values); on a local vault that is an audited read. |
| `run [--manifest FILE] -- COMMAND [ARGS...]` | Resolve every entry and start `COMMAND` with the values in its environment (plus `SOURCEORRERY_PROJECT`). Missing required secrets abort before the child starts; an optional secret whose vault does not exist is skipped. The child never inherits `SOURCEORRERY_PASSPHRASE` or `SOURCEORRERY_PASSPHRASE_FILE`. `--vault` overrides the manifest's default vault. |

The parent resolves values in memory without printing them, then passes
them to the child through its environment. Processes with permission to
inspect the child can read that environment; the child and its dependencies
can also log or copy values. See the [threat model](threat-model.md).

### `import`: moving a `.env` file into a vault

> [!NOTE]
> Create the destination vault first. `--dry-run` stores no
> secret values and does not edit the manifest, but opening an existing
> vault and inspecting metadata still appends audit events.

```bash
sourceorrery import .env --dry-run      # preview key names and planned changes
sourceorrery import .env                # store the values, declare the keys
sourceorrery --vault test import .env.test
sourceorrery import .env.example --manifest-only
```

Each `KEY=value` becomes a secret named after the key in lower case with
hyphens (`DATABASE_URL` → `database-url`), stored as a new version in the
vault (`--vault`, else the manifest's vault, else `development`) and tagged
`imported-from=<file name>`. Each key is declared in the nearest
`sourceorrery.toml` (created if there is none) by appending
`[secrets.<name>]` entries, so the file's comments and existing entries are
kept; an `env` line is added when the default name would not deliver the
original variable (`apiKey` → `env = "apiKey"`).

Nothing the command prints contains a value: the table (or `-o json`)
lists each key, its secret name, what happened in the vault and in the
manifest, and a note. A secret the vault already holds is left as it is
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
else; neither writes a manifest. Running it again updates the files
SourceOrrery wrote and leaves alone a skill of the same name that it did
not. Paths per agent, the Claude Code plugin and what the skills do:
[AI coding agents](ai-agents.md).

## `backup` and `restore`

```
sourceorrery backup --out FILE [--secret NAME]... [--include-deleted] [--force]
sourceorrery restore FILE [--only NAME]... [--overwrite] [--keep-deleted] [--dry-run]
```

`backup` writes every live secret of the selected vault, every version with
its value (disabled and expired ones included), into one file sealed under
a passphrase of its own, asked twice, or taken from
`SOURCEORRERY_BACKUP_PASSPHRASE` for scripts; it is never a command-line
argument. When the vault's [reveal guard](#the-reveal-guard) is on, the
vault passphrase and a code are asked for first, as for a reveal.
`--secret` limits the backup to named secrets, `--include-deleted`
adds the soft-deleted ones with their deleted state, and an existing file
is replaced only with `--force`. The file is written readable by the
current user alone, and it is as sensitive as the vault: whoever has it
and the passphrase has the values. The command prints names and counts,
never a value; the export is recorded as one `vault_backup` audit event
per secret. The format is in [Backup file format](backup-format.md).

`restore` reads a backup into the selected vault (`--vault`, which may be
any vault, not only the one the backup came from): every version becomes
a new version of the target secret, oldest first, with its metadata kept
and two tags added, `sourceorrery.restored-from` (the original version id)
and `sourceorrery.restored-created-on`. A secret that already exists is
skipped unless `--overwrite` adds the versions on top; one the vault holds
soft-deleted is always skipped. A secret the backup holds as deleted comes
back live, or is soft-deleted again with `--keep-deleted`. `--only` limits
the restore to named secrets and `--dry-run` prints what would happen by
name. Each written version is one `secret_restore` audit event; restoring
is safe to repeat. A wrong passphrase is `backup_passphrase`, an altered
file `crypto`, a file from a newer release `backup_format`.

```
sourceorrery backup --out development-2026-10-22.sobackup --vault development
sourceorrery restore development-2026-10-22.sobackup --vault development-copy --dry-run
```

With `-o json`, both print `{"vault", "file", ...}` with the secrets'
names, version counts and outcomes only.

## `ui`

```
sourceorrery ui [--vault NAME] [--theme dark|light|terminal] [--lock-after MINUTES] [--read-only]
```

An interactive browser for the vaults in the home directory, which can
also change their metadata. It shows **metadata only**. Its browsing
interface has no operation returning a stored value, so screen buffers
and metadata snapshots do not contain secret values. The process still
holds the unlocked vault key and temporarily handles new values entered
at the hidden prompt. Stored text is escaped as in every
other table (see `--output` above), so metadata in the file cannot drive
the terminal. Times are UTC.

| View | Shows |
|------|-------|
| `1` Overview | The vault at a glance, and where a vault opens: secrets by status, by expiry, and what expires or activates next; the audit chain as `audit --verify` would report it (`v` checks it again); 14 days of activity, denials and failures marked, with the last value read and the last failed unlock; the vault's file and key protectors. |
| `2` Secrets | Every live secret: status, short version id, last update, expiry, tags. `Enter` opens its details: every field and the `sourceorrery://` reference, every version (newest first), and the secret's recent audit events. |
| `3` Deleted | Soft-deleted secrets, their purge date and the days left. `Enter` shows the fields and recent activity; a deleted secret's versions cannot be listed until it is recovered. |
| `4` Audit log | The newest 1000 events, denials and failures marked. |
| `5` Vaults | The vault files in the home directory with size and modification time. Listing them needs no unlock; `Enter` opens one. |

**Opening a vault.** The vault named by `--vault` or the manifest is
unlocked **before** the screen is taken over, with the usual unlock order
and passphrase prompt; if that fails, the command fails as any other
would. With no vault named, `ui` starts on Vaults. Opening a vault from
there suspends the screen for the same unlock (and prompt, if one is
needed) and comes back to the browser. `ui` needs a terminal on stdin and
stdout and has no JSON output; both are checked before anything is
unlocked, so a refused start prompts for nothing and records nothing.

**Locking.** After `--lock-after` minutes without a key (default 10,
`SOURCEORRERY_UI_LOCK_AFTER`; `0` never locks), and at once on `L`, the
browser drops the open vault: its handle goes, and with it the vault key,
which is zeroised; everything read from it goes too. `Enter` unlocks it
again, with the same unlock order and prompt as opening it.

**Changing secrets.** In the Secrets and Deleted views (and their
details), unless `--read-only` is given:

| Key | Change | The vault records |
|-----|--------|-------------------|
| `space` | Enable or disable the selected version (in details: the version selected there; in the list: the newest) | `secret_update` |
| `e` | Change that version's metadata: enabled, content type, tags, not before, expires | `secret_update` |
| `n` | A new version of the secret, starting from the newest version's content type and tags | `secret_set` |
| `a` | A new secret (a new version, if a live secret has the name) | `secret_set` |
| `d` | Delete the secret: soft in a recoverable vault, for good in a purgeable one | `secret_delete` |
| `u` | Recover a deleted secret (Deleted view) | `secret_recover` |

Every change is checked first with the vault's own rules (names, tags,
time windows), so one the vault would refuse is never sent, and then
shown for confirmation; `Enter` makes it, `Esc` drops it. Deleting for
good must be confirmed by typing the secret's name. Afterwards the
browser reads the vault again (one `secret_list`, and a `secret_inspect`
if details are open). A value is never typed into the browser: for `n`
and `a`, confirming leaves the screen and asks for it twice at the same
hidden prompt as `secret set`, then stores it and comes back; an empty
value, or two that differ, store nothing. Purging, protectors,
destroying, migrating and acknowledging a truncation are not available
in the browser; nothing can be changed in a blocked vault.

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

| Key | Action |
|-----|--------|
| `↑` `↓` / `k` `j` | Move the selection (in details: the versions) |
| `PgUp` `PgDn` | Move by a screenful |
| `Home` `End` / `g` `G` | First / last |
| `Tab` `Shift-Tab` / `←` `→` / `1`–`5` | Switch view |
| `Enter` | Details of the selected secret; open the selected vault |
| `Esc` | Back: close the help, the search box, the details; clear the filter |
| `/` | Search |
| `r` | Read the vault again (on Vaults: list the files again) |
| `v` | Check the audit chain again |
| `L` | Lock now: drop the vault and wipe its key |
| `space` `e` `n` `a` `d` `u` | Changes (see above) |
| `?` | Keys and search syntax |
| `q` / `Ctrl-C` | Quit |

What the vault records: everything is read once, when first shown, and
kept until `r`.

| Browser action | Audit events |
|----------------|--------------|
| Opening a vault | one `vault_open` |
| The secret list: on opening, and on each `r` | one `secret_list` |
| The deleted list: the first time the Overview or the Deleted view is shown after opening or `r` | one `secret_list` |
| A secret's details: the first time they open after opening or `r` | one `secret_inspect` |
| The audit log, verifying the chain, the protectors, the vault list, searching, moving, redrawing, locking | none |

What is shown is a snapshot: a change made from another terminal appears
after `r`.

| Theme | Env | Look |
|-------|-----|------|
| `dark` (default) | `SOURCEORRERY_THEME` | The documentation site's dark palette: warm charcoal, navy ink, callout colours for status and messages. Painted over the whole screen. |
| `light` | | The site's light "paper" palette, painted the same way. |
| `terminal` | | The terminal's own background and named colours, as the banner uses. |

`dark` and `light` use 24-bit colour on Windows and wherever `COLORTERM`
says `truecolor`, and the nearest xterm 256 colours elsewhere (macOS
Terminal, for one). `NO_COLOR` turns colour off in every theme.

The browser is the `ui` cargo feature of `sourceorrery-cli`, on by default.
A build without it (`--no-default-features --features os-keyring`) has no
`ui` command.

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
