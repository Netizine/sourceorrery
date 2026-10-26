# Rotating a secret

`sourceorrery secret rotate <name>` replaces a credential in four recorded
steps: **issue** a new value, **validate** it, **activate** it, and
**retire** the previous one once a grace period has ended. The issuer's side
(minting the new credential, checking it, revoking the old one) is a
command you name in the manifest; SourceOrrery runs it the way `run` runs a
program, with the value only in the child's environment, and records each
step as an ordinary audited operation on the vault. The workflow works
against any vault whose properties are per version: a local vault,
[HashiCorp Vault](providers/hashicorp-vault.md) and
[Azure Key Vault](providers/azure-key-vault.md); on
[AWS Secrets Manager](providers/aws-secrets-manager.md) it is `unsupported`
(below).

## The steps

| Step | What happens in the vault | What the hook does |
|------|---------------------------|--------------------|
| issue | a new version is written **disabled**, with the current version's content type and tags, tagged as a candidate of the version it replaces | `issue` prints the new value on its standard output; it receives the **current** value in the secret's environment variable so it can authenticate to the issuer. Without an `issue` command the value is read from stdin, a file or a hidden prompt, like `secret set` |
| validate | the candidate is tagged `validated`, still disabled | `validate` receives the **candidate** in the secret's environment variable and exits 0 to accept it. Any other exit status marks the candidate `failed`; it stays disabled and the current version stays current |
| activate | the candidate is enabled, **then** the previous version is disabled, so one version is always accessible; the end of the grace period is recorded | none |
| retire | the previous version is tagged `retired` (it stays in the vault, disabled: versions are immutable history and the contract has no per-version delete); the current one is `complete` | `retire` revokes the previous credential at the issuer; it receives the **current** value in the secret's environment variable and the retired version's id in `SOURCEORRERY_RETIRED_VERSION` |

Issue, validate and activate run in one process: a disabled version cannot
be read back through the contract, so only the process that issued a
candidate can validate it, and a candidate left in the `issued` state by a
crash is marked `failed` by the next rotation. Retirement runs in the same
process when there is no grace period, and in a later run of
`--step retire` when there is one.

Every hook also receives `SOURCEORRERY_SECRET` (the secret's name),
`SOURCEORRERY_ROTATION_STEP` (`issue`, `validate` or `retire`),
`SOURCEORRERY_PROJECT` (the manifest's project name) and, for `validate`
and `retire`, `SOURCEORRERY_VERSION` (the version the value belongs to).
The variables that open a vault or answer its view check
(`SOURCEORRERY_RECOVERY_KEY`, `SOURCEORRERY_RECOVERY_KEY_FILE`,
`SOURCEORRERY_PASSWORD`, `SOURCEORRERY_PASSWORD_FILE`, `SOURCEORRERY_TOTP`)
are removed from the hook's environment. So are the secret's own variable,
`SOURCEORRERY_VERSION` and `SOURCEORRERY_RETIRED_VERSION` whenever the
vault does not set them: when the current version cannot be read
(disabled, expired, deleted or missing), the issue hook runs without the
variable, never with a value the shell or an enclosing `sourceorrery run`
left behind. Any other failure to read it stops the rotation.
Hooks inherit the terminal for their own output; SourceOrrery prints
version ids and states, never a value.

## Declaring the hooks

```toml
[secrets.database-password]

[rotation.database-password]
issue    = ["./scripts/db-rotate.sh", "issue"]      # stdout: the new password
validate = ["./scripts/db-rotate.sh", "validate"]   # exit 0: it works
retire   = ["./scripts/db-rotate.sh", "retire"]     # revoke the old one
retire_after = "7d"                                 # days, hours or minutes
```

A hook is the program and its arguments, not a shell line, and runs in the
current directory. Every key is optional: without `issue` the value is
typed or piped; without `validate` the candidate is accepted as issued;
without `retire` retirement only records the state; without `retire_after`
the previous version is retired in the run that activates the new one. A
`[rotation.<name>]` table must name a secret declared in `[secrets]`, and
like the rest of the manifest it cannot hold a value.

A script for a database user might look like this (the value never appears
on a command line):

```sh
#!/bin/sh
set -eu
case "$1" in
  issue)     new="$(openssl rand -base64 32)"
             PGPASSWORD="$DATABASE_PASSWORD" psql -h db -U app -c "ALTER USER app PASSWORD '$new'" >/dev/null
             printf '%s' "$new" ;;
  validate)  PGPASSWORD="$DATABASE_PASSWORD" psql -h db -U app -c 'select 1' >/dev/null ;;
  retire)    : ;;   # a password has nothing to revoke; an API key would be deleted here
esac
```

## Running it

```console
$ sourceorrery secret rotate database-password
Issued version 7c2e… of 'database-password' (disabled until activated)
✓ Activated version 7c2e… of 'database-password'; version 3a91… is disabled
Version 3a91… is retired after 2026-10-30T04:12:09Z: run `sourceorrery secret rotate database-password --step retire` then

$ sourceorrery secret rotate database-password --step status
VERSION   STATUS    ROTATION    REPLACES  RETIRE ON
7c2e…     enabled   active      3a91…     2026-10-30T04:12:09Z
3a91…     disabled  superseded  -         -
version 3a91… awaits retirement after 2026-10-30T04:12:09Z (--step retire --now to retire earlier)

$ sourceorrery secret rotate database-password --step retire        # a week later
✓ Retired version 3a91… of 'database-password'; version 7c2e… is current
```

| Option | Meaning |
|--------|---------|
| `--step rotate` (default) | issue, validate, activate; retire at once when no grace period is set |
| `--step activate` | enable the validated candidate a `--no-activate` run left behind |
| `--step retire [--now]` | retire the previous version once the grace period has ended, or now |
| `--step status` | every version with its rotation state; what is waiting |
| `--no-activate` | stop after validation; the candidate stays disabled |
| `--retire-after 7d` | the grace period, overriding the manifest |
| `--stdin`, `--from-file FILE`, `--keep-trailing-newline`, `--allow-empty` | where the value comes from when there is no `issue` command, as for `secret set` |
| `--manifest FILE` | the manifest to read the hooks from (default: the nearest `sourceorrery.toml`) |
| `-o json` | one object per run: `candidate`, `previous`, `validated`, `activated`, `retire_on`, `retired` |

A secret that the manifest does not declare is rotated in the vault
`--vault` names, with the value from stdin and no hooks. `--vault` overrides
the manifest's default vault, as it does for `run`, never a vault an entry
names explicitly.

## What is recorded

The state lives in tags on the versions, so it survives a crash, is visible
in `secret versions` and `secret rotate --step status`, and travels with
an exported copy of the vault (`vault export`):

| Tag | On | Value |
|-----|----|-------|
| `sourceorrery.rotation.state` | every version a rotation touched | `issued`, `validated`, `failed`, `active`, `complete`, `superseded`, `retired` |
| `sourceorrery.rotation.previous` | a candidate and the version it became | the version it replaces |
| `sourceorrery.rotation.superseded-by` | a superseded or retired version | the version that replaced it |
| `sourceorrery.rotation.activated-on` | an activated version | when it was enabled |
| `sourceorrery.rotation.retire-on` | an `active` version | when its predecessor may be retired; removed on retirement |
| `sourceorrery.rotation.retired-on` | a retired version | when it was retired |

The user's own tags are carried from the version being replaced to the
candidate; `secret update --tag` replaces the whole tag set, so editing a
rotating secret's tags by hand also removes its rotation state.

In the audit log a rotation is one `secret_set` (the candidate) and several
`secret_update` events (validated, enabled, the previous version disabled,
retirement), each an ordinary operation with its outcome; the issue hook's
read of the current value and the retire hook's read of the current value
are `secret_get` events. There is no rotation-specific event.

Refusals carry the code `rotation` with the versions and times involved: a
validated candidate waiting for activation blocks a new rotation (`--step
activate` it, or let it fail validation), so does a version an earlier
rotation replaced that is still waiting to be retired (`--step retire`,
with `--now` inside its grace period: a new rotation would replace the
record that it awaits retirement, and its `retire` hook, which revokes it
at the issuer, would never run), there is nothing to activate or
retire, or the grace period has not ended. A grace period is at most
`3650d` (ten years).

## Where it does not work

AWS Secrets Manager keeps `enabled` and the other properties on the
**secret**, not on a version, so a disabled candidate cannot sit next to the
enabled current version; `secret rotate` answers `unsupported` before
writing anything (`SecretClient::capabilities` lacks
`PerVersionProperties`). Use the service's own rotation (Lambda rotation
functions) there. HashiCorp Vault keeps per-version properties in
`custom_metadata` and rotates like a local vault.

Rotation does not recall a value a running process already holds: see
[what revocation reaches](enterprise.md#what-revocation-reaches). What it
does is make the next read return the new credential and, through the
`retire` hook, make the old one stop working at the issuer.
