# Upgrading from 0.2.0

SourceOrrery 0.3.0 changes how a vault is kept and opened
([ADR 0009](adr/0009-local-vaults-checks-and-storage.md),
[ADR 0010](adr/0010-authenticated-key-wraps-and-private-files.md)): the
vault key is kept as this machine's key in the OS credential store and
under one recovery key, the file format is schema 5, and passphrases,
protectors, recovery codes and `[vaults.*]` manifest tables are gone.
There is no conversion. 0.3.0 refuses a vault file of an earlier release
(schema 3 from 0.2.0, schema 4 from development builds of `main`) with
`migration_required` and leaves it exactly as it was: it writes nothing to
the file or beside it, and `vault export`, `vault destroy` and
`vault create` refuse it too. `vault export` and `vault import` copy
schema 5 vaults between machines; they never convert an older one.

Upgrading a vault means keeping its file where 0.2.0 still reads it,
creating a new vault with 0.3.0, and setting each secret again from the
old one: 0.2.0 reveals each value into a pipe and 0.3.0 reads it from the
pipe, so no value is written to disk or typed. The steps below were run
with the 0.2.0 release CLI against this release in Git Bash, PowerShell
7.6 and cmd.exe on Windows, for a local vault and for a remote one at
HashiCorp Vault; every value arrived byte for byte.

This is the ordinary upgrade, for a vault you trust. If the vault's key, a
copy of it, or a machine that held it may be compromised, moving the
values does not help: rotate them at their issuers and follow the
compromise response in the [threat model](threat-model.md) (known gap 10)
instead.

## What moves and what stays

| | |
|---|---|
| Each secret's current value | Moves: what 0.2.0's `secret get --reveal` returns, the newest enabled version within its time window |
| Its content type, tags and time window | Set again with `secret update` (step 5), as 0.2.0's `secret get NAME` shows them |
| The vault's name | Kept, so a project's `sourceorrery.toml` names the new vault without a change |
| Older versions, deleted secrets, the audit log | Stay in the old file, readable with 0.2.0 for as long as you keep both |
| The reveal guard, second factor and recovery codes | Stay with the old file. 0.3.0 has the view check instead, which `setup` offers |

## 1. Keep the 0.2.0 CLI

Keep the 0.2.0 binary under another name before you upgrade, or download
its archive from the
[v0.2.0 release](https://github.com/Netizine/sourceorrery/releases/tag/v0.2.0)
and check it against the release's `SHA256SUMS`, or its provenance:

```bash
gh attestation verify sourceorrery-0.2.0-x86_64-pc-windows-msvc.zip --repo Netizine/sourceorrery \
  --signer-workflow Netizine/sourceorrery/.github/workflows/release.yml
```

Below, 0.2.0 is `sourceorrery-0.2.0` and 0.3.0 is `sourceorrery`.

## 2. Move the old file out of the vaults folder

Both releases find a vault as `vaults/<name>.sorvault` in the
SourceOrrery home: `%LOCALAPPDATA%\sourceorrery` on Windows,
`~/Library/Application Support/sourceorrery` on macOS,
`~/.local/share/sourceorrery` on Linux, or `SOURCEORRERY_HOME`. Move the
old file into a home of its own, which 0.2.0 reads with `--home`. Its
passphrase, and its entry in the OS credential store, still open it
there: the entry is named after the vault's id, not its path.

<!-- tabs: shell -->

#### Bash

```bash
mkdir -p ~/sourceorrery-0.2.0/vaults
mv ~/.local/share/sourceorrery/vaults/development.sorvault ~/sourceorrery-0.2.0/vaults/
sourceorrery-0.2.0 --home ~/sourceorrery-0.2.0 secret list --vault development
```

#### PowerShell

```powershell
New-Item -ItemType Directory -Force "$HOME\sourceorrery-0.2.0\vaults" | Out-Null
Move-Item "$env:LOCALAPPDATA\sourceorrery\vaults\development.sorvault" "$HOME\sourceorrery-0.2.0\vaults\"
sourceorrery-0.2.0 --home "$HOME\sourceorrery-0.2.0" secret list --vault development
```

<!-- /tabs -->

Move the file; never delete it. While it is in the vaults folder, 0.3.0
says the vault already exists.

## 3. Create the new vault

```bash
sourceorrery setup            # or: sourceorrery vault create development
```

Give it the same name. Keep its new recovery key apart from this machine:
the old passphrase does not open it.

## 4. Set each secret from the old vault

List the names with `secret list` as in step 2, then:

<!-- tabs: shell -->

#### Bash

```bash
set -euo pipefail
old() { sourceorrery-0.2.0 --home ~/sourceorrery-0.2.0 "$@"; }
for name in database-url api-token tls-key; do
  old secret get "$name" --vault development --reveal --raw |
    sourceorrery secret set "$name" --vault development --stdin --keep-trailing-newline
done
```

#### PowerShell

PowerShell 7, piping from one program straight into the other:

```powershell
$ErrorActionPreference = 'Stop'; $PSNativeCommandUseErrorActionPreference = $true
$old = "$HOME\bin\sourceorrery-0.2.0.exe"
foreach ($name in 'database-url', 'api-token', 'tls-key') {
  & $old --home "$HOME\sourceorrery-0.2.0" secret get $name --vault development --reveal --raw |
    sourceorrery secret set $name --vault development --stdin --keep-trailing-newline
}
```

Windows PowerShell 5.1, and a PowerShell function or script block between
the two programs, handle the output as lines of text: every line break
becomes CRLF and one is added at the end, so each value is stored
changed. Use PowerShell 7 as above, Git Bash, or cmd.exe, whose pipes pass
the bytes through.

<!-- /tabs -->

`--raw` writes each value with nothing added, and `--keep-trailing-newline`
stores it with nothing removed, so a value that ends in a line break (a
PEM key) keeps it. 0.2.0 asks for its passphrase, and what its reveal
guard asks for, as it always has; storing asks nothing of 0.3.0, whose
view check guards viewing and revealing.

If a read fails, 0.3.0 receives no input and refuses to store an empty
value, and the loop stops: nothing wrong is stored. An empty secret is
refused the same way; set it again by hand with `--allow-empty`. A
disabled, expired or not-yet-valid secret is not revealed: pass
`--version ID` (from `old secret versions NAME --vault development`) to
move that version.

## 5. Set the metadata again

For each secret that has a content type, tags or a time window in
0.2.0's `secret get NAME`:

```bash
sourceorrery secret update database-url --vault development \
  --content-type text/plain --tag team=payments --expires 2027-06-30T00:00:00Z
```

## 6. Check

```bash
sourceorrery secret list --vault development
sourceorrery check            # in each project that uses the vault
```

`check` resolves every secret the manifest names without reading a value.
0.3.0 refuses `[vaults.*]` tables and `[secrets.*].vault` keys in a
manifest and says which: remove them.

## 7. Retire the old vault

When nothing needs its older versions or its log any more:

```bash
sourceorrery-0.2.0 --home ~/sourceorrery-0.2.0 vault destroy development
```

removes the file and its entries in the OS credential store. Copies and
backups of it elsewhere still open with its passphrase.

## A remote vault

A 0.2.0 remote vault, a `[vaults.<name>]` table in `sourceorrery.toml`, is
not a file: its secrets stay at the provider, where 0.2.0 keeps reading
them. 0.3.0 reaches a provider through a connection a local vault holds
([providers](providers/index.md)). Create the new vault with a connection
(`setup`, or `vault create` with the provider's flags), pointed at a
location 0.2.0 does not use (another KV mount, AWS prefix or key vault) so
that the two releases never write the same secret. Then run the loop of
step 4 with two changes: 0.2.0 runs in the project's directory, where its
manifest declares the remote vault, and 0.3.0 stores each value at the
provider:

```bash
set -euo pipefail
old() { (cd ~/src/my-application && sourceorrery-0.2.0 "$@"); }
for name in database-url api-token; do
  old secret get "$name" --vault production --reveal --raw |
    sourceorrery secret set "$name" --vault development --storage hashicorp-vault --stdin --keep-trailing-newline
done
```

Once every project's manifest names the local vault, the old secrets at
the provider can be removed with the provider's own tools.
