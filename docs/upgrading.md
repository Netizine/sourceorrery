# Vault files, export and import

SourceOrrery 0.3.0 uses **vault schema 5**, **C ABI 2** and **contract 2**.
Use the CLI, SDK and native library from the same release. There is no
in-place migration or compatibility layer for earlier vault formats.

## Supported files

Only schema 5 vaults are supported. An older file is refused with
`migration_required`; a newer format is refused with an explanatory error.
Neither case authorises conversion or deletion. Keep unsupported files
separate and create a new vault with `sourceorrery setup` when starting
with this release. Do not edit a file's schema marker: the format and key
wraps are authenticated.

A recovery key unlocks a supported vault; it does not convert an
unsupported file. The [format reference](vault-format.md) describes the
on-disk records, and the [first-run guide](getting-started.md) covers
creating a vault.

## Export a supported vault

```bash
sourceorrery vault export development --out development.sorvault
```

The destination must not exist. Export uses SQLite's online backup to
produce a consistent encrypted copy, preserving local secret versions,
metadata, connections, projects and audit history. It removes this
machine's key wrap and the view check from the copy. The copy opens with
the vault's recovery key only; export does not create a new recovery key
or change the original vault's key.

Keep the recovery key apart from the exported file. Stored provider
credentials remain sealed inside the copy. Values kept at AWS Secrets
Manager, Azure Key Vault or HashiCorp Vault remain at those services:
**exporting the local vault is not a backup of remote provider data**.
Use each provider's backup and recovery controls for that data.

## Import on another machine

Provision the recovery key through a restricted file, then import into a
home that does not already contain a vault with the same name:

```bash
sourceorrery --recovery-key-file /run/secrets/development.recovery-key   vault import development.sorvault
```

Import reads the exported file without modifying it, verifies the copy's
name, settings and audit chain, and registers the imported vault. When an
OS credential store is available, it adds this machine's key. With
`SOURCEORRERY_KEYRING=off`, continue supplying the recovery key to open it.
Use `--name NAME` to register a different name.

The imported vault has no view check by default. Set one with
`--password-file FILE` during import, or open the setup screens afterward
to configure a password and authenticator. A recovery key remains an
alternative that satisfies the check. [CLI reference](cli.md#vault)

## Restoring and compromise response

An export is a point-in-time copy. Importing it does not merge later
versions or audit history from another file. A complete older snapshot
can be internally authentic even though it omits later changes; compare
an externally retained audit checkpoint when freshness matters.

Replacing a recovery key changes its wrap in the current file, not the
underlying vault key. An older copy can still open with its old recovery
key. If a key or vault copy may be compromised, rotate the exposed
credentials and provision a new vault. See the
[threat model](threat-model.md#known-gaps).

## Native SDK libraries

Java, .NET, Go, PHP and C++ check the native library's ABI before opening a
vault. An incompatible library fails with `abi_mismatch`. Python and
Node.js build the client into their native extensions. Use the matching
0.3.0 packages and archives rather than mixing release generations.
