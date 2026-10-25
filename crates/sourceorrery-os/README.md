# sourceorrery-os

Operating-system file primitives for [SourceOrrery](https://sourceorrery.ai):
one function, `create_private_new`, that creates a new, empty file only
its creator can open, for a secret about to be written to it (a vault's
recovery key).

* **Windows:** created with `CREATE_NEW` and an explicit security
  descriptor: owned by the process's user, with a protected access list
  that grants full access to that user and to `SYSTEM` only, so nothing is
  inherited from the folder. The owner and access list are read back
  through the handle and checked before the file is returned, and a volume
  that does not keep permissions (FAT) is refused.
* **Unix:** `O_CREAT | O_EXCL` with mode `0600`, checked afterwards.

An existing file is never opened or changed, and a file that fails a check
is removed again. There is no fallback to ordinary creation.

**You probably want another crate.** This is a building block of the
`sourceorrery` command-line tool
([`sourceorrery-cli`](https://crates.io/crates/sourceorrery-cli)). It is
one of the two crates in the workspace that use `unsafe` (for the Win32
calls), as [ADR 0010](https://github.com/Netizine/sourceorrery/blob/main/docs/adr/0010-authenticated-key-wraps-and-private-files.md)
explains.

For application reads, use the read-only
[`sourceorrery` SDK](https://crates.io/crates/sourceorrery). Use the CLI to
create vaults and set secret values; follow the
[CLI installation guide](https://sourceorrery.ai/getting-started/#install).

## Licence

MIT or Apache-2.0, at your option. Source:
<https://github.com/Netizine/sourceorrery/tree/main/crates/sourceorrery-os>.
