# SourceOrrery errors

Every failure has a stable code (in `-o json` output:
`{"error":{"code":"...","message":"..."}}`) and, in the SDKs, a `hint`
saying what to do. No message ever contains a secret value.

| Code | Meaning | What to do |
|------|---------|------------|
| `vault_not_found` | No vault file with that name in the home directory | `sourceorrery vault list`; create it with `sourceorrery vault create <name>`, or check `SOURCEORRERY_HOME` and `--vault` |
| `locked` | Nothing could unlock the vault | On a desktop the OS credential store should do it. Headless: the user adds a passphrase protector and provides `SOURCEORRERY_PASSPHRASE_FILE` (see install.md, Headless). Never guess passphrases |
| `unsupported` | No OS credential store on this machine | Use a passphrase protector (install.md, Headless) |
| `not_found` | The vault has no secret with that name | The user stores it: `sourceorrery secret set <name>`, or `sourceorrery import` from a `.env` file |
| `version_not_found` | No such version | `sourceorrery secret versions <name>`; drop the version pin |
| `disabled`, `expired`, `not_yet_valid` | Policy: the version may not be read now | The user decides: `secret update <name> --version <id> --enable`, a new `--expires`, or a new value |
| `deleted` | The secret is soft-deleted | `sourceorrery secret recover <name>` if the user wants it back |
| `deleted_conflict` | Storing a name that is soft-deleted | Recover it, or (ask the user) purge it first |
| `invalid_name` | Secret names: letters, digits, hyphens, at most 127 | Rename, e.g. `database_url` → `database-url` |
| `manifest` | `sourceorrery.toml` is missing or invalid | Fix the file; `sourceorrery check` validates it. A `value` key is never allowed |
| `migration_required` | The vault file is in an older format | Tell the user; migrating (`sourceorrery vault migrate <name>`) is their decision |
| `vault_mismatch` | The file for one vault holds another vault (renamed, copied or swapped) | Tell the user; never work around it. Moving the file back or restoring a backup is their call |
| `crypto` | The vault file failed an integrity check, or its audit log was truncated | Stop and tell the user. Do not run `audit --acknowledge` yourself |

`sourceorrery check` lists every secret the manifest needs with its
status, reading no values: run it first when a program cannot start.
`sourceorrery run` refuses to start a program while a required secret is
unavailable and names it.

Full reference: https://sourceorrery.ai/reference/error-codes/
