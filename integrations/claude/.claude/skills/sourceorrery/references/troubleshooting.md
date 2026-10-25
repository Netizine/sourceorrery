# SourceOrrery errors

Every failure has a stable code (in `-o json` output:
`{"error":{"code":"...","message":"..."}}`) and, in the SDKs, a `hint`
saying what to do. No message ever contains a secret value.

| Code | Meaning | What to do |
|------|---------|------------|
| `vault_not_found` | No vault file with that name in the home directory | `sourceorrery vault list`; check `SOURCEORRERY_HOME` and `--vault`, or ask the user to create it (`sourceorrery setup`) |
| `locked` | This machine has no key for the vault and no recovery key opened it | On the machine that created it the OS credential store does it. Elsewhere the user provides the recovery key in a file, `SOURCEORRERY_RECOVERY_KEY_FILE` (see install.md, Headless). Never ask to see a recovery key |
| `permission_denied` | The vault's view check refused (or a provider's policy did) | Never set `SOURCEORRERY_PASSWORD`, `--password-file` or `--code` yourself: ask the user to run the command. `sourceorrery check` reads metadata without the check |
| `unauthenticated` | A provider the vault keeps secrets at has no credentials for this process | The user signs in with the provider's own tools, or stores credentials in the vault's connection (`sourceorrery setup`) |
| `unsupported` | Not available here: a provider this build leaves out, or something the secret's storage cannot express | Tell the user; the message names what |
| `not_found` | The vault has no secret with that name | The user stores it: `sourceorrery secret set <name>`, or `sourceorrery import` from a `.env` file |
| `version_not_found` | No such version | `sourceorrery secret versions <name>`; drop the version pin |
| `disabled`, `expired`, `not_yet_valid` | Policy: the version may not be read now | The user decides: `secret update <name> --version <id> --enable`, a new `--expires`, or a new value |
| `deleted` | The secret is soft-deleted | `sourceorrery secret recover <name>` if the user wants it back |
| `deleted_conflict` | Storing a name that is soft-deleted | Recover it, or (ask the user) purge it first |
| `invalid_name` | Secret names: letters, digits, hyphens, at most 127 | Rename, e.g. `database_url` → `database-url` |
| `manifest` | `sourceorrery.toml` is missing or invalid | Fix the file; `sourceorrery check` validates it. A `value` key is never allowed |
| `migration_required` | The vault format is unsupported and the file was left unchanged | Stop and tell the user; link the supported-files guide at https://sourceorrery.ai/guides/upgrading/. Do not reveal values or delete, move, relabel or convert the file |
| `outcome_unknown` | A provider write may have happened even though its result could not be recorded | Stop and report the uncertainty. Do not blindly repeat the write; the user can compare metadata and the provider audit trail before deciding what to do |
| `vault_mismatch` | The file for one vault holds another vault (renamed, copied or swapped) | Tell the user; never work around it. Moving the file back or bringing in an exported copy is their call |
| `crypto` | The vault file failed an integrity check, or its audit log was truncated | Stop and tell the user. Do not run `audit --acknowledge` yourself |

`sourceorrery check` lists every secret the manifest needs with its
status, reading no values: run it first when a program cannot start.
`sourceorrery run` refuses to start a program while a required secret is
unavailable and names it.

Full reference: https://sourceorrery.ai/reference/error-codes/
