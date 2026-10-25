# Security remediation: validation ledger

The evidence record for
[the remediation plan](../SECURITY-REMEDIATION-PLAN-2026-10-25.md) of
[the 2026-10-25 review](../SECURITY-REVIEW-2026-10-25.md): per batch, the
commit, what it closes, what was run and what was not. The review itself
stays the record of the findings; nothing here rewrites it. "Run" means
executed on this machine; a check that needs CI, another platform or a
live service is listed as not run until it has been.

## Starting point (B01)

| | |
|---|---|
| Reviewed commit | `18138d3` (main, PR #43 merged) |
| Branch | `security-remediation`, from `18138d3` plus `5f7e0d6` (Dependabot pull requests run like forks; its own Font Awesome token) |
| Machine | Windows 11 Pro 10.0.22621, 4-core Intel i7-8650U, 16 GB |
| Rust | 1.99.1 (current); 1.91.1 (declared minimum) installed for B30 |
| Node | 22.15.1 (system); 24.11.1 (Playwright's) for the site, which needs 22.19+ |
| Python | 3.14.0 |
| Others | .NET 10.0.402, Java 27, Go 1.27.3, Docker 28.4.0 (Linux, and PHP: not installed locally) |

### Dependency graphs (for B22)

| Graph | Lock file |
|---|---|
| Rust workspace | `Cargo.lock` |
| Python native extension | `bindings/python/Cargo.lock`, `bindings/python/pyproject.toml`, `bindings/python/ci-requirements.txt` |
| Node native extension | `bindings/node/Cargo.lock`, `bindings/node/package-lock.json` |
| Site | `site/package-lock.json` |
| Coverage tooling | `scripts/coverage/package-lock.json`, `scripts/coverage/requirements.txt` |
| LocalStack CLI | `scripts/ci/lstk/package-lock.json` |
| Java | `bindings/java/pom.xml` (no lock file) |
| .NET | `bindings/dotnet/**/*.csproj` (no lock file) |
| Go | `bindings/go/go.mod` (no third-party modules) |
| PHP | `composer.json` (no third-party packages) |

### Test runners

| Surface | Runner |
|---|---|
| Rust crates | `cargo test -p <crate>`, one crate at a time with `-j 2` on this machine |
| Cross-language contract | `tests/conformance/sdk/harness.py --runner <lang>` over each binding's `conformance/` |
| Python | `bindings/python/tests` (pytest) |
| Node | `bindings/node/__test__` (node --test) |
| Java | `bindings/java/src/test` (Maven) |
| .NET | `bindings/dotnet/SourceOrrery.Tests` (dotnet test) |
| Go | `bindings/go/*_test.go` |
| C, C++ | `bindings/cpp/tests`, `crates/sourceorrery-ffi/examples` |
| PHP | `bindings/php/tests/run.php` (in Docker here) |
| Release helpers | `python -B -m unittest scripts/release/*_test.py scripts/ci/*_test.py` |
| Site tooling | `node --test site/scripts/docs-tooling.test.mjs` |

### Baseline results

Run 2026-10-25 on `5f7e0d6` (the reviewed tree plus the Dependabot CI
change, which touches no Rust), `SOURCEORRERY_KEYRING=off`, one crate at a
time, `--locked --no-fail-fast`:

| Check | Result |
|---|---|
| Rust, all 11 workspace crates | 513 passed, 0 failed, 1 ignored (`ui::snapshot::write_design_snapshots`, by design) |
| Of those, live provider tests | 14 return early without a service (`SOURCEORRERY_VAULT_TEST_ADDR`: 3, `SOURCEORRERY_AWS_TEST_ENDPOINT`: 6, `SOURCEORRERY_AZURE_TEST_ENDPOINT`: 5); counted as passed, but they exercise nothing here |
| Release and CI helpers (Python) | 48 passed |
| Site tooling (`docs-tooling.test.mjs`, Node 24) | 10 passed |
| Not run here | the language SDK suites and the cross-language harness (need the release CLI, C ABI and fixture vault per binding; run in B31), the emulator and live-service suites, other platforms, the minimum toolchain (B30) |

No test opened a real vault or the real credential store: the suites use
temporary homes, recovery keys and an in-memory store, as CLAUDE.md
requires. The fixture values are synthetic.

## Decisions taken with the owner

| Topic | Decision |
|---|---|
| Recovery-key replacement (SR01) | Authenticate the wrap inventory; document the narrower guarantee; compromise response is a new vault with rotated values ([ADR 0010](adr/0010-authenticated-key-wraps-and-private-files.md)). No in-place DEK rotation in 0.3.0. |
| Vault format | Schema 5; schemas 1 to 4 refused with `migration_required`. |
| Windows key files (SR04) | A new crate, `sourceorrery-os`, over `windows-sys`: the second crate allowed `unsafe`, one safe function, explained in ADR 0010. |
| Site icons (SR13) | The licensed Font Awesome Pro kit stays (custom icon, duotone). The token is a repository secret for Actions and for Dependabot. Pull requests from forks, which cannot have it, skip the docs build with a notice and are built after merge: the owner's disposition of SR13 rather than a credential-free build. |
| Publication | Nothing is pushed until the owner asks. |

## Items

| Item | Batches | Status |
|---|---|---|
| SR01 | B02, B03, B24, B28 | open |
| SR02 | B08–B11, B28 | open |
| SR03 | B06, B07, B28 | open |
| SR04 | B04, B05, B31 | open |
| SR05 | B12, B31 | open |
| SR06 | B13, B31 | open |
| SR07 | B14, B31 | open |
| SR08 | B15, B28 | open |
| SR09 | B05, B28 | open |
| SR10 | B16 | open |
| SR11 | B17 | open |
| SR12 | B24, B32 | open |
| SR13 | B23 | open |
| SR14 | B18, B28 | open |
| REC01 | B25, B26, B32 | open |
| REC02 | B25, B27, B32 | open |
| REC03 | B22, B30 | open |
| REC04 | B01, each batch, B28 | open |
| REC05 | B19 | open |
| REC06 | B09 | open |
| REC07 | B20, B21 | open |
| REC08 | B06, B07, B18, B29 | open |
| REC09 | B30, B31, B32 | open |

## Batches

Each entry: commit, what it closes, behaviour and compatibility, tests run
(passed, failed, skipped), and what is left.

### B01 — baseline and ledger

* **Closes:** the B01 prerequisites; starts REC04's record.
* **Changes:** this ledger; the review and the plan committed beside the
  earlier review (`SECURITY-REVIEW-2026-10-25.md`,
  `SECURITY-REMEDIATION-PLAN-2026-10-25.md`). No code.
* **Evidence:** the baseline above. Failure-injection helpers are added
  with the regression each batch needs, not as a framework up front.

### B02 — key-replacement contract and schema 5

* **Closes:** the SR01 design decision.
* **Changes:** [ADR 0010](adr/0010-authenticated-key-wraps-and-private-files.md)
  (the wraps join the settings record; what replacing a recovery key
  guarantees and what it cannot; the compromise procedure: rotate at the
  issuers, new vault, destroy the old; schema 5; the `sourceorrery-os`
  exception for B04). `docs/vault-format.md`, `docs/threat-model.md` (gap
  10, the controls table), `docs/cli.md`, ADR 0007 and ADR 0009 notes, the
  changelog, the headless guide.
* **Compatibility:** schema 5; schemas 1 to 4 refused with
  `migration_required`, the file unchanged. No ABI, contract or error-code
  change. In-place vault-key rotation stays out of 0.3.0.
* **Review:** every entry point that changes `key_wraps` (create,
  replacement by `change_settings` and `replace_recovery_key`, adding this
  machine's key, export, import) is listed with the event that checkpoints
  it; export and import are documented as keeping the vault key.

### B03 — authenticated key-wrap inventory

* **Closes:** SR01 in the file (the documentation half is B02; B24 checks
  the final wording, B28 the matrix).
* **Changes:** `integrity::SettingsFields::key_wraps` and
  `key_wrap_canonical` (domain `sourceorrery/v5/key-wrap`: every column of
  the row); `Meta` and `write_settings_tag` read the rows; every wrap change
  rewrites the record in its transaction and its event carries the tag
  (`protector_add` for replacement and for this machine's key, the copy's
  `vault_export`, `vault_import` always); `SCHEMA_VERSION` 5.
* **Tests run:** storage 75 unit tests (new:
  `an_old_recovery_wrap_put_back_does_not_open_the_vault`, the SR01
  reproduction, with the wrap alone and with the whole old record;
  `a_wrap_row_added_or_swapped_is_refused`;
  `every_change_to_the_wraps_leaves_a_vault_that_opens` over creation with
  this machine's key, `change_settings`, `replace_recovery_key` and
  `add_this_machine_key`;
  `a_file_of_an_earlier_schema_is_refused_without_being_changed`, byte for
  byte; `the_settings_record_covers_every_part_of_every_key_wrap` over each
  column, an extra row and none). The SR01 test **fails without the fix**
  (checked by dropping the section from the record: the old key opened the
  tampered copy). Then storage (all targets), provider, the Rust client,
  the C ABI, conformance and the CLI: all pass, export/import round trips
  included. The CLI test that planted a wrap row now expects the refusal.
  clippy `-D warnings` clean for storage.
* **Not run here:** the language SDK suites (B31).

### B04 and B05 — private key files, and a create that cannot strand a vault

One commit: the CLI's new dependency, the crate and the lock file must
land together to build.

* **Closes:** SR04 on Windows and Unix as implemented here (B31 runs it on
  the other platforms and with a second account), SR09.
* **Changes:** new crate `sourceorrery-os` (ADR 0010): one safe function,
  `create_private_new`; on Windows `CreateFileW` with `CREATE_NEW`, no
  sharing, a non-inheritable handle and an explicit descriptor (owner the
  process's user; protected DACL: full access for that user and `SYSTEM`
  only), then the volume's `FILE_PERSISTENT_ACLS`, the owner and every ACE
  read back through the handle; any failure removes the empty file; on
  Unix `O_EXCL` with `0600`, the mode checked. RAII owners for the token,
  handles and system buffers; every `unsafe` block documented; the crate
  denies `unsafe_op_in_unsafe_fn` and `undocumented_unsafe_blocks`. CLAUDE.md
  names it as the second crate allowed `unsafe`; `publish-crates.py` lists it
  for its first, token-authenticated publication. `vault create` reserves
  the key file before the vault exists, writes, flushes and syncs it, and
  undoes the vault and the file it made when the key cannot be delivered
  to the file, stdout or the JSON body; the message says "restricted to
  your account and Windows SYSTEM" (Unix: "readable by you only").
* **Tests run (Windows):** `sourceorrery-os` 5 tests: the new file grants
  `SYSTEM` and the user full access and Users, Everyone and Authenticated
  Users none (computed with `GetEffectiveRightsFromAclW`); the same under a
  folder that grants Users read (the fixture checked: an ordinary file
  there is readable by Users); an existing file left byte for byte; a
  failed check removes the file; the check refuses another owner, an
  unprotected or missing DACL, an inherited, narrower, extra, missing or
  deny entry, and a volume without persistent ACLs. CLI:
  `a_recovery_key_that_cannot_be_delivered_leaves_no_vault` (the review's
  missing-folder reproduction; stdout closed, plain and JSON; the stated
  protection), with the existing never-written-over case; all 210 CLI tests
  pass; release helpers 48. clippy `-D warnings` clean for the crate and the
  CLI with and without default features.
* **Not run here:** the Unix branch (no Linux toolchain or image on this
  machine: CI builds it on Linux and macOS), a real second account opening
  the file, a FAT volume, write and flush failures (no fault injection for
  the disk; the code path is the same `?` as the open failure). B31.

### B06 — the vault's gate before every provider dispatch

* **Closes:** SR03's dispatch half (B07 covers what a dispatched call's
  outcome is when it cannot be recorded).
* **Changes:** `SqliteVault::preflight_at_connection`: the gate
  `record_at_connection` applies (chain head, no truncation waiting, the
  verified settings record and connection row, the secret's catalog row
  for the change), without its writes; a refusal is recorded. `Routed::at`,
  the one path to every provider call (reads, listings, writes, recovery,
  purge, `missing`, `forget_missing`), calls it before opening or using a
  client, cached or not. No lock is held during the provider call; a change
  made in between is caught when the call is recorded.
* **Tests run:** `a_blocked_vault_sends_nothing_to_its_providers` (the
  review's reproduction: warm client, newest audit row removed, then get,
  properties, versions, set, update, delete, deleted, recover, purge, list,
  list deleted): every call refused with `crypto` and the counting provider
  called **zero** times; the provider's secret and deleted secret
  unchanged. Without the preflight the test fails (13 provider calls
  against 4). Provider crate 14 tests, storage 75; clippy clean for both.
* **Residual, carried into B07:** a vault blocked *between* the preflight
  and the dispatch is caught only when the call is recorded, after the
  provider acted.

### B07 — provider outcomes the vault cannot commit

* **Closes:** SR03's second half: what a dispatched change returns and
  records when its result is not known, or not recorded.
* **Design:** [ADR 0011](adr/0011-provider-writes-fail-closed.md), sections
  1, 2 and 4 (section 3 is B08).
* **Changes:** core: `SecretError::OutcomeUnknown { at, reason }`, code
  `outcome_unknown` (appended, not transient); `SecretError::is_refusal`
  (the codes that show a provider changed nothing) and
  `after_change_sent` (any other failure of a sent change becomes
  `outcome_unknown`); `AuditOutcome::Pending` and `Unknown` (appended,
  with `AuditOutcome::ALL`); `AuditOperation::changes_a_secret`. Storage:
  `SqliteVault::attempt_at_connection` commits a `pending` event (`at
  connection <id>: sent`) after the gate; `record_at_connection` takes the
  `Attempt` it completes (`(attempt <id>)` in the detail) and records
  `outcome_unknown` as `unknown`; `unresolved_attempts` lists attempts that
  nothing but an `unknown` completed and that no later successful change of
  the same secret through the same connection settled (authenticated rows
  only). `Routed::at`: gate, open the client (a failure there is recorded
  without an attempt: nothing was sent), record the attempt for a change,
  call, classify, record; a change the provider made that the vault could
  not record is `outcome_unknown`, never the vault's error alone. Nothing
  is retried. The Rust client's `ErrorKind::OutcomeUnknown` with a hint;
  the CLI shows `pending` plainly and `unknown` as an error (table, `ui`,
  OTLP severity), and `audit` names the unresolved attempts with what to do.
* **Decision:** the bindings are not changed. They type the codes a read
  returns; no SDK and no C ABI function changes a secret (ADR 0005), so none
  can meet `outcome_unknown`, which reaches them, like `rotation`, as their
  base error with the code kept. This is how the plan's "all bindings
  recognize any new public code" is met; a typed error per binding would
  be code no test can reach.
* **Tests run:** `routed` 12 (new: `a_refused_change_completes_its_attempt`;
  `a_lost_answer_is_outcome_unknown_until_a_later_change_settles_it`, a
  provider that makes the change and loses the answer: one call, never
  retried, two versions at the provider, `unknown` recorded, the attempt
  listed until a later successful set; a refused delete does not settle
  it; a purge with a lost answer is settled by `forget_missing`;
  `a_change_made_but_not_recorded_is_outcome_unknown`, another process
  taking the name while the provider creates it;
  `an_attempt_cut_short_by_a_restart_is_listed_when_the_vault_opens_again`;
  `attempts_and_unknown_outcomes_never_carry_a_value`; the blocked-vault
  test also shows no attempt is recorded before a refused dispatch; the
  catalog test checks every change has its attempt and completion). Core
  53 (the classification, the outcome labels), the Rust client 16 (every
  code has a kind), storage 75, provider 7 unit tests (`outcome_unknown`
  passes both adapters unchanged), CLI 210. The C ABI and conformance build.
  clippy `-D warnings` clean for core, the client, storage, provider and the
  CLI.
* **Not run here:** the language SDK suites (no change reaches them).

### B08 — the publication design

* **Closes:** SR02's design decision, before B10 and B11.
* **Design:** [ADR 0011](adr/0011-provider-writes-fail-closed.md) section 3:
  the invariant (a SourceOrrery reader never applies a policy looser than
  the one a version's writer asked for, at any moment, after any failure);
  HashiCorp Vault: committed documents plus per-writer intents for a
  version not yet written, every `custom_metadata` change a merge patch of
  its own keys, the data written with check-and-set; AWS Secrets Manager:
  narrow to the meet of the old and new policy, publish, then reach the
  target in an order that never loosens below it; Azure unchanged. What
  needs provider IAM, legacy and external entries, metadata-only reads,
  concurrent writers (Vault: covered; AWS: one writer at a time per secret,
  since the service has no conditional writes) and lost answers (B07) are
  each settled there.
* **Evidence for the design:** the Vault behaviours it relies on were
  checked against a disposable `hashicorp/vault:2.2.1` dev server (the CI
  image): metadata can be created before any data and a data write with
  `cas: 0` then lands as version 1; a stale `cas` is refused with 400
  "check-and-set parameter did not match the current version"; a merge
  patch adds and removes (`null`) single keys and needs
  `application/merge-patch+json`; a patch of missing metadata is 404; a
  `POST` that sets only `max_versions` creates missing metadata and leaves
  existing `custom_metadata` alone (an empty `POST` creates nothing);
  `custom_metadata` allows 64 keys, 128-byte keys and 512-byte values. The
  AWS tag rules were taken from the Secrets Manager user guide and the
  general tagging reference (B09).
* **Contract case:** the lifecycle scenario
  `a_new_restricted_version_is_never_returned` (a disabled version, then
  one before its window, written over an enabled one: never returned by
  name or by version, and every metadata read says why). Conformance 59
  tests pass (the local vault and both adapters); the live suites run it in
  B10 and B11. The in-flight half of the invariant is the model test of
  B10, since the shared suite cannot interrupt a write.

### B10 — fail-closed publication on HashiCorp Vault

* **Closes:** SR02 for HashiCorp Vault.
* **Changes:** `kv`: intents `sourceorrery.v<N>~<nonce>`;
  `Metadata::effective_props` (the committed document, or the defaults,
  restricted by every intent: disabled if any is, the latest `not_before`,
  the earliest `expires_on`), used by every read, metadata-only ones
  included; `intents_for`, `keys_for`. `set_secret`: read, intent patched
  in when a property is not the default (a new secret's metadata created
  with a `POST` of `max_versions` only), data written with
  `options.cas = N`, one commit patch (the committed document, this
  writer's intent and any leftover for the version removed); a
  check-and-set refusal is `invalid_argument` "another writer added
  version …" with the intent removed; a lost data answer or a failed
  commit is `outcome_unknown`. `update_secret_properties` is one merge
  patch that also removes the version's intents. Delete patches the marker
  in first; recover asks KV's undelete first; a failure of the second
  step is `outcome_unknown` and leaves the secret deleted and recoverable.
  The transport sends `PATCH` as `application/merge-patch+json`; a 403 on a
  patch says properties are written with `patch`. The guide lists the
  capabilities a writing token needs.
* **Tests run:** `tests/publication.rs`, a model of KV v2 with the behaviours
  checked against Vault 2.2.1 (B08) that snapshots the metadata after
  every request it applies: `a_disabled_version_is_never_readable_whichever_request_fails`
  (each of the intent, data and commit requests refused, failed, or applied
  with its answer lost: version 2 is never enabled in any snapshot, never
  readable by name or version, and the writer gets a refusal only when
  nothing was written and `outcome_unknown` when it was);
  `a_write_commits_its_properties_and_removes_its_intent` (the request
  sequence; refused at the intent, nothing written; the `patch` message);
  `a_leftover_intent_only_restricts_until_the_version_is_committed`;
  `two_writers_never_lift_each_others_restrictions` (two writers'
  requests forced into an interleaving: A's disabled version 2 is never
  enabled, B is refused and writes nothing, only the committed document
  stays); `a_delete_or_recover_cut_short_leaves_the_secret_deleted`. All
  five **fail without the fix** (the adapter's sources set aside, the same
  tests: "Refuse at PATCH metadata #1: version 2 enabled after POST data",
  the review's reproduction). `kv` unit test
  `intents_restrict_a_version_and_never_loosen_it`. The crate's 18 tests
  pass; clippy `-D warnings` clean. **Live:** the lifecycle suite, the new
  scenario included, directly and through `Routed` (B07's attempts
  included), passes against a disposable `hashicorp/vault:2.2.1` dev
  server; afterwards the 62 mounts it made hold 110 `custom_metadata` keys
  and no leftover intent.
* **Not run here:** a Vault policy without `patch` against the live server
  (the model covers the refusal); Vault Enterprise namespaces.
