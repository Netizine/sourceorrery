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

### B09 and B11 — AWS input checked first, and fail-closed publication

One commit: the checks and the new write order share the tag plan.

* **Closes:** REC06; SR02 for AWS Secrets Manager (one writer at a time per
  secret, as ADR 0011 states).
* **Limits used (verified 2026-10-25):** the Secrets Manager user guide
  ("Tagging secrets": 50 tags a secret, keys 1 to 128 and values 0 to 256
  characters, `aws:` reserved, case-sensitive), the API reference (`Tag`:
  key 1..128, value 0..256) and AWS's general tagging reference, whose
  allowed set (letters, digits, spaces, `_ . : / = + - @`) includes the
  colon that Secrets Manager's own page leaves out and that `aws:` keys and
  every timestamp here use; `aws:` tags do not count against the 50. Value
  limit 65,536 bytes.
* **Changes:** `mapping::check_user_tags` (length, characters, `aws:` and
  `sourceorrery:` refused in any case), `check_content_type` (stored as a
  tag value), `check_value`, `check_tag_count` over the most tags held at
  once; all run before any request that writes, in `set_secret` and
  `update_secret_properties`. `SecretProps::meet` and
  `at_least_as_strict_as`; `TagPlan` (stale non-policy tags removed first,
  wanted tags written, stale policy tags removed last; AWS's own tags never
  touched) with `peak` and `states`. `set_secret` of an existing secret:
  narrow to the meet, `PutSecretValue`, then the plan; a refused put undoes
  the narrowing; a lost answer or a failed plan step is `outcome_unknown`;
  the read of the new version's creation time afterwards is best effort.
  `update_secret_properties` runs the plan; a failure after a step landed
  is `outcome_unknown`. `from_tags` no longer takes `aws:` tags for user
  tags (they were written back, which AWS refuses). Live tests: a shared
  `sourceorrery_conformance::live::target` says what each suite ran against
  (an emulator or dev server on this machine, or a service) and fails a
  suite that would skip when `SOURCEORRERY_LIVE_REQUIRED=true`, which the
  Vault job sets always and the AWS and Azure jobs set when their emulator
  is up.
* **Tests run:** mapping unit tests 10 (new:
  `user_tags_content_types_and_values_are_checked_before_any_request`,
  `the_meet_is_the_stricter_policy_of_both`,
  `a_tag_plan_never_loosens_below_its_target_and_keeps_aws_tags`, every
  pair of five policies). `tests/publication.rs`, a model of Secrets
  Manager's JSON protocol on a loopback port, snapshotting the tags and
  the current version after every change:
  `a_new_version_is_never_current_under_a_looser_policy` (three
  transitions, each with no fault and with tag, put and untag requests
  refused, failed or applied with an unreadable answer: the new version is
  current only under a policy at least as strict as asked, the old one
  before that only under one at least as strict as it had, a write that
  landed is never a refusal, a refused write leaves the old policy);
  `an_update_never_passes_through_a_looser_policy`;
  `invalid_input_sends_nothing_that_writes` (reserved keys, a bad
  character, 51 tags, 48 that with the properties exceed 50, an oversized
  value, a content type with `;`: zero writing requests; a valid write
  keeps an `aws:` tag and does not count it). All three **fail without the
  fix** (the old `lib.rs`: "the new version under enabled after
  PutSecretValue" with no fault at all, "enabled, no window after
  UntagResource" for the update, writes sent for invalid input). clippy
  `-D warnings` clean. **Live:** LocalStack 2026.10.0 (the pinned image,
  started with lstk): the 6 live tests pass, the lifecycle suite with the
  new scenario directly and through `Routed`. Vault live suite again with
  the shared helper: passes, reporting the dev server.
* **Not run here:** the real AWS service (LocalStack only, as in CI);
  concurrent writers on AWS, which the design does not cover.

### B12 — PHP readers have one native owner

* **Closes:** SR05 in the code (execution with PHP FFI: below).
* **Changes:** `SecretReader::__clone` refuses, and first drops the
  handle from the copy, so the copy owns nothing even if PHP destroys it
  after `__clone` throws; `__serialize` / `__unserialize` refuse.
  `SecretValue::__clone` drops its bytes from the copy the same way (it
  refused already, but a destroyed copy could have freed the original's
  bytes). `Project` holds no native handle (its values are `SecretValue`s,
  shared by reference); nothing to change there. Guide: a reader is the one
  owner of its handle.
* **Tests added (`bindings/php/tests/run.php`):** a refused clone of a
  reader and of a value, with a collection after it and the original still
  reading; a refused `serialize()` of a reader; a failed read followed by a
  good one; every call after close refused, `descriptor()` included;
  repeated close; the destructor after close.
* **Tests run:** PHP 8.2.35 (Debian bookworm, FFI) in a `node:24-bookworm`
  container, against a Linux release build of the CLI and the C ABI from
  this tree and the fixture vault `scripts/ci/fixture-vault.sh` made with
  it: `bindings/php/tests/run.php`, "PHP SDK: all checks passed". The same
  run made the fixture's recovery-key file with `--recovery-key-out` on
  Linux, reported "readable by you only": B04's Unix branch executed.

### B13 — .NET values stay alive through their callbacks

* **Closes:** SR06.
* **Changes:** `SecretValue` counts the callbacks running in `Use` and
  holds no lock while one runs. `Dispose` (from any thread, from inside a
  callback, or through the owning `Secret` or `Project`) marks disposal
  requested: every new use throws `ObjectDisposedException` and
  `IsClosed` is true at once, and the buffer is freed exactly once, by
  `Dispose` when no callback runs or by the last callback to return.
  `Dispose` never waits. The finalizer frees an unreachable value; a
  running callback keeps its value reachable. An internal constructor takes
  the release function, so tests can instrument the free.
* **Tests run:** `SecretValueLifetimeTests`, 7 tests over test-owned
  buffers and an instrumented release (no native library, no freed memory
  read): disposal inside the callback, nested callbacks, a callback that
  throws (also after disposing), a dispose from another thread forced with
  events while a callback runs (it returns at once, the free waits), the
  owning `Secret` disposed inside the callback, repeated dispose, and the
  finalizer over 2000 abandoned values plus a collection during a callback.
  All 7 pass (`dotnet test`, .NET 10, Windows). Against the old logic (its
  free routed through the same probe): the four in-callback cases fail
  (freed while the callback ran) and the cross-thread case deadlocks (the
  old `Use` held the lock through the callback).

### B14 — Java readers are held for the whole native call

* **Closes:** SR07.
* **Changes:** `ai.sourceorrery.internal.Guarded`: every call holds a
  read lock for its whole native call (any number of platform or virtual
  threads at once); `close()` refuses new calls at once, takes the write
  lock (so it waits for the running calls), frees once; a call cannot close
  its own handle. `SecretReader` routes `get`, `properties`, `resolve` and
  `descriptor` through it. Guide: what `close()` waits for.
* **Tests run:** `GuardedTest`, 5 tests with a fake handle and latches
  (close queued on the lock behind four running calls, checked through the
  lock rather than by sleeping: nothing freed until they return, new calls
  refused, freed once; sixteen calls inside at the same moment; a failed
  call releases the lock; close from inside a call refused; calls racing
  close never see the handle freed). With the existing extraction tests: 9
  pass (`javac` and the JUnit 6.1.3 launcher against the local Maven
  repository, JDK 27, since Maven is not installed here). `ReaderTest`
  gains `everyCallAfterCloseIsRefused` and `closeWhileReadsRunWaitsForThem`
  (eight virtual threads reading while the reader closes).
* **Integration (Windows):** a release build of the CLI and the C ABI and
  the fixture vault: `dotnet test` of the solution, 22 passed (7 new);
  Java `ReaderTest`, `GuardedTest` and the extraction tests against the
  native library, 25 passed, none skipped.

### B22 — every dependency graph audited

* **Closes:** REC03's audit coverage (B30 exercises any upgrade).
* **Inventory (2026-10-25):** three Cargo lock files (root, Python
  extension, Node extension); four npm lock files (`site`, `bindings/node`,
  `scripts/coverage`, `scripts/ci/lstk`); two hash-pinned Python
  requirement files and `bindings/python/pyproject.toml` (no runtime
  dependencies); the Maven `pom.xml` (test and plugin dependencies); six
  `.csproj` files (one with test packages); `go.mod`, `composer.json`, the
  C++ CMake build and the six npm platform packages, all without
  third-party dependencies.
* **Changes:** `scripts/ci/dependency-audit.py` (cargo-audit, `npm audit
  --package-lock-only`, the OSV.dev query API for PyPI, Maven and NuGet
  pins; a graph that must stay dependency-free is checked to stay so;
  every tracked lock file and package manifest must be covered); a
  vulnerability, a failed scanner, an unreadable answer, a missing or an
  uncovered graph fails; an unreviewed maintenance notice is a warning, and
  fails with `--strict`. The `audit` CI job (`dependency audit`) runs it
  with cargo-audit 0.22.2 and Node 24; its unit tests run in the scripts
  job. Dependabot gains `scripts/coverage` for npm and pip.
  `docs/supply-chain.md`: the inventory, the policy, the reviewed notices.
* **Maintenance notices (not vulnerabilities):** RUSTSEC-2026-0370
  (`zvariant`), -0371 (`zbus_names`), -0372 (`zvariant_derive`), in all
  three Cargo graphs, through `sourceorrery-storage` →
  `zbus-secret-service-keyring-store` 1.0.1 → `secret-service` 5.2.0 →
  `zbus` 5.19 (the Linux credential store). Upstream:
  z-galaxy/zbus#2043, merged into `zbus` 6. Removed by `secret-service` on
  `zbus` 6; revisit on that release. No upgrade is made here: none exists.
* **Tests run:** live, 2026-10-25: all 20 graphs pass (Rust: no
  vulnerabilities, the three reviewed notices; npm: 0 of 360, 154, 55 and
  7 dependencies vulnerable, the site's audited without the icon token;
  PyPI 7 and 13 pins, Maven 9 and NuGet 4 references clean). The OSV path
  flags known-vulnerable pins in all three ecosystems (Jinja2 2.4.1, Log4j
  2.14.1, Newtonsoft.Json 12.0.1). `dependency_audit_test.py`, 12 tests with
  faked scanners: a vulnerable Cargo lock, a cargo-audit that cannot fetch
  its database, npm not installed, npm vulnerabilities and npm errors, OSV
  findings and an unreachable OSV, reviewed versus unreviewed notices
  (strict and not), uncovered lock files and manifests, dependency-free
  npm packages, graphs that gain dependencies, a listed graph that
  disappears, the parsers.
* **Not covered:** the transitive Maven and NuGet graphs (direct references
  only; their resolution needs Maven and the .NET SDK, and Dependabot
  follows them); GitHub Actions (pinned by SHA; Dependabot and zizmor).

### B23 — SR13, the owner's disposition

* **Decision (owner):** the licensed Font Awesome Pro kit stays (its custom
  mark and the duotone set are a paid subscription); the token is a
  repository secret for Actions and for Dependabot. No public substitute.
* **Changes:** `docs.yml` checks for the token first: present, the build
  runs as before; missing on a pull request from a fork, the build is
  skipped with a notice and a summary line (built after merge); missing
  anywhere else, the job fails. The Azure Static Web Apps jobs skip fork
  pull requests (they could never deploy: `pull_request`, not
  `pull_request_target`, so a fork's code is never given the deployment
  token). Coverage already skipped forks and Dependabot. `site/README.md`
  says so.
* **Tests run:** the workflows parse (the site's `yaml` package). Not run
  here: an Actions run from a fork (needs GitHub).

### B25 — repository and release controls, observed

* **Nature:** read-only. `gh api` on 2026-10-25; secret names only, no
  value read; nothing changed.
* **Observed:** `main` requires the one check `CI`, bound to the GitHub
  Actions app (id 15368), not strict, no reviews, admins not included,
  force pushes and deletion refused, no signed commits. No rulesets: tags
  (`v*`, `bindings/go/v*`) are unprotected. Release immutability off.
  Actions: every action allowed, SHA pinning not required by the setting
  (zizmor enforces it in CI), `GITHUB_TOKEN` read-only by default, Actions
  cannot approve reviews. No environments: the publishing credentials are
  repository secrets (names recorded in `docs/release.md`) readable by any
  workflow on any branch. Dependabot secrets: `FONTAWESOME_NPM_AUTH_TOKEN`.
  Both release workflows are `workflow_dispatch` only and, before B26,
  published from any branch without checking the commit's CI.
* **Not observable from GitHub:** which workflow, environment and branch
  each registry's trusted publisher trusts (PyPI, npm, crates.io, NuGet);
  recorded as unknown.
* **Recorded:** `docs/release.md`, "Repository controls, as observed",
  with the changes they call for (a tag ruleset, a `release` environment
  holding the credentials with registries bound to it, immutable
  releases, the branch rule applied to admins and strict), for the owner
  to review. None is made by the remediation.

### B26 — the exact release commit must have passed CI in full

* **Closes:** REC01 for the first publication and for the retry.
* **Changes:** `scripts/release/check-release-validation.py`: the commit is
  on `main`; a completed `ci.yml` run for exactly it, on `main`, from a
  push or a dispatch, in this repository, concluded `success`; every job of
  that run concluded `success` (a docs-only run, which skips the build
  jobs, and a cancelled run are refused; a later complete attempt counts);
  the commit's `CI` check was reported by the GitHub Actions app; any API
  failure refuses. `release.yml` preflight and `ReleasePackages.yaml` plan
  (for the commit the tag names) run it with `actions: read` and
  `checks: read`; a real run must also be dispatched from `main`, so a
  branch cannot bring its own gate; a dry run runs the same gate and
  reports with warnings. `ci.yml` gains `workflow_dispatch`, so a
  docs-only commit can get a full run (the classifier treats a dispatch as
  code). `docs/release.md` describes the gate.
* **Tests run:** `check_release_validation_test.py`, 10 tests with a faked
  API: a fully validated commit; not on `main` (diverged, behind); a short
  SHA; runs that are not `main`'s CI (another branch, a pull request
  event, another workflow file, a failure, another commit, a fork); a
  skipped, cancelled, failed or unfinished job; jobs that cannot all be
  read; a later complete attempt; a `CI` check from another app; an API
  failure at each call; real versus dry-run exit status. **Live**, read-only
  against GitHub: `main`'s commit 18138d3 is validated (CI run
  40175798981, 44 jobs, all success, `CI` from github-actions); the
  unpushed local commit is refused (unknown to GitHub). The workflows
  parse. Not run here: the workflows themselves (they publish; only a
  dispatch would run them, which the owner decides).

### B15 — recovery-key sources read only when needed

* **Closes:** SR08.
* **Changes:** `NonInteractiveUnlock::new` reads nothing; each
  `recovery_key` call consults the next source in order (the option, then
  `SOURCEORRERY_RECOVERY_KEY`, then the file), only when the vault asks:
  a vault this machine's key opens reads none, and the first key that
  works stops the search. A key equal to one already offered is consulted
  but not offered again. The report behind a `locked` hint records what was
  consulted, so a source never reached says "not consulted". A needed file
  that cannot be read or is empty is `io`, now with a hint that names the
  recovery-key file. The CLI was already lazy (it tries the environment
  variable or the file, then prompts); the difference from the SDKs, which
  try all three and never prompt, is unchanged and documented. Every
  binding inherits this from the Rust client.
* **Tests run:** unit 10 (new:
  `an_unusable_later_file_is_never_read_while_an_earlier_key_is_tried`,
  laziness and duplicate cases in the existing ones); `reader` 7, new
  `an_unusable_later_source_never_fails_an_open_an_earlier_one_completes`
  (a missing and an empty file behind the right key open; behind a wrong
  key they fail with `io`, named, the key not echoed; a wrong key then the
  right file opens). It **fails without the fix** ("cannot read
  recovery-key file …missing.txt" before the right key was tried). clippy
  clean.

### B16 — the child of `run` gets only the vault's values for its variables

* **Closes:** SR10.
* **Changes:** `run` removes every variable the manifest names from the
  child before it sets those that resolved, so an optional secret that is
  missing, disabled, outside its window or deleted leaves its variable
  absent; other variables pass through, and the unlock and view-check
  variables stay removed. On Windows the standard library matches the names
  case-insensitively, as the environment does. Rotation hooks receive no
  manifest variables, so they are unchanged. `docs/cli.md` says so.
* **Tests run:** `an_unresolved_optional_secret_leaves_its_variable_absent_in_the_child`
  (Windows: an optional secret the vault lacks and a disabled one, each
  with a stale parent value, one of them in lower case; a resolved one
  replaces its parent value; an unrelated variable survives). It **fails
  without the fix** (the child saw `[pw][stale-parent-value][stale-parent-value][kept]`).
  The other `run` tests pass (required failure stops the launch, the unlock
  variables never reach the child, the exit status passes whole).
* **Not run here:** the Unix spelling of the test (`sh -c`; CI runs it on
  Linux and macOS).

### B17 — the view check asks what the vault asks now

* **Closes:** SR11.
* **Changes:** `view_check()`, `password_hint()` and `authenticator()`
  read the view-check state as the file holds it now (one read
  transaction, through the verified settings record) and remember it for
  the handle, instead of the state cached when the handle opened. So
  `check_view` no longer returns early on a check another process set
  after this handle opened, and the CLI's prompts (which ask what
  `view_check()` says) agree with the decision. The documented exceptions
  stay: a handle the recovery key opened passes, and `run`, `check`,
  `init` and the SDKs never ask. A tampered record is refused as before.
* **Tests run:** `a_handle_follows_the_view_check_another_process_changes`
  (two handles: a password set, replaced and cleared elsewhere; an
  authenticator enrolled, verified and removed elsewhere; wrong answers
  counted elsewhere make this handle wait; the recovery-key handle passes).
  It **fails without the fix** (the second handle reported `none` after the
  password was set). Storage 76 tests; clippy clean. Same-user isolation is
  not claimed: the view check is a check, not encryption (ADR 0009).

### B18 — every refused settings change is recorded once

* **Closes:** SR14.
* **Inventory of the settings mutators:** connections (add, settings,
  credentials, test, remove), projects (link, unlink), descriptions,
  `change_settings`, recovery-key replacement and import all complete
  through one transaction helper that records a refusal (`fail`); the view
  check did not: `set_password` validated before its transaction (an empty
  password, a hint that gives the password away, Argon2 work factors past
  the limits), `enrol_authenticator` prepared its record before it,
  `verify_authenticator` and `check_view` returned early on a record they
  could not parse or weigh.
* **Changes:** `refuse_view_change`: a refusal before the transaction is
  recorded in its own transaction that passes the usual gate (one `guard` /
  `failure` event, the error code as its detail); Argon2 still runs before
  the write lock is taken, and the change is applied to the state as stored
  when it commits. The early returns in `verify_authenticator` and
  `check_view` go through `fail`. An audit write that fails is returned,
  never reported as recorded. `docs/cli.md`'s `guard` row says so.
* **Tests run:** `a_hint_must_not_give_the_password_away` now asserts one
  `failure` per refusal (four hints, an empty password);
  `every_view_check_change_is_recorded_once_and_never_its_input` (work
  factors past the limits, an enrolment without a password, a verification
  with nothing enrolled, a removal with nothing enrolled, around a
  successful set: five events, in order, none carrying the password or the
  hint). Both **fail without the fix** (no event for the hint refusals;
  four events instead of five). Storage 77 tests; clippy clean.
* **Not run here:** an audit-storage failure (no fault injection for
  SQLite writes; the error is returned by the same `?` as any write).

### B19 — Vault replies bounded while they are read

* **Closes:** REC05.
* **Changes:** `http::read_body` reads a reply chunk by chunk: a declared
  length over the 8 MiB cap is refused before anything is read; a body
  without a declared length, or past it, is stopped as soon as the next
  chunk would pass the cap (checked addition); the buffer is zeroised, and
  when it grows the old buffer is zeroised as it drops, so at most the cap
  plus one chunk is held. reqwest's decompression features are off, so the
  cap applies to the bytes as sent. Timeouts (10 s connect, 60 s overall)
  and error texts are unchanged. The guide's error table says so.
* **Tests run:** `tests/transport.rs`, 4 tests against a raw loopback
  server: a declared length over the cap; an endless chunked body (512 MiB
  offered: the server could hand over less than 16 x the cap before the
  client hung up); exactly the cap (read whole, then a parse error) and the
  cap plus one byte (refused); a body cut off part way (`provider_unavailable`,
  nothing of it echoed). Against the old `bytes()` reading the endless case
  **fails** (all 536,870,912 bytes were read before the refusal). The
  crate's 22 tests pass; clippy clean.
* **Not run here:** a slow body against the 60-second timeout (too long for
  a unit test; the timeout is reqwest's own).

### B20 — fewer plaintext copies in the CLI's input

* **Closes:** REC07, the CLI part (B21 the providers).
* **Inventory:** the hidden prompt (`rpassword`'s `String`, moved into
  `SecretBytes`: no copy here); a value from a file (`std::fs::read`) or
  stdin (`read_to_end` into a growing `Vec`: every reallocation freed a
  copy unwiped, and a failed read dropped the partial value unwiped); a
  password or recovery key from a file (`context::read_secret_file`, the
  same); a quoted `.env` value (a buffer the size of the rest of the file,
  then `shrink_to_fit`, which reallocated and freed the large one unwiped;
  an unclosed quote dropped the partial value); `import`'s whole file
  (already zeroised); a typed authenticator code (`read_line`'s `String`);
  the recovery key in `vault create`'s JSON body (a `serde_json` string,
  dropped unwiped).
* **Changes:** `cli::plain`: `push` grows a wiped buffer by moving it into
  a new one and wiping the old; `read_to_end` and `read_file` read into
  such a buffer in 8 KiB chunks (sized from the file's length when known),
  wiping the partial read on failure; `into_secret` moves a buffer into
  `SecretBytes` without a copy. `prompt::read_value` and
  `context::read_secret_file` use them; the `.env` parser builds quoted
  values with `push`; `read_line` reads into a wiped `String`; `vault
  create` wipes the key's copy in its JSON body after printing it. The
  threat model's memory-hygiene row names what stays outside (the
  terminal, the OS, stdout's own buffer, `rpassword`, other programs).
* **Tests run:** `plain` unit tests 3 (growth keeps every byte in order; an
  interrupted read is retried and a broken one reported; a file is read
  whole with a buffer sized from it, no growth, and moved into
  `SecretBytes` at the same address). The existing input tests pass
  unchanged (trailing newlines kept or stripped, empty values refused, the
  `.env` forms, escapes and errors that never carry a value, stdin and
  `--from-file`): CLI 214 tests. clippy clean. No claim is made about
  memory the program does not own.

### B21 — fewer plaintext copies in the provider adapters

* **Closes:** REC07, the provider part.
* **Inventory:** HashiCorp Vault: a write built the value into a
  `serde_json::Value` and reqwest serialised it into its own buffer, both
  dropped unwiped; a read moved the value `String` (no copy), but a base64
  value's text and a foreign object's parsed fields were dropped unwiped,
  and the object was serialised with `to_vec` (growth copies). AWS: a read
  copied `secret_string` / `secret_binary` out of the SDK's answer; a write
  hands the value to the SDK (its request owns it). Azure: a read moved the
  value; a base64 value's text was dropped unwiped; a write hands the value
  to the SDK. Credentials go into each SDK's credential types, which own
  them.
* **Changes:** Vault: `kv::to_wiped_json` serialises into a buffer wiped on
  drop that grows the wiping way; the transport sends every body from such
  a buffer as `Bytes::from_owner`, so reqwest frees it by wiping (new direct
  dependency `bytes`, already in the lock file); `write_data` wipes its JSON
  document after the request in every outcome; `decode_value` wipes the
  base64 text and the foreign object's fields. AWS: `read_value` moves the
  value out of the answer. Azure: the base64 text is held so it is wiped.
  The threat model's memory row states what the SDKs, hyper and rustls own.
* **Tests run:** `kv` unit test `json_copies_of_a_value_are_serialised_and_wiped`
  (nested strings serialised, then wiped; numbers kept); every provider test
  passes: Vault 23 (the publication model and the transport tests included,
  the B10 semantics unchanged), AWS 19 (the publication model included),
  Azure 17; the Vault live suite against the dev server passes. clippy clean.
* **Not run here:** the Azure live suite (its emulator; CI runs it). No
  allocation trace was taken: the change is reviewed by ownership.

### B27 — retried uploads are of verified files only

* **Closes:** REC02.
* **Changes:** `scripts/release/verify-release-artifacts.py`: the release's
  `SHA256SUMS` must carry a build provenance attestation from `release.yml`
  of this repository, GitHub-hosted runner, for exactly the commit the
  release gate validated, before it is trusted as the inventory (a checksum
  file from the same mutable release proves nothing by itself); then the
  downloaded files must be exactly its files for the job's patterns (none
  missing, none unexpected, none listed twice), each with the digest
  `SHA256SUMS` gives and its own attestation. `--dir` omitted checks
  `SHA256SUMS` alone, for the jobs that use its digests. A release without
  provenance is refused with its way out (a new version, or a separate
  review): no bypass. A verification-service failure refuses.
  `ReleasePackages.yaml`: the plan passes the validated commit to every
  job; npm, PyPI, NuGet and Maven Central verify their files right after
  downloading them and before any check or upload; the package managers
  verify `SHA256SUMS`; crates.io, Maven Central and pkg.go.dev check that
  the tag still names the validated commit (tags are unprotected, B25);
  the helper is taken from the workflow's own revision; each job gets
  `attestations: read`. `docs/release.md` describes it.
* **Tests run:** `verify_release_artifacts_test.py`, 12 tests with a fake
  `gh`: the files verify; a pattern takes only its files; changed bytes;
  a replaced file with a replaced `SHA256SUMS` (no provenance); a file
  without its own attestation; provenance for another commit; a missing,
  an unexpected and a twice-listed file; a pattern the release never had;
  the service failing; a legacy release; checksums alone; the exit status.
  **Live** against v0.2.0 (read-only; two of its files, 13 KB and 223 KB,
  downloaded to the scratch directory): verified, with `SHA256SUMS`; one
  byte appended to a file, refused by its digest; the v0.1.4 commit given
  instead, refused by the attestation ("expected SourceRepositoryDigest …").
  The workflow parses; it was not dispatched.

### B24 — documentation that matches the release it installs

* **Closes:** SR12 for the documentation; its install and first-read
  examples are run against the stamped candidate in B32.
* **One version, one release status.** The repository is bumped to
  **0.3.0** with `set-version.py --keep-node-links` (manifests and lock
  files only), so a build of this branch reports the version whose format
  it writes: as 0.2.0 it refused 0.2.0's own vaults as "an earlier
  release". `scripts/release/docs-version.py` stamps that workspace version
  into a fixed list of 32 install pages (README, `docs/building.md`,
  `supply-chain.md`, `ai-agents.md`, `coverage.md`, every SDK page, the
  site's getting-started and home pages, every binding and npm platform
  README): every SourceOrrery version in them (a CHANGELOG release, or the
  workspace version) becomes the workspace version, in links, tags,
  package versions and labels. History sentences that named other releases
  were rewritten; the registry install commands are pinned
  (`pip install sourceorrery==0.3.0`, `npm install @sourceorreryai/sdk@0.3.0`,
  `cargo add sourceorrery@0.3.0`, …; the Rust page's `sourceorrery = "0.1"`
  could not have resolved). Released or not comes from `CHANGELOG.md`: while
  no `## [0.3.0] - date` heading exists, 16 entry pages carry a generated
  note ("SourceOrrery 0.3.0 is not released yet", the current release and
  its documentation at its tag, and the upgrade guide), and the site header
  says `0.3.0 · unreleased` on every page (`site/src/lib/release-version.mjs`,
  the same two sources; it read `site/package.json` before). Moving the
  CHANGELOG entries under the release heading clears both.
* **Enforced:** `docs-version.py --check` in the docs workflow (with no
  token, so forks run it; README and CHANGELOG added to its paths) and in
  CI's release-scripts job, whose unit test also checks the repository; the
  release workflow refuses a real run whose documentation does not name the
  release as released (`--check --expect X.Y.Z`; a dry run warns).
  `docs/release.md` steps 1 and 4 replace the manual "point the install
  instructions at the new release".
* **Upgrading from 0.2.0** (`docs/upgrading.md`, on the site under Guides):
  keep the 0.2.0 CLI, move the file into a home of its own (0.2.0 reads it
  with `--home`; its credential-store entry is named after the vault id),
  create the new vault, pipe each value from 0.2.0's `secret get --reveal
  --raw` into `secret set --stdin --keep-trailing-newline`, set metadata
  again with `secret update`, check, and retire the old vault with 0.2.0's
  `vault destroy` when nothing needs it. A remote vault (`[vaults.*]`) moves
  the same way into a connection pointed elsewhere. Compromise response
  stays separate (threat model, gap 10). The `migration_required` message,
  the SDK hint and the agent skill's row now say the file is unchanged and
  is kept; before, the message said "recreate the vault with
  `sourceorrery setup`", which then failed with "already exists" while the
  old file was in place, and the skill now tells the agent to stop: the
  move reveals values.
* **Tests run:** the procedure, with the 0.2.0 Windows release CLI
  (downloaded and verified with `gh attestation verify` for the v0.2.0
  commit) and this branch's CLI, isolated home, credential store off,
  synthetic values compared by SHA-256: 41 checks pass. This release refuses
  the 0.2.0 file (schema 3) for `secret list`, `secret get --reveal`, `run`,
  `check`, `vault destroy`, `vault export` and `vault create`, with
  `migration_required`, and the home is byte-for-byte unchanged with no key
  or export file written. 0.2.0 reads the moved file; Git Bash, PowerShell
  7.6 (program to program) and cmd.exe pipes carry three values (one a
  PEM-style value ending in a line break, one secret whose newest version is
  disabled) byte for byte; a PowerShell 7 function in between, and Windows
  PowerShell 5.1, turn each value into CRLF lines, as the guide warns; a
  wrong 0.2.0 passphrase stops the loop with nothing stored; content type,
  tags and expiry match after `secret update`; 0.2.0's `vault destroy`
  removes the kept file. **Live** remote route against a Vault 2.2.1 dev
  server: a 0.2.0 remote vault at `secret/` into a connection at `next/`,
  both values byte for byte, 0.2.0's copies untouched. The conformance test
  for earlier schemas now covers schema 4 and checks the file byte for
  byte and the message's way out. `docs_version_test.py`, 9 tests; site
  tooling, 12 tests (MDX comment conversion; the header version); the site
  builds (46 pages) and its 4128 internal links resolve; integrations
  regenerated with `SOURCEORRERY_BLESS=1`.
* **Also in this batch:** the provider guides' "no audit log of
  SourceOrrery's own" bullet is replaced: the vault's own log records every
  provider call (ADR 0011), beside the provider's trail. The vault-format
  page is titled schema 5 (it said 4) and its site description says 5 (it
  said 3).
* **Not run here:** the install commands themselves (0.3.0 is not
  published; B32), and the remote route for AWS and Azure.

### B28 — the failure matrix

* **Closes:** REC04 as a matrix: every SR item has named regressions with
  evidence, or the verification that is still owed (B31/B32), below.
* **Matrix.** "Local" means run on this Windows machine in this ledger's
  batches; "CI" means only the hosted jobs run it (nothing was pushed, so
  they have not run on this branch yet).

  | Item | Area | Regression (where) | Evidence |
  |---|---|---|---|
  | SR01 | persisted state | `an_old_recovery_wrap_put_back_does_not_open_the_vault`, `a_wrap_row_added_or_swapped_is_refused`, `the_settings_record_covers_every_part_of_every_key_wrap`, `every_change_to_the_wraps_leaves_a_vault_that_opens` (storage) | local; fails without the fix (B03) |
  | SR02 | provider partial outcomes | Vault and AWS `tests/publication.rs` models (every request refused, failed or answer lost; two writers interleaved); lifecycle `a_new_restricted_version_is_never_returned` (every backend) | local, models fail without the fix; live Vault 2.2.1 and LocalStack AWS local; Azure emulator CI |
  | SR03 | provider calls while quarantined | `a_blocked_vault_sends_nothing_to_its_providers` (routed) | local; 13 provider calls without the fix |
  | SR03 / REC08 | outcomes, restart, retry | `a_lost_answer_is_outcome_unknown_until_a_later_change_settles_it` (never retried), `a_change_made_but_not_recorded_is_outcome_unknown`, `an_attempt_cut_short_by_a_restart_is_listed_when_the_vault_opens_again`, `a_refused_change_completes_its_attempt` (routed) | local |
  | SR04 | file permissions | `a_new_file_admits_only_its_owner_and_system`, `a_folder_that_grants_users_read_grants_them_nothing_on_the_file`, `a_failed_check_removes_the_empty_file`, `the_check_accepts_exactly_owner_and_system` (`sourceorrery-os`) | local (Windows); Unix branch in the Linux container (B12); a second account opening the file: B31 |
  | SR05 | SDK ownership | PHP `tests/run.php` clone and serialise cases | Linux container, PHP 8.2 (B12) |
  | SR06 | SDK ownership | `SecretValueLifetimeTests` (7) | local, .NET 10; four fail and one deadlocks without the fix |
  | SR07 | SDK ownership, concurrency | `GuardedTest` (5), `closeWhileReadsRunWaitsForThem`, `everyCallAfterCloseIsRefused` | local, JDK 27 |
  | SR08 | source selection | `an_unusable_later_source_never_fails_an_open_an_earlier_one_completes` (reader); SDK scenarios `open-key-file-not-needed`, `open-option-before-key-file`, `open-key-file-needed-and-missing` (new here) | local: Rust, Python, .NET and Java runners; Node, Go, C, C++ and PHP: CI |
  | SR09 | output failure, boundaries | `a_recovery_key_that_cannot_be_delivered_leaves_no_vault` (CLI: missing folder, stdout closed, plain and JSON) | local |
  | SR10 | child environment | `an_unresolved_optional_secret_leaves_its_variable_absent_in_the_child` | local (Windows spelling); Unix spelling CI |
  | SR11 | persisted state, two handles | `a_handle_follows_the_view_check_another_process_changes` | local |
  | SR12 | documentation | `docs_version_test.py`; the 0.2.0 transition checks (B24) | local; install commands of the stamped candidate: B32 |
  | SR13 | fork builds | the docs workflow's token step | needs a fork pull request (owner's disposition, B23) |
  | SR14 | refused changes audited | `every_view_check_change_is_recorded_once_and_never_its_input`, `a_hint_must_not_give_the_password_away` | local |
  | REC05 | bounded replies | `tests/transport.rs` (4) | local |
  | REC06 | AWS input | `user_tags_content_types_and_values_are_checked_before_any_request`, `invalid_input_sends_nothing_that_writes` | local |
  | REC07 | plaintext copies | `json_copies_of_a_value_are_serialised_and_wiped`, `cli::plain` tests | local (ownership review, no allocation trace) |
  | all | sensitive output | `attempts_and_unknown_outcomes_never_carry_a_value`; the conformance canaries; every SDK scenario's `*_excludes` | local |

* **Added here.** The SDK harness takes `env` and `unset` per scenario, so
  the recovery-key source order is held to the same contract in all nine
  languages with no runner change; it lists every scenario it does not run
  as `SKIP` with what it needs and counts them; and with
  `SOURCEORRERY_LIVE_REQUIRED=true` (as the live Rust suites already read
  it) a skipped provider scenario fails the run, so a job meant to read a
  provider cannot pass without reading it (per-version scenarios stay a
  skip: that is the provider's capability). `harness_test.py`, 5 tests,
  joins CI's script tests.
* **Found and fixed.** B15's new SDK hint had lost its line continuations
  (runs of 13 spaces mid-sentence in every language's hint):
  `every_hint_reads_as_one_sentence_run` now checks each hint and message,
  and fails on the damaged string. B21's `bytes` dependency was missing from
  the Python and Node extensions' lock files, which CI's `--locked` build
  of the wheel would have refused; both locks are updated (offline, one
  dependency edge) and `cargo metadata --locked` passes in all three roots.
* **Tests run:** harness against the fixture vault from
  `scripts/ci/fixture-vault.sh` with this branch's release CLI and C ABI:
  Rust, Python (a 0.3.0 wheel built with `maturin --locked`), .NET and Java
  29/29 with 6 provider scenarios skipped; against a Vault 2.2.1 dev server
  with the connection in the vault and `SOURCEORRERY_LIVE_REQUIRED=true`,
  all four 35/35 with none skipped; with the variable set and no
  `--remote`, the run fails. Client crate 11, clippy clean.
* **Owed (blocks sign-off, B31/B32):** the Node, Go, C, C++ and PHP runners
  on this branch (CI; no C compiler here); the Azure live suite; macOS and
  Linux runs of everything marked local; a second Windows account against
  SR04's files.

### B29 — what grows with a vault's history, measured

* **Closes:** REC08's scalability part (B06, B07 and B18 consolidated the
  state transitions; every write still enters through `begin` or
  `begin_view_check`, the three exceptions being the acknowledgement of a
  truncation, the purge right after the unlock's own check, and a new or
  exported file, each with its reason in the code).
* **Harness:** `crates/sourceorrery-provider/examples/scale.rs` builds a
  vault of N secrets and at least M audit events (reads, each recording
  one) and times what the CLI and the SDKs do: unlock, read, properties,
  listings, versions, the audit queries (newest, a follow poll, all),
  verification, export, the same through `Routed`, and four handles
  reading at once. Synthetic values, recovery key, no credential store.
  Machine: Intel Core i7-8650U (4 cores, 8 threads), 16 GB, Samsung NVMe
  SSD, Windows 11 Pro, NTFS; release build; median of 15 runs (5 for the
  whole-log operations). History varied at 10 secrets (1,000, 10,000 and
  100,000 events), secrets varied at 20,000 events (1,000 and 10,000).
* **Found:** every operation counted the keyed audit rows with a scan of
  the whole table three times (the gate's chain-head check, the append's,
  and the head written after it), so a read grew with its own history: 13
  ms at 1,000 events, 16 at 10,000, **91 at 100,000**; listings 128 ms, four
  handles 98 ms each. A partial index `audit_keyed` alone halved that (50
  ms) but, with no table statistics, the planner then chose it for the
  truncation, settings and checkpoint checks it does not serve (the
  truncation check, part of every operation, scanned every keyed row: 59
  ms). Running `ANALYZE` fixed the choice in a probe, but a plan that
  depends on statistics is not one to rely on.
* **Changed:** the audit indexes are one idempotent set, created with the
  schema and again at every unlock (a schema 5 file written before
  `audit_keyed` existed, or with an index dropped, has them all before the
  checks run; no index holds authenticated state). Each per-operation
  check names its index with `INDEXED BY` (the count and the newest keyed
  row `audit_keyed`, the acknowledgements and truncations
  `audit_verifications`, the newest settings checkpoint `audit_settings`,
  the checkpoints `audit_checkpoints`); the attempts query, read by
  `audit` only, scans the table (`NOT INDEXED`). No check is skipped: the
  counts, the walk at unlock and every audit row are as before.
* **Results** (median ms; before → after at the same file):

  | | 1k events | 10k | 100k | 1,000 secrets, 20k | 10,000 secrets, 20k |
  |---|---|---|---|---|---|
  | open | 21 → 21 | 63 → 68 | 524 → 553 | 162 → 90 | 118 → 101 |
  | get_secret | 13 → 13 | 16 → 17 | 91 → 22 | 28 → 14 | 28 → 15 |
  | list every secret | 14 → 15 | 18 → 15 | 128 → 18 | 55 → 33 | 173 → 180 |
  | Routed get_secret | 13 → 15 | 17 → 15 | 96 → 20 | 32 → 13 | 28 → 14 |
  | 4 handles, a read each | 13 → 14 | 17 → 15 | 98 → 21 | 27 → 14 | 28 → 15 |
  | follow poll | 0.25 → 0.17 | 0.84 → 0.77 | 26 → 27 | 5.0 → 4.1 | 9.0 → 5.2 |
  | verify the chain | 6 → 7 | 49 → 50 | 536 → 520 | 107 → 82 | 98 → 94 |

  (The 1k and 10k "before" columns are the first run's, made with the same
  pre-fix binary on fixtures built the same way.)
* **Budgets, for that machine:** to 100,000 events and 10,000 secrets, a
  read within 25 ms, an unlock within a second, a listing of 10,000 secrets
  within 250 ms; `docs/architecture.md` ("How costs grow") records them
  with what each grows with. They are not enforced in CI (timings on shared
  runners are not comparable); the harness is how to check them.
* **Left, measured and explained:** the walk at unlock (about 5 µs an
  event since the newest acknowledgement; it is the check that finds a row
  replaced inside the log, and verifying from a later point would skip
  authenticating those rows, a decision of its own); a follow poll scans by
  time (27 ms at 100,000 events, once per interval of at least a second; an
  id cursor would make it incremental, a change to `AuditQuery`); the keyed
  count is linear in the index (about 2 ms per 100,000, three per
  operation; one per write transaction would do); a read's floor is the
  audit commit in rollback-journal mode (about 12 ms here), which WAL would
  lower at the cost of files beside the vault, a format decision.
* **Tests run:** `every_check_reads_its_index_not_the_whole_log` (the head
  check's statements read `audit_keyed`; every audit index dropped, then
  an unlock: all five back, reads and listings work, the chain intact); it
  **fails without the index** (the plan names no index). Storage, provider,
  conformance and CLI suites; clippy clean for storage and provider.

### B30 — the minimum Rust and the feature combinations, built

* **Closes:** REC09's toolchain and feature part; REC03's maintenance
  dependency check has nothing to validate (B22 applied no update: the
  zbus notices wait on an upstream release).
* **Changes:** CI job `msrv` (in the `CI` gate's `needs`): it reads
  `rust-version` from the workspace and fails unless both native
  extensions declare the same; on that toolchain (1.91.1) it runs
  `cargo test --workspace --locked` and `scripts/ci/feature-matrix.sh`,
  the bounded list of supported combinations: the headless build of the
  CLI, the C ABI (and so the client), the adapters and storage, each
  feature on its own on top of it (`os-keyring`, `ui`, `otlp`, each
  provider, `remote`), the headless crates' tests, and both native
  extensions with and without their defaults. `docs/building.md` lists the
  combinations and the local commands.
* **Found:** the headless builds' tests assumed the defaults. The client's
  `a_secret_a_connection_stores_is_read_at_its_provider` expected
  `provider_unavailable` where a build without the provider correctly says
  `unsupported` (hint: "does not include a HashiCorp Vault provider"); it
  now asserts what each build does, attempts and log included. Two CLI
  tests need a provider and one the OTLP exporter: they are gated on those
  features, and new headless tests check that a build without the provider
  says so for a secret kept there while reading the file's own, and that
  one without OTLP refuses `--format otlp` and names JSON Lines.
* **Tests run (local, Windows, Rust 1.91.1, `target/msrv`):** every
  workspace package's tests, one package per command: core 53, crypto 28,
  storage 78, CLI 175 + 42 + 9 (with the UI session's changes then in the
  tree), os 5, provider 7 + 12, AWS 11 + 6 + 3, Azure 13 + 5, Vault 9 + 3 +
  3 + 5 + 4, client 11 + 7 + 1, C ABI 8 + 1 + 6 + 9, conformance 5 + 2 + 13
  + 43; the feature matrix, all 25 commands. On stable, the same fixed tests
  pass with and without default features; clippy clean for both.
* **Not run here:** the matrix on Linux and macOS (CI's `msrv` job runs it
  on Linux).

### B31 — platforms, packaged binaries and bounded fuzzing

* **Closes, as far as one Windows machine and Docker reach:** REC09's
  platform part; runtime evidence for SR04–SR08 is in B12–B15 and B28.
  What only CI or other machines can run is listed at the end and blocks
  sign-off.
* **Found: the Linux packages needed glibc 2.39.** Read from the headers of
  the v0.2.0 release's own binaries (each archive verified with `gh
  attestation verify` against the release workflow and the v0.2.0 commit;
  nothing extracted was run on the host): the Linux CLI and C ABI, x64 and
  arm64, need `GLIBC_2.39`, because they are built on `ubuntu-latest`
  (24.04), and so do the .NET and Java packages that carry the library and
  the Node addon built the same way. The released 0.2.0 CLI does not start
  on Debian 12 (`GLIBC_2.38' not found`), the base of most language
  container images; only the Python wheels (manylinux 2.28) did. The docs
  said "glibc-based distributions".
* **Changed:** `release.yml` builds the Linux CLI, C ABI and Node addon on
  `ubuntu-22.04` and `ubuntu-22.04-arm` (with Python 3.12 set up there,
  since `set-version.py` needs 3.11 and 22.04 has 3.10). Built so in an
  `ubuntu:22.04` container, the CLI and the C ABI need `GLIBC_2.34`, and
  the CLI runs, creates a vault, stores and reads a secret on Debian 12,
  Ubuntu 22.04 and Rocky Linux 9 (glibc 2.34). The architecture's platform
  matrix now states every floor: Linux glibc 2.34 (wheels 2.28), musl not
  supported; macOS 11.0 on Apple silicon and 10.12 on Intel (the binaries'
  `LC_BUILD_VERSION`); Windows 10 / Server 2016, x64 and arm64 (Rust's
  minimum for its MSVC targets; the PE headers say 6.0). Getting started
  says so for the Linux archive.
* **Bounded fuzzing:** `sourceorrery_conformance::fuzz::Mutator`, a
  deterministic mutator (deletes, inserts, repeats and replaces a few
  bytes of a valid seed), and tests that require a value or an error,
  never a panic: the core's manifest, reference, timestamp and grace-period
  parsers (5,000 cases each); a vault file with one field of one row
  mangled per copy (300 copies over the settings, key wraps, rows, values,
  version tags and audit fields: every copy opens, reads, lists and
  verifies as the stored value or an error, never another value); what
  HashiCorp Vault (properties documents, intents, deletion marker, times,
  value JSON), Secrets Manager (tags) and Key Vault (tags, identifiers,
  base64 values) return, 5,000 cases each. They run in CI's ordinary test
  jobs. **They found a panic:** `rotation::parse_grace` split off the last
  byte, so a manifest whose `retire_after` ends in a character longer than
  one byte (`7é`) made the CLI panic (`run`, `check`) and each SDK's project
  load fail with an internal error (the C ABI catches the panic). It reads
  the last character now; the grace test has the cases. Miri and sanitizers
  were not added: the `unsafe` code is the C ABI and `sourceorrery-os`,
  whose tests call into SQLite and the Windows API, which Miri cannot run.
* **Also checked:** the C ABI refuses another ABI: the current .NET SDK
  against the v0.2.0 `sourceorrery_ffi.dll` (verified as above) fails with
  `abi_mismatch` ("implements C ABI version 1; this SDK was built for
  version 2"), and opens with this branch's library.
* **Tests run:** the glibc reads and the container runs above (Docker,
  `ubuntu:22.04`, `debian:12`, `rockylinux:9`); the fuzz tests (core,
  conformance, and the three providers) on stable, and the providers' on
  1.91.1; clippy clean for the changed crates.
* **Owed (blocks sign-off):** macOS runs of everything (no Mac here); the
  Linux and macOS SDK suites and conformance runners for Node, Go, C, C++,
  PHP, Java and .NET (CI's `sdk-*` jobs; Rust, Python, .NET and Java ran on
  Windows in B28, PHP in a Linux container in B12); the OS credential-store
  smoke tests (CI's `keyring` job; not run on this machine by the owner's
  rule); the Azure live suite (CI); a second Windows account against SR04's
  files; real AWS, Azure and HashiCorp services (emulators and a dev server
  only); the release workflow on its new runners (a hosted dry run).

### B32 — the candidate rehearsed locally, and the recommendation

* **Candidate:** branch `security-remediation`, source commit 1472a86 for
  the checks below (32 commits over `main`'s 18138d3, six of them the UI
  work of a parallel session); version **0.3.0** in every manifest
  (`set-version.py 0.3.0 --check`), vault schema **5**, C ABI
  (`SO_ABI_VERSION`) **2**, contract **"2"**. Nothing was tagged, pushed,
  uploaded or deployed.
* **Inventory the release workflow builds from it** (unchanged but for the
  Linux runners): the CLI and C ABI archives for six targets (Windows,
  macOS and Linux glibc, x64 and arm64) with SBOMs, the Python wheels and
  sdist, the npm package and its six platform packages, the NuGet package,
  the Maven jar, nine crates, the Go module tag, the Packagist tag, the
  Homebrew, Scoop and WinGet manifests, and `SHA256SUMS`, each file with a
  build provenance attestation.
* **Rehearsal artifacts built here** (not release files; built from the
  working tree, with the UI session's then-uncommitted changes present):
  `sourceorrery.exe` 21,216,256 bytes
  `3192809b89c4ad23446e1ce97cb3dd887e2c4050f50945a87da0977daaa613f1`;
  `sourceorrery_ffi.dll` 16,202,752 bytes
  `21b048e21e73dd79772383382606650784a915d725fa00bb209a3c9c30b739c0`
  (x86_64-pc-windows-msvc); built on Ubuntu 22.04, `sourceorrery`
  22,335,160 bytes
  `11ca121d9226b9ffc8e0a49955c3a42ebb25f6f35c6e29b333123adb53bba7ae` and
  `libsourceorrery_ffi.so` 17,871,392 bytes
  `19c02164fccd52e101f1066518d71c4beb33cfebdf3b3b415c8befdbea864113`
  (x86_64-unknown-linux-gnu, glibc 2.34).
* **Checks over the committed tree** (a clean worktree at 1472a86, stable
  Rust 1.99.1): `cargo fmt --all --check` clean; every package's tests
  pass, 598 in all (core 53, crypto 28, storage 78, CLI 247, os 5,
  provider 19, AWS 20, conformance 63, Azure 18, Vault 24, client 19, C ABI
  24; one ignored), the C ABI header and integration drift tests among
  them. **`cargo clippy --workspace --all-targets -- -D warnings` fails**:
  28 findings, all in `crates/sourceorrery-cli/src/ui/` from the UI
  session's commits (`default_trait_access`, `semicolon_if_nothing_returned`,
  `too_many_lines` and others); none in what this remediation changed,
  whose crates are clippy-clean on their own.
* **Rehearsed with the candidate CLI:** the first run of getting started
  (version 0.3.0; vault with its recovery key in a file; `secret set` from
  stdin; listing without the value; reveal; `init --all` writing a
  value-free manifest; `check`; `run` giving the child the value; `audit
  --verify`; `vault export`, `vault import` into another home, opened with
  the recovery key): 12 checks pass. The upgrade from 0.2.0 (`docs/upgrading.md`)
  with the 0.2.0 release CLI: 41 checks pass. Old schemas are refused
  without a byte changing (B24, again here). The release's documentation
  step in a disposable worktree: with the CHANGELOG heading dated,
  `docs-version.py --check --expect 0.3.0` refuses until the pages are
  stamped, then passes with every "not released yet" note gone.
  `abi_mismatch` for a 0.2.0 C ABI library under the current .NET SDK.
* **Release helpers, dry:** all 96 Python helper tests pass;
  `check-release-validation.py --warn-only` refuses 1472a86 (GitHub does
  not know the commit), as it must before a push and a full CI run;
  `verify-release-artifacts.py` was exercised live in B27. The dependency
  audit passes on every graph (the three reviewed zbus notices). The site
  builds (46 pages) and its 4133 internal links resolve.
* **Recommendation: no-go for a release from this commit; go for pushing
  the branch and running CI.** Before a 0.3.0 tag:
  1. the UI session's 28 clippy findings fixed (CI's `clippy` job fails on
     them);
  2. the branch pushed and `ci.yml` green in full, every job, including the
     new `msrv` job, the `sdk-*` jobs on Linux and macOS, `keyring`, and
     the provider jobs with `SOURCEORRERY_LIVE_REQUIRED` (the owed items of
     B28 and B31);
  3. a hosted dry run of `release.yml` from `main` (the first on the Ubuntu
     22.04 runners), with its packages tried as `docs/release.md` step 2
     says;
  4. the items that need people or other machines: a second Windows
     account against SR04's files, a Mac, real provider services if their
     claims are to be more than emulator-tested.
  Every SR and REC item has its regression or verification named in this
  ledger; none is marked closed here, because the hosted runs above are
  part of their evidence.
