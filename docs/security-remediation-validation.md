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
