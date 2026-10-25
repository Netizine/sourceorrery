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
