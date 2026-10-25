# SourceOrrery 0.3.0 security remediation plan

**Status: proposed; no implementation started.**

This plan covers all **14 findings (four P1, nine P2, one P3)** and all **nine additional recommendations** in [the security review](SECURITY-REVIEW-2026-10-25.md). It is based on commit `18138d3e8cdb75387b12eb70e165ca5a62d9adbd` and the matching review pasted into this chat.

Work is divided into **32 ordered batches**. Each batch has one primary outcome, dependencies, affected files, tests, and acceptance criteria. The order is the default execution sequence; independent batches can proceed in parallel as described below. Each batch should remain a separately reviewable change. If implementation exposes a larger problem, split that batch and update this plan rather than quietly broadening it.

**Current authorization is planning only.** No fixes, source edits, commits, pushes, remote workflow dispatches, releases, or account-setting changes are authorized by this plan. Creating this document does not start any batch. Future execution should stop at a locally validated release candidate until publication is explicitly requested.

## Recommended decisions

1. **Recovery-key replacement:** authenticate the active wrap inventory and document that replacing a recovery key updates access to the active file; it does not erase an old key holder's knowledge of the existing data-encryption key (DEK). The 0.3.0 compromise-response procedure should create an independently keyed vault and rotate affected credentials at their issuers. Ordinary export/import preserves key material and must not be described as compromise recovery. In-place DEK rotation is a separate feature unless the product explicitly requires it for 0.3.0; if required, add and complete that work before closing SR01.
2. **Compatibility:** settle the on-disk format in B02 before changing authenticated records. Use a new explicit format revision if the new verification rules are incompatible with current schema-4 files; do not silently redefine an existing format. Document any refusal of development vaults. Preserve the ABI/contract decision unless an actual interface change requires another revision; append error codes rather than renumbering them.
3. **Provider operations:** enforce local integrity before dispatch and represent unknown/partial outcomes honestly. Do not promise a distributed transaction across SQLite and a cloud provider. Provider writes that cannot preserve required access policy must be refused before publication until a safe representation is implemented.
4. **SDK ownership:** reject PHP reader cloning, defer .NET buffer release while callbacks are active, and protect Java calls for their entire native lifetime. Preserve public read-only behavior.
5. **Environment injection:** clear manifest-declared destinations in the child before applying resolved values; retain unrelated environment variables. Optional unavailable secrets should not implicitly use an inherited credential.
6. **Documentation and releases:** make validation work without repository secrets, require validation of the exact release commit, and verify original artifact provenance before retry publication. Record unknown repository/account settings before proposing changes to them.

These are proposed implementation choices, not assertions that they have already been applied. B02 and B08 turn the complex key/provider choices into reviewable design records before their dependent code changes.

## Coverage and dependencies

Additional review recommendations are assigned stable IDs here: **REC01** release-commit validation; **REC02** retry provenance; **REC03** dependency graphs and maintenance; **REC04** failure conformance; **REC05** streamed response limits; **REC06** AWS tag validation; **REC07** plaintext-copy reduction; **REC08** scalability and state-transition maintainability; **REC09** platform/toolchain contracts. These labels correspond to recommendations 1–9 in the review, not new findings or new severity ratings.

| Review item | Batches that deliver it |
|---|---|
| SR01 P1 — recovery-wrap integrity and replacement guarantee | B02, B03, B24, B28 |
| SR02 P1 — fail-closed provider publication | B08, B09, B10, B11, B28 |
| SR03 P1 — provider operations during local quarantine | B06, B07, B28 |
| SR04 P1 — Windows recovery-key file permissions | B04, B05, B31 |
| SR05 P2 — PHP cloning and native ownership | B12, B31 |
| SR06 P2 — .NET callback disposal | B13, B31 |
| SR07 P2 — Java concurrent close | B14, B31 |
| SR08 P2 — recovery-source order | B15, B28 |
| SR09 P2 — failed recovery-key delivery | B05, B28 |
| SR10 P2 — inherited optional credentials | B16 |
| SR11 P2 — stale view-check state | B17 |
| SR12 P2 — release/API/audit documentation | B24, B32 |
| SR13 P2 — secret-dependent fork docs build | B23 |
| SR14 P3 — rejected settings changes absent from audit | B18, B28 |
| REC01 — require validation of release commit | B25, B26, B32 |
| REC02 — verify artifacts before retry publishing | B25, B27, B32 |
| REC03 — scan all dependency graphs and track maintenance | B22, B30 |
| REC04 — failure matrix as conformance surface | B01, every defect batch, B28 |
| REC05 — streaming response cap | B19 |
| REC06 — AWS namespace/service-limit validation | B09 |
| REC07 — reduce temporary plaintext copies | B20, B21 |
| REC08 — scalable audit history and centralized state transitions | B06, B07, B18, B29 |
| REC09 — minimum toolchain, feature and platform contracts | B30, B31, B32 |

After B01, these streams can proceed independently: storage design/integrity (B02–03), Windows file handling (B04), SDK lifetime fixes (B12–14), source selection and environment handling (B15–16), response limits (B19), dependency checks (B22), docs installation (B23), and read-only release-settings inventory (B25). Keep one editor responsible for a shared file at a time. In particular, coordinate changes to storage transactions, provider write paths, and `.github/workflows/ci.yml`.

## Batch 01 — Establish the implementation baseline

**Covers:** REC04; prerequisites for all findings. **Depends on:** none.

**Work:** verify the implementation checkout against the reviewed commit, preserve unrelated user files, and record any intervening changes. Inventory the existing regression fixtures, language test runners, lockfiles, and supported targets. Add only minimal reusable test support needed for deterministic failure injection, isolated provider stubs, and native lifetime observations; add each actual regression beside its fix, not a large unrelated test framework.

**Affected files:** this plan; `tests/conformance/src/lib.rs`, `tests/conformance/tests/security.rs`, `crates/sourceorrery-provider/tests/routed.rs`, and language test helpers only where reuse is justified. Proposed coverage ledger: `docs/security-remediation-validation.md`.

**Tests:** run the existing Rust workspace baseline once; record existing skips and environment-dependent cases. Verify fixtures use temporary vaults, synthetic values, and no real credential store. Preserve the earlier review's resolved regression cases.

**Acceptance:** the ledger identifies the starting SHA, test/toolchain versions, executed versus skipped checks, and every SR/REC item. No production values or user vaults enter test fixtures. Existing failures are distinguished from new failures.

## Batch 02 — Decide the key-replacement and vault-format contract

**Covers:** SR01. **Depends on:** B01.

**Work:** write a short ADR defining active-wrap authentication, replacement versus compromise recovery, export/import behavior, and the format/compatibility rules. Specify how creation, replacement, machine-key addition/removal, export, import, and destruction affect the authenticated inventory. Choose the exact new schema revision if required. Include an independently keyed replacement-vault procedure and issuer credential rotation for suspected compromise; retain old backups without claiming they can be made unreadable remotely.

**Affected files:** a new ADR under `docs/adr/` using the next available number; `docs/vault-format.md`, `docs/threat-model.md`, `docs/adr/0007-versioning-and-compatibility.md`, references from ADR 0009. No storage implementation in this batch.

**Tests:** design review against all key-management entry points and old-format fixtures; check that the proposed procedure does not rely on export/import to generate a fresh DEK.

**Acceptance:** one unambiguous guarantee, format decision, compatibility policy, and compromise-response procedure exist. No statement implies that authenticating a wrap inventory revokes a DEK already known to another party. If full DEK rotation is required, its implementation/recovery tests become explicit additional release dependencies rather than being hidden inside B03.

## Batch 03 — Authenticate the active key-wrap inventory

**Covers:** SR01. **Depends on:** B02.

**Work:** implement the ADR's canonical wrap-inventory authentication and audit checkpoint binding. Make every legitimate wrap change update both consistently. Verify the active inventory after obtaining a candidate DEK and before normal vault use. Preserve legitimate machine/recovery unlock, export, and import semantics. Handle compatibility using B02's explicit format rules.

**Affected files:** `crates/sourceorrery-storage/src/integrity.rs`; `src/sqlite/wraps.rs`, `settings.rs`, `schema.rs`, `mod.rs`, `export.rs`, `audit.rs` under that crate; `crates/sourceorrery-storage/src/registry.rs`; storage tests and `tests/conformance/tests/security.rs`.

**Tests:** table-driven inventory edits, additions, removals, substitution, and historical-state validation; interrupted replacement; machine-key operations; export/import round trips; prior-format refusal without mutation; existing integrity/conformance tests.

**Acceptance:** an out-of-date or altered active inventory is rejected before secrets are returned. Successful wrap changes and their checkpoints commit consistently. The current file honors replacement, and documentation retains B02's narrower cryptographic guarantee. No legitimate export/import path bypasses verification.

## Batch 04 — Create recovery-key files with restrictive Windows permissions

**Covers:** SR04. **Depends on:** B01.

**Work:** introduce a small platform-specific secret-file creation helper. On Windows, apply the restrictive security descriptor at creation, prevent broad inherited access, and establish the intended owner/system access. Keep exclusive creation and Unix `0600`. Fail before writing key bytes if the required protection cannot be established. Isolate any necessary unsafe/platform API usage in the smallest reviewed boundary consistent with workspace lint rules; prefer an appropriate safe wrapper where available.

**Affected files:** `crates/sourceorrery-cli/src/commands/vault.rs`; a proposed private file helper module; `crates/sourceorrery-cli/Cargo.toml` and lockfile only if a dependency is needed; `crates/sourceorrery-cli/tests/cli.rs`.

**Tests:** Windows shared-parent ACL fixture, restrictive-parent fixture, existing destination, creation failure, and unsupported filesystem behavior; Unix mode check. Inspect final ACLs and use a separate test identity where the CI environment supports it.

**Acceptance:** broad read grants are absent before any plaintext is written; existing files are never overwritten. A failure leaves no plaintext key in an insecure file. Output messages describe guarantees actually enforced.

## Batch 05 — Make vault creation and recovery-key delivery failure-safe

**Covers:** SR09; completes SR04 integration. **Depends on:** B03, B04.

**Work:** reserve the output safely before finalizing creation, coordinate vault registration and key delivery, and define cleanup/retry behavior for each failure point. Cover initial open, write, flush/synchronization, and finalization failures. Cleanup must remove only resources created by this attempt. Keep explicit behavior for stdout/JSON key delivery and a broken output stream; do not silently retain an inaccessible recovery-only vault or overwrite an earlier key file.

**Affected files:** `crates/sourceorrery-cli/src/commands/vault.rs`; B04's helper; `crates/sourceorrery-storage/src/registry.rs` if lifecycle coordination requires it; CLI and storage creation tests.

**Tests:** missing parent, permission denial, pre-existing file, short/failed write, flush failure, broken pipe, concurrent creation, and failures immediately around vault registration. Run existing creation-race tests again after these changes.

**Acceptance:** every failure leaves either no new registered vault or an explicitly documented recoverable outcome with a retained valid key. Existing vaults/files are preserved. Retry behavior is deterministic, and successful creation produces a usable key with B04's permissions.

## Batch 06 — Check integrity before every provider dispatch

**Covers:** SR03; REC08. **Depends on:** B03.

**Work:** add one reusable storage preflight for current integrity/quarantine state and use it before every provider operation, including cached clients, listings, reads, writes, and recovery operations. Define the boundary between preflight and later concurrent state changes; avoid holding a SQLite write lock across arbitrary network waits. Do not use a process-local flag as the sole authority.

**Affected files:** `crates/sourceorrery-provider/src/routed.rs`; `crates/sourceorrery-storage/src/sqlite/mod.rs`, `audit.rs`, `connections.rs`; `crates/sourceorrery-provider/tests/routed.rs`; conformance security tests.

**Tests:** instrumented provider call counters, cached and uncached clients, pre-existing quarantine, newly detected integrity failure, and interleaving of local state changes with dispatch. Assert the relevant provider method is never called when preflight refuses.

**Acceptance:** a vault already blocked at preflight performs zero provider calls. All routes share the same current-state gate. The residual race/partial-outcome behavior is explicitly carried into B07, not described as distributed atomicity.

## Batch 07 — Represent provider outcomes that cannot be committed locally

**Covers:** SR03; REC04/REC08. **Depends on:** B06.

**Work:** implement durable operation intent/outcome or an equivalent reviewed reconciliation design. Distinguish definite refusal, definite provider success, and unknown outcome after communication failure. Ensure local audit/catalog failure after a provider success cannot be reported as though nothing happened. Define restart reconciliation and retry/idempotency rules per operation. Do not blindly retry non-idempotent operations.

**Affected files:** `crates/sourceorrery-provider/src/routed.rs`; storage `sqlite/connections.rs`, `audit.rs`, `schema.rs`; `crates/sourceorrery-core/src/audit.rs`, `error.rs` if necessary; `crates/sourceorrery/src/error.rs`; error mappings/conformance fixtures in each binding if a public code is added; `docs/providers/index.md` and audit documentation.

**Tests:** failure before dispatch, provider rejection, confirmed remote success followed by local persistence failure, response loss, restart with an incomplete operation, and safe retry. Test that error bodies and intent/outcome records exclude values and credentials.

**Acceptance:** callers can distinguish a rejected operation from one that may have happened. Recovery preserves integrity without forging certainty about missing events. Every schema/error-contract addition follows B02 and the existing versioning rules; all bindings recognize any new public code.

## Batch 08 — Specify safe provider publication and policy semantics

**Covers:** SR02. **Depends on:** B07.

**Work:** document the state machine for publishing values with disabled/time-window policy for Vault and AWS. Prefer provider-native atomic controls where they meet the contract; otherwise design a version-bound committed representation that every SourceOrrery reader honors. Explicitly cover externally created entries, older stored representations, metadata-only APIs, concurrent writers/readers, and ambiguous outcomes. State which guarantees apply through SourceOrrery and which require provider IAM; SourceOrrery metadata cannot impose restrictions on a separately authorized native provider client.

**Affected files:** a short new ADR or focused amendment to `docs/adr/0008-remote-providers.md`; `docs/providers/hashicorp-vault.md`, `docs/providers/aws-secrets-manager.md`; proposed contract cases in `tests/conformance/src/lifecycle.rs`.

**Tests:** review the design against each write boundary and documented provider capability; use a small state-transition model to show that a restricted or uncommitted version is never returned by SourceOrrery. Confirm the design handles a response lost after server acceptance.

**Acceptance:** the implementation choice and legacy-entry handling are settled before B10/B11. Merely swapping request order or attempting cleanup is not accepted as proof. If a combination cannot be implemented safely, define its pre-write `unsupported` result and capability/documentation changes explicitly.

## Batch 09 — Validate AWS tags and limits before writes

**Covers:** REC06; supports SR02. **Depends on:** B08.

**Work:** reserve `sourceorrery:` for internal policy tags, validate user tags and the final combined tag set against verified AWS constraints, and reject invalid values before provider mutation. Account for internal metadata consuming the service's limits. Preserve the distinction between omitted user tags and explicit replacement/clearing. Verify current service limits from official provider documentation during implementation.

**Affected files:** `crates/sourceorrery-provider-aws/src/mapping.rs`, `lib.rs`; provider unit tests and a focused mock transport test if needed; `docs/providers/aws-secrets-manager.md`.

**Tests:** reserved keys, malformed names/values, combined-limit boundaries, normal metadata round trips, and a provider request counter proving zero writes for invalid input. Compare error semantics with Azure's existing validation.

**Acceptance:** invalid user input cannot overwrite internal policy fields or fail only after publication. Valid existing user tags retain their documented behavior.

## Batch 10 — Implement fail-closed publication for HashiCorp Vault

**Covers:** SR02. **Depends on:** B08.

**Work:** implement the chosen publication representation/state machine in the Vault adapter and reader/metadata mapping. Apply the B07 outcome rules. Keep metadata, latest-version selection, explicit-version reads, and legacy-entry treatment consistent. Do not expand claimed provider capabilities without proving their behavior.

**Affected files:** `crates/sourceorrery-provider-vault/src/lib.rs`, `kv.rs`, `http.rs` only where necessary; `tests/errors.rs` plus proposed publication-failure tests; `tests/conformance/src/lifecycle.rs`; Vault provider guide.

**Tests:** synthetic provider failures at every publication stage, restricted time windows, simultaneous readers, explicit/latest version selection, concurrent writers, response loss, and retry. Then run the lifecycle suite against a disposable real Vault service.

**Acceptance:** no SourceOrrery read returns a version before its restrictive policy is effective. Unsupported combinations are refused before a write. Confirmed and uncertain outcomes remain distinguishable; a returned error never falsely guarantees that the provider was unchanged.

## Batch 11 — Implement fail-closed publication for AWS

**Covers:** SR02. **Depends on:** B08, B09.

**Work:** implement the AWS-specific publication flow, treating its secret-wide policy and version labels explicitly. Preserve prior-version accessibility where the contract requires it. Avoid advertising per-version policy that AWS does not implement. Integrate the partial-outcome/reconciliation design.

**Affected files:** `crates/sourceorrery-provider-aws/src/lib.rs`, `mapping.rs`; AWS unit/mock tests and `tests/live.rs`; shared lifecycle capability tests; AWS provider guide.

**Tests:** existing and new secret paths, tag/staging failures, lost responses, concurrent reads, retry, and unsupported per-version operations. Use an emulator for repeatable failures and a bounded authorized service test for semantics the emulator cannot establish.

**Acceptance:** policy restrictions cannot be bypassed by value publication followed by a failed policy update. Unsupported operations make zero mutations. Tests report whether they used an emulator or the actual service and do not pass silently when prerequisites are absent.

## Batch 12 — Give PHP readers one native owner

**Covers:** SR05. **Depends on:** B01.

**Work:** prohibit cloning of `SecretReader`, following the established `SecretValue` convention. Check other owning wrappers for equivalent implicit copy/serialization paths, but keep unrelated binding changes separate. Preserve idempotent close and predictable use-after-close errors.

**Affected files:** `bindings/php/src/SecretReader.php`; `bindings/php/tests/run.php`; PHP SDK documentation if ownership rules need clarification.

**Tests:** clone rejection, explicit close, repeated close, destruction after close, exceptions during use, and ordinary reads from the original object after a failed clone. Run with PHP FFI and the candidate native library.

**Acceptance:** PHP code cannot duplicate ownership accidentally; each native reader is freed once. No apparently open wrapper retains a freed native handle. The PHP tests execute rather than being recorded as unavailable.

## Batch 13 — Keep .NET buffers alive through callbacks

**Covers:** SR06. **Depends on:** B01.

**Work:** introduce an active-use lifetime guard with deferred final release, preserving the zero-copy `Use` API. Define disposal-requested versus fully released state and reject new uses after disposal is requested. Make active-callback accounting exception-safe and handle nested calls. Avoid introducing a deadlock when a callback itself requests disposal.

**Affected files:** `bindings/dotnet/SourceOrrery/SecretValue.cs`; `bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs`; add a focused lifetime test file in that test project if clearer; model documentation for disposal semantics.

**Tests:** disposal inside callback, nested callbacks, callback exception, concurrent external dispose, owner-triggered dispose, repeated dispose, and finalizer stress. Use an instrumented free boundary to verify timing, then ordinary native-library integration tests.

**Acceptance:** the underlying buffer remains allocated until every existing callback finishes, and releases exactly once afterward. Calls begun after a disposal request fail predictably. No test needs to dereference freed memory to demonstrate correctness.

## Batch 14 — Protect Java readers for the entire native call

**Covers:** SR07. **Depends on:** B01.

**Work:** use a lifetime guard or read/write lock around complete native calls, with exclusive close waiting for active calls. Cover every accessor, not only `get`. Preserve support for sharing a reader among platform/virtual threads, and define calls racing close without relying on an atomic pointer snapshot alone.

**Affected files:** `bindings/java/src/main/java/ai/sourceorrery/SecretReader.java`; `bindings/java/src/test/java/ai/sourceorrery/ReaderTest.java`; a private handle helper if needed; `docs/sdks/java.md`.

**Tests:** deterministic barriers around native get/properties/resolve/descriptor calls, concurrent close, repeated close, read failure followed by close, and normal parallel reads. Use an observed/mock close boundary first and the candidate native library for integration.

**Acceptance:** native free cannot overlap any active call. Close completes once active calls finish, future calls fail cleanly, and concurrency tests do not depend solely on timing or repeated crash attempts.

## Batch 15 — Resolve recovery sources only when needed

**Covers:** SR08. **Depends on:** B01.

**Work:** replace eager fallback-file loading with lazy evaluation in the documented order. Keep diagnostics accurate about sources actually attempted; deduplicate candidates without exposing them. Preserve explicit environment opt-out. Reconcile any intentional CLI/SDK difference rather than copying behavior into individual bindings.

**Affected files:** `crates/sourceorrery/src/unlock.rs`, `reader.rs`, `error.rs`; `crates/sourceorrery/tests/reader.rs`; `crates/sourceorrery-ffi/tests/reader.rs`; shared SDK scenarios/runners only if the fixture needs an additional operation.

**Tests:** valid machine, explicit, and environment sources combined with missing/unreadable/empty later files; wrong earlier credentials followed by a valid later source; all sources unavailable; duplicate candidates; environment disabled. Use an in-memory machine store for deterministic unit tests.

**Acceptance:** an unused fallback cannot defeat a successful earlier source. Required fallback errors still produce useful typed diagnostics. Every binding inherits the behavior from Rust, and no extra prompt appears in a library.

## Batch 16 — Make the child environment match manifest resolution

**Covers:** SR10. **Depends on:** B01.

**Work:** remove each manifest-declared destination from the child before inserting successfully resolved values. Retain unrelated environment variables and the existing removal of unlock credentials. Check case-insensitive destination handling on Windows. Document the absence behavior of optional entries.

**Affected files:** `crates/sourceorrery-cli/src/commands/project.rs`; `crates/sourceorrery-cli/tests/cli.rs`; `docs/cli.md`; rotation-hook handling only if it shares and needs the same helper, without silently changing separate hook semantics.

**Tests:** optional missing/disabled/expired/deleted entry with an inherited synthetic value; valid override; unrelated environment retention; required failure prevents launch; reserved unlock variables remain absent; Windows case variants; exit-status preservation.

**Acceptance:** unresolved optional entries are absent from the child, resolved entries have the intended value, unrelated variables survive, and no secret is logged by the verification commands.

## Batch 17 — Read current view-check state before deciding no check is needed

**Covers:** SR11. **Depends on:** B03.

**Work:** move the no-check decision after an authenticated current-state read. Refresh cached presentation state consistently, including password hints and authenticator status where appropriate. Keep the documented recovery-key bypass and the deliberate exclusion of `run`, `check`, `init`, and SDK reads.

**Affected files:** `crates/sourceorrery-storage/src/sqlite/view.rs` and storage tests; `crates/sourceorrery-cli/src/context.rs`, setup/session integration only if prompt refresh requires adjustment.

**Tests:** two handles observing enable, clear, password replacement, authenticator enrollment/removal, and current lockout state; recovery-key-opened handle behavior; tampered settings refusal; inspection of a quarantined vault.

**Acceptance:** a later `check_view` uses current authenticated policy, not the handle's original no-check state. UI prompts agree with that policy. This change does not claim same-user isolation or add view prompts to runtime consumers.

## Batch 18 — Audit rejected settings changes consistently

**Covers:** SR14; REC04/REC08. **Depends on:** B03, B17.

**Work:** centralize completion of public settings mutations so validation failures are recorded exactly once when the vault is available and the audit path is writable. Inventory early returns across password, authenticator, connection, recovery-key, and project-setting operations. Keep expensive derivation outside long-lived write locks where possible; revalidate mutable state when committing.

**Affected files:** `crates/sourceorrery-storage/src/sqlite/view.rs`, `settings.rs`, `audit.rs` and applicable settings modules; storage tests; `tests/conformance/tests/security.rs`; audit-contract documentation.

**Tests:** empty password, invalid hint, unsupported KDF parameters, invalid settings and connection requests, normal success, state changed during preparation, and audit-storage failure. Assert event count, outcome type, and absence of sensitive rejected input.

**Acceptance:** every settings attempt covered by the audit contract follows one completion path and produces one outcome when persistence is possible. Audit I/O failure is surfaced rather than silently claiming a durable record. No duplicate outcomes or plaintext failures enter the log.

## Batch 19 — Bound Vault response memory while reading

**Covers:** REC05. **Depends on:** B01; coordinate with B10 if both touch transport code.

**Work:** enforce the existing response-size policy during streaming, with checked accumulation and an early stop beyond the bound. Treat declared length as an early rejection hint, not the only bound. Apply the limit to decoded/decompressed bytes as appropriate to the actual HTTP stack. Preserve timeouts and sanitized errors.

**Affected files:** `crates/sourceorrery-provider-vault/src/http.rs`; provider `Cargo.toml` only if stream support requires a feature; `tests/errors.rs` and focused transport fixtures.

**Tests:** responses with and without length headers, chunked transfer, too-large declared length, overflow-safe accounting, exact boundary, boundary-plus-one, early disconnect, decompression where enabled, and slow response timeout.

**Acceptance:** oversized bodies are rejected without buffering their complete content. Peak owned response buffering is bounded by the configured cap plus a documented small read-chunk overhead. Errors do not include response bodies or tokens.

## Batch 20 — Reduce temporary plaintext copies in CLI input handling

**Covers:** REC07, CLI portion. **Depends on:** B05, B16.

**Work:** inventory owned input buffers in hidden prompts, file/stdin reads, dotenv parsing, recovery-key output, and error paths. Use zeroizing ownership from the earliest practical point, avoid unnecessary clones and reallocations, and clear partial buffers on failure. Keep legitimate explicit reveal/output behavior intact.

**Affected files:** `crates/sourceorrery-cli/src/prompt.rs`, `dotenv.rs`, `context.rs`, `commands/import.rs`, `commands/vault.rs`; narrow setup/input buffer code if the inventory identifies a concrete copy; existing CLI/input tests.

**Tests:** input/parsing/read failures, trailing-newline rules, malformed UTF-8, aborted prompts where testable, and log/error canaries. Test owned-buffer release through a controlled hook where useful; avoid broad allocator/OS memory-erasure claims.

**Acceptance:** each owned plaintext buffer has a documented lifetime and cleanup path. Avoidable copies are removed, errors remain value-free, and existing input behavior is preserved. Copies made by terminals, runtimes, or user applications are stated as outside the guarantee.

## Batch 21 — Reduce temporary plaintext copies in provider adapters

**Covers:** REC07, provider portion. **Depends on:** B10, B11, B19.

**Work:** inventory value/credential copies through request construction, encoding, response parsing, and JSON intermediates across Vault, AWS, and Azure. Reduce copies the project controls and shorten their lifetime; use zeroizing owners where compatible. Document unavoidable SDK-owned buffers rather than claiming they are wiped. Do not bypass provider SDK correctness or TLS protections to reduce a copy.

**Affected files:** `crates/sourceorrery-provider-vault/src/{lib.rs,kv.rs,http.rs,auth.rs}`; AWS `src/{lib.rs,mapping.rs}`; Azure `src/{lib.rs,mapping.rs,credential.rs}`; provider tests and threat-model memory-limit text.

**Tests:** text/binary value round trips, success/error/timeout cleanup paths, redacted debug/error output, and regression of B10/B11 publication semantics. Review representative allocation/lifetime traces where supported.

**Acceptance:** unnecessary project-owned plaintext copies are removed or wiped reliably, sensitive error/debug output remains absent, and documented limits match the actual third-party SDK ownership model. Keep separate provider commits if this exceeds a small reviewable change.

## Batch 22 — Scan every dependency graph and track maintenance warnings

**Covers:** REC03. **Depends on:** B01.

**Work:** inventory all independently resolved production and build-tool dependencies, wire their audits into CI, and document policy for vulnerabilities versus maintenance notices. At minimum include all three Rust lockfiles, the site and Node binding locks, and the npm locks in `scripts/coverage` and `scripts/ci/lstk`. Include Python CI requirements and other package manifests in the inventory even if they require a different scanner. Record the upstream path for the three D-Bus maintenance warnings; put required dependency upgrades in separate small changes with relevant keyring/MSRV tests.

**Affected files:** `.github/workflows/ci.yml`, `.github/dependabot.yml`, `docs/supply-chain.md`; a small proposed inventory/audit helper and its tests under `scripts/ci/`. Dependency manifests/locks change only in separately identified upgrade work, not incidentally while adding audit coverage.

**Tests:** execute each inventory entry with current advisory data; use mocked scanner results to prove an affected graph or scanner failure cannot disappear from the gate. Verify excluded/unsupported graphs are reported explicitly. Exercise any maintenance dependency update through the affected platform tests and B30.

**Acceptance:** every independent graph has a named check or explicit documented gap; known release-blocking vulnerabilities and unavailable required scans prevent a clean result. Maintenance warnings have an owner-by-role, upstream reference, target upgrade or reviewed rationale, and revisit trigger. A maintenance exception is not labeled a vulnerability fix.

## Batch 23 — Make documentation builds work without private registry credentials

**Covers:** SR13. **Depends on:** B01.

**Work:** select public or appropriately licensed local icon assets/fallbacks after checking redistribution rights. Remove the private token requirement from ordinary install/build/test. Separate trusted deployment configuration from untrusted pull-request validation, including coverage workflows that install site dependencies.

**Affected files:** `site/src/lib/font-awesome.mjs`, `site/package.json`, `site/package-lock.json`, `site/.npmrc`; `.github/workflows/docs.yml`, applicable site/coverage/deployment jobs; site build documentation.

**Tests:** clean install with the Font Awesome token unset, `npm test`, full Astro build and postbuild link check using Node satisfying `site/package.json`; icon visual spot checks; fork-equivalent and Dependabot-equivalent validation without secrets.

**Acceptance:** documentation validation succeeds without private credentials or access to a developer cache. Asset licensing is recorded, icon presentation is usable, and no untrusted checkout is given deployment secrets. No `pull_request_target` workaround exposes the token.

## Batch 24 — Align documentation with the implemented release contract

**Covers:** SR12; documentation completion for the other findings. **Depends on:** B02–B21 and B23 for final acceptance; editorial preparation may start earlier.

**Work:** align installation versions, CLI/SDK examples, recovery/keyring behavior, provider audit/export behavior, optional environment handling, and the final schema/ABI/contract decisions. Label prerelease documentation clearly. Derive repeated release labels from one authoritative source where practical. Write a tested earlier-version transition procedure that preserves old files and compatible tooling, and does not imply current export/import migrates an older schema. Keep compromise recovery distinct from ordinary upgrade/recreation.

**Affected files:** `README.md`, `CHANGELOG.md`; `docs/{getting-started,cli,building,release,supply-chain,threat-model,vault-format}.md`; `docs/providers/*.md`, `docs/sdks/*.md`; relevant binding READMEs; `site/README.md`, `site/scripts/sync-docs.mjs`, `site/src/lib/doc-metadata.mjs`, getting-started/headless source pages; `crates/sourceorrery-cli/skills/` as the authoritative integration source. Regenerate derived integration/docs files through the existing generators rather than editing them independently.

**Tests:** version-stamping tests, docs tooling and full build/link check, integration drift test, old-schema refusal without mutation, and install/first-read examples against the candidate versions. Audit the final claims against B02, B07, and B08 instead of copying schema 4/ABI 2 mechanically from the original review.

**Acceptance:** following a documented install command produces a package that supports the documented options. Every stated audit/key/provider guarantee matches the implementation. Generated artifacts are reproducible, and users have an accurate upgrade/compromise-response procedure without accidental loss of their existing vaults.

## Batch 25 — Inventory release-account and repository controls

**Covers:** prerequisites for REC01/REC02/REC09. **Depends on:** B01. **Nature:** read-only discovery during later implementation, not settings changes.

**Work:** inspect branch/tag rules, required check identities, Actions permissions, deployment environments, registry trusted-publisher constraints, release immutability, Dependabot secret availability, and provider first-publication requirements. Record which controls actually apply to manual workflow dispatch and retry publication. Never include secret values in the evidence.

**Affected files:** the validation ledger; proposed updates to `docs/release.md` and `docs/supply-chain.md` recording observed configuration and unresolved dependencies. Remote settings are only inspected.

**Tests:** compare workflow permissions and release paths with the observed settings. Identify the expected release source SHA and every publish destination. Confirm that a setting applies to the intended workflow/surface rather than assuming it does.

**Acceptance:** release policy is based on observed settings with observation dates. Unknown settings remain explicit; no claim of protection rests on an unverified branch rule or registry trust relationship. Required future configuration changes are listed separately for review.

## Batch 26 — Require validation of the exact release commit

**Covers:** REC01. **Depends on:** B22, B23, B25; final required-check list includes B30/B31 when available.

**Work:** make both initial and retry publishing require an immutable selected SHA and the intended validation evidence for that SHA. Use a reusable validation workflow or a small tested gate. Bind checks to trusted workflow/application identities as well as conclusions; reject a green result for another SHA, partial/path-skipped coverage, or a similarly named untrusted check. Dry runs must exercise the same gate. Keep default workflow permissions minimal.

**Affected files:** `.github/workflows/release.yml`, `ReleasePackages.yaml`, `ci.yml`; a proposed `scripts/release/check-release-validation.py` and matching unit test if a helper is needed; `docs/release.md`.

**Tests:** mocked missing/pending/failed/cancelled/skipped checks, wrong SHA, wrong workflow identity, API error, changed tag/ref, complete trusted success, and dry-run behavior. Workflow validation must show no publish job can bypass the prerequisite.

**Acceptance:** no publication path proceeds without complete trusted validation for its selected source commit. Fetch/API failure blocks rather than defaults to success. Validation of the deterministically stamped candidate remains part of B32; a green unstamped build alone is not treated as package validation.

## Batch 27 — Verify artifacts before retry publication

**Covers:** REC02. **Depends on:** B25, B26.

**Work:** verify downloaded artifacts against original build provenance, expected repository/workflow identity, immutable source commit, and byte digest. Validate the complete expected package inventory before upload. Define separate handling for source-rebuilt crates/Maven packages and legacy releases without attestations. Do not silently substitute freshly downloaded checksums from the same mutable release as proof of original provenance.

**Affected files:** `.github/workflows/ReleasePackages.yaml`, relevant provenance/inventory output in `release.yml`; a proposed `scripts/release/verify-release-artifacts.py` and tests; `docs/release.md`, `docs/supply-chain.md`.

**Tests:** valid signed fixture or verified historical artifact, changed bytes, missing attestation, wrong commit/repository/workflow, missing/duplicate/unexpected packages, verification service failure, and source rebuild from a mismatched tag. Dry-run mode performs verification without uploading or generating public attestations.

**Acceptance:** altered or unproven inputs cannot reach a trusted-publisher job. Legacy handling is explicit and separately reviewed; there is no automatic bypass. The artifact that passed verification is the same artifact subsequently selected for upload.

## Batch 28 — Close the cross-component failure-test matrix

**Covers:** REC04; validation completion for SR01–SR03, SR08–SR09, SR14. **Depends on:** B03–B21.

**Work:** reconcile tests delivered by the individual batches against one matrix: persisted security state, transaction boundaries, provider partial outcomes, source selection, output failures, SDK ownership, and sensitive-output guarantees. Add only missing behavioral cases; do not duplicate private implementation details in tests. Extend shared conformance semantics where multiple backends/bindings must agree, while keeping language ownership tests local.

**Affected files:** `tests/conformance/src/lifecycle.rs`, `tests/conformance/tests/{security,lifecycle}.rs`, `tests/conformance/sdk/{scenarios.json,harness.py}`; SDK runners under each binding if a shared operation changes; targeted storage/provider/CLI tests; validation ledger.

**Tests:** execute the completed matrix, including partial failures, boundaries, concurrency, and restart/retry. Add explicit skip/fail reporting for unavailable required services so a release run cannot treat an early-returned live test as executed coverage. Retain the old review's resolved regression cases.

**Acceptance:** every SR item has a named regression or documented verification method with evidence. Shared semantics pass across the relevant backends/bindings. Required-but-unexecuted cases remain open and block release sign-off; a test count alone is not acceptance evidence.

## Batch 29 — Establish scalability budgets and consolidate state-transition helpers

**Covers:** REC08. **Depends on:** B07, B18, B28.

**Work:** benchmark unlock, individual reads, listings, audit export/follow, and routed operations across increasing history and secret counts. Use synthetic small/medium/large fixtures—for example 1,000, 10,000, and 100,000 audit events—and vary history independently from secret count. Record hardware and baseline, choose practical budgets for supported workloads, and apply only measured improvements. Consolidate remaining duplicated preflight/completion logic where it prevents future missing checks. Split any substantial optimization into its own follow-up batch.

**Affected files:** proposed benchmark harness under `crates/sourceorrery-storage/benches/` or `scripts/dev/`; measured hot paths in storage `sqlite/{audit,rows,mod}.rs`, router, or CLI audit export; `docs/architecture.md` and validation ledger. Touch implementation only when measurements or duplicated security invariants justify it.

**Tests:** repeatable latency/memory/query-growth measurements, concurrent-client contention, long-history correctness, and all integrity/quarantine tests after any optimization. Performance budgets should be tied to a documented machine/workload rather than brittle universal timing thresholds.

**Acceptance:** workload limits and measured growth are recorded; no accidental repeated full-history work is left unexplained. Consolidation preserves each security gate and failure outcome. Performance improvements never skip authentication, quarantine checks, or promised audit events.

## Batch 30 — Validate the minimum Rust version and feature combinations

**Covers:** REC09; dependency compatibility from REC03. **Depends on:** B22 and the final dependency changes from functional batches.

**Work:** add explicit builds on the declared minimum Rust toolchain for the root workspace and both native-binding Rust roots. Cover headless/no-default-feature paths and each supported provider/UI/OTLP feature combination according to the actual manifests. Use a bounded intentional matrix rather than every mathematically possible combination. If the stated minimum cannot be supported, change the requirement deliberately and document it.

**Affected files:** `.github/workflows/ci.yml`; `Cargo.toml`, native-binding manifests/locks only for justified compatibility changes; `docs/building.md`, relevant crate/SDK READMEs.

**Tests:** locked builds/tests with the minimum and current supported toolchains; explicit provider feature selection, no-keyring/headless build, and native-extension compile checks. Validate any maintenance dependency update from B22 here.

**Acceptance:** the declared minimum is demonstrated, not inferred from dependency metadata. Supported feature combinations compile and exercise relevant behavior. Unsupported combinations are explicit; compatibility fixes do not weaken checks to obtain a green result.

## Batch 31 — Validate supported platforms, SDK packages, and service integrations

**Covers:** REC09; runtime completion for SR04–SR08. **Depends on:** B12–B15, B23, B28, B30; uses the completed storage/provider implementation.

**Work:** execute the existing SDK suite/conformance runners on supported Windows/macOS/Linux targets. Run credential-store smoke tests using isolated test identities/stores, full PHP FFI tests, native-library loading, and memory-lifetime checks. Test packaged Linux artifacts on the oldest advertised libc/distribution and record macOS/Windows minimums. Run provider conformance against disposable services with sufficient permissions to exercise failure behavior; clearly distinguish emulator from real-service coverage.

**Affected files:** CI matrix and shared fixture action; `.github/actions/sdk-fixture/action.yml`; `scripts/dev/keyring-smoke.*`, `scripts/ci/{fixture-vault.sh,vault-federation.sh,aws-federation.sh,azure-federation.sh,localstack.sh}` as needed; language test/conformance runners; `docs/building.md`, `docs/sdks/index.md`, provider guides and validation ledger.

**Tests:** real packaged CLI/FFI/native extension loads; all supported language runners; native ownership stress with suitable instrumentation; Windows ACL and child environment tests; keyring/recovery fallback; provider lifecycle, restrictive publication, and quarantine cases. Where feasible, add bounded fuzz/sanitizer/Miri checks for applicable parsing/unsafe Rust boundaries; record platform/tool limitations accurately.

**Acceptance:** every advertised target/language has execution evidence or is explicitly removed from this release's support claim through a reviewed scope change. Required live tests did run, and missing service credentials cannot produce a false pass. Test setup never accesses a developer's normal vaults or credential entries. Real-service runs use a defined test scope and cleanup.

## Batch 32 — Rehearse the complete release candidate and record sign-off

**Covers:** final acceptance of SR01–SR14 and REC01–REC09. **Depends on:** B01–B31 accepted, including any additional batches required by their decisions or discovered regressions.

**Work:** assemble a candidate from the reviewed commit in a disposable checkout, stamp 0.3.0 through the existing release script, build candidate packages, and validate the stamped contents. Rehearse install/first-run/upgrade guidance using those packages. Record a release manifest with source SHA, intended version, final schema/ABI/contract, target/package inventory, checksums, and validation evidence. Review initial and retry-publication paths without performing publication.

**Affected files:** existing `scripts/release/{set-version.py,publish-crates.py,package-managers.py,npm-platform-packages.py}`; `scripts/ci/abi-check.py`, `php-package-install.sh`; release workflow definitions only for fixes found by rehearsal; release notes and validation ledger. Version stamping for rehearsal happens in a disposable copy.

**Tests:** full Rust checks; all required dependency scans; Python release/CI helper tests; site build/link checks; generated-header and integration consistency; cross-language conformance against candidate artifacts; ABI/version mismatch refusal; old-schema refusal without mutation; package installation and native loading. Exercise release validation/provenance helpers in dry-run mode. A hosted dry-run workflow is a separate future remote action, not part of the current planning authorization.

**Acceptance:** all review findings and recommendations have explicit closure evidence; no required check is merely assumed from the earlier audit. Stamped packages match their docs and inventory. Any unresolved item remains visible with a disposition requiring review; it cannot be marked fixed because release is approaching. The deliverable is a locally validated candidate and a clear go/no-go recommendation. **No tag, remote push, registry upload, website deployment, or release publication occurs without a later instruction.**

## Validation commands and evidence rules

These are commands for **future implementation**, not checks executed while creating this plan. Run the relevant focused tests in each batch; use the complete suite at integration/candidate checkpoints and after changes that justify it.

From the repository root:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo test -p sourceorrery-cli --test integrations --locked
cargo test --manifest-path tests/conformance/Cargo.toml --test security --locked

cargo audit --file Cargo.lock
cargo audit --file bindings/python/Cargo.lock
cargo audit --file bindings/node/Cargo.lock

python -B -m unittest scripts/release/set_version_test.py scripts/release/test_publish_crates.py scripts/release/package_managers_test.py scripts/release/npm_platform_packages_test.py scripts/ci/abi_check_test.py scripts/ci/azure_vault_test.py
```

For each npm lockfile directory identified in B22, run `npm audit --package-lock-only --ignore-scripts --json` and retain the date/database result. In `site`, use a compatible Node runtime and a clean credential-free environment for `npm ci --ignore-scripts`, `npm test`, and `npm run build` (which includes the existing postbuild link check). Use each binding's documented fixture/build/test runner rather than inventing a common command that skips its native setup.

For each completed batch, record:

- Source SHA/diff and which SR/REC items it closes.
- Changed behavior and any schema/API/compatibility consequence.
- Exact tests, environment/tool versions, and artifacts used.
- Passed, failed, skipped, and unavailable cases separately.
- Acceptance evidence and any follow-up dependency introduced.

Use synthetic canaries and isolated fixtures. Tests should assert behavioral guarantees and lifecycle boundaries; they should not merely repeat the implementation. Preserve real secret values, credentials, tokens, and plaintext memory contents outside reports/logs.

## Completion checklist

All boxes intentionally remain unchecked: this is a plan, not an implementation record.

- [ ] B01 baseline and coverage ledger
- [ ] B02 key-replacement/format decision
- [ ] B03 active-wrap integrity
- [ ] B04 restrictive Windows key files
- [ ] B05 failure-safe creation and key delivery
- [ ] B06 provider integrity preflight
- [ ] B07 durable/uncertain provider outcomes
- [ ] B08 provider publication design
- [ ] B09 AWS input and tag limits
- [ ] B10 Vault fail-closed publication
- [ ] B11 AWS fail-closed publication
- [ ] B12 PHP native ownership
- [ ] B13 .NET callback lifetime
- [ ] B14 Java concurrent lifetime
- [ ] B15 lazy unlock sources
- [ ] B16 manifest-controlled child environment
- [ ] B17 current view-check state
- [ ] B18 rejected settings audit coverage
- [ ] B19 bounded HTTP streaming
- [ ] B20 CLI temporary-buffer hygiene
- [ ] B21 provider temporary-buffer hygiene
- [ ] B22 all dependency graphs and maintenance dispositions
- [ ] B23 credential-free docs builds
- [ ] B24 accurate release/SDK/provider documentation
- [ ] B25 observed release controls
- [ ] B26 release-commit validation gate
- [ ] B27 retry artifact verification
- [ ] B28 complete failure/conformance matrix
- [ ] B29 performance budgets and state-transition consolidation
- [ ] B30 minimum toolchain and features
- [ ] B31 supported platform/SDK/service execution
- [ ] B32 stamped candidate rehearsal and sign-off

The prior review remains the evidence record. This plan and the future validation ledger should track remediation without rewriting historical findings to imply checks or fixes that have not occurred.
