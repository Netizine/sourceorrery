# SourceOrrery security and code quality review — 2026-10-25

## Decision and scope

**Recommendation: hold publication of 0.3.0 until the high-priority findings below are resolved and the affected SDKs pass lifetime and failure-path regression tests.** The design has substantial defensive work and the existing Rust checks pass, but targeted tests exposed failures in recovery-key replacement, provider policy publication, audit quarantine, and Windows recovery-key file protection.

This review records **14 actionable findings: four P1, nine P2, and one P3**, followed by additional improvement suggestions. P1 means a release blocker; P2 means a concrete defect to resolve before shipping the affected supported surface; P3 means lower-priority hardening or contract completeness. These are engineering priorities, not CVSS scores. No universal unauthenticated remote compromise is claimed.

- Reviewed local `main` at **`18138d3e8cdb75387b12eb70e165ca5a62d9adbd`**, including its current implementation and the changes since `v0.2.0`: **515 files, 45,299 insertions, 16,874 deletions**.
- Covered architecture/threat-model documents, core contracts, crypto, storage, CLI/setup/browser/import/run/rotation flows, Rust client, C ABI, all language-binding ownership surfaces, provider adapters, conformance tests, CI, release packaging, installation documentation, site tooling, and agent integrations.
- Revisited `SECURITY-REVIEW-2026-10-20.md`; its findings were not simply carried forward.
- Performed static review, existing checks, and disposable probes using synthetic values, an in-memory credential store or `--no-keyring`, and a loopback fake provider. No real vault or cloud account was used.
- **No fixes, source changes, commits, pushes, publication, or remote mutations were made.** This report is the only repository file added by the review. The three pre-existing untracked image files were left untouched.

Line references below describe this exact commit. “Reproduced” identifies behavior exercised during this review. “Source-confirmed” identifies a definite control-flow/ownership defect without running a crashing or service-dependent reproduction.

## What the project is building

SourceOrrery replaces development `.env` files with encrypted secret storage and a value-free project manifest. The CLI manages lifecycle and supplies selected secrets to a child process; applications read through SDKs whose semantics originate in Rust. Local values are AEAD-encrypted, policy metadata is authenticated, and a keyed audit history detects specified forms of tampering and partial rollback.

The upcoming design makes a local vault the organizing unit: it holds a machine-key wrap, a portable recovery-key wrap, an optional password/authenticator **view check**, provider connections with sealed credentials, a catalog choosing storage per secret, and project links. A router dispatches operations to local SQLite, HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault. This is a significant storage/security redesign, not just a CLI refresh: schema 4 rejects earlier vault formats, and the ABI/contract advances to version 2.

The intended boundary is sensible and explicitly documented: at-rest protection and reduced accidental disclosure today; same-user agent isolation requires a future authenticated broker and OS isolation. This review does **not** count same-user access, deliberate reveal, application copies, child-environment inspection, complete-file rollback, or the intentionally incompatible old vault format as new vulnerabilities. The view check is a convenience/privacy control, not a cryptographic authorization boundary.

## Findings at a glance

| ID | Priority | Finding | Evidence |
|---|---|---|---|
| SR01 | P1 | An old recovery wrap can reactivate the replaced key against current secrets | Reproduced; audit remains intact |
| SR02 | P1 | Failed HashiCorp policy write leaves an intended-disabled version readable | Reproduced with loopback fake Vault |
| SR03 | P1 | Routed provider mutations happen before local audit-quarantine rejection | Reproduced with cached routed client |
| SR04 | P1 | Windows recovery-key output inherits potentially shared read access | Reproduced by inspecting resulting ACL |
| SR05 | P2 | PHP reader cloning duplicates ownership of one native pointer | Source-confirmed |
| SR06 | P2 | .NET callback can dispose its own active native span | Reproduced with instrumented free stub |
| SR07 | P2 | Java concurrent close can free a reader during a native call | Source-confirmed |
| SR08 | P2 | A broken fallback key file prevents valid earlier unlock sources | Reproduced through C ABI |
| SR09 | P2 | Recovery-key output failure leaves a recovery-only vault without its key | Reproduced through CLI |
| SR10 | P2 | Unavailable optional secrets leave inherited credentials in the child | Reproduced through CLI |
| SR11 | P2 | An existing handle ignores a subsequently enabled view check | Reproduced with two handles |
| SR12 | P2 | Installation/API/audit documentation mixes incompatible release behavior | Compared against `v0.2.0` source |
| SR13 | P2 | Fork documentation builds require an unavailable private-registry secret | Workflow inspection; tarball returns 401 |
| SR14 | P3 | Rejected password changes bypass the audit completion path | Reproduced; zero additional events |

## Detailed findings

### SR01 — Replaced recovery keys can be reactivated by replaying an old wrap

**Locations:** `crates/sourceorrery-storage/src/sqlite/wraps.rs:373–409`; `crates/sourceorrery-storage/src/integrity.rs:585–641`. Related promises: `docs/cli.md:54`, `docs/threat-model.md:107`.

Recovery-key replacement deletes the old recovery wrap and wraps the **same data-encryption key** under the new recovery key. The active `key_wraps` set is absent from the authenticated settings record and its replay checkpoints. The replacement audit event does not bind the new wrap set.

**Trigger and result:** create a recovery-only vault, preserve its old wrap row and key, replace the key, and write a new secret. The old key correctly fails against the untouched current file. Restore only the old authentic wrap row, leaving current secrets, settings, and audit history in place. The old key then opens the vault and reads the value written after replacement. Verification still reports `first_broken=None`, `truncations=0`, `unacknowledged=0`, `head_valid=true`.

This requires possession of an old key/wrap and access to the current vault file; it is not an arbitrary outsider attack. It is nevertheless a partial-replay gap in the current integrity design and undermines the promise that the old recovery key stops working.

**Recommended change:** authenticate/checkpoint the active wrap set and verify it after unwrap, including additions, deletion, substitution, and replay. Also decide and document the actual compromise-recovery guarantee. Someone holding an old key and wrap can recover the unchanged DEK and decrypt newer ciphertext directly; authenticating the table alone cannot revoke that knowledge. Genuine compromise recovery needs a new DEK with appropriate re-encryption/re-authentication, or an explicitly narrower replacement guarantee and a safe replacement-vault procedure.

**Regression check:** repeat the above replay while retaining the current audit head; opening must fail and must not return post-replacement values. Separately test/document the behavior of old exported copies and any DEK-rotation procedure.

### SR02 — A failed provider policy write can make a restricted value readable

**Locations:** `crates/sourceorrery-provider-vault/src/lib.rs:445–472`; `crates/sourceorrery-provider-vault/src/kv.rs:249–274`. Related source-level pattern: `crates/sourceorrery-provider-aws/src/lib.rs:560–578`.

The Vault adapter writes a new data version before writing the corresponding disabled/time-window metadata. A missing metadata record defaults to enabled with no time restriction. If the second request fails, the operation returns an error after the new version has become accessible.

**Reproduction:** a loopback fake Vault accepted a seeded version, accepted the next data write, and rejected that version's metadata write with HTTP 400. `secret set key --disabled` exited 1 with `invalid_argument`; the next metadata read returned version 2 with `enabled=true`; a reveal returned the synthetic version-2 value successfully. This used the current CLI and a disposable local vault. Even without a failure, concurrent reads can observe the interval between the writes.

For an existing AWS secret, the code similarly sends `PutSecretValue` before `write_tags`; a tag failure can leave the new current version under the previous policy. That AWS case was identified from source, not reproduced against AWS or an emulator.

**Recommended change:** design value publication and policy application to fail closed, including partial writes, response loss, retries, and concurrent readers. Validate provider-specific limits before the first mutation. Where the provider cannot preserve a claimed capability, refuse the unsupported operation or use a representation with an explicit pending/committed state that readers enforce. Best-effort cleanup after returning an error does not eliminate the exposure window.

**Regression check:** inject refusal/timeouts at each provider write, including “server accepted write, response lost.” The requested disabled/future/expired version must never be returned, and partial outcomes must be reported accurately. Exercise the equivalent AWS ordering too.

### SR03 — Audit-quarantined routed handles still mutate provider secrets

**Locations:** `crates/sourceorrery-provider/src/routed.rs:204–252`; `crates/sourceorrery-storage/src/sqlite/connections.rs:809–817,828–873`.

`Routed::at` calls the provider first and only afterward calls `record_at_connection`, whose `begin` performs the local integrity/quarantine gate. `storage_of` does not perform that gate, and a cached provider client avoids fresh connection-state reads. A refusal returned to the caller therefore does not mean the remote operation was refused.

**Reproduction:** use a second disposable SQLite vault as the provider, warm the routed client, and remove the newest local read-audit event. `routed.delete_secret` returned `crypto`, but the provider secret was deleted. After the local vault recorded the truncation and had `unacknowledged=1`, `routed.recover_deleted_secret` also returned `crypto`, but recovered the provider secret anyway. No live provider was contacted.

**Recommended change:** gate every provider operation on current local integrity/quarantine state before any external effect, including cached-client paths. Define durable intent/outcome and reconciliation semantics for remote operations; a local SQLite transaction cannot undo an already completed external mutation. Handle a local audit failure after a legitimate remote success as an explicit partial outcome, rather than implying nothing happened.

**Regression check:** warm the cache, quarantine the vault, then invoke every remote read/mutation and assert zero provider calls. Also exercise truncation discovered immediately before dispatch and local audit failure after provider success.

### SR04 — Windows recovery-key files are not restricted to the owner

**Location:** `crates/sourceorrery-cli/src/commands/vault.rs:33–48,60–67`.

`write_recovery_key` requests mode `0600` only on Unix. On Windows it creates the plaintext recovery-key file with inherited permissions, yet the command says the file is “readable by you only.” The key opens the entire vault and passes its view check.

**Reproduction:** create a disposable destination directory with an inheritable `BUILTIN\Users` read/execute ACE, then run `vault create ... --no-keyring --recovery-key-out FILE`. Creation succeeded, and the output key file retained an inherited `BUILTIN\Users` read ACE. No actual user's secret or second account was used; the resulting ACL itself demonstrates the extra grant. Exposure requires such a shared/readable parent, not every Windows installation.

Windows documents that a newly created file without an explicit security descriptor inherits its parent ACL: [Microsoft file security documentation](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights).

**Recommended change:** create the file atomically with a restrictive Windows security descriptor and suitable owner/system access, or fail clearly when that guarantee cannot be established. Setting permissions after writing creates an avoidable exposure interval. Keep the Unix behavior and make the output claim match the enforced guarantee.

**Regression check:** create in a deliberately shared directory on Windows and verify no broad read grant survives. Test failures without writing any key bytes under insecure permissions.

### SR05 — PHP reader cloning causes duplicate native-handle ownership

**Locations:** `bindings/php/src/SecretReader.php:23–30,130–149`; C ownership contract in `crates/sourceorrery-ffi/include/sourceorrery.h:206–213`.

The reader has an owning `CData` handle but permits default cloning. `$copy = clone $reader; $copy->close();` frees the native reader while the original object's handle remains non-null. Its next operation can use freed memory, and later destruction can free the pointer again. The neighboring `SecretValue` already prohibits cloning, which makes the omission particularly inconsistent.

**Evidence:** source-confirmed using [PHP's documented shallow-copy semantics](https://www.php.net/manual/en/language.oop5.cloning.php). PHP was unavailable locally, so no crashing reproduction was run.

**Recommended change:** prohibit reader cloning or place native ownership in one shared lifetime object. Include destructor and exceptional paths, not only explicit `close`.

**Regression check:** cloning must be rejected predictably or safely share ownership; closing/destructing either object must never leave an apparently open object with a freed pointer.

### SR06 — .NET reentrant disposal invalidates an active secret span

**Locations:** `bindings/dotnet/SourceOrrery/SecretValue.cs:49–57,84–93`.

`Use` invokes user code with a span into native memory while holding `lock(gate)`. The callback can call `Dispose` on the same value; the same thread reenters the lock, frees the buffer, and continues with its still-live span. `GC.KeepAlive` protects against collection, not explicit disposal. C# locks are explicitly reentrant: [Microsoft lock documentation](https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/statements/lock).

**Reproduction:** the exact source file was compiled in a disposable project with an instrumented native-free stub. Calling `Dispose` inside `Use` produced `FreedWhileCallbackActive=True`, `SpanLengthAfterFree=16`, `Closed=True`. Freed memory was not dereferenced; this was a controlled lifetime probe, not an exploitation or crash test.

**Recommended change:** defer release while callbacks are active, with exception-safe lifetime accounting, or use a temporary managed copy that is wiped afterward. Consider nested `Use` and disposal via an owning `Secret` too.

**Regression check:** reentrant disposal cannot free the active buffer until the outermost relevant callback finishes; exceptions and nested callbacks must still release once.

### SR07 — Java's thread-safe reader does not protect in-flight calls from close

**Locations:** `bindings/java/src/main/java/ai/sourceorrery/SecretReader.java:10–14,67–101,110–115`; `crates/sourceorrery-ffi/include/sourceorrery.h:206–213`.

`require()` snapshots an `AtomicReference<MemorySegment>`, after which the native call uses the pointer without a lifetime guard. Another thread may clear the reference and call `Native.readerClose` before or during that call. Atomic reference replacement prevents duplicate close ownership; it does not keep the native allocation alive for existing readers. This conflicts with the class's thread-safety claim and the C ABI's prohibition on closing an in-use handle.

**Evidence:** source-confirmed interleaving; no deliberately crashing concurrent native test was run.

**Recommended change:** protect the complete native operation with a read/write lock or reference-counted lifetime guard; close must wait for in-flight calls. The .NET reader's `ReaderHandle` is a useful ownership model.

**Regression check:** use barriers to pause a read after acquiring its handle, start close, and verify freeing waits until the call completes. Cover get, properties, resolve, and descriptor.

### SR08 — Eager fallback-file loading breaks the documented unlock order

**Locations:** `crates/sourceorrery/src/unlock.rs:83–120`; `crates/sourceorrery/src/reader.rs:115–143`.

`NonInteractiveUnlock::gather` reads the configured recovery-key file before the OS store or explicit key is attempted. A missing, unreadable, or empty fallback file therefore aborts opening even when a higher-priority source is valid. This affects the shared Rust SDK path and its bindings, and differs from the stated machine key → explicit key → environment → file order.

**Reproduction:** through the current C ABI, a correct explicit recovery key opened a disposable vault successfully. The same correct key plus a nonexistent `recovery_key_file` failed with `io`. An inherited stale file setting can likewise break otherwise valid application startup.

**Recommended change:** consult sources lazily in the documented order, retaining useful diagnostics when a source is actually attempted. Do not let a source that was never needed override a successful earlier one.

**Regression check:** valid machine/explicit/environment credentials must work with missing, unreadable, and empty later-source files; exhaustion of all usable sources must still yield accurate diagnostics.

### SR09 — Failure to save the generated recovery key leaves an unusable vault

**Locations:** `crates/sourceorrery-cli/src/commands/vault.rs:151–161,219–225`.

Creation checks whether the output file already exists, then creates and commits the vault before trying to create/write the recovery-key output. If that output fails and `--no-keyring` was used, the only generated unlock key is dropped when the command exits. The registered vault survives without a way for the caller to open it.

**Reproduction:** use an output path below a nonexistent parent. Creation exited 1 with “cannot create … recovery.key,” but `vault list` still contained the new recovery-only vault. The synthetic fixture held no existing user data; the immediate impact is a stranded vault, occupied name, and broken provisioning/retry behavior.

**Recommended change:** safely reserve/validate the output destination before committing creation, then coordinate key delivery and rollback. Cover write/flush failures as well as initial open failures. If a complete rollback cannot be guaranteed, provide a recoverable, explicit outcome instead of discarding the only key.

**Regression check:** missing parent, permission denial, existing destination, and simulated write/flush failure leave either no new vault or a documented recoverable outcome. Never overwrite an existing key file.

### SR10 — Optional unavailable entries retain inherited environment credentials

**Location:** `crates/sourceorrery-cli/src/commands/project.rs:440–486`.

When an optional entry cannot be resolved, it is omitted from the injection list. `Command` still inherits the parent environment, and only the five SourceOrrery unlock variables are removed. An already-set variable for that unavailable entry therefore reaches the child unchanged. Disabling or deleting the vault entry can leave an application using a stale or unintended credential inherited from its shell.

**Reproduction:** disable `optional-token`, declare it `required=false`, and set a synthetic parent `OPTIONAL_TOKEN`. The CLI logged that the disabled secret was not injected, yet a child checking only whether the variable existed returned exit 23 instead of the expected absent-variable exit 0. No value was printed.

This is environment-selection correctness, not a claim that SourceOrrery can revoke credentials already copied elsewhere.

**Recommended change:** remove every manifest-declared destination from the child environment before applying successfully resolved values, or provide an explicit, documented inheritance choice. Preserve unrelated environment variables.

**Regression check:** optional missing/disabled/expired/deleted entries do not silently fall back to inherited values; valid entries replace inherited values; required failures still prevent launch.

### SR11 — A cached “no view check” state remains valid after another handle enables it

**Locations:** `crates/sourceorrery-storage/src/sqlite/view.rs:333–344,674–689`.

`check_view` returns immediately when the handle's cached view state says no password exists. It never reaches the fresh authenticated state read below that branch. Consequently, a handle opened before another process enables the check keeps accepting empty answers.

**Reproduction:** open two handles using an in-memory machine-key store, set a password through one, then submit empty answers to both. The updated handle refused; the older handle accepted. This did not use the documented recovery-key bypass.

**Recommended change:** obtain current authenticated state before the no-check fast path. Make the consistency contract for existing handles explicit, including authenticator changes and prompts.

**Regression check:** cross-handle password enable/clear and authenticator changes are honored by later calls. This finding concerns the view-check API's behavior; it does not elevate that check into same-user isolation.

### SR12 — Documentation tells users to combine incompatible package versions and APIs

**Locations:** `docs/sdks/python.md:35,81–85`; `site/src/content/docs/getting-started.mdx:21–22,48,302`; `site/scripts/sync-docs.mjs:85`. Related provider-audit text: `docs/providers/hashicorp-vault.md:112–136`, `docs/providers/aws-secrets-manager.md:117–126`, `docs/providers/azure-key-vault.md:111–122`.

The Python guide installs a 0.2.0 wheel while documenting the new recovery-key options. At `v0.2.0`, the constructor accepts passphrase options instead, so the documented recovery-key keyword is incompatible. Getting-started content similarly claims/installs 0.2.0 while describing `--recovery-key-out`; the generated vault-format description still says schema 3. Provider guides also retain the old statement that provider operations have no local audit/export, whereas `Routed` now records those operations locally.

**Evidence:** compared the current examples against the tagged constructor and current routing code. No registry package was installed solely for this check.

**Recommended change:** synchronize installation versions, examples, schema/ABI labels, migration instructions, and provider-audit guarantees. Clearly label development documentation until 0.3.0 is actually published. Generate repeated release labels from one source and smoke-test examples against the exact documented package version.

The workspace still declaring `0.2.0` is **not itself a finding**: release tooling intentionally stamps package versions. The defect is the contradictory user instructions and compatibility claims.

**Regression check:** follow each install/first-run/SDK example using its specified package; verify the resulting vault format and commands match. Provide a tested transition procedure for owners of earlier vaults before advertising the new release.

### SR13 — Fork documentation checks cannot fetch the private icon dependency

**Locations:** `.github/workflows/docs.yml:14–19,46–48`; `site/package-lock.json:405–407`.

The docs workflow runs on pull requests and calls `npm ci` with `FONTAWESOME_NPM_AUTH_TOKEN`. Its lockfile requires a private `@awesome.me` kit tarball. Fork pull-request workflows do not receive repository secrets, so their documentation checks cannot install that dependency.

**Evidence:** an unauthenticated HEAD request to the exact locked tarball returned HTTP 401. The workflow's missing-secret condition follows [GitHub's fork secret restrictions](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets). Dependabot needs separately configured secrets; those account settings were not inspected, so its precise current outcome is not asserted.

**Recommended change:** make PR documentation builds credential-free using public or appropriately licensed local assets/fallbacks, and keep privileged deployment separate. Do not expose the token by checking out untrusted PR code in a secret-bearing `pull_request_target` job.

**Regression check:** run the docs install/build with the token unset, as a fork contribution would. The ordinary quality check should succeed without deployment credentials.

### SR14 — Some rejected settings mutations leave no audit event

**Location:** `crates/sourceorrery-storage/src/sqlite/view.rs:384–404`.

`set_password` performs fallible sealing/input validation before entering `change_view`. Empty passwords, invalid hints, or unsupported KDF parameters can return before the audited mutation path. A reproduced empty-password rejection added **zero** events, despite the broad claim that rejected operations are recorded.

**Recommended change:** route public mutation outcomes through a common audited completion path, including validation errors. Avoid holding a database write lock throughout expensive KDF work where possible; record only non-sensitive failure information.

**Regression check:** cover invalid input for every public settings mutation, not only normal secret-property operations. Each promised audited attempt must produce exactly one appropriate outcome without containing the rejected password/hint.

## Additional security and code quality improvements

These are follow-up recommendations, not additional reproduced exploits or claims that external repository settings are currently insecure.

1. **Bind publication to validation of the selected commit.** `release.yml:612–614` depends on build/packaging jobs rather than the normal CI outcome. Require the selected SHA's successful tests, conformance, lint, and dependency checks, or reuse a validation workflow. A successful package build is insufficient evidence of release readiness. Branch protection/environment settings were not inspected.
2. **Verify original artifacts during retry publication.** `ReleasePackages.yaml:213–234,275–285,318–328,436–438` downloads release assets for trusted publishing without verifying their original build attestations. Consume the provenance already emitted by `release.yml:695–699` and bind it to the expected commit/workflow and artifact digest. Checksums fetched from the same mutable location alone do not establish original build provenance. Whether release immutability is enabled was not inspected.
3. **Audit all independent dependency graphs in CI.** The CI `cargo audit` job at `ci.yml:477–481` covers the root lockfile, while the Python and Node native builds have separate locks. Audit all three and retain npm audits too. Current scans are clean for known vulnerabilities, but all Rust locks carry maintenance warnings for `zbus_names`, `zvariant`, and `zvariant_derive`; plan a tested upstream transition rather than treating “unmaintained” as an exploit.
4. **Make the failure matrix a first-class conformance surface.** Add reusable cases for every persisted security-sensitive table, provider partial writes, local audit failure around remote calls, source fallback, and SDK ownership. Existing happy-path/conformance breadth is valuable; most findings arose at these boundaries. Keep semantic cases centralized while testing language-specific lifetime rules in each binding.
5. **Enforce the Vault response limit while streaming.** `crates/sourceorrery-provider-vault/src/http.rs` checks a declared length, then buffers the entire response before checking the 8 MiB bound again. A chunked/untruthful response can consume more memory before rejection. Cap bytes while reading; test absent `Content-Length` and oversized streams.
6. **Validate AWS tag namespaces and limits before mutation.** `sourceorrery-provider-aws/src/mapping.rs` merges user tags with `sourceorrery:` policy tags. Reserve that namespace explicitly and check AWS-specific limits before the value write. This also reduces the partial-write triggers described in SR02. Azure already has more explicit provider-specific validation.
7. **Reduce unnecessary plaintext copies on parsing/serialization paths.** Provider JSON/String intermediates and some CLI parsing/error paths are ordinary allocations even when the final `SecretBytes` is zeroized. Review the lifetime of temporary buffers and zeroize where practical. This is residue reduction within the stated process-memory limitations, not proof of a new remote disclosure.
8. **Benchmark realistic audit-history growth and improve maintainability around state transitions.** Measure unlock, reads, listings, export/follow, and provider dispatch with large histories and concurrent clients. Centralize integrity preflight and operation completion rather than relying on every new method to place early returns correctly. Prefer these focused changes over wholesale module rewrites merely to reduce file size.
9. **Exercise the declared platform/toolchain contracts.** Add or retain explicit minimum-Rust-version builds, target-platform SDK lifetime checks, and native-library/package smoke tests. This review used Rust 1.99.1, not the declared minimum 1.91.1, and did not verify Linux binary compatibility or macOS behavior.

## Previous review: what changed

| Earlier finding | Current assessment |
|---|---|
| R1: historical metadata replay bypass | Addressed for secret/version/settings records by authenticated checkpoints and passing replay tests. SR01 identifies the separate remaining wrap-table gap. |
| R2: concurrent creation deletes winner | Addressed by exclusive file reservation; the concurrent-creation security test passes. SR09 is a different, key-delivery failure. |
| R3: reference to uninitialized FFI output | Addressed by raw-pointer initialization before reference creation; `MaybeUninit` regression test passes. |
| R4: ninth passphrase protector never attempted | Superseded by the new recovery-key model; that multi-passphrase-protector API is removed. |
| R5: unaudited rejected operations | Original secret-operation cases now have passing failure-audit tests; SR14 shows that settings validation still has a gap. |
| R6: multiline Rust attribute breaks docs generation | Resolved: documentation generation succeeded in a disposable copy, producing 40 files; tooling tests pass. Full Astro compilation was not performed. |
| R7: Windows exit statuses truncated | Resolved: whole-status propagation is implemented and its regression test passes. |
| R8: Argon2 working memory not wiped | Addressed in source with caller-owned zeroizing working memory and passing reference-derivation tests. No new allocator-residue experiment was run. |

## Verification performed

| Check | Result and interpretation |
|---|---|
| `cargo test --workspace --locked` | Exit 0; **513 reported passed, 1 ignored**. The ignored test writes design snapshots. **14 live-provider test cases early-return without configured endpoints**, so their reported success is not evidence of live-cloud coverage. Local lifecycle, tamper, FFI, CLI, routing, and mock/error tests did execute. |
| `cargo fmt --all -- --check` | Passed. |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed. |
| `cargo audit --json` and `cargo audit --no-fetch --json --file …` for both native-binding locks | Zero known vulnerabilities in all three Rust lockfiles. Three unmaintained-package warnings in each: `RUSTSEC-2026-0371` (`zbus_names`), `RUSTSEC-2026-0370` (`zvariant`), `RUSTSEC-2026-0372` (`zvariant_derive`). Database commit `21d909e4c8bd4e14c7aea58bf980c881a0053ab1`, updated 2026-10-24. |
| `npm audit --package-lock-only --ignore-scripts --json` in `site` and `bindings/node` | Both exit 0, zero vulnerabilities. Reported dependency totals: 360 and 154 respectively. Site packages chiefly serve static-site builds; Node tooling is largely development dependencies. |
| Python release/CI helper tests | **48 passed**: version stamping, crate publication decisions, package-manager generation, npm platform packages, ABI checks, and Azure test helper. Python 3.14.0, bytecode writing disabled. |
| Site documentation-tooling tests | **10 passed**, Node 22.15.1. |
| Documentation generation in disposable `git archive HEAD` copy | Passed; 40 files generated. |
| Focused security/correctness probes | Reproduced SR01–04, SR06, SR08–11, SR14. SR06 used an instrumented native-free stub; SR03 used a second local vault as a provider; SR02 used a loopback fake Vault. |
| Limited credential-pattern search | No matches for the selected private-key, AWS access-key, GitHub-token, and Slack-token patterns in searched source content. This was not a comprehensive entropy scan or historical secret scan. |

The full Astro build/link check was not run: the installed Node 22.15.1 is below the site's declared 22.19 minimum. No newer runtime or dependencies were installed for the review. PHP execution was unavailable. Full Java/PHP/Go/C++/.NET/Python/Node binding suites, sanitizers/Miri, fuzzing, the minimum Rust toolchain, non-default feature combinations, Linux/macOS execution, real credential-store behavior, live provider permissions, and remote CI/repository settings remain unverified here. A passing vulnerability database scan does not establish absence of new or unreported vulnerabilities.

## Suggested implementation order

1. Resolve SR01–04 with explicit security guarantees and failing regression cases first: recovery-key replacement, provider policy publication, quarantine preflight, and Windows key-file permissions.
2. Resolve the supported SDK lifetime defects (SR05–07) and unlock-order bug (SR08); run the complete affected language suites with native lifetime stress coverage.
3. Resolve CLI failure/environment behavior (SR09–10), view-state consistency (SR11), and failure-auditing coverage (SR14).
4. Align and exercise release documentation and fork builds (SR12–13), then validate a stamped 0.3.0 release candidate across the intended platforms and packages.

The underlying architecture is worth retaining: centralized Rust semantics, explicit capability differences, read-only SDKs, restricted credential entry, AEAD binding, redacted values, replay-aware metadata, and substantial conformance coverage are strong foundations. The next work should concentrate on the security boundaries between these components and on failure/lifetime behavior, where the reproduced problems cluster.
