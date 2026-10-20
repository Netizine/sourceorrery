**SourceOrrery — security and code review, 20 October 2026**

Reviewed commit `34f34609b0a9e8467358b0778628f9412772533d` and the current working tree in `C:\dev\sourceorrery`. The pre-existing untracked `sourceorrery.png` was left untouched. This review added this report; application source and dependency versions were not changed.

The project has a clear separation between domain contracts, cryptographic wrappers, encrypted SQLite storage, the CLI, and the C ABI. Secret values have explicit disclosure paths, ciphertext is bound to its record with AEAD additional data, and mutable metadata and audit records are authenticated. The documented distinction between at-rest protection and same-user process isolation is appropriate.

**Verdict: changes required before production use.** Eight actionable findings remain: two P1/high-priority issues, five P2/medium-priority issues, and one P3/hardening issue. Most were reproduced against disposable local data. The FFI finding is supported by source inspection and Rust's documented initialization contract; it was not checked with Miri.

| ID | Priority | Finding | Evidence |
| --- | --- | --- | --- |
| R1 | P1 | Historical metadata rows bypass disable and soft-delete policy | Reproduced; current audit chain still verifies |
| R2 | P1 | Concurrent creation can delete a successfully created vault | Reproduced on Windows |
| R3 | P2 | FFI output helper references uninitialized caller storage | Source and official Rust contract |
| R4 | P2 | Ninth passphrase protector is accepted but never tried | Reproduced through the public Rust API |
| R5 | P2 | Some failed operations leave no operation audit event | Reproduced with an invalid property update |
| R6 | P2 | Documentation generation fails on a multiline Rust attribute | `npm run build` fails |
| R7 | P2 | `run` loses Windows child exit codes above 255 | Reproduced with exit code 3010 |
| R8 | P3 | Argon2 working memory retains key-derivation material | Disposable allocator probe |

1. **R1 — Bind authenticated rows to the current policy state.**

   Location: [version verification, rows.rs:97](C:/dev/sourceorrery/crates/sourceorrery-storage/src/sqlite/rows.rs:97) and [secret-state verification, rows.rs:223](C:/dev/sourceorrery/crates/sourceorrery-storage/src/sqlite/rows.rs:223).

   The MAC proves that a row was once authentic, but nothing establishes that it is the current revision. A party with an earlier copy of the same row and write access to the vault can restore its fields and tag after a later policy change. Restoring a version row from before disable makes retrieval succeed. Restoring a secret row from before soft deletion makes it live again. Neither operation requires the attacker to know a passphrase, DEK, or metadata key; the next authorized reader consumes the stale policy.

   This is more permissive than the documented complete-snapshot rollback limitation: the current audit rows and head can remain untouched, including the authentic record of the later disable or deletion.

   Reproduction used a disposable passphrase vault and a synthetic value. Save the original `secret_versions` and `secrets` rows in memory, disable the version, and confirm `get --reveal` returns `disabled`. Restore only the saved version row with SQLite. Retrieval then succeeds and `audit --verify` reports `first_broken: null`, `truncations: 0`, and `head_valid: true`. Soft delete followed by restoring only the saved `secrets` row produces the same result. The original audit history was preserved throughout both tests.

   Bind current row revisions or digests to an authenticated current-state checkpoint linked to the latest audit state, and verify that relationship before honoring policy. Merely adding another MACed revision field to each row does not prevent replay of that field with its tag. Add regression coverage for same-row historical replay after disable, time-window changes, and deletion. Whole-file rollback will still need the documented external checkpoint.

2. **R2 — Reserve vault filenames exclusively before initialization and cleanup.**

   Location: [sqlite/mod.rs:128](C:/dev/sourceorrery/crates/sourceorrery-storage/src/sqlite/mod.rs:128), especially lines 137–139, and [schema.rs:112](C:/dev/sourceorrery/crates/sourceorrery-storage/src/sqlite/schema.rs:112).

   `create` checks `path.exists()` and subsequently uses a nonexclusive SQLite open. Multiple creators can pass the check and open the same database. A losing initializer can then encounter a database error and unconditionally remove the shared path. Cleanup does not establish that this invocation owns the file it deletes.

   A standalone Rust probe synchronized 12 calls to `SqliteVault::create` against the same temporary path, using synthetic passphrases and deliberately cheap Argon2 parameters for the concurrency test. On the first round, one call returned success, but after all calls completed the vault file did not exist. This is a data-loss bug, independent of a malicious caller.

   Atomically reserve the file with exclusive creation, track ownership for failure cleanup, and initialize its database transactionally. A competing creator should receive `VaultExists` without touching the winning creator's file. Add a concurrent-creation regression that reopens the successful result after every caller has finished.

3. **R3 — Initialize FFI output storage before creating a reference to it.**

   Location: [ffi/vault.rs:150](C:/dev/sourceorrery/crates/sourceorrery-ffi/src/vault.rs:150), particularly lines 156–157.

   `output<T>` first creates `&mut *ptr` and then assigns `initial`. Its safety contract, like the exported C APIs, only requires output storage valid for writes. An ordinary C caller may therefore pass an uninitialized `so_bytes out;` or `so_vault *handle;`. Rust documents creating a reference to uninitialized storage as undefined behavior and shows raw-pointer writes for initializing output parameters. [Rust MaybeUninit documentation](https://doc.rust-lang.org/std/mem/union.MaybeUninit.html#method.as_mut_ptr).

   Initialize with `ptr.write(initial)` before constructing the mutable reference. Audit the output helpers under the same contract, and add a `MaybeUninit` caller test suitable for Miri. Existing smoke tests initialize their output objects, so their success does not cover this case. No native crash or exploit was demonstrated; Miri was unavailable.

4. **R4 — Enforce the passphrase-protector limit when adding protectors.**

   Location: [protectors.rs:50](C:/dev/sourceorrery/crates/sourceorrery-storage/src/sqlite/protectors.rs:50) and [add_protector at line 397](C:/dev/sourceorrery/crates/sourceorrery-storage/src/sqlite/protectors.rs:397).

   Unlock tries only the first eight passphrase protectors, ordered by creation time and ID. Adding protectors has no corresponding limit. The API can therefore report success for a new recovery credential that will never be considered during unlock.

   A disposable Rust API test installed nine differently labeled, distinct passphrase protectors using `Argon2Params::TESTING`. Listing reported nine. After closing the vault, passphrases one and eight unlocked successfully; passphrase nine returned `locked`.

   Reject additions beyond the supported limit inside the existing write transaction, or provide explicit protector selection within a bounded unlock design. Keep the resource ceiling; make the creation contract agree with it. Test that every accepted protector can subsequently unlock the vault, and that a rejected addition produces no partial installation.

5. **R5 — Route validation failures through the audit completion path.**

   Location: [sqlite/mod.rs:669](C:/dev/sourceorrery/crates/sourceorrery-storage/src/sqlite/mod.rs:669), with similar early returns in mutation and protector-management methods.

   `update.apply(&mut props, now)?` returns directly on invalid metadata, causing the transaction to roll back without calling `self.fail`. Other validation paths also return before an operation audit row is written. This contradicts the contract that failed operations are recorded, and makes attempts disappear even though the audit chain remains internally valid.

   Reproduced by updating a valid secret with `not_before = 2026-12-31T00:00:00Z` and `expires_on = 2026-11-01T00:00:00Z`. The call returned `invalid_argument`, while the number of `secret_update` audit rows stayed at one before and after the attempt. The CLI's separate successful `vault_open` row does not record the rejected update.

   Route expected validation and operation errors through `fail`, preserving rollback of the operation body and committing only its failure event. Use the existing name-validation helper's policy of omitting arbitrary invalid input from audit data. Extend conformance coverage to rejected windows, empty updates, invalid names, and rejected protector operations; existing successful-operation and selected-failure tests do not cover these paths.

6. **R6 — Make documentation extraction tolerate rustfmt's multiline attributes.**

   Location: [sync-docs.mjs:289](C:/dev/sourceorrery/site/scripts/sync-docs.mjs:289).

   The error-variant regex assumes `#[error("...")]` has no whitespace around its inner delimiters and cannot consume a backslash-newline continuation. `SecretError::MigrationRequired` now uses a multiline error attribute. Extraction skips that variant, then line 313 throws `code for MigrationRequired has no documented variant`.

   `npm run build` exited with status 1 during prebuild on Node 22.15.1. Astro compilation and the postbuild link check were never reached. The same build command is used by documentation CI and site deployment, so the current source cannot complete that pipeline.

   Support the valid multiline Rust syntax, including escaped newlines, or generate the reference from structured Rust output instead of regex parsing. Validate extraction against every current `SecretError` variant and then rerun the complete site build and link checks.

7. **R7 — Preserve the child's full Windows exit status.**

   Location: [project.rs:285](C:/dev/sourceorrery/crates/sourceorrery-cli/src/commands/project.rs:285).

   The child exit code is converted through `u8`; all Windows statuses outside 0–255 become `1`. An isolated empty-manifest test returned `3010` for direct `cmd.exe /C "exit 3010"`, but returned `1` through `sourceorrery run`. This loses meaningful process results and can break automation that wraps installers or other Windows programs.

   Use platform-appropriate full-width exit handling and test a Windows result above 255 in addition to the existing small nonzero result. Keep cleanup of plaintext buffers before process termination.

8. **R8 — Zeroize Argon2's working allocation.**

   Location: [kdf.rs:87](C:/dev/sourceorrery/crates/sourceorrery-crypto/src/kdf.rs:87).

   The `hash_password_into` convenience method allocates its working memory internally. The locked Argon2 0.6.0 implementation frees that allocation without zeroizing it; enabling its `zeroize` feature does not erase the whole working area. A disposable allocator probe linked against the project's crypto crate observed the 8 MiB testing allocation at deallocation and reconstructed the same KEK from the retained final lane block after dropping the original `SymmetricKey`. [Pinned upstream allocation implementation](https://github.com/RustCrypto/password-hashes/blob/b1e0ad6fe229b1ba74e4696c7359ab45d7e931f0/argon2/src/block.rs).

   Use the explicit-memory hashing API with a zeroizing block allocation, and zeroizing output storage on error and success paths. This is a residue-reduction improvement. It does not establish a new isolation guarantee against a process, debugger, or kernel already allowed to read memory; those adversaries remain outside the documented boundary.

**Verification performed**

| Check | Result |
| --- | --- |
| `cargo test --workspace --locked` | Passed: 134 tests; no failures |
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed |
| `cargo test -p sourceorrery-storage --no-default-features --locked` | Passed: 10 additional tests |
| `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked` | Passed |
| `cargo audit --json` | No known vulnerabilities among 216 dependencies; three maintenance notices |
| `npm audit --json` | No known vulnerabilities among 359 dependencies |
| `npm run build` | Failed during documentation generation, as described in R6 |
| Focused disposable probes | Confirmed row replay, creation data loss, protector limit mismatch, missing failure audit, Windows exit-code loss, and Argon2 residue |
| Common credential signatures in tracked text | No matching private-key headers, AWS access-key IDs, or GitHub token patterns; this was a narrow signature check, not a historical secret audit |

Rust checks ran on Windows with rustc/cargo 1.96.1. RustSec used database commit `999ec89d5d3f10f20be14750ec8c2d8b44e0ac9b`, updated 17 October 2026. Its notices concern unmaintained `zvariant 5.15.1`, `zbus_names 4.3.5`, and `zvariant_derive 5.15.1`, whose functionality is moving into zbus 6. They are maintenance notices, not findings of an exploitable dependency vulnerability. Track an upstream-compatible update to the Linux credential-store dependency chain. [RUSTSEC-2026-0370](https://rustsec.org/advisories/RUSTSEC-2026-0370.html), [RUSTSEC-2026-0371](https://rustsec.org/advisories/RUSTSEC-2026-0371.html), [RUSTSEC-2026-0372](https://rustsec.org/advisories/RUSTSEC-2026-0372.html).

**Coverage and limits**

The review covered all five Rust crates, lifecycle and security conformance tests, CLI and FFI tests, the generated C header, manifests and lockfiles, all four GitHub workflows, site configuration/scripts/components, and the architecture, format, and threat-model documents. Checks used temporary homes and synthetic data; real vaults and OS credential-store entries were not used.

No additional confirmed primitive misuse, SQL injection, or normal-path secret-value disclosure was found. The existing tests exercise ciphertext substitution, direct metadata edits, audit tampering, schema migration, and explicit disclosure. Their principal gaps are historical same-row replay, concurrent creation, negative audit paths, and uninitialized C outputs.

For scalability, metadata reads and explicit-version retrieval currently materialize every version's ciphertext through `query_raw_versions`, while list operations repeat those reads per secret. Consider separate metadata projections, bounded selection, and pagination before supporting large version histories. No production-size performance benchmark was run, so this is an improvement opportunity rather than an additional measured defect.

Linux/macOS runtime behavior, actual OS-keyring integrations, deployed Azure settings, release signing/provenance, and the declared minimum Rust version were not executed or independently validated. No fuzzing, Miri run, historical Git secret scan, or external penetration test was performed. Site compilation and link correctness remain unverified because prebuild fails. Same-user isolation, child-environment visibility, whole-file rollback, and copies of keyring-backed vaults outside the configured home remain the documented limitations; they were not counted as new defects.

Address R1 and R2 first, then the FFI contract, accepted protector behavior, failure auditing, documentation build, and Windows exit statuses. R8 and the maintenance/scalability observations can follow as hardening work. Passing existing checks does not resolve the reproduced findings above.
