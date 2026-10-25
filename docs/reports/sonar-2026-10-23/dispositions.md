# Dispositions — 24 October 2026

The work done against the [23 October inventory](inventory.md) and the checklist in `todo.md`, on branch `quality-pass-2026-10-24` (from c95d0b4). **Nothing has been pushed**, so no CI run, Sonar analysis or quality-gate result covers these changes yet. Every percentage and warning count below the snapshot's is local evidence, not the next Sonar result.

## The 52 open issues

| Disposition | Issues |
| --- | ---: |
| Fixed in code (including the 33 shell and 8 informational .NET findings) | 44 |
| Synthetic test data, fixture changed so it no longer looks like a credential | 1 |
| `unsafe` removed | 1 |
| `unsafe` retained, with the rationale below (4 of the 6 with lifetime/zeroising fixes next to it) | 6 |

Real defects found while reviewing them, each with a test where one is practical:

- **.NET reader handle lifetime.** `SecretReader` claimed thread safety but closed `so_reader` while another thread (or the finalizer, when the reader became unreachable during a call) could be using it, which the C ABI forbids. It is now a `SafeHandle` that every call leases. Covered by `DisposeWaitsForACallInProgress`.
- **.NET value lifetime.** A `SecretValue` that became unreachable during `Use`/`Expose` could be zeroised and freed by its finalizer while the span was being read. Fixed with `GC.KeepAlive`; this race cannot be tested deterministically.
- **.NET error paths.** The UTF-8 passphrase copy was not cleared when opening or loading failed (a wrong passphrase is the common failure). A value's native buffer had no owner if parsing its metadata failed. Fixed; neither path is reachable through the real library, so there is no test.
- **Java extraction cleanup.** The extracted library's temporary directory was left behind on every JVM exit (`deleteOnExit` order). Covered by `nothingIsLeftBehindAtExit`, which fails on the old order.

These change shipped SDK code (Java and .NET), so publishing them needs a new version (ADR 0007: a compatible fix is 0.2.1). No public API or C ABI changed.

| Issue | Severity | Rule | Analyzed location | Disposition |
| --- | --- | --- | --- | --- |
| `AaFqMvdmxc0nYNeDNy6B` | BLOCKER | `secrets:S7273` | `crates/sourceorrery-core/src/manifest.rs:660` | **Synthetic, fixture changed.** The flagged string was never a credential: it has been this one literal since 9bf1c9a, inside the test that asserts a manifest cannot carry a credential. It copied the `CAESI` body prefix of real `hvs.` service tokens, which the detector matches. Now `hvs.NOT-A-TOKEN-SMUGGLED-CANARY`. Nothing to revoke. PR 43 flagged that literal once the test moved: a long run of letters and hyphens after `hvs.` matches too, so it is now `hvs.canary not-a-token`. |
| `AaFqMvfvxc0nYNeDNy6C` | CRITICAL | `java:S5443` | `bindings/java/src/main/java/ai/sourceorrery/internal/Native.java:109` | **Fixed.** Extraction moved to `internal/NativeExtraction.java`. The directory is now created owner-only (`rwx------`) explicitly on POSIX (previously only by JDK default). The copy no longer uses `REPLACE_EXISTING`, so an entry planted in the new directory fails the copy. The `deleteOnExit` order is corrected: the empty directory was left in the temporary directory on every exit. On Windows (no POSIX permissions) the per-user `%TEMP%` is used, and a DLL still loaded at exit cannot be deleted. Tests: `NativeExtractionTest` (3 tests, Linux container); the leak test fails on the old order. Sonar may still report the Windows branch; that rationale is the disposition. PR 43 reported it, and the rationale did not hold: on a developer machine `%TEMP%` passed a sandbox tool's group, an unknown SID, SYSTEM and Administrators on to the new directory, the first two with write and delete. **Fixed:** with access lists (Windows) the directory is created with one entry, allowing the `user.name` principal, which must also be its owner; `withAccessListsTheLibraryIsTheUsersAlone` fails on the old code. |
| `AaFqMvh0xc0nYNeDNy60` | CRITICAL | `javascript:S2871` | `site/scripts/sync-docs.mjs:191` | **Fixed.** An explicit code-unit comparator (`byCodeUnit`); `localeCompare` would make the order depend on the machine's locale. The generated docs (38 files) are byte-identical before and after; the site builds 41 pages and 3,372 internal references pass. |
| `AaFqMvgpxc0nYNeDNy6F` | MAJOR | `csharpsquid:S6640` | `bindings/dotnet/SourceOrrery/Native/NativeLibraryLoader.cs:87` | **Removed.** `ReadCString` takes the address as `nint`; `Marshal.PtrToStringUTF8` needs no unsafe code. The four C-string functions return `nint`. |
| `AaFqMvgjxc0nYNeDNy6E` | MAJOR | `csharpsquid:S6640` | `bindings/dotnet/SourceOrrery/Native/NativeMethods.cs:12` | **Retained.** `SoBytes` mirrors C `so_bytes { uint8_t *ptr; size_t len; }` and must stay blittable with the same layout. Its pointer is read only by `SecretValue.Span` and `Interop.TakeString`, each bounded by `Len`, and released only through `so_bytes_free`. |
| `AaFqMvgjxc0nYNeDNy6D` | MAJOR | `csharpsquid:S6640` | `bindings/dotnet/SourceOrrery/Native/NativeMethods.cs:18` | **Retained.** The `LibraryImport` declarations of the C ABI's pointer signatures; no logic. |
| `AaFqMvg0xc0nYNeDNy6H` | MAJOR | `csharpsquid:S6640` | `bindings/dotnet/SourceOrrery/Project.cs:23` | **Retained**, to pin argument buffers and pass stack out-slots for one call each. **Fixed:** the passphrase copy is now cleared when loading fails (it was skipped by the exception); each value is owned, and zeroised on failure, before its entry is parsed; values already read are zeroised if a later entry fails. |
| `AaFqMvg7xc0nYNeDNy6J` | MAJOR | `csharpsquid:S6640` | `bindings/dotnet/SourceOrrery/SecretReader.cs:12` | **Retained**, to pin argument buffers for one call each. **Fixed:** the reader handle is now a `SafeHandle` (`Native/ReaderHandle.cs`) that every call leases. `Dispose` on another thread, or the finalizer, previously could close the handle during a call, which the C ABI forbids (`so_reader_close`: "not in use by any other thread"). Also fixed: the passphrase copy is cleared when opening fails; the value is owned before its metadata is parsed. Test: `DisposeWaitsForACallInProgress`. |
| `AaFqMvg7xc0nYNeDNy6I` | MAJOR | `csharpsquid:S6640` | `bindings/dotnet/SourceOrrery/SecretReader.cs:153` | **Retained.** `Interop.TakeString` decodes a native UTF-8 buffer of known length and frees it with `so_bytes_free`; the new `TakeSecret` gives the value an owner before parsing. |
| `AaFqMvguxc0nYNeDNy6G` | MAJOR | `csharpsquid:S6640` | `bindings/dotnet/SourceOrrery/SecretValue.cs:14` | **Retained**: the type's purpose is a span over native memory without a managed copy. **Fixed:** `GC.KeepAlive(this)` in `Use`, `Expose` and `ExposeText`, so the finalizer cannot zeroise and free the memory while a span over it is in use. |
| `AaFqMvhHxc0nYNeDNy6S` | MAJOR | `csharpsquid:S6966` | `bindings/dotnet/examples/GetSecret/Program.cs:23` | **Fixed.** `await Console.Out.WriteLineAsync` / `Console.Error.WriteLineAsync`; the example builds (warnings are errors). |
| `AaFqMvhfxc0nYNeDNy6p` | MAJOR | `shelldre:S7688` | `scripts/coverage/native.sh:25` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhfxc0nYNeDNy6q` | MAJOR | `shelldre:S7688` | `scripts/coverage/native.sh:25` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhfxc0nYNeDNy6r` | MAJOR | `shelldre:S7688` | `scripts/coverage/native.sh:42` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhfxc0nYNeDNy6s` | MAJOR | `shelldre:S7688` | `scripts/coverage/native.sh:47` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhfxc0nYNeDNy6t` | MAJOR | `shelldre:S7688` | `scripts/coverage/native.sh:47` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhfxc0nYNeDNy6u` | MAJOR | `shelldre:S7688` | `scripts/coverage/native.sh:64` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhfxc0nYNeDNy6v` | MAJOR | `shelldre:S7688` | `scripts/coverage/native.sh:68` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhfxc0nYNeDNy6w` | MAJOR | `shelldre:S7688` | `scripts/coverage/native.sh:102` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhfxc0nYNeDNy6x` | MAJOR | `shelldre:S7688` | `scripts/coverage/native.sh:120` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhfxc0nYNeDNy6y` | MAJOR | `shelldre:S7688` | `scripts/coverage/native.sh:123` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhfxc0nYNeDNy6z` | MAJOR | `shelldre:S7688` | `scripts/coverage/native.sh:194` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhYxc0nYNeDNy6T` | MAJOR | `shelldre:S7688` | `scripts/coverage/run.sh:9` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhYxc0nYNeDNy6U` | MAJOR | `shelldre:S7688` | `scripts/coverage/run.sh:12` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhYxc0nYNeDNy6V` | MAJOR | `shelldre:S7688` | `scripts/coverage/run.sh:24` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhYxc0nYNeDNy6W` | MAJOR | `shelldre:S7688` | `scripts/coverage/run.sh:25` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhYxc0nYNeDNy6X` | MAJOR | `shelldre:S7688` | `scripts/coverage/run.sh:35` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhYxc0nYNeDNy6Y` | MAJOR | `shelldre:S7688` | `scripts/coverage/run.sh:38` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhYxc0nYNeDNy6Z` | MAJOR | `shelldre:S7688` | `scripts/coverage/run.sh:38` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhYxc0nYNeDNy6a` | MAJOR | `shelldre:S7688` | `scripts/coverage/run.sh:43` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhYxc0nYNeDNy6b` | MAJOR | `shelldre:S7688` | `scripts/coverage/run.sh:47` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhYxc0nYNeDNy6c` | MAJOR | `shelldre:S7688` | `scripts/coverage/run.sh:50` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhYxc0nYNeDNy6d` | MAJOR | `shelldre:S7688` | `scripts/coverage/run.sh:50` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhYxc0nYNeDNy6e` | MAJOR | `shelldre:S7688` | `scripts/coverage/run.sh:81` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhYxc0nYNeDNy6f` | MAJOR | `shelldre:S7688` | `scripts/coverage/run.sh:83` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhYxc0nYNeDNy6g` | MAJOR | `shelldre:S7688` | `scripts/coverage/run.sh:92` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhYxc0nYNeDNy6h` | MAJOR | `shelldre:S7688` | `scripts/coverage/run.sh:103` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhYxc0nYNeDNy6i` | MAJOR | `shelldre:S7688` | `scripts/coverage/run.sh:103` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhYxc0nYNeDNy6j` | MAJOR | `shelldre:S7688` | `scripts/coverage/run.sh:104` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhYxc0nYNeDNy6k` | MAJOR | `shelldre:S7688` | `scripts/coverage/run.sh:104` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhYxc0nYNeDNy6l` | MAJOR | `shelldre:S7688` | `scripts/coverage/run.sh:127` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhYxc0nYNeDNy6m` | MAJOR | `shelldre:S7688` | `scripts/coverage/run.sh:127` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhYxc0nYNeDNy6n` | MAJOR | `shelldre:S7688` | `scripts/coverage/run.sh:135` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvhYxc0nYNeDNy6o` | MAJOR | `shelldre:S7688` | `scripts/coverage/run.sh:135` | **Fixed.** `[[ ]]` in all 33 places. Every right-hand side is a literal, so pattern matching changes no result; heredocs untouched. `bash -n` passes, and shellcheck reports nothing new. |
| `AaFqMvg7xc0nYNeDNy6K` | INFO | `external_roslyn:CA1513` | `bindings/dotnet/SourceOrrery/SecretReader.cs:145` | **Fixed.** `ObjectDisposedException.ThrowIf(IsClosed, this)` in the new `SecretReader.Begin`. |
| `AaFqMvhCxc0nYNeDNy6R` | INFO | `external_roslyn:CA1861` | `bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs:231` | **Fixed.** `static readonly string[] ProjectSecretNames`. |
| `AaFqMvhCxc0nYNeDNy6L` | INFO | `external_roslyn:CA2101` | `bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs:34` | **Fixed.** `LibraryImport` with `StringMarshalling.Utf8`: POSIX environment strings are bytes and the C ABI reads them as UTF-8. Verified on Linux, where it runs. |
| `AaFqMvhCxc0nYNeDNy6M` | INFO | `external_roslyn:CA2101` | `bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs:37` | **Fixed.** `LibraryImport` with `StringMarshalling.Utf8`: POSIX environment strings are bytes and the C ABI reads them as UTF-8. Verified on Linux, where it runs. |
| `AaFqMvhCxc0nYNeDNy6O` | INFO | `external_roslyn:SYSLIB1054` | `bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs:35` | **Fixed** with the same `LibraryImport` (the test project targets net10.0; `AllowUnsafeBlocks` is for the generated marshalling). |
| `AaFqMvhCxc0nYNeDNy6N` | INFO | `external_roslyn:SYSLIB1054` | `bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs:38` | **Fixed** with the same `LibraryImport` (the test project targets net10.0; `AllowUnsafeBlocks` is for the generated marshalling). |
| `AaFqMvhCxc0nYNeDNy6P` | INFO | `external_roslyn:xUnit2032` | `bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs:137` | **Fixed.** `Assert.IsType<T>(value, exactMatch: false)` keeps the assignability check. |
| `AaFqMvhCxc0nYNeDNy6Q` | INFO | `external_roslyn:xUnit2032` | `bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs:165` | **Fixed.** `Assert.IsType<T>(value, exactMatch: false)` keeps the assignability check. |

## Scanner and build warnings (33 occurrences, 29 messages)

| Warning | Disposition |
| --- | --- |
| 4 × JaCoCo report not found | Configuration problem, addressed: the report path is now set only on the source module (`SourceOrrery.Analysis.Source.csproj`), not globally for the .NET modules. Needs a scan to confirm. |
| 3 × Go file "not included in the project" | Configuration problem, addressed the same way (Go report only on the module that owns the files). Needs a scan. |
| 98 + 1 LCOV problems in `rust-combined.lcov` | Addressed: the scanner imports `rust-production.lcov` on the source module only. `prepare-reports.py` drops records only for files already classified as tests and fails on unknown files or invalid lines (3 tests pass). The complete report is still uploaded. Needs a scan. |
| Unresolved imports/types; preview features | Only the first JavaSensor run reported them: the one whose classpath lacked the SDK's main classes. The other module reported neither. `sonar.java.jdkHome` was already JDK 25 (`scan.sh`). The patch adds `bindings/java/target/classes` to the test libraries. No preview language feature is used: `java.lang.foreign` is final in Java 22. If they persist, the next step is one scan with DEBUG. |
| 2 × `sonar.modules` deprecated | Upstream: generated by SonarScanner for .NET's multi-module properties. Not changed; removing it would drop language analysis. |
| 19 × duplication ignored in a test file | Expected: test classification working. Not a defect. |
| Java security cache key already present | Upstream scanner notice; no action. |
| npm `EBADPLATFORM` (INFO, 5) | Sonar's dependency analysis runs `npm install --package-lock-only` inside each `bindings/node/npm/<platform>` package, whose `os`/`cpu` fields refuse Linux. The host install (`npm ci --prefix bindings/node`) succeeded and the Node SDK tests ran. Those packages have no dependencies, so nothing is lost. |
| Site: `i18n` collection absent; `docs → 404` entry not found | Starlight looks up optional UI translations and an optional custom 404 body; the default 404 page is built. Accounted for, not changed: silencing them means an empty translation collection or replacing the theme's 404 text. |

The comparison with this snapshot after one fresh scan is still to do (it needs the push).

## Coverage work (section C)

- Python tooling: 53 tests pass (10 CI, 5 coverage, 35 release, 3 report filter; 9 fewer than before because the Moto workaround's tests are gone). The report has 568/649 lines (87.52%) and 215/258 branches (83.33%).
- Node helpers: 2 tests pass; 21/28 lines (75%).
- Site: unit tests plus the full build (sync, Astro, link check) under c8 in `sdk.sh site` and `run.ps1`, with `--clean=false` for the second run. `bash scripts/coverage/sdk.sh site` on Linux (Node 24 container): unit tests alone 275/1,033 lines; merged with the build 965/1,033 (93.41%), 41 pages, 3,372 internal references. The Windows `run.ps1` entry point was not rerun: the local Node 22.15 is below Astro's minimum 22.22.
- The final regenerated tooling XML is validated by `check-reports.py` after the validator's own execution is recorded (`run.sh --stage verify`). That ordering is in place but has not run end to end.
- The 2 uncovered new AWS-provider lines are `lib.rs:392-393`: the error for a deletion date the client cannot represent. Every caller checks that a date exists first, so only a malformed service response reaches it. A meaningful test needs an HTTP mock of `DescribeSecret`, which this crate does not have. Left uncovered, justified.
- Not done: the full changed pipeline on Ubuntu, a hosted coverage run and its Sonar import.

## LocalStack instead of Moto

- CI (`provider-aws`) and coverage start LocalStack through lstk 1.4.1, installed with `npm ci` from `scripts/ci/lstk`'s lock file (integrity hashes for every platform). The image `localstack-pro:2026.10.0` is pinned in `.lstk/config.toml`. `scripts/ci/localstack.sh` selects, starts (lstk waits for readiness) and collects logs; logs are uploaded on failure with the token removed.
- `LOCALSTACK_AUTH_TOKEN` is the repository secret, given only to the three steps that run lstk. A fork's pull request never receives it: its emulator steps are skipped with a warning annotation and step summary. Any other run without it fails. It must be a LocalStack **CI** auth token; a developer token is not accepted in CI.
- Locally against the pinned image: the provider's tests pass (5 live, 5 unit), as do the Rust SDK harness (29/29), the remote CLI steps and STS federation. The federation role moved to account `000000000000`, the account LocalStack maps the `test` key to.
- LocalStack differs from the AWS API reference. It refuses `ListSecretVersionIds` for a secret scheduled for deletion, which AWS allows, and it gives version `CreatedDate` in whole seconds (both in 2026.10.0 and 2026.10.2). By decision on 24 October, the two deletion tests then compare everything except the version times and emit a `::warning::` annotation (`cargo test -- --show-output`). Against an endpoint that lists those versions they compare the times too: verified against Moto 5.2.4, with no warnings.
- Moto's timestamp workaround, its fixture, its tests and its workflow steps are removed. The Sonar test inventory and the docs are updated.
- Not checked: the C runner's `--remote` harness (no C compiler in this environment; same harness and scenarios as Rust), and the hosted runs.

## Publishing (section E): for the account holder

- crates.io Trusted Publishing for `sourceorrery-provider`, `sourceorrery-provider-aws`, `sourceorrery-provider-vault` (owner Netizine, repository sourceorrery, workflows `release.yml` and `ReleasePackages.yaml`, no environment). Then revoke the bootstrap token and delete `CRATES_BOOTSTRAP_TOKEN`.
- `WINGET_TOKEN`: replace with a token that has the documented scopes.
- WinGet PR [microsoft/winget-pkgs#460455](https://github.com/microsoft/winget-pkgs/pull/460455) (read-only check, 24 October): the CLA is agreed and `license/cla` passes. Validation steps 1–7, 9 and 10 pass; installation validation (08) is neutral and the PR is labelled `Validation-Executable-Error` ("post-install executable validation returned an unexpected result; review is required"). Running `sourceorrery` without arguments and with `--version` both exit 0 here, so the cause is in the validation logs, which a maintainer reviews. Nothing was posted.
- Homebrew/Scoop with the corrected `PACKAGING_TOKEN`: untested until the next controlled publishing run.

## Verified this session

| Check | Result |
| --- | --- |
| `cargo test -p sourceorrery-core` manifest tests | 15 passed |
| `cargo test -p sourceorrery-provider-aws` against LocalStack 2026.10.0 / Moto 5.2.4 | 5 + 5 passed on each |
| `cargo fmt --check`, `cargo clippy -D warnings` (core, provider-aws) | clean |
| .NET solution build, warnings as errors | clean |
| .NET tests, Windows, fixture vault | 16 passed |
| .NET tests, Linux (.NET 10 container, Linux C ABI, its own fixture) | 16 passed, including the remote test that calls `setenv`/`unsetenv` |
| Java tests, Linux (Temurin 25 container) | NativeExtractionTest 3 passed; ReaderTest skipped (no fixture) |
| Java load through the jar-resource extraction, Linux C ABI | contract 1, ABI 1; no extraction directory left after exit |
| SDK conformance harness, .NET runner, Windows | 26/26 |
| `sdk.sh site` under c8, Linux | 965/1,033 lines; build and link check pass |
| Rust SDK harness `--remote`, LocalStack | 29/29 |
| AWS federation, LocalStack | passed |
| Tooling tests (`tooling.sh`) and `check-scope.py` | 53 Python + 2 Node passed; scope 235 + 46 files |
| Site sync output, old vs new sort | byte-identical |
| Site build and link check (Node 24) | 41 pages, 3,372 references |
| actionlint, zizmor (high), shellcheck | clean; shellcheck only pre-existing notes outside the change |

## Still open

- Push one reviewed candidate (with c95d0b4), then one CI, docs and coverage run; diagnose by failing step.
- The unchanged quality gate on that commit: new-code coverage and the maintainability severity (15 > 14) are not known until then.
- Release decision: Java and .NET SDK fixes are shipped code, so publishing them is 0.2.1.
- Dependabot does not track the image tag in `.lstk/config.toml`; it tracks lstk through `scripts/ci/lstk`.
