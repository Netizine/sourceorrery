# SonarCloud inventory — 23 October 2026

For the 24 October checklist. Snapshot of the public default-branch analysis on commit `224c3fb`, from [coverage run 40008371065](https://github.com/Netizine/sourceorrery/actions/runs/40008371065). Local uncommitted patches are not reflected in these findings.

## Scope and exact counts

- Downloaded all **153 / 153 visible issue records**, page 1 with page size 500. No pagination or result cap was hit.
- **52 unresolved issues**: 1 blocker, 2 critical, 41 major, 8 info.
- Unresolved types: 9 vulnerability, 1 bug, 42 code_smell.
- Every unresolved issue has status `OPEN`; no other open/accepted/reopened statuses were returned. The query used no status, severity, type or new-code filter. **101 CLOSED/FIXED** records are retained in the raw JSON but omitted from the action inventory below.
- **0 public security hotspots**: unfiltered, `TO_REVIEW`, and `REVIEWED` requests all returned total 0. This does not mean the vulnerability-labelled issues below have been reviewed.
- Anonymous public API access only. Hidden/restricted records, private organization data and dependency-alert inventories were not queried; their absence is not a zero-count assertion.
- Machine-readable full export: [inventory.json](inventory.json). Raw issue/hotspot/gate/measure responses are alongside it. API severity labels and impact severities differ; JSON retains both.

## Quality gate

**ERROR** on the published analysis. Overall coverage **80.6%**, line coverage **81.4%**, branch coverage **60.8%**. The overall denominator is **25,989 lines**, with **4,831 uncovered**.

| Condition | Actual | Failure threshold | Result |
| --- | ---: | --- | --- |
| `new_coverage` | 2.5 | LT 80 | ERROR |
| `new_duplicated_lines_density` | 0.0 | GT 3 | OK |
| `new_bugs_severity` | 0 | GT 9 | OK |
| `new_code_smells_severity` | 15 | GT 14 | ERROR |
| `new_sca_severity_any_issue` | 0 | GT 9 | OK |
| `new_vulnerabilities_severity` | 0 | GT 9 | OK |

New-code period: previous version, starting **23 October 2026 at 11:58:14 +01:00**. New-code coverage is 2.5% over 555 lines, with 541 uncovered. Of those, 539 are tooling lines and 2 are in the AWS provider. The maintainability severity value is a metric, not an issue count. [Dashboard](https://sonarcloud.io/dashboard?id=Netizine_sourceorrery&branch=main).

## Rule and file groups

| API severity | Rule | File | Count |
| --- | --- | --- | ---: |
| BLOCKER | `secrets:S7273` | `crates/sourceorrery-core/src/manifest.rs` | 1 |
| CRITICAL | `java:S5443` | `bindings/java/src/main/java/ai/sourceorrery/internal/Native.java` | 1 |
| CRITICAL | `javascript:S2871` | `site/scripts/sync-docs.mjs` | 1 |
| MAJOR | `csharpsquid:S6640` | `bindings/dotnet/SourceOrrery/Native/NativeLibraryLoader.cs` | 1 |
| MAJOR | `csharpsquid:S6640` | `bindings/dotnet/SourceOrrery/Native/NativeMethods.cs` | 2 |
| MAJOR | `csharpsquid:S6640` | `bindings/dotnet/SourceOrrery/Project.cs` | 1 |
| MAJOR | `csharpsquid:S6640` | `bindings/dotnet/SourceOrrery/SecretReader.cs` | 2 |
| MAJOR | `csharpsquid:S6640` | `bindings/dotnet/SourceOrrery/SecretValue.cs` | 1 |
| MAJOR | `csharpsquid:S6966` | `bindings/dotnet/examples/GetSecret/Program.cs` | 1 |
| MAJOR | `shelldre:S7688` | `scripts/coverage/native.sh` | 11 |
| MAJOR | `shelldre:S7688` | `scripts/coverage/run.sh` | 22 |
| INFO | `external_roslyn:CA1513` | `bindings/dotnet/SourceOrrery/SecretReader.cs` | 1 |
| INFO | `external_roslyn:CA1861` | `bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs` | 1 |
| INFO | `external_roslyn:CA2101` | `bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs` | 2 |
| INFO | `external_roslyn:SYSLIB1054` | `bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs` | 2 |
| INFO | `external_roslyn:xUnit2032` | `bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs` | 2 |

## Complete unresolved inventory

All 52 entries follow, grouped by severity/rule/file. These are scanner findings requiring review, not independently confirmed defects. Locations link to the analyzed commit, so later local edits do not silently change the evidence.

| Severity | Rule | Analyzed file:line | Finding | Issue |
| --- | --- | --- | --- | --- |
| BLOCKER | `secrets:S7273` | [crates/sourceorrery-core/src/manifest.rs:660](https://github.com/Netizine/sourceorrery/blob/224c3fb/crates/sourceorrery-core/src/manifest.rs#L660) | Make sure this Hashicorp Vault service token gets revoked, changed, and removed from the code. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvdmxc0nYNeDNy6B) |
| CRITICAL | `java:S5443` | [bindings/java/src/main/java/ai/sourceorrery/internal/Native.java:109](https://github.com/Netizine/sourceorrery/blob/224c3fb/bindings/java/src/main/java/ai/sourceorrery/internal/Native.java#L109) | Make sure publicly writable directories are used safely here. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvfvxc0nYNeDNy6C) |
| CRITICAL | `javascript:S2871` | [site/scripts/sync-docs.mjs:191](https://github.com/Netizine/sourceorrery/blob/224c3fb/site/scripts/sync-docs.mjs#L191) | Provide a compare function that depends on "String.localeCompare", to reliably sort elements alphabetically. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvh0xc0nYNeDNy60) |
| MAJOR | `csharpsquid:S6640` | [bindings/dotnet/SourceOrrery/Native/NativeLibraryLoader.cs:87](https://github.com/Netizine/sourceorrery/blob/224c3fb/bindings/dotnet/SourceOrrery/Native/NativeLibraryLoader.cs#L87) | Avoid using this unsafe code block. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvgpxc0nYNeDNy6F) |
| MAJOR | `csharpsquid:S6640` | [bindings/dotnet/SourceOrrery/Native/NativeMethods.cs:12](https://github.com/Netizine/sourceorrery/blob/224c3fb/bindings/dotnet/SourceOrrery/Native/NativeMethods.cs#L12) | Avoid using this unsafe code block. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvgjxc0nYNeDNy6E) |
| MAJOR | `csharpsquid:S6640` | [bindings/dotnet/SourceOrrery/Native/NativeMethods.cs:18](https://github.com/Netizine/sourceorrery/blob/224c3fb/bindings/dotnet/SourceOrrery/Native/NativeMethods.cs#L18) | Avoid using this unsafe code block. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvgjxc0nYNeDNy6D) |
| MAJOR | `csharpsquid:S6640` | [bindings/dotnet/SourceOrrery/Project.cs:23](https://github.com/Netizine/sourceorrery/blob/224c3fb/bindings/dotnet/SourceOrrery/Project.cs#L23) | Avoid using this unsafe code block. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvg0xc0nYNeDNy6H) |
| MAJOR | `csharpsquid:S6640` | [bindings/dotnet/SourceOrrery/SecretReader.cs:12](https://github.com/Netizine/sourceorrery/blob/224c3fb/bindings/dotnet/SourceOrrery/SecretReader.cs#L12) | Avoid using this unsafe code block. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvg7xc0nYNeDNy6J) |
| MAJOR | `csharpsquid:S6640` | [bindings/dotnet/SourceOrrery/SecretReader.cs:153](https://github.com/Netizine/sourceorrery/blob/224c3fb/bindings/dotnet/SourceOrrery/SecretReader.cs#L153) | Avoid using this unsafe code block. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvg7xc0nYNeDNy6I) |
| MAJOR | `csharpsquid:S6640` | [bindings/dotnet/SourceOrrery/SecretValue.cs:14](https://github.com/Netizine/sourceorrery/blob/224c3fb/bindings/dotnet/SourceOrrery/SecretValue.cs#L14) | Avoid using this unsafe code block. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvguxc0nYNeDNy6G) |
| MAJOR | `csharpsquid:S6966` | [bindings/dotnet/examples/GetSecret/Program.cs:23](https://github.com/Netizine/sourceorrery/blob/224c3fb/bindings/dotnet/examples/GetSecret/Program.cs#L23) | Await WriteLineAsync instead. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhHxc0nYNeDNy6S) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/native.sh:25](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/native.sh#L25) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhfxc0nYNeDNy6p) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/native.sh:25](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/native.sh#L25) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhfxc0nYNeDNy6q) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/native.sh:42](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/native.sh#L42) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhfxc0nYNeDNy6r) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/native.sh:47](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/native.sh#L47) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhfxc0nYNeDNy6s) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/native.sh:47](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/native.sh#L47) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhfxc0nYNeDNy6t) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/native.sh:64](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/native.sh#L64) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhfxc0nYNeDNy6u) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/native.sh:68](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/native.sh#L68) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhfxc0nYNeDNy6v) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/native.sh:102](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/native.sh#L102) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhfxc0nYNeDNy6w) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/native.sh:120](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/native.sh#L120) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhfxc0nYNeDNy6x) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/native.sh:123](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/native.sh#L123) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhfxc0nYNeDNy6y) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/native.sh:194](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/native.sh#L194) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhfxc0nYNeDNy6z) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/run.sh:9](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/run.sh#L9) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhYxc0nYNeDNy6T) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/run.sh:12](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/run.sh#L12) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhYxc0nYNeDNy6U) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/run.sh:24](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/run.sh#L24) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhYxc0nYNeDNy6V) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/run.sh:25](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/run.sh#L25) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhYxc0nYNeDNy6W) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/run.sh:35](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/run.sh#L35) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhYxc0nYNeDNy6X) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/run.sh:38](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/run.sh#L38) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhYxc0nYNeDNy6Y) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/run.sh:38](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/run.sh#L38) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhYxc0nYNeDNy6Z) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/run.sh:43](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/run.sh#L43) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhYxc0nYNeDNy6a) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/run.sh:47](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/run.sh#L47) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhYxc0nYNeDNy6b) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/run.sh:50](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/run.sh#L50) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhYxc0nYNeDNy6c) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/run.sh:50](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/run.sh#L50) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhYxc0nYNeDNy6d) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/run.sh:81](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/run.sh#L81) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhYxc0nYNeDNy6e) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/run.sh:83](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/run.sh#L83) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhYxc0nYNeDNy6f) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/run.sh:92](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/run.sh#L92) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhYxc0nYNeDNy6g) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/run.sh:103](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/run.sh#L103) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhYxc0nYNeDNy6h) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/run.sh:103](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/run.sh#L103) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhYxc0nYNeDNy6i) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/run.sh:104](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/run.sh#L104) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhYxc0nYNeDNy6j) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/run.sh:104](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/run.sh#L104) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhYxc0nYNeDNy6k) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/run.sh:127](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/run.sh#L127) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhYxc0nYNeDNy6l) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/run.sh:127](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/run.sh#L127) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhYxc0nYNeDNy6m) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/run.sh:135](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/run.sh#L135) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhYxc0nYNeDNy6n) |
| MAJOR | `shelldre:S7688` | [scripts/coverage/run.sh:135](https://github.com/Netizine/sourceorrery/blob/224c3fb/scripts/coverage/run.sh#L135) | Use '[[' instead of '[' for conditional tests. The '[[' construct is safer and more feature-rich. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhYxc0nYNeDNy6o) |
| INFO | `external_roslyn:CA1513` | [bindings/dotnet/SourceOrrery/SecretReader.cs:145](https://github.com/Netizine/sourceorrery/blob/224c3fb/bindings/dotnet/SourceOrrery/SecretReader.cs#L145) | Use 'ObjectDisposedException.ThrowIf' instead of explicitly throwing a new exception instance | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvg7xc0nYNeDNy6K) |
| INFO | `external_roslyn:CA1861` | [bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs:231](https://github.com/Netizine/sourceorrery/blob/224c3fb/bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs#L231) | Prefer 'static readonly' fields over constant array arguments if the called method is called repeatedly and is not mutating the passed array | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhCxc0nYNeDNy6R) |
| INFO | `external_roslyn:CA2101` | [bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs:34](https://github.com/Netizine/sourceorrery/blob/224c3fb/bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs#L34) | Specify marshaling for P/Invoke string arguments | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhCxc0nYNeDNy6L) |
| INFO | `external_roslyn:CA2101` | [bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs:37](https://github.com/Netizine/sourceorrery/blob/224c3fb/bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs#L37) | Specify marshaling for P/Invoke string arguments | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhCxc0nYNeDNy6M) |
| INFO | `external_roslyn:SYSLIB1054` | [bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs:35](https://github.com/Netizine/sourceorrery/blob/224c3fb/bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs#L35) | Mark the method 'setenv' with 'LibraryImportAttribute' instead of 'DllImportAttribute' to generate P/Invoke marshalling code at compile time | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhCxc0nYNeDNy6O) |
| INFO | `external_roslyn:SYSLIB1054` | [bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs:38](https://github.com/Netizine/sourceorrery/blob/224c3fb/bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs#L38) | Mark the method 'unsetenv' with 'LibraryImportAttribute' instead of 'DllImportAttribute' to generate P/Invoke marshalling code at compile time | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhCxc0nYNeDNy6N) |
| INFO | `external_roslyn:xUnit2032` | [bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs:137](https://github.com/Netizine/sourceorrery/blob/224c3fb/bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs#L137) | The naming of Assert.IsAssignableFrom can be confusing. An overload of Assert.IsType is available with an exact match flag which can be set to false to perform the same operation. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhCxc0nYNeDNy6P) |
| INFO | `external_roslyn:xUnit2032` | [bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs:165](https://github.com/Netizine/sourceorrery/blob/224c3fb/bindings/dotnet/SourceOrrery.Tests/ReaderTests.cs#L165) | The naming of Assert.IsAssignableFrom can be confusing. An overload of Assert.IsType is available with an exact match flag which can be set to false to perform the same operation. | [Open](https://sonarcloud.io/project/issues?id=Netizine_sourceorrery&open=AaFqMvhCxc0nYNeDNy6Q) |

## Remaining scanner warnings in the successful run

The saved scanner log contains **33 warning occurrences**, listed exactly below (repeated identical messages grouped). These are log occurrences, not the Sonar UI warning count. Original local log: `coverage/github-40008371065.log`; [upload-analysis step log](https://github.com/Netizine/sourceorrery/actions/runs/40008371065).

| Occurrences | Exact warning |
| ---: | --- |
| 4 | No coverage report can be found with sonar.coverage.jacoco.xmlReportPaths='bindings/java/target/site/jacoco/jacoco.xml'. Using default locations: target/site/jacoco/jacoco.xml,target/site/jacoco-it/jacoco.xml,build/reports/jacoco/test/jacocoTestReport.xml |
| 1 | Unresolved imports/types have been detected during analysis. Enable DEBUG mode to see them. |
| 1 | Use of preview features have been detected during analysis. Enable DEBUG mode to see them. |
| 1 | File 'bindings/go/project.go' is not included in the project, ignoring coverage |
| 1 | File 'bindings/go/errors.go' is not included in the project, ignoring coverage |
| 1 | File 'bindings/go/sourceorrery.go' is not included in the project, ignoring coverage |
| 2 | The sonar.modules is a deprecated property and should not be used anymore, it inhibits an optimized analysis |
| 1 | Found 98 problems in LCOV report: /home/runner/work/sourceorrery/sourceorrery/coverage/rust-combined.lcov. More details in verbose mode |
| 1 | Duplication reported for 'crates/sourceorrery-cli/tests/integrations.rs' will be ignored because it's a test file. |
| 1 | Duplication reported for 'tests/conformance/src/lib.rs' will be ignored because it's a test file. |
| 1 | Duplication reported for 'crates/sourceorrery-provider/src/tests.rs' will be ignored because it's a test file. |
| 1 | Duplication reported for 'crates/sourceorrery-cli/src/ui/setup/tests.rs' will be ignored because it's a test file. |
| 1 | Duplication reported for 'tests/conformance/tests/lifecycle.rs' will be ignored because it's a test file. |
| 1 | Duplication reported for 'crates/sourceorrery-cli/src/ui/view/tests.rs' will be ignored because it's a test file. |
| 1 | Duplication reported for 'crates/sourceorrery-cli/tests/cli.rs' will be ignored because it's a test file. |
| 1 | Duplication reported for 'tests/conformance/src/lifecycle.rs' will be ignored because it's a test file. |
| 1 | Duplication reported for 'crates/sourceorrery-storage/src/sqlite/tests.rs' will be ignored because it's a test file. |
| 1 | Duplication reported for 'crates/sourceorrery/examples/conformance.rs' will be ignored because it's a test file. |
| 1 | Duplication reported for 'crates/sourceorrery-provider-vault/tests/live.rs' will be ignored because it's a test file. |
| 1 | Duplication reported for 'crates/sourceorrery-ffi/tests/reader.rs' will be ignored because it's a test file. |
| 1 | Duplication reported for 'crates/sourceorrery-provider-vault/tests/errors.rs' will be ignored because it's a test file. |
| 1 | Duplication reported for 'crates/sourceorrery-cli/src/ui/fake.rs' will be ignored because it's a test file. |
| 1 | Duplication reported for 'crates/sourceorrery-provider-aws/tests/live.rs' will be ignored because it's a test file. |
| 1 | Duplication reported for 'crates/sourceorrery/tests/reader.rs' will be ignored because it's a test file. |
| 1 | Duplication reported for 'tests/conformance/tests/security.rs' will be ignored because it's a test file. |
| 1 | Duplication reported for 'crates/sourceorrery-ffi/tests/header.rs' will be ignored because it's a test file. |
| 1 | Duplication reported for 'crates/sourceorrery-ffi/tests/smoke.rs' will be ignored because it's a test file. |
| 1 | Could not write cache key javasecurity:types: (Cache already contains key 'javasecurity:types:') |
| 1 | Found 1 problems in LCOV report: /home/runner/work/sourceorrery/sourceorrery/coverage/rust-combined.lcov. More details in verbose mode |

- Four JaCoCo path warnings came from unrelated .NET module directories. The Java production module imported its report.
- Three Go warnings came from the test module; the production module imported Go coverage.
- Rust reported 98 LCOV problems in the test module and 1 in the production module. The saved LCOV has 99 valid existing paths and valid DA line numbers. The production import copy removes only `crates/sourceorrery-cli/src/ui/fake.rs`, already classified as a test; all 98 production records and execution counts remain.
- Java test analysis reported unresolved imports and preview-feature detection. The paused patch adds SDK main classes to the Java test classpath. Its effect on both warnings is not yet confirmed by a new scan.
- `sonar.modules` deprecation and the Java security cache-key warning originate in the multi-module scanner. They have not been eliminated. Rust duplication warnings explicitly say test-file duplicates are ignored; test classification is working.
- Dependency analysis also logged INFO-level npm `EBADPLATFORM` messages for intentional Windows/macOS platform package manifests on Ubuntu. Those are separate from the scanner WARN inventory and were not independently revalidated.

## Paused local coverage patches — validation completed before the stop request

- Patches are **uncommitted and unpushed**. No new CI run or Sonar upload validates them. Source/test exclusions and quality-gate thresholds were not changed.
- Existing Python tests were measured via `tooling.sh`: **19 CI + 5 coverage + 35 release + 3 report-filter = 62 tests passed**. The Python XML exists with **631/729 lines (86.56%)** and **233/282 branches (82.62%)**; combined coverage.py display rounded to 85%. Actual downstream converter/validator execution still has to be collected in the full pipeline.
- Two existing Node helper tests passed; tooling LCOV **21/28 lines (75%)**.
- Native Windows `run.ps1 -Target site` completed before interruption: **10 tests**, **41-page build**, **3,372 internal-reference checks** all passed. The actual latest merged report is **971/1,030 lines (94.27%)**. An earlier independent warm-up run reported 980/1,030; use the latest artifact, not the earlier percentage.
- Site build still warns that the `i18n` collection is absent/empty and `docs → 404` was not found. Build and link checks passed; these warnings were not fixed.
- MSBuild settings evaluation showed five report properties on the Source module and none on the Tests module. This verifies evaluated configuration, not server-side importer behavior.
- The real downloaded Rust artifact filtered from 99 to 98 records, omitting only the already-classified test file stated above. Three focused filtering tests passed.
- Bash syntax checks and `git diff --check` passed before the stop request. The final refreshed tooling XML validation is wired in `run.sh` but that final full-pipeline stage has **not** been executed. No fresh full all-language run, workflow lint after these edits, final independent review completion, or Sonar warning-clearing confirmation has been claimed.
- Paused files: `SonarQube.Analysis.xml`, `SourceOrrery.Analysis.Source.csproj`, `.github/workflows/coverage.yml`, `scripts/coverage/{run.sh,run.ps1,sdk.sh,sdk.md,tooling.sh,tooling.coveragerc}`, `scripts/sonar/{check-reports.py,prepare-reports.py,test_prepare_reports.py}`, and `docs/coverage.md`.

No further fixes, tests, commits, pushes or workflow runs were started for this inventory.
