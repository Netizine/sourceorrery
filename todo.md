# Tomorrow: quality and release checklist — 24 October 2026

This replaces the old milestone plan. The objective is to finish a verified, supportable release without another open-ended cycle of fixes, scans and token spend. No implementation, tests, pushes or releases were started while preparing this checklist.

## Status after the 24 October session

Branch `quality-pass-2026-10-24` (local commits, **not pushed**). Budget set by James: everything doable locally, no push. Every issue ID's disposition, the warnings, the local test evidence and the open items are in [dispositions.md](docs/reports/sonar-2026-10-23/dispositions.md). LocalStack decision (24 October): migrate, and on an emulator that refuses to list a deleted secret's versions, skip only the version-time comparison with a warning.

## Start here: control the cost

- [x] Set a hard time/spend limit before implementation. Do not infer permission for unlimited cleanup or automatic continuation. *24 Oct: everything doable locally; no push.*
- [x] Read this file and the [complete Sonar inventory](docs/reports/sonar-2026-10-23/inventory.md). Reuse its issue IDs, file locations and existing evidence; do not research the project again.
- [x] Inspect the existing local changes before editing. Finish or deliberately discard each unfinished patch; do not recreate it.
- [x] Batch work by root cause. Avoid duplicate agent investigations, one-fix-per-push cycles, repeated full builds and broad dependency upgrades.
- [x] Record the issue IDs addressed and relevant test results. Stop at the budget limit with a concrete handoff. *dispositions.md*

## Already done — do not repeat

| Item | Verified state on 23 October |
| --- | --- |
| Release | [0.2.0 is public](https://github.com/Netizine/sourceorrery/releases/tag/v0.2.0), with 53 assets, checksums and build attestations. Release source: 956c05a6eb287db1f655f8440664c5150ba92570. |
| Branch merge | agent-skills is merged into main. |
| Registries | All nine crates, including the three new providers, are published at 0.2.0. All seven npm packages, PyPI, Maven Central, NuGet, Packagist and the Go module are verified publicly. |
| Package managers | Homebrew and Scoop were updated and their published contents verified. Their workflow credentials failed; publication was recovered using the existing GitHub login. |
| Smoke tests | Published Windows CLI checksum and provenance verified; isolated encrypted-vault create/store/read passed. Published npm and Python Windows native libraries loaded. NuGet repository signature verified. |
| CI | [43/43 jobs passed](https://github.com/Netizine/sourceorrery/actions/runs/40008371102) on 224c3fb; [release-source CI](https://github.com/Netizine/sourceorrery/actions/runs/40006503163) also passed. |
| Coverage | [Run 40008371065 succeeded](https://github.com/Netizine/sourceorrery/actions/runs/40008371065): reports generated and uploaded. A successful upload does **not** mean a passing quality gate. |
| Original three Sonar warnings | Python version configured, tests classified, referenced TypeScript configurations resolved. Automatic Analysis is off; CI analysis is active. |
| Documentation | Postpublication wording, release-tag build instructions and WinGet schema 1.12 are committed locally as c95d0b4, **not pushed**. Site build/link checks passed. |
| GitHub findings | Read-only checks found **0 open repository issues** and **0 open Dependabot alerts**. These do not replace the Sonar review. |

The published release workflow is red because its Homebrew/Scoop and WinGet credentials failed. Registry publishing succeeded. Do not rebuild all packages to repair that workflow status.

## Current Sonar findings: 52 open, not 153 outstanding

The export downloaded **153/153 visible records**: **52 OPEN** and **101 CLOSED/FIXED**. The 101 closed findings are not tomorrow's backlog.

| Open findings | Count |
| --- | ---: |
| Blocker | 1 |
| Critical | 2 |
| Major | 41 |
| Informational | 8 |
| Vulnerability-labelled | 9 |
| Bug-labelled | 1 |
| Code-smell-labelled | 42 |
| Public security hotspots | 0 |

Severity and type are separate classifications; do not add those two sets together. These are scanner findings, not independently confirmed vulnerabilities. Public API visibility does not establish that restricted organization data is empty.

**Every open finding, its rule, analyzed line and Sonar link is in [inventory.md](docs/reports/sonar-2026-10-23/inventory.md).** The [JSON export](docs/reports/sonar-2026-10-23/inventory.json) and raw responses retain the evidence. Snapshot: main at 224c3fb; local edits below have not been analyzed.

### A. Security and critical correctness — first

- [x] **1 blocker: possible Vault token**, crates/sourceorrery-core/src/manifest.rs:660, rule secrets:S7273. Determine whether it is a real credential or synthetic test data. If real, revoke/replace it and remove the exposure. If synthetic, make the fixture unambiguously non-secret and record the evidence. Do not print credentials into logs or this checklist. *synthetic; fixture changed.*
- [x] **1 critical security finding: native-library extraction**, bindings/java/src/main/java/ai/sourceorrery/internal/Native.java:109, rule java:S5443. Review temporary-directory ownership/permissions, overwrite and symlink/race behavior, cleanup and library loading. Fix any actual weakness with a focused regression test; otherwise document why the existing behavior is safe. *fixed; 3 tests.*
- [x] **1 critical correctness finding: sorting**, site/scripts/sync-docs.mjs:191, rule javascript:S2871. Use the intended deterministic ordering/comparator and verify generated documentation remains stable. Do not introduce machine-locale-dependent output accidentally. *fixed; output byte-identical.*
- [x] **7 major security findings: .NET unsafe blocks**, rule csharpsquid:S6640. Review NativeLibraryLoader.cs (1), NativeMethods.cs (2), Project.cs (1), SecretReader.cs (2), and SecretValue.cs (1), under bindings/dotnet/SourceOrrery/. Check pointer lifetime, bounds, ownership, zeroing and error paths. Keep necessary FFI operations narrowly scoped; do not remove required interop merely to silence the rule. Every retained unsafe block needs a specific rationale. *1 removed, 6 retained with rationale; handle/value lifetime fixed.*

These four batches cover all **9 vulnerability-labelled findings** and the **1 bug**. Do not blanket-mark findings safe or lower the quality gate.

### B. Remaining maintainability and informational findings

- [x] **33 shell findings**, rule shelldre:S7688: 11 in scripts/coverage/native.sh, 22 in scripts/coverage/run.sh. Read the exact rule/messages in the inventory, apply the equivalent correction consistently, and verify quoting, whitespace-containing paths, exit behavior and fail-fast behavior. Run shell syntax/lint plus affected existing tests once for the batch.
- [x] **1 .NET example finding**, rule csharpsquid:S6966: asynchronous output in bindings/dotnet/examples/GetSecret/Program.cs:23. Correct it consistently with the async flow; build the example.
- [x] **1 disposal suggestion**, CA1513: SecretReader.cs:145.
- [x] **1 allocation suggestion**, CA1861: ReaderTests.cs:231.
- [x] **2 P/Invoke string-marshalling advisories**, CA2101: ReaderTests.cs:34,37. Specify encoding appropriate to the native functions; verify the helpers on supported platforms.
- [x] **2 interop-generation advisories**, SYSLIB1054: ReaderTests.cs:35,38. Evaluate target frameworks and native signatures before changing DllImport to LibraryImport; coordinate with the marshalling fixes.
- [x] **2 assertion advisories**, xUnit2032: ReaderTests.cs:137,165. Preserve assignability/exact-type semantics while updating assertions.

These batches account for the other **42 open findings**. Record an explicit disposition for each of the 52 issue IDs; a justified false positive is different from an unexamined suppression.

## C. Finish existing coverage work before trusting another percentage

| Hosted metric | Result |
| --- | --- |
| Overall coverage | 80.6% |
| Line / branch coverage | 81.4% / 60.8% |
| New-code coverage | **2.5%**, fails the **80%** requirement |
| New-code lines | 555 to cover, 541 uncovered; 539 of those uncovered lines are tooling, 2 are AWS-provider code |
| New-code maintainability severity metric | **15**, fails maximum **14**; this is not an issue count |
| New-code period | Previous version, starting 23 October 2026 at 11:58:14 BST |

Do not change the baseline, thresholds or source exclusions to manufacture a pass.

### Existing local work — review and finish, do not reimplement

- [x] Measure existing Python CI/release/coverage tests with scripts/coverage/tooling.sh and tooling.coveragerc; preserve execution from real report converters and validators. *53 tests; 87.52% lines.*
- [x] Measure existing Node helper tests and include their report.
- [x] Retain site unit-test and existing build/link-check execution in c8, preserving test data with --clean=false for the second run. Keep Bash and Windows entry points consistent. *Linux sdk.sh site: 965/1,033 lines (93.41%), build and links pass; run.ps1 not rerun (local Node too old).*
- [x] Finish module-scoped report settings in SourceOrrery.Analysis.Source.csproj; confirm non-C# reports are imported in their owning source module without losing coverage elsewhere.
- [x] Keep the full combined Rust LCOV artifact. Verify scripts/sonar/prepare-reports.py removes **only** files already classified as tests from the import copy and fails on unknown files/invalid lines. No production file may disappear.
- [x] Verify Java test analysis receives SDK main classes and JUnit dependencies. Check the absolute Maven dependency-output path and JaCoCo path. *configured; scan needed.*
- [x] Verify the final regenerated tooling XML is checked by check-reports.py, not just an earlier intermediate XML. *wired in run.sh; not run end to end.*
- [x] Investigate the two uncovered AWS-provider new lines; add a meaningful test if warranted. Do not change behavior just to satisfy line coverage. *lib.rs:392-393, defensive; no test.*
- [ ] Complete independent review, workflow lint and one full hosted coverage/import validation. Local percentages below are **not** the next Sonar result.

Already validated locally before work was paused:

- 62 Python tooling tests passed; report has 631/729 lines (86.56%) and 233/282 branches (82.62%).
- Two Node helper tests passed; tooling report has 21/28 lines (75%).
- Latest Windows site entry-point run passed 10 tests, built 41 pages, and checked 3,372 internal references; report has **971/1,030 lines (94.27%)**. An earlier warm-up showed 95.14%; use the latest artifact.
- Rust filtering retained 98/99 records, removing only already-classified test file crates/sourceorrery-cli/src/ui/fake.rs; three filter tests passed.
- MSBuild inspection showed five report settings on Source and none on Tests. Bash syntax and diff checks passed.
- **Not verified:** full final changed pipeline, final refreshed-XML stage, next Sonar import, final workflow lint, completed independent review, or clearance of remaining warnings.

Uncommitted implementation files to inspect:

~~~text
.github/workflows/coverage.yml
SonarQube.Analysis.xml
SourceOrrery.Analysis.Source.csproj
docs/coverage.md
scripts/coverage/run.ps1
scripts/coverage/run.sh
scripts/coverage/sdk.md
scripts/coverage/sdk.sh
scripts/coverage/tooling.coveragerc        (new)
scripts/coverage/tooling.sh                (new)
scripts/sonar/check-reports.py
scripts/sonar/prepare-reports.py            (new)
scripts/sonar/test_prepare_reports.py       (new)
~~~

### Replace Moto with LocalStack in GitHub Actions — requested 24 October

- [x] Replace the Moto service in the AWS-provider job in .github/workflows/ci.yml and in .github/workflows/coverage.yml with LocalStack started through **lstk** on Ubuntu runners.
- [x] Use the repository secret **LOCALSTACK_AUTH_TOKEN** (renamed by James on 24 October; it must be a LocalStack CI auth token). It is given only to the steps that run lstk, not the whole job:

~~~yaml
env:
  LOCALSTACK_AUTH_TOKEN: ${{ secrets.LOCALSTACK_AUTH_TOKEN }}
~~~

- [x] Install a pinned version of @localstack/lstk, optionally configure the runner profile with **lstk setup aws**, then run **lstk start**. Commit the pinned emulator image configuration in **.lstk/config.toml**; verify the current configuration syntax during implementation. *lstk 1.4.1 from scripts/ci/lstk's lock file; image 2026.10.0.*
- [x] Keep SOURCEORRERY_AWS_TEST_ENDPOINT pointed at the local emulator (currently http://127.0.0.1:4566), with test-only AWS credentials/region. Confirm Secrets Manager is available with the CI token's license. LocalStack belongs on Linux runners; leave Windows/macOS SDK testing independent of the emulator.
- [x] Use lstk's startup readiness check and remove the Moto-specific health polling. Keep the separate HashiCorp Vault service/readiness check. Forward any emulator options using LOCALSTACK_-prefixed variables or the committed configuration profiles.
- [x] Capture **lstk logs --verbose** with **if: always()** and upload the diagnostic log on failure. Start each test run with fresh disposable state so lifecycle tests remain independent; persistent snapshots/Cloud Pods are unnecessary for this migration.
- [x] Verify the existing AWS lifecycle, remote CLI/SDK conformance and coverage tests against LocalStack, including stable version timestamps, deletion/recovery/purge and the external seven-day recovery-window regression. Preserve the corrected production AWS deletion metadata behavior. *locally; LocalStack refuses ListSecretVersionIds for deleted secrets, see dispositions.md.*
- [x] Once those checks pass, remove the Moto timestamp workaround, its fixture/tests and workflow invocations; update related Sonar test-inventory references and coverage/provider documentation. Do not keep emulator-specific patches in the production provider.
- [x] Define explicit behavior when the CI token is unavailable, including fork pull requests. Report any skipped emulator tests clearly and keep untrusted fork code away from repository secrets.
- [ ] Include this migration in the same reviewed CI/coverage batch above, with focused validation first, rather than starting a separate series of release builds.

## D. Remaining analysis/build warnings

The successful scan has **33 warning occurrences / 29 distinct messages**, fully listed in the inventory. Distinguish actionable configuration problems from expected test-file notices.

- [x] Confirm Go and Rust reports no longer generate misleading “not in project” / LCOV warnings from being applied to unrelated modules. *configured; scan needed.*
- [x] Confirm JaCoCo uses the correct path in its owning module.
- [ ] Resolve Java unresolved imports/types. Investigate the preview-feature/source-level warning against actual Java source, compiled classes and analyzer support; do not guess a version or downgrade the SDK.
- [x] Determine whether sonar.modules deprecation is generated by the .NET scanner. Do not edit generated files or discard required language analysis to hide an upstream warning. *upstream scanner.*
- [x] Record expected “duplication ignored because test file” notices separately from defects.
- [x] Review INFO-level npm EBADPLATFORM output for the intentionally separate platform packages; confirm it does not hide a failed host-package install.
- [x] Resolve or explicitly account for the site's empty/missing i18n collection and “docs → 404” warnings. Preserve the established theme, local assets and no tracking. *accounted for.*
- [ ] After one fresh scan, compare issue IDs and warning categories with this snapshot. Confirm the original Python/test/TypeScript warnings have not returned.

## E. Finish publishing setup without another bootstrap release

- [ ] **Configure Trusted Publishing for the three now-existing crates:** sourceorrery-provider, sourceorrery-provider-aws, sourceorrery-provider-vault. Each needs owner Netizine, repository sourceorrery, workflow release.yml, empty environment; add ReleasePackages.yaml for recovery publishing too. See [release instructions](docs/release.md).
- [ ] After configurations are complete, revoke the temporary crates.io bootstrap token and remove CRATES_BOOTSTRAP_TOKEN. Keep the ordinary release's bootstrap_providers option off. **Enabling Trusted Publishing does not require another version.**
- [x] Correct **PACKAGING_TOKEN** permissions — completed by the account holder on **24 October 2026**. The existing fine-grained token selects Netizine/homebrew-sourceorrery and Netizine/scoop-sourceorrery, with **Contents: read and write** and **Metadata: read-only**. Pull-request access was removed. Token expiry: **20 January 2027**; renew before then.
- [ ] Verify Homebrew/Scoop automation with the corrected **PACKAGING_TOKEN** during the next controlled publishing run. The permissions are saved, but no workflow has tested the change yet. The 0.2.0 files are already published; do not rebuild packages or duplicate commits just to verify credentials.
- [ ] Repair **WINGET_TOKEN** using documented compatible token/scopes. Failure: “Resource not accessible by personal access token.” Never copy a broad local CLI credential into an Actions secret as a shortcut.
- [x] Review existing [WinGet PR #460455](https://github.com/microsoft/winget-pkgs/pull/460455), not a duplicate submission. Snapshot: validation steps 1–7 passed; installation validation running, later checks queued, CLA pending. *24 Oct: Validation-Executable-Error label; maintainer review.*
- [x] The account holder must personally review/accept Microsoft's CLA; the agent must not make that legal declaration. Then check remaining validation and maintainer feedback. External catalog approval is separate from binary quality. *Agreed by James on the PR, 24 Oct 01:51 UTC; license/cla passes.*
- [ ] Push existing documentation commit c95d0b4 with the final reviewed batch. It updates release/source-build wording and WinGet schema 1.12. Change pending-WinGet wording only after actual catalog merge/indexing.

## F. One controlled verification and release decision

- [x] Finish chosen code/reporting batches locally and run only their relevant tests first.
- [x] Review the complete diff once. Do not stage unrelated artwork: SourceOrrerySecureArchitecture.png, SourceOrrerySecureArchitecture.svg, sourceorrery-fontawesome.svg.
- [ ] Push one reviewed candidate; allow normal CI, docs deployment and all-language coverage to run. Diagnose by failing step rather than repeatedly rerunning every job.
- [ ] Confirm the unchanged Sonar quality gate actually passes on that exact commit, coverage imports are credible, and outstanding security/reliability findings have verified fixes or documented finding-specific rationales.
- [ ] Check runtime/security/compatibility tests relevant to changed code. Preserve SemVer, ABI and contract gates.
- [ ] If only docs/analysis configuration changed, keep published 0.2.0 artifacts; do not manufacture a new release.
- [ ] If shipped implementation changed, use a new immutable version. A compatible fix would normally be **0.2.1**; breaking changes need the version required by the compatibility gate. This is a real code-fix release, not a Trusted Publishing workaround. Never overwrite v0.2.0.
- [ ] For an actual new release: one full dry run, then publish the **same reviewed commit** once. Recover individual registry failures for that same version, without rebuilding unrelated artifacts.
- [ ] Verify public versions, hashes/provenance/signatures and a small set of real package smoke tests. Record the commit, run links and external approvals still pending.

**Go/no-go:** no known unaddressed release-blocking defect; credible coverage and a passing unchanged quality gate; required CI and compatibility checks passing; reviewed source matches published artifacts; remaining account/external tasks recorded. Successful upload alone is not the acceptance criterion.

## Preserve these limits and deferred work

- Desktop OS-keyring checks on macOS and Linux remain outstanding from the old todo. Reuse scripts/dev/keyring-smoke.sh and record evidence in the threat model when environments are available. Headless CI is not a desktop-session test.
- Authenticode signing and macOS signing/notarization were deliberately deferred because of cost. Do not purchase certificates or expand tomorrow into signing infrastructure.
- Independent security audit / “enterprise-ready” claims remain incomplete. The [engineering review](docs/security-review.md) is evidence, not an independent audit; retain development-credentials guidance.
- Broker architecture, new SDK languages, platforms and other roadmap features are outside this quality/release pass.
- No documentation theme redesign, remote fonts/icons, analytics or automatic update checking.
- Do not claim every scanner finding is a real defect or that a clean scan proves security. Preserve evidence and limits.

## Resume locations

- Checkout: C:\dev\sourceorrery, branch main.
- Local HEAD: c95d0b4, one unpushed documentation/WinGet commit.
- Remote main / last analyzed commit: 224c3fb614908afab1c9e9681f4bd7492683cee1.
- Published 0.2.0 tag: 956c05a6eb287db1f655f8440664c5150ba92570.
- [Full inventory and validation notes](docs/reports/sonar-2026-10-23/inventory.md).
- Downloaded reports: coverage/ci-40008371065/.
- Scanner log: coverage/github-40008371065.log.
- Release verification: coverage/release-verification/0.2.0/.
- Local reports and tool environments already exist under coverage/; reuse them where valid.
- Instructions: site/AGENTS.md. Release policy: [ADR 0007](docs/adr/0007-versioning-and-compatibility.md).

This is a handoff for tomorrow, not an instruction to keep working tonight or a scheduled autonomous run.
