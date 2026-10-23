# Test coverage and SonarCloud

SourceOrrery 0.1.4 generates coverage with each language's test tools and
imports the reports into the existing
[SonarCloud project](https://sonarcloud.io/project/overview?id=Netizine_sourceorrery).
The `Coverage and SonarCloud` workflow runs on Ubuntu, alongside the normal
cross-platform CI. It uses the same disposable SDK vault and existing tests.

## Enable CI analysis

[SonarCloud coverage requires CI-based analysis](https://docs.sonarsource.com/sonarqube-cloud/analyzing-source-code/test-coverage/overview).
Automatic Analysis cannot import these reports.

1. In the SonarCloud project, open **Administration → Analysis Method** and
   turn off **Automatic Analysis** before the first CI scan.
2. Create a Sonar token authorized to analyze this project. In the GitHub
   repository, open **Settings → Secrets and variables → Actions** and add
   it as the repository secret **`SONAR_TOKEN`**. Keep it out of source,
   workflow YAML and command history.
3. Keep the existing **`FONTAWESOME_NPM_AUTH_TOKEN`** repository secret: the
   site needs it to install its local icon package before analysis.
4. Once these changes are pushed, run **Coverage and SonarCloud** from
   GitHub Actions, or let a push to `main` / a same-repository pull request
   trigger it. `workflow_dispatch` becomes available once the workflow is
   present on the default branch.

The project key is **`Netizine_sourceorrery`**, the organization key is
**`netizine-3`**, and the server is **`https://sonarcloud.io`** (EU). These
public identifiers are in `scripts/sonar/scan.sh`; the scanner reads the
workspace version (`0.1.4`) from `Cargo.toml`. No project variables are
required. Without `SONAR_TOKEN`, the
workflow still generates coverage artifacts and explicitly warns that no
Sonar analysis was uploaded.

Fork pull requests do not receive the private package or Sonar secrets, so
this workflow skips them. The normal CI remains separate; coverage runs
after a trusted merge. Do not use `pull_request_target` to execute a fork's
code with repository secrets.

## What each report measures

All paths below are relative to the checkout root. The artifact named
`coverage-reports` retains the reports for 14 days.

| Implementation | Measurement | Report imported by Sonar |
|---|---|---|
| Rust core, CLI, Rust SDK and C ABI | `cargo-llvm-cov`; workspace tests, C smoke test and Rust/C/C++ conformance | `coverage/rust-combined.lcov` |
| Python native extension | Instrumented PyO3 build, exercised by Python tests | Merged into `coverage/rust-combined.lcov` |
| Node native extension | Instrumented N-API build, exercised by Node tests | Merged into `coverage/rust-combined.lcov` |
| Python API | coverage.py, branch coverage enabled | `coverage/python.xml` (Cobertura) |
| JavaScript API used by JS/TS callers | c8 / V8 | `coverage/node/lcov.info` |
| Documentation JavaScript tooling | c8 / V8, existing Node tests | `coverage/site/lcov.info` |
| Java | JaCoCo, opt-in Maven `coverage` profile | `bindings/java/target/site/jacoco/jacoco.xml` |
| .NET | Coverlet with the existing VSTest runner | `coverage/dotnet.xml` (OpenCover) |
| Go | `go test -coverprofile` with cgo enabled | `coverage/go.out` |
| C++ header implementation | GCC coverage, converted by gcovr | `coverage/cpp.xml` (Sonar generic XML) |
| PHP | Xdebug with the existing test runner | `coverage/php.xml` (Sonar generic XML) |

C's public header contains declarations; its executable implementation is
Rust and is measured there. TypeScript declarations also have no executable
lines; TypeScript callers use the measured JavaScript wrapper. Rust reports
from the three native builds are merged with `lcov`, retaining execution
of shared Rust dependencies from all three runtimes.

Coverage measures exercised code, not correctness or security. Stable Rust
executes doctests without collecting their coverage; Rust coverage of
externally invoked `no_mangle` entry points also has upstream limitations.
The site tests exercise JavaScript tooling, not browser interactions or
Astro component rendering. The Ubuntu report does not measure Windows or
macOS credential-store branches. Those limitations are not hidden by
blanket source exclusions or invented coverage percentages.

## Why the three analysis warnings are addressed

**Python version.** `SonarQube.Analysis.xml` sets
`sonar.python.version=3.11,3.12,3.13,3.14`, matching the SDK's Python 3.11+
minimum and the analyzer's currently supported versions. The coverage job
runs Python 3.12; that does not change the package's compatibility promise.

**Test classification.** This repository includes C#, so one
[SonarScanner for .NET](https://docs.sonarsource.com/sonarqube-cloud/analyzing-source-code/scanners/sonarscanner-for-dotnet/using)
run handles the whole project. That scanner does **not** accept manually
setting `sonar.sources` or `sonar.tests`: it derives them from MSBuild.
`SourceOrrery.Analysis.Source.csproj` and
`SourceOrrery.Analysis.Tests.csproj` explicitly classify non-C# files as
production/tooling or tests. C# keeps its real library, example, test and
conformance projects. Test directories, Python fixtures and harnesses,
Go `_test.go`, Rust test modules and Node `.test.mjs` files are classified
as tests. Inline Rust test modules remain in their production source file.

The two analysis projects intentionally live at the repository root.
Moving them into `scripts/` would cause the scanner to move outside files
into its root source list, losing test classification. Their build output
goes under ignored `build/sonar/`. `scanAll=false` prevents automatic
discovery from adding a second set of files; explicit `Content` items also
include Rust, Java and C/C++, as supported by the
[scanner's multi-language configuration](https://docs.sonarsource.com/sonarqube-cloud/analyzing-source-code/scanners/sonarscanner-for-dotnet/configuring).

**TypeScript configuration.** The workflow runs `npm ci` in both
`bindings/node` and `site`, builds the native Node loader and runs Astro
content/type generation. `sonar.typescript.tsconfigPaths` explicitly lists
the two maintained configurations. Astro's `astro/tsconfigs/strict` base
therefore exists when analysis starts. Dependencies and generated files
are excluded from source indexing, rather than removing the valid
`extends` setting to silence the warning.

Java analysis receives its compiled classes, test dependencies and JDK.
C/C++ analysis receives `coverage/compile_commands.json`, generated from
the actual SDK driver compilations. All reports and analysis run in the
same checkout so absolute compiler and coverage paths remain valid.

## Generate reports locally

The complete workflow in `.github/workflows/coverage.yml` is the reference
for tool versions and setup. The native coverage script requires Linux:
use Ubuntu or a suitable Linux development environment for the full run.
Java and .NET's opt-in coverage commands can also run on their other
supported platforms.

After installing the toolchains and coverage dependencies shown in that
workflow, use a fresh SDK fixture as described in
[Building from source](building.md#the-sdk-test-vault). Keep those exported
fixture variables in the same shell. Do not use a personal vault.

```bash
# Before tests: install each project's dependencies and generate Astro types.
npm ci --prefix bindings/node
npm ci --prefix scripts/coverage
npm ci --prefix site
npm run sync --prefix site
npm run astro --prefix site -- sync

# These also measure the Rust extensions; do not repeat sdk.sh python/node.
bash scripts/coverage/native.sh
bash scripts/coverage/native.sh python
bash scripts/coverage/native.sh node
lcov --add-tracefile coverage/rust.lcov \
  --add-tracefile coverage/rust-python.lcov \
  --add-tracefile coverage/rust-node.lcov \
  --output-file coverage/rust-combined.lcov

bash scripts/coverage/sdk.sh site
bash scripts/coverage/sdk.sh go
bash scripts/coverage/sdk.sh php
mvn --batch-mode -f bindings/java/pom.xml -Pcoverage clean verify
dotnet test bindings/dotnet/SourceOrrery.Tests/SourceOrrery.Tests.csproj \
  -c Release -p:CollectCoverage=true

python scripts/sonar/check-reports.py
python scripts/sonar/check-scope.py
```

For a Sonar upload, use the workflow's additional Java dependency-copy and
`.NET begin → build → test → end` steps. The scanner must start **before**
the .NET build; importing reports with a second independent scan would
replace the project's analysis rather than combine languages.

Missing fixtures fail the coverage scripts instead of silently skipping
the SDK suites. `check-reports.py` rejects missing reports and reports with
no executed production lines. `check-scope.py` validates the evaluated
MSBuild file inventory, checks representative files from every language
and rejects overlapping source/test or dependency/generated-file entries.

When adding a language or moving tests, update its report generation,
`SonarQube.Analysis.xml`, the source/test patterns in
`scripts/sonar/Analysis.props`, and those inventory checks together. Use
Sonar's [coverage parameter reference](https://docs.sonarsource.com/sonarqube-cloud/analyzing-source-code/test-coverage/test-coverage-parameters)
to select the importer: generic coverage XML, Cobertura, JaCoCo and
OpenCover are different formats.
