# Test coverage and SonarCloud

SourceOrrery 0.2.0 generates coverage with each language's test tools and
imports the reports into the existing
[SonarCloud project](https://sonarcloud.io/project/overview?id=Netizine_sourceorrery).
The `Coverage and SonarCloud` workflow runs on Ubuntu, alongside the normal
cross-platform CI. It uses the same disposable SDK vault and existing tests.

**GitHub generates the reports for you.** After a push to `main` or a trusted
pull request, open **Actions → Coverage and SonarCloud**. A successful run
uploads the combined analysis to SonarCloud using the repository's
`SONAR_TOKEN` secret and keeps a downloadable **coverage-reports** artifact.
Local coverage is optional; adding the secret does not require running a
scanner or installing every language toolchain on your computer.

The artifact contains XML, LCOV and Go coverage data for analysis tools.
Use the SonarCloud project's **Measures → Coverage** view for the combined
results, or the workflow logs for individual test and coverage summaries.

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
workspace version from `Cargo.toml`. No project variables are
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
| Rust core, CLI, providers, Rust SDK and C ABI | `cargo-llvm-cov`; workspace tests, C smoke test and Rust/C/C++ conformance | `coverage/rust-combined.lcov` |
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
from the three native builds, and from the Azure provider's own run, are
merged with `lcov`, retaining execution of shared Rust dependencies from all
runtimes.

Workspace membership determines which Rust crates run, including the provider
crates. CI starts disposable HashiCorp Vault and LocalStack services for their
endpoint-dependent lifecycle tests. LocalStack for Azure and for AWS bind the
same ports, so the coverage job starts Azure first, collects
`bash scripts/coverage/native.sh azure` into `coverage/rust-azure.lcov`,
stops it, and then starts AWS for the rest. These tests use synthetic data and emulator
credentials, with no production cloud account. The normal CI also runs remote
CLI/SDK conformance and Vault federation checks; those separate jobs do not
currently contribute their execution to the coverage report.

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

The Node SDK's own typecheck uses its TypeScript 7 dependency. SonarCloud
currently documents support through
[TypeScript 6.0.3](https://docs.sonarsource.com/sonarqube-cloud/analyzing-source-code/languages/javascript-typescript-css/).
The maintained configurations use compatible options, but newer TypeScript
features may receive incomplete semantic analysis. JavaScript execution coverage
still comes from the independent c8 reports; the project compiler is retained.

Java analysis receives its compiled classes, test dependencies and JDK.
C/C++ analysis receives `coverage/compile_commands.json`, generated from
the actual SDK driver compilations. All reports and analysis run in the
same checkout so absolute compiler and coverage paths remain valid.

## Generate reports locally

Local commands collect reports without uploading anything and do not need
`SONAR_TOKEN`. The scripts check prerequisites before running tests and do not
install global tools.

### Windows: run one report

For the documentation tooling, install Node 24 (minimum 22.19), then use
PowerShell from the repository root:

```powershell
npm ci --ignore-scripts --prefix scripts/coverage
# If site dependencies are not already installed:
npm ci --ignore-scripts --prefix site
pwsh scripts/coverage/run.ps1 -Target site -Check
pwsh scripts/coverage/run.ps1 -Target site
```

This runs the site's existing Node tests and writes
`coverage/site/lcov.info`. Installing site dependencies requires the existing
Font Awesome npm authentication configuration; collecting an installed site's
coverage does not contact that service.

For the .NET SDK, install the .NET 10 SDK, Rust and Git for Windows, then run:

```powershell
pwsh scripts/coverage/run.ps1 -Target dotnet -Check
pwsh scripts/coverage/run.ps1 -Target dotnet
```

The .NET command builds the CLI and C ABI, creates a new test vault under
`coverage/`, runs the SDK tests, and writes `coverage/dotnet.xml`. It restores
the calling process's environment afterwards. A single-language report is
useful for local changes; GitHub produces the combined project report.

### Ubuntu: run all reports

The full run needs Ubuntu/Linux because native C++ coverage uses GCC and gcov.
Use Rust with the workspace's declared minimum version, Node 24, Python 3.12,
Go 1.24+, JDK 25+, Maven, the .NET 10 SDK, and PHP 8.2+ with FFI and Xdebug.
The pinned setup in `.github/workflows/coverage.yml` is the reference.

On Ubuntu 24.04, after installing those language toolchains, prepare the
coverage dependencies once:

```bash
sudo apt-get install build-essential pkg-config libdbus-1-dev lcov python3-venv
python3 -m venv coverage/venv
. coverage/venv/bin/activate
python -m pip install --require-hashes --only-binary :all: -r scripts/coverage/requirements.txt
rustup component add llvm-tools-preview
cargo install --locked cargo-llvm-cov --version 0.9.1
npm ci --ignore-scripts --prefix bindings/node
npm ci --ignore-scripts --prefix scripts/coverage
npm ci --ignore-scripts --prefix site
```

Then one entry point generates the reports:

```bash
bash scripts/coverage/run.sh --check
bash scripts/coverage/run.sh
```

The runner creates a fresh test vault, measures all workspace crates and SDKs,
measures the existing CI/release/coverage tooling tests, merges the Rust reports,
and verifies every expected report. Generated files
stay in ignored build, dependency and coverage directories. Existing test vaults
and real secrets are not used.

The provider server tests run when `SOURCEORRERY_VAULT_TEST_ADDR` and
`SOURCEORRERY_AWS_TEST_ENDPOINT` point to disposable Vault and LocalStack instances,
with their corresponding test credentials. Use the Vault service image, the
LocalStack start (`scripts/ci/localstack.sh`, `.lstk/config.toml`) and the
environment in the coverage workflow as the reference. The Azure provider's
live coverage comes from `bash scripts/coverage/native.sh azure` with
LocalStack for Azure running (`scripts/ci/localstack.sh start azure`,
`.lstk/azure.toml`), before the AWS emulator starts. Without these endpoints, the local
runner explicitly reports that those provider paths remain uncovered; ordinary
workspace tests still run. Never point these lifecycle tests at production services.

From Windows, an **already installed and configured** Ubuntu WSL distribution
can run the same commands:

```powershell
pwsh scripts/coverage/run.ps1 -Target all -Distribution Ubuntu -Check
pwsh scripts/coverage/run.ps1 -Target all -Distribution Ubuntu
```

Install the prerequisites and dependencies inside that Linux environment first.
Its `node_modules` must contain Linux packages; a Windows dependency installation
cannot be reused reliably. The wrapper does not install WSL or start Docker.

CI calls the same runner's `collect`, `dotnet`, and `verify` stages, with the
scanner's **begin → build → test → end** order around the .NET stage. Keep uploads
in that workflow: a second independent scan would replace the project's analysis
rather than combine languages.

Missing fixtures fail the coverage scripts instead of silently skipping
the SDK suites. `check-reports.py` rejects missing reports and reports with
no executed production lines. `check-scope.py` validates the evaluated
MSBuild file inventory, checks representative files from every language
and rejects overlapping source/test or dependency/generated-file entries.

When adding a language or moving tests, update its report generation,
`SonarQube.Analysis.xml`, the source/test patterns in
`scripts/sonar/Analysis.props`, the module-specific report paths in
`SourceOrrery.Analysis.Source.csproj`, and those inventory checks together. Use
Sonar's [coverage parameter reference](https://docs.sonarsource.com/sonarqube-cloud/analyzing-source-code/test-coverage/test-coverage-parameters)
to select the importer: generic coverage XML, Cobertura, JaCoCo and
OpenCover are different formats.

The complete Rust report remains available as `coverage/rust-combined.lcov`.
The scanner imports `coverage/rust-production.lcov`, which preserves its counts
for files classified as production by the existing MSBuild inventory. Test-only
records are left out of that import copy; tests remain included in static analysis.
Reports are assigned to the module that owns those source files, avoiding duplicate
imports into the separate test and .NET modules.

Tooling reports are `coverage/tooling-python.xml` and
`coverage/tooling-node/lcov.info`. Their source scope includes unexecuted tools,
so a passing test run does not mean full coverage. The Windows PowerShell runner
is not instrumented by the Ubuntu job. Sonar's quality gate evaluates coverage of
new code separately from overall coverage and can fail even when report generation
and upload succeed.
