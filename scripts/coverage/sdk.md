# SDK and documentation tooling coverage

For the normal local workflow, use `bash scripts/coverage/run.sh --check` and
`bash scripts/coverage/run.sh` on Ubuntu. On Windows, use
`pwsh scripts/coverage/run.ps1 -Target site` or `-Target dotnet` for one report.
See [the coverage guide](../../docs/coverage.md) for prerequisites and GitHub's
automatic reports. These local entry points do not upload or need a Sonar token.

These helpers collect coverage from the existing tests. Run them from the
repository root on Ubuntu after creating the shared SDK fixture with
`.github/actions/sdk-fixture` (or `scripts/ci/fixture-vault.sh`). The SDK modes
fail if its environment variables are absent, because the tests would otherwise
skip their vault checks. They do not build extensions or install dependencies.

## Prerequisites

- Python 3.11 or newer, as declared in `bindings/python/pyproject.toml`; CI uses
  3.12. Install the hash-locked `scripts/coverage/requirements.txt` in that
  interpreter; it shares the SDK CI's pytest pin.
- Node 22.19 or newer for the documentation site's dependencies. Install the
  pinned public coverage tool with
  `npm ci --prefix scripts/coverage --global=false --ignore-scripts`.
  Separately install the Node SDK and site dependencies. Site installation needs
  the existing Font Awesome registry token; this coverage package does not.
- Go 1.24 or newer, a C compiler, and the built SourceOrrery C ABI library.
- PHP 8.2 or newer with FFI and Xdebug. No PHPUnit or Composer dependencies are
  required by the existing PHP runner.

`SOURCEORRERY_COVERAGE_PYTHON` can select a Python executable. The helper preserves
`PYTHONPATH` and native coverage variables such as `RUSTFLAGS` and
`LLVM_PROFILE_FILE`.

## Collect reports

Run `native.sh python` and `native.sh node` to build the native extensions with
Rust instrumentation and collect their wrapper coverage in the same test runs:

```sh
bash scripts/coverage/native.sh python
bash scripts/coverage/native.sh node
bash scripts/coverage/sdk.sh site
bash scripts/coverage/sdk.sh go
bash scripts/coverage/sdk.sh php
```

If native extensions have already been prepared, `sdk.sh python` and `sdk.sh node`
can run independently. Python must import the checked-in package under
`bindings/python/python/sourceorrery`, with its compiled extension available;
an ordinary wheel installation would measure a different source tree.

| Report | Format | Sonar property |
| --- | --- | --- |
| `coverage/python.xml` | Cobertura | `sonar.python.coverage.reportPaths` |
| `coverage/node/lcov.info` | LCOV | `sonar.javascript.lcov.reportPaths` |
| `coverage/site/lcov.info` | LCOV | `sonar.javascript.lcov.reportPaths` |
| `coverage/go.out` | Go coverprofile | `sonar.go.coverage.reportPaths` |
| `coverage/php.xml` | Sonar generic coverage XML | `sonar.coverageReportPaths` |

Pass both JavaScript reports as a comma-separated list. Add the PHP report to
any other generic coverage reports, such as C++. It is not Clover and must not
be assigned to `sonar.php.coverage.reportPaths`.

Python uses a repository-relative Cobertura source directory. JavaScript LCOV
paths, normalized Go filenames, and PHP XML paths resolve from the repository
root. The separate Rust reports cover the PyO3 and N-API implementations;
JavaScript and Python reports cover their checked-in wrapper code.

## Scope and validation

The site report measures the production modules in `site/plugins`, `site/src/lib`,
and `site/scripts` exercised by the Node tests. It includes unexecuted modules as
uncovered. It does not measure Astro component rendering or browser interaction.
Node SDK coverage measures `bindings/node/lib`, excluding the generated native
loader. Go measures the SDK package, excluding examples and conformance programs.

PHP starts Xdebug before the existing runner loads the SDK, filters to SDK source,
and converts its line data without replacing the runner or masking its exit
status. Executable but unvisited lines are uncovered; non-executable lines are
omitted. The report does not claim branch coverage. Entirely unloaded files are
left to Sonar's source analysis to count as uncovered.

Validate the PHP converter independently of PHP or a vault fixture:

```sh
python -m unittest discover -s scripts/coverage -p 'test_*.py' -v
bash -n scripts/coverage/sdk.sh
```

References: [coverage.py XML configuration](https://coverage.readthedocs.io/en/latest/config.html),
[c8](https://github.com/bcoe/c8),
[Xdebug coverage](https://xdebug.org/docs/code_coverage), and
[Sonar generic coverage](https://docs.sonarsource.com/sonarqube-cloud/analyzing-source-code/test-coverage/generic-test-data).
