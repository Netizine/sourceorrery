# Cross-language SDK conformance harness

One scenario list, ten SDKs, one judge. `scenarios.json` is the contract
every SDK must honour against the fixture vault that
`scripts/ci/fixture-vault.sh` creates; `harness.py` drives one SDK's
*runner* through every scenario and compares what it observed with the
scenario's expectations. The per-language test suites keep covering what
is specific to a language (redaction, disposal, threading); the harness
covers what must be identical everywhere: unlock order, policy outcomes,
values, metadata, error codes, messages and hints.

```bash
cargo build --release -p sourceorrery-cli -p sourceorrery-ffi
eval "$(bash scripts/ci/fixture-vault.sh)"
cargo build --release -p sourceorrery --example conformance
python tests/conformance/sdk/harness.py --runner rust
python tests/conformance/sdk/harness.py --runner python      # after maturin develop
python tests/conformance/sdk/harness.py --list
```

## Runner protocol

A runner is a program invoked once per scenario:

```
<runner> <op> [key=value ...]
```

| `op` | keys | observes |
|------|------|----------|
| `open` | open options | `descriptor.name`, `descriptor.protectors` (comma-joined) |
| `get` | `name`, optional `version` | `value`, properties |
| `get-newest-explicit` | `name` | reads `properties(name).version`, then `get(name, that version)`; `value`, properties |
| `properties` | `name`, optional `version` | properties |
| `resolve` | `reference` | `value`, properties |
| `load` | `manifest` | `project.name`, `project.count`, `project.names` (sorted, comma-joined), `secret.<ENV>` per resolved entry |

Open options, accepted by every op: `vault` (default `SOURCEORRERY_TEST_VAULT`),
`home`, `passphrase`, `passphrase_file`, `environment` (`false` ignores the
`SOURCEORRERY_PASSPHRASE*` variables; default true).

The runner prints `key<TAB>value` lines on stdout, nothing else:

* success: `outcome	ok`, then the observations above. Properties are
  `version`, `enabled` (`true`/`false`), `content_type` (empty when none),
  `reference` and one `tag.<key>` per tag.
* failure: `outcome	error`, `code`, `message` (without the hint), `hint`,
  `transient` (`true`/`false`) and `type` (the language's error type name,
  informational).

Runners over the raw C ABI may instead print the core's JSON and let the
harness derive the fields: `properties_json`, `descriptor_json`, and for
`load` `project_info_json` plus `entry.<i>.json` / `entry.<i>.value`.

Values in these lines are the fixture's test data, read by the harness
only; no runner is a tool for people.

## Runners

| SDK | Runner | Build first |
|-----|--------|-------------|
| Rust | `crates/sourceorrery/examples/conformance.rs` | `cargo build --release -p sourceorrery --example conformance` |
| Python | `bindings/python/conformance/run.py` | `maturin develop` (or `pip install bindings/python`) |
| JavaScript | `bindings/node/conformance/run.mjs` | `npm run build` in `bindings/node` |
| Java | `bindings/java/conformance/Run.java` (source-file mode on `target/classes`) | `mvn compile` in `bindings/java` |
| .NET | `bindings/dotnet/conformance/` | `dotnet build bindings/dotnet/conformance -c Release` |
| Go | `bindings/go/conformance/` | `go build -o conformance-go ./conformance` in `bindings/go` with `CGO_LDFLAGS` |
| C | `crates/sourceorrery-ffi/examples/conformance.c` | compile like `examples/get_secret.c` |
| C++ | `bindings/cpp/conformance/run.cpp` | compile like `bindings/cpp/tests/reader_test.cpp` |
| PHP | `bindings/php/conformance/run.php` | nothing |

`harness.py --runner <name>` knows a default command for each; pass
`--command "..."` when the binary lives elsewhere (CI does, for the compiled
ones).

## Expectations

`expect` in a scenario may hold: `outcome`; `code`; `message`;
`message_excludes`; `hint_contains`, `hint_excludes`, `hint_starts_with`;
`transient`; `value`; `version` (a string, or `{"not": "..."}`); `enabled`;
`content_type`; `tags` (subset); `reference`; `descriptor.name`;
`descriptor.protectors_contains`; `project.name`; `project.count`;
`project.secrets` (`ENV: value`); `project.absent` (names that must not have
resolved). `${vault}`, `${home}`, `${passphrase}`, `${manifest}`,
`${old_version}` are substituted from the fixture environment and
`${version}` from the observation.

## Adding a scenario

Add it to `scenarios.json` with an `about` line, run every runner you have
locally, and let CI run the rest: each `sdk-*` job runs the harness after
the language's own suite. A behaviour that needs a new runner `op` is a
change to every runner, which is deliberate: the ops are the SDK surface.

## Remote vaults

Scenarios with `"requires": "remote"` read a vault that a manifest declares
in `[vaults.<name>]`, through the `manifest` open option, and run only
with `--remote`, when `SOURCEORRERY_TEST_REMOTE_VAULT` and
`SOURCEORRERY_TEST_REMOTE_MANIFEST` name that vault and manifest. The
provider CI jobs (`provider-vault`) set them up with the CLI and run the
Rust and C runners; a runner takes part by passing a `manifest=` argument
through to its SDK's open options. A scenario with `"requires":
"remote-per-version"` also needs the provider to keep properties per
version (HashiCorp Vault does, AWS Secrets Manager does not) and runs
only with `--remote-per-version` as well.

