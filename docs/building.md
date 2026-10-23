# Building from source

Everything SourceOrrery ships, the CLI, the C ABI and the ten SDKs, builds
from one repository. Build it yourself to try a change that is not
released, to run on a platform the release does not cover, or to check
that what you run is what the source says. This page covers what to
install, how to get the code, and how to build and test each part; every
[SDK page](sdks/index.md) ends with the steps for its own language.

## What you need

Every build compiles Rust, so every build needs:

| Tool | Version | Why |
|------|---------|-----|
| Git | any recent | to clone the repository |
| Rust, installed with rustup | 1.88 or newer | the core. `rust-toolchain.toml` selects the stable channel with `rustfmt` and `clippy`; rustup installs it on the first `cargo` command in the checkout |
| A C compiler | | the bundled SQLite is compiled from C: the Visual Studio Build Tools on Windows, the Xcode Command Line Tools on macOS, gcc or clang on Linux |
| `pkg-config` and the D-Bus headers | Linux only | the Secret Service (the OS credential store); not needed for a build with `--no-default-features` |
| Bash | | the script that creates the test vault: Git Bash on Windows |

<!-- tabs: os -->

#### Windows

```powershell
winget install --id Git.Git -e                  # Git and Git Bash
winget install --id Rustlang.Rustup -e
winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
```

The last line installs the MSVC compiler and the Windows SDK (the
*Desktop development with C++* workload), which Rust's default Windows
toolchain links with. Open a new terminal afterwards so that `cargo` is on
`PATH`.

#### macOS

```bash
xcode-select --install                                           # the C compiler and Git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # Rust
```

#### Linux

Debian and Ubuntu:

```bash
sudo apt-get install -y git curl build-essential pkg-config libdbus-1-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Fedora: `sudo dnf install -y git gcc pkgconf-pkg-config dbus-devel`, then
the same rustup line.

<!-- /tabs -->

Each SDK needs its own toolchain on top:

| SDK | Also needs |
|-----|------------|
| Python | Python 3.11 or newer, with `pip` and `venv` |
| JavaScript / TypeScript | Node.js 20 or newer, with npm |
| Rust | nothing more |
| Java | a JDK, 22 or newer (CI uses Temurin 25), and Maven |
| .NET | the .NET 8 SDK or newer for the library; the .NET 10 SDK for its tests and example, which target `net10.0` |
| Go | Go 1.24 or newer and a C compiler for cgo: gcc or clang, or MinGW-w64 gcc on Windows |
| C | the C compiler above |
| C++ | a C++17 compiler; CMake 3.16 or newer for the example and the test |
| PHP | PHP 8.2 or newer with the `ffi` extension, and Composer |
| Conformance harness | Python 3, whichever SDK it drives |

## Get the code

```bash
git clone https://github.com/Netizine/sourceorrery
cd sourceorrery
git checkout v0.1.4          # the release; stay on main for the newest changes
```

A build from source carries the version committed in the repository, not
the release number: the release workflow stamps that into every manifest
as it builds. To give your build the release's version, stamp it the same
way before building:

```bash
python scripts/release/set-version.py 0.1.4
```

It edits the manifests in your checkout (`git checkout .` undoes it). For
the Node package, run `npm ci` in `bindings/node` before stamping, as the
release does: stamping replaces the package's local links to its platform
packages with that version.

## The CLI and the C ABI

```bash
cargo build --release -p sourceorrery-cli -p sourceorrery-ffi
```

The first build downloads and compiles every dependency and takes a few
minutes. What lands in `target/release/`:

| File | What it is |
|------|------------|
| `sourceorrery` (`sourceorrery.exe` on Windows) | the CLI |
| `libsourceorrery_ffi.so` (Linux), `libsourceorrery_ffi.dylib` (macOS), `sourceorrery_ffi.dll` with its import library `sourceorrery_ffi.dll.lib` (Windows) | the C ABI as a shared library |
| `libsourceorrery_ffi.a` (Linux, macOS), `sourceorrery_ffi.lib` (Windows) | the C ABI as a static library |

The headers are `crates/sourceorrery-ffi/include/sourceorrery.h` and, for
C++, `bindings/cpp/include/sourceorrery.hpp`.

To put the CLI on your `PATH` (in `~/.cargo/bin`):

```bash
cargo install --locked --path crates/sourceorrery-cli
```

### Features

| Crate | Default features | Without them |
|-------|------------------|--------------|
| `sourceorrery-cli` | `os-keyring`, `ui` | `--no-default-features`: passphrase protectors only and no `sourceorrery ui`; add `--features ui` to keep the browser |
| `sourceorrery-ffi`, `sourceorrery` | `os-keyring` | `--no-default-features`: passphrase protectors only |

A build without `os-keyring` needs no D-Bus headers on Linux and suits
servers and containers, which have no credential store
([Headless](https://sourceorrery.ai/guides/headless/)).

## Running the tests

The Rust workspace, with the same checks CI runs:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

The tests use passphrase vaults in temporary directories; they never touch
your credential store or your own vaults.

### The OS-keyring path

`scripts/dev/keyring-smoke.sh` (macOS, Linux) and
`scripts/dev/keyring-smoke.ps1` (Windows) exercise the OS-keyring
protector against this machine's credential store, in an isolated home:
create, read, add and remove protectors, destroy with and without
`--keep-os-key`, with the store inspected after each step. They print PASS
or FAIL per check and never a value; exit 2 means the store is not
available in this session (no desktop, no session bus). CI runs them
headlessly on all three platforms (the `keyring` job); run one by hand in a
desktop session to validate the store you use day to day:

```bash
cargo build -p sourceorrery-cli
bash scripts/dev/keyring-smoke.sh            # macOS Keychain, GNOME Keyring, KWallet, KeePassXC
pwsh scripts/dev/keyring-smoke.ps1           # Windows Credential Manager
```

On Linux the store checks need `secret-tool` (`libsecret-tools`); without
it the functional checks still run.

### The SDK test vault

Every SDK's tests, its example and the conformance harness read a vault
that the CLI creates, so build the CLI and the C ABI first (above), then,
in Bash (Git Bash on Windows):

```bash
eval "$(bash scripts/ci/fixture-vault.sh)"
```

`scripts/ci/fixture-vault.sh` creates a throwaway home directory with a
vault named `ci`, protected by a fixed test passphrase, holding a secret in
every state the tests check: two versions of `database-password`, a
disabled newest version, an expired, a not-yet-valid and a deleted secret.
It prints `export` lines, which `eval` applies to the current shell only:

| Variable | Value |
|----------|-------|
| `SOURCEORRERY_HOME` | the throwaway home directory |
| `SOURCEORRERY_PASSPHRASE` | the test passphrase |
| `SOURCEORRERY_TEST_VAULT` | `ci` |
| `SOURCEORRERY_TEST_MANIFEST` | a `sourceorrery.toml` that names the `ci` vault |
| `SOURCEORRERY_TEST_OLD_VERSION` | the oldest version of `database-password` |
| `SOURCEORRERY_NATIVE_DIR` | `target/release`, where the C ABI library is |
| `SOURCEORRERY_CLI` | the CLI that created the vault |

Run each SDK's tests from that shell. Never put real secrets in this vault:
its passphrase is in the repository.

### Each SDK

From the repository root, in the shell where you ran the fixture script:

| SDK | Build and test |
|-----|----------------|
| Rust | `cargo test -p sourceorrery` |
| Python | `pip install ./bindings/python pytest`, then `python -m pytest bindings/python/tests` (in a virtual environment) |
| JavaScript | `cd bindings/node && npm ci && npm run build && npm test && npm run typecheck` |
| Java | `cd bindings/java && mvn test` |
| .NET | `dotnet test bindings/dotnet/SourceOrrery.sln` |
| Go | `cd bindings/go && CGO_LDFLAGS="-L$SOURCEORRERY_NATIVE_DIR" LD_LIBRARY_PATH="$SOURCEORRERY_NATIVE_DIR" DYLD_LIBRARY_PATH="$SOURCEORRERY_NATIVE_DIR" go test ./...` |
| C++ | `cmake -S bindings/cpp -B build/cpp -DSOURCEORRERY_NATIVE_DIR="$SOURCEORRERY_NATIVE_DIR" && cmake --build build/cpp --config Release`, then `ctest --test-dir build/cpp -C Release` with the library on the loader path |
| C | compile `crates/sourceorrery-ffi/examples/get_secret.c` against the header and the library and run it |
| PHP | `php bindings/php/tests/run.php` |

Each SDK page has the full sequence, with the example and the platform
details. On Windows, the C and C++ steps use MSVC's `cl`, which is on
`PATH` only in a *Developer Command Prompt for VS*: start Git Bash from
there (`"C:\Program Files\Git\bin\bash.exe"`) so that the compiler and the
fixture's variables are in one shell.

### The conformance harness

One list of scenarios, `tests/conformance/sdk/scenarios.json`, holds every
SDK to the same behaviour. `harness.py` runs a small runner program per SDK
through all of them and judges what it reports:

```bash
python tests/conformance/sdk/harness.py --runner python
```

The interpreted runners (`python`, `node`, `java`, `php`) need only the
SDK built as above. The compiled ones are built first:

| Runner | Build it with |
|--------|---------------|
| `rust` | `cargo build --release -p sourceorrery --example conformance` |
| `dotnet` | `dotnet build bindings/dotnet/conformance -c Release` |
| `go` | `go build -o conformance-go ./conformance` in `bindings/go` (`conformance-go.exe` on Windows) |
| `c`, `cpp` | compile `crates/sourceorrery-ffi/examples/conformance.c` and `bindings/cpp/conformance/run.cpp` into `build/conformance_c` and `build/conformance_cpp` |

The protocol and how to add a scenario are in
[`tests/conformance/sdk/README.md`](../tests/conformance/sdk/README.md).

## Linux from Windows or macOS

The CI images are Debian-based. To check a change on Linux without a Linux
machine, run the tests in the official Rust image with Docker:

```bash
docker run --rm -v "$PWD:/work" -w /work rust:1-bookworm \
  bash -c 'apt-get update && apt-get install -y libdbus-1-dev pkg-config && cargo test --workspace --locked'
```

In Git Bash on Windows, put `MSYS_NO_PATHCONV=1` in front of `docker` so
that `/work` is not rewritten as a Windows path. The build writes to
`target/` in your checkout; add `-e CARGO_TARGET_DIR=/tmp/target` to keep
the Linux build apart from your own.

## The documentation site

`site/` is the Astro Starlight site at sourceorrery.ai; `docs/` is its
source. With Node.js 22.12 or newer:

```bash
cd site
npm ci
npm run dev        # http://localhost:4321
npm run build      # build, then check every internal link
```

Details: [`site/README.md`](../site/README.md).
