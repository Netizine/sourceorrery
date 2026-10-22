# Supply chain

SourceOrrery runs inside every application that reads a secret with it, so
a tampered package would be as dangerous as a tampered vault. This page
describes how the source becomes the packages you install, what stops
someone altering them on the way, how to check what you installed, and
what is not done yet. The [threat model](threat-model.md) covers the vault
itself.

## From commit to package

* **Every change through CI.** Changes reach `main` through pull requests,
  and a pull request merges only when the `CI` gate passes: formatting,
  Clippy with warnings as errors, every test on Ubuntu, Windows and macOS,
  every SDK's tests and the cross-language conformance harness against a
  real vault, and `cargo audit` against the RustSec advisory database.
* **One workflow, one commit, every package.** A release is cut by
  dispatching `.github/workflows/release.yml` by hand, never by pushing a
  tag. One run builds the CLI and the C ABI for six targets and every SDK
  package from a single commit, creates the GitHub Release with
  `SHA256SUMS`, and publishes to each registry. No package is uploaded
  from a developer's machine. The procedure is in [Releasing](release.md).
* **Locked dependencies.** CI and the release build with `cargo --locked`
  against the committed `Cargo.lock` (the Python and Node extensions have
  lock files of their own) and with `npm ci` against `package-lock.json`.
  A dependency changes only in a commit that changes a lock file.
* **Immutable versions.** The workflow refuses a tag that already exists.
  A version is never rebuilt or replaced; a mistake is fixed by the next
  patch version.
* **No cryptography of our own.** Every primitive comes from the RustCrypto
  crates ([architecture](architecture.md#4-cryptography-sourceorrery-crypto)).

## Trusted publishing

With trusted publishing, a registry is told once which repository and
which workflow file may publish a package. At release time the publishing
job presents an identity token that GitHub signs for that one workflow run
(OpenID Connect), and the registry exchanges it for a credential that
expires within the hour, for that package only. No long-lived token exists, so there
is none to leak from a CI log, steal from a maintainer's laptop or reuse
elsewhere. npm also records a **provenance** statement, signed through
Sigstore, that ties each published tarball to the commit and the workflow
run that built it.

| Registry | Package | Published with | What you can check |
|----------|---------|----------------|--------------------|
| npm | `@sourceorreryai/sdk` and its six platform packages | Trusted publishing, from `release.yml` or `ReleasePackages.yaml` in `Netizine/sourceorrery` | Provenance and registry signatures |
| NuGet | `SourceOrrery` | Trusted publishing (a key that lives one hour) | nuget.org's repository signature |
| Maven Central | `ai.sourceorrery:sourceorrery` | A Central user token; every file signed with the release key | The `.asc` signature next to each file |
| PyPI | `sourceorrery` | An API token | The SHA-256 of each file, against the release |
| crates.io | the six `sourceorrery*` crates | An API token | The checksums in `Cargo.lock` |
| Go module proxy | `github.com/netizine/sourceorrery/bindings/go` | Nothing uploaded: the tag `bindings/go/vX.Y.Z` | The Go checksum database |
| Packagist | `sourceorrery/sourceorrery` | Nothing uploaded: the tag `vX.Y.Z` | The commit recorded in `composer.lock` |
| GitHub Release | CLI and C ABI archives, wheels, jar, `.nupkg`, npm tarballs | The release workflow | `SHA256SUMS` and the workflow run linked from the release |

The wheels and sdist on PyPI, the npm tarballs and the jar on Maven
Central are byte for byte the files attached to the GitHub Release, so
their SHA-256 hashes appear in its `SHA256SUMS`. The two copies are
published through different accounts, so comparing them is a real check:
someone would have to compromise both to change a package unnoticed. The
`.nupkg` on nuget.org differs from the release's only by the repository
signature nuget.org adds.

## Checking what you installed

### npm

In a project that depends on `@sourceorreryai/sdk`:

```bash
npm audit signatures
```

It checks the registry signature of every installed package and the
provenance of those that carry one; the SourceOrrery packages count among
the *verified attestations*. The package page on npmjs.com shows the same
provenance, with links to the commit and the workflow run.

### NuGet

```bash
dotnet nuget verify --all ~/.nuget/packages/sourceorrery/0.1.3/sourceorrery.0.1.3.nupkg
```

Expect `Signature type: Repository` with the subject
`NuGet.org Repository by Microsoft`.

### Maven Central

Every file is signed with the SourceOrrery release key:

```text
F14C 928F CC55 C651 7F1A  E1E7 DAFA E59A 4372 DBC2
```

```bash
gpg --keyserver keyserver.ubuntu.com --recv-keys F14C928FCC55C6517F1AE1E7DAFAE59A4372DBC2
curl -LO https://repo1.maven.org/maven2/ai/sourceorrery/sourceorrery/0.1.3/sourceorrery-0.1.3.jar
curl -LO https://repo1.maven.org/maven2/ai/sourceorrery/sourceorrery/0.1.3/sourceorrery-0.1.3.jar.asc
gpg --verify sourceorrery-0.1.3.jar.asc sourceorrery-0.1.3.jar    # Good signature from "SourceOrrery Releases ..."
```

### PyPI

PyPI files carry no attestation yet, so pin the hashes. Each file's
SHA-256 is on its PyPI page and in the release's `SHA256SUMS`; check that
the two agree, then require them:

```text
# requirements.txt
sourceorrery==0.1.3 \
    --hash=sha256:<hash of the wheel for each platform you deploy to>
```

```bash
pip install --require-hashes -r requirements.txt
```

`pip-compile --generate-hashes` (pip-tools) and
`uv pip compile --generate-hashes` write those lines for you from PyPI.

### Cargo

`Cargo.lock` records the checksum of every crate, and Cargo verifies it on
every build. Install the CLI with `--locked`:

```bash
cargo install --locked sourceorrery-cli
```

The crate ships the lock file the release was built and tested with;
without `--locked`, Cargo resolves the newest compatible version of every
dependency at install time instead.

### Go

Nothing to do. The `go` command checks every module version against the
checksum database at `sum.golang.org` and records it in `go.sum`; a
published version can never change.

### Composer

Packagist serves the repository at the release tag, and `composer.lock`
records the commit it installed. Compare it with the tag:

```bash
git ls-remote https://github.com/Netizine/sourceorrery refs/tags/v0.1.3
```

### Release archives

Check every download against `SHA256SUMS`, as
[Getting started](https://sourceorrery.ai/getting-started/) shows for the
CLI. The file sits next to the archives, so it proves the download is
intact, not that the release is authentic; for the files that are also on
a registry, compare with the registry's hash as above.

## What SourceOrrery changes in your own supply chain

A malicious dependency, a poisoned install script or a misled coding agent
looks first for credentials in plain files: `.env`, configuration files,
shell history. With SourceOrrery there are none to find. What it does not
change yet:

* **Code running as you can open the vault as you.** An install script or
  an agent runs with your user's rights, so it can run the CLI and unlock
  any vault you can unlock without typing anything. A vault with an
  OS-keyring protector opens silently; a vault protected only by a
  passphrase opens only where the passphrase is available. Keep production
  secrets in vaults that development machines cannot unlock, and keep
  `SOURCEORRERY_PASSPHRASE` out of shells that install packages. The
  authenticated broker (milestone 3) is what will change this
  ([threat model](threat-model.md#the-three-guarantees)).
* **Code inside your application reads what your application reads.** A
  compromised dependency can read every secret the application can. What
  it cannot do through an SDK is write: no SDK can set, disable, delete or
  purge a secret, change a protector or touch the audit log
  ([ADR 0005](adr/0005-read-only-sdks.md)), so it cannot plant a value for
  the next deployment through the library. Every read is recorded in the
  vault's audit log, which `sourceorrery audit` shows.
* **`sourceorrery run` hands values to every dependency in the child.** It
  puts them in the environment of the process it starts. An SDK keeps each
  value in the process that asked for it, in a guarded buffer, until it is
  closed.

## Not done yet

* PyPI and crates.io are published with API tokens stored as repository
  secrets, not by trusted publishing, and PyPI files carry no attestation.
* The release archives have checksums but no signature or build
  attestation.
* macOS binaries are not signed or notarised; Windows binaries are not
  Authenticode-signed.
* The workflows refer to third-party GitHub Actions by version tag rather
  than by commit, and dependency updates are not automated.
* There is no software bill of materials and no claim of reproducible
  builds.

These are on the [roadmap](roadmap.md). To report a package you suspect
was tampered with, follow the
[security policy](../SECURITY.md): email security@sourceorrery.ai, not a
public issue.
