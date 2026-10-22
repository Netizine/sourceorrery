# Supply chain

SourceOrrery runs inside every application that reads a secret with it, so
a tampered package would be as dangerous as a tampered vault. This page
describes how the source becomes the packages you install, what stops
someone altering them on the way, how to check what you installed, and
what is not done yet. The [threat model](threat-model.md) covers the vault
itself.

> [!NOTE]
> This page describes the **0.1.4** release workflow. Verify the actual
> package's version, workflow run and available attestations when installing;
> a configured publishing method is not itself proof about a downloaded file.

## From commit to package

* **Checks matched to the change.** Code changes trigger formatting,
  Clippy with warnings as errors, tests on Ubuntu, Windows and macOS,
  SDK tests and the cross-language conformance harness against a real
  vault, and `cargo audit` against the RustSec advisory database. The `CI`
  gate aggregates those jobs. Documentation-only changes may skip the
  native builds; the documentation workflow builds and link-checks the site.
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
* **Pinned actions, automated updates.** Every third-party GitHub Action
  the workflows use is referenced by the full commit SHA of a release,
  with the version as a comment, so a moved or compromised tag cannot
  change what runs in CI or in a release build. Dependabot
  (`.github/dependabot.yml`) opens a weekly grouped pull request per
  ecosystem for the actions and for the Rust, npm, Python, NuGet and
  Maven dependencies (Rust lock files only; a range change is a deliberate
  commit), and the `workflows` CI job runs zizmor over `.github/` so an
  unpinned action or a shell step that expands an input fails the gate.
* **Immutable versions.** The workflow refuses a tag that already exists.
  A version is never rebuilt or replaced; a mistake is fixed by the next
  patch version.
* **No cryptography of our own.** Every primitive comes from the RustCrypto
  crates ([architecture](architecture.md#4-cryptography-sourceorrery-crypto)).

## Trusted publishing

With trusted publishing, a registry is told once which repository and
which workflow file may publish a package. At release time the publishing
job presents an identity token that GitHub signs for that one workflow run
(OpenID Connect), and the registry exchanges it for a short-lived publishing
credential under the configured trust policy. The workflow does not need a
stored long-lived token for those registries. npm and PyPI also record a **provenance**
statement, signed through Sigstore, that ties each published file to the
commit and the workflow run that built it.

Every registry that supports trusted publishing gets the packages that
way, from `release.yml` or `ReleasePackages.yaml` in
`Netizine/sourceorrery`:

| Registry | Package | Published with | What you can check |
|----------|---------|----------------|--------------------|
| npm | `@sourceorreryai/sdk` and its six platform packages | Trusted publishing | Provenance and registry signatures |
| PyPI | `sourceorrery` | Trusted publishing | An attestation for every file, and its SHA-256 against the release |
| crates.io | the six `sourceorrery*` crates | Trusted publishing (a token that lives 30 minutes) | The checksums in `Cargo.lock` |
| NuGet | `SourceOrrery` | Trusted publishing (a key that lives one hour) | nuget.org's repository signature |
| Maven Central | `ai.sourceorrery:sourceorrery` | A Central user token (Central has no trusted publishing); every file signed with the release key | The `.asc` signature next to each file |
| Go module proxy | `github.com/netizine/sourceorrery/bindings/go` | Nothing uploaded: the tag `bindings/go/vX.Y.Z` | The Go checksum database |
| Packagist | `sourceorrery/sourceorrery` | Nothing uploaded: the tag `vX.Y.Z` | The commit recorded in `composer.lock` |
| GitHub Release | CLI and C ABI archives, wheels, jar, `.nupkg`, npm tarballs, `SHA256SUMS` | The release workflow | A build provenance attestation per file (`gh attestation verify`), `SHA256SUMS`, and the workflow run linked from the release |
| Homebrew tap | `sourceorrery` in `Netizine/homebrew-sourceorrery` | Nothing uploaded: the release workflow commits a formula naming the release archive for each platform and its SHA-256 | Homebrew checks the hash before installing; the formula is a readable file in the tap |
| Scoop bucket | `sourceorrery` in `Netizine/scoop-sourceorrery` | Nothing uploaded: the release workflow commits a manifest naming the release archives and their SHA-256 | Scoop checks the hash before installing |
| WinGet | `Netizine.SourceOrrery` | A pull request on `microsoft/winget-pkgs` with manifests naming the release archives and their SHA-256, validated there | WinGet checks `InstallerSha256` before installing |

The wheels and sdist on PyPI, the npm tarballs and the jar on Maven
Central are byte for byte the files attached to the GitHub Release, so
their SHA-256 hashes appear in its `SHA256SUMS`. Comparing the copies can
detect a mismatch between the registry and release, but both originate in
the same build workflow: a compromised workflow could publish matching
malicious files to both. Check provenance as well as hashes. The
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
dotnet nuget verify --all ~/.nuget/packages/sourceorrery/0.1.4/sourceorrery.0.1.4.nupkg
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
curl -LO https://repo1.maven.org/maven2/ai/sourceorrery/sourceorrery/0.1.4/sourceorrery-0.1.4.jar
curl -LO https://repo1.maven.org/maven2/ai/sourceorrery/sourceorrery/0.1.4/sourceorrery-0.1.4.jar.asc
gpg --verify sourceorrery-0.1.4.jar.asc sourceorrery-0.1.4.jar    # Good signature from "SourceOrrery Releases ..."
```

### PyPI

Each file published by trusted publishing carries an attestation, shown
under *Provenance* on the file's page on pypi.org with the repository,
workflow and commit that built it. To check one yourself:

```bash
pip install pypi-attestations
pypi-attestations verify pypi --repository https://github.com/Netizine/sourceorrery \
    pypi:sourceorrery-<version>-cp311-abi3-manylinux_2_28_x86_64.whl
```

To make sure every install gets exactly those files, pin the hashes. Each
file's SHA-256 is on its PyPI page and in the release's `SHA256SUMS`;
check that the two agree, then require them:

```text
# requirements.txt
sourceorrery==0.1.4 \
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
cargo install --locked sourceorrery-cli --version 0.1.4
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
git ls-remote https://github.com/Netizine/sourceorrery refs/tags/v0.1.4
```

### Release archives

Every file on a GitHub Release, `SHA256SUMS` included, carries a **build
provenance attestation**: a statement signed through Sigstore in the
release workflow run, stored with the repository, naming the file's
SHA-256, the commit and the workflow that built it. Check a download
against it with the GitHub CLI (signed in, or `--owner` for a public
repository without signing in):

```bash
gh attestation verify sourceorrery-0.1.4-x86_64-unknown-linux-gnu.tar.gz --repo Netizine/sourceorrery
```

The command fails for a file that was altered after the build or that did
not come out of `release.yml` in `Netizine/sourceorrery`. It proves origin
on a GitHub-hosted runner; it does not make the code safe, and no
reproducible-build claim is made. The attestations are listed under
*Attestations* on the repository's *Actions* tab as well.

`SHA256SUMS` next to the archives proves a download is intact without the
GitHub CLI, as [Getting started](https://sourceorrery.ai/getting-started/)
shows; for the files that are also on a registry, compare with the
registry's hash as above.

## What SourceOrrery changes in your own supply chain

A malicious dependency, a poisoned install script or a misled coding agent
may look for credentials in plain files: `.env`, configuration files or
shell history. Replacing plaintext configuration with vault references
reduces that exposure after the original files and copies are removed.
It does not change these limits:

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
  purge a secret, change a protector or manage the audit log
  ([ADR 0005](adr/0005-read-only-sdks.md)), so it cannot plant a value for
  the next deployment through the library. Every read is recorded in the
  vault's audit log, which `sourceorrery audit` shows.
* **`sourceorrery run` hands values to every dependency in the child.** It
  puts them in the environment of the process it starts. An SDK keeps each
  value in the process that asked for it, in a guarded buffer, until it is
  closed.

## Not done yet

> [!WARNING]
> Checksums and provenance do not establish that code is safe. The
> binaries are not notarised or Authenticode-signed, and no
> reproducible-build claim is made.

* Maven Central is published with a stored user token, because Central
  offers no trusted publishing; its files are GPG-signed instead.
* macOS binaries are not signed or notarised; Windows binaries are not
  Authenticode-signed.
* There is no software bill of materials and no claim of reproducible
  builds.

These are on the [roadmap](roadmap.md). To report a package you suspect
was tampered with, follow the
[security policy](../SECURITY.md): email security@sourceorrery.ai, not a
public issue.
