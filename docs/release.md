# Releasing

Releases are cut by hand from the **Release** workflow
(`.github/workflows/release.yml`), never by pushing a tag. One run builds
every artefact for one version from one commit, publishes the GitHub
Release and, for each registry whose secret exists, publishes the package.
A dry run does everything except create the tag, the release and the
registry uploads, so the pipeline can be exercised before a single token
exists.

## Procedure

1. Update `CHANGELOG.md`: move the `[Unreleased]` entries under a new
   `## [X.Y.Z] - YYYY-MM-DD` heading and commit to `main`.
2. In GitHub, open *Actions → Release → Run workflow*, enter the version
   (`X.Y.Z`, no `v`) and leave **dry_run** ticked. Wait for green. The
   `release-dry-run-X.Y.Z` artifact holds everything the real run would
   attach, plus `SHA256SUMS` and the release notes; download it and try a
   package or two.
3. Run the workflow again with **dry_run** unticked. It creates the tag
   `vX.Y.Z` on the chosen commit, the GitHub Release with every archive and
   package and `SHA256SUMS`, then the publish jobs run (or are skipped,
   see below).
4. Check the registries and update the version in the repository for the
   next cycle if you keep a development version there (the workflow stamps
   the manifests itself from the version you typed; the committed version
   does not have to match).

The workflow refuses a version that is not semver and, outside a dry run,
a tag that already exists. Releases are immutable: a mistake is fixed by
the next patch version.

## What one run produces

| Job | Output |
|-----|--------|
| `native` (six targets) | `sourceorrery-X.Y.Z-<target>.{tar.gz,zip}`: the CLI. `sourceorrery-ffi-X.Y.Z-<target>.{tar.gz,zip}`: the shared and static C ABI libraries, `sourceorrery.h`, `sourceorrery.hpp`, licences. |
| `python` (six targets + sdist) | abi3 wheels for Python 3.11+ (`manylinux_2_28` on Linux) and the sdist. |
| `node-build`, `node-package` | `@sourceorrery/sdk` and the six `@sourceorrery/sdk-<platform>` tarballs. |
| `java` | `sourceorrery-X.Y.Z.jar` with the native libraries embedded per platform. |
| `dotnet` | `SourceOrrery.X.Y.Z.nupkg` with `runtimes/<rid>/native`. |
| `crates` | a `cargo publish --workspace --dry-run` proving every crate packages in dependency order. |
| `php` | `composer validate --strict` on the root `composer.json` and a Composer install of the version from a local tag (`scripts/ci/php-package-install.sh`); nothing is uploaded, the package Packagist serves is the git tag itself. |
| `release` | the GitHub Release (or the dry-run artifact) with `SHA256SUMS`. |

Targets: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`,
`aarch64-pc-windows-msvc`.

Every manifest is stamped with the version first by
`scripts/release/set-version.py` (Cargo manifests and lock files, the
Python package, `package.json`, `pom.xml`, `Directory.Build.props`); Go and
PHP take their version from the tag.

## Registry secrets

Each publish job runs only when the run is not a dry run **and** its
secret is set in the repository (*Settings → Secrets and variables →
Actions*). A job whose secret is absent is skipped, not failed, so the
registries can be brought online one at a time.

| Registry | Job | Secrets | Where to get them |
|----------|-----|---------|-------------------|
| crates.io | `publish-crates` | `CARGO_REGISTRY_TOKEN` | crates.io → Account settings → API tokens (scope `publish-new` + `publish-update`). Publishes `sourceorrery-core`, `sourceorrery-crypto`, `sourceorrery-storage`, `sourceorrery`, `sourceorrery-ffi`, `sourceorrery-cli` in dependency order. |
| PyPI | `publish-pypi` | `PYPI_API_TOKEN` | pypi.org → Account settings → API tokens. The first upload needs a token scoped to the account; after that, scope it to the `sourceorrery` project. |
| npm | `publish-npm` | `NPM_TOKEN` | npmjs.com → Access tokens → Granular token with publish rights on the `@sourceorrery` scope (create the organisation first). |
| NuGet | `publish-nuget` | `NUGET_API_KEY` | nuget.org → API keys, glob `SourceOrrery*`, push new packages and versions. |
| Maven Central | `publish-maven` | `MAVEN_CENTRAL_USERNAME`, `MAVEN_CENTRAL_PASSWORD`, `MAVEN_GPG_PRIVATE_KEY`, `MAVEN_GPG_PASSPHRASE` | central.sonatype.com → verify the `ai.sourceorrery` namespace (DNS TXT record), then *View account → Generate user token* for the two credentials; an ASCII-armoured GPG private key whose public key is on `keys.openpgp.org` and its passphrase. |
| pkg.go.dev | `publish-go` | none (uses `GITHUB_TOKEN`) | Pushes the tag `bindings/go/vX.Y.Z` and fetches the version through `proxy.golang.org`, which indexes it. |
| Packagist | `publish-packagist` | `PACKAGIST_USERNAME`, `PACKAGIST_API_TOKEN` | The Packagist account name and its API token (*Profile → Show API Token*; the *safe* token, which can only trigger updates, is enough), after the one-time submission described under [The PHP package and Packagist](#the-php-package-and-packagist). The job asks Packagist to re-read the repository, fails with that pointer if the repository was never submitted, and waits for the version to appear. |

No secret is needed for the GitHub Release itself (`GITHUB_TOKEN` with
`contents: write`).

## The PHP package and Packagist

Packagist and Composer `vcs` repositories read one file, `composer.json`
at the root of the repository, and turn every git tag that carries one
into a version; neither can be pointed at a subdirectory. Three ways to
publish a package whose code lives in `bindings/php` were weighed:

- **The repository is the package.** `composer.json` at the root autoloads
  `SourceOrrery\` from `bindings/php/src/`. The release tag is the
  Packagist version, and `composer require` downloads GitHub's archive of
  the tag (the whole tree, about 1.5 MB) into
  `vendor/sourceorrery/sourceorrery`. Nothing else moves.
- **A subtree split.** The release job would push the history of
  `bindings/php` to a second repository (`Netizine/sourceorrery-php`), tag
  it there, and Packagist would follow that repository. A leaner download,
  at the price of a second repository, a token that can push to it, and a
  split that has to be re-run for every release and can drift from the tag.
- **Monorepo support on Packagist.** Only Private Packagist can index a
  subdirectory; packagist.org cannot.

The first option is the lightest and the only one whose versions are the
release tags themselves, so it is what the repository does. Consequences:

- `bindings/php/composer.json` is gone; the root manifest is the only one.
  It maps `SourceOrreryException.php` and `Project.php` in a classmap next
  to the PSR-4 rule because each holds more than one class, which PSR-4
  alone cannot find.
- The whole tree ships. `archive.exclude` in `composer.json` would not trim
  it (it only shapes `composer archive`, which Packagist never runs), and
  `.gitattributes export-ignore` would also strip the *Source code* archives
  GitHub attaches to every release, so neither is used.
- A tag that predates the root manifest has no Packagist version: 0.1.0 is
  installed from its tag as a `path` repository
  ([docs/sdks/php.md](sdks/php.md)). The first Packagist version is the
  first release after it.
- `scripts/ci/php-package-install.sh` copies the checkout into a scratch
  repository, tags it, and proves `composer require` of that version and
  Composer's autoloading of every class. The `sdk-php` CI job runs it on
  every push and the `php` release job runs it with the release version.

What the Packagist submission needs, once and by hand:

1. This change on `main`: Packagist reads the default branch when a
   repository is submitted and refuses one without a root `composer.json`.
2. A packagist.org account (its name is `PACKAGIST_USERNAME`) that submits
   `https://github.com/Netizine/sourceorrery` at
   <https://packagist.org/packages/submit>. The package name comes from the
   manifest, `sourceorrery/sourceorrery`; the first submission claims the
   `sourceorrery` vendor for that account.
3. The account's API token (*Profile → Show API Token*) as
   `PACKAGIST_API_TOKEN`. The *safe* token, which can only trigger package
   updates, is all the job uses.
4. Optionally, Packagist's GitHub hook (offered on the package page after
   submission) so that pushes update the package without a release run; the
   job's API call covers releases either way.

## Verifying a release

```bash
curl -LO https://github.com/Netizine/sourceorrery/releases/download/vX.Y.Z/SHA256SUMS
curl -LO https://github.com/Netizine/sourceorrery/releases/download/vX.Y.Z/sourceorrery-X.Y.Z-x86_64-unknown-linux-gnu.tar.gz
sha256sum -c --ignore-missing SHA256SUMS
```

Package signing (Sigstore for npm and PyPI provenance, cosign for the
archives) is on the roadmap; until then the checksums and the workflow run
linked from the release are the provenance.
