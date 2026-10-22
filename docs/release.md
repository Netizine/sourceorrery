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
5. Point the install instructions at the new release: the download links
   in `site/src/content/docs/getting-started.mdx` and `docs/sdks/*.md`, and
   the examples in `docs/building.md` and `docs/supply-chain.md`, name the
   version in every file name and tag.

The workflow refuses a version that is not semver and, outside a dry run,
a tag that already exists. Releases are immutable: a mistake is fixed by
the next patch version.

## What one run produces

| Job | Output |
|-----|--------|
| `native` (six targets) | `sourceorrery-X.Y.Z-<target>.{tar.gz,zip}`: the CLI. `sourceorrery-ffi-X.Y.Z-<target>.{tar.gz,zip}`: the shared and static C ABI libraries, `sourceorrery.h`, `sourceorrery.hpp`, licences. |
| `python` (six targets + sdist) | abi3 wheels for Python 3.11+ (`manylinux_2_28` on Linux) and the sdist. |
| `node-build`, `node-package` | `@sourceorreryai/sdk` and the six `@sourceorreryai/sdk-<platform>` tarballs. `node-build` compiles the addon per target and, on `x86_64-unknown-linux-gnu`, keeps the `index.js` loader and `index.d.ts` that `napi build` generates (artifact `npm-loader`); `node-package` lays out the platform packages around the addons, adds the loader, packs, then installs the main and `linux-x64-gnu` tarballs into a scratch project and requires `@sourceorreryai/sdk`, so a main package that cannot be loaded fails the run. |
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
Python package, `package.json` and the `npm/<platform>` manifests,
`pom.xml`, `Directory.Build.props`); Go and PHP take their version from
the tag. In the repository `bindings/node/package.json` depends on the
platform packages as `file:npm/<platform>` links so that `npm ci` resolves
without them being on the registry; stamping replaces the links with the
version, which is what the published package depends on, so the node jobs
run `npm ci` before they stamp.

## Registry secrets

Each publish job runs only when the run is not a dry run **and** its
secret is set in the repository (*Settings → Secrets and variables →
Actions → New repository secret*). A job whose secret is absent is
skipped, not failed, so the registries can be brought online one at a
time. The **Release packages** workflow
([below](#publishing-an-existing-release)) uses the same secrets.

| Registry | Release job | Secrets |
|----------|-------------|---------|
| npm | `publish-npm` | none (trusted publishing; switched on by the repository variable `NPM_TRUSTED_PUBLISHING`) |
| PyPI | `publish-pypi` | `PYPI_API_TOKEN` |
| NuGet | `publish-nuget` | `NUGET_USER` (trusted publishing; no API key) |
| crates.io | `publish-crates` | `CARGO_REGISTRY_TOKEN` |
| Maven Central | `publish-maven` | `MAVEN_CENTRAL_USERNAME`, `MAVEN_CENTRAL_PASSWORD`, `MAVEN_GPG_PRIVATE_KEY`, `MAVEN_GPG_PASSPHRASE` |
| Packagist | `publish-packagist` | `PACKAGIST_USERNAME`, `PACKAGIST_API_TOKEN` |
| pkg.go.dev | `publish-go` | none (uses `GITHUB_TOKEN`) |

No secret is needed for the GitHub Release itself (`GITHUB_TOKEN` with
`contents: write`).

### Setting up each registry

**npm** (`@sourceorreryai/sdk` and six `@sourceorreryai/sdk-<platform>`
packages), with trusted publishing, so no token is stored anywhere. The
publish jobs run npm 11 (trusted publishing needs 11.5.1 or later), which
trades the job's GitHub identity token for a short-lived credential; npm
grants it only to the workflows each package lists. npm can only attach a
trusted publisher to a package that exists, so the first version of each
package is published by hand, once.

1. The npmjs.com account `sourceorreryai`, with two-factor authentication.
   The packages live in its user scope, `@sourceorreryai`.
2. The first version, by hand: download the release's seven npm tarballs
   (`sourceorreryai-sdk-*.tgz`), run `npm login`, then
   `npm publish ./<tarball> --access public` for the six platform
   tarballs and, last, the main one, confirming each with two-factor
   authentication. Keep the `./`: npm reads a path such as
   `dist/<tarball>` as a GitHub repository.
3. For each of the seven packages, at
   `https://www.npmjs.com/package/<name>/access`, *Trusted Publisher →
   GitHub Actions*: Organization or user `Netizine`, Repository
   `sourceorrery`, Workflow filename `release.yml`; then a second one
   with `ReleasePackages.yaml`. Every field is case-sensitive, and npm
   checks them only when a publish happens. npm's documentation says a new
   trusted publisher expires if no publish uses it within two days, so add
   them shortly before the release that will use them.
4. The repository variable (not secret) `NPM_TRUSTED_PUBLISHING` set to
   `true` (*Settings → Secrets and variables → Actions → Variables*).
   Without it both workflows skip npm.
5. Optionally, once a release has gone through: each package's
   *Settings → Publishing access → Require two-factor authentication and
   disallow tokens*. Trusted publishing keeps working; no token can
   publish.

**PyPI** (`sourceorrery`):

1. A pypi.org account (two-factor authentication is mandatory).
2. *Account settings → API tokens → Add API token*, scope **Entire
   account**: a token scoped to the project can only be made once the
   project exists. Save it as `PYPI_API_TOKEN` (it starts with `pypi-`).
3. After the first upload, replace it with a token scoped to the
   `sourceorrery` project.

**NuGet** (`SourceOrrery`), with trusted publishing, so no API key is
stored anywhere. The publish jobs trade the job's GitHub identity token
for a NuGet key that lives one hour, through `NuGet/login`; nuget.org
grants it only to the workflows its policy names.

1. Sign in to nuget.org, click your user name, then *Trusted Publishing*.
2. Add a policy, owned by your account (or the organisation that will own
   the package): Repository Owner `Netizine`, Repository `sourceorrery`,
   Workflow File `release.yml` (the file name only), Environment empty.
   Allow publishing new packages and new versions, glob `SourceOrrery`.
   The policy works before the package exists; the first push creates it.
3. Add a second, identical policy with Workflow File
   `ReleasePackages.yaml`, so the **Release packages** workflow can push
   too.
4. Save your nuget.org profile name (the user name, not the e-mail
   address) as the repository secret `NUGET_USER`.

A new policy can show as *temporarily active* for 7 days, mostly for
private repositories, until a first publish locks it to the repository; if
nothing publishes in that window it turns inactive and can be restarted
from the same page.

**crates.io** (`sourceorrery-core`, `sourceorrery-crypto`,
`sourceorrery-storage`, `sourceorrery`, `sourceorrery-ffi`,
`sourceorrery-cli`, published in that order):

1. Log in to crates.io with GitHub and verify an email address under
   *Account Settings*; crates.io refuses publishes without one.
2. *Account Settings → API Tokens → New Token*: scopes `publish-new` and
   `publish-update`, crates `sourceorrery*`, an expiry. Save it as
   `CARGO_REGISTRY_TOKEN`. The first publish claims the six names.

**Maven Central** (`ai.sourceorrery:sourceorrery`):

1. An account at central.sonatype.com.
2. *Namespaces → Add namespace* `ai.sourceorrery`. Central shows a
   verification key; add it as a DNS TXT record on `sourceorrery.ai`, then
   press *Verify*.
3. *Account → Generate User Token*. Its username is
   `MAVEN_CENTRAL_USERNAME`, its password `MAVEN_CENTRAL_PASSWORD` (not the
   account's login).
4. A signing key, published where Central looks for it:

   ```bash
   gpg --full-generate-key                                  # RSA 4096, with a passphrase
   gpg --keyserver keys.openpgp.org --send-keys <KEY-ID>    # then confirm the e-mail it sends
   gpg --keyserver keyserver.ubuntu.com --send-keys <KEY-ID>
   gpg --armor --export-secret-keys <KEY-ID>                # the whole block is MAVEN_GPG_PRIVATE_KEY
   ```

   The passphrase is `MAVEN_GPG_PASSPHRASE`.

**Packagist** (`sourceorrery/sourceorrery`): the one-time submission
under [The PHP package and Packagist](#the-php-package-and-packagist),
then the account name as `PACKAGIST_USERNAME` and its *safe* API token
(*Profile → Show API Token*) as `PACKAGIST_API_TOKEN`. The release job
asks Packagist to re-read the repository, fails with that pointer if the
repository was never submitted, and waits for the version to appear.

**pkg.go.dev**: nothing to set up. The release job pushes the tag
`bindings/go/vX.Y.Z` and fetches the version through `proxy.golang.org`,
which indexes it.

## Publishing an existing release

`.github/workflows/ReleasePackages.yaml` (*Actions → Release packages →
Run workflow*) publishes the packages of a release that already exists,
for a registry whose secret was added after the release ran. It builds no
new release:

- npm, PyPI and NuGet upload the exact files attached to the release.
- crates.io publishes from the release tag's source.
- Maven Central rebuilds the jar from the tag with the native libraries
  out of the release's jar, because Central needs sources, javadoc and
  signatures, which the release does not carry.
- Packagist and pkg.go.dev upload nothing; they are pointed at the tag.

Inputs: the tag (empty means the latest release), **dry_run** (on by
default) and one tick box per registry. Every registry's files are
checked before anything is uploaded, a version a registry already has is
skipped, and a registry without its secret is skipped. A dry run checks
every ticked registry, with or without secrets, and uploads nothing.

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

What each registry adds on top (npm provenance, the Maven Central
signatures, nuget.org's repository signature) and how a user checks it is
in [Supply chain](supply-chain.md); signing the archives themselves is on
the [roadmap](roadmap.md#supply-chain).
