# Releasing

Releases are cut by hand from the **Release** workflow
(`.github/workflows/release.yml`), never by pushing a tag. One run builds
every artefact for one version from one commit, publishes the GitHub
Release and publishes each package to its registry. A dry run does
everything except create the tag, the release and the registry uploads,
so the pipeline can be exercised without touching a registry.

The current release is [**0.2.0**](https://github.com/Netizine/sourceorrery/releases/tag/v0.2.0),
published on 23 October 2026. The new public manifest fields and audit
operations change the Rust API compared with 0.1.4, so these features
could not ship as a compatible 0.1.5 patch. The existing compatibility gate
remains enabled. The [first provider publication](#first-provider-publication-for-020)
was part of the same full release run: every crate, SDK and release asset
uses **0.2.0**. Enabling trusted publishing for the new providers afterward
does not require a 0.2.1 release.

## Procedure

1. Choose the version by [ADR 0007](adr/0007-versioning-and-compatibility.md):
   before 1.0 a patch may add but never breaks any surface (CLI, Rust
   API, C ABI, contract, SDKs, vault file); anything else is a minor
   release. A C ABI change needs `SO_ABI_VERSION` bumped, a contract
   change `CONTRACT_VERSION`. The `semver` job of the workflow checks the
   Rust API against crates.io for the version you type and fails the run
   when a bigger bump is needed. Update `CHANGELOG.md`: move the
   `[Unreleased]` entries under a new `## [X.Y.Z] - YYYY-MM-DD` heading.
   With the repository at that version
   (`python scripts/release/set-version.py X.Y.Z --keep-node-links`), run
   `python scripts/release/docs-version.py`: every install page then names
   X.Y.Z and no longer says it is unreleased. The workflow refuses a real
   release whose documentation does not (`docs-version.py --check --expect
   X.Y.Z`). Commit to `main`, then push the complete release candidate
   once. A Git push makes that commit available to Actions; it does not
   start a release.
2. In GitHub, open *Actions → Release → Run workflow*, enter the version
   (`X.Y.Z`, no `v`) and leave **dry_run** ticked. Leave **bootstrap_providers**
   unticked for ordinary releases; the initial 0.2.0 publication is recorded below.
   Wait for green. The
   `release-dry-run-X.Y.Z` artifact holds everything the real run would
   attach, plus `SHA256SUMS` and the release notes; download it and try a
   package or two.
3. Manually dispatch the workflow again from the same reviewed commit,
   with the same version and provider option, and **dry_run** unticked.
   It creates the tag
   `vX.Y.Z` on the chosen commit, the GitHub Release with every archive and
   package and `SHA256SUMS`, then the publish jobs run (or are skipped,
   see below).
4. Check the registries. When work on the next version starts, bump the
   repository to it (`set-version.py X.Y.Z --keep-node-links`) and run
   `docs-version.py`: the install pages name the new version and say it is
   not released yet, with a link to the current release's documentation at
   its tag. CI checks the pages against the workspace version on every
   change (`docs-version.py --check`).

The workflow refuses a version that is not semver and, outside a dry run,
a tag that already exists. It also refuses a real release that is not
dispatched from `main`, or whose commit was not validated in full:
`scripts/release/check-release-validation.py` requires the commit to be on
`main`, a completed `ci.yml` run for exactly that commit (a push or a
dispatch on `main`, in this repository) in which every job ran and passed,
and the commit's `CI` check reported by GitHub Actions. A commit whose
push was docs-only skipped the build jobs: run CI on it with *Actions → CI
→ Run workflow* on `main` first. Any failure to read the GitHub API
refuses. A dry run runs the same gate and reports its verdict as warnings,
so release changes can be tried from a branch. *Release packages* applies
the same gate to the commit the tag names. Published package contents are
immutable; code changes require a new version. A failed registry upload can instead be
retried for the same version with [Release packages](#publishing-an-existing-release).

## What one run produces

| Job | Output |
|-----|--------|
| `sbom` | `sourceorrery-X.Y.Z-<target>.cdx.json`, `sourceorrery-ffi-X.Y.Z-<target>.cdx.json`, `sourceorrery-python-X.Y.Z-<target>.cdx.json`, `sourceorrery-node-X.Y.Z-<target>.cdx.json`: CycloneDX 1.5 bills of materials for the six targets, rendered from the lock files by `cargo cyclonedx` on one runner (artifact `sbom`). The `native` job builds the CLI and the C ABI with `cargo auditable`, which embeds the dependency list in the binaries. |
| `semver` | nothing: `cargo semver-checks` on `sourceorrery` and `sourceorrery-core` against the crates.io baseline, with the version you typed; the release waits for it. |
| `native` (six targets) | `sourceorrery-X.Y.Z-<target>.{tar.gz,zip}`: the CLI. `sourceorrery-ffi-X.Y.Z-<target>.{tar.gz,zip}`: the shared and static C ABI libraries, `sourceorrery.h`, `sourceorrery.hpp`, licences. |
| `python` (six targets + sdist) | abi3 wheels for Python 3.11+ (`manylinux_2_28` on Linux) and the sdist. |
| `node-build`, `node-package` | `@sourceorreryai/sdk` and the six `@sourceorreryai/sdk-<platform>` tarballs. `node-build` compiles the addon per target and, on `x86_64-unknown-linux-gnu`, keeps the `index.js` loader and `index.d.ts` that `napi build` generates (artifact `npm-loader`); `node-package` lays out the platform packages around the addons, adds the loader, packs, then installs the main and `linux-x64-gnu` tarballs into a scratch project and requires `@sourceorreryai/sdk`, so a main package that cannot be loaded fails the run. |
| `java` | `sourceorrery-X.Y.Z.jar` with the native libraries embedded per platform. |
| `dotnet` | `SourceOrrery.X.Y.Z.nupkg` with `runtimes/<rid>/native`. |
| `crates` | `scripts/release/publish-crates.py X.Y.Z` runs Cargo's dry-run verification for every publishable workspace crate in dependency order. |
| `publish-crates` | in a real release, publishes the workspace crates through OIDC. With `bootstrap_providers` ticked, core is published through OIDC first, the three new providers use the temporary credential, and the remaining workspace crates use OIDC. Exact versions already published are skipped. All ordinary release and SDK jobs still run. |
| `php` | `composer validate --strict` on the root `composer.json` and a Composer install of the version from a local tag (`scripts/ci/php-package-install.sh`); nothing is uploaded, the package Packagist serves is the git tag itself. |
| `release` | the GitHub Release (or the dry-run artifact) with `SHA256SUMS`, and a build provenance attestation for every file in a real release. |
| `package-managers` | the Homebrew formula, the Scoop manifest and the three WinGet manifests, rendered from `SHA256SUMS` by `scripts/release/package-managers.py` (artifact `package-managers`); every URL is a release archive and every hash comes from the release. |

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

## Registry credentials

No publish job runs in a dry run. crates.io, PyPI, npm and NuGet are
published by **trusted publishing**: the job presents the identity token
GitHub signs for that workflow run, and the registry exchanges it for a
short-lived credential, granted only if the package's trusted-publisher
settings name `Netizine/sourceorrery` and the workflow file. No token for
them is stored for normal releases. The first publication of the three
crates.io providers uses a temporary token in the same full release run;
revoke it after configuring their trusted publishers. Maven
Central and Packagist still use stored
secrets (*Settings → Secrets and variables → Actions*); their jobs are
skipped, not failed, while the secrets are absent. The **Release
packages** workflow ([below](#publishing-an-existing-release)) needs the
same settings, with its own file name, `ReleasePackages.yaml`.

| Registry | Release job | Runs when | Stored credential |
|----------|-------------|-----------|-------------------|
| crates.io | `publish-crates` | every real release | none for normal releases; temporary `CRATES_BOOTSTRAP_TOKEN` for the three new providers when `bootstrap_providers` is ticked |
| PyPI | `publish-pypi` | every real release | none (trusted publishing) |
| npm | `publish-npm` | the repository variable `NPM_TRUSTED_PUBLISHING` is `true` | none (trusted publishing) |
| NuGet | `publish-nuget` | the secret `NUGET_USER` exists | none besides the profile name (trusted publishing) |
| Maven Central | `publish-maven` | its secrets exist | `MAVEN_CENTRAL_USERNAME`, `MAVEN_CENTRAL_PASSWORD`, `MAVEN_GPG_PRIVATE_KEY`, `MAVEN_GPG_PASSPHRASE` |
| Packagist | `publish-packagist` | its secrets exist | `PACKAGIST_USERNAME`, `PACKAGIST_API_TOKEN` |
| pkg.go.dev | `publish-go` | every real release | none (uses `GITHUB_TOKEN`) |
| Homebrew tap, Scoop bucket | `publish-homebrew-scoop` | the secret `PACKAGING_TOKEN` exists | `PACKAGING_TOKEN` |
| WinGet | `publish-winget` | the secret `WINGET_TOKEN` exists | `WINGET_TOKEN` |

crates.io and PyPI have no switch: a registry that does not trust the
workflow fails the job loudly instead of skipping it. No secret is needed
for the GitHub Release itself (`GITHUB_TOKEN` with `contents: write`).

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

**PyPI** (`sourceorrery`), with trusted publishing, so no token is stored
anywhere. `pypa/gh-action-pypi-publish` trades the job's GitHub identity
token for a short-lived upload token and uploads a signed attestation
(PEP 740) with every file.

1. A pypi.org account (two-factor authentication is mandatory) that owns
   the `sourceorrery` project.
2. The project's *Manage → Publishing → Add a new publisher → GitHub*:
   Owner `Netizine`, Repository name `sourceorrery`, Workflow name
   `release.yml`, Environment name empty. Then a second publisher with
   Workflow name `ReleasePackages.yaml`.
3. Delete any `PYPI_API_TOKEN` repository secret and revoke the token on
   pypi.org; nothing reads it any more.

**crates.io** (`sourceorrery-core`, `sourceorrery-crypto`,
`sourceorrery-storage`, `sourceorrery-provider-vault`,
`sourceorrery-provider-aws`, `sourceorrery-provider-azure`,
`sourceorrery-provider`, `sourceorrery`, `sourceorrery-ffi`,
`sourceorrery-cli`), with trusted publishing for normal
releases. `scripts/release/publish-crates.py` discovers the publishable
workspace members, verifies their versions and lets Cargo publish them in
dependency order. Both release workflows skip exact versions already on
crates.io, including versions uploaded during bootstrap. A registry lookup
error or a yanked version fails the job; it is never treated as permission
to publish. `rust-lang/crates-io-auth-action` trades the
job's GitHub identity token for a crates.io token that lives 30 minutes
and revokes it when the job ends. crates.io grants it only for crates
whose settings name the workflow, so every crate needs the setting, or the
publish stops at the first crate without it. A crate must already exist
before its Trusted Publishing configuration can be created. The
[crates.io rollout documentation](https://blog.rust-lang.org/2025/07/11/crates-io-development-update-2025-07/)
requires an initial token-authenticated publication; pending publishers
for names that do not exist are not available. The three providers are
new in 0.2.0 and used the initial-publication option below. The six existing
crates, including core, used OIDC throughout that release.

1. For each crate, *Settings → Trusted Publishing → Add →
   GitHub*: Repository owner `Netizine`, Repository name `sourceorrery`,
   Workflow filename `release.yml`, Environment empty. Then a second
   configuration with `ReleasePackages.yaml`.
2. Delete any `CARGO_REGISTRY_TOKEN` repository secret and revoke the token
   under *Account Settings → API Tokens*.
3. Optionally, once a release has gone through: each crate's *Settings →
   Trusted Publishing → Only allow trusted publishing*, so that no API
   token can publish it.

#### First provider publication for 0.2.0

All nine crates are now published as 0.2.0. The procedure below records
their initial publication; future releases use ordinary trusted publishing
after the providers' registry configuration is complete.

The real providers use `AsyncSecretClient`, `Provider` and `RemoteVault`
from the new core. Published core 0.1.4 does not contain those APIs, so
publishing providers against it would produce unusable packages. The full
release publishes the actual sources in this order: `sourceorrery-core` 0.2.0, then
`sourceorrery-provider-vault` and `sourceorrery-provider-aws` 0.2.0, then
`sourceorrery-provider` 0.2.0. The two concrete providers' test-only
dependency on the adapter is path-only, so Cargo strips that back edge
from their published manifests; local tests still exercise the adapter.
The remaining workspace crates follow, and the ordinary SDK and GitHub
Release jobs run too. **bootstrap_providers** changes how those three new
crate names are authenticated; it is not a provider-only release mode.

1. Commit and push the complete release candidate and ensure normal CI is green.
   In *Actions → Release → Run workflow*, select that commit's branch,
   enter `0.2.0`, tick **bootstrap_providers**, and leave **dry_run** ticked.
   This is the full dry run: the Rust compatibility gate, Cargo's
   packaging/build verification for every publishable workspace crate,
   and the ordinary native and SDK build jobs remain enabled. Review the
   `release-dry-run-0.2.0` artifact and its source commit. It creates no
   registry version, tag or GitHub Release.
2. Confirm all six existing crates already trust `Netizine/sourceorrery`,
   workflow `release.yml`, with the environment field empty. They use
   OIDC even if their *Only allow trusted publishing* setting is enabled.
3. In [crates.io API tokens](https://crates.io/settings/tokens), create a
   short-lived token restricted to creating new crates (`publish-new`),
   scoped to exactly `sourceorrery-provider-vault`,
   `sourceorrery-provider-aws` and `sourceorrery-provider`. Store it as the
   repository Actions secret **CRATES_BOOTSTRAP_TOKEN** through GitHub's
   secret entry form. Do not put it in a workflow input, command line,
   committed file or chat. It does not need access to publish core.
4. Run **Release** again from the same reviewed commit, version `0.2.0`,
   **bootstrap_providers** ticked and **dry_run** unticked. After the same
   full build and checks, the workflow creates the `v0.2.0` tag and GitHub
   Release and runs the ordinary registry jobs. The crates.io job publishes
   core through its existing OIDC trust, the three real provider crates
   using the temporary token, then the remaining workspace crates through
   OIDC. Already-published exact versions are skipped. All packages retain
   version **0.2.0**; no second full release is needed to finish this flow.
5. Add both trusted-publisher configurations listed above to each new
   provider crate. Revoke the temporary token on crates.io and delete
   **CRATES_BOOTSTRAP_TOKEN** from the repository. Optionally enable
   *Only allow trusted publishing* on all three. These are registry
   settings: enabling them requires no new package version or release.
   Leave **bootstrap_providers** unticked on future ordinary releases.

#### First publication of the Azure Key Vault provider

`sourceorrery-provider-azure` is new and not yet on crates.io, so the first
release that contains it needs the same initial publication; it is the only
name in `PROVIDERS` of `scripts/release/publish-crates.py`, the crates the
bootstrap step publishes with the temporary token. Every other crate,
including the three providers published in 0.2.0, uses OIDC. Keep
**CRATES_BOOTSTRAP_TOKEN** until then, or create a new `publish-new` token
scoped to exactly `sourceorrery-provider-azure` for that run.

1. Dry-run the release with **bootstrap_providers** ticked, as above.
2. Run it for real with **bootstrap_providers** ticked: core through OIDC,
   `sourceorrery-provider-azure` with the temporary token, then the remaining
   workspace crates, `sourceorrery-provider` among them, through OIDC.
3. Add both trusted-publisher configurations to `sourceorrery-provider-azure`,
   revoke the temporary token, delete **CRATES_BOOTSTRAP_TOKEN**, and remove
   the name from `PROVIDERS`. Later releases leave **bootstrap_providers**
   unticked.

The Git push, dry-run dispatch and real dispatch are separate actions;
only the real dispatch publishes. If a registry job fails after the GitHub
Release exists, use **Release packages** for `v0.2.0` as described below,
first with **dry_run** ticked. That workflow has the same initial-provider
option for any provider publication still missing. Do not change already
published package contents or move the tag to resume an upload.

For a local packaging check, with no credentials or uploads:

```bash
python3 scripts/release/publish-crates.py 0.2.0 --group bootstrap
python3 scripts/release/publish-crates.py 0.2.0
```

The helper defaults to dry-run. Only `--publish` permits uploads; the
workflow supplies the appropriate credential separately for core and
the new provider names.

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

**Homebrew tap and Scoop bucket** (`Netizine/homebrew-sourceorrery`,
`Netizine/scoop-sourceorrery`): the release job commits
`Formula/sourceorrery.rb` to the tap and `bucket/sourceorrery.json` to the
bucket, both rendered from the release's `SHA256SUMS`. Users run
`brew install Netizine/sourceorrery/sourceorrery` and
`scoop bucket add sourceorrery https://github.com/Netizine/scoop-sourceorrery`
then `scoop install sourceorrery`. The manifest also carries `checkver` and
`autoupdate`, so a bucket that runs Scoop's Excavator would follow releases
by itself; the job keeps it current either way.

1. The two repositories, each with a licence and nothing else needed.
2. A fine-grained personal access token (*Settings → Developer settings →
   Fine-grained tokens*) limited to those two repositories with
   *Contents: read and write*, saved as the repository secret
   `PACKAGING_TOKEN`. Set an expiry and note it. An absent secret skips
   the job; an expired token or missing repository permissions fails it.
   If GitHub returns `403`, check access to both repositories and the
   token's *Contents: read and write* permission before retrying.

**WinGet** (`Netizine.SourceOrrery`): the release job renders the three
manifests (`version`, `installer`, `defaultLocale`, manifest schema 1.12,
installer type `zip` with a `portable` nested installer) and runs
`wingetcreate submit`, which forks `microsoft/winget-pkgs` under the
token's account and opens a pull request there. The first submission of a
package and every version after it go through that repository's automated
validation and, for a new package, a moderator; a version is installable
once its pull request is merged, usually within a few days.

1. A classic personal access token with the `public_repo` scope (a
   fine-grained token cannot open a pull request on a repository you do not
   own), saved as the repository secret `WINGET_TOKEN`.
2. `wingetcreate` creates the fork on first use. For the first contribution,
   the account holder must also review and accept Microsoft's Contributor
   License Agreement when its policy bot requests it on the pull request.
   The [0.2.0 submission](https://github.com/microsoft/winget-pkgs/pull/460455)
   is awaiting that acceptance and catalog approval.

## Repository controls, as observed

Observed read-only with `gh api` on 2026-10-25 (no setting was changed;
secret values are never read, only their names). A release's safety rests on
these settings as they are, so a protection is claimed here only when it was
seen; recheck them before a release.

| Control | Observed | What it means for a release |
|---|---|---|
| `main` branch rule | required check `CI` only, bound to the GitHub Actions app (id 15368); not strict (an out-of-date branch may merge); no reviews; admins not included; force pushes and deletion refused; no signed commits | a commit on `main` passed `CI`, unless an admin bypassed it |
| Rulesets | none | **tags are not protected**: anyone with write access can create, move or delete `v*` and `bindings/go/v*`; `release.yml` refuses an existing tag but cannot stop one being moved later |
| Release immutability | off | a GitHub Release's assets can be replaced after publication |
| Actions | every action allowed; SHA pinning not required by the repository (zizmor in CI enforces it); default `GITHUB_TOKEN` read-only; Actions cannot approve pull requests | |
| Environments | **none** | the publishing jobs run with no reviewer, branch or tag restriction, and the registry credentials (`CRATES_BOOTSTRAP_TOKEN`, `MAVEN_*`, `NUGET_USER`, `PACKAGIST_*`, `PACKAGING_TOKEN`, `WINGET_TOKEN`) are repository secrets any workflow on any branch can read |
| `release.yml`, `ReleasePackages.yaml` | `workflow_dispatch` only; a real release from **any branch**, with no check that its commit passed `CI` | REC01 and REC02 of the 2026-10-25 review (B26, B27) |
| Dependabot secrets | `FONTAWESOME_NPM_AUTH_TOKEN` only | its pull requests can build the site, nothing else |
| Registry trust (PyPI, npm, crates.io trusted publishers; NuGet trusted publishing) | **not observable from GitHub**: which workflow, environment and branch each registry trusts is set in each registry's account | unknown until each is checked there |

Changes these observations call for, each for its owner to review and make
(none is made by the remediation):

* a ruleset protecting `v*` and `bindings/go/v*` from update and deletion,
  with creation limited to the release workflow;
* a `release` environment with required reviewers, deployments only from
  `main`, holding the registry credentials instead of the repository, and
  the registries' trusted publishers bound to that environment;
* immutable releases on;
* the branch rule applied to admins, and strict status checks.

## Publishing an existing release

`.github/workflows/ReleasePackages.yaml` (*Actions → Release packages →
Run workflow*) publishes the packages of a release that already exists,
for a registry that was set up after the release ran or failed during it.
It builds no new release:

- npm, PyPI and NuGet upload the exact files attached to the release.
- crates.io publishes from the release tag's source.
- Maven Central rebuilds the jar from the tag with the native libraries
  out of the release's jar, because Central needs sources, javadoc and
  signatures, which the release does not carry.
- Packagist and pkg.go.dev upload nothing; they are pointed at the tag.
- The Homebrew tap, the Scoop bucket and WinGet get manifests rendered from
  the release's `SHA256SUMS` with the renderer in the checkout, so a fix to
  the renderer can be applied to an existing release.

Before anything is uploaded, every file is verified against the release
run's own provenance (`scripts/release/verify-release-artifacts.py`): the
release's `SHA256SUMS` must carry a build provenance attestation from
`release.yml` of this repository, on a GitHub-hosted runner, for the commit
the release gate validated (the tag's), and only then is it the
inventory; the downloaded files must be exactly its files for that
registry (none missing, none extra), each with its digest and its own
attestation. The jobs that build from the tag (crates.io, Maven Central)
or tag it (pkg.go.dev) check the tag still names that commit, since tags
are not protected (above). A release without provenance, built before
attestations, is refused: publish a new version instead, or have its files
reviewed separately; there is no switch that skips the check. A dry run
verifies the same way.

Inputs: the tag (empty means the latest release), **dry_run** (on by
default), one tick box per registry, and **bootstrap_providers** for the
initial publication of the three provider crates. Every registry's files are
checked before anything is uploaded, a version a registry already has is
skipped, and npm, NuGet, Maven Central and Packagist are skipped while
their variable or secrets are missing; a ticked crates.io or PyPI box
publishes using its configured trust (with the temporary provider-token
exception above). A dry run checks every ticked
registry, with or without secrets, and uploads nothing.

For a partially completed 0.2.0 release, select `v0.2.0` and the failed
registries, run a dry run, then dispatch again with **dry_run** unticked.
If new provider crates still need their first publication, tick both
**crates** and **bootstrap_providers**, retaining the temporary
**CRATES_BOOTSTRAP_TOKEN** until those uploads finish. If the providers
are already published and configured for trusted publishing, leave the
provider option unticked. The job uses the release tag's sources and skips
existing exact versions, so recovery does not require 0.2.1.

## What each registry page shows

Each package's page is written for someone who has just found it there:
what the package is, that vaults are created and secrets stored with the
CLI (no SDK installs it), and where the documentation is. Change the
text in its source:

| Page | Text comes from |
|------|-----------------|
| crates.io, each crate | `crates/<crate>/README.md` (the `readme` key in its `Cargo.toml`), plus `description`, `keywords` and `categories` |
| PyPI | `bindings/python/README.md` and `description` in `bindings/python/pyproject.toml` |
| npm, `@sourceorreryai/sdk` | `bindings/node/README.md` and `description` in `bindings/node/package.json` |
| npm, the six platform packages | `scripts/release/npm-platform-packages.py`, which the release runs after `napi create-npm-dirs` regenerates `bindings/node/npm/<platform>/` |
| NuGet | `bindings/dotnet/README.md` (`PackageReadmeFile`) and `Description` in `SourceOrrery.csproj` |
| Maven Central | `name`, `description` and `url` in `bindings/java/pom.xml`; the javadoc's package overview is `package-info.java` |
| pkg.go.dev | `bindings/go/README.md` and the package comment in `sourceorrery.go` |
| Packagist | the repository's root `README.md` (Packagist reads a GitHub repository's README, whatever `composer.json` says) and `description` in `composer.json` |
| GitHub Release | the *Release notes* step of `release.yml`; the CLI archives carry `crates/sourceorrery-cli/README.md`, the C ABI archives `scripts/release/ffi-archive-README.md` |

Registries take the text from the version they publish, so a change shows
up with the next release; Packagist alone re-reads the root README
whenever it updates the package.

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
gh attestation verify sourceorrery-X.Y.Z-x86_64-unknown-linux-gnu.tar.gz --repo Netizine/sourceorrery
```

The `release` job attests the build provenance of every file it attaches
(`actions/attest-build-provenance`, with `id-token` and `attestations`
permissions on that job only), in real releases only: an attestation is
public and permanent, so a dry run makes none. **Release packages**
re-uploads files the release already carries and attests nothing new.
What each registry adds on top (npm provenance, the Maven Central
signatures, nuget.org's repository signature) and how a user checks it is
in [Supply chain](supply-chain.md); signing the binaries themselves is on
the [roadmap](roadmap.md#supply-chain).
