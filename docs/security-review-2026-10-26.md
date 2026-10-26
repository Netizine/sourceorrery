# SourceOrrery security audit — 2026-10-26

## Decision and scope

**Fifteen findings are confirmed and fixed on branch
`windows-static-crt`; none is above medium.** Three are medium: the PyPI
job of the package retry workflow ran an unpinned tool while holding the
trusted-publishing identity; the Node SDK, installed without its platform
package, ran a module another Windows account could plant in
`C:\node_modules`; and the C ABI tarballs, installed system-wide as the
SDK guides said, belonged to whichever local account had the CI runner's
uid. The rest are low. Eighteen candidates need a validation that could
not be made on this machine (another OS, a second account, a hosted
GitHub or registry fact, a real provider); they are listed with what
would settle each, and five of them got a hardening change anyway. Four
were rejected.

- Audited `windows-static-crt` at **`f40b2d6`** (0.3.0 plus the static C
  runtime change), the whole repository: core, crypto, storage, CLI and
  its screens, the Rust client, the C ABI, every binding, the provider
  adapters, the conformance suites, the workflows and release scripts,
  the site and the agent skills. Earlier reviews
  ([25 October](../SECURITY-REVIEW-2026-10-25.md),
  [validation ledger](security-remediation-validation.md),
  [archive](security-review-archive-2026-10.md)) were read first; a fixed
  item is not reported again unless its code changed.
- Method: the security-audit skill, `standard` profile. Reconnaissance
  built a coverage ledger (surface × boundary × attack class), 75 units
  in the end; four hunter waves covered every unit, each followed by a
  coverage critic whose accepted gaps became the next wave's units. Every
  candidate went to a fresh verifier, which could confirm only on a
  bounded local observation, and every confirmed or open record was then
  checked again by another fresh verifier (corrections applied, and a
  changed root cause checked by a third). The run's records (ledger,
  candidates, verifier records, artifacts) are kept outside the
  repository.
- Hunters and verifiers read source only. The decisive observations were
  made by the parent as repository tests on the owner's machine:
  `SOURCEORRERY_KEYRING=off`, temporary homes, recovery keys,
  `MemoryStore`, loopback stand-ins for the providers, synthetic values.
  To show a bug in the audited code, the fix's file was put back byte for
  byte to `f40b2d6` while the new test ran, then restored. No real vault,
  credential store, cloud account or registry was used; nothing was
  pushed, published or dispatched.
- Severity is the skill's (likelihood and impact, then overall), not the
  P1–P3 scale of the 25 October review. Same-user processes, holders of
  the vault key or recovery key, and the threat model's known gaps are
  out of scope by definition.

## Findings at a glance

| ID | Severity | Finding | Evidence | Status |
|---|---|---|---|---|
| SA01 | Medium | The PyPI job of `ReleasePackages.yaml` ran `pipx run twine` (newest twine and dependencies) while holding `id-token: write` | Workflow as written | Fixed |
| SA02 | Low | After an audit acknowledgement, an edited row before it was never checked, so an older checkpoint could be emptied and a row put back | Reproduced | Fixed |
| SA03 | Low | An open `Routed` (the browser) kept a connection's old address and credentials after the connection changed | Reproduced | Fixed |
| SA04 | Low | A second rotation during a pending retirement dropped it: the old credential's `retire` hook never ran | Reproduced | Fixed |
| SA05 | Low | The loopback check took any host beginning `127.` or `localhost` for this machine, so `http://` could go to a DNS name | Reproduced | Fixed |
| SA06 | Low | The setup screens committed against a view check that changed after it was passed | Reproduced | Fixed |
| SA07 | Low | `import` printed `.env` text before `=` as a key, value text included | Reproduced | Fixed |
| SA08 | Low | The rotation issue hook took the secret's variable from the CLI's environment when the vault had no current value | Reproduced | Fixed |
| SA09 | Low | An oversized `retire_after` panicked every manifest reader | Reproduced | Fixed |
| SA10 | Low | `cargo-auditable`, `cargo-cyclonedx` and maturin ran at whatever version was newest when a release was cut | Workflow as written | Fixed (wingetcreate open) |
| SA11 | Low | `dependency-audit.py --strict`, documented to stop a release, was never run | Workflow as written | Fixed |
| SA12 | Low | A change to the site's npm dependencies counted as documentation, so the dependency audit was skipped | Reproduced (classifier) | Fixed |
| SA13 | Medium | The Node SDK's generated loader, without its platform package, ran a module found in any parent `node_modules` (on Windows, `C:\node_modules` is writable by every account) | Reproduced (stand-in parent, drive ACL observed) | Fixed |
| SA14 | Low | The AWS SDK's automatic retries repeated a write whose answer was lost; a refused repeat made the adapter restore the old, looser policy on the version just published | Reproduced (loopback model) | Fixed |
| SA15 | Medium | The unix release tarballs recorded the CI runner's account; the guides' `sudo tar xzf` into `/opt/sourceorrery` restored it, so the local account with that uid owned the C ABI library every documented build loads | Reproduced (containers) | Fixed |

Needs validation, rejected and hardening are after the details.

## Confirmed findings

### SA01 — Unpinned `twine` ran in the job holding the PyPI publishing identity (medium)

**Location:** `.github/workflows/ReleasePackages.yaml:307–358` at `f40b2d6`
(job `pypi`: `permissions: id-token: write`, step *Check the
distributions*, `pipx run twine check --strict dist/*`).

`pipx run` resolves twine and its dependency tree from PyPI at their
newest versions, with no version, hash or lock, in the same job that
trades its OIDC token for a PyPI upload token and then uploads `dist/` by
path. A compromised twine (or dependency) release could mint the
publishing identity (PyPI, and the other registries that trust
`ReleasePackages.yaml` with an empty environment, per `docs/release.md`)
or replace the verified files before the upload. The job ran in dry runs
too. This contradicts the supply-chain rule that a dependency changes
only in a reviewed lock-file commit.

**Fix:** the job is split. `pypi-check` downloads and verifies the files
against the release's provenance and runs twine; it has no `id-token` and
uploads nothing. `pypi` runs only in a real run, downloads and verifies
the files itself and runs nothing but `gh`, the verifier and the
SHA-pinned publish action (which checks metadata itself). Lint:
actionlint 1.7.7 reports nothing new.

### SA02 — Rows before the newest acknowledgement were never authenticated (low)

**Location:** `crates/sourceorrery-storage/src/sqlite/audit.rs:418–441`
(`chain_problem` walks from the newest acknowledgement only).

Since schema 3 the chain also records the newest checkpoint of each row's
state. Once a truncation was acknowledged, the unlock walked only the rows
after the acknowledgement, but rows before it still decide which
checkpoint is newest. A file writer (the threat model's tamperer) could
empty the checkpoint of an event before the acknowledgement and put back a
secret's earlier, authentic version row (a version re-enabled after it was
disabled), and the vault opened and served it.

**Trigger and result:** `a_checkpoint_hidden_after_an_acknowledgement_is_still_refused`
(conformance security suite): set a value, keep its row, disable it, cut
the log's last row, acknowledge, put the old row back and empty the
disable event's checkpoint. At `f40b2d6` the vault opened and
`get_secret` returned the value; now the unlock is refused.

**Fix:** every keyed row before the newest acknowledgement must still
verify against the predecessor hash it stores, unless an authentic
acknowledgement accepted it as it stands. A detection lists the rows that
do not verify (`; unverifiable rows <id>:<8-byte keyed digest>, …`), the
acknowledgement repeats them, and an acknowledgement is refused when a
row that does not verify is not in a pending detection (that refusal
records a detection first). A listed row edited again changes its digest
and breaks the chain again. Tests: the scenario above, a forged
checkpoint row, and a listed row edited after its acknowledgement. The
schema is unchanged; a vault whose acknowledged history already holds an
edited row is refused once and opens again after `audit --acknowledge`
([vault format](vault-format.md#acknowledging-a-truncation)).

### SA03 — A connection changed elsewhere kept being used as it was (low)

**Location:** `crates/sourceorrery-provider/src/routed.rs:223–237`
(`Routed::client` caches by connection id only) and `:254–264` (`at`).

`Routed` opened each connection's client once and kept it for its life;
the dispatch gate checked that the connection row existed and verified,
not that it was the row the client came from. The browser holds one
`Routed` per open vault and runs the setup screens in-process (`c`); after
they moved a connection to another address or replaced its credentials,
listings, new values typed at the hidden prompt and other changes still
went to the old address with the old credential, and the audit recorded
them at the connection that now named the new one. A long-lived SDK
reader had the same staleness for changes made by another process.

**Trigger and result:** `a_connection_changed_elsewhere_is_opened_again_before_its_next_call`
(`crates/sourceorrery-provider/tests/routed.rs`): a second handle moves a
Vault connection to another address and drops its token; at `f40b2d6` the
next write and listing went through the client opened from the old
address with the token.

**Fix:** `SqliteVault::preflight_at_connection` returns the revision (the
row's tag) of the connection it verified, and `Routed` keeps each client
with the revision it was opened from, reopening when they differ.
Settings, credentials and revision come from one verified read
(`SqliteVault::connection_to_open`), so a change in between cannot pair
one state's address with another's credential.

### SA04 — A rotation during a pending retirement dropped it (low)

**Location:** `crates/sourceorrery-core/src/rotation.rs:264–319`
(`issue`), `:403` (`activate`); `crates/sourceorrery-cli/src/commands/rotate.rs:203`.

The only record that a superseded version still owes retirement (whose
`retire` hook revokes it at the issuer) is the `previous` tag of the
active version. `issue` refused only a validated candidate, so a second
rotation inside the grace period, or after a failed retire hook, made the
active version the new candidate's `previous`; activation then marked it
superseded, and nothing pointed at the first version again. A credential
rotated out (often because it leaked) kept working at the issuer while
the tool reported nothing pending.

**Trigger and result:** conformance scenario
`rotation_waits_for_the_version_it_must_retire`: at `f40b2d6` the second
`issue` returned `Ok` with the earlier retirement pending.

**Fix:** `rotation::ready_to_issue` refuses (code `rotation`, naming both
versions) while an active version's predecessor is not retired; `issue`
and the CLI call it before the issue hook mints anything. Tests: the
scenario (refused inside and after the grace period, allowed after
retire) and `rotation_waits_for_the_pending_retirement` in the CLI suite.

### SA05 — `http://` accepted for DNS names beginning `127.` or `localhost` (low)

**Location:** `crates/sourceorrery-core/src/connection.rs:380`
(`is_loopback_url`).

The check compared text prefixes, so `http://127.attacker.example`,
`http://127.0.0.1.nip.io` and `http://localhost.example.com` passed as
this machine. A Vault address or AWS endpoint so written sent tokens,
signed requests and values in clear text off the machine, and the Vault
client turned its proxy off for it.

**Trigger and result:** `clear_text_goes_only_to_names_that_are_this_machine`
(core): at `f40b2d6` the first DNS name was accepted.

**Fix:** the host is parsed: `localhost` (any case), an IPv4 literal that
`Ipv4Addr` parses as loopback, or a bracketed `::1`, then only an
optional port. Every DNS name is refused.

### SA06 — The setup screens committed past a view check changed after it was passed (low)

**Location:** `crates/sourceorrery-cli/src/ui/setup/backend.rs:241`
(`Live::commit`), `crates/sourceorrery-storage/src/sqlite/settings.rs:55`.

The screens decide once, when they open a vault, whether its settings may
change; the review can be committed any time later. A view check set,
replaced or strengthened through another handle in between was ignored:
the commit could replace the recovery key (which passes the new check by
itself) or clear an authenticator enrolled later. The 25 October review's
SR11 class, on the settings path.

**Trigger and result:** `a_view_check_set_elsewhere_after_opening_refuses_the_commit`
(setup tests): at `f40b2d6` the commit reached *Done* after a password was
set elsewhere.

**Fix:** `SqliteVault::view_identity` names the check in force (the sealed
password and authenticator, not their counters), the screens record the
one they passed or found absent, and `change_settings_if` refuses with
`permission_denied` inside the commit's transaction when the stored check
is another. A vault opened with its recovery key is not bound. The view
check is still not a same-user boundary (known gap 11).

### SA07 — `import` echoed `.env` text before `=` (low)

**Location:** `crates/sourceorrery-cli/src/dotenv.rs:123` (any text before
`=` is a key), `crates/sourceorrery-cli/src/commands/import.rs:159, 221`.

A malformed line, such as a credentialed connection string or the end of
wrapped base64 on a line of its own, became an assignment whose "key" was
value text, and `import` (with or without `--dry-run`, table or JSON, and
its errors) printed it. The migrate-env skill tells agents to learn key
names from exactly this output.

**Trigger and result:** `import_never_shows_text_before_equals_that_is_not_a_variable_name`
(integrations suite): at `f40b2d6` the duplicate-key error printed the
canary.

**Fix:** only text shaped like a variable name is shown; anything else,
and a key whose value is only `=` padding, is `(not shown)` in the table,
JSON and errors, and skipped. Residual: a name-shaped base64 tail with a
single `=` looks exactly like an empty assignment; it is skipped as empty
and never stored, but its key is listed.

### SA08 — The issue hook took an inherited value for the secret's variable (low)

**Location:** `crates/sourceorrery-cli/src/commands/rotate.rs:92–139`
(`run_hook`), `:203–221` (`rotate_now`).

The 25 October fix SR10 made `run` remove every declared variable before
setting the resolved ones; the rotation hooks were judged unaffected (B16)
but do receive the secret's variable. When the current version could not
be read (disabled, expired, deleted), the issue hook ran with whatever
the shell held under that name and minted the new credential from it.

**Trigger and result:** `a_hook_never_takes_an_inherited_value_for_the_vaults`
(CLI suite): at `f40b2d6` the rotation succeeded with a value derived from
the inherited `DATABASE_PASSWORD`.

**Fix:** the hooks' environment loses the secret's variable,
`SOURCEORRERY_VERSION` and `SOURCEORRERY_RETIRED_VERSION` before the
vault's are set, and only not-found, disabled, expired and deleted run the
issue hook without a current value; any other failure stops the rotation.
B16's note in the validation ledger is corrected.

### SA09 — An oversized grace period panicked manifest readers (low)

**Location:** `crates/sourceorrery-core/src/rotation.rs:112` (`parse_grace`).

`retire_after = "999999999999999d"` (or `--retire-after`) overflowed while
the duration was built, panicking `check`, `run`, the SDKs and the C ABI
on a repository's manifest. **Fix:** checked arithmetic, at most `3650d`,
otherwise `invalid_argument`; `activate` uses `checked_add`. The grace
test has the cases.

### SA10 — Release build tools at the newest upstream version (low)

**Location:** `.github/workflows/release.yml:217, 302, 404–415`.

`cargo install --locked cargo-cyclonedx` / `cargo-auditable` and both
maturin-action steps took whatever was newest on release day, in jobs
whose outputs are attested and shipped. **Fix:** `cargo-cyclonedx 0.5.9`,
`cargo-auditable 0.7.7` and `maturin-version: v1.15.0` (the version
`bindings/python/ci-requirements.txt` pins). `wingetcreate`, which runs
with the WinGet token, came from `https://aka.ms/wingetcreate/latest`;
both workflows now download the 1.12.13.0 release asset and refuse it
unless its SHA-256 is the one GitHub records for that file
(`24042bd3…bd9ffea`).

### SA11 — The strict dependency audit was never run (low)

`docs/supply-chain.md` says an unreviewed RustSec maintenance notice
fails a release (`--strict`), but no workflow ran `dependency-audit.py
--strict`. **Fix:** the release preflight installs the pinned `cargo-audit
0.22.2` and Node 24 and runs it; a dry run reports instead of stopping.

### SA12 — Site dependency changes skipped the dependency audit (low)

**Location:** `scripts/ci/classify-changes.sh` (`site/*` is documentation).

A Dependabot bump of `site/package-lock.json` was classified docs-only, so
CI skipped every job including the dependency audit, and the deployed
site's build then used the new packages. **Fix:** the classifier also
outputs `deps`, true for code and for any lock file, package manifest or
`.npmrc` that would otherwise count as documentation (by file name, the
names the audit's inventory check looks for, so a graph added under
`docs/` or `site/` later is caught too), and the audit job runs when
`code` or `deps` is true. Checked on commit `1770287` (a site npm bump):
`deps=true` now, `docs` before; shellcheck is clean.

### SA13 — The Node SDK ran a module planted in a parent `node_modules` (medium)

**Location:** `bindings/node/lib/index.js:7` requires the napi-rs
generated `index.js` (built in CI, not committed); its fallbacks
`require('@sourceorreryai/sdk-<platform>')` and
`require('@sourceorreryai/sdk-wasm32-wasi')` by bare name.

When the platform package is missing or fails to load (32-bit Node on
Windows, for which none is published while the main package installs
anyway; `--omit=optional`; a lockfile without the entry), the loader's
bare-name requires search every parent directory's `node_modules`. On
Windows any authenticated user can create `C:\node_modules` (the default
drive-root ACL, observed with `icacls C:\`), so another account's module
ran inside the process and became the SDK's binding, which is handed the
recovery key. On macOS the generated loader asks for the never-published
`@sourceorreryai/sdk-darwin-universal` first, on every load, so even a
default install reaches the search there; a project under a shared
directory such as `/tmp` or `/Users/Shared` is exposed (read from source,
not run on macOS).

**Trigger and result:** a project laid out from `f40b2d6`'s package and
the generated loader, with no platform package and a decoy only in a
parent `node_modules` outside the project: the decoy ran and was adopted,
under the platform package's name and under the never-published WASI
name; without it the require threw. The 0.3.0 tarball's own loader
(generated by `@napi-rs/cli` 3.10.9) and a second OS account were not
run.

**Fix:** `bindings/node/lib/native.js` loads the addon by absolute path
only: the file a local build leaves in the package, or the platform
package beside the SDK or inside it. No bare name, no WASI fallback, no
`NAPI_RS_*` variables; a missing addon fails naming the package. The
generated `index.js` is still built and shipped, unused (the package's
`exports` keep it out of reach). `__test__/loader.test.mjs` plants a
module under every name in a parent `node_modules` and checks it never
runs, and that the platform package beside the SDK loads; with
`lib/index.js` at `f40b2d6` the first test fails. **Follow-up:** stop
generating and shipping the unused loader, and give the main package
`os`/`cpu` fields so an unsupported platform fails at install.

### SA14 — AWS SDK retries turned a published write into a "refusal" (low)

**Location:** `crates/sourceorrery-provider-aws/src/lib.rs:252–288`
(`sdk_config` keeps the SDK's default retries), `:450–485`
(`put_existing`).

The SDK retried every operation up to three times. A `PutSecretValue` the
service applied but whose answer was lost (a 500, a reset) was sent
again; when the repeat was refused, `put_existing` took that for "nothing
published" and removed the narrowed policy while the new version was
current, so a version written disabled became readable, and the vault
recorded the write as refused rather than `outcome_unknown`. This broke
ADR 0011 ("nothing is retried"). The repeat's refusal against the real
service needs an independent cause (revoked credentials, an IAM change, a
delay past the signing window); that was modelled, not observed.

**Trigger and result:** `a_change_whose_answer_was_lost_is_never_sent_again`
(AWS publication model, with an exact-occurrence fault schedule): at
`f40b2d6` the SDK sent `PutSecretValue` twice and the disabled tag was
removed while the new version was current.

**Fix:** `RetryConfig::disabled()` on the loader, which also wins over
`AWS_MAX_ATTEMPTS` and a profile; a failure is returned as it is. The
same root cause on Azure (the SDK's default retries on delete, recover
and purge) is open below.

### SA15 — The C ABI install belonged to the account with the runner's uid (medium)

**Location:** `.github/workflows/release.yml:333–334` (plain `tar -czf` on
the runner); `docs/sdks/c.md:58, 70`, and the same command in the C++, Go
and PHP guides (`sudo tar xzf … -C /opt/sourceorrery`).

The unix release archives recorded the runner's non-root account (the
Linux job itself needs `sudo`), and the guides installed the C ABI
system-wide by extracting the archive as root, which restores the
archived owner. On a shared Linux machine the library and headers every
documented C, C++, Go and PHP build loads (rpath, `LD_LIBRARY_PATH`,
`DYLD_LIBRARY_PATH`, `SOURCEORRERY_NATIVE_DIR`) belonged to whichever
local account had the runner's uid, 1001 on GitHub's Ubuntu runners and
the second human account by default; it could rewrite them and run code
in every other user's SDK process, root's included. The CLI's own install
(`sudo install`) was not affected; on macOS uid 501 is usually the first
admin account already.

**Trigger and result:** in network-less Debian containers, an archive
packed as uid 1001 the way the release did and extracted as the guide
said left `/opt/sourceorrery/libsourceorrery_ffi.so` owned 1001:1001 and
writable by that account (not by another); packed with root ownership it
was 0:0. The uid in the published 0.3.0 archives was not listed (it
needs a download) and macOS `bsdtar` was not run.

**Fix:** the archives are packed root-owned (GNU tar
`--owner=0 --group=0 --numeric-owner`, bsdtar `--uid 0 --gid 0`) and the
step refuses one with a member that is not root-owned or is writable by
group or others; the four guides extract with `--no-same-owner`, which
also installs the already-published 0.3.0 archives root-owned (checked).
On a shared machine an existing install is put right by emptying
`/opt/sourceorrery` and extracting a `SHA256SUMS`-checked archive again
with `--no-same-owner`; a `chown -R root:` alone would keep any change the
account with that uid already made.

## Needs validation (open)

Each was traced in source and survived verification, but the decisive
fact could not be observed here. The run records give each a validation
plan.

| Candidate | What would settle it |
|---|---|
| Manifest discovery has no ownership bound on Windows (known gap 15 now documents it) | A `sourceorrery.toml` owned by another SID in a parent folder; the fix needs a Windows owner check, which `sourceorrery-os` (ADR 0010: one function) does not hold today — a decision for the owner |
| Unix discovery checks ownership through symlinks and is not bound to the file it reads | A Linux run as root with a second uid |
| macOS: `create_private_new` checks mode bits only; an inherited directory ACL may expose a new recovery-key file | A macOS run |
| `vault export` reserves its output, closes it, and SQLite reopens the name | A second account writing a non-sticky output directory |
| Go, C and C++ on Windows import `sourceorrery_ffi.dll` by name while the docs put it on `PATH` (the current directory is searched first) | A Windows run with a planted DLL; placing the DLL beside the executable avoids it |
| `init --integration` and the manifest save write through symlinks committed in a repository | A run with symlink rights (not available on this machine) |
| Release jobs restore Actions caches that CI and coverage jobs write | setup-java's cache key, decided inside the action |
| `ReleasePackages.yaml` dry runs execute the selected tag's code in jobs holding `id-token: write` and the Maven signing key | Who can create tags and dispatch, and the registries' trusted-publisher settings. Since addressed in the workflow: a dry run refuses a tag whose commit is not on `main` (`--require-main`) and never imports the signing key |
| Publishing identity and secrets are not bound to an environment; the from-main check is in the dispatched file | The same hosted facts. The publishing jobs now run in the `release` environment (dry runs in `release-dry-run`); limiting it to `main`, moving the secrets into it and naming it on each trusted publisher are repository and registry settings (`docs/release.md`, "The release environment") |
| The release gate names `main` by short name (a tag named `main`, run by a dispatch or by its own tag-push trigger) | How GitHub's API resolves `main` with such a tag, and the `head_branch` it reports for such runs |
| The Static Web Apps deploy skipped Dependabot by the event's actor, so a maintainer's reopen or "Update branch" on a Dependabot PR built its unmerged dependencies with the Font Awesome and deployment tokens | Whether GitHub gives such a run the Actions secrets, and what the deploy action exposes to the build; the guard now checks the PR's author, as `coverage.yml` does (hardening, committed) |
| AWS reads apply tags read before a version listed later | A loopback model test interleaving a write between the two reads |
| Provider version ids are recorded in the audit chain with no length bound | A planted-client test; the AWS and Azure SDKs' acceptance of such replies |
| HashiCorp Vault: `custom_metadata` keys for pruned versions are never removed (64-key limit) | Upstream Vault's limit check on merged metadata |
| Azure: the SDK's default retries re-send delete, recover and purge; a landed change can be recorded as refused | A mock-transport adapter test (SA14's AWS fix shows the shape: no SDK retries) |
| Azure: the SDK's developer-tools credential ran `cmd /C "cd %SYSTEMROOT% && az …"` in the caller's working directory, so from a folder on a second drive an `az` there could run first, with the unlock variables | cmd.exe's search on a non-system drive, not run here; the helpers now start in the system directory without those variables (hardening, committed) |
| `secret rotate --step status` printed provider version ids without escaping | A loopback provider returning a crafted id; the lines are now escaped anyway (hardening) |
| ADR 0006 named the npm scope `@sourceorrery`, which the project does not use | Whether that scope is held; the ADR now names `@sourceorreryai` |

## Rejected

- **`-vvv` prints AWS request bodies.** The SDK's trace of each request
  runs after its stalled-stream interceptor has boxed the body
  (`SdkBody { inner: BoxBody }`); a loopback run under `-vvv` and
  `SOURCEORRERY_LOG=trace` showed no value. The new CLI test keeps it so.
- **HashiCorp Vault: purge and re-create between two requests of a
  write.** Only a principal that writes the secret's metadata can do it,
  and known gap 13 treats that principal as administering the policy.
- **Azure: a new secret becomes a new version of an existing Key Vault
  secret.** The user's own write, with their own Key Vault rights, to the
  storage they named; adding a version is the contract.
- **SDK `OpenOptions` print the recovery key in their default string
  form.** No SourceOrrery code formats them; application logs are the
  caller's (guarantee 1). Redaction parity with Rust is a hardening item.

## Hardening noted, not fixed

- The wizard's connection test is not recorded as `connection_test`
  (`ui/setup/backend.rs`), though `docs/cli.md` says it is.
- Stored credentials follow a connection's id, not its address: changing
  the address keeps them, and the wizard tests kept credentials against
  unsaved settings.
- An AWS prefix without a separator (`myapp`) overlaps another
  (`myappx`).
- `audit export --format otlp` follows redirects and allows plain
  `http://` to any host; its errors echo the endpoint and a malformed
  header.
- The Node SDK's generated loader is still built and shipped, now unused
  (SA13): stop generating it (`napi build --no-js`), and give the main
  package `os`/`cpu` fields so an unsupported platform fails at install.
- The HashiCorp Vault adapter's messages say a version "is held at least
  as restricted as asked" without re-reading it.
- `WINGET_TOKEN` is a classic `public_repo` token of the account that
  owns this repository, so it can also push tags and change release
  assets here; a separate account that owns the `winget-pkgs` fork would
  confine it. (`wingetcreate` itself is now pinned, SA10.)
- The Static Web Apps step gives the Font Awesome token to the whole
  build, not only to the install as `docs.yml` does; building in an
  unprivileged job and deploying the artifact would separate them.
- The macOS `libsourceorrery_ffi.dylib` sets no `@rpath` install name, so
  a program linked against it may record the build machine's path.
- `check-pe-imports.py` refuses known C runtime DLLs (a denylist); an
  allowlist of system DLLs would also catch any new non-system import.
- The SDK guides say to check archives against `SHA256SUMS` but give no
  command, unlike the CLI's getting-started page.
- With the helpers' executor in place (above), `az`/`azd` are still found
  on `PATH`; a `PATH` entry another account writes is the machine's
  configuration, not this program's.

## Coverage and limits

Every one of the 75 units has a closing hunter record with the paths and
checks behind it. The wave-1 critic added five units (release identity,
the Node loader, stored-credential binding, unbounded provider text and
diagnostics), hunted in wave 2; the wave-2 critic added two (the site
deploy's Dependabot guard and the C SDK's library search), hunted in
wave 3; the wave-3 critic added one (how the Azure SDK starts the Azure
CLI), hunted in wave 4. **Coverage is not claimed complete:** the wave-4
critic proposed one more unit, and the audit stopped before hunting it
or running the final-clean critic. That unit is recorded as deferred: it
asks where the AWS adapter's identity comes from when a connection stores
no access key. The SDK's default chain ends at the instance metadata
endpoint over plain HTTP, and a connection binds no account, so on a
workstation without local AWS credentials whatever answers that address
could choose the account that values are written to and read from. It is
a lead for the next pass, not a finding: whether a workstation routes
that address on-link is a network fact, and nothing was checked.

Only the final tree was built and tested (each crate's tests, clippy with
`-D warnings`, the Node loader test, workflow lint); the intermediate
commits were not built one by one. Not covered by observation: macOS and
Linux behaviour beyond the containers above, a second OS account, the
real providers (AWS, Azure, HashiCorp Vault), the hosted repository and
registries, and the 0.3.0 packages as published. The CI provider jobs
and the release dry run are what exercise those, and they were not run
(James dispatches them).

## Commits

The fixes are local commits on `windows-static-crt`, after `f40b2d6`,
not pushed. Each commit holds its fix, its test and its documentation;
the CHANGELOG `[Unreleased]` section lists the user-visible ones.

| Commit | Finding |
|---|---|
| `e672da5` | SA05 loopback by parsed host |
| `708724c` | SA09 bounded grace period |
| `27e7b12` | SA04 rotation waits for the pending retirement |
| `4edac97` | SA08 hooks never take the shell's value |
| `0adf7f3` | rotate status escapes version ids (open lead, hardening) |
| `8d1554e` | SA07 `.env` text before `=` not shown |
| `3afb52f` | SA02 rows before the acknowledgement authenticated |
| `90f8868` | SA06 setup commit bound to the view check passed |
| `fb85231` | SA03 connection client reopened after a change |
| `ccb4449`, `6cbe49c` | SA13 Node addon loaded from the SDK's own install |
| `bceada8` | SA14 AWS SDK retries off |
| `19b2f03` | SA01 twine outside the publishing job |
| `16197ef` | SA10 release tools pinned |
| `30b9ccd` | SA11 strict dependency audit at release |
| `b52cf8a`, `ceba950` | SA12 dependency files run the audit |
| `8f3ff28` | regression test for the rejected trace candidate |
| `266475c` | site deploy's Dependabot guard (open lead, hardening) |
| `1b58fb8` | SA15 root-owned tarballs and `--no-same-owner` |
| `5b5f384` | Azure CLI helpers start in the system directory (open lead, hardening) |
| this report's commit | report, CHANGELOG, ADR 0006, known gap 15 |
