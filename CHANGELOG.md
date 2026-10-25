# Changelog

All notable changes to SourceOrrery are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

**Breaking: vaults from earlier releases are not read.** A vault file of
schema 1 to 4 (schema 4: development builds of `main`) is refused with
`migration_required`, never rewritten: keep the file for the release that
wrote it, recreate the vault with `sourceorrery setup` and set its secrets
again from the old file, as `docs/upgrading.md` describes (ADR 0009, ADR
0010). The format is schema 5.
How a vault opens, what it asks and where it keeps secrets change
together, so the CLI, the Rust API, the C ABI's open options and every
SDK's open options change with them (ADR 0007: a minor release;
`SO_ABI_VERSION` is 2 and `CONTRACT_VERSION` `"2"`, so an SDK refuses a
native library of an earlier release).

### Changed

* **Keys.** A vault's key is kept twice: as this machine's key in the OS
  credential store, managed for you, and under one **recovery key** (125
  bits), shown once when the vault is made. It opens the vault anywhere
  else (WSL, a container, CI, another machine, an exported copy):
  `SOURCEORRERY_RECOVERY_KEY`, `--recovery-key-file` /
  `SOURCEORRERY_RECOVERY_KEY_FILE`, or a prompt. Passphrase protectors,
  recovery codes, `SOURCEORRERY_PASSPHRASE` and `--passphrase-file` are
  gone. The SDKs take `recovery_key` and `recovery_key_file` options (C:
  `so_reader_open(name, options_json, recovery_key, ..)` with
  `{"home", "recovery_key_file", "environment"}`) and never prompt.
* **The view check** replaces the reveal guard and the second factor: an
  optional password (Argon2id, with a hint) and an authenticator app's
  code on top, asked before a person views the vault or reveals a value
  (`ui`, `secret list`, `secret get`, `secret versions`, `audit`). It is a
  check, not encryption: `run`, `check`, `init` and every SDK never ask
  it. `SOURCEORRERY_PASSWORD`, `--password-file` and `--code` /
  `SOURCEORRERY_TOTP` answer it; a refusal is `permission_denied`, and
  repeated wrong answers wait longer each time. Its records are part of
  the vault's settings, which the audit chain checkpoints like a secret's
  rows, so a vault whose settings were replaced by an older copy (to
  switch the check off, say) refuses to open.
* **Storage per secret.** A vault keeps each secret in its own file or at
  HashiCorp Vault, AWS Secrets Manager or Azure Key Vault through a
  connection it holds (settings, and credentials sealed under the vault
  key). `secret set` and `import` take `--storage`; every other command
  and the SDKs find the secret where it is. `[vaults.<name>]` manifest
  tables and the per-secret `vault` override are refused with a message
  saying where that moved; a manifest names a vault and its secrets only.
* **Setup on screens.** `sourceorrery setup` (and `vault create NAME`, or
  `c` in the browser, for an existing vault) walks through the name, the
  recovery key, the view check and the storage, testing each connection,
  and commits everything in one transaction at the review.
  `vault create NAME` with flags does the same without a terminal
  (`--recovery-key-out`, `--password-file`, `--no-keyring`, one flag set
  per provider), and `setup --guide` prints that command.
* **`init`** writes or extends `sourceorrery.toml` from the vault's
  catalog: on a terminal, screens to tick secrets (with **All**) and add
  new ones, stored in the vault as they are added; without one,
  `--all` or `--secret NAME`. An existing manifest is edited in place. The
  vault records the project's folder and each secret's description.
* **The browser** (`ui`) shows where each secret is kept, the vault's
  projects (found or missing, `x` forgets one), the view check and the
  connections, adds secrets at a chosen storage (`a`), and opens the setup
  screens (`c`, `n`).
* **Export and import** replace backup and restore: `vault export --out
  FILE` writes a copy that opens with the recovery key only, and
  `vault import FILE` brings it onto a machine, verified, with this
  machine's key added.
* Removed commands: `vault protector`, `vault passphrase`, `vault 2fa`,
  `vault recovery`, `vault guard`, `vault info` (folded into `vault list`
  and the browser's Overview), `vault migrate`, `backup` and `restore`.

### Added

* Azure Key Vault provider (crate `sourceorrery-provider-azure`, feature
  `provider-azure`, part of `remote` and on by default), reached through a
  vault's connection (`vault create --azure-key-vault URL`). It signs in
  with a service principal the connection stores, or the first identity
  the environment provides: a service principal, workload identity
  federation, the Azure CLI or Azure Developer CLI, or a managed identity.
  Properties belong to one version, as in the contract, so rotation works;
  a version's time window can be replaced but not removed
  (`docs/providers/azure-key-vault.md`).
* `Capability::ClearableTimeWindow`: whether `update_secret_properties` can
  remove a version's `not_before` and `expires_on`. The local vault,
  HashiCorp Vault and AWS Secrets Manager report it; Azure Key Vault does
  not, and refuses the removal with `unsupported`.

### Changed

* The HashiCorp Vault provider and `audit export --format otlp` verify a
  server's certificate against the operating system's certificate store
  instead of a bundled copy of Mozilla's, as the Azure provider does
  (`VAULT_CACERT` is trusted in addition). All three providers now share
  one HTTP client (`reqwest` 0.13) rather than carrying two versions. A
  refused certificate's reason is in the Vault provider's error, and the
  CLI no longer prints the TLS verifier's own report of it at the default
  verbosity.
* **Upgrading from 0.2.0** is a guide of its own (`docs/upgrading.md`): the
  old file is kept where 0.2.0 reads it, and each value moves through a
  pipe into a new vault, for local and remote vaults. `migration_required`
  says the file was left unchanged and how to keep it, instead of
  `sourceorrery setup` alone, which failed with "already exists" while the
  old file was in place.
* The install pages name one version, the workspace's, stamped by
  `scripts/release/docs-version.py` and checked in CI and by the release
  workflow; until it is released they say so, and the site header shows it
  as unreleased. Registry install commands are pinned to it. The provider
  guides say the vault's own log records every provider call.

### Security

Fixes from the security review of 2026-10-25
(`SECURITY-REVIEW-2026-10-25.md`; what each closes and how it was tested
is in `docs/security-remediation-validation.md`).

* **Key wraps are authenticated.** The settings record covers every key
  wrap, so a recovery-key wrap put back after the key was replaced, or any
  wrap row added or swapped, makes the vault refuse to open. Replacing a
  recovery key stops that key opening the vault; it does not change the
  vault key (ADR 0010).
* **Recovery-key files are private from the start.** `vault create
  --recovery-key-out` creates the file before the vault, restricted to
  your account and Windows SYSTEM on Windows (checked after creation; a
  volume that cannot keep permissions is refused) and mode `0600` on Unix,
  and syncs it. A key that cannot be delivered, to the file or to stdout,
  leaves no vault behind.
* **A blocked vault calls no provider.** Every call at a connection first
  passes the vault's integrity gate, so a vault whose audit log was cut
  short sends nothing, also through a client opened earlier.
* **A change at a connection says when it may have happened.** It is
  recorded as an attempt (`pending`) before it is sent; a failure other
  than a refusal, or a change the vault could not record, is the new error
  code `outcome_unknown` and the audit outcome `unknown`, and `sourceorrery
  audit` lists the attempts whose result the vault never learned
  (ADR 0011).
* **HashiCorp Vault: a new version is never readable under a looser policy
  than it was written with.** A disabled or not-yet-valid version was
  written before its properties, and stayed readable if the second request
  failed. Its properties now go in first as the writer's intent, the data
  is written with check-and-set, and one merge patch commits them; every
  `custom_metadata` change is a merge patch of its own keys, so two writers
  never drop each other's, and the one that loses a version number is
  refused and writes nothing. A writing token needs the `patch` capability
  on `<mount>/metadata/*` (`docs/providers/hashicorp-vault.md`).
* **AWS Secrets Manager: the same, for one writer at a time.** A new
  version was made current before its tags; now the tags are first
  narrowed to the stricter of the old and new policy, then the value is
  put, then the tags reach the new properties in an order that never
  loosens below them (an update used to remove stale tags first, which
  could enable a secret for a moment). Tags, content types and values the
  service would refuse are refused before any write, `aws:` and
  `sourceorrery:` keys included, and AWS's own `aws:` tags are no longer
  taken for user tags and written back.

### Fixed

* A manifest whose `retire_after` ends in a character longer than one byte
  (`7é`) made the CLI panic, and each SDK's project load fail with an
  internal error; it is refused as an invalid grace period. Found by the
  bounded fuzz tests that now run in CI over the parsers of manifests,
  references, provider replies and vault files.
* The Linux packages (the CLI, the C ABI and the .NET and Java packages that
  carry it, the Node addon) are built on Ubuntu 22.04 and need glibc 2.34
  (Ubuntu 22.04, Debian 12, RHEL 9, Amazon Linux 2023 and the images built
  on them); built on 24.04 they needed 2.39. Every platform's minimum is in the architecture's
  platform matrix.
* Every operation counted the vault's keyed audit rows with a scan of the
  whole log, three times, so reads slowed as their own audit rows
  accumulated (91 ms a read at 100,000 events on a laptop, 22 ms now; a
  listing 128 ms, 18 now). An index serves the count, each check names the
  index it reads, and a vault gets the indexes it lacks when it is
  unlocked. `docs/architecture.md` records what still grows, and why.
* HashiCorp Vault: a reply is read chunk by chunk and stopped at its 8 MiB
  cap; one without a declared length used to be buffered whole first.
* HashiCorp Vault: an update made on a machine whose clock trails the Vault
  server's no longer reports an `updated_on` earlier than the version's
  `created_on`.

* A refused change of the view check (an empty password, a hint that gives
  it away, work factors past the limits, an authenticator step refused for
  a corrupt record) is recorded in the audit log like every refused
  operation, by its code alone.
* The view check is decided on the vault's current settings: a password
  or an authenticator another process set after a handle opened the vault
  is asked for, and the prompts follow.
* `run`: an optional secret that does not resolve leaves its variable
  absent in the child. A value of that name in `run`'s own environment
  used to pass through, where the program could take it for the vault's.
* Rust client and every SDK: a recovery-key source is read only when the
  vault asks for a key and the earlier sources are used up, so a missing or
  empty `SOURCEORRERY_RECOVERY_KEY_FILE` no longer fails an open that this
  machine's key, the `recovery_key` option or `SOURCEORRERY_RECOVERY_KEY`
  completes. Needed and unusable, it is `io` with a hint that names it.
* PHP SDK: a `SecretReader` can no longer be cloned or serialised; a clone
  shared the native handle, and closing either freed the other's. A refused
  clone of a reader or a value owns nothing, whatever PHP does with it.
* .NET SDK: a `SecretValue` disposed inside its own `Use` callback (directly
  or through its `Secret` or `Project`) freed the bytes the callback's span
  still pointed at. Disposal now refuses new uses at once and frees the
  bytes, once, when the last running callback returns; no lock is held
  while a callback runs.
* Java SDK: `SecretReader.close()` could free the native reader while a
  call on another thread was still using it. Every call now holds the
  reader for its whole native call, and `close()` waits for them; a call
  after `close()` throws `IllegalStateException`.
* .NET SDK: `SecretReader.Dispose` waits for a call already running on
  another thread instead of closing the native reader under it, and a
  reader or value that becomes unreachable during a call can no longer be
  freed by its finalizer mid-call. A recovery key is cleared when opening
  or loading fails, and a value is zeroised if building its result fails.
* Java SDK: the native library is extracted into a new directory that only
  the current user can access on Linux and macOS, never over an existing
  file, and the directory is removed at exit instead of being left behind.

## [0.2.0] - 2026-10-23

This is a minor release because the Rust API changes: `Manifest` gains
remote-vault and rotation fields, `OpenOptions` gains a manifest option,
and `AuditOperation` gains variants and a larger `ALL` array. Existing Rust
struct literals and exhaustive matches may need changes. The C ABI and
vault-file compatibility rules remain separate (ADR 0007).

### Fixed

* AWS Secrets Manager deleted-secret metadata uses AWS's scheduled deletion
  date as the purge deadline, without adding a second recovery window.
  AWS does not expose the deletion request time; `deleted_on` is the Unix
  epoch to indicate that it is unknown.

### Security

The engineering pass of the milestone 4 security review
(`docs/security-review.md`) found and fixed:

* The audit chain's interior linkage was checked only by `audit --verify`:
  a row deleted from the middle of the log (the record of a detected
  truncation, a version's checkpoint) passed the unlock. Every unlock now
  walks the chain from the newest acknowledgement and quarantines on a
  break; the head record counts the keyed rows under its MAC, so every
  operation notices a keyed row removed between two operations. The file
  format is unchanged; an older head is accepted until the next write.
* Manifest discovery walked to the filesystem root, so a `sourceorrery.toml`
  planted in a world-writable or shared parent could point a process's
  Vault token at another host. Discovery stops at the repository, the home
  directory and, on Unix, directories owned by someone else. `http://` is
  accepted for the local machine only; the Vault client follows no
  redirect and uses no proxy for a loopback address.
* A passphrase with the shape of a recovery code (twenty-five letters and
  spaces) was folded before use by the CLI and no longer unlocked. The
  vault now tries a passphrase as typed first and as a code second, for
  every caller.
* The second factor's replay step and the reveal guard were written from a
  per-handle snapshot, so two processes could accept one code or overwrite
  each other's guard. Guard writes re-read and verify the stored state in
  their transaction.
* Manifest validation errors echoed the offending value; provider error
  text reached SDK messages unbounded and unescaped; a backup written over
  an existing file kept its mode and followed a link; `SOURCEORRERY_TOTP`
  and `SOURCEORRERY_BACKUP_PASSPHRASE` reached `run` children; invisible
  formatting characters passed the terminal sanitiser; loader variables
  (`LD_PRELOAD`, `NODE_OPTIONS`, ...) were valid manifest destinations;
  secret names could start with a hyphen; the backup passphrase was not
  strength-rated; several buffers holding the enrolment key, a hook's
  output, a typed passphrase's intermediates or a Vault credential were
  not zeroising. All fixed.

### Changed

* Secret names may no longer start or end with a hyphen (an imported
  `_PRIVATE` key is skipped rather than stored as `-private`).
* A manifest `env` naming `PATH`, an `LD_*` or `DYLD_*` variable,
  `NODE_OPTIONS`, `JAVA_TOOL_OPTIONS` or another loader or runtime option
  is a manifest error.
* `--tag` keys under `sourceorrery.` are refused.
* A remote provider's `address` or `endpoint_url` must be `https://`, or
  `http://` to localhost.

### Added

* A CI coverage workflow for the Rust workspace and all SDK implementations,
  plus JavaScript documentation tooling, with one SonarCloud analysis.
  Python targets and source/test classification are explicit; Node and Astro
  dependencies are installed before TypeScript analysis.
  Local PowerShell and Ubuntu runners generate reports without uploading.
* The full 0.2.0 release can publish the three new provider crates with a
  temporary token while the six existing crates keep using trusted
  publishing. Core is published first, then the providers, then the
  remaining workspace crates; ordinary SDK and release jobs still run.
  The existing-release recovery workflow supports the same option and
  skips exact versions already published. Configuring provider trusted
  publishing afterward requires no new release.
* A vault passphrase typed at the prompt must rate at least "good" on a
  strength estimate (a score 0 to 4 from the character runs, with common
  passwords, dictionary-style words, repeated characters, keyboard and
  alphabet sequences, years and short lengths counted against it; an
  estimate from rules, no wordlist shipped) unless `--allow-weak`; a
  passphrase supplied through `SOURCEORRERY_PASSPHRASE` or
  `--passphrase-file` is accepted with a warning when it rates lower.
  `vault passphrase generate` prints a random passphrase once (20
  characters, about 125 bits, by default) and `vault passphrase check`
  prints the estimate for one. The crypto crate gains `totp` (RFC 6238 over
  HMAC-SHA1 with the RFC's test vectors, replay refusal and a one-step
  window), recovery codes (125 bits over an alphabet without look-alikes)
  and passphrase generation, for the second factor and the recovery that
  follow.
* The vault stores a **reveal guard** (what an interactive reveal or export
  must present again: the passphrase, a second-factor code, both or
  neither), a **second factor** (a TOTP secret sealed with the vault key,
  with the last accepted step so a code is never accepted twice; an
  enrolment counts only once one code has been accepted) and a
  **passphrase hint** (in clear, shown at the prompt, never trusted, and
  refused when it would itself unlock the vault). The guard and the
  enrolment are part of the authenticated settings record, appended only
  when present, so every existing vault's tag still verifies and a file
  edit cannot switch the guard off. `SqliteVault::verify_passphrase`
  checks a passphrase (or a recovery code) in place; every check, change
  and refusal is audited under the new operation `guard`
  (`docs/vault-format.md`).
* The commands for all of it. `vault 2fa enable` enrols an authenticator
  app (a QR code drawn on stderr, the `otpauth://` URI only with
  `--show-uri`, the base32 key once with `-o json`) and keeps the
  enrolment only once a code from the app has matched (`--no-verify` and
  `vault 2fa verify` for later); `vault 2fa disable` and `status`.
  `vault guard --reveal passphrase,second-factor|none` sets what
  `secret get --reveal`, `backup`, `vault protector add|remove`, `vault
  recovery codes`, `vault 2fa enable` and `vault guard` itself must
  present again: the passphrase from where an unlock takes it, the code
  from the new global `--code` / `SOURCEORRERY_TOTP` or a prompt on the
  terminal (never a pipe); a refusal is `permission_denied` and prints
  nothing of the value. `run`, `check`, `ui` and the SDKs are untouched.
  `vault recovery codes [--count N]` prints up to 7 recovery codes once
  and installs them as passphrase protectors `recovery-1..N`, replacing
  earlier ones; a code unlocks the vault wherever a passphrase is
  accepted (prompt, `SOURCEORRERY_PASSPHRASE`, a file), with case,
  hyphens and look-alike letters ignored. `vault passphrase set` replaces
  the passphrase after checking the current one (and a code when the
  guard asks); `vault passphrase hint [TEXT|--clear]` manages the hint
  the prompt shows. `vault info` reports the guard, the enrolment, the
  recovery codes' labels and the hint (`docs/cli.md`, "The reveal
  guard"; `docs/threat-model.md`).
* `sourceorrery setup`: the guided first run, six screens on the terminal
  from the first vault to the first `run` (Cargo feature `ui`): the vault,
  with a passphrase typed against a live strength meter or generated and
  shown once, and the OS credential store as a second key where it
  exists; the first secret, a database password typed against the same
  meter or generated and stored unseen; recovery codes shown once behind
  a "written down" tick box, and the hint; the second factor, as a QR code
  to scan and one code to prove it; the reveal guard; and the manifest,
  written and checked, with the `run` line. Hidden fields are drawn as
  dots from their length and wiped afterwards; nothing typed as a secret
  is kept by the screens. Without a terminal, or with `--guide`, the same
  six steps are printed as commands (`-o json` too). `docs/getting-started.md`
  is the walkthrough; the README's quick start begins with it. The
  `otpauth://` URI `vault 2fa enable` shows leaves out the format's
  default algorithm, digits and period, so the QR code is a version
  smaller.
* `sourceorrery audit export` writes a local vault's audit log, oldest
  first, for a collector: as JSON Lines on stdout (one object per event
  plus `vault`, then a trailer with the count, the last id and the chain
  verification, so a collector can tell a complete export from a truncated
  log), or as OTLP/HTTP log records posted to `--endpoint` (or the
  `OTEL_EXPORTER_OTLP_*` variables) with the verification as the last
  record (Cargo feature `otlp`, on by default). `--since` starts from a
  time; `--follow` keeps exporting new events as they are recorded.
  `audit --vault <remote>` prints where the provider keeps its trail and
  the query that shows SourceOrrery's operations there instead of an error
  (`-o json`: `provider`, `audit_trail`, `query`, `docs`); `audit export`
  on a remote vault is `unsupported` with the same pointer. The provider
  pages gain an "Audit trail" section each, and `docs/enterprise.md`
  "Collecting the audit trail".
* `sourceorrery secret rotate NAME` rotates a credential as a recorded
  workflow over any vault: the new value is written as a disabled candidate
  (from the manifest's `[rotation.NAME]` `issue` command, whose standard
  output is the value and which receives the current value in the secret's
  environment variable, or from stdin), validated by the `validate` command,
  activated (enabled, then the previous version disabled, so one version is
  always accessible) and the previous credential retired at the issuer by
  the `retire` command once `retire_after` has passed, in a later
  `--step retire` run. Hooks run the way `run` runs a program (an argv, no
  shell; the value only in the child's environment). State lives in the
  versions' `sourceorrery.rotation.*` tags, so a rotation survives a crash
  and shows in `secret versions` and `--step status`; every step is an
  ordinary `secret_set` or `secret_update` audit event. Refusals carry the
  new code `rotation`. The core's `rotation` module is the state machine;
  `SecretClient::capabilities` (new, default: everything) lets a backend
  whose properties are per secret, AWS Secrets Manager, refuse rotation
  with `unsupported` before anything is written. Two lifecycle conformance
  scenarios cover activation and a failed validation (`docs/rotation.md`).
* `sourceorrery check --access` reads each value and discards it, so the
  status says whether this identity may read the secret and not only
  inspect it: a remote provider's policy can allow metadata and deny
  values, and the plain `check` stays metadata-only. A denied read on a
  remote vault now carries a hint in the provider's own terms (the Vault
  paths to grant and `vault read sys/capabilities-self`; the
  `secretsmanager:*` actions and `aws sts get-caller-identity`).
  `docs/enterprise.md` describes who decides what per provider, the
  workload identity set-up for GitHub Actions, Kubernetes and VMs, and
  what a revocation reaches; `scripts/ci/vault-federation.sh` and
  `scripts/ci/aws-federation.sh` prove the federated logins, a
  metadata-only policy and a revoked token in the provider CI jobs.
* AWS Secrets Manager is the second remote provider: `provider =
  "aws-secrets-manager"` with `region`, an optional `prefix` and an optional
  `endpoint_url` serves the secrets under that prefix behind the same
  contract (`docs/providers/aws-secrets-manager.md`). Credentials come from
  the AWS SDK's default chain, never the manifest. Secrets Manager keeps
  properties per secret, not per version, so `enabled`, `content_type` and
  the time window apply to every version and `update_secret_properties`
  accepts only the newest version; the lifecycle conformance suite gains
  capability flags (`lifecycle_with`) so such a documented difference skips
  exactly the scenario that needs it. The crate `sourceorrery-provider-aws`
  (the official SDK, trimmed to its Tokio and rustls stack) is on by
  default everywhere (feature `provider-aws`, part of `remote`). The
  `provider-aws` CI job runs the suite against the moto emulator and the
  SDK harness's remote scenarios through the CLI, the Rust and the C
  runners.
* HashiCorp Vault is the first remote provider: `provider =
  "hashicorp-vault"` in a `[vaults.<name>]` table serves a KV version 2
  mount behind the same contract as a local vault (versions, per-version
  properties in `custom_metadata`, soft delete as `delete`/`undelete`, purge
  as metadata deletion; `docs/providers/hashicorp-vault.md`). Credentials
  come from `VAULT_TOKEN`, `~/.vault-token`, an AppRole, a JWT or the
  Kubernetes service account token, never the manifest. The crate
  `sourceorrery-provider-vault` is a small `reqwest`/`rustls` client that
  never logs a body; it is on by default in the CLI, the `sourceorrery`
  crate, the C ABI library and the Python and Node extensions (feature
  `provider-vault`, part of `remote`; `--no-default-features` builds stay
  local-only). The `provider-vault` CI job runs the lifecycle conformance
  suite against a Vault container and reads a Vault-backed vault through
  the SDK harness's new `--remote` scenarios.
* Remote vaults in the manifest: a `[vaults.<name>]` table in
  `sourceorrery.toml` names a provider (`hashicorp-vault`,
  `aws-secrets-manager`) and its addressing keys, and
  nothing else: there is no credential key, and an unknown key is a parse
  error. `SecretReader::open` resolves a vault name through the nearest
  manifest or the one `OpenOptions::manifest` names, `so_reader_open`
  through the `manifest` key of `options_json`, and every SDK through a
  `manifest` option; `Project::load` always uses the manifest it loads.
  `vault list` shows remote vaults with their provider and location, and
  the commands about the vault file (`vault create`, `vault protector`,
  `vault destroy`, `vault migrate`, `audit`, `backup`, `restore`, `ui`)
  refuse a remote vault by name. The error codes `unauthenticated` and
  `provider_unavailable` (transient) are new; a provider the build leaves
  out is `unsupported`, naming it (`docs/providers/index.md`).
* `AsyncSecretClient`, the asynchronous shape of the contract, in
  `sourceorrery-core` (ADR 0008): the same methods and semantics as
  `SecretClient`, object safe, for the remote providers of milestone 4.
  The new `sourceorrery-provider` crate holds the adapters between the two
  shapes, `Blocking<A>` (an async client as a `SecretClient`, on a Tokio
  runtime it owns or borrows) and `AsyncLocal<C>` (a synchronous client as
  an `AsyncSecretClient`, on Tokio's blocking pool), which pass every
  operation and every error code through unchanged. The lifecycle
  conformance scenarios are now functions over `&dyn SecretClient`
  (`sourceorrery_conformance::lifecycle`), run against the SQLite vault
  directly and through the adapter pair.
* `scripts/dev/keyring-smoke.sh` and `.ps1` exercise the OS-keyring
  protector against a real credential store (create, read, protector add
  and remove, destroy with and without `--keep-os-key`, the store inspected
  after each step) in an isolated home, and the `keyring` CI job runs them
  headlessly against a temporary macOS keychain, GNOME Keyring on a private
  session bus and Windows Credential Manager.
* `sourceorrery backup --out FILE` writes every live secret of a vault,
  every version with its value, into one file sealed under a passphrase of
  its own (Argon2id, XChaCha20-Poly1305; `SOURCEORRERY_BACKUP_PASSPHRASE`
  for scripts), optionally only named secrets or including deleted ones;
  `sourceorrery restore FILE` writes it into a vault as new versions with
  their metadata kept and the original version recorded in tags, skipping
  secrets that exist unless `--overwrite`, with `--only`, `--keep-deleted`
  and `--dry-run`. The core contract gains `VaultBackup` and the audit
  operations `vault_backup` and `secret_restore`; the error codes
  `backup_passphrase` and `backup_format` are new. The format is in
  `docs/backup-format.md`.
* Every release carries a CycloneDX 1.5 software bill of materials per
  shipped binary and target: the CLI, the C ABI library, the Python
  extension and the Node addon, listing every Rust crate compiled in. The
  CLI and the C ABI library are built with `cargo auditable`, so
  `cargo audit bin` can check a shipped binary against the advisory
  database.
* Every file on a GitHub Release, `SHA256SUMS` included, carries a build
  provenance attestation signed in the release workflow run, so
  `gh attestation verify <file> --repo Netizine/sourceorrery` proves which
  commit and workflow built a download.
* ADR 0007 fixes what a version number promises for every surface (CLI,
  Rust API, C ABI, contract, SDKs, vault file, error codes) and how it is
  checked: `scripts/ci/abi-check.py` fails CI when a declaration of the
  previous release's C header changed or disappeared without a
  `SO_ABI_VERSION` bump, the `abi-compat` job runs the previous release's C
  conformance runner against the current library, and the release workflow
  runs `cargo semver-checks` on `sourceorrery` and `sourceorrery-core` for
  the version typed. The Go, Java, .NET, PHP and C++ SDKs compare
  `so_abi_version()` with the version they were built against before
  opening anything and refuse a mismatch with the code `abi_mismatch`.
* Paged listings: `SecretClient::list_properties_of_secrets_page` and
  `list_deleted_secrets_page` take `ListOptions` (`max_results`, a
  `ContinuationToken`) and return a `Page` whose token is the last name
  returned, so a listing can be read in name windows without duplicates or
  skips while the vault changes. `secret list` gains `--limit N` and
  `--after NAME`; with either, `-o json` prints `{"items", "continuation"}`.
* The CLI installs from a Homebrew tap (`brew install
  Netizine/sourceorrery/sourceorrery`, macOS and Linux), a Scoop bucket
  (`Netizine/scoop-sourceorrery`) and WinGet (`Netizine.SourceOrrery`).
  The release workflow renders the formula and the manifests from the
  release's `SHA256SUMS` (`scripts/release/package-managers.py`), commits
  them to the tap and the bucket and opens the WinGet pull request; the
  *Release packages* workflow can do the same for an existing release.

### Changed

* `vault list -o json` prints one object per vault (`name`, `kind`, and
  `path` for a local vault or `provider` and `location` for a remote one)
  instead of an array of names, so that remote vaults can be listed.
* Listing a vault no longer costs one audit-chain scan and two queries per
  secret: the SQLite backend reads the checkpoints of every secret in one
  statement and the names, `secrets` rows and version rows of the listing
  window in three more, verifying each row exactly as before (a row the
  chain records but the table lacks, or whose tag is not the newest
  checkpoint, still refuses the listing).
* Every third-party GitHub Action in the workflows is pinned to the commit
  of its release, with the version as a comment, and Dependabot updates
  the pins and the Rust, npm, Python, NuGet and Maven dependencies weekly
  in one grouped pull request per ecosystem. A `workflows` CI job runs
  zizmor over `.github/`, so an unpinned action or a shell step that
  expands an input fails the gate. The release workflow is read-only
  except for the two jobs that create the tag and the GitHub Release.

## [0.1.4] - 2026-10-22

### Added

* `sourceorrery import <file>` moves a `.env` file into a vault: each value
  is stored as a secret (`DATABASE_URL` → `database-url`, tagged
  `imported-from`) and each key declared in `sourceorrery.toml`, appended
  so the file's comments are kept, with an explicit `env` where the
  default name would not deliver the original variable. Output, JSON and
  errors carry key names and line numbers only, never a value.
  `--dry-run`, `--manifest-only` (for `.env.example`), `--only`,
  `--exclude` and `--overwrite`; secrets already in the vault are left
  alone, so it can be re-run.
* Skills for AI coding agents: `sourceorrery` (install, vaults, `run`, the
  SDKs, errors) and `sourceorrery-migrate-env` (import the `.env` files,
  find and convert every read of their variables in nine languages and in
  scripts, Docker and CI, remove the plaintext), in the Agent Skills
  format, never letting the agent see a value.
  `sourceorrery init --integration <agent>` writes them, from the binary
  and without any download, for Claude Code (plus a migration subagent),
  Gemini CLI, GitHub Copilot, Google Antigravity, Cline, OpenAI Codex (plus
  `agents/openai.yaml`), Cursor, Hermes Agent, Kilo Code, Kimi Code CLI,
  Kiro and OpenCode, or `all`; `--scope user` and `--skills-dir` install
  them outside the project. An existing manifest is kept, files
  SourceOrrery wrote are updated and anyone else's are left alone.
  `integrations/` holds the same files per agent, and the repository is a
  Claude Code plugin marketplace (`plugins/sourceorrery`).

### Changed

* PyPI and crates.io are published by trusted publishing, like npm and
  NuGet: the release jobs exchange the workflow's GitHub identity token
  for a short-lived credential (`rust-lang/crates-io-auth-action` for
  crates.io), and no `PYPI_API_TOKEN` or `CARGO_REGISTRY_TOKEN` is read
  any more. PyPI files now carry a signed attestation. Both jobs run in
  every real release and fail rather than skip if the registry does not
  trust the workflow; `ReleasePackages.yaml` does the same.
* Every registry page explains its package: each of the six crates has a
  README on crates.io; the PyPI, npm, NuGet, Go and PHP READMEs, the Maven
  description and javadoc overview say what the SDK is, that vaults are
  created and secrets stored with the `sourceorrery` CLI (which no SDK
  installs and which need not be present where the application runs), and
  link to sourceorrery.ai. The six npm platform packages say which
  platform their addon is for and to install `@sourceorreryai/sdk`
  instead (`scripts/release/npm-platform-packages.py`, run after
  `napi create-npm-dirs`).
* The CLI archives carry the CLI's README, the C ABI archives a README of
  their own (what is inside, who needs it, how to link it), and the
  GitHub Release notes list what each file is for.

### Security

* A vault is only served under its own name. Opening vault `X` used to
  load `<home>/vaults/X.sorvault` without checking that the file holds
  the vault `X`, so a file renamed, copied or swapped in from another
  vault that unlocks with the same passphrase or credential store was
  served under the wrong name. Every open by name (the CLI, `ui`,
  `audit`, `vault migrate`, the SDKs and the C ABI) now compares the
  requested name with the authenticated name in the file and refuses a
  mismatch with the new, append-only code `vault_mismatch`, recording
  the refusal in that file's audit log. A legacy file under the wrong
  name is refused before it is migrated. Every SDK has a typed error for
  the code (`VaultMismatchError`, `VaultMismatchException`,
  `ErrVaultMismatch`), and the SDK conformance harness checks it.

### Fixed

* The Linux and macOS C ABI archives no longer include Cargo's
  `libsourceorrery_ffi.rlib` and `libsourceorrery_ffi.d` next to the
  libraries.

## [0.1.3] - 2026-10-21

The first release: an encrypted local secrets vault with a
cloud-secrets-manager-style lifecycle, a CLI and an interactive vault manager, read-only
SDKs for ten languages over one Rust core, and a release pipeline to every
package registry.

### Added — core and encrypted vault

* `sourceorrery-core`: the `SecretClient` contract modelled on the managed
  cloud secrets services (set → a new immutable version, get the newest
  accessible version, metadata-only listing, property updates, soft delete,
  recover, purge, audit), stable append-only error codes, portable naming rules,
  enforced `not_before` / `expires_on`, `SecretBytes` (zeroising, redacted,
  never serialisable), `sourceorrery://` references and the
  `sourceorrery.toml` manifest, which cannot hold a value and whose errors
  never echo what they rejected.
* `sourceorrery-crypto`: XChaCha20-Poly1305 with AAD binding, Argon2id
  (caller-owned, zeroised working memory; parameters read from a vault are
  capped at 1 GiB, 64 passes and 16 lanes), envelope key wrapping, HKDF and
  HMAC-SHA256, OS randomness.
* `sourceorrery-storage`: one encrypted SQLite file per vault (on-disk
  schema 3).
  * Key protectors: the OS credential store and Argon2id passphrases,
    several per vault, at most eight passphrase protectors. A keyring
    entry is deleted only when it provably belongs to this vault and no
    sibling references it.
  * Every value is encrypted on its own, bound to vault, name and version;
    a read decrypts only the version it returns.
  * Soft delete with retention (7–90 days) and automatic purge;
    `secure_delete` on purge.
  * Integrity: every mutable row carries an HMAC under a key derived from
    the vault key; the audit log is a keyed hash chain with a keyed head
    record; every change records the row's new tag as a checkpoint in its
    audit event, so an older authentic copy of a row is refused; vault
    settings are authenticated, and the wrapped vault key's AAD names the
    format, so a rolled-back schema marker cannot unwrap.
  * Audit: every operation, success or failure, including failed unlocks
    and refused input, with metadata reads recorded as `secret_inspect`
    and never a value.
  * A detected truncation of the audit log blocks the vault: every unlock
    and operation is refused until its owner reviews the surviving history
    and acknowledges it (`audit --acknowledge`).
  * `vault migrate` upgrades a file written in an earlier on-disk format,
    by explicit command only. Vault files are created exclusively, so
    concurrent creators cannot remove each other's file.

### Added — CLI

* `sourceorrery vault create|list|info|protector|destroy|migrate`,
  `secret set|get|list|versions|update|delete|recover|purge`,
  `audit [--verify|--acknowledge]`, `init`, `check`, `run -- <command>`,
  `completions` and `ui`; `-o json` everywhere, with stable error codes.
* Values are read interactively, from stdin or a file — never as an
  argument — and shown only with `secret get --reveal`.
* `run` injects the manifest's secrets into a child's environment,
  removes `SOURCEORRERY_PASSPHRASE` and `SOURCEORRERY_PASSPHRASE_FILE`
  from it, and exits with the child's status whole.
* Human-readable output shows control and bidirectional-formatting
  characters as escapes (`\u{1b}`), so text planted in a vault file cannot
  move the cursor, erase lines or set the clipboard; JSON and revealed
  values are byte-exact.
* With no arguments, the SourceOrrery wordmark in Unicode half blocks
  (plain text when piped) and a quick start.

### Added — `sourceorrery ui`, the vault manager

* A Ratatui browser, the `ui` cargo feature of `sourceorrery-cli` (on by
  default). Views: Overview (secrets by status and expiry, what expires or
  activates next, the audit chain as `audit --verify` reports it, 14 days
  of audit activity, the last value read and failed unlock, protectors),
  Secrets with details (every field, every version, recent activity),
  Deleted, Audit log and Vaults (a picker that needs no unlock).
* `/` searches the current view: words anywhere; `tag:`, `status:`,
  `type:` and `expires:<30d` for secrets, `op:`, `outcome:`, `secret:` and
  `actor:` for the audit log.
* Changes, each checked with the vault's own rules and confirmed first:
  enable or disable a version, edit its metadata, a new version or secret,
  delete, recover. A new value is typed at the CLI's hidden prompt with the
  screen suspended and goes straight to the vault; deleting for good in a
  purgeable vault means typing the name. `--read-only` refuses every
  change. Purge, protectors, destroy, migrate and acknowledgement stay in
  the CLI.
* Metadata only: the views read through an interface with no operation
  that returns a value; changes go through a separate one. Every metadata
  read is audited, so each thing is read once, when first shown, and again
  on `r`. Vaults open for inspection, so a blocked vault shows its audit
  log and is never asked for secrets.
* `--theme dark|light|terminal`: the documentation site's palettes (with
  the nearest xterm 256 colours where there is no 24-bit colour) or the
  terminal's own; `NO_COLOR` honoured.
* Idle lock: after `--lock-after` minutes without a key (default 10) and
  on `L`, the vault is dropped and its key zeroised.

### Added — SDKs and the C ABI

* `sourceorrery`, the read-only Rust client every SDK is built on:
  `SecretReader` opens a vault in the CLI's unlock order (OS credential
  store, an explicit passphrase, `SOURCEORRERY_PASSPHRASE`,
  `SOURCEORRERY_PASSPHRASE_FILE`, never a prompt), reads the newest
  accessible or an explicit version, properties and references;
  `Project::load` resolves a `sourceorrery.toml` like `sourceorrery run`.
  Every error carries its stable code, a kind and a hint saying what to do.
* `sourceorrery-ffi`: a stable C ABI (cbindgen header, checked in CI):
  read-only `so_reader_*` and `so_project_*` handles for SDKs,
  `so_vault_*` for tooling, values in caller-owned buffers that
  `so_bytes_free` zeroises, errors as code, message and hint.
* Ten read-only SDKs (ADR 0005, technologies in ADR 0006), each with typed
  errors, guarded values that print as `[REDACTED]`, a project loader, a
  tested example and a guide under `docs/sdks/`: Python (`sourceorrery`,
  abi3 wheels), JavaScript/TypeScript (`@sourceorreryai/sdk` with platform
  packages), Rust, Java (`ai.sourceorrery:sourceorrery`, Foreign Function
  and Memory API), .NET (`SourceOrrery`, `LibraryImport`), Go
  (`github.com/netizine/sourceorrery/bindings/go`), C, C++ (header-only)
  and PHP (`sourceorrery/sourceorrery`, FFI).
* A cross-language conformance harness (`tests/conformance/sdk/`): one
  list of scenarios, a runner per SDK and one judge. CI runs every SDK's
  tests, example and the harness on Ubuntu, Windows and macOS against a
  vault the CLI creates in the job.

### Added — releases

* `release.yml` (`workflow_dispatch` with `version` and `dry_run`): the CLI
  and the C ABI for six targets, Python wheels, npm, Maven and NuGet
  packages with the native libraries embedded, a GitHub Release with
  `SHA256SUMS`, and publish jobs for crates.io, PyPI, npm, NuGet, Maven
  Central, Packagist and pkg.go.dev that run once each registry is set up.
  npm and NuGet use trusted publishing. The npm main package is installed
  and loaded in the run before anything ships.
* `ReleasePackages.yaml` publishes an existing release's packages to a
  registry set up after it ran.
* `scripts/release/set-version.py` stamps the version into every manifest;
  the Composer manifest is at the repository root, where Packagist reads
  it. Procedure and per-registry setup: `docs/release.md`.

[0.1.4]: https://github.com/Netizine/sourceorrery/releases/tag/v0.1.4
[0.1.3]: https://github.com/Netizine/sourceorrery/releases/tag/v0.1.3
