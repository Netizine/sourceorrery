# Security review, October 2026

The engineering pass of milestone 4's review (M4.9): every claim in the
[threat model](threat-model.md) checked against the code that makes it,
by five independent read-only passes (crypto and unlock; storage integrity
and the audit chain; the CLI and its screens; the SDK, the C ABI and the
providers; the core contract and the test suite), each finding verified
by hand before anything changed. What was wrong is fixed in the same
change set as this page; what was imprecise in the documentation is
corrected; what remains is listed, with the reason it stays.

This is not an independent audit, and the wording in the README and the
[supply chain](supply-chain.md) page that says so is unchanged: that call
is the maintainer's, after their own review.

## Scope and method

| Surface | Read in full | Claims checked against |
|---------|--------------|------------------------|
| `sourceorrery-crypto`; protectors, unlock, keystore, registry; the Rust client's unlock order; the CLI's passphrase handling and strength estimate | yes | at-rest protection, passphrase hardening, memory hygiene, the second factor, recovery codes |
| `sourceorrery-storage`: integrity, the audit chain, rows and checkpoints, the guard, backup | yes | the Tamperer row, every integrity control, known gaps 5, 6, 7, 11, 12 |
| The CLI: every command, the browser, the set-up wizard; the end-to-end tests | yes | the Careless-operator row, the non-negotiable rules, the reveal guard, child environment hygiene |
| `sourceorrery`, `sourceorrery-ffi`, the adapters, both providers, the Python and Node native layers | yes | read-only SDKs, no prompt in a library, values guarded in every language, credentials never from the manifest, no body in a message |
| `sourceorrery-core`, the conformance suites, the SDK harness, CI | yes | enforced policy, name and manifest rules, no secret in diagnostics, which controls have a test |

Findings are rated by what they let an adversary of the threat model do,
not by how hard they were to find. "Fixed" means the code changed and a
test now fails without the fix; "documented" means the behaviour was
acceptable but the documentation overstated it; "open" means it stays,
with the reason.

## Findings

### High

1. **The audit chain's interior linkage was not enforced at unlock**
   (`storage::sqlite::audit`). Each row's hash was checked against the
   row's *own stored* predecessor hash, and only the chain head (the
   newest keyed row) was compared with the file; the walk that checks that
   row *n+1* follows row *n* existed only in `audit --verify`. A tamperer
   who could write the file but not unlock it could delete one row from
   the middle of the log and the vault opened normally. Three consequences
   contradicted the threat model: deleting the keyed `audit_verify` row
   that records a detected truncation lifted the quarantine without an
   acknowledgement; deleting a version's `secret_set` row together with
   the version made the previous version current again; and removing the
   row that checkpointed a delete or a disable, with an older copy of the
   row put back, was accepted. **Fixed.** Every unlock now walks the chain
   from the newest authentic acknowledgement to the end and refuses, records
   and quarantines on the first row that does not follow its predecessor or
   whose hash does not verify, exactly as a removed tail is treated; the
   head record now also carries the number of keyed rows under its MAC, so
   the check every operation starts with catches a keyed row removed or
   demoted between two operations of an open handle without walking the
   log. The surviving history is accepted only after `audit --acknowledge`,
   as before; a break inside already-acknowledged history is not reported
   again. Tests: an interior deletion, a deleted truncation record, a
   deleted version checkpoint and an edited row each refuse the unlock and
   are recorded once; a keyed row removed while the vault is open fails
   the next operation. The vault file format did not change; a head record
   written before the count exists is accepted until the next keyed write
   replaces it, and the walk covers such a file in the meantime
   ([vault format](vault-format.md)).

2. **Manifest discovery walked to the filesystem root**
   (`core::manifest::Manifest::discover`). With no explicit path, the SDKs,
   `so_reader_open`, `run`, `check` and `secret rotate` looked for
   `sourceorrery.toml` in the working directory and every parent. A
   manifest does not hold a credential, but it decides *where the
   environment's credential is sent*: a `[vaults.production]` table
   planted in a world-writable ancestor (`/tmp` above `/tmp/app`, a shared
   parent on a multi-user host) with `address = "http://attacker:8200"`
   made any process that opened `production` send its `VAULT_TOKEN` (or
   post its AppRole secret id or JWT) to that address before a secret was
   asked for. This is the shape of git's CVE-2022-24765. **Fixed.**
   Discovery stops after the first directory holding a `.git` entry (the
   repository), after the user's home directory, and, on Unix, before any
   directory or manifest owned by someone other than the home directory's
   owner; a manifest outside those bounds is treated as absent. An explicit
   `--manifest` or `OpenOptions::manifest` is used as given. In the same
   spirit, `http://` is now accepted only for the local machine (a
   credential travels with every request), no redirect is ever followed
   (the token header would travel with a cross-host redirect), and a proxy
   from the environment is not used for a loopback address.

### Medium

3. **A passphrase with the shape of a recovery code was rewritten before
   use** (the CLI's unlock, introduced in this milestone). Twenty-five
   letters with spaces, such as `correct horse battery staple`, matched
   the code shape, were folded to upper case without spaces, and no longer
   unlocked from the CLI while the SDK, which does not fold, still did.
   **Fixed.** The vault itself now tries a supplied passphrase as typed
   first and, only when it has a code's shape, the normalised form second,
   in the storage crate, so the CLI, the SDKs and the guard's passphrase
   check agree. A test creates a vault with that phrase and unlocks it.

4. **The second factor's replay guard and the guard settings were read
   from a per-handle snapshot** (`storage::sqlite::guard`). Two processes
   on one vault could each accept the same code once within its window,
   and a change to the reveal guard made by one could be overwritten by
   the other's stale copy under a valid tag. **Fixed.** Every guard write
   re-reads the stored state inside its transaction, verifies its tag,
   changes only the field the operation changes, and a code is checked
   against the *stored* last accepted step before it is written. Tested
   with two handles on one file. The hint, the passphrase check and the
   refused-code record now go through the same transaction and quarantine
   checks as every other operation (previously they wrote outside them).

5. **Manifest validation errors repeated the offending value**
   (`core::manifest::Manifest::validate`). TOML-level errors reported a
   position only, as documented, but a value that parsed and failed
   validation (`version = "hvs…"`, `env = …`, `vault = …`,
   `retire_after = …`) was echoed by `check`, `run`, the SDKs and the C
   ABI. **Fixed.** Validation errors name the table key and the rule,
   never the value; the test that feeds canaries through every path now
   covers these fields.

6. **Policy and rotation state on a remote vault are the provider's
   metadata, which nothing authenticates.** On HashiCorp Vault the
   `enabled` flag, the time window, the deletion marker and the rotation
   tags live in `custom_metadata`; on AWS Secrets Manager in tags. A
   principal with `update` on `<mount>/metadata/<name>` (a different ACL
   capability from writing the value) or `secretsmanager:TagResource` can
   re-enable a disabled version, clear a window, or mark a retired version
   as a validated rotation candidate that the next `secret rotate
   --step activate` would promote. The local vault is protected against
   exactly this by its tags and checkpoints; a remote vault cannot be, the
   provider owns the metadata. **Documented** on both provider pages, in
   [enterprise](enterprise.md) (who may hold metadata write capability)
   and as a known gap; the CLI now also refuses a `--tag` under the
   `sourceorrery.` prefix, so the state cannot be planted by hand through
   it, and `secret rotate` is unchanged (a forged candidate still needs
   write access to the provider's metadata).

7. **Untrusted server text reached SDK and C ABI messages unbounded and
   unescaped.** Vault's `errors` strings, its reported mount type and
   version, and the AWS service's message were interpolated into
   `SecretError` text; the CLI escapes every line it prints, but an SDK
   exception or `so_last_error_message` carried the text as received, so a
   hostile or spoofed server could put terminal control sequences or
   megabytes into an application's logs. **Fixed.** Foreign text passes
   through one core helper (`sourceorrery_core::text`) that bounds it and
   replaces control and invisible formatting characters before it enters
   a message; reply bodies are capped.

### Low

8. **A backup written over an existing file kept that file's mode** and
   followed a symbolic link in its place. **Fixed:** the file is always
   created new (0600 on Unix, never through a link); `--force` removes the
   old file first.
9. **`SOURCEORRERY_TOTP` and `SOURCEORRERY_BACKUP_PASSPHRASE` reached
   `run` children and rotation hooks.** **Fixed:** both are stripped with
   the two unlock variables; the test probes all four.
10. **Invisible formatting characters passed the terminal sanitiser.**
    Zero-width spaces, the word joiner, the byte-order mark and the tag
    characters are not control characters, so a planted label could hide
    text or read as another name. **Fixed:** they are escaped like the
    bidirectional controls; the zero-width joiner and non-joiner, which
    scripts need, stay as typed.
11. **Loader and runtime variables were valid destinations.** A manifest,
    which is repository content, could deliver a value as `LD_PRELOAD`,
    `NODE_OPTIONS` or `JAVA_TOOL_OPTIONS`, which the runtime then prints
    or acts on. **Fixed:** `validate_env_name` refuses `PATH`, the `LD_`
    and `DYLD_` prefixes, the option variables of Node, Java, Python, the
    shells, Perl, Ruby, .NET and git.
12. **Secret names could begin or end with a hyphen** (`-private`, from
    an imported `_PRIVATE`), which a command line reads as an option.
    **Fixed:** refused like vault names; an environment key that would
    produce one is not importable.
13. **The backup passphrase was not strength-rated**, although a backup
    holds every value under that passphrase alone. **Fixed:** rated like
    a vault passphrase (`--allow-weak` to override at the prompt; a value
    from the environment is warned about).
14. **Memory residue.** The enrolment key and URI left `TotpSecret` as
    plain strings (and reached a `Debug`-printable struct in the wizard);
    the strength estimator built intermediate copies of the passphrase in
    ordinary buffers; a rotation hook's captured output was a plain
    vector; the `--code` argument was a plain `String` inside a `Debug`
    type; Vault credentials were plain `String`s in a public `Debug`
    struct. **Fixed** in each case with zeroising buffers and redacting
    types. Still ordinary memory: the JSON `secret get --reveal` and
    `vault 2fa enable -o json` produce (the caller asked for a string), the
    login body `reqwest` serialises, and the copies an application makes
    (known gap 9).
15. **A corrupt passphrase protector row aborted the whole unlock**, so
    one damaged row denied the others. **Fixed:** skipped with a reason,
    like a row whose parameters exceed the ceiling.
16. **An environment passphrase rejected at attempt one fell through to
    the interactive prompt without a word.** **Fixed:** one line on stderr
    says which source was rejected.
17. **Dates from provider metadata could overflow** (`deleted_on + 90
    days` on a planted far-future marker panicked). **Fixed** with checked
    arithmetic.
18. **A forged row with an unknown operation name failed the whole audit
    listing**, which the owner needs to review before acknowledging.
    **Fixed:** such a row is left out of the listing; the chain walk
    records the edit itself.
19. **Vault creation was not one transaction.** A crash between the
    protector and the first audit row left a file that unlocked only as
    "history missing". **Fixed.**
20. **The backup format page overstated what the verifier tells apart.**
    Editing the header's KDF parameters, salt or verifier makes a correct
    passphrase fail the verifier, which reads as `backup_passphrase`, not
    `crypto`; only the payload's authentication distinguishes tampering.
    **Documented.**
21. **The guard applies to local vaults only**, and a recovery code
    satisfies its passphrase factor (it is a way in by design).
    **Documented** in the CLI reference and gap 12.
22. **The keyring identity check before `vault destroy` is
    unauthenticated** (a decoy file copying a real vault's id passes it; a
    deleted entry costs availability only). **Documented** in gap 8.

### Information

- `--code` on the command line is visible in process listings for the
  minute it is valid (gap 12, unchanged).
- Hidden fields in the set-up wizard show one dot per character, so the
  length of a passphrase is visible on screen while it is typed.
- `Principal::local_user` honours `SOURCEORRERY_ACTOR`: the audit actor is
  a label the caller chooses, as documented.
- `rotation::validated` is callable for any issued version by any process;
  the CLI's sequencing is what makes "never activated without validation"
  hold.
- A restore keeps `sourceorrery.rotation.*` tags from the backup; a
  restored "validated" candidate makes the next rotation ask to activate
  it. Review a restored vault's rotation state before rotating.
- `Blocking::run` panics when a remote reader is used from inside a Tokio
  task; the C ABI catches it, the Rust crate does not.

## Claims verified as holding

Each of these was traced to the code that satisfies it and, where listed
in the threat model's controls table, to a test that would fail without
it. They are recorded here so the next review can start from the deltas.

- **At rest.** XChaCha20-Poly1305 with a fresh random nonce per seal and
  an AAD naming vault, secret and version; the vault key exists on disk
  only wrapped under a KEK from Argon2id (per-protector random salt,
  parameters capped before any work) or the OS credential store, with the
  schema bound into the wrapping AAD. KDF memory and every key and value
  type are zeroised; `Debug` redacts them; `SecretBytes` has no
  `Serialize` anywhere in the workspace.
- **Rows and settings.** Every `secrets` and `secret_versions` row carries
  an HMAC under an HKDF sub-key of the DEK, with an unambiguous canonical
  encoding (fixed field order, length prefixes, presence bytes), verified
  on every read; a row is honoured only when its tag equals the newest
  checkpoint on the chain. The settings record covers schema, name, id,
  creation time, recovery level, retention and, when present, the second
  factor and the reveal guard. A vault is served only under its own name.
  `secure_delete` is on.
- **The audit chain**, with finding 1 fixed: a keyed hash chain with a
  keyed head, rows written before unlock chained under a public key and
  never counted as checkpoints or truncations, suffix truncation and head
  loss detected at unlock and before every operation, interior breaks
  detected at unlock, acknowledgement as a keyed row.
- **Reads.** The only reveal paths are `output::print_revealed` and the
  JSON branch of `secret get --reveal`; no command takes a value as an
  argument; metadata commands, errors, `-v`, audit details and JSON carry
  no value, passphrase, key or code; hidden prompts never echo; the
  browser reads through a value-free trait and audits each read once;
  the wizard draws hidden fields from their length and sends values
  straight to the vault.
- **The reveal guard** runs before any value is read or written on every
  path it covers, reads a code from `--code` or a terminal and never a
  pipe, and refuses without printing anything of the value.
- **SDKs.** The C ABI's read-only surface and the Rust client expose no
  write, protector or audit operation; the SDKs never prompt and never
  migrate; the unlock order is one; values stay in native memory until
  freed and are zeroised then; every hint and message is value-free; the
  `unsafe` in the C ABI handles null, lengths, UTF-8, panics across the
  boundary and double frees.
- **Providers.** Credentials come from the documented sources only, never
  the manifest; URLs with user information or a query are refused; TLS is
  never disabled; no body is logged; names are validated before any path
  is built; the adapters pass every call and error through.
- **Core.** Policy is evaluated on every retrieval with strict window
  boundaries; `select_latest_accessible` returns only accessible versions;
  names and references are validated before storage; the manifest cannot
  hold a value; error codes are unique and append-only.

## Controls without a direct test

The threat model's controls table claims these, and the code satisfies
them, but no test fails if the control is removed. They are the next
tests to write, in rough order of value:

- the DEK never on disk in the clear (the existing test scans for values
  and the passphrase, not the key);
- Argon2id with a distinct random salt per protector, and the memory and
  lane ceilings (only the iteration ceiling is tested);
- `SecretBytes` not `Serialize` (a compile-time assertion would make a
  future derive fail CI);
- KDF residue and zeroisation in general;
- secure deletion on purge (a scan of the file for a purged ciphertext);
- the idle lock in the browser dropping the vault;
- automatic purge at `scheduled_purge_on` and the 90-day default;
- the sanitiser on tags, names and hints (two sources are covered).

## What this review did not do

It did not fuzz the parsers, run a memory-safety tool over the C ABI,
measure side channels, or test the OS credential store beyond the
existing headless job. It read the code as written on one day; the
dependency set is checked by `cargo audit` in CI and was clean at the
time, with the `ctutils` advisory of the same week already resolved.
