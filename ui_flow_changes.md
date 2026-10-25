# Vault setup and UI flow: where it stands, and the plan to fix it

Status: **All six phases done** on branch `vault-checks-and-storage`, as
one commit on top of `main` (PR 43). The history below records the order
the work was done in:
ADR 0009 accepted 2026-10-24, then storage and core, then storage
routing: the provider crates take connection settings
(`core::connection`) and optional stored credentials, opened by
`open_connection`; the vault keeps its connections (the `connections`
table) and records each secret's storage (`secrets.storage`); `Routed`
serves a vault over all of them and passes the lifecycle suite over the
file, a stand-in connection and each provider's live service. In Phase
3 the manifest names no remote vault and every reader (SDK,
C ABI, bindings, CLI) goes through `Routed`; `vault create` takes
connection flags and `secret set` / `import` take `--storage`; the SDK
harness, fixture vault, CI provider jobs and federation scripts use
connections, all green in CI on PR 43. Phase 4 replaced `backup` and
`restore` with `vault export` and `vault import`, kept project folders and
secret descriptions in the vault, gave `init` its own screens and the
setup wizard its one transaction, and removed the interim vault commands;
Phase 5 brought storage, projects and the setup screens into the browser;
Phase 6 rewrote the docs, skills, site pages and release notes. One gap
found on the way, the settings record not being checkpointed on the audit
chain, was closed afterwards in a commit of its own (threat model, gap 6;
`docs/vault-format.md`, *The settings record*).
Written 2026-10-24 from James's walkthrough of `sourceorrery setup` (14
screenshots) and a review of the CLI, the setup wizard, the `ui` browser,
the storage crate and the manifest. James answered §6 the same day and then
narrowed the checks: the password is only a check on viewing the vault and
revealing a value, the PIN is dropped, and everything else just runs. The
design is in [ADR 0009](docs/adr/0009-local-vaults-checks-and-storage.md)
(accepted), which this plan follows.

Backwards compatibility is not required. James is deleting his existing
vaults, and old vault files, manifests and commands may break.

Contents:

1. [Summary](#1-summary)
2. [The flow as it stands](#2-the-flow-as-it-stands)
3. [What is wrong](#3-what-is-wrong)
4. [The target model](#4-the-target-model)
5. [The vault key and the view check](#5-the-vault-key-and-the-view-check)
6. [Decisions](#6-decisions)
7. [Plan](#7-plan)
8. [What goes away](#8-what-goes-away)

---

## 1. Summary

Today `sourceorrery setup` is a first-run tour. It creates a vault, then
stores a secret called `database-password`, issues recovery codes, enrols an
authenticator, sets a *separate* "reveal guard" and writes a manifest into
whatever folder it was run from. Remote providers do not appear at all: they
are declared per project in `sourceorrery.toml`, and each vault name is
either a local file or a remote provider, never both.

James's model is different. **Setup is about the vault, not about secrets
or projects:**

- **One vault key.** The vault gets an auto-generated key. On this machine
  the OS credential store opens it, as Windows Hello does. Elsewhere the
  recovery key opens it.
- **An optional view check.** A password (with an optional hint), and
  optionally an authenticator code on top, decides whether a person may
  view the vault and reveal a value. Nothing else asks: `run`, `init`,
  `check` and the SDKs just run.
- **Storage.** The user chooses where the vault's secrets may live: the
  SourceOrrery vault (always on), plus any of HashiCorp Vault, AWS Secrets
  Manager and Azure Key Vault. Each third-party choice gets a connection,
  set up in the same flow.
- **Secrets.** Each secret is added in the `ui` browser with a name, a value
  and a storage location.
- **Projects.** `init` builds the manifest from secrets picked out of an
  existing vault (all of them, or some), and adds any new ones the project
  needs to the vault as it goes. The vault remembers each project folder
  that uses it.

`setup` and `vault create [NAME]` become the same wizard. `vault create` with
the name of an existing vault edits that vault, for example to change a
connection. The vault-level commands become `vault create`, `vault export`
and `vault import`.

This is a redesign of the storage layer, the access model, the provider
configuration and the CLI surface, not a reskin. The plan in §7 has six
phases.

---

## 2. The flow as it stands

### 2.1 `sourceorrery setup`, screen by screen

The screenshots are of an existing vault `development` (created on
2026-10-21 with `vault create development`, OS keyring only), run from
`C:\dev\test`.

| # | Screen | What it shows | What happens underneath |
|---|--------|---------------|-------------------------|
| 1 | **Welcome** | Rail `1 Vault · 2 First secret · 3 Recovery · 4 Second factor · 5 Reveal guard · 6 Project`; "From the first vault to the first run, in six short steps"; `[ Begin ]` | Nothing. `wizard::Step::Welcome`. |
| 2 | **1 Vault** (vault exists) | "A vault named **development** exists already: continue to use it (it may ask for its passphrase), or type another name." Field `Vault name: development`, `[ Use this vault ]` | `Request::OpenExisting` → screen suspended → `Ctx::open_local` (OS keyring first, then the passphrase prompt) → back. For a new name the step shows instead: keyring checkbox, passphrase + confirm with a strength meter, `[ Generate ]`, `[ Create ]`. |
| 3 | **2 First secret** | Header now `vault development · OS keyring + passphrase`. Note "Using the existing vault 'development'." Text: "The first secret is your database password. A database password cannot be weak…". Fields `Secret name: database-password`, `Value`, strength meter, `Confirm`, `[ Generate a strong value for me ]`, `[ Store the secret ]` | The name comes from `setup --secret` (default `database-password`). |
| 4–5 | First secret, typed | 14 dots, meter `strong (about 72 bits)`, confirm `matches` | Value held in a `Zeroizing` buffer; strength-gated (`Score::REQUIRED` = "good"). |
| 6 | **3 Recovery** | Note "Secret 'database-password' stored." Text on recovery codes; "5 codes are issued; run `vault recovery codes` to replace them". `[ Show my recovery codes ]`, `Passphrase hint`, `[ Continue ]` | `set_secret` wrote a new version into `development`. |
| 7 | Recovery, codes shown | "YOUR 5 RECOVERY CODES · shown once", five 25-character codes, checkbox "I have written these codes down…" | `replace_recovery_codes`: five new passphrase protectors `recovery-1..5`; **any earlier codes are deleted**. |
| 8 | **4 Second factor** | "An authenticator app (any that speaks TOTP)… before a value is shown or the vault exported." `[ Enrol an authenticator app ]`, `[ Skip ]` | — |
| 9 | Second factor, QR (short terminal) | QR code filling the screen; "Cannot scan? Enter this key by hand: …" on the last line above the footer; **no code field visible** | `enrol_second_factor`: TOTP seed sealed under the vault key, unverified. |
| 10 | Second factor, QR (tall terminal) | Same with a different key (a second enrolment), `Code from the app` filled in, `[ Verify the code ]`, `[ Skip ]` | `verify_second_factor`. Three wrong codes remove the enrolment. |
| — | **5 Reveal guard** | Not captured. Offers "The passphrase and a code from the app", "The passphrase", "Nothing: unlocking is enough" | `set_reveal_guard`. James chose passphrase + second factor. |
| 11 | **6 Project** | "Wrote C:\dev\test\sourceorrery.toml"; table `database-password · DATABASE_PASSWORD · ok`; `[ Finish ]` | `Manifest::template` with the one secret, written to the current directory, then checked metadata-only like `check`. |
| 12 | **Done** | vault `development (OS keyring and passphrase)`, file path, first secret, 5 recovery codes, second factor verified, reveal guard "passphrase and second-factor", manifest path. NEXT: `run -- <cmd>`, `secret get … --reveal`, `secret set NAME --vault development · ui · check`, `SOURCEORRERY_PASSPHRASE_FILE=/run/secrets/vault sourceorrery run -- <command>` | — |
| 13 | Windows Hello (reference) | A sign-in screen with sign-in options: fingerprint, PIN, security key | The model James wants: the device holds the key, the owner chooses what is asked. |
| 14 | **`sourceorrery ui` Overview** | `vault development · recoverable for 90 days · 6 protectors`; tabs Overview, Secrets 2, Deleted 0, Audit log 43, Vaults 1; secrets by status, expiry, audit chain intact, 14-day activity; VAULT panel: created, file, protectors `os-keyring` (2026-10-21) and `recovery-1..5` (2026-10-24 04:55). Footer `v verify chain · a add secret · L lock · Tab views · ? keys · q quit` | `MetadataSource` reads; every read audited once. |

Code: `crates/sourceorrery-cli/src/ui/setup/{wizard,view,backend}.rs`,
`commands/setup.rs` (the same six steps printed as commands with `--guide`
or without a terminal).

### 2.2 `sourceorrery vault create development`, today

No wizard. With no `--protector` it creates the file with a single
**OS-keyring** protector and asks nothing. It prints the path and a tip to
add a passphrase protector for WSL, Docker or CI. With `--protector
passphrase` it prompts twice and requires a passphrase rated "good".
It sets no recovery codes, second factor, guard or connections.
(`commands/vault.rs::create`.)

### 2.3 Everything else that configures a vault today

| Command | Does |
|---------|------|
| `vault protector list\|add\|remove` | Ways to unwrap the key: `os-keyring`, `passphrase` (up to 8). |
| `vault passphrase generate\|check\|set\|hint` | Make or rate a passphrase, change it, set the clear-text hint. |
| `vault 2fa enable\|verify\|disable\|status` | TOTP enrolment (seed sealed under the vault key). |
| `vault guard --reveal …` | What `secret get --reveal` and `backup` must present again. This is separate from unlocking: `run`, `check` and the SDKs are never asked. |
| `vault recovery codes [--count N]` | Replace the recovery-code protectors. |
| `vault info`, `vault list`, `vault destroy`, `vault migrate` | Inspect, list, delete, upgrade schema 1/2 → 3. |

### 2.4 Secrets, projects and providers, today

- **Secrets:** `secret set|get|list|versions|update|delete|recover|purge|rotate`,
  all scoped by `--vault` or the manifest's vault. `ui` can add a secret
  (`a`: name, then a hidden prompt outside the screen), add a version,
  change metadata, delete and recover.
- **Projects:** `init` writes `Manifest::template`, a fixed
  `database-password` entry with `purpose = "Database authentication"`,
  whatever the vault holds. That is the block James pasted. `import` moves
  a `.env` into a vault and declares each key. `check` and `run` resolve
  the manifest. The vault does not know which folders use it.
- **Third-party providers:** declared in the **manifest**, one per vault name:
  `[vaults.<name>] provider = "azure-key-vault", vault_url = …`. A vault name
  with such a table is entirely remote; without one it is the local file.
  Credentials come from the environment (Vault token, AWS chain, Azure
  chain). Setup, `vault create` and `ui` never touch providers; `ui` refuses
  remote vaults.
- **Moving vaults:** `backup` / `restore` carry secrets only, sealed under a
  separate backup passphrase, and restore them into an existing vault as new
  versions. They don't carry protectors, the second factor, the guard or
  connections. Copying the `.sorvault` file does carry them, but an
  OS-keyring protector only works on the machine it came from. On a
  keyring-only vault like `development`, the recovery codes are therefore
  the only way to open a copy anywhere else.

### 2.5 How access works today

```
vault key (DEK, 32 random bytes) ──► every value; HKDF → metadata key (tags, audit chain)
  ▲ wrapped by each protector's KEK
  ├─ os-keyring : random KEK in Credential Manager / Keychain / Secret Service (no prompt)
  ├─ passphrase : Argon2id(passphrase)
  └─ recovery-N : Argon2id(code) — passphrase protectors, reusable until replaced
TOTP seed: sealed under the vault key; checked only by the reveal guard
Reveal guard: {passphrase?, second factor?} — asked by `secret get --reveal`, `backup`
```

Unlock order: every OS-keyring protector, then up to three passphrase
prompts against every passphrase protector. A recovery code satisfies the
guard's "passphrase" factor (threat model §12).

---

## 3. What is wrong

Problems 1–6 are about the model; 7–13 are defects the screenshots show.

1. **Setup creates secrets and projects.** Steps 2 and 6 make a
   `database-password` secret and write a manifest into the current folder.
   A vault setup should produce a configured vault and nothing else.
2. **Two access policies instead of one.** Unlocking uses the OS keyring
   (no prompt). Showing a value uses the reveal guard (passphrase + code).
   `run`, `check` and the SDKs skip the guard. James's rule is one setting
   that every check follows.
3. **The second factor belongs to a guard, not to the vault.** It is
   enrolled per vault, as it should be, but only consulted for reveal and
   backup.
4. **Providers are invisible to the vault.** Where a secret lives is decided
   by which vault *name* the manifest points at, not chosen when the secret
   is added. One vault cannot hold a local database password and an LLM key
   kept in Azure Key Vault side by side.
5. **`init` ignores the vault.** It writes a template secret instead of
   letting the user pick from what the vault holds, and it runs with no
   vault at all.
6. **The vault-level commands are scattered.** Ten-odd `vault` subcommands
   plus `backup`/`restore` cover what James describes as create (or edit),
   export and import.
7. **Wrong label on an opened vault** (screens 3, 12). The header and the
   summary say "OS keyring + passphrase" for a vault whose protectors are
   `os-keyring` and `recovery-1..5` only (screen 14). `view.rs:65` and
   `view.rs:453` print "+ passphrase" whenever a keyring protector exists,
   because a vault the wizard *creates* always has a passphrase. An opened
   vault may not.
8. **A guard that asks for a passphrase the vault does not have.** The
   wizard always offers the passphrase options (`wizard.rs::guard_options`),
   and `set_reveal_guard` checks only the second factor. So `development` now
   asks for "the passphrase" on every reveal, and only a recovery code can
   answer it.
9. **Re-running setup silently replaces recovery codes** (screens 6–7). On an
   existing vault, "Show my recovery codes" deletes the previous set
   (`replace_recovery_codes`) and does not say so. It also stores the
   first secret again (a new version when the name already exists).
10. **The authenticator code field can be off screen** (screen 9). The QR
    code takes about 25 rows. On a terminal of about 30 rows the code field
    and the Verify and Skip buttons fall below the bottom edge, leaving the
    manual key on the last line above the footer, while focus sits on a
    field nobody can see.
11. **Recovery wording reads as single-use.** "Each recovery code unlocks the
    vault once typed…" (`view.rs:292`, `docs/getting-started.md:64`) reads
    as "one use each"; the codes work until replaced.
12. **The Done screen points the wrong way** (screen 12). Its next steps
    are secret commands with `--vault` flags, plus a POSIX
    `VAR=value command` line in a PowerShell session.
13. **Smaller issues:**
    - The footer hint is cut off at 100 columns ("…go to the vaul").
    - The first secret's value is strength-gated as if every secret were
      a password the user chose (an API key is whatever the provider
      issued).
    - The vault name rule (lowercase, digits, hyphens) doesn't allow `_`.
    - The Overview shows "6 protectors", an implementation detail, but not
      the checks, storage or projects.

---

## 4. The target model

### 4.1 Concepts

| Concept | Meaning |
|---------|---------|
| **Vault** | One encrypted file on this machine, named with letters, digits, `-` or `_` (no spaces, at most 64, unique ignoring case). Always local: it is the catalog of its secrets wherever their values live. |
| **Vault key** | 256 random bits, generated when the vault is created, never shown, never stored in clear. Everything the vault seals uses it. |
| **Key wraps** | How the key is opened: **this machine** (a random key in the OS credential store, created at create and at import, no prompt) and the **recovery key** (anywhere). |
| **View check** | Optional, chosen at creation: a **password** (salted hash, optional **hint**), optionally plus an **authenticator code**. Asked only to view the vault (`ui`, listings, `audit`, changing its settings) and to reveal a value. It is a check, not encryption: it does not protect the values. |
| **Recovery key** | One generated code, shown once. It opens the vault on another machine, on a machine without a credential store, and in an exported copy; it also passes the view check. |
| **Storage** | Where the vault's secrets may live: **SourceOrrery vault** (always on) plus any of **HashiCorp Vault**, **AWS Secrets Manager**, **Azure Key Vault**. |
| **Connection** | The settings for one enabled third-party provider (address/mount/namespace, region/prefix/endpoint, vault URL) and how it authenticates. Stored in the vault, not in a manifest. |
| **Secret** | Name, value, storage location (and optional description, tags, time window). Added and managed in `ui`. |
| **Project** | A folder with a `sourceorrery.toml` built from secrets picked out of one vault. The vault records the folder's path and name. |

### 4.2 Commands

| Command | Role |
|---------|------|
| `sourceorrery setup` | The vault wizard. No vault yet: create one. Vaults exist: pick one to change, or create another. |
| `sourceorrery vault create [NAME]` | The same wizard with NAME filled in: creates it if new, opens it for changes if it exists. Has flags for a non-interactive create (CI, the SDK fixture vault). |
| `sourceorrery vault export [NAME] --out FILE` | A portable copy of the vault, without its view check. No check: the copy opens only with the recovery key. |
| `sourceorrery vault import FILE [--name NAME]` | Brings a vault onto this machine with its recovery key, then offers to set a view check again. |
| `sourceorrery vault list`, `vault destroy NAME` | Kept, as today. |
| `sourceorrery init [VAULT]` | Its own screens; requires a vault; no check. Which vault, then the vault's secrets (with All), then a loop adding new secrets to the vault, then write `sourceorrery.toml` and record the folder in the vault (§4.4). |
| `sourceorrery ui [VAULT]` | Asks the view check. Add and manage secrets (with storage), view projects, audit, vaults. |
| `sourceorrery check`, `run` | Just run, as today, resolved through the vault's storage routing. |
| `sourceorrery import .env` | As today, plus `--storage`. |
| `sourceorrery secret …` | Kept for scripts, CI and agents. `list`, `get` (with or without `--reveal`) and `versions` ask the view check; the rest just run. `set` gains `--storage`. Not part of setup. |
| `sourceorrery audit`, `completions` | As today. |

### 4.3 The vault wizard (`setup` / `vault create`)

Nothing is written until the review screen confirms. Today each step
writes as it goes (the vault at step 1, a secret at step 2, codes at
step 3…), so an abandoned run leaves a half-configured vault. The
authenticator seed is generated and verified in memory, then sealed at
commit.

| Screen | Content |
|--------|---------|
| **Start** | No vault in the home directory: "Create your first vault". Otherwise a list of vaults (name, view check, storage) and "Create a new vault". Changing an existing vault first asks its view check, if it has one, or the recovery key (hidden fields, in the screen). |
| **Name** | `[A-Za-z0-9_-]{1,64}`, validated as typed. Read-only when editing (no rename in the first cut). |
| **View check** | A checkbox: "Ask for a password before showing this vault or a value". Under it, once ticked: "Also ask for a code from an authenticator app". One line explains: "Only viewing the vault and revealing a value ask for it; `run`, `init` and your apps never do." |
| ↳ Password | Typed twice with the strength meter, or generated (shown once, behind the "written down" tick). An optional hint, refused if it matches the password. |
| ↳ Authenticator | QR **beside** the key, code field and buttons (two columns), so it fits 80×24. A code is verified before moving on. |
| **Recovery key** | Shown once, with the "written down" tick: "It opens this vault on another machine, in an exported copy, and where there is no credential store (WSL, containers, CI)." When editing, it is kept unless the user asks for a new one, and a new one says the old one stops working. Without an OS credential store, the screen also says the vault will open there with this key. |
| **Storage** | SourceOrrery vault (ticked, locked on), HashiCorp Vault, AWS Secrets Manager, Azure Key Vault. Providers not compiled into this build are shown as unavailable. |
| **Connections** | One form per ticked provider: HashiCorp (address, mount, namespace, auth), AWS (region, prefix, endpoint URL, credentials), Azure (vault URL, credentials). Credentials: "this machine's sign-in" (environment, CLI login, workload or managed identity, as today) or "stored in this vault" (sealed, never shown again). `[ Test connection ]` makes one metadata call and shows the provider's reason on failure (the existing messages: `UnknownIssuer`, 403, …). |
| **Review** | Everything above; `[ Create vault ]` or `[ Save changes ]`. One transaction. |
| **Done** | Vault, file, view check, storage. Next: `sourceorrery ui` to add secrets; `sourceorrery init` in a project folder. No secret commands, no shell-specific syntax. |

`setup --guide` (no terminal, or asked for) prints the non-interactive
`vault create` command with its flags instead of six commands.

### 4.4 `init`

```
sourceorrery init [VAULT] [--project-name NAME] [--all | --secret NAME …]
```

The vault is the source of truth, and `init` reads it without the view
check: it needs names, never values. Projects often share some secrets and
add a few of their own, so `init` has its own screens, built like the setup
wizard (`ui/init/`: a state machine over a backend, drawn by a view, driven
by a fake in tests). Without a terminal it takes `--all` or `--secret`
instead.

| Screen | Content |
|--------|---------|
| **Vault** | No vault exists → "no vault yet: run `sourceorrery setup`", with a button that starts it. One vault → this screen is skipped. Several → "Which vault?", a list with each vault's storage and number of secrets. |
| **Project** | Project name (default: the folder's name) and where the manifest goes (default `./sourceorrery.toml`). |
| **Secrets** | The vault's secrets as a checkbox list: name, storage, description and the environment variable it will be delivered in. **`[ All ]`** at the top ticks every one (and untick all again); `/` filters by name. |
| **Add new?** | "Add a new secret to the vault for this project?" `[ Add a secret ]` `[ No, continue ]`. Asked again after every secret added, so the user loops until done. |
| ↳ New secret | Name, validated as typed against the secret name rules and refused if the vault has it already ("tick it in the list instead"). Value and confirmation, hidden (dots from the length, a zeroising buffer, never shown), no strength rule (an API key is whatever its issuer made). Storage, when the vault has more than one. Optional description (it becomes `purpose`). Environment variable, derived and editable. `[ Store ]` puts the secret in the vault at once, so the value leaves memory straight away; the secret is ticked for this project. |
| **Review** | The secrets to write, with their variables and a `required` tick each, and the ones added to the vault on this run. `[ Write sourceorrery.toml ]`. Leaving before this writes no manifest; secrets already stored stay in the vault for any project to use, and the screen says so. |
| **Done** | The manifest's path, the count of secrets, and next: `sourceorrery run -- <your command>`, `sourceorrery check`. |

The manifest it writes. `purpose` comes from the secret's description in the
vault:

```toml
[project]
name = "my-application"
vault = "development"

[secrets.database-password]
required = true
purpose = "Database authentication"   # documentation only
```

Writing it also records the folder (path + project name) in the vault,
audited as `project_link`; each new secret is a `secret_set`.

**When `sourceorrery.toml` exists already**, `init` is the way to add to it
(there is no `--force`):

- **Straight to the list.** It loads the vault the manifest names and goes
  straight to the Secrets screen, skipping the Vault and Project screens.
  The project name and path stay as they are.
- **The list.** The manifest's secrets are ticked; the vault's other
  secrets are there to tick as well, and **All** works as before.
- **Missing from the vault.** A manifest entry the vault does not have is
  shown ticked and marked "not in the vault", with `[ Add its value ]`.
  That opens the New secret form with the name filled in.
- **Adding and unticking.** The add-new loop is the same, and each secret
  stored is ticked. Unticking an entry removes it from the manifest when
  it is written.
- **Writing.** The file is edited in place (`toml_edit`, already in the
  lock file), so comments, key order, `env` overrides, `version` pins,
  `required` flags and `[rotation.*]` tables survive. Only the
  `[secrets.*]` entries ticked or unticked change.
- **A vault this machine does not have.** If the named vault is missing,
  `init` says so and offers `vault import` (bring it here) or `setup`
  (create one under that name).

Without a terminal: `--all` or `--secret NAME …` pick secrets, and there is
no add-new step, since a value is never a command-line argument. A script
stores new secrets first (`secret set NAME --stdin`), then runs `init`.

`init --integration` (agent skills) is unchanged. `run` and `check` read the
vault the same way, with no check: the manifest names the vault and the
secrets, and the vault supplies the values.

### 4.5 `ui`

| View | Change |
|------|--------|
| **Overview** | Header: `vault development · password + authenticator · storage: SourceOrrery, Azure Key Vault`. Panels: secrets by status **and by storage**, expiry, audit chain, activity, **View check** (password, authenticator, recovery key issued on), **Storage** (each connection: target, credential source, last test result), **Projects** (count, how many missing). `c` opens the wizard on this vault; `a` adds a secret. |
| **Secrets** | New `STORAGE` and `PROJECTS` columns. Add (`a`): name → storage (one of the vault's enabled storages) → value at the hidden prompt with the screen suspended (the current rule stays). Details add the storage location and the projects that use the secret. |
| **Projects** (new) | `PATH · NAME · SECRETS · STATUS`. On open, each path is checked on disk: ✓ green when `sourceorrery.toml` is there, ✗ red when the folder or file is gone. `x` on a ✗ row removes the link (confirmed, audited `project_unlink`). `Enter` shows the manifest's secrets and whether each resolves (metadata only, as `check`). |
| Deleted, Audit log | As today. |
| **Vaults** | As today, plus `n`: create a vault (the wizard). |

The browser asks the view check when it opens a vault and again after its
idle lock. It still never shows, copies or holds a value, and still reads
each thing once. The project status check is a file-system look, not a vault
read, so it is not audited.

### 4.6 Export and import

- `vault export`:
  - No check: the copy opens only with the recovery key.
  - Writes a consistent copy of the vault file: settings, connections
    (credentials stay sealed), the catalog, local values, projects and the
    audit log, so the chain travels with it.
  - Leaves out this machine's key wrap and the view check (the password
    hash, the hint and the authenticator); the copy records that in its
    own log.
  - Replaces `backup`.
- `vault import`:
  - Opens the copy with the recovery key.
  - Verifies its name, settings and audit chain.
  - Adds this machine's key wrap and registers the vault under its name,
    or `--name`; a name that exists already (ignoring case) is refused.
  - Offers to set a view check again: through the wizard's check screen
    on a terminal, otherwise `--password-file`.
  - Replaces `restore`.

---

## 5. The vault key and the view check

The ADR has the details; the outline:

**What opens the vault key.** This machine's OS credential store, with no
prompt (as Windows Hello does), or the recovery key: on another machine, in
an exported copy, and where there is no credential store (WSL, containers,
CI, from `SOURCEORRERY_RECOVERY_KEY` or a file). A copied file opens only
with the recovery key.

**The view check.** Optional, chosen when the vault is created:

| Part | How it is checked | What the file holds |
|------|-------------------|---------------------|
| Password | Argon2id(password, salt) compared with the stored hash | The salted hash, sealed under the vault key; never the password |
| Hint (optional) | — | Sealed under the vault key; shown at the password prompt |
| Authenticator code (optional, "password plus") | RFC 6238 against the seed, one use per time step | The seed, sealed under the vault key, as today |

**Asked by:** `ui` (on opening and after its idle lock), `secret list`,
`secret get` (with or without `--reveal`), `secret versions`, `audit`, and
`vault create` on an existing vault, without which anyone could switch the
check off. Answers come from `SOURCEORRERY_PASSWORD` / `--password-file` and
`--code` / `SOURCEORRERY_TOTP` for scripts, else the prompt. The recovery key
also passes it.

**Never asked by:** `run`, `check`, `init`, `import`, the commands that
change secrets, `vault export` / `import`, `vault list` / `destroy` and the
SDKs. They just run; `init`, `run` and `check` read the vault as the source
of truth.

**Failures** are `permission_denied`, audited. After five wrong answers in a
row each attempt waits 30 seconds, doubling to 15 minutes. The recovery key
always works.

**What it is for:** stopping someone who uses SourceOrrery to look, such as a
technician or a colleague at an unlocked machine. It is a check, not
encryption, and the values are protected at rest by the vault key as today.
Someone who can run commands as the owner can still get values through
`run`, or read the credential store and the file with their own program.
James chose this over a password that also locks the key; the ADR records
the trade-off.

---

## 6. Decisions

James accepted the recommendations on 2026-10-24 and then narrowed the
checks. Where his answers changed a recommendation, the decision says so.

| # | Question | Decision |
|---|----------|----------|
| D1 | What the checks are | **Changed:** an optional view check, a password, chosen at creation. It is not encryption and does not protect the values. |
| D2 | A PIN | **Changed:** dropped. |
| D3 | The authenticator code | **Changed:** "password plus", only on top of a password. |
| D4 | Recovery | One recovery key (the existing 125-bit, 25-character recovery-code format), shown once. It opens the vault on another machine, in an export and where there is no credential store, and passes the view check. |
| D5 | What asks for the check | **Changed:** only viewing the vault (`ui`, `secret list`, `secret get`, `secret versions`, `audit`, changing its settings) and revealing a value. `run`, `check`, `init`, the SDKs and everything else just run. No unlock session is needed. |
| D6 | Connection credentials | A choice per connection: this machine's sign-in (environment, CLI login, workload identity), or stored sealed in the vault. |
| D7 | Connections per provider | One per provider kind to start; the data model is keyed by connection id so several are possible later. |
| D8 | Vault names | Letters, digits, `-`, `_`; unique ignoring case; no rename in the first cut. |
| D9 | `secret …` subcommands | Kept for scripts, CI and agents; left out of setup and its Done screen. |
| D10 | `backup` / `restore` | Replaced by `vault export` / `vault import`. |
| D11 | Exports | **Changed:** an export leaves out the view check and opens only with the recovery key. Import sets the check again. |
| D12 | Project → secret links | The vault stores path + name only; the manifest at that path is the source of its secret list. |
| D13 | A provider-stored secret in the local vault | A catalog row (name, storage, description, created); versions, enabled flag and expiry are the provider's (ADR 0008 mappings). |
| D14 | Value at the provider | In clear to the provider, so other consumers and provider-side rotation keep working. |
| D15 | Per-secret `vault = …` in the manifest | Removed: one vault per project, storage routing replaces it. |
| D16 | Naming | "Password" for the check (`SOURCEORRERY_PASSWORD`, `--password-file`); "recovery key" for opening a vault away from its machine (`SOURCEORRERY_RECOVERY_KEY`, `--recovery-key-file`). "Passphrase" goes. |
| D17 | Moving secrets out of a schema-3 vault | **Changed:** no migration path. James is deleting his existing vaults. Old files are refused with a message saying so. |
| D18 | The password hint | **Changed:** kept, optional, now sealed under the vault key instead of plain text. |
| D19 | `init` | **Changed:** no check. It reads the vault as the source of truth: at least one vault must exist, it asks which one when there are several, and it writes the picked secrets by name only. `run` and `check` read the vault the same way. |
| D20 | `init`'s screens | **Added by James:** `init` has its own screens. The secret list has an All toggle. Afterwards it asks, in a loop, whether to add a new secret (name by the rules, hidden value, storage when there is a choice), stores each in the vault, and then writes `sourceorrery.toml`. |
| D21 | `init` with an existing `sourceorrery.toml` | **Added by James:** it loads the vault the manifest names, ticks the manifest's secrets and lets new ones be added (from the vault, or through the add-new loop). The file is edited in place, so everything else in it survives. |

---

## 7. Plan

### Before starting

- **Merge the open branches first.** `quality-pass-2026-10-24` and
  `azure-key-vault-provider` should be pushed and merged before Phase 1,
  because Azure Key Vault is one of the storage choices. The Phase 0 drafts
  sit on a local branch, `vault-checks-and-storage`, stacked on
  `azure-key-vault-provider`; rebase it onto `origin/main` once those
  merge.
- **Keep CI runs few.** Work on one branch and open at most three PRs: (A)
  phases 0–3, (B) phases 4–5, (C) phase 6. Splitting further multiplies
  full CI runs.

### Phase 0: the design record (docs only) — done

- [ADR 0009](docs/adr/0009-local-vaults-checks-and-storage.md), *accepted*
  2026-10-24:
  - the vault as a local catalog;
  - the vault key and the view check;
  - storage, connections and routing;
  - projects and the manifest;
  - the command surface, export and import;
  - the schema 4 outline;
  - the threat-model changes.
- `docs/vault-format.md` and `docs/threat-model.md` describe the released
  build, so they change with the code that implements the ADR (Phases 1–2),
  not before it. Until then the ADR holds the schema and the threat-model
  changes.

Done: James approved the ADR on 2026-10-24, after D21.

### Phase 1: storage and core (`sourceorrery-core`, `-crypto`, `-storage`) — done

Every commit builds and passes the workspace tests. Where a storage change
removes an API, its callers (CLI, SDK, C ABI, bindings, conformance) move
in the same commit; the screens that later phases rebuild may be left
minimal in between, since nothing on this branch is released until the
whole change is. The commits, in order:

1. **Vault names** (D8):
   - `validate_vault_name` takes letters, digits, `-` and `_`.
   - The registry finds a vault by name ignoring case and refuses to
     create one whose name differs from an existing one only in case.
2. **Schema 4, no migration** (D17):
   - Older schemas are refused with a message that the vault must be
     recreated.
   - `migrate.rs`, `OpenOptions::allow_legacy_migration`,
     `VaultRegistry::migrate`, `vault migrate` and their tests go.
3. **Credential stores behind a trait:**
   - `keystore::CredentialStore`, with the OS store and an in-memory
     store for tests.
   - The registry carries one; `SOURCEORRERY_KEYRING=off` gives none.
   - A refactor only: behaviour is unchanged.
4. **Key wraps:**
   - `key_protectors` becomes `key_wraps` (this machine, one recovery
     key; HKDF for the recovery key).
   - Creating a vault returns its recovery key; opening tries this
     machine, then the recovery key.
   - Passphrase protectors, recovery codes, `vault protector`,
     `vault passphrase` and `vault recovery codes` go.
   - The unlock sources become `SOURCEORRERY_RECOVERY_KEY` /
     `SOURCEORRERY_RECOVERY_KEY_FILE` in the CLI, the SDK, the C ABI,
     the bindings and the fixture vault.
5. **The view check:**
   - The sealed password hash and hint, the authenticator under the
     password, the failure counter with its delay, and `check_view`
     (which the recovery key also passes).
   - The reveal guard and the clear-text hint go.
   - The CLI asks for the check where it asked for the guard.
6. **Export and import in storage:**
   - `export_to(path)`: a consistent copy without this machine's wrap or
     the view check.
   - `import_from(path, recovery key)`: verified, given this machine's
     wrap, registered.
   - New audit operations: `vault_change`, `vault_export`,
     `vault_import`.

The tables for storage, connections and projects, and `secrets.description`,
arrive with Phases 2 and 4, which use them.

Done when:

- the storage and core tests pass with `Argon2Params::TESTING` and the
  in-memory credential store;
- the view check is tested with and without the password and the code,
  right and wrong;
- a copied file opens with the recovery key and nothing else;
- an export carries no password hash, hint or seed;
- the five-failure delay holds across processes.

### Phase 2: storage routing (`sourceorrery-provider`, conformance) — done

- **`Routed`:** a `SecretClient` over a local vault that dispatches each
  call by the secret's `storage`. Local values stay in the file.
  Provider-stored secrets go to that connection's client
  (`open_connection(connection, credentials)` replacing
  `open_remote(name, &RemoteVault)`). The catalog row is written in the
  same operation as the provider call. A failure on either side is
  reported, never half-applied silently.
- **Placement and contract:** `Routed` lives in `sourceorrery-provider`
  (dispatch only, like the adapters there). The contract's operations are
  unchanged; choosing the storage of a *new* secret is `Routed`'s own
  method.
- **Capabilities:** per storage, so rotation refuses a secret whose
  provider lacks `PerVersionProperties`.
- **Local audit of remote access:** reads and changes of provider-stored
  secrets are recorded in the local audit log too (new; today a remote
  vault has no local log).
- **Provider crates:** constructors take connection settings plus a
  credential source (ambient, or explicit credentials as `SecretBytes`).
  The `[vaults.*]` parsing goes. *Done but for the parsing:*
  `ConnectionSettings` and `Credentials` are in `core::connection`, each
  provider's `connect` takes `Option<&Credentials>` (none = its ambient
  chain), and `open_connection` replaces `open_remote`. The manifest still
  reads `[vaults.*]` into `ConnectionSettings` (`RemoteVault` is an alias)
  until Phase 3 resolves projects through the vault.
- **Connections in the vault** (done): the `connections` table, with
  `SqliteVault::{connections, connection, add_connection,
  set_connection_settings, set_connection_credentials, remove_connection,
  record_connection_test, connection_credentials}`. Stored credentials are
  sealed under the vault key (AAD `sourceorrery/v4/connection/<vault
  id>/<id>`); each row is tagged and the settings record lists every row
  with its tag, so a row edited, added, removed or replaced by an older
  copy is refused. One connection per provider. Changes are audited as
  `vault_change`, tests as the new `connection_test`. A vault made on this
  branch before the table existed must be recreated (no migration).
- **`secrets.storage`** (done): a connection id, or NULL for the file, in
  the row's tag (and so its checkpoints), with a foreign key to
  `connections`. A row with a storage is a catalog entry with no versions:
  the vault's own `SecretClient` operations and the old backup refuse it
  (`unsupported`, naming the connection) and its listings leave it out.
  For `Routed`: `storage_of(name)`, `secrets_at(connection)`, and
  `record_at_connection(connection, operation, name, version, result,
  CatalogChange::{Keep, Add, Remove})`, which audits what was done at the
  provider (`at connection <id>`, with the error code on failure) and
  catalogues or removes the entry in the same transaction, only when the
  provider call succeeded. `remove_connection` refuses a connection that
  still stores a secret, naming them. `secrets.description` is not added
  yet (it comes with `init`, Phase 4).
- **`Routed`** (done, `sourceorrery-provider/src/routed.rs`): routes each
  call by `storage_of`, opens a connection on first use (stored or ambient
  credentials; `with_opener` for tests and the live suites) and records
  every provider call with `record_at_connection`. New secrets go to the
  file unless `storing_new_in(connection)`; `set_secret_in` picks a
  storage explicitly. Listings are the vault's own while no connection
  stores anything, else the merged, catalog-filtered list paged by name
  (an unreachable provider fails the listing). `missing()` reports what a
  provider lost out of band and `forget_missing` drops it once confirmed.
  Capabilities are per storage through the new core
  `SecretClient::capabilities_of` (rotation uses it); `capabilities()` is
  the new-secret storage's. Tested: the lifecycle suite over the file and
  over a stand-in connection (`tests/routed.rs`), the catalog scenarios,
  and the lifecycle suite in each provider's `live` test with stored
  credentials.
- **Conformance:**
  - `lifecycle(fresh)` runs against `Routed` once per storage kind:
    local always, providers in their CI jobs.
  - New scenarios: catalog and provider agree after set, delete, recover
    and purge; a connection a secret still uses cannot be removed; a
    secret deleted at the provider out of band is reported, not hidden;
    listing shows every storage.

Done when the lifecycle suite passes for `Routed` over local storage, and
over each provider in its live job.

### Phase 3: the SDK, the C ABI and bindings — done

Done in three commits, because two pieces this phase needs were planned
later: the CLI's non-interactive storage flags (Phase 4) and the CI
provider jobs and federation scripts (Phase 6), which wrote `[vaults.*]`.

1. *Done:* the manifest loses `[vaults.*]` and the per-secret `vault` key
   (both refused with a message saying what replaced them); `SecretReader`
   and `Project` read through `Routed`, and an error names the provider of
   the secret's storage; `OpenOptions::manifest` and
   `SecretReader::provider` go, and with them `manifest` in the C ABI's
   options JSON (an unknown key now; no declaration changes, so
   `SO_ABI_VERSION` stays) and in every binding, whose remote-vault tests
   go too; the CLI's `Opened` wraps `Routed` (`check`, `run`, `secret`,
   rotation), its remote-vault paths go, and `audit` points at the trail
   of each provider that stores a secret.
2. *Done:* `vault create NAME --recovery-key-out FILE` takes one flag set
   per provider, named by it: `--hashicorp-vault ADDRESS`
   [`--hashicorp-vault-mount`, `-namespace`, `-token-file`];
   `--aws-secrets-manager REGION` [`--aws-secrets-manager-prefix`,
   `-endpoint`, `--aws-access-key-id` with `--aws-secret-access-key-file`];
   `--azure-key-vault URL` [`--azure-tenant-id`, `--azure-client-id`,
   `--azure-client-secret-file`]. A credential comes from a file only;
   without one the connection is ambient. Every connection is checked
   before the vault is created, and a refused one removes it again.
   `secret set` and `import` take `--storage sourceorrery|<provider>|<id>`
   for new secrets; `vault info` lists the connections. `docs/cli.md`
   gains these in Phase 6.
3. *Done:* `fixture-vault.sh` takes one provider's `vault create` flags
   after the home directory; the `ci` vault then has that connection and
   keeps `remote-password` (and, per version, `remote-rotated-key`) there,
   and a second manifest names a local and a remote secret
   (`SOURCEORRERY_TEST_REMOTE_MANIFEST`). The harness's remote scenarios
   read them through the same vault. Each provider job makes that fixture
   with the connection's credentials stored and none in the environment,
   and runs the Rust and C runners with `--remote`. The federation scripts
   create a vault whose connection stores nothing and prove each platform
   identity through it. Proven locally against the Vault dev server and
   LocalStack for AWS and for Azure (Rust runner, all three federation
   scripts); the C runner needs CI.

- **`crates/sourceorrery`:**
  - `OpenOptions` replaces `passphrase` / `passphrase_file` with
    `recovery_key` / `recovery_key_file`. An SDK never asks the view
    check.
  - `Project::load` resolves through `Routed`; the manifest has no
    `[vaults.*]`.
  - The `locked` hint names the recovery-key sources.
- **`sourceorrery-ffi`:**
  - The C options struct's passphrase fields become recovery-key fields,
    an ABI change versioned under ADR 0007 (`SO_ABI_VERSION` bumped).
  - The header is regenerated, and `bindings/go/sourceorrery.h` with it.
- **Bindings:**
  - Each binding passes the renamed options through; the error codes are
    unchanged, and there is still no logic in them.
  - Their docs and tests drop `[vaults.*]` (the Python tests and the
    Python and Node sources mention it today).
- **SDK harness:**
  - `tests/conformance/sdk/scenarios.json` and `harness.py` read the
    remote cases through the fixture vault's connection (item 3).
  - `scripts/ci/fixture-vault.sh` uses
    `vault create … --recovery-key-out …` with the connection flags and
    `secret set --storage`, and still exports `SOURCEORRERY_RECOVERY_KEY`.

Done when every SDK suite passes against the new fixture vault.

### Phase 4: CLI surface and the wizard (`sourceorrery-cli`) — done

Done in seven commits, each buildable and tested on its own:

1. *Done:* `vault export [NAME] --out FILE` and `vault import FILE
   [--name NAME]` over Phase 1's storage; import sets the view check
   again from `--password-file`, and says how otherwise until the wizard
   offers it. `backup` and `restore` go, with the backup format in core
   and storage and its conformance tests. The error codes
   `backup_passphrase` and `backup_format`, and the audit operations
   `vault_backup` and `secret_restore`, stay, since codes are never taken
   back.
2. *Done:* storage for projects and descriptions, deferred from Phase 1.
   `projects` rows hold a keyed MAC of the folder's path (one record per
   folder), the path and project name sealed under the vault key (AAD
   `sourceorrery/v4/project/<vault id>/<id>`) and a tag; the settings
   record lists them by id and tag after the connections, so a row edited,
   added, removed or replayed is refused. `link_project` (absolute UTF-8
   path; a folder linked again keeps its id and takes the new name),
   `unlink_project` and `projects`; audited `project_link` /
   `project_unlink` by id only. `secrets.description` (one line, at most
   200 characters) is in the row's tag and checkpoints, for file and
   catalog rows alike: `set_description` (`secret_update`, without the
   text) and `description_of` (`secret_inspect`); `secret set
   --description`. An export carries both. Vault files made on this branch
   before this commit lack the table and column and must be recreated
   (schema 4 is unreleased; no migration).
3. *Done:* `init [VAULT] [--project-name NAME] [--all | --secret NAME …]
   [--path FILE]` without screens. It needs a vault on this machine: the
   one an existing manifest names (another one asked for is refused, and
   a missing one points at `vault import` and `vault create`), else VAULT
   or `--vault`, else the only one; several are listed. It reads the
   vault's catalog (`SqliteVault::catalog`, audited `secret_list`, no view
   check), declares each pick as `[secrets.<name>]` with `required =
   true` and `purpose` from the description, and records the folder
   (canonical, without Windows' `\\?\` prefix). An existing manifest is edited
   in place with `toml_edit`: new tables land after its other secrets and
   every other byte stays; its project name is kept. Without picks it
   refuses and says how; `--vault-name`, `--force` and
   `Manifest::template` are gone. `init --integration` installs the
   skills and writes the manifest only when secrets are picked (a
   manifest now comes from the vault), else says how to write one.
4. *Done:* `ui/init/`, the §4.4 screens, shown by `init` on a terminal
   when no secret is picked with a flag (`--theme` as for `ui`). A state
   machine (`wizard.rs`: Vault, Project, Secrets, Add new, New secret,
   Review, Done) over `backend.rs` (`Backend`: `vaults`, `open`, `store`,
   `write`; `Live` and the test fake), drawn by `view.rs`. The vault opens
   before the screen starts, or with it suspended, since it may prompt for
   the recovery key. Secrets: a checkbox list with **All**, `/` filters,
   storage, variable and description per row; a manifest entry the vault
   lacks is marked and Enter gives it a value. New secret: name checked as
   typed (rules, and "tick it in the list" for one the vault has), the
   value twice in hidden fields, storage when there is more than the vault
   file, description, variable (derived, editable, checked against the
   other picks); `[ Store ]` sends it to the vault at once. Review:
   `required` per secret, what is taken out (with its rotation table),
   what was stored; nothing is written before it, and leaving earlier says
   which secrets stayed in the vault. The flag path and the screens share
   `commands::init`'s edit (`Change::{Add, Remove, Required}`). Differences
   from §4.4: the vault list shows names only (a count or the storage
   would mean unlocking every vault); with no vault the screen names
   `vault create` until the setup wizard gives it a button (commit 5); a
   value given from the list returns to the list.
5. *Done:* `ui/setup/`, the §4.3 wizard, shown by `setup` and by `vault
   create [NAME]` on a terminal: NAME is created when new and changed
   when it exists; `vault create` with any flag of the non-interactive
   create, or without a terminal, creates at once. A state machine
   (`wizard.rs`: Start, Unlock, Name, View check, Password,
   Authenticator, Recovery key, Storage, Connections, Review, Done) over
   `backend.rs` (`Backend`: `vaults`, `store`, `providers`, `open`,
   `check_view`, `test_connection`, `commit`; `Live` and the test fake),
   drawn by `view.rs`. Opening a vault to change it never prompts: this
   machine's key, else its recovery key typed on the screen (which passes
   the view check by itself); then the view check, asked on the screen
   with the hint. The password is rated as it is typed, or generated and
   shown once behind a "written down" tick. The authenticator key is made
   and verified in memory: the QR code on the left, the key, the code
   field and the buttons on the right; three wrong codes make a new key.
   The recovery key is made in memory and shown once (storage's
   `RecoveryKey`, `VaultRegistry::create_with_recovery_key`); a change
   keeps it unless a new one is asked for. Providers not compiled in are
   shown as unavailable. Each connection form takes this machine's
   sign-in or credentials stored in the vault (dots; the stored ones are
   kept when none are typed), and `[ Test connection ]` makes one
   metadata call through `open_connection`. The review commits the whole
   of it with storage's `SqliteVault::change_settings` (`SettingsChange`:
   `PasswordChange`, `AuthenticatorChange`, the recovery key and
   `ConnectionChange`s): one transaction, each part checked and audited
   as when made alone, a part refused rolling back every other and
   leaving one `vault_change` failure; a new vault that cannot take its
   settings is removed again. A refused commit stays on the review, and
   trying again sends the same recovery key. `setup --guide` (or no
   terminal, or JSON) prints the non-interactive `vault create NAME
   --recovery-key-out FILE` with its optional flags; that create takes
   the global `--password-file` and makes the password and the
   connections in the same transaction. Differences from §4.3: the start
   screen lists the vaults on this machine with "Create a new vault";
   retention and purge stay flags of the non-interactive create.
5a. *Done:* the interim `vault password | 2fa | recovery-key | info`
   commands go (and `commands/checks.rs` with them); the vault
   subcommands are §4.2's `create`, `list`, `export`, `import` and
   `destroy`. The password, the authenticator and a new recovery key are
   set on the setup screens; without them `vault create` and `vault
   import` take `--password-file`, and the authenticator is the screens'
   only (ADR 0009, section 7). `vault password generate | check` go with
   them: the screens generate and rate a password. `vault info`'s details
   are the `ui` Overview's and the screens'; `vault list` stays a listing
   that opens nothing (opening every vault would write an audit row in
   each, and a failure row in every one this machine cannot open), and
   `vault create -o json` reports the keys that open the new vault (kind
   and id), which the keyring smoke scripts check the credential store
   against; their recovery-key replacement checks go (the screens' live
   test proves the old key stops working). The QR renderer keeps only the
   one-module quiet zone. The SDK's `locked` hint points at `sourceorrery
   vault create NAME` for a new recovery key, and `vault import` at it for
   a view check. The CLI tests of the removed commands move to `vault
   create --password-file`; enrolment, verification and replay stay
   covered by the screens', the storage's and `context`'s tests. The
   storage operations they called (`set_password`, `clear_view_check`,
   `enrol_authenticator`, `replace_recovery_key`, …) stay, for those tests
   and the conformance suite. `docs/` and the site still describe the
   removed commands until Phase 6.
6. *Done:* snapshots of every new screen in every theme for James's
   review: `init`'s and the setup wizard's (over their fakes, the
   authenticator also at 80×24), and the browser's new ones (Phase 5).
   `cargo test -p sourceorrery-cli ui::snapshot -- --ignored` writes them
   to `target/ui-snapshots`.

- **`cli.rs`:**
  - The §4.2 surface.
  - Removed: the `vault protector | passphrase | 2fa | guard | recovery |
    info | migrate` subcommands, `backup`, `restore`, and `--protector` on
    `vault create`.
  - The D16 names land: `--password-file`, `--recovery-key-file`,
    `--recovery-key-out`.
- **`ui/setup/`, rewritten:**
  - `wizard.rs`: the §4.3 state machine (Start, Name, ViewCheck, Password,
    Authenticator, RecoveryKey, Storage, Connections, Review, Done),
    in-memory until Review.
  - `backend.rs`: a new `Backend` with `list_vaults`, `open(name)`,
    `check(answers)`, `test_connection` and `commit(plan)`. `Live` and the
    fake implement it.
  - `view.rs`:
    - the two-column authenticator screen (problem 10);
    - labels taken from the vault's actual record (problem 7);
    - the wording fixes (problems 11–13).
- **Commands:**
  - `setup.rs`: `--guide` prints the non-interactive create.
  - `vault.rs`: create or update, export, import, list, destroy.
  - `guard.rs` → `view_check.rs`: one `enforce`, called only by the
    viewing commands of §5.
  - `project.rs::init`: the flag path of §4.4 (`--all`, `--secret`).
- **`ui/init/`, new:**
  - The §4.4 screens, laid out like `ui/setup/`: `wizard.rs` (Vault,
    Project, Secrets, AddNew, NewSecret, Review, Done), `view.rs`,
    `backend.rs`.
  - `backend.rs`: `list_vaults`, `secrets(vault)` (names, storage,
    descriptions; no value), `store(name, value, storage, description)`,
    `write_manifest(plan)` and `link_project`. `Live` and the fake
    implement it.
  - Hidden fields follow the setup wizard's rules: drawn from their length,
    held in zeroising buffers, gone to the vault as `SecretBytes` on
    `[ Store ]`.
  - `secret.rs` and `import.rs`: `--storage`.
  - `backup.rs`: removed.
  - `context.rs`: opens `Routed` and has no manifest remote lookup.
- **Tests:**
  - Wizard tests through the fake: every screen, with and without a
    password and a code, and a cancelled run leaves nothing behind.
  - `init` tests through its fake: All and none, a loop of several new
    secrets, a taken or invalid name refused, a value that never reaches a
    screen buffer, and leaving before Review writes no manifest.
  - `init` on an existing manifest: it opens on the named vault with the
    manifest's secrets ticked, a missing one is marked and can be given a
    value, and new ones are added. A manifest with comments, `env`
    overrides, a `version` pin and a `[rotation]` table keeps all of them
    byte for byte outside the changed entries.
  - `tests/cli.rs` end to end with `SOURCEORRERY_HOME` isolation: the
    viewing commands ask, and `run`, `check` and `init` never do.
  - Design snapshots for every new screen in every theme
    (`cargo test -p sourceorrery-cli ui::snapshot -- --ignored`).

Done when:

- clippy (pedantic) is clean;
- James has reviewed the snapshots;
- repeating the §2.1 screenshot run on a fresh home shows none of
  problems 7–13.

### Phase 5: the `ui` browser — done

Done as planned, in the one commit the branch became, with these details:

- The browser opens a vault through `Routed`, as `run` and `secret` do:
  `MetadataSource` and `MetadataEditor` are implemented for it (the
  SQLite-only implementations went). The secret list is the file's plus
  one listing per connection that stores secrets (`Routed::list_at` and
  `list_deleted_at`, new); a provider that fails is noted
  (`Unreachable`, its code on the Storage panel) and the rest is shown.
- `MetadataSource` gains `secrets_at`, `deleted_at`, `connections`,
  `stored_at`, `view_settings` (what the check asks for, whether a hint
  is set, the authenticator's enrolment) and `capabilities_of`; nothing
  returns a value. `MetadataEditor` gains `add_secret(name, value,
  options, storage)` and `unlink_project(id)`.
- `ui::edit` checks a change against the storage's capabilities (a
  per-secret service's older version, a time window Key Vault cannot
  remove, a disabled first version), so the provider never refuses it.
  The new-secret form has a storage field when the vault has
  connections.
- Overview: the header names the view check and the storages; the
  Secrets panel counts by storage; the bottom row is Vault, View check,
  Storage (each connection's secrets, sign-in and last test, its target)
  and Projects (found and missing). Secrets: `STORAGE` and `PROJECTS`
  columns, and the details name both. Projects (view 3): path, name, the
  manifest's secret count and ✓/✗, read with the vault; Enter shows the
  manifest's secrets and whether each resolves; `x` forgets a project
  whose folder or manifest is gone (confirmed, `project_unlink`). `c`
  runs the setup screens on the open vault (or the one selected in
  Vaults) and `n` on Vaults creates one, on the browser's own terminal;
  the vault is read again afterwards.
- The view check on open and after the idle lock was already there:
  reopening asks it again.

- **`source.rs`:** `MetadataSource` gains `connections()` (settings and
  last test, never credentials), `view_check()` (what is set, never the
  hash or the seed) and `projects()`. Still no method returns a value.
- **`editor.rs`:** `MetadataEditor` gains `add_secret(name, value,
  storage)` (the value from `prompt::read_hidden` with the screen
  suspended, as now) and `unlink_project(path)`. Still no purge, protector
  or acknowledgement operations. Vault settings change through the wizard
  (`c`), not the editor.
- **`app.rs` and `view/`:**
  - The Overview panels, the Secrets columns, the Projects view with the
    on-open path check and ✓/✗, and Vaults `n`.
  - The view check when a vault opens and after the idle lock.
- **Audit:** the projects list is read once per open or `r`, like the
  secret list. Path checks are not vault reads.

Done when the browser tests and snapshots pass and the CLAUDE.md browser
rules still hold as written, apart from the two editor additions.

### Phase 6: docs, skills, site, release notes — done

Done as planned, in the same commit. Beyond the list below: the crate and
package READMEs and Cargo descriptions, the bindings' doc comments, the
site's hand-written pages (`getting-started.mdx`, `guides/headless.md`,
`index.mdx`) and `sync-docs.mjs` descriptions, a note on
`docs/security-review.md` that it predates ADR 0009, and the settings
record's replay written up as threat-model gap 6 with a roadmap item.

- **Docs:** `docs/cli.md` (rewritten sections: setup, vault, init, ui,
  export/import), `getting-started.md` (vault → `ui` → `init` → `run`),
  `architecture.md`, `threat-model.md`, `vault-format.md`, `enterprise.md`,
  `docs/providers/*.md` (connections set up in the wizard instead of
  manifest tables), `docs/sdks/*`, `rotation.md`, `README.md`, `CLAUDE.md`
  and the banner quick start. ADR 0009 gains a Measurements section, as
  ADR 0008 has. `backup-format.md` goes, with the links to it from
  `architecture.md`, `cli.md`, `roadmap.md`, `threat-model.md` and
  `vault-format.md` (Phase 4 removed the format).
- **Skills:** `crates/sourceorrery-cli/skills/` (five files mention
  `setup`, `secret set` or the guard), then
  `SOURCEORRERY_BLESS=1 cargo test -p sourceorrery-cli --test integrations`.
  The skills must still never tell an agent to read, print or write a
  value.
- **CI:** *done in Phase 3:* the `provider-vault`, `provider-aws` and
  `provider-azure` jobs and `scripts/ci/*-federation.sh` create connections
  instead of writing `[vaults.*]`, and every job that opens a vault gets
  the recovery key from the fixture. Every job stays in the `CI` gate's
  `needs:`.
- **Release notes:** CHANGELOG "Unreleased" gets one breaking-change entry:
  vaults from earlier releases are not read (D17). The site docs are
  re-synced.

---

## 8. What goes away

No compatibility layer is planned for any of these:

- **Setup steps:** the first secret, the reveal guard and the project step;
  the setup `--secret`, `--project-name` and `--path` flags.
- **The reveal guard**, as a separate setting and as `vault guard`: the
  view check replaces it.
- **Vault subcommands:** `vault protector`, `vault passphrase`, `vault 2fa`,
  `vault recovery`, `vault info` and `vault migrate` (folded into the
  wizard, `vault list` and the Overview); `vault create --protector`.
- **Passphrase protectors:** this machine's wrap and one recovery key
  replace them; the wrap is managed for the user, not listed.
- **Backups:** `backup` and `restore`, and `SOURCEORRERY_BACKUP_PASSPHRASE`.
- **Manifest tables and overrides:** `[vaults.<name>]` tables and the
  per-secret `vault = …` override (D15).
- **Old vault files:** schemas 1–3, refused (D17).
- **`SOURCEORRERY_PASSPHRASE` and `SOURCEORRERY_PASSPHRASE_FILE`:** replaced
  by the recovery-key variables for opening and `SOURCEORRERY_PASSWORD` for
  the check (D16).
