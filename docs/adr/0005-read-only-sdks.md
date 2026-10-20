# ADR 0005: Language SDKs only read

**Status:** accepted · **Date:** 2026-10-20

## Context

Milestone 2 ships SourceOrrery to applications in Python, JavaScript and
TypeScript, Rust, Java, .NET, Go, C, C++ and PHP. The C ABI
(`sourceorrery-ffi`) exposes the whole `SecretClient` lifecycle, so the
SDKs could too. An application, however, only ever needs to *read*: it
opens the vault its manifest names and gets the values it was promised.
Creating, changing, deleting, recovering and purging secrets, managing
protectors and reading the audit log are administrative acts that belong
to a person at a terminal, with the CLI's confirmations and audit identity.

Every write path a library exposes is a path an attacker who controls the
application (a dependency, a prompt-injected agent, a bug) can use to
poison a secret, disable a version, or delete history. Removing those
paths from the SDKs removes that surface.

## Decision

1. **Every SDK is read-only.** The surface is: open a vault with the CLI's
   unlock order, get the newest accessible version or an explicit version,
   read a version's properties, resolve a `sourceorrery://` reference, load
   the secrets a `sourceorrery.toml` declares (mirroring `sourceorrery run`),
   and close. Nothing else.
2. **The C ABI gets a read-only handle type.** `so_reader_*` and
   `so_project_*` functions operate on `so_reader` / `so_project`, distinct
   from the write-capable `so_vault`. A binding links only those symbols,
   so even a bug in a binding cannot reach `so_secret_set`. The full
   `so_vault_*` surface stays for administrative tooling.
3. **All logic stays in Rust.** The `sourceorrery` client crate owns the
   unlock order (OS credential store, explicit passphrase,
   `SOURCEORRERY_PASSPHRASE`, `SOURCEORRERY_PASSPHRASE_FILE`, never a
   prompt), the manifest semantics and, for every failure, the *hint*: the
   actionable sentence that tells the person what to do (which CLI command
   creates the vault, which passphrase sources were tried, why a version
   was refused by policy, that an integrity failure means comparing with a
   backup). Bindings map the stable code to a typed error and carry code,
   message and hint through unchanged.
4. **Values are guarded in every language.** A value lives in native
   memory until the application closes it (zeroised by `so_bytes_free`),
   and the wrapper type prints as `[REDACTED]`, refuses serialisation where
   the language allows (pickle, `json.dumps`, `toJSON`, `serialize`,
   `encoding/json`) and copies bytes out only through a deliberate
   `expose()`-style call. Once an application copies the bytes, keeping
   them safe is its job; the documentation says so.
5. **Every SDK is proven in CI** against a vault the CLI creates in the
   job with a passphrase protector and `SOURCEORRERY_PASSPHRASE` in the
   environment, on Ubuntu, Windows and macOS: its tests, its example and,
   where the language has one, its type checker.

## Consequences

* Applications cannot rotate or write secrets through the SDK. Rotation is
  a CLI (and, later, broker) concern, as ADR 0001 already implies.
* `so_last_error_hint()` joins `so_last_error_code()` and
  `so_last_error_message()` in the C ABI; messages and hints never carry
  a value.
* Adding an operation to the SDKs means adding it to the `sourceorrery`
  crate and the `so_reader` surface first, with a conformance test, then
  to each binding; a binding never gains a capability on its own.
* The write-capable `so_vault_*` ABI remains for tooling but no shipped
  package exposes it.
