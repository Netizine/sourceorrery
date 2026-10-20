# Contributing to SourceOrrery

Thank you for helping build a secrets platform that developers and their
agents can trust. A few rules keep that trust intact.

## The non-negotiables

1. **Secret values never leave `SecretBytes`** except through the single
   deliberate disclosure path (`get --reveal`, `run`, SDK `value` accessors).
   No value in a log line, an error message, an audit record, a `Debug`
   impl, a metadata struct or a test fixture that is written to disk
   unencrypted.
2. **The Rust core owns semantics.** If a backend or binding needs a rule,
   the rule goes in `sourceorrery-core` and gets a conformance test.
3. **Error codes are append-only.** `SecretError::code` values are a
   contract with every SDK. Add new ones; never rename or reuse.
4. **No cryptography of our own.** Audited primitives only, wrapped in
   `sourceorrery-crypto`. Changes there need a second reviewer.
5. **Names are Azure Key Vault compatible** so vaults can be mirrored to a
   managed service later.

## Development

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

CI runs the same on Ubuntu, Windows and macOS, plus a build with
`--no-default-features` (no OS keyring) for headless servers.

Tests must not touch the real OS credential store: use passphrase
protectors with `Argon2Params::TESTING` (see `tests/conformance`).

## Pull requests

* One logical change per PR, with tests. Behavioural changes to the
  `SecretClient` contract need a conformance test in `tests/conformance`.
* Update `CHANGELOG.md` under *Unreleased*.
* Document user-facing changes in `docs/cli.md`.
* Commit messages: imperative subject line, body explaining *why*.

## Licence

By contributing you agree your work is dual-licensed under MIT and Apache
2.0, like the rest of the project.
