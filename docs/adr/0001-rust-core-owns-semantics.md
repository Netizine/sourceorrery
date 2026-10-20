# ADR 0001: The Rust core owns all secret-management semantics

**Status:** accepted · **Date:** 2026-10-20

## Context

SourceOrrery will be consumed from many languages through several transports
(native bindings, a local broker, a C ABI). If each integration reimplements
rules — which version is "latest", what a disabled or expired version means,
how deletion and recovery behave, what an error is called — behaviour will
drift and the security story becomes unreviewable.

## Decision

`sourceorrery-core` is the single source of semantics: the `SecretClient`
contract, `SecretError` codes, naming rules, policy evaluation, audit types
and the manifest. Storage backends implement the contract; bindings expose it.
Neither adds business logic. `tests/conformance` encodes the semantics and
every backend and SDK must pass it.

## Consequences

* New behaviour is designed once, in Rust, with a conformance test.
* Bindings can be regenerated or replaced (UniFFI today, something else
  tomorrow) without changing what a secret operation means.
* The core must stay free of I/O and crypto so it can be embedded anywhere.
