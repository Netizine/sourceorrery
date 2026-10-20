# ADR 0004: `get_secret` without a version returns the newest *accessible* version

**Status:** accepted · **Date:** 2026-10-20

## Context

Azure Key Vault returns the newest version and fails if it is disabled.
During a rotation that goes wrong, operators want to roll back quickly
without re-uploading the old value.

## Decision

`get_secret(name, None)` returns the newest version that is enabled and
inside its `not_before`/`expires_on` window. Disabling a bad new version
therefore rolls consumers back to the previous one instantly. If no version
is accessible, the error describes why the *newest* one was rejected, which is
what a person debugging the rotation needs.

Explicit `get_secret(name, Some(version))` applies policy to that version only
and never falls back. `get_secret_properties` applies no policy, so disabled
and expired versions remain inspectable.

## Consequences

* Rollback is `secret update NAME --disable`.
* Consumers pinning versions (manifest `version = ...`) get exact semantics.
* Time windows are enforced per version, so an expired newest version yields
  an older, unexpired one if present. Documented in the CLI reference.
