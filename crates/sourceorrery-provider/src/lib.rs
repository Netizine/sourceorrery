//! # SourceOrrery providers
//!
//! The SourceOrrery contract has two shapes, both defined in
//! `sourceorrery-core`: [`SecretClient`] for backends that answer from local
//! storage and [`AsyncSecretClient`] for backends that wait on the network.
//! This crate holds the adapters that turn one into the other, so every
//! backend serves both and the rest of the workspace needs to know only
//! one of them:
//!
//! * [`Blocking`] makes an [`AsyncSecretClient`] a [`SecretClient`] by
//!   driving each call to completion on a Tokio runtime. The CLI, the C ABI
//!   and the conformance suite reach remote providers through it.
//! * [`AsyncLocal`] makes a [`SecretClient`] an [`AsyncSecretClient`] by
//!   running each call on Tokio's blocking pool, so an async application
//!   reads the local vault without stalling its executor.
//!
//! Neither adapter interprets a call: arguments, results and errors pass
//! through unchanged, and a value is only ever held in `SecretBytes`. The
//! remote providers themselves are separate crates built on
//! [`AsyncSecretClient`] (see `docs/adr/0008-remote-providers.md`).

#![forbid(unsafe_code)]

mod blocking;
mod local;

pub use blocking::Blocking;
pub use local::AsyncLocal;
pub use sourceorrery_core::{AsyncSecretClient, SecretClient};

#[cfg(test)]
mod tests;
