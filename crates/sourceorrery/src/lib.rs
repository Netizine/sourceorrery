//! # SourceOrrery client
//!
//! The read-only client every SourceOrrery SDK is built on. It opens a vault
//! the way the `sourceorrery` CLI does, reads secret values and metadata,
//! resolves `sourceorrery://vault/name[/version]` references and loads the
//! secrets a project declares in `sourceorrery.toml`.
//!
//! It deliberately offers **no** way to create, change, delete, recover or
//! purge a secret and no key, check, connection or audit management.
//! Reads still append audit events. Use the separately installed CLI to
//! create vaults and set secret values:
//! [CLI installation guide](https://sourceorrery.ai/getting-started/#install).
//! Installing the SDK does not install the CLI, and applications do not
//! need a CLI process running alongside them.
//!
//! ```no_run
//! use sourceorrery::SecretReader;
//!
//! let reader = SecretReader::open("development")?;
//! let secret = reader.get("database-password")?;
//! connect(secret.value.expose());
//! # fn connect(_: &[u8]) {}
//! # Ok::<(), sourceorrery::Error>(())
//! ```
//!
//! ## Unlocking
//!
//! [`SecretReader::open`] opens the vault in the same order as the CLI:
//! this machine's key in the OS credential store first (no prompt), then
//! the vault's recovery key, given in [`OpenOptions`], in
//! `SOURCEORRERY_RECOVERY_KEY` or in the file named by
//! `SOURCEORRERY_RECOVERY_KEY_FILE`. There is never an interactive prompt,
//! and a reader never asks for the vault's view check, which guards only
//! people viewing the vault (ADR 0009).
//! Vaults are looked up under `SOURCEORRERY_HOME` or the platform data
//! directory unless [`OpenOptions::home`] says otherwise.
//!
//! ## Errors
//!
//! Every failure is an [`Error`] carrying the core's stable code
//! ([`Error::code`]), a message and an actionable [`Error::hint`] that says
//! what to do about it (which CLI command creates the vault, which key
//! sources were tried, why a version was refused by policy, ...). SDKs map
//! [`ErrorKind`] to their own exception types and keep the code and hint.
//!
//! ## Values
//!
//! A value is returned as [`SecretBytes`]: zeroised on drop, redacted in
//! `Debug` output and not serialisable. Once an application copies the bytes
//! out, keeping them safe is its job.

#![forbid(unsafe_code)]

mod error;
mod project;
mod reader;
mod unlock;

pub use error::{Error, ErrorKind, Result};
pub use project::{Project, ProjectSecret};
pub use reader::{OpenOptions, SecretReader};
pub use sourceorrery_core::{
    CONTRACT_VERSION, RecoveryLevel, Secret, SecretBytes, SecretError, SecretProperties,
    SecretReference, VaultDescriptor,
};
pub use unlock::{KeySource, UnlockReport};

/// Environment variable naming the SourceOrrery home directory.
pub const HOME_ENV: &str = sourceorrery_storage::registry::HOME_ENV;

/// Environment variable supplying a vault's recovery key directly, where
/// this machine's credential store cannot open it (CI, containers; an
/// environment variable is visible to process inspection).
pub const RECOVERY_KEY_ENV: &str = "SOURCEORRERY_RECOVERY_KEY";

/// Environment variable naming a file that holds the vault's recovery key.
pub const RECOVERY_KEY_FILE_ENV: &str = "SOURCEORRERY_RECOVERY_KEY_FILE";
