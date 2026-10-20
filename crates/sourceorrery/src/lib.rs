//! # SourceOrrery client
//!
//! The read-only client every SourceOrrery SDK is built on. It opens a vault
//! the way the `sourceorrery` CLI does, reads secret values and metadata,
//! resolves `sourceorrery://vault/name[/version]` references and loads the
//! secrets a project declares in `sourceorrery.toml`.
//!
//! It deliberately offers **no** way to create, change, delete, recover or
//! purge a secret and no protector or audit management: an application that
//! only reads cannot be tricked into writing. Administration is the CLI's job.
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
//! [`SecretReader::open`] unlocks the vault in the same order as the CLI:
//! the OS credential store first (no prompt), then a passphrase given in
//! [`OpenOptions`], then `SOURCEORRERY_PASSPHRASE`, then the file named by
//! `SOURCEORRERY_PASSPHRASE_FILE`. There is never an interactive prompt.
//! Vaults are looked up under `SOURCEORRERY_HOME` or the platform data
//! directory unless [`OpenOptions::home`] says otherwise.
//!
//! ## Errors
//!
//! Every failure is an [`Error`] carrying the core's stable code
//! ([`Error::code`]), a message and an actionable [`Error::hint`] that says
//! what to do about it (which CLI command creates the vault, which passphrase
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
    CONTRACT_VERSION, RecoveryLevel, Secret, SecretBytes, SecretProperties, SecretReference,
    VaultDescriptor,
};
pub use unlock::{PassphraseSource, UnlockReport};

/// Environment variable naming the SourceOrrery home directory.
pub const HOME_ENV: &str = sourceorrery_storage::registry::HOME_ENV;

/// Environment variable supplying a vault passphrase directly (CI only;
/// environment variables are visible to process inspection).
pub const PASSPHRASE_ENV: &str = "SOURCEORRERY_PASSPHRASE";

/// Environment variable naming a file that holds the vault passphrase.
pub const PASSPHRASE_FILE_ENV: &str = "SOURCEORRERY_PASSPHRASE_FILE";
