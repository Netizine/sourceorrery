//! # SourceOrrery storage
//!
//! The local **encrypted vault** backend: a single SQLite file holding
//! versioned, individually encrypted secret values, their metadata, the
//! wrapped vault key and a metadata-only audit log.
//!
//! ## Key hierarchy
//!
//! ```text
//! key wrap (this machine: a credential-store key | recovery: HKDF(recovery key))
//!        │  wraps (XChaCha20-Poly1305, AAD = vault id + wrap id)
//!        ▼
//! vault DEK ── encrypts each value (AAD = vault id + secret name + version)
//! ```
//!
//! Every vault has one recovery wrap, which opens it anywhere (another
//! machine, WSL, a container, CI, an exported copy), and usually a
//! this-machine wrap, which opens it here without asking. The optional view
//! check (a password, and an authenticator code on top) decides whether a
//! person may view the vault; it does not protect the values (ADR 0009).
//!
//! ## What is and is not encrypted
//!
//! Encrypted: every secret value, and the credentials a connection stores.
//! Plaintext: vault metadata, secret names, version identifiers, tags,
//! timestamps, connection settings (addresses, regions) and audit events.
//! Do not put sensitive information in names or tags.
//!
//! Plaintext is not unprotected: mutable metadata (enabled flags, time
//! windows, tags, deletion state) carries an HMAC tag under a key derived
//! from the DEK, the audit log is a keyed hash chain, and every change to a
//! row is checkpointed in that chain so an older authentic copy of the row
//! cannot be replayed. See [`integrity`].

#![forbid(unsafe_code)]

pub mod integrity;
pub mod keystore;
pub mod registry;
pub mod sqlite;
pub mod unlock;
pub mod wrap;

pub use integrity::AuditVerification;
pub use keystore::{CredentialStore, MemoryStore, NoStore, OsStore};
pub use registry::{DestroyReport, VaultRegistry};
/// Argon2id cost parameters, as `SqliteVault::set_password` takes them.
pub use sourceorrery_crypto::Argon2Params;
pub use sqlite::{
    Acknowledgement, AuthenticatorChange, CatalogChange, CatalogEntry, ConnectionChange,
    ConnectionInfo, ConnectionTest, CreateVaultOptions, Created, CredentialSource, FREE_FAILURES,
    Imported, MAX_DESCRIPTION_LEN, MAX_HINT_LEN, MAX_PROJECT_NAME_LEN, OpenOptions, PasswordChange,
    ProjectLink, RecoveryKey, SecondFactorInfo, SecretStorage, SettingsChange, SqliteVault,
    ViewAnswers, ViewCheck, validate_description,
};
pub use unlock::{NoInteraction, RecoveryKeyPrompt, StaticRecoveryKey, UnlockProvider};
pub use wrap::{WrapInfo, WrapKind};

/// Backend identifier reported in [`sourceorrery_core::VaultDescriptor`].
pub const BACKEND_NAME: &str = "encrypted-sqlite";

/// On-disk schema version written to new vaults, and the only one read.
/// A vault from an earlier release is refused by
/// [`sqlite::SqliteVault::open`] with `migration_required`; there is no
/// migration (ADR 0009).
pub const SCHEMA_VERSION: u32 = 5;

/// File extension of vault files.
pub const VAULT_FILE_EXTENSION: &str = "sorvault";
