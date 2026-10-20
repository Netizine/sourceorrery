//! # SourceOrrery storage
//!
//! The local **encrypted vault** backend: a single SQLite file holding
//! versioned, individually encrypted secret values, their metadata, the
//! wrapped vault key and a metadata-only audit log.
//!
//! ## Key hierarchy
//!
//! ```text
//! key protector (OS keyring entry | Argon2id(passphrase))
//!        │  wraps (XChaCha20-Poly1305, AAD = vault id + protector id)
//!        ▼
//! vault DEK ── encrypts each value (AAD = vault id + secret name + version)
//! ```
//!
//! A vault may have several protectors wrapping the same DEK, so a vault
//! created with the Windows Credential Manager can also be unlocked with a
//! passphrase inside WSL, Docker or CI.
//!
//! ## What is and is not encrypted
//!
//! Encrypted: every secret value. Plaintext: vault metadata, secret names,
//! version identifiers, tags, timestamps and audit events. Do not put
//! sensitive information in names or tags.
//!
//! Plaintext is not unprotected: mutable metadata (enabled flags, time
//! windows, tags, deletion state) carries an HMAC tag under a key derived
//! from the DEK, and the audit log is a keyed hash chain. See
//! [`integrity`].

#![forbid(unsafe_code)]

pub mod integrity;
pub mod keystore;
pub mod protector;
pub mod registry;
pub mod sqlite;
pub mod unlock;

pub use integrity::AuditVerification;
pub use protector::{ProtectorInfo, ProtectorKind, ProtectorSpec};
pub use registry::{DestroyReport, VaultRegistry};
pub use sqlite::{CreateVaultOptions, OpenOptions, SqliteVault};
pub use unlock::{NoInteraction, PassphrasePrompt, StaticPassphrase, UnlockProvider};

/// Backend identifier reported in [`sourceorrery_core::VaultDescriptor`].
pub const BACKEND_NAME: &str = "encrypted-sqlite";

/// On-disk schema version written to new vaults. Older vaults are migrated
/// forward on first unlock; see [`sqlite::SqliteVault::open`].
pub const SCHEMA_VERSION: u32 = 2;

/// File extension of vault files.
pub const VAULT_FILE_EXTENSION: &str = "sorvault";
