//! # SourceOrrery core
//!
//! Domain contracts shared by every SourceOrrery component: the CLI, the
//! storage backends, the (future) local broker and every language binding.
//!
//! This crate owns *semantics*. It contains no cryptography and no storage;
//! it defines what a secret, a version, a policy decision and an audit event
//! *are*, and the [`SecretClient`] contract every backend must honour (in
//! its async shape, [`AsyncSecretClient`], for backends that wait on the
//! network).
//!
//! The model follows the `SecretClient` shape of the managed cloud secrets
//! services (immutable versions, enable and disable, time windows, soft
//! delete and recovery), so the mental model is familiar, while depending
//! on none of them.
//!
//! ## Guarantees that belong to this crate
//!
//! * Secret values are only ever carried in [`SecretBytes`], which zeroises on
//!   drop, redacts itself in `Debug` output and has no `Serialize` impl.
//! * Secret and vault names are validated once, here, with one rule set.
//! * Access policy (enabled / not-before / expiry) is evaluated here so every
//!   backend enforces identical rules.
//! * Error variants carry stable string codes (see [`SecretError::code`]) so
//!   SDK bindings in other languages can map them consistently.

#![forbid(unsafe_code)]

pub mod audit;
pub mod backup;
pub mod error;
pub mod identity;
pub mod listing;
pub mod manifest;
pub mod policy;
pub mod remote;
pub mod secret;
pub mod timestamp;
pub mod traits;
pub mod vault;

pub use audit::{AuditEvent, AuditOperation, AuditOutcome, AuditQuery};
pub use backup::{
    ExportOptions, RESTORED_CREATED_ON_TAG, RESTORED_FROM_TAG, RestoreOptions, RestoreReport,
    RestoredSecret, SecretSnapshot, SkipReason, SkippedSecret, Snapshot, VaultBackup,
    VersionSnapshot,
};
pub use error::{Result, SecretError};
pub use identity::{Principal, PrincipalKind};
pub use listing::{ContinuationToken, ListOptions, Page};
pub use manifest::{MANIFEST_FILE_NAME, Manifest, ProjectSection, SecretRequirement};
pub use policy::{AccessPolicy, AllowAll, Decision, SoftDeletePolicy};
pub use remote::{Provider, RemoteVault, VaultConfig};
pub use secret::{
    DeletedSecret, RecoveryLevel, Secret, SecretBytes, SecretProperties, SecretReference,
    SetSecretOptions, UpdateSecretProperties, validate_secret_name, validate_version_id,
};
pub use traits::{AsyncSecretClient, SecretClient};
pub use vault::{VaultDescriptor, validate_vault_name};

/// Version of the public contract implemented by this crate.
///
/// Bindings and the broker protocol negotiate against this value, not against
/// the crate version, so the binding generator can change without changing
/// the meaning of a secret operation.
pub const CONTRACT_VERSION: &str = "1";

/// URI scheme used by [`SecretReference`] (`sourceorrery://vault/name/version`).
pub const REFERENCE_SCHEME: &str = "sourceorrery";
