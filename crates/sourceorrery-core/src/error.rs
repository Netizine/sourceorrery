//! Typed errors with stable, language-neutral codes.

use thiserror::Error;

/// Result alias used throughout SourceOrrery.
pub type Result<T> = std::result::Result<T, SecretError>;

/// Every failure a secret operation can report.
///
/// Each variant maps to a stable code via [`SecretError::code`]. Messages are
/// for humans and may change; codes are a compatibility contract for SDKs.
///
/// Error messages never contain secret values. Variants carry names, versions
/// and timestamps only.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SecretError {
    /// The named secret does not exist (and is not in the deleted state).
    #[error("secret '{name}' was not found")]
    NotFound { name: String },

    /// The secret exists but the requested version does not.
    #[error("version '{version}' of secret '{name}' was not found")]
    VersionNotFound { name: String, version: String },

    /// The secret has been soft-deleted and must be recovered before use.
    #[error("secret '{name}' is deleted; recover it before use")]
    Deleted { name: String },

    /// A soft-deleted secret with this name blocks creating a new one.
    #[error("a deleted secret named '{name}' exists; recover or purge it first")]
    DeletedConflict { name: String },

    /// Recovery or purge was requested for a secret that is not deleted.
    #[error("secret '{name}' is not in the deleted state")]
    NotDeleted { name: String },

    /// The version is disabled by policy.
    #[error("secret '{name}' version '{version}' is disabled")]
    Disabled { name: String, version: String },

    /// The version's activation time has not been reached.
    #[error("secret '{name}' version '{version}' is not valid before {not_before}")]
    NotYetValid {
        name: String,
        version: String,
        not_before: String,
    },

    /// The version's expiry time has passed.
    #[error("secret '{name}' version '{version}' expired on {expires_on}")]
    Expired {
        name: String,
        version: String,
        expires_on: String,
    },

    /// The name does not satisfy the naming rules.
    #[error("invalid name '{name}': {reason}")]
    InvalidName { name: String, reason: String },

    /// A caller-supplied argument was rejected.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// The caller is authenticated but not authorised.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// The vault could not be opened (no key for this machine, a wrong
    /// recovery key, ...).
    #[error("vault is locked: {0}")]
    Locked(String),

    /// The vault does not exist.
    #[error("vault '{name}' was not found")]
    VaultNotFound { name: String },

    /// A vault with this name already exists.
    #[error("vault '{name}' already exists")]
    VaultExists { name: String },

    /// A project manifest could not be read or is invalid.
    #[error("manifest error: {0}")]
    Manifest(String),

    /// A cryptographic operation failed (authentication failure, bad key, ...).
    #[error("cryptographic failure: {0}")]
    Crypto(String),

    /// The storage backend failed.
    #[error("storage failure: {0}")]
    Storage(String),

    /// An I/O operation failed.
    #[error("i/o failure: {0}")]
    Io(String),

    /// The backend does not implement this operation.
    #[error("unsupported operation: {0}")]
    Unsupported(String),

    /// The vault file was written by an earlier release, in an on-disk
    /// format this release does not read. There is no migration: the
    /// format changed with how a vault is opened and checked, so the vault
    /// is recreated (the code keeps its old name; codes are append-only).
    #[error(
        "vault '{name}' was written by an earlier release (schema {schema}); this release \
         cannot open it: recreate the vault with `sourceorrery setup`"
    )]
    MigrationRequired { name: String, schema: u32 },

    /// The file found for the requested vault holds a different vault: it
    /// was renamed or copied from that vault, or swapped in by someone who
    /// can write the vault directory. Refused so that a vault is never
    /// served under another vault's name.
    #[error("the file for vault '{requested}' holds the vault '{found}'")]
    VaultMismatch { requested: String, found: String },

    /// The passphrase did not open an encrypted backup file. No operation
    /// produces it since `vault export` replaced backups (ADR 0009); it
    /// stays because codes are never taken back.
    #[error("the passphrase does not open this backup")]
    BackupPassphrase,

    /// A backup file was written in a newer format than the build read.
    /// No operation produces it since `vault export` replaced backups
    /// (ADR 0009); it stays because codes are never taken back.
    #[error("backup format {version} is newer than this build understands; upgrade sourceorrery")]
    BackupFormat { version: u16 },

    /// A remote provider has no credentials for this process, or they have
    /// expired. `reason` is the provider's own description of what is
    /// missing: never a credential, nor any part of one.
    #[error("not authenticated to {provider}: {reason}")]
    Unauthenticated { provider: String, reason: String },

    /// A remote provider could not be reached or answered with a server
    /// error. Transient: the same call may succeed later.
    #[error("{provider} is unavailable: {reason}")]
    ProviderUnavailable { provider: String, reason: String },

    /// A rotation step was asked for in a state that does not allow it: a
    /// validated candidate is already waiting, there is nothing to activate
    /// or retire, or the grace period has not ended. The message carries
    /// versions and times only.
    #[error("rotation of '{name}': {reason}")]
    Rotation { name: String, reason: String },
}

impl SecretError {
    /// Stable, `snake_case` code for this error.
    ///
    /// SDKs map these to idiomatic exceptions; the CLI prints them in JSON
    /// output. Codes are append-only: a code is never renamed or reused.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => "not_found",
            Self::VersionNotFound { .. } => "version_not_found",
            Self::Deleted { .. } => "deleted",
            Self::DeletedConflict { .. } => "deleted_conflict",
            Self::NotDeleted { .. } => "not_deleted",
            Self::Disabled { .. } => "disabled",
            Self::NotYetValid { .. } => "not_yet_valid",
            Self::Expired { .. } => "expired",
            Self::InvalidName { .. } => "invalid_name",
            Self::InvalidArgument(_) => "invalid_argument",
            Self::PermissionDenied(_) => "permission_denied",
            Self::Locked(_) => "locked",
            Self::VaultNotFound { .. } => "vault_not_found",
            Self::VaultExists { .. } => "vault_exists",
            Self::Manifest(_) => "manifest",
            Self::Crypto(_) => "crypto",
            Self::Storage(_) => "storage",
            Self::Io(_) => "io",
            Self::Unsupported(_) => "unsupported",
            Self::MigrationRequired { .. } => "migration_required",
            Self::BackupPassphrase => "backup_passphrase",
            Self::BackupFormat { .. } => "backup_format",
            Self::VaultMismatch { .. } => "vault_mismatch",
            Self::Unauthenticated { .. } => "unauthenticated",
            Self::ProviderUnavailable { .. } => "provider_unavailable",
            Self::Rotation { .. } => "rotation",
        }
    }

    /// True when retrying the same call later could succeed without
    /// administrative action (e.g. a `not_yet_valid` secret).
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::NotYetValid { .. } | Self::ProviderUnavailable { .. }
        )
    }
}

impl From<std::io::Error> for SecretError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique() {
        let errors = [
            SecretError::NotFound { name: "a".into() },
            SecretError::VersionNotFound {
                name: "a".into(),
                version: "b".into(),
            },
            SecretError::Deleted { name: "a".into() },
            SecretError::DeletedConflict { name: "a".into() },
            SecretError::NotDeleted { name: "a".into() },
            SecretError::Disabled {
                name: "a".into(),
                version: "b".into(),
            },
            SecretError::NotYetValid {
                name: "a".into(),
                version: "b".into(),
                not_before: "t".into(),
            },
            SecretError::Expired {
                name: "a".into(),
                version: "b".into(),
                expires_on: "t".into(),
            },
            SecretError::InvalidName {
                name: "a".into(),
                reason: "r".into(),
            },
            SecretError::InvalidArgument("x".into()),
            SecretError::PermissionDenied("x".into()),
            SecretError::Locked("x".into()),
            SecretError::VaultNotFound { name: "a".into() },
            SecretError::VaultExists { name: "a".into() },
            SecretError::Manifest("x".into()),
            SecretError::Crypto("x".into()),
            SecretError::Storage("x".into()),
            SecretError::Io("x".into()),
            SecretError::Unsupported("x".into()),
            SecretError::MigrationRequired {
                name: "a".into(),
                schema: 1,
            },
            SecretError::VaultMismatch {
                requested: "a".into(),
                found: "b".into(),
            },
            SecretError::BackupPassphrase,
            SecretError::BackupFormat { version: 2 },
            SecretError::Unauthenticated {
                provider: "p".into(),
                reason: "r".into(),
            },
            SecretError::ProviderUnavailable {
                provider: "p".into(),
                reason: "r".into(),
            },
            SecretError::Rotation {
                name: "a".into(),
                reason: "r".into(),
            },
        ];
        let mut codes: Vec<_> = errors.iter().map(SecretError::code).collect();
        let total = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), total, "error codes must be unique");
    }
}
