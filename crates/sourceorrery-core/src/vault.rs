//! Vault naming and description.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::{Result, SecretError};
use crate::secret::RecoveryLevel;

/// Maximum length of a vault name.
pub const MAX_VAULT_NAME_LEN: usize = 64;

/// Validate a vault name: 1–64 ASCII letters, digits, hyphens or
/// underscores, not starting with a hyphen (a command line would read it as
/// a flag). Vault names become file names and URI authorities, so the rules
/// are stricter than secret names. Two names that differ only in case name
/// the same vault (Windows and macOS file names ignore case); the registry
/// enforces that.
pub fn validate_vault_name(name: &str) -> Result<()> {
    let invalid = |reason: &str| SecretError::InvalidName {
        name: name.to_owned(),
        reason: reason.to_owned(),
    };
    if name.is_empty() {
        return Err(invalid("must not be empty"));
    }
    if name.len() > MAX_VAULT_NAME_LEN {
        return Err(invalid("must be at most 64 characters"));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(invalid(
            "may contain only ASCII letters, digits, hyphens and underscores",
        ));
    }
    if name.starts_with('-') {
        return Err(invalid("must not start with a hyphen"));
    }
    Ok(())
}

/// Non-sensitive description of a vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultDescriptor {
    /// Vault name.
    pub name: String,
    /// Stable random identifier, bound into every ciphertext's AAD.
    pub id: String,
    /// Backend kind (`encrypted-sqlite`, ...).
    pub backend: String,
    /// On-disk location for file-backed vaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_on: OffsetDateTime,
    /// Deletion behaviour for secrets in this vault.
    pub recovery_level: RecoveryLevel,
    /// Soft-delete retention in days.
    pub retention_days: u32,
    /// The kinds of key that open this vault (`this-machine`, `recovery`).
    #[serde(default)]
    pub protectors: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_names() {
        assert!(validate_vault_name("development").is_ok());
        assert!(validate_vault_name("prod-eu-1").is_ok());
        assert!(validate_vault_name("Prod").is_ok());
        assert!(validate_vault_name("has_underscore").is_ok());
        assert!(validate_vault_name("_leading").is_ok());
        assert!(validate_vault_name("prod-").is_ok());
        assert!(validate_vault_name(&"a".repeat(64)).is_ok());
        assert!(validate_vault_name("").is_err());
        assert!(validate_vault_name("-prod").is_err());
        assert!(validate_vault_name("has space").is_err());
        assert!(validate_vault_name("dot.ted").is_err());
        assert!(validate_vault_name("../escape").is_err());
        assert!(validate_vault_name("café").is_err());
        assert!(validate_vault_name(&"a".repeat(65)).is_err());
    }
}
