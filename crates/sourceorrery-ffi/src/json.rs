//! JSON shapes that exist only at this boundary.
//!
//! Secret properties, deleted secrets, audit events, `SetSecretOptions` and
//! `UpdateSecretProperties` cross the boundary in the core's own serde
//! shape. The two inputs below have no serde form in the core, so they are
//! defined here; both reject unknown fields so a misspelt option fails
//! loudly instead of being ignored.

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use sourceorrery_core::audit::{AuditOperation, AuditQuery};
use sourceorrery_core::{RecoveryLevel, Result, SecretError};
use sourceorrery_crypto::Argon2Params;
use sourceorrery_storage::CreateVaultOptions;
use time::OffsetDateTime;

use crate::buffer::so_bytes;

/// Options accepted by `so_vault_create`. Every field is optional.
///
/// ```json
/// {
///   "recovery_level": "recoverable" | "purgeable",
///   "retention_days": 90,
///   "argon2": { "memory_kib": 65536, "iterations": 3, "parallelism": 1 }
/// }
/// ```
///
/// `argon2` sets the cost of the passphrase protector and is ignored for an
/// OS-keyring protector. Leave it unset outside tests: the defaults are the
/// interactive parameters from `sourceorrery_crypto::Argon2Params`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateOptions {
    /// Deletion behaviour for secrets in the vault.
    #[serde(default)]
    pub recovery_level: Option<RecoveryLevel>,
    /// Soft-delete retention in days (7–90).
    #[serde(default)]
    pub retention_days: Option<u32>,
    /// Passphrase key-derivation cost.
    #[serde(default)]
    pub argon2: Option<Argon2Params>,
}

impl CreateOptions {
    /// The vault settings, with defaults for anything unset.
    pub fn vault_options(&self) -> CreateVaultOptions {
        let defaults = CreateVaultOptions::default();
        CreateVaultOptions {
            recovery_level: self.recovery_level.unwrap_or(defaults.recovery_level),
            retention_days: self.retention_days.unwrap_or(defaults.retention_days),
        }
    }

    /// Argon2id parameters for a passphrase protector.
    pub fn argon2_params(&self) -> Argon2Params {
        self.argon2.unwrap_or_default()
    }
}

/// Filter accepted by `so_audit_events`. Every field is optional.
///
/// ```json
/// {
///   "secret_name": "database-password",
///   "operation": "secret_get",
///   "since": "2026-10-20T00:00:00Z",
///   "limit": 100
/// }
/// ```
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditFilter {
    /// Only events about this secret.
    #[serde(default)]
    pub secret_name: Option<String>,
    /// Only events of this operation.
    #[serde(default)]
    pub operation: Option<AuditOperation>,
    /// Only events at or after this time.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub since: Option<OffsetDateTime>,
    /// Return at most this many events, newest first.
    #[serde(default)]
    pub limit: Option<usize>,
}

impl From<AuditFilter> for AuditQuery {
    fn from(filter: AuditFilter) -> Self {
        Self {
            secret_name: filter.secret_name,
            operation: filter.operation,
            since: filter.since,
            limit: filter.limit,
        }
    }
}

/// Parse a JSON argument, reporting problems as `invalid_argument`.
pub(crate) fn parse<T: DeserializeOwned>(bytes: &[u8], what: &str) -> Result<T> {
    serde_json::from_slice(bytes)
        .map_err(|err| SecretError::InvalidArgument(format!("{what}: invalid JSON: {err}")))
}

/// Serialise a response into a caller-owned buffer.
pub(crate) fn to_bytes<T: Serialize>(value: &T) -> Result<so_bytes> {
    let json = serde_json::to_vec(value)
        .map_err(|err| SecretError::Storage(format!("cannot serialise response: {err}")))?;
    Ok(so_bytes::from_vec(json))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_options_default_and_reject_unknown_fields() {
        let options: CreateOptions = parse(b"{}", "options").unwrap();
        let vault = options.vault_options();
        assert_eq!(vault.recovery_level, RecoveryLevel::Recoverable);
        assert_eq!(vault.retention_days, 90);
        assert_eq!(options.argon2_params(), Argon2Params::INTERACTIVE);

        let options: CreateOptions = parse(
            br#"{"recovery_level":"purgeable","retention_days":7,"argon2":{"memory_kib":8192,"iterations":1,"parallelism":1}}"#,
            "options",
        )
        .unwrap();
        assert_eq!(
            options.vault_options().recovery_level,
            RecoveryLevel::Purgeable
        );
        assert_eq!(options.vault_options().retention_days, 7);
        assert_eq!(options.argon2_params(), Argon2Params::TESTING);

        let err = parse::<CreateOptions>(br#"{"retentionDays":7}"#, "options").unwrap_err();
        assert_eq!(err.code(), "invalid_argument");
    }

    #[test]
    fn audit_filter_maps_to_query() {
        let filter: AuditFilter = parse(
            br#"{"secret_name":"k","operation":"secret_get","since":"2026-10-20T00:00:00Z","limit":2}"#,
            "query",
        )
        .unwrap();
        let query = AuditQuery::from(filter);
        assert_eq!(query.secret_name.as_deref(), Some("k"));
        assert_eq!(query.operation, Some(AuditOperation::SecretGet));
        assert!(query.since.is_some());
        assert_eq!(query.limit, Some(2));
        assert_eq!(
            AuditQuery::from(parse::<AuditFilter>(b"{}", "query").unwrap()),
            AuditQuery::default()
        );
    }
}
