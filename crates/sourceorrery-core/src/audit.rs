//! Metadata-only audit events.
//!
//! An audit event records *that* something happened to a secret, by whom and
//! with what outcome. It never records the value. Backends must uphold this;
//! the conformance suite checks it.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::identity::Principal;

/// The operations SourceOrrery audits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOperation {
    /// A vault was created.
    VaultCreate,
    /// A vault was unlocked (or an unlock attempt failed).
    VaultOpen,
    /// A key protector was added to a vault.
    ProtectorAdd,
    /// A key protector was removed from a vault.
    ProtectorRemove,
    /// A new secret version was written.
    SecretSet,
    /// A secret value was read.
    SecretGet,
    /// Secret metadata was listed.
    SecretList,
    /// Version metadata was changed.
    SecretUpdate,
    /// A secret was soft-deleted.
    SecretDelete,
    /// A deleted secret was recovered.
    SecretRecover,
    /// A deleted secret was permanently purged.
    SecretPurge,
    /// The vault file was migrated to a newer schema version.
    VaultMigrate,
    /// The audit chain head was checked before appending to the log.
    /// Recorded with outcome `failure` when the check fails: rows were
    /// removed from the end of the log, or the head record is missing or
    /// invalid. Recorded with outcome `success` when the vault's owner
    /// acknowledges such a detection and lifts the block it placed on the
    /// vault.
    AuditVerify,
    /// Secret metadata was read without disclosing a value: properties, the
    /// version list, or a deleted secret's details.
    SecretInspect,
    /// Every version of a secret, disabled and expired ones included, was
    /// read for an encrypted backup (`VaultBackup::export`); one event per
    /// secret, with the version count as detail.
    VaultBackup,
    /// A version was written from a backup (`VaultBackup::restore`); one
    /// event per version, checkpointed like `secret_set`.
    SecretRestore,
    /// The reveal guard: a passphrase re-check or a second-factor code
    /// (`success` / `denied`), the second factor enrolled, verified or
    /// disabled, the guard or the passphrase hint changed. The detail names
    /// which; never a code, a secret or a hint.
    Guard,
}

impl AuditOperation {
    /// Stable `snake_case` label, identical to the serde form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VaultCreate => "vault_create",
            Self::VaultOpen => "vault_open",
            Self::ProtectorAdd => "protector_add",
            Self::ProtectorRemove => "protector_remove",
            Self::SecretSet => "secret_set",
            Self::SecretGet => "secret_get",
            Self::SecretList => "secret_list",
            Self::SecretUpdate => "secret_update",
            Self::SecretDelete => "secret_delete",
            Self::SecretRecover => "secret_recover",
            Self::SecretPurge => "secret_purge",
            Self::VaultMigrate => "vault_migrate",
            Self::AuditVerify => "audit_verify",
            Self::SecretInspect => "secret_inspect",
            Self::VaultBackup => "vault_backup",
            Self::SecretRestore => "secret_restore",
            Self::Guard => "guard",
        }
    }

    /// Every operation, for documentation and exhaustive tests.
    pub const ALL: [AuditOperation; 17] = [
        Self::VaultCreate,
        Self::VaultOpen,
        Self::ProtectorAdd,
        Self::ProtectorRemove,
        Self::SecretSet,
        Self::SecretGet,
        Self::SecretList,
        Self::SecretUpdate,
        Self::SecretDelete,
        Self::SecretRecover,
        Self::SecretPurge,
        Self::VaultMigrate,
        Self::AuditVerify,
        Self::SecretInspect,
        Self::VaultBackup,
        Self::SecretRestore,
        Self::Guard,
    ];
}

impl fmt::Display for AuditOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AuditOperation {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|op| op.as_str() == s)
            .ok_or_else(|| format!("unknown audit operation '{s}'"))
    }
}

/// How an audited operation ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    /// The operation completed.
    Success,
    /// Policy refused the operation (disabled, expired, unauthorised, ...).
    Denied,
    /// The operation failed for another reason (not found, storage error).
    Failure,
}

impl AuditOutcome {
    /// Stable lowercase label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Denied => "denied",
            Self::Failure => "failure",
        }
    }
}

impl FromStr for AuditOutcome {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "success" => Ok(Self::Success),
            "denied" => Ok(Self::Denied),
            "failure" => Ok(Self::Failure),
            other => Err(format!("unknown audit outcome '{other}'")),
        }
    }
}

impl fmt::Display for AuditOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One audit record. Contains no secret material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Monotonic identifier assigned by the backend.
    pub id: u64,
    /// When it happened.
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_on: OffsetDateTime,
    /// Who did it.
    pub actor: Principal,
    /// What they did.
    pub operation: AuditOperation,
    /// Which secret, if the operation targets one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,
    /// Which version, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// How it ended.
    pub outcome: AuditOutcome,
    /// Error code or short note. Never a secret value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Filter for [`crate::SecretClient::audit_events`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditQuery {
    /// Only events about this secret.
    pub secret_name: Option<String>,
    /// Only events of this operation.
    pub operation: Option<AuditOperation>,
    /// Only events at or after this time.
    pub since: Option<OffsetDateTime>,
    /// Return at most this many events, newest first.
    pub limit: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_labels_match_serde() {
        for op in AuditOperation::ALL {
            let json = serde_json::to_string(&op).unwrap();
            assert_eq!(json, format!("\"{}\"", op.as_str()));
            assert_eq!(op.as_str().parse::<AuditOperation>().unwrap(), op);
        }
    }

    #[test]
    fn outcome_round_trips() {
        for outcome in [
            AuditOutcome::Success,
            AuditOutcome::Denied,
            AuditOutcome::Failure,
        ] {
            assert_eq!(outcome.as_str().parse::<AuditOutcome>().unwrap(), outcome);
        }
    }
}
