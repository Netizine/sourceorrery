//! Encrypted backups: the in-memory [`Snapshot`] a vault exports and
//! restores, and the [`VaultBackup`] contract a backend implements.
//!
//! A snapshot carries secret *values*, so it lives only in memory, holds
//! each value as [`SecretBytes`] and has no `Serialize`. How it is sealed
//! into a file is the backend's business (`docs/backup-format.md`); the
//! CLI is the only consumer, SDKs stay read-only (ADR 0005).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::Result;
use crate::secret::SecretBytes;

/// Tag a restored version carries with the id of the version it came from.
pub const RESTORED_FROM_TAG: &str = "sourceorrery.restored-from";
/// Tag a restored version carries with the original version's creation time.
pub const RESTORED_CREATED_ON_TAG: &str = "sourceorrery.restored-created-on";

/// One version of a secret with its value.
#[derive(Debug)]
pub struct VersionSnapshot {
    pub version: String,
    pub enabled: bool,
    pub content_type: Option<String>,
    pub tags: BTreeMap<String, String>,
    pub not_before: Option<OffsetDateTime>,
    pub expires_on: Option<OffsetDateTime>,
    pub created_on: OffsetDateTime,
    pub updated_on: OffsetDateTime,
    /// The plaintext. `Debug` prints `[REDACTED]`.
    pub value: SecretBytes,
}

/// A secret's soft-deleted state at export time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletedState {
    pub deleted_on: OffsetDateTime,
    pub scheduled_purge_on: Option<OffsetDateTime>,
}

/// One secret with every version, oldest first.
#[derive(Debug)]
pub struct SecretSnapshot {
    pub name: String,
    pub created_on: OffsetDateTime,
    /// `Some` for a soft-deleted secret (only exported on request).
    pub deleted: Option<DeletedState>,
    pub versions: Vec<VersionSnapshot>,
}

/// Everything a backup holds: the secrets of one vault at one moment. No
/// audit rows: the log is the file's history, not its data.
#[derive(Debug)]
pub struct Snapshot {
    /// Name of the vault the snapshot was taken from.
    pub vault: String,
    /// Id of that vault.
    pub vault_id: String,
    pub created_on: OffsetDateTime,
    pub secrets: Vec<SecretSnapshot>,
}

impl Snapshot {
    /// Every version across every secret.
    pub fn version_count(&self) -> usize {
        self.secrets.iter().map(|s| s.versions.len()).sum()
    }
}

/// What to export.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExportOptions {
    /// Only these secrets; `None` exports every one. A name that does not
    /// exist is `not_found`.
    pub secrets: Option<Vec<String>>,
    /// Include soft-deleted secrets (with their deleted state).
    pub include_deleted: bool,
}

/// How to restore.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RestoreOptions {
    /// Only these secrets of the snapshot; `None` restores every one.
    pub only: Option<Vec<String>>,
    /// Add the versions to a secret that already exists instead of
    /// skipping it.
    pub overwrite: bool,
    /// Soft-delete a secret again after restoring it when the snapshot has
    /// it deleted; by default it comes back live.
    pub keep_deleted: bool,
}

/// Why a secret of the snapshot was not restored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// The target already has a live secret of that name (`overwrite` adds
    /// to it instead).
    Exists,
    /// The target has a soft-deleted secret of that name; recover or purge
    /// it first.
    Deleted,
}

/// A secret that was not restored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedSecret {
    pub name: String,
    pub reason: SkipReason,
}

/// A secret that was restored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoredSecret {
    pub name: String,
    /// Versions written.
    pub versions: usize,
    /// True when the secret was soft-deleted again (`keep_deleted`).
    pub deleted: bool,
}

/// What a restore did. Names and counts only.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreReport {
    pub restored: Vec<RestoredSecret>,
    pub skipped: Vec<SkippedSecret>,
}

/// Export and restore the secrets of a vault.
///
/// Semantics every implementation must honour (the conformance suite
/// checks them):
///
/// * `export` reads every version of each selected secret, **including
///   disabled and expired ones**, which `get_secret` would refuse: a
///   backup is complete or it is not a backup. It is the one privileged
///   read in the contract, and it is recorded as one `vault_backup` audit
///   event per secret (name and version count, never a value).
/// * `restore` goes through the ordinary write path: every version of the
///   snapshot becomes a **new** version of the target secret, oldest first
///   so the newest stays newest, with its metadata (enabled, content type,
///   tags, time window) kept and the original version id and creation time
///   recorded in the tags [`RESTORED_FROM_TAG`] and
///   [`RESTORED_CREATED_ON_TAG`]. Each written version is one keyed
///   `secret_restore` audit event with the row's checkpoint, exactly like
///   `secret_set`; nothing is inserted behind the integrity rules.
/// * A name that already exists in the target is skipped and reported
///   (`SkipReason::Exists`) unless `overwrite` is set, in which case the
///   versions are added on top. A name the target holds soft-deleted is
///   always skipped (`SkipReason::Deleted`). Restoring is therefore safe to
///   repeat.
/// * A deleted secret in the snapshot comes back live; with `keep_deleted`
///   it is soft-deleted again right after (one ordinary `secret_delete`).
/// * A snapshot name that is not a valid secret name is `invalid_name`.
pub trait VaultBackup {
    /// Take a snapshot of the vault's secrets with their values.
    fn export(&self, options: &ExportOptions) -> Result<Snapshot>;

    /// Write the snapshot's secrets into this vault.
    fn restore(&self, snapshot: &Snapshot, options: &RestoreOptions) -> Result<RestoreReport>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_never_shows_a_value() {
        let snapshot = Snapshot {
            vault: "dev".into(),
            vault_id: "id".into(),
            created_on: OffsetDateTime::UNIX_EPOCH,
            secrets: vec![SecretSnapshot {
                name: "api-key".into(),
                created_on: OffsetDateTime::UNIX_EPOCH,
                deleted: None,
                versions: vec![VersionSnapshot {
                    version: "v1".into(),
                    enabled: true,
                    content_type: None,
                    tags: BTreeMap::new(),
                    not_before: None,
                    expires_on: None,
                    created_on: OffsetDateTime::UNIX_EPOCH,
                    updated_on: OffsetDateTime::UNIX_EPOCH,
                    value: SecretBytes::from("CANARY-value-7f3a"),
                }],
            }],
        };
        let text = format!("{snapshot:?}");
        assert!(text.contains("api-key"));
        assert!(!text.contains("CANARY"), "{text}");
        assert_eq!(snapshot.version_count(), 1);
    }
}
