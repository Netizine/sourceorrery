//! `VaultBackup` for the SQLite vault: the privileged export that reads
//! every version's value, and the restore that writes versions through
//! the same checkpointed path as `set_secret`.

use std::collections::BTreeMap;

use rusqlite::Transaction;
use sourceorrery_core::audit::{AuditOperation, AuditOutcome};
use sourceorrery_core::backup::{
    DeletedState, ExportOptions, RESTORED_CREATED_ON_TAG, RESTORED_FROM_TAG, RestoreOptions,
    RestoreReport, RestoredSecret, SecretSnapshot, SkipReason, SkippedSecret, Snapshot,
    VaultBackup, VersionSnapshot,
};
use sourceorrery_core::{
    Result, SecretBytes, SecretClient, SecretError, SetSecretOptions, timestamp,
    validate_secret_name,
};
use sourceorrery_crypto::{aead, random};

use super::audit::{Checkpoints, vault_checkpoints};
use super::rows::{NewVersion, SecretRow, load_ciphertext};
use super::schema::{crypto, db, from_nanos, nanos, opt_from_nanos, value_aad};
use super::{ListingWindow, SqliteVault};
use crate::integrity::Checkpoint;

impl SqliteVault {
    /// Every version of `name` with its value, oldest first, verified like
    /// a read and decrypted whatever its policy state. Only `export` calls
    /// this.
    fn export_versions(
        &self,
        tx: &Transaction<'_>,
        name: &str,
        window: &mut ListingWindow,
        checkpoints: &BTreeMap<String, Checkpoint>,
    ) -> Result<Vec<VersionSnapshot>> {
        let raw = window.versions.remove(name).unwrap_or_default();
        let mut versions = self.verify_versions(name, raw, checkpoints)?;
        versions.reverse(); // newest first in the vault, oldest first in a backup
        let mut out = Vec::with_capacity(versions.len());
        for row in versions {
            let ciphertext = load_ciphertext(tx, name, &row.props.version)?;
            let plaintext = aead::open(
                &self.dek,
                value_aad(&self.meta.id, name, &row.props.version).as_bytes(),
                &ciphertext,
            )
            .map_err(crypto)?;
            let props = row.props;
            out.push(VersionSnapshot {
                version: props.version,
                enabled: props.enabled,
                content_type: props.content_type,
                tags: props.tags,
                not_before: props.not_before,
                expires_on: props.expires_on,
                created_on: props.created_on,
                updated_on: props.updated_on,
                value: SecretBytes::new(plaintext.to_vec()),
            });
        }
        Ok(out)
    }

    /// Write one secret of a snapshot: a new live row when the target has
    /// none, then every version in order, each a keyed `secret_restore`
    /// event with its checkpoint. Returns how many versions were written.
    fn restore_secret(
        &self,
        tx: &Transaction<'_>,
        secret: &SecretSnapshot,
        add_to_existing: bool,
    ) -> Result<usize> {
        let op = AuditOperation::SecretRestore;
        let name = secret.name.as_str();
        let now = timestamp::now();
        let now_nanos = nanos(now)?;
        let mut state = if add_to_existing {
            None
        } else {
            let row = SecretRow {
                created_on: now_nanos,
                deleted_on: None,
                scheduled_purge_on: None,
                recovery_id: None,
            };
            Some(Checkpoint::Present(self.insert_secret(tx, name, &row)?))
        };
        for source in &secret.versions {
            let mut tags = source.tags.clone();
            tags.insert(RESTORED_FROM_TAG.to_owned(), source.version.clone());
            tags.insert(
                RESTORED_CREATED_ON_TAG.to_owned(),
                timestamp::format(source.created_on),
            );
            let options = SetSecretOptions {
                content_type: source.content_type.clone(),
                tags,
                enabled: source.enabled,
                not_before: source.not_before,
                expires_on: source.expires_on,
            };
            options.validate()?;
            let version = random::random_hex(16).map_err(crypto)?;
            let seq: i64 = tx
                .query_row(
                    "SELECT COALESCE(MAX(seq), 0) + 1 FROM secret_versions",
                    [],
                    |row| row.get(0),
                )
                .map_err(db)?;
            let ciphertext = aead::seal(
                &self.dek,
                value_aad(&self.meta.id, name, &version).as_bytes(),
                source.value.expose(),
            )
            .map_err(crypto)?;
            let version_tag = self.insert_version(
                tx,
                &NewVersion {
                    name,
                    version: &version,
                    seq,
                    ciphertext: &ciphertext,
                    options: &options,
                    now: now_nanos,
                },
            )?;
            self.audit_change(
                tx,
                op,
                name,
                Some(&version),
                Some(&format!("from version {}", source.version)),
                Checkpoints {
                    state: state.take(),
                    version: Some(Checkpoint::Present(version_tag)),
                },
            )?;
        }
        Ok(secret.versions.len())
    }
}

impl VaultBackup for SqliteVault {
    fn export(&self, options: &ExportOptions) -> Result<Snapshot> {
        let op = AuditOperation::VaultBackup;
        let mut conn = self.lock()?;
        let tx = self.begin(&mut conn, op)?;
        if let Some(names) = &options.secrets {
            for name in names {
                if let Err(err) = validate_secret_name(name) {
                    return self.fail(tx, op, None, None, err);
                }
            }
        }
        let result = (|| -> Result<Snapshot> {
            let checkpoints = vault_checkpoints(&tx, &self.metadata_key, &self.meta.id)?;
            let mut window = Self::listing_window(&tx, &checkpoints, None, usize::MAX)?;
            let no_versions = BTreeMap::new();
            let wanted = |name: &str| {
                options
                    .secrets
                    .as_ref()
                    .is_none_or(|names| names.iter().any(|n| n == name))
            };
            let mut secrets = Vec::new();
            let mut seen: Vec<&str> = Vec::new();
            let names = std::mem::take(&mut window.names);
            for name in &names {
                let state = checkpoints.get(name);
                let row = self.verify_secret_row(
                    name,
                    window.rows.remove(name),
                    state.and_then(|c| c.state),
                )?;
                let Some(row) = row else { continue };
                if !wanted(name) {
                    continue;
                }
                seen.push(name);
                let deleted = match row.deleted_on {
                    None => None,
                    Some(_) if !options.include_deleted => continue,
                    Some(deleted_on) => Some(DeletedState {
                        deleted_on: from_nanos(deleted_on)?,
                        scheduled_purge_on: opt_from_nanos(row.scheduled_purge_on)?,
                    }),
                };
                let versions = self.export_versions(
                    &tx,
                    name,
                    &mut window,
                    state.map_or(&no_versions, |c| &c.versions),
                )?;
                self.audit(
                    &tx,
                    op,
                    Some(name),
                    None,
                    AuditOutcome::Success,
                    Some(&format!("{} versions", versions.len())),
                )?;
                secrets.push(SecretSnapshot {
                    name: name.clone(),
                    created_on: from_nanos(row.created_on)?,
                    deleted,
                    versions,
                });
            }
            if let Some(missing) = options
                .secrets
                .as_ref()
                .and_then(|names| names.iter().find(|n| !seen.contains(&n.as_str())))
            {
                return Err(SecretError::NotFound {
                    name: missing.clone(),
                });
            }
            Ok(Snapshot {
                vault: self.meta.name.clone(),
                vault_id: self.meta.id.clone(),
                created_on: timestamp::now(),
                secrets,
            })
        })();
        match result {
            Ok(snapshot) => {
                tx.commit().map_err(db)?;
                Ok(snapshot)
            }
            Err(err) => self.fail(tx, op, None, None, err),
        }
    }

    fn restore(&self, snapshot: &Snapshot, options: &RestoreOptions) -> Result<RestoreReport> {
        let op = AuditOperation::SecretRestore;
        let mut report = RestoreReport::default();
        for secret in &snapshot.secrets {
            if options
                .only
                .as_ref()
                .is_some_and(|only| !only.iter().any(|n| n == &secret.name))
            {
                continue;
            }
            let name = secret.name.as_str();
            let written = {
                let mut conn = self.lock()?;
                let tx = self.begin(&mut conn, op)?;
                let tx = self.validated(tx, op, name)?;
                let existing = match self.load_secret_row(&tx, name) {
                    Ok(row) => row,
                    Err(err) => return self.fail(tx, op, Some(name), None, err),
                };
                let add_to_existing = match existing {
                    Some(row) if row.deleted_on.is_some() => {
                        tx.commit().map_err(db)?;
                        report.skipped.push(SkippedSecret {
                            name: name.to_owned(),
                            reason: SkipReason::Deleted,
                        });
                        continue;
                    }
                    Some(_) if !options.overwrite => {
                        tx.commit().map_err(db)?;
                        report.skipped.push(SkippedSecret {
                            name: name.to_owned(),
                            reason: SkipReason::Exists,
                        });
                        continue;
                    }
                    Some(_) => true,
                    None => false,
                };
                match self.restore_secret(&tx, secret, add_to_existing) {
                    Ok(count) => {
                        tx.commit().map_err(db)?;
                        count
                    }
                    Err(err) => return self.fail(tx, op, Some(name), None, err),
                }
            };
            let deleted = options.keep_deleted && secret.deleted.is_some();
            if deleted {
                self.delete_secret(name)?;
            }
            report.restored.push(RestoredSecret {
                name: name.to_owned(),
                versions: written,
                deleted,
            });
        }
        Ok(report)
    }
}
