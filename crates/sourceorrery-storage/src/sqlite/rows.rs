//! Row types for secrets and versions, their authenticated reads and
//! writes, and version selection.

use std::collections::BTreeMap;

use rusqlite::{Connection, OptionalExtension, params};
use sourceorrery_core::policy;
use sourceorrery_core::{
    DeletedSecret, Result, SecretError, SecretProperties, SetSecretOptions, validate_version_id,
};
use sourceorrery_crypto::{Ciphertext, MAC_LEN, SymmetricKey};
use time::OffsetDateTime;

use super::SqliteVault;
use super::schema::{
    Meta, crypto, db, from_nanos, integrity_error, integrity_error_because, opt_from_nanos,
    opt_nanos, recovery_id,
};
use crate::integrity::{self, Checkpoint, SecretFields, VersionFields};

pub(super) struct SecretRow {
    pub(super) created_on: i64,
    pub(super) deleted_on: Option<i64>,
    pub(super) scheduled_purge_on: Option<i64>,
    pub(super) recovery_id: Option<String>,
}

impl SecretRow {
    pub(super) fn fields<'a>(&'a self, vault_id: &'a str, name: &'a str) -> SecretFields<'a> {
        SecretFields {
            vault_id,
            name,
            created_on: self.created_on,
            deleted_on: self.deleted_on,
            scheduled_purge_on: self.scheduled_purge_on,
            recovery_id: self.recovery_id.as_deref(),
        }
    }
}

pub(super) struct VersionRow {
    pub(super) props: SecretProperties,
    pub(super) ciphertext: Ciphertext,
    /// Stored fields the tag covers that `props` does not carry verbatim.
    pub(super) seq: i64,
    pub(super) created_on: i64,
}

/// Everything needed to insert one new version row.
pub(super) struct NewVersion<'a> {
    pub(super) name: &'a str,
    pub(super) version: &'a str,
    pub(super) seq: i64,
    pub(super) ciphertext: &'a Ciphertext,
    pub(super) options: &'a SetSecretOptions,
    pub(super) now: i64,
}

#[allow(clippy::struct_field_names)]
pub(super) struct RawVersion {
    pub(super) version: String,
    pub(super) seq: i64,
    pub(super) nonce: Vec<u8>,
    pub(super) ciphertext: Vec<u8>,
    pub(super) content_type: Option<String>,
    pub(super) tags_json: String,
    pub(super) enabled: bool,
    pub(super) not_before: Option<i64>,
    pub(super) expires_on: Option<i64>,
    pub(super) created_on: i64,
    pub(super) updated_on: i64,
    pub(super) tag: Option<Vec<u8>>,
}

impl RawVersion {
    pub(super) fn fields<'a>(&'a self, vault_id: &'a str, name: &'a str) -> VersionFields<'a> {
        VersionFields {
            vault_id,
            name,
            version: &self.version,
            seq: self.seq,
            enabled: self.enabled,
            content_type: self.content_type.as_deref(),
            tags_json: &self.tags_json,
            not_before: self.not_before,
            expires_on: self.expires_on,
            created_on: self.created_on,
            updated_on: self.updated_on,
        }
    }

    pub(super) fn into_row(
        self,
        meta: &Meta,
        key: &SymmetricKey,
        name: &str,
    ) -> Result<VersionRow> {
        if !integrity::verify_version_tag(key, &self.fields(&meta.id, name), self.tag.as_deref()) {
            return Err(integrity_error(name));
        }
        let tags: BTreeMap<String, String> = serde_json::from_str(&self.tags_json)
            .map_err(|err| SecretError::Storage(format!("corrupt tags for {name}: {err}")))?;
        let props = SecretProperties {
            vault: meta.name.clone(),
            name: name.to_owned(),
            version: self.version,
            enabled: self.enabled,
            content_type: self.content_type,
            tags,
            not_before: opt_from_nanos(self.not_before)?,
            expires_on: opt_from_nanos(self.expires_on)?,
            created_on: from_nanos(self.created_on)?,
            updated_on: from_nanos(self.updated_on)?,
            recovery_level: meta.recovery_level,
        };
        let ciphertext = Ciphertext::from_parts(&self.nonce, self.ciphertext).map_err(crypto)?;
        Ok(VersionRow {
            props,
            ciphertext,
            seq: self.seq,
            created_on: self.created_on,
        })
    }
}

pub(super) fn query_raw_versions(conn: &Connection, name: &str) -> Result<Vec<RawVersion>> {
    let mut stmt = conn
        .prepare(
            "SELECT version, seq, nonce, ciphertext, content_type, tags_json, enabled,
                    not_before, expires_on, created_on, updated_on, tag
             FROM secret_versions WHERE name = ?1 ORDER BY seq DESC",
        )
        .map_err(db)?;
    let raw = stmt
        .query_map(params![name], |row| {
            Ok(RawVersion {
                version: row.get(0)?,
                seq: row.get(1)?,
                nonce: row.get(2)?,
                ciphertext: row.get(3)?,
                content_type: row.get(4)?,
                tags_json: row.get(5)?,
                enabled: row.get::<_, i64>(6)? != 0,
                not_before: row.get(7)?,
                expires_on: row.get(8)?,
                created_on: row.get(9)?,
                updated_on: row.get(10)?,
                tag: row.get(11)?,
            })
        })
        .map_err(db)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db)?;
    Ok(raw)
}

pub(super) fn select_version<'a>(
    name: &str,
    versions: &'a [VersionRow],
    version: Option<&str>,
    now: OffsetDateTime,
    enforce_policy: bool,
) -> Result<&'a VersionRow> {
    match version {
        Some(wanted) => {
            validate_version_id(wanted)?;
            let found = versions
                .iter()
                .find(|v| v.props.version == wanted)
                .ok_or_else(|| SecretError::VersionNotFound {
                    name: name.to_owned(),
                    version: wanted.to_owned(),
                })?;
            if enforce_policy {
                policy::evaluate_access(&found.props, now)?;
            }
            Ok(found)
        }
        None if enforce_policy => {
            let props: Vec<SecretProperties> = versions.iter().map(|v| v.props.clone()).collect();
            let chosen = policy::select_latest_accessible(name, &props, now)?;
            versions
                .iter()
                .find(|v| v.props.version == chosen.version)
                .ok_or_else(|| SecretError::NotFound {
                    name: name.to_owned(),
                })
        }
        None => versions.first().ok_or_else(|| SecretError::NotFound {
            name: name.to_owned(),
        }),
    }
}

impl SqliteVault {
    /// The `secrets` row for `name`, if the secret exists.
    ///
    /// The row is honoured only when it is the state the audit chain last
    /// recorded for it: its tag must equal the newest keyed checkpoint and
    /// must verify over the stored fields. A row with no checkpoint, a row
    /// the chain records as removed, and a missing row the chain records as
    /// present are all refused with `crypto`.
    pub(super) fn load_secret_row(
        &self,
        conn: &Connection,
        name: &str,
    ) -> Result<Option<SecretRow>> {
        let found: Option<(SecretRow, Option<Vec<u8>>)> = conn
            .query_row(
                "SELECT created_on, deleted_on, scheduled_purge_on, recovery_id, tag
                 FROM secrets WHERE name = ?1",
                params![name],
                |row| {
                    Ok((
                        SecretRow {
                            created_on: row.get(0)?,
                            deleted_on: row.get(1)?,
                            scheduled_purge_on: row.get(2)?,
                            recovery_id: row.get(3)?,
                        },
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(db)?;
        let checkpoint = self.checkpoints(conn, name)?.state;
        match (found, checkpoint) {
            (None, None | Some(Checkpoint::Absent)) => Ok(None),
            (None, Some(Checkpoint::Present(_))) => Err(integrity_error_because(
                name,
                "the secret row is missing but the audit log records it as present",
            )),
            (Some(_), None) => Err(integrity_error_because(
                name,
                "the secret row has no checkpoint in the audit log",
            )),
            (Some((row, tag)), Some(checkpoint)) => {
                if !checkpoint.matches(tag.as_deref()) {
                    return Err(integrity_error_because(
                        name,
                        "the secret row is not the state the audit log last recorded",
                    ));
                }
                let fields = row.fields(&self.meta.id, name);
                if integrity::verify_secret_tag(&self.metadata_key, &fields, tag.as_deref()) {
                    Ok(Some(row))
                } else {
                    Err(integrity_error(name))
                }
            }
        }
    }

    /// Load a live (not deleted) secret row or the matching error.
    pub(super) fn require_live(&self, conn: &Connection, name: &str) -> Result<SecretRow> {
        match self.load_secret_row(conn, name)? {
            None => Err(SecretError::NotFound {
                name: name.to_owned(),
            }),
            Some(row) if row.deleted_on.is_some() => Err(SecretError::Deleted {
                name: name.to_owned(),
            }),
            Some(row) => Ok(row),
        }
    }

    /// Load a deleted secret row or the matching error.
    pub(super) fn require_deleted(&self, conn: &Connection, name: &str) -> Result<SecretRow> {
        match self.load_secret_row(conn, name)? {
            None => Err(SecretError::NotFound {
                name: name.to_owned(),
            }),
            Some(row) if row.deleted_on.is_none() => Err(SecretError::NotDeleted {
                name: name.to_owned(),
            }),
            Some(row) => Ok(row),
        }
    }

    /// All versions of `name`, newest first, each with its tag verified and
    /// equal to the newest checkpoint the audit chain holds for it. Every
    /// version the chain records must be present: removing the newest
    /// version's row would otherwise quietly make an older value current.
    pub(super) fn load_versions(&self, conn: &Connection, name: &str) -> Result<Vec<VersionRow>> {
        let raw = query_raw_versions(conn, name)?;
        let checkpoints = self.checkpoints(conn, name)?.versions;
        for version in checkpoints.keys() {
            if !raw.iter().any(|r| &r.version == version) {
                return Err(integrity_error_because(
                    name,
                    &format!("version {version} is missing but the audit log records it"),
                ));
            }
        }
        raw.into_iter()
            .map(|r| match checkpoints.get(&r.version) {
                None => Err(integrity_error_because(
                    name,
                    &format!("version {} has no checkpoint in the audit log", r.version),
                )),
                Some(checkpoint) if !checkpoint.matches(r.tag.as_deref()) => {
                    Err(integrity_error_because(
                        name,
                        &format!(
                            "version {} is not the state the audit log last recorded",
                            r.version
                        ),
                    ))
                }
                Some(_) => r.into_row(&self.meta, &self.metadata_key, name),
            })
            .collect()
    }

    pub(super) fn newest_props(&self, conn: &Connection, name: &str) -> Result<SecretProperties> {
        self.load_versions(conn, name)?
            .into_iter()
            .next()
            .map(|v| v.props)
            .ok_or_else(|| SecretError::Storage(format!("secret '{name}' has no versions")))
    }

    pub(super) fn deleted_from_row(
        &self,
        conn: &Connection,
        name: &str,
        row: &SecretRow,
    ) -> Result<DeletedSecret> {
        let deleted_on = row.deleted_on.ok_or_else(|| SecretError::NotDeleted {
            name: name.to_owned(),
        })?;
        Ok(DeletedSecret {
            properties: self.newest_props(conn, name)?,
            deleted_on: from_nanos(deleted_on)?,
            scheduled_purge_on: opt_from_nanos(row.scheduled_purge_on)?,
            recovery_id: row
                .recovery_id
                .clone()
                .unwrap_or_else(|| recovery_id(&self.meta.name, name)),
        })
    }

    // --- authenticated writes ------------------------------------------
    //
    // Each returns the tag it stored, which the caller records as the row's
    // checkpoint in the same transaction's audit event.

    /// Insert one version row together with its tag.
    pub(super) fn insert_version(
        &self,
        conn: &Connection,
        new: &NewVersion<'_>,
    ) -> Result<[u8; MAC_LEN]> {
        let tags_json = serde_json::to_string(&new.options.tags)
            .map_err(|err| SecretError::Storage(err.to_string()))?;
        let not_before = opt_nanos(new.options.not_before)?;
        let expires_on = opt_nanos(new.options.expires_on)?;
        let tag = integrity::version_tag(
            &self.metadata_key,
            &VersionFields {
                vault_id: &self.meta.id,
                name: new.name,
                version: new.version,
                seq: new.seq,
                enabled: new.options.enabled,
                content_type: new.options.content_type.as_deref(),
                tags_json: &tags_json,
                not_before,
                expires_on,
                created_on: new.now,
                updated_on: new.now,
            },
        );
        conn.execute(
            "INSERT INTO secret_versions
                (name, version, seq, nonce, ciphertext, content_type, tags_json, enabled,
                 not_before, expires_on, created_on, updated_on, tag)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11, ?12)",
            params![
                new.name,
                new.version,
                new.seq,
                new.ciphertext.nonce.as_slice(),
                new.ciphertext.bytes,
                new.options.content_type,
                tags_json,
                i64::from(new.options.enabled),
                not_before,
                expires_on,
                new.now,
                tag.as_slice(),
            ],
        )
        .map_err(db)?;
        Ok(tag)
    }

    /// Insert a new, live `secrets` row together with its tag.
    pub(super) fn insert_secret(
        &self,
        conn: &Connection,
        name: &str,
        row: &SecretRow,
    ) -> Result<[u8; MAC_LEN]> {
        let tag = integrity::secret_tag(&self.metadata_key, &row.fields(&self.meta.id, name));
        conn.execute(
            "INSERT INTO secrets (name, created_on, tag) VALUES (?1, ?2, ?3)",
            params![name, row.created_on, tag.as_slice()],
        )
        .map_err(db)?;
        Ok(tag)
    }

    /// Write a `secrets` row's deletion state together with its tag.
    pub(super) fn write_secret_state(
        &self,
        conn: &Connection,
        name: &str,
        row: &SecretRow,
    ) -> Result<[u8; MAC_LEN]> {
        let tag = integrity::secret_tag(&self.metadata_key, &row.fields(&self.meta.id, name));
        conn.execute(
            "UPDATE secrets
             SET deleted_on = ?2, scheduled_purge_on = ?3, recovery_id = ?4, tag = ?5
             WHERE name = ?1",
            params![
                name,
                row.deleted_on,
                row.scheduled_purge_on,
                row.recovery_id,
                tag.as_slice()
            ],
        )
        .map_err(db)?;
        Ok(tag)
    }

    /// Remove a `secrets` row (its versions cascade). The caller records
    /// [`Checkpoint::Absent`] for the name.
    pub(super) fn delete_secret_row(conn: &Connection, name: &str) -> Result<()> {
        conn.execute("DELETE FROM secrets WHERE name = ?1", params![name])
            .map_err(db)?;
        Ok(())
    }

    /// Every name the vault may hold: the rows in `secrets` plus the names
    /// the audit chain records as present, so that a row removed out of
    /// band is still visited (and refused) by a listing.
    pub(super) fn candidate_names(&self, conn: &Connection) -> Result<Vec<String>> {
        let mut names: std::collections::BTreeSet<String> = {
            let mut stmt = conn.prepare("SELECT name FROM secrets").map_err(db)?;
            stmt.query_map([], |row| row.get(0))
                .map_err(db)?
                .collect::<rusqlite::Result<_>>()
                .map_err(db)?
        };
        names.extend(super::audit::checkpointed_names(
            conn,
            &self.metadata_key,
            &self.meta.id,
        )?);
        Ok(names.into_iter().collect())
    }
}
