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
    /// The connection that stores the value, or `None` for the file. A row
    /// with a storage is a catalog entry: no versions, and its deletion
    /// state is the provider's.
    pub(super) storage: Option<String>,
    /// What the secret is for, as its owner wrote it; in local and catalog
    /// rows alike, since it belongs to the vault's catalog, not to a value.
    pub(super) description: Option<String>,
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
            storage: self.storage.as_deref(),
            description: self.description.as_deref(),
        }
    }

    /// This row, when its value is in the file; the refusal a local
    /// operation gives a secret stored through a connection otherwise.
    pub(super) fn local(self, name: &str) -> Result<Self> {
        match &self.storage {
            None => Ok(self),
            Some(connection) => Err(stored_elsewhere(name, connection)),
        }
    }
}

/// The refusal a local operation gives a secret whose value a connection
/// stores: the file holds no version of it.
pub(super) fn stored_elsewhere(name: &str, connection: &str) -> SecretError {
    SecretError::Unsupported(format!(
        "secret '{name}' is stored through connection {connection}, not in the vault file; \
         reach it through the vault's storage routing"
    ))
}

/// The verified metadata of one version. It carries no ciphertext: the
/// value of the one version an operation returns is fetched separately with
/// [`load_ciphertext`], so inspecting or listing a secret never reads the
/// values of its versions.
pub(super) struct VersionRow {
    pub(super) props: SecretProperties,
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

/// One `secret_versions` row as stored, before verification: exactly the
/// columns the version tag covers (see [`VersionFields`]) plus the tag
/// itself. `nonce` and `ciphertext` are not part of this projection.
#[allow(clippy::struct_field_names)]
pub(super) struct RawVersion {
    pub(super) version: String,
    pub(super) seq: i64,
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
        Ok(VersionRow {
            props,
            seq: self.seq,
            created_on: self.created_on,
        })
    }
}

/// A `secrets` row as stored, with its tag, before verification.
pub(super) type StoredSecretRow = (SecretRow, Option<Vec<u8>>);

const SECRET_COLUMNS: &str =
    "created_on, deleted_on, scheduled_purge_on, recovery_id, storage, description, tag";

/// A `secrets` row read with [`SECRET_COLUMNS`] starting at `offset`.
fn stored_secret_row(row: &rusqlite::Row<'_>, offset: usize) -> rusqlite::Result<StoredSecretRow> {
    Ok((
        SecretRow {
            created_on: row.get(offset)?,
            deleted_on: row.get(offset + 1)?,
            scheduled_purge_on: row.get(offset + 2)?,
            recovery_id: row.get(offset + 3)?,
            storage: row.get(offset + 4)?,
            description: row.get(offset + 5)?,
        },
        row.get(offset + 6)?,
    ))
}

/// The stored `secrets` row for `name`, unverified.
pub(super) fn query_secret_row(conn: &Connection, name: &str) -> Result<Option<StoredSecretRow>> {
    conn.query_row(
        &format!("SELECT {SECRET_COLUMNS} FROM secrets WHERE name = ?1"),
        params![name],
        |row| stored_secret_row(row, 0),
    )
    .optional()
    .map_err(db)
}

/// The names of the `secrets` rows whose value the connection `id`
/// stores, unverified, in order.
pub(super) fn query_names_at(conn: &Connection, id: &str) -> Result<Vec<String>> {
    conn.prepare("SELECT name FROM secrets WHERE storage = ?1 ORDER BY name")
        .map_err(db)?
        .query_map(params![id], |row| row.get(0))
        .map_err(db)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db)
}

/// Every name in `secrets` that sorts after `after`, in order.
pub(super) fn query_secret_names(conn: &Connection, after: Option<&str>) -> Result<Vec<String>> {
    let mut stmt = conn
        .prepare("SELECT name FROM secrets WHERE ?1 IS NULL OR name > ?1 ORDER BY name")
        .map_err(db)?;
    let names = stmt
        .query_map(params![after], |row| row.get(0))
        .map_err(db)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db)?;
    Ok(names)
}

/// The stored `secrets` rows whose names sort after `after` and up to
/// `through` (inclusive), unverified, by name. `None` leaves that end open.
pub(super) fn query_secret_rows(
    conn: &Connection,
    after: Option<&str>,
    through: Option<&str>,
) -> Result<BTreeMap<String, StoredSecretRow>> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT name, {SECRET_COLUMNS} FROM secrets
             WHERE (?1 IS NULL OR name > ?1) AND (?2 IS NULL OR name <= ?2)"
        ))
        .map_err(db)?;
    let rows = stmt
        .query_map(params![after, through], |row| {
            Ok((row.get::<_, String>(0)?, stored_secret_row(row, 1)?))
        })
        .map_err(db)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db)?;
    Ok(rows)
}

const VERSION_COLUMNS: &str = "version, seq, content_type, tags_json, enabled,
                    not_before, expires_on, created_on, updated_on, tag";

fn raw_version(row: &rusqlite::Row<'_>, offset: usize) -> rusqlite::Result<RawVersion> {
    Ok(RawVersion {
        version: row.get(offset)?,
        seq: row.get(offset + 1)?,
        content_type: row.get(offset + 2)?,
        tags_json: row.get(offset + 3)?,
        enabled: row.get::<_, i64>(offset + 4)? != 0,
        not_before: row.get(offset + 5)?,
        expires_on: row.get(offset + 6)?,
        created_on: row.get(offset + 7)?,
        updated_on: row.get(offset + 8)?,
        tag: row.get(offset + 9)?,
    })
}

/// The unverified metadata of every version of `name`, newest first.
///
/// This is the metadata projection only; see [`RawVersion`]. Callers must
/// go through [`SqliteVault::load_versions`], which applies the tag and
/// checkpoint rules.
pub(super) fn query_raw_versions(conn: &Connection, name: &str) -> Result<Vec<RawVersion>> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {VERSION_COLUMNS} FROM secret_versions WHERE name = ?1 ORDER BY seq DESC"
        ))
        .map_err(db)?;
    let raw = stmt
        .query_map(params![name], |row| raw_version(row, 0))
        .map_err(db)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db)?;
    Ok(raw)
}

/// The unverified version metadata of every secret whose name sorts after
/// `after` and up to `through` (inclusive), newest first per name. Same
/// projection as [`query_raw_versions`], one statement for a whole listing
/// window; the result goes through [`SqliteVault::verify_versions`].
pub(super) fn query_raw_versions_in(
    conn: &Connection,
    after: Option<&str>,
    through: Option<&str>,
) -> Result<BTreeMap<String, Vec<RawVersion>>> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT name, {VERSION_COLUMNS} FROM secret_versions
             WHERE (?1 IS NULL OR name > ?1) AND (?2 IS NULL OR name <= ?2)
             ORDER BY name, seq DESC"
        ))
        .map_err(db)?;
    let mut out: BTreeMap<String, Vec<RawVersion>> = BTreeMap::new();
    let rows = stmt
        .query_map(params![after, through], |row| {
            Ok((row.get::<_, String>(0)?, raw_version(row, 1)?))
        })
        .map_err(db)?;
    for row in rows {
        let (name, raw) = row.map_err(db)?;
        out.entry(name).or_default().push(raw);
    }
    Ok(out)
}

/// The stored nonce and ciphertext of exactly one version.
///
/// Only the version an operation is about to return is read, and only after
/// its metadata row has passed [`SqliteVault::load_versions`] and the
/// version has been selected, in the same transaction. The ciphertext needs
/// no tag of its own: its AEAD binds it to the vault, name and version
/// through the AAD, so a moved or edited value fails to decrypt.
pub(super) fn load_ciphertext(conn: &Connection, name: &str, version: &str) -> Result<Ciphertext> {
    let found: Option<(Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT nonce, ciphertext FROM secret_versions WHERE name = ?1 AND version = ?2",
            params![name, version],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(db)?;
    // The metadata row was read under this transaction's write lock, so the
    // value row cannot have gone away in between; a miss is a damaged file.
    let (nonce, bytes) = found.ok_or_else(|| {
        SecretError::Storage(format!(
            "secret '{name}' version {version} has no value row"
        ))
    })?;
    Ciphertext::from_parts(&nonce, bytes).map_err(crypto)
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
        let found = query_secret_row(conn, name)?;
        let checkpoint = self.checkpoints(conn, name)?.state;
        self.verify_secret_row(name, found, checkpoint)
    }

    /// The rule behind [`Self::load_secret_row`], applied to a row and the
    /// newest state checkpoint the chain holds for its name, both already
    /// read. Listings call it with rows from one statement.
    pub(super) fn verify_secret_row(
        &self,
        name: &str,
        found: Option<StoredSecretRow>,
        checkpoint: Option<Checkpoint>,
    ) -> Result<Option<SecretRow>> {
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

    /// Load a live (not deleted) secret row stored in the file, or the
    /// matching error.
    pub(super) fn require_live(&self, conn: &Connection, name: &str) -> Result<SecretRow> {
        match self.load_secret_row(conn, name)? {
            None => Err(SecretError::NotFound {
                name: name.to_owned(),
            }),
            Some(row) if row.deleted_on.is_some() => Err(SecretError::Deleted {
                name: name.to_owned(),
            }),
            Some(row) => row.local(name),
        }
    }

    /// Load a deleted secret row stored in the file, or the matching error.
    pub(super) fn require_deleted(&self, conn: &Connection, name: &str) -> Result<SecretRow> {
        match self.load_secret_row(conn, name)? {
            None => Err(SecretError::NotFound {
                name: name.to_owned(),
            }),
            Some(row) if row.storage.is_some() => row.local(name),
            Some(row) if row.deleted_on.is_none() => Err(SecretError::NotDeleted {
                name: name.to_owned(),
            }),
            Some(row) => Ok(row),
        }
    }

    /// The metadata of all versions of `name`, newest first, each with its
    /// tag verified and equal to the newest checkpoint the audit chain holds
    /// for it. Every version the chain records must be present: removing the
    /// newest version's row would otherwise quietly make an older value
    /// current.
    ///
    /// No ciphertext is read here. A version's value is fetched on its own
    /// with [`load_ciphertext`] once it has been selected.
    pub(super) fn load_versions(&self, conn: &Connection, name: &str) -> Result<Vec<VersionRow>> {
        let raw = query_raw_versions(conn, name)?;
        let checkpoints = self.checkpoints(conn, name)?.versions;
        self.verify_versions(name, raw, &checkpoints)
    }

    /// The rule behind [`Self::load_versions`], applied to the stored rows
    /// of `name` and the version checkpoints the chain holds for it, both
    /// already read.
    pub(super) fn verify_versions(
        &self,
        name: &str,
        raw: Vec<RawVersion>,
        checkpoints: &BTreeMap<String, Checkpoint>,
    ) -> Result<Vec<VersionRow>> {
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

    /// The newest version's properties.
    ///
    /// Which version is newest can only be judged against the complete set
    /// of versions: a row removed out of band or an inserted one with a
    /// higher `seq` is caught by the checkpoint rule, not by the row that
    /// happens to sort first. So this goes through [`Self::load_versions`]
    /// (metadata only) rather than selecting one row.
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
        let properties = self.newest_props(conn, name)?;
        self.deleted_from_parts(name, row, properties)
    }

    /// [`Self::deleted_from_row`] with the newest version's properties
    /// already verified.
    pub(super) fn deleted_from_parts(
        &self,
        name: &str,
        row: &SecretRow,
        properties: SecretProperties,
    ) -> Result<DeletedSecret> {
        let deleted_on = row.deleted_on.ok_or_else(|| SecretError::NotDeleted {
            name: name.to_owned(),
        })?;
        Ok(DeletedSecret {
            properties,
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
            "INSERT INTO secrets (name, created_on, storage, description, tag)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                name,
                row.created_on,
                row.storage,
                row.description,
                tag.as_slice()
            ],
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

    /// Write a `secrets` row's description together with its tag.
    pub(super) fn write_secret_description(
        &self,
        conn: &Connection,
        name: &str,
        row: &SecretRow,
    ) -> Result<[u8; MAC_LEN]> {
        let tag = integrity::secret_tag(&self.metadata_key, &row.fields(&self.meta.id, name));
        conn.execute(
            "UPDATE secrets SET description = ?2, tag = ?3 WHERE name = ?1",
            params![name, row.description, tag.as_slice()],
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
}
