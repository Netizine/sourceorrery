//! The encrypted SQLite vault.
//!
//! One SQLite file per vault holding individually encrypted values, their
//! authenticated metadata, the wrapped vault key and a keyed audit chain.
//! The module is split by responsibility:
//!
//! * `schema`: the SQL schema, connections and transactions, the
//!   `vault_meta` record and small encoding helpers.
//! * `rows`: row types, authenticated reads and writes of secrets and
//!   versions, and version selection.
//! * `audit`: the audit chain writer, head record, verification, and the
//!   completion helpers every operation ends with (`audit`, `fail`,
//!   `finish_read`), so no operation can skip its audit row.
//! * `protectors`: unlocking, key protectors and OS-keyring ownership.
//! * `migrate`: the explicit schema 1 → 2 migration.
//!
//! This file keeps the vault type, its construction and the
//! [`SecretClient`] implementation.

mod audit;
mod migrate;
mod protectors;
mod rows;
mod schema;
#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{Connection, params};
use sourceorrery_core::audit::{AuditEvent, AuditOperation, AuditOutcome, AuditQuery};
use sourceorrery_core::policy::SoftDeletePolicy;
use sourceorrery_core::{
    DeletedSecret, Principal, RecoveryLevel, Result, Secret, SecretBytes, SecretClient,
    SecretError, SecretProperties, SetSecretOptions, UpdateSecretProperties, VaultDescriptor,
    timestamp, validate_secret_name, validate_vault_name,
};
use sourceorrery_crypto::{SymmetricKey, aead, random};

use crate::integrity::{self, VersionFields};
use crate::keystore;
use crate::protector::{ProtectorKind, ProtectorSpec};
use crate::registry::restrict_permissions;
use crate::unlock::UnlockProvider;
use crate::{BACKEND_NAME, SCHEMA_VERSION};

use self::audit::{AuditRow, AuditWriter};
use self::migrate::migrate_v1_to_v2;
use self::protectors::{
    Unlocked, add_protector, any_keyring_protector_wrapped_current, read_protectors,
    rewrap_protector, try_passphrases, try_unwrap,
};
use self::rows::{NewVersion, SecretRow, select_version};
use self::schema::{
    Meta, SCHEMA, begin_write, crypto, db, from_nanos, nanos, open_connection, opt_nanos,
    read_meta, recovery_id, value_aad, write_settings_tag,
};

/// Maximum passphrase attempts per `open`.
pub const MAX_UNLOCK_ATTEMPTS: u32 = 3;

/// Most passphrase protectors tried per attempt. Each one costs an Argon2id
/// derivation whose parameters come from the file, so the total work an
/// unlock can be made to do is bounded here and in `Argon2Params::MAX`.
pub(super) const MAX_PASSPHRASE_PROTECTORS: usize = 8;

/// Oldest on-disk schema this build can open (and migrate forward).
pub(super) const OLDEST_SUPPORTED_SCHEMA: u32 = 1;

/// Options for [`SqliteVault::open_with`].
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenOptions {
    /// Unlock a vault written by an older schema and migrate it forward.
    ///
    /// Off by default. The legacy format is unauthenticated, so migrating is
    /// a trust decision the user makes explicitly (`vault migrate`); plain
    /// `open` refuses with [`SecretError::MigrationRequired`]. Even when set,
    /// a file whose key material shows it was already in the current format
    /// is refused, because that means the schema marker was rolled back.
    pub allow_legacy_migration: bool,
}

/// Settings fixed at vault creation.
#[derive(Clone, Copy, Debug)]
pub struct CreateVaultOptions {
    /// Deletion behaviour for secrets in the vault.
    pub recovery_level: RecoveryLevel,
    /// Soft-delete retention in days (7–90).
    pub retention_days: u32,
}

impl Default for CreateVaultOptions {
    fn default() -> Self {
        Self {
            recovery_level: RecoveryLevel::Recoverable,
            retention_days: SoftDeletePolicy::default().retention_days,
        }
    }
}

/// An unlocked encrypted vault.
#[derive(Debug)]
pub struct SqliteVault {
    conn: Mutex<Connection>,
    dek: SymmetricKey,
    /// HKDF sub-key of `dek` that authenticates metadata and the audit chain.
    metadata_key: SymmetricKey,
    meta: Meta,
    path: PathBuf,
    actor: Principal,
}

impl SqliteVault {
    /// Create a new vault file at `path` with one initial key protector.
    ///
    /// If the protector cannot be installed (for example the OS credential
    /// store is unavailable) the file is removed again so no un-openable
    /// vault is left behind.
    pub fn create(
        path: &Path,
        name: &str,
        options: CreateVaultOptions,
        protector: ProtectorSpec,
    ) -> Result<Self> {
        validate_vault_name(name)?;
        SoftDeletePolicy::new(options.retention_days)?;
        if path.exists() {
            return Err(SecretError::VaultExists {
                name: name.to_owned(),
            });
        }
        if let Some(parent) = path.parent() {
            crate::registry::ensure_private_dir(parent)?;
        }

        let result = Self::create_inner(path, name, options, protector);
        if result.is_err() {
            let _ = std::fs::remove_file(path);
        }
        result
    }

    fn create_inner(
        path: &Path,
        name: &str,
        options: CreateVaultOptions,
        protector: ProtectorSpec,
    ) -> Result<Self> {
        let conn = open_connection(path)?;
        restrict_permissions(path, 0o600)?;
        conn.execute_batch(SCHEMA).map_err(db)?;

        let now = timestamp::now();
        let recovery_level_raw = serde_json::to_string(&options.recovery_level)
            .map_err(|err| SecretError::Storage(err.to_string()))?;
        let meta = Meta {
            schema: SCHEMA_VERSION,
            name: name.to_owned(),
            id: random::random_hex(16).map_err(crypto)?,
            created_on: now,
            recovery_level: options.recovery_level,
            recovery_level_raw: recovery_level_raw.clone(),
            retention_days: options.retention_days,
            settings_tag: None,
        };
        let rows: [(&str, String); 6] = [
            ("schema_version", SCHEMA_VERSION.to_string()),
            ("name", meta.name.clone()),
            ("id", meta.id.clone()),
            ("created_on", nanos(now)?.to_string()),
            ("recovery_level", recovery_level_raw),
            ("retention_days", meta.retention_days.to_string()),
        ];
        for (key, value) in rows {
            conn.execute(
                "INSERT INTO vault_meta (key, value) VALUES (?1, ?2)",
                params![key, value],
            )
            .map_err(db)?;
        }

        let dek = SymmetricKey::generate().map_err(crypto)?;
        let metadata_key = integrity::derive_metadata_key(&dek);
        let actor = Principal::local_user();
        add_protector(&conn, &meta, &dek, protector, None)?;
        write_settings_tag(&conn, &metadata_key, &meta)?;
        AuditWriter {
            meta: &meta,
            key: Some(&metadata_key),
            actor: &actor,
            allow_empty_chain: true,
        }
        .record(
            &conn,
            AuditOperation::VaultCreate,
            None,
            None,
            AuditOutcome::Success,
            Some(BACKEND_NAME),
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
            dek,
            metadata_key,
            meta,
            path: path.to_path_buf(),
            actor,
        })
    }

    /// Open and unlock the vault at `path`.
    ///
    /// OS-keyring protectors are tried first (no interaction). If none
    /// unlocks the vault, `unlock` is asked for a passphrase up to
    /// [`MAX_UNLOCK_ATTEMPTS`] times. Every failed attempt is audited.
    ///
    /// A vault written by an older schema version is **not** opened: the
    /// call fails with [`SecretError::MigrationRequired`]. Use
    /// [`SqliteVault::open_with`] (or `vault migrate`) to migrate it.
    pub fn open(path: &Path, unlock: &dyn UnlockProvider) -> Result<Self> {
        Self::open_with(path, unlock, OpenOptions::default())
    }

    /// [`SqliteVault::open`] with options.
    pub fn open_with(
        path: &Path,
        unlock: &dyn UnlockProvider,
        options: OpenOptions,
    ) -> Result<Self> {
        if !path.is_file() {
            return Err(SecretError::VaultNotFound {
                name: path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("?")
                    .to_owned(),
            });
        }
        let conn = open_connection(path)?;
        let meta = read_meta(&conn)?;
        if meta.schema < SCHEMA_VERSION && !options.allow_legacy_migration {
            return Err(SecretError::MigrationRequired {
                name: meta.name,
                schema: meta.schema,
            });
        }
        let protectors = read_protectors(&conn)?;
        let actor = Principal::local_user();
        if protectors.is_empty() {
            return Err(SecretError::Locked(
                "vault has no key protectors".to_owned(),
            ));
        }
        // Rows written here precede unlock: no metadata key yet.
        let unkeyed = AuditWriter {
            meta: &meta,
            key: None,
            actor: &actor,
            allow_empty_chain: false,
        };

        let mut reasons: Vec<String> = Vec::new();

        for protector in protectors
            .iter()
            .filter(|p| matches!(p.kind, ProtectorKind::OsKeyring { .. }))
        {
            let ProtectorKind::OsKeyring { account, .. } = &protector.kind else {
                continue;
            };
            match keystore::load_key(account) {
                Ok(Some(kek)) => match try_unwrap(&meta, protector, &kek) {
                    Ok((dek, wrapped_schema)) => {
                        let unlocked = Unlocked {
                            protector_id: protector.id.clone(),
                            kek,
                            wrapped_schema,
                        };
                        return Self::finish_open(conn, dek, meta, path, actor, &unlocked);
                    }
                    Err(err) => reasons.push(format!("{}: {err}", protector.label)),
                },
                Ok(None) => reasons.push(format!(
                    "{}: no entry in {}",
                    protector.label,
                    keystore::STORE_NAME
                )),
                Err(err) => reasons.push(format!("{}: {err}", protector.label)),
            }
        }

        if let Some((dek, unlocked)) =
            try_passphrases(&conn, &meta, &protectors, unlock, &unkeyed, &mut reasons)?
        {
            return Self::finish_open(conn, dek, meta, path, actor, &unlocked);
        }

        unkeyed.record(
            &conn,
            AuditOperation::VaultOpen,
            None,
            None,
            AuditOutcome::Failure,
            Some("locked"),
        )?;
        Err(SecretError::Locked(reasons.join("; ")))
    }

    fn finish_open(
        mut conn: Connection,
        dek: SymmetricKey,
        mut meta: Meta,
        path: &Path,
        actor: Principal,
        unlocked: &Unlocked,
    ) -> Result<Self> {
        let metadata_key = integrity::derive_metadata_key(&dek);
        if meta.schema < SCHEMA_VERSION {
            // The file says "legacy" but only key material is trustworthy:
            // a key wrapped under the current schema proves the marker was
            // rolled back, and the migration must not launder that file.
            let rolled_back = unlocked.wrapped_schema >= SCHEMA_VERSION
                || any_keyring_protector_wrapped_current(&conn, &meta)?;
            if rolled_back {
                AuditWriter {
                    meta: &meta,
                    key: None,
                    actor: &actor,
                    allow_empty_chain: false,
                }
                .record(
                    &conn,
                    AuditOperation::VaultMigrate,
                    None,
                    None,
                    AuditOutcome::Failure,
                    Some("schema marker rolled back"),
                )?;
                return Err(SecretError::Crypto(
                    "vault reports an older schema but its key is bound to the current one: \
                     the schema marker was altered; refusing to migrate"
                        .to_owned(),
                ));
            }
            migrate_v1_to_v2(&mut conn, &mut meta, &dek, &metadata_key, &actor, unlocked)?;
        } else {
            let fields = meta.settings_fields()?;
            let settings_ok = integrity::verify_settings_tag(
                &metadata_key,
                &fields,
                meta.settings_tag.as_deref(),
            ) && SoftDeletePolicy::new(meta.retention_days).is_ok();
            if !settings_ok {
                AuditWriter {
                    meta: &meta,
                    key: Some(&metadata_key),
                    actor: &actor,
                    allow_empty_chain: false,
                }
                .record(
                    &conn,
                    AuditOperation::VaultOpen,
                    None,
                    None,
                    AuditOutcome::Failure,
                    Some("settings integrity check failed"),
                )?;
                return Err(SecretError::Crypto(
                    "vault settings integrity check failed (schema, name, recovery level or \
                     retention were altered)"
                        .to_owned(),
                ));
            }
            if unlocked.wrapped_schema < SCHEMA_VERSION {
                // A protector left over from a migration that could not
                // re-wrap it (another passphrase): bind it now that we can.
                rewrap_protector(&conn, &meta, &dek, &unlocked.protector_id, &unlocked.kek)?;
            }
        }
        AuditWriter {
            meta: &meta,
            key: Some(&metadata_key),
            actor: &actor,
            allow_empty_chain: false,
        }
        .record(
            &conn,
            AuditOperation::VaultOpen,
            None,
            None,
            AuditOutcome::Success,
            None,
        )?;
        let vault = Self {
            conn: Mutex::new(conn),
            dek,
            metadata_key,
            meta,
            path: path.to_path_buf(),
            actor,
        };
        vault.purge_expired_deletions()?;
        Ok(vault)
    }

    /// Replace the principal recorded in audit events (default: OS user).
    #[must_use]
    pub fn with_actor(mut self, actor: Principal) -> Self {
        self.actor = actor;
        self
    }

    /// Non-sensitive description of this vault.
    pub fn descriptor(&self) -> Result<VaultDescriptor> {
        let protectors = self.protectors()?.into_iter().map(|p| p.label).collect();
        Ok(VaultDescriptor {
            name: self.meta.name.clone(),
            id: self.meta.id.clone(),
            backend: BACKEND_NAME.to_owned(),
            path: Some(self.path.clone()),
            created_on: self.meta.created_on,
            recovery_level: self.meta.recovery_level,
            retention_days: self.meta.retention_days,
            protectors,
        })
    }

    /// On-disk location.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| SecretError::Storage("vault connection poisoned".to_owned()))
    }
}

impl SecretClient for SqliteVault {
    fn vault_name(&self) -> &str {
        &self.meta.name
    }

    fn set_secret(
        &self,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
    ) -> Result<SecretProperties> {
        validate_secret_name(name)?;
        options.validate()?;
        let mut conn = self.lock()?;
        let tx = begin_write(&mut conn)?;
        let op = AuditOperation::SecretSet;
        let now = timestamp::now();
        let now_nanos = nanos(now)?;

        match self.load_secret_row(&tx, name) {
            Ok(Some(row)) if row.deleted_on.is_some() => {
                return self.fail(
                    tx,
                    op,
                    Some(name),
                    None,
                    SecretError::DeletedConflict {
                        name: name.to_owned(),
                    },
                );
            }
            Ok(Some(_)) => {}
            Ok(None) => {
                let row = SecretRow {
                    created_on: now_nanos,
                    deleted_on: None,
                    scheduled_purge_on: None,
                    recovery_id: None,
                };
                let tag =
                    integrity::secret_tag(&self.metadata_key, &row.fields(&self.meta.id, name));
                tx.execute(
                    "INSERT INTO secrets (name, created_on, tag) VALUES (?1, ?2, ?3)",
                    params![name, now_nanos, tag.as_slice()],
                )
                .map_err(db)?;
            }
            Err(err) => return self.fail(tx, op, Some(name), None, err),
        }

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
            value.expose(),
        )
        .map_err(crypto)?;
        drop(value);
        self.insert_version(
            &tx,
            &NewVersion {
                name,
                version: &version,
                seq,
                ciphertext: &ciphertext,
                options: &options,
                now: now_nanos,
            },
        )?;

        let props = SecretProperties {
            vault: self.meta.name.clone(),
            name: name.to_owned(),
            version: version.clone(),
            enabled: options.enabled,
            content_type: options.content_type,
            tags: options.tags,
            not_before: options.not_before,
            expires_on: options.expires_on,
            created_on: now,
            updated_on: now,
            recovery_level: self.meta.recovery_level,
        };
        self.audit(
            &tx,
            op,
            Some(name),
            Some(&version),
            AuditOutcome::Success,
            None,
        )?;
        tx.commit().map_err(db)?;
        Ok(props)
    }

    fn get_secret(&self, name: &str, version: Option<&str>) -> Result<Secret> {
        validate_secret_name(name)?;
        let mut conn = self.lock()?;
        let tx = begin_write(&mut conn)?;
        let op = AuditOperation::SecretGet;
        if let Err(err) = self.require_live(&tx, name) {
            return self.fail(tx, op, Some(name), version, err);
        }
        let versions = match self.load_versions(&tx, name) {
            Ok(v) => v,
            Err(err) => return self.fail(tx, op, Some(name), version, err),
        };
        let chosen = match select_version(name, &versions, version, timestamp::now(), true) {
            Ok(v) => v,
            Err(err) => return self.fail(tx, op, Some(name), version, err),
        };
        let plaintext = match aead::open(
            &self.dek,
            value_aad(&self.meta.id, name, &chosen.props.version).as_bytes(),
            &chosen.ciphertext,
        ) {
            Ok(p) => p,
            Err(err) => {
                return self.fail(tx, op, Some(name), Some(&chosen.props.version), crypto(err));
            }
        };
        self.audit(
            &tx,
            op,
            Some(name),
            Some(&chosen.props.version),
            AuditOutcome::Success,
            None,
        )?;
        tx.commit().map_err(db)?;
        Ok(Secret {
            properties: chosen.props.clone(),
            value: SecretBytes::new(plaintext.to_vec()),
        })
    }

    fn get_secret_properties(&self, name: &str, version: Option<&str>) -> Result<SecretProperties> {
        let mut conn = self.lock()?;
        let tx = begin_write(&mut conn)?;
        let op = AuditOperation::SecretInspect;
        let tx = self.validated(tx, op, name)?;
        let result = self.require_live(&tx, name).and_then(|_| {
            let versions = self.load_versions(&tx, name)?;
            select_version(name, &versions, version, timestamp::now(), false)
                .map(|v| v.props.clone())
        });
        self.finish_read(tx, op, Some(name), "properties", result)
    }

    fn list_properties_of_secrets(&self) -> Result<Vec<SecretProperties>> {
        let mut conn = self.lock()?;
        let tx = begin_write(&mut conn)?;
        let op = AuditOperation::SecretList;
        let names: Vec<String> = {
            let mut stmt = tx
                .prepare("SELECT name FROM secrets WHERE deleted_on IS NULL ORDER BY name")
                .map_err(db)?;
            stmt.query_map([], |row| row.get(0))
                .map_err(db)?
                .collect::<rusqlite::Result<_>>()
                .map_err(db)?
        };
        let mut out = Vec::with_capacity(names.len());
        for name in &names {
            // The secrets row itself is verified too: a tampered
            // `deleted_on` must not resurface a secret in listings.
            let listed = self
                .require_live(&tx, name)
                .and_then(|_| self.newest_props(&tx, name));
            match listed {
                Ok(props) => out.push(props),
                Err(err) => return self.fail(tx, op, Some(name), None, err),
            }
        }
        self.audit(&tx, op, None, None, AuditOutcome::Success, None)?;
        tx.commit().map_err(db)?;
        Ok(out)
    }

    fn list_properties_of_secret_versions(&self, name: &str) -> Result<Vec<SecretProperties>> {
        let mut conn = self.lock()?;
        let tx = begin_write(&mut conn)?;
        let op = AuditOperation::SecretInspect;
        let tx = self.validated(tx, op, name)?;
        let result = self.require_live(&tx, name).and_then(|_| {
            Ok(self
                .load_versions(&tx, name)?
                .into_iter()
                .map(|v| v.props)
                .collect())
        });
        self.finish_read(tx, op, Some(name), "versions", result)
    }

    fn update_secret_properties(
        &self,
        name: &str,
        version: Option<&str>,
        update: UpdateSecretProperties,
    ) -> Result<SecretProperties> {
        validate_secret_name(name)?;
        if update.is_empty() {
            return Err(SecretError::InvalidArgument("nothing to update".to_owned()));
        }
        let mut conn = self.lock()?;
        let tx = begin_write(&mut conn)?;
        let op = AuditOperation::SecretUpdate;
        if let Err(err) = self.require_live(&tx, name) {
            return self.fail(tx, op, Some(name), version, err);
        }
        let versions = match self.load_versions(&tx, name) {
            Ok(v) => v,
            Err(err) => return self.fail(tx, op, Some(name), version, err),
        };
        let now = timestamp::now();
        let target = match select_version(name, &versions, version, now, false) {
            Ok(v) => v,
            Err(err) => return self.fail(tx, op, Some(name), version, err),
        };
        let mut props = target.props.clone();
        update.apply(&mut props, now)?;
        let tags_json = serde_json::to_string(&props.tags)
            .map_err(|err| SecretError::Storage(err.to_string()))?;
        let not_before = opt_nanos(props.not_before)?;
        let expires_on = opt_nanos(props.expires_on)?;
        let updated_on = nanos(now)?;
        let tag = integrity::version_tag(
            &self.metadata_key,
            &VersionFields {
                vault_id: &self.meta.id,
                name,
                version: &props.version,
                seq: target.seq,
                enabled: props.enabled,
                content_type: props.content_type.as_deref(),
                tags_json: &tags_json,
                not_before,
                expires_on,
                created_on: target.created_on,
                updated_on,
            },
        );
        tx.execute(
            "UPDATE secret_versions
             SET enabled = ?3, content_type = ?4, tags_json = ?5, not_before = ?6,
                 expires_on = ?7, updated_on = ?8, tag = ?9
             WHERE name = ?1 AND version = ?2",
            params![
                name,
                props.version,
                i64::from(props.enabled),
                props.content_type,
                tags_json,
                not_before,
                expires_on,
                updated_on,
                tag.as_slice(),
            ],
        )
        .map_err(db)?;
        self.audit(
            &tx,
            op,
            Some(name),
            Some(&props.version),
            AuditOutcome::Success,
            None,
        )?;
        tx.commit().map_err(db)?;
        Ok(props)
    }

    fn delete_secret(&self, name: &str) -> Result<DeletedSecret> {
        validate_secret_name(name)?;
        let mut conn = self.lock()?;
        let tx = begin_write(&mut conn)?;
        let op = AuditOperation::SecretDelete;
        let row = match self.require_live(&tx, name) {
            Ok(row) => row,
            Err(err) => return self.fail(tx, op, Some(name), None, err),
        };
        let props = match self.newest_props(&tx, name) {
            Ok(props) => props,
            Err(err) => return self.fail(tx, op, Some(name), None, err),
        };
        let now = timestamp::now();
        let deleted = if self.meta.recovery_level.soft_delete_enabled() {
            let purge_on = self.meta.retention().scheduled_purge_on(now);
            let rid = recovery_id(&self.meta.name, name);
            let state = SecretRow {
                created_on: row.created_on,
                deleted_on: Some(nanos(now)?),
                scheduled_purge_on: Some(nanos(purge_on)?),
                recovery_id: Some(rid.clone()),
            };
            self.write_secret_state(&tx, name, &state)?;
            DeletedSecret {
                properties: props,
                deleted_on: now,
                scheduled_purge_on: Some(purge_on),
                recovery_id: rid,
            }
        } else {
            tx.execute("DELETE FROM secrets WHERE name = ?1", params![name])
                .map_err(db)?;
            DeletedSecret {
                properties: props,
                deleted_on: now,
                scheduled_purge_on: Some(now),
                recovery_id: String::new(),
            }
        };
        self.audit(
            &tx,
            op,
            Some(name),
            Some(&deleted.properties.version),
            AuditOutcome::Success,
            Some(if deleted.recovery_id.is_empty() {
                "purged"
            } else {
                "soft-deleted"
            }),
        )?;
        tx.commit().map_err(db)?;
        Ok(deleted)
    }

    fn get_deleted_secret(&self, name: &str) -> Result<DeletedSecret> {
        let mut conn = self.lock()?;
        let tx = begin_write(&mut conn)?;
        let op = AuditOperation::SecretInspect;
        let tx = self.validated(tx, op, name)?;
        let result = self
            .require_deleted(&tx, name)
            .and_then(|row| self.deleted_from_row(&tx, name, &row));
        self.finish_read(tx, op, Some(name), "deleted", result)
    }

    fn list_deleted_secrets(&self) -> Result<Vec<DeletedSecret>> {
        let mut conn = self.lock()?;
        let tx = begin_write(&mut conn)?;
        let op = AuditOperation::SecretList;
        let names: Vec<String> = {
            let mut stmt = tx
                .prepare("SELECT name FROM secrets WHERE deleted_on IS NOT NULL ORDER BY name")
                .map_err(db)?;
            stmt.query_map([], |row| row.get(0))
                .map_err(db)?
                .collect::<rusqlite::Result<_>>()
                .map_err(db)?
        };
        let mut out = Vec::with_capacity(names.len());
        for name in &names {
            let listed = self
                .require_deleted(&tx, name)
                .and_then(|row| self.deleted_from_row(&tx, name, &row));
            match listed {
                Ok(deleted) => out.push(deleted),
                Err(err) => return self.fail(tx, op, Some(name), None, err),
            }
        }
        self.finish_read(tx, op, None, "deleted", Ok(out))
    }

    fn recover_deleted_secret(&self, name: &str) -> Result<SecretProperties> {
        validate_secret_name(name)?;
        let mut conn = self.lock()?;
        let tx = begin_write(&mut conn)?;
        let op = AuditOperation::SecretRecover;
        let row = match self.require_deleted(&tx, name) {
            Ok(row) => row,
            Err(err) => return self.fail(tx, op, Some(name), None, err),
        };
        let state = SecretRow {
            created_on: row.created_on,
            deleted_on: None,
            scheduled_purge_on: None,
            recovery_id: None,
        };
        self.write_secret_state(&tx, name, &state)?;
        let props = match self.newest_props(&tx, name) {
            Ok(props) => props,
            Err(err) => return self.fail(tx, op, Some(name), None, err),
        };
        self.audit(
            &tx,
            op,
            Some(name),
            Some(&props.version),
            AuditOutcome::Success,
            None,
        )?;
        tx.commit().map_err(db)?;
        Ok(props)
    }

    fn purge_deleted_secret(&self, name: &str) -> Result<()> {
        validate_secret_name(name)?;
        let mut conn = self.lock()?;
        let tx = begin_write(&mut conn)?;
        let op = AuditOperation::SecretPurge;
        if let Err(err) = self.require_deleted(&tx, name) {
            return self.fail(tx, op, Some(name), None, err);
        }
        tx.execute("DELETE FROM secrets WHERE name = ?1", params![name])
            .map_err(db)?;
        self.audit(&tx, op, Some(name), None, AuditOutcome::Success, None)?;
        tx.commit().map_err(db)?;
        Ok(())
    }

    fn audit_events(&self, query: AuditQuery) -> Result<Vec<AuditEvent>> {
        let conn = self.lock()?;
        let since = opt_nanos(query.since)?;
        let limit = i64::try_from(query.limit.unwrap_or(1000)).unwrap_or(i64::MAX);
        let operation = query.operation.map(AuditOperation::as_str);
        let mut stmt = conn
            .prepare(
                "SELECT id, occurred_on, actor, operation, secret_name, version, outcome, detail
                 FROM audit_events
                 WHERE (?1 IS NULL OR secret_name = ?1)
                   AND (?2 IS NULL OR operation = ?2)
                   AND (?3 IS NULL OR occurred_on >= ?3)
                 ORDER BY id DESC LIMIT ?4",
            )
            .map_err(db)?;
        let raw: Vec<AuditRow> = stmt
            .query_map(params![query.secret_name, operation, since, limit], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            })
            .map_err(db)?
            .collect::<rusqlite::Result<_>>()
            .map_err(db)?;
        raw.into_iter()
            .map(
                |(id, occurred_on, actor, operation, secret_name, version, outcome, detail)| {
                    Ok(AuditEvent {
                        id: u64::try_from(id).unwrap_or_default(),
                        occurred_on: from_nanos(occurred_on)?,
                        actor: Principal::parse(&actor).unwrap_or_else(|| {
                            Principal::new(sourceorrery_core::PrincipalKind::User, actor)
                        }),
                        operation: operation.parse().map_err(SecretError::Storage)?,
                        secret_name,
                        version,
                        outcome: outcome.parse().map_err(SecretError::Storage)?,
                        detail,
                    })
                },
            )
            .collect()
    }
}
