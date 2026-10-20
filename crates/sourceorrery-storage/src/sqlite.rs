//! The encrypted SQLite vault.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, params};
use sourceorrery_core::audit::{AuditEvent, AuditOperation, AuditOutcome, AuditQuery};
use sourceorrery_core::policy::{self, SoftDeletePolicy};
use sourceorrery_core::{
    DeletedSecret, Principal, RecoveryLevel, Result, Secret, SecretBytes, SecretClient,
    SecretError, SecretProperties, SetSecretOptions, UpdateSecretProperties, VaultDescriptor,
    timestamp, validate_secret_name, validate_vault_name, validate_version_id,
};
use sourceorrery_crypto::{Ciphertext, SymmetricKey, aead, envelope, kdf, random};
use time::OffsetDateTime;

use crate::keystore;
use crate::protector::{ProtectorInfo, ProtectorKind, ProtectorRecord, ProtectorSpec};
use crate::registry::restrict_permissions;
use crate::unlock::{PassphrasePrompt, UnlockProvider};
use crate::{BACKEND_NAME, SCHEMA_VERSION};

/// Maximum passphrase attempts per `open`.
pub const MAX_UNLOCK_ATTEMPTS: u32 = 3;

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

#[derive(Clone, Debug)]
struct Meta {
    name: String,
    id: String,
    created_on: OffsetDateTime,
    recovery_level: RecoveryLevel,
    retention_days: u32,
}

impl Meta {
    fn retention(&self) -> SoftDeletePolicy {
        SoftDeletePolicy {
            retention_days: self.retention_days,
        }
    }
}

/// An unlocked encrypted vault.
#[derive(Debug)]
pub struct SqliteVault {
    conn: Mutex<Connection>,
    dek: SymmetricKey,
    meta: Meta,
    path: PathBuf,
    actor: Principal,
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS vault_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS key_protectors (
    id            TEXT PRIMARY KEY,
    label         TEXT NOT NULL UNIQUE,
    kind_json     TEXT NOT NULL,
    wrapped_nonce BLOB NOT NULL,
    wrapped_dek   BLOB NOT NULL,
    created_on    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS secrets (
    name               TEXT PRIMARY KEY,
    created_on         INTEGER NOT NULL,
    deleted_on         INTEGER,
    scheduled_purge_on INTEGER,
    recovery_id        TEXT
);
CREATE TABLE IF NOT EXISTS secret_versions (
    name         TEXT NOT NULL REFERENCES secrets(name) ON DELETE CASCADE,
    version      TEXT NOT NULL,
    seq          INTEGER NOT NULL UNIQUE,
    nonce        BLOB NOT NULL,
    ciphertext   BLOB NOT NULL,
    content_type TEXT,
    tags_json    TEXT NOT NULL,
    enabled      INTEGER NOT NULL,
    not_before   INTEGER,
    expires_on   INTEGER,
    created_on   INTEGER NOT NULL,
    updated_on   INTEGER NOT NULL,
    PRIMARY KEY (name, version)
);
CREATE INDEX IF NOT EXISTS secret_versions_by_seq ON secret_versions(name, seq DESC);
CREATE TABLE IF NOT EXISTS audit_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_on INTEGER NOT NULL,
    actor       TEXT NOT NULL,
    operation   TEXT NOT NULL,
    secret_name TEXT,
    version     TEXT,
    outcome     TEXT NOT NULL,
    detail      TEXT
);
CREATE INDEX IF NOT EXISTS audit_events_by_secret ON audit_events(secret_name, id DESC);
";

fn open_connection(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).map_err(db)?;
    conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA secure_delete = ON;")
        .map_err(db)?;
    Ok(conn)
}

#[allow(clippy::needless_pass_by_value)] // used as a `map_err` function pointer
fn db(err: rusqlite::Error) -> SecretError {
    SecretError::Storage(err.to_string())
}

#[allow(clippy::needless_pass_by_value)] // used as a `map_err` function pointer
fn crypto(err: sourceorrery_crypto::CryptoError) -> SecretError {
    SecretError::Crypto(err.to_string())
}

fn nanos(ts: OffsetDateTime) -> Result<i64> {
    i64::try_from(timestamp::to_unix_nanos(ts))
        .map_err(|_| SecretError::InvalidArgument("timestamp out of range".to_owned()))
}

fn from_nanos(value: i64) -> Result<OffsetDateTime> {
    timestamp::from_unix_nanos(i128::from(value))
}

fn opt_nanos(ts: Option<OffsetDateTime>) -> Result<Option<i64>> {
    ts.map(nanos).transpose()
}

fn opt_from_nanos(value: Option<i64>) -> Result<Option<OffsetDateTime>> {
    value.map(from_nanos).transpose()
}

fn value_aad(vault_id: &str, name: &str, version: &str) -> String {
    format!("sourceorrery/v1/value/{vault_id}/{name}/{version}")
}

fn protector_aad(vault_id: &str, protector_id: &str) -> String {
    format!("sourceorrery/v1/protector/{vault_id}/{protector_id}")
}

fn recovery_id(vault: &str, name: &str) -> String {
    format!("sourceorrery://{vault}/deletedsecrets/{name}")
}

// ---------------------------------------------------------------------------
// Row types
// ---------------------------------------------------------------------------

/// `(id, label, kind_json, wrapped_nonce, wrapped_dek, created_on)`
type ProtectorRow = (String, String, String, Vec<u8>, Vec<u8>, i64);

/// `(id, occurred_on, actor, operation, secret_name, version, outcome, detail)`
type AuditRow = (
    i64,
    i64,
    String,
    String,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
);

struct SecretRow {
    deleted_on: Option<i64>,
    scheduled_purge_on: Option<i64>,
    recovery_id: Option<String>,
}

struct VersionRow {
    props: SecretProperties,
    ciphertext: Ciphertext,
}

#[allow(clippy::struct_field_names)]
struct RawVersion {
    version: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    content_type: Option<String>,
    tags_json: String,
    enabled: bool,
    not_before: Option<i64>,
    expires_on: Option<i64>,
    created_on: i64,
    updated_on: i64,
}

impl RawVersion {
    fn into_row(self, meta: &Meta, name: &str) -> Result<VersionRow> {
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
        Ok(VersionRow { props, ciphertext })
    }
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

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
        let meta = Meta {
            name: name.to_owned(),
            id: random::random_hex(16).map_err(crypto)?,
            created_on: now,
            recovery_level: options.recovery_level,
            retention_days: options.retention_days,
        };
        let recovery_level = serde_json::to_string(&meta.recovery_level)
            .map_err(|err| SecretError::Storage(err.to_string()))?;
        let rows: [(&str, String); 6] = [
            ("schema_version", SCHEMA_VERSION.to_string()),
            ("name", meta.name.clone()),
            ("id", meta.id.clone()),
            ("created_on", nanos(now)?.to_string()),
            ("recovery_level", recovery_level),
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
        let actor = Principal::local_user();
        add_protector(&conn, &meta, &dek, protector, None)?;
        record_audit(
            &conn,
            &actor,
            AuditOperation::VaultCreate,
            None,
            None,
            AuditOutcome::Success,
            Some(BACKEND_NAME),
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
            dek,
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
    pub fn open(path: &Path, unlock: &dyn UnlockProvider) -> Result<Self> {
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
        let protectors = read_protectors(&conn)?;
        let actor = Principal::local_user();
        if protectors.is_empty() {
            return Err(SecretError::Locked(
                "vault has no key protectors".to_owned(),
            ));
        }

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
                    Ok(dek) => return Self::finish_open(conn, dek, meta, path, actor),
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

        let passphrase_protectors: Vec<&ProtectorRecord> = protectors
            .iter()
            .filter(|p| matches!(p.kind, ProtectorKind::Passphrase { .. }))
            .collect();

        if passphrase_protectors.is_empty() {
            reasons.push("no passphrase protector is installed".to_owned());
        } else {
            let labels = passphrase_protectors
                .iter()
                .map(|p| p.label.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            for attempt in 1..=MAX_UNLOCK_ATTEMPTS {
                let prompt = PassphrasePrompt {
                    vault: &meta.name,
                    protector_label: &labels,
                    attempt,
                    max_attempts: MAX_UNLOCK_ATTEMPTS,
                };
                let Some(passphrase) = unlock.passphrase(&prompt)? else {
                    reasons.push("no passphrase supplied".to_owned());
                    break;
                };
                for protector in &passphrase_protectors {
                    let ProtectorKind::Passphrase { salt, params } = &protector.kind else {
                        continue;
                    };
                    let salt = hex::decode(salt).map_err(|_| {
                        SecretError::Storage(format!("corrupt salt on protector {}", protector.id))
                    })?;
                    let kek =
                        kdf::derive_key(passphrase.expose(), &salt, *params).map_err(crypto)?;
                    if let Ok(dek) = try_unwrap(&meta, protector, &kek) {
                        return Self::finish_open(conn, dek, meta, path, actor);
                    }
                }
                record_audit(
                    &conn,
                    &actor,
                    AuditOperation::VaultOpen,
                    None,
                    None,
                    AuditOutcome::Denied,
                    Some("incorrect passphrase"),
                )?;
                reasons.push(format!("passphrase attempt {attempt} rejected"));
            }
        }

        record_audit(
            &conn,
            &actor,
            AuditOperation::VaultOpen,
            None,
            None,
            AuditOutcome::Failure,
            Some("locked"),
        )?;
        Err(SecretError::Locked(reasons.join("; ")))
    }

    fn finish_open(
        conn: Connection,
        dek: SymmetricKey,
        meta: Meta,
        path: &Path,
        actor: Principal,
    ) -> Result<Self> {
        record_audit(
            &conn,
            &actor,
            AuditOperation::VaultOpen,
            None,
            None,
            AuditOutcome::Success,
            None,
        )?;
        let vault = Self {
            conn: Mutex::new(conn),
            dek,
            meta,
            path: path.to_path_buf(),
            actor,
        };
        vault.purge_expired_deletions()?;
        Ok(vault)
    }

    /// Remove OS-keyring entries referenced by the vault at `path`, without
    /// unlocking it. Used before deleting a vault file.
    pub(crate) fn forget_protectors(path: &Path) -> Result<()> {
        let conn = open_connection(path)?;
        for protector in read_protectors(&conn)? {
            if let ProtectorKind::OsKeyring { account, .. } = &protector.kind {
                // Best effort: a missing store must not block deletion.
                let _ = keystore::delete_key(account);
            }
        }
        Ok(())
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

    /// Installed key protectors.
    pub fn protectors(&self) -> Result<Vec<ProtectorInfo>> {
        let conn = self.lock()?;
        Ok(read_protectors(&conn)?
            .iter()
            .map(ProtectorRecord::info)
            .collect())
    }

    /// Add another way to unlock this vault.
    pub fn add_protector(&self, spec: ProtectorSpec, label: Option<&str>) -> Result<ProtectorInfo> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().map_err(db)?;
        let info = add_protector(&tx, &self.meta, &self.dek, spec, label)?;
        record_audit(
            &tx,
            &self.actor,
            AuditOperation::ProtectorAdd,
            None,
            None,
            AuditOutcome::Success,
            Some(&info.label),
        )?;
        tx.commit().map_err(db)?;
        Ok(info)
    }

    /// Remove a protector by id or label. The last protector cannot be
    /// removed: that would make the vault permanently unreadable.
    pub fn remove_protector(&self, id_or_label: &str) -> Result<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().map_err(db)?;
        let protectors = read_protectors(&tx)?;
        let target = protectors
            .iter()
            .find(|p| p.id == id_or_label || p.label == id_or_label)
            .ok_or_else(|| {
                SecretError::InvalidArgument(format!("no protector named '{id_or_label}'"))
            })?;
        if protectors.len() == 1 {
            return Err(SecretError::InvalidArgument(
                "cannot remove the last key protector; add another one first".to_owned(),
            ));
        }
        if let ProtectorKind::OsKeyring { account, .. } = &target.kind {
            keystore::delete_key(account)?;
        }
        tx.execute(
            "DELETE FROM key_protectors WHERE id = ?1",
            params![target.id],
        )
        .map_err(db)?;
        record_audit(
            &tx,
            &self.actor,
            AuditOperation::ProtectorRemove,
            None,
            None,
            AuditOutcome::Success,
            Some(&target.label),
        )?;
        tx.commit().map_err(db)?;
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| SecretError::Storage("vault connection poisoned".to_owned()))
    }

    /// Purge soft-deleted secrets whose retention has elapsed.
    fn purge_expired_deletions(&self) -> Result<usize> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().map_err(db)?;
        let now = nanos(timestamp::now())?;
        let expired: Vec<String> = {
            let mut stmt = tx
                .prepare(
                    "SELECT name FROM secrets
                     WHERE deleted_on IS NOT NULL AND scheduled_purge_on IS NOT NULL
                       AND scheduled_purge_on <= ?1",
                )
                .map_err(db)?;
            let rows = stmt
                .query_map(params![now], |row| row.get::<_, String>(0))
                .map_err(db)?;
            rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db)?
        };
        let system = Principal::system();
        for name in &expired {
            tx.execute("DELETE FROM secrets WHERE name = ?1", params![name])
                .map_err(db)?;
            record_audit(
                &tx,
                &system,
                AuditOperation::SecretPurge,
                Some(name),
                None,
                AuditOutcome::Success,
                Some("retention elapsed"),
            )?;
        }
        tx.commit().map_err(db)?;
        Ok(expired.len())
    }

    fn audit(
        &self,
        conn: &Connection,
        operation: AuditOperation,
        name: Option<&str>,
        version: Option<&str>,
        outcome: AuditOutcome,
        detail: Option<&str>,
    ) -> Result<()> {
        record_audit(conn, &self.actor, operation, name, version, outcome, detail)
    }

    /// Audit a failed operation and return its error.
    fn fail<T>(
        &self,
        conn: &Connection,
        operation: AuditOperation,
        name: Option<&str>,
        version: Option<&str>,
        err: SecretError,
    ) -> Result<T> {
        let outcome = match err {
            SecretError::Disabled { .. }
            | SecretError::NotYetValid { .. }
            | SecretError::Expired { .. }
            | SecretError::PermissionDenied(_) => AuditOutcome::Denied,
            _ => AuditOutcome::Failure,
        };
        record_audit(
            conn,
            &self.actor,
            operation,
            name,
            version,
            outcome,
            Some(err.code()),
        )?;
        Err(err)
    }
}

// ---------------------------------------------------------------------------
// Free helpers over a connection
// ---------------------------------------------------------------------------

fn read_meta(conn: &Connection) -> Result<Meta> {
    let mut stmt = conn
        .prepare("SELECT key, value FROM vault_meta")
        .map_err(db)?;
    let map: HashMap<String, String> = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(db)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db)?;
    let get = |key: &str| -> Result<&String> {
        map.get(key)
            .ok_or_else(|| SecretError::Storage(format!("vault metadata is missing '{key}'")))
    };
    let schema: u32 = get("schema_version")?
        .parse()
        .map_err(|_| SecretError::Storage("corrupt schema_version".to_owned()))?;
    if schema != SCHEMA_VERSION {
        return Err(SecretError::Storage(format!(
            "vault schema version {schema} is not supported by this build (expects {SCHEMA_VERSION})"
        )));
    }
    let created_on = from_nanos(
        get("created_on")?
            .parse()
            .map_err(|_| SecretError::Storage("corrupt created_on".to_owned()))?,
    )?;
    let recovery_level: RecoveryLevel = serde_json::from_str(get("recovery_level")?)
        .map_err(|_| SecretError::Storage("corrupt recovery_level".to_owned()))?;
    let retention_days: u32 = get("retention_days")?
        .parse()
        .map_err(|_| SecretError::Storage("corrupt retention_days".to_owned()))?;
    Ok(Meta {
        name: get("name")?.clone(),
        id: get("id")?.clone(),
        created_on,
        recovery_level,
        retention_days,
    })
}

fn read_protectors(conn: &Connection) -> Result<Vec<ProtectorRecord>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, label, kind_json, wrapped_nonce, wrapped_dek, created_on
             FROM key_protectors ORDER BY created_on, id",
        )
        .map_err(db)?;
    let raw: Vec<ProtectorRow> = stmt
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .map_err(db)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db)?;
    raw.into_iter()
        .map(|(id, label, kind_json, nonce, wrapped, created_on)| {
            let kind: ProtectorKind = serde_json::from_str(&kind_json)
                .map_err(|err| SecretError::Storage(format!("corrupt protector {id}: {err}")))?;
            Ok(ProtectorRecord {
                id,
                label,
                kind,
                wrapped: Ciphertext::from_parts(&nonce, wrapped).map_err(crypto)?,
                created_on: from_nanos(created_on)?,
            })
        })
        .collect()
}

fn try_unwrap(
    meta: &Meta,
    protector: &ProtectorRecord,
    kek: &SymmetricKey,
) -> Result<SymmetricKey> {
    envelope::unwrap_key(
        kek,
        &protector.wrapped,
        protector_aad(&meta.id, &protector.id).as_bytes(),
    )
    .map_err(crypto)
}

fn add_protector(
    conn: &Connection,
    meta: &Meta,
    dek: &SymmetricKey,
    spec: ProtectorSpec,
    label: Option<&str>,
) -> Result<ProtectorInfo> {
    let id = random::random_hex(8).map_err(crypto)?;
    let (kind, kek) = match spec {
        ProtectorSpec::OsKeyring => {
            if !keystore::available() {
                return Err(SecretError::Unsupported(format!(
                    "{} is not available ({}); use a passphrase protector instead",
                    keystore::STORE_NAME,
                    keystore::unavailable_reason().unwrap_or_default()
                )));
            }
            let account = format!("vault/{}/{id}", meta.id);
            let kek = SymmetricKey::generate().map_err(crypto)?;
            keystore::store_key(&account, &kek)?;
            (
                ProtectorKind::OsKeyring {
                    service: keystore::SERVICE.to_owned(),
                    account,
                },
                kek,
            )
        }
        ProtectorSpec::Passphrase { passphrase, params } => {
            if passphrase.is_empty() {
                return Err(SecretError::InvalidArgument(
                    "passphrase must not be empty".to_owned(),
                ));
            }
            let salt = random::random_bytes::<{ kdf::SALT_LEN }>().map_err(crypto)?;
            let kek = kdf::derive_key(passphrase.expose(), &salt, params).map_err(crypto)?;
            (
                ProtectorKind::Passphrase {
                    salt: hex::encode(salt),
                    params,
                },
                kek,
            )
        }
    };

    let existing: Vec<String> = read_protectors(conn)?
        .into_iter()
        .map(|p| p.label)
        .collect();
    let label = if let Some(custom) = label {
        if custom.trim().is_empty() {
            return Err(SecretError::InvalidArgument(
                "protector label must not be empty".to_owned(),
            ));
        }
        if existing.iter().any(|l| l == custom) {
            return Err(SecretError::InvalidArgument(format!(
                "a protector labelled '{custom}' already exists"
            )));
        }
        custom.to_owned()
    } else {
        let base = kind.label().to_owned();
        if existing.contains(&base) {
            format!("{base}-{}", &id[..4])
        } else {
            base
        }
    };

    let wrapped =
        envelope::wrap_key(&kek, dek, protector_aad(&meta.id, &id).as_bytes()).map_err(crypto)?;
    let created_on = timestamp::now();
    let kind_json =
        serde_json::to_string(&kind).map_err(|err| SecretError::Storage(err.to_string()))?;
    conn.execute(
        "INSERT INTO key_protectors (id, label, kind_json, wrapped_nonce, wrapped_dek, created_on)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            id,
            label,
            kind_json,
            wrapped.nonce.as_slice(),
            wrapped.bytes,
            nanos(created_on)?
        ],
    )
    .map_err(db)?;

    Ok(ProtectorInfo {
        id,
        label,
        kind: kind.label().to_owned(),
        created_on,
    })
}

fn record_audit(
    conn: &Connection,
    actor: &Principal,
    operation: AuditOperation,
    secret_name: Option<&str>,
    version: Option<&str>,
    outcome: AuditOutcome,
    detail: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO audit_events (occurred_on, actor, operation, secret_name, version, outcome, detail)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            nanos(timestamp::now())?,
            actor.to_string(),
            operation.as_str(),
            secret_name,
            version,
            outcome.as_str(),
            detail
        ],
    )
    .map_err(db)?;
    Ok(())
}

fn load_secret_row(conn: &Connection, name: &str) -> Result<Option<SecretRow>> {
    conn.query_row(
        "SELECT deleted_on, scheduled_purge_on, recovery_id FROM secrets WHERE name = ?1",
        params![name],
        |row| {
            Ok(SecretRow {
                deleted_on: row.get(0)?,
                scheduled_purge_on: row.get(1)?,
                recovery_id: row.get(2)?,
            })
        },
    )
    .optional()
    .map_err(db)
}

/// Load a live (not deleted) secret row or the matching error.
fn require_live(conn: &Connection, name: &str) -> Result<SecretRow> {
    match load_secret_row(conn, name)? {
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
fn require_deleted(conn: &Connection, name: &str) -> Result<SecretRow> {
    match load_secret_row(conn, name)? {
        None => Err(SecretError::NotFound {
            name: name.to_owned(),
        }),
        Some(row) if row.deleted_on.is_none() => Err(SecretError::NotDeleted {
            name: name.to_owned(),
        }),
        Some(row) => Ok(row),
    }
}

/// All versions of `name`, newest first.
fn load_versions(conn: &Connection, meta: &Meta, name: &str) -> Result<Vec<VersionRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT version, nonce, ciphertext, content_type, tags_json, enabled,
                    not_before, expires_on, created_on, updated_on
             FROM secret_versions WHERE name = ?1 ORDER BY seq DESC",
        )
        .map_err(db)?;
    let raw: Vec<RawVersion> = stmt
        .query_map(params![name], |row| {
            Ok(RawVersion {
                version: row.get(0)?,
                nonce: row.get(1)?,
                ciphertext: row.get(2)?,
                content_type: row.get(3)?,
                tags_json: row.get(4)?,
                enabled: row.get::<_, i64>(5)? != 0,
                not_before: row.get(6)?,
                expires_on: row.get(7)?,
                created_on: row.get(8)?,
                updated_on: row.get(9)?,
            })
        })
        .map_err(db)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db)?;
    raw.into_iter().map(|r| r.into_row(meta, name)).collect()
}

fn newest_props(conn: &Connection, meta: &Meta, name: &str) -> Result<SecretProperties> {
    load_versions(conn, meta, name)?
        .into_iter()
        .next()
        .map(|v| v.props)
        .ok_or_else(|| SecretError::Storage(format!("secret '{name}' has no versions")))
}

fn deleted_from_row(
    conn: &Connection,
    meta: &Meta,
    name: &str,
    row: &SecretRow,
) -> Result<DeletedSecret> {
    let deleted_on = row.deleted_on.ok_or_else(|| SecretError::NotDeleted {
        name: name.to_owned(),
    })?;
    Ok(DeletedSecret {
        properties: newest_props(conn, meta, name)?,
        deleted_on: from_nanos(deleted_on)?,
        scheduled_purge_on: opt_from_nanos(row.scheduled_purge_on)?,
        recovery_id: row
            .recovery_id
            .clone()
            .unwrap_or_else(|| recovery_id(&meta.name, name)),
    })
}

fn select_version<'a>(
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

// ---------------------------------------------------------------------------
// SecretClient
// ---------------------------------------------------------------------------

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
        let tx = conn.transaction().map_err(db)?;
        let now = timestamp::now();

        match load_secret_row(&tx, name)? {
            Some(row) if row.deleted_on.is_some() => {
                return self.fail(
                    &tx,
                    AuditOperation::SecretSet,
                    Some(name),
                    None,
                    SecretError::DeletedConflict {
                        name: name.to_owned(),
                    },
                );
            }
            Some(_) => {}
            None => {
                tx.execute(
                    "INSERT INTO secrets (name, created_on) VALUES (?1, ?2)",
                    params![name, nanos(now)?],
                )
                .map_err(db)?;
            }
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
        let tags_json = serde_json::to_string(&options.tags)
            .map_err(|err| SecretError::Storage(err.to_string()))?;
        tx.execute(
            "INSERT INTO secret_versions
                (name, version, seq, nonce, ciphertext, content_type, tags_json, enabled,
                 not_before, expires_on, created_on, updated_on)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)",
            params![
                name,
                version,
                seq,
                ciphertext.nonce.as_slice(),
                ciphertext.bytes,
                options.content_type,
                tags_json,
                i64::from(options.enabled),
                opt_nanos(options.not_before)?,
                opt_nanos(options.expires_on)?,
                nanos(now)?,
            ],
        )
        .map_err(db)?;

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
            AuditOperation::SecretSet,
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
        let conn = self.lock()?;
        let op = AuditOperation::SecretGet;
        if let Err(err) = require_live(&conn, name) {
            return self.fail(&conn, op, Some(name), version, err);
        }
        let versions = load_versions(&conn, &self.meta, name)?;
        let chosen = match select_version(name, &versions, version, timestamp::now(), true) {
            Ok(v) => v,
            Err(err) => return self.fail(&conn, op, Some(name), version, err),
        };
        let plaintext = match aead::open(
            &self.dek,
            value_aad(&self.meta.id, name, &chosen.props.version).as_bytes(),
            &chosen.ciphertext,
        ) {
            Ok(p) => p,
            Err(err) => {
                return self.fail(
                    &conn,
                    op,
                    Some(name),
                    Some(&chosen.props.version),
                    crypto(err),
                );
            }
        };
        self.audit(
            &conn,
            op,
            Some(name),
            Some(&chosen.props.version),
            AuditOutcome::Success,
            None,
        )?;
        Ok(Secret {
            properties: chosen.props.clone(),
            value: SecretBytes::new(plaintext.to_vec()),
        })
    }

    fn get_secret_properties(&self, name: &str, version: Option<&str>) -> Result<SecretProperties> {
        validate_secret_name(name)?;
        let conn = self.lock()?;
        require_live(&conn, name)?;
        let versions = load_versions(&conn, &self.meta, name)?;
        select_version(name, &versions, version, timestamp::now(), false).map(|v| v.props.clone())
    }

    fn list_properties_of_secrets(&self) -> Result<Vec<SecretProperties>> {
        let conn = self.lock()?;
        let names: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT name FROM secrets WHERE deleted_on IS NULL ORDER BY name")
                .map_err(db)?;
            stmt.query_map([], |row| row.get(0))
                .map_err(db)?
                .collect::<rusqlite::Result<_>>()
                .map_err(db)?
        };
        let mut out = Vec::with_capacity(names.len());
        for name in &names {
            out.push(newest_props(&conn, &self.meta, name)?);
        }
        self.audit(
            &conn,
            AuditOperation::SecretList,
            None,
            None,
            AuditOutcome::Success,
            None,
        )?;
        Ok(out)
    }

    fn list_properties_of_secret_versions(&self, name: &str) -> Result<Vec<SecretProperties>> {
        validate_secret_name(name)?;
        let conn = self.lock()?;
        require_live(&conn, name)?;
        Ok(load_versions(&conn, &self.meta, name)?
            .into_iter()
            .map(|v| v.props)
            .collect())
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
        let tx = conn.transaction().map_err(db)?;
        let op = AuditOperation::SecretUpdate;
        if let Err(err) = require_live(&tx, name) {
            return self.fail(&tx, op, Some(name), version, err);
        }
        let versions = load_versions(&tx, &self.meta, name)?;
        let now = timestamp::now();
        let target = match select_version(name, &versions, version, now, false) {
            Ok(v) => v,
            Err(err) => return self.fail(&tx, op, Some(name), version, err),
        };
        let mut props = target.props.clone();
        update.apply(&mut props, now)?;
        let tags_json = serde_json::to_string(&props.tags)
            .map_err(|err| SecretError::Storage(err.to_string()))?;
        tx.execute(
            "UPDATE secret_versions
             SET enabled = ?3, content_type = ?4, tags_json = ?5, not_before = ?6,
                 expires_on = ?7, updated_on = ?8
             WHERE name = ?1 AND version = ?2",
            params![
                name,
                props.version,
                i64::from(props.enabled),
                props.content_type,
                tags_json,
                opt_nanos(props.not_before)?,
                opt_nanos(props.expires_on)?,
                nanos(now)?,
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
        let tx = conn.transaction().map_err(db)?;
        let op = AuditOperation::SecretDelete;
        if let Err(err) = require_live(&tx, name) {
            return self.fail(&tx, op, Some(name), None, err);
        }
        let props = newest_props(&tx, &self.meta, name)?;
        let now = timestamp::now();
        let deleted = if self.meta.recovery_level.soft_delete_enabled() {
            let purge_on = self.meta.retention().scheduled_purge_on(now);
            let rid = recovery_id(&self.meta.name, name);
            tx.execute(
                "UPDATE secrets SET deleted_on = ?2, scheduled_purge_on = ?3, recovery_id = ?4
                 WHERE name = ?1",
                params![name, nanos(now)?, nanos(purge_on)?, rid],
            )
            .map_err(db)?;
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
        validate_secret_name(name)?;
        let conn = self.lock()?;
        let row = require_deleted(&conn, name)?;
        deleted_from_row(&conn, &self.meta, name, &row)
    }

    fn list_deleted_secrets(&self) -> Result<Vec<DeletedSecret>> {
        let conn = self.lock()?;
        let names: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT name FROM secrets WHERE deleted_on IS NOT NULL ORDER BY name")
                .map_err(db)?;
            stmt.query_map([], |row| row.get(0))
                .map_err(db)?
                .collect::<rusqlite::Result<_>>()
                .map_err(db)?
        };
        names
            .iter()
            .map(|name| {
                let row = require_deleted(&conn, name)?;
                deleted_from_row(&conn, &self.meta, name, &row)
            })
            .collect()
    }

    fn recover_deleted_secret(&self, name: &str) -> Result<SecretProperties> {
        validate_secret_name(name)?;
        let mut conn = self.lock()?;
        let tx = conn.transaction().map_err(db)?;
        let op = AuditOperation::SecretRecover;
        if let Err(err) = require_deleted(&tx, name) {
            return self.fail(&tx, op, Some(name), None, err);
        }
        tx.execute(
            "UPDATE secrets SET deleted_on = NULL, scheduled_purge_on = NULL, recovery_id = NULL
             WHERE name = ?1",
            params![name],
        )
        .map_err(db)?;
        let props = newest_props(&tx, &self.meta, name)?;
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
        let tx = conn.transaction().map_err(db)?;
        let op = AuditOperation::SecretPurge;
        if let Err(err) = require_deleted(&tx, name) {
            return self.fail(&tx, op, Some(name), None, err);
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

#[cfg(test)]
mod tests {
    use sourceorrery_crypto::Argon2Params;

    use super::*;

    fn spec() -> ProtectorSpec {
        ProtectorSpec::Passphrase {
            passphrase: SecretBytes::from("correct horse battery staple"),
            params: Argon2Params::TESTING,
        }
    }

    #[test]
    fn create_open_and_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dev.sorvault");
        {
            let vault =
                SqliteVault::create(&path, "dev", CreateVaultOptions::default(), spec()).unwrap();
            vault
                .set_secret(
                    "database-password",
                    SecretBytes::from("hunter2"),
                    SetSecretOptions::default(),
                )
                .unwrap();
        }
        let unlock = crate::unlock::StaticPassphrase::new("correct horse battery staple");
        let vault = SqliteVault::open(&path, &unlock).unwrap();
        let secret = vault.get_secret("database-password", None).unwrap();
        assert_eq!(secret.value.expose(), b"hunter2");
        assert_eq!(vault.descriptor().unwrap().protectors, vec!["passphrase"]);
    }

    #[test]
    fn wrong_passphrase_is_locked_and_audited() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dev.sorvault");
        SqliteVault::create(&path, "dev", CreateVaultOptions::default(), spec()).unwrap();
        let unlock = crate::unlock::StaticPassphrase::new("nope");
        let err = SqliteVault::open(&path, &unlock).unwrap_err();
        assert_eq!(err.code(), "locked");

        let vault = SqliteVault::open(
            &path,
            &crate::unlock::StaticPassphrase::new("correct horse battery staple"),
        )
        .unwrap();
        let events = vault.audit_events(AuditQuery::default()).unwrap();
        assert!(events.iter().any(|e| {
            e.operation == AuditOperation::VaultOpen && e.outcome == AuditOutcome::Denied
        }));
    }

    #[test]
    fn failed_create_leaves_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dev.sorvault");
        let err = SqliteVault::create(
            &path,
            "dev",
            CreateVaultOptions::default(),
            ProtectorSpec::Passphrase {
                passphrase: SecretBytes::from(""),
                params: Argon2Params::TESTING,
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), "invalid_argument");
        assert!(!path.exists());
    }
}
