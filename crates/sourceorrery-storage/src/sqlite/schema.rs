//! SQL schema, connections, transactions, the `vault_meta` record and the
//! small encoding helpers shared by the other vault modules.

use std::collections::HashMap;
use std::path::Path;

use rusqlite::{Connection, Transaction, TransactionBehavior, params};
use sourceorrery_core::policy::SoftDeletePolicy;
use sourceorrery_core::{RecoveryLevel, Result, SecretError, timestamp};
use sourceorrery_crypto::SymmetricKey;
use time::OffsetDateTime;

use super::{OLDEST_SUPPORTED_SCHEMA, SCHEMA_VERSION};
use crate::integrity::{self, SettingsFields};

#[derive(Clone, Debug)]
pub(super) struct Meta {
    pub(super) schema: u32,
    pub(super) name: String,
    pub(super) id: String,
    pub(super) created_on: OffsetDateTime,
    pub(super) recovery_level: RecoveryLevel,
    /// `recovery_level` exactly as stored; part of the settings tag.
    pub(super) recovery_level_raw: String,
    pub(super) retention_days: u32,
    /// Hex HMAC over the settings, or `None` on a legacy (schema 1) file.
    pub(super) settings_tag: Option<String>,
}

impl Meta {
    pub(super) fn retention(&self) -> SoftDeletePolicy {
        SoftDeletePolicy {
            retention_days: self.retention_days,
        }
    }

    pub(super) fn settings_fields(&self) -> Result<SettingsFields<'_>> {
        Ok(SettingsFields {
            vault_id: &self.id,
            schema: self.schema,
            name: &self.name,
            created_on: nanos(self.created_on)?,
            recovery_level: &self.recovery_level_raw,
            retention_days: self.retention_days,
        })
    }
}

pub(super) const SCHEMA: &str = "
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
    recovery_id        TEXT,
    tag                BLOB
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
    tag          BLOB,
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
    detail      TEXT,
    prev_hash   BLOB,
    hash        BLOB,
    keyed       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS audit_events_by_secret ON audit_events(secret_name, id DESC);
";

/// Columns added by the schema 1 → 2 migration.
pub(super) const MIGRATE_V1_TO_V2: &str = "
ALTER TABLE secrets ADD COLUMN tag BLOB;
ALTER TABLE secret_versions ADD COLUMN tag BLOB;
ALTER TABLE audit_events ADD COLUMN prev_hash BLOB;
ALTER TABLE audit_events ADD COLUMN hash BLOB;
ALTER TABLE audit_events ADD COLUMN keyed INTEGER NOT NULL DEFAULT 0;
";

pub(super) fn open_connection(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).map_err(db)?;
    conn.execute_batch(
        "PRAGMA foreign_keys = ON; PRAGMA secure_delete = ON; PRAGMA busy_timeout = 5000;",
    )
    .map_err(db)?;
    Ok(conn)
}

/// Start a write transaction.
///
/// `BEGIN IMMEDIATE` takes the write lock up front, so two processes cannot
/// both read the audit chain head and then append to it. The `body`
/// savepoint lets [`SqliteVault::fail`] discard a half-done operation while
/// still committing its audit row.
pub(super) fn begin_write(conn: &mut Connection) -> Result<Transaction<'_>> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(db)?;
    tx.execute_batch("SAVEPOINT body").map_err(db)?;
    Ok(tx)
}

#[allow(clippy::needless_pass_by_value)] // used as a `map_err` function pointer
pub(super) fn db(err: rusqlite::Error) -> SecretError {
    SecretError::Storage(err.to_string())
}

#[allow(clippy::needless_pass_by_value)] // used as a `map_err` function pointer
pub(super) fn crypto(err: sourceorrery_crypto::CryptoError) -> SecretError {
    SecretError::Crypto(err.to_string())
}

/// The error for a row whose integrity tag does not verify. Names only.
pub(super) fn integrity_error(name: &str) -> SecretError {
    SecretError::Crypto(format!("metadata integrity check failed for {name}"))
}

pub(super) fn nanos(ts: OffsetDateTime) -> Result<i64> {
    i64::try_from(timestamp::to_unix_nanos(ts))
        .map_err(|_| SecretError::InvalidArgument("timestamp out of range".to_owned()))
}

pub(super) fn from_nanos(value: i64) -> Result<OffsetDateTime> {
    timestamp::from_unix_nanos(i128::from(value))
}

pub(super) fn opt_nanos(ts: Option<OffsetDateTime>) -> Result<Option<i64>> {
    ts.map(nanos).transpose()
}

pub(super) fn opt_from_nanos(value: Option<i64>) -> Result<Option<OffsetDateTime>> {
    value.map(from_nanos).transpose()
}

pub(super) fn value_aad(vault_id: &str, name: &str, version: &str) -> String {
    format!("sourceorrery/v1/value/{vault_id}/{name}/{version}")
}

/// AAD binding a wrapped vault key to its protector *and* to the on-disk
/// schema it was wrapped under. A key wrapped under schema 2 cannot be
/// unwrapped as if the file were schema 1, which is what lets a rolled-back
/// schema marker be told apart from a genuine legacy vault.
pub(super) fn protector_aad(vault_id: &str, protector_id: &str, schema: u32) -> String {
    format!("sourceorrery/v{schema}/protector/{vault_id}/{protector_id}")
}

pub(super) fn recovery_id(vault: &str, name: &str) -> String {
    format!("sourceorrery://{vault}/deletedsecrets/{name}")
}

pub(super) fn read_meta(conn: &Connection) -> Result<Meta> {
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
    if !(OLDEST_SUPPORTED_SCHEMA..=SCHEMA_VERSION).contains(&schema) {
        return Err(SecretError::Storage(format!(
            "vault schema version {schema} is not supported by this build (expects {SCHEMA_VERSION})"
        )));
    }
    let created_on = from_nanos(
        get("created_on")?
            .parse()
            .map_err(|_| SecretError::Storage("corrupt created_on".to_owned()))?,
    )?;
    let recovery_level_raw = get("recovery_level")?.clone();
    let recovery_level: RecoveryLevel = serde_json::from_str(&recovery_level_raw)
        .map_err(|_| SecretError::Storage("corrupt recovery_level".to_owned()))?;
    let retention_days: u32 = get("retention_days")?
        .parse()
        .map_err(|_| SecretError::Storage("corrupt retention_days".to_owned()))?;
    Ok(Meta {
        schema,
        name: get("name")?.clone(),
        id: get("id")?.clone(),
        created_on,
        recovery_level,
        recovery_level_raw,
        retention_days,
        settings_tag: map.get(integrity::SETTINGS_KEY).cloned(),
    })
}

/// Write (or refresh) the authenticated settings record.
pub(super) fn write_settings_tag(conn: &Connection, key: &SymmetricKey, meta: &Meta) -> Result<()> {
    let tag = integrity::settings_tag(key, &meta.settings_fields()?);
    conn.execute(
        "INSERT INTO vault_meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![integrity::SETTINGS_KEY, tag],
    )
    .map_err(db)?;
    Ok(())
}
