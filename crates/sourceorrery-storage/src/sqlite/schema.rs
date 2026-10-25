//! SQL schema, connections, transactions, the `vault_meta` record and the
//! small encoding helpers shared by the other vault modules.

use std::collections::HashMap;
use std::path::Path;

use rusqlite::{Connection, Transaction, TransactionBehavior, params};
use sourceorrery_core::policy::SoftDeletePolicy;
use sourceorrery_core::{RecoveryLevel, Result, SecretError, timestamp};
use sourceorrery_crypto::{MAC_LEN, SymmetricKey};
use time::OffsetDateTime;

use super::SCHEMA_VERSION;
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
    /// Hex HMAC over the settings; `None` only on a damaged file, which
    /// the unlock refuses.
    pub(super) settings_tag: Option<String>,
    /// The view check's values as stored; part of the settings tag when
    /// present. The live state after opening is `SqliteVault::view`; this
    /// is what the file said when it was opened.
    pub(super) view: ViewState,
    /// Every `connections` row as `(id, tag)`, ordered by id, as the file
    /// held them when read; part of the settings tag.
    pub(super) connections: Vec<(String, Vec<u8>)>,
    /// Every `projects` row as `(id, tag)`, ordered by id, likewise.
    pub(super) projects: Vec<(String, Vec<u8>)>,
    /// Every `key_wraps` row as `(id, encoding)` (ADR 0010).
    pub(super) key_wraps: Vec<(String, Vec<u8>)>,
}

/// The authenticated settings that can change after creation: the view
/// check's sealed password hash and hint, the authenticator record and
/// the count of wrong answers, each as its stored JSON string so the tag
/// covers exactly the bytes in the file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct ViewState {
    pub(super) password: Option<String>,
    pub(super) password_hint: Option<String>,
    pub(super) second_factor: Option<String>,
    pub(super) check_failures: Option<String>,
}

/// `vault_meta` key of the sealed password hash.
pub(super) const PASSWORD_KEY: &str = "password";
/// `vault_meta` key of the sealed password hint.
pub(super) const PASSWORD_HINT_KEY: &str = "password_hint";
/// `vault_meta` key of the authenticator record.
pub(super) const SECOND_FACTOR_KEY: &str = "second_factor";
/// `vault_meta` key of the count of wrong view-check answers.
pub(super) const CHECK_FAILURES_KEY: &str = "check_failures";

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
            password: self.view.password.as_deref(),
            password_hint: self.view.password_hint.as_deref(),
            second_factor: self.view.second_factor.as_deref(),
            check_failures: self.view.check_failures.as_deref(),
            connections: &self.connections,
            projects: &self.projects,
            key_wraps: &self.key_wraps,
        })
    }

    /// The stored settings tag, decoded; `None` when it is missing or not a
    /// tag.
    pub(super) fn stored_settings_tag(&self) -> Option<SettingsTag> {
        let bytes = hex::decode(self.settings_tag.as_deref()?).ok()?;
        <[u8; MAC_LEN]>::try_from(bytes).ok().map(SettingsTag)
    }

    /// This metadata with another view-check state, for computing the tag
    /// a change will carry.
    pub(super) fn with_view(&self, view: &ViewState) -> Self {
        let mut meta = self.clone();
        meta.view = view.clone();
        meta
    }
}

pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS vault_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS key_wraps (
    id            TEXT PRIMARY KEY,
    kind_json     TEXT NOT NULL,
    wrapped_nonce BLOB NOT NULL,
    wrapped_key   BLOB NOT NULL,
    created_on    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS connections (
    id                 TEXT PRIMARY KEY,
    kind               TEXT NOT NULL,
    settings_json      TEXT NOT NULL,
    credential_source  TEXT NOT NULL,
    sealed_credentials TEXT,
    created_on         INTEGER NOT NULL,
    last_test_on       INTEGER,
    last_test_outcome  TEXT,
    tag                BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS secrets (
    name               TEXT PRIMARY KEY,
    created_on         INTEGER NOT NULL,
    deleted_on         INTEGER,
    scheduled_purge_on INTEGER,
    recovery_id        TEXT,
    storage            TEXT REFERENCES connections(id),
    description        TEXT,
    tag                BLOB
);
CREATE INDEX IF NOT EXISTS secrets_by_storage ON secrets(storage) WHERE storage IS NOT NULL;
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
CREATE TABLE IF NOT EXISTS projects (
    id        TEXT PRIMARY KEY,
    path_mac  BLOB NOT NULL UNIQUE,
    sealed    TEXT NOT NULL,
    linked_on INTEGER NOT NULL,
    tag       BLOB NOT NULL
);
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
    keyed       INTEGER NOT NULL DEFAULT 0,
    state_tag   BLOB,
    version_tag BLOB,
    settings_tag BLOB
);
CREATE INDEX IF NOT EXISTS audit_events_by_secret ON audit_events(secret_name, id DESC);
CREATE INDEX IF NOT EXISTS audit_checkpoints ON audit_events(secret_name, id)
    WHERE state_tag IS NOT NULL OR version_tag IS NOT NULL;
CREATE INDEX IF NOT EXISTS audit_verifications ON audit_events(id)
    WHERE operation = 'audit_verify';
CREATE INDEX IF NOT EXISTS audit_settings ON audit_events(id)
    WHERE settings_tag IS NOT NULL;
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

/// [`integrity_error`] with the reason the row was refused. `reason` must
/// name rows and events only, never a value.
pub(super) fn integrity_error_because(name: &str, reason: &str) -> SecretError {
    SecretError::Crypto(format!(
        "metadata integrity check failed for {name}: {reason}"
    ))
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
    if schema < SCHEMA_VERSION {
        // There is no migration: the format changed with how a vault is
        // opened and checked, and the owner recreates the vault.
        return Err(SecretError::MigrationRequired {
            name: get("name").cloned().unwrap_or_default(),
            schema,
        });
    }
    if schema > SCHEMA_VERSION {
        return Err(SecretError::Storage(format!(
            "vault schema version {schema} is newer than this build supports \
             ({SCHEMA_VERSION}); use a newer release"
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
        view: ViewState {
            password: map.get(PASSWORD_KEY).cloned(),
            password_hint: map.get(PASSWORD_HINT_KEY).cloned(),
            second_factor: map.get(SECOND_FACTOR_KEY).cloned(),
            check_failures: map.get(CHECK_FAILURES_KEY).cloned(),
        },
        connections: read_row_tags(conn, "connections")?,
        projects: read_row_tags(conn, "projects")?,
        key_wraps: read_wrap_entries(conn, get("id")?)?,
    })
}

/// Every `key_wraps` row as `(id, encoding)`, ordered by id, as the
/// settings record lists them.
pub(super) fn read_wrap_entries(
    conn: &Connection,
    vault_id: &str,
) -> Result<Vec<(String, Vec<u8>)>> {
    type Row = (String, String, Vec<u8>, Vec<u8>, i64);
    let rows: Vec<Row> = conn
        .prepare(
            "SELECT id, kind_json, wrapped_nonce, wrapped_key, created_on
             FROM key_wraps ORDER BY id",
        )
        .map_err(db)?
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .map_err(db)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db)?;
    Ok(rows
        .into_iter()
        .map(|(id, kind_json, nonce, wrapped, created_on)| {
            let encoding = integrity::key_wrap_canonical(
                vault_id, &id, &kind_json, &nonce, &wrapped, created_on,
            );
            (id, encoding)
        })
        .collect())
}

/// Every row of `table` (`connections` or `projects`) as `(id, tag)`,
/// ordered by id.
pub(super) fn read_row_tags(conn: &Connection, table: &str) -> Result<Vec<(String, Vec<u8>)>> {
    debug_assert!(matches!(table, "connections" | "projects"));
    conn.prepare(&format!("SELECT id, tag FROM {table} ORDER BY id"))
        .map_err(db)?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(db)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db)
}

/// Insert or replace one `vault_meta` row.
pub(super) fn put_meta(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO vault_meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )
    .map_err(db)?;
    Ok(())
}

/// Remove one `vault_meta` row, if present.
pub(super) fn delete_meta(conn: &Connection, key: &str) -> Result<()> {
    conn.execute("DELETE FROM vault_meta WHERE key = ?1", params![key])
        .map_err(db)?;
    Ok(())
}

/// The tag a change left on the settings record. The change's audit event
/// must carry it (`Checkpoints::settings`): a record whose tag the chain
/// does not record last is refused.
#[must_use = "the audit event of a settings change must record the tag it wrote"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SettingsTag(pub(super) [u8; MAC_LEN]);

/// Write (or refresh) the authenticated settings record: `meta`'s fields
/// with the connections, projects and key wraps `conn` holds now, so a
/// write inside a transaction covers the rows that transaction left.
pub(super) fn write_settings_tag(
    conn: &Connection,
    key: &SymmetricKey,
    meta: &Meta,
) -> Result<SettingsTag> {
    let connections = read_row_tags(conn, "connections")?;
    let projects = read_row_tags(conn, "projects")?;
    let key_wraps = read_wrap_entries(conn, &meta.id)?;
    let fields = SettingsFields {
        connections: &connections,
        projects: &projects,
        key_wraps: &key_wraps,
        ..meta.settings_fields()?
    };
    let tag = integrity::settings_tag(key, &fields);
    conn.execute(
        "INSERT INTO vault_meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![integrity::SETTINGS_KEY, hex::encode(tag)],
    )
    .map_err(db)?;
    Ok(SettingsTag(tag))
}
