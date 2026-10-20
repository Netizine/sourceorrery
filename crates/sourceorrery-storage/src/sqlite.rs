//! The encrypted SQLite vault.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sourceorrery_core::audit::{AuditEvent, AuditOperation, AuditOutcome, AuditQuery};
use sourceorrery_core::policy::{self, SoftDeletePolicy};
use sourceorrery_core::{
    DeletedSecret, Principal, RecoveryLevel, Result, Secret, SecretBytes, SecretClient,
    SecretError, SecretProperties, SetSecretOptions, UpdateSecretProperties, VaultDescriptor,
    timestamp, validate_secret_name, validate_vault_name, validate_version_id,
};
use sourceorrery_crypto::{Ciphertext, MAC_LEN, SymmetricKey, aead, envelope, kdf, random};
use time::OffsetDateTime;

use crate::integrity::{
    self, AuditFields, AuditVerification, SecretFields, SettingsFields, VersionFields,
};
use crate::keystore;
use crate::protector::{ProtectorInfo, ProtectorKind, ProtectorRecord, ProtectorSpec};
use crate::registry::restrict_permissions;
use crate::unlock::{PassphrasePrompt, UnlockProvider};
use crate::{BACKEND_NAME, SCHEMA_VERSION};

/// Maximum passphrase attempts per `open`.
pub const MAX_UNLOCK_ATTEMPTS: u32 = 3;

/// Most passphrase protectors tried per attempt. Each one costs an Argon2id
/// derivation whose parameters come from the file, so the total work an
/// unlock can be made to do is bounded here and in `Argon2Params::MAX`.
const MAX_PASSPHRASE_PROTECTORS: usize = 8;

/// Oldest on-disk schema this build can open (and migrate forward).
const OLDEST_SUPPORTED_SCHEMA: u32 = 1;

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

/// What unlocked the vault: needed afterwards to re-wrap the key under the
/// current format and to judge a legacy schema marker.
struct Unlocked {
    protector_id: String,
    kek: SymmetricKey,
    /// Schema whose AAD the stored wrapped key was bound to.
    wrapped_schema: u32,
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

#[derive(Clone, Debug)]
struct Meta {
    schema: u32,
    name: String,
    id: String,
    created_on: OffsetDateTime,
    recovery_level: RecoveryLevel,
    /// `recovery_level` exactly as stored; part of the settings tag.
    recovery_level_raw: String,
    retention_days: u32,
    /// Hex HMAC over the settings, or `None` on a legacy (schema 1) file.
    settings_tag: Option<String>,
}

impl Meta {
    fn retention(&self) -> SoftDeletePolicy {
        SoftDeletePolicy {
            retention_days: self.retention_days,
        }
    }

    fn settings_fields(&self) -> Result<SettingsFields<'_>> {
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
const MIGRATE_V1_TO_V2: &str = "
ALTER TABLE secrets ADD COLUMN tag BLOB;
ALTER TABLE secret_versions ADD COLUMN tag BLOB;
ALTER TABLE audit_events ADD COLUMN prev_hash BLOB;
ALTER TABLE audit_events ADD COLUMN hash BLOB;
ALTER TABLE audit_events ADD COLUMN keyed INTEGER NOT NULL DEFAULT 0;
";

fn open_connection(path: &Path) -> Result<Connection> {
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
fn begin_write(conn: &mut Connection) -> Result<Transaction<'_>> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(db)?;
    tx.execute_batch("SAVEPOINT body").map_err(db)?;
    Ok(tx)
}

#[allow(clippy::needless_pass_by_value)] // used as a `map_err` function pointer
fn db(err: rusqlite::Error) -> SecretError {
    SecretError::Storage(err.to_string())
}

#[allow(clippy::needless_pass_by_value)] // used as a `map_err` function pointer
fn crypto(err: sourceorrery_crypto::CryptoError) -> SecretError {
    SecretError::Crypto(err.to_string())
}

/// The error for a row whose integrity tag does not verify. Names only.
fn integrity_error(name: &str) -> SecretError {
    SecretError::Crypto(format!("metadata integrity check failed for {name}"))
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

/// AAD binding a wrapped vault key to its protector *and* to the on-disk
/// schema it was wrapped under. A key wrapped under schema 2 cannot be
/// unwrapped as if the file were schema 1, which is what lets a rolled-back
/// schema marker be told apart from a genuine legacy vault.
fn protector_aad(vault_id: &str, protector_id: &str, schema: u32) -> String {
    format!("sourceorrery/v{schema}/protector/{vault_id}/{protector_id}")
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

/// An audit row plus its chain columns.
struct ChainRow {
    row: AuditRow,
    prev_hash: Option<Vec<u8>>,
    hash: Option<Vec<u8>>,
    keyed: bool,
}

impl ChainRow {
    fn fields<'a>(&'a self, vault_id: &'a str) -> AuditFields<'a> {
        let (id, occurred_on, actor, operation, secret_name, version, outcome, detail) = &self.row;
        AuditFields {
            vault_id,
            id: *id,
            occurred_on: *occurred_on,
            actor,
            operation,
            secret_name: secret_name.as_deref(),
            version: version.as_deref(),
            outcome,
            detail: detail.as_deref(),
            keyed: self.keyed,
        }
    }
}

struct SecretRow {
    created_on: i64,
    deleted_on: Option<i64>,
    scheduled_purge_on: Option<i64>,
    recovery_id: Option<String>,
}

impl SecretRow {
    fn fields<'a>(&'a self, vault_id: &'a str, name: &'a str) -> SecretFields<'a> {
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

struct VersionRow {
    props: SecretProperties,
    ciphertext: Ciphertext,
    /// Stored fields the tag covers that `props` does not carry verbatim.
    seq: i64,
    created_on: i64,
}

/// Everything needed to insert one new version row.
struct NewVersion<'a> {
    name: &'a str,
    version: &'a str,
    seq: i64,
    ciphertext: &'a Ciphertext,
    options: &'a SetSecretOptions,
    now: i64,
}

#[allow(clippy::struct_field_names)]
struct RawVersion {
    version: String,
    seq: i64,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    content_type: Option<String>,
    tags_json: String,
    enabled: bool,
    not_before: Option<i64>,
    expires_on: Option<i64>,
    created_on: i64,
    updated_on: i64,
    tag: Option<Vec<u8>>,
}

impl RawVersion {
    fn fields<'a>(&'a self, vault_id: &'a str, name: &'a str) -> VersionFields<'a> {
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

    fn into_row(self, meta: &Meta, key: &SymmetricKey, name: &str) -> Result<VersionRow> {
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

fn query_raw_versions(conn: &Connection, name: &str) -> Result<Vec<RawVersion>> {
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

// ---------------------------------------------------------------------------
// Audit writer
// ---------------------------------------------------------------------------

/// Appends rows to the audit chain.
///
/// `key` is `None` only before the vault is unlocked; rows written then are
/// chained with the all-zero key and flagged unkeyed.
struct AuditWriter<'a> {
    meta: &'a Meta,
    key: Option<&'a SymmetricKey>,
    actor: &'a Principal,
    /// Accept a log with no rows and no head record. True only while a vault
    /// is being created or migrated; for an existing vault that state means
    /// the whole history and its head were removed.
    allow_empty_chain: bool,
}

impl AuditWriter<'_> {
    /// Append one row. Runs in the caller's transaction when there is one,
    /// otherwise in its own immediate transaction so the read-then-append
    /// on the chain head is atomic across processes.
    fn record(
        &self,
        conn: &Connection,
        operation: AuditOperation,
        secret_name: Option<&str>,
        version: Option<&str>,
        outcome: AuditOutcome,
        detail: Option<&str>,
    ) -> Result<()> {
        if self.meta.schema < 2 {
            // Pre-migration rows (failed unlocks of a schema 1 vault): the
            // chain columns do not exist yet; the migration chains them.
            return record_legacy(
                conn,
                self.actor,
                operation,
                secret_name,
                version,
                outcome,
                detail,
            );
        }
        let own_tx = conn.is_autocommit();
        if own_tx {
            conn.execute_batch("BEGIN IMMEDIATE").map_err(db)?;
        }
        let result = self.append(conn, operation, secret_name, version, outcome, detail);
        if own_tx {
            match &result {
                Ok(()) => conn.execute_batch("COMMIT").map_err(db)?,
                Err(_) => {
                    let _ = conn.execute_batch("ROLLBACK");
                }
            }
        }
        result
    }

    /// Append a row. A keyed append first checks that the recorded chain
    /// head is still the newest keyed row; if rows have been removed from
    /// the end of the log since the last keyed write, an `audit_verify` /
    /// `failure` row recording that goes in first, so the evidence becomes
    /// part of the chain before the head is re-anchored.
    fn append(
        &self,
        conn: &Connection,
        operation: AuditOperation,
        secret_name: Option<&str>,
        version: Option<&str>,
        outcome: AuditOutcome,
        detail: Option<&str>,
    ) -> Result<()> {
        if let Some(key) = self.key
            && let Some(problem) = head_problem(conn, key, &self.meta.id, self.allow_empty_chain)?
        {
            self.append_row(
                conn,
                AuditOperation::AuditVerify,
                None,
                None,
                AuditOutcome::Failure,
                Some(&problem),
            )?;
        }
        self.append_row(conn, operation, secret_name, version, outcome, detail)
    }

    fn append_row(
        &self,
        conn: &Connection,
        operation: AuditOperation,
        secret_name: Option<&str>,
        version: Option<&str>,
        outcome: AuditOutcome,
        detail: Option<&str>,
    ) -> Result<()> {
        let occurred_on = nanos(timestamp::now())?;
        let actor = self.actor.to_string();
        let prev = last_hash(conn)?;
        let keyed = self.key.is_some();
        conn.execute(
            "INSERT INTO audit_events
                (occurred_on, actor, operation, secret_name, version, outcome, detail,
                 prev_hash, keyed)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                occurred_on,
                actor,
                operation.as_str(),
                secret_name,
                version,
                outcome.as_str(),
                detail,
                prev.as_slice(),
                i64::from(keyed),
            ],
        )
        .map_err(db)?;
        let id = conn.last_insert_rowid();
        let fields = AuditFields {
            vault_id: &self.meta.id,
            id,
            occurred_on,
            actor: &actor,
            operation: operation.as_str(),
            secret_name,
            version,
            outcome: outcome.as_str(),
            detail,
            keyed,
        };
        let zero = integrity::zero_key();
        let key = self.key.unwrap_or(&zero);
        let hash = integrity::audit_hash(key, &prev, &fields);
        conn.execute(
            "UPDATE audit_events SET hash = ?2 WHERE id = ?1",
            params![id, hash.as_slice()],
        )
        .map_err(db)?;
        if let Some(key) = self.key {
            write_head(conn, key, &self.meta.id, id, &hash)?;
        }
        Ok(())
    }
}

/// Schema 1 insert: no chain columns.
fn record_legacy(
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

/// Chain hash of the newest audit row, or zeros for an empty log.
fn last_hash(conn: &Connection) -> Result<[u8; MAC_LEN]> {
    let last: Option<Option<Vec<u8>>> = conn
        .query_row(
            "SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(db)?;
    Ok(integrity::hash_or_zero(last.flatten().as_deref()))
}

fn write_head(
    conn: &Connection,
    key: &SymmetricKey,
    vault_id: &str,
    id: i64,
    hash: &[u8; MAC_LEN],
) -> Result<()> {
    conn.execute(
        "INSERT INTO vault_meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![
            integrity::AUDIT_HEAD_KEY,
            integrity::head_value(key, vault_id, id, hash)
        ],
    )
    .map_err(db)?;
    Ok(())
}

fn read_head(conn: &Connection) -> Result<Option<String>> {
    conn.query_row(
        "SELECT value FROM vault_meta WHERE key = ?1",
        params![integrity::AUDIT_HEAD_KEY],
        |row| row.get(0),
    )
    .optional()
    .map_err(db)
}

/// `(id, hash)` of the newest row written with the metadata key.
fn last_keyed_row(conn: &Connection) -> Result<Option<(i64, Vec<u8>)>> {
    conn.query_row(
        "SELECT id, hash FROM audit_events WHERE keyed = 1 ORDER BY id DESC LIMIT 1",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get::<_, Option<Vec<u8>>>(1)?.unwrap_or_default(),
            ))
        },
    )
    .optional()
    .map_err(db)
}

/// Compare the recorded chain head with the newest keyed row. `None` when
/// they agree; otherwise a short, value-free description of the problem,
/// suitable as audit detail.
fn head_problem(
    conn: &Connection,
    key: &SymmetricKey,
    vault_id: &str,
    allow_empty: bool,
) -> Result<Option<String>> {
    Ok(match (read_head(conn)?, last_keyed_row(conn)?) {
        (None, None) if allow_empty => None,
        (None, None) => Some("audit history missing: no keyed rows and no head record".to_owned()),
        (None, Some(_)) => Some("audit chain head missing".to_owned()),
        (Some(_), None) => Some("audit chain head stale: no keyed rows remain".to_owned()),
        (Some(head), Some((id, hash))) => {
            if integrity::head_matches(key, vault_id, &head, id, &hash) {
                None
            } else {
                Some(match integrity::head_id(&head) {
                    Some(head_id) if head_id > id => {
                        format!("rows removed after event {id} (head was event {head_id})")
                    }
                    Some(head_id) => format!("audit chain head stale (head was event {head_id})"),
                    None => "audit chain head invalid".to_owned(),
                })
            }
        }
    })
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

    /// OS-keyring accounts referenced by the vault at `path`, without
    /// unlocking it, each with whether the account is the one this vault
    /// would have created for that protector (`vault/<vault id>/<protector
    /// id>`). Protector metadata is unauthenticated until the vault is
    /// unlocked, so callers must not delete an account that fails that
    /// check, and should also make sure no other vault references it.
    pub(crate) fn keyring_accounts(path: &Path) -> Result<Vec<(String, bool)>> {
        let conn = open_connection(path)?;
        let meta = read_meta(&conn)?;
        Ok(read_protectors(&conn)?
            .into_iter()
            .filter_map(|protector| match protector.kind {
                ProtectorKind::OsKeyring { account, .. } => {
                    let owned = account == keyring_account(&meta.id, &protector.id);
                    Some((account, owned))
                }
                ProtectorKind::Passphrase { .. } => None,
            })
            .collect())
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
        let tx = begin_write(&mut conn)?;
        let info = add_protector(&tx, &self.meta, &self.dek, spec, label)?;
        self.audit(
            &tx,
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
    ///
    /// For an OS-keyring protector the credential-store entry is deleted
    /// only after the database change is committed, and only when the
    /// stored account is the one this vault created and no other vault file
    /// beside this one references it. Returns a note when the entry was kept
    /// (so the caller can tell the user), `None` otherwise.
    pub fn remove_protector(&self, id_or_label: &str) -> Result<Option<String>> {
        let mut conn = self.lock()?;
        let tx = begin_write(&mut conn)?;
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
        let keyring_account = match &target.kind {
            ProtectorKind::OsKeyring { account, .. } => Some(account.clone()),
            ProtectorKind::Passphrase { .. } => None,
        };
        let target_id = target.id.clone();
        let target_label = target.label.clone();
        tx.execute(
            "DELETE FROM key_protectors WHERE id = ?1",
            params![target_id],
        )
        .map_err(db)?;
        self.audit(
            &tx,
            AuditOperation::ProtectorRemove,
            None,
            None,
            AuditOutcome::Success,
            Some(&target_label),
        )?;
        tx.commit().map_err(db)?;
        drop(conn);

        let Some(account) = keyring_account else {
            return Ok(None);
        };
        if account != keyring_account_name(&self.meta.id, &target_id) {
            return Ok(Some(format!(
                "kept OS-keyring entry {account}: its name does not match this vault's identity"
            )));
        }
        let registry = crate::VaultRegistry::with_root(
            self.path
                .parent()
                .and_then(Path::parent)
                .unwrap_or_else(|| Path::new(".")),
        );
        if registry.keyring_account_referenced_elsewhere(&self.path, &account)? {
            return Ok(Some(format!(
                "kept OS-keyring entry {account}: another vault in this home references it"
            )));
        }
        match keystore::delete_key(&account) {
            Ok(()) => Ok(None),
            Err(err) => Ok(Some(format!(
                "protector removed, but its OS-keyring entry {account} could not be deleted: {err}"
            ))),
        }
    }

    /// Check every audit row's chain hash and the recorded chain head.
    ///
    /// Read-only: writes no audit row of its own. See
    /// [`AuditVerification`] for how to read the result.
    pub fn verify_audit_chain(&self) -> Result<AuditVerification> {
        let conn = self.lock()?;
        let rows = read_chain(&conn)?;
        let zero = integrity::zero_key();
        let mut prev = integrity::ZERO_HASH;
        let mut out = AuditVerification {
            rows: 0,
            keyed: 0,
            unkeyed: 0,
            first_broken: None,
            truncations: 0,
            head_valid: head_problem(&conn, &self.metadata_key, &self.meta.id, false)?.is_none(),
        };
        for row in &rows {
            out.rows += 1;
            let key = if row.keyed {
                out.keyed += 1;
                &self.metadata_key
            } else {
                out.unkeyed += 1;
                &zero
            };
            let fields = row.fields(&self.meta.id);
            let linked = row.prev_hash.as_deref() == Some(prev.as_slice());
            let authentic = integrity::verify_audit_hash(key, &prev, &fields, row.hash.as_deref());
            if !(linked && authentic) && out.first_broken.is_none() {
                out.first_broken = Some(u64::try_from(fields.id).unwrap_or_default());
            }
            if row.keyed
                && authentic
                && fields.operation == AuditOperation::AuditVerify.as_str()
                && fields.outcome == AuditOutcome::Failure.as_str()
            {
                out.truncations += 1;
            }
            prev = integrity::hash_or_zero(row.hash.as_deref());
        }
        Ok(out)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| SecretError::Storage("vault connection poisoned".to_owned()))
    }

    /// Purge soft-deleted secrets whose retention has elapsed.
    fn purge_expired_deletions(&self) -> Result<usize> {
        let mut conn = self.lock()?;
        let tx = begin_write(&mut conn)?;
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
        let writer = AuditWriter {
            meta: &self.meta,
            key: Some(&self.metadata_key),
            actor: &system,
            allow_empty_chain: false,
        };
        let mut purged = 0;
        for name in &expired {
            // A deletion state that does not verify was not written by this
            // vault: leave the row alone (reads will refuse it) and record
            // the failure rather than purge on an attacker's say-so.
            if let Err(err) = self.load_secret_row(&tx, name) {
                writer.record(
                    &tx,
                    AuditOperation::SecretPurge,
                    Some(name),
                    None,
                    AuditOutcome::Failure,
                    Some(err.code()),
                )?;
                continue;
            }
            tx.execute("DELETE FROM secrets WHERE name = ?1", params![name])
                .map_err(db)?;
            writer.record(
                &tx,
                AuditOperation::SecretPurge,
                Some(name),
                None,
                AuditOutcome::Success,
                Some("retention elapsed"),
            )?;
            purged += 1;
        }
        tx.commit().map_err(db)?;
        Ok(purged)
    }

    fn writer(&self) -> AuditWriter<'_> {
        AuditWriter {
            meta: &self.meta,
            key: Some(&self.metadata_key),
            actor: &self.actor,
            allow_empty_chain: false,
        }
    }

    /// Validate a secret name inside an operation so that a rejected name is
    /// still an audited failure. The name itself is not recorded: an invalid
    /// name is arbitrary input and could be a value pasted by mistake.
    fn validated<'c>(
        &self,
        tx: Transaction<'c>,
        operation: AuditOperation,
        name: &str,
    ) -> Result<Transaction<'c>> {
        match validate_secret_name(name) {
            Ok(()) => Ok(tx),
            Err(err) => self.fail(tx, operation, None, None, err),
        }
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
        self.writer()
            .record(conn, operation, name, version, outcome, detail)
    }

    /// Abandon the operation in `tx`, audit its failure and return the error.
    ///
    /// Everything written since [`begin_write`] is rolled back; the audit
    /// row alone is committed so failures stay on the record.
    fn fail<T>(
        &self,
        tx: Transaction<'_>,
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
        tx.execute_batch("ROLLBACK TO SAVEPOINT body; RELEASE SAVEPOINT body;")
            .map_err(db)?;
        self.writer()
            .record(&tx, operation, name, version, outcome, Some(err.code()))?;
        tx.commit().map_err(db)?;
        Err(err)
    }

    /// Finish a metadata-only read: success and failure are both audited,
    /// with `detail` naming what was inspected.
    fn finish_read<T>(
        &self,
        tx: Transaction<'_>,
        operation: AuditOperation,
        name: Option<&str>,
        detail: &str,
        result: Result<T>,
    ) -> Result<T> {
        match result {
            Ok(value) => {
                self.audit(
                    &tx,
                    operation,
                    name,
                    None,
                    AuditOutcome::Success,
                    Some(detail),
                )?;
                tx.commit().map_err(db)?;
                Ok(value)
            }
            Err(err) => self.fail(tx, operation, name, None, err),
        }
    }

    // --- authenticated reads -------------------------------------------

    fn load_secret_row(&self, conn: &Connection, name: &str) -> Result<Option<SecretRow>> {
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
        match found {
            None => Ok(None),
            Some((row, tag)) => {
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
    fn require_live(&self, conn: &Connection, name: &str) -> Result<SecretRow> {
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
    fn require_deleted(&self, conn: &Connection, name: &str) -> Result<SecretRow> {
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

    /// All versions of `name`, newest first, each with its tag verified.
    fn load_versions(&self, conn: &Connection, name: &str) -> Result<Vec<VersionRow>> {
        query_raw_versions(conn, name)?
            .into_iter()
            .map(|r| r.into_row(&self.meta, &self.metadata_key, name))
            .collect()
    }

    fn newest_props(&self, conn: &Connection, name: &str) -> Result<SecretProperties> {
        self.load_versions(conn, name)?
            .into_iter()
            .next()
            .map(|v| v.props)
            .ok_or_else(|| SecretError::Storage(format!("secret '{name}' has no versions")))
    }

    fn deleted_from_row(
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

    /// Insert one version row together with its tag.
    fn insert_version(&self, conn: &Connection, new: &NewVersion<'_>) -> Result<()> {
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
        Ok(())
    }

    /// Write a `secrets` row's deletion state together with its tag.
    fn write_secret_state(&self, conn: &Connection, name: &str, row: &SecretRow) -> Result<()> {
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
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Free helpers over a connection
// ---------------------------------------------------------------------------

/// Ask `unlock` for a passphrase up to [`MAX_UNLOCK_ATTEMPTS`] times and try
/// it against every passphrase protector (at most
/// [`MAX_PASSPHRASE_PROTECTORS`], each within `Argon2Params::MAX`). Returns
/// the vault key and what unlocked it; otherwise `None`, with the reasons
/// appended and every rejected attempt audited.
fn try_passphrases(
    conn: &Connection,
    meta: &Meta,
    protectors: &[ProtectorRecord],
    unlock: &dyn UnlockProvider,
    unkeyed: &AuditWriter<'_>,
    reasons: &mut Vec<String>,
) -> Result<Option<(SymmetricKey, Unlocked)>> {
    let passphrase_protectors: Vec<&ProtectorRecord> = protectors
        .iter()
        .filter(|p| matches!(p.kind, ProtectorKind::Passphrase { .. }))
        .take(MAX_PASSPHRASE_PROTECTORS)
        .collect();
    if passphrase_protectors.is_empty() {
        reasons.push("no passphrase protector is installed".to_owned());
        return Ok(None);
    }
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
            return Ok(None);
        };
        for protector in &passphrase_protectors {
            let ProtectorKind::Passphrase { salt, params } = &protector.kind else {
                continue;
            };
            // Parameters come from the file: a protector asking for more
            // work than the ceiling is skipped, never run.
            if !params.within_limits() {
                reasons.push(format!(
                    "{}: Argon2 parameters exceed the supported limits",
                    protector.label
                ));
                continue;
            }
            let salt = hex::decode(salt).map_err(|_| {
                SecretError::Storage(format!("corrupt salt on protector {}", protector.id))
            })?;
            let kek = kdf::derive_key(passphrase.expose(), &salt, *params).map_err(crypto)?;
            if let Ok((dek, wrapped_schema)) = try_unwrap(meta, protector, &kek) {
                let unlocked = Unlocked {
                    protector_id: protector.id.clone(),
                    kek,
                    wrapped_schema,
                };
                return Ok(Some((dek, unlocked)));
            }
        }
        unkeyed.record(
            conn,
            AuditOperation::VaultOpen,
            None,
            None,
            AuditOutcome::Denied,
            Some("incorrect passphrase"),
        )?;
        reasons.push(format!("passphrase attempt {attempt} rejected"));
    }
    Ok(None)
}

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
fn write_settings_tag(conn: &Connection, key: &SymmetricKey, meta: &Meta) -> Result<()> {
    let tag = integrity::settings_tag(key, &meta.settings_fields()?);
    conn.execute(
        "INSERT INTO vault_meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![integrity::SETTINGS_KEY, tag],
    )
    .map_err(db)?;
    Ok(())
}

/// The OS-keyring account this vault creates for a protector.
fn keyring_account_name(vault_id: &str, protector_id: &str) -> String {
    format!("vault/{vault_id}/{protector_id}")
}

/// Alias used by [`SqliteVault::keyring_accounts`].
fn keyring_account(vault_id: &str, protector_id: &str) -> String {
    keyring_account_name(vault_id, protector_id)
}

/// Re-wrap the vault key for one protector under the current schema's AAD.
fn rewrap_protector(
    conn: &Connection,
    meta: &Meta,
    dek: &SymmetricKey,
    protector_id: &str,
    kek: &SymmetricKey,
) -> Result<()> {
    let wrapped = envelope::wrap_key(
        kek,
        dek,
        protector_aad(&meta.id, protector_id, SCHEMA_VERSION).as_bytes(),
    )
    .map_err(crypto)?;
    conn.execute(
        "UPDATE key_protectors SET wrapped_nonce = ?2, wrapped_dek = ?3 WHERE id = ?1",
        params![protector_id, wrapped.nonce.as_slice(), wrapped.bytes],
    )
    .map_err(db)?;
    Ok(())
}

/// True when any OS-keyring protector's stored key unwraps under the
/// current schema's AAD: evidence that the file was already in the current
/// format whatever its schema marker says.
fn any_keyring_protector_wrapped_current(conn: &Connection, meta: &Meta) -> Result<bool> {
    for protector in read_protectors(conn)? {
        let ProtectorKind::OsKeyring { account, .. } = &protector.kind else {
            continue;
        };
        let Ok(Some(kek)) = keystore::load_key(account) else {
            continue;
        };
        let current = envelope::unwrap_key(
            &kek,
            &protector.wrapped,
            protector_aad(&meta.id, &protector.id, SCHEMA_VERSION).as_bytes(),
        );
        if current.is_ok() {
            return Ok(true);
        }
    }
    Ok(false)
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

/// Unwrap the vault key with `kek`, trying the current schema's AAD first
/// and then the oldest supported one. Returns the key and the schema whose
/// AAD matched.
fn try_unwrap(
    meta: &Meta,
    protector: &ProtectorRecord,
    kek: &SymmetricKey,
) -> Result<(SymmetricKey, u32)> {
    let mut last = None;
    for schema in [SCHEMA_VERSION, OLDEST_SUPPORTED_SCHEMA] {
        match envelope::unwrap_key(
            kek,
            &protector.wrapped,
            protector_aad(&meta.id, &protector.id, schema).as_bytes(),
        ) {
            Ok(dek) => return Ok((dek, schema)),
            Err(err) => last = Some(err),
        }
    }
    Err(last.map_or_else(
        || SecretError::Crypto("no schema to unwrap under".to_owned()),
        crypto,
    ))
}

/// The label for a new protector: the caller's, if unique and non-empty,
/// else the kind's label, suffixed with part of the id when already taken.
fn choose_label(
    conn: &Connection,
    requested: Option<&str>,
    kind_label: &str,
    id: &str,
) -> Result<String> {
    let existing: Vec<String> = read_protectors(conn)?
        .into_iter()
        .map(|p| p.label)
        .collect();
    if let Some(custom) = requested {
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
        return Ok(custom.to_owned());
    }
    let base = kind_label.to_owned();
    Ok(if existing.contains(&base) {
        format!("{base}-{}", &id[..4])
    } else {
        base
    })
}

fn add_protector(
    conn: &Connection,
    meta: &Meta,
    dek: &SymmetricKey,
    spec: ProtectorSpec,
    label: Option<&str>,
) -> Result<ProtectorInfo> {
    let id = random::random_hex(8).map_err(crypto)?;

    // Validate everything that can fail cheaply before touching the OS
    // credential store, so a rejected label never leaves an orphan key.
    let label = choose_label(conn, label, spec.kind_label(), &id)?;

    let (kind, kek, stored_account) = match spec {
        ProtectorSpec::OsKeyring => {
            if !keystore::available() {
                return Err(SecretError::Unsupported(format!(
                    "{} is not available ({}); use a passphrase protector instead",
                    keystore::STORE_NAME,
                    keystore::unavailable_reason().unwrap_or_default()
                )));
            }
            let account = keyring_account_name(&meta.id, &id);
            let kek = SymmetricKey::generate().map_err(crypto)?;
            keystore::store_key(&account, &kek)?;
            (
                ProtectorKind::OsKeyring {
                    service: keystore::SERVICE.to_owned(),
                    account: account.clone(),
                },
                kek,
                Some(account),
            )
        }
        ProtectorSpec::Passphrase { passphrase, params } => {
            if passphrase.is_empty() {
                return Err(SecretError::InvalidArgument(
                    "passphrase must not be empty".to_owned(),
                ));
            }
            if !params.within_limits() {
                return Err(SecretError::InvalidArgument(
                    "Argon2 parameters exceed the supported limits".to_owned(),
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
                None,
            )
        }
    };

    let insert = || -> Result<()> {
        let wrapped = envelope::wrap_key(
            &kek,
            dek,
            protector_aad(&meta.id, &id, SCHEMA_VERSION).as_bytes(),
        )
        .map_err(crypto)?;
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
                nanos(timestamp::now())?
            ],
        )
        .map_err(db)?;
        Ok(())
    };
    let created_on = timestamp::now();
    if let Err(err) = insert() {
        // The database row did not land: do not leave the key behind.
        if let Some(account) = &stored_account {
            let _ = keystore::delete_key(account);
        }
        return Err(err);
    }

    Ok(ProtectorInfo {
        id,
        label,
        kind: kind.label().to_owned(),
        created_on,
    })
}

/// Every audit row with its chain columns, oldest first.
fn read_chain(conn: &Connection) -> Result<Vec<ChainRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, occurred_on, actor, operation, secret_name, version, outcome, detail,
                    prev_hash, hash, keyed
             FROM audit_events ORDER BY id",
        )
        .map_err(db)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(ChainRow {
                row: (
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ),
                prev_hash: row.get(8)?,
                hash: row.get(9)?,
                keyed: row.get::<_, i64>(10)? != 0,
            })
        })
        .map_err(db)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db)?;
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Migration
// ---------------------------------------------------------------------------

/// Bring a schema 1 vault to schema 2 in one transaction: add the integrity
/// columns, tag every secret and version row, chain every audit row with the
/// metadata key, record the migration and bump `schema_version`.
fn migrate_v1_to_v2(
    conn: &mut Connection,
    meta: &mut Meta,
    dek: &SymmetricKey,
    key: &SymmetricKey,
    actor: &Principal,
    unlocked: &Unlocked,
) -> Result<()> {
    let tx = begin_write(conn)?;
    tx.execute_batch(MIGRATE_V1_TO_V2).map_err(db)?;
    migrate_secret_tags(&tx, meta, key)?;
    migrate_version_tags(&tx, meta, key)?;
    migrate_audit_chain(&tx, meta, key)?;
    tx.execute(
        "UPDATE vault_meta SET value = ?1 WHERE key = 'schema_version'",
        params![SCHEMA_VERSION.to_string()],
    )
    .map_err(db)?;
    meta.schema = SCHEMA_VERSION;
    // Bind every key we hold to the new format: the protector that unlocked
    // us, and any OS-keyring protector whose key the store gives back. Other
    // passphrase protectors are re-wrapped the next time they unlock.
    rewrap_protector(&tx, meta, dek, &unlocked.protector_id, &unlocked.kek)?;
    for protector in read_protectors(&tx)? {
        if protector.id == unlocked.protector_id {
            continue;
        }
        let ProtectorKind::OsKeyring { account, .. } = &protector.kind else {
            continue;
        };
        if let Ok(Some(kek)) = keystore::load_key(account)
            && try_unwrap(meta, &protector, &kek).is_ok()
        {
            rewrap_protector(&tx, meta, dek, &protector.id, &kek)?;
        }
    }
    write_settings_tag(&tx, key, meta)?;
    AuditWriter {
        meta,
        key: Some(key),
        actor,
        allow_empty_chain: true,
    }
    .record(
        &tx,
        AuditOperation::VaultMigrate,
        None,
        None,
        AuditOutcome::Success,
        Some("schema 1 -> 2"),
    )?;
    tx.commit().map_err(db)
}

fn migrate_secret_tags(conn: &Connection, meta: &Meta, key: &SymmetricKey) -> Result<()> {
    let rows: Vec<(String, SecretRow)> = {
        let mut stmt = conn
            .prepare(
                "SELECT name, created_on, deleted_on, scheduled_purge_on, recovery_id FROM secrets",
            )
            .map_err(db)?;
        stmt.query_map([], |row| {
            Ok((
                row.get(0)?,
                SecretRow {
                    created_on: row.get(1)?,
                    deleted_on: row.get(2)?,
                    scheduled_purge_on: row.get(3)?,
                    recovery_id: row.get(4)?,
                },
            ))
        })
        .map_err(db)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db)?
    };
    for (name, row) in &rows {
        let tag = integrity::secret_tag(key, &row.fields(&meta.id, name));
        conn.execute(
            "UPDATE secrets SET tag = ?2 WHERE name = ?1",
            params![name, tag.as_slice()],
        )
        .map_err(db)?;
    }
    Ok(())
}

fn migrate_version_tags(conn: &Connection, meta: &Meta, key: &SymmetricKey) -> Result<()> {
    let names: Vec<String> = {
        let mut stmt = conn.prepare("SELECT name FROM secrets").map_err(db)?;
        stmt.query_map([], |row| row.get(0))
            .map_err(db)?
            .collect::<rusqlite::Result<_>>()
            .map_err(db)?
    };
    for name in &names {
        for raw in query_raw_versions(conn, name)? {
            let tag = integrity::version_tag(key, &raw.fields(&meta.id, name));
            conn.execute(
                "UPDATE secret_versions SET tag = ?3 WHERE name = ?1 AND version = ?2",
                params![name, raw.version, tag.as_slice()],
            )
            .map_err(db)?;
        }
    }
    Ok(())
}

fn migrate_audit_chain(conn: &Connection, meta: &Meta, key: &SymmetricKey) -> Result<()> {
    let mut prev = integrity::ZERO_HASH;
    let mut head: Option<(i64, [u8; MAC_LEN])> = None;
    for mut row in read_chain(conn)? {
        // Every historical row is chained under the metadata key, including
        // failed unlocks recorded by the schema 1 build.
        row.keyed = true;
        let fields = row.fields(&meta.id);
        let hash = integrity::audit_hash(key, &prev, &fields);
        conn.execute(
            "UPDATE audit_events SET prev_hash = ?2, hash = ?3, keyed = 1 WHERE id = ?1",
            params![fields.id, prev.as_slice(), hash.as_slice()],
        )
        .map_err(db)?;
        head = Some((fields.id, hash));
        prev = hash;
    }
    if let Some((id, hash)) = head {
        write_head(conn, key, &meta.id, id, &hash)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Version selection
// ---------------------------------------------------------------------------

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

        // The pre-unlock rows are unkeyed but the chain is still intact.
        let check = vault.verify_audit_chain().unwrap();
        assert!(check.is_intact(), "{check:?}");
        assert_eq!(check.unkeyed, 2, "one denied attempt and one failure row");
        assert_eq!(check.rows, check.keyed + check.unkeyed);
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

    #[test]
    fn failed_operations_keep_their_audit_row() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dev.sorvault");
        let vault =
            SqliteVault::create(&path, "dev", CreateVaultOptions::default(), spec()).unwrap();
        assert_eq!(
            vault.recover_deleted_secret("missing").unwrap_err().code(),
            "not_found"
        );
        assert_eq!(
            vault
                .update_secret_properties(
                    "missing",
                    None,
                    UpdateSecretProperties {
                        enabled: Some(false),
                        ..Default::default()
                    },
                )
                .unwrap_err()
                .code(),
            "not_found"
        );
        let events = vault.audit_events(AuditQuery::default()).unwrap();
        let failures: Vec<_> = events
            .iter()
            .filter(|e| e.outcome == AuditOutcome::Failure)
            .map(|e| e.operation)
            .collect();
        assert!(failures.contains(&AuditOperation::SecretRecover));
        assert!(failures.contains(&AuditOperation::SecretUpdate));
        assert!(vault.verify_audit_chain().unwrap().is_intact());
    }
}
