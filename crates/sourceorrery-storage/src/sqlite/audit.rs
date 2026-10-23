//! The audit chain: appending rows under the metadata key, the head record
//! that pins the newest keyed row, verification, and the completion helpers
//! that every vault operation ends with.

use std::collections::BTreeMap;

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sourceorrery_core::audit::{AuditEvent, AuditOperation, AuditOutcome};
use sourceorrery_core::{Principal, Result, SecretError, timestamp, validate_secret_name};
use sourceorrery_crypto::{MAC_LEN, SymmetricKey};

use super::schema::{Meta, begin_write, db, from_nanos, nanos};
use super::{Acknowledgement, SqliteVault};
use crate::integrity::{self, AuditFields, AuditVerification, Checkpoint};

/// Detail prefix of the keyed `audit_verify` / `success` row that records
/// the owner's acknowledgement of every truncation detected before it.
pub(super) const ACKNOWLEDGED_DETAIL: &str = "truncation acknowledged";

/// `(id, occurred_on, actor, operation, secret_name, version, outcome, detail)`
pub(super) type AuditRow = (
    i64,
    i64,
    String,
    String,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
);

/// An audit row plus its chain and checkpoint columns.
pub(super) struct ChainRow {
    pub(super) row: AuditRow,
    pub(super) prev_hash: Option<Vec<u8>>,
    pub(super) hash: Option<Vec<u8>>,
    pub(super) keyed: bool,
    pub(super) state_tag: Option<Vec<u8>>,
    pub(super) version_tag: Option<Vec<u8>>,
}

impl ChainRow {
    pub(super) fn fields<'a>(&'a self, vault_id: &'a str) -> AuditFields<'a> {
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
            state_tag: self.state_tag.as_deref(),
            version_tag: self.version_tag.as_deref(),
        }
    }

    /// True when `hash` is this row's chain hash under `key`.
    fn authentic(&self, key: &SymmetricKey, vault_id: &str) -> bool {
        let prev = integrity::hash_or_zero(self.prev_hash.as_deref());
        integrity::verify_audit_hash(key, &prev, &self.fields(vault_id), self.hash.as_deref())
    }

    fn id(&self) -> i64 {
        self.row.0
    }

    /// True for the row that acknowledges every truncation detected before
    /// it (see [`ACKNOWLEDGED_DETAIL`]).
    fn is_acknowledgement(&self) -> bool {
        self.row.3 == AuditOperation::AuditVerify.as_str()
            && self.row.6 == AuditOutcome::Success.as_str()
            && self
                .row
                .7
                .as_deref()
                .is_some_and(|detail| detail.starts_with(ACKNOWLEDGED_DETAIL))
    }

    /// True for the row that records a detected truncation.
    fn is_truncation(&self) -> bool {
        self.row.3 == AuditOperation::AuditVerify.as_str()
            && self.row.6 == AuditOutcome::Failure.as_str()
    }
}

/// The public form of an audit row.
pub(super) fn event_from_row(row: AuditRow) -> Result<AuditEvent> {
    let (id, occurred_on, actor, operation, secret_name, version, outcome, detail) = row;
    Ok(AuditEvent {
        id: u64::try_from(id).unwrap_or_default(),
        occurred_on: from_nanos(occurred_on)?,
        actor: Principal::parse(&actor)
            .unwrap_or_else(|| Principal::new(sourceorrery_core::PrincipalKind::User, actor)),
        operation: operation.parse().map_err(SecretError::Storage)?,
        secret_name,
        version,
        outcome: outcome.parse().map_err(SecretError::Storage)?,
        detail,
    })
}

/// The row checkpoints a success event carries (see `integrity`).
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Checkpoints {
    /// State of the `secrets` row the event names.
    pub(super) state: Option<Checkpoint>,
    /// State of the `secret_versions` row the event names.
    pub(super) version: Option<Checkpoint>,
}

/// One audit event to append.
#[derive(Clone, Copy, Debug)]
pub(super) struct Entry<'a> {
    pub(super) operation: AuditOperation,
    pub(super) secret_name: Option<&'a str>,
    pub(super) version: Option<&'a str>,
    pub(super) outcome: AuditOutcome,
    pub(super) detail: Option<&'a str>,
    pub(super) checkpoints: Checkpoints,
}

/// Appends rows to the audit chain.
///
/// `key` is `None` only before the vault is unlocked; rows written then are
/// chained with the all-zero key and flagged unkeyed.
pub(super) struct AuditWriter<'a> {
    pub(super) meta: &'a Meta,
    pub(super) key: Option<&'a SymmetricKey>,
    pub(super) actor: &'a Principal,
    /// Accept a log with no rows and no head record. True only while a vault
    /// is being created or migrated; for an existing vault that state means
    /// the whole history and its head were removed.
    pub(super) allow_empty_chain: bool,
}

impl AuditWriter<'_> {
    /// Append one row without checkpoints. Runs in the caller's transaction
    /// when there is one, otherwise in its own immediate transaction so the
    /// read-then-append on the chain head is atomic across processes.
    pub(super) fn record(
        &self,
        conn: &Connection,
        operation: AuditOperation,
        secret_name: Option<&str>,
        version: Option<&str>,
        outcome: AuditOutcome,
        detail: Option<&str>,
    ) -> Result<()> {
        self.record_entry(
            conn,
            &Entry {
                operation,
                secret_name,
                version,
                outcome,
                detail,
                checkpoints: Checkpoints::default(),
            },
        )
    }

    /// Append one row. As [`AuditWriter::record`].
    pub(super) fn record_entry(&self, conn: &Connection, entry: &Entry<'_>) -> Result<()> {
        if self.meta.schema < 2 {
            // Pre-migration rows (failed unlocks of a schema 1 vault): the
            // chain columns do not exist yet; the migration chains them.
            return record_legacy(conn, self.actor, entry);
        }
        let own_tx = conn.is_autocommit();
        if own_tx {
            conn.execute_batch("BEGIN IMMEDIATE").map_err(db)?;
        }
        let result = self.append(conn, entry);
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
    pub(super) fn append(&self, conn: &Connection, entry: &Entry<'_>) -> Result<()> {
        if let Some(key) = self.key
            && let Some(problem) = head_problem(conn, key, &self.meta.id, self.allow_empty_chain)?
        {
            self.append_row(
                conn,
                &Entry {
                    operation: AuditOperation::AuditVerify,
                    secret_name: None,
                    version: None,
                    outcome: AuditOutcome::Failure,
                    detail: Some(&problem),
                    checkpoints: Checkpoints::default(),
                },
            )?;
        }
        self.append_row(conn, entry)
    }

    pub(super) fn append_row(&self, conn: &Connection, entry: &Entry<'_>) -> Result<()> {
        let occurred_on = nanos(timestamp::now())?;
        let actor = self.actor.to_string();
        let prev = last_hash(conn)?;
        let keyed = self.key.is_some();
        let state_tag = entry.checkpoints.state.as_ref().map(Checkpoint::as_blob);
        let version_tag = entry.checkpoints.version.as_ref().map(Checkpoint::as_blob);
        if self.meta.schema >= 3 {
            conn.execute(
                "INSERT INTO audit_events
                    (occurred_on, actor, operation, secret_name, version, outcome, detail,
                     prev_hash, keyed, state_tag, version_tag)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    occurred_on,
                    actor,
                    entry.operation.as_str(),
                    entry.secret_name,
                    entry.version,
                    entry.outcome.as_str(),
                    entry.detail,
                    prev.as_slice(),
                    i64::from(keyed),
                    state_tag,
                    version_tag,
                ],
            )
            .map_err(db)?;
        } else {
            // A schema 2 file before its migration (a refused unlock, or a
            // refused migration): it has no checkpoint columns yet and no
            // checkpoint is ever recorded in it. The migration re-chains
            // these rows under the current encoding.
            debug_assert!(state_tag.is_none() && version_tag.is_none());
            conn.execute(
                "INSERT INTO audit_events
                    (occurred_on, actor, operation, secret_name, version, outcome, detail,
                     prev_hash, keyed)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    occurred_on,
                    actor,
                    entry.operation.as_str(),
                    entry.secret_name,
                    entry.version,
                    entry.outcome.as_str(),
                    entry.detail,
                    prev.as_slice(),
                    i64::from(keyed),
                ],
            )
            .map_err(db)?;
        }
        let id = conn.last_insert_rowid();
        let fields = AuditFields {
            vault_id: &self.meta.id,
            id,
            occurred_on,
            actor: &actor,
            operation: entry.operation.as_str(),
            secret_name: entry.secret_name,
            version: entry.version,
            outcome: entry.outcome.as_str(),
            detail: entry.detail,
            keyed,
            state_tag,
            version_tag,
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
pub(super) fn record_legacy(conn: &Connection, actor: &Principal, entry: &Entry<'_>) -> Result<()> {
    conn.execute(
        "INSERT INTO audit_events (occurred_on, actor, operation, secret_name, version, outcome, detail)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            nanos(timestamp::now())?,
            actor.to_string(),
            entry.operation.as_str(),
            entry.secret_name,
            entry.version,
            entry.outcome.as_str(),
            entry.detail
        ],
    )
    .map_err(db)?;
    Ok(())
}

/// Chain hash of the newest audit row, or zeros for an empty log.
pub(super) fn last_hash(conn: &Connection) -> Result<[u8; MAC_LEN]> {
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

pub(super) fn write_head(
    conn: &Connection,
    key: &SymmetricKey,
    vault_id: &str,
    id: i64,
    hash: &[u8; MAC_LEN],
) -> Result<()> {
    let keyed = keyed_count(conn)?;
    conn.execute(
        "INSERT INTO vault_meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![
            integrity::AUDIT_HEAD_KEY,
            integrity::head_value(key, vault_id, id, hash, keyed)
        ],
    )
    .map_err(db)?;
    Ok(())
}

/// Rows flagged as written with the metadata key.
pub(super) fn keyed_count(conn: &Connection) -> Result<u64> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM audit_events WHERE keyed = 1",
            [],
            |row| row.get(0),
        )
        .map_err(db)?;
    Ok(u64::try_from(count).unwrap_or_default())
}

/// Walk the chain from the newest acknowledgement (history before it was
/// reviewed and accepted by the vault's owner) to the end, checking that
/// every row links to the row before it and that its hash verifies. `None`
/// when the chain holds; otherwise a short, value-free description naming
/// the first row that does not, suitable as audit detail.
///
/// This is the check the head alone cannot make: the head names the newest
/// keyed row and counts the keyed rows, which catches rows removed from the
/// end and keyed rows removed from the middle, but not a row replaced by a
/// forgery between two others. Run at unlock, once, over the rows that
/// matter; every operation after that relies on the head.
pub(super) fn chain_problem(
    conn: &Connection,
    key: &SymmetricKey,
    vault_id: &str,
) -> Result<Option<String>> {
    // The newest authentic acknowledgement, if any: the walk starts after it.
    let mut acks = conn
        .prepare(&format!(
            "SELECT {CHAIN_COLUMNS} FROM audit_events
             WHERE operation = '{}' AND outcome = '{}' AND keyed = 1
             ORDER BY id DESC",
            AuditOperation::AuditVerify.as_str(),
            AuditOutcome::Success.as_str()
        ))
        .map_err(db)?;
    let mut start: Option<(i64, [u8; MAC_LEN])> = None;
    for row in acks.query_map([], chain_row).map_err(db)? {
        let row = row.map_err(db)?;
        if row.is_acknowledgement() && row.authentic(key, vault_id) {
            start = Some((row.id(), integrity::hash_or_zero(row.hash.as_deref())));
            break;
        }
    }
    let (after, mut prev) = start.unwrap_or((0, integrity::ZERO_HASH));
    let zero = integrity::zero_key();
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {CHAIN_COLUMNS} FROM audit_events WHERE id > ?1 ORDER BY id"
        ))
        .map_err(db)?;
    for row in stmt.query_map(params![after], chain_row).map_err(db)? {
        let row = row.map_err(db)?;
        let row_key = if row.keyed { key } else { &zero };
        let fields = row.fields(vault_id);
        let linked = row.prev_hash.as_deref() == Some(prev.as_slice());
        let authentic = integrity::verify_audit_hash(row_key, &prev, &fields, row.hash.as_deref());
        if !(linked && authentic) {
            return Ok(Some(format!(
                "audit chain broken at event {}: {}",
                row.id(),
                if linked {
                    "its hash does not verify"
                } else {
                    "it does not follow the row before it (a row was removed or replaced)"
                }
            )));
        }
        prev = integrity::hash_or_zero(row.hash.as_deref());
    }
    Ok(None)
}

pub(super) fn read_head(conn: &Connection) -> Result<Option<String>> {
    conn.query_row(
        "SELECT value FROM vault_meta WHERE key = ?1",
        params![integrity::AUDIT_HEAD_KEY],
        |row| row.get(0),
    )
    .optional()
    .map_err(db)
}

/// `(id, hash)` of the newest row written with the metadata key.
pub(super) fn last_keyed_row(conn: &Connection) -> Result<Option<(i64, Vec<u8>)>> {
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

/// The error for an operation refused because the chain head is stale.
pub(super) fn truncated_message(problem: &str) -> String {
    format!(
        "audit log integrity: {problem}. The state recorded by the missing events cannot be \
         verified, so this operation was refused. The detection is now on record and the vault \
         stays blocked until the surviving history has been reviewed (`sourceorrery audit \
         --verify`) and the truncation acknowledged (`sourceorrery audit --acknowledge`)"
    )
}

/// The error for an operation refused because a detected truncation has not
/// been acknowledged. `pending` is what [`unacknowledged_truncations`]
/// returned; it names events only, never values.
pub(super) fn quarantined_message(pending: &[ChainRow]) -> String {
    let found = match pending {
        [one] => format!(
            "the truncation detected at event {} ({}) is unacknowledged",
            one.id(),
            one.row.7.as_deref().unwrap_or("no detail")
        ),
        many => format!(
            "{} truncations are unacknowledged (events {})",
            many.len(),
            event_id_list(many.iter().map(ChainRow::id))
        ),
    };
    format!(
        "audit log integrity: {found}; the vault is blocked until the surviving history has \
         been reviewed and the truncation acknowledged (`sourceorrery audit --acknowledge`)"
    )
}

fn event_id_list(ids: impl Iterator<Item = i64>) -> String {
    ids.map(|id| id.to_string()).collect::<Vec<_>>().join(", ")
}

/// Detail of the acknowledgement row covering `ids`.
fn acknowledgement_detail(ids: &[i64]) -> String {
    let noun = if ids.len() == 1 { "event" } else { "events" };
    format!(
        "{ACKNOWLEDGED_DETAIL} ({noun} {})",
        event_id_list(ids.iter().copied())
    )
}

/// Detected truncations nobody has acknowledged: the keyed `audit_verify` /
/// `failure` rows written after the newest keyed `audit_verify` / `success`
/// acknowledgement, oldest first. Only rows whose chain hash verifies under
/// `key` count either way, since a row flagged keyed that does not verify
/// was not written by this vault; `audit --verify` reports such rows as
/// broken.
pub(super) fn unacknowledged_truncations(
    conn: &Connection,
    key: &SymmetricKey,
    vault_id: &str,
) -> Result<Vec<ChainRow>> {
    // The operation is a literal so the partial index `audit_verifications`
    // applies; it is a fixed label, not input.
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {CHAIN_COLUMNS} FROM audit_events
             WHERE operation = '{}' AND keyed = 1
             ORDER BY id",
            AuditOperation::AuditVerify.as_str()
        ))
        .map_err(db)?;
    let rows: Vec<ChainRow> = stmt
        .query_map([], chain_row)
        .map_err(db)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db)?;
    let mut pending = Vec::new();
    for row in rows {
        if !row.authentic(key, vault_id) {
            continue;
        }
        if row.is_acknowledgement() {
            pending.clear();
        } else if row.is_truncation() {
            pending.push(row);
        }
    }
    Ok(pending)
}

/// Compare the recorded chain head with the newest keyed row. `None` when
/// they agree; otherwise a short, value-free description of the problem,
/// suitable as audit detail.
pub(super) fn head_problem(
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
            let keyed = keyed_count(conn)?;
            if integrity::head_matches(key, vault_id, &head, id, &hash, keyed) {
                None
            } else {
                Some(match integrity::parse_head(&head) {
                    Some(record) if record.id > id => {
                        format!(
                            "rows removed after event {id} (head was event {})",
                            record.id
                        )
                    }
                    Some(record) if record.id == id && record.keyed.is_some_and(|n| n != keyed) => {
                        format!(
                            "keyed audit rows removed or altered inside the log (the head records \
                             {}, {keyed} remain)",
                            record.keyed.unwrap_or_default()
                        )
                    }
                    Some(record) => {
                        format!("audit chain head stale (head was event {})", record.id)
                    }
                    None => "audit chain head invalid".to_owned(),
                })
            }
        }
    })
}

const CHAIN_COLUMNS: &str =
    "id, occurred_on, actor, operation, secret_name, version, outcome, detail,
                             prev_hash, hash, keyed, state_tag, version_tag";

fn chain_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChainRow> {
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
        state_tag: row.get(11)?,
        version_tag: row.get(12)?,
    })
}

/// Every audit row with its chain columns, oldest first.
pub(super) fn read_chain(conn: &Connection) -> Result<Vec<ChainRow>> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {CHAIN_COLUMNS} FROM audit_events ORDER BY id"
        ))
        .map_err(db)?;
    let rows = stmt
        .query_map([], chain_row)
        .map_err(db)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db)?;
    Ok(rows)
}

/// What the keyed audit chain records as the current state of one secret:
/// the newest checkpoint of its `secrets` row, and the checkpoint of each of
/// its versions since the row was last recorded absent (versions of an
/// earlier, purged secret of the same name do not count).
#[derive(Debug, Default)]
pub(super) struct SecretCheckpoints {
    pub(super) state: Option<Checkpoint>,
    pub(super) versions: BTreeMap<String, Checkpoint>,
}

/// Checkpoint rows for `name`, every one authenticated under `key`: an
/// attacker who can write the file can append rows flagged keyed, so a
/// checkpoint counts only if its chain hash verifies, and a checkpoint row
/// that does not verify is an error rather than skipped, since skipping it
/// would promote an older checkpoint to newest.
fn read_checkpoints(
    conn: &Connection,
    key: &SymmetricKey,
    vault_id: &str,
    name: &str,
) -> Result<Vec<ChainRow>> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {CHAIN_COLUMNS} FROM audit_events
             WHERE secret_name = ?1 AND keyed = 1
               AND (state_tag IS NOT NULL OR version_tag IS NOT NULL)
             ORDER BY id"
        ))
        .map_err(db)?;
    let rows: Vec<ChainRow> = stmt
        .query_map(params![name], chain_row)
        .map_err(db)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db)?;
    for row in &rows {
        if !row.authentic(key, vault_id) {
            return Err(SecretError::Crypto(format!(
                "audit checkpoint for {name} does not verify (event {})",
                row.row.0
            )));
        }
    }
    Ok(rows)
}

fn decode_checkpoint(blob: Option<&[u8]>, name: &str, id: i64) -> Result<Option<Checkpoint>> {
    blob.map(|blob| {
        Checkpoint::from_blob(blob).ok_or_else(|| {
            SecretError::Crypto(format!(
                "audit checkpoint for {name} is malformed (event {id})"
            ))
        })
    })
    .transpose()
}

impl SecretCheckpoints {
    /// True when the newest state checkpoint says the `secrets` row exists.
    pub(super) fn is_present(&self) -> bool {
        matches!(self.state, Some(Checkpoint::Present(_)))
    }

    /// Apply one authenticated checkpoint row, in chain order.
    fn fold(&mut self, row: &ChainRow, name: &str) -> Result<()> {
        let id = row.row.0;
        if let Some(state) = decode_checkpoint(row.state_tag.as_deref(), name, id)? {
            if state == Checkpoint::Absent {
                // The secret was removed: whatever versions it had are gone
                // with it, and a later secret of the same name starts afresh.
                self.versions.clear();
            }
            self.state = Some(state);
        }
        if let Some(version) = decode_checkpoint(row.version_tag.as_deref(), name, id)? {
            let Some(version_id) = row.row.5.clone() else {
                return Err(SecretError::Crypto(format!(
                    "audit checkpoint for {name} names no version (event {id})"
                )));
            };
            self.versions.insert(version_id, version);
        }
        Ok(())
    }
}

/// The chain's current state for `name`. See [`SecretCheckpoints`].
pub(super) fn secret_checkpoints(
    conn: &Connection,
    key: &SymmetricKey,
    vault_id: &str,
    name: &str,
) -> Result<SecretCheckpoints> {
    let mut out = SecretCheckpoints::default();
    for row in read_checkpoints(conn, key, vault_id, name)? {
        out.fold(&row, name)?;
    }
    Ok(out)
}

/// The chain's current state for every secret it records, from one scan of
/// the checkpoint rows: each row is authenticated once and folded into its
/// name's [`SecretCheckpoints`] under the rules of [`secret_checkpoints`].
/// Listings use this so that their cost does not grow with one chain scan
/// per secret; a name whose newest state checkpoint says the row exists is
/// in the map even when the `secrets` table no longer has the row, so a
/// row removed out of band is still looked for and refused.
pub(super) fn vault_checkpoints(
    conn: &Connection,
    key: &SymmetricKey,
    vault_id: &str,
) -> Result<BTreeMap<String, SecretCheckpoints>> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {CHAIN_COLUMNS} FROM audit_events
             WHERE secret_name IS NOT NULL AND keyed = 1
               AND (state_tag IS NOT NULL OR version_tag IS NOT NULL)
             ORDER BY id"
        ))
        .map_err(db)?;
    let rows: Vec<ChainRow> = stmt
        .query_map([], chain_row)
        .map_err(db)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db)?;
    let mut out: BTreeMap<String, SecretCheckpoints> = BTreeMap::new();
    for row in rows {
        let name = row.row.4.clone().unwrap_or_default();
        if !row.authentic(key, vault_id) {
            return Err(SecretError::Crypto(format!(
                "audit checkpoint for {name} does not verify (event {})",
                row.row.0
            )));
        }
        out.entry(name.clone()).or_default().fold(&row, &name)?;
    }
    Ok(out)
}

impl SqliteVault {
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
            unacknowledged: 0,
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
            if row.keyed && authentic {
                if row.is_truncation() {
                    out.truncations += 1;
                    out.unacknowledged += 1;
                } else if row.is_acknowledgement() {
                    out.unacknowledged = 0;
                }
            }
            prev = integrity::hash_or_zero(row.hash.as_deref());
        }
        Ok(out)
    }

    /// Detected truncations of the audit log that nobody has acknowledged,
    /// oldest first: the keyed `audit_verify` / `failure` events written
    /// after the newest acknowledgement. While any exist the vault is
    /// blocked (every unlock and operation is refused with `crypto`) until
    /// [`SqliteVault::acknowledge_truncations`] has run. Read-only.
    pub fn unacknowledged_truncations(&self) -> Result<Vec<AuditEvent>> {
        let conn = self.lock()?;
        unacknowledged_truncations(&conn, &self.metadata_key, &self.meta.id)?
            .into_iter()
            .map(|row| event_from_row(row.row))
            .collect()
    }

    /// Acknowledge every detected truncation and lift the block on the
    /// vault.
    ///
    /// `event_ids` must be exactly the ids
    /// [`SqliteVault::unacknowledged_truncations`] returned to the caller.
    /// The acknowledgement covers every truncation detected before it, so a
    /// truncation another process detected in the meantime must not be
    /// acknowledged unseen: a mismatch is refused with `invalid_argument` and
    /// nothing is written. So is an acknowledgement with nothing to
    /// acknowledge. If the chain head is stale at this moment (rows went
    /// missing since the vault was unlocked) the new truncation is recorded
    /// and the call is refused with `crypto`, exactly as any other write
    /// would be.
    ///
    /// On success one keyed `audit_verify` / `success` row is appended whose
    /// detail is `truncation acknowledged (events …)`: the record that the
    /// owner reviewed the surviving history and accepted it as
    /// authoritative. The truncation events themselves stay on the chain
    /// and in [`AuditVerification::truncations`].
    pub fn acknowledge_truncations(&self, event_ids: &[u64]) -> Result<Acknowledgement> {
        let mut conn = self.lock()?;
        let tx = begin_write(&mut conn)?;
        if let Some(problem) = head_problem(&tx, &self.metadata_key, &self.meta.id, false)? {
            // Put the detection on the chain, as any keyed write would, and
            // refuse: what is acknowledged must be what was shown.
            self.writer().append_row(
                &tx,
                &Entry {
                    operation: AuditOperation::AuditVerify,
                    secret_name: None,
                    version: None,
                    outcome: AuditOutcome::Failure,
                    detail: Some(&problem),
                    checkpoints: Checkpoints::default(),
                },
            )?;
            tx.commit().map_err(db)?;
            return Err(SecretError::Crypto(truncated_message(&problem)));
        }
        let pending = unacknowledged_truncations(&tx, &self.metadata_key, &self.meta.id)?;
        if pending.is_empty() {
            return Err(SecretError::InvalidArgument(
                "no detected truncation is waiting to be acknowledged".to_owned(),
            ));
        }
        let ids: Vec<i64> = pending.iter().map(ChainRow::id).collect();
        let mut expected: Vec<i64> = event_ids
            .iter()
            .map(|id| i64::try_from(*id).unwrap_or(-1))
            .collect();
        expected.sort_unstable();
        expected.dedup();
        if expected != ids {
            return Err(SecretError::InvalidArgument(format!(
                "the unacknowledged truncations are events {}; list them again before \
                 acknowledging",
                event_id_list(ids.iter().copied())
            )));
        }
        let detail = acknowledgement_detail(&ids);
        self.writer().record(
            &tx,
            AuditOperation::AuditVerify,
            None,
            None,
            AuditOutcome::Success,
            Some(&detail),
        )?;
        let event_id = u64::try_from(tx.last_insert_rowid()).unwrap_or_default();
        tx.commit().map_err(db)?;
        Ok(Acknowledgement {
            event_id,
            truncations: pending
                .into_iter()
                .map(|row| event_from_row(row.row))
                .collect::<Result<_>>()?,
        })
    }

    /// Purge soft-deleted secrets whose retention has elapsed.
    pub(super) fn purge_expired_deletions(&self) -> Result<usize> {
        let mut conn = self.lock()?;
        // Runs right after the `vault_open` row, which has already checked
        // and, if need be, re-anchored the chain head.
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
            writer.record_entry(
                &tx,
                &Entry {
                    operation: AuditOperation::SecretPurge,
                    secret_name: Some(name),
                    version: None,
                    outcome: AuditOutcome::Success,
                    detail: Some("retention elapsed"),
                    checkpoints: Checkpoints {
                        state: Some(Checkpoint::Absent),
                        version: None,
                    },
                },
            )?;
            purged += 1;
        }
        tx.commit().map_err(db)?;
        Ok(purged)
    }

    pub(super) fn writer(&self) -> AuditWriter<'_> {
        AuditWriter {
            meta: &self.meta,
            key: Some(&self.metadata_key),
            actor: &self.actor,
            allow_empty_chain: false,
        }
    }

    /// Start an operation: take the write lock, make sure the audit chain's
    /// head still names its newest keyed row, and that no detected
    /// truncation is waiting to be acknowledged.
    ///
    /// Row state is judged against the newest checkpoint in the chain, so a
    /// log whose tail was removed must not be consulted: it would present an
    /// older checkpoint as current. The operation is refused and audited as
    /// a failure; recording it puts the detection itself on the chain (an
    /// `audit_verify` / `failure` row) and re-anchors the head. From then on
    /// every operation is refused the same way, until the owner has
    /// reviewed the surviving history and acknowledged the truncation
    /// ([`SqliteVault::acknowledge_truncations`]); a handle opened for
    /// inspection is bound by this too.
    pub(super) fn begin<'c>(
        &self,
        conn: &'c mut Connection,
        operation: AuditOperation,
    ) -> Result<Transaction<'c>> {
        let tx = begin_write(conn)?;
        if let Some(problem) = head_problem(&tx, &self.metadata_key, &self.meta.id, false)? {
            return self.fail(
                tx,
                operation,
                None,
                None,
                SecretError::Crypto(truncated_message(&problem)),
            );
        }
        let pending = unacknowledged_truncations(&tx, &self.metadata_key, &self.meta.id)?;
        if pending.is_empty() {
            Ok(tx)
        } else {
            self.fail(
                tx,
                operation,
                None,
                None,
                SecretError::Crypto(quarantined_message(&pending)),
            )
        }
    }

    /// The current state of `name` according to the keyed audit chain.
    pub(super) fn checkpoints(&self, conn: &Connection, name: &str) -> Result<SecretCheckpoints> {
        secret_checkpoints(conn, &self.metadata_key, &self.meta.id, name)
    }

    /// Record a successful change to `name`, with the state the changed
    /// rows now have.
    pub(super) fn audit_change(
        &self,
        conn: &Connection,
        operation: AuditOperation,
        name: &str,
        version: Option<&str>,
        detail: Option<&str>,
        checkpoints: Checkpoints,
    ) -> Result<()> {
        self.writer().record_entry(
            conn,
            &Entry {
                operation,
                secret_name: Some(name),
                version,
                outcome: AuditOutcome::Success,
                detail,
                checkpoints,
            },
        )
    }

    /// Validate a secret name inside an operation so that a rejected name is
    /// still an audited failure. The name itself is not recorded: an invalid
    /// name is arbitrary input and could be a value pasted by mistake.
    pub(super) fn validated<'c>(
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

    pub(super) fn audit(
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
    pub(super) fn fail<T>(
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
    pub(super) fn finish_read<T>(
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
}
