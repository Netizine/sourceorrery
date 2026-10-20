//! The audit chain: appending rows under the metadata key, the head record
//! that pins the newest keyed row, verification, and the completion helpers
//! that every vault operation ends with.

use std::collections::BTreeMap;

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sourceorrery_core::audit::{AuditOperation, AuditOutcome};
use sourceorrery_core::{Principal, Result, SecretError, timestamp, validate_secret_name};
use sourceorrery_crypto::{MAC_LEN, SymmetricKey};

use super::SqliteVault;
use super::schema::{Meta, begin_write, db, nanos};
use crate::integrity::{self, AuditFields, AuditVerification, Checkpoint};

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
         verified, so this operation was refused; the detection is now on record \
         (`sourceorrery audit --verify`) and later operations proceed on the surviving history"
    )
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

/// The chain's current state for `name`. See [`SecretCheckpoints`].
pub(super) fn secret_checkpoints(
    conn: &Connection,
    key: &SymmetricKey,
    vault_id: &str,
    name: &str,
) -> Result<SecretCheckpoints> {
    let mut out = SecretCheckpoints::default();
    for row in read_checkpoints(conn, key, vault_id, name)? {
        let id = row.row.0;
        if let Some(state) = decode_checkpoint(row.state_tag.as_deref(), name, id)? {
            if state == Checkpoint::Absent {
                // The secret was removed: whatever versions it had are gone
                // with it, and a later secret of the same name starts afresh.
                out.versions.clear();
            }
            out.state = Some(state);
        }
        if let Some(version) = decode_checkpoint(row.version_tag.as_deref(), name, id)? {
            let Some(version_id) = row.row.5.clone() else {
                return Err(SecretError::Crypto(format!(
                    "audit checkpoint for {name} names no version (event {id})"
                )));
            };
            out.versions.insert(version_id, version);
        }
    }
    Ok(out)
}

/// Names whose newest keyed state checkpoint says the secret exists, so a
/// `secrets` row removed out of band is still looked for. Checkpoint rows
/// are authenticated as in [`secret_checkpoints`].
pub(super) fn checkpointed_names(
    conn: &Connection,
    key: &SymmetricKey,
    vault_id: &str,
) -> Result<Vec<String>> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {CHAIN_COLUMNS} FROM audit_events
             WHERE secret_name IS NOT NULL AND keyed = 1 AND state_tag IS NOT NULL
             ORDER BY id"
        ))
        .map_err(db)?;
    let rows: Vec<ChainRow> = stmt
        .query_map([], chain_row)
        .map_err(db)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db)?;
    let mut newest: BTreeMap<String, bool> = BTreeMap::new();
    for row in rows {
        let name = row.row.4.clone().unwrap_or_default();
        if !row.authentic(key, vault_id) {
            return Err(SecretError::Crypto(format!(
                "audit checkpoint for {name} does not verify (event {})",
                row.row.0
            )));
        }
        let present = !row.state_tag.as_deref().is_some_and(<[u8]>::is_empty);
        newest.insert(name, present);
    }
    Ok(newest
        .into_iter()
        .filter_map(|(name, present)| present.then_some(name))
        .collect())
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

    /// Start an operation: take the write lock and make sure the audit
    /// chain's head still names its newest keyed row.
    ///
    /// Row state is judged against the newest checkpoint in the chain, so a
    /// log whose tail was removed must not be consulted: it would present an
    /// older checkpoint as current. The operation is refused and audited as
    /// a failure; recording it puts the detection itself on the chain (an
    /// `audit_verify` / `failure` row) and re-anchors the head, so later
    /// operations proceed on the surviving history.
    pub(super) fn begin<'c>(
        &self,
        conn: &'c mut Connection,
        operation: AuditOperation,
    ) -> Result<Transaction<'c>> {
        let tx = begin_write(conn)?;
        match head_problem(&tx, &self.metadata_key, &self.meta.id, false)? {
            None => Ok(tx),
            Some(problem) => self.fail(
                tx,
                operation,
                None,
                None,
                SecretError::Crypto(truncated_message(&problem)),
            ),
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
