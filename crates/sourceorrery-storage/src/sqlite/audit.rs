//! The audit chain: appending rows under the metadata key, the head record
//! that pins the newest keyed row, verification, and the completion helpers
//! that every vault operation ends with.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sourceorrery_core::audit::{AuditOperation, AuditOutcome};
use sourceorrery_core::{Principal, Result, SecretError, timestamp, validate_secret_name};
use sourceorrery_crypto::{MAC_LEN, SymmetricKey};

use super::SqliteVault;
use super::schema::{Meta, begin_write, db, nanos};
use crate::integrity::{self, AuditFields, AuditVerification};

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

/// An audit row plus its chain columns.
pub(super) struct ChainRow {
    pub(super) row: AuditRow,
    pub(super) prev_hash: Option<Vec<u8>>,
    pub(super) hash: Option<Vec<u8>>,
    pub(super) keyed: bool,
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
        }
    }
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
    /// Append one row. Runs in the caller's transaction when there is one,
    /// otherwise in its own immediate transaction so the read-then-append
    /// on the chain head is atomic across processes.
    pub(super) fn record(
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
    pub(super) fn append(
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

    pub(super) fn append_row(
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
pub(super) fn record_legacy(
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

/// Every audit row with its chain columns, oldest first.
pub(super) fn read_chain(conn: &Connection) -> Result<Vec<ChainRow>> {
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

    pub(super) fn writer(&self) -> AuditWriter<'_> {
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
