//! The explicit schema 1 → 2 migration: adds the integrity columns, tags
//! every row, chains the audit log, authenticates the settings and re-wraps
//! every key it holds under the new format, in one transaction.

use rusqlite::{Connection, params};
use sourceorrery_core::audit::{AuditOperation, AuditOutcome};
use sourceorrery_core::{Principal, Result};
use sourceorrery_crypto::{MAC_LEN, SymmetricKey};

use super::SCHEMA_VERSION;
use super::audit::{AuditWriter, read_chain, write_head};
use super::protectors::{Unlocked, read_protectors, rewrap_protector, try_unwrap};
use super::rows::{SecretRow, query_raw_versions};
use super::schema::{MIGRATE_V1_TO_V2, Meta, begin_write, db, write_settings_tag};
use crate::integrity;
use crate::keystore;
use crate::protector::ProtectorKind;

/// Bring a schema 1 vault to schema 2 in one transaction: add the integrity
/// columns, tag every secret and version row, chain every audit row with the
/// metadata key, record the migration and bump `schema_version`.
pub(super) fn migrate_v1_to_v2(
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

pub(super) fn migrate_secret_tags(
    conn: &Connection,
    meta: &Meta,
    key: &SymmetricKey,
) -> Result<()> {
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

pub(super) fn migrate_version_tags(
    conn: &Connection,
    meta: &Meta,
    key: &SymmetricKey,
) -> Result<()> {
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

pub(super) fn migrate_audit_chain(
    conn: &Connection,
    meta: &Meta,
    key: &SymmetricKey,
) -> Result<()> {
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
