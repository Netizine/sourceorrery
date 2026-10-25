//! The vault's catalog of its secrets: every live one by name, where it is
//! kept, and the description its owner gave it (ADR 0009, section 6). The
//! description belongs to the catalog, so a secret a connection stores has
//! one as a secret in the file does, and `init` writes it into a manifest
//! as `purpose`. Nothing here reads a value or a version.
//!
//! A description is plain text in the file, like a secret's name and tags,
//! and authenticated with the secret's row: the row's tag covers it and
//! every change is checkpointed in the audit chain (`secret_update`), so an
//! edited or replayed description is refused when it is read. The audit
//! detail says that it changed, never what it says.

use std::collections::BTreeSet;

use rusqlite::Connection;
use sourceorrery_core::audit::AuditOperation;
use sourceorrery_core::{Result, SecretError};

use super::audit::{Checkpoints, vault_checkpoints};
use super::rows::{SecretRow, query_secret_rows};
use super::schema::db;
use super::{SecretStorage, SqliteVault};
use crate::integrity::Checkpoint;

/// One live secret as the catalog has it: no value, no version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogEntry {
    /// The secret's name.
    pub name: String,
    /// Where its value is kept.
    pub storage: SecretStorage,
    /// What it is for, when its owner said.
    pub description: Option<String>,
}

/// The longest description, in characters.
pub const MAX_DESCRIPTION_LEN: usize = 200;

/// Check a description: one line of 1 to [`MAX_DESCRIPTION_LEN`]
/// characters with no control character (`invalid_argument`). It is shown
/// in listings and written into manifests, so a line break or an escape
/// sequence has no place in it.
pub fn validate_description(text: &str) -> Result<()> {
    if text.trim().is_empty() {
        return Err(SecretError::InvalidArgument(
            "a description must not be empty; give none to leave it out".to_owned(),
        ));
    }
    if text.chars().count() > MAX_DESCRIPTION_LEN {
        return Err(SecretError::InvalidArgument(format!(
            "a description is at most {MAX_DESCRIPTION_LEN} characters"
        )));
    }
    if text.chars().any(char::is_control) {
        return Err(SecretError::InvalidArgument(
            "a description is one line without control characters".to_owned(),
        ));
    }
    Ok(())
}

impl SqliteVault {
    /// Every live secret, by name: those in the file that are not deleted
    /// and those a connection stores. Each row is verified against the
    /// state the audit chain last recorded for it, from one scan of the
    /// chain, so a row edited, replayed or removed out of band is refused
    /// (`crypto`) rather than listed or left out. Audited as `secret_list`.
    pub fn catalog(&self) -> Result<Vec<CatalogEntry>> {
        let op = AuditOperation::SecretList;
        let mut conn = self.lock()?;
        let tx = self.begin(&mut conn, op)?;
        let result = self.catalog_entries(&tx);
        self.finish_read(tx, op, None, "catalog", result)
    }

    fn catalog_entries(&self, conn: &Connection) -> Result<Vec<CatalogEntry>> {
        let checkpoints = vault_checkpoints(conn, &self.metadata_key, &self.meta.id)?;
        let mut rows = query_secret_rows(conn, None, None)?;
        let mut names: BTreeSet<String> = rows.keys().cloned().collect();
        names.extend(
            checkpoints
                .iter()
                .filter(|(_, state)| state.is_present())
                .map(|(name, _)| name.clone()),
        );
        let mut entries = Vec::with_capacity(names.len());
        for name in names {
            let state = checkpoints.get(&name).and_then(|c| c.state);
            let Some(row) = self.verify_secret_row(&name, rows.remove(&name), state)? else {
                continue;
            };
            if row.deleted_on.is_some() {
                continue;
            }
            entries.push(CatalogEntry {
                storage: row
                    .storage
                    .map_or(SecretStorage::Vault, SecretStorage::Connection),
                description: row.description,
                name,
            });
        }
        Ok(entries)
    }

    /// The row of the secret `name` as the catalog has it: in the file and
    /// not deleted, or catalogued at a connection.
    fn catalogued(&self, conn: &Connection, name: &str) -> Result<SecretRow> {
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

    /// Give the secret `name` a description ([`validate_description`]), or
    /// with `None` take it away. A secret a connection stores takes one the
    /// same way: no provider is asked. Audited as `secret_update`, with the
    /// row's new state checkpointed.
    pub fn set_description(&self, name: &str, description: Option<&str>) -> Result<()> {
        let op = AuditOperation::SecretUpdate;
        let mut conn = self.lock()?;
        let tx = self.begin(&mut conn, op)?;
        let tx = self.validated(tx, op, name)?;
        let checked = description.map_or(Ok(()), validate_description);
        let row = match checked.and_then(|()| self.catalogued(&tx, name)) {
            Ok(row) => row,
            Err(err) => return self.fail(tx, op, Some(name), None, err),
        };
        let row = SecretRow {
            description: description.map(str::to_owned),
            ..row
        };
        let tag = self.write_secret_description(&tx, name, &row)?;
        self.audit_change(
            &tx,
            op,
            name,
            None,
            Some(if description.is_some() {
                "description set"
            } else {
                "description removed"
            }),
            Checkpoints {
                state: Some(Checkpoint::Present(tag)),
                version: None,
                settings: None,
            },
        )?;
        tx.commit().map_err(db)
    }

    /// The description of the secret `name`, `None` when it has none.
    /// Audited as `secret_inspect`.
    pub fn description_of(&self, name: &str) -> Result<Option<String>> {
        let op = AuditOperation::SecretInspect;
        let mut conn = self.lock()?;
        let tx = self.begin(&mut conn, op)?;
        let tx = self.validated(tx, op, name)?;
        let result = self.catalogued(&tx, name).map(|row| row.description);
        self.finish_read(tx, op, Some(name), "description", result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_description_is_one_short_line() {
        validate_description("Database authentication").unwrap();
        validate_description(&"x".repeat(MAX_DESCRIPTION_LEN)).unwrap();
        validate_description("Clé d'API de paiement").unwrap();
        for bad in [
            String::new(),
            "   ".to_owned(),
            "x".repeat(MAX_DESCRIPTION_LEN + 1),
            "two\nlines".to_owned(),
            "an \x1b[2J escape".to_owned(),
            "a\ttab".to_owned(),
        ] {
            assert_eq!(
                validate_description(&bad).unwrap_err().code(),
                "invalid_argument",
                "{bad:?}"
            );
        }
    }
}
