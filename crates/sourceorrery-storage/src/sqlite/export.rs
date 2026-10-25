//! Moving a vault to another machine (ADR 0009, section 8).
//!
//! An **export** is a consistent copy of the file, made with SQLite's
//! online backup, that opens with the recovery key and nothing else: this
//! machine's key wrap and the view check (the sealed password hash, its
//! hint, the authenticator and the count of wrong answers) are left out of
//! it. The settings, the secrets with every version and the audit log
//! travel; the copy's chain goes on with its own `vault_export` row.
//!
//! An **import** copies such a file into a home under its own name or a new
//! one, opens it with the recovery key (no credential store is consulted,
//! so a key of this machine's that the file names does not open it),
//! verifies it as every open does, and gives it this machine's wrap. The
//! file it is given is only read.

use std::path::Path;
use std::sync::Arc;

use rusqlite::{Connection, MAIN_DB, OpenFlags, params};
use sourceorrery_core::audit::{AuditOperation, AuditOutcome};
use sourceorrery_core::{Result, SecretError};

use super::audit::{Checkpoints, Entry};
use super::rows::SecretRow;
use super::schema::{
    SettingsTag, ViewState, begin_write, db, open_connection, put_meta, read_meta, recovery_id,
    write_settings_tag,
};
use super::wraps::{keyring_account, new_this_machine_wrap, read_wraps};
use super::{OpenOptions, SqliteVault, create_exclusive, reserve_path};
use crate::integrity::Checkpoint;
use crate::keystore::{CredentialStore, NoStore};
use crate::unlock::UnlockProvider;
use crate::wrap::WrapKind;

/// A vault just imported ([`crate::VaultRegistry::import_from`]).
#[derive(Debug)]
pub struct Imported {
    /// The open vault, under its name in this home.
    pub vault: SqliteVault,
    /// The name the copy carried, when it was imported under another.
    pub renamed_from: Option<String>,
    /// True when this machine can open the vault without asking.
    pub this_machine: bool,
}

/// A connection that only reads the file at `path`: the file an import is
/// given is never written.
fn open_read_only(path: &Path) -> Result<Connection> {
    if !path.is_file() {
        return Err(SecretError::Io(format!("{} is not a file", path.display())));
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(db)?;
    conn.execute_batch("PRAGMA busy_timeout = 5000;")
        .map_err(db)?;
    Ok(conn)
}

/// Remove a copy that could not be finished, with any rollback journal
/// SQLite left beside it.
fn discard(path: &Path) {
    let _ = std::fs::remove_file(path);
    let mut journal = path.as_os_str().to_owned();
    journal.push("-journal");
    let _ = std::fs::remove_file(journal);
}

/// The ids of the this-machine wraps in the file.
fn this_machine_wraps(conn: &Connection) -> Result<Vec<String>> {
    Ok(read_wraps(conn)?
        .into_iter()
        .filter(|wrap| matches!(wrap.kind, WrapKind::ThisMachine { .. }))
        .map(|wrap| wrap.id)
        .collect())
}

fn delete_wraps(conn: &Connection, ids: &[String]) -> Result<()> {
    for id in ids {
        conn.execute("DELETE FROM key_wraps WHERE id = ?1", params![id])
            .map_err(db)?;
    }
    Ok(())
}

impl SqliteVault {
    /// Write a copy of this vault to `path` for another machine.
    ///
    /// The copy opens with the recovery key only: this machine's key and
    /// the view check are left out, and the copy's own log records
    /// `vault_export` with what was left out. The settings, the secrets
    /// with every version and the audit log are kept. No check is asked,
    /// since the copy opens only with the recovery key. Audited here as
    /// `vault_export` too.
    ///
    /// `path` must not exist: an export never replaces a file
    /// (`invalid_argument`), and one that fails leaves no file behind.
    pub fn export_to(&self, path: &Path) -> Result<()> {
        let op = AuditOperation::VaultExport;
        let mut conn = self.lock()?;
        // The write lock is held until this vault's row is recorded, so the
        // copy is the vault as that row finds it. Readers are not blocked by
        // it, and the backup reads through a connection of its own.
        let tx = self.begin(&mut conn, op)?;
        if let Err(err) = create_exclusive(path) {
            let err = if err.kind() == std::io::ErrorKind::AlreadyExists {
                SecretError::InvalidArgument(format!(
                    "{} already exists; an export never replaces a file",
                    path.display()
                ))
            } else {
                err.into()
            };
            return self.fail(tx, op, None, None, err);
        }
        let detail = match self.write_copy(path) {
            Ok(detail) => detail,
            Err(err) => {
                discard(path);
                return self.fail(tx, op, None, None, err);
            }
        };
        let recorded = self
            .audit(&tx, op, None, None, AuditOutcome::Success, Some(&detail))
            .and_then(|()| tx.commit().map_err(db));
        if recorded.is_err() {
            // A copy this vault's log does not record is not left behind.
            discard(path);
        }
        recorded
    }

    /// Back this vault up into the empty file at `path`, then take out of
    /// the copy what must not travel. Returns the audit detail naming it.
    fn write_copy(&self, path: &Path) -> Result<String> {
        open_connection(&self.path)?
            .backup(MAIN_DB, path, None)
            .map_err(db)?;
        let mut copy = open_connection(path)?;
        // What is left out never reaches the disk again, not even in a
        // rollback journal or a temporary file.
        copy.execute_batch("PRAGMA journal_mode = MEMORY; PRAGMA temp_store = MEMORY;")
            .map_err(db)?;
        let tx = begin_write(&mut copy)?;
        // The copy's settings verify under this vault's key, so the view
        // check read here is the one the vault holds.
        let view = self.stored_view_state(&tx)?;
        let machine = this_machine_wraps(&tx)?;
        delete_wraps(&tx, &machine)?;
        let settings = self.write_view_state(&tx, &ViewState::default())?;

        let left_out: Vec<&str> = [
            (!machine.is_empty(), "this machine's key"),
            (view.password.is_some(), "the password"),
            (view.password_hint.is_some(), "its hint"),
            (view.second_factor.is_some(), "the authenticator"),
        ]
        .into_iter()
        .filter_map(|(present, what)| present.then_some(what))
        .collect();
        let detail = if left_out.is_empty() {
            "copy made; nothing to leave out".to_owned()
        } else {
            format!("copy made; left out: {}", left_out.join(", "))
        };
        self.audit_settings(
            &tx,
            AuditOperation::VaultExport,
            AuditOutcome::Success,
            &detail,
            settings,
        )?;
        tx.commit().map_err(db)?;
        // Rebuilt, the file keeps no free page that held what was left out.
        copy.execute_batch("VACUUM").map_err(db)?;
        Ok(detail)
    }

    /// The name the vault file at `path` says it has, read without opening
    /// the vault and without writing to the file. It is not authentic until
    /// the vault is opened, which refuses a name that was altered.
    pub(crate) fn stored_name(path: &Path) -> Result<String> {
        Ok(read_meta(&open_read_only(path)?)?.name)
    }

    /// Import the vault file at `source` as the vault `name` at `path`, a
    /// free path in a home: copied with the online backup, opened with the
    /// recovery key from `unlock` only, renamed when `name` is not its own,
    /// and given this machine's wrap in `store` when the store is available.
    /// Nothing is left at `path` when it fails.
    pub(crate) fn import(
        source: &Path,
        path: &Path,
        name: &str,
        store: Arc<dyn CredentialStore>,
        unlock: &dyn UnlockProvider,
    ) -> Result<Imported> {
        let reader = open_read_only(source)?;
        reserve_path(path, name)?;
        // From here on this call owns the file, as `create` does.
        let result = reader
            .backup(MAIN_DB, path, None)
            .map_err(db)
            .and_then(|()| Self::open_with(path, Arc::new(NoStore), unlock, OpenOptions::default()))
            .and_then(|vault| vault.adopt(name, store));
        if result.is_err() {
            discard(path);
        }
        result
    }

    /// Make an opened copy this home's vault `name`.
    fn adopt(mut self, name: &str, store: Arc<dyn CredentialStore>) -> Result<Imported> {
        let renamed_from = (name != self.meta.name).then(|| self.meta.name.clone());
        let this_machine = self.record_import(name, store.as_ref())?;
        name.clone_into(&mut self.meta.name);
        self.store = store;
        Ok(Imported {
            vault: self,
            renamed_from,
            this_machine,
        })
    }

    /// In one transaction: the new name when `name` is not the copy's own,
    /// no this-machine wrap of the copy's (the key it names is not this
    /// vault's to use), a new one in `store` when the store is available,
    /// and the `vault_import` row. Returns whether the wrap was added.
    fn record_import(&self, name: &str, store: &dyn CredentialStore) -> Result<bool> {
        let op = AuditOperation::VaultImport;
        let mut conn = self.lock()?;
        let tx = self.begin(&mut conn, op)?;
        let mut settings = None;
        let mut detail = vec![if name == self.meta.name {
            "imported".to_owned()
        } else {
            settings = Some(self.rename(&tx, name)?);
            format!("imported as '{name}' (exported as '{}')", self.meta.name)
        }];
        let foreign = this_machine_wraps(&tx)?;
        delete_wraps(&tx, &foreign)?;
        if !foreign.is_empty() {
            detail.push("another machine's key removed".to_owned());
        }
        let account = if store.available() {
            let wrap = new_this_machine_wrap(&tx, &self.meta, &self.dek, store)?;
            detail.push("this machine can open it".to_owned());
            Some(keyring_account(&self.meta.id, &wrap.id))
        } else {
            detail.push(format!(
                "it opens with the recovery key only ({} is not available)",
                store.name()
            ));
            None
        };
        let detail = detail.join("; ");
        let entry = Entry {
            operation: op,
            secret_name: None,
            version: None,
            outcome: AuditOutcome::Success,
            detail: Some(&detail),
            checkpoints: Checkpoints {
                settings,
                ..Checkpoints::default()
            },
        };
        let recorded = self
            .writer()
            .record_entry(&tx, &entry)
            .and_then(|()| tx.commit().map_err(db));
        if let (Err(_), Some(account)) = (&recorded, &account) {
            // The file goes, so its key must not stay in the store.
            let _ = store.delete_key(account);
        }
        recorded.map(|()| account.is_some())
    }

    /// Give the vault the name `name`: its settings record and the recovery
    /// id of every deleted secret, which names the vault, follow. Each
    /// rewritten secret row is checkpointed in a `vault_change` row; the
    /// caller's event records the settings tag returned.
    fn rename(&self, conn: &Connection, name: &str) -> Result<SettingsTag> {
        let deleted: Vec<String> = conn
            .prepare("SELECT name FROM secrets WHERE deleted_on IS NOT NULL ORDER BY name")
            .map_err(db)?
            .query_map([], |row| row.get(0))
            .map_err(db)?
            .collect::<rusqlite::Result<_>>()
            .map_err(db)?;
        for secret in &deleted {
            let row = SecretRow {
                recovery_id: Some(recovery_id(name, secret)),
                ..self.require_deleted(conn, secret)?
            };
            let tag = self.write_secret_state(conn, secret, &row)?;
            self.audit_change(
                conn,
                AuditOperation::VaultChange,
                secret,
                None,
                Some("recovery id follows the vault's new name"),
                Checkpoints {
                    state: Some(Checkpoint::Present(tag)),
                    version: None,
                    settings: None,
                },
            )?;
        }
        let mut meta = self.meta.with_view(&self.stored_view_state(conn)?);
        name.clone_into(&mut meta.name);
        put_meta(conn, "name", name)?;
        write_settings_tag(conn, &self.metadata_key, &meta)
    }
}
