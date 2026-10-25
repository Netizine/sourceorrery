//! The encrypted SQLite vault.
//!
//! One SQLite file per vault holding individually encrypted values, their
//! authenticated metadata, the wrapped vault key and a keyed audit chain.
//! The module is split by responsibility:
//!
//! * `schema`: the SQL schema, connections and transactions, the
//!   `vault_meta` record and small encoding helpers.
//! * `rows`: row types, authenticated reads and writes of secrets and
//!   versions, and version selection.
//! * `audit`: the audit chain writer, head record, verification, and the
//!   completion helpers every operation ends with (`audit`, `fail`,
//!   `finish_read`), so no operation can skip its audit row.
//! * `wraps`: opening, the key wraps (this machine, the recovery key) and
//!   credential-store ownership.
//! * `view`: the view check (password, hint, authenticator).
//! * `connections`: how the vault reaches a provider (settings, sealed
//!   credentials, the last test).
//! * `catalog`: what the vault says about a secret besides its value (its
//!   description).
//! * `projects`: the project folders built from the vault (sealed path and
//!   name, keyed path MAC).
//! * `export`: copies for another machine, and their import.
//!
//! This file keeps the vault type, its construction and the
//! [`SecretClient`] implementation. Every operation starts with
//! `SqliteVault::begin` (write lock plus audit-head check), validates its
//! input through `validated` / `fail` so a rejected call is still an audited
//! failure, and ends with exactly one audit row; changes record the new
//! state of the rows they touched as checkpoints in that row.

mod audit;
mod catalog;
mod connections;
mod export;
mod projects;
mod rows;
mod schema;
mod settings;
#[cfg(test)]
mod tests;
mod view;
mod wraps;

pub use self::catalog::{CatalogEntry, MAX_DESCRIPTION_LEN, validate_description};
pub use self::connections::{
    CatalogChange, ConnectionChange, ConnectionInfo, ConnectionTest, CredentialSource,
    SecretStorage,
};
pub use self::export::Imported;
pub use self::projects::{MAX_PROJECT_NAME_LEN, ProjectLink};
pub use self::settings::SettingsChange;
pub use self::view::{
    AuthenticatorChange, FREE_FAILURES, MAX_HINT_LEN, PasswordChange, SecondFactorInfo,
    ViewAnswers, ViewCheck,
};
pub use self::wraps::RecoveryKey;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, Transaction, params};
use serde::Serialize;
use sourceorrery_core::audit::{AuditEvent, AuditOperation, AuditOutcome, AuditQuery};
use sourceorrery_core::policy::SoftDeletePolicy;
use sourceorrery_core::{
    ContinuationToken, DeletedSecret, ListOptions, Page, Principal, RecoveryLevel, Result, Secret,
    SecretBytes, SecretClient, SecretError, SecretProperties, SetSecretOptions,
    UpdateSecretProperties, VaultDescriptor, timestamp, validate_vault_name,
};
use sourceorrery_crypto::{SymmetricKey, aead, random};
use zeroize::Zeroizing;

use crate::integrity::{self, Checkpoint, VersionFields};
use crate::keystore::CredentialStore;
use crate::registry::restrict_permissions;
use crate::unlock::UnlockProvider;
use crate::{BACKEND_NAME, SCHEMA_VERSION};

use self::audit::{
    AuditRow, AuditWriter, Checkpoints, Entry, SecretCheckpoints, chain_problem, event_from_row,
    head_problem, quarantined_message, settings_message, settings_problem, truncated_message,
    unacknowledged_truncations, vault_checkpoints,
};
use self::rows::{
    NewVersion, RawVersion, SecretRow, StoredSecretRow, load_ciphertext, query_raw_versions_in,
    query_secret_names, query_secret_rows, select_version, stored_elsewhere,
};
use self::schema::{
    Meta, SCHEMA, ViewState, begin_write, crypto, db, nanos, open_connection, opt_nanos, read_meta,
    recovery_id, value_aad, write_settings_tag,
};
use self::wraps::{
    new_recovery_wrap, new_this_machine_wrap, read_wraps, recovery_wrap_for, try_recovery_key,
    try_this_machine,
};

/// Maximum recovery-key attempts per `open`.
pub const MAX_UNLOCK_ATTEMPTS: u32 = 3;

/// Options for [`SqliteVault::open_with`].
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenOptions {
    /// Unlock a vault whose audit log has a detected truncation that nobody
    /// has acknowledged (a *quarantined* vault), for inspection and
    /// acknowledgement only.
    ///
    /// Off by default: plain `open` refuses such a vault with
    /// [`SecretError::Crypto`]. A handle opened this way can read the log,
    /// verify the chain and call [`SqliteVault::acknowledge_truncations`];
    /// every secret and key operation on it is still refused until
    /// the truncation is acknowledged. A chain head found stale at this
    /// unlock is recorded rather than refused, so the truncation can be
    /// reviewed and acknowledged in the same session, and the retention
    /// purge an unlock normally performs is skipped while the vault is
    /// quarantined. On a vault with nothing to acknowledge this is an
    /// ordinary unlock.
    pub allow_quarantined: bool,
}

/// What [`SqliteVault::acknowledge_truncations`] recorded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Acknowledgement {
    /// Id of the keyed `audit_verify` / `success` event that records the
    /// acknowledgement.
    pub event_id: u64,
    /// The truncations it covers: the `audit_verify` / `failure` events
    /// that detected them, oldest first.
    pub truncations: Vec<AuditEvent>,
}

/// Settings fixed at vault creation.
#[derive(Clone, Copy, Debug)]
pub struct CreateVaultOptions {
    /// Deletion behaviour for secrets in the vault.
    pub recovery_level: RecoveryLevel,
    /// Soft-delete retention in days (7–90).
    pub retention_days: u32,
    /// Let this machine open the vault without asking, by keeping a key in
    /// the credential store, when the store is available (default). Without
    /// it, or without a store, the vault opens with its recovery key only.
    pub this_machine: bool,
}

impl Default for CreateVaultOptions {
    fn default() -> Self {
        Self {
            recovery_level: RecoveryLevel::Recoverable,
            retention_days: SoftDeletePolicy::default().retention_days,
            this_machine: true,
        }
    }
}

/// A vault just created, with the recovery key to show its owner once.
#[derive(Debug)]
pub struct Created {
    /// The open vault.
    pub vault: SqliteVault,
    /// The recovery key (`XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`). It opens the vault
    /// anywhere and is not stored: shown once, then wiped when dropped.
    pub recovery_key: Zeroizing<String>,
    /// True when this machine can open the vault without asking.
    pub this_machine: bool,
}

/// Create `path` as an empty file readable by its owner only, failing with
/// `AlreadyExists` when anything is there already.
fn create_exclusive(path: &Path) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map(drop)
}

/// Create the vault file exclusively. `AlreadyExists` means another vault
/// (or a concurrent creator) owns the path; any other error is passed on.
fn reserve_path(path: &Path, name: &str) -> Result<()> {
    match create_exclusive(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(SecretError::VaultExists {
                name: name.to_owned(),
            })
        }
        Err(err) => Err(err.into()),
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
    /// The view check as it is now (`meta.view` is what the file said at
    /// open).
    view: Mutex<ViewState>,
    path: PathBuf,
    actor: Principal,
    /// Where this vault's this-machine keys are kept.
    store: Arc<dyn CredentialStore>,
    /// The recovery key opened this handle, which passes the view check.
    opened_with_recovery_key: bool,
}

impl SqliteVault {
    /// Create a new vault file at `path`: a fresh vault key, its recovery
    /// wrap (the recovery key is returned, to be shown once) and, when
    /// `options.this_machine` is set and `store` is available, a
    /// this-machine wrap so the vault opens here without asking.
    ///
    /// The path is reserved by creating the file exclusively, so of several
    /// callers racing to create the same vault exactly one succeeds and the
    /// others get [`SecretError::VaultExists`] without touching the winner's
    /// file. If anything fails afterwards (for example the credential store
    /// refuses the key) the creator removes its own file again, so no
    /// half-made vault is left behind.
    pub fn create(
        path: &Path,
        name: &str,
        options: CreateVaultOptions,
        store: Arc<dyn CredentialStore>,
    ) -> Result<Created> {
        Self::create_with(path, name, options, store, None)
    }

    /// [`SqliteVault::create`] with the recovery key `recovery_key`, made
    /// and shown beforehand, instead of a new one.
    pub(crate) fn create_with(
        path: &Path,
        name: &str,
        options: CreateVaultOptions,
        store: Arc<dyn CredentialStore>,
        recovery_key: Option<RecoveryKey>,
    ) -> Result<Created> {
        validate_vault_name(name)?;
        SoftDeletePolicy::new(options.retention_days)?;
        if let Some(parent) = path.parent() {
            crate::registry::ensure_private_dir(parent)?;
        }
        reserve_path(path, name)?;

        // From here on this call owns the file: only the creator that
        // reserved the path may remove it.
        let result = Self::create_inner(path, name, options, store, recovery_key);
        if result.is_err() {
            let _ = std::fs::remove_file(path);
        }
        result
    }

    fn create_inner(
        path: &Path,
        name: &str,
        options: CreateVaultOptions,
        store: Arc<dyn CredentialStore>,
        recovery_key: Option<RecoveryKey>,
    ) -> Result<Created> {
        // The reserved file is empty, which SQLite treats as a new database.
        let mut conn = open_connection(path)?;
        restrict_permissions(path, 0o600)?;
        conn.execute_batch(SCHEMA).map_err(db)?;
        // Everything that makes the file a vault lands in one transaction:
        // a crash leaves an empty database, never a vault without its
        // keys, its settings tag or its first audit row.
        let tx = begin_write(&mut conn)?;

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
            view: ViewState::default(),
            connections: Vec::new(),
            projects: Vec::new(),
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
            tx.execute(
                "INSERT INTO vault_meta (key, value) VALUES (?1, ?2)",
                params![key, value],
            )
            .map_err(db)?;
        }

        let dek = SymmetricKey::generate().map_err(crypto)?;
        let metadata_key = integrity::derive_metadata_key(&dek);
        let actor = Principal::local_user();
        let recovery_key = match recovery_key {
            Some(key) => {
                recovery_wrap_for(&tx, &meta, &dek, &key)?;
                key.into_text()
            }
            None => new_recovery_wrap(&tx, &meta, &dek)?.1,
        };
        let this_machine = options.this_machine && store.available();
        if this_machine {
            new_this_machine_wrap(&tx, &meta, &dek, store.as_ref())?;
        }
        let settings = write_settings_tag(&tx, &metadata_key, &meta)?;
        AuditWriter {
            meta: &meta,
            key: Some(&metadata_key),
            actor: &actor,
            allow_empty_chain: true,
        }
        .record_entry(
            &tx,
            &Entry {
                operation: AuditOperation::VaultCreate,
                secret_name: None,
                version: None,
                outcome: AuditOutcome::Success,
                detail: Some(BACKEND_NAME),
                checkpoints: Checkpoints {
                    settings: Some(settings),
                    ..Checkpoints::default()
                },
            },
        )?;
        tx.commit().map_err(db)?;

        let vault = Self {
            conn: Mutex::new(conn),
            dek,
            metadata_key,
            view: Mutex::new(meta.view.clone()),
            meta,
            path: path.to_path_buf(),
            actor,
            store,
            opened_with_recovery_key: false,
        };
        Ok(Created {
            vault,
            recovery_key,
            this_machine,
        })
    }

    /// Open the vault at `path`.
    ///
    /// A this-machine key in `store` is tried first (no interaction). If
    /// none opens the vault, `unlock` is asked for the recovery key up to
    /// [`MAX_UNLOCK_ATTEMPTS`] times. Every failed attempt is audited.
    ///
    /// A vault written by an earlier release (an older schema) is refused
    /// with [`SecretError::MigrationRequired`]: there is no migration.
    pub fn open(
        path: &Path,
        store: Arc<dyn CredentialStore>,
        unlock: &dyn UnlockProvider,
    ) -> Result<Self> {
        Self::open_with(path, store, unlock, OpenOptions::default())
    }

    /// [`SqliteVault::open`] with options.
    ///
    /// Opening by path takes the file as it is, whatever vault it holds.
    /// [`crate::VaultRegistry`] opens by name and refuses a file that holds
    /// another vault ([`SecretError::VaultMismatch`]).
    pub fn open_with(
        path: &Path,
        store: Arc<dyn CredentialStore>,
        unlock: &dyn UnlockProvider,
        options: OpenOptions,
    ) -> Result<Self> {
        Self::open_checked(path, None, store, unlock, options)
    }

    /// [`SqliteVault::open_with`] for the vault named `name`: once the name
    /// stored in the file is authenticated, a file that holds another vault
    /// is refused with [`SecretError::VaultMismatch`] and the refusal is
    /// recorded in that file's audit log.
    pub(crate) fn open_named(
        path: &Path,
        name: &str,
        store: Arc<dyn CredentialStore>,
        unlock: &dyn UnlockProvider,
        options: OpenOptions,
    ) -> Result<Self> {
        Self::open_checked(path, Some(name), store, unlock, options)
    }

    fn open_checked(
        path: &Path,
        expected_name: Option<&str>,
        store: Arc<dyn CredentialStore>,
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
        let wraps = read_wraps(&conn)?;
        let actor = Principal::local_user();
        if wraps.is_empty() {
            return Err(SecretError::Locked("vault has no key wraps".to_owned()));
        }
        // Rows written here precede unlock: no metadata key yet.
        let unkeyed = AuditWriter {
            meta: &meta,
            key: None,
            actor: &actor,
            allow_empty_chain: false,
        };

        let mut reasons: Vec<String> = Vec::new();
        let opened = match try_this_machine(&meta, &wraps, store.as_ref(), &mut reasons) {
            Some(dek) => Some((dek, false)),
            None => try_recovery_key(&conn, &meta, &wraps, unlock, &unkeyed, &mut reasons)?
                .map(|dek| (dek, true)),
        };
        if let Some((dek, with_recovery_key)) = opened {
            return Self::finish_open(
                conn,
                dek,
                meta,
                path,
                actor,
                store,
                options,
                expected_name,
                with_recovery_key,
            );
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

    #[allow(clippy::too_many_arguments)] // one call per unlock route, all of them needed
    fn finish_open(
        conn: Connection,
        dek: SymmetricKey,
        meta: Meta,
        path: &Path,
        actor: Principal,
        store: Arc<dyn CredentialStore>,
        options: OpenOptions,
        expected_name: Option<&str>,
        with_recovery_key: bool,
    ) -> Result<Self> {
        let metadata_key = integrity::derive_metadata_key(&dek);
        let head_stale = Self::refuse_if_truncated(
            &conn,
            &metadata_key,
            &meta,
            &actor,
            options.allow_quarantined,
        )?;
        Self::verify_settings(&conn, &metadata_key, &meta, &actor)?;
        // The settings tag covers the name, so it is authentic here.
        Self::refuse_if_misnamed(&conn, &metadata_key, &meta, &actor, expected_name)?;

        // A detected truncation that nobody has acknowledged blocks the
        // vault: only an unlock asked for inspection gets a handle, and that
        // handle refuses every operation until the acknowledgement is on
        // the chain.
        let pending = unacknowledged_truncations(&conn, &metadata_key, &meta.id)?;
        let quarantined = head_stale || !pending.is_empty();
        if quarantined && !options.allow_quarantined {
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
                Some("truncation unacknowledged"),
            )?;
            return Err(SecretError::Crypto(quarantined_message(&pending)));
        }
        // A quarantined vault's settings are judged by their tag alone (see
        // `verified_meta`): the missing events may have held the newest
        // checkpoint.
        if !quarantined {
            Self::refuse_if_settings_replayed(&conn, &metadata_key, &meta, &actor)?;
        }
        // On a stale head this append records the detection first (every
        // keyed append does), so what the inspecting caller sees is on the
        // chain before the handle is handed out.
        let detail = match (quarantined, with_recovery_key) {
            (true, _) => Some("inspection (truncation unacknowledged)"),
            (false, true) => Some("opened with the recovery key"),
            (false, false) => None,
        };
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
            detail,
        )?;
        let vault = Self {
            conn: Mutex::new(conn),
            dek,
            metadata_key,
            view: Mutex::new(meta.view.clone()),
            meta,
            path: path.to_path_buf(),
            actor,
            store,
            opened_with_recovery_key: with_recovery_key,
        };
        if !quarantined {
            vault.purge_expired_deletions()?;
        }
        Ok(vault)
    }

    /// Refuse to unlock a vault whose audit chain head no longer names the
    /// newest keyed row: rows were removed from the end of the log, so the
    /// checkpoints that remain may not be the newest and no row state can be
    /// judged against them. Recording the refusal puts the detection on the
    /// chain and re-anchors the head; from then on the vault is blocked
    /// until the truncation is acknowledged. With `allow_quarantined` the
    /// stale head is reported (`true`) instead of refused, so the caller
    /// can record it and hand out a handle for inspection.
    fn refuse_if_truncated(
        conn: &Connection,
        key: &SymmetricKey,
        meta: &Meta,
        actor: &Principal,
        allow_quarantined: bool,
    ) -> Result<bool> {
        let writer = AuditWriter {
            meta,
            key: Some(key),
            actor,
            allow_empty_chain: false,
        };
        let problem = if let Some(problem) = head_problem(conn, key, &meta.id, false)? {
            problem
        } else {
            // The head holds, so a keyed write would record nothing; the
            // walk is what finds a row removed or replaced inside the log,
            // and its finding goes on the chain here.
            let Some(problem) = chain_problem(conn, key, &meta.id)? else {
                return Ok(false);
            };
            if !unacknowledged_truncations(conn, key, &meta.id)?.is_empty() {
                // Already on record and blocking the vault: the quarantine
                // check below refuses, without recording the same break
                // again at every unlock.
                return Ok(false);
            }
            writer.record(
                conn,
                AuditOperation::AuditVerify,
                None,
                None,
                AuditOutcome::Failure,
                Some(&problem),
            )?;
            problem
        };
        if allow_quarantined {
            return Ok(true);
        }
        writer.record(
            conn,
            AuditOperation::VaultOpen,
            None,
            None,
            AuditOutcome::Failure,
            Some("audit log truncated"),
        )?;
        Err(SecretError::Crypto(truncated_message(&problem)))
    }

    /// Refuse a vault opened by a name that is not its own: the file found
    /// for `expected` holds another vault, renamed, copied or swapped in.
    /// Recording the refusal puts it on that vault's own log.
    fn refuse_if_misnamed(
        conn: &Connection,
        key: &SymmetricKey,
        meta: &Meta,
        actor: &Principal,
        expected: Option<&str>,
    ) -> Result<()> {
        let Some(expected) = expected else {
            return Ok(());
        };
        if meta.name == expected {
            return Ok(());
        }
        let detail = format!("opened as vault '{expected}'");
        AuditWriter {
            meta,
            key: Some(key),
            actor,
            allow_empty_chain: false,
        }
        .record(
            conn,
            AuditOperation::VaultOpen,
            None,
            None,
            AuditOutcome::Failure,
            Some(detail.as_str()),
        )?;
        Err(SecretError::VaultMismatch {
            requested: expected.to_owned(),
            found: meta.name.clone(),
        })
    }

    /// Refuse to unlock a vault whose authenticated settings do not verify.
    fn verify_settings(
        conn: &Connection,
        key: &SymmetricKey,
        meta: &Meta,
        actor: &Principal,
    ) -> Result<()> {
        let fields = meta.settings_fields()?;
        let settings_ok =
            integrity::verify_settings_tag(key, &fields, meta.settings_tag.as_deref())
                && SoftDeletePolicy::new(meta.retention_days).is_ok();
        if settings_ok {
            return Ok(());
        }
        AuditWriter {
            meta,
            key: Some(key),
            actor,
            allow_empty_chain: false,
        }
        .record(
            conn,
            AuditOperation::VaultOpen,
            None,
            None,
            AuditOutcome::Failure,
            Some("settings integrity check failed"),
        )?;
        Err(SecretError::Crypto(
            "vault settings integrity check failed (schema, name, recovery level, retention, \
             the view check, a connection or a project were altered)"
                .to_owned(),
        ))
    }

    /// Refuse to unlock a vault whose settings record, authentic as it is,
    /// is not the one the audit chain records last: an older copy of the
    /// whole record put back, which would switch the view check off, reset
    /// the count of wrong answers or bring back a removed connection. Like
    /// a replayed row it stays refused; the refusal is recorded.
    fn refuse_if_settings_replayed(
        conn: &Connection,
        key: &SymmetricKey,
        meta: &Meta,
        actor: &Principal,
    ) -> Result<()> {
        let Some(problem) = settings_problem(conn, key, &meta.id, meta.settings_tag.as_deref())?
        else {
            return Ok(());
        };
        let detail = format!("settings integrity check failed: {problem}");
        AuditWriter {
            meta,
            key: Some(key),
            actor,
            allow_empty_chain: false,
        }
        .record(
            conn,
            AuditOperation::VaultOpen,
            None,
            None,
            AuditOutcome::Failure,
            Some(detail.as_str()),
        )?;
        Err(SecretError::Crypto(settings_message(&problem)))
    }

    /// Replace the principal recorded in audit events (default: OS user).
    #[must_use]
    pub fn with_actor(mut self, actor: Principal) -> Self {
        self.actor = actor;
        self
    }

    /// Non-sensitive description of this vault.
    pub fn descriptor(&self) -> Result<VaultDescriptor> {
        let protectors = self.wraps()?.into_iter().map(|w| w.kind).collect();
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

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| SecretError::Storage("vault connection poisoned".to_owned()))
    }

    /// The next window of candidate names after `after`, at most `limit` of
    /// them, with their `secrets` and `secret_versions` rows: three
    /// statements whatever the window holds. `checkpoints` is the chain's
    /// state for every secret, read once per page by [`Self::page_of`].
    ///
    /// The candidate names are the union of the table's names and the names
    /// whose newest state checkpoint says the row exists, so a row removed
    /// out of band is still visited and refused. Which version of a secret
    /// is newest is judged against all of its versions, as `load_versions`
    /// does; only the set of *names* is cut into windows.
    fn listing_window(
        conn: &Connection,
        checkpoints: &BTreeMap<String, SecretCheckpoints>,
        after: Option<&str>,
        limit: usize,
    ) -> Result<ListingWindow> {
        let mut names: BTreeSet<String> = query_secret_names(conn, after)?.into_iter().collect();
        names.extend(
            checkpoints
                .iter()
                .filter(|(name, state)| {
                    state.is_present() && after.is_none_or(|after| name.as_str() > after)
                })
                .map(|(name, _)| name.clone()),
        );
        let mut names = names.into_iter();
        let window: Vec<String> = names.by_ref().take(limit).collect();
        let more = names.next().is_some();
        let Some(through) = window.last() else {
            return Ok(ListingWindow::default());
        };
        Ok(ListingWindow {
            rows: query_secret_rows(conn, after, Some(through))?,
            versions: query_raw_versions_in(conn, after, Some(through))?,
            names: window,
            more,
        })
    }

    /// One page of a listing: candidate names are visited in order, each
    /// verified (its `secrets` row against the chain, then, for the rows
    /// `wanted` selects, every version), until `max_results` items have been
    /// built or no name is left; `build` turns a verified row and its newest
    /// version into an item. Names the other listing owns (deleted for a
    /// live listing and the reverse) are skipped, so a page holds
    /// `max_results` items unless it is the last, and its token is the name
    /// of its last item. The token is present while candidate *names*
    /// remain: deciding whether any of them is an item would mean verifying
    /// rows beyond the page, so the page after the last item can be empty.
    fn page_of<T>(
        &self,
        tx: &Transaction<'_>,
        options: &ListOptions,
        wanted: impl Fn(&SecretRow) -> bool,
        build: impl Fn(&str, &SecretRow, SecretProperties) -> Result<T>,
    ) -> Result<Page<T>> {
        options.validate()?;
        let checkpoints = vault_checkpoints(tx, &self.metadata_key, &self.meta.id)?;
        let no_versions = BTreeMap::new();
        let limit = options.limit();
        let mut after = options.after().map(str::to_owned);
        let mut items = Vec::new();
        loop {
            let mut window =
                Self::listing_window(tx, &checkpoints, after.as_deref(), limit - items.len())?;
            let mut names = window.names.iter();
            for name in names.by_ref() {
                // Every row is verified against its checkpoint: a tampered
                // or resurrected `deleted_on` must not resurface a secret in
                // listings, and a row the chain records but the table lacks
                // is an error rather than a quiet omission.
                let state = checkpoints.get(name);
                let row = self.verify_secret_row(
                    name,
                    window.rows.remove(name),
                    state.and_then(|c| c.state),
                )?;
                let Some(row) = row else { continue };
                // A connection stores the value of a row with a storage, so
                // the file has nothing to list for it.
                if row.storage.is_some() || !wanted(&row) {
                    continue;
                }
                let raw = window.versions.remove(name).unwrap_or_default();
                let versions = state.map_or(&no_versions, |c| &c.versions);
                let newest = self
                    .verify_versions(name, raw, versions)?
                    .into_iter()
                    .next()
                    .map(|v| v.props)
                    .ok_or_else(|| {
                        SecretError::Storage(format!("secret '{name}' has no versions"))
                    })?;
                items.push(build(name, &row, newest)?);
                if items.len() == limit {
                    let more = names.next().is_some() || window.more;
                    return Ok(Page {
                        items,
                        continuation: more.then(|| ContinuationToken::new(name)),
                    });
                }
            }
            if !window.more {
                return Ok(Page {
                    items,
                    continuation: None,
                });
            }
            after = window.names.pop();
        }
    }
}

/// The rows one window of a listing is judged from; see
/// [`SqliteVault::listing_window`].
#[derive(Default)]
struct ListingWindow {
    /// The window's candidate names, in order.
    names: Vec<String>,
    /// True when names remain after the last one.
    more: bool,
    rows: BTreeMap<String, StoredSecretRow>,
    versions: BTreeMap<String, Vec<RawVersion>>,
}

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
        let op = AuditOperation::SecretSet;
        let mut conn = self.lock()?;
        let tx = self.begin(&mut conn, op)?;
        let tx = self.validated(tx, op, name)?;
        if let Err(err) = options.validate() {
            return self.fail(tx, op, Some(name), None, err);
        }
        let now = timestamp::now();
        let now_nanos = nanos(now)?;

        // The secrets row is checkpointed only when this call creates it.
        let state = match self.load_secret_row(&tx, name) {
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
            Ok(Some(SecretRow {
                storage: Some(connection),
                ..
            })) => {
                return self.fail(
                    tx,
                    op,
                    Some(name),
                    None,
                    stored_elsewhere(name, &connection),
                );
            }
            Ok(Some(_)) => None,
            Ok(None) => {
                let row = SecretRow {
                    created_on: now_nanos,
                    deleted_on: None,
                    scheduled_purge_on: None,
                    recovery_id: None,
                    storage: None,
                    description: None,
                };
                Some(Checkpoint::Present(self.insert_secret(&tx, name, &row)?))
            }
            Err(err) => return self.fail(tx, op, Some(name), None, err),
        };

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
        let version_tag = self.insert_version(
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
        self.audit_change(
            &tx,
            op,
            name,
            Some(&version),
            None,
            Checkpoints {
                state,
                version: Some(Checkpoint::Present(version_tag)),
                settings: None,
            },
        )?;
        tx.commit().map_err(db)?;
        Ok(props)
    }

    fn get_secret(&self, name: &str, version: Option<&str>) -> Result<Secret> {
        let op = AuditOperation::SecretGet;
        let mut conn = self.lock()?;
        let tx = self.begin(&mut conn, op)?;
        let tx = self.validated(tx, op, name)?;
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
        // Only the selected version's value is read; the other versions'
        // ciphertext never leaves the file.
        let ciphertext = match load_ciphertext(&tx, name, &chosen.props.version) {
            Ok(c) => c,
            Err(err) => return self.fail(tx, op, Some(name), Some(&chosen.props.version), err),
        };
        let plaintext = match aead::open(
            &self.dek,
            value_aad(&self.meta.id, name, &chosen.props.version).as_bytes(),
            &ciphertext,
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
        let op = AuditOperation::SecretInspect;
        let mut conn = self.lock()?;
        let tx = self.begin(&mut conn, op)?;
        let tx = self.validated(tx, op, name)?;
        let result = self.require_live(&tx, name).and_then(|_| {
            let versions = self.load_versions(&tx, name)?;
            select_version(name, &versions, version, timestamp::now(), false)
                .map(|v| v.props.clone())
        });
        self.finish_read(tx, op, Some(name), "properties", result)
    }

    fn list_properties_of_secrets(&self) -> Result<Vec<SecretProperties>> {
        self.list_properties_of_secrets_page(ListOptions::default())
            .map(|page| page.items)
    }

    fn list_properties_of_secrets_page(
        &self,
        options: ListOptions,
    ) -> Result<Page<SecretProperties>> {
        let op = AuditOperation::SecretList;
        let mut conn = self.lock()?;
        let tx = self.begin(&mut conn, op)?;
        let result = self.page_of(
            &tx,
            &options,
            |row| row.deleted_on.is_none(),
            |_, _, props| Ok(props),
        );
        match result {
            Ok(page) => {
                self.audit(&tx, op, None, None, AuditOutcome::Success, None)?;
                tx.commit().map_err(db)?;
                Ok(page)
            }
            Err(err) => self.fail(tx, op, None, None, err),
        }
    }

    fn list_properties_of_secret_versions(&self, name: &str) -> Result<Vec<SecretProperties>> {
        let op = AuditOperation::SecretInspect;
        let mut conn = self.lock()?;
        let tx = self.begin(&mut conn, op)?;
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
        let op = AuditOperation::SecretUpdate;
        let mut conn = self.lock()?;
        let tx = self.begin(&mut conn, op)?;
        let tx = self.validated(tx, op, name)?;
        if update.is_empty() {
            return self.fail(
                tx,
                op,
                Some(name),
                version,
                SecretError::InvalidArgument("nothing to update".to_owned()),
            );
        }
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
        if let Err(err) = update.apply(&mut props, now) {
            // `props` is untouched by a rejected update.
            return self.fail(tx, op, Some(name), Some(&props.version), err);
        }
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
        self.audit_change(
            &tx,
            op,
            name,
            Some(&props.version),
            None,
            Checkpoints {
                state: None,
                version: Some(Checkpoint::Present(tag)),
                settings: None,
            },
        )?;
        tx.commit().map_err(db)?;
        Ok(props)
    }

    fn delete_secret(&self, name: &str) -> Result<DeletedSecret> {
        let op = AuditOperation::SecretDelete;
        let mut conn = self.lock()?;
        let tx = self.begin(&mut conn, op)?;
        let tx = self.validated(tx, op, name)?;
        let row = match self.require_live(&tx, name) {
            Ok(row) => row,
            Err(err) => return self.fail(tx, op, Some(name), None, err),
        };
        let props = match self.newest_props(&tx, name) {
            Ok(props) => props,
            Err(err) => return self.fail(tx, op, Some(name), None, err),
        };
        let now = timestamp::now();
        let (deleted, state) = if self.meta.recovery_level.soft_delete_enabled() {
            let purge_on = self.meta.retention().scheduled_purge_on(now);
            let rid = recovery_id(&self.meta.name, name);
            let state = SecretRow {
                deleted_on: Some(nanos(now)?),
                scheduled_purge_on: Some(nanos(purge_on)?),
                recovery_id: Some(rid.clone()),
                ..row
            };
            let tag = self.write_secret_state(&tx, name, &state)?;
            (
                DeletedSecret {
                    properties: props,
                    deleted_on: now,
                    scheduled_purge_on: Some(purge_on),
                    recovery_id: rid,
                },
                Checkpoint::Present(tag),
            )
        } else {
            Self::delete_secret_row(&tx, name)?;
            (
                DeletedSecret {
                    properties: props,
                    deleted_on: now,
                    scheduled_purge_on: Some(now),
                    recovery_id: String::new(),
                },
                Checkpoint::Absent,
            )
        };
        self.audit_change(
            &tx,
            op,
            name,
            Some(&deleted.properties.version),
            Some(if deleted.recovery_id.is_empty() {
                "purged"
            } else {
                "soft-deleted"
            }),
            Checkpoints {
                state: Some(state),
                version: None,
                settings: None,
            },
        )?;
        tx.commit().map_err(db)?;
        Ok(deleted)
    }

    fn get_deleted_secret(&self, name: &str) -> Result<DeletedSecret> {
        let op = AuditOperation::SecretInspect;
        let mut conn = self.lock()?;
        let tx = self.begin(&mut conn, op)?;
        let tx = self.validated(tx, op, name)?;
        let result = self
            .require_deleted(&tx, name)
            .and_then(|row| self.deleted_from_row(&tx, name, &row));
        self.finish_read(tx, op, Some(name), "deleted", result)
    }

    fn list_deleted_secrets(&self) -> Result<Vec<DeletedSecret>> {
        self.list_deleted_secrets_page(ListOptions::default())
            .map(|page| page.items)
    }

    fn list_deleted_secrets_page(&self, options: ListOptions) -> Result<Page<DeletedSecret>> {
        let op = AuditOperation::SecretList;
        let mut conn = self.lock()?;
        let tx = self.begin(&mut conn, op)?;
        let result = self.page_of(
            &tx,
            &options,
            |row| row.deleted_on.is_some(),
            |name, row, props| self.deleted_from_parts(name, row, props),
        );
        self.finish_read(tx, op, None, "deleted", result)
    }

    fn recover_deleted_secret(&self, name: &str) -> Result<SecretProperties> {
        let op = AuditOperation::SecretRecover;
        let mut conn = self.lock()?;
        let tx = self.begin(&mut conn, op)?;
        let tx = self.validated(tx, op, name)?;
        let row = match self.require_deleted(&tx, name) {
            Ok(row) => row,
            Err(err) => return self.fail(tx, op, Some(name), None, err),
        };
        let state = SecretRow {
            deleted_on: None,
            scheduled_purge_on: None,
            recovery_id: None,
            ..row
        };
        let tag = self.write_secret_state(&tx, name, &state)?;
        let props = match self.newest_props(&tx, name) {
            Ok(props) => props,
            Err(err) => return self.fail(tx, op, Some(name), None, err),
        };
        self.audit_change(
            &tx,
            op,
            name,
            Some(&props.version),
            None,
            Checkpoints {
                state: Some(Checkpoint::Present(tag)),
                version: None,
                settings: None,
            },
        )?;
        tx.commit().map_err(db)?;
        Ok(props)
    }

    fn purge_deleted_secret(&self, name: &str) -> Result<()> {
        let op = AuditOperation::SecretPurge;
        let mut conn = self.lock()?;
        let tx = self.begin(&mut conn, op)?;
        let tx = self.validated(tx, op, name)?;
        if let Err(err) = self.require_deleted(&tx, name) {
            return self.fail(tx, op, Some(name), None, err);
        }
        Self::delete_secret_row(&tx, name)?;
        self.audit_change(
            &tx,
            op,
            name,
            None,
            None,
            Checkpoints {
                state: Some(Checkpoint::Absent),
                version: None,
                settings: None,
            },
        )?;
        tx.commit().map_err(db)?;
        Ok(())
    }

    /// Events newest first. A row whose operation or outcome no longer
    /// parses (a tamperer's edit, which the chain walk at unlock also
    /// records) is left out rather than failing the whole listing, so the
    /// surviving history can still be reviewed before an acknowledgement.
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
        Ok(raw
            .into_iter()
            .filter_map(|row| event_from_row(row).ok())
            .collect())
    }
}
