//! Connections (ADR 0009, section 4): how the vault reaches a provider.
//!
//! A connection is a provider's settings ([`ConnectionSettings`], plain
//! text but authenticated) and a credential source: *ambient*, the
//! provider's own chain as its SDK or CLI finds it, or *stored*:
//! [`Credentials`] sealed under the vault key and bound to the vault and the
//! connection. Each row carries a tag over its fields, and the settings
//! record lists every row with that tag, so an edited row is refused when it
//! is read, and a row added, removed or replaced by an older copy is
//! refused at unlock. Stored credentials leave the vault only through
//! [`SqliteVault::connection_credentials`], to open the connection; no
//! listing carries them.
//!
//! Adding, changing and removing a connection is audited as `vault_change`,
//! recording a test as `connection_test`. The detail names the connection
//! and its provider, never a credential. A vault has one connection per
//! provider for now; rows are keyed by id so several can follow.
//!
//! A secret a connection stores is a catalog entry in `secrets`: its row
//! names the connection in `storage` (covered by the row's tag and so by
//! its checkpoints) and holds no version; its versions, enabled flag, time
//! window and deletion state are the provider's. [`SqliteVault::storage_of`]
//! says where a secret is, [`SqliteVault::record_at_connection`] records in
//! this vault's log what was done there and keeps the catalog in step, and
//! a connection that still stores a secret cannot be removed.

use rusqlite::{Connection, params};
use serde::Serialize;
use sourceorrery_core::audit::{AuditOperation, AuditOutcome};
use sourceorrery_core::{
    ConnectionSettings, Credentials, Result, SecretBytes, SecretError, timestamp,
    validate_secret_name,
};
use sourceorrery_crypto::random;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use super::SqliteVault;
use super::audit::{
    Checkpoints, outcome_of, settings_message, settings_problem, unacknowledged_truncations,
};
use super::rows::{SecretRow, query_names_at};
use super::schema::{
    Meta, SettingsTag, crypto, db, from_nanos, integrity_error, nanos, read_meta,
    write_settings_tag,
};
use crate::integrity::{self, Checkpoint, ConnectionFields};

/// Where a connection's credentials come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialSource {
    /// The provider's own chain, as its SDK or CLI finds it: the
    /// environment, a CLI login, a workload or managed identity.
    Ambient,
    /// Credentials sealed in the vault.
    Stored,
}

impl CredentialSource {
    /// `ambient` or `stored`, as stored.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ambient => "ambient",
            Self::Stored => "stored",
        }
    }

    fn of(credentials: Option<&Credentials>) -> Self {
        if credentials.is_some() {
            Self::Stored
        } else {
            Self::Ambient
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        [Self::Ambient, Self::Stored]
            .into_iter()
            .find(|source| source.as_str() == raw)
    }
}

/// The outcome of a test that passed.
const PASSED: &str = "ok";

/// The last test of a connection: when it ran and how it ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConnectionTest {
    /// When the test ran.
    #[serde(with = "time::serde::rfc3339")]
    pub tested_on: OffsetDateTime,
    /// `ok`, or the stable code of the error it ended with.
    pub outcome: String,
}

impl ConnectionTest {
    /// True when the test passed.
    pub fn passed(&self) -> bool {
        self.outcome == PASSED
    }
}

/// A connection as the vault keeps it, without its credentials.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConnectionInfo {
    /// The connection's id in this vault.
    pub id: String,
    /// The provider and how to reach it.
    pub settings: ConnectionSettings,
    /// Whether the vault stores its credentials.
    pub credentials: CredentialSource,
    /// When it was added.
    #[serde(with = "time::serde::rfc3339")]
    pub created_on: OffsetDateTime,
    /// The last test, until the settings or credentials change.
    pub last_test: Option<ConnectionTest>,
}

/// Where a secret's value is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretStorage {
    /// In the vault file.
    Vault,
    /// At the provider the connection with this id reaches.
    Connection(String),
}

/// What [`SqliteVault::record_at_connection`] does to the catalog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogChange {
    /// Nothing: the secret is catalogued at the connection already.
    Keep,
    /// Catalogue a new secret at the connection. The vault must have no
    /// secret of that name.
    Add,
    /// Take the secret's entry out: it was purged at the connection.
    Remove,
}

/// One change to a vault's connections, as [`SqliteVault::change_settings`]
/// makes it with the others in one transaction: what
/// [`SqliteVault::add_connection`], [`SqliteVault::set_connection_settings`],
/// [`SqliteVault::set_connection_credentials`] and
/// [`SqliteVault::remove_connection`] each do alone.
#[derive(Clone, Debug)]
pub enum ConnectionChange {
    /// Add a connection, with stored credentials or the ambient chain.
    Add {
        settings: ConnectionSettings,
        credentials: Option<Credentials>,
    },
    /// New settings for the connection `id`, for the same provider.
    Settings {
        id: String,
        settings: ConnectionSettings,
    },
    /// New credentials for the connection `id`, or none stored.
    Credentials {
        id: String,
        credentials: Option<Credentials>,
    },
    /// Remove the connection `id`.
    Remove { id: String },
}

/// AAD binding stored credentials to their vault and connection.
fn credentials_aad(vault_id: &str, id: &str) -> String {
    format!("sourceorrery/v4/connection/{vault_id}/{id}")
}

fn corrupt(id: &str) -> SecretError {
    SecretError::Storage(format!("corrupt connection {id}"))
}

fn no_such(id: &str) -> SecretError {
    SecretError::InvalidArgument(format!("the vault has no connection '{id}'"))
}

/// A `connections` row as stored.
struct ConnectionRow {
    id: String,
    kind: String,
    settings_json: String,
    credential_source: String,
    sealed_credentials: Option<String>,
    created_on: i64,
    last_test_on: Option<i64>,
    last_test_outcome: Option<String>,
    tag: Vec<u8>,
}

impl ConnectionRow {
    fn fields<'a>(&'a self, vault_id: &'a str) -> ConnectionFields<'a> {
        ConnectionFields {
            vault_id,
            id: &self.id,
            kind: &self.kind,
            settings_json: &self.settings_json,
            credential_source: &self.credential_source,
            sealed_credentials: self.sealed_credentials.as_deref(),
            created_on: self.created_on,
            last_test_on: self.last_test_on,
            last_test_outcome: self.last_test_outcome.as_deref(),
        }
    }

    fn settings(&self) -> Result<ConnectionSettings> {
        let settings: ConnectionSettings =
            serde_json::from_str(&self.settings_json).map_err(|_| corrupt(&self.id))?;
        if settings.provider().name() != self.kind {
            return Err(corrupt(&self.id));
        }
        Ok(settings)
    }

    fn info(&self) -> Result<ConnectionInfo> {
        let credentials =
            CredentialSource::parse(&self.credential_source).ok_or_else(|| corrupt(&self.id))?;
        if (credentials == CredentialSource::Stored) != self.sealed_credentials.is_some() {
            return Err(corrupt(&self.id));
        }
        let last_test = match (self.last_test_on, &self.last_test_outcome) {
            (Some(on), Some(outcome)) => Some(ConnectionTest {
                tested_on: from_nanos(on)?,
                outcome: outcome.clone(),
            }),
            (None, None) => None,
            _ => return Err(corrupt(&self.id)),
        };
        Ok(ConnectionInfo {
            id: self.id.clone(),
            settings: self.settings()?,
            credentials,
            created_on: from_nanos(self.created_on)?,
            last_test,
        })
    }

    /// Forget the last test: it was of other settings or credentials.
    fn untested(&mut self) {
        self.last_test_on = None;
        self.last_test_outcome = None;
    }
}

/// Every `connections` row, oldest first.
fn read_rows(conn: &Connection) -> Result<Vec<ConnectionRow>> {
    conn.prepare(
        "SELECT id, kind, settings_json, credential_source, sealed_credentials, created_on,
                last_test_on, last_test_outcome, tag
         FROM connections ORDER BY created_on, id",
    )
    .map_err(db)?
    .query_map([], |row| {
        Ok(ConnectionRow {
            id: row.get(0)?,
            kind: row.get(1)?,
            settings_json: row.get(2)?,
            credential_source: row.get(3)?,
            sealed_credentials: row.get(4)?,
            created_on: row.get(5)?,
            last_test_on: row.get(6)?,
            last_test_outcome: row.get(7)?,
            tag: row.get(8)?,
        })
    })
    .map_err(db)?
    .collect::<rusqlite::Result<_>>()
    .map_err(db)
}

/// The plaintext sealed for stored credentials: a kind label, then each
/// part, every one as a big-endian `u32` length and its bytes. It is built
/// in a buffer of exactly its size, so it never reallocates and leaves no
/// copy behind, and the buffer is wiped on drop.
fn encode_credentials(credentials: &Credentials) -> Result<Zeroizing<Vec<u8>>> {
    let parts: Vec<&[u8]> = match credentials {
        Credentials::VaultToken(token) => vec![b"vault-token".as_slice(), token.expose()],
        Credentials::AwsAccessKey {
            access_key_id,
            secret_access_key,
        } => vec![
            b"aws-access-key".as_slice(),
            access_key_id.as_bytes(),
            secret_access_key.expose(),
        ],
        Credentials::AzureClientSecret {
            tenant_id,
            client_id,
            client_secret,
        } => vec![
            b"azure-client-secret".as_slice(),
            tenant_id.as_bytes(),
            client_id.as_bytes(),
            client_secret.expose(),
        ],
    };
    let mut out = Zeroizing::new(Vec::with_capacity(
        parts.iter().map(|part| 4 + part.len()).sum(),
    ));
    for part in parts {
        let len = u32::try_from(part.len()).map_err(|_| {
            SecretError::InvalidArgument("the credentials are too large to store".to_owned())
        })?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(part);
    }
    Ok(out)
}

/// The credentials [`encode_credentials`] encoded, or `None` for bytes it
/// cannot have written.
fn decode_credentials(plain: &[u8]) -> Option<Credentials> {
    let mut parts = Vec::new();
    let mut rest = plain;
    while !rest.is_empty() {
        let (len, tail) = rest.split_first_chunk::<4>()?;
        let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
        if tail.len() < len {
            return None;
        }
        let (part, tail) = tail.split_at(len);
        parts.push(part);
        rest = tail;
    }
    let (kind, parts) = parts.split_first()?;
    let text = |part: &[u8]| String::from_utf8(part.to_vec()).ok();
    let secret = |part: &[u8]| SecretBytes::new(part.to_vec());
    match (std::str::from_utf8(kind).ok()?, parts) {
        ("vault-token", [token]) => Some(Credentials::VaultToken(secret(token))),
        ("aws-access-key", [id, key]) => Some(Credentials::AwsAccessKey {
            access_key_id: text(id)?,
            secret_access_key: secret(key),
        }),
        ("azure-client-secret", [tenant, client, key]) => Some(Credentials::AzureClientSecret {
            tenant_id: text(tenant)?,
            client_id: text(client)?,
            client_secret: secret(key),
        }),
        _ => None,
    }
}

/// Valid credentials for the provider `settings` reach.
fn check_credentials(credentials: &Credentials, settings: &ConnectionSettings) -> Result<()> {
    credentials.validate()?;
    credentials.check_for(settings)
}

impl SqliteVault {
    /// The settings record as the file holds it now, verified: the view
    /// check, and which connections and projects exist with which tags. Its
    /// tag must verify and be the newest settings checkpoint on the audit
    /// chain, as a row's must. While a detected truncation waits to be
    /// acknowledged the chain cannot say which checkpoint is newest (the
    /// missing events may have held it), so the tag alone is judged; the
    /// vault refuses every change then but what weighing the view check
    /// writes, and the acknowledgement records the record as it stands.
    pub(super) fn verified_meta(&self, conn: &Connection) -> Result<Meta> {
        let meta = read_meta(conn)?;
        if !integrity::verify_settings_tag(
            &self.metadata_key,
            &meta.settings_fields()?,
            meta.settings_tag.as_deref(),
        ) {
            return Err(SecretError::Crypto(
                "vault settings integrity check failed (the view check, a connection or a \
                 project was altered)"
                    .to_owned(),
            ));
        }
        if let Some(problem) = settings_problem(
            conn,
            &self.metadata_key,
            &self.meta.id,
            meta.settings_tag.as_deref(),
        )? && unacknowledged_truncations(conn, &self.metadata_key, &self.meta.id)?.is_empty()
        {
            return Err(SecretError::Crypto(settings_message(&problem)));
        }
        Ok(meta)
    }

    /// The connection rows `meta` lists, each with the tag it lists and a
    /// tag that verifies; a row edited, added or left out is refused.
    fn listed_rows(&self, conn: &Connection, meta: &Meta) -> Result<Vec<ConnectionRow>> {
        let rows = read_rows(conn)?;
        if rows.len() != meta.connections.len() {
            return Err(integrity_error("the vault's connections"));
        }
        for row in &rows {
            let listed = meta
                .connections
                .iter()
                .any(|(id, tag)| *id == row.id && *tag == row.tag);
            if !listed
                || !integrity::verify_connection_tag(
                    &self.metadata_key,
                    &row.fields(&self.meta.id),
                    Some(&row.tag),
                )
            {
                return Err(integrity_error(&format!("connection {}", row.id)));
            }
        }
        Ok(rows)
    }

    /// Every connection row, verified, in one read transaction so the rows
    /// and the record that lists them are read together.
    fn verified_rows(&self) -> Result<Vec<ConnectionRow>> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().map_err(db)?;
        let meta = self.verified_meta(&tx)?;
        self.listed_rows(&tx, &meta)
    }

    fn verified_row(&self, id: &str) -> Result<ConnectionRow> {
        self.verified_rows()?
            .into_iter()
            .find(|row| row.id == id)
            .ok_or_else(|| no_such(id))
    }

    /// Tag `row` and write it, updating the row with its id in place (the
    /// secrets it stores refer to that row).
    fn write_row(&self, conn: &Connection, row: &mut ConnectionRow) -> Result<()> {
        row.tag =
            integrity::connection_tag(&self.metadata_key, &row.fields(&self.meta.id)).to_vec();
        conn.execute(
            "INSERT INTO connections (id, kind, settings_json, credential_source,
                 sealed_credentials, created_on, last_test_on, last_test_outcome, tag)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET kind = excluded.kind,
                 settings_json = excluded.settings_json,
                 credential_source = excluded.credential_source,
                 sealed_credentials = excluded.sealed_credentials,
                 created_on = excluded.created_on, last_test_on = excluded.last_test_on,
                 last_test_outcome = excluded.last_test_outcome, tag = excluded.tag",
            params![
                row.id,
                row.kind,
                row.settings_json,
                row.credential_source,
                row.sealed_credentials,
                row.created_on,
                row.last_test_on,
                row.last_test_outcome,
                row.tag,
            ],
        )
        .map_err(db)?;
        Ok(())
    }

    fn seal_credentials(&self, id: &str, credentials: &Credentials) -> Result<String> {
        self.seal_bound(
            &credentials_aad(&self.meta.id, id),
            &encode_credentials(credentials)?,
        )
    }

    /// Change the connections in one transaction that passes the checks
    /// every operation passes: `change` gets the verified rows, writes what
    /// it changes and returns the result with the audit outcome and detail.
    /// The settings record then covers the rows as they are. A refusal is
    /// audited as a failure and nothing is written.
    fn change_connections<T>(
        &self,
        operation: AuditOperation,
        change: impl FnOnce(&Connection, Vec<ConnectionRow>) -> Result<(T, AuditOutcome, String)>,
    ) -> Result<T> {
        let mut conn = self.lock()?;
        let tx = self.begin(&mut conn, operation)?;
        let changed = self.verified_meta(&tx).and_then(|meta| {
            let rows = self.listed_rows(&tx, &meta)?;
            let changed = change(&tx, rows)?;
            let tag = write_settings_tag(&tx, &self.metadata_key, &meta)?;
            Ok((changed, tag))
        });
        let ((value, outcome, detail), tag) = match changed {
            Ok(changed) => changed,
            Err(err) => return self.fail(tx, operation, None, None, err),
        };
        self.audit_settings(&tx, operation, outcome, &detail, tag)?;
        tx.commit().map_err(db)?;
        Ok(value)
    }

    /// Like [`Self::change_connections`] for the one row `id`.
    fn change_connection<T>(
        &self,
        operation: AuditOperation,
        id: &str,
        change: impl FnOnce(&mut ConnectionRow) -> Result<(T, AuditOutcome, String)>,
    ) -> Result<T> {
        self.change_connections(operation, |conn, rows| {
            let mut row = rows
                .into_iter()
                .find(|row| row.id == id)
                .ok_or_else(|| no_such(id))?;
            let changed = change(&mut row)?;
            self.write_row(conn, &mut row)?;
            Ok(changed)
        })
    }

    /// The vault's connections, oldest first, without their credentials.
    pub fn connections(&self) -> Result<Vec<ConnectionInfo>> {
        self.verified_rows()?
            .iter()
            .map(ConnectionRow::info)
            .collect()
    }

    /// The connection `id`, without its credentials.
    pub fn connection(&self, id: &str) -> Result<ConnectionInfo> {
        self.verified_row(id)?.info()
    }

    /// The credentials the connection `id` stores, to open it with; `None`
    /// when it uses the provider's ambient chain. They are never shown: a
    /// caller passes them to the provider and drops them.
    pub fn connection_credentials(&self, id: &str) -> Result<Option<Credentials>> {
        let row = self.verified_row(id)?;
        let Some(sealed) = &row.sealed_credentials else {
            return Ok(None);
        };
        let plain = self.unseal_bound(
            &credentials_aad(&self.meta.id, id),
            sealed,
            "connection credentials",
        )?;
        let credentials = decode_credentials(&plain).ok_or_else(|| corrupt(id))?;
        check_credentials(&credentials, &row.settings()?)?;
        Ok(Some(credentials))
    }

    /// Add a connection to the provider `settings` reach, with stored
    /// `credentials` or, without, the provider's ambient chain. The settings
    /// and credentials are checked, and a vault that already has a
    /// connection to that provider refuses another (`invalid_argument`).
    /// Audited as `vault_change`.
    pub fn add_connection(
        &self,
        settings: &ConnectionSettings,
        credentials: Option<&Credentials>,
    ) -> Result<ConnectionInfo> {
        self.change_connections(AuditOperation::VaultChange, |conn, rows| {
            let (info, detail) = self.add_row(conn, &rows, settings, credentials)?;
            Ok((info, AuditOutcome::Success, detail))
        })
    }

    /// Replace the settings of the connection `id` with `settings` for the
    /// same provider (another provider needs a connection of its own). The
    /// credentials stay; the last test is forgotten. Audited as
    /// `vault_change`.
    pub fn set_connection_settings(
        &self,
        id: &str,
        settings: &ConnectionSettings,
    ) -> Result<ConnectionInfo> {
        self.change_connection(AuditOperation::VaultChange, id, |row| {
            let (info, detail) = Self::settings_row(row, id, settings)?;
            Ok((info, AuditOutcome::Success, detail))
        })
    }

    /// Store `credentials` for the connection `id`, or, with `None`, stop
    /// storing any so it uses the provider's ambient chain. The last test is
    /// forgotten. Audited as `vault_change`.
    pub fn set_connection_credentials(
        &self,
        id: &str,
        credentials: Option<&Credentials>,
    ) -> Result<ConnectionInfo> {
        self.change_connection(AuditOperation::VaultChange, id, |row| {
            let (info, detail) = self.credentials_row(row, id, credentials)?;
            Ok((info, AuditOutcome::Success, detail))
        })
    }

    /// Record a test of the connection `id` that ended with `result`: one
    /// metadata call the caller made to the provider. The outcome (`ok`, or
    /// the error's code) and the time are kept until the settings or the
    /// credentials change. Audited as `connection_test`, a failed test with
    /// outcome `failure`.
    pub fn record_connection_test(
        &self,
        id: &str,
        result: std::result::Result<(), &SecretError>,
    ) -> Result<ConnectionTest> {
        self.change_connection(AuditOperation::ConnectionTest, id, |row| {
            let (outcome, audited) = match result {
                Ok(()) => (PASSED.to_owned(), AuditOutcome::Success),
                Err(err) => (err.code().to_owned(), AuditOutcome::Failure),
            };
            let detail = format!("connection {id} tested: {outcome}");
            let test = ConnectionTest {
                tested_on: timestamp::now(),
                outcome,
            };
            row.last_test_on = Some(nanos(test.tested_on)?);
            row.last_test_outcome = Some(test.outcome.clone());
            Ok((test, audited, detail))
        })
    }

    /// Remove the connection `id` and the credentials it stores. A
    /// connection that still stores a secret is refused (`invalid_argument`,
    /// naming the secrets): purge them first. Audited as `vault_change`.
    pub fn remove_connection(&self, id: &str) -> Result<()> {
        self.change_connections(AuditOperation::VaultChange, |conn, rows| {
            let detail = self.remove_row(conn, &rows, id)?;
            Ok(((), AuditOutcome::Success, detail))
        })
    }

    /// Make `change` to the connections inside the caller's write
    /// transaction, with the checks every connection change passes, and
    /// return its audit detail with the settings tag it left; the caller
    /// records both.
    pub(super) fn apply_connection_change(
        &self,
        conn: &Connection,
        change: &ConnectionChange,
    ) -> Result<(String, SettingsTag)> {
        let meta = self.verified_meta(conn)?;
        let rows = self.listed_rows(conn, &meta)?;
        let row_of = |rows: Vec<ConnectionRow>, id: &str| {
            rows.into_iter()
                .find(|row| row.id == id)
                .ok_or_else(|| no_such(id))
        };
        let detail = match change {
            ConnectionChange::Add {
                settings,
                credentials,
            } => self.add_row(conn, &rows, settings, credentials.as_ref())?.1,
            ConnectionChange::Settings { id, settings } => {
                let mut row = row_of(rows, id)?;
                let (_, detail) = Self::settings_row(&mut row, id, settings)?;
                self.write_row(conn, &mut row)?;
                detail
            }
            ConnectionChange::Credentials { id, credentials } => {
                let mut row = row_of(rows, id)?;
                let (_, detail) = self.credentials_row(&mut row, id, credentials.as_ref())?;
                self.write_row(conn, &mut row)?;
                detail
            }
            ConnectionChange::Remove { id } => self.remove_row(conn, &rows, id)?,
        };
        let tag = write_settings_tag(conn, &self.metadata_key, &meta)?;
        Ok((detail, tag))
    }

    /// Check and write a new connection row; its info and audit detail.
    fn add_row(
        &self,
        conn: &Connection,
        rows: &[ConnectionRow],
        settings: &ConnectionSettings,
        credentials: Option<&Credentials>,
    ) -> Result<(ConnectionInfo, String)> {
        settings.validate()?;
        if let Some(credentials) = credentials {
            check_credentials(credentials, settings)?;
        }
        let provider = settings.provider();
        if rows.iter().any(|row| row.kind == provider.name()) {
            return Err(SecretError::InvalidArgument(format!(
                "the vault already has a connection to {}; change or remove it instead",
                provider.display_name()
            )));
        }
        let id = random::random_hex(8).map_err(crypto)?;
        let source = CredentialSource::of(credentials);
        let mut row = ConnectionRow {
            kind: provider.name().to_owned(),
            settings_json: serde_json::to_string(settings)
                .map_err(|err| SecretError::Storage(err.to_string()))?,
            credential_source: source.as_str().to_owned(),
            sealed_credentials: credentials
                .map(|credentials| self.seal_credentials(&id, credentials))
                .transpose()?,
            created_on: nanos(timestamp::now())?,
            last_test_on: None,
            last_test_outcome: None,
            tag: Vec::new(),
            id,
        };
        self.write_row(conn, &mut row)?;
        let detail = format!(
            "connection {} added: {provider}, {} credentials",
            row.id,
            source.as_str()
        );
        Ok((row.info()?, detail))
    }

    /// `row` with new settings for the same provider; its info and detail.
    fn settings_row(
        row: &mut ConnectionRow,
        id: &str,
        settings: &ConnectionSettings,
    ) -> Result<(ConnectionInfo, String)> {
        settings.validate()?;
        let current = row.settings()?.provider();
        if settings.provider() != current {
            return Err(SecretError::InvalidArgument(format!(
                "connection {id} reaches {}; settings for {} need a connection of their own",
                current.display_name(),
                settings.provider().display_name()
            )));
        }
        row.settings_json =
            serde_json::to_string(settings).map_err(|err| SecretError::Storage(err.to_string()))?;
        row.untested();
        Ok((row.info()?, format!("connection {id}: settings changed")))
    }

    /// `row` with new credentials, or none stored; its info and detail.
    fn credentials_row(
        &self,
        row: &mut ConnectionRow,
        id: &str,
        credentials: Option<&Credentials>,
    ) -> Result<(ConnectionInfo, String)> {
        if let Some(credentials) = credentials {
            check_credentials(credentials, &row.settings()?)?;
        }
        let source = CredentialSource::of(credentials);
        row.sealed_credentials = credentials
            .map(|credentials| self.seal_credentials(id, credentials))
            .transpose()?;
        source.as_str().clone_into(&mut row.credential_source);
        row.untested();
        let detail = match source {
            CredentialSource::Stored => format!("connection {id}: credentials stored"),
            CredentialSource::Ambient => {
                format!("connection {id}: credentials ambient, none stored")
            }
        };
        Ok((row.info()?, detail))
    }

    /// Delete the row `id` unless it still stores a secret; the detail.
    fn remove_row(&self, conn: &Connection, rows: &[ConnectionRow], id: &str) -> Result<String> {
        if !rows.iter().any(|row| row.id == id) {
            return Err(no_such(id));
        }
        let stored = self.names_at(conn, id)?;
        if !stored.is_empty() {
            const SHOWN: usize = 5;
            let mut named: Vec<String> = stored
                .iter()
                .take(SHOWN)
                .map(|n| format!("'{n}'"))
                .collect();
            if stored.len() > SHOWN {
                named.push(format!("{} more", stored.len() - SHOWN));
            }
            return Err(SecretError::InvalidArgument(format!(
                "connection {id} still stores {} secret(s) ({}); purge them before removing it",
                stored.len(),
                named.join(", ")
            )));
        }
        conn.execute("DELETE FROM connections WHERE id = ?1", params![id])
            .map_err(db)?;
        Ok(format!("connection {id} removed"))
    }

    // --- the catalog of secrets a connection stores ----------------------

    /// The names of the secrets the connection `id` stores, each one's row
    /// verified as the state the audit chain last recorded.
    fn names_at(&self, conn: &Connection, id: &str) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for name in query_names_at(conn, id)? {
            if self
                .load_secret_row(conn, &name)?
                .is_some_and(|row| row.storage.as_deref() == Some(id))
            {
                names.push(name);
            }
        }
        Ok(names)
    }

    /// The names of the secrets the connection `id` stores, in order.
    pub fn secrets_at(&self, id: &str) -> Result<Vec<String>> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().map_err(db)?;
        let meta = self.verified_meta(&tx)?;
        if !self.listed_rows(&tx, &meta)?.iter().any(|row| row.id == id) {
            return Err(no_such(id));
        }
        self.names_at(&tx, id)
    }

    /// Where the secret `name` is kept, or `None` when the vault has no
    /// secret of that name. A deleted secret in the file is still kept
    /// there. Not audited: it is how a caller routes the operation it then
    /// performs, which is.
    pub fn storage_of(&self, name: &str) -> Result<Option<SecretStorage>> {
        validate_secret_name(name)?;
        let mut conn = self.lock()?;
        let tx = conn.transaction().map_err(db)?;
        Ok(self.load_secret_row(&tx, name)?.map(|row| {
            row.storage
                .map_or(SecretStorage::Vault, SecretStorage::Connection)
        }))
    }

    /// Record in this vault what was done at the connection `connection` for
    /// the secret `name` (or, without one, for the connection as a whole,
    /// such as a listing): one audit row for `operation` about `version`,
    /// with the outcome (`at connection <id>`, and the error's code when it
    /// failed), and the catalog `change` it made, in one transaction. A
    /// change is made only when `result` is `Ok`, and needs a name. A secret
    /// that is not catalogued there (for [`CatalogChange::Keep`] and
    /// [`CatalogChange::Remove`]), or that the vault already has (for
    /// [`CatalogChange::Add`]), is refused and the refusal is recorded.
    pub fn record_at_connection(
        &self,
        connection: &str,
        operation: AuditOperation,
        name: Option<&str>,
        version: Option<&str>,
        result: std::result::Result<(), &SecretError>,
        change: CatalogChange,
    ) -> Result<()> {
        let mut conn = self.lock()?;
        let tx = self.begin(&mut conn, operation)?;
        let tx = match name {
            Some(name) => self.validated(tx, operation, name)?,
            None => tx,
        };
        let state = match self.catalog_change(&tx, connection, name, result.is_ok(), change) {
            Ok(state) => state,
            Err(err) => return self.fail(tx, operation, name, version, err),
        };
        let detail = match result {
            Ok(()) => format!("at connection {connection}"),
            Err(err) => format!("at connection {connection}: {}", err.code()),
        };
        match (name, result) {
            (Some(name), Ok(())) => self.audit_change(
                &tx,
                operation,
                name,
                version,
                Some(&detail),
                Checkpoints {
                    state,
                    version: None,
                    settings: None,
                },
            )?,
            (name, result) => self.audit(
                &tx,
                operation,
                name,
                version,
                result.err().map_or(AuditOutcome::Success, outcome_of),
                Some(&detail),
            )?,
        }
        tx.commit().map_err(db)
    }

    /// Check `name` against the catalog for `change` at `connection`, and
    /// make the change when `applied`; the state checkpoint it leaves.
    fn catalog_change(
        &self,
        conn: &Connection,
        connection: &str,
        name: Option<&str>,
        applied: bool,
        change: CatalogChange,
    ) -> Result<Option<Checkpoint>> {
        let meta = self.verified_meta(conn)?;
        if !self
            .listed_rows(conn, &meta)?
            .iter()
            .any(|row| row.id == connection)
        {
            return Err(no_such(connection));
        }
        let Some(name) = name else {
            return match change {
                CatalogChange::Keep => Ok(None),
                CatalogChange::Add | CatalogChange::Remove => Err(SecretError::InvalidArgument(
                    "a change to the catalog names a secret".to_owned(),
                )),
            };
        };
        match (self.load_secret_row(conn, name)?, change) {
            (None, CatalogChange::Add) if applied => {
                let row = SecretRow {
                    created_on: nanos(timestamp::now())?,
                    deleted_on: None,
                    scheduled_purge_on: None,
                    recovery_id: None,
                    storage: Some(connection.to_owned()),
                    description: None,
                };
                Ok(Some(Checkpoint::Present(
                    self.insert_secret(conn, name, &row)?,
                )))
            }
            (None, CatalogChange::Add) => Ok(None),
            (None, _) => Err(SecretError::NotFound {
                name: name.to_owned(),
            }),
            (Some(_), CatalogChange::Add) => Err(SecretError::InvalidArgument(format!(
                "the vault already has a secret '{name}'"
            ))),
            (Some(row), _) if row.storage.as_deref() != Some(connection) => {
                Err(SecretError::InvalidArgument(format!(
                    "secret '{name}' is not stored through connection {connection}"
                )))
            }
            (Some(_), CatalogChange::Remove) if applied => {
                Self::delete_secret_row(conn, name)?;
                Ok(Some(Checkpoint::Absent))
            }
            (Some(_), _) => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_round_trip_through_their_encoding() {
        let all = [
            Credentials::VaultToken(SecretBytes::from("hvs.token")),
            Credentials::AwsAccessKey {
                access_key_id: "AKIAEXAMPLE".to_owned(),
                secret_access_key: SecretBytes::from("secret"),
            },
            Credentials::AzureClientSecret {
                tenant_id: "tenant".to_owned(),
                client_id: "client".to_owned(),
                client_secret: SecretBytes::new(vec![0, 159, 146, 150]),
            },
        ];
        for credentials in all {
            let plain = encode_credentials(&credentials).unwrap();
            assert_eq!(plain.len(), plain.capacity(), "never reallocated");
            let back = decode_credentials(&plain).unwrap();
            assert_eq!(format!("{back:?}"), format!("{credentials:?}"));
            assert_eq!(
                encode_credentials(&back).unwrap().as_slice(),
                plain.as_slice()
            );
        }
    }

    #[test]
    fn bytes_the_encoding_cannot_have_written_are_refused() {
        let token = encode_credentials(&Credentials::VaultToken(SecretBytes::from("t"))).unwrap();
        let mut extra = token.to_vec();
        extra.extend_from_slice(&[0, 0, 0, 1, b'x']);
        for bad in [
            &[][..],
            &token[..token.len() - 1],
            &extra[..],
            &[0, 0, 0, 5, b'o', b't', b'h', b'e', b'r', 0, 0, 0, 0][..],
            &[0, 0, 0, 9][..],
        ] {
            assert!(decode_credentials(bad).is_none(), "{bad:?}");
        }
    }
}
