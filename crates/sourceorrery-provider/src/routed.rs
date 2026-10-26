//! Routing (ADR 0009, section 5): one vault over every storage it uses.
//!
//! [`Routed`] is a [`SecretClient`] over a local vault ([`SqliteVault`])
//! that sends each call to where the secret is kept: the vault file, or the
//! provider a connection of the vault reaches. The contract does not change.
//! Choosing the storage of a new secret is `Routed`'s own
//! ([`Routed::storing_new_in`], [`Routed::set_secret_in`]); every existing
//! secret is routed by the vault's catalog ([`SqliteVault::storage_of`]).
//!
//! What a provider did is recorded in the vault's own audit log, with the
//! connection in the detail ([`SqliteVault::record_at_connection`]), and the
//! catalog follows in the same step: a secret created at a provider is
//! catalogued, and one purged there leaves the catalog. A failure on either
//! side is returned, never half-applied silently. A connection is opened
//! when first needed, with the credentials it stores or else the provider's
//! ambient chain, and stays open while the connection is unchanged: once its
//! settings or credentials change, through this vault or another handle, the
//! next call opens it again from the vault.
//!
//! A change (set, update, delete, recover, purge) is recorded as an attempt
//! before it is sent ([`SqliteVault::attempt_at_connection`]), and its
//! result says whether it may have happened (ADR 0011): a refusal is
//! returned as the provider gave it; any other failure, and a change the
//! provider made that the vault could not record, is `outcome_unknown`.
//! Nothing is retried; [`SqliteVault::unresolved_attempts`] lists the
//! changes whose result the vault never learned.
//!
//! Listings show every storage. While no connection stores a secret they
//! are the vault's own; otherwise a listing reads the vault and every
//! connection that stores something, keeps the provider's secrets that the
//! catalog names (a provider may hold others), and pages the merged list by
//! name. A provider that cannot be reached fails the listing. A secret a
//! provider no longer has, deleted there out of band, is not hidden:
//! [`Routed::missing`] reports it, reading it fails with the provider's
//! `not_found`, and [`Routed::forget_missing`] takes it out of the catalog.
//!
//! Routing is dispatch only: policy, version selection and error mapping
//! are the vault's or the provider's, passed through unchanged.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use sourceorrery_core::audit::{AuditEvent, AuditOperation, AuditQuery};
use sourceorrery_core::{
    Capability, ConnectionSettings, Credentials, DeletedSecret, ListOptions, Page, Result, Secret,
    SecretBytes, SecretClient, SecretError, SecretProperties, SetSecretOptions,
    UpdateSecretProperties,
};
use sourceorrery_storage::{
    Attempt, CatalogChange, ConnectionRevision, SecretStorage, SqliteVault,
};

/// A provider's client, as [`Routed`] holds it.
pub type ConnectionClient = Box<dyn SecretClient + Send + Sync>;

/// Opens the client for a connection, given the vault's name, the
/// connection's settings and the credentials it stores, if any. The default
/// is [`crate::open_connection`].
pub type Opener = dyn Fn(&str, &ConnectionSettings, Option<&Credentials>) -> Result<ConnectionClient>
    + Send
    + Sync;

/// A secret the catalog names that its provider no longer has, live or
/// deleted: removed there out of band.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissingSecret {
    /// The secret.
    pub name: String,
    /// The connection the catalog says stores it.
    pub connection: String,
}

/// A [`SecretClient`] over a vault and the providers its connections reach,
/// routing each call by where the secret is kept. See the module
/// documentation.
pub struct Routed {
    vault: SqliteVault,
    new_in: SecretStorage,
    new_capabilities: &'static [Capability],
    opener: Box<Opener>,
    open: Mutex<BTreeMap<String, OpenClient>>,
}

/// A connection's client and the revision of the connection it was opened
/// from.
type OpenClient = (ConnectionRevision, Arc<dyn SecretClient + Send + Sync>);

impl fmt::Debug for Routed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let open: Vec<String> = self
            .open
            .lock()
            .map(|open| open.keys().cloned().collect())
            .unwrap_or_default();
        f.debug_struct("Routed")
            .field("vault", &self.vault)
            .field("new_in", &self.new_in)
            .field("open", &open)
            .finish_non_exhaustive()
    }
}

/// Where a call goes.
enum Route {
    /// The vault file keeps the secret.
    Vault,
    /// The vault has no secret of that name.
    New,
    /// The connection with this id stores it.
    At(String),
}

/// What a call at a connection is recorded as.
#[derive(Clone, Copy)]
struct Record<'a> {
    operation: AuditOperation,
    name: Option<&'a str>,
    /// The version asked for; the one the provider answered about is
    /// recorded when there is one.
    version: Option<&'a str>,
    change: CatalogChange,
}

impl<'a> Record<'a> {
    fn of(operation: AuditOperation, name: &'a str, version: Option<&'a str>) -> Self {
        Self {
            operation,
            name: Some(name),
            version,
            change: CatalogChange::Keep,
        }
    }

    fn listing() -> Self {
        Self {
            operation: AuditOperation::SecretList,
            name: None,
            version: None,
            change: CatalogChange::Keep,
        }
    }

    fn changing(self, change: CatalogChange) -> Self {
        Self { change, ..self }
    }
}

#[allow(clippy::needless_pass_by_value)] // used as a `map_err` function
fn poisoned<T>(_: T) -> SecretError {
    SecretError::Storage("the routed client's connection cache was poisoned".to_owned())
}

fn open_default(
    vault: &str,
    settings: &ConnectionSettings,
    credentials: Option<&Credentials>,
) -> Result<ConnectionClient> {
    crate::open_connection(vault, settings, credentials).map(|remote| remote.client)
}

/// The connections that store a secret, each with the names it stores, in
/// order.
type Stored = BTreeMap<String, Vec<String>>;

impl Routed {
    /// Route over `vault`, opening connections with
    /// [`crate::open_connection`]. New secrets go into the vault file until
    /// [`Self::storing_new_in`] says otherwise.
    pub fn new(vault: SqliteVault) -> Self {
        Self::with_opener(vault, open_default)
    }

    /// [`Self::new`] with connections opened by `opener`: a test's own
    /// client, or a provider's client built another way.
    pub fn with_opener(
        vault: SqliteVault,
        opener: impl Fn(&str, &ConnectionSettings, Option<&Credentials>) -> Result<ConnectionClient>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        let new_capabilities = vault.capabilities();
        Self {
            vault,
            new_in: SecretStorage::Vault,
            new_capabilities,
            opener: Box::new(opener),
            open: Mutex::new(BTreeMap::new()),
        }
    }

    /// Keep new secrets in `storage`: the vault file, or a connection of
    /// the vault (`invalid_argument` when it has none with that id).
    /// [`SecretClient::capabilities`] then reports that storage's.
    pub fn storing_new_in(mut self, storage: SecretStorage) -> Result<Self> {
        self.new_capabilities = match &storage {
            SecretStorage::Vault => self.vault.capabilities(),
            SecretStorage::Connection(id) => self
                .vault
                .connection(id)?
                .settings
                .provider()
                .capabilities(),
        };
        self.new_in = storage;
        Ok(self)
    }

    /// The vault: its connections, catalog and settings.
    pub fn vault(&self) -> &SqliteVault {
        &self.vault
    }

    /// Where new secrets go.
    pub fn new_secrets_in(&self) -> &SecretStorage {
        &self.new_in
    }

    fn route(&self, name: &str) -> Route {
        match self.vault.storage_of(name) {
            Ok(Some(SecretStorage::Connection(id))) => Route::At(id),
            Ok(None) => Route::New,
            // The vault answers, and records, a name it refuses or a row it
            // cannot verify.
            Ok(Some(SecretStorage::Vault)) | Err(_) => Route::Vault,
        }
    }

    /// The client of the connection `id` as the gate found it at
    /// `revision`: the one opened earlier while the connection is unchanged,
    /// else opened now from the vault and kept in its place. A client
    /// opened from settings or credentials the vault no longer has is never
    /// called again.
    fn client(
        &self,
        id: &str,
        revision: &ConnectionRevision,
    ) -> Result<Arc<dyn SecretClient + Send + Sync>> {
        if let Some((opened_at, client)) = self.open.lock().map_err(poisoned)?.get(id)
            && opened_at == revision
        {
            return Ok(Arc::clone(client));
        }
        let connection = self.vault.connection_to_open(id)?;
        let opened: Arc<dyn SecretClient + Send + Sync> = Arc::from((self.opener)(
            self.vault.vault_name(),
            &connection.settings,
            connection.credentials.as_ref(),
        )?);
        drop(connection.credentials);
        self.open
            .lock()
            .map_err(poisoned)?
            .insert(id.to_owned(), (connection.revision, Arc::clone(&opened)));
        Ok(opened)
    }

    /// Make `call` at the connection `id` and record it in the vault as
    /// `record` says, with the version `version_of` finds in the answer.
    ///
    /// Every call at a connection passes here, and the vault's own gate
    /// comes first ([`SqliteVault::preflight_at_connection`]): a vault whose
    /// log was truncated, whose settings or connection row do not verify,
    /// or whose catalog does not have the secret there, sends nothing to
    /// the provider, also through a client opened earlier.
    ///
    /// A change is recorded as an attempt before it is sent, and what it
    /// returns says whether it may have happened (ADR 0011): a refusal as
    /// the provider gave it, any other failure as `outcome_unknown`
    /// ([`SecretError::after_change_sent`]), and a change the provider made
    /// that the vault then could not record as `outcome_unknown` too, never
    /// as the vault's error alone.
    fn at<T>(
        &self,
        id: &str,
        record: Record<'_>,
        call: impl FnOnce(&dyn SecretClient) -> Result<T>,
        version_of: impl FnOnce(&T) -> Option<&str>,
    ) -> Result<T> {
        let revision =
            self.vault
                .preflight_at_connection(id, record.operation, record.name, record.change)?;
        let client = match self.client(id, &revision) {
            Ok(client) => client,
            Err(err) => {
                // Nothing was sent: the connection could not be opened.
                self.record(id, record, record.version, Err(&err), None)?;
                return Err(err);
            }
        };
        let attempt = match record.name {
            Some(name) if record.operation.changes_a_secret() => Some(
                self.vault
                    .attempt_at_connection(id, record.operation, name, record.change)?,
            ),
            _ => None,
        };
        let outcome = match call(&*client) {
            Err(err) if attempt.is_some() => Err(err.after_change_sent(&at(id))),
            outcome => outcome,
        };
        let version = match &outcome {
            Ok(value) => version_of(value).or(record.version).map(str::to_owned),
            Err(_) => record.version.map(str::to_owned),
        };
        let recorded = self.record(
            id,
            record,
            version.as_deref(),
            outcome.as_ref().map(drop),
            attempt,
        );
        match (recorded, outcome) {
            (Ok(()), outcome) => outcome,
            (Err(err), Ok(_)) if attempt.is_some() => Err(SecretError::OutcomeUnknown {
                at: at(id),
                reason: format!(
                    "the provider answered that it made the change, and this vault could not record it: \
                     {err}"
                ),
            }),
            (Err(_), Err(unknown @ SecretError::OutcomeUnknown { .. })) => Err(unknown),
            (Err(err), _) => Err(err),
        }
    }

    /// [`SqliteVault::record_at_connection`] for a call `at` makes.
    fn record(
        &self,
        id: &str,
        record: Record<'_>,
        version: Option<&str>,
        result: std::result::Result<(), &SecretError>,
        attempt: Option<Attempt>,
    ) -> Result<()> {
        self.vault.record_at_connection(
            id,
            record.operation,
            record.name,
            version,
            result,
            record.change,
            attempt,
        )
    }

    fn set_at(
        &self,
        id: &str,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
        change: CatalogChange,
    ) -> Result<SecretProperties> {
        self.at(
            id,
            Record::of(AuditOperation::SecretSet, name, None).changing(change),
            |client| client.set_secret(name, value, options),
            |props| Some(props.version.as_str()),
        )
    }

    /// Write `value` as a new version of `name` in `storage`: for a new
    /// secret, the storage it is created in. A secret kept elsewhere is
    /// refused (`invalid_argument`); its new versions go where it is.
    pub fn set_secret_in(
        &self,
        storage: &SecretStorage,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
    ) -> Result<SecretProperties> {
        match (self.route(name), storage) {
            (Route::New, SecretStorage::Connection(id)) => {
                self.set_at(id, name, value, options, CatalogChange::Add)
            }
            (Route::At(at), SecretStorage::Connection(id)) if at == *id => {
                self.set_at(id, name, value, options, CatalogChange::Keep)
            }
            (Route::New | Route::Vault, SecretStorage::Vault) => {
                self.vault.set_secret(name, value, options)
            }
            (Route::At(at), _) => Err(SecretError::InvalidArgument(format!(
                "secret '{name}' is stored through connection {at}; its new versions go there"
            ))),
            (Route::Vault, SecretStorage::Connection(_)) => Err(SecretError::InvalidArgument(
                format!("secret '{name}' is kept in the vault file; its new versions go there"),
            )),
        }
    }

    /// The connections that store a secret, with the names each stores.
    fn stored(&self) -> Result<Stored> {
        let mut stored = Stored::new();
        for connection in self.vault.connections()? {
            let names = self.vault.secrets_at(&connection.id)?;
            if !names.is_empty() {
                stored.insert(connection.id, names);
            }
        }
        Ok(stored)
    }

    fn live(&self, stored: &Stored) -> Result<Vec<SecretProperties>> {
        let mut items = self.vault.list_properties_of_secrets()?;
        for (id, names) in stored {
            items.extend(self.live_at(id, names)?);
        }
        items.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(items)
    }

    fn deleted(&self, stored: &Stored) -> Result<Vec<DeletedSecret>> {
        let mut items = self.vault.list_deleted_secrets()?;
        for (id, names) in stored {
            items.extend(self.deleted_at(id, names)?);
        }
        items.sort_by(|a, b| a.properties.name.cmp(&b.properties.name));
        Ok(items)
    }

    /// The live secrets of `names` at the connection `id`: one listing
    /// there, recorded in the vault.
    fn live_at(&self, id: &str, names: &[String]) -> Result<Vec<SecretProperties>> {
        let listed = self.at(
            id,
            Record::listing(),
            |client| client.list_properties_of_secrets(),
            |_| None,
        )?;
        Ok(listed
            .into_iter()
            .filter(|props| names.binary_search(&props.name).is_ok())
            .collect())
    }

    /// The deleted secrets of `names` at the connection `id`: one listing
    /// there, recorded in the vault.
    fn deleted_at(&self, id: &str, names: &[String]) -> Result<Vec<DeletedSecret>> {
        let listed = self.at(
            id,
            Record::listing(),
            |client| client.list_deleted_secrets(),
            |_| None,
        )?;
        Ok(listed
            .into_iter()
            .filter(|deleted| names.binary_search(&deleted.properties.name).is_ok())
            .collect())
    }

    /// The live secrets the vault keeps at the connection `id`, by name:
    /// one listing at its provider, recorded in the vault. A listing of
    /// every storage fails when one provider does; this is how a caller
    /// lists each on its own and says which could not be reached.
    pub fn list_at(&self, id: &str) -> Result<Vec<SecretProperties>> {
        let names = self.vault.secrets_at(id)?;
        if names.is_empty() {
            return Ok(Vec::new());
        }
        self.live_at(id, &names)
    }

    /// The deleted secrets the vault keeps at the connection `id`, as
    /// [`Self::list_at`] lists the live ones.
    pub fn list_deleted_at(&self, id: &str) -> Result<Vec<DeletedSecret>> {
        let names = self.vault.secrets_at(id)?;
        if names.is_empty() {
            return Ok(Vec::new());
        }
        self.deleted_at(id, &names)
    }

    /// The secrets the catalog names that their provider no longer has,
    /// live or deleted, by connection and name.
    pub fn missing(&self) -> Result<Vec<MissingSecret>> {
        let mut missing = Vec::new();
        for (id, names) in self.stored()? {
            let live = self.at(
                &id,
                Record::listing(),
                |client| client.list_properties_of_secrets(),
                |_| None,
            )?;
            let deleted = self.at(
                &id,
                Record::listing(),
                |client| client.list_deleted_secrets(),
                |_| None,
            )?;
            for name in names {
                let there = live.iter().any(|props| props.name == name)
                    || deleted.iter().any(|gone| gone.properties.name == name);
                if !there {
                    missing.push(MissingSecret {
                        name,
                        connection: id.clone(),
                    });
                }
            }
        }
        Ok(missing)
    }

    /// Take `name` out of the catalog once its provider has confirmed it no
    /// longer has it, live or deleted (`invalid_argument` while it does).
    /// Audited as `vault_change`, after the two reads that confirmed it.
    pub fn forget_missing(&self, name: &str) -> Result<()> {
        let Route::At(id) = self.route(name) else {
            return Err(SecretError::InvalidArgument(format!(
                "secret '{name}' is not stored through a connection"
            )));
        };
        let inspect = Record::of(AuditOperation::SecretInspect, name, None);
        let live = self.at(
            &id,
            inspect,
            |client| client.get_secret_properties(name, None),
            |props| Some(props.version.as_str()),
        );
        let deleted = self.at(
            &id,
            inspect,
            |client| client.get_deleted_secret(name),
            |gone| Some(gone.properties.version.as_str()),
        );
        let gone = |result: &Result<_>| matches!(result, Err(SecretError::NotFound { .. }));
        if !gone(&live.map(drop)) || !gone(&deleted.map(drop)) {
            return Err(SecretError::InvalidArgument(format!(
                "connection {id} still has secret '{name}'; purge it there through this vault"
            )));
        }
        self.vault.record_at_connection(
            &id,
            AuditOperation::VaultChange,
            Some(name),
            None,
            Ok(()),
            CatalogChange::Remove,
            None,
        )
    }
}

/// Where a change at the connection `id` may have been made, as
/// `outcome_unknown` names it.
fn at(id: &str) -> String {
    format!("connection {id}")
}

impl SecretClient for Routed {
    fn vault_name(&self) -> &str {
        self.vault.vault_name()
    }

    /// Those of the storage new secrets go to.
    fn capabilities(&self) -> &'static [Capability] {
        self.new_capabilities
    }

    fn capabilities_of(&self, name: &str) -> Result<&'static [Capability]> {
        match self.route(name) {
            Route::At(id) => Ok(self
                .vault
                .connection(&id)?
                .settings
                .provider()
                .capabilities()),
            Route::Vault => Ok(self.vault.capabilities()),
            Route::New => Ok(self.new_capabilities),
        }
    }

    fn set_secret(
        &self,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
    ) -> Result<SecretProperties> {
        match self.route(name) {
            Route::At(id) => self.set_at(&id, name, value, options, CatalogChange::Keep),
            Route::New => match &self.new_in {
                SecretStorage::Connection(id) => {
                    self.set_at(id, name, value, options, CatalogChange::Add)
                }
                SecretStorage::Vault => self.vault.set_secret(name, value, options),
            },
            Route::Vault => self.vault.set_secret(name, value, options),
        }
    }

    fn get_secret(&self, name: &str, version: Option<&str>) -> Result<Secret> {
        match self.route(name) {
            Route::At(id) => self.at(
                &id,
                Record::of(AuditOperation::SecretGet, name, version),
                |client| client.get_secret(name, version),
                |secret| Some(secret.properties.version.as_str()),
            ),
            Route::Vault | Route::New => self.vault.get_secret(name, version),
        }
    }

    fn get_secret_properties(&self, name: &str, version: Option<&str>) -> Result<SecretProperties> {
        match self.route(name) {
            Route::At(id) => self.at(
                &id,
                Record::of(AuditOperation::SecretInspect, name, version),
                |client| client.get_secret_properties(name, version),
                |props| Some(props.version.as_str()),
            ),
            Route::Vault | Route::New => self.vault.get_secret_properties(name, version),
        }
    }

    fn list_properties_of_secrets(&self) -> Result<Vec<SecretProperties>> {
        self.live(&self.stored()?)
    }

    fn list_properties_of_secrets_page(
        &self,
        options: ListOptions,
    ) -> Result<Page<SecretProperties>> {
        let stored = self.stored()?;
        if stored.is_empty() {
            return self.vault.list_properties_of_secrets_page(options);
        }
        Page::from_sorted(self.live(&stored)?, &options, |props| &props.name)
    }

    fn list_properties_of_secret_versions(&self, name: &str) -> Result<Vec<SecretProperties>> {
        match self.route(name) {
            Route::At(id) => self.at(
                &id,
                Record::of(AuditOperation::SecretInspect, name, None),
                |client| client.list_properties_of_secret_versions(name),
                |_| None,
            ),
            Route::Vault | Route::New => self.vault.list_properties_of_secret_versions(name),
        }
    }

    fn update_secret_properties(
        &self,
        name: &str,
        version: Option<&str>,
        update: UpdateSecretProperties,
    ) -> Result<SecretProperties> {
        match self.route(name) {
            Route::At(id) => self.at(
                &id,
                Record::of(AuditOperation::SecretUpdate, name, version),
                |client| client.update_secret_properties(name, version, update),
                |props| Some(props.version.as_str()),
            ),
            Route::Vault | Route::New => self.vault.update_secret_properties(name, version, update),
        }
    }

    fn delete_secret(&self, name: &str) -> Result<DeletedSecret> {
        match self.route(name) {
            Route::At(id) => self.at(
                &id,
                Record::of(AuditOperation::SecretDelete, name, None),
                |client| client.delete_secret(name),
                |deleted| Some(deleted.properties.version.as_str()),
            ),
            Route::Vault | Route::New => self.vault.delete_secret(name),
        }
    }

    fn get_deleted_secret(&self, name: &str) -> Result<DeletedSecret> {
        match self.route(name) {
            Route::At(id) => self.at(
                &id,
                Record::of(AuditOperation::SecretInspect, name, None),
                |client| client.get_deleted_secret(name),
                |deleted| Some(deleted.properties.version.as_str()),
            ),
            Route::Vault | Route::New => self.vault.get_deleted_secret(name),
        }
    }

    fn list_deleted_secrets(&self) -> Result<Vec<DeletedSecret>> {
        self.deleted(&self.stored()?)
    }

    fn list_deleted_secrets_page(&self, options: ListOptions) -> Result<Page<DeletedSecret>> {
        let stored = self.stored()?;
        if stored.is_empty() {
            return self.vault.list_deleted_secrets_page(options);
        }
        Page::from_sorted(self.deleted(&stored)?, &options, |deleted| {
            &deleted.properties.name
        })
    }

    fn recover_deleted_secret(&self, name: &str) -> Result<SecretProperties> {
        match self.route(name) {
            Route::At(id) => self.at(
                &id,
                Record::of(AuditOperation::SecretRecover, name, None),
                |client| client.recover_deleted_secret(name),
                |props| Some(props.version.as_str()),
            ),
            Route::Vault | Route::New => self.vault.recover_deleted_secret(name),
        }
    }

    fn purge_deleted_secret(&self, name: &str) -> Result<()> {
        match self.route(name) {
            Route::At(id) => self.at(
                &id,
                Record::of(AuditOperation::SecretPurge, name, None).changing(CatalogChange::Remove),
                |client| client.purge_deleted_secret(name),
                |()| None,
            ),
            Route::Vault | Route::New => self.vault.purge_deleted_secret(name),
        }
    }

    /// The vault's log, which records what was done at every connection.
    fn audit_events(&self, query: AuditQuery) -> Result<Vec<AuditEvent>> {
        self.vault.audit_events(query)
    }
}
