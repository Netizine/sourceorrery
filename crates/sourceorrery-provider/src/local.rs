//! `AsyncLocal`: an `AsyncSecretClient` over a synchronous `SecretClient`.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use sourceorrery_core::{
    AsyncSecretClient, AuditEvent, AuditQuery, Capability, DeletedSecret, ListOptions, Page,
    Result, Secret, SecretBytes, SecretClient, SecretError, SecretProperties, SecretReference,
    SetSecretOptions, UpdateSecretProperties,
};

/// An [`AsyncSecretClient`] that runs a [`SecretClient`] on Tokio's
/// blocking pool.
///
/// The local vault reads and writes a file, holding its connection lock
/// while it does; on an async executor that would stall every other task
/// on the thread. Each call here moves to a blocking thread, so an async
/// application reads a local vault through the same trait as a remote one.
/// The client is shared through an `Arc`, so the adapter is cheap to clone
/// and can be used from many tasks at once (the vault serialises its own
/// access).
///
/// Everything passes through unchanged, errors included. The one error the
/// adapter adds is [`SecretError::Storage`] when the blocking task itself
/// fails (it panicked or the runtime shut down), which never happens on a
/// healthy vault. The adapter must be called from inside a Tokio runtime,
/// which is where `spawn_blocking` finds its pool.
pub struct AsyncLocal<C> {
    inner: Arc<C>,
}

impl<C> AsyncLocal<C>
where
    C: SecretClient + Send + Sync + 'static,
{
    /// Wrap `client`.
    pub fn new(client: C) -> Self {
        Self {
            inner: Arc::new(client),
        }
    }

    /// Wrap a client that is already shared.
    pub fn from_arc(client: Arc<C>) -> Self {
        Self { inner: client }
    }

    /// The wrapped synchronous client.
    pub fn inner(&self) -> &C {
        &self.inner
    }

    /// Run `op` against the client on the blocking pool.
    async fn blocking<T, F>(&self, op: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&C) -> Result<T> + Send + 'static,
    {
        let client = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || op(&client))
            .await
            .map_err(|err| {
                let why = if err.is_panic() {
                    "panicked"
                } else {
                    "was cancelled"
                };
                SecretError::Storage(format!("the local vault's blocking task {why}"))
            })?
    }
}

impl<C> Clone for AsyncLocal<C> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<C: SecretClient> fmt::Debug for AsyncLocal<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncLocal")
            .field("vault", &self.inner.vault_name())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<C> AsyncSecretClient for AsyncLocal<C>
where
    C: SecretClient + Send + Sync + 'static,
{
    fn vault_name(&self) -> &str {
        self.inner.vault_name()
    }

    fn capabilities(&self) -> &'static [Capability] {
        self.inner.capabilities()
    }

    async fn set_secret(
        &self,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
    ) -> Result<SecretProperties> {
        let name = name.to_owned();
        self.blocking(move |c| c.set_secret(&name, value, options))
            .await
    }

    async fn get_secret(&self, name: &str, version: Option<&str>) -> Result<Secret> {
        let (name, version) = (name.to_owned(), version.map(str::to_owned));
        self.blocking(move |c| c.get_secret(&name, version.as_deref()))
            .await
    }

    async fn get_secret_properties(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<SecretProperties> {
        let (name, version) = (name.to_owned(), version.map(str::to_owned));
        self.blocking(move |c| c.get_secret_properties(&name, version.as_deref()))
            .await
    }

    async fn list_properties_of_secrets(&self) -> Result<Vec<SecretProperties>> {
        self.blocking(SecretClient::list_properties_of_secrets)
            .await
    }

    async fn list_properties_of_secrets_page(
        &self,
        options: ListOptions,
    ) -> Result<Page<SecretProperties>> {
        self.blocking(move |c| c.list_properties_of_secrets_page(options))
            .await
    }

    async fn list_properties_of_secret_versions(
        &self,
        name: &str,
    ) -> Result<Vec<SecretProperties>> {
        let name = name.to_owned();
        self.blocking(move |c| c.list_properties_of_secret_versions(&name))
            .await
    }

    async fn update_secret_properties(
        &self,
        name: &str,
        version: Option<&str>,
        update: UpdateSecretProperties,
    ) -> Result<SecretProperties> {
        let (name, version) = (name.to_owned(), version.map(str::to_owned));
        self.blocking(move |c| c.update_secret_properties(&name, version.as_deref(), update))
            .await
    }

    async fn delete_secret(&self, name: &str) -> Result<DeletedSecret> {
        let name = name.to_owned();
        self.blocking(move |c| c.delete_secret(&name)).await
    }

    async fn get_deleted_secret(&self, name: &str) -> Result<DeletedSecret> {
        let name = name.to_owned();
        self.blocking(move |c| c.get_deleted_secret(&name)).await
    }

    async fn list_deleted_secrets(&self) -> Result<Vec<DeletedSecret>> {
        self.blocking(SecretClient::list_deleted_secrets).await
    }

    async fn list_deleted_secrets_page(&self, options: ListOptions) -> Result<Page<DeletedSecret>> {
        self.blocking(move |c| c.list_deleted_secrets_page(options))
            .await
    }

    async fn recover_deleted_secret(&self, name: &str) -> Result<SecretProperties> {
        let name = name.to_owned();
        self.blocking(move |c| c.recover_deleted_secret(&name))
            .await
    }

    async fn purge_deleted_secret(&self, name: &str) -> Result<()> {
        let name = name.to_owned();
        self.blocking(move |c| c.purge_deleted_secret(&name)).await
    }

    async fn audit_events(&self, query: AuditQuery) -> Result<Vec<AuditEvent>> {
        self.blocking(move |c| c.audit_events(query)).await
    }

    async fn resolve(&self, reference: &SecretReference) -> Result<Secret> {
        let reference = reference.clone();
        self.blocking(move |c| c.resolve(&reference)).await
    }
}
