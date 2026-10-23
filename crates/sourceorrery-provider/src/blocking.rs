//! `Blocking`: a synchronous `SecretClient` over an `AsyncSecretClient`.

use std::fmt;
use std::future::Future;

use sourceorrery_core::{
    AsyncSecretClient, AuditEvent, AuditQuery, DeletedSecret, ListOptions, Page, Result, Secret,
    SecretBytes, SecretClient, SecretError, SecretProperties, SecretReference, SetSecretOptions,
    UpdateSecretProperties,
};
use tokio::runtime::{Handle, Runtime};

/// Where a [`Blocking`] adapter runs its futures.
enum Driver {
    /// A current-thread runtime the adapter created and owns.
    Owned(Runtime),
    /// A runtime the caller runs; the adapter only borrows it.
    Shared(Handle),
}

impl Driver {
    fn block_on<F: Future>(&self, future: F) -> F::Output {
        match self {
            Self::Owned(runtime) => runtime.block_on(future),
            Self::Shared(handle) => handle.block_on(future),
        }
    }
}

/// A [`SecretClient`] that drives an [`AsyncSecretClient`] to completion on
/// each call.
///
/// Every operation is forwarded unchanged and returns what the async client
/// returned, errors included, so a remote provider behind this adapter
/// behaves exactly as the contract describes to a caller that only knows
/// the synchronous shape: the CLI, the C ABI and every SDK built on it.
///
/// [`Blocking::new`] gives the adapter a small current-thread runtime of its
/// own (Tokio's blocking pool, which [`crate::AsyncLocal`] uses, starts
/// threads only on demand). [`Blocking::with_handle`] borrows a runtime the
/// application already runs instead. Either way a call blocks the calling
/// thread until the operation completes, so an adapter must not be used
/// from inside an async task: Tokio refuses to block a runtime thread and
/// panics. From async code use the [`AsyncSecretClient`] directly.
pub struct Blocking<A> {
    inner: A,
    driver: Driver,
}

impl<A: AsyncSecretClient> Blocking<A> {
    /// Wrap `client` with a current-thread runtime of its own.
    ///
    /// Fails with [`SecretError::Io`] when the runtime cannot be created
    /// (the operating system refused the resources it needs).
    pub fn new(client: A) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| SecretError::Io(format!("cannot start the client's runtime: {err}")))?;
        Ok(Self {
            inner: client,
            driver: Driver::Owned(runtime),
        })
    }

    /// Wrap `client`, running its futures on the runtime behind `handle`.
    ///
    /// The calling thread must not belong to that runtime: a call from an
    /// async task on it would deadlock a current-thread runtime, which
    /// Tokio prevents by panicking.
    pub fn with_handle(client: A, handle: Handle) -> Self {
        Self {
            inner: client,
            driver: Driver::Shared(handle),
        }
    }

    /// The wrapped async client.
    pub fn inner(&self) -> &A {
        &self.inner
    }

    /// Unwrap the async client, dropping the adapter's runtime.
    pub fn into_inner(self) -> A {
        self.inner
    }

    fn run<F: Future>(&self, future: F) -> F::Output {
        self.driver.block_on(future)
    }
}

impl<A: AsyncSecretClient> fmt::Debug for Blocking<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Blocking")
            .field("vault", &self.inner.vault_name())
            .field(
                "runtime",
                &match self.driver {
                    Driver::Owned(_) => "owned",
                    Driver::Shared(_) => "shared",
                },
            )
            .finish_non_exhaustive()
    }
}

impl<A: AsyncSecretClient> SecretClient for Blocking<A> {
    fn vault_name(&self) -> &str {
        self.inner.vault_name()
    }

    fn set_secret(
        &self,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
    ) -> Result<SecretProperties> {
        self.run(self.inner.set_secret(name, value, options))
    }

    fn get_secret(&self, name: &str, version: Option<&str>) -> Result<Secret> {
        self.run(self.inner.get_secret(name, version))
    }

    fn get_secret_properties(&self, name: &str, version: Option<&str>) -> Result<SecretProperties> {
        self.run(self.inner.get_secret_properties(name, version))
    }

    fn list_properties_of_secrets(&self) -> Result<Vec<SecretProperties>> {
        self.run(self.inner.list_properties_of_secrets())
    }

    fn list_properties_of_secrets_page(
        &self,
        options: ListOptions,
    ) -> Result<Page<SecretProperties>> {
        self.run(self.inner.list_properties_of_secrets_page(options))
    }

    fn list_properties_of_secret_versions(&self, name: &str) -> Result<Vec<SecretProperties>> {
        self.run(self.inner.list_properties_of_secret_versions(name))
    }

    fn update_secret_properties(
        &self,
        name: &str,
        version: Option<&str>,
        update: UpdateSecretProperties,
    ) -> Result<SecretProperties> {
        self.run(self.inner.update_secret_properties(name, version, update))
    }

    fn delete_secret(&self, name: &str) -> Result<DeletedSecret> {
        self.run(self.inner.delete_secret(name))
    }

    fn get_deleted_secret(&self, name: &str) -> Result<DeletedSecret> {
        self.run(self.inner.get_deleted_secret(name))
    }

    fn list_deleted_secrets(&self) -> Result<Vec<DeletedSecret>> {
        self.run(self.inner.list_deleted_secrets())
    }

    fn list_deleted_secrets_page(&self, options: ListOptions) -> Result<Page<DeletedSecret>> {
        self.run(self.inner.list_deleted_secrets_page(options))
    }

    fn recover_deleted_secret(&self, name: &str) -> Result<SecretProperties> {
        self.run(self.inner.recover_deleted_secret(name))
    }

    fn purge_deleted_secret(&self, name: &str) -> Result<()> {
        self.run(self.inner.purge_deleted_secret(name))
    }

    fn audit_events(&self, query: AuditQuery) -> Result<Vec<AuditEvent>> {
        self.run(self.inner.audit_events(query))
    }

    fn resolve(&self, reference: &SecretReference) -> Result<Secret> {
        self.run(self.inner.resolve(reference))
    }
}
