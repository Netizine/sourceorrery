//! The `SecretClient` contract, in its synchronous and asynchronous shapes.

use crate::audit::{AuditEvent, AuditQuery};
use crate::error::{Result, SecretError};
use crate::listing::{ListOptions, Page};
use crate::secret::{
    DeletedSecret, Secret, SecretBytes, SecretProperties, SecretReference, SetSecretOptions,
    UpdateSecretProperties,
};

/// Everything a secret backend must be able to do.
///
/// Modelled on the `SecretClient` of managed cloud secrets services. Semantics every
/// implementation must honour (the conformance suite checks them):
///
/// * `set_secret` on an existing name creates a **new immutable version**;
///   it never mutates an old one.
/// * `get_secret` without a version returns the **newest accessible**
///   version (enabled, inside its time window). With a version it returns
///   exactly that version or a policy error.
/// * `list_*` methods return **metadata only**, ordered by name. The
///   `_page` variants return a window of that order: up to `max_results`
///   items whose names sort after the continuation token, and a token of
///   their own, the name of the last item, while names remain after it.
///   Because the token marks a position in the name order and some of the
///   names after it may belong to the other listing (deleted secrets in a
///   live listing and the reverse), the final page can hold fewer items
///   than `max_results`, even none; a caller pages until the token is
///   `None`, not until a page is empty (see [`Page`]). Each page is one
///   listing operation in the audit log.
/// * `update_secret_properties` changes metadata, never the value.
/// * `delete_secret` soft-deletes **all versions** when the vault is
///   recoverable; `recover_deleted_secret` restores them; `purge_deleted_secret`
///   is the only permanent removal.
/// * Every operation that reads or changes a secret is recorded in the audit
///   log, successes and failures alike, and no event **ever** contains a
///   value. Metadata reads (`get_secret_properties`, version lists, deleted
///   secret details) are recorded as `secret_inspect`. Reading the audit log
///   itself and verifying the chain are read-only and not recorded.
///
/// The trait is synchronous because the first backend is a local encrypted
/// store. Remote backends implement [`AsyncSecretClient`], the same contract
/// in async form; the semantics above are shared, and the adapters in the
/// `sourceorrery-provider` crate make every backend serve both shapes.
pub trait SecretClient {
    /// Name of the vault this client is bound to.
    fn vault_name(&self) -> &str;

    /// Create a new version of `name` holding `value`.
    fn set_secret(
        &self,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
    ) -> Result<SecretProperties>;

    /// Retrieve a version's value and metadata. `None` selects the newest
    /// accessible version.
    fn get_secret(&self, name: &str, version: Option<&str>) -> Result<Secret>;

    /// Retrieve metadata only. Does not evaluate access policy, so disabled
    /// and expired versions can be inspected without exposing a value.
    fn get_secret_properties(&self, name: &str, version: Option<&str>) -> Result<SecretProperties>;

    /// Metadata of the newest version of every live secret, by name.
    fn list_properties_of_secrets(&self) -> Result<Vec<SecretProperties>>;

    /// One page of [`Self::list_properties_of_secrets`].
    ///
    /// The default cuts the page out of the complete listing; a backend
    /// overrides it to read only the names in the window.
    fn list_properties_of_secrets_page(
        &self,
        options: ListOptions,
    ) -> Result<Page<SecretProperties>> {
        Page::from_sorted(self.list_properties_of_secrets()?, &options, |p| &p.name)
    }

    /// Metadata of every version of `name`, newest first.
    fn list_properties_of_secret_versions(&self, name: &str) -> Result<Vec<SecretProperties>>;

    /// Change metadata of one version (`None` selects the newest).
    fn update_secret_properties(
        &self,
        name: &str,
        version: Option<&str>,
        update: UpdateSecretProperties,
    ) -> Result<SecretProperties>;

    /// Soft-delete all versions of `name`.
    ///
    /// Completes synchronously for local vaults. Remote backends may take
    /// time to finish; their async client will expose a poller.
    fn delete_secret(&self, name: &str) -> Result<DeletedSecret>;

    /// Inspect a soft-deleted secret.
    fn get_deleted_secret(&self, name: &str) -> Result<DeletedSecret>;

    /// All soft-deleted secrets, by name.
    fn list_deleted_secrets(&self) -> Result<Vec<DeletedSecret>>;

    /// One page of [`Self::list_deleted_secrets`]; see
    /// [`Self::list_properties_of_secrets_page`].
    fn list_deleted_secrets_page(&self, options: ListOptions) -> Result<Page<DeletedSecret>> {
        Page::from_sorted(self.list_deleted_secrets()?, &options, |d| {
            &d.properties.name
        })
    }

    /// Undo a soft delete.
    fn recover_deleted_secret(&self, name: &str) -> Result<SecretProperties>;

    /// Permanently remove a soft-deleted secret. Privileged.
    fn purge_deleted_secret(&self, name: &str) -> Result<()>;

    /// Metadata-only audit trail, newest first.
    fn audit_events(&self, query: AuditQuery) -> Result<Vec<AuditEvent>>;

    /// Resolve a [`SecretReference`] against this vault.
    fn resolve(&self, reference: &SecretReference) -> Result<Secret> {
        if reference.vault != self.vault_name() {
            return Err(SecretError::InvalidArgument(format!(
                "reference {reference} targets vault '{}' but this client is bound to '{}'",
                reference.vault,
                self.vault_name()
            )));
        }
        self.get_secret(&reference.name, reference.version.as_deref())
    }
}

/// [`SecretClient`] for backends that wait on the network.
///
/// The same operations with the same semantics (the table on
/// [`SecretClient`] is the contract for both shapes); only the calling
/// convention differs. Remote providers (HashiCorp Vault, AWS Secrets
/// Manager) implement this trait; the local vault stays
/// synchronous. The adapters in the `sourceorrery-provider` crate turn one
/// shape into the other, so the CLI, the C ABI and the conformance suite
/// run unchanged against any backend.
///
/// The trait is object safe (`Box<dyn AsyncSecretClient>`) because a
/// provider is chosen at run time from the manifest; `async-trait` supplies
/// the boxing until native `async fn` in traits can be called through
/// `dyn`. Implementations are `Send + Sync` so one client can serve many
/// tasks.
///
/// Two differences a remote backend may legitimately show, both documented
/// per provider: `audit_events` returns [`SecretError::Unsupported`] with a
/// hint naming where the provider's own audit log lives (the local vault's
/// recording of metadata reads is not emulated), and the operations that
/// the provider's service completes asynchronously (`delete_secret` on
/// some) return once the request is accepted.
#[async_trait::async_trait]
pub trait AsyncSecretClient: Send + Sync {
    /// Name of the vault this client is bound to.
    fn vault_name(&self) -> &str;

    /// Create a new version of `name` holding `value`.
    async fn set_secret(
        &self,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
    ) -> Result<SecretProperties>;

    /// Retrieve a version's value and metadata. `None` selects the newest
    /// accessible version.
    async fn get_secret(&self, name: &str, version: Option<&str>) -> Result<Secret>;

    /// Retrieve metadata only, without evaluating access policy.
    async fn get_secret_properties(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<SecretProperties>;

    /// Metadata of the newest version of every live secret, by name.
    async fn list_properties_of_secrets(&self) -> Result<Vec<SecretProperties>>;

    /// One page of [`Self::list_properties_of_secrets`]; see
    /// [`SecretClient::list_properties_of_secrets_page`].
    async fn list_properties_of_secrets_page(
        &self,
        options: ListOptions,
    ) -> Result<Page<SecretProperties>> {
        Page::from_sorted(self.list_properties_of_secrets().await?, &options, |p| {
            &p.name
        })
    }

    /// Metadata of every version of `name`, newest first.
    async fn list_properties_of_secret_versions(&self, name: &str)
    -> Result<Vec<SecretProperties>>;

    /// Change metadata of one version (`None` selects the newest).
    async fn update_secret_properties(
        &self,
        name: &str,
        version: Option<&str>,
        update: UpdateSecretProperties,
    ) -> Result<SecretProperties>;

    /// Soft-delete all versions of `name`.
    async fn delete_secret(&self, name: &str) -> Result<DeletedSecret>;

    /// Inspect a soft-deleted secret.
    async fn get_deleted_secret(&self, name: &str) -> Result<DeletedSecret>;

    /// All soft-deleted secrets, by name.
    async fn list_deleted_secrets(&self) -> Result<Vec<DeletedSecret>>;

    /// One page of [`Self::list_deleted_secrets`]; see
    /// [`SecretClient::list_deleted_secrets_page`].
    async fn list_deleted_secrets_page(&self, options: ListOptions) -> Result<Page<DeletedSecret>> {
        Page::from_sorted(self.list_deleted_secrets().await?, &options, |d| {
            &d.properties.name
        })
    }

    /// Undo a soft delete.
    async fn recover_deleted_secret(&self, name: &str) -> Result<SecretProperties>;

    /// Permanently remove a soft-deleted secret. Privileged.
    async fn purge_deleted_secret(&self, name: &str) -> Result<()>;

    /// Metadata-only audit trail, newest first; `unsupported` on a backend
    /// whose service keeps its own log.
    async fn audit_events(&self, query: AuditQuery) -> Result<Vec<AuditEvent>>;

    /// Resolve a [`SecretReference`] against this vault.
    async fn resolve(&self, reference: &SecretReference) -> Result<Secret> {
        if reference.vault != self.vault_name() {
            return Err(SecretError::InvalidArgument(format!(
                "reference {reference} targets vault '{}' but this client is bound to '{}'",
                reference.vault,
                self.vault_name()
            )));
        }
        self.get_secret(&reference.name, reference.version.as_deref())
            .await
    }
}
