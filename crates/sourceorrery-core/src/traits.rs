//! The `SecretClient` contract.

use crate::audit::{AuditEvent, AuditQuery};
use crate::error::{Result, SecretError};
use crate::secret::{
    DeletedSecret, Secret, SecretBytes, SecretProperties, SecretReference, SetSecretOptions,
    UpdateSecretProperties,
};

/// Everything a secret backend must be able to do.
///
/// Modelled on Azure Key Vault's `SecretClient`. Semantics every
/// implementation must honour (the conformance suite checks them):
///
/// * `set_secret` on an existing name creates a **new immutable version**;
///   it never mutates an old one.
/// * `get_secret` without a version returns the **newest accessible**
///   version (enabled, inside its time window). With a version it returns
///   exactly that version or a policy error.
/// * `list_*` methods return **metadata only**.
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
/// store. Remote backends will get an `AsyncSecretClient` sibling; the
/// semantics above are shared.
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

    /// Metadata of the newest version of every live secret.
    fn list_properties_of_secrets(&self) -> Result<Vec<SecretProperties>>;

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

    /// All soft-deleted secrets.
    fn list_deleted_secrets(&self) -> Result<Vec<DeletedSecret>>;

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
