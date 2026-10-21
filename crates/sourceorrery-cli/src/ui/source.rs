//! The browser's only view of a vault.

use std::fmt::Debug;

use sourceorrery_core::{
    AuditEvent, AuditQuery, DeletedSecret, Result, SecretClient, SecretProperties, VaultDescriptor,
};
use sourceorrery_storage::SqliteVault;

/// What the browser may ask of a vault: metadata, never a value.
///
/// Deliberately not [`SecretClient`]. Nothing here returns a value, so no
/// screen can show one by mistake; a screen that needs more of the vault
/// adds a method here, and a method that would return a value does not
/// belong here at all. Each method says what the vault records in its audit
/// log when it is called.
pub trait MetadataSource: Debug {
    /// The vault's non-sensitive description. Not audited.
    fn descriptor(&self) -> Result<VaultDescriptor>;

    /// Detected audit-log truncations nobody has acknowledged. While there
    /// are any, the vault refuses every secret operation (and records each
    /// refusal), so the browser shows only the audit log. Not audited.
    fn truncations(&self) -> Result<Vec<AuditEvent>>;

    /// The newest version of every live secret. One `secret_list` event.
    fn secrets(&self) -> Result<Vec<SecretProperties>>;

    /// Every version of one live secret, newest first. One
    /// `secret_inspect` event.
    fn versions(&self, name: &str) -> Result<Vec<SecretProperties>>;

    /// Soft-deleted secrets. One `secret_list` event.
    fn deleted(&self) -> Result<Vec<DeletedSecret>>;

    /// Audit events, newest first. Not audited.
    fn audit(&self, query: AuditQuery) -> Result<Vec<AuditEvent>>;
}

impl MetadataSource for SqliteVault {
    fn descriptor(&self) -> Result<VaultDescriptor> {
        SqliteVault::descriptor(self)
    }

    fn truncations(&self) -> Result<Vec<AuditEvent>> {
        self.unacknowledged_truncations()
    }

    fn secrets(&self) -> Result<Vec<SecretProperties>> {
        self.list_properties_of_secrets()
    }

    fn versions(&self, name: &str) -> Result<Vec<SecretProperties>> {
        self.list_properties_of_secret_versions(name)
    }

    fn deleted(&self) -> Result<Vec<DeletedSecret>> {
        self.list_deleted_secrets()
    }

    fn audit(&self, query: AuditQuery) -> Result<Vec<AuditEvent>> {
        self.audit_events(query)
    }
}

/// Tests keep a handle on the vault they give the browser, to count what
/// it read.
#[cfg(test)]
impl<T: MetadataSource> MetadataSource for std::rc::Rc<T> {
    fn descriptor(&self) -> Result<VaultDescriptor> {
        (**self).descriptor()
    }
    fn truncations(&self) -> Result<Vec<AuditEvent>> {
        (**self).truncations()
    }
    fn secrets(&self) -> Result<Vec<SecretProperties>> {
        (**self).secrets()
    }
    fn versions(&self, name: &str) -> Result<Vec<SecretProperties>> {
        (**self).versions(name)
    }
    fn deleted(&self) -> Result<Vec<DeletedSecret>> {
        (**self).deleted()
    }
    fn audit(&self, query: AuditQuery) -> Result<Vec<AuditEvent>> {
        (**self).audit(query)
    }
}
