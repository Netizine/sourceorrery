//! The browser's only view of a vault.

use std::fmt::Debug;

use sourceorrery_core::{Result, SecretClient, SecretProperties, VaultDescriptor};
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

    /// The newest version of every live secret. One `secret_list` event.
    fn secrets(&self) -> Result<Vec<SecretProperties>>;
}

impl MetadataSource for SqliteVault {
    fn descriptor(&self) -> Result<VaultDescriptor> {
        SqliteVault::descriptor(self)
    }

    fn secrets(&self) -> Result<Vec<SecretProperties>> {
        self.list_properties_of_secrets()
    }
}
