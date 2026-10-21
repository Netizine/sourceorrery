//! What the browser may change in a vault.
//!
//! Kept apart from [`MetadataSource`], which is all the views see, so that
//! drawing can never write. And limited to changes the browser confirms
//! first and the vault records: a version's metadata, deleting and
//! recovering a secret, and a new version whose value comes from the
//! ordinary hidden prompt. Purging, protectors, destroying, migrating and
//! acknowledging a truncation stay in the CLI. Nothing here returns a
//! value.

use std::fmt::Debug;

use sourceorrery_core::{
    DeletedSecret, Result, SecretBytes, SecretClient, SecretProperties, SetSecretOptions,
    UpdateSecretProperties,
};
use sourceorrery_storage::SqliteVault;

use super::source::MetadataSource;

pub trait MetadataEditor: Debug {
    /// Change one version's metadata, never its value. One
    /// `secret_update` event.
    fn update(
        &self,
        name: &str,
        version: &str,
        update: UpdateSecretProperties,
    ) -> Result<SecretProperties>;

    /// Delete a secret, every version: soft in a recoverable vault, for
    /// good in a purgeable one. One `secret_delete` event.
    fn delete(&self, name: &str) -> Result<DeletedSecret>;

    /// Undo a soft delete. One `secret_recover` event.
    fn recover(&self, name: &str) -> Result<SecretProperties>;

    /// Store a new version. `value` comes from the hidden prompt and goes
    /// nowhere else. One `secret_set` event.
    fn add_version(
        &self,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
    ) -> Result<SecretProperties>;
}

/// A vault the browser can read, and change through [`MetadataEditor`].
pub trait Vault: MetadataSource + MetadataEditor {}

impl<T: MetadataSource + MetadataEditor> Vault for T {}

impl MetadataEditor for SqliteVault {
    fn update(
        &self,
        name: &str,
        version: &str,
        update: UpdateSecretProperties,
    ) -> Result<SecretProperties> {
        self.update_secret_properties(name, Some(version), update)
    }

    fn delete(&self, name: &str) -> Result<DeletedSecret> {
        self.delete_secret(name)
    }

    fn recover(&self, name: &str) -> Result<SecretProperties> {
        self.recover_deleted_secret(name)
    }

    fn add_version(
        &self,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
    ) -> Result<SecretProperties> {
        self.set_secret(name, value, options)
    }
}

/// Tests keep a handle on the vault they give the browser.
#[cfg(test)]
impl<T: MetadataEditor> MetadataEditor for std::rc::Rc<T> {
    fn update(
        &self,
        name: &str,
        version: &str,
        update: UpdateSecretProperties,
    ) -> Result<SecretProperties> {
        (**self).update(name, version, update)
    }
    fn delete(&self, name: &str) -> Result<DeletedSecret> {
        (**self).delete(name)
    }
    fn recover(&self, name: &str) -> Result<SecretProperties> {
        (**self).recover(name)
    }
    fn add_version(
        &self,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
    ) -> Result<SecretProperties> {
        (**self).add_version(name, value, options)
    }
}
