//! What the browser may change in a vault.
//!
//! Kept apart from [`MetadataSource`], which is all the views see, so that
//! drawing can never write. And limited to changes the browser confirms
//! first and the vault records: a version's metadata, deleting and
//! recovering a secret, a new secret or version whose value comes from the
//! ordinary hidden prompt, and forgetting a project folder that is gone.
//! Purging, the vault's keys, destroying and acknowledging a truncation stay in
//! the CLI; the vault's settings change on the setup screens. Nothing here
//! returns a value. A secret a connection stores is changed at its
//! provider, and the vault records that call.

use std::fmt::Debug;

use sourceorrery_core::{
    DeletedSecret, Result, SecretBytes, SecretClient, SecretProperties, SetSecretOptions,
    UpdateSecretProperties,
};
use sourceorrery_provider::Routed;
use sourceorrery_storage::SecretStorage;

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

    /// Store a new version of a secret, where it is kept. `value` comes
    /// from the hidden prompt and goes nowhere else. One `secret_set`
    /// event.
    fn add_version(
        &self,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
    ) -> Result<SecretProperties>;

    /// Store a new secret in `storage`: the vault file, or one of its
    /// connections. `value` comes from the hidden prompt and goes nowhere
    /// else. One `secret_set` event.
    fn add_secret(
        &self,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
        storage: &SecretStorage,
    ) -> Result<SecretProperties>;

    /// Forget the project folder `id`; the folder and its manifest are not
    /// touched. One `project_unlink` event.
    fn unlink_project(&self, id: &str) -> Result<()>;
}

/// A vault the browser can read, and change through [`MetadataEditor`].
pub trait Vault: MetadataSource + MetadataEditor {}

impl<T: MetadataSource + MetadataEditor> Vault for T {}

impl MetadataEditor for Routed {
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

    fn add_secret(
        &self,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
        storage: &SecretStorage,
    ) -> Result<SecretProperties> {
        self.set_secret_in(storage, name, value, options)
    }

    fn unlink_project(&self, id: &str) -> Result<()> {
        self.vault().unlink_project(id)
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
    fn add_secret(
        &self,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
        storage: &SecretStorage,
    ) -> Result<SecretProperties> {
        (**self).add_secret(name, value, options, storage)
    }
    fn unlink_project(&self, id: &str) -> Result<()> {
        (**self).unlink_project(id)
    }
}
