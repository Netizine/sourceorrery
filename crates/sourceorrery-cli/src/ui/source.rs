//! The browser's only view of a vault.

use std::fmt::Debug;

use sourceorrery_core::{
    AuditEvent, AuditQuery, Capability, DeletedSecret, Result, SecretClient, SecretProperties,
    VaultDescriptor,
};
use sourceorrery_provider::Routed;
use sourceorrery_storage::{
    AuditVerification, ConnectionInfo, ProjectLink, SecondFactorInfo, ViewCheck, WrapInfo,
};

/// What the vault's view check asks for: never the password's hash, its
/// hint's text or the authenticator's key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ViewSettings {
    pub check: ViewCheck,
    /// A hint is shown when the password is asked for.
    pub hint: bool,
    /// The authenticator enrolled, when there is one.
    pub authenticator: Option<SecondFactorInfo>,
}

/// What the browser may ask of a vault: metadata, never a value.
///
/// Deliberately not [`SecretClient`]. Nothing here returns a value, so no
/// screen can show one by mistake; a screen that needs more of the vault
/// adds a method here, and a method that would return a value does not
/// belong here at all. Each method says what the vault records in its audit
/// log when it is called. A secret a connection stores is read at its
/// provider, and the vault records that call too.
pub trait MetadataSource: Debug {
    /// The vault's non-sensitive description. Not audited.
    fn descriptor(&self) -> Result<VaultDescriptor>;

    /// Detected audit-log truncations nobody has acknowledged. While there
    /// are any, the vault refuses every secret operation (and records each
    /// refusal), so the browser shows only the audit log. Not audited.
    fn truncations(&self) -> Result<Vec<AuditEvent>>;

    /// The newest version of every live secret the vault file keeps. One
    /// `secret_list` event.
    fn secrets(&self) -> Result<Vec<SecretProperties>>;

    /// The newest version of every live secret the connection `id` stores,
    /// from its provider. One listing there, recorded as `secret_list`.
    fn secrets_at(&self, id: &str) -> Result<Vec<SecretProperties>>;

    /// Every version of one live secret, newest first, from where it is
    /// kept. One `secret_inspect` event.
    fn versions(&self, name: &str) -> Result<Vec<SecretProperties>>;

    /// The secrets the vault file keeps soft-deleted. One `secret_list`
    /// event.
    fn deleted(&self) -> Result<Vec<DeletedSecret>>;

    /// The soft-deleted secrets of the connection `id`, from its provider.
    /// One listing there, recorded as `secret_list`.
    fn deleted_at(&self, id: &str) -> Result<Vec<DeletedSecret>>;

    /// Audit events, newest first. Not audited.
    fn audit(&self, query: AuditQuery) -> Result<Vec<AuditEvent>>;

    /// Check the audit log's hash chain and head record, as
    /// `audit --verify` does. Not audited.
    fn verify(&self) -> Result<AuditVerification>;

    /// The ways the vault's key opens (this machine, the recovery key):
    /// kinds and dates, never the keys. Not audited.
    fn keys(&self) -> Result<Vec<WrapInfo>>;

    /// The vault's connections to providers: their settings and last
    /// test, never their credentials. Not audited.
    fn connections(&self) -> Result<Vec<ConnectionInfo>>;

    /// The names of the secrets the connection `id` stores. Not audited.
    fn stored_at(&self, id: &str) -> Result<Vec<String>>;

    /// What the view check asks for. Not audited.
    fn view_settings(&self) -> Result<ViewSettings>;

    /// The project folders the vault records. Not audited.
    fn projects(&self) -> Result<Vec<ProjectLink>>;

    /// What the storage of `name` can express, so a change it would refuse
    /// is never sent. Not audited.
    fn capabilities_of(&self, name: &str) -> Result<&'static [Capability]>;
}

impl MetadataSource for Routed {
    fn descriptor(&self) -> Result<VaultDescriptor> {
        self.vault().descriptor()
    }

    fn truncations(&self) -> Result<Vec<AuditEvent>> {
        self.vault().unacknowledged_truncations()
    }

    fn secrets(&self) -> Result<Vec<SecretProperties>> {
        self.vault().list_properties_of_secrets()
    }

    fn secrets_at(&self, id: &str) -> Result<Vec<SecretProperties>> {
        self.list_at(id)
    }

    fn versions(&self, name: &str) -> Result<Vec<SecretProperties>> {
        self.list_properties_of_secret_versions(name)
    }

    fn deleted(&self) -> Result<Vec<DeletedSecret>> {
        self.vault().list_deleted_secrets()
    }

    fn deleted_at(&self, id: &str) -> Result<Vec<DeletedSecret>> {
        self.list_deleted_at(id)
    }

    fn audit(&self, query: AuditQuery) -> Result<Vec<AuditEvent>> {
        self.vault().audit_events(query)
    }

    fn verify(&self) -> Result<AuditVerification> {
        self.vault().verify_audit_chain()
    }

    fn keys(&self) -> Result<Vec<WrapInfo>> {
        self.vault().wraps()
    }

    fn connections(&self) -> Result<Vec<ConnectionInfo>> {
        self.vault().connections()
    }

    fn stored_at(&self, id: &str) -> Result<Vec<String>> {
        self.vault().secrets_at(id)
    }

    fn view_settings(&self) -> Result<ViewSettings> {
        let vault = self.vault();
        Ok(ViewSettings {
            check: vault.view_check()?,
            hint: vault.password_hint()?.is_some(),
            authenticator: vault.authenticator()?,
        })
    }

    fn projects(&self) -> Result<Vec<ProjectLink>> {
        self.vault().projects()
    }

    fn capabilities_of(&self, name: &str) -> Result<&'static [Capability]> {
        SecretClient::capabilities_of(self, name)
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
    fn secrets_at(&self, id: &str) -> Result<Vec<SecretProperties>> {
        (**self).secrets_at(id)
    }
    fn versions(&self, name: &str) -> Result<Vec<SecretProperties>> {
        (**self).versions(name)
    }
    fn deleted(&self) -> Result<Vec<DeletedSecret>> {
        (**self).deleted()
    }
    fn deleted_at(&self, id: &str) -> Result<Vec<DeletedSecret>> {
        (**self).deleted_at(id)
    }
    fn audit(&self, query: AuditQuery) -> Result<Vec<AuditEvent>> {
        (**self).audit(query)
    }
    fn verify(&self) -> Result<AuditVerification> {
        (**self).verify()
    }
    fn keys(&self) -> Result<Vec<WrapInfo>> {
        (**self).keys()
    }
    fn connections(&self) -> Result<Vec<ConnectionInfo>> {
        (**self).connections()
    }
    fn stored_at(&self, id: &str) -> Result<Vec<String>> {
        (**self).stored_at(id)
    }
    fn view_settings(&self) -> Result<ViewSettings> {
        (**self).view_settings()
    }
    fn projects(&self) -> Result<Vec<ProjectLink>> {
        (**self).projects()
    }
    fn capabilities_of(&self, name: &str) -> Result<&'static [Capability]> {
        (**self).capabilities_of(name)
    }
}
