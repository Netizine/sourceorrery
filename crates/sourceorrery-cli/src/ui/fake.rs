//! An in-memory vault for the browser's tests, counting each kind of read
//! and recording each change.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::rc::Rc;

use sourceorrery_core::{
    AuditEvent, AuditOperation, AuditOutcome, AuditQuery, Capability, ConnectionSettings,
    DeletedSecret, Principal, RecoveryLevel, Result, SecretBytes, SecretError, SecretProperties,
    SetSecretOptions, UpdateSecretProperties, VaultDescriptor, timestamp,
};
use time::Duration;

use sourceorrery_storage::{
    AuditVerification, ConnectionInfo, CredentialSource, ProjectLink, SecretStorage, WrapInfo,
};

use super::app::VaultEntry;
use super::editor::MetadataEditor;
use super::source::{MetadataSource, ViewSettings};

#[derive(Debug, Default)]
pub struct Fake {
    pub names: RefCell<Vec<&'static str>>,
    pub deleted_names: RefCell<Vec<&'static str>>,
    pub tags: Vec<(&'static str, &'static str)>,
    /// Report an unacknowledged truncation.
    pub blocked: Cell<bool>,
    /// Fail every read the vault would audit.
    pub fail: Cell<bool>,
    /// `secret_list` reads: the secret list and the deleted list.
    pub lists: Cell<usize>,
    pub list_delay: Cell<std::time::Duration>,
    /// `secret_inspect` reads: version lists.
    pub inspects: Cell<usize>,
    pub fail_versions: Cell<bool>,
    pub capability_reads: Cell<usize>,
    pub audit_actor: Option<Principal>,
    pub audit_detail: Option<String>,
    /// Audit-log reads (not audited by the vault).
    pub audit_reads: Cell<usize>,
    pub fail_audit: Cell<bool>,
    /// Chain verifications (not audited).
    pub verifies: Cell<usize>,
    /// Report a broken chain.
    pub broken: Cell<bool>,
    /// Deleting is for good.
    pub purgeable: Cell<bool>,
    /// Secrets whose versions are disabled.
    pub disabled: RefCell<BTreeSet<String>>,
    /// Changes, in order: what was asked for, and of a value only its length.
    pub writes: RefCell<Vec<Write>>,
    /// Connections, each with the names it stores (not in `names`).
    pub connections: RefCell<Vec<(ConnectionInfo, Vec<&'static str>)>>,
    /// The connection whose provider fails every listing.
    pub unreachable: RefCell<Option<String>>,
    /// Listings at connections.
    pub listings_at: Cell<usize>,
    pub projects: RefCell<Vec<ProjectLink>>,
    pub view: RefCell<ViewSettings>,
    /// What the storage of a secret at a connection can express.
    pub remote_capabilities: Cell<&'static [Capability]>,
    pub version_ids: RefCell<Option<Vec<String>>>,
}

/// A change the browser made.
#[derive(Clone, Debug)]
pub enum Write {
    Update(String, String, UpdateSecretProperties),
    Delete(String),
    Recover(String),
    AddVersion(String, usize, SetSecretOptions),
    AddSecret(String, usize, SecretStorage),
    Unlink(String),
}

/// The fake keeps names as `&'static str`; names the browser adds are
/// leaked to fit. Tests only.
fn leak(name: &str) -> &'static str {
    Box::leak(name.to_owned().into_boxed_str())
}

impl Fake {
    pub fn with(names: &[&'static str]) -> Rc<Self> {
        Rc::new(Self {
            names: RefCell::new(names.to_vec()),
            ..Self::default()
        })
    }

    /// A HashiCorp Vault connection `c1` storing `names`.
    pub fn with_connection(names: &[&'static str], at_connection: &[&'static str]) -> Rc<Self> {
        let fake = Self::with(names);
        fake.connections.borrow_mut().push((
            ConnectionInfo {
                id: "c1".to_owned(),
                settings: ConnectionSettings::HashicorpVault {
                    address: "https://vault.example.com:8200".to_owned(),
                    mount: "secret".to_owned(),
                    namespace: None,
                },
                credentials: CredentialSource::Ambient,
                created_on: timestamp::now(),
                last_test: None,
            },
            at_connection.to_vec(),
        ));
        fake
    }

    /// A project folder recorded at `path`.
    pub fn link(&self, id: &str, name: &str, path: &std::path::Path) {
        self.projects.borrow_mut().push(ProjectLink {
            id: id.to_owned(),
            path: path.to_path_buf(),
            name: name.to_owned(),
            linked_on: timestamp::now(),
        });
    }

    fn stored(&self, id: &str) -> Vec<&'static str> {
        self.connections
            .borrow()
            .iter()
            .find(|(c, _)| c.id == id)
            .map(|(_, names)| names.clone())
            .unwrap_or_default()
    }

    fn at_a_connection(&self, name: &str) -> bool {
        self.connections
            .borrow()
            .iter()
            .any(|(_, names)| names.contains(&name))
    }

    pub fn vault_entries() -> Vec<VaultEntry> {
        ["development", "staging"]
            .into_iter()
            .map(|name| VaultEntry {
                name: name.to_owned(),
                path: PathBuf::from(format!("/home/vaults/{name}.sorvault")),
                size: Some(65_536),
                modified: Some(timestamp::now()),
            })
            .collect()
    }

    fn props(&self, name: &str, version: &str) -> SecretProperties {
        let now = timestamp::now();
        SecretProperties {
            vault: "development".into(),
            name: name.to_owned(),
            version: version.to_owned(),
            enabled: !self.disabled.borrow().contains(name),
            content_type: None,
            tags: self
                .tags
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            not_before: None,
            expires_on: None,
            created_on: now,
            updated_on: now,
            recovery_level: RecoveryLevel::Recoverable,
        }
    }

    fn audited(&self, counter: &Cell<usize>) -> Result<()> {
        counter.set(counter.get() + 1);
        if self.fail.get() {
            return Err(SecretError::Crypto("audit chain head stale".into()));
        }
        if self.blocked.get() {
            return Err(SecretError::Crypto("vault is blocked".into()));
        }
        Ok(())
    }
}

fn event(id: u64, operation: AuditOperation, secret: Option<&str>) -> AuditEvent {
    AuditEvent {
        id,
        occurred_on: timestamp::now(),
        actor: Principal::local_user(),
        operation,
        secret_name: secret.map(str::to_owned),
        version: None,
        outcome: AuditOutcome::Success,
        detail: None,
    }
}

impl MetadataSource for Fake {
    fn descriptor(&self) -> Result<VaultDescriptor> {
        Ok(VaultDescriptor {
            name: "development".into(),
            id: "0".repeat(32),
            backend: "fake".into(),
            path: None,
            created_on: timestamp::now(),
            recovery_level: if self.purgeable.get() {
                RecoveryLevel::Purgeable
            } else {
                RecoveryLevel::Recoverable
            },
            retention_days: 90,
            protectors: vec!["recovery".into()],
        })
    }

    fn truncations(&self) -> Result<Vec<AuditEvent>> {
        Ok(if self.blocked.get() {
            vec![AuditEvent {
                outcome: AuditOutcome::Failure,
                detail: Some("rows removed after event 40 (head was event 41)".into()),
                ..event(42, AuditOperation::AuditVerify, None)
            }]
        } else {
            Vec::new()
        })
    }

    fn secrets(&self) -> Result<Vec<SecretProperties>> {
        std::thread::sleep(self.list_delay.get());
        self.audited(&self.lists)?;
        Ok(self
            .names
            .borrow()
            .iter()
            .map(|name| self.props(name, "0123456789abcdef0123456789abcdef"))
            .collect())
    }

    fn versions(&self, name: &str) -> Result<Vec<SecretProperties>> {
        self.audited(&self.inspects)?;
        if self.fail_versions.get() {
            return Err(SecretError::Crypto("synthetic version read failure".into()));
        }
        if let Some(ids) = self.version_ids.borrow().as_ref() {
            return Ok(ids.iter().map(|id| self.props(name, id)).collect());
        }
        Ok(vec![
            self.props(name, "0123456789abcdef0123456789abcdef"),
            self.props(name, "fedcba9876543210fedcba9876543210"),
        ])
    }

    fn deleted(&self) -> Result<Vec<DeletedSecret>> {
        self.audited(&self.lists)?;
        let now = timestamp::now();
        Ok(self
            .deleted_names
            .borrow()
            .iter()
            .map(|name| DeletedSecret {
                properties: self.props(name, "0123456789abcdef0123456789abcdef"),
                deleted_on: now - Duration::days(1),
                scheduled_purge_on: Some(now + Duration::days(89)),
                recovery_id: format!("sourceorrery://development/deleted/{name}"),
            })
            .collect())
    }

    fn audit(&self, query: AuditQuery) -> Result<Vec<AuditEvent>> {
        self.audit_reads.set(self.audit_reads.get() + 1);
        if self.fail_audit.get() {
            return Err(SecretError::Crypto("synthetic audit read failure".into()));
        }
        let mut events = vec![event(1, AuditOperation::VaultCreate, None)];
        let mut id = 1;
        for name in self.names.borrow().iter() {
            id += 1;
            events.push(event(id, AuditOperation::SecretSet, Some(name)));
        }
        id += 1;
        events.push(AuditEvent {
            outcome: AuditOutcome::Failure,
            detail: Some("locked".into()),
            ..event(id, AuditOperation::VaultOpen, None)
        });
        for event in &mut events {
            if let Some(actor) = &self.audit_actor {
                event.actor = actor.clone();
            }
            if let Some(detail) = &self.audit_detail {
                event.detail = Some(detail.clone());
            }
        }
        events.reverse();
        Ok(events
            .into_iter()
            .filter(|e| {
                query
                    .secret_name
                    .as_ref()
                    .is_none_or(|n| e.secret_name.as_ref() == Some(n))
            })
            .take(query.limit.unwrap_or(usize::MAX))
            .collect())
    }

    fn verify(&self) -> Result<AuditVerification> {
        self.verifies.set(self.verifies.get() + 1);
        let rows = 2 + u64::try_from(self.names.borrow().len()).unwrap_or(0);
        Ok(AuditVerification {
            rows,
            keyed: rows - 1,
            unkeyed: 1,
            first_broken: self.broken.get().then_some(2),
            truncations: u64::from(self.blocked.get()),
            unacknowledged: u64::from(self.blocked.get()),
            head_valid: true,
        })
    }

    fn keys(&self) -> Result<Vec<WrapInfo>> {
        Ok(vec![WrapInfo {
            id: "0".repeat(16),
            kind: "recovery".into(),
            created_on: timestamp::now(),
        }])
    }

    fn secrets_at(&self, id: &str) -> Result<Vec<SecretProperties>> {
        self.listings_at.set(self.listings_at.get() + 1);
        if self.unreachable.borrow().as_deref() == Some(id) {
            return Err(SecretError::ProviderUnavailable {
                provider: "hashicorp-vault".into(),
                reason: "connection refused".into(),
            });
        }
        Ok(self
            .stored(id)
            .iter()
            .map(|name| self.props(name, "abcdefabcdefabcdefabcdefabcdefab"))
            .collect())
    }

    fn deleted_at(&self, id: &str) -> Result<Vec<DeletedSecret>> {
        self.listings_at.set(self.listings_at.get() + 1);
        if self.unreachable.borrow().as_deref() == Some(id) {
            return Err(SecretError::ProviderUnavailable {
                provider: "hashicorp-vault".into(),
                reason: "connection refused".into(),
            });
        }
        Ok(Vec::new())
    }

    fn connections(&self) -> Result<Vec<ConnectionInfo>> {
        Ok(self
            .connections
            .borrow()
            .iter()
            .map(|(c, _)| c.clone())
            .collect())
    }

    fn stored_at(&self, id: &str) -> Result<Vec<String>> {
        Ok(self.stored(id).into_iter().map(str::to_owned).collect())
    }

    fn view_settings(&self) -> Result<ViewSettings> {
        Ok(self.view.borrow().clone())
    }

    fn projects(&self) -> Result<Vec<ProjectLink>> {
        Ok(self.projects.borrow().clone())
    }

    fn capabilities_of(&self, name: &str) -> Result<&'static [Capability]> {
        self.capability_reads.set(self.capability_reads.get() + 1);
        Ok(if self.at_a_connection(name) {
            self.remote_capabilities.get()
        } else {
            Capability::ALL
        })
    }
}

impl MetadataEditor for Fake {
    fn update(
        &self,
        name: &str,
        version: &str,
        update: UpdateSecretProperties,
    ) -> Result<SecretProperties> {
        self.audited(&Cell::new(0))?;
        if let Some(enabled) = update.enabled {
            if enabled {
                self.disabled.borrow_mut().remove(name);
            } else {
                self.disabled.borrow_mut().insert(name.to_owned());
            }
        }
        self.writes
            .borrow_mut()
            .push(Write::Update(name.to_owned(), version.to_owned(), update));
        Ok(self.props(name, version))
    }

    fn delete(&self, name: &str) -> Result<DeletedSecret> {
        self.audited(&Cell::new(0))?;
        self.names.borrow_mut().retain(|n| *n != name);
        if !self.purgeable.get() {
            self.deleted_names.borrow_mut().push(leak(name));
        }
        self.writes
            .borrow_mut()
            .push(Write::Delete(name.to_owned()));
        let now = timestamp::now();
        Ok(DeletedSecret {
            properties: self.props(name, "0123456789abcdef0123456789abcdef"),
            deleted_on: now,
            scheduled_purge_on: Some(now + Duration::days(90)),
            recovery_id: String::new(),
        })
    }

    fn recover(&self, name: &str) -> Result<SecretProperties> {
        self.audited(&Cell::new(0))?;
        self.deleted_names.borrow_mut().retain(|n| *n != name);
        self.names.borrow_mut().push(leak(name));
        self.writes
            .borrow_mut()
            .push(Write::Recover(name.to_owned()));
        Ok(self.props(name, "0123456789abcdef0123456789abcdef"))
    }

    fn add_version(
        &self,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
    ) -> Result<SecretProperties> {
        self.audited(&Cell::new(0))?;
        if !self.names.borrow().contains(&name) {
            self.names.borrow_mut().push(leak(name));
        }
        self.writes
            .borrow_mut()
            .push(Write::AddVersion(name.to_owned(), value.len(), options));
        Ok(self.props(name, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
    }

    fn add_secret(
        &self,
        name: &str,
        value: SecretBytes,
        _options: SetSecretOptions,
        storage: &SecretStorage,
    ) -> Result<SecretProperties> {
        self.audited(&Cell::new(0))?;
        match storage {
            SecretStorage::Vault => self.names.borrow_mut().push(leak(name)),
            SecretStorage::Connection(id) => {
                if let Some((_, names)) = self
                    .connections
                    .borrow_mut()
                    .iter_mut()
                    .find(|(c, _)| c.id == *id)
                {
                    names.push(leak(name));
                }
            }
        }
        self.writes.borrow_mut().push(Write::AddSecret(
            name.to_owned(),
            value.len(),
            storage.clone(),
        ));
        Ok(self.props(name, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
    }

    fn unlink_project(&self, id: &str) -> Result<()> {
        self.projects.borrow_mut().retain(|p| p.id != id);
        self.writes.borrow_mut().push(Write::Unlink(id.to_owned()));
        Ok(())
    }
}
