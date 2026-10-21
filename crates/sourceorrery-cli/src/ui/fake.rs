//! An in-memory vault for the browser's tests, counting each kind of read.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;

use sourceorrery_core::{
    AuditEvent, AuditOperation, AuditOutcome, AuditQuery, DeletedSecret, Principal, RecoveryLevel,
    Result, SecretError, SecretProperties, VaultDescriptor, timestamp,
};
use time::Duration;

use super::app::VaultEntry;
use super::source::MetadataSource;

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
    /// `secret_inspect` reads: version lists.
    pub inspects: Cell<usize>,
    /// Audit-log reads (not audited by the vault).
    pub audit_reads: Cell<usize>,
}

impl Fake {
    pub fn with(names: &[&'static str]) -> Rc<Self> {
        Rc::new(Self {
            names: RefCell::new(names.to_vec()),
            ..Self::default()
        })
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
            enabled: true,
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
            recovery_level: RecoveryLevel::Recoverable,
            retention_days: 90,
            protectors: vec!["passphrase".into()],
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
}
