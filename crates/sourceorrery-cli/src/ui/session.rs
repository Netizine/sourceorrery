//! One open vault: what the browser has read from it, and reading more.
//!
//! Everything is read on demand and then kept: the secret list when the
//! vault opens, the deleted list and the audit log the first time their
//! view is shown, a secret's versions and activity the first time its
//! details open. [`Session::reload`] forgets all of it. Every read the
//! vault audits is a row in its log, so reading less is the point.
//!
//! A vault blocked by an unacknowledged audit-log truncation refuses every
//! secret read and records each refusal, so a blocked session never asks:
//! it holds the truncations and the audit log, nothing else.

use std::collections::HashMap;

use sourceorrery_core::{
    AuditEvent, AuditQuery, DeletedSecret, Result, SecretProperties, VaultDescriptor, timestamp,
};
use sourceorrery_storage::{AuditVerification, ProtectorInfo};
use time::OffsetDateTime;

use super::editor::{MetadataEditor, Vault};

/// Most audit events the audit view holds, newest first.
pub const AUDIT_LIMIT: usize = 1000;

/// Events shown under a secret's details.
pub const ACTIVITY_LIMIT: usize = 50;

#[derive(Debug)]
pub struct Session {
    source: Box<dyn Vault>,
    pub vault: VaultDescriptor,
    /// Unacknowledged truncations, oldest first. Not empty: the vault is
    /// blocked and only its audit log can be shown.
    pub blocked: Vec<AuditEvent>,
    pub secrets: Vec<SecretProperties>,
    deleted: Option<Vec<DeletedSecret>>,
    audit: Option<Vec<AuditEvent>>,
    details: HashMap<String, Detail>,
    protectors: Option<Vec<ProtectorInfo>>,
    verification: Option<Verification>,
}

/// The audit chain as last checked.
#[derive(Debug)]
pub struct Verification {
    pub result: AuditVerification,
    pub at: OffsetDateTime,
}

/// What a secret's details show beyond its list row.
#[derive(Debug, Default)]
pub struct Detail {
    /// Every version, newest first. `None` for a deleted secret: its
    /// versions cannot be listed until it is recovered.
    pub versions: Option<Vec<SecretProperties>>,
    /// Its audit events, newest first.
    pub activity: Vec<AuditEvent>,
}

impl Session {
    pub fn open(source: Box<dyn Vault>) -> Result<Self> {
        let vault = source.descriptor()?;
        let blocked = source.truncations()?;
        let secrets = if blocked.is_empty() {
            source.secrets()?
        } else {
            Vec::new()
        };
        Ok(Self {
            source,
            vault,
            blocked,
            secrets,
            deleted: None,
            audit: None,
            details: HashMap::new(),
            protectors: None,
            verification: None,
        })
    }

    pub fn is_blocked(&self) -> bool {
        !self.blocked.is_empty()
    }

    /// The write side of the vault, for `ui::edit` only: the views read
    /// what this session holds and never see it.
    pub fn editor(&self) -> &dyn MetadataEditor {
        &*self.source
    }

    /// Read the vault again and forget everything read before.
    pub fn reload(&mut self) -> Result<()> {
        let vault = self.source.descriptor()?;
        let blocked = self.source.truncations()?;
        let secrets = if blocked.is_empty() {
            self.source.secrets()?
        } else {
            Vec::new()
        };
        self.vault = vault;
        self.blocked = blocked;
        self.secrets = secrets;
        self.deleted = None;
        self.audit = None;
        self.details.clear();
        self.protectors = None;
        self.verification = None;
        Ok(())
    }

    pub fn deleted(&self) -> Option<&[DeletedSecret]> {
        self.deleted.as_deref()
    }

    /// Read the deleted secrets, unless they are already held.
    pub fn load_deleted(&mut self) -> Result<()> {
        if self.deleted.is_none() {
            self.deleted = Some(if self.is_blocked() {
                Vec::new()
            } else {
                self.source.deleted()?
            });
        }
        Ok(())
    }

    pub fn audit(&self) -> Option<&[AuditEvent]> {
        self.audit.as_deref()
    }

    /// Read the newest [`AUDIT_LIMIT`] audit events, unless already held.
    pub fn load_audit(&mut self) -> Result<()> {
        if self.audit.is_none() {
            self.audit = Some(self.source.audit(AuditQuery {
                limit: Some(AUDIT_LIMIT),
                ..AuditQuery::default()
            })?);
        }
        Ok(())
    }

    pub fn protectors(&self) -> Option<&[ProtectorInfo]> {
        self.protectors.as_deref()
    }

    /// Read the key protectors, unless already held. Not audited.
    pub fn load_protectors(&mut self) -> Result<()> {
        if self.protectors.is_none() {
            self.protectors = Some(self.source.protectors()?);
        }
        Ok(())
    }

    pub fn verification(&self) -> Option<&Verification> {
        self.verification.as_ref()
    }

    /// Check the audit chain now. Not audited; it reads every row of the
    /// log, so it runs when the overview is first shown and on `v`.
    pub fn verify(&mut self) -> Result<&Verification> {
        let result = self.source.verify()?;
        Ok(self.verification.insert(Verification {
            result,
            at: timestamp::now(),
        }))
    }

    pub fn detail(&self, name: &str) -> Option<&Detail> {
        self.details.get(name)
    }

    /// Read a secret's versions (a live one only) and its activity, unless
    /// already held. The versions are read first, so the activity includes
    /// the `secret_inspect` that read them.
    pub fn load_detail(&mut self, name: &str, live: bool) -> Result<()> {
        if self.details.contains_key(name) {
            return Ok(());
        }
        let versions = if live && !self.is_blocked() {
            Some(self.source.versions(name)?)
        } else {
            None
        };
        let activity = self.source.audit(AuditQuery {
            secret_name: Some(name.to_owned()),
            limit: Some(ACTIVITY_LIMIT),
            ..AuditQuery::default()
        })?;
        self.details
            .insert(name.to_owned(), Detail { versions, activity });
        Ok(())
    }
}
