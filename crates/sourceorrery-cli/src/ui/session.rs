//! One open vault: what the browser has read from it, and reading more.
//!
//! Everything is read on demand and then kept: the secret list, the
//! vault's connections, its view check and its project folders when the
//! vault opens, the deleted list and the audit log the first time their
//! view is shown, a secret's versions and activity the first time its
//! details open. [`Session::reload`] forgets all of it. Every read the
//! vault audits is a row in its log, so reading less is the point.
//!
//! The secrets a connection stores are listed at its provider, one
//! listing per connection, each recorded in the vault. A provider that
//! cannot be reached is noted ([`Unreachable`]) and the rest is shown.
//! Whether a project's folder still has its manifest is a look at the
//! disk, not a vault read.
//!
//! A vault blocked by an unacknowledged audit-log truncation refuses every
//! secret read and records each refusal, so a blocked session never asks:
//! it holds the truncations and the audit log, nothing else.

use std::collections::{BTreeMap, HashMap};

use sourceorrery_core::{
    AuditEvent, AuditQuery, Capability, DeletedSecret, MANIFEST_FILE_NAME, Manifest, Result,
    SecretError, SecretProperties, VaultDescriptor, timestamp,
};
use sourceorrery_storage::{AuditVerification, ConnectionInfo, ProjectLink, WrapInfo};
use time::OffsetDateTime;

use super::editor::{MetadataEditor, Vault};
use super::source::ViewSettings;

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
    /// The vault's connections, oldest first.
    pub connections: Vec<ConnectionInfo>,
    /// The connection that stores each secret kept at one, by name.
    pub storage: BTreeMap<String, String>,
    /// Connections whose provider could not be listed.
    pub unreachable: Vec<Unreachable>,
    /// What the view check asks for.
    pub view: ViewSettings,
    /// The project folders the vault records, as found on disk.
    pub projects: Vec<Project>,
    deleted: Option<Vec<DeletedSecret>>,
    audit: Option<Vec<AuditEvent>>,
    details: HashMap<String, Detail>,
    keys: Option<Vec<WrapInfo>>,
    verification: Option<Verification>,
}

/// A connection whose provider refused or failed a listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unreachable {
    pub connection: String,
    /// The error's stable code and message.
    pub code: &'static str,
    pub reason: String,
}

/// A project folder the vault records, and what its manifest said when
/// the vault was read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Project {
    pub link: ProjectLink,
    pub status: ProjectStatus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProjectStatus {
    /// Its `sourceorrery.toml` is there: the vault it names and the
    /// secrets it declares, in order.
    Found { vault: String, secrets: Vec<String> },
    /// The folder or its manifest is gone.
    Missing,
    /// The manifest is there and cannot be read: why.
    Unreadable(String),
}

impl Project {
    /// What the project's manifest says, read from its folder now.
    pub fn look(link: ProjectLink) -> Self {
        let manifest = link.path.join(MANIFEST_FILE_NAME);
        let status = if manifest.is_file() {
            match Manifest::load(&manifest) {
                Ok(read) => ProjectStatus::Found {
                    vault: read.project.vault,
                    secrets: read.secrets.into_keys().collect(),
                },
                Err(err) => ProjectStatus::Unreadable(err.to_string()),
            }
        } else {
            ProjectStatus::Missing
        };
        Self { link, status }
    }

    /// The secrets its manifest declares (none when it is not there).
    pub fn secrets(&self) -> &[String] {
        match &self.status {
            ProjectStatus::Found { secrets, .. } => secrets,
            _ => &[],
        }
    }
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
    /// Capability evidence captured during this explicit detail load.
    pub capabilities: Option<&'static [Capability]>,
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
        let mut session = Self {
            source,
            vault,
            blocked,
            secrets: Vec::new(),
            connections: Vec::new(),
            storage: BTreeMap::new(),
            unreachable: Vec::new(),
            view: ViewSettings::default(),
            projects: Vec::new(),
            deleted: None,
            audit: None,
            details: HashMap::new(),
            keys: None,
            verification: None,
        };
        if !session.is_blocked() {
            session.read_contents()?.keep(&mut session);
        }
        Ok(session)
    }

    /// The vault's settings, its secrets (the file's and each connection's)
    /// and its project folders, all of them or none.
    fn read_contents(&self) -> Result<Contents> {
        let connections = self.source.connections()?;
        let mut storage = BTreeMap::new();
        let mut stored = Vec::new();
        for connection in &connections {
            let names = self.source.stored_at(&connection.id)?;
            if !names.is_empty() {
                stored.push(connection.id.clone());
            }
            for name in names {
                storage.insert(name, connection.id.clone());
            }
        }
        let mut secrets = self.source.secrets()?;
        let mut unreachable = Vec::new();
        for id in &stored {
            match self.source.secrets_at(id) {
                Ok(listed) => secrets.extend(listed),
                Err(err) => unreachable.push(Unreachable::from(id, &err)),
            }
        }
        secrets.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Contents {
            view: self.source.view_settings()?,
            projects: self
                .source
                .projects()?
                .into_iter()
                .map(Project::look)
                .collect(),
            connections,
            storage,
            secrets,
            unreachable,
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

    /// What the storage of `name` can express: where it is kept, or where
    /// a new secret is created.
    pub fn capabilities_of(&self, name: &str) -> Result<&'static [Capability]> {
        self.source.capabilities_of(name)
    }

    pub fn cached_capabilities(&self, name: &str) -> &'static [Capability] {
        self.detail(name)
            .and_then(|d| d.capabilities)
            .unwrap_or_else(|| {
                self.connection_of(name)
                    .map_or(Capability::ALL, |c| c.settings.provider().capabilities())
            })
    }

    /// The connection that stores `name`, when one does.
    pub fn connection_of(&self, name: &str) -> Option<&ConnectionInfo> {
        let id = self.storage.get(name)?;
        self.connections.iter().find(|c| c.id == *id)
    }

    /// The projects whose manifest declares `name`.
    pub fn projects_using(&self, name: &str) -> Vec<&Project> {
        self.projects
            .iter()
            .filter(|p| p.secrets().iter().any(|s| s == name))
            .collect()
    }

    /// Read the vault again and forget everything read before. A read
    /// that fails leaves what was read before.
    pub fn reload(&mut self) -> Result<()> {
        let vault = self.source.descriptor()?;
        let blocked = self.source.truncations()?;
        let contents = if blocked.is_empty() {
            self.read_contents()?
        } else {
            Contents::default()
        };
        self.vault = vault;
        self.blocked = blocked;
        contents.keep(self);
        self.deleted = None;
        self.audit = None;
        self.details.clear();
        self.keys = None;
        self.verification = None;
        Ok(())
    }

    pub fn deleted(&self) -> Option<&[DeletedSecret]> {
        self.deleted.as_deref()
    }

    /// Read the deleted secrets (the file's, and each connection's that
    /// was reached), unless they are already held.
    pub fn load_deleted(&mut self) -> Result<()> {
        if self.deleted.is_some() {
            return Ok(());
        }
        if self.is_blocked() {
            self.deleted = Some(Vec::new());
            return Ok(());
        }
        let mut deleted = self.source.deleted()?;
        let mut stored: Vec<&String> = self.storage.values().collect();
        stored.sort();
        stored.dedup();
        for id in stored {
            if self.unreachable.iter().any(|u| u.connection == *id) {
                continue;
            }
            match self.source.deleted_at(id) {
                Ok(listed) => deleted.extend(listed),
                Err(err) => self.unreachable.push(Unreachable::from(id, &err)),
            }
        }
        deleted.sort_by(|a, b| a.properties.name.cmp(&b.properties.name));
        self.deleted = Some(deleted);
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

    pub fn keys(&self) -> Option<&[WrapInfo]> {
        self.keys.as_deref()
    }

    /// Read the ways the vault's key opens, unless already held. Not
    /// audited.
    pub fn load_keys(&mut self) -> Result<()> {
        if self.keys.is_none() {
            self.keys = Some(self.source.keys()?);
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
        let capabilities = Some(self.source.capabilities_of(name)?);
        self.details.insert(
            name.to_owned(),
            Detail {
                versions,
                activity,
                capabilities,
            },
        );
        Ok(())
    }
}

/// What [`Session::read_contents`] read.
#[derive(Default)]
struct Contents {
    secrets: Vec<SecretProperties>,
    connections: Vec<ConnectionInfo>,
    storage: BTreeMap<String, String>,
    unreachable: Vec<Unreachable>,
    view: ViewSettings,
    projects: Vec<Project>,
}

impl Contents {
    fn keep(self, session: &mut Session) {
        session.secrets = self.secrets;
        session.connections = self.connections;
        session.storage = self.storage;
        session.unreachable = self.unreachable;
        session.view = self.view;
        session.projects = self.projects;
    }
}

impl Unreachable {
    fn from(connection: &str, err: &SecretError) -> Self {
        Self {
            connection: connection.to_owned(),
            code: err.code(),
            reason: err.to_string(),
        }
    }
}
