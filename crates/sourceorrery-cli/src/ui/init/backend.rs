//! What `init`'s screens do to the world, behind one trait, so they can be
//! driven in tests (and drawn for the design snapshots) with a fake that
//! touches no vault.
//!
//! A value typed on the screens arrives here as [`SecretBytes`] and goes
//! straight to the vault; nothing here returns one. What comes back is
//! what the screens may show: vault names, the catalog (names, storage and
//! descriptions) and outcomes.

use std::path::PathBuf;

use sourceorrery_core::{SecretBytes, SetSecretOptions};
use sourceorrery_storage::{CatalogEntry, SecretStorage};

use crate::commands::init::{self, Change};
use crate::context::{Ctx, Opened};

/// A place a new secret may be kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageChoice {
    /// `SourceOrrery vault`, or the provider's name.
    pub label: String,
    pub storage: SecretStorage,
}

/// A vault the screens opened: its name, its catalog, and where it can
/// keep a new secret (the vault file first).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedVault {
    pub name: String,
    pub catalog: Vec<CatalogEntry>,
    pub storages: Vec<StorageChoice>,
}

/// What the review writes: the manifest at `path` for `project` and
/// `vault`, with these changes to its secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub path: PathBuf,
    pub project: String,
    pub vault: String,
    pub changes: Vec<Change>,
}

/// What writing the plan left.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Saved {
    pub manifest: PathBuf,
    /// The secrets the manifest declares now.
    pub secrets: usize,
}

/// The world as `init`'s screens see it.
pub trait Backend {
    /// The vaults in the home directory, by name.
    fn vaults(&self) -> Result<Vec<String>, String>;
    /// Open the vault `name` (may prompt for its recovery key: the caller
    /// takes the screen down first) and read its catalog.
    fn open(&mut self, name: &str) -> Result<OpenedVault, String>;
    /// Store a new secret in the open vault, with its description.
    fn store(
        &mut self,
        name: &str,
        value: SecretBytes,
        storage: &SecretStorage,
        description: Option<&str>,
    ) -> Result<(), String>;
    /// Write the manifest the plan describes and record the folder.
    fn write(&mut self, plan: &Plan) -> Result<Saved, String>;
}

/// The backend over this machine's vaults, through the calls the commands
/// make: `catalog`, `set_secret` routed to the secret's storage,
/// `set_description`, and `init`'s own manifest edit and folder record.
pub struct Live<'a> {
    ctx: &'a Ctx,
    opened: Option<Opened>,
}

impl<'a> Live<'a> {
    pub fn new(ctx: &'a Ctx) -> Self {
        Self { ctx, opened: None }
    }

    fn vault(&self) -> Result<&Opened, String> {
        self.opened
            .as_ref()
            .ok_or_else(|| "no vault is open".to_owned())
    }
}

impl Backend for Live<'_> {
    fn vaults(&self) -> Result<Vec<String>, String> {
        self.ctx.registry.list().map_err(|err| err.to_string())
    }

    fn open(&mut self, name: &str) -> Result<OpenedVault, String> {
        // No view check: init needs names, never values.
        let opened = self.ctx.open(name).map_err(|err| format!("{err:#}"))?;
        let vault = opened.vault();
        let catalog = vault.catalog().map_err(|err| err.to_string())?;
        let mut storages = vec![StorageChoice {
            label: "SourceOrrery vault".to_owned(),
            storage: SecretStorage::Vault,
        }];
        for connection in vault.connections().map_err(|err| err.to_string())? {
            storages.push(StorageChoice {
                label: connection.settings.provider().display_name().to_owned(),
                storage: SecretStorage::Connection(connection.id),
            });
        }
        let opened_vault = OpenedVault {
            name: sourceorrery_core::SecretClient::vault_name(vault).to_owned(),
            catalog,
            storages,
        };
        self.opened = Some(opened);
        Ok(opened_vault)
    }

    fn store(
        &mut self,
        name: &str,
        value: SecretBytes,
        storage: &SecretStorage,
        description: Option<&str>,
    ) -> Result<(), String> {
        let opened = self.vault()?;
        opened
            .set_secret_in(storage, name, value, SetSecretOptions::default())
            .map_err(|err| err.to_string())?;
        if let Some(description) = description {
            opened
                .vault()
                .set_description(name, Some(description))
                .map_err(|err| err.to_string())?;
        }
        Ok(())
    }

    fn write(&mut self, plan: &Plan) -> Result<Saved, String> {
        let opened = self.vault()?;
        let existing = init::read_existing(&plan.path).map_err(|err| format!("{err:#}"))?;
        let (previous, project) = match &existing {
            Some((text, manifest)) => {
                if !manifest.project.vault.eq_ignore_ascii_case(&plan.vault) {
                    return Err(format!(
                        "{} names vault '{}', not '{}'",
                        plan.path.display(),
                        manifest.project.vault,
                        plan.vault
                    ));
                }
                (Some(text.as_str()), manifest.project.name.clone())
            }
            None => (None, plan.project.clone()),
        };
        let base = previous.map_or_else(
            || init::new_manifest_text(&project, &plan.vault),
            str::to_owned,
        );
        let text = init::edit_secrets(&base, &plan.changes).map_err(|err| format!("{err:#}"))?;
        init::save(opened.vault(), &plan.path, previous, &text, &project)
            .map_err(|err| format!("{err:#}"))?;
        let secrets = sourceorrery_core::Manifest::parse(&text)
            .map(|manifest| manifest.secrets.len())
            .unwrap_or_default();
        Ok(Saved {
            manifest: plan.path.clone(),
            secrets,
        })
    }
}
