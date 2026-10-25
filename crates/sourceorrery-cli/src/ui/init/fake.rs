//! A backend that touches no vault: fixed vaults and a fixed catalog, and
//! what the screens asked for, recorded, so they can be driven and drawn in
//! tests.

use sourceorrery_core::SecretBytes;
use sourceorrery_storage::{CatalogEntry, SecretStorage};

use super::backend::{Backend, OpenedVault, Plan, Saved, StorageChoice};

#[derive(Debug, Default)]
pub struct Fake {
    pub vaults: Vec<String>,
    pub catalog: Vec<CatalogEntry>,
    /// A connection the vault has, besides the vault file.
    pub connection: bool,
    /// Refuse to open a vault with this message.
    pub refuse_open: Option<String>,
    /// The vaults opened, in order.
    pub opened: Vec<String>,
    /// `(name, value length, storage, description)` of each secret stored.
    pub stored: Vec<(String, usize, SecretStorage, Option<String>)>,
    /// The plan written.
    pub written: Option<Plan>,
}

impl Fake {
    /// One vault, `dev`, holding `database-password` (described) and
    /// `api-key`, with a HashiCorp Vault connection.
    pub fn one_vault() -> Self {
        Self {
            vaults: vec!["dev".to_owned()],
            catalog: vec![
                CatalogEntry {
                    name: "api-key".to_owned(),
                    storage: SecretStorage::Connection("c1".to_owned()),
                    description: None,
                },
                CatalogEntry {
                    name: "database-password".to_owned(),
                    storage: SecretStorage::Vault,
                    description: Some("Database authentication".to_owned()),
                },
            ],
            connection: true,
            ..Self::default()
        }
    }
}

impl Backend for Fake {
    fn vaults(&self) -> Result<Vec<String>, String> {
        Ok(self.vaults.clone())
    }

    fn open(&mut self, name: &str) -> Result<OpenedVault, String> {
        if let Some(refusal) = &self.refuse_open {
            return Err(refusal.clone());
        }
        self.opened.push(name.to_owned());
        let mut storages = vec![StorageChoice {
            label: "SourceOrrery vault".to_owned(),
            storage: SecretStorage::Vault,
        }];
        if self.connection {
            storages.push(StorageChoice {
                label: "HashiCorp Vault".to_owned(),
                storage: SecretStorage::Connection("c1".to_owned()),
            });
        }
        Ok(OpenedVault {
            name: name.to_owned(),
            catalog: self.catalog.clone(),
            storages,
        })
    }

    fn store(
        &mut self,
        name: &str,
        value: SecretBytes,
        storage: &SecretStorage,
        description: Option<&str>,
    ) -> Result<(), String> {
        self.stored.push((
            name.to_owned(),
            value.expose().len(),
            storage.clone(),
            description.map(str::to_owned),
        ));
        Ok(())
    }

    fn write(&mut self, plan: &Plan) -> Result<Saved, String> {
        self.written = Some(plan.clone());
        Ok(Saved {
            manifest: plan.path.clone(),
            secrets: plan.changes.len(),
        })
    }
}
