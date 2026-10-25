//! Shared fixtures for the SourceOrrery conformance suite.
//!
//! Every SDK binding is expected to run the same scenarios against the same
//! semantics; the fixtures here define those scenarios once. The
//! [`lifecycle`] module holds the scenarios every backend must pass, over
//! `&dyn SecretClient`, and [`lifecycle::lifecycle`] runs them.

#![forbid(unsafe_code)]

pub mod lifecycle;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use sourceorrery_storage::{
    Acknowledgement, CreateVaultOptions, NoStore, SqliteVault, StaticRecoveryKey, VaultRegistry,
};

/// A temporary home directory holding fixture vaults. Its registry has no
/// credential store, so a fixture never touches the real OS store and every
/// vault opens with the recovery key it was created with, which the fixture
/// remembers.
#[derive(Debug)]
pub struct Fixture {
    /// Keeps the temporary directory alive.
    pub home: tempfile::TempDir,
    /// Registry rooted in `home`.
    pub registry: VaultRegistry,
    recovery_keys: Mutex<BTreeMap<String, String>>,
}

impl Fixture {
    /// Create an empty home.
    pub fn new() -> Self {
        let home = tempfile::tempdir().expect("temp dir");
        let registry = VaultRegistry::with_root(home.path()).with_store(Arc::new(NoStore));
        Self {
            home,
            registry,
            recovery_keys: Mutex::new(BTreeMap::new()),
        }
    }

    /// Create a vault, remembering its recovery key.
    pub fn create_vault(&self, name: &str) -> SqliteVault {
        self.create_vault_with(name, CreateVaultOptions::default())
    }

    /// Create a vault with explicit options.
    pub fn create_vault_with(&self, name: &str, options: CreateVaultOptions) -> SqliteVault {
        let created = self.registry.create(name, options).expect("create vault");
        self.recovery_keys
            .lock()
            .expect("fixture keys")
            .insert(name.to_owned(), created.recovery_key.to_string());
        created.vault
    }

    /// The recovery key of a vault this fixture created.
    pub fn recovery_key(&self, name: &str) -> String {
        self.recovery_keys
            .lock()
            .expect("fixture keys")
            .get(name)
            .cloned()
            .unwrap_or_else(|| panic!("the fixture created no vault named {name}"))
    }

    /// What opens a fixture vault: its recovery key, once.
    pub fn unlock(&self, name: &str) -> StaticRecoveryKey {
        StaticRecoveryKey::new(self.recovery_key(name))
    }

    /// Re-open a fixture vault with its recovery key.
    pub fn open_vault(&self, name: &str) -> SqliteVault {
        self.registry
            .open(name, &self.unlock(name))
            .expect("open vault")
    }

    /// Open a fixture vault for audit-log inspection: works on a vault
    /// blocked by an unacknowledged truncation.
    pub fn inspect_vault(&self, name: &str) -> SqliteVault {
        self.registry
            .open_for_inspection(name, &self.unlock(name))
            .expect("open vault for inspection")
    }

    /// Acknowledge every detected truncation of a fixture vault's audit
    /// log, as its owner would with `sourceorrery audit --acknowledge`.
    pub fn acknowledge_truncations(&self, name: &str) -> Acknowledgement {
        let vault = self.inspect_vault(name);
        let ids: Vec<u64> = vault
            .unacknowledged_truncations()
            .expect("list truncations")
            .iter()
            .map(|e| e.id)
            .collect();
        vault
            .acknowledge_truncations(&ids)
            .expect("acknowledge truncations")
    }
}

impl Default for Fixture {
    fn default() -> Self {
        Self::new()
    }
}
