//! Shared fixtures for the SourceOrrery conformance suite.
//!
//! Every SDK binding is expected to run the same scenarios against the same
//! semantics; the fixtures here define those scenarios once.

#![forbid(unsafe_code)]

use sourceorrery_core::SecretBytes;
use sourceorrery_crypto::Argon2Params;
use sourceorrery_storage::{
    Acknowledgement, CreateVaultOptions, ProtectorSpec, SqliteVault, StaticPassphrase,
    VaultRegistry,
};

/// Passphrase used by every fixture vault.
pub const FIXTURE_PASSPHRASE: &str = "conformance-passphrase";

/// A temporary home directory holding fixture vaults.
#[derive(Debug)]
pub struct Fixture {
    /// Keeps the temporary directory alive.
    pub home: tempfile::TempDir,
    /// Registry rooted in `home`.
    pub registry: VaultRegistry,
}

impl Fixture {
    /// Create an empty home.
    pub fn new() -> Self {
        let home = tempfile::tempdir().expect("temp dir");
        let registry = VaultRegistry::with_root(home.path());
        Self { home, registry }
    }

    /// Create a passphrase-protected vault with cheap KDF parameters.
    pub fn create_vault(&self, name: &str) -> SqliteVault {
        self.create_vault_with(name, CreateVaultOptions::default())
    }

    /// Create a vault with explicit options.
    pub fn create_vault_with(&self, name: &str, options: CreateVaultOptions) -> SqliteVault {
        self.registry
            .create(
                name,
                options,
                ProtectorSpec::Passphrase {
                    passphrase: SecretBytes::from(FIXTURE_PASSPHRASE),
                    params: Argon2Params::TESTING,
                },
            )
            .expect("create vault")
    }

    /// Re-open a fixture vault with the fixture passphrase.
    pub fn open_vault(&self, name: &str) -> SqliteVault {
        self.registry
            .open(name, &StaticPassphrase::new(FIXTURE_PASSPHRASE))
            .expect("open vault")
    }

    /// Unlock a legacy-schema fixture vault and migrate it forward.
    pub fn migrate_vault(&self, name: &str) -> SqliteVault {
        self.registry
            .migrate(name, &StaticPassphrase::new(FIXTURE_PASSPHRASE))
            .expect("migrate vault")
    }

    /// Unlock a fixture vault for audit-log inspection: works on a vault
    /// blocked by an unacknowledged truncation.
    pub fn inspect_vault(&self, name: &str) -> SqliteVault {
        self.registry
            .open_for_inspection(name, &StaticPassphrase::new(FIXTURE_PASSPHRASE))
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
