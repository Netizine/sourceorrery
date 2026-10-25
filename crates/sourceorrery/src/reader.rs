//! The read-only vault handle.

use std::path::{Path, PathBuf};

use sourceorrery_core::{
    Provider, Secret, SecretBytes, SecretClient, SecretError, SecretProperties, SecretReference,
    VaultDescriptor,
};
use sourceorrery_provider::Routed;
use sourceorrery_storage::{SecretStorage, VaultRegistry};

use crate::error::{Context, Error, Result};
use crate::unlock::NonInteractiveUnlock;

/// How to find and unlock a vault.
///
/// The defaults reproduce the CLI: vaults under `SOURCEORRERY_HOME` (or the
/// platform data directory), opened by this machine's key in the OS
/// credential store, then the recovery key in `SOURCEORRERY_RECOVERY_KEY`,
/// then in `SOURCEORRERY_RECOVERY_KEY_FILE`. Where each secret is kept, the
/// vault file or a provider one of the vault's connections reaches, is the
/// vault's own record.
#[derive(Clone, Debug)]
pub struct OpenOptions {
    /// Directory holding the `vaults/` folder. `None` honours
    /// `SOURCEORRERY_HOME` and falls back to the platform data directory.
    pub home: Option<PathBuf>,
    /// The vault's recovery key, supplied by the application, tried before
    /// the environment sources. It is zeroised when the options are dropped.
    pub recovery_key: Option<SecretBytes>,
    /// A file holding the recovery key (trailing newlines ignored), tried
    /// instead of `SOURCEORRERY_RECOVERY_KEY_FILE`.
    pub recovery_key_file: Option<PathBuf>,
    /// Consult `SOURCEORRERY_RECOVERY_KEY` and `SOURCEORRERY_RECOVERY_KEY_FILE`
    /// (default `true`). `SOURCEORRERY_HOME` is honoured regardless whenever
    /// `home` is unset.
    pub environment: bool,
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            home: None,
            recovery_key: None,
            recovery_key_file: None,
            environment: true,
        }
    }
}

impl OpenOptions {
    /// The CLI's defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Look for vaults under `home` instead of `SOURCEORRERY_HOME`.
    #[must_use]
    pub fn home(mut self, home: impl Into<PathBuf>) -> Self {
        self.home = Some(home.into());
        self
    }

    /// Try this recovery key before the environment sources.
    #[must_use]
    pub fn recovery_key(mut self, key: impl Into<SecretBytes>) -> Self {
        self.recovery_key = Some(key.into());
        self
    }

    /// Read the recovery key from this file.
    #[must_use]
    pub fn recovery_key_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.recovery_key_file = Some(path.into());
        self
    }

    /// Whether the `SOURCEORRERY_RECOVERY_KEY*` variables are consulted.
    #[must_use]
    pub fn environment(mut self, environment: bool) -> Self {
        self.environment = environment;
        self
    }

    fn registry(&self) -> sourceorrery_core::Result<VaultRegistry> {
        match &self.home {
            Some(home) if !home.as_os_str().is_empty() => Ok(VaultRegistry::with_root(home)),
            _ => VaultRegistry::from_env(),
        }
    }
}

/// An unlocked vault that can only be read.
///
/// Each read goes where the vault keeps the secret: its own file, or the
/// provider one of its connections reaches, opened on first use with the
/// credentials the connection stores or the provider's own chain. Reads
/// at a provider are recorded in the vault's audit log too. One reader may
/// be shared between threads. Dropping it zeroises the vault key held in
/// memory.
#[derive(Debug)]
pub struct SecretReader {
    vault: Routed,
    home: PathBuf,
}

impl SecretReader {
    /// Open `vault` with [`OpenOptions::default`].
    pub fn open(vault: &str) -> Result<Self> {
        Self::open_with(vault, &OpenOptions::default())
    }

    /// Open `vault` with explicit options.
    ///
    /// The vault file is opened in this order: this machine's key in the OS
    /// credential store, then the recovery key from `options.recovery_key`,
    /// `SOURCEORRERY_RECOVERY_KEY`, then `options.recovery_key_file` or
    /// `SOURCEORRERY_RECOVERY_KEY_FILE`. Each failed attempt is audited by
    /// the vault. No provider is contacted until a secret it stores is read.
    /// A vault written by an earlier release is refused with
    /// `migration_required`.
    pub fn open_with(vault: &str, options: &OpenOptions) -> Result<Self> {
        let registry = options
            .registry()
            .map_err(|err| Error::new(&err, &Context::default()))?;
        let home = registry.root().to_path_buf();
        // Each source is read only if the vault asks for it (SR08).
        let unlock = NonInteractiveUnlock::new(
            options.recovery_key.as_ref(),
            options.recovery_key_file.as_deref(),
            options.environment,
        );
        let opened = registry.open(vault, &unlock).map_err(|err| {
            Error::new(
                &err,
                &Context {
                    vault: Some(vault),
                    home: Some(&home),
                    unlock: Some(&unlock.report()),
                    provider: None,
                },
            )
        })?;
        Ok(Self {
            vault: Routed::new(opened),
            home,
        })
    }

    /// Name of the vault this reader is bound to.
    pub fn vault_name(&self) -> &str {
        self.vault.vault_name()
    }

    /// Directory vaults are looked up under.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Non-sensitive description of the vault (name, id, path, key wraps).
    pub fn descriptor(&self) -> Result<VaultDescriptor> {
        self.vault
            .vault()
            .descriptor()
            .map_err(|err| self.error(&err, None))
    }

    /// The newest accessible version of `name`: enabled and inside its
    /// `not_before` / `expires_on` window. When none is accessible the error
    /// explains why the newest version was refused.
    pub fn get(&self, name: &str) -> Result<Secret> {
        self.vault
            .get_secret(name, None)
            .map_err(|err| self.error(&err, Some(name)))
    }

    /// Exactly `version` of `name`, or a policy error if that version is
    /// disabled or outside its time window.
    pub fn get_version(&self, name: &str, version: &str) -> Result<Secret> {
        self.vault
            .get_secret(name, Some(version))
            .map_err(|err| self.error(&err, Some(name)))
    }

    /// Metadata of one version (`None`: the newest). Policy is not applied,
    /// so disabled and expired versions can be inspected.
    pub fn properties(&self, name: &str, version: Option<&str>) -> Result<SecretProperties> {
        self.vault
            .get_secret_properties(name, version)
            .map_err(|err| self.error(&err, Some(name)))
    }

    /// Resolve `sourceorrery://vault/name[/version]`. The reference must
    /// name this reader's vault.
    pub fn resolve(&self, reference: &str) -> Result<Secret> {
        let parsed = SecretReference::parse(reference).map_err(|err| self.error(&err, None))?;
        self.resolve_reference(&parsed)
    }

    /// Resolve a parsed reference.
    pub fn resolve_reference(&self, reference: &SecretReference) -> Result<Secret> {
        self.vault
            .resolve(reference)
            .map_err(|err| self.error(&err, Some(&reference.name)))
    }

    /// The provider that stores `name`, when a connection of the vault does.
    fn provider_of(&self, name: &str) -> Option<Provider> {
        let vault = self.vault.vault();
        match vault.storage_of(name).ok()?? {
            SecretStorage::Connection(id) => {
                vault.connection(&id).ok().map(|c| c.settings.provider())
            }
            SecretStorage::Vault => None,
        }
    }

    fn error(&self, err: &SecretError, name: Option<&str>) -> Error {
        Error::new(
            err,
            &Context {
                vault: Some(self.vault_name()),
                home: Some(&self.home),
                unlock: None,
                provider: name.and_then(|name| self.provider_of(name)),
            },
        )
    }
}
