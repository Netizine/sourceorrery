//! The read-only vault handle.

use std::path::{Path, PathBuf};

use sourceorrery_core::{
    Secret, SecretBytes, SecretClient, SecretError, SecretProperties, SecretReference,
    VaultDescriptor,
};
use sourceorrery_storage::{SqliteVault, VaultRegistry};

use crate::error::{Context, Error, Result};
use crate::unlock::NonInteractiveUnlock;

/// How to find and unlock a vault.
///
/// The defaults reproduce the CLI: vaults under `SOURCEORRERY_HOME` (or the
/// platform data directory), unlocked by the OS credential store, then
/// `SOURCEORRERY_PASSPHRASE`, then `SOURCEORRERY_PASSPHRASE_FILE`.
#[derive(Clone, Debug)]
pub struct OpenOptions {
    /// Directory holding the `vaults/` folder. `None` honours
    /// `SOURCEORRERY_HOME` and falls back to the platform data directory.
    pub home: Option<PathBuf>,
    /// A passphrase supplied by the application, tried before the
    /// environment sources. It is zeroised when the options are dropped.
    pub passphrase: Option<SecretBytes>,
    /// A file holding the passphrase (trailing newlines ignored), tried
    /// instead of `SOURCEORRERY_PASSPHRASE_FILE`.
    pub passphrase_file: Option<PathBuf>,
    /// Consult `SOURCEORRERY_PASSPHRASE` and `SOURCEORRERY_PASSPHRASE_FILE`
    /// (default `true`). `SOURCEORRERY_HOME` is honoured regardless whenever
    /// `home` is unset.
    pub environment: bool,
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            home: None,
            passphrase: None,
            passphrase_file: None,
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

    /// Try this passphrase before the environment sources.
    #[must_use]
    pub fn passphrase(mut self, passphrase: impl Into<SecretBytes>) -> Self {
        self.passphrase = Some(passphrase.into());
        self
    }

    /// Read the passphrase from this file.
    #[must_use]
    pub fn passphrase_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.passphrase_file = Some(path.into());
        self
    }

    /// Whether the `SOURCEORRERY_PASSPHRASE*` variables are consulted.
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
/// One reader may be shared between threads. Dropping it zeroises the vault
/// key held in memory.
#[derive(Debug)]
pub struct SecretReader {
    vault: SqliteVault,
    home: PathBuf,
}

impl SecretReader {
    /// Open `vault` with [`OpenOptions::default`].
    pub fn open(vault: &str) -> Result<Self> {
        Self::open_with(vault, &OpenOptions::default())
    }

    /// Open `vault` with explicit options.
    ///
    /// Unlock order: OS credential store, `options.passphrase`,
    /// `SOURCEORRERY_PASSPHRASE`, then `options.passphrase_file` or
    /// `SOURCEORRERY_PASSPHRASE_FILE`. Each failed attempt is audited by the
    /// vault. A vault in an older on-disk format is refused with
    /// `migration_required`; readers never migrate.
    pub fn open_with(vault: &str, options: &OpenOptions) -> Result<Self> {
        let registry = options
            .registry()
            .map_err(|err| Error::new(&err, &Context::default()))?;
        let home = registry.root().to_path_buf();
        let unlock = NonInteractiveUnlock::gather(
            options.passphrase.as_ref(),
            options.passphrase_file.as_deref(),
            options.environment,
        )
        .map_err(|err| {
            Error::new(
                &err,
                &Context {
                    vault: Some(vault),
                    home: Some(&home),
                    unlock: None,
                },
            )
        })?;
        let opened = registry.open(vault, &unlock).map_err(|err| {
            Error::new(
                &err,
                &Context {
                    vault: Some(vault),
                    home: Some(&home),
                    unlock: Some(&unlock.report),
                },
            )
        })?;
        Ok(Self {
            vault: opened,
            home,
        })
    }

    /// Name of the vault this reader is bound to.
    pub fn vault_name(&self) -> &str {
        self.vault.vault_name()
    }

    /// Directory the vault was found under.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Non-sensitive description of the vault (name, id, path, protectors).
    pub fn descriptor(&self) -> Result<VaultDescriptor> {
        self.vault.descriptor().map_err(|err| self.error(&err))
    }

    /// The newest accessible version of `name`: enabled and inside its
    /// `not_before` / `expires_on` window. When none is accessible the error
    /// explains why the newest version was refused.
    pub fn get(&self, name: &str) -> Result<Secret> {
        self.vault
            .get_secret(name, None)
            .map_err(|err| self.error(&err))
    }

    /// Exactly `version` of `name`, or a policy error if that version is
    /// disabled or outside its time window.
    pub fn get_version(&self, name: &str, version: &str) -> Result<Secret> {
        self.vault
            .get_secret(name, Some(version))
            .map_err(|err| self.error(&err))
    }

    /// Metadata of one version (`None`: the newest). Policy is not applied,
    /// so disabled and expired versions can be inspected.
    pub fn properties(&self, name: &str, version: Option<&str>) -> Result<SecretProperties> {
        self.vault
            .get_secret_properties(name, version)
            .map_err(|err| self.error(&err))
    }

    /// Resolve `sourceorrery://vault/name[/version]`. The reference must
    /// name this reader's vault.
    pub fn resolve(&self, reference: &str) -> Result<Secret> {
        let parsed = SecretReference::parse(reference).map_err(|err| self.error(&err))?;
        self.resolve_reference(&parsed)
    }

    /// Resolve a parsed reference.
    pub fn resolve_reference(&self, reference: &SecretReference) -> Result<Secret> {
        self.vault
            .resolve(reference)
            .map_err(|err| self.error(&err))
    }

    fn error(&self, err: &SecretError) -> Error {
        Error::new(
            err,
            &Context {
                vault: Some(self.vault_name()),
                home: Some(&self.home),
                unlock: None,
            },
        )
    }
}
