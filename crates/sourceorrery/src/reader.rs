//! The read-only vault handle.

use std::path::{Path, PathBuf};

use sourceorrery_core::{
    Manifest, Provider, RemoteVault, Secret, SecretBytes, SecretClient, SecretError,
    SecretProperties, SecretReference, VaultDescriptor,
};
use sourceorrery_provider::Remote;
use sourceorrery_storage::{SqliteVault, VaultRegistry};

use crate::error::{Context, Error, Result};
use crate::unlock::NonInteractiveUnlock;

/// How to find and unlock a vault.
///
/// The defaults reproduce the CLI: vaults under `SOURCEORRERY_HOME` (or the
/// platform data directory), unlocked by the OS credential store, then
/// `SOURCEORRERY_PASSPHRASE`, then `SOURCEORRERY_PASSPHRASE_FILE`; a vault
/// that the nearest `sourceorrery.toml` declares as remote (`[vaults.<name>]`)
/// is opened at its provider instead.
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
    /// The `sourceorrery.toml` whose `[vaults.<name>]` tables say which
    /// vaults are remote and where. `None` uses the nearest manifest above
    /// the current directory, as `sourceorrery run` does; a vault without a
    /// table, or no manifest at all, is a local vault file.
    pub manifest: Option<PathBuf>,
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            home: None,
            passphrase: None,
            passphrase_file: None,
            environment: true,
            manifest: None,
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

    /// Resolve remote vaults through this manifest instead of the nearest
    /// `sourceorrery.toml`.
    #[must_use]
    pub fn manifest(mut self, path: impl Into<PathBuf>) -> Self {
        self.manifest = Some(path.into());
        self
    }

    /// The `[vaults.<vault>]` table for `vault`, from the manifest the
    /// options name or the nearest one; `None` for a local vault.
    fn remote_vault(&self, vault: &str) -> Result<Option<RemoteVault>> {
        let path = match &self.manifest {
            Some(path) if !path.as_os_str().is_empty() => path.clone(),
            _ => {
                let Some(found) = std::env::current_dir()
                    .ok()
                    .and_then(|cwd| Manifest::discover(&cwd))
                else {
                    return Ok(None);
                };
                found
            }
        };
        let manifest = Manifest::load(&path).map_err(|err| {
            Error::new(
                &err,
                &Context {
                    vault: Some(vault),
                    ..Context::default()
                },
            )
        })?;
        Ok(manifest.remote_vault(vault).cloned())
    }

    fn registry(&self) -> sourceorrery_core::Result<VaultRegistry> {
        match &self.home {
            Some(home) if !home.as_os_str().is_empty() => Ok(VaultRegistry::with_root(home)),
            _ => VaultRegistry::from_env(),
        }
    }
}

/// Where a reader's secrets come from.
#[derive(Debug)]
enum Backend {
    /// An encrypted vault file in the home directory.
    Local(Box<SqliteVault>),
    /// A remote provider named by the manifest.
    Remote(Remote),
}

/// An unlocked vault that can only be read.
///
/// One reader may be shared between threads. Dropping it zeroises the vault
/// key held in memory.
#[derive(Debug)]
pub struct SecretReader {
    backend: Backend,
    home: PathBuf,
    provider: Option<Provider>,
}

impl SecretReader {
    /// Open `vault` with [`OpenOptions::default`].
    pub fn open(vault: &str) -> Result<Self> {
        Self::open_with(vault, &OpenOptions::default())
    }

    /// Open `vault` with explicit options.
    ///
    /// A vault the manifest declares as remote ([`OpenOptions::manifest`])
    /// is opened at its provider with the credentials the provider's own
    /// environment supplies. Otherwise the vault file is unlocked in this
    /// order: OS credential store, `options.passphrase`,
    /// `SOURCEORRERY_PASSPHRASE`, then `options.passphrase_file` or
    /// `SOURCEORRERY_PASSPHRASE_FILE`. Each failed attempt is audited by the
    /// vault. A vault in an older on-disk format is refused with
    /// `migration_required`; readers never migrate.
    pub fn open_with(vault: &str, options: &OpenOptions) -> Result<Self> {
        let registry = options
            .registry()
            .map_err(|err| Error::new(&err, &Context::default()))?;
        let home = registry.root().to_path_buf();
        if let Some(remote) = options.remote_vault(vault)? {
            let provider = remote.provider();
            let opened = sourceorrery_provider::open_remote(vault, &remote).map_err(|err| {
                Error::new(
                    &err,
                    &Context {
                        vault: Some(vault),
                        provider: Some(provider),
                        ..Context::default()
                    },
                )
            })?;
            return Ok(Self {
                backend: Backend::Remote(opened),
                home,
                provider: Some(provider),
            });
        }
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
                    provider: None,
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
                    provider: None,
                },
            )
        })?;
        Ok(Self {
            backend: Backend::Local(Box::new(opened)),
            home,
            provider: None,
        })
    }

    fn client(&self) -> &dyn SecretClient {
        match &self.backend {
            Backend::Local(vault) => vault.as_ref(),
            Backend::Remote(remote) => remote.client.as_ref(),
        }
    }

    /// Name of the vault this reader is bound to.
    pub fn vault_name(&self) -> &str {
        self.client().vault_name()
    }

    /// Directory local vaults are looked up under.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// The remote provider serving this vault; `None` for a local vault file.
    pub fn provider(&self) -> Option<Provider> {
        self.provider
    }

    /// Non-sensitive description of the vault (name, id, path, protectors;
    /// for a remote vault, what its provider reports).
    pub fn descriptor(&self) -> Result<VaultDescriptor> {
        match &self.backend {
            Backend::Local(vault) => vault.descriptor().map_err(|err| self.error(&err)),
            Backend::Remote(remote) => Ok(remote.descriptor.clone()),
        }
    }

    /// The newest accessible version of `name`: enabled and inside its
    /// `not_before` / `expires_on` window. When none is accessible the error
    /// explains why the newest version was refused.
    pub fn get(&self, name: &str) -> Result<Secret> {
        self.client()
            .get_secret(name, None)
            .map_err(|err| self.error(&err))
    }

    /// Exactly `version` of `name`, or a policy error if that version is
    /// disabled or outside its time window.
    pub fn get_version(&self, name: &str, version: &str) -> Result<Secret> {
        self.client()
            .get_secret(name, Some(version))
            .map_err(|err| self.error(&err))
    }

    /// Metadata of one version (`None`: the newest). Policy is not applied,
    /// so disabled and expired versions can be inspected.
    pub fn properties(&self, name: &str, version: Option<&str>) -> Result<SecretProperties> {
        self.client()
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
        self.client()
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
                provider: self.provider,
            },
        )
    }
}
