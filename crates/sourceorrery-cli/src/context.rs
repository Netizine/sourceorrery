//! Shared state for every command: where vaults live, how to unlock them,
//! how to print.

use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, anyhow};
use sourceorrery_core::{
    AuditEvent, AuditQuery, DeletedSecret, ListOptions, Manifest, Page, RemoteVault,
    Result as CoreResult, Secret, SecretBytes, SecretClient, SecretProperties, SecretReference,
    SetSecretOptions, UpdateSecretProperties, VaultDescriptor,
};
use sourceorrery_provider::Remote;
use sourceorrery_storage::{PassphrasePrompt, SqliteVault, UnlockProvider, VaultRegistry};

use crate::cli::{Cli, OutputFormat};
use crate::prompt;

/// Environment variable that supplies a passphrase directly (CI only).
pub const PASSPHRASE_ENV: &str = "SOURCEORRERY_PASSPHRASE";

/// Variables that unlock a vault. `run` strips them from the child's environment.
pub const UNLOCK_ENV_VARS: [&str; 2] = [PASSPHRASE_ENV, "SOURCEORRERY_PASSPHRASE_FILE"];

#[derive(Debug)]
pub struct Ctx {
    pub registry: VaultRegistry,
    pub output: OutputFormat,
    pub vault_flag: Option<String>,
    pub passphrase_file: Option<PathBuf>,
    pub verbose: u8,
}

impl Ctx {
    pub fn from_cli(cli: &Cli) -> anyhow::Result<Self> {
        let registry = match &cli.home {
            Some(home) => VaultRegistry::with_root(home.clone()),
            None => VaultRegistry::from_env()?,
        };
        Ok(Self {
            registry,
            output: cli.output,
            vault_flag: cli.vault.clone(),
            passphrase_file: cli.passphrase_file.clone(),
            verbose: cli.verbose,
        })
    }

    pub fn json(&self) -> bool {
        self.output == OutputFormat::Json
    }

    /// The vault a command should act on: `--vault`, else the manifest found
    /// upwards from the current directory.
    pub fn vault_name(&self) -> anyhow::Result<String> {
        self.selected_vault()?.ok_or_else(|| {
            anyhow!(
                "no vault specified: pass --vault <name>, set SOURCEORRERY_VAULT, or run `sourceorrery init`"
            )
        })
    }

    /// [`Ctx::vault_name`], with `None` when neither `--vault` nor a
    /// manifest names one. A manifest that cannot be read is still an error.
    pub fn selected_vault(&self) -> anyhow::Result<Option<String>> {
        if let Some(name) = &self.vault_flag {
            return Ok(Some(name.clone()));
        }
        Ok(Self::manifest()?.map(|manifest| manifest.project.vault))
    }

    /// The nearest `sourceorrery.toml` above the current directory, parsed.
    /// `None` when there is none; one that cannot be read is an error.
    fn manifest() -> anyhow::Result<Option<Manifest>> {
        let cwd = std::env::current_dir().context("cannot determine current directory")?;
        match Manifest::discover(&cwd) {
            Some(path) => Ok(Some(Manifest::load(&path)?)),
            None => Ok(None),
        }
    }

    /// The `[vaults.<name>]` table of the nearest manifest, when `name` is a
    /// remote vault; `None` for a local vault file.
    pub fn remote_vault(name: &str) -> anyhow::Result<Option<RemoteVault>> {
        Ok(Self::manifest()?.and_then(|m| m.remote_vault(name).cloned()))
    }

    /// Every remote vault the nearest manifest declares, by name.
    pub fn remote_vaults() -> anyhow::Result<BTreeMap<String, RemoteVault>> {
        Ok(Self::manifest()?.map(|m| m.vaults).unwrap_or_default())
    }

    /// Fail when `name` is a remote vault, naming `command` as local-only.
    pub fn refuse_remote(name: &str, command: &str) -> anyhow::Result<()> {
        match Self::remote_vault(name)? {
            Some(remote) => Err(anyhow!(
                "vault '{name}' is a remote vault ({}, declared in sourceorrery.toml); \
                 `sourceorrery {command}` works on local vaults only",
                remote.provider().display_name()
            )),
            None => Ok(()),
        }
    }

    /// Open a vault by name for the operations of the contract: the local
    /// file unlocked, or the remote provider the manifest names.
    pub fn open(&self, name: &str) -> anyhow::Result<Opened> {
        if let Some(remote) = Self::remote_vault(name)? {
            return Ok(Opened::Remote(sourceorrery_provider::open_remote(
                name, &remote,
            )?));
        }
        Ok(Opened::Local(Box::new(self.open_local_file(name)?)))
    }

    /// Open the vault selected by [`Ctx::vault_name`].
    pub fn open_default(&self) -> anyhow::Result<Opened> {
        let name = self.vault_name()?;
        self.open(&name)
    }

    /// Open a vault that must be a local file, for what only a file has
    /// (protectors, the audit log, backups, migration). `command` names the
    /// command for the refusal a remote vault gets.
    pub fn open_local(&self, name: &str, command: &str) -> anyhow::Result<SqliteVault> {
        Self::refuse_remote(name, command)?;
        self.open_local_file(name)
    }

    /// [`Ctx::open_local`] for the vault selected by [`Ctx::vault_name`].
    pub fn open_local_default(&self, command: &str) -> anyhow::Result<SqliteVault> {
        let name = self.vault_name()?;
        self.open_local(&name, command)
    }

    fn open_local_file(&self, name: &str) -> anyhow::Result<SqliteVault> {
        let unlocker = self.unlocker();
        Ok(self.registry.open(name, &unlocker)?)
    }

    /// Open the selected vault to inspect its audit log: like
    /// [`Ctx::open_local_default`], but a vault blocked by an unacknowledged
    /// audit-log truncation is unlocked too, with every secret and
    /// protector operation refused until the truncation is acknowledged.
    /// Only the `audit` command uses this.
    pub fn inspect_default(&self) -> anyhow::Result<SqliteVault> {
        let name = self.vault_name()?;
        self.inspect(&name)
    }

    /// [`Ctx::inspect_default`] for a vault named explicitly. Besides
    /// `audit`, the `ui` browser opens vaults this way, so that a blocked
    /// vault can still show its audit log there; the vault itself refuses
    /// every secret operation until the truncation is acknowledged. A
    /// remote vault has no local audit log and is refused.
    pub fn inspect(&self, name: &str) -> anyhow::Result<SqliteVault> {
        Self::refuse_remote(name, "audit` and `sourceorrery ui")?;
        let unlocker = self.unlocker();
        Ok(self.registry.open_for_inspection(name, &unlocker)?)
    }

    pub fn unlocker(&self) -> Unlocker {
        Unlocker {
            file: self.passphrase_file.clone(),
            interactive: std::io::stdin().is_terminal(),
        }
    }

    /// Obtain a passphrase for creating a protector: from the environment or
    /// file when configured, otherwise prompted twice.
    pub fn new_passphrase(&self, purpose: &str) -> anyhow::Result<SecretBytes> {
        if let Some(pass) = passphrase_from_env() {
            return Ok(pass);
        }
        if let Some(file) = &self.passphrase_file {
            return read_passphrase_file(file);
        }
        if !std::io::stdin().is_terminal() {
            return Err(anyhow!(
                "cannot prompt for a passphrase: stdin is not a terminal. \
                 Set {PASSPHRASE_ENV} or --passphrase-file."
            ));
        }
        let first = prompt::read_hidden(&format!("Choose a passphrase {purpose}: "))?;
        let second = prompt::read_hidden("Confirm passphrase: ")?;
        if first != second {
            return Err(anyhow!("passphrases do not match"));
        }
        if first.is_empty() {
            return Err(anyhow!("passphrase must not be empty"));
        }
        Ok(first)
    }
}

fn passphrase_from_env() -> Option<SecretBytes> {
    std::env::var(PASSPHRASE_ENV)
        .ok()
        .filter(|v| !v.is_empty())
        .map(SecretBytes::from_string)
}

fn read_passphrase_file(path: &Path) -> anyhow::Result<SecretBytes> {
    let mut bytes = std::fs::read(path)
        .with_context(|| format!("cannot read passphrase file {}", path.display()))?;
    while bytes.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Err(anyhow!("passphrase file {} is empty", path.display()));
    }
    Ok(SecretBytes::new(bytes))
}

/// Supplies passphrases: environment variable, then file, then an
/// interactive prompt (when stdin is a terminal).
#[derive(Debug)]
pub struct Unlocker {
    file: Option<PathBuf>,
    interactive: bool,
}

impl UnlockProvider for Unlocker {
    fn passphrase(&self, prompt: &PassphrasePrompt<'_>) -> CoreResult<Option<SecretBytes>> {
        // Non-interactive sources are tried once only; a wrong value is wrong.
        if prompt.attempt == 1 {
            if let Some(pass) = passphrase_from_env() {
                return Ok(Some(pass));
            }
            if let Some(file) = &self.file {
                return read_passphrase_file(file)
                    .map(Some)
                    .map_err(|err| sourceorrery_core::SecretError::Io(err.to_string()));
            }
        }
        if !self.interactive {
            return Ok(None);
        }
        let text = if prompt.attempt == 1 {
            format!("Passphrase for vault '{}': ", prompt.vault)
        } else {
            format!(
                "Passphrase for vault '{}' (attempt {} of {}): ",
                prompt.vault, prompt.attempt, prompt.max_attempts
            )
        };
        prompt::read_hidden(&text)
            .map(Some)
            .map_err(|err| sourceorrery_core::SecretError::Io(err.to_string()))
    }
}

/// A vault open for the operations of the contract: the local file, or the
/// client of the remote provider the manifest names. Commands that need
/// what only a file has use [`Ctx::open_local`] instead.
#[derive(Debug)]
pub enum Opened {
    /// An unlocked vault file.
    Local(Box<SqliteVault>),
    /// A remote vault behind its provider.
    Remote(Remote),
}

impl Opened {
    fn client(&self) -> &dyn SecretClient {
        match self {
            Self::Local(vault) => vault.as_ref(),
            Self::Remote(remote) => remote.client.as_ref(),
        }
    }

    /// Name, backend and location.
    pub fn descriptor(&self) -> CoreResult<VaultDescriptor> {
        match self {
            Self::Local(vault) => vault.descriptor(),
            Self::Remote(remote) => Ok(remote.descriptor.clone()),
        }
    }

    /// The vault file, when the vault is one.
    pub fn local(&self) -> Option<&SqliteVault> {
        match self {
            Self::Local(vault) => Some(vault.as_ref()),
            Self::Remote(_) => None,
        }
    }
}

impl SecretClient for Opened {
    fn vault_name(&self) -> &str {
        self.client().vault_name()
    }
    fn set_secret(
        &self,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
    ) -> CoreResult<SecretProperties> {
        self.client().set_secret(name, value, options)
    }
    fn get_secret(&self, name: &str, version: Option<&str>) -> CoreResult<Secret> {
        self.client().get_secret(name, version)
    }
    fn get_secret_properties(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> CoreResult<SecretProperties> {
        self.client().get_secret_properties(name, version)
    }
    fn list_properties_of_secrets(&self) -> CoreResult<Vec<SecretProperties>> {
        self.client().list_properties_of_secrets()
    }
    fn list_properties_of_secrets_page(
        &self,
        options: ListOptions,
    ) -> CoreResult<Page<SecretProperties>> {
        self.client().list_properties_of_secrets_page(options)
    }
    fn list_properties_of_secret_versions(&self, name: &str) -> CoreResult<Vec<SecretProperties>> {
        self.client().list_properties_of_secret_versions(name)
    }
    fn update_secret_properties(
        &self,
        name: &str,
        version: Option<&str>,
        update: UpdateSecretProperties,
    ) -> CoreResult<SecretProperties> {
        self.client()
            .update_secret_properties(name, version, update)
    }
    fn delete_secret(&self, name: &str) -> CoreResult<DeletedSecret> {
        self.client().delete_secret(name)
    }
    fn get_deleted_secret(&self, name: &str) -> CoreResult<DeletedSecret> {
        self.client().get_deleted_secret(name)
    }
    fn list_deleted_secrets(&self) -> CoreResult<Vec<DeletedSecret>> {
        self.client().list_deleted_secrets()
    }
    fn list_deleted_secrets_page(&self, options: ListOptions) -> CoreResult<Page<DeletedSecret>> {
        self.client().list_deleted_secrets_page(options)
    }
    fn recover_deleted_secret(&self, name: &str) -> CoreResult<SecretProperties> {
        self.client().recover_deleted_secret(name)
    }
    fn purge_deleted_secret(&self, name: &str) -> CoreResult<()> {
        self.client().purge_deleted_secret(name)
    }
    fn audit_events(&self, query: AuditQuery) -> CoreResult<Vec<AuditEvent>> {
        self.client().audit_events(query)
    }
    fn resolve(&self, reference: &SecretReference) -> CoreResult<Secret> {
        self.client().resolve(reference)
    }
}
