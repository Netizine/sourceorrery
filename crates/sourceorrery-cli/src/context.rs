//! Shared state for every command: where vaults live, how to unlock them,
//! how to print.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, anyhow};
use sourceorrery_core::{Manifest, Result as CoreResult, SecretBytes};
use sourceorrery_storage::{PassphrasePrompt, SqliteVault, UnlockProvider, VaultRegistry};

use crate::cli::{Cli, OutputFormat};
use crate::prompt;

/// Environment variable that supplies a passphrase directly (CI only).
pub const PASSPHRASE_ENV: &str = "SOURCEORRERY_PASSPHRASE";

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
        if let Some(name) = &self.vault_flag {
            return Ok(name.clone());
        }
        let cwd = std::env::current_dir().context("cannot determine current directory")?;
        if let Some(path) = Manifest::discover(&cwd) {
            let manifest = Manifest::load(&path)?;
            return Ok(manifest.project.vault);
        }
        Err(anyhow!(
            "no vault specified: pass --vault <name>, set SOURCEORRERY_VAULT, or run `sourceorrery init`"
        ))
    }

    /// Open and unlock a vault by name.
    pub fn open(&self, name: &str) -> anyhow::Result<SqliteVault> {
        let unlocker = self.unlocker();
        Ok(self.registry.open(name, &unlocker)?)
    }

    /// Open the vault selected by [`Ctx::vault_name`].
    pub fn open_default(&self) -> anyhow::Result<SqliteVault> {
        let name = self.vault_name()?;
        self.open(&name)
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
