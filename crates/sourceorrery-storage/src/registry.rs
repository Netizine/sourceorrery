//! Where vaults live on disk, and how they are found by name.

use std::path::{Path, PathBuf};

use sourceorrery_core::{Result, SecretError, validate_vault_name};

use crate::VAULT_FILE_EXTENSION;
use crate::protector::ProtectorSpec;
use crate::sqlite::{CreateVaultOptions, SqliteVault};
use crate::unlock::UnlockProvider;

/// Environment variable overriding the SourceOrrery home directory.
pub const HOME_ENV: &str = "SOURCEORRERY_HOME";

/// Maps vault names to files under a home directory.
///
/// Default home: the per-user local data directory
/// (`%LOCALAPPDATA%\sourceorrery` on Windows,
/// `~/Library/Application Support/sourceorrery` on macOS,
/// `$XDG_DATA_HOME/sourceorrery` or `~/.local/share/sourceorrery` on Linux),
/// overridable with `SOURCEORRERY_HOME`.
#[derive(Clone, Debug)]
pub struct VaultRegistry {
    root: PathBuf,
}

impl VaultRegistry {
    /// Registry rooted at the default or `SOURCEORRERY_HOME` location.
    pub fn from_env() -> Result<Self> {
        if let Some(home) = std::env::var_os(HOME_ENV).filter(|v| !v.is_empty()) {
            return Ok(Self::with_root(PathBuf::from(home)));
        }
        let base = directories::BaseDirs::new().ok_or_else(|| {
            SecretError::Io(
                "cannot determine the user data directory; set SOURCEORRERY_HOME".to_owned(),
            )
        })?;
        Ok(Self::with_root(base.data_local_dir().join("sourceorrery")))
    }

    /// Registry rooted at an explicit directory.
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Home directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Directory holding vault files.
    pub fn vaults_dir(&self) -> PathBuf {
        self.root.join("vaults")
    }

    /// File path for a vault name (validated, so names cannot escape).
    pub fn vault_path(&self, name: &str) -> Result<PathBuf> {
        validate_vault_name(name)?;
        Ok(self
            .vaults_dir()
            .join(format!("{name}.{VAULT_FILE_EXTENSION}")))
    }

    /// True when a vault file exists for `name`.
    pub fn exists(&self, name: &str) -> bool {
        self.vault_path(name).is_ok_and(|p| p.is_file())
    }

    /// Names of all vaults, sorted.
    pub fn list(&self) -> Result<Vec<String>> {
        let dir = self.vaults_dir();
        if !dir.is_dir() {
            return Ok(Vec::new());
        }
        let mut names: Vec<String> = std::fs::read_dir(&dir)?
            .filter_map(std::result::Result::ok)
            .filter_map(|entry| {
                let path = entry.path();
                let is_vault = path
                    .extension()
                    .is_some_and(|ext| ext == VAULT_FILE_EXTENSION);
                if !is_vault || !path.is_file() {
                    return None;
                }
                let stem = path.file_stem()?.to_str()?.to_owned();
                validate_vault_name(&stem).ok().map(|()| stem)
            })
            .collect();
        names.sort();
        Ok(names)
    }

    /// Create a new vault.
    pub fn create(
        &self,
        name: &str,
        options: CreateVaultOptions,
        protector: ProtectorSpec,
    ) -> Result<SqliteVault> {
        let path = self.vault_path(name)?;
        if path.exists() {
            return Err(SecretError::VaultExists {
                name: name.to_owned(),
            });
        }
        ensure_private_dir(&self.vaults_dir())?;
        SqliteVault::create(&path, name, options, protector)
    }

    /// Open and unlock an existing vault.
    pub fn open(&self, name: &str, unlock: &dyn UnlockProvider) -> Result<SqliteVault> {
        let path = self.vault_path(name)?;
        if !path.is_file() {
            return Err(SecretError::VaultNotFound {
                name: name.to_owned(),
            });
        }
        SqliteVault::open(&path, unlock)
    }

    /// Permanently delete a vault file and any OS-keyring entries it owns.
    ///
    /// Does not require unlocking: protector metadata is not encrypted.
    pub fn destroy(&self, name: &str) -> Result<()> {
        let path = self.vault_path(name)?;
        if !path.is_file() {
            return Err(SecretError::VaultNotFound {
                name: name.to_owned(),
            });
        }
        SqliteVault::forget_protectors(&path)?;
        std::fs::remove_file(&path)?;
        Ok(())
    }
}

/// Create `dir` (and parents) readable only by the current user where the
/// platform supports POSIX permissions.
pub(crate) fn ensure_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    restrict_permissions(dir, 0o700)
}

/// Restrict a file to the current user where the platform supports POSIX
/// permissions. On Windows, files under the user's profile already inherit
/// user-only ACLs.
#[allow(clippy::unnecessary_wraps)] // fallible only on unix
pub(crate) fn restrict_permissions(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}
