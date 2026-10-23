//! Where vaults live on disk, and how they are found by name.

use std::path::{Path, PathBuf};

use serde::Serialize;
use sourceorrery_core::{Result, SecretError, validate_vault_name};

use crate::VAULT_FILE_EXTENSION;
use crate::protector::ProtectorSpec;
use crate::sqlite::{CreateVaultOptions, OpenOptions, SqliteVault};
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

/// What [`VaultRegistry::destroy`] did about the vault's OS-keyring keys.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct DestroyReport {
    /// Keyring accounts whose entries were deleted.
    pub removed_keys: Vec<String>,
    /// Keyring accounts left in place, with the reason: the account did not
    /// belong to this vault's identity, another vault file in the same home
    /// still references it, or the caller asked to keep keys.
    pub kept_keys: Vec<(String, String)>,
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

    /// The passphrase hint stored in the named vault's file, if any, read
    /// without unlocking it. It is stored in clear and nothing authenticates
    /// it before unlock: show it at a prompt, never trust it.
    pub fn passphrase_hint(&self, name: &str) -> Result<Option<String>> {
        let path = self.vault_path(name)?;
        crate::sqlite::read_passphrase_hint(&path)
    }

    /// Open and unlock an existing vault.
    ///
    /// A vault in an older on-disk format is refused with
    /// [`SecretError::MigrationRequired`]; see [`VaultRegistry::migrate`].
    /// A vault whose audit log has a detected truncation that nobody has
    /// acknowledged is refused with [`SecretError::Crypto`]; see
    /// [`VaultRegistry::open_for_inspection`]. A file under `name` that
    /// holds another vault (renamed, copied or swapped in) is refused with
    /// [`SecretError::VaultMismatch`] once its stored name is authenticated;
    /// this applies to every way of opening by name.
    pub fn open(&self, name: &str, unlock: &dyn UnlockProvider) -> Result<SqliteVault> {
        let path = self.vault_path(name)?;
        if !path.is_file() {
            return Err(SecretError::VaultNotFound {
                name: name.to_owned(),
            });
        }
        SqliteVault::open_named(&path, name, unlock, OpenOptions::default())
    }

    /// Open a vault for inspection of its audit log: as [`VaultRegistry::open`],
    /// except that a vault blocked by an unacknowledged truncation is
    /// unlocked too, with every secret and protector operation refused until
    /// [`SqliteVault::acknowledge_truncations`] has run. See
    /// [`OpenOptions::allow_quarantined`].
    pub fn open_for_inspection(
        &self,
        name: &str,
        unlock: &dyn UnlockProvider,
    ) -> Result<SqliteVault> {
        let path = self.vault_path(name)?;
        if !path.is_file() {
            return Err(SecretError::VaultNotFound {
                name: name.to_owned(),
            });
        }
        SqliteVault::open_named(
            &path,
            name,
            unlock,
            OpenOptions {
                allow_quarantined: true,
                ..OpenOptions::default()
            },
        )
    }

    /// Unlock a vault written by an older schema and migrate it forward.
    ///
    /// This is an explicit trust decision: the legacy format carries no
    /// integrity tags, so whatever the file says is taken at face value once.
    /// A vault whose key material shows it was already in the current format
    /// (a downgraded file) is refused.
    pub fn migrate(&self, name: &str, unlock: &dyn UnlockProvider) -> Result<SqliteVault> {
        let path = self.vault_path(name)?;
        if !path.is_file() {
            return Err(SecretError::VaultNotFound {
                name: name.to_owned(),
            });
        }
        SqliteVault::open_named(
            &path,
            name,
            unlock,
            OpenOptions {
                allow_legacy_migration: true,
                ..OpenOptions::default()
            },
        )
    }

    /// Permanently delete a vault file and the OS-keyring keys it owns.
    ///
    /// Does not require unlocking. Because protector metadata is not
    /// authenticated without the vault key, a keyring entry is only deleted
    /// when its account name is the one this vault would have created for
    /// that protector and no other vault file in this home references it;
    /// anything else is kept and reported. `keep_keys` skips keyring
    /// deletion entirely.
    pub fn destroy(&self, name: &str, keep_keys: bool) -> Result<DestroyReport> {
        let path = self.vault_path(name)?;
        if !path.is_file() {
            return Err(SecretError::VaultNotFound {
                name: name.to_owned(),
            });
        }
        let mut report = DestroyReport::default();
        for (account, owned) in SqliteVault::keyring_accounts(&path)? {
            if keep_keys {
                report
                    .kept_keys
                    .push((account, "kept on request".to_owned()));
            } else if !owned {
                report.kept_keys.push((
                    account,
                    "account name does not match this vault's identity".to_owned(),
                ));
            } else if self.keyring_account_referenced_elsewhere(&path, &account)? {
                report.kept_keys.push((
                    account,
                    "another vault in this home references the same key".to_owned(),
                ));
            } else {
                // Best effort: a missing store must not block deletion of the file.
                match crate::keystore::delete_key(&account) {
                    Ok(()) => report.removed_keys.push(account),
                    Err(err) => report.kept_keys.push((account, err.to_string())),
                }
            }
        }
        std::fs::remove_file(&path)?;
        Ok(report)
    }

    /// True when any vault file in this home other than `except` lists
    /// `account` among its OS-keyring protectors.
    pub(crate) fn keyring_account_referenced_elsewhere(
        &self,
        except: &Path,
        account: &str,
    ) -> Result<bool> {
        for name in self.list()? {
            let path = self.vault_path(&name)?;
            if same_file(&path, except) {
                continue;
            }
            // A sibling that cannot be read is not evidence either way; skip it.
            let Ok(accounts) = SqliteVault::keyring_accounts(&path) else {
                continue;
            };
            if accounts.iter().any(|(a, _)| a == account) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
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
