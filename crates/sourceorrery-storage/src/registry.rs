//! Where vaults live on disk, and how they are found by name.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use sourceorrery_core::{Result, SecretError, validate_vault_name};

use crate::VAULT_FILE_EXTENSION;
use crate::keystore::{self, CredentialStore};
use crate::sqlite::{CreateVaultOptions, Created, Imported, OpenOptions, SqliteVault};
use crate::unlock::UnlockProvider;

/// Environment variable overriding the SourceOrrery home directory.
pub const HOME_ENV: &str = "SOURCEORRERY_HOME";

/// Maps vault names to files under a home directory.
///
/// Default home: the per-user local data directory
/// (`%LOCALAPPDATA%\sourceorrery` on Windows,
/// `~/Library/Application Support/sourceorrery` on macOS,
/// `$XDG_DATA_HOME/sourceorrery` or `~/.local/share/sourceorrery` on Linux),
/// overridable with `SOURCEORRERY_HOME`. It also carries the credential
/// store its vaults keep their OS-keyring keys in ([`keystore::from_env`]
/// unless [`VaultRegistry::with_store`] names another).
#[derive(Clone, Debug)]
pub struct VaultRegistry {
    root: PathBuf,
    store: Arc<dyn CredentialStore>,
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
        Self {
            root: root.into(),
            store: keystore::from_env(),
        }
    }

    /// The same registry with its vaults' keys in `store`.
    #[must_use]
    pub fn with_store(mut self, store: Arc<dyn CredentialStore>) -> Self {
        self.store = store;
        self
    }

    /// The credential store this registry's vaults use.
    pub fn store(&self) -> &Arc<dyn CredentialStore> {
        &self.store
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

    /// True when a vault called `name`, in any case, exists.
    pub fn exists(&self, name: &str) -> bool {
        self.resolve(name).is_ok_and(|found| found.is_some())
    }

    /// The vault's own spelling of `name`: two names that differ only in
    /// case name one vault, so `dev` finds the vault created as `Dev` on
    /// every platform, not only where file names ignore case. `None` when
    /// there is no such vault; an invalid name is an error.
    pub fn resolve(&self, name: &str) -> Result<Option<String>> {
        validate_vault_name(name)?;
        Ok(self
            .list()?
            .into_iter()
            .find(|found| found.eq_ignore_ascii_case(name)))
    }

    /// The path of the existing vault `name` (in any case), or
    /// [`SecretError::VaultNotFound`].
    fn existing(&self, name: &str) -> Result<(String, PathBuf)> {
        let found = self
            .resolve(name)?
            .ok_or_else(|| SecretError::VaultNotFound {
                name: name.to_owned(),
            })?;
        let path = self.vault_path(&found)?;
        Ok((found, path))
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

    /// Create a new vault, returning it with its recovery key to show once
    /// ([`SqliteVault::create`]). A name that differs from an existing
    /// vault's only in case is refused as [`SecretError::VaultExists`].
    pub fn create(&self, name: &str, options: CreateVaultOptions) -> Result<Created> {
        let path = self.vault_path(name)?;
        if let Some(existing) = self.resolve(name)? {
            return Err(SecretError::VaultExists { name: existing });
        }
        if path.exists() {
            return Err(SecretError::VaultExists {
                name: name.to_owned(),
            });
        }
        ensure_private_dir(&self.vaults_dir())?;
        SqliteVault::create(&path, name, options, self.store.clone())
    }

    /// [`VaultRegistry::create`] with `recovery_key`, which its owner has
    /// seen already, as the vault's recovery key (the setup wizard shows it
    /// before anything is saved).
    pub fn create_with_recovery_key(
        &self,
        name: &str,
        options: CreateVaultOptions,
        recovery_key: crate::RecoveryKey,
    ) -> Result<Created> {
        let path = self.vault_path(name)?;
        if let Some(existing) = self.resolve(name)? {
            return Err(SecretError::VaultExists { name: existing });
        }
        if path.exists() {
            return Err(SecretError::VaultExists {
                name: name.to_owned(),
            });
        }
        ensure_private_dir(&self.vaults_dir())?;
        SqliteVault::create_with(&path, name, options, self.store.clone(), Some(recovery_key))
    }

    /// Import a vault exported elsewhere ([`SqliteVault::export_to`]) into
    /// this home, under the name it was exported with or `name`.
    ///
    /// The copy is opened with the recovery key `unlock` supplies, and only
    /// with it, and verified as every open verifies: its name and settings,
    /// and its audit chain. It then gets this machine's key when the
    /// credential store is available. A name that is taken, in any case, is
    /// refused with [`SecretError::VaultExists`], so an import never
    /// replaces a vault. A failed import leaves nothing in the home, and the
    /// file at `source` is only read. The vault's log records
    /// `vault_import`.
    pub fn import_from(
        &self,
        source: &Path,
        unlock: &dyn UnlockProvider,
        name: Option<&str>,
    ) -> Result<Imported> {
        // The copy's own name only chooses the path here; opening the copy
        // refuses a name that was altered.
        let name = match name {
            Some(name) => name.to_owned(),
            None => SqliteVault::stored_name(source)?,
        };
        let path = self.vault_path(&name)?;
        if let Some(existing) = self.resolve(&name)? {
            return Err(SecretError::VaultExists { name: existing });
        }
        ensure_private_dir(&self.vaults_dir())?;
        SqliteVault::import(source, &path, &name, self.store.clone(), unlock)
    }

    /// Open and unlock an existing vault.
    ///
    /// A vault written by an earlier release is refused with
    /// [`SecretError::MigrationRequired`]: there is no migration.
    /// A vault whose audit log has a detected truncation that nobody has
    /// acknowledged is refused with [`SecretError::Crypto`]; see
    /// [`VaultRegistry::open_for_inspection`]. A file under `name` that
    /// holds another vault (renamed, copied or swapped in) is refused with
    /// [`SecretError::VaultMismatch`] once its stored name is authenticated;
    /// this applies to every way of opening by name. `name` is matched
    /// ignoring case ([`VaultRegistry::resolve`]).
    pub fn open(&self, name: &str, unlock: &dyn UnlockProvider) -> Result<SqliteVault> {
        let (found, path) = self.existing(name)?;
        SqliteVault::open_named(
            &path,
            &found,
            self.store.clone(),
            unlock,
            OpenOptions::default(),
        )
    }

    /// Open a vault for inspection of its audit log: as [`VaultRegistry::open`],
    /// except that a vault blocked by an unacknowledged truncation is
    /// unlocked too, with every secret and settings operation refused until
    /// [`SqliteVault::acknowledge_truncations`] has run. See
    /// [`OpenOptions::allow_quarantined`].
    pub fn open_for_inspection(
        &self,
        name: &str,
        unlock: &dyn UnlockProvider,
    ) -> Result<SqliteVault> {
        let (found, path) = self.existing(name)?;
        SqliteVault::open_named(
            &path,
            &found,
            self.store.clone(),
            unlock,
            OpenOptions {
                allow_quarantined: true,
            },
        )
    }

    /// Permanently delete a vault file and the credential-store keys it owns.
    ///
    /// Does not require unlocking. Because wrap rows are not authenticated
    /// without the vault key, a keyring entry is only deleted when its
    /// account name is the one this vault would have created for that wrap
    /// and no other vault file in this home references it;
    /// anything else is kept and reported. `keep_keys` skips keyring
    /// deletion entirely.
    pub fn destroy(&self, name: &str, keep_keys: bool) -> Result<DestroyReport> {
        let (_, path) = self.existing(name)?;
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
                match self.store.delete_key(&account) {
                    Ok(()) => report.removed_keys.push(account),
                    Err(err) => report.kept_keys.push((account, err.to_string())),
                }
            }
        }
        std::fs::remove_file(&path)?;
        Ok(report)
    }

    /// True when any vault file in this home other than `except` lists
    /// `account` among its this-machine keys.
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

#[cfg(test)]
mod tests {
    use sourceorrery_core::SecretClient;

    use super::*;
    use crate::keystore::NoStore;
    use crate::{NoInteraction, StaticRecoveryKey};

    /// A registry in a temporary home whose vaults open with their
    /// recovery key only: a test never touches the real OS store.
    fn registry(home: &tempfile::TempDir) -> VaultRegistry {
        VaultRegistry::with_root(home.path()).with_store(Arc::new(NoStore))
    }

    #[test]
    fn a_name_finds_its_vault_ignoring_case_and_cannot_be_taken_twice() {
        let home = tempfile::tempdir().unwrap();
        let registry = registry(&home);
        let created = registry
            .create("Dev_Team", CreateVaultOptions::default())
            .unwrap();
        let key = created.recovery_key.clone();
        drop(created);

        assert_eq!(
            registry.resolve("dev_team").unwrap().as_deref(),
            Some("Dev_Team")
        );
        assert!(registry.exists("DEV_TEAM"));
        let vault = registry
            .open("dev_TEAM", &StaticRecoveryKey::new(key.as_str()))
            .unwrap();
        assert_eq!(vault.vault_name(), "Dev_Team");
        drop(vault);

        let err = registry
            .create("dev_team", CreateVaultOptions::default())
            .unwrap_err();
        assert_eq!(err.code(), "vault_exists");
        assert!(err.to_string().contains("Dev_Team"), "{err}");
        assert_eq!(registry.list().unwrap(), vec!["Dev_Team".to_owned()]);
    }

    #[test]
    fn an_unknown_or_invalid_name_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let registry = registry(&home);
        assert_eq!(registry.resolve("missing").unwrap(), None);
        assert!(!registry.exists("missing"));
        let err = registry.open("missing", &NoInteraction).unwrap_err();
        assert_eq!(err.code(), "vault_not_found");
        assert_eq!(
            registry.resolve("has space").unwrap_err().code(),
            "invalid_name"
        );
    }
}
