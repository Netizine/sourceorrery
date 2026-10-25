//! Credential stores for key-encryption keys.
//!
//! A vault reaches its key-encryption keys through a [`CredentialStore`]:
//! [`OsStore`], the operating system's store, backed by `keyring-core` with
//! one native store per platform (Windows Credential Manager, macOS
//! Keychain, and the D-Bus Secret Service on other Unix systems);
//! [`NoStore`], for machines and runs that must not use one; and
//! [`MemoryStore`], an in-process store for tests and tooling, so that a
//! test never touches the real store. [`from_env`] picks the OS store unless
//! `SOURCEORRERY_KEYRING=off`.
//!
//! Only 32-byte KEKs are ever stored here; secret values never are.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};

use sourceorrery_core::{Result, SecretError};
use sourceorrery_crypto::SymmetricKey;

/// Service name under which SourceOrrery entries are filed.
pub const SERVICE: &str = "sourceorrery";

/// Human-readable name of the OS store compiled into this build.
pub const STORE_NAME: &str = imp::STORE_NAME;

/// Environment variable that switches the OS store off: `off` treats it as
/// absent ([`NoStore`]), for tests, containers and shared machines.
pub const KEYRING_ENV: &str = "SOURCEORRERY_KEYRING";

/// Where a vault keeps the key-encryption keys that unlock it on this
/// machine. Every method is keyed by an account name the vault derives from
/// its own identity.
pub trait CredentialStore: Debug + Send + Sync {
    /// The store's name, for messages.
    fn name(&self) -> &str;

    /// True when the store can be used right now.
    fn available(&self) -> bool;

    /// Why the store is unavailable, if it is.
    fn unavailable_reason(&self) -> Option<String>;

    /// Store `key` under `account`, replacing any existing entry.
    fn store_key(&self, account: &str, key: &SymmetricKey) -> Result<()>;

    /// Load the key stored under `account`, or `None` if there is no entry.
    fn load_key(&self, account: &str) -> Result<Option<SymmetricKey>>;

    /// Delete the entry under `account`. A missing entry is not an error.
    fn delete_key(&self, account: &str) -> Result<()>;
}

/// The store [`KEYRING_ENV`] asks for: [`NoStore`] when it is `off`,
/// otherwise [`OsStore`].
pub fn from_env() -> Arc<dyn CredentialStore> {
    match std::env::var(KEYRING_ENV) {
        Ok(value) if value.eq_ignore_ascii_case("off") => Arc::new(NoStore),
        _ => Arc::new(OsStore),
    }
}

/// The operating system's credential store.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsStore;

impl CredentialStore for OsStore {
    fn name(&self) -> &'static str {
        STORE_NAME
    }

    fn available(&self) -> bool {
        imp::available()
    }

    fn unavailable_reason(&self) -> Option<String> {
        imp::unavailable_reason()
    }

    fn store_key(&self, account: &str, key: &SymmetricKey) -> Result<()> {
        imp::store_key(account, key)
    }

    fn load_key(&self, account: &str) -> Result<Option<SymmetricKey>> {
        imp::load_key(account)
    }

    fn delete_key(&self, account: &str) -> Result<()> {
        imp::delete_key(account)
    }
}

/// No credential store: never available, holds nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoStore;

impl NoStore {
    fn refused() -> SecretError {
        SecretError::Unsupported(format!(
            "the OS credential store is switched off ({KEYRING_ENV}=off)"
        ))
    }
}

impl CredentialStore for NoStore {
    fn name(&self) -> &'static str {
        "none (switched off)"
    }

    fn available(&self) -> bool {
        false
    }

    fn unavailable_reason(&self) -> Option<String> {
        Some(format!("switched off with {KEYRING_ENV}=off"))
    }

    fn store_key(&self, _account: &str, _key: &SymmetricKey) -> Result<()> {
        Err(Self::refused())
    }

    fn load_key(&self, _account: &str) -> Result<Option<SymmetricKey>> {
        Err(Self::refused())
    }

    fn delete_key(&self, _account: &str) -> Result<()> {
        Err(Self::refused())
    }
}

/// A store in this process's memory, gone when it is dropped. For tests and
/// tooling: it stands in for the OS store without touching it.
#[derive(Debug, Default)]
pub struct MemoryStore {
    entries: Mutex<BTreeMap<String, SymmetricKey>>,
}

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// The accounts it holds a key for, in order.
    pub fn accounts(&self) -> Vec<String> {
        self.entries
            .lock()
            .map(|entries| entries.keys().cloned().collect())
            .unwrap_or_default()
    }

    fn entries(&self) -> Result<std::sync::MutexGuard<'_, BTreeMap<String, SymmetricKey>>> {
        self.entries
            .lock()
            .map_err(|_| SecretError::Storage("in-memory credential store poisoned".to_owned()))
    }
}

impl CredentialStore for MemoryStore {
    fn name(&self) -> &'static str {
        "in-memory store"
    }

    fn available(&self) -> bool {
        true
    }

    fn unavailable_reason(&self) -> Option<String> {
        None
    }

    fn store_key(&self, account: &str, key: &SymmetricKey) -> Result<()> {
        self.entries()?.insert(account.to_owned(), key.clone());
        Ok(())
    }

    fn load_key(&self, account: &str) -> Result<Option<SymmetricKey>> {
        Ok(self.entries()?.get(account).cloned())
    }

    fn delete_key(&self, account: &str) -> Result<()> {
        self.entries()?.remove(account);
        Ok(())
    }
}

#[cfg(feature = "os-keyring")]
mod imp {
    use std::sync::OnceLock;

    use keyring_core::{Entry, Error as KeyringError};
    use sourceorrery_core::{Result, SecretError};
    use sourceorrery_crypto::SymmetricKey;

    use super::SERVICE;

    #[cfg(windows)]
    pub const STORE_NAME: &str = "Windows Credential Manager";
    #[cfg(target_vendor = "apple")]
    pub const STORE_NAME: &str = "macOS Keychain";
    #[cfg(all(unix, not(target_vendor = "apple")))]
    pub const STORE_NAME: &str = "Secret Service (D-Bus)";

    static INIT: OnceLock<std::result::Result<(), String>> = OnceLock::new();

    fn init() -> &'static std::result::Result<(), String> {
        INIT.get_or_init(|| {
            #[cfg(windows)]
            let store = windows_native_keyring_store::Store::new();
            #[cfg(target_vendor = "apple")]
            let store = apple_native_keyring_store::keychain::Store::new();
            #[cfg(all(unix, not(target_vendor = "apple")))]
            let store = zbus_secret_service_keyring_store::Store::new();

            match store {
                Ok(store) => {
                    keyring_core::set_default_store(store);
                    Ok(())
                }
                Err(err) => Err(err.to_string()),
            }
        })
    }

    fn ensure() -> Result<()> {
        init().clone().map_err(|reason| {
            SecretError::Unsupported(format!("{STORE_NAME} is not available: {reason}"))
        })
    }

    fn map_err(err: KeyringError) -> SecretError {
        match err {
            KeyringError::NoStorageAccess(inner) => {
                SecretError::Unsupported(format!("{STORE_NAME} refused access: {inner}"))
            }
            other => SecretError::Storage(format!("{STORE_NAME}: {other}")),
        }
    }

    pub fn available() -> bool {
        init().is_ok()
    }

    pub fn unavailable_reason() -> Option<String> {
        init().clone().err()
    }

    pub fn store_key(account: &str, key: &SymmetricKey) -> Result<()> {
        ensure()?;
        Entry::new(SERVICE, account)
            .and_then(|entry| entry.set_secret(key.expose()))
            .map_err(map_err)
    }

    pub fn load_key(account: &str) -> Result<Option<SymmetricKey>> {
        ensure()?;
        let entry = Entry::new(SERVICE, account).map_err(map_err)?;
        match entry.get_secret() {
            Ok(bytes) => {
                // Wipe the store's copy of the key as soon as we are done with it,
                // whether or not it turns out to be well formed.
                let bytes = zeroize::Zeroizing::new(bytes);
                let key = SymmetricKey::from_slice(&bytes).map_err(|err| {
                    SecretError::Crypto(format!("stored key for {account} is malformed: {err}"))
                })?;
                Ok(Some(key))
            }
            Err(KeyringError::NoEntry) => Ok(None),
            Err(other) => Err(map_err(other)),
        }
    }

    pub fn delete_key(account: &str) -> Result<()> {
        ensure()?;
        let entry = Entry::new(SERVICE, account).map_err(map_err)?;
        match entry.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(other) => Err(map_err(other)),
        }
    }
}

#[cfg(not(feature = "os-keyring"))]
mod imp {
    use sourceorrery_core::{Result, SecretError};
    use sourceorrery_crypto::SymmetricKey;

    pub const STORE_NAME: &str = "none (built without the os-keyring feature)";

    fn unsupported() -> SecretError {
        SecretError::Unsupported(
            "this build has no OS credential store support; open the vault with its recovery key"
                .to_owned(),
        )
    }

    pub fn available() -> bool {
        false
    }

    #[allow(clippy::unnecessary_wraps)] // mirrors the keyring-enabled signature
    pub fn unavailable_reason() -> Option<String> {
        Some(STORE_NAME.to_owned())
    }

    pub fn store_key(_account: &str, _key: &SymmetricKey) -> Result<()> {
        Err(unsupported())
    }

    pub fn load_key(_account: &str) -> Result<Option<SymmetricKey>> {
        Err(unsupported())
    }

    pub fn delete_key(_account: &str) -> Result<()> {
        Err(unsupported())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_memory_store_keeps_replaces_and_forgets_keys() {
        let store = MemoryStore::new();
        assert!(store.available());
        assert!(store.load_key("vault/a/b").unwrap().is_none());
        let first = SymmetricKey::generate().unwrap();
        store.store_key("vault/a/b", &first).unwrap();
        assert_eq!(store.load_key("vault/a/b").unwrap().unwrap(), first);
        let second = SymmetricKey::generate().unwrap();
        store.store_key("vault/a/b", &second).unwrap();
        assert_eq!(store.load_key("vault/a/b").unwrap().unwrap(), second);
        assert_eq!(store.accounts(), vec!["vault/a/b".to_owned()]);
        store.delete_key("vault/a/b").unwrap();
        store.delete_key("vault/a/b").unwrap();
        assert!(store.load_key("vault/a/b").unwrap().is_none());
    }

    #[test]
    fn the_switched_off_store_refuses_everything() {
        let store = NoStore;
        assert!(!store.available());
        assert!(store.unavailable_reason().unwrap().contains(KEYRING_ENV));
        let key = SymmetricKey::generate().unwrap();
        assert_eq!(
            store.store_key("a", &key).unwrap_err().code(),
            "unsupported"
        );
        assert_eq!(store.load_key("a").unwrap_err().code(), "unsupported");
        assert_eq!(store.delete_key("a").unwrap_err().code(), "unsupported");
    }
}
