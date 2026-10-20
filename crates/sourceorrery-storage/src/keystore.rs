//! Operating-system credential store access for key-encryption keys.
//!
//! Backed by `keyring-core` with one native store per platform:
//! Windows Credential Manager, macOS Keychain, and the D-Bus Secret Service
//! (GNOME Keyring, KWallet, KeePassXC, ...) on other Unix systems.
//!
//! Only 32-byte KEKs are ever stored here; secret values never are.

use sourceorrery_core::Result;
use sourceorrery_crypto::SymmetricKey;

/// Service name under which SourceOrrery entries are filed.
pub const SERVICE: &str = "sourceorrery";

/// Human-readable name of the store compiled into this build.
pub const STORE_NAME: &str = imp::STORE_NAME;

/// True when the OS credential store can be used right now.
pub fn available() -> bool {
    imp::available()
}

/// Why the store is unavailable, if it is.
pub fn unavailable_reason() -> Option<String> {
    imp::unavailable_reason()
}

/// Store `key` under `account`, replacing any existing entry.
pub fn store_key(account: &str, key: &SymmetricKey) -> Result<()> {
    imp::store_key(account, key)
}

/// Load the key stored under `account`, or `None` if there is no entry.
pub fn load_key(account: &str) -> Result<Option<SymmetricKey>> {
    imp::load_key(account)
}

/// Delete the entry under `account`. Missing entries are not an error.
pub fn delete_key(account: &str) -> Result<()> {
    imp::delete_key(account)
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
            "this build has no OS credential store support; use a passphrase protector".to_owned(),
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
