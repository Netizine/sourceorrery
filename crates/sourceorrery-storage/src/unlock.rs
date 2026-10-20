//! How a vault obtains a passphrase when no OS-keyring protector can be used.

use sourceorrery_core::{Result, SecretBytes};

/// Context handed to an [`UnlockProvider`].
#[derive(Clone, Copy, Debug)]
pub struct PassphrasePrompt<'a> {
    /// Vault being unlocked.
    pub vault: &'a str,
    /// Label of the passphrase protector(s) that will be tried.
    pub protector_label: &'a str,
    /// 1-based attempt number.
    pub attempt: u32,
    /// Maximum attempts the vault will make.
    pub max_attempts: u32,
}

/// Supplies passphrases on demand. The CLI implements this with an
/// interactive prompt; tests and automation use [`StaticPassphrase`].
pub trait UnlockProvider {
    /// Return a passphrase to try, or `None` to give up.
    fn passphrase(&self, prompt: &PassphrasePrompt<'_>) -> Result<Option<SecretBytes>>;
}

/// Never supplies a passphrase. Only OS-keyring protectors can unlock.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoInteraction;

impl UnlockProvider for NoInteraction {
    fn passphrase(&self, _prompt: &PassphrasePrompt<'_>) -> Result<Option<SecretBytes>> {
        Ok(None)
    }
}

/// Supplies one fixed passphrase, once.
#[derive(Debug)]
pub struct StaticPassphrase(SecretBytes);

impl StaticPassphrase {
    /// Wrap a passphrase.
    pub fn new(passphrase: impl Into<SecretBytes>) -> Self {
        Self(passphrase.into())
    }
}

impl UnlockProvider for StaticPassphrase {
    fn passphrase(&self, prompt: &PassphrasePrompt<'_>) -> Result<Option<SecretBytes>> {
        if prompt.attempt > 1 {
            return Ok(None);
        }
        Ok(Some(self.0.clone()))
    }
}
