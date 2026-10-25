//! How a vault obtains its recovery key when this machine's credential
//! store cannot open it.

use sourceorrery_core::{Result, SecretBytes};

/// Context handed to an [`UnlockProvider`].
#[derive(Clone, Copy, Debug)]
pub struct RecoveryKeyPrompt<'a> {
    /// Vault being opened.
    pub vault: &'a str,
    /// 1-based attempt number.
    pub attempt: u32,
    /// Maximum attempts the vault will make.
    pub max_attempts: u32,
}

/// Supplies the recovery key on demand. The CLI implements this with its
/// sources (environment, file) and an interactive prompt; tests and
/// automation use [`StaticRecoveryKey`].
pub trait UnlockProvider {
    /// Return a recovery key to try, or `None` to give up.
    fn recovery_key(&self, prompt: &RecoveryKeyPrompt<'_>) -> Result<Option<SecretBytes>>;
}

/// Never supplies a recovery key: only this machine's credential store can
/// open the vault.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoInteraction;

impl UnlockProvider for NoInteraction {
    fn recovery_key(&self, _prompt: &RecoveryKeyPrompt<'_>) -> Result<Option<SecretBytes>> {
        Ok(None)
    }
}

/// Supplies one fixed recovery key, once.
#[derive(Debug)]
pub struct StaticRecoveryKey(SecretBytes);

impl StaticRecoveryKey {
    /// Wrap a recovery key.
    pub fn new(key: impl Into<SecretBytes>) -> Self {
        Self(key.into())
    }
}

impl UnlockProvider for StaticRecoveryKey {
    fn recovery_key(&self, prompt: &RecoveryKeyPrompt<'_>) -> Result<Option<SecretBytes>> {
        if prompt.attempt > 1 {
            return Ok(None);
        }
        Ok(Some(self.0.clone()))
    }
}
