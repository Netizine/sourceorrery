//! Envelope encryption: wrap a data-encryption key (DEK) under a
//! key-encryption key (KEK).
//!
//! A vault has one DEK that encrypts every secret value, and one wrapped
//! copy of that DEK per *key protector* (OS keyring, passphrase, ...).
//! Adding a protector wraps the same DEK again; removing one deletes a
//! wrapped copy. Secret values never need re-encrypting.

use crate::Result;
use crate::aead::{self, Ciphertext};
use crate::key::SymmetricKey;

/// Encrypt `dek` under `kek`, binding it to `aad` (vault id + protector id).
pub fn wrap_key(kek: &SymmetricKey, dek: &SymmetricKey, aad: &[u8]) -> Result<Ciphertext> {
    aead::seal(kek, aad, dek.expose())
}

/// Recover a DEK wrapped by [`wrap_key`].
pub fn unwrap_key(kek: &SymmetricKey, wrapped: &Ciphertext, aad: &[u8]) -> Result<SymmetricKey> {
    let plain = aead::open(kek, aad, wrapped)?;
    SymmetricKey::from_slice(&plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CryptoError;

    #[test]
    fn wrap_and_unwrap() {
        let kek = SymmetricKey::generate().unwrap();
        let dek = SymmetricKey::generate().unwrap();
        let wrapped = wrap_key(&kek, &dek, b"vault/protector").unwrap();
        assert_eq!(unwrap_key(&kek, &wrapped, b"vault/protector").unwrap(), dek);
        assert_eq!(
            unwrap_key(&kek, &wrapped, b"vault/other").unwrap_err(),
            CryptoError::Authentication
        );
        let other = SymmetricKey::generate().unwrap();
        assert_eq!(
            unwrap_key(&other, &wrapped, b"vault/protector").unwrap_err(),
            CryptoError::Authentication
        );
    }
}
