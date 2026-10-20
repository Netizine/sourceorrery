//! Authenticated encryption: XChaCha20-Poly1305 with random 24-byte nonces.
//!
//! XChaCha20's 192-bit nonce makes random nonces safe without any counter
//! state, which matters for a store that is written from many short-lived
//! CLI processes.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::key::SymmetricKey;
use crate::{CryptoError, Result, random};

/// Nonce length in bytes.
pub const NONCE_LEN: usize = 24;

/// Authentication tag length in bytes (appended to the ciphertext).
pub const TAG_LEN: usize = 16;

/// Nonce plus ciphertext-with-tag. Safe to store and serialise.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ciphertext {
    /// Random per-message nonce.
    pub nonce: [u8; NONCE_LEN],
    /// Encrypted bytes followed by the 16-byte Poly1305 tag.
    pub bytes: Vec<u8>,
}

impl Ciphertext {
    /// Rebuild from separately stored columns.
    pub fn from_parts(nonce: &[u8], bytes: Vec<u8>) -> Result<Self> {
        let nonce: [u8; NONCE_LEN] =
            nonce
                .try_into()
                .map_err(|_| CryptoError::InvalidNonceLength {
                    expected: NONCE_LEN,
                    actual: nonce.len(),
                })?;
        Ok(Self { nonce, bytes })
    }
}

fn cipher(key: &SymmetricKey) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| CryptoError::InvalidKeyLength {
        expected: crate::key::KEY_LEN,
        actual: key.expose().len(),
    })
}

/// Encrypt `plaintext`, authenticating `aad` alongside it.
///
/// `aad` must describe where the ciphertext will live (vault id, secret
/// name, version). The same `aad` must be supplied to [`open`].
pub fn seal(key: &SymmetricKey, aad: &[u8], plaintext: &[u8]) -> Result<Ciphertext> {
    let nonce_bytes = random::random_bytes::<NONCE_LEN>()?;
    let nonce = XNonce::from(nonce_bytes);
    let bytes = cipher(key)?
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Authentication)?;
    Ok(Ciphertext {
        nonce: nonce_bytes,
        bytes,
    })
}

/// Decrypt and verify. Returns a zeroising buffer.
pub fn open(key: &SymmetricKey, aad: &[u8], ciphertext: &Ciphertext) -> Result<Zeroizing<Vec<u8>>> {
    let nonce = XNonce::from(ciphertext.nonce);
    cipher(key)?
        .decrypt(
            &nonce,
            Payload {
                msg: &ciphertext.bytes,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Authentication)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = SymmetricKey::generate().unwrap();
        let ct = seal(&key, b"ctx", b"hello").unwrap();
        assert_eq!(ct.bytes.len(), 5 + TAG_LEN);
        let pt = open(&key, b"ctx", &ct).unwrap();
        assert_eq!(&*pt, b"hello");
    }

    #[test]
    fn nonces_differ_per_message() {
        let key = SymmetricKey::generate().unwrap();
        let a = seal(&key, b"", b"x").unwrap();
        let b = seal(&key, b"", b"x").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.bytes, b.bytes);
    }

    #[test]
    fn tamper_is_detected() {
        let key = SymmetricKey::generate().unwrap();
        let mut ct = seal(&key, b"ctx", b"hello").unwrap();
        ct.bytes[0] ^= 1;
        assert_eq!(
            open(&key, b"ctx", &ct).unwrap_err(),
            CryptoError::Authentication
        );
    }

    #[test]
    fn aad_mismatch_is_detected() {
        let key = SymmetricKey::generate().unwrap();
        let ct = seal(&key, b"record-a", b"hello").unwrap();
        assert_eq!(
            open(&key, b"record-b", &ct).unwrap_err(),
            CryptoError::Authentication
        );
    }

    #[test]
    fn wrong_key_is_detected() {
        let ct = seal(&SymmetricKey::generate().unwrap(), b"ctx", b"hello").unwrap();
        let other = SymmetricKey::generate().unwrap();
        assert_eq!(
            open(&other, b"ctx", &ct).unwrap_err(),
            CryptoError::Authentication
        );
    }

    #[test]
    fn ciphertext_parts_validate_nonce_length() {
        assert!(Ciphertext::from_parts(&[0u8; 12], vec![]).is_err());
        assert!(Ciphertext::from_parts(&[0u8; 24], vec![]).is_ok());
    }
}
