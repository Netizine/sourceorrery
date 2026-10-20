//! Symmetric key material.

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{CryptoError, Result, random};

/// Length of every symmetric key in SourceOrrery, in bytes.
pub const KEY_LEN: usize = 32;

/// A 256-bit symmetric key. Zeroised on drop, redacted in `Debug`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey([u8; KEY_LEN]);

impl SymmetricKey {
    /// Generate a fresh random key from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        Ok(Self(random::random_bytes::<KEY_LEN>()?))
    }

    /// Wrap existing key bytes.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Wrap a slice, rejecting the wrong length.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let array: [u8; KEY_LEN] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength {
                expected: KEY_LEN,
                actual: bytes.len(),
            })?;
        Ok(Self(array))
    }

    /// Decode a hex-encoded key.
    pub fn from_hex(hex_text: &str) -> Result<Self> {
        let bytes = Zeroizing::new(hex::decode(hex_text.trim()).map_err(|_| CryptoError::Hex)?);
        Self::from_slice(&bytes)
    }

    /// Borrow the raw key. Keep the borrow short.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Hex-encode the key (for storage in an OS credential store).
    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.0))
    }
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SymmetricKey([REDACTED])")
    }
}

impl PartialEq for SymmetricKey {
    fn eq(&self, other: &Self) -> bool {
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }
}

impl Eq for SymmetricKey {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_is_random() {
        let a = SymmetricKey::generate().unwrap();
        let b = SymmetricKey::generate().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.expose().len(), KEY_LEN);
    }

    #[test]
    fn hex_round_trip() {
        let key = SymmetricKey::generate().unwrap();
        let back = SymmetricKey::from_hex(&key.to_hex()).unwrap();
        assert_eq!(key, back);
        assert!(SymmetricKey::from_hex("zz").is_err());
        assert!(SymmetricKey::from_hex("abcd").is_err());
    }

    #[test]
    fn debug_is_redacted() {
        let key = SymmetricKey::from_bytes([0x41; KEY_LEN]);
        assert_eq!(format!("{key:?}"), "SymmetricKey([REDACTED])");
    }
}
