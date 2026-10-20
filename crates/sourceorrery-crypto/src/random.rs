//! Randomness from the operating system CSPRNG.

use crate::{CryptoError, Result};

/// Fill `buf` with random bytes.
pub fn fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|err| CryptoError::Random(err.to_string()))
}

/// `N` random bytes.
pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    fill(&mut buf)?;
    Ok(buf)
}

/// `byte_len` random bytes, lowercase hex encoded (`2 * byte_len` chars).
///
/// Used for vault, protector and version identifiers.
pub fn random_hex(byte_len: usize) -> Result<String> {
    let mut buf = vec![0u8; byte_len];
    fill(&mut buf)?;
    Ok(hex::encode(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_has_expected_shape() {
        let id = random_hex(16).unwrap();
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(id, random_hex(16).unwrap());
    }
}
