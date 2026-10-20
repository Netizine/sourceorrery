//! Passphrase-based key derivation with Argon2id.

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};

use crate::key::{KEY_LEN, SymmetricKey};
use crate::{CryptoError, Result};

/// Salt length in bytes.
pub const SALT_LEN: usize = 16;

/// Tunable Argon2id cost parameters. Stored next to the salt so a vault keeps
/// working when the defaults are raised later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Number of passes.
    pub iterations: u32,
    /// Degree of parallelism.
    pub parallelism: u32,
}

impl Argon2Params {
    /// Interactive-unlock defaults: 64 MiB, 3 passes, 1 lane.
    ///
    /// Comfortably above the OWASP minimum (19 MiB, 2 passes) while keeping a
    /// CLI unlock well under a second on developer hardware.
    pub const INTERACTIVE: Self = Self {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 1,
    };

    /// Cheap parameters for unit tests only. Never use for real vaults.
    pub const TESTING: Self = Self {
        memory_kib: 8 * 1024,
        iterations: 1,
        parallelism: 1,
    };

    /// The largest parameters [`derive_key`] will run: 1 GiB of memory,
    /// 64 passes and 16 lanes. Parameters are stored in the vault file, so
    /// without a ceiling a corrupted or hostile file could make an unlock
    /// consume arbitrary memory and CPU before anything is authenticated.
    pub const MAX: Self = Self {
        memory_kib: 1024 * 1024,
        iterations: 64,
        parallelism: 16,
    };

    /// True when every parameter is at or below [`Argon2Params::MAX`].
    pub fn within_limits(self) -> bool {
        self.memory_kib <= Self::MAX.memory_kib
            && self.iterations <= Self::MAX.iterations
            && self.parallelism <= Self::MAX.parallelism
    }
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::INTERACTIVE
    }
}

/// Derive a 256-bit key from a passphrase and salt.
pub fn derive_key(passphrase: &[u8], salt: &[u8], params: Argon2Params) -> Result<SymmetricKey> {
    if salt.len() < 8 {
        return Err(CryptoError::Kdf("salt must be at least 8 bytes".to_owned()));
    }
    if !params.within_limits() {
        return Err(CryptoError::Kdf(format!(
            "Argon2 parameters exceed the supported limits ({} KiB, {} passes, {} lanes)",
            Argon2Params::MAX.memory_kib,
            Argon2Params::MAX.iterations,
            Argon2Params::MAX.parallelism
        )));
    }
    let params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|err| CryptoError::Kdf(err.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|err| CryptoError::Kdf(err.to_string()))?;
    Ok(SymmetricKey::from_bytes(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_inputs() {
        let salt = [7u8; SALT_LEN];
        let a = derive_key(b"correct horse", &salt, Argon2Params::TESTING).unwrap();
        let b = derive_key(b"correct horse", &salt, Argon2Params::TESTING).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn sensitive_to_passphrase_and_salt() {
        let salt = [7u8; SALT_LEN];
        let base = derive_key(b"correct horse", &salt, Argon2Params::TESTING).unwrap();
        let other_pass = derive_key(b"correct horsf", &salt, Argon2Params::TESTING).unwrap();
        let other_salt =
            derive_key(b"correct horse", &[8u8; SALT_LEN], Argon2Params::TESTING).unwrap();
        assert_ne!(base, other_pass);
        assert_ne!(base, other_salt);
    }

    #[test]
    fn rejects_parameters_beyond_the_ceiling() {
        let salt = [7u8; SALT_LEN];
        let huge_time = Argon2Params {
            iterations: 10_000,
            ..Argon2Params::TESTING
        };
        assert!(derive_key(b"x", &salt, huge_time).is_err());
        let huge_memory = Argon2Params {
            memory_kib: 8 * 1024 * 1024,
            ..Argon2Params::TESTING
        };
        assert!(derive_key(b"x", &salt, huge_memory).is_err());
        assert!(Argon2Params::INTERACTIVE.within_limits());
    }

    #[test]
    fn rejects_short_salt() {
        assert!(derive_key(b"x", &[0u8; 4], Argon2Params::TESTING).is_err());
    }
}
