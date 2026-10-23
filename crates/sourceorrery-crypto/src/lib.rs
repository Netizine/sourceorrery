//! # SourceOrrery crypto
//!
//! Thin, opinionated wrappers over audited RustCrypto primitives. This crate
//! implements **no** algorithms of its own; it fixes the choices so the rest
//! of SourceOrrery cannot get them wrong:
//!
//! | Purpose                    | Primitive                      |
//! |----------------------------|--------------------------------|
//! | Value / key encryption     | XChaCha20-Poly1305 (24-byte random nonce) |
//! | Passphrase → key           | Argon2id (v1.3)                |
//! | Sub-key derivation         | HKDF-SHA256                    |
//! | Metadata / audit integrity | HMAC-SHA256                    |
//! | Randomness                 | OS CSPRNG via `getrandom`      |
//!
//! Every ciphertext is bound to its location with additional authenticated
//! data (AAD), so a ciphertext copied from one record to another fails to
//! decrypt rather than silently yielding the wrong secret.

#![forbid(unsafe_code)]

pub mod aead;
pub mod envelope;
pub mod kdf;
pub mod key;
pub mod mac;
pub mod random;
pub mod totp;

pub use aead::{Ciphertext, NONCE_LEN, TAG_LEN, open, seal};
pub use envelope::{unwrap_key, wrap_key};
pub use kdf::{Argon2Params, SALT_LEN, derive_key};
pub use key::{KEY_LEN, SymmetricKey};
pub use mac::{MAC_LEN, derive_subkey, mac, verify_mac};
pub use random::{random_bytes, random_hex, random_passphrase, recovery_code};
pub use totp::TotpSecret;

use thiserror::Error;

/// Failures reported by this crate. None of them carries key or plaintext
/// material.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// Decryption failed: wrong key, wrong AAD, or tampered ciphertext.
    /// Deliberately undifferentiated.
    #[error("authentication failed: wrong key, wrong context or tampered data")]
    Authentication,
    /// A key had the wrong length.
    #[error("invalid key length {actual}, expected {expected}")]
    InvalidKeyLength { expected: usize, actual: usize },
    /// A nonce had the wrong length.
    #[error("invalid nonce length {actual}, expected {expected}")]
    InvalidNonceLength { expected: usize, actual: usize },
    /// Key derivation was misconfigured.
    #[error("key derivation failed: {0}")]
    Kdf(String),
    /// The OS random source failed.
    #[error("random number generation failed: {0}")]
    Random(String),
    /// Hex decoding failed.
    #[error("invalid hex encoding")]
    Hex,
    /// An input had the wrong shape (a secret of the wrong size, text that
    /// is not base32). Names the rule, never the input.
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, CryptoError>;
