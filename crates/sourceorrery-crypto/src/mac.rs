//! Keyed integrity: sub-key derivation with HKDF-SHA256 and message
//! authentication with HMAC-SHA256.
//!
//! The vault derives a *metadata key* from its data-encryption key with
//! [`derive_subkey`] and uses [`mac`] / [`verify_mac`] to authenticate the
//! mutable metadata it cannot encrypt (flags, time windows, deletion state)
//! and to chain its audit log. Keys derived with different labels are
//! independent, so the metadata key reveals nothing about the DEK.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::key::{KEY_LEN, SymmetricKey};
use crate::{CryptoError, Result};

/// Length of a MAC tag in bytes.
pub const MAC_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// Derive an independent 256-bit sub-key from `key` for the purpose named by
/// `label`, using HKDF-SHA256 with no salt and `label` as the info string.
///
/// Deterministic: the same key and label always yield the same sub-key.
/// Different labels yield unrelated keys.
pub fn derive_subkey(key: &SymmetricKey, label: &str) -> SymmetricKey {
    let hkdf = Hkdf::<Sha256>::new(None, key.expose());
    let mut out = [0u8; KEY_LEN];
    hkdf.expand(label.as_bytes(), &mut out)
        .expect("a 32-byte HKDF output is always within the expansion limit");
    SymmetricKey::from_bytes(out)
}

/// Derive a 256-bit key from a generated, high-entropy secret (a recovery
/// key, never a password a person chose) with HKDF-SHA256: `salt` as the
/// HKDF salt and `label` as the info string.
///
/// Fast by design: the secret's own entropy is what resists guessing, so a
/// slow hash would add nothing. A secret a person chose goes through
/// Argon2id ([`crate::kdf::derive_key`]) instead.
pub fn derive_from_secret(secret: &[u8], salt: &[u8], label: &str) -> SymmetricKey {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), secret);
    let mut out = zeroize::Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(label.as_bytes(), out.as_mut_slice())
        .expect("a 32-byte HKDF output is always within the expansion limit");
    SymmetricKey::from_bytes(*out)
}

fn hmac(key: &SymmetricKey, data: &[u8]) -> HmacSha256 {
    let mut mac =
        HmacSha256::new_from_slice(key.expose()).expect("HMAC accepts keys of any length");
    mac.update(data);
    mac
}

/// HMAC-SHA256 tag over `data`.
pub fn mac(key: &SymmetricKey, data: &[u8]) -> [u8; MAC_LEN] {
    let out = hmac(key, data).finalize().into_bytes();
    let mut tag = [0u8; MAC_LEN];
    tag.copy_from_slice(&out);
    tag
}

/// Check `tag` against `data` in constant time.
///
/// Returns [`CryptoError::Authentication`] when the tag has the wrong length
/// or does not match.
pub fn verify_mac(key: &SymmetricKey, data: &[u8], tag: &[u8]) -> Result<()> {
    if tag.len() != MAC_LEN {
        return Err(CryptoError::Authentication);
    }
    hmac(key, data)
        .verify_slice(tag)
        .map_err(|_| CryptoError::Authentication)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SymmetricKey {
        SymmetricKey::from_bytes([byte; KEY_LEN])
    }

    #[test]
    fn subkey_is_deterministic_and_label_separated() {
        let a = derive_subkey(&key(1), "sourceorrery/v2/metadata");
        let b = derive_subkey(&key(1), "sourceorrery/v2/metadata");
        let c = derive_subkey(&key(1), "sourceorrery/v2/other");
        let d = derive_subkey(&key(2), "sourceorrery/v2/metadata");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_ne!(a, key(1), "sub-key must differ from the parent key");
    }

    #[test]
    fn hkdf_sha256_known_answer() {
        // HKDF-SHA256(ikm = 0x0b * 32, salt = none, info = "info", L = 32),
        // computed independently with Python's hmac/hashlib. Pins the
        // no-salt, info-is-label construction so an accidental change to
        // either is caught.
        let sub = derive_subkey(&key(0x0b), "info");
        assert_eq!(
            hex::encode(sub.expose()),
            "cf9941092b80e1dbe641be211be39d3db199c0a121e807dbfa8ed794fea695e3"
        );
    }

    #[test]
    fn secret_derivation_is_salted_and_label_separated() {
        let a = derive_from_secret(b"ABCDE12345", &[1u8; 16], "sourceorrery/v4/recovery-key/x");
        let b = derive_from_secret(b"ABCDE12345", &[1u8; 16], "sourceorrery/v4/recovery-key/x");
        assert_eq!(a, b);
        assert_ne!(
            a,
            derive_from_secret(b"ABCDE12345", &[2u8; 16], "sourceorrery/v4/recovery-key/x")
        );
        assert_ne!(
            a,
            derive_from_secret(b"ABCDE12345", &[1u8; 16], "sourceorrery/v4/recovery-key/y")
        );
        assert_ne!(
            a,
            derive_from_secret(b"ABCDE12346", &[1u8; 16], "sourceorrery/v4/recovery-key/x")
        );
    }

    #[test]
    fn salted_hkdf_sha256_known_answer() {
        // RFC 5869, test case 1: IKM = 0x0b * 22, salt = 0x00..=0x0c,
        // info = 0xf0..=0xf9; the first 32 bytes of its OKM. That info is
        // not UTF-8, so the crate is pinned to the RFC here and the wrapper
        // to the crate with a UTF-8 label below.
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let mut okm = [0u8; KEY_LEN];
        Hkdf::<Sha256>::new(Some(&salt), &ikm)
            .expand(&info, &mut okm)
            .unwrap();
        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        );

        let mut same = [0u8; KEY_LEN];
        Hkdf::<Sha256>::new(Some(&salt), &ikm)
            .expand(b"recovery", &mut same)
            .unwrap();
        assert_eq!(
            derive_from_secret(&ikm, &salt, "recovery"),
            SymmetricKey::from_bytes(same)
        );
    }

    #[test]
    fn mac_round_trip_and_tamper() {
        let k = key(7);
        let tag = mac(&k, b"hello");
        assert_eq!(tag.len(), MAC_LEN);
        verify_mac(&k, b"hello", &tag).unwrap();
        assert_eq!(
            verify_mac(&k, b"hellp", &tag).unwrap_err(),
            CryptoError::Authentication
        );
        let mut bad = tag;
        bad[0] ^= 1;
        assert_eq!(
            verify_mac(&k, b"hello", &bad).unwrap_err(),
            CryptoError::Authentication
        );
        assert_eq!(
            verify_mac(&key(8), b"hello", &tag).unwrap_err(),
            CryptoError::Authentication
        );
    }

    #[test]
    fn mac_rejects_wrong_tag_length() {
        let k = key(7);
        let tag = mac(&k, b"hello");
        assert!(verify_mac(&k, b"hello", &tag[..16]).is_err());
        assert!(verify_mac(&k, b"hello", &[]).is_err());
    }

    #[test]
    fn hmac_sha256_rfc4231_case_2() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?"
        // with the key zero-padded to 32 bytes (HMAC pads short keys with
        // zeros, so this equals the published vector).
        let mut raw = [0u8; KEY_LEN];
        raw[..4].copy_from_slice(b"Jefe");
        let tag = mac(
            &SymmetricKey::from_bytes(raw),
            b"what do ya want for nothing?",
        );
        assert_eq!(
            hex::encode(tag),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}
