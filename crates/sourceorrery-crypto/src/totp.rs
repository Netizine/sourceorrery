//! Time-based one-time passwords (RFC 6238 over HMAC-SHA1, RFC 4226), the
//! algorithm every authenticator app speaks: a 160-bit shared secret, a
//! 30-second step, six digits.
//!
//! The secret is a [`TotpSecret`]: zeroised on drop, redacted in `Debug`,
//! exposed only to compute a code or to show the enrolment once (as base32
//! or an `otpauth://` URI). Verification compares in constant time, accepts
//! one step either side of the current one, and refuses any step at or
//! before the last accepted one, so a code cannot be replayed.

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::random;
use crate::{CryptoError, Result};

/// Length of a generated secret in bytes (160 bits, the RFC's recommendation).
pub const SECRET_LEN: usize = 20;
/// Seconds per step.
pub const PERIOD_SECS: u64 = 30;
/// Digits in a code.
pub const DIGITS: usize = 6;
/// Steps accepted either side of the current one (clock drift).
pub const WINDOW: u64 = 1;

/// A TOTP shared secret.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct TotpSecret(Vec<u8>);

impl TotpSecret {
    /// A fresh random secret of [`SECRET_LEN`] bytes.
    pub fn generate() -> Result<Self> {
        let mut bytes = vec![0u8; SECRET_LEN];
        random::fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// Wrap raw secret bytes (10 to 64 bytes).
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() < 10 || bytes.len() > 64 {
            return Err(CryptoError::InvalidInput(
                "a TOTP secret is 10 to 64 bytes".to_owned(),
            ));
        }
        Ok(Self(bytes))
    }

    /// Parse the base32 form an authenticator app shows or accepts.
    pub fn from_base32(text: &str) -> Result<Self> {
        Self::from_bytes(base32_decode(text)?)
    }

    /// The raw bytes.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// The secret as unpadded base32 (RFC 4648), the form enrolment shows.
    pub fn to_base32(&self) -> String {
        base32_encode(&self.0)
    }

    /// The `otpauth://totp/` URI an authenticator app enrols from.
    /// `issuer` and `account` are shown in the app; neither is secret.
    pub fn otpauth_uri(&self, issuer: &str, account: &str) -> String {
        format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={PERIOD_SECS}",
            percent_encode(issuer),
            percent_encode(account),
            self.to_base32(),
            percent_encode(issuer)
        )
    }

    /// The code for `counter` (RFC 4226 dynamic truncation, [`DIGITS`] digits).
    pub fn code(&self, counter: u64) -> String {
        let mut mac = Hmac::<Sha1>::new_from_slice(&self.0).expect("HMAC accepts any key length");
        mac.update(&counter.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let offset = usize::from(digest[19] & 0x0f);
        let binary = (u32::from(digest[offset] & 0x7f) << 24)
            | (u32::from(digest[offset + 1]) << 16)
            | (u32::from(digest[offset + 2]) << 8)
            | u32::from(digest[offset + 3]);
        format!("{:0width$}", binary % 1_000_000, width = DIGITS)
    }

    /// The code for the step containing `unix_secs`.
    pub fn code_at(&self, unix_secs: u64) -> String {
        self.code(counter_at(unix_secs))
    }

    /// Check `code` at `unix_secs`, accepting [`WINDOW`] steps either side,
    /// and refusing any step at or before `last_counter` (the last accepted
    /// one). Returns the step that matched, to be stored as the new
    /// `last_counter`; `None` when the code is not valid now.
    pub fn verify(&self, code: &str, unix_secs: u64, last_counter: Option<u64>) -> Option<u64> {
        let code = code.trim().replace(' ', "");
        if code.len() != DIGITS || !code.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let current = counter_at(unix_secs);
        let first = current.saturating_sub(WINDOW);
        let mut matched = None;
        // Every candidate is computed and compared, so the time taken does
        // not say which step (if any) matched.
        for counter in first..=current + WINDOW {
            let expected = self.code(counter);
            let ok: bool = expected.as_bytes().ct_eq(code.as_bytes()).into();
            if ok && last_counter.is_none_or(|last| counter > last) && matched.is_none() {
                matched = Some(counter);
            }
        }
        matched
    }
}

impl std::fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpSecret([REDACTED])")
    }
}

/// The step `unix_secs` falls in.
pub fn counter_at(unix_secs: u64) -> u64 {
    unix_secs / PERIOD_SECS
}

/// Seconds until the current step ends, for a countdown.
pub fn seconds_left(unix_secs: u64) -> u64 {
    PERIOD_SECS - (unix_secs % PERIOD_SECS)
}

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 without padding.
pub fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32_ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(BASE32_ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// RFC 4648 base32, padding and spaces ignored, case-insensitive.
pub fn base32_decode(text: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for c in text.chars() {
        if c == '=' || c == ' ' || c == '-' {
            continue;
        }
        let value = match c.to_ascii_uppercase() {
            'A'..='Z' => c.to_ascii_uppercase() as u32 - 'A' as u32,
            '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => {
                return Err(CryptoError::InvalidInput(
                    "not base32: only letters and the digits 2 to 7 are allowed".to_owned(),
                ));
            }
        };
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

/// Percent-encode everything outside the unreserved set, for the URI's
/// label and issuer.
fn percent_encode(text: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238, Appendix B: the SHA-1 vectors with the ASCII secret
    /// "12345678901234567890"; the RFC lists eight digits, the last six are
    /// the six-digit code.
    fn rfc_secret() -> TotpSecret {
        TotpSecret::from_bytes(b"12345678901234567890".to_vec()).unwrap()
    }

    #[test]
    fn rfc_6238_sha1_vectors() {
        let secret = rfc_secret();
        for (time, eight) in [
            (59u64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            assert_eq!(secret.code_at(time), &eight[2..], "t={time}");
        }
    }

    #[test]
    fn verification_accepts_the_window_and_refuses_replay() {
        let secret = rfc_secret();
        let now = 1_111_111_111;
        let current = counter_at(now);
        let code = secret.code(current);
        assert_eq!(secret.verify(&code, now, None), Some(current));
        // The step before and after are accepted, two away is not.
        assert_eq!(
            secret.verify(&secret.code(current - 1), now, None),
            Some(current - 1)
        );
        assert_eq!(
            secret.verify(&secret.code(current + 1), now, None),
            Some(current + 1)
        );
        assert_eq!(secret.verify(&secret.code(current + 2), now, None), None);
        // Once a step is accepted it, and every earlier step, is refused.
        assert_eq!(secret.verify(&code, now, Some(current)), None);
        assert_eq!(
            secret.verify(&secret.code(current - 1), now, Some(current)),
            None
        );
        assert_eq!(
            secret.verify(&secret.code(current + 1), now, Some(current)),
            Some(current + 1)
        );
        // Shape: six digits, spaces allowed.
        let spaced = format!("{} {}", &code[..3], &code[3..]);
        assert_eq!(secret.verify(&spaced, now, None), Some(current));
        assert_eq!(secret.verify("12345", now, None), None);
        assert_eq!(secret.verify("abcdef", now, None), None);
        assert_eq!(secret.verify("", now, None), None);
    }

    #[test]
    fn base32_round_trips_and_matches_the_rfc() {
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_decode("MZXW6YTBOI======").unwrap(), b"foobar");
        assert_eq!(base32_decode("mzxw 6ytb-oi").unwrap(), b"foobar");
        assert!(base32_decode("MZXW1").is_err());
        let secret = TotpSecret::generate().unwrap();
        assert_eq!(secret.expose().len(), SECRET_LEN);
        let text = secret.to_base32();
        assert_eq!(text.len(), 32);
        assert_eq!(TotpSecret::from_base32(&text).unwrap(), secret);
        assert_ne!(TotpSecret::generate().unwrap(), secret);
    }

    #[test]
    fn the_uri_names_issuer_and_account_and_never_debug_prints_the_secret() {
        let secret = rfc_secret();
        let uri = secret.otpauth_uri("SourceOrrery", "vault development");
        assert_eq!(
            uri,
            format!(
                "otpauth://totp/SourceOrrery:vault%20development?secret={}&issuer=SourceOrrery&algorithm=SHA1&digits=6&period=30",
                secret.to_base32()
            )
        );
        assert_eq!(format!("{secret:?}"), "TotpSecret([REDACTED])");
        assert!(!format!("{secret:?}").contains("1234"));
        assert_eq!(seconds_left(59), 1);
        assert_eq!(seconds_left(60), 30);
        assert!(TotpSecret::from_bytes(vec![0; 4]).is_err());
    }
}
