//! Randomness from the operating system CSPRNG, and the recovery codes and
//! generated passphrases built on it.

use zeroize::Zeroizing;

use crate::{CryptoError, Result};

/// Crockford's base32 alphabet: no I, L, O or U, so a code read back from
/// paper is not mistaken.
const CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Characters a generated passphrase draws from: letters, digits and the
/// symbols every shell and prompt accepts unquoted or quoted alike.
const PASSPHRASE_ALPHABET: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.,;:!?@#%&*+=";

/// Groups of five characters in a recovery code.
pub const CODE_GROUPS: usize = 5;
/// Characters per group.
pub const CODE_GROUP_LEN: usize = 5;
/// Bits of entropy in a recovery code (25 characters of 5 bits).
pub const CODE_BITS: u32 = 125;
const _: () = assert!(CODE_GROUPS * CODE_GROUP_LEN * 5 == CODE_BITS as usize);

/// Bits of entropy per generated passphrase character, in thousandths:
/// log2 of the alphabet's 77 characters.
const PASSPHRASE_MILLIBITS_PER_CHAR: usize = 6266;

/// One uniformly random index below `bound` (rejection sampling, so no
/// modulo bias).
fn random_index(bound: usize) -> Result<usize> {
    debug_assert!(bound > 0 && bound <= 256);
    let limit = 256 - (256 % bound);
    loop {
        let [byte] = random_bytes::<1>()?;
        if usize::from(byte) < limit {
            return Ok(usize::from(byte) % bound);
        }
    }
}

/// A recovery code: [`CODE_GROUPS`] groups of [`CODE_GROUP_LEN`] characters
/// from an alphabet without look-alikes, separated by hyphens
/// (`7K3QX-M9ZT2-...`), [`CODE_BITS`] bits of entropy. The code is a
/// passphrase: it unlocks the vault, so it is zeroised when dropped and
/// shown to its owner once.
pub fn recovery_code() -> Result<Zeroizing<String>> {
    let mut code = Zeroizing::new(String::with_capacity(CODE_GROUPS * (CODE_GROUP_LEN + 1)));
    for group in 0..CODE_GROUPS {
        if group > 0 {
            code.push('-');
        }
        for _ in 0..CODE_GROUP_LEN {
            code.push(CODE_ALPHABET[random_index(CODE_ALPHABET.len())?] as char);
        }
    }
    Ok(code)
}

/// The form a typed passphrase takes as a recovery code, when it has the
/// shape of one: [`CODE_GROUPS`] × [`CODE_GROUP_LEN`] characters of the
/// code alphabet once normalised, typed with at most a few separators.
/// `None` for anything else, so a passphrase that happens to be 25 letters
/// long is never mistaken for a code: an unlock tries the passphrase as
/// typed first and this form second.
pub fn recovery_code_form(typed: &str) -> Option<Zeroizing<String>> {
    let expected = CODE_GROUPS * CODE_GROUP_LEN;
    if typed.len() > expected + CODE_GROUPS + 4 {
        return None;
    }
    let normalised = normalise_recovery_code(typed);
    let shaped =
        normalised.len() == expected && normalised.bytes().all(|b| CODE_ALPHABET.contains(&b));
    shaped.then_some(normalised)
}

/// Normalise a recovery code as a person typed it: uppercase, hyphens and
/// spaces removed, the look-alikes Crockford's alphabet maps (I and L to 1,
/// O to 0) folded, so what was written down unlocks even when read back
/// loosely. The result is what [`recovery_code`] produced minus its hyphens.
pub fn normalise_recovery_code(typed: &str) -> Zeroizing<String> {
    Zeroizing::new(
        typed
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| match c.to_ascii_uppercase() {
                'I' | 'L' => '1',
                'O' => '0',
                other => other,
            })
            .collect(),
    )
}

/// A random passphrase of `len` characters: letters, digits and symbols from
/// a 77-character alphabet, about 6.3 bits each (20 characters are 125
/// bits). Zeroised when dropped.
pub fn random_passphrase(len: usize) -> Result<Zeroizing<String>> {
    let mut text = Zeroizing::new(String::with_capacity(len));
    for _ in 0..len {
        text.push(PASSPHRASE_ALPHABET[random_index(PASSPHRASE_ALPHABET.len())?] as char);
    }
    Ok(text)
}

/// Bits of entropy of a passphrase [`random_passphrase`] made, by length.
pub fn passphrase_bits(len: usize) -> u32 {
    u32::try_from(len * PASSPHRASE_MILLIBITS_PER_CHAR / 1000).unwrap_or(u32::MAX)
}

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
    fn recovery_codes_and_passphrases_have_the_documented_shape() {
        let code = recovery_code().unwrap();
        assert_eq!(code.len(), CODE_GROUPS * CODE_GROUP_LEN + CODE_GROUPS - 1);
        for (i, group) in code.split('-').enumerate() {
            assert_eq!(group.len(), CODE_GROUP_LEN, "group {i}");
            assert!(group.bytes().all(|b| CODE_ALPHABET.contains(&b)));
        }
        assert_ne!(*code, *recovery_code().unwrap());
        assert_eq!(CODE_BITS, 125);
        let typed = format!(
            " {} ",
            code.to_lowercase().replace('0', "o").replace('1', "l")
        );
        assert_eq!(*normalise_recovery_code(&typed), code.replace('-', ""));

        let pass = random_passphrase(20).unwrap();
        assert_eq!(pass.len(), 20);
        assert!(pass.bytes().all(|b| PASSPHRASE_ALPHABET.contains(&b)));
        assert_ne!(*pass, *random_passphrase(20).unwrap());
        assert_eq!(passphrase_bits(20), 125);
        assert_eq!(PASSPHRASE_ALPHABET.len(), 77);
        assert_eq!(*random_passphrase(0).unwrap(), "");
    }

    #[test]
    fn hex_has_expected_shape() {
        let id = random_hex(16).unwrap();
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(id, random_hex(16).unwrap());
    }
}
