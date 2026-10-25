//! Bounded, deterministic fuzzing for the parsers of input SourceOrrery
//! does not control: what a provider's server sends, what a vault file or
//! a manifest holds. Each case is a valid seed with a few bytes deleted,
//! inserted, repeated or replaced; the same seed number gives the same
//! cases on every run, so a failure is reproducible. A test runs a fixed
//! number of cases and requires a value or an error for each, never a
//! panic. This is not coverage-guided fuzzing; it is the bounded check CI
//! runs on every change.

/// A xorshift64 generator and the mutations it drives.
#[derive(Debug, Clone)]
pub struct Mutator(u64);

/// Bytes the mutations insert: JSON and TOML punctuation, digits and time
/// separators, the separators SourceOrrery's own formats use, a NUL, bytes
/// that are not UTF-8 on their own, and letters of the reserved prefix.
const BYTES: &[u8] = b"{}[]\":,=~./#0123456789-TZ:+ \\\n\x00\xff\xc3sourceorrery";

impl Mutator {
    /// A generator that starts from `seed` (not zero).
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    /// The next number.
    pub fn number(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// A number below `n` (0 when `n` is 0).
    pub fn below(&mut self, n: usize) -> usize {
        let n = u64::try_from(n.max(1)).unwrap_or(u64::MAX);
        usize::try_from(self.number() % n).unwrap_or_default()
    }

    /// `seed` as bytes with one to four mutations.
    pub fn mutate_bytes(&mut self, seed: &[u8]) -> Vec<u8> {
        let mut bytes = seed.to_vec();
        for _ in 0..=self.below(4) {
            let at = self.below(bytes.len() + 1);
            match self.below(4) {
                0 if at < bytes.len() => {
                    bytes.remove(at);
                }
                1 => bytes.insert(at, BYTES[self.below(BYTES.len())]),
                2 if at < bytes.len() => {
                    let end = (at + self.below(8)).min(bytes.len());
                    let piece = bytes[at..end].to_vec();
                    bytes.splice(at..at, piece);
                }
                _ if at < bytes.len() => bytes[at] = BYTES[self.below(BYTES.len())],
                _ => {}
            }
        }
        bytes
    }

    /// `seed` with one to four mutations, as text (invalid UTF-8 replaced,
    /// as a JSON or TOML reader would see it after decoding).
    pub fn mutate(&mut self, seed: &str) -> String {
        String::from_utf8_lossy(&self.mutate_bytes(seed.as_bytes())).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::Mutator;

    #[test]
    fn the_cases_are_reproducible_and_differ_from_their_seed() {
        let mut a = Mutator::new(7);
        let mut b = Mutator::new(7);
        let cases: Vec<String> = (0..50)
            .map(|_| a.mutate("sourceorrery://dev/k/v1"))
            .collect();
        assert_eq!(
            cases,
            (0..50)
                .map(|_| b.mutate("sourceorrery://dev/k/v1"))
                .collect::<Vec<_>>()
        );
        assert!(
            cases
                .iter()
                .filter(|c| *c != "sourceorrery://dev/k/v1")
                .count()
                > 40
        );
        assert_eq!(
            Mutator::new(0).number(),
            Mutator::new(1).number(),
            "zero is not a seed"
        );
    }
}
