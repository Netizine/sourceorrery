//! A passphrase strength estimate, the kind a sign-up form shows: a score
//! from 0 (guessed at once) to 4 (strong), the estimated bits of guessing
//! work behind it, and what weakened it.
//!
//! It is an estimate, not a measurement: it counts the character classes in
//! use and the length, then takes away what an attacker's wordlist and
//! pattern rules would find for free (a common password, a dictionary word
//! with the usual substitutions, repeated characters, keyboard and
//! alphabet runs, a year, a short length). The common-password list is
//! small and the wordlist absent on purpose: a few hundred kilobytes of
//! dictionaries would not change the advice, which is to use a long random
//! passphrase, and `sourceorrery` can generate one. Nothing here keeps or
//! prints the text it is given.

// The estimate is arithmetic over small counts: the casts between usize,
// f64 and u32 here cannot lose anything that matters to a score of 0 to 4.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use zeroize::Zeroizing;

/// The score a form shows: 0 to 4.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Score {
    /// Guessed at once: empty, very short, or a common password.
    Guessable = 0,
    /// Falls to a small dictionary attack.
    Weak = 1,
    /// Falls to an offline attack against a leaked file.
    Fair = 2,
    /// Enough for a vault that an attacker must brute-force through Argon2id.
    Good = 3,
    /// Beyond what brute force reaches.
    Strong = 4,
}

impl Score {
    /// The word a form shows.
    pub fn label(self) -> &'static str {
        match self {
            Self::Guessable => "guessable",
            Self::Weak => "weak",
            Self::Fair => "fair",
            Self::Good => "good",
            Self::Strong => "strong",
        }
    }

    /// The least score `vault create`, `vault passphrase set` and the
    /// set-up wizard accept without `--allow-weak`.
    pub const REQUIRED: Self = Self::Good;
}

/// The estimate for one passphrase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Estimate {
    /// The score.
    pub score: Score,
    /// Estimated bits of guessing work, after the deductions.
    pub bits: u32,
    /// What weakened it, in the order found; empty for a strong passphrase.
    pub warnings: Vec<&'static str>,
}

impl Estimate {
    /// True when the passphrase meets [`Score::REQUIRED`].
    pub fn acceptable(&self) -> bool {
        self.score >= Score::REQUIRED
    }
}

/// The hundred-odd passwords every cracking wordlist starts with, lowercase.
const COMMON: &[&str] = &[
    "password",
    "123456",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty",
    "abc123",
    "111111",
    "iloveyou",
    "admin",
    "welcome",
    "monkey",
    "login",
    "letmein",
    "dragon",
    "passw0rd",
    "master",
    "hello",
    "freedom",
    "whatever",
    "qazwsx",
    "trustno1",
    "starwars",
    "football",
    "baseball",
    "superman",
    "batman",
    "sunshine",
    "princess",
    "shadow",
    "michael",
    "jennifer",
    "charlie",
    "donald",
    "ashley",
    "bailey",
    "access",
    "flower",
    "hottie",
    "loveme",
    "zaq12wsx",
    "password1",
    "password123",
    "secret",
    "changeme",
    "default",
    "guest",
    "root",
    "toor",
    "test",
    "testing",
    "temp",
    "pass",
    "letmein1",
    "welcome1",
    "admin123",
    "user",
    "sourceorrery",
    "vault",
    "development",
    "production",
    "database",
    "mysql",
    "postgres",
    "oracle",
    "cisco",
    "ubuntu",
    "linux",
    "windows",
    "apple",
    "google",
    "amazon",
    "github",
    "openai",
    "anthropic",
    "chatgpt",
    "claude",
    "aaaaaa",
    "000000",
    "121212",
    "654321",
    "696969",
    "112233",
    "987654321",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1q2w3e4r",
    "1qaz2wsx",
    "q1w2e3r4",
    "11111111",
    "00000000",
    "88888888",
    "12341234",
    "monkey1",
    "cheese",
    "pepper",
    "summer",
    "winter",
    "spring",
    "autumn",
    "january",
    "december",
    "computer",
    "internet",
    "samsung",
    "nothing",
    "killer",
    "hunter",
    "hunter2",
    "soccer",
    "hockey",
    "jordan",
    "harley",
    "ranger",
    "buster",
    "thomas",
    "robert",
    "daniel",
    "andrew",
    "joshua",
    "matthew",
];

/// Keyboard rows and alphabets whose runs count as one guess each.
const SEQUENCES: &[&str] = &[
    "abcdefghijklmnopqrstuvwxyz",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
    "0987654321",
    "!@#$%^&*()",
];

/// Estimate `passphrase`.
pub fn estimate(passphrase: &str) -> Estimate {
    let chars: Zeroizing<Vec<char>> = Zeroizing::new(passphrase.chars().collect());
    let len = chars.len();
    let mut warnings = Vec::new();
    if len == 0 {
        return Estimate {
            score: Score::Guessable,
            bits: 0,
            warnings: vec!["empty"],
        };
    }

    // A common password, as typed, with the trailing digits or symbol
    // every rule set appends, with the usual letter substitutions, or
    // backwards.
    let lower: Zeroizing<String> = Zeroizing::new(passphrase.to_lowercase());
    let stripped: Zeroizing<String> = Zeroizing::new(
        lower
            .trim_end_matches(|c: char| c.is_ascii_digit() || c.is_ascii_punctuation())
            .to_owned(),
    );
    let candidates: [Zeroizing<String>; 5] = [
        lower.clone(),
        stripped.clone(),
        Zeroizing::new(unleet(&lower)),
        Zeroizing::new(unleet(&stripped)),
        Zeroizing::new(reverse(&lower)),
    ];
    if candidates
        .iter()
        .any(|word| COMMON.contains(&word.as_str()))
    {
        return Estimate {
            score: Score::Guessable,
            bits: 4,
            warnings: vec!["a common password"],
        };
    }

    let (mut bits, patterns) = cost_runs(&chars);
    let (has_lower, has_upper, has_digit, has_symbol) = classes(&chars);

    // Deductions and warnings.
    let unique = {
        let mut seen: Vec<char> = Vec::with_capacity(len);
        for c in chars.iter() {
            if !seen.contains(c) {
                seen.push(*c);
            }
        }
        seen.len()
    };
    if patterns.repeat || unique * 2 < len {
        warnings.push("repeated characters");
        if unique * 2 < len {
            bits *= 0.5;
        }
    }
    if patterns.sequence {
        warnings.push("a keyboard or alphabet sequence");
    }
    if patterns.year {
        warnings.push("a year");
    }
    if has_lower && !has_upper && !has_digit && !has_symbol {
        warnings.push("only lowercase letters");
    } else if has_digit && !has_lower && !has_upper && !has_symbol {
        warnings.push("only digits");
    }
    if len < 8 {
        warnings.push("shorter than 8 characters");
        bits = bits.min(20.0);
    } else if len < 12 {
        warnings.push("shorter than 12 characters");
    }
    // Capitalising the first letter and ending with digits or a symbol is
    // the pattern every rule set tries first.
    if len >= 2
        && chars[0].is_uppercase()
        && chars[1..].iter().all(|c| !c.is_uppercase())
        && chars
            .last()
            .is_some_and(|c| c.is_ascii_digit() || c.is_ascii_punctuation())
    {
        warnings.push("a capital first letter and a digit or symbol last");
        bits -= 6.0;
    }

    let bits = bits.max(0.0) as u32;
    let score = match bits {
        0..=19 => Score::Guessable,
        20..=31 => Score::Weak,
        32..=43 => Score::Fair,
        44..=59 => Score::Good,
        _ => Score::Strong,
    };
    Estimate {
        score,
        bits,
        warnings,
    }
}

/// Which cheap patterns the runs showed.
#[derive(Default)]
struct Patterns {
    repeat: bool,
    sequence: bool,
    year: bool,
}

/// Which character classes are in use: lower, upper, digit, symbol.
fn classes(chars: &[char]) -> (bool, bool, bool, bool) {
    let (mut has_lower, mut has_upper, mut has_digit, mut has_symbol) =
        (false, false, false, false);
    for c in chars {
        if c.is_lowercase() {
            has_lower = true;
        } else if c.is_uppercase() {
            has_upper = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else {
            has_symbol = true;
        }
    }
    (has_lower, has_upper, has_digit, has_symbol)
}

/// Cost the passphrase as the runs an attacker's rules see: a run of
/// letters is a word (a dictionary entry plus a little variation) once it
/// is four letters or more, a run of digits a number or a year, a run of
/// symbols a separator; every boundary between runs adds a little.
fn cost_runs(chars: &[char]) -> (f64, Patterns) {
    let len = chars.len();
    let mut bits = 0.0f64;
    let mut patterns = Patterns::default();
    let mut boundaries = 0u32;
    let mut start = 0;
    while start < len {
        let class = class_of(chars[start]);
        let mut end = start + 1;
        while end < len && class_of(chars[end]) == class {
            end += 1;
        }
        let run: Zeroizing<String> = Zeroizing::new(chars[start..end].iter().collect());
        let n = end - start;
        let same_char = n > 1 && chars[start + 1..end].iter().all(|c| *c == chars[start]);
        let run_lower: Zeroizing<String> = Zeroizing::new(run.to_lowercase());
        let is_sequence = n >= 4 && longest_run(&run_lower) == n;
        bits += match class {
            Class::Letter if same_char => {
                patterns.repeat = true;
                3.0
            }
            Class::Letter if is_sequence => {
                patterns.sequence = true;
                6.0
            }
            // A run that reads as a word (one case throughout, or a capital
            // first letter) is a dictionary entry plus a little variation;
            // letters in mixed case are not a word and count one by one.
            Class::Letter if n >= 4 && word_like(&chars[start..end]) => {
                let uppercase = run.chars().filter(char::is_ascii_uppercase).count();
                10.0 + n as f64 / 2.0 + uppercase.min(3) as f64
            }
            Class::Letter
                if run.chars().any(char::is_uppercase) && run.chars().any(char::is_lowercase) =>
            {
                n as f64 * 5.7
            }
            Class::Letter => n as f64 * 4.7,
            Class::Digit if looks_like_year(&run) => {
                patterns.year = true;
                7.0
            }
            Class::Digit if same_char || is_sequence => {
                if same_char {
                    patterns.repeat = true;
                } else {
                    patterns.sequence = true;
                }
                4.0
            }
            Class::Digit => n as f64 * 3.32,
            Class::Symbol if same_char => 4.0,
            Class::Symbol => n as f64 * 5.0,
        };
        if start > 0 {
            boundaries += 1;
        }
        start = end;
    }
    (bits + f64::from(boundaries) * 2.0, patterns)
}

/// One case throughout, or a capital first letter and lowercase after it.
fn word_like(run: &[char]) -> bool {
    let lower = run.iter().filter(|c| c.is_lowercase()).count();
    let upper = run.iter().filter(|c| c.is_uppercase()).count();
    lower == 0 || upper == 0 || (upper == 1 && run[0].is_uppercase())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Letter,
    Digit,
    Symbol,
}

fn class_of(c: char) -> Class {
    if c.is_alphabetic() {
        Class::Letter
    } else if c.is_ascii_digit() {
        Class::Digit
    } else {
        Class::Symbol
    }
}

/// Undo the usual letter-for-digit substitutions (`p4ssw0rd`).
fn unleet(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '4' | '@' => 'a',
            '3' => 'e',
            '1' | '!' | '|' => 'i',
            '0' => 'o',
            '5' | '$' => 's',
            '7' => 't',
            other => other,
        })
        .collect()
}

fn reverse(text: &str) -> String {
    text.chars().rev().collect()
}

/// The longest run of consecutive characters from one of [`SEQUENCES`],
/// forwards or backwards.
fn longest_run(lower: &str) -> usize {
    let chars: Vec<char> = lower.chars().collect();
    let mut best = 0;
    for sequence in SEQUENCES {
        let seq: Vec<char> = sequence.chars().collect();
        for (i, first) in chars.iter().enumerate() {
            let Some(start) = seq.iter().position(|c| c == first) else {
                continue;
            };
            // Forwards along the sequence.
            let mut run = 1;
            while start + run < seq.len()
                && i + run < chars.len()
                && seq[start + run] == chars[i + run]
            {
                run += 1;
            }
            best = best.max(run);
            // Backwards.
            let mut run = 1;
            while start >= run && i + run < chars.len() && seq[start - run] == chars[i + run] {
                run += 1;
            }
            best = best.max(run);
        }
    }
    best
}

fn looks_like_year(lower: &str) -> bool {
    let bytes = lower.as_bytes();
    bytes
        .windows(4)
        .any(|w| w.iter().all(u8::is_ascii_digit) && (w.starts_with(b"19") || w.starts_with(b"20")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_passwords_are_guessable_however_dressed() {
        for text in [
            "password",
            "Password1",
            "P@ssw0rd!",
            "drowssap",
            "123456",
            "qwerty",
            "",
        ] {
            let e = estimate(text);
            assert_eq!(e.score, Score::Guessable, "{text}: {e:?}");
            assert!(!e.acceptable());
        }
    }

    #[test]
    fn patterns_are_weak_and_random_passphrases_are_strong() {
        let short = estimate("abc1");
        assert!(short.score <= Score::Weak, "{short:?}");
        assert!(short.warnings.contains(&"shorter than 8 characters"));
        let sequence = estimate("abcdefgh77!");
        assert!(sequence.score <= Score::Fair, "{sequence:?}");
        assert!(
            sequence
                .warnings
                .contains(&"a keyboard or alphabet sequence")
        );
        let repeated = estimate("aaaaaaaabbbb");
        assert!(repeated.score <= Score::Weak, "{repeated:?}");
        assert!(repeated.warnings.contains(&"repeated characters"));
        let year = estimate("Harbour2024!");
        assert!(year.score <= Score::Fair, "{year:?}");
        assert!(year.warnings.contains(&"a year"));
        let typical = estimate("Chocolate7!");
        assert!(!typical.acceptable(), "{typical:?}");

        let good = estimate("correct-horse-battery");
        assert!(good.acceptable(), "{good:?}");
        let strong = estimate("x9#Lq2!vP7&mZ4@rT1^w");
        assert_eq!(strong.score, Score::Strong, "{strong:?}");
        assert_eq!(strong.warnings, Vec::<&str>::new());
        assert!(strong.bits > 100);
    }
}
