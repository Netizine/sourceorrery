//! Non-interactive passphrase sources, in the CLI's order.

use std::path::{Path, PathBuf};

use sourceorrery_core::{Result as CoreResult, SecretBytes, SecretError};
use sourceorrery_storage::{PassphrasePrompt, UnlockProvider};

use crate::{PASSPHRASE_ENV, PASSPHRASE_FILE_ENV};

/// Where a passphrase may come from, in the order they are tried after the
/// OS credential store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PassphraseSource {
    /// A passphrase passed by the application in `OpenOptions`.
    Explicit,
    /// `SOURCEORRERY_PASSPHRASE`.
    Environment,
    /// The file named by `SOURCEORRERY_PASSPHRASE_FILE` or `OpenOptions`.
    File,
}

impl PassphraseSource {
    /// Name used in hints.
    pub fn label(self) -> &'static str {
        match self {
            Self::Explicit => "passphrase option",
            Self::Environment => PASSPHRASE_ENV,
            Self::File => PASSPHRASE_FILE_ENV,
        }
    }
}

/// What the client found when it gathered passphrases: used to explain a
/// `locked` error.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnlockReport {
    /// Sources that supplied a passphrase, in the order they were tried.
    pub supplied: Vec<PassphraseSource>,
    /// Sources that were consulted but had nothing (unset, empty, no file).
    pub empty: Vec<PassphraseSource>,
    /// Passphrase file that was configured, if any.
    pub file: Option<PathBuf>,
    /// Whether the environment was consulted at all.
    pub environment: bool,
}

impl UnlockReport {
    /// One line per source, for hints.
    pub(crate) fn describe(&self) -> String {
        let mut parts = Vec::new();
        for source in [
            PassphraseSource::Explicit,
            PassphraseSource::Environment,
            PassphraseSource::File,
        ] {
            let state = if self.supplied.contains(&source) {
                "tried"
            } else if self.empty.contains(&source) {
                match source {
                    PassphraseSource::Explicit => "not given",
                    PassphraseSource::Environment | PassphraseSource::File => "not set",
                }
            } else {
                "not consulted"
            };
            let label = match (source, &self.file) {
                (PassphraseSource::File, Some(path)) => {
                    format!("{} ({})", source.label(), path.display())
                }
                _ => source.label().to_owned(),
            };
            parts.push(format!("{label}: {state}"));
        }
        parts.join(", ")
    }
}

/// Supplies, one per attempt, the passphrases found in the configured
/// sources. Never prompts.
#[derive(Debug)]
pub(crate) struct NonInteractiveUnlock {
    candidates: Vec<SecretBytes>,
    pub(crate) report: UnlockReport,
}

impl NonInteractiveUnlock {
    /// Gather passphrases: the explicit one, then the environment variable,
    /// then the file. Duplicates are tried once.
    pub(crate) fn gather(
        explicit: Option<&SecretBytes>,
        file: Option<&Path>,
        environment: bool,
    ) -> CoreResult<Self> {
        let file: Option<PathBuf> = match file {
            Some(path) => Some(path.to_path_buf()),
            None if environment => std::env::var_os(PASSPHRASE_FILE_ENV)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
            None => None,
        };
        let from_file = match &file {
            Some(path) => Some(read_passphrase_file(path)?),
            None => None,
        };
        let from_env = if environment {
            passphrase_from_env()
        } else {
            None
        };

        let mut candidates: Vec<SecretBytes> = Vec::new();
        let mut report = UnlockReport {
            file,
            environment,
            ..UnlockReport::default()
        };
        let mut offer = |source: PassphraseSource, pass: Option<SecretBytes>| match pass {
            Some(pass) if !pass.is_empty() => {
                report.supplied.push(source);
                if !candidates.contains(&pass) {
                    candidates.push(pass);
                }
            }
            _ => report.empty.push(source),
        };
        offer(PassphraseSource::Explicit, explicit.cloned());
        offer(PassphraseSource::Environment, from_env);
        offer(PassphraseSource::File, from_file);
        Ok(Self { candidates, report })
    }
}

impl UnlockProvider for NonInteractiveUnlock {
    fn passphrase(&self, prompt: &PassphrasePrompt<'_>) -> CoreResult<Option<SecretBytes>> {
        let index = prompt.attempt.saturating_sub(1) as usize;
        Ok(self.candidates.get(index).cloned())
    }
}

fn passphrase_from_env() -> Option<SecretBytes> {
    std::env::var(PASSPHRASE_ENV)
        .ok()
        .filter(|v| !v.is_empty())
        .map(SecretBytes::from_string)
}

/// Read a passphrase file the way the CLI does: trailing newlines are not
/// part of the passphrase, and an empty file is an error.
fn read_passphrase_file(path: &Path) -> CoreResult<SecretBytes> {
    let mut bytes = std::fs::read(path).map_err(|err| {
        SecretError::Io(format!(
            "cannot read passphrase file {}: {err}",
            path.display()
        ))
    })?;
    while bytes.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Err(SecretError::Io(format!(
            "passphrase file {} is empty",
            path.display()
        )));
    }
    Ok(SecretBytes::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prompt(attempt: u32) -> PassphrasePrompt<'static> {
        PassphrasePrompt {
            vault: "dev",
            protector_label: "passphrase",
            attempt,
            max_attempts: 3,
        }
    }

    #[test]
    fn explicit_passphrase_comes_first_and_duplicates_collapse() {
        let explicit = SecretBytes::from("one");
        let unlock = NonInteractiveUnlock::gather(Some(&explicit), None, false).unwrap();
        assert_eq!(unlock.report.supplied, vec![PassphraseSource::Explicit]);
        assert_eq!(
            unlock.passphrase(&prompt(1)).unwrap(),
            Some(SecretBytes::from("one"))
        );
        assert_eq!(unlock.passphrase(&prompt(2)).unwrap(), None);
        assert!(
            unlock
                .report
                .describe()
                .contains("passphrase option: tried")
        );
        assert!(
            unlock
                .report
                .describe()
                .contains("SOURCEORRERY_PASSPHRASE: not set")
        );
    }

    #[test]
    fn passphrase_file_is_trimmed_and_must_not_be_empty() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("pass");
        std::fs::write(&file, "from-file\r\n\n").unwrap();
        let unlock = NonInteractiveUnlock::gather(None, Some(&file), false).unwrap();
        assert_eq!(
            unlock.passphrase(&prompt(1)).unwrap(),
            Some(SecretBytes::from("from-file"))
        );
        assert_eq!(unlock.report.supplied, vec![PassphraseSource::File]);
        assert!(unlock.report.describe().contains("pass): tried"));

        std::fs::write(&file, "\n").unwrap();
        let err = NonInteractiveUnlock::gather(None, Some(&file), false).unwrap_err();
        assert_eq!(err.code(), "io");

        let missing = dir.path().join("missing");
        let err = NonInteractiveUnlock::gather(None, Some(&missing), false).unwrap_err();
        assert_eq!(err.code(), "io");
    }

    #[test]
    fn empty_explicit_passphrase_is_not_a_candidate() {
        let empty = SecretBytes::from("");
        let unlock = NonInteractiveUnlock::gather(Some(&empty), None, false).unwrap();
        assert_eq!(unlock.report.supplied, Vec::new());
        assert_eq!(unlock.passphrase(&prompt(1)).unwrap(), None);
    }
}
