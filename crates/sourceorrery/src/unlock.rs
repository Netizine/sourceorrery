//! Non-interactive recovery-key sources, in the CLI's order.

use std::path::{Path, PathBuf};

use sourceorrery_core::{Result as CoreResult, SecretBytes, SecretError};
use sourceorrery_storage::{RecoveryKeyPrompt, UnlockProvider};

use crate::{RECOVERY_KEY_ENV, RECOVERY_KEY_FILE_ENV};

/// Where a recovery key may come from, in the order they are tried after
/// this machine's credential store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeySource {
    /// A recovery key passed by the application in `OpenOptions`.
    Explicit,
    /// `SOURCEORRERY_RECOVERY_KEY`.
    Environment,
    /// The file named by `SOURCEORRERY_RECOVERY_KEY_FILE` or `OpenOptions`.
    File,
}

impl KeySource {
    /// Name used in hints.
    pub fn label(self) -> &'static str {
        match self {
            Self::Explicit => "recovery_key option",
            Self::Environment => RECOVERY_KEY_ENV,
            Self::File => RECOVERY_KEY_FILE_ENV,
        }
    }
}

/// What the client found when it gathered recovery keys: used to explain a
/// `locked` error.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnlockReport {
    /// Sources that supplied a key, in the order they were tried.
    pub supplied: Vec<KeySource>,
    /// Sources that were consulted but had nothing (unset, empty, no file).
    pub empty: Vec<KeySource>,
    /// Recovery-key file that was configured, if any.
    pub file: Option<PathBuf>,
    /// Whether the environment was consulted at all.
    pub environment: bool,
}

impl UnlockReport {
    /// One line per source, for hints.
    pub(crate) fn describe(&self) -> String {
        let mut parts = Vec::new();
        for source in [KeySource::Explicit, KeySource::Environment, KeySource::File] {
            let state = if self.supplied.contains(&source) {
                "tried"
            } else if self.empty.contains(&source) {
                match source {
                    KeySource::Explicit => "not given",
                    KeySource::Environment | KeySource::File => "not set",
                }
            } else {
                "not consulted"
            };
            let label = match (source, &self.file) {
                (KeySource::File, Some(path)) => {
                    format!("{} ({})", source.label(), path.display())
                }
                _ => source.label().to_owned(),
            };
            parts.push(format!("{label}: {state}"));
        }
        parts.join(", ")
    }
}

/// Supplies, one per attempt, the recovery keys found in the configured
/// sources. Never prompts.
#[derive(Debug)]
pub(crate) struct NonInteractiveUnlock {
    candidates: Vec<SecretBytes>,
    pub(crate) report: UnlockReport,
}

impl NonInteractiveUnlock {
    /// Gather recovery keys: the explicit one, then the environment
    /// variable, then the file. Duplicates are tried once.
    pub(crate) fn gather(
        explicit: Option<&SecretBytes>,
        file: Option<&Path>,
        environment: bool,
    ) -> CoreResult<Self> {
        let file: Option<PathBuf> = match file {
            Some(path) => Some(path.to_path_buf()),
            None if environment => std::env::var_os(RECOVERY_KEY_FILE_ENV)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
            None => None,
        };
        let from_file = match &file {
            Some(path) => Some(read_key_file(path)?),
            None => None,
        };
        let from_env = if environment { key_from_env() } else { None };

        let mut candidates: Vec<SecretBytes> = Vec::new();
        let mut report = UnlockReport {
            file,
            environment,
            ..UnlockReport::default()
        };
        let mut offer = |source: KeySource, key: Option<SecretBytes>| match key {
            Some(key) if !key.is_empty() => {
                report.supplied.push(source);
                if !candidates.contains(&key) {
                    candidates.push(key);
                }
            }
            _ => report.empty.push(source),
        };
        offer(KeySource::Explicit, explicit.cloned());
        offer(KeySource::Environment, from_env);
        offer(KeySource::File, from_file);
        Ok(Self { candidates, report })
    }
}

impl UnlockProvider for NonInteractiveUnlock {
    fn recovery_key(&self, prompt: &RecoveryKeyPrompt<'_>) -> CoreResult<Option<SecretBytes>> {
        let index = prompt.attempt.saturating_sub(1) as usize;
        Ok(self.candidates.get(index).cloned())
    }
}

fn key_from_env() -> Option<SecretBytes> {
    std::env::var(RECOVERY_KEY_ENV)
        .ok()
        .filter(|v| !v.is_empty())
        .map(SecretBytes::from_string)
}

/// Read a recovery-key file the way the CLI does: trailing newlines are not
/// part of the key, and an empty file is an error.
fn read_key_file(path: &Path) -> CoreResult<SecretBytes> {
    let mut bytes = std::fs::read(path).map_err(|err| {
        SecretError::Io(format!(
            "cannot read recovery-key file {}: {err}",
            path.display()
        ))
    })?;
    while bytes.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Err(SecretError::Io(format!(
            "recovery-key file {} is empty",
            path.display()
        )));
    }
    Ok(SecretBytes::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prompt(attempt: u32) -> RecoveryKeyPrompt<'static> {
        RecoveryKeyPrompt {
            vault: "dev",
            attempt,
            max_attempts: 3,
        }
    }

    #[test]
    fn the_explicit_key_comes_first_and_duplicates_collapse() {
        let explicit = SecretBytes::from("one");
        let unlock = NonInteractiveUnlock::gather(Some(&explicit), None, false).unwrap();
        assert_eq!(unlock.report.supplied, vec![KeySource::Explicit]);
        assert_eq!(
            unlock.recovery_key(&prompt(1)).unwrap(),
            Some(SecretBytes::from("one"))
        );
        assert_eq!(unlock.recovery_key(&prompt(2)).unwrap(), None);
        assert!(
            unlock
                .report
                .describe()
                .contains("recovery_key option: tried")
        );
        assert!(
            unlock
                .report
                .describe()
                .contains("SOURCEORRERY_RECOVERY_KEY: not set")
        );
    }

    #[test]
    fn the_key_file_is_trimmed_and_must_not_be_empty() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("key");
        std::fs::write(&file, "from-file\r\n\n").unwrap();
        let unlock = NonInteractiveUnlock::gather(None, Some(&file), false).unwrap();
        assert_eq!(
            unlock.recovery_key(&prompt(1)).unwrap(),
            Some(SecretBytes::from("from-file"))
        );
        assert_eq!(unlock.report.supplied, vec![KeySource::File]);
        assert!(unlock.report.describe().contains("key): tried"));

        std::fs::write(&file, "\n").unwrap();
        let err = NonInteractiveUnlock::gather(None, Some(&file), false).unwrap_err();
        assert_eq!(err.code(), "io");

        let missing = dir.path().join("missing");
        let err = NonInteractiveUnlock::gather(None, Some(&missing), false).unwrap_err();
        assert_eq!(err.code(), "io");
    }

    #[test]
    fn an_empty_explicit_key_is_not_a_candidate() {
        let empty = SecretBytes::from("");
        let unlock = NonInteractiveUnlock::gather(Some(&empty), None, false).unwrap();
        assert_eq!(unlock.report.supplied, Vec::new());
        assert_eq!(unlock.recovery_key(&prompt(1)).unwrap(), None);
    }
}
