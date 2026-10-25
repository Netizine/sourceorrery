//! Non-interactive recovery-key sources, in the CLI's order.
//!
//! A source is consulted only when the vault asks for a recovery key and
//! every earlier source is used up: a vault this machine's key opens reads
//! none of them, and a key that works stops the search, so an unset, empty
//! or unreadable later source never fails an open that an earlier one
//! completes (SR08 of the 2026-10-25 review).

use std::cell::RefCell;
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
    /// Sources that were consulted but had nothing (unset, empty). A source
    /// in neither list was not consulted: the vault opened, or stopped
    /// asking, before its turn.
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

/// Supplies, one per attempt, the recovery keys of the configured sources
/// in order: the explicit one, then the environment variable, then the
/// file, each read only when its turn comes. A key equal to one already
/// offered is not offered again. Never prompts.
#[derive(Debug)]
pub(crate) struct NonInteractiveUnlock {
    explicit: Option<SecretBytes>,
    environment: bool,
    state: RefCell<Sources>,
}

/// What has been consulted so far.
#[derive(Debug)]
struct Sources {
    /// The next source to consult, as an index into [`ORDER`].
    next: usize,
    offered: Vec<SecretBytes>,
    report: UnlockReport,
}

const ORDER: [KeySource; 3] = [KeySource::Explicit, KeySource::Environment, KeySource::File];

impl NonInteractiveUnlock {
    /// The sources to try: `explicit`, `SOURCEORRERY_RECOVERY_KEY` when
    /// `environment` allows it, then `file` or, when the environment
    /// allows it, `SOURCEORRERY_RECOVERY_KEY_FILE`. Nothing is read here.
    pub(crate) fn new(
        explicit: Option<&SecretBytes>,
        file: Option<&Path>,
        environment: bool,
    ) -> Self {
        let file: Option<PathBuf> = match file {
            Some(path) => Some(path.to_path_buf()),
            None if environment => std::env::var_os(RECOVERY_KEY_FILE_ENV)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
            None => None,
        };
        Self {
            explicit: explicit.cloned(),
            environment,
            state: RefCell::new(Sources {
                next: 0,
                offered: Vec::new(),
                report: UnlockReport {
                    file,
                    environment,
                    ..UnlockReport::default()
                },
            }),
        }
    }

    /// What was consulted, for a `locked` error's hint.
    pub(crate) fn report(&self) -> UnlockReport {
        self.state.borrow().report.clone()
    }

    /// The key `source` holds now, if any; a file that cannot be read or is
    /// empty is an error, since it was named.
    fn read(&self, source: KeySource, file: Option<&Path>) -> CoreResult<Option<SecretBytes>> {
        Ok(match source {
            KeySource::Explicit => self.explicit.clone(),
            KeySource::Environment if self.environment => key_from_env(),
            KeySource::Environment => None,
            KeySource::File => match file {
                Some(path) => Some(read_key_file(path)?),
                None => None,
            },
        })
    }
}

impl UnlockProvider for NonInteractiveUnlock {
    fn recovery_key(&self, _prompt: &RecoveryKeyPrompt<'_>) -> CoreResult<Option<SecretBytes>> {
        let mut state = self.state.borrow_mut();
        while let Some(&source) = ORDER.get(state.next) {
            state.next += 1;
            let file = state.report.file.clone();
            match self.read(source, file.as_deref())? {
                Some(key) if !key.is_empty() => {
                    state.report.supplied.push(source);
                    if !state.offered.contains(&key) {
                        state.offered.push(key.clone());
                        return Ok(Some(key));
                    }
                }
                _ => state.report.empty.push(source),
            }
        }
        Ok(None)
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
        let unlock = NonInteractiveUnlock::new(Some(&explicit), None, false);
        assert_eq!(unlock.report(), UnlockReport::default(), "nothing read yet");
        assert_eq!(
            unlock.recovery_key(&prompt(1)).unwrap(),
            Some(SecretBytes::from("one"))
        );
        assert_eq!(unlock.report().supplied, vec![KeySource::Explicit]);
        assert!(
            unlock
                .report()
                .describe()
                .contains("SOURCEORRERY_RECOVERY_KEY: not consulted")
        );
        assert_eq!(unlock.recovery_key(&prompt(2)).unwrap(), None);
        let described = unlock.report().describe();
        assert!(
            described.contains("recovery_key option: tried"),
            "{described}"
        );
        assert!(
            described.contains("SOURCEORRERY_RECOVERY_KEY: not set"),
            "{described}"
        );

        // The same key from a later source is consulted, not offered twice.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("key");
        std::fs::write(&file, "one\n").unwrap();
        let unlock = NonInteractiveUnlock::new(Some(&explicit), Some(&file), false);
        assert_eq!(
            unlock.recovery_key(&prompt(1)).unwrap(),
            Some(SecretBytes::from("one"))
        );
        assert_eq!(unlock.recovery_key(&prompt(2)).unwrap(), None);
        assert_eq!(
            unlock.report().supplied,
            vec![KeySource::Explicit, KeySource::File]
        );
    }

    #[test]
    fn the_key_file_is_trimmed_and_must_not_be_empty() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("key");
        std::fs::write(&file, "from-file\r\n\n").unwrap();
        let unlock = NonInteractiveUnlock::new(None, Some(&file), false);
        assert_eq!(
            unlock.recovery_key(&prompt(1)).unwrap(),
            Some(SecretBytes::from("from-file"))
        );
        assert_eq!(unlock.report().supplied, vec![KeySource::File]);
        assert!(unlock.report().describe().contains("key): tried"));

        // An empty or missing file is an error, but only once it is reached.
        std::fs::write(&file, "\n").unwrap();
        let unlock = NonInteractiveUnlock::new(None, Some(&file), false);
        assert_eq!(unlock.recovery_key(&prompt(1)).unwrap_err().code(), "io");
        let missing = dir.path().join("missing");
        let unlock = NonInteractiveUnlock::new(None, Some(&missing), false);
        assert_eq!(unlock.recovery_key(&prompt(1)).unwrap_err().code(), "io");
    }

    #[test]
    fn an_unusable_later_file_is_never_read_while_an_earlier_key_is_tried() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        let explicit = SecretBytes::from("right");
        let unlock = NonInteractiveUnlock::new(Some(&explicit), Some(&missing), false);
        // The vault takes the first key: the file is never consulted.
        assert_eq!(
            unlock.recovery_key(&prompt(1)).unwrap(),
            Some(explicit.clone())
        );
        let described = unlock.report().describe();
        assert!(described.contains("missing): not consulted"), "{described}");
        // Were the first key wrong, the vault would ask again: then the
        // file is read, and its error says which file.
        let err = unlock.recovery_key(&prompt(2)).unwrap_err();
        assert_eq!(err.code(), "io");
        assert!(err.to_string().contains("missing"), "{err}");
    }

    #[test]
    fn an_empty_explicit_key_is_not_a_candidate() {
        let empty = SecretBytes::from("");
        let unlock = NonInteractiveUnlock::new(Some(&empty), None, false);
        assert_eq!(unlock.recovery_key(&prompt(1)).unwrap(), None);
        assert_eq!(unlock.report().supplied, Vec::new());
        assert_eq!(unlock.report().empty.len(), 3);
    }
}
