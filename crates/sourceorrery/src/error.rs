//! Errors with stable codes and actionable hints.
//!
//! The hint is the part a person needs when a read fails in an application
//! they did not write: which command creates the vault, which passphrase
//! sources were tried, why a version was refused. Hints are produced here, in
//! Rust, so every SDK says the same thing. They never contain a value.

use std::fmt;
use std::path::Path;

use sourceorrery_core::SecretError;
use sourceorrery_storage::VAULT_FILE_EXTENSION;

use crate::unlock::UnlockReport;
use crate::{HOME_ENV, PASSPHRASE_ENV, PASSPHRASE_FILE_ENV};

/// Result alias used throughout the client.
pub type Result<T> = std::result::Result<T, Error>;

/// Category of an [`Error`], one per stable code the client can report.
///
/// SDKs map these to their exception types. The list follows
/// `SecretError::code()`; a code this version does not know maps to
/// [`ErrorKind::Other`] and is never dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// `not_found`: no secret with that name.
    NotFound,
    /// `version_not_found`: the secret exists but the version does not.
    VersionNotFound,
    /// `deleted`: the secret is soft-deleted.
    Deleted,
    /// `disabled`: the version is disabled by policy.
    Disabled,
    /// `not_yet_valid`: the version's `not_before` has not been reached.
    NotYetValid,
    /// `expired`: the version's `expires_on` has passed.
    Expired,
    /// `invalid_name`: a secret or vault name breaks the naming rules.
    InvalidName,
    /// `invalid_argument`: a malformed reference, version or option.
    InvalidArgument,
    /// `permission_denied`: authenticated but not authorised.
    PermissionDenied,
    /// `locked`: no protector or passphrase source could unlock the vault.
    Locked,
    /// `vault_not_found`: no vault file with that name in the home directory.
    VaultNotFound,
    /// `migration_required`: the vault file is in an older format.
    MigrationRequired,
    /// `vault_mismatch`: the file found for the vault holds another vault
    /// (renamed, copied or swapped in).
    VaultMismatch,
    /// `manifest`: `sourceorrery.toml` is missing or invalid.
    Manifest,
    /// `crypto`: a value, its metadata or the audit chain failed verification.
    Crypto,
    /// `storage`: the vault file could not be read or queried.
    Storage,
    /// `io`: a file or directory could not be read.
    Io,
    /// `unsupported`: the operation needs something this platform lacks
    /// (typically an OS credential store).
    Unsupported,
    /// A code added after this client was written.
    Other,
}

impl ErrorKind {
    /// Kind for a stable code.
    pub fn from_code(code: &str) -> Self {
        match code {
            "not_found" => Self::NotFound,
            "version_not_found" => Self::VersionNotFound,
            "deleted" => Self::Deleted,
            "disabled" => Self::Disabled,
            "not_yet_valid" => Self::NotYetValid,
            "expired" => Self::Expired,
            "invalid_name" => Self::InvalidName,
            "invalid_argument" => Self::InvalidArgument,
            "permission_denied" => Self::PermissionDenied,
            "locked" => Self::Locked,
            "vault_not_found" => Self::VaultNotFound,
            "migration_required" => Self::MigrationRequired,
            "vault_mismatch" => Self::VaultMismatch,
            "manifest" => Self::Manifest,
            "crypto" => Self::Crypto,
            "storage" => Self::Storage,
            "io" => Self::Io,
            "unsupported" => Self::Unsupported,
            _ => Self::Other,
        }
    }

    /// True for policy refusals (`disabled`, `not_yet_valid`, `expired`).
    pub fn is_policy(self) -> bool {
        matches!(self, Self::Disabled | Self::NotYetValid | Self::Expired)
    }
}

/// A failed read, with the core's stable code and a hint about what to do.
#[derive(Clone, Debug)]
pub struct Error {
    kind: ErrorKind,
    code: &'static str,
    message: String,
    hint: String,
    transient: bool,
}

impl Error {
    /// Stable, `snake_case` code (`not_found`, `locked`, ...). Codes are
    /// append-only; see `SecretError::code`.
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// Category of the error.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// What went wrong, without the hint. Never contains a value.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// What to do about it. Empty when there is nothing specific to say.
    pub fn hint(&self) -> &str {
        &self.hint
    }

    /// True when retrying later could succeed without administrative action
    /// (a version whose `not_before` has not been reached).
    pub fn is_transient(&self) -> bool {
        self.transient
    }

    /// Wrap a core error, with the hint a reader bound to `vault` would
    /// give. For bindings and tools that call the core directly.
    pub fn from_core(err: &SecretError, vault: Option<&str>) -> Self {
        Self::new(
            err,
            &Context {
                vault,
                ..Context::default()
            },
        )
    }

    /// Wrap a core error with the hint for `context`.
    pub(crate) fn new(err: &SecretError, context: &Context<'_>) -> Self {
        Self {
            kind: ErrorKind::from_code(err.code()),
            code: err.code(),
            message: err.to_string(),
            hint: hint_for(err, context),
            transient: err.is_transient(),
        }
    }

    /// Replace the message, keeping code, hint and kind.
    pub(crate) fn with_message(mut self, message: String) -> Self {
        self.message = message;
        self
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)?;
        if !self.hint.is_empty() {
            write!(f, ". {}", self.hint)?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {}

impl From<SecretError> for Error {
    /// Wrap without vault context; prefer [`Error::from_core`] when the
    /// vault is known, so hints can name it.
    fn from(err: SecretError) -> Self {
        Self::from_core(&err, None)
    }
}

/// What the hint generator knows about the failed call.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Context<'a> {
    /// Vault the call was about.
    pub vault: Option<&'a str>,
    /// Home directory the vault was looked up in.
    pub home: Option<&'a Path>,
    /// Passphrase sources consulted by `open`.
    pub unlock: Option<&'a UnlockReport>,
}

impl Context<'_> {
    fn vault_flag(&self) -> String {
        self.vault
            .map(|v| format!(" --vault {v}"))
            .unwrap_or_default()
    }

    fn home_note(&self) -> String {
        match self.home {
            Some(home) => format!(
                " Vaults are looked up under {} (set {HOME_ENV} to use another directory).",
                home.display()
            ),
            None => format!(" Set {HOME_ENV} if the vault lives in another directory."),
        }
    }
}

/// Hint for a vault file found under another vault's name.
fn mismatch_hint(requested: &str, found: &str, ctx: &Context<'_>) -> String {
    format!(
        "The file {requested}.{VAULT_FILE_EXTENSION} is the vault '{found}', renamed or copied, \
         or put there by someone who can write the vault directory; SourceOrrery never serves \
         one vault under another's name. Move it back to {found}.{VAULT_FILE_EXTENSION} or \
         restore '{requested}' from a backup, and if nobody moved it, treat it as tampering.{}",
        ctx.home_note()
    )
}

/// The actionable part of an error. Mentions commands and configuration,
/// never values.
fn hint_for(err: &SecretError, ctx: &Context<'_>) -> String {
    match err {
        SecretError::VaultNotFound { name } => format!(
            "Create it with `sourceorrery vault create {name}` (add `--protector passphrase` \
             for headless use), or check the name.{}",
            ctx.home_note()
        ),
        SecretError::Locked(_) => {
            let sources = ctx.unlock.map_or_else(
                || "no passphrase sources were consulted".to_owned(),
                UnlockReport::describe,
            );
            let vault = ctx.vault.unwrap_or("<name>");
            format!(
                "The OS credential store was tried first, then the passphrase sources \
                 ({sources}). Set {PASSPHRASE_ENV} or {PASSPHRASE_FILE_ENV}, pass a passphrase \
                 when opening, or add a protector this machine can use with \
                 `sourceorrery vault protector add --kind passphrase --vault {vault}`"
            )
        }
        SecretError::MigrationRequired { name, .. } => format!(
            "Run `sourceorrery vault migrate {name}` on a copy of the file you trust. SDKs \
             never migrate a vault on their own because the older format is unauthenticated"
        ),
        SecretError::NotFound { name } => format!(
            "Store it with `sourceorrery secret set {name}{}` (the value is read from stdin or a \
             prompt, never from an argument). `sourceorrery secret list{}` shows what the vault holds",
            ctx.vault_flag(),
            ctx.vault_flag()
        ),
        SecretError::VersionNotFound { name, .. } => format!(
            "`sourceorrery secret versions {name}{}` lists the versions that exist; omit the \
             version to read the newest accessible one",
            ctx.vault_flag()
        ),
        SecretError::Deleted { name } => format!(
            "The secret is soft-deleted. Recover it with `sourceorrery secret recover {name}{}` \
             or store it again after purging",
            ctx.vault_flag()
        ),
        SecretError::Disabled { name, version } => format!(
            "Policy: this version is disabled, so it cannot be read. Enable it with \
             `sourceorrery secret update {name} --version {version} --enable{}` or store a new \
             version; a read without an explicit version picks the newest enabled version \
             inside its time window",
            ctx.vault_flag()
        ),
        SecretError::NotYetValid {
            name,
            version,
            not_before,
        } => format!(
            "Policy: the version's activation time {not_before} has not been reached. Wait for \
             it, clear it with `sourceorrery secret update {name} --version {version} \
             --clear-not-before{}`, or read another version",
            ctx.vault_flag()
        ),
        SecretError::Expired {
            name,
            version,
            expires_on,
        } => format!(
            "Policy: the version expired on {expires_on}. Store a new version with \
             `sourceorrery secret set {name}{}` or extend it with `sourceorrery secret update \
             {name} --version {version} --expires <RFC 3339>{}`",
            ctx.vault_flag(),
            ctx.vault_flag()
        ),
        SecretError::VaultMismatch { requested, found } => mismatch_hint(requested, found, ctx),
        SecretError::Crypto(_) => format!(
            "The vault file failed an integrity check: a value, its metadata or the audit chain \
             does not verify, so the file was edited, truncated or restored from a partial copy. \
             Compare it with a backup and run `sourceorrery audit --verify{}`",
            ctx.vault_flag()
        ),
        SecretError::Unsupported(_) => format!(
            "No OS credential store is available here (headless Linux, a container, CI). On a \
             machine that can unlock the vault, add a passphrase protector with `sourceorrery \
             vault protector add --kind passphrase{}`, then unlock with {PASSPHRASE_ENV} or \
             {PASSPHRASE_FILE_ENV}",
            ctx.vault_flag()
        ),
        SecretError::InvalidName { .. } => "Secret names are 1-127 ASCII letters, digits and \
             hyphens; vault names are 1-64 lowercase letters, digits and hyphens"
            .to_owned(),
        SecretError::InvalidArgument(_) => "References look like \
             `sourceorrery://vault/name` or `sourceorrery://vault/name/version`, and a \
             reference must name the vault the reader is bound to"
            .to_owned(),
        SecretError::Manifest(_) => "Fix sourceorrery.toml (it declares names and references \
             only; a `value` key is a parse error) and check it with `sourceorrery check`"
            .to_owned(),
        SecretError::Storage(_) | SecretError::Io(_) => format!(
            "Check that the vault file and its directory are readable by this process.{}",
            ctx.home_note()
        ),
        SecretError::PermissionDenied(_) => {
            "This identity is not allowed to read the secret".to_owned()
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_cover_every_core_code() {
        let codes = [
            "not_found",
            "version_not_found",
            "deleted",
            "disabled",
            "not_yet_valid",
            "expired",
            "invalid_name",
            "invalid_argument",
            "permission_denied",
            "locked",
            "vault_not_found",
            "migration_required",
            "vault_mismatch",
            "manifest",
            "crypto",
            "storage",
            "io",
            "unsupported",
        ];
        for code in codes {
            assert_ne!(ErrorKind::from_code(code), ErrorKind::Other, "{code}");
        }
        assert_eq!(ErrorKind::from_code("something_new"), ErrorKind::Other);
        assert!(ErrorKind::Expired.is_policy());
        assert!(!ErrorKind::Locked.is_policy());
    }

    #[test]
    fn display_joins_message_and_hint() {
        let err = Error::new(
            &SecretError::NotFound {
                name: "db-password".into(),
            },
            &Context {
                vault: Some("dev"),
                ..Context::default()
            },
        );
        assert_eq!(err.code(), "not_found");
        assert_eq!(err.kind(), ErrorKind::NotFound);
        let text = err.to_string();
        assert!(text.starts_with("secret 'db-password' was not found. "));
        assert!(text.contains("sourceorrery secret set db-password --vault dev"));
        assert!(!err.is_transient());

        let transient = Error::new(
            &SecretError::NotYetValid {
                name: "k".into(),
                version: "v1".into(),
                not_before: "2100-01-01T00:00:00Z".into(),
            },
            &Context::default(),
        );
        assert!(transient.is_transient());
        assert!(transient.hint().contains("--clear-not-before"));
    }

    #[test]
    fn mismatch_hint_names_both_files() {
        let err = Error::new(
            &SecretError::VaultMismatch {
                requested: "prod".into(),
                found: "dev".into(),
            },
            &Context {
                vault: Some("prod"),
                ..Context::default()
            },
        );
        assert_eq!(err.code(), "vault_mismatch");
        assert_eq!(err.kind(), ErrorKind::VaultMismatch);
        assert_eq!(
            err.message(),
            "the file for vault 'prod' holds the vault 'dev'"
        );
        assert!(
            err.hint()
                .starts_with("The file prod.sorvault is the vault 'dev'")
        );
        assert!(err.hint().contains("Move it back to dev.sorvault"));
        assert!(!err.is_transient());
    }

    #[test]
    fn locked_hint_lists_the_sources() {
        let report = UnlockReport {
            supplied: vec![crate::PassphraseSource::Environment],
            empty: vec![
                crate::PassphraseSource::Explicit,
                crate::PassphraseSource::File,
            ],
            file: None,
            environment: true,
        };
        let err = Error::new(
            &SecretError::Locked("passphrase: wrong".into()),
            &Context {
                vault: Some("dev"),
                home: Some(Path::new("/home/x/so")),
                unlock: Some(&report),
            },
        );
        assert!(err.hint().contains("SOURCEORRERY_PASSPHRASE: tried"));
        assert!(err.hint().contains("passphrase option: not given"));
        assert!(
            err.hint()
                .contains("protector add --kind passphrase --vault dev")
        );
    }
}
