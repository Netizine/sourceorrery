//! Shared state for every command: where vaults live, how to unlock them,
//! how to print.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, anyhow};
use sourceorrery_core::{
    AuditEvent, AuditQuery, Capability, DeletedSecret, ListOptions, Manifest, Page,
    Result as CoreResult, Secret, SecretBytes, SecretClient, SecretProperties, SecretReference,
    SetSecretOptions, UpdateSecretProperties, timestamp,
};
use sourceorrery_provider::Routed;
use sourceorrery_storage::{
    RecoveryKeyPrompt, SecretStorage, SqliteVault, UnlockProvider, VaultRegistry, ViewAnswers,
};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::cli::{Cli, OutputFormat};
use crate::strength::{self, Score};
use crate::{output, prompt};

/// Environment variable that supplies a vault's recovery key directly,
/// where this machine's credential store cannot open it (CI, containers).
pub const RECOVERY_KEY_ENV: &str = "SOURCEORRERY_RECOVERY_KEY";

/// Environment variable that supplies the view check's password (scripts).
pub const PASSWORD_ENV: &str = "SOURCEORRERY_PASSWORD";

/// Variables that open a vault or answer its view check. `run` and the
/// rotation hooks strip them from the child's environment: a program
/// started with its secrets is not handed the means to read every other
/// one.
pub const UNLOCK_ENV_VARS: [&str; 5] = [
    RECOVERY_KEY_ENV,
    "SOURCEORRERY_RECOVERY_KEY_FILE",
    PASSWORD_ENV,
    "SOURCEORRERY_PASSWORD_FILE",
    "SOURCEORRERY_TOTP",
];

#[derive(Debug)]
pub struct Ctx {
    pub registry: VaultRegistry,
    pub output: OutputFormat,
    pub vault_flag: Option<String>,
    /// `--recovery-key-file` / `SOURCEORRERY_RECOVERY_KEY_FILE`.
    pub recovery_key_file: Option<PathBuf>,
    /// `--password-file` / `SOURCEORRERY_PASSWORD_FILE`: the view check's
    /// password, for scripts.
    pub password_file: Option<PathBuf>,
    pub verbose: u8,
    /// `--code` / `SOURCEORRERY_TOTP`: an authenticator code for the view
    /// check, consumed by the first check.
    pub code: Option<Code>,
}

impl Ctx {
    pub fn from_cli(cli: &Cli) -> anyhow::Result<Self> {
        let registry = match &cli.home {
            Some(home) => VaultRegistry::with_root(home.clone()),
            None => VaultRegistry::from_env()?,
        };
        Ok(Self {
            registry,
            output: cli.output,
            vault_flag: cli.vault.clone(),
            recovery_key_file: cli.recovery_key_file.clone(),
            password_file: cli.password_file.clone(),
            verbose: cli.verbose,
            code: cli.code.clone(),
        })
    }

    pub fn json(&self) -> bool {
        self.output == OutputFormat::Json
    }

    /// The vault a command should act on: `--vault`, else the manifest found
    /// upwards from the current directory.
    pub fn vault_name(&self) -> anyhow::Result<String> {
        self.selected_vault()?.ok_or_else(|| {
            anyhow!(
                "no vault specified: pass --vault <name>, set SOURCEORRERY_VAULT, or run `sourceorrery init`"
            )
        })
    }

    /// [`Ctx::vault_name`], with `None` when neither `--vault` nor a
    /// manifest names one. A manifest that cannot be read is still an error.
    pub fn selected_vault(&self) -> anyhow::Result<Option<String>> {
        if let Some(name) = &self.vault_flag {
            return Ok(Some(name.clone()));
        }
        Ok(Self::manifest()?.map(|manifest| manifest.project.vault))
    }

    /// The nearest `sourceorrery.toml` above the current directory, parsed.
    /// `None` when there is none; one that cannot be read is an error.
    fn manifest() -> anyhow::Result<Option<Manifest>> {
        let cwd = std::env::current_dir().context("cannot determine current directory")?;
        match Manifest::discover(&cwd) {
            Some(path) => Ok(Some(Manifest::load(&path)?)),
            None => Ok(None),
        }
    }

    /// Open a vault by name for the operations of the contract, each routed
    /// to where the vault keeps the secret: its file, or the provider one of
    /// its connections reaches.
    pub fn open(&self, name: &str) -> anyhow::Result<Opened> {
        Ok(Opened(Routed::new(self.open_local(name)?)))
    }

    /// Open the vault selected by [`Ctx::vault_name`].
    pub fn open_default(&self) -> anyhow::Result<Opened> {
        let name = self.vault_name()?;
        self.open(&name)
    }

    /// Open the vault file itself, for what only the file has (its key
    /// wraps, its view check, its settings).
    pub fn open_local(&self, name: &str) -> anyhow::Result<SqliteVault> {
        let unlocker = self.unlocker();
        Ok(self.registry.open(name, &unlocker)?)
    }

    /// Open the selected vault to inspect its audit log: like
    /// [`Ctx::open_local`], but a vault blocked by an unacknowledged
    /// audit-log truncation is unlocked too, with every secret and
    /// settings operation refused until the truncation is acknowledged.
    /// Only the `audit` command uses this.
    pub fn inspect_default(&self) -> anyhow::Result<SqliteVault> {
        let name = self.vault_name()?;
        self.inspect(&name)
    }

    /// [`Ctx::inspect_default`] for a vault named explicitly. Besides
    /// `audit`, the `ui` browser opens vaults this way, so that a blocked
    /// vault can still show its audit log there; the vault itself refuses
    /// every secret operation until the truncation is acknowledged.
    pub fn inspect(&self, name: &str) -> anyhow::Result<SqliteVault> {
        let unlocker = self.unlocker();
        Ok(self.registry.open_for_inspection(name, &unlocker)?)
    }

    pub fn unlocker(&self) -> Unlocker {
        Unlocker {
            file: self.recovery_key_file.clone(),
            interactive: std::io::stdin().is_terminal(),
            automated: std::cell::Cell::new(false),
        }
    }

    /// A new password for the view check, from `file`. Automation's password
    /// is its owner's business: one the strength estimate (`strength`) rates
    /// below [`Score::REQUIRED`] only gets a warning on stderr. A password
    /// typed by a person is rated on the setup screens, which refuse a weak
    /// one.
    pub fn password_from_file(file: &Path) -> anyhow::Result<SecretBytes> {
        let password = read_secret_file(file, "password")?;
        warn_if_weak(&password, "the password file");
        Ok(password)
    }

    /// The answers to `vault`'s view check, gathered from where a person or
    /// a script gives them: the password from `SOURCEORRERY_PASSWORD` or
    /// `--password-file`, else the prompt (after the hint); the
    /// authenticator code from `--code` / `SOURCEORRERY_TOTP`, else the
    /// prompt. Only what the check asks for is gathered; without a terminal
    /// a missing answer stays missing and the vault refuses it.
    pub fn view_answers(&self, vault: &SqliteVault) -> anyhow::Result<ViewAnswers> {
        let check = vault.view_check()?;
        let mut answers = ViewAnswers::default();
        if check.is_none() || vault.opened_with_recovery_key() {
            return Ok(answers);
        }
        let interactive = std::io::stdin().is_terminal();
        answers.password = if let Some(password) = password_from_env() {
            Some(password)
        } else if let Some(file) = &self.password_file {
            Some(read_secret_file(file, "password")?)
        } else if interactive {
            if let Some(hint) = vault.password_hint()? {
                eprintln!("Hint: {}", output::sanitize(&hint));
            }
            Some(prompt::read_hidden(&format!(
                "Password of vault '{}': ",
                vault.vault_name()
            ))?)
        } else {
            None
        };
        if check.authenticator {
            answers.code = match &self.code {
                Some(code) => Some(code.as_str().to_owned()),
                None if interactive => {
                    Some(prompt::read_line("Code from the authenticator app: ")?)
                }
                None => None,
            };
        }
        Ok(answers)
    }

    /// [`Ctx::check_view`] for a vault opened by [`Ctx::open`].
    pub fn check_view_opened(&self, vault: &Opened) -> anyhow::Result<()> {
        self.check_view(vault.vault())
    }

    /// Ask `vault`'s view check (nothing when none is set, or when the
    /// recovery key opened the vault) and have the vault weigh the answers.
    /// A refusal is `permission_denied`, already audited by the vault; when
    /// no terminal could ask, the message says how a script answers.
    pub fn check_view(&self, vault: &SqliteVault) -> anyhow::Result<()> {
        let answers = self.view_answers(vault)?;
        let unanswered = answers.password.is_none() && !std::io::stdin().is_terminal();
        let authenticator = vault.view_check()?.authenticator;
        vault.check_view(&answers, timestamp::now()).map_err(|err| {
            if unanswered {
                anyhow!(
                    "{err}; without a terminal, set {PASSWORD_ENV} or --password-file{}",
                    if authenticator {
                        " and pass --code"
                    } else {
                        ""
                    }
                )
            } else {
                err.into()
            }
        })
    }
}

/// Say on stderr when a password automation supplied is
/// weak; the estimate never prints it, only what weakened it.
pub(crate) fn warn_if_weak(secret: &SecretBytes, source: &str) {
    let estimate = strength::estimate(secret.expose_utf8().unwrap_or_default());
    if !estimate.acceptable() {
        output::note(&format!(
            "the value from {source} rates {}{}; it should be at least \"{}\"",
            estimate.score.label(),
            if estimate.warnings.is_empty() {
                String::new()
            } else {
                format!(" ({})", estimate.warnings.join(", "))
            },
            Score::REQUIRED.label()
        ));
    }
}

fn recovery_key_from_env() -> Option<SecretBytes> {
    std::env::var(RECOVERY_KEY_ENV)
        .ok()
        .filter(|v| !v.is_empty())
        .map(SecretBytes::from_string)
}

fn password_from_env() -> Option<SecretBytes> {
    std::env::var(PASSWORD_ENV)
        .ok()
        .filter(|v| !v.is_empty())
        .map(SecretBytes::from_string)
}

/// A secret from a file, trailing newlines removed; an empty file is an
/// error. `what` names it in messages. Read into a wiped buffer
/// ([`crate::plain`]) and moved into the result.
pub(crate) fn read_secret_file(path: &Path, what: &str) -> anyhow::Result<SecretBytes> {
    let mut bytes = crate::plain::read_file(path)
        .with_context(|| format!("cannot read {what} file {}", path.display()))?;
    while bytes.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Err(anyhow!("{what} file {} is empty", path.display()));
    }
    Ok(crate::plain::into_secret(bytes))
}

/// An authenticator code from `--code` or `SOURCEORRERY_TOTP`: good for a
/// minute and once, but a credential while it lasts, so it is wiped when
/// dropped and never printed by `Debug`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Code(String);

impl Code {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for Code {
    type Err = std::convert::Infallible;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Ok(Self(text.to_owned()))
    }
}

impl std::fmt::Debug for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Code([REDACTED])")
    }
}

/// Supplies the recovery key: environment variable, then file, then an
/// interactive prompt (when stdin is a terminal). The vault tries it
/// however it is typed (case, hyphens, spaces and look-alikes do not
/// matter).
#[derive(Debug)]
pub struct Unlocker {
    file: Option<PathBuf>,
    interactive: bool,
    /// The first attempt came from the environment or a file.
    automated: std::cell::Cell<bool>,
}

impl UnlockProvider for Unlocker {
    fn recovery_key(&self, prompt: &RecoveryKeyPrompt<'_>) -> CoreResult<Option<SecretBytes>> {
        // Non-interactive sources are tried once only; a wrong key is wrong.
        if prompt.attempt == 1 {
            if let Some(key) = recovery_key_from_env() {
                self.automated.set(true);
                return Ok(Some(key));
            }
            if let Some(file) = &self.file {
                self.automated.set(true);
                return read_secret_file(file, "recovery-key")
                    .map(Some)
                    .map_err(|err| sourceorrery_core::SecretError::Io(err.to_string()));
            }
        }
        if !self.interactive {
            return Ok(None);
        }
        if prompt.attempt == 2 && self.automated.get() {
            // Say why the prompt appears at all: the key the environment
            // or the file supplied was rejected, and this is not it.
            eprintln!(
                "The recovery key from {} was not accepted; type it.",
                if recovery_key_from_env().is_some() {
                    RECOVERY_KEY_ENV
                } else {
                    "the recovery-key file"
                }
            );
        }
        let text = if prompt.attempt == 1 {
            format!(
                "This machine cannot open vault '{}' by itself. Recovery key: ",
                prompt.vault
            )
        } else {
            format!(
                "Recovery key for vault '{}' (attempt {} of {}): ",
                prompt.vault, prompt.attempt, prompt.max_attempts
            )
        };
        prompt::read_hidden(&text)
            .map(Some)
            .map_err(|err| sourceorrery_core::SecretError::Io(err.to_string()))
    }
}

/// A vault open for the operations of the contract, each routed to where
/// the vault keeps the secret. Commands that need what only the file has
/// use [`Opened::vault`] or [`Ctx::open_local`].
#[derive(Debug)]
pub struct Opened(Routed);

impl Opened {
    fn client(&self) -> &dyn SecretClient {
        &self.0
    }

    /// The vault file.
    pub fn vault(&self) -> &SqliteVault {
        self.0.vault()
    }

    /// [`SecretClient::set_secret`], with `storage` for a new secret (and
    /// refused for an existing one kept elsewhere).
    pub fn set_secret_in(
        &self,
        storage: &SecretStorage,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
    ) -> CoreResult<SecretProperties> {
        self.0.set_secret_in(storage, name, value, options)
    }
}

impl SecretClient for Opened {
    fn vault_name(&self) -> &str {
        self.client().vault_name()
    }
    fn capabilities(&self) -> &'static [Capability] {
        self.client().capabilities()
    }
    fn capabilities_of(&self, name: &str) -> CoreResult<&'static [Capability]> {
        self.client().capabilities_of(name)
    }
    fn set_secret(
        &self,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
    ) -> CoreResult<SecretProperties> {
        self.client().set_secret(name, value, options)
    }
    fn get_secret(&self, name: &str, version: Option<&str>) -> CoreResult<Secret> {
        self.client().get_secret(name, version)
    }
    fn get_secret_properties(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> CoreResult<SecretProperties> {
        self.client().get_secret_properties(name, version)
    }
    fn list_properties_of_secrets(&self) -> CoreResult<Vec<SecretProperties>> {
        self.client().list_properties_of_secrets()
    }
    fn list_properties_of_secrets_page(
        &self,
        options: ListOptions,
    ) -> CoreResult<Page<SecretProperties>> {
        self.client().list_properties_of_secrets_page(options)
    }
    fn list_properties_of_secret_versions(&self, name: &str) -> CoreResult<Vec<SecretProperties>> {
        self.client().list_properties_of_secret_versions(name)
    }
    fn update_secret_properties(
        &self,
        name: &str,
        version: Option<&str>,
        update: UpdateSecretProperties,
    ) -> CoreResult<SecretProperties> {
        self.client()
            .update_secret_properties(name, version, update)
    }
    fn delete_secret(&self, name: &str) -> CoreResult<DeletedSecret> {
        self.client().delete_secret(name)
    }
    fn get_deleted_secret(&self, name: &str) -> CoreResult<DeletedSecret> {
        self.client().get_deleted_secret(name)
    }
    fn list_deleted_secrets(&self) -> CoreResult<Vec<DeletedSecret>> {
        self.client().list_deleted_secrets()
    }
    fn list_deleted_secrets_page(&self, options: ListOptions) -> CoreResult<Page<DeletedSecret>> {
        self.client().list_deleted_secrets_page(options)
    }
    fn recover_deleted_secret(&self, name: &str) -> CoreResult<SecretProperties> {
        self.client().recover_deleted_secret(name)
    }
    fn purge_deleted_secret(&self, name: &str) -> CoreResult<()> {
        self.client().purge_deleted_secret(name)
    }
    fn audit_events(&self, query: AuditQuery) -> CoreResult<Vec<AuditEvent>> {
        self.client().audit_events(query)
    }
    fn resolve(&self, reference: &SecretReference) -> CoreResult<Secret> {
        self.client().resolve(reference)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sourceorrery_core::SecretError;
    use sourceorrery_storage::{
        Argon2Params, CreateVaultOptions, CredentialStore, MemoryStore, SqliteVault,
    };

    use super::*;

    const PASSWORD: &str = "Orbit-Lantern-Copper-Nine-42";

    /// A vault with a password that this machine (a memory store) opened,
    /// so the recovery key does not pass the check for it, and a context
    /// whose answers come from a password file: nothing here prompts.
    fn vault_and_ctx(dir: &tempfile::TempDir, password: &str) -> (SqliteVault, Ctx) {
        let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
        let created = SqliteVault::create(
            &dir.path().join("dev.sorvault"),
            "dev",
            CreateVaultOptions::default(),
            store.clone(),
        )
        .unwrap();
        assert!(created.this_machine);
        created
            .vault
            .set_password(&SecretBytes::from(PASSWORD), None, Argon2Params::TESTING)
            .unwrap();
        let file = dir.path().join("password.txt");
        std::fs::write(
            &file,
            format!(
                "{password}
"
            ),
        )
        .unwrap();
        let ctx = Ctx {
            registry: VaultRegistry::with_root(dir.path()).with_store(store),
            output: OutputFormat::Table,
            vault_flag: Some("dev".to_owned()),
            recovery_key_file: None,
            password_file: Some(file),
            verbose: 0,
            code: None,
        };
        (created.vault, ctx)
    }

    fn denied(err: &anyhow::Error) -> bool {
        err.downcast_ref::<SecretError>()
            .is_some_and(|err| err.code() == "permission_denied")
    }

    #[test]
    fn the_password_file_answers_the_view_check() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, ctx) = vault_and_ctx(&dir, PASSWORD);
        assert!(!vault.opened_with_recovery_key());
        ctx.check_view(&vault).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let (vault, ctx) = vault_and_ctx(&dir, "not the password");
        let err = ctx.check_view(&vault).unwrap_err();
        assert!(denied(&err), "{err:#}");
        assert!(!format!("{err:#}").contains(PASSWORD));
    }

    #[test]
    fn the_code_is_asked_for_on_top_of_the_password() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut ctx) = vault_and_ctx(&dir, PASSWORD);
        let now = timestamp::now();
        let unix = u64::try_from(now.unix_timestamp()).unwrap();
        let secret = vault.enrol_authenticator().unwrap();
        assert!(
            vault
                .verify_authenticator(&secret.code_at(unix), now)
                .unwrap()
        );

        // A wrong code is refused with the right password.
        ctx.code = Some("000000".parse().unwrap());
        let err = ctx.check_view(&vault).unwrap_err();
        assert!(denied(&err), "{err:#}");
        // The next step's code passes, once.
        ctx.code = Some(secret.code_at(unix + 30).parse().unwrap());
        let later = SqliteVault::check_view(
            &vault,
            &ctx.view_answers(&vault).unwrap(),
            now + time::Duration::seconds(30),
        );
        later.unwrap();
        let err = ctx.check_view(&vault).unwrap_err();
        assert!(denied(&err), "a code is good once: {err:#}");
    }
}
