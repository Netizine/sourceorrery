//! What the setup wizard does to the world, behind one trait, so the
//! screens can be driven in tests (and drawn for the design snapshots) with
//! a fake that touches no vault.
//!
//! Nothing here returns a value, a password or a credential. A password,
//! an authenticator secret, a recovery key or a credential typed on the
//! screens arrives inside a [`Plan`] and goes to the vault at commit; what
//! comes back is what the screens may show: names, paths, what the view
//! check asks for, connections without their credentials, outcomes.

use sourceorrery_core::{
    ConnectionSettings, Credentials, ListOptions, Provider, SecretBytes, SecretClient, timestamp,
};
use sourceorrery_storage::{
    ConnectionInfo, CreateVaultOptions, NoInteraction, SettingsChange, SqliteVault,
    StaticRecoveryKey, ViewAnswers, ViewCheck,
};

use crate::context::Ctx;

/// An existing vault the wizard opened to change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    pub name: String,
    pub path: String,
    /// What its view check asks for.
    pub view: ViewCheck,
    /// The check is passed already: the vault was opened with its recovery
    /// key, which passes it by itself.
    pub passed: bool,
    /// The password hint, shown with the password field.
    pub hint: Option<String>,
    pub connections: Vec<ConnectionInfo>,
}

/// What opening a vault came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenOutcome {
    Opened(Opened),
    /// This machine cannot open it by itself: its recovery key is needed.
    NeedsRecoveryKey,
}

/// The credentials a connection test signs in with.
#[derive(Clone, Debug)]
pub enum TestCredentials {
    /// The provider's own chain on this machine.
    Ambient,
    /// Typed on the screen.
    Given(Credentials),
    /// The ones the existing connection `id` stores.
    Kept(String),
}

/// What the review commits: a new vault, or changes to the open one.
#[derive(Debug)]
pub struct Plan {
    pub name: String,
    pub create: bool,
    pub change: SettingsChange,
}

/// What a commit left, for the last screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Committed {
    pub name: String,
    pub path: String,
    pub view: ViewCheck,
    /// This machine opens the vault without asking.
    pub this_machine: bool,
    pub connections: Vec<ConnectionInfo>,
}

/// The world as the setup wizard sees it.
pub trait Backend {
    /// The vaults in the home directory, by name.
    fn vaults(&self) -> Result<Vec<String>, String>;
    /// The credential store that lets this machine open a vault without
    /// asking, when it is available here.
    fn store(&self) -> Option<String>;
    /// The providers this build of SourceOrrery includes.
    fn providers(&self) -> Vec<Provider>;
    /// Open the vault `name`: with this machine's key, else with
    /// `recovery_key` when given.
    fn open(
        &mut self,
        name: &str,
        recovery_key: Option<SecretBytes>,
    ) -> Result<OpenOutcome, String>;
    /// Weigh the open vault's view check.
    fn check_view(&mut self, password: SecretBytes, code: Option<String>) -> Result<(), String>;
    /// One metadata call to the provider `settings` reach.
    fn test_connection(
        &mut self,
        settings: &ConnectionSettings,
        credentials: &TestCredentials,
    ) -> Result<(), String>;
    /// Create the vault, or change the open one, as `plan` says, in one
    /// transaction (a new vault that cannot take its settings is removed
    /// again).
    fn commit(&mut self, plan: Plan) -> Result<Committed, String>;
}

/// The backend over this machine's vaults, through the storage calls the
/// commands make.
pub struct Live<'a> {
    ctx: &'a Ctx,
    vault: Option<SqliteVault>,
}

impl<'a> Live<'a> {
    pub fn new(ctx: &'a Ctx) -> Self {
        Self { ctx, vault: None }
    }

    fn committed(vault: &SqliteVault) -> Result<Committed, String> {
        let text = |err: sourceorrery_core::SecretError| err.to_string();
        let descriptor = vault.descriptor().map_err(text)?;
        Ok(Committed {
            name: descriptor.name,
            path: descriptor
                .path
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            view: vault.view_check().map_err(text)?,
            this_machine: vault
                .wraps()
                .map_err(text)?
                .iter()
                .any(|wrap| wrap.kind == "this-machine"),
            connections: vault.connections().map_err(text)?,
        })
    }
}

impl Backend for Live<'_> {
    fn vaults(&self) -> Result<Vec<String>, String> {
        self.ctx.registry.list().map_err(|err| err.to_string())
    }

    fn store(&self) -> Option<String> {
        let store = self.ctx.registry.store();
        store.available().then(|| store.name().to_owned())
    }

    fn providers(&self) -> Vec<Provider> {
        Provider::ALL
            .into_iter()
            .filter(|provider| match provider {
                Provider::HashicorpVault => {
                    cfg!(any(feature = "remote", feature = "provider-vault"))
                }
                Provider::AwsSecretsManager => {
                    cfg!(any(feature = "remote", feature = "provider-aws"))
                }
                Provider::AzureKeyVault => {
                    cfg!(any(feature = "remote", feature = "provider-azure"))
                }
            })
            .collect()
    }

    fn open(
        &mut self,
        name: &str,
        recovery_key: Option<SecretBytes>,
    ) -> Result<OpenOutcome, String> {
        let opened = match &recovery_key {
            Some(key) => {
                let typed = key.expose_utf8().unwrap_or_default();
                self.ctx.registry.open(name, &StaticRecoveryKey::new(typed))
            }
            None => self.ctx.registry.open(name, &NoInteraction),
        };
        let vault = match opened {
            Ok(vault) => vault,
            // Without its key, or with a key that is not its own.
            Err(err) if err.code() == "locked" => {
                return Ok(OpenOutcome::NeedsRecoveryKey);
            }
            Err(err) => return Err(err.to_string()),
        };
        let text = |err: sourceorrery_core::SecretError| err.to_string();
        let opened = Opened {
            name: vault.vault_name().to_owned(),
            path: vault
                .descriptor()
                .map_err(text)?
                .path
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            view: vault.view_check().map_err(text)?,
            passed: vault.opened_with_recovery_key(),
            hint: vault.password_hint().map_err(text)?,
            connections: vault.connections().map_err(text)?,
        };
        self.vault = Some(vault);
        Ok(OpenOutcome::Opened(opened))
    }

    fn check_view(&mut self, password: SecretBytes, code: Option<String>) -> Result<(), String> {
        let vault = self.vault.as_ref().ok_or("no vault is open")?;
        vault
            .check_view(
                &ViewAnswers {
                    password: Some(password),
                    code,
                    recovery_key: None,
                },
                timestamp::now(),
            )
            .map_err(|err| err.to_string())
    }

    fn test_connection(
        &mut self,
        settings: &ConnectionSettings,
        credentials: &TestCredentials,
    ) -> Result<(), String> {
        let kept;
        let credentials = match credentials {
            TestCredentials::Ambient => None,
            TestCredentials::Given(given) => Some(given),
            TestCredentials::Kept(id) => {
                let vault = self.vault.as_ref().ok_or("no vault is open")?;
                kept = vault
                    .connection_credentials(id)
                    .map_err(|err| err.to_string())?;
                kept.as_ref()
            }
        };
        let remote = sourceorrery_provider::open_connection("setup", settings, credentials)
            .map_err(|err| err.to_string())?;
        remote
            .client
            .list_properties_of_secrets_page(ListOptions::first(1))
            .map(drop)
            .map_err(|err| err.to_string())
    }

    fn commit(&mut self, plan: Plan) -> Result<Committed, String> {
        if !plan.create {
            let vault = self.vault.as_ref().ok_or("no vault is open")?;
            vault
                .change_settings(&plan.change)
                .map_err(|err| err.to_string())?;
            return Self::committed(vault);
        }
        let mut change = plan.change;
        let key = change
            .recovery_key
            .take()
            .ok_or("a new vault needs the recovery key its owner was shown")?;
        let created = self
            .ctx
            .registry
            .create_with_recovery_key(
                &plan.name,
                CreateVaultOptions {
                    this_machine: true,
                    ..CreateVaultOptions::default()
                },
                key,
            )
            .map_err(|err| err.to_string())?;
        if !change.is_empty()
            && let Err(err) = created.vault.change_settings(&change)
        {
            // No half-made vault is left behind.
            drop(created);
            let _ = self.ctx.registry.destroy(&plan.name, false);
            return Err(format!("the vault was not created: {err}"));
        }
        let committed = Self::committed(&created.vault)?;
        self.vault = Some(created.vault);
        Ok(committed)
    }
}
