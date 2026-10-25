//! The setup wizard's state (ADR 0009, section 7): which vault, its name,
//! its view check (a password, and an authenticator code on top), its
//! recovery key, where its secrets may be kept and how each provider is
//! reached, and a review that commits it all in one transaction.
//!
//! Nothing is written before the review. A password, an authenticator
//! secret, a recovery key and a credential live here in memory until then:
//! the password and the credentials typed in [`Zeroizing`] buffers the
//! screens draw as dots from their length; the authenticator secret, the
//! recovery key and a generated password are shown once, by design, behind
//! a "written down" tick or a code that proves the app has the secret.

use sourceorrery_core::{ConnectionSettings, Credentials, Provider, SecretBytes, timestamp};
use sourceorrery_crypto::{Argon2Params, TotpSecret, random};
use sourceorrery_storage::{
    AuthenticatorChange, ConnectionChange, ConnectionInfo, CredentialSource, PasswordChange,
    RecoveryKey, SettingsChange, ViewCheck,
};
use zeroize::Zeroizing;

use super::backend::{Backend, Committed, OpenOutcome, Opened, Plan, TestCredentials};
use crate::strength::{self, Estimate};

/// Characters in a generated password (about 125 bits).
pub const GENERATED_PASSWORD_LEN: usize = 20;
/// Codes tried before a new authenticator key is made.
const CODE_ATTEMPTS: u32 = 3;
/// Longest text accepted in a field.
const MAX_TYPED: usize = 256;
/// The providers, in the order the storage screen lists them.
pub const PROVIDERS: [Provider; 3] = Provider::ALL;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Start,
    Unlock,
    Name,
    ViewCheck,
    Password,
    Authenticator,
    RecoveryKey,
    Storage,
    Connections,
    Review,
    Done,
}

impl Step {
    /// The steps the rail shows, in order.
    pub const RAIL: [Step; 6] = [
        Step::Start,
        Step::Name,
        Step::ViewCheck,
        Step::RecoveryKey,
        Step::Storage,
        Step::Review,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Step::Start | Step::Unlock => "Vault",
            Step::Name => "Name",
            Step::ViewCheck | Step::Password | Step::Authenticator => "View check",
            Step::RecoveryKey => "Recovery key",
            Step::Storage | Step::Connections => "Storage",
            Step::Review => "Review",
            Step::Done => "Done",
        }
    }

    /// The rail step this one belongs to.
    pub fn rail_step(self) -> Step {
        match self {
            Step::Unlock => Step::Start,
            Step::Password | Step::Authenticator => Step::ViewCheck,
            Step::Connections => Step::Storage,
            step => step,
        }
    }

    fn rail_index(self) -> usize {
        Step::RAIL
            .iter()
            .position(|s| *s == self.rail_step())
            .unwrap_or(Step::RAIL.len())
    }

    /// `other` comes before this step.
    pub fn is_past(self, other: Step) -> bool {
        other.rail_index() < self.rail_index()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Scroll(crate::ui::app::Action),
    Input(char),
    Erase,
    Next,
    Prev,
    Enter,
    /// Dismiss the message, else go back a screen (leave on the first).
    Back,
    Quit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Info(String),
    Error(String),
}

/// A field of a connection form; what each holds depends on the provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    /// The address, the region or the vault URL.
    Location,
    /// The mount, or the prefix.
    Second,
    /// The namespace, or the endpoint URL.
    Third,
    /// This machine's sign-in, or credentials stored in the vault.
    Source,
    /// The access key id, or the tenant id.
    FirstId,
    /// The client id.
    SecondId,
    /// The token, the secret access key or the client secret.
    Secret,
    Test,
}

/// A control on a screen, in focus order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    Vault(usize),
    CreateNew,
    Leave,
    UnlockKey,
    UnlockPassword,
    UnlockCode,
    OpenVault,
    Name,
    Continue,
    AskPassword,
    AskCode,
    KeepPassword,
    Password,
    Confirm,
    Generate,
    Written,
    Hint,
    KeepAuthenticator,
    Code,
    Verify,
    NewRecoveryKey,
    RecoveryWritten,
    /// A provider on the storage screen, by index into [`PROVIDERS`].
    Provider(usize),
    /// A field of the connection form at this index.
    Form(usize, Field),
    Commit,
    Exit,
}

impl Control {
    /// Takes typed text.
    pub fn is_text(self) -> bool {
        matches!(
            self,
            Control::UnlockKey
                | Control::UnlockPassword
                | Control::UnlockCode
                | Control::Name
                | Control::Password
                | Control::Confirm
                | Control::Hint
                | Control::Code
        ) || matches!(
            self,
            Control::Form(
                _,
                Field::Location
                    | Field::Second
                    | Field::Third
                    | Field::FirstId
                    | Field::SecondId
                    | Field::Secret
            )
        )
    }

    /// Typed text is shown as dots.
    pub fn is_hidden(self) -> bool {
        matches!(
            self,
            Control::UnlockKey
                | Control::UnlockPassword
                | Control::Password
                | Control::Confirm
                | Control::Form(_, Field::Secret)
        )
    }

    pub fn is_toggle(self) -> bool {
        matches!(
            self,
            Control::AskPassword
                | Control::AskCode
                | Control::KeepPassword
                | Control::Written
                | Control::KeepAuthenticator
                | Control::NewRecoveryKey
                | Control::RecoveryWritten
                | Control::Provider(_)
                | Control::Form(_, Field::Source)
        )
    }
}

/// How one provider is reached: a form on the connections screen.
pub struct Form {
    pub provider: Provider,
    /// The vault's connection to it, when it has one.
    pub existing: Option<ConnectionInfo>,
    pub location: String,
    pub second: String,
    pub third: String,
    /// Credentials stored in the vault, else this machine's sign-in.
    pub stored: bool,
    pub first_id: String,
    pub second_id: String,
    secret: Zeroizing<String>,
    /// The last test: passed, or the provider's reason.
    pub tested: Option<Result<(), String>>,
}

impl Form {
    fn new(provider: Provider) -> Self {
        Self {
            provider,
            existing: None,
            location: String::new(),
            second: if provider == Provider::HashicorpVault {
                "secret".to_owned()
            } else {
                String::new()
            },
            third: String::new(),
            stored: false,
            first_id: String::new(),
            second_id: String::new(),
            secret: Zeroizing::default(),
            tested: None,
        }
    }

    fn from_existing(info: &ConnectionInfo) -> Self {
        let mut form = Self::new(info.settings.provider());
        match &info.settings {
            ConnectionSettings::HashicorpVault {
                address,
                mount,
                namespace,
            } => {
                address.clone_into(&mut form.location);
                mount.clone_into(&mut form.second);
                form.third = namespace.clone().unwrap_or_default();
            }
            ConnectionSettings::AwsSecretsManager {
                region,
                prefix,
                endpoint_url,
            } => {
                region.clone_into(&mut form.location);
                form.second = prefix.clone().unwrap_or_default();
                form.third = endpoint_url.clone().unwrap_or_default();
            }
            ConnectionSettings::AzureKeyVault { vault_url } => {
                vault_url.clone_into(&mut form.location);
            }
        }
        form.stored = info.credentials == CredentialSource::Stored;
        form.existing = Some(info.clone());
        form
    }

    /// The fields this form shows, in focus order.
    pub fn fields(&self) -> Vec<Field> {
        let mut fields = vec![Field::Location];
        if self.provider != Provider::AzureKeyVault {
            fields.extend([Field::Second, Field::Third]);
        }
        fields.push(Field::Source);
        if self.stored {
            match self.provider {
                Provider::HashicorpVault => {}
                Provider::AwsSecretsManager => fields.push(Field::FirstId),
                Provider::AzureKeyVault => fields.extend([Field::FirstId, Field::SecondId]),
            }
            fields.push(Field::Secret);
        }
        fields.push(Field::Test);
        fields
    }

    /// The label of `field` for this provider.
    pub fn label(&self, field: Field) -> &'static str {
        match (self.provider, field) {
            (Provider::HashicorpVault, Field::Location) => "Address",
            (Provider::HashicorpVault, Field::Second) => "Mount",
            (Provider::HashicorpVault, Field::Third) => "Namespace",
            (Provider::HashicorpVault, Field::Secret) => "Token",
            (Provider::AwsSecretsManager, Field::Location) => "Region",
            (Provider::AwsSecretsManager, Field::Second) => "Prefix",
            (Provider::AwsSecretsManager, Field::Third) => "Endpoint URL",
            (Provider::AwsSecretsManager, Field::FirstId) => "Access key id",
            (Provider::AwsSecretsManager, Field::Secret) => "Secret access key",
            (Provider::AzureKeyVault, Field::Location) => "Vault URL",
            (Provider::AzureKeyVault, Field::FirstId) => "Tenant id",
            (Provider::AzureKeyVault, Field::SecondId) => "Client id",
            (Provider::AzureKeyVault, Field::Secret) => "Client secret",
            (_, Field::Source) => "Credentials",
            _ => "",
        }
    }

    /// The text of a field that is not hidden.
    pub fn text(&self, field: Field) -> &str {
        match field {
            Field::Location => &self.location,
            Field::Second => &self.second,
            Field::Third => &self.third,
            Field::FirstId => &self.first_id,
            Field::SecondId => &self.second_id,
            _ => "",
        }
    }

    fn text_mut(&mut self, field: Field) -> Option<&mut String> {
        Some(match field {
            Field::Location => &mut self.location,
            Field::Second => &mut self.second,
            Field::Third => &mut self.third,
            Field::FirstId => &mut self.first_id,
            Field::SecondId => &mut self.second_id,
            _ => return None,
        })
    }

    pub fn secret_len(&self) -> usize {
        self.secret.chars().count()
    }

    /// The stored credentials keep as they are: the connection stores some
    /// and none were typed.
    pub fn keeps_credentials(&self) -> bool {
        self.stored
            && self.secret.is_empty()
            && self
                .existing
                .as_ref()
                .is_some_and(|e| e.credentials == CredentialSource::Stored)
    }

    pub fn settings(&self) -> ConnectionSettings {
        let optional = |text: &str| {
            let text = text.trim();
            (!text.is_empty()).then(|| text.to_owned())
        };
        match self.provider {
            Provider::HashicorpVault => ConnectionSettings::HashicorpVault {
                address: self.location.trim().to_owned(),
                mount: self.second.trim().to_owned(),
                namespace: optional(&self.third),
            },
            Provider::AwsSecretsManager => ConnectionSettings::AwsSecretsManager {
                region: self.location.trim().to_owned(),
                prefix: optional(&self.second),
                endpoint_url: optional(&self.third),
            },
            Provider::AzureKeyVault => ConnectionSettings::AzureKeyVault {
                vault_url: self.location.trim().to_owned(),
            },
        }
    }

    /// The credentials typed, checked; `None` for this machine's sign-in
    /// or for the stored ones kept.
    fn credentials(&self) -> Result<Option<Credentials>, String> {
        if !self.stored || self.keeps_credentials() {
            return Ok(None);
        }
        let secret = || SecretBytes::from_string(self.secret.to_string());
        let credentials = match self.provider {
            Provider::HashicorpVault => Credentials::VaultToken(secret()),
            Provider::AwsSecretsManager => Credentials::AwsAccessKey {
                access_key_id: self.first_id.trim().to_owned(),
                secret_access_key: secret(),
            },
            Provider::AzureKeyVault => Credentials::AzureClientSecret {
                tenant_id: self.first_id.trim().to_owned(),
                client_id: self.second_id.trim().to_owned(),
                client_secret: secret(),
            },
        };
        credentials
            .validate()
            .and_then(|()| credentials.check_for(&self.settings()))
            .map_err(|err| format!("the {} credentials: {err}", self.provider.display_name()))?;
        Ok(Some(credentials))
    }

    fn test_credentials(&self) -> Result<TestCredentials, String> {
        if self.keeps_credentials()
            && let Some(existing) = &self.existing
        {
            return Ok(TestCredentials::Kept(existing.id.clone()));
        }
        Ok(match self.credentials()? {
            Some(credentials) => TestCredentials::Given(credentials),
            None => TestCredentials::Ambient,
        })
    }

    /// The settings and credentials, checked as the vault will check them.
    fn check(&self) -> Result<(), String> {
        self.settings()
            .validate()
            .map_err(|err| format!("the {} connection: {err}", self.provider.display_name()))?;
        self.credentials().map(drop)
    }
}

pub struct Wizard<B> {
    backend: B,
    pub step: Step,
    pub viewport: std::cell::RefCell<crate::ui::viewport::Viewport>,
    focus: usize,
    pub message: Option<Message>,
    quit: bool,
    /// The hash cost of a new password (lowered in tests).
    pub params: Argon2Params,

    pub vaults: Vec<String>,
    /// The credential store this machine can keep a vault's key in.
    pub store: Option<String>,
    /// The providers this build includes.
    pub available: Vec<Provider>,

    // Opening a vault to change it.
    pub chosen: Option<String>,
    pub needs_key: bool,
    unlock_key: Zeroizing<String>,
    unlock_password: Zeroizing<String>,
    pub unlock_code: String,
    pending: Option<Opened>,
    /// The vault being changed; `None` while creating one.
    pub editing: Option<Opened>,

    pub name: String,

    // The view check.
    pub ask_password: bool,
    pub ask_code: bool,
    pub keep_password: bool,
    password: Zeroizing<String>,
    confirm: Zeroizing<String>,
    pub estimate: Option<Estimate>,
    /// Shown once, until the review commits it.
    pub generated: Option<Zeroizing<String>>,
    pub generated_written: bool,
    pub hint: String,
    pub keep_authenticator: bool,
    enrolment: Option<TotpSecret>,
    pub code: String,
    /// The step of the code that verified the enrolment.
    verified: Option<u64>,
    attempts: u32,

    // The recovery key.
    pub new_recovery: bool,
    /// Shown once, until the review commits it.
    pub recovery: Option<RecoveryKey>,
    pub recovery_written: bool,

    // Storage.
    pub ticked: [bool; 3],
    pub forms: Vec<Form>,

    pub committed: Option<Committed>,
}

impl<B: Backend> Wizard<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            viewport: Default::default(),
            step: Step::Start,
            focus: 0,
            message: None,
            quit: false,
            params: Argon2Params::default(),
            vaults: Vec::new(),
            store: None,
            available: Vec::new(),
            chosen: None,
            needs_key: false,
            unlock_key: Zeroizing::default(),
            unlock_password: Zeroizing::default(),
            unlock_code: String::new(),
            pending: None,
            editing: None,
            name: String::new(),
            ask_password: false,
            ask_code: false,
            keep_password: false,
            password: Zeroizing::default(),
            confirm: Zeroizing::default(),
            estimate: None,
            generated: None,
            generated_written: false,
            hint: String::new(),
            keep_authenticator: false,
            enrolment: None,
            code: String::new(),
            verified: None,
            attempts: 0,
            new_recovery: false,
            recovery: None,
            recovery_written: false,
            ticked: [false; 3],
            forms: Vec::new(),
            committed: None,
        }
    }

    /// The first screen: the vault `name` names (to change it when it
    /// exists, else to create it), or the start screen.
    pub fn begin(&mut self, name: Option<&str>) -> Result<(), String> {
        self.vaults = self.backend.vaults()?;
        self.store = self.backend.store();
        self.available = self.backend.providers();
        match name {
            Some(name) => {
                if let Some(existing) = self.existing_name(name) {
                    self.choose(&existing);
                } else {
                    self.create_new(name);
                }
            }
            None => self.go(Step::Start),
        }
        Ok(())
    }

    pub fn should_quit(&self) -> bool {
        self.quit
    }

    /// The backend, for what the tests recorded in it.
    #[cfg(test)]
    pub fn backend(&self) -> &B {
        &self.backend
    }

    #[cfg(test)]
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// The vault named `name`, ignoring case, in its own spelling.
    fn existing_name(&self, name: &str) -> Option<String> {
        self.vaults
            .iter()
            .find(|vault| vault.eq_ignore_ascii_case(name))
            .cloned()
    }

    pub fn creating(&self) -> bool {
        self.editing.is_none()
    }

    /// What the vault being changed had before.
    pub fn had(&self) -> ViewCheck {
        self.editing.as_ref().map(|e| e.view).unwrap_or_default()
    }

    /// The controls of the current screen, in focus order.
    pub fn controls(&self) -> Vec<Control> {
        match self.step {
            Step::Start => (0..self.vaults.len())
                .map(Control::Vault)
                .chain([Control::CreateNew, Control::Leave])
                .collect(),
            Step::Unlock if self.needs_key => vec![Control::UnlockKey, Control::OpenVault],
            Step::Unlock => {
                let mut c = vec![Control::UnlockPassword];
                if self.pending.as_ref().is_some_and(|p| p.view.authenticator) {
                    c.push(Control::UnlockCode);
                }
                c.push(Control::OpenVault);
                c
            }
            Step::Name => vec![Control::Name, Control::Continue],
            Step::ViewCheck => {
                let mut c = vec![Control::AskPassword];
                if self.ask_password {
                    c.push(Control::AskCode);
                }
                c.push(Control::Continue);
                c
            }
            Step::Password => {
                let mut c = Vec::new();
                if self.had().password {
                    c.push(Control::KeepPassword);
                }
                if !(self.keep_password && self.had().password) {
                    if self.generated.is_some() {
                        c.extend([Control::Generate, Control::Written]);
                    } else {
                        c.extend([Control::Password, Control::Confirm, Control::Generate]);
                    }
                    c.push(Control::Hint);
                }
                c.push(Control::Continue);
                c
            }
            Step::Authenticator => {
                let mut c = Vec::new();
                if self.had().authenticator {
                    c.push(Control::KeepAuthenticator);
                }
                if !self.keeps_authenticator() && self.verified.is_none() {
                    c.extend([Control::Code, Control::Verify]);
                }
                c.push(Control::Continue);
                c
            }
            Step::RecoveryKey => {
                let mut c = Vec::new();
                if !self.creating() {
                    c.push(Control::NewRecoveryKey);
                }
                if self.recovery.is_some() {
                    c.push(Control::RecoveryWritten);
                }
                c.push(Control::Continue);
                c
            }
            Step::Storage => (0..PROVIDERS.len())
                .filter(|&i| self.available.contains(&PROVIDERS[i]))
                .map(Control::Provider)
                .chain([Control::Continue])
                .collect(),
            Step::Connections => {
                let mut c = Vec::new();
                for (i, form) in self.forms.iter().enumerate() {
                    if self.is_ticked(form.provider) {
                        c.extend(form.fields().into_iter().map(|f| Control::Form(i, f)));
                    }
                }
                c.push(Control::Continue);
                c
            }
            Step::Review => vec![Control::Commit],
            Step::Done => vec![Control::Exit],
        }
    }

    pub fn focused(&self) -> Control {
        let controls = self.controls();
        controls[self.focus.min(controls.len() - 1)]
    }

    /// Characters typed into a hidden field.
    pub fn hidden_len(&self, control: Control) -> usize {
        match control {
            Control::UnlockKey => self.unlock_key.chars().count(),
            Control::UnlockPassword => self.unlock_password.chars().count(),
            Control::Password => self.password.chars().count(),
            Control::Confirm => self.confirm.chars().count(),
            Control::Form(i, Field::Secret) => self.forms.get(i).map_or(0, Form::secret_len),
            _ => 0,
        }
    }

    /// The confirmation matches the password, or is still empty.
    pub fn confirm_state(&self) -> Option<bool> {
        (!self.confirm.is_empty()).then(|| self.password.as_str() == self.confirm.as_str())
    }

    /// What is wrong with the name typed, as it is typed.
    pub fn name_problem(&self) -> Option<String> {
        if self.name.is_empty() {
            return None;
        }
        if let Err(err) = sourceorrery_core::validate_vault_name(&self.name) {
            return Some(err.to_string());
        }
        self.existing_name(&self.name).map(|existing| {
            format!("vault '{existing}' exists: pick it on the first screen to change it")
        })
    }

    pub fn is_ticked(&self, provider: Provider) -> bool {
        PROVIDERS
            .iter()
            .position(|p| *p == provider)
            .is_some_and(|i| self.ticked[i])
    }

    /// The authenticator key and its URI, while one is being enrolled.
    pub fn enrolment(&self) -> Option<(Zeroizing<String>, Zeroizing<String>)> {
        let secret = self.enrolment.as_ref()?;
        Some((
            secret.to_base32(),
            secret.otpauth_uri("SourceOrrery", &self.name),
        ))
    }

    /// The hint of the vault whose view check is being asked.
    pub fn pending_hint(&self) -> Option<&str> {
        self.pending.as_ref()?.hint.as_deref()
    }

    /// The authenticator's code has been checked against the new key.
    pub fn verified(&self) -> bool {
        self.verified.is_some()
    }

    /// The enrolled authenticator stays.
    pub fn keeps_authenticator(&self) -> bool {
        self.keep_authenticator && self.had().authenticator
    }

    pub fn update(&mut self, action: Action) {
        match action {
            Action::Scroll(action) => self.viewport.borrow_mut().move_by(action),
            Action::Quit => self.quit = true,
            Action::Back => {
                if self.message.take().is_none() {
                    self.back();
                }
            }
            Action::Next => self.focus = (self.focus + 1) % self.controls().len(),
            Action::Prev => {
                let n = self.controls().len();
                self.focus = (self.focus + n - 1) % n;
            }
            Action::Erase => self.erase(),
            Action::Input(c) => self.input(c),
            Action::Enter => self.activate(self.focused()),
        }
    }

    fn go(&mut self, step: Step) {
        *self.viewport.borrow_mut() = Default::default();
        self.step = step;
        self.focus = 0;
        // A message is about the screen it was given on.
        self.message = None;
        match step {
            Step::Authenticator if !self.keeps_authenticator() && self.enrolment.is_none() => {
                self.new_enrolment();
            }
            Step::RecoveryKey if self.creating() && self.recovery.is_none() => {
                self.new_recovery_key();
            }
            Step::Connections => {
                for provider in PROVIDERS {
                    if self.is_ticked(provider)
                        && !self.forms.iter().any(|f| f.provider == provider)
                    {
                        self.forms.push(Form::new(provider));
                    }
                }
            }
            _ => {}
        }
    }

    fn fail(&mut self, text: impl Into<String>) {
        self.message = Some(Message::Error(text.into()));
    }

    fn back(&mut self) {
        match self.step {
            Step::Start | Step::Done => self.quit = true,
            Step::ViewCheck if self.creating() => self.go(Step::Name),
            Step::Unlock | Step::Name | Step::ViewCheck => self.restart(),
            Step::Authenticator => self.go(Step::Password),
            Step::RecoveryKey if self.ask_code => self.go(Step::Authenticator),
            Step::RecoveryKey if self.ask_password => self.go(Step::Password),
            Step::Password | Step::RecoveryKey => self.go(Step::ViewCheck),
            Step::Storage => self.go(Step::RecoveryKey),
            Step::Review if self.ticked.iter().any(|t| *t) => self.go(Step::Connections),
            Step::Connections | Step::Review => self.go(Step::Storage),
        }
    }

    /// Back to the start, forgetting the vault opened and what was typed.
    fn restart(&mut self) {
        self.chosen = None;
        self.needs_key = false;
        self.unlock_key = Zeroizing::default();
        self.unlock_password = Zeroizing::default();
        self.unlock_code.clear();
        self.pending = None;
        self.editing = None;
        self.name.clear();
        self.ask_password = false;
        self.ask_code = false;
        self.keep_password = false;
        self.password = Zeroizing::default();
        self.confirm = Zeroizing::default();
        self.estimate = None;
        self.generated = None;
        self.generated_written = false;
        self.hint.clear();
        self.keep_authenticator = false;
        self.enrolment = None;
        self.code.clear();
        self.verified = None;
        self.attempts = 0;
        self.new_recovery = false;
        self.recovery = None;
        self.recovery_written = false;
        self.ticked = [false; 3];
        self.forms.clear();
        self.go(Step::Start);
    }

    fn input(&mut self, c: char) {
        let control = self.focused();
        if control.is_text() {
            if c.is_control() {
                return;
            }
            self.message = None;
            self.type_into(control, c);
            return;
        }
        match c {
            ' ' if control.is_toggle() => self.toggle(control),
            'q' if matches!(self.step, Step::Start | Step::Done) => self.quit = true,
            _ => {}
        }
    }

    fn type_into(&mut self, control: Control, c: char) {
        let room = |text: &str| text.chars().count() < MAX_TYPED;
        match control {
            Control::UnlockKey if room(&self.unlock_key) => self.unlock_key.push(c),
            Control::UnlockPassword if room(&self.unlock_password) => self.unlock_password.push(c),
            Control::UnlockCode if c.is_ascii_digit() && self.unlock_code.len() < 6 => {
                self.unlock_code.push(c);
            }
            Control::Name if self.name.len() < 64 => self.name.push(c),
            Control::Password if room(&self.password) => {
                self.password.push(c);
                self.estimate = Some(strength::estimate(&self.password));
            }
            Control::Confirm if room(&self.confirm) => self.confirm.push(c),
            Control::Hint if self.hint.chars().count() < sourceorrery_storage::MAX_HINT_LEN => {
                self.hint.push(c);
            }
            Control::Code if c.is_ascii_digit() && self.code.len() < 6 => self.code.push(c),
            Control::Form(i, Field::Secret) => {
                if let Some(form) = self.forms.get_mut(i)
                    && room(&form.secret)
                {
                    form.secret.push(c);
                    form.tested = None;
                }
            }
            Control::Form(i, field) => {
                if let Some(form) = self.forms.get_mut(i) {
                    form.tested = None;
                    if let Some(text) = form.text_mut(field)
                        && room(text)
                    {
                        text.push(c);
                    }
                }
            }
            _ => {}
        }
    }

    fn erase(&mut self) {
        match self.focused() {
            Control::UnlockKey => {
                self.unlock_key.pop();
            }
            Control::UnlockPassword => {
                self.unlock_password.pop();
            }
            Control::UnlockCode => {
                self.unlock_code.pop();
            }
            Control::Name => {
                self.name.pop();
            }
            Control::Password => {
                self.password.pop();
                self.estimate =
                    (!self.password.is_empty()).then(|| strength::estimate(&self.password));
            }
            Control::Confirm => {
                self.confirm.pop();
            }
            Control::Hint => {
                self.hint.pop();
            }
            Control::Code => {
                self.code.pop();
            }
            Control::Form(i, field) => {
                if let Some(form) = self.forms.get_mut(i) {
                    form.tested = None;
                    if field == Field::Secret {
                        form.secret.pop();
                    } else if let Some(text) = form.text_mut(field) {
                        text.pop();
                    }
                }
            }
            _ => {}
        }
    }

    fn toggle(&mut self, control: Control) {
        match control {
            Control::AskPassword => {
                self.ask_password = !self.ask_password;
                if !self.ask_password {
                    self.ask_code = false;
                }
            }
            Control::AskCode => self.ask_code = !self.ask_code,
            Control::KeepPassword => self.keep_password = !self.keep_password,
            Control::Written => self.generated_written = !self.generated_written,
            Control::KeepAuthenticator => {
                self.keep_authenticator = !self.keep_authenticator;
                if !self.keep_authenticator && self.enrolment.is_none() {
                    self.new_enrolment();
                }
            }
            Control::NewRecoveryKey => {
                self.new_recovery = !self.new_recovery;
                if self.new_recovery {
                    self.new_recovery_key();
                } else {
                    self.recovery = None;
                    self.recovery_written = false;
                }
            }
            Control::RecoveryWritten => self.recovery_written = !self.recovery_written,
            Control::Provider(i) if self.available.contains(&PROVIDERS[i]) => {
                self.ticked[i] = !self.ticked[i];
            }
            Control::Form(i, Field::Source) => {
                if let Some(form) = self.forms.get_mut(i) {
                    form.stored = !form.stored;
                    form.tested = None;
                }
            }
            _ => {}
        }
    }

    fn activate(&mut self, control: Control) {
        if control.is_text() {
            // Enter in a field moves on, as Tab does.
            self.update(Action::Next);
            return;
        }
        if control.is_toggle() {
            self.toggle(control);
            return;
        }
        match control {
            Control::Vault(i) => {
                let name = self.vaults[i].clone();
                self.choose(&name);
            }
            Control::CreateNew => self.create_new(""),
            Control::Leave | Control::Exit => self.quit = true,
            Control::OpenVault => self.unlock(),
            Control::Continue => self.next(),
            Control::Generate => self.toggle_generated(),
            Control::Verify => self.verify_code(),
            Control::Form(i, Field::Test) => self.test(i),
            Control::Commit => self.commit(),
            _ => {}
        }
    }

    // --- choosing and opening a vault ---------------------------------

    fn create_new(&mut self, name: &str) {
        self.editing = None;
        self.pending = None;
        name.clone_into(&mut self.name);
        self.go(Step::Name);
    }

    fn choose(&mut self, name: &str) {
        self.chosen = Some(name.to_owned());
        match self.backend.open(name, None) {
            Ok(OpenOutcome::Opened(opened)) => self.opened(opened),
            Ok(OpenOutcome::NeedsRecoveryKey) => {
                self.needs_key = true;
                self.go(Step::Unlock);
            }
            Err(err) => self.fail(err),
        }
    }

    fn opened(&mut self, opened: Opened) {
        if opened.view.is_none() || opened.passed {
            self.start_editing(opened);
        } else {
            // Changing a vault passes its view check first: without it
            // anyone could switch the check off.
            self.needs_key = false;
            self.pending = Some(opened);
            self.go(Step::Unlock);
        }
    }

    fn unlock(&mut self) {
        let Some(name) = self.chosen.clone() else {
            return;
        };
        if self.needs_key {
            let key = SecretBytes::from_string(self.unlock_key.to_string());
            self.unlock_key = Zeroizing::default();
            match self.backend.open(&name, Some(key)) {
                Ok(OpenOutcome::Opened(opened)) => self.opened(opened),
                Ok(OpenOutcome::NeedsRecoveryKey) => {
                    self.fail("that recovery key does not open this vault");
                }
                Err(err) => self.fail(err),
            }
            return;
        }
        let password = SecretBytes::from_string(self.unlock_password.to_string());
        self.unlock_password = Zeroizing::default();
        let code = (!self.unlock_code.is_empty()).then(|| std::mem::take(&mut self.unlock_code));
        match self.backend.check_view(password, code) {
            Ok(()) => {
                if let Some(opened) = self.pending.take() {
                    self.start_editing(opened);
                }
            }
            Err(err) => self.fail(err),
        }
    }

    fn start_editing(&mut self, opened: Opened) {
        self.name.clone_from(&opened.name);
        self.ask_password = opened.view.password;
        self.ask_code = opened.view.authenticator;
        self.keep_password = opened.view.password;
        self.keep_authenticator = opened.view.authenticator;
        self.new_recovery = false;
        self.recovery = None;
        self.ticked = PROVIDERS.map(|provider| {
            opened
                .connections
                .iter()
                .any(|c| c.settings.provider() == provider)
        });
        self.forms = opened.connections.iter().map(Form::from_existing).collect();
        let note = format!(
            "Changing vault '{}': nothing is saved until the review.",
            opened.name
        );
        self.editing = Some(opened);
        self.go(Step::ViewCheck);
        self.message = Some(Message::Info(note));
    }

    // --- moving on --------------------------------------------------------

    fn next(&mut self) {
        match self.step {
            Step::Name => {
                if self.name.is_empty() {
                    return self.fail("type the vault's name");
                }
                if let Some(problem) = self.name_problem() {
                    return self.fail(problem);
                }
                self.go(Step::ViewCheck);
            }
            Step::ViewCheck => {
                if self.ask_password {
                    self.go(Step::Password);
                } else {
                    self.go(Step::RecoveryKey);
                }
            }
            Step::Password => {
                if let Err(err) = self.check_password() {
                    return self.fail(err);
                }
                if self.ask_code {
                    self.go(Step::Authenticator);
                } else {
                    self.go(Step::RecoveryKey);
                }
            }
            Step::Authenticator => {
                if !self.keeps_authenticator() && self.verified.is_none() {
                    return self.fail(
                        "type a code from the app and verify it: the vault then knows the app \
                         has the key",
                    );
                }
                self.go(Step::RecoveryKey);
            }
            Step::RecoveryKey => {
                if self.recovery.is_some() && !self.recovery_written {
                    return self.fail(
                        "write the recovery key down and tick the box: it is not shown again",
                    );
                }
                self.go(Step::Storage);
            }
            Step::Storage => {
                if self.ticked.iter().any(|t| *t) {
                    self.go(Step::Connections);
                } else {
                    self.go(Step::Review);
                }
            }
            Step::Connections => {
                let checked: Result<(), String> = self
                    .forms
                    .iter()
                    .filter(|form| self.is_ticked(form.provider))
                    .try_for_each(Form::check);
                if let Err(err) = checked {
                    return self.fail(err);
                }
                self.go(Step::Review);
            }
            _ => {}
        }
    }

    fn check_password(&self) -> Result<(), String> {
        if self.keep_password && self.had().password {
            return Ok(());
        }
        let typed = if let Some(generated) = &self.generated {
            if !self.generated_written {
                return Err(
                    "write the password down (or keep it in a password manager) and tick the box"
                        .to_owned(),
                );
            }
            generated.as_str()
        } else {
            match &self.estimate {
                None => return Err("type a password, or let the wizard generate one".to_owned()),
                Some(estimate) if !estimate.acceptable() => {
                    return Err(format!(
                        "the password rates {}; it needs {}. Make it longer, or let the wizard \
                         generate one",
                        estimate.score.label(),
                        strength::Score::REQUIRED.label()
                    ));
                }
                Some(_) => {}
            }
            if self.confirm_state() != Some(true) {
                return Err("the confirmation does not match the password".to_owned());
            }
            self.password.as_str()
        };
        let hint = self.hint.trim().to_lowercase();
        if !hint.is_empty() && hint.contains(&typed.to_lowercase()) {
            return Err("the hint must not give the password away".to_owned());
        }
        Ok(())
    }

    fn toggle_generated(&mut self) {
        if self.generated.take().is_some() {
            self.generated_written = false;
        } else {
            match random::random_passphrase(GENERATED_PASSWORD_LEN) {
                Ok(generated) => {
                    self.password = Zeroizing::default();
                    self.confirm = Zeroizing::default();
                    self.estimate = None;
                    self.generated = Some(generated);
                }
                Err(err) => self.fail(format!("cannot generate a password: {err}")),
            }
        }
        self.focus = 0;
    }

    fn new_enrolment(&mut self) {
        match TotpSecret::generate() {
            Ok(secret) => {
                self.enrolment = Some(secret);
                self.verified = None;
                self.code.clear();
                self.attempts = 0;
            }
            Err(err) => self.fail(format!("cannot make an authenticator key: {err}")),
        }
    }

    fn verify_code(&mut self) {
        if self.code.len() != 6 {
            return self.fail("type the six digits the app shows");
        }
        let Some(secret) = &self.enrolment else {
            return;
        };
        let now = u64::try_from(timestamp::now().unix_timestamp()).unwrap_or(0);
        if let Some(counter) = secret.verify(&self.code, now, None) {
            self.verified = Some(counter);
            self.code.clear();
            self.message = Some(Message::Info(
                "Code accepted: the app has the key. It is saved with the vault at the review."
                    .to_owned(),
            ));
            self.focus = 0;
            return;
        }
        self.attempts += 1;
        self.code.clear();
        if self.attempts >= CODE_ATTEMPTS {
            self.new_enrolment();
            self.fail(
                "no code matched, so a new key was made: check the phone's clock, remove the \
                 old entry from the app and scan this one",
            );
        } else {
            self.fail(format!(
                "that code did not match ({} of {CODE_ATTEMPTS}); wait for the next one and try \
                 again",
                self.attempts
            ));
        }
    }

    fn new_recovery_key(&mut self) {
        match RecoveryKey::generate() {
            Ok(key) => {
                self.recovery = Some(key);
                self.recovery_written = false;
            }
            Err(err) => self.fail(format!("cannot make a recovery key: {err}")),
        }
    }

    fn test(&mut self, i: usize) {
        let Some(form) = self.forms.get(i) else {
            return;
        };
        let credentials = match form.test_credentials() {
            Ok(credentials) => credentials,
            Err(err) => return self.fail(err),
        };
        let settings = form.settings();
        if let Err(err) = settings.validate() {
            return self.fail(format!(
                "the {} connection: {err}",
                form.provider.display_name()
            ));
        }
        let result = self.backend.test_connection(&settings, &credentials);
        if let Some(form) = self.forms.get_mut(i) {
            form.tested = Some(result);
        }
    }

    // --- the review ---------------------------------------------------

    /// What the review commits, built afresh from what is on the screens,
    /// so a commit that failed can be tried again.
    pub fn plan(&self) -> Result<Plan, String> {
        let had = self.had();
        let password = if !self.ask_password {
            if had.password {
                PasswordChange::Clear
            } else {
                PasswordChange::Keep
            }
        } else if self.keep_password && had.password {
            PasswordChange::Keep
        } else {
            let text = self
                .generated
                .as_ref()
                .map_or_else(|| self.password.to_string(), |g| g.to_string());
            let hint = self.hint.trim();
            PasswordChange::Set {
                password: SecretBytes::from_string(text),
                hint: (!hint.is_empty()).then(|| hint.to_owned()),
                params: self.params,
            }
        };
        let authenticator = if !self.ask_password {
            // Clearing the password takes the authenticator with it.
            AuthenticatorChange::Keep
        } else if !self.ask_code {
            if had.authenticator {
                AuthenticatorChange::Remove
            } else {
                AuthenticatorChange::Keep
            }
        } else if self.keeps_authenticator() {
            AuthenticatorChange::Keep
        } else {
            match (&self.enrolment, self.verified) {
                (Some(secret), Some(counter)) => AuthenticatorChange::Verified {
                    secret: secret.clone(),
                    counter,
                },
                _ => return Err("the authenticator has not been verified".to_owned()),
            }
        };
        let recovery_key = if self.creating() || self.new_recovery {
            Some(
                self.recovery
                    .clone()
                    .ok_or("the recovery key has not been made")?,
            )
        } else {
            None
        };
        Ok(Plan {
            name: self.name.clone(),
            create: self.creating(),
            change: SettingsChange {
                password,
                authenticator,
                recovery_key,
                connections: self.connection_changes()?,
            },
        })
    }

    fn connection_changes(&self) -> Result<Vec<ConnectionChange>, String> {
        let mut changes = Vec::new();
        let existing = |provider: Provider| {
            self.editing.as_ref().and_then(|e| {
                e.connections
                    .iter()
                    .find(|c| c.settings.provider() == provider)
            })
        };
        for (i, provider) in PROVIDERS.into_iter().enumerate() {
            let form = self.forms.iter().find(|f| f.provider == provider);
            match (self.ticked[i], existing(provider), form) {
                (true, None, Some(form)) => changes.push(ConnectionChange::Add {
                    settings: form.settings(),
                    credentials: form.credentials()?,
                }),
                (true, Some(info), Some(form)) => {
                    if form.settings() != info.settings {
                        changes.push(ConnectionChange::Settings {
                            id: info.id.clone(),
                            settings: form.settings(),
                        });
                    }
                    let was_stored = info.credentials == CredentialSource::Stored;
                    match (form.stored, form.credentials()?) {
                        (true, Some(credentials)) => {
                            changes.push(ConnectionChange::Credentials {
                                id: info.id.clone(),
                                credentials: Some(credentials),
                            });
                        }
                        (false, _) if was_stored => changes.push(ConnectionChange::Credentials {
                            id: info.id.clone(),
                            credentials: None,
                        }),
                        _ => {}
                    }
                }
                (false, Some(info), _) => changes.push(ConnectionChange::Remove {
                    id: info.id.clone(),
                }),
                _ => {}
            }
        }
        Ok(changes)
    }

    fn commit(&mut self) {
        let plan = match self.plan() {
            Ok(plan) => plan,
            Err(err) => return self.fail(err),
        };
        match self.backend.commit(plan) {
            Ok(committed) => {
                // What was shown once is gone with the review.
                self.password = Zeroizing::default();
                self.confirm = Zeroizing::default();
                self.generated = None;
                self.enrolment = None;
                self.recovery = None;
                for form in &mut self.forms {
                    form.secret = Zeroizing::default();
                }
                self.message = None;
                self.committed = Some(committed);
                self.go(Step::Done);
            }
            Err(err) => self.fail(err),
        }
    }
}
