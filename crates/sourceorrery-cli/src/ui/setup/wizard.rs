//! The wizard's state: the step, what is typed, and what the backend said.
//!
//! Everything a person types as a secret (the vault passphrase, the first
//! secret's value, their confirmations) lives in a [`Zeroizing`] buffer and
//! leaves this struct only as [`SecretBytes`] on its way to the vault; the
//! screens get its length and its strength estimate, never the text. The
//! generated passphrase and the recovery codes are the exceptions, by
//! design: they are shown once, behind a "written down" gate, and dropped
//! as soon as the step is left.

use sourceorrery_core::{SecretBytes, validate_secret_name, validate_vault_name};
use sourceorrery_crypto::random;
use sourceorrery_storage::RevealGuard;
use zeroize::Zeroizing;

use super::backend::{Backend, Enrolment, ProjectReady, VaultReady};
use crate::strength::{self, Estimate};

/// Recovery codes the wizard issues.
pub const RECOVERY_CODES: usize = 5;
/// Characters in a generated vault passphrase (about 125 bits).
pub const GENERATED_PASSPHRASE_LEN: usize = 20;
/// Characters in a generated secret value (about 150 bits).
pub const GENERATED_SECRET_LEN: usize = 24;
/// Codes tried before an enrolment is abandoned.
const CODE_ATTEMPTS: u32 = 3;
/// Longest text accepted in a hidden field.
const MAX_TYPED: usize = 256;
/// Longest passphrase hint (the vault's own limit).
const MAX_HINT: usize = sourceorrery_storage::MAX_HINT_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Welcome,
    Vault,
    Secret,
    Recovery,
    SecondFactor,
    Guard,
    Project,
    Done,
}

impl Step {
    /// The steps the rail shows, in order.
    pub const RAIL: [Step; 6] = [
        Step::Vault,
        Step::Secret,
        Step::Recovery,
        Step::SecondFactor,
        Step::Guard,
        Step::Project,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Step::Welcome => "Welcome",
            Step::Vault => "Vault",
            Step::Secret => "First secret",
            Step::Recovery => "Recovery",
            Step::SecondFactor => "Second factor",
            Step::Guard => "Reveal guard",
            Step::Project => "Project",
            Step::Done => "Done",
        }
    }

    fn index(self) -> usize {
        Step::RAIL
            .iter()
            .position(|s| *s == self)
            .unwrap_or(match self {
                Step::Welcome => 0,
                _ => Step::RAIL.len(),
            })
    }

    /// `other` comes before this step.
    pub fn is_past(self, other: Step) -> bool {
        other != Step::Welcome && other.index() < self.index()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Input(char),
    Erase,
    /// Focus the next control.
    Next,
    Prev,
    /// Activate the focused control (a text field moves on).
    Enter,
    /// Dismiss the message; on the first and last screen, leave.
    Back,
    Quit,
}

/// Work only the event loop can do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Unlock this existing vault (may prompt for its passphrase).
    OpenExisting(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Info(String),
    Error(String),
}

/// A control on a step, in focus order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    Start,
    VaultName,
    /// Also unlock with the OS credential store (checkbox).
    Keyring,
    Passphrase,
    PassphraseConfirm,
    /// Generate a passphrase, or go back to typing one.
    GeneratePassphrase,
    /// "I have written it down" (checkbox).
    PassphraseWritten,
    CreateVault,
    SecretName,
    SecretValue,
    SecretConfirm,
    GenerateSecret,
    StoreSecret,
    ShowCodes,
    CodesWritten,
    Hint,
    FinishRecovery,
    Enrol,
    Code,
    Verify,
    SkipSecondFactor,
    GuardChoice,
    SetGuard,
    Finish,
    Exit,
}

impl Control {
    /// Takes typed text.
    pub fn is_text(self) -> bool {
        matches!(
            self,
            Control::VaultName
                | Control::Passphrase
                | Control::PassphraseConfirm
                | Control::SecretName
                | Control::SecretValue
                | Control::SecretConfirm
                | Control::Hint
                | Control::Code
        )
    }

    /// Typed text is shown as dots.
    pub fn is_hidden(self) -> bool {
        matches!(
            self,
            Control::Passphrase
                | Control::PassphraseConfirm
                | Control::SecretValue
                | Control::SecretConfirm
        )
    }

    fn is_toggle(self) -> bool {
        matches!(
            self,
            Control::Keyring
                | Control::PassphraseWritten
                | Control::CodesWritten
                | Control::GuardChoice
        )
    }
}

/// What the recovery step left behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recovery {
    pub codes: usize,
    pub hint: bool,
}

pub struct Wizard<B> {
    backend: B,
    pub step: Step,
    focus: usize,
    pub message: Option<Message>,
    quit: bool,
    request: Option<Request>,

    // Vault.
    pub vault_name: String,
    pub keyring_store: Option<&'static str>,
    pub keyring: bool,
    passphrase: Zeroizing<String>,
    passphrase_confirm: Zeroizing<String>,
    pub passphrase_estimate: Option<Estimate>,
    /// Shown once, until the vault is created.
    pub generated_passphrase: Option<Zeroizing<String>>,
    pub passphrase_written: bool,
    pub vault: Option<VaultReady>,

    // First secret.
    pub secret_name: String,
    secret: Zeroizing<String>,
    secret_confirm: Zeroizing<String>,
    pub secret_estimate: Option<Estimate>,
    pub secret_generated: bool,
    /// The name stored.
    pub stored: Option<String>,

    // Recovery.
    /// Shown once, until the step is left.
    pub codes: Option<Vec<Zeroizing<String>>>,
    pub codes_written: bool,
    pub hint: String,
    pub recovery: Option<Recovery>,

    // Second factor.
    pub enrolment: Option<Enrolment>,
    pub code: String,
    attempts: u32,
    /// `Some(true)` verified, `Some(false)` skipped.
    pub second_factor: Option<bool>,

    // Guard.
    pub guard_choice: usize,
    pub guard: Option<RevealGuard>,

    // Project.
    pub project: Option<ProjectReady>,
}

impl<B: Backend> Wizard<B> {
    pub fn new(backend: B, vault_name: &str, secret_name: &str) -> Self {
        let keyring_store = backend.keyring();
        Self {
            backend,
            step: Step::Welcome,
            focus: 0,
            message: None,
            quit: false,
            request: None,
            vault_name: vault_name.to_owned(),
            keyring_store,
            keyring: keyring_store.is_some(),
            passphrase: Zeroizing::default(),
            passphrase_confirm: Zeroizing::default(),
            passphrase_estimate: None,
            generated_passphrase: None,
            passphrase_written: false,
            vault: None,
            secret_name: secret_name.to_owned(),
            secret: Zeroizing::default(),
            secret_confirm: Zeroizing::default(),
            secret_estimate: None,
            secret_generated: false,
            stored: None,
            codes: None,
            codes_written: false,
            hint: String::new(),
            recovery: None,
            enrolment: None,
            code: String::new(),
            attempts: 0,
            second_factor: None,
            guard_choice: 0,
            guard: None,
            project: None,
        }
    }

    pub fn should_quit(&self) -> bool {
        self.quit
    }

    /// The backend, for what the tests recorded in it.
    #[cfg(test)]
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Open the existing vault a [`Request::OpenExisting`] named. The caller
    /// has taken the screen down, so the unlock may prompt.
    pub fn open_existing(&mut self, name: &str) {
        let result = self.backend.open_vault(name);
        self.opened(result);
    }

    pub fn take_request(&mut self) -> Option<Request> {
        self.request.take()
    }

    /// The vault name typed names an existing vault file.
    pub fn vault_exists(&self) -> bool {
        self.backend.vault_exists(&self.vault_name)
    }

    /// The controls of the current step, in focus order.
    pub fn controls(&self) -> Vec<Control> {
        match self.step {
            Step::Welcome => vec![Control::Start],
            Step::Vault => {
                let mut c = vec![Control::VaultName];
                if self.vault_exists() {
                    c.push(Control::CreateVault);
                    return c;
                }
                if self.keyring_store.is_some() {
                    c.push(Control::Keyring);
                }
                if self.generated_passphrase.is_some() {
                    c.extend([Control::GeneratePassphrase, Control::PassphraseWritten]);
                } else {
                    c.extend([
                        Control::Passphrase,
                        Control::PassphraseConfirm,
                        Control::GeneratePassphrase,
                    ]);
                }
                c.push(Control::CreateVault);
                c
            }
            Step::Secret => {
                let mut c = vec![Control::SecretName];
                if self.secret_generated {
                    c.push(Control::GenerateSecret);
                } else {
                    c.extend([
                        Control::SecretValue,
                        Control::SecretConfirm,
                        Control::GenerateSecret,
                    ]);
                }
                c.push(Control::StoreSecret);
                c
            }
            Step::Recovery => vec![
                if self.codes.is_some() {
                    Control::CodesWritten
                } else {
                    Control::ShowCodes
                },
                Control::Hint,
                Control::FinishRecovery,
            ],
            Step::SecondFactor => {
                if self.enrolment.is_some() {
                    vec![Control::Code, Control::Verify, Control::SkipSecondFactor]
                } else {
                    vec![Control::Enrol, Control::SkipSecondFactor]
                }
            }
            Step::Guard => vec![Control::GuardChoice, Control::SetGuard],
            Step::Project => vec![Control::Finish],
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
            Control::Passphrase => self.passphrase.chars().count(),
            Control::PassphraseConfirm => self.passphrase_confirm.chars().count(),
            Control::SecretValue => self.secret.chars().count(),
            Control::SecretConfirm => self.secret_confirm.chars().count(),
            _ => 0,
        }
    }

    /// The confirmation field matches, or is still empty.
    pub fn confirm_state(&self, control: Control) -> Option<bool> {
        let (first, second) = match control {
            Control::PassphraseConfirm => (&self.passphrase, &self.passphrase_confirm),
            Control::SecretConfirm => (&self.secret, &self.secret_confirm),
            _ => return None,
        };
        (!second.is_empty()).then(|| first.as_str() == second.as_str())
    }

    /// The guard choices on offer: what each asks for, and its label.
    pub fn guard_options(&self) -> Vec<(RevealGuard, &'static str)> {
        let mut options = Vec::new();
        if self.second_factor == Some(true) {
            options.push((
                RevealGuard {
                    passphrase: true,
                    second_factor: true,
                },
                "The passphrase and a code from the app",
            ));
        }
        options.push((
            RevealGuard {
                passphrase: true,
                second_factor: false,
            },
            "The passphrase",
        ));
        options.push((RevealGuard::default(), "Nothing: unlocking is enough"));
        options
    }

    pub fn update(&mut self, action: Action) {
        match action {
            Action::Quit => self.quit = true,
            Action::Back => {
                if self.message.take().is_none() && matches!(self.step, Step::Welcome | Step::Done)
                {
                    self.quit = true;
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

    fn opened(&mut self, result: Result<VaultReady, String>) {
        match result {
            Ok(ready) => {
                self.message = Some(Message::Info(format!(
                    "Using the existing vault '{}'.",
                    ready.name
                )));
                self.vault = Some(ready);
                self.go(Step::Secret);
            }
            Err(err) => self.message = Some(Message::Error(err)),
        }
    }

    fn go(&mut self, step: Step) {
        self.step = step;
        self.focus = 0;
        if step == Step::Project {
            self.write_project();
        }
    }

    fn input(&mut self, c: char) {
        let control = self.focused();
        if control.is_text() {
            if c.is_control() {
                return;
            }
            self.message = None;
            match control {
                Control::VaultName if self.vault_name.len() < 64 => self.vault_name.push(c),
                Control::SecretName if self.secret_name.len() < 127 => self.secret_name.push(c),
                Control::Hint if self.hint.chars().count() < MAX_HINT => self.hint.push(c),
                Control::Code if c.is_ascii_digit() && self.code.len() < 6 => self.code.push(c),
                Control::Passphrase if self.passphrase.len() < MAX_TYPED => {
                    self.passphrase.push(c);
                    self.passphrase_estimate = Some(strength::estimate(&self.passphrase));
                }
                Control::PassphraseConfirm if self.passphrase_confirm.len() < MAX_TYPED => {
                    self.passphrase_confirm.push(c);
                }
                Control::SecretValue if self.secret.len() < MAX_TYPED => {
                    self.secret.push(c);
                    self.secret_estimate = Some(strength::estimate(&self.secret));
                }
                Control::SecretConfirm if self.secret_confirm.len() < MAX_TYPED => {
                    self.secret_confirm.push(c);
                }
                _ => {}
            }
            return;
        }
        match c {
            ' ' if control.is_toggle() => self.activate(control),
            'q' if matches!(self.step, Step::Welcome | Step::Done) => self.quit = true,
            _ => {}
        }
    }

    fn erase(&mut self) {
        match self.focused() {
            Control::VaultName => {
                self.vault_name.pop();
            }
            Control::SecretName => {
                self.secret_name.pop();
            }
            Control::Hint => {
                self.hint.pop();
            }
            Control::Code => {
                self.code.pop();
            }
            Control::Passphrase => {
                self.passphrase.pop();
                self.passphrase_estimate =
                    (!self.passphrase.is_empty()).then(|| strength::estimate(&self.passphrase));
            }
            Control::PassphraseConfirm => {
                self.passphrase_confirm.pop();
            }
            Control::SecretValue => {
                self.secret.pop();
                self.secret_estimate =
                    (!self.secret.is_empty()).then(|| strength::estimate(&self.secret));
            }
            Control::SecretConfirm => {
                self.secret_confirm.pop();
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
        match control {
            Control::Start => self.go(Step::Vault),
            Control::Keyring => self.keyring = !self.keyring,
            Control::PassphraseWritten => self.passphrase_written = !self.passphrase_written,
            Control::CodesWritten => self.codes_written = !self.codes_written,
            Control::GuardChoice => {
                self.guard_choice = (self.guard_choice + 1) % self.guard_options().len();
            }
            Control::GeneratePassphrase => self.toggle_generated_passphrase(),
            Control::CreateVault => self.create_vault(),
            Control::GenerateSecret => {
                self.secret_generated = !self.secret_generated;
                self.secret = Zeroizing::default();
                self.secret_confirm = Zeroizing::default();
                self.secret_estimate = None;
                self.focus = 0;
            }
            Control::StoreSecret => self.store_secret(),
            Control::ShowCodes => match self.backend.recovery_codes(RECOVERY_CODES) {
                Ok(codes) => {
                    self.codes = Some(codes);
                    self.codes_written = false;
                    self.focus = 0;
                }
                Err(err) => self.message = Some(Message::Error(err)),
            },
            Control::FinishRecovery => self.finish_recovery(),
            Control::Enrol => match self.backend.enrol() {
                Ok(enrolment) => {
                    self.enrolment = Some(enrolment);
                    self.code.clear();
                    self.attempts = 0;
                    self.focus = 0;
                }
                Err(err) => self.message = Some(Message::Error(err)),
            },
            Control::Verify => self.verify_code(),
            Control::SkipSecondFactor => {
                if self.enrolment.take().is_some()
                    && let Err(err) = self.backend.cancel_enrolment()
                {
                    self.message = Some(Message::Error(err));
                    return;
                }
                self.second_factor = Some(false);
                self.guard_choice = 0;
                self.go(Step::Guard);
            }
            Control::SetGuard => {
                let (guard, _) = self.guard_options()[self.guard_choice];
                match self.backend.set_guard(guard) {
                    Ok(set) => {
                        self.guard = Some(set);
                        self.message = None;
                        self.go(Step::Project);
                    }
                    Err(err) => self.message = Some(Message::Error(err)),
                }
            }
            Control::Finish => {
                if self.project.is_none() {
                    self.write_project();
                } else {
                    self.go(Step::Done);
                }
            }
            Control::Exit => self.quit = true,
            _ => {}
        }
    }

    fn toggle_generated_passphrase(&mut self) {
        if self.generated_passphrase.take().is_some() {
            self.passphrase_written = false;
        } else {
            match random::random_passphrase(GENERATED_PASSPHRASE_LEN) {
                Ok(generated) => {
                    self.passphrase = Zeroizing::default();
                    self.passphrase_confirm = Zeroizing::default();
                    self.passphrase_estimate = None;
                    self.generated_passphrase = Some(generated);
                }
                Err(err) => {
                    self.message = Some(Message::Error(format!(
                        "cannot generate a passphrase: {err}"
                    )));
                }
            }
        }
        self.focus = 0;
    }

    fn create_vault(&mut self) {
        if let Err(err) = validate_vault_name(&self.vault_name) {
            self.message = Some(Message::Error(err.to_string()));
            return;
        }
        if self.vault_exists() {
            self.request = Some(Request::OpenExisting(self.vault_name.clone()));
            return;
        }
        let passphrase = if let Some(generated) = &self.generated_passphrase {
            if !self.passphrase_written {
                self.message = Some(Message::Error(
                    "write the passphrase down (or store it in a password manager) and tick \
                     the box: nothing can recover a vault whose passphrase is lost"
                        .to_owned(),
                ));
                return;
            }
            SecretBytes::from_string(generated.to_string())
        } else {
            match &self.passphrase_estimate {
                None => {
                    self.message = Some(Message::Error("type a passphrase".to_owned()));
                    return;
                }
                Some(estimate) if !estimate.acceptable() => {
                    self.message = Some(Message::Error(format!(
                        "the passphrase rates {}; it needs {}. Make it longer, or let the \
                         wizard generate one",
                        estimate.score.label(),
                        strength::Score::REQUIRED.label()
                    )));
                    return;
                }
                Some(_) => {}
            }
            if self.confirm_state(Control::PassphraseConfirm) != Some(true) {
                self.message = Some(Message::Error(
                    "the confirmation does not match the passphrase".to_owned(),
                ));
                return;
            }
            SecretBytes::from_string(self.passphrase.to_string())
        };
        let keyring = self.keyring && self.keyring_store.is_some();
        match self
            .backend
            .create_vault(&self.vault_name, passphrase, keyring)
        {
            Ok(ready) => {
                self.passphrase = Zeroizing::default();
                self.passphrase_confirm = Zeroizing::default();
                self.passphrase_estimate = None;
                self.generated_passphrase = None;
                self.message = Some(Message::Info(format!(
                    "Vault '{}' created at {}.",
                    ready.name, ready.path
                )));
                self.vault = Some(ready);
                self.go(Step::Secret);
            }
            Err(err) => self.message = Some(Message::Error(err)),
        }
    }

    fn store_secret(&mut self) {
        if let Err(err) = validate_secret_name(&self.secret_name) {
            self.message = Some(Message::Error(err.to_string()));
            return;
        }
        let value = if self.secret_generated {
            match random::random_passphrase(GENERATED_SECRET_LEN) {
                Ok(generated) => SecretBytes::from_string(generated.to_string()),
                Err(err) => {
                    self.message = Some(Message::Error(format!("cannot generate a value: {err}")));
                    return;
                }
            }
        } else {
            match &self.secret_estimate {
                None => {
                    self.message = Some(Message::Error("type a value".to_owned()));
                    return;
                }
                Some(estimate) if !estimate.acceptable() => {
                    self.message = Some(Message::Error(format!(
                        "the value rates {}; a database password needs {}. Make it longer, \
                         or let the wizard generate one",
                        estimate.score.label(),
                        strength::Score::REQUIRED.label()
                    )));
                    return;
                }
                Some(_) => {}
            }
            if self.confirm_state(Control::SecretConfirm) != Some(true) {
                self.message = Some(Message::Error(
                    "the confirmation does not match the value".to_owned(),
                ));
                return;
            }
            SecretBytes::from_string(self.secret.to_string())
        };
        match self.backend.set_secret(&self.secret_name, value) {
            Ok(()) => {
                self.secret = Zeroizing::default();
                self.secret_confirm = Zeroizing::default();
                self.secret_estimate = None;
                self.message = Some(Message::Info(format!(
                    "Secret '{}' stored{}.",
                    self.secret_name,
                    if self.secret_generated {
                        "; the generated value was never shown and lives only in the vault"
                    } else {
                        ""
                    }
                )));
                self.stored = Some(self.secret_name.clone());
                self.go(Step::Recovery);
            }
            Err(err) => self.message = Some(Message::Error(err)),
        }
    }

    fn finish_recovery(&mut self) {
        if self.codes.is_some() && !self.codes_written {
            self.message = Some(Message::Error(
                "write the codes down and tick the box; they are not shown again".to_owned(),
            ));
            return;
        }
        let hint = self.hint.trim();
        if !hint.is_empty()
            && let Err(err) = self.backend.set_hint(hint)
        {
            self.message = Some(Message::Error(err));
            return;
        }
        self.recovery = Some(Recovery {
            codes: self.codes.as_ref().map_or(0, Vec::len),
            hint: !hint.is_empty(),
        });
        // The codes are gone from memory with the step.
        self.codes = None;
        self.message = None;
        self.go(Step::SecondFactor);
    }

    fn verify_code(&mut self) {
        if self.code.len() != 6 {
            self.message = Some(Message::Error(
                "type the six digits the app shows".to_owned(),
            ));
            return;
        }
        match self.backend.verify_code(&self.code) {
            Ok(true) => {
                self.enrolment = None;
                self.code.clear();
                self.second_factor = Some(true);
                self.guard_choice = 0;
                self.message = Some(Message::Info(
                    "Code accepted: the second factor is enrolled and verified.".to_owned(),
                ));
                self.go(Step::Guard);
            }
            Ok(false) => {
                self.attempts += 1;
                self.code.clear();
                self.focus = 0;
                if self.attempts >= CODE_ATTEMPTS {
                    self.enrolment = None;
                    self.attempts = 0;
                    match self.backend.cancel_enrolment() {
                        Ok(()) => {
                            self.message = Some(Message::Error(
                                "no code matched, so the enrolment was removed; check the \
                                 phone's clock, then enrol again or skip"
                                    .to_owned(),
                            ));
                        }
                        Err(err) => self.message = Some(Message::Error(err)),
                    }
                } else {
                    self.message = Some(Message::Error(format!(
                        "that code did not match ({} of {CODE_ATTEMPTS}); wait for the next \
                         one and try again",
                        self.attempts
                    )));
                }
            }
            Err(err) => self.message = Some(Message::Error(err)),
        }
    }

    fn write_project(&mut self) {
        let secret = self
            .stored
            .clone()
            .unwrap_or_else(|| self.secret_name.clone());
        match self.backend.write_project(&secret) {
            Ok(project) => {
                if !project.ok {
                    self.message = Some(Message::Error(
                        "a required secret in the manifest is missing or inaccessible; see \
                         the rows below"
                            .to_owned(),
                    ));
                }
                self.project = Some(project);
            }
            Err(err) => self.message = Some(Message::Error(err)),
        }
    }
}
