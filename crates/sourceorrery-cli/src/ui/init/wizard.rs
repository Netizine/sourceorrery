//! The state of `init`'s screens (ADR 0009, section 6): which vault, the
//! project, the vault's secrets to tick (with **All**), a loop adding new
//! secrets to the vault, and a review that writes the manifest.
//!
//! A value typed for a new secret, and its confirmation, live in
//! [`Zeroizing`] buffers and leave this struct only as [`SecretBytes`] on
//! their way to the vault, at `[ Store ]`; the screens get their length,
//! never the text. Nothing reaches the manifest until the review is
//! confirmed, and leaving earlier writes none: secrets stored on the way
//! stay in the vault for any project.

use std::path::{Path, PathBuf};

use sourceorrery_core::manifest::{default_env_name, validate_env_name};
use sourceorrery_core::{Manifest, SecretBytes, validate_secret_name};
use sourceorrery_storage::{
    MAX_DESCRIPTION_LEN, MAX_PROJECT_NAME_LEN, SecretStorage, validate_description,
};
use zeroize::Zeroizing;

use super::backend::{Backend, OpenedVault, Plan, Saved};
use crate::commands::init::Change;

/// Longest value accepted in a hidden field.
const MAX_TYPED: usize = 4096;
/// Longest secret name (the naming rule's own limit).
const MAX_NAME: usize = 127;
/// Longest manifest path and environment variable typed.
const MAX_PATH: usize = 4096;
const MAX_ENV: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Vault,
    Project,
    Secrets,
    AddNew,
    NewSecret,
    Review,
    Done,
}

impl Step {
    /// The steps the rail shows, in order.
    pub const RAIL: [Step; 5] = [
        Step::Vault,
        Step::Project,
        Step::Secrets,
        Step::AddNew,
        Step::Review,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Step::Vault => "Vault",
            Step::Project => "Project",
            Step::Secrets => "Secrets",
            Step::AddNew | Step::NewSecret => "New secrets",
            Step::Review => "Review",
            Step::Done => "Done",
        }
    }

    fn rail_index(self) -> usize {
        let step = if self == Step::NewSecret {
            Step::AddNew
        } else {
            self
        };
        Step::RAIL
            .iter()
            .position(|s| *s == step)
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
    /// Focus the next control.
    Next,
    Prev,
    /// Activate the focused control (a text field moves on).
    Enter,
    /// Dismiss the message, else go back a screen (leave on the first).
    Back,
    Quit,
}

/// Work only the event loop can do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Open this vault (may prompt for its recovery key).
    Open(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Info(String),
    Error(String),
}

/// A control on a screen, in focus order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    /// A vault in the list, by index.
    Vault(usize),
    Leave,
    ProjectName,
    ManifestPath,
    Continue,
    Filter,
    /// Tick every secret shown, or untick them all.
    All,
    /// A secret in the list, by index into [`Wizard::rows`].
    Row(usize),
    AddSecret,
    NoMore,
    Name,
    Value,
    Confirm,
    Storage,
    Description,
    Env,
    Store,
    Cancel,
    /// Whether a secret to write is required, by index into the rows.
    Required(usize),
    Write,
    BackToList,
    Exit,
}

impl Control {
    /// Takes typed text.
    pub fn is_text(self) -> bool {
        matches!(
            self,
            Control::ProjectName
                | Control::ManifestPath
                | Control::Filter
                | Control::Name
                | Control::Value
                | Control::Confirm
                | Control::Description
                | Control::Env
        )
    }

    /// Typed text is shown as dots.
    pub fn is_hidden(self) -> bool {
        matches!(self, Control::Value | Control::Confirm)
    }

    fn is_toggle(self) -> bool {
        matches!(
            self,
            Control::All | Control::Row(_) | Control::Storage | Control::Required(_)
        )
    }
}

/// One secret the Secrets screen lists: one the vault has, or one the
/// manifest declares and the vault does not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub name: String,
    /// Where the vault keeps it; `None` when the vault does not have it.
    pub storage: Option<String>,
    pub description: Option<String>,
    /// The variable it is delivered in.
    pub env: String,
    pub ticked: bool,
    pub required: bool,
    /// The manifest declares it, and whether as required.
    pub declared: Option<bool>,
    /// Stored in the vault on this run.
    pub stored_now: bool,
}

impl Row {
    pub fn in_vault(&self) -> bool {
        self.storage.is_some()
    }
}

/// Where the screens start: the project's defaults, and the manifest when
/// one exists.
pub struct Start {
    pub project: String,
    pub manifest_path: String,
    pub existing: Option<Manifest>,
}

pub struct Wizard<B> {
    backend: B,
    pub step: Step,
    pub viewport: std::cell::RefCell<crate::ui::viewport::Viewport>,
    focus: usize,
    pub message: Option<Message>,
    quit: bool,
    request: Option<Request>,

    /// The vaults to choose from.
    pub vaults: Vec<String>,
    pub vault: Option<OpenedVault>,
    pub project: String,
    pub manifest_path: String,
    pub existing: Option<Manifest>,
    pub rows: Vec<Row>,
    pub filter: String,

    // The new secret being typed.
    pub new_name: String,
    value: Zeroizing<String>,
    confirm: Zeroizing<String>,
    /// Index into the open vault's storages.
    pub storage: usize,
    pub description: String,
    pub env: String,
    env_edited: bool,
    return_to: Step,

    /// Secrets stored in the vault on this run, in order.
    pub stored: Vec<String>,
    pub saved: Option<Saved>,
}

impl<B: Backend> Wizard<B> {
    pub fn new(backend: B, start: Start) -> Self {
        Self {
            backend,
            viewport: Default::default(),
            step: Step::Vault,
            focus: 0,
            message: None,
            quit: false,
            request: None,
            vaults: Vec::new(),
            vault: None,
            project: start.project,
            manifest_path: start.manifest_path,
            existing: start.existing,
            rows: Vec::new(),
            filter: String::new(),
            new_name: String::new(),
            value: Zeroizing::default(),
            confirm: Zeroizing::default(),
            storage: 0,
            description: String::new(),
            env: String::new(),
            env_edited: false,
            return_to: Step::AddNew,
            stored: Vec::new(),
            saved: None,
        }
    }

    /// Open the first screen: the vault the manifest names or `vault`,
    /// else the only vault there is, else the list to choose from. Opening
    /// may prompt, so the caller does this before the screen starts.
    pub fn begin(&mut self, vault: Option<&str>) -> Result<(), String> {
        let named = self
            .existing
            .as_ref()
            .map(|manifest| manifest.project.vault.clone())
            .or_else(|| vault.map(str::to_owned));
        if let Some(name) = named {
            return self.open_first(&name);
        }
        self.vaults = self.backend.vaults()?;
        if let [only] = self.vaults.as_slice() {
            let only = only.clone();
            return self.open_first(&only);
        }
        Ok(())
    }

    fn open_first(&mut self, name: &str) -> Result<(), String> {
        let opened = self.backend.open(name)?;
        self.opened(opened);
        Ok(())
    }

    /// Open the vault a [`Request::Open`] named. The caller has taken the
    /// screen down, so the unlock may prompt.
    pub fn open(&mut self, name: &str) {
        match self.backend.open(name) {
            Ok(opened) => self.opened(opened),
            Err(err) => self.message = Some(Message::Error(err)),
        }
    }

    pub fn should_quit(&self) -> bool {
        self.quit
    }

    pub fn take_request(&mut self) -> Option<Request> {
        self.request.take()
    }

    /// The backend, for what the tests recorded in it.
    #[cfg(test)]
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// The secrets stored on this run when no manifest was written.
    pub fn stored_without_manifest(&self) -> &[String] {
        if self.saved.is_some() {
            &[]
        } else {
            &self.stored
        }
    }

    /// The rows the filter shows, by index.
    pub fn visible_rows(&self) -> Vec<usize> {
        let filter = self.filter.to_ascii_lowercase();
        (0..self.rows.len())
            .filter(|&i| self.rows[i].name.to_ascii_lowercase().contains(&filter))
            .collect()
    }

    /// The controls of the current screen, in focus order.
    pub fn controls(&self) -> Vec<Control> {
        match self.step {
            Step::Vault => (0..self.vaults.len())
                .map(Control::Vault)
                .chain([Control::Leave])
                .collect(),
            Step::Project => vec![
                Control::ProjectName,
                Control::ManifestPath,
                Control::Continue,
            ],
            Step::Secrets => [Control::Filter, Control::All]
                .into_iter()
                .chain(self.visible_rows().into_iter().map(Control::Row))
                .chain([Control::Continue])
                .collect(),
            Step::AddNew => vec![Control::AddSecret, Control::NoMore],
            Step::NewSecret => {
                let mut c = vec![Control::Name, Control::Value, Control::Confirm];
                if self.storages() > 1 {
                    c.push(Control::Storage);
                }
                c.extend([
                    Control::Description,
                    Control::Env,
                    Control::Store,
                    Control::Cancel,
                ]);
                c
            }
            Step::Review => (0..self.rows.len())
                .filter(|&i| self.rows[i].ticked)
                .map(Control::Required)
                .chain([Control::Write, Control::BackToList])
                .collect(),
            Step::Done => vec![Control::Exit],
        }
    }

    pub fn focused(&self) -> Control {
        let controls = self.controls();
        controls[self.focus.min(controls.len() - 1)]
    }

    fn storages(&self) -> usize {
        self.vault.as_ref().map_or(0, |v| v.storages.len())
    }

    /// The label of the storage chosen for the new secret.
    pub fn storage_label(&self) -> &str {
        self.vault
            .as_ref()
            .and_then(|v| v.storages.get(self.storage))
            .map_or("SourceOrrery vault", |s| s.label.as_str())
    }

    /// Characters typed into a hidden field.
    pub fn hidden_len(&self, control: Control) -> usize {
        match control {
            Control::Value => self.value.chars().count(),
            Control::Confirm => self.confirm.chars().count(),
            _ => 0,
        }
    }

    /// The confirmation matches the value, or is still empty.
    pub fn confirm_state(&self) -> Option<bool> {
        (!self.confirm.is_empty()).then(|| self.value.as_str() == self.confirm.as_str())
    }

    /// What is wrong with the name typed so far, as it is typed.
    pub fn name_problem(&self) -> Option<String> {
        if self.new_name.is_empty() {
            return None;
        }
        if let Err(err) = validate_secret_name(&self.new_name) {
            return Some(err.to_string());
        }
        self.rows
            .iter()
            .any(|row| row.name == self.new_name && row.in_vault())
            .then(|| "the vault has this secret already: tick it in the list instead".to_owned())
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
    }

    fn back(&mut self) {
        match self.step {
            Step::Project if self.vaults.len() > 1 => self.go(Step::Vault),
            Step::Secrets if self.existing.is_none() => self.go(Step::Project),
            // The first screen of this run.
            Step::Vault | Step::Done | Step::Project | Step::Secrets => self.quit = true,
            Step::AddNew => self.go(Step::Secrets),
            Step::NewSecret => self.cancel_new(),
            Step::Review => self.go(Step::AddNew),
        }
    }

    fn opened(&mut self, opened: OpenedVault) {
        let label = |storage: &SecretStorage| {
            opened
                .storages
                .iter()
                .find(|s| s.storage == *storage)
                .map_or_else(
                    || match storage {
                        SecretStorage::Vault => "SourceOrrery vault".to_owned(),
                        SecretStorage::Connection(id) => format!("connection {id}"),
                    },
                    |s| s.label.clone(),
                )
        };
        let declared = |name: &str| {
            self.existing
                .as_ref()
                .and_then(|manifest| manifest.secrets.get(name))
        };
        let env_of = |name: &str| {
            declared(name)
                .and_then(|requirement| requirement.env.clone())
                .unwrap_or_else(|| default_env_name(name))
        };
        let mut rows: Vec<Row> = opened
            .catalog
            .iter()
            .map(|entry| Row {
                name: entry.name.clone(),
                storage: Some(label(&entry.storage)),
                description: entry.description.clone(),
                env: env_of(&entry.name),
                ticked: declared(&entry.name).is_some(),
                required: declared(&entry.name).is_none_or(|r| r.required),
                declared: declared(&entry.name).map(|r| r.required),
                stored_now: false,
            })
            .collect();
        if let Some(manifest) = &self.existing {
            for (name, requirement) in &manifest.secrets {
                if !rows.iter().any(|row| &row.name == name) {
                    rows.push(Row {
                        name: name.clone(),
                        storage: None,
                        description: requirement.purpose.clone(),
                        env: env_of(name),
                        ticked: true,
                        required: requirement.required,
                        declared: Some(requirement.required),
                        stored_now: false,
                    });
                }
            }
        }
        rows.sort_by(|a, b| a.name.cmp(&b.name));
        self.rows = rows;
        self.vault = Some(opened);
        self.message = None;
        self.go(if self.existing.is_some() {
            Step::Secrets
        } else {
            Step::Project
        });
    }

    fn input(&mut self, c: char) {
        let control = self.focused();
        if control.is_text() {
            if c.is_control() {
                return;
            }
            self.message = None;
            match control {
                Control::ProjectName if self.project.chars().count() < MAX_PROJECT_NAME_LEN => {
                    self.project.push(c);
                }
                Control::ManifestPath if self.manifest_path.len() < MAX_PATH => {
                    self.manifest_path.push(c);
                }
                Control::Filter if self.filter.len() < MAX_NAME => self.filter.push(c),
                Control::Name if self.new_name.len() < MAX_NAME => {
                    self.new_name.push(c);
                    self.derive_env();
                }
                Control::Value if self.value.len() < MAX_TYPED => self.value.push(c),
                Control::Confirm if self.confirm.len() < MAX_TYPED => self.confirm.push(c),
                Control::Description if self.description.chars().count() < MAX_DESCRIPTION_LEN => {
                    self.description.push(c);
                }
                Control::Env if self.env.len() < MAX_ENV => {
                    self.env.push(c);
                    self.env_edited = true;
                }
                _ => {}
            }
            return;
        }
        match c {
            ' ' if control.is_toggle() => self.toggle(control),
            '/' if self.step == Step::Secrets => self.focus = 0,
            'q' if matches!(self.step, Step::Vault | Step::Done) => self.quit = true,
            _ => {}
        }
    }

    fn erase(&mut self) {
        match self.focused() {
            Control::ProjectName => {
                self.project.pop();
            }
            Control::ManifestPath => {
                self.manifest_path.pop();
            }
            Control::Filter => {
                self.filter.pop();
            }
            Control::Name => {
                self.new_name.pop();
                self.derive_env();
            }
            Control::Value => {
                self.value.pop();
            }
            Control::Confirm => {
                self.confirm.pop();
            }
            Control::Description => {
                self.description.pop();
            }
            Control::Env => {
                // Left empty, it is the name's default at [ Store ].
                self.env.pop();
                self.env_edited = true;
            }
            _ => {}
        }
    }

    /// The variable follows the name until it is typed itself.
    fn derive_env(&mut self) {
        if !self.env_edited {
            self.env = default_env_name(&self.new_name);
        }
    }

    fn toggle(&mut self, control: Control) {
        match control {
            Control::All => {
                let shown = self.visible_rows();
                let tick = !shown.iter().all(|&i| self.rows[i].ticked);
                for i in shown {
                    self.rows[i].ticked = tick;
                }
            }
            Control::Row(i) => self.rows[i].ticked = !self.rows[i].ticked,
            Control::Required(i) => self.rows[i].required = !self.rows[i].required,
            Control::Storage => self.storage = (self.storage + 1) % self.storages().max(1),
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
            Control::Vault(i) => self.request = Some(Request::Open(self.vaults[i].clone())),
            Control::Leave | Control::Exit => self.quit = true,
            Control::Continue if self.step == Step::Project => self.project_continue(),
            Control::Continue => self.go(Step::AddNew),
            Control::Row(i) if !self.rows[i].in_vault() => {
                let name = self.rows[i].name.clone();
                self.start_new(Some(name));
            }
            Control::All | Control::Row(_) | Control::Storage | Control::Required(_) => {
                self.toggle(control);
            }
            Control::AddSecret => self.start_new(None),
            Control::NoMore => self.go(Step::Review),
            Control::Store => self.store(),
            Control::Cancel => self.cancel_new(),
            Control::Write => self.write(),
            Control::BackToList => self.go(Step::Secrets),
            _ => {}
        }
    }

    fn project_continue(&mut self) {
        let name = self.project.trim();
        if name.is_empty() {
            self.message = Some(Message::Error("type the project's name".to_owned()));
            return;
        }
        if self.manifest_path.trim().is_empty() {
            self.message = Some(Message::Error(
                "type where the manifest goes (sourceorrery.toml)".to_owned(),
            ));
            return;
        }
        if Path::new(self.manifest_path.trim()).exists() {
            self.message = Some(Message::Error(format!(
                "{} exists already: run init in its folder to add to it",
                self.manifest_path.trim()
            )));
            return;
        }
        self.project = name.to_owned();
        self.go(Step::Secrets);
    }

    fn start_new(&mut self, name: Option<String>) {
        self.return_to = self.step;
        let row = name
            .as_deref()
            .and_then(|n| self.rows.iter().find(|row| row.name == n));
        self.description = row
            .and_then(|row| row.description.clone())
            .unwrap_or_default();
        self.env = row.map(|row| row.env.clone()).unwrap_or_default();
        self.env_edited = row.is_some();
        self.new_name = name.unwrap_or_default();
        self.value = Zeroizing::default();
        self.confirm = Zeroizing::default();
        self.storage = 0;
        let prefilled = !self.new_name.is_empty();
        self.go(Step::NewSecret);
        if prefilled {
            // The name is the manifest's: the value is what is missing.
            self.focus = 1;
        }
    }

    fn cancel_new(&mut self) {
        self.value = Zeroizing::default();
        self.confirm = Zeroizing::default();
        self.new_name.clear();
        self.description.clear();
        self.env.clear();
        self.env_edited = false;
        let back = self.return_to;
        self.go(back);
    }

    fn fail(&mut self, text: impl Into<String>) {
        self.message = Some(Message::Error(text.into()));
    }

    fn store(&mut self) {
        let name = self.new_name.clone();
        if name.is_empty() {
            return self.fail("type the secret's name");
        }
        if let Some(problem) = self.name_problem() {
            return self.fail(problem);
        }
        if self.value.is_empty() {
            return self.fail("type the value");
        }
        if self.confirm_state() != Some(true) {
            return self.fail("the confirmation does not match the value");
        }
        let description = self.description.trim().to_owned();
        if !description.is_empty()
            && let Err(err) = validate_description(&description)
        {
            return self.fail(err.to_string());
        }
        if self.env.is_empty() {
            self.env = default_env_name(&name);
        }
        if let Err(err) = validate_env_name(&self.env) {
            return self.fail(err.to_string());
        }
        if let Some(other) = self
            .rows
            .iter()
            .find(|row| row.ticked && row.name != name && row.env.eq_ignore_ascii_case(&self.env))
        {
            return self.fail(format!(
                "{} is the variable of '{}' already; give this one another",
                self.env, other.name
            ));
        }
        let Some(vault) = &self.vault else {
            return self.fail("no vault is open");
        };
        let Some(choice) = vault
            .storages
            .get(self.storage)
            .or_else(|| vault.storages.first())
            .cloned()
        else {
            return self.fail("the vault offers nowhere to keep a secret");
        };
        let vault_name = vault.name.clone();
        let value = SecretBytes::from_string(self.value.to_string());
        let described = (!description.is_empty()).then_some(description.as_str());
        match self.backend.store(&name, value, &choice.storage, described) {
            Ok(()) => {
                self.value = Zeroizing::default();
                self.confirm = Zeroizing::default();
                let row = Row {
                    name: name.clone(),
                    storage: Some(choice.label.clone()),
                    description: described.map(str::to_owned),
                    env: self.env.clone(),
                    ticked: true,
                    required: true,
                    declared: None,
                    stored_now: true,
                };
                if let Some(existing) = self.rows.iter_mut().find(|r| r.name == name) {
                    *existing = Row {
                        required: existing.required,
                        declared: existing.declared,
                        ..row
                    };
                } else {
                    self.rows.push(row);
                    self.rows.sort_by(|a, b| a.name.cmp(&b.name));
                }
                self.stored.push(name.clone());
                let at = if choice.storage == SecretStorage::Vault {
                    String::new()
                } else {
                    format!(" (kept at {})", choice.label)
                };
                self.message = Some(Message::Info(format!(
                    "Stored '{name}' in vault '{vault_name}'{at}; it is ticked for this project."
                )));
                self.new_name.clear();
                self.description.clear();
                self.env.clear();
                self.env_edited = false;
                // A value given from the list goes back to the list; the
                // add-new loop asks again.
                let next = if self.return_to == Step::Secrets {
                    Step::Secrets
                } else {
                    Step::AddNew
                };
                self.go(next);
            }
            Err(err) => self.fail(err),
        }
    }

    /// The changes the review writes.
    pub fn changes(&self) -> Vec<Change> {
        let mut changes = Vec::new();
        for row in &self.rows {
            match (row.declared, row.ticked) {
                (None, true) => changes.push(Change::Add {
                    name: row.name.clone(),
                    required: row.required,
                    purpose: row.description.clone(),
                    env: (row.env != default_env_name(&row.name)).then(|| row.env.clone()),
                }),
                (Some(_), false) => changes.push(Change::Remove(row.name.clone())),
                (Some(was), true) if was != row.required => changes.push(Change::Required {
                    name: row.name.clone(),
                    required: row.required,
                }),
                _ => {}
            }
        }
        changes
    }

    fn write(&mut self) {
        if self.existing.is_none() && !self.rows.iter().any(|row| row.ticked) {
            return self.fail("tick at least one secret, or add one, for the manifest to declare");
        }
        let Some(vault) = &self.vault else {
            return self.fail("no vault is open");
        };
        let plan = Plan {
            path: PathBuf::from(self.manifest_path.trim()),
            project: self.project.clone(),
            vault: vault.name.clone(),
            changes: self.changes(),
        };
        match self.backend.write(&plan) {
            Ok(saved) => {
                self.saved = Some(saved);
                self.message = None;
                self.go(Step::Done);
            }
            Err(err) => self.fail(err),
        }
    }
}
