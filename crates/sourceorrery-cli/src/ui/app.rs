//! Browser state and what each action does to it. There is no terminal in
//! here, so every behaviour is tested directly. Opening a vault needs the
//! terminal (the recovery-key and view-check prompts), and so do the setup
//! screens, so the app only asks for them ([`Request`]) and the event loop
//! does them.

use std::path::PathBuf;
use std::time::Duration;

use ratatui::widgets::TableState;
use sourceorrery_core::{
    AuditEvent, Capability, DeletedSecret, SecretBytes, SecretError, SecretProperties,
    SetSecretOptions, timestamp,
};
use sourceorrery_storage::SecretStorage;
use time::OffsetDateTime;

use super::edit::{Change, Confirm, Dialog, Form, Kept, StorageChoice};
use super::search::Query;
use super::session::{Project, ProjectStatus, Session};
use crate::output;

/// The views, in tab order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Secrets,
    Projects,
    Deleted,
    Audit,
    Vaults,
}

impl Tab {
    pub const ALL: [Tab; 6] = [
        Tab::Overview,
        Tab::Secrets,
        Tab::Projects,
        Tab::Deleted,
        Tab::Audit,
        Tab::Vaults,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Secrets => "Secrets",
            Tab::Projects => "Projects",
            Tab::Deleted => "Deleted",
            Tab::Audit => "Audit log",
            Tab::Vaults => "Vaults",
        }
    }

    fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }
}

/// Something the user asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Up,
    Down,
    PageUp,
    PageDown,
    Top,
    Bottom,
    NextTab,
    PrevTab,
    Show(Tab),
    /// Details of the selected secret, or open the selected vault.
    Open,
    /// Close what is open: help, the search box, details, the filter.
    Back,
    Search,
    Input(char),
    Erase,
    /// Keep the filter and leave the search box.
    Commit,
    /// Read the vault again (audited), or rescan the vaults.
    Refresh,
    /// Check the audit chain again (not audited).
    Verify,
    /// Lock the open vault now: drop it, wiping its key from memory.
    Lock,
    /// Enable or disable the selected version.
    Toggle,
    /// Change the selected version's metadata.
    Edit,
    /// Store a new version of the selected secret.
    NewVersion,
    /// Store a new secret.
    Add,
    /// Delete the selected secret.
    Delete,
    /// Recover the selected deleted secret.
    Recover,
    /// Change the vault's settings (its view check, recovery key and
    /// storage) on the setup screens.
    ChangeVault,
    /// Forget the selected project, whose folder is gone.
    Unlink,
    Help,
    Quit,
}

/// How keys are read: as commands, as text for the search box, or only to
/// close the help.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Search,
    Help,
    /// A form or a confirmation is open.
    Dialog,
}

/// Work only the event loop can do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Open this vault (may prompt for its recovery key and view check).
    Open(String),
    /// List the vaults in the home directory again.
    ListVaults,
    /// Read a new value for this secret at the hidden prompt and hand it
    /// to [`App::write_version`].
    ReadValue(String),
    /// The setup screens: create a vault (`None`), or change this one.
    Setup(Option<String>),
}

/// A vault file in the home directory. Listing needs no unlock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultEntry {
    pub name: String,
    pub path: PathBuf,
    pub size: Option<u64>,
    pub modified: Option<OffsetDateTime>,
}

/// A one-line message for the status bar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Info(String),
    Error(String),
}

/// The selection and filter of one view.
#[derive(Debug, Default)]
pub struct ListState {
    pub table: TableState,
    pub query: String,
    /// Rows the view showed at the last draw: the step of PageUp/PageDown.
    pub page: usize,
    initialized: bool,
    pending_selection: Option<String>,
}

#[derive(Debug)]
pub struct App {
    pub vaults: Vec<VaultEntry>,
    pub session: Option<Session>,
    pub tab: Tab,
    lists: [ListState; 6],
    /// The secret whose details are shown, on the Secrets or Deleted view,
    /// or the project's id on the Projects view.
    pub detail: Option<String>,
    /// Selection in the details' version list.
    pub versions: TableState,
    /// Keys go to the search box.
    pub editing: bool,
    pub help: bool,
    pub help_view: super::viewport::Viewport,
    pub declarations: TableState,
    pub declaration_page: usize,
    pub overview_view: std::cell::RefCell<super::viewport::Viewport>,
    pub message: Option<Message>,
    request: Option<Request>,
    quit: bool,
    /// Lock the open vault after this long without a key.
    lock_after: Option<Duration>,
    /// The vault that was locked, to unlock again with Enter.
    pub locked: Option<Locked>,
    /// A form or confirmation over the views.
    pub dialog: Option<Dialog>,
    pub dialog_view: super::viewport::Viewport,
    /// A confirmed new version waiting for its value from the hidden
    /// prompt, and the storage a new secret is created in.
    pending_value: Option<(String, SetSecretOptions, Option<SecretStorage>)>,
    /// Changes are refused.
    read_only: bool,
    selection_lost: bool,
}

/// A vault the browser locked: its handle and key are gone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Locked {
    pub vault: String,
    /// Locked for being idle, rather than with `L`.
    pub idle: bool,
}

impl App {
    /// A browser with no vault open yet: it starts on the vault list.
    pub fn new(vaults: Vec<VaultEntry>) -> Self {
        let mut app = Self {
            vaults,
            session: None,
            tab: Tab::Vaults,
            lists: Default::default(),
            detail: None,
            versions: TableState::default(),
            editing: false,
            help: false,
            help_view: Default::default(),
            declarations: TableState::default(),
            declaration_page: 1,
            overview_view: Default::default(),
            message: None,
            request: None,
            quit: false,
            lock_after: None,
            locked: None,
            dialog: None,
            dialog_view: Default::default(),
            pending_value: None,
            read_only: false,
            selection_lost: false,
        };
        app.clamp();
        app
    }

    /// Lock the open vault after `after` without a key (`None`: never).
    #[must_use]
    pub fn with_lock_after(mut self, after: Option<Duration>) -> Self {
        self.lock_after = after;
        self
    }

    pub fn lock_after(&self) -> Option<Duration> {
        self.lock_after
    }

    /// Refuse every change (`--read-only`).
    #[must_use]
    pub fn with_read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// How long until the open vault locks, `idle` after the last key;
    /// `None` when nothing would lock.
    pub fn locks_in(&self, idle: Duration) -> Option<Duration> {
        self.session.as_ref()?;
        self.lock_after.map(|after| after.saturating_sub(idle))
    }

    /// Drop the open vault: its handle goes, and with it the vault key,
    /// which is zeroised as it is dropped. What was read goes too.
    pub fn lock(&mut self, idle: bool) {
        let Some(session) = self.session.take() else {
            return;
        };
        let vault = session.vault.name.clone();
        drop(session);
        self.lists = Default::default();
        self.detail = None;
        self.editing = false;
        self.help = false;
        self.dialog = None;
        self.pending_value = None;
        self.message = Some(Message::Info(format!(
            "locked vault '{vault}': its key is wiped from memory"
        )));
        self.locked = Some(Locked { vault, idle });
        self.tab = Tab::Overview;
        self.clamp();
    }

    /// Show `session`: its secrets, or its audit log when it is blocked.
    pub fn set_session(&mut self, session: Session) {
        let blocked = session.is_blocked();
        self.session = Some(session);
        self.lists = Default::default();
        self.detail = None;
        self.editing = false;
        self.message = None;
        self.locked = None;
        self.show(if blocked { Tab::Audit } else { Tab::Overview });
    }

    /// The event loop's answer to [`Request::Open`].
    pub fn opened(&mut self, name: &str, result: Result<Session, String>) {
        match result {
            Ok(session) => {
                self.set_session(session);
                if self.message.is_none() {
                    self.message = Some(Message::Info(format!("opened vault '{name}'")));
                }
            }
            Err(err) => {
                self.message = Some(Message::Error(format!(
                    "could not open vault '{name}': {err}"
                )));
            }
        }
    }

    pub fn set_vaults(&mut self, vaults: Vec<VaultEntry>) {
        let key = self.selected_key(Tab::Vaults);
        self.vaults = vaults;
        self.restore_selection(Tab::Vaults, key);
    }

    pub fn should_quit(&self) -> bool {
        self.quit
    }

    pub fn take_request(&mut self) -> Option<Request> {
        self.request.take()
    }

    pub fn mode(&self) -> Mode {
        if self.help {
            Mode::Help
        } else if self.dialog.is_some() {
            Mode::Dialog
        } else if self.editing {
            Mode::Search
        } else {
            Mode::Normal
        }
    }

    pub fn list(&self, tab: Tab) -> &ListState {
        &self.lists[tab.index()]
    }

    pub fn list_mut(&mut self, tab: Tab) -> &mut ListState {
        &mut self.lists[tab.index()]
    }

    fn query(&self, tab: Tab) -> Query {
        Query::parse(&self.list(tab).query)
    }

    /// Live secrets the Secrets view's filter lets through.
    pub fn shown_secrets(&self) -> Vec<&SecretProperties> {
        let Some(session) = &self.session else {
            return Vec::new();
        };
        let (query, now) = (self.query(Tab::Secrets), timestamp::now());
        session
            .secrets
            .iter()
            .filter(|p| query.secret(p, output::status(p, now), now))
            .collect()
    }

    /// Deleted secrets the Deleted view's filter lets through.
    pub fn shown_deleted(&self) -> Vec<&DeletedSecret> {
        let Some(deleted) = self.session.as_ref().and_then(Session::deleted) else {
            return Vec::new();
        };
        let (query, now) = (self.query(Tab::Deleted), timestamp::now());
        deleted
            .iter()
            .filter(|d| query.secret(&d.properties, "deleted", now))
            .collect()
    }

    /// Audit events the Audit view's filter lets through.
    pub fn shown_events(&self) -> Vec<&AuditEvent> {
        let Some(events) = self.session.as_ref().and_then(Session::audit) else {
            return Vec::new();
        };
        let query = self.query(Tab::Audit);
        events.iter().filter(|e| query.event(e)).collect()
    }

    /// Projects the Projects view's filter lets through.
    pub fn shown_projects(&self) -> Vec<&Project> {
        let Some(session) = &self.session else {
            return Vec::new();
        };
        let query = self.query(Tab::Projects);
        session
            .projects
            .iter()
            .filter(|p| query.vault(&format!("{} {}", p.link.name, p.link.path.display())))
            .collect()
    }

    pub fn shown_vaults(&self) -> Vec<&VaultEntry> {
        let query = self.query(Tab::Vaults);
        self.vaults
            .iter()
            .filter(|v| query.vault(&v.name))
            .collect()
    }

    fn shown_len(&self, tab: Tab) -> usize {
        match tab {
            Tab::Overview => 0,
            Tab::Secrets => self.shown_secrets().len(),
            Tab::Projects => self.shown_projects().len(),
            Tab::Deleted => self.shown_deleted().len(),
            Tab::Audit => self.shown_events().len(),
            Tab::Vaults => self.shown_vaults().len(),
        }
    }

    /// Rows in a view before filtering, when its data is held.
    pub fn total(&self, tab: Tab) -> Option<usize> {
        let session = self.session.as_ref();
        let readable = session.filter(|s| !s.is_blocked());
        match tab {
            Tab::Overview => None,
            Tab::Secrets => readable.map(|s| s.secrets.len()),
            Tab::Projects => readable.map(|s| s.projects.len()),
            Tab::Deleted => readable.and_then(Session::deleted).map(<[_]>::len),
            Tab::Audit => session.and_then(Session::audit).map(<[_]>::len),
            Tab::Vaults => Some(self.vaults.len()),
        }
    }

    fn selected_index(&self) -> Option<usize> {
        self.list(self.tab).table.selected()
    }

    pub fn selected_secret(&self) -> Option<&SecretProperties> {
        self.selected_index()
            .and_then(|i| self.shown_secrets().get(i).copied())
    }

    pub fn selected_deleted(&self) -> Option<&DeletedSecret> {
        self.selected_index()
            .and_then(|i| self.shown_deleted().get(i).copied())
    }

    pub fn selected_project(&self) -> Option<&Project> {
        self.selected_index()
            .and_then(|i| self.shown_projects().get(i).copied())
    }

    /// The project whose details are shown.
    pub fn project_detail(&self) -> Option<&Project> {
        let id = self
            .detail
            .as_deref()
            .filter(|_| self.tab == Tab::Projects)?;
        self.session
            .as_ref()?
            .projects
            .iter()
            .find(|p| p.link.id == id)
    }

    pub fn selected_vault(&self) -> Option<&VaultEntry> {
        self.selected_index()
            .and_then(|i| self.shown_vaults().get(i).copied())
    }

    pub fn update(&mut self, action: Action) {
        if self.help {
            match action {
                Action::Help | Action::Back => self.help = false,
                Action::Quit => self.quit = true,
                action => self.help_view.move_by(action),
            }
            return;
        }
        if self.dialog.is_some()
            && matches!(
                action,
                Action::PageUp | Action::PageDown | Action::Top | Action::Bottom
            )
        {
            self.dialog_view.move_by(action);
            return;
        }
        if let Some(dialog) = self.dialog.take() {
            self.dialog = self.update_dialog(dialog, action);
            return;
        }
        self.dialog_view = Default::default();
        match action {
            Action::Quit => self.quit = true,
            Action::Help => self.help = true,
            Action::Toggle => self.start_toggle(),
            Action::Edit => self.start_edit(),
            Action::NewVersion if self.tab == Tab::Vaults => self.start_setup(None),
            Action::NewVersion => self.start_new_version(),
            Action::Add => self.start_add(),
            Action::Delete => self.start_delete(),
            Action::Recover => self.start_recover(),
            Action::ChangeVault => {
                let name = match self.tab {
                    Tab::Vaults => self.selected_vault().map(|v| v.name.clone()),
                    _ => self.session.as_ref().map(|s| s.vault.name.clone()),
                };
                if let Some(name) = name {
                    self.start_setup(Some(name));
                }
            }
            Action::Unlink => self.start_unlink(),
            Action::Back => self.back(),
            Action::Search => {
                self.detail = None;
                self.editing = true;
            }
            Action::Input(c) => {
                let key = self.selected_key(self.tab);
                self.list_mut(self.tab).query.push(c);
                self.restore_selection(self.tab, key);
            }
            Action::Erase => {
                let key = self.selected_key(self.tab);
                self.list_mut(self.tab).query.pop();
                self.restore_selection(self.tab, key);
            }
            Action::Commit => self.editing = false,
            Action::NextTab => self.show(Tab::ALL[(self.tab.index() + 1) % Tab::ALL.len()]),
            Action::PrevTab => {
                self.show(Tab::ALL[(self.tab.index() + Tab::ALL.len() - 1) % Tab::ALL.len()]);
            }
            Action::Show(tab) => self.show(tab),
            Action::Open => self.open(),
            Action::Refresh => self.refresh(),
            Action::Verify => self.verify(),
            Action::Lock => self.lock(false),
            Action::Up
            | Action::Down
            | Action::PageUp
            | Action::PageDown
            | Action::Top
            | Action::Bottom => self.move_by(action),
        }
    }

    fn move_by(&mut self, action: Action) {
        if self.tab == Tab::Overview {
            self.overview_view.borrow_mut().move_by(action);
            return;
        }
        let page = if self.tab == Tab::Projects && self.detail.is_some() {
            self.declaration_page
        } else {
            self.list(self.tab).page
        }
        .max(1);
        let (table, len) = if self.tab == Tab::Projects && self.detail.is_some() {
            let len = self.project_detail().map_or(0, |p| p.secrets().len());
            (&mut self.declarations, len)
        } else if let Some(name) = &self.detail {
            let len = self
                .session
                .as_ref()
                .and_then(|s| s.detail(name))
                .and_then(|d| d.versions.as_ref())
                .map_or(0, Vec::len);
            (&mut self.versions, len)
        } else {
            let len = self.shown_len(self.tab);
            (&mut self.lists[self.tab.index()].table, len)
        };
        let current = table.selected().unwrap_or(0);
        let target = match action {
            Action::Down if table.selected().is_none() => 0,
            Action::Up => current.saturating_sub(1),
            Action::Down => current.saturating_add(1),
            Action::PageUp => current.saturating_sub(page),
            Action::PageDown => current.saturating_add(page),
            Action::Bottom => usize::MAX,
            _ => 0,
        };
        table.select(len.checked_sub(1).map(|last| target.min(last)));
    }

    /// Select row `index` of the current view, clamped to what it shows.
    fn select(&mut self, index: usize) {
        let last = self.shown_len(self.tab).checked_sub(1);
        self.list_mut(self.tab)
            .table
            .select(last.map(|last| index.min(last)));
    }

    /// Keep the selection inside the current view.
    fn clamp(&mut self) {
        if !self.list(self.tab).initialized {
            self.select(0);
            self.list_mut(self.tab).initialized = true;
        } else if let Some(current) = self.selected_index() {
            if current >= self.shown_len(self.tab) {
                self.list_mut(self.tab).table.select(None);
            }
        }
    }

    /// Full cached identities, never rendered/abbreviated labels.
    fn row_keys(&self, tab: Tab) -> Vec<String> {
        match tab {
            Tab::Overview => Vec::new(),
            Tab::Secrets => self
                .shown_secrets()
                .iter()
                .map(|p| format!("{}\0{}", p.vault, p.name))
                .collect(),
            Tab::Deleted => self
                .shown_deleted()
                .iter()
                .map(|d| format!("{}\0{}", d.properties.vault, d.properties.name))
                .collect(),
            Tab::Projects => self
                .shown_projects()
                .iter()
                .map(|p| p.link.id.clone())
                .collect(),
            Tab::Audit => self
                .shown_events()
                .iter()
                .map(|e| e.id.to_string())
                .collect(),
            Tab::Vaults => self
                .shown_vaults()
                .iter()
                .map(|v| format!("{}\0{}", v.name, v.path.display()))
                .collect(),
        }
    }

    fn selected_key(&self, tab: Tab) -> Option<String> {
        self.row_keys(tab)
            .get(self.list(tab).table.selected()?)
            .cloned()
    }

    fn restore_selection(&mut self, tab: Tab, key: Option<String>) {
        let index = key
            .as_ref()
            .and_then(|key| self.row_keys(tab).iter().position(|k| k == key));
        if key.is_some() && index.is_none() {
            self.selection_lost = true;
            self.message = Some(Message::Info("Selection cleared: the selected object is no longer visible; navigate to select a target.".into()));
        }
        self.list_mut(tab).table.select(index);
    }

    fn show(&mut self, tab: Tab) {
        self.tab = tab;
        self.detail = None;
        self.editing = false;
        self.load_view();
        if let Some(key) = self.list_mut(tab).pending_selection.take() {
            self.restore_selection(tab, Some(key));
        }
        self.clamp();
    }

    /// Read what the current view shows, if it is not held yet.
    fn load_view(&mut self) {
        let Some(session) = &mut self.session else {
            return;
        };
        let loaded = match self.tab {
            Tab::Overview => session
                .load_deleted()
                .and_then(|()| session.load_audit())
                .and_then(|()| session.load_keys())
                .and_then(|()| match session.verification() {
                    Some(_) => Ok(()),
                    None => session.verify().map(|_| ()),
                }),
            Tab::Deleted => session.load_deleted(),
            Tab::Audit => session.load_audit(),
            // The projects are read with the vault.
            Tab::Secrets | Tab::Projects | Tab::Vaults => Ok(()),
        };
        if let Err(err) = loaded {
            self.message = Some(failure("reading the vault failed", &err));
        }
    }

    fn open(&mut self) {
        if self.session.is_none() && self.tab != Tab::Vaults {
            if let Some(locked) = &self.locked {
                self.request = Some(Request::Open(locked.vault.clone()));
            }
            return;
        }
        match self.tab {
            Tab::Vaults => {
                let Some(name) = self.selected_vault().map(|v| v.name.clone()) else {
                    return;
                };
                let current = self.session.as_ref().map(|s| s.vault.name.as_str());
                if current == Some(name.as_str()) {
                    let blocked = self.session.as_ref().is_some_and(Session::is_blocked);
                    self.show(if blocked { Tab::Audit } else { Tab::Overview });
                } else {
                    self.request = Some(Request::Open(name));
                }
            }
            Tab::Secrets => {
                if let Some(name) = self.selected_secret().map(|p| p.name.clone()) {
                    self.open_detail(name, true);
                }
            }
            Tab::Deleted => {
                if let Some(name) = self.selected_deleted().map(|d| d.properties.name.clone()) {
                    self.open_detail(name, false);
                }
            }
            Tab::Projects => {
                // Its manifest's secrets were read with the vault.
                if let Some(id) = self.selected_project().map(|p| p.link.id.clone()) {
                    self.detail = Some(id);
                    self.declarations = TableState::default().with_selected(Some(0));
                }
            }
            Tab::Overview | Tab::Audit => {}
        }
    }

    /// Check the audit chain again and say what was found.
    fn verify(&mut self) {
        let Some(session) = &mut self.session else {
            return;
        };
        self.message = Some(match session.verify() {
            Ok(v) if v.result.is_intact() => Message::Info(format!(
                "audit chain intact: {} rows, {} written before unlock",
                v.result.rows, v.result.unkeyed
            )),
            Ok(_) => Message::Error(
                "audit chain is not intact: see the overview, and run \
                 `sourceorrery audit --verify`"
                    .to_owned(),
            ),
            Err(err) => failure("verifying the audit chain failed", &err),
        });
    }

    fn open_detail(&mut self, name: String, live: bool) {
        let Some(session) = &mut self.session else {
            return;
        };
        match session.load_detail(&name, live) {
            Ok(()) => {
                self.detail = Some(name);
                self.versions = TableState::default().with_selected(Some(0));
            }
            Err(err) => self.message = Some(failure(&format!("reading '{name}' failed"), &err)),
        }
    }

    fn back(&mut self) {
        let key = self.selected_key(self.tab);
        if self.editing {
            self.editing = false;
            self.list_mut(self.tab).query.clear();
            self.restore_selection(self.tab, key);
        } else if self.detail.is_some() {
            self.detail = None;
        } else if !self.list(self.tab).query.is_empty() {
            self.list_mut(self.tab).query.clear();
            self.restore_selection(self.tab, key);
        }
    }

    fn refresh(&mut self) {
        if self.tab == Tab::Vaults {
            self.request = Some(Request::ListVaults);
            return;
        }
        match self.reread() {
            Ok(name) if !self.selection_lost => {
                self.message = Some(Message::Info(format!("reloaded vault '{name}'")))
            }
            Ok(_) => {}
            Err(err) => {
                self.message = Some(failure(
                    "refresh failed; showing what was read before",
                    &err,
                ));
            }
        }
    }

    /// Read the vault again: the list, the current view, the open details
    /// (with the same version selected). Returns the vault's name.
    fn reread(&mut self) -> Result<String, SecretError> {
        let keys = Tab::ALL.map(|tab| self.selected_key(tab));
        let version = self
            .target_version()
            .filter(|_| self.detail.is_some())
            .map(|p| p.version);
        self.selection_lost = false;
        let Some(session) = &mut self.session else {
            return Ok(String::new());
        };
        session.reload()?;
        let name = session.vault.name.clone();
        self.load_view();
        for (tab, key) in Tab::ALL.into_iter().zip(keys) {
            if self.total(tab).is_none() && matches!(tab, Tab::Audit | Tab::Deleted) {
                self.list_mut(tab).pending_selection = key;
            } else {
                self.restore_selection(tab, key);
            }
        }
        if let Some(detail) = self.detail.take() {
            if self.tab == Tab::Projects {
                let session = self.session.as_ref();
                if session.is_some_and(|s| s.projects.iter().any(|p| p.link.id == detail)) {
                    self.detail = Some(detail);
                }
                self.clamp();
                return Ok(name);
            }
            let live = self.tab == Tab::Secrets;
            let still_there = match self.tab {
                Tab::Secrets => self.shown_secrets().iter().any(|p| p.name == detail),
                _ => self
                    .shown_deleted()
                    .iter()
                    .any(|d| d.properties.name == detail),
            };
            if still_there {
                self.open_detail(detail, live);
                let index = version.as_ref().and_then(|id| {
                    self.session
                        .as_ref()?
                        .detail(self.detail.as_deref()?)?
                        .versions
                        .as_ref()?
                        .iter()
                        .position(|p| p.version == *id)
                });
                self.versions.select(index);
                if version.is_some() && index.is_none() {
                    self.selection_lost = true;
                    self.message = Some(Message::Info("Selection cleared: the selected version disappeared; navigate to select a target.".into()));
                }
            }
        }
        self.clamp();
        Ok(name)
    }

    // --- changes ----------------------------------------------------------

    /// May this browser change the vault now? Says why not.
    fn can_change(&mut self) -> bool {
        let why = if self.read_only {
            Some(
                "this browser is read-only (--read-only); change secrets with `sourceorrery secret`",
            )
        } else if self.session.is_none() {
            Some("no vault is open")
        } else if self.session.as_ref().is_some_and(Session::is_blocked) {
            Some(
                "the vault is blocked: nothing can change until `sourceorrery audit --acknowledge`",
            )
        } else {
            None
        };
        if let Some(why) = why {
            self.message = Some(Message::Error(why.to_owned()));
        }
        why.is_none()
    }

    /// The version a change applies to: the one selected in the details,
    /// else the newest version of the secret selected in the list.
    fn target_version(&self) -> Option<SecretProperties> {
        if self.tab != Tab::Secrets {
            return None;
        }
        match &self.detail {
            Some(name) => self
                .session
                .as_ref()?
                .detail(name)?
                .versions
                .as_ref()?
                .get(self.versions.selected()?)
                .cloned(),
            None => self.selected_secret().cloned(),
        }
    }

    /// Where `name` is kept, as a form checks a change against it.
    fn kept(&self, name: &str) -> Kept {
        let Some(session) = &self.session else {
            return Kept::default();
        };
        Kept {
            place: session.connection_of(name).map_or_else(
                || "the vault".to_owned(),
                |c| c.settings.provider().display_name().to_owned(),
            ),
            capabilities: session.capabilities_of(name).unwrap_or(Capability::ALL),
        }
    }

    /// `p` is the newest version of its secret.
    fn is_newest(&self, p: &SecretProperties) -> bool {
        self.session.as_ref().is_some_and(|s| {
            s.secrets
                .iter()
                .any(|newest| newest.name == p.name && newest.version == p.version)
        })
    }

    fn start_toggle(&mut self) {
        let Some(p) = self.target_version() else {
            return;
        };
        let kept = self.kept(&p.name);
        if !self.is_newest(&p)
            && !kept
                .capabilities
                .contains(&Capability::PerVersionProperties)
        {
            self.message = Some(Message::Error(format!(
                "{} keeps `enabled` for the whole secret, not per version: switch the newest \
                 version",
                kept.place
            )));
            return;
        }
        if self.can_change() {
            self.dialog = Some(Dialog::Confirm(Confirm::toggle(&p)));
        }
    }

    fn start_edit(&mut self) {
        if let Some(p) = self.target_version()
            && self.can_change()
        {
            let form = Form::edit(&p).kept_in(self.kept(&p.name), self.is_newest(&p));
            self.dialog = Some(Dialog::Form(form));
        }
    }

    fn start_new_version(&mut self) {
        let name = self.target_version().map(|p| p.name);
        let newest = name.and_then(|name| {
            self.session
                .as_ref()?
                .secrets
                .iter()
                .find(|p| p.name == name)
                .cloned()
        });
        if let Some(newest) = newest
            && self.can_change()
        {
            let form = Form::new_version(&newest).kept_in(self.kept(&newest.name), true);
            self.dialog = Some(Dialog::Form(form));
        }
    }

    fn start_add(&mut self) {
        if !matches!(self.tab, Tab::Overview | Tab::Secrets) || !self.can_change() {
            return;
        }
        let Some(session) = &self.session else {
            return;
        };
        let live = session.secrets.iter().map(|p| p.name.clone()).collect();
        let deleted = session
            .deleted()
            .unwrap_or_default()
            .iter()
            .map(|d| d.properties.name.clone())
            .collect();
        // The vault file, then each connection, as the vault lists them.
        let mut storages = vec![StorageChoice {
            label: "SourceOrrery vault".to_owned(),
            storage: SecretStorage::Vault,
            kept: Kept::default(),
        }];
        storages.extend(session.connections.iter().map(|c| {
            let provider = c.settings.provider();
            StorageChoice {
                label: provider.display_name().to_owned(),
                storage: SecretStorage::Connection(c.id.clone()),
                kept: Kept {
                    place: provider.display_name().to_owned(),
                    capabilities: provider.capabilities(),
                },
            }
        }));
        let form = Form::add(live, deleted).storing_in(storages);
        self.dialog = Some(Dialog::Form(form));
    }

    fn start_delete(&mut self) {
        if self.tab != Tab::Secrets {
            return;
        }
        let name = self
            .detail
            .clone()
            .or_else(|| self.selected_secret().map(|p| p.name.clone()));
        if let Some(name) = name
            && self.can_change()
            && let Some(session) = &self.session
        {
            let vault = &session.vault;
            let purgeable = vault.recovery_level == sourceorrery_core::RecoveryLevel::Purgeable;
            self.dialog = Some(Dialog::Confirm(Confirm::delete(
                &name,
                purgeable,
                vault.retention_days,
                timestamp::now(),
            )));
        }
    }

    fn start_unlink(&mut self) {
        if self.tab != Tab::Projects {
            return;
        }
        let project = self.project_detail().or_else(|| self.selected_project());
        let Some(project) = project.cloned() else {
            return;
        };
        if project.status != ProjectStatus::Missing {
            self.message = Some(Message::Error(format!(
                "project '{}' is still there: only a project whose folder or manifest is gone \
                 is forgotten here",
                output::sanitize(&project.link.name)
            )));
            return;
        }
        if self.can_change() {
            self.dialog = Some(Dialog::Confirm(Confirm::unlink(&project.link)));
        }
    }

    /// The setup screens, for a new vault or the vault `name`.
    fn start_setup(&mut self, name: Option<String>) {
        if self.read_only {
            self.message = Some(Message::Error(
                "this browser is read-only (--read-only); change vaults with `sourceorrery \
                 setup`"
                    .to_owned(),
            ));
            return;
        }
        self.request = Some(Request::Setup(name));
    }

    /// The event loop's answer to [`Request::Setup`]: the vault the setup
    /// screens created or changed, if they did. The vault list is read
    /// again by then; the open vault, when it is the one changed, is read
    /// again here.
    pub fn set_up(&mut self, result: Result<Option<String>, String>) {
        match result {
            Ok(None) => {}
            Ok(Some(name)) => {
                let open = self.session.as_ref().map(|s| s.vault.name.clone());
                if open.as_deref() == Some(name.as_str()) {
                    self.after_change(Ok(format!("changed vault '{name}'")));
                } else {
                    self.message = Some(Message::Info(format!(
                        "set up vault '{name}': Enter on it in Vaults opens it"
                    )));
                    if self.tab == Tab::Vaults
                        && let Some(i) = self.shown_vaults().iter().position(|v| v.name == name)
                    {
                        self.select(i);
                    }
                }
            }
            Err(err) => {
                self.message = Some(Message::Error(format!("the setup screens failed: {err}")));
            }
        }
    }

    fn start_recover(&mut self) {
        if self.tab != Tab::Deleted {
            return;
        }
        let name = self
            .detail
            .clone()
            .or_else(|| self.selected_deleted().map(|d| d.properties.name.clone()));
        if let Some(name) = name
            && self.can_change()
        {
            self.dialog = Some(Dialog::Confirm(Confirm::recover(&name)));
        }
    }

    /// One key in an open dialog. Returns the dialog if it stays open.
    fn update_dialog(&mut self, dialog: Dialog, action: Action) -> Option<Dialog> {
        match (dialog, action) {
            (_, Action::Back) => None,
            (dialog, Action::Quit) => {
                self.quit = true;
                Some(dialog)
            }
            (Dialog::Form(mut form), action) => {
                match action {
                    Action::Up | Action::PrevTab => form.prev(),
                    Action::Down | Action::NextTab => form.next(),
                    Action::Input(c) => form.input(c),
                    Action::Erase => form.erase(),
                    Action::Commit => {
                        return match form.submit(timestamp::now()) {
                            Ok(confirm) => {
                                self.dialog_view = Default::default();
                                Some(Dialog::Confirm(confirm))
                            }
                            Err(err) => {
                                form.error = Some(err);
                                Some(Dialog::Form(form))
                            }
                        };
                    }
                    _ => {}
                }
                Some(Dialog::Form(form))
            }
            (Dialog::Confirm(mut confirm), action) => {
                match action {
                    Action::Input(c) => confirm.input(c),
                    Action::Erase => confirm.erase(),
                    Action::Commit => match confirm.ready() {
                        Ok(()) => {
                            self.carry_out(confirm.change);
                            return None;
                        }
                        Err(err) => confirm.error = Some(err),
                    },
                    _ => {}
                }
                Some(Dialog::Confirm(confirm))
            }
        }
    }

    /// Make a confirmed change, then read the vault again.
    fn carry_out(&mut self, change: Change) {
        if !self.can_change() {
            return;
        }
        if !self.change_target_exists(&change) {
            self.message = Some(Message::Error("The confirmed target is no longer available. Reopen the action and review it again.".into()));
            return;
        }
        let Some(session) = &self.session else {
            return;
        };
        let editor = session.editor();
        let done = match change {
            Change::AddVersion {
                name,
                options,
                storage,
            } => {
                // The value comes from the hidden prompt, outside the screen.
                self.request = Some(Request::ReadValue(name.clone()));
                self.pending_value = Some((name, options, storage));
                return;
            }
            Change::Unlink { id, name } => editor
                .unlink_project(&id)
                .map(|()| format!("forgot project '{}'", output::sanitize(&name))),
            Change::Update {
                name,
                version,
                update,
            } => {
                let enabled = update.enabled;
                editor.update(&name, &version, update).map(|p| {
                    let what = match enabled {
                        Some(true) => "enabled",
                        Some(false) => "disabled",
                        None => "changed",
                    };
                    format!("{what} version {} of '{name}'", short(&p.version))
                })
            }
            Change::Delete { name } => editor.delete(&name).map(|d| {
                if d.recovery_id.is_empty() {
                    format!("deleted '{name}' for good")
                } else {
                    format!("deleted '{name}'; recoverable with u on the Deleted view")
                }
            }),
            Change::Recover { name } => {
                editor.recover(&name).map(|_| format!("recovered '{name}'"))
            }
        };
        self.after_change(done);
    }

    fn change_target_exists(&self, change: &Change) -> bool {
        let Some(s) = &self.session else {
            return false;
        };
        match change {
            Change::Update { name, version, .. } => s
                .secrets
                .iter()
                .chain(
                    s.detail(name)
                        .and_then(|d| d.versions.as_ref())
                        .into_iter()
                        .flatten(),
                )
                .any(|p| p.name == *name && p.version == *version),
            Change::Delete { name } => s.secrets.iter().any(|p| p.name == *name),
            Change::Recover { name } => s
                .deleted()
                .unwrap_or_default()
                .iter()
                .any(|p| p.properties.name == *name),
            Change::Unlink { id, .. } => s
                .projects
                .iter()
                .any(|p| p.link.id == *id && p.status == ProjectStatus::Missing),
            Change::AddVersion { name, storage, .. } => {
                if storage.is_some() {
                    !s.secrets.iter().any(|p| p.name == *name)
                } else {
                    s.secrets.iter().any(|p| p.name == *name)
                }
            }
        }
    }

    /// The event loop's answer to [`Request::ReadValue`]: the value read at
    /// the hidden prompt, which goes straight to the vault and is dropped
    /// (and zeroised) there. The browser keeps nothing of it.
    pub fn write_version(&mut self, value: Result<SecretBytes, String>) {
        let Some((name, options, storage)) = self.pending_value.take() else {
            return;
        };
        let value = match value {
            Ok(value) => value,
            Err(why) => {
                self.message = Some(Message::Error(format!(
                    "nothing stored for '{name}': {why}"
                )));
                return;
            }
        };
        let Some(session) = &self.session else {
            return;
        };
        let editor = session.editor();
        let done = match &storage {
            Some(storage) => editor.add_secret(&name, value, options, storage),
            None => editor.add_version(&name, value, options),
        }
        .map(|p| format!("stored version {} of '{name}'", short(&p.version)));
        let stored = done.is_ok();
        self.after_change(done);
        if stored
            && self.detail.is_none()
            && self.tab == Tab::Secrets
            && let Some(i) = self.shown_secrets().iter().position(|p| p.name == name)
        {
            self.select(i);
        }
    }

    fn after_change(&mut self, done: Result<String, SecretError>) {
        match done {
            Ok(done) => {
                self.message = Some(match self.reread() {
                    Ok(_) => Message::Info(done),
                    Err(err) => {
                        failure(&format!("{done}, but reading the vault again failed"), &err)
                    }
                });
            }
            Err(err) => self.message = Some(failure("the vault refused the change", &err)),
        }
    }
}

fn failure(what: &str, err: &SecretError) -> Message {
    Message::Error(format!("{what} ({}): {err}", err.code()))
}

fn short(version: &str) -> String {
    version.chars().take(8).collect()
}

#[cfg(test)]
pub mod tests {
    use std::rc::Rc;
    use std::time::Duration;

    use super::super::fake::Fake;
    use super::*;

    /// A browser on the fake vault, where a user lands: the overview.
    pub fn app_with(fake: &Rc<Fake>) -> App {
        let mut app = App::new(Fake::vault_entries());
        app.set_session(Session::open(Box::new(Rc::clone(fake))).unwrap());
        app
    }

    /// The same, moved to the secret list.
    fn on_secrets(fake: &Rc<Fake>) -> App {
        let mut app = app_with(fake);
        app.update(Action::Show(Tab::Secrets));
        app
    }

    fn selected(app: &App) -> Option<String> {
        match app.tab {
            Tab::Secrets => app.selected_secret().map(|p| p.name.clone()),
            Tab::Deleted => app.selected_deleted().map(|d| d.properties.name.clone()),
            Tab::Vaults => app.selected_vault().map(|v| v.name.clone()),
            Tab::Projects => app.selected_project().map(|p| p.link.name.clone()),
            Tab::Overview | Tab::Audit => None,
        }
    }

    fn type_text(app: &mut App, text: &str) {
        app.update(Action::Search);
        for c in text.chars() {
            app.update(Action::Input(c));
        }
    }

    #[test]
    fn refresh_preserves_full_version_identity_and_removal_clears_target() {
        let fake = Fake::with(&["a", "b"]);
        let mut app = on_secrets(&fake);
        app.update(Action::Open);
        app.update(Action::Down);
        let id = app.target_version().unwrap().version;
        *fake.version_ids.borrow_mut() = Some(vec![
            "new-version".into(),
            "0123456789abcdef0123456789abcdef".into(),
            id.clone(),
        ]);
        app.update(Action::Refresh);
        assert_eq!(app.target_version().unwrap().version, id);
        assert_eq!(app.versions.selected(), Some(2));
        *fake.version_ids.borrow_mut() = Some(vec!["new-version".into()]);
        app.update(Action::Refresh);
        assert_eq!(app.versions.selected(), None);
        app.update(Action::Edit);
        app.update(Action::Toggle);
        assert!(app.dialog.is_none());
        assert!(fake.writes.borrow().is_empty());
    }

    #[test]
    fn reordering_and_filtering_use_identity_and_never_pick_a_neighbour() {
        let fake = Fake::with(&["alpha-key", "bravo-key", "charlie-key"]);
        let mut app = on_secrets(&fake);
        app.update(Action::Down);
        *fake.names.borrow_mut() = vec!["charlie-key", "alpha-key", "bravo-key"];
        app.update(Action::Refresh);
        assert_eq!(selected(&app).as_deref(), Some("bravo-key"));
        let reads = fake.lists.get();
        type_text(&mut app, "alpha");
        assert_eq!(selected(&app), None);
        app.update(Action::Commit);
        app.update(Action::Edit);
        app.clamp();
        assert_eq!(selected(&app), None);
        assert!(app.dialog.is_none());
        app.update(Action::Down);
        assert_eq!(selected(&app).as_deref(), Some("alpha-key"));
        assert_eq!(fake.lists.get(), reads);
    }

    #[test]
    fn confirmation_rechecks_its_typed_target_without_reading() {
        let fake = Fake::with(&["a"]);
        let mut app = on_secrets(&fake);
        app.update(Action::Toggle);
        app.session.as_mut().unwrap().secrets.clear();
        let reads = fake.lists.get();
        app.update(Action::Commit);
        assert!(fake.writes.borrow().is_empty());
        assert_eq!(fake.lists.get(), reads);
        assert!(matches!(app.message, Some(Message::Error(_))));
    }

    #[test]
    fn without_a_vault_it_starts_on_the_vault_list() {
        let app = App::new(Fake::vault_entries());
        assert_eq!(app.tab, Tab::Vaults);
        assert_eq!(selected(&app).as_deref(), Some("development"));
        assert_eq!(app.shown_secrets().len(), 0);
    }

    #[test]
    fn a_vault_opens_on_the_overview_which_reads_what_it_shows_once() {
        let fake = Fake::with(&["a", "b"]);
        fake.deleted_names.borrow_mut().push("old");
        let mut app = app_with(&fake);
        assert_eq!(app.tab, Tab::Overview);
        // secrets and the deleted list (audited), the log and the chain (not)
        assert_eq!((fake.lists.get(), fake.inspects.get()), (2, 0));
        assert_eq!((fake.audit_reads.get(), fake.verifies.get()), (1, 1));
        let session = app.session.as_ref().unwrap();
        assert!(session.verification().is_some() && session.keys().is_some());

        for tab in Tab::ALL {
            app.update(Action::Show(tab));
        }
        app.update(Action::Show(Tab::Overview));
        assert_eq!(
            (
                fake.lists.get(),
                fake.audit_reads.get(),
                fake.verifies.get()
            ),
            (2, 1, 1)
        );
    }

    #[test]
    fn movement_stays_inside_the_list() {
        let fake = Fake::with(&["a", "b", "c"]);
        let mut app = on_secrets(&fake);
        assert_eq!(selected(&app).as_deref(), Some("a"));
        app.update(Action::Up);
        assert_eq!(selected(&app).as_deref(), Some("a"));
        for _ in 0..3 {
            app.update(Action::Down);
        }
        assert_eq!(selected(&app).as_deref(), Some("c"));
        app.update(Action::Top);
        assert_eq!(selected(&app).as_deref(), Some("a"));
        app.update(Action::Bottom);
        assert_eq!(selected(&app).as_deref(), Some("c"));
    }

    #[test]
    fn pages_move_by_the_rows_on_screen() {
        let fake = Fake::with(&["a", "b", "c", "d", "e", "f", "g"]);
        let mut app = on_secrets(&fake);
        app.list_mut(Tab::Secrets).page = 3;
        app.update(Action::PageDown);
        assert_eq!(selected(&app).as_deref(), Some("d"));
        app.update(Action::PageDown);
        app.update(Action::PageDown);
        assert_eq!(selected(&app).as_deref(), Some("g"));
        app.update(Action::PageUp);
        assert_eq!(selected(&app).as_deref(), Some("d"));
    }

    #[test]
    fn an_empty_vault_selects_nothing() {
        let fake = Fake::with(&[]);
        let mut app = on_secrets(&fake);
        for action in [Action::Down, Action::Bottom, Action::PageDown, Action::Open] {
            app.update(action);
            assert_eq!(app.list(Tab::Secrets).table.selected(), None);
            assert_eq!(app.detail, None);
        }
    }

    #[test]
    fn the_deleted_list_is_read_once_whichever_view_reads_it_first() {
        let fake = Fake::with(&["a", "b"]);
        fake.deleted_names.borrow_mut().push("old");
        let mut app = app_with(&fake);
        app.update(Action::Show(Tab::Deleted));
        assert_eq!(selected(&app).as_deref(), Some("old"));
        assert_eq!(app.total(Tab::Deleted), Some(1));
        app.update(Action::Show(Tab::Secrets));
        app.update(Action::Show(Tab::Deleted));
        assert_eq!(fake.lists.get(), 2, "nothing is read twice");
    }

    #[test]
    fn details_read_versions_once_per_secret() {
        let fake = Fake::with(&["a", "b"]);
        let mut app = on_secrets(&fake);
        app.update(Action::Open);
        assert_eq!(app.detail.as_deref(), Some("a"));
        assert_eq!(fake.inspects.get(), 1);
        let detail = app.session.as_ref().unwrap().detail("a").unwrap();
        assert_eq!(detail.versions.as_ref().map(Vec::len), Some(2));

        app.update(Action::Down);
        assert_eq!(
            app.versions.selected(),
            Some(1),
            "movement scrolls the versions"
        );
        app.update(Action::Back);
        assert_eq!(app.detail, None);
        app.update(Action::Open);
        assert_eq!(fake.inspects.get(), 1, "held, not read again");
        app.update(Action::Back);
        app.update(Action::Down);
        app.update(Action::Open);
        assert_eq!(app.detail.as_deref(), Some("b"));
        assert_eq!(fake.inspects.get(), 2);
    }

    #[test]
    fn a_deleted_secret_shows_its_activity_without_reading_versions() {
        let fake = Fake::with(&["a"]);
        fake.deleted_names.borrow_mut().push("old");
        let mut app = app_with(&fake);
        app.update(Action::Show(Tab::Deleted));
        app.update(Action::Open);
        assert_eq!(app.detail.as_deref(), Some("old"));
        assert_eq!(fake.inspects.get(), 0);
        let detail = app.session.as_ref().unwrap().detail("old").unwrap();
        assert!(detail.versions.is_none());
    }

    #[test]
    fn search_filters_the_current_view_and_esc_clears_it() {
        let fake = Fake::with(&["api-key", "database-password", "db-url"]);
        let mut app = on_secrets(&fake);
        type_text(&mut app, "db");
        assert_eq!(app.mode(), Mode::Search);
        assert_eq!(app.shown_secrets().len(), 1, "only db-url contains 'db'");
        app.update(Action::Erase);
        app.update(Action::Erase);
        type_text(&mut app, "p");
        assert_eq!(
            app.shown_secrets().len(),
            2,
            "api-key and database-password"
        );
        app.update(Action::Commit);
        assert_eq!(app.mode(), Mode::Normal);
        app.update(Action::Down);
        assert_eq!(selected(&app).as_deref(), Some("api-key"));
        app.update(Action::Back);
        assert_eq!(app.shown_secrets().len(), 3, "Esc clears the filter");
        assert_eq!(fake.lists.get(), 2, "searching reads nothing");
    }

    #[test]
    fn each_view_keeps_its_own_filter() {
        let fake = Fake::with(&["api-key", "db-url"]);
        let mut app = on_secrets(&fake);
        type_text(&mut app, "api");
        app.update(Action::Commit);
        app.update(Action::Show(Tab::Audit));
        assert_eq!(app.list(Tab::Audit).query, "");
        app.update(Action::Show(Tab::Secrets));
        assert_eq!(app.list(Tab::Secrets).query, "api");
    }

    #[test]
    fn opening_another_vault_is_a_request_for_the_event_loop() {
        let fake = Fake::with(&["a"]);
        let mut app = app_with(&fake);
        app.update(Action::Show(Tab::Vaults));
        assert_eq!(selected(&app).as_deref(), Some("development"));
        app.update(Action::Open);
        assert_eq!(app.take_request(), None, "it is already open");
        assert_eq!(app.tab, Tab::Overview);

        app.update(Action::Show(Tab::Vaults));
        app.update(Action::Down);
        app.update(Action::Open);
        assert_eq!(app.take_request(), Some(Request::Open("staging".into())));
        app.opened("staging", Err("locked: wrong passphrase".into()));
        let Some(Message::Error(text)) = &app.message else {
            panic!("{:?}", app.message);
        };
        assert!(text.contains("could not open vault 'staging'"), "{text}");
        assert_eq!(app.session.as_ref().unwrap().vault.name, "development");

        app.update(Action::Refresh);
        assert_eq!(app.take_request(), Some(Request::ListVaults));
    }

    #[test]
    fn a_blocked_vault_shows_only_its_audit_log_and_reads_no_secrets() {
        let fake = Fake::with(&["a"]);
        fake.blocked.set(true);
        let mut app = app_with(&fake);
        assert_eq!(app.tab, Tab::Audit);
        assert!(app.session.as_ref().is_some_and(Session::is_blocked));
        for tab in Tab::ALL {
            app.update(Action::Show(tab));
            app.update(Action::Open);
            app.update(Action::Back);
        }
        app.update(Action::Show(Tab::Secrets));
        app.update(Action::Refresh);
        assert_eq!((fake.lists.get(), fake.inspects.get()), (0, 0));
        assert_eq!(app.shown_secrets().len(), 0);
    }

    #[test]
    fn a_refresh_reads_again_and_keeps_open_details() {
        let fake = Fake::with(&["b", "c"]);
        let mut app = on_secrets(&fake);
        app.update(Action::Down);
        app.update(Action::Open);
        fake.names.borrow_mut().insert(0, "a");
        app.update(Action::Refresh);
        assert_eq!(
            fake.lists.get(),
            3,
            "opening read two lists, the refresh one more"
        );
        assert_eq!(fake.inspects.get(), 2, "the open details are read again");
        assert_eq!(app.detail.as_deref(), Some("c"));
        assert_eq!(
            app.message,
            Some(Message::Info("reloaded vault 'development'".into()))
        );

        fake.names.borrow_mut().retain(|n| *n != "c");
        app.update(Action::Refresh);
        assert_eq!(app.detail, None, "gone: details close");
    }

    #[test]
    fn a_failed_refresh_keeps_what_was_shown_and_says_why() {
        let fake = Fake::with(&["a", "b"]);
        let mut app = app_with(&fake);
        fake.fail.set(true);
        app.update(Action::Refresh);
        assert_eq!(app.session.as_ref().unwrap().secrets.len(), 2);
        let Some(Message::Error(text)) = &app.message else {
            panic!("expected an error, got {:?}", app.message);
        };
        assert!(text.contains("(crypto)"), "{text}");
    }

    #[test]
    fn verifying_checks_the_chain_again_and_says_what_it_found() {
        let fake = Fake::with(&["a"]);
        let mut app = app_with(&fake);
        app.update(Action::Verify);
        assert_eq!(fake.verifies.get(), 2);
        assert!(
            matches!(&app.message, Some(Message::Info(t)) if t.starts_with("audit chain intact")),
            "{:?}",
            app.message
        );
        fake.broken.set(true);
        app.update(Action::Verify);
        assert!(matches!(&app.message, Some(Message::Error(t)) if t.contains("not intact")));
        let v = app.session.as_ref().unwrap().verification().unwrap();
        assert_eq!(v.result.first_broken, Some(2));
        assert_eq!(fake.lists.get(), 2, "verifying is not an audited read");
    }

    #[test]
    fn locking_drops_the_vault_and_enter_asks_for_it_again() {
        let fake = Fake::with(&["a"]);
        let mut app = app_with(&fake);
        assert_eq!(Rc::strong_count(&fake), 2, "the session holds the vault");
        app.update(Action::Show(Tab::Secrets));
        app.update(Action::Lock);
        assert_eq!(Rc::strong_count(&fake), 1, "the vault handle is gone");
        assert!(app.session.is_none());
        assert_eq!(
            app.locked,
            Some(Locked {
                vault: "development".into(),
                idle: false
            })
        );
        assert_eq!(app.tab, Tab::Overview);
        app.update(Action::Open);
        assert_eq!(
            app.take_request(),
            Some(Request::Open("development".into()))
        );
        app.opened(
            "development",
            Ok(Session::open(Box::new(Rc::clone(&fake))).unwrap()),
        );
        assert!(app.locked.is_none() && app.session.is_some());
    }

    #[test]
    fn the_idle_lock_counts_from_the_last_key() {
        let fake = Fake::with(&["a"]);
        let ten = Duration::from_secs(600);
        let mut app = App::new(Vec::new()).with_lock_after(Some(ten));
        assert_eq!(
            app.locks_in(Duration::ZERO),
            None,
            "nothing open, nothing to lock"
        );
        app.set_session(Session::open(Box::new(Rc::clone(&fake))).unwrap());
        assert_eq!(
            app.locks_in(Duration::from_secs(60)),
            Some(Duration::from_secs(540))
        );
        assert_eq!(app.locks_in(Duration::from_mins(15)), Some(Duration::ZERO));
        app.lock(true);
        assert!(app.locked.as_ref().is_some_and(|l| l.idle));
        assert_eq!(app.locks_in(Duration::ZERO), None);

        let mut never = app_with(&fake);
        assert_eq!(never.lock_after(), None);
        assert_eq!(never.locks_in(Duration::from_hours(24)), None);
        never.update(Action::Lock);
        assert!(never.session.is_none(), "L locks even without an idle lock");
    }

    #[test]
    fn help_takes_every_key_until_closed() {
        let fake = Fake::with(&["a", "b"]);
        let mut app = on_secrets(&fake);
        app.update(Action::Help);
        assert_eq!(app.mode(), Mode::Help);
        app.update(Action::Down);
        app.update(Action::Show(Tab::Audit));
        app.update(Action::Lock);
        assert_eq!(
            (app.tab, selected(&app).as_deref()),
            (Tab::Secrets, Some("a"))
        );
        assert!(app.session.is_some());
        app.update(Action::Back);
        assert_eq!(app.mode(), Mode::Normal);
        app.update(Action::Help);
        app.update(Action::Quit);
        assert!(app.should_quit());
    }

    // --- changes ------------------------------------------------------

    use super::super::edit::Dialog;
    use super::super::fake::Write;

    fn writes(fake: &Rc<Fake>) -> Vec<Write> {
        fake.writes.borrow().clone()
    }

    fn type_in(app: &mut App, text: &str) {
        for c in text.chars() {
            app.update(Action::Input(c));
        }
    }

    #[test]
    fn a_change_asks_first_and_esc_changes_nothing() {
        let fake = Fake::with(&["a"]);
        let mut app = on_secrets(&fake);
        app.update(Action::Toggle);
        assert_eq!(app.mode(), Mode::Dialog);
        assert!(matches!(&app.dialog, Some(Dialog::Confirm(c)) if c.title == "DISABLE VERSION"));
        app.update(Action::Back);
        assert!(app.dialog.is_none());
        assert!(writes(&fake).is_empty());
    }

    #[test]
    fn toggling_disables_the_version_and_reads_the_vault_again() {
        let fake = Fake::with(&["a"]);
        let mut app = on_secrets(&fake);
        let lists = fake.lists.get();
        app.update(Action::Toggle);
        app.update(Action::Commit);
        let done = writes(&fake);
        assert!(
            matches!(&done[..], [Write::Update(name, version, update)]
                if name == "a" && version.starts_with("01234567") && update.enabled == Some(false)),
            "{done:?}"
        );
        assert_eq!(fake.lists.get(), lists + 1, "read again after the change");
        assert!(!app.selected_secret().unwrap().enabled);
        assert_eq!(
            app.message,
            Some(Message::Info("disabled version 01234567 of 'a'".into()))
        );
    }

    #[test]
    fn in_details_a_change_applies_to_the_selected_version() {
        let fake = Fake::with(&["a"]);
        let mut app = on_secrets(&fake);
        app.update(Action::Open);
        app.update(Action::Down);
        app.update(Action::Toggle);
        app.update(Action::Commit);
        assert!(
            matches!(&writes(&fake)[..], [Write::Update(_, v, _)] if v.starts_with("fedcba98"))
        );
        assert_eq!(app.detail.as_deref(), Some("a"), "the details stay open");
        assert_eq!(app.versions.selected(), Some(1), "on the same version");
    }

    #[test]
    fn an_edit_sends_only_what_changed() {
        let fake = Fake::with(&["a"]);
        let mut app = on_secrets(&fake);
        app.update(Action::Edit);
        app.update(Action::Down);
        app.update(Action::Down); // enabled, content type, tags
        type_in(&mut app, "team=payments");
        app.update(Action::Commit);
        assert!(matches!(&app.dialog, Some(Dialog::Confirm(c)) if c.title == "CHANGE VERSION"));
        app.update(Action::Commit);
        let done = writes(&fake);
        let [Write::Update(_, _, update)] = &done[..] else {
            panic!("{done:?}");
        };
        assert_eq!(update.enabled, None);
        assert_eq!(update.content_type, None);
        assert_eq!(
            update
                .tags
                .as_ref()
                .and_then(|t| t.get("team"))
                .map(String::as_str),
            Some("payments")
        );
    }

    #[test]
    fn a_bad_edit_stays_in_the_form_and_sends_nothing() {
        let fake = Fake::with(&["a"]);
        let mut app = on_secrets(&fake);
        app.update(Action::Edit);
        for _ in 0..4 {
            app.update(Action::Down); // to expires
        }
        type_in(&mut app, "soon");
        app.update(Action::Commit);
        let Some(Dialog::Form(form)) = &app.dialog else {
            panic!("{:?}", app.dialog);
        };
        assert!(
            form.error
                .as_deref()
                .is_some_and(|e| e.starts_with("expires:"))
        );
        assert!(writes(&fake).is_empty());
    }

    #[test]
    fn a_soft_delete_is_recovered_from_the_deleted_view() {
        let fake = Fake::with(&["a", "b"]);
        let mut app = on_secrets(&fake);
        app.update(Action::Delete);
        app.update(Action::Commit);
        assert!(matches!(&writes(&fake)[..], [Write::Delete(n)] if n == "a"));
        assert_eq!(app.shown_secrets().len(), 1);

        app.update(Action::Show(Tab::Deleted));
        assert_eq!(selected(&app).as_deref(), Some("a"));
        app.update(Action::Recover);
        assert!(matches!(&app.dialog, Some(Dialog::Confirm(c)) if c.title == "RECOVER"));
        app.update(Action::Commit);
        assert!(matches!(&writes(&fake)[1..], [Write::Recover(n)] if n == "a"));
        assert_eq!(app.shown_deleted().len(), 0);
    }

    #[test]
    fn deleting_for_good_must_be_typed_first() {
        let fake = Fake::with(&["db"]);
        fake.purgeable.set(true);
        let mut app = on_secrets(&fake);
        app.update(Action::Delete);
        app.update(Action::Commit);
        assert!(writes(&fake).is_empty());
        let Some(Dialog::Confirm(confirm)) = &app.dialog else {
            panic!("{:?}", app.dialog);
        };
        assert_eq!(confirm.error.as_deref(), Some("type 'db' to confirm"));
        type_in(&mut app, "db");
        app.update(Action::Commit);
        assert!(matches!(&writes(&fake)[..], [Write::Delete(n)] if n == "db"));
        assert_eq!(
            app.message,
            Some(Message::Info("deleted 'db' for good".into()))
        );
    }

    #[test]
    fn a_new_version_takes_its_value_from_the_hidden_prompt() {
        let fake = Fake::with(&["a"]);
        let mut app = on_secrets(&fake);
        app.update(Action::NewVersion);
        app.update(Action::Commit);
        assert!(matches!(&app.dialog, Some(Dialog::Confirm(c)) if c.title == "NEW VERSION"));
        app.update(Action::Commit);
        assert!(app.dialog.is_none());
        assert_eq!(app.take_request(), Some(Request::ReadValue("a".into())));
        assert!(
            writes(&fake).is_empty(),
            "nothing is written before the value"
        );

        app.write_version(Ok(SecretBytes::from("s3cr3t")));
        let done = writes(&fake);
        assert!(
            matches!(&done[..], [Write::AddVersion(n, 6, options)] if n == "a" && options.enabled),
            "{done:?}"
        );
        assert!(matches!(&app.message, Some(Message::Info(t)) if t.starts_with("stored version")));
        app.write_version(Ok(SecretBytes::from("again")));
        assert_eq!(writes(&fake).len(), 1, "one value per confirmed change");
    }

    #[test]
    fn an_empty_or_failed_prompt_stores_nothing() {
        let fake = Fake::with(&["a"]);
        let mut app = on_secrets(&fake);
        app.update(Action::NewVersion);
        app.update(Action::Commit);
        app.update(Action::Commit);
        app.write_version(Err("the value is empty".into()));
        assert!(writes(&fake).is_empty());
        assert_eq!(
            app.message,
            Some(Message::Error(
                "nothing stored for 'a': the value is empty".into()
            ))
        );
    }

    #[test]
    fn a_new_secret_is_named_in_the_browser_and_selected_once_stored() {
        let fake = Fake::with(&["a"]);
        let mut app = on_secrets(&fake);
        app.update(Action::Add);
        type_in(&mut app, "new-key");
        app.update(Action::Commit);
        assert!(matches!(&app.dialog, Some(Dialog::Confirm(c)) if c.title == "NEW SECRET"));
        app.update(Action::Commit);
        assert_eq!(
            app.take_request(),
            Some(Request::ReadValue("new-key".into()))
        );
        app.write_version(Ok(SecretBytes::from("v")));
        assert!(matches!(
            &writes(&fake)[..],
            [Write::AddSecret(n, 1, SecretStorage::Vault)] if n == "new-key"
        ));
        assert_eq!(selected(&app).as_deref(), Some("new-key"));
    }

    #[test]
    fn a_refused_change_says_why() {
        let fake = Fake::with(&["a"]);
        let mut app = on_secrets(&fake);
        fake.fail.set(true);
        app.update(Action::Toggle);
        app.update(Action::Commit);
        assert!(writes(&fake).is_empty());
        assert!(
            matches!(&app.message, Some(Message::Error(t))
                if t.starts_with("the vault refused the change (crypto)")),
            "{:?}",
            app.message
        );
    }

    #[test]
    fn read_only_refuses_every_change() {
        let fake = Fake::with(&["a"]);
        fake.deleted_names.borrow_mut().push("old");
        let mut app = App::new(Vec::new()).with_read_only(true);
        app.set_session(Session::open(Box::new(Rc::clone(&fake))).unwrap());
        app.update(Action::Add);
        app.update(Action::Show(Tab::Secrets));
        for action in [
            Action::Toggle,
            Action::Edit,
            Action::NewVersion,
            Action::Add,
            Action::Delete,
        ] {
            app.update(action);
            assert!(app.dialog.is_none(), "{action:?}");
            assert!(matches!(&app.message, Some(Message::Error(t)) if t.contains("read-only")));
        }
        app.update(Action::Show(Tab::Deleted));
        app.update(Action::Recover);
        assert!(app.dialog.is_none());
        assert!(writes(&fake).is_empty());
    }

    #[test]
    fn a_blocked_vault_cannot_be_changed() {
        let fake = Fake::with(&["a"]);
        fake.blocked.set(true);
        let mut app = app_with(&fake);
        app.update(Action::Show(Tab::Overview));
        app.update(Action::Add);
        assert!(app.dialog.is_none());
        assert!(matches!(&app.message, Some(Message::Error(t)) if t.contains("blocked")));
    }

    #[test]
    fn locking_drops_a_change_in_progress() {
        let fake = Fake::with(&["a"]);
        let mut app = on_secrets(&fake);
        app.update(Action::NewVersion);
        app.update(Action::Commit);
        app.update(Action::Commit);
        assert!(app.take_request().is_some());
        app.lock(true);
        app.write_version(Ok(SecretBytes::from("late")));
        assert!(
            writes(&fake).is_empty(),
            "the pending version went with the lock"
        );
        assert!(app.dialog.is_none());
    }

    #[test]
    fn secrets_at_a_connection_are_listed_there_and_one_is_added_there() {
        let fake = Fake::with_connection(&["local"], &["remote"]);
        let mut app = on_secrets(&fake);
        let session = app.session.as_ref().unwrap();
        let names: Vec<&str> = session.secrets.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["local", "remote"]);
        assert_eq!(
            session.storage.get("remote").map(String::as_str),
            Some("c1")
        );
        assert_eq!(
            fake.listings_at.get(),
            2,
            "the secret list and the deleted list, once each, at the connection"
        );

        app.update(Action::Add);
        type_in(&mut app, "new-token");
        app.update(Action::Down);
        app.update(Action::Input(' '));
        app.update(Action::Commit);
        app.update(Action::Commit);
        assert_eq!(
            app.take_request(),
            Some(Request::ReadValue("new-token".to_owned()))
        );
        app.write_version(Ok(SecretBytes::from("value")));
        assert!(matches!(
            writes(&fake).as_slice(),
            [Write::AddSecret(name, 5, SecretStorage::Connection(id))]
                if name == "new-token" && id == "c1"
        ));
    }

    #[test]
    fn a_provider_that_cannot_be_reached_leaves_the_rest_shown() {
        let fake = Fake::with_connection(&["local"], &["remote"]);
        *fake.unreachable.borrow_mut() = Some("c1".to_owned());
        let app = app_with(&fake);
        let session = app.session.as_ref().unwrap();
        assert_eq!(session.secrets.len(), 1);
        assert_eq!(session.unreachable.len(), 1);
        assert_eq!(session.unreachable[0].code, "provider_unavailable");
    }

    #[test]
    fn what_a_storage_cannot_express_is_refused_before_it_is_sent() {
        let fake = Fake::with_connection(&[], &["remote"]);
        fake.remote_capabilities.set(&[]);
        let mut app = on_secrets(&fake);
        app.update(Action::Open);
        // The older of the two versions, at a storage with properties per
        // secret.
        app.update(Action::Down);
        app.update(Action::Toggle);
        assert!(app.dialog.is_none());
        assert!(matches!(&app.message, Some(Message::Error(t)) if t.contains("newest")));
        app.update(Action::Edit);
        // The content type.
        app.update(Action::Down);
        type_in(&mut app, "x");
        app.update(Action::Commit);
        let Some(Dialog::Form(form)) = &app.dialog else {
            panic!("{:?}", app.dialog);
        };
        assert!(
            form.error
                .as_deref()
                .unwrap_or_default()
                .contains("newest version")
        );
        assert!(writes(&fake).is_empty());
    }

    #[test]
    fn a_project_that_is_gone_is_forgotten_and_one_that_is_there_is_not() {
        let fake = Fake::with(&["api-key"]);
        let found = tempfile::tempdir().unwrap();
        std::fs::write(
            found.path().join("sourceorrery.toml"),
            "[project]\nname = \"shop\"\nvault = \"development\"\n\n[secrets.api-key]\n",
        )
        .unwrap();
        fake.link("p1", "shop", found.path());
        fake.link("p2", "old-site", &found.path().join("gone"));
        let mut app = app_with(&fake);
        assert_eq!(
            app.session
                .as_ref()
                .unwrap()
                .projects_using("api-key")
                .len(),
            1
        );
        app.update(Action::Show(Tab::Projects));
        assert_eq!(app.total(Tab::Projects), Some(2));
        app.update(Action::Unlink);
        assert!(app.dialog.is_none(), "shop is still there");
        app.update(Action::Down);
        app.update(Action::Unlink);
        app.update(Action::Commit);
        assert!(matches!(writes(&fake).as_slice(), [Write::Unlink(id)] if id == "p2"));
        assert_eq!(app.total(Tab::Projects), Some(1));

        let mut read_only = app_with(&fake).with_read_only(true);
        fake.link("p3", "older-site", &found.path().join("also-gone"));
        read_only.update(Action::Refresh);
        read_only.update(Action::Show(Tab::Projects));
        read_only.update(Action::Bottom);
        read_only.update(Action::Unlink);
        assert!(read_only.dialog.is_none());
        assert_eq!(writes(&fake).len(), 1);
    }

    #[test]
    fn the_setup_screens_are_asked_for_and_their_vault_read_again() {
        let fake = Fake::with(&["a"]);
        let mut app = app_with(&fake);
        app.update(Action::ChangeVault);
        assert_eq!(
            app.take_request(),
            Some(Request::Setup(Some("development".to_owned())))
        );
        let lists = fake.lists.get();
        app.set_up(Ok(Some("development".to_owned())));
        assert!(fake.lists.get() > lists, "the open vault is read again");
        assert!(matches!(&app.message, Some(Message::Info(t)) if t.contains("changed")));

        app.update(Action::Show(Tab::Vaults));
        app.update(Action::NewVersion);
        assert_eq!(app.take_request(), Some(Request::Setup(None)));
        app.set_up(Ok(Some("staging".to_owned())));
        assert_eq!(selected(&app).as_deref(), Some("staging"));

        let mut read_only = app_with(&fake).with_read_only(true);
        read_only.update(Action::ChangeVault);
        assert_eq!(read_only.take_request(), None);
    }
}
