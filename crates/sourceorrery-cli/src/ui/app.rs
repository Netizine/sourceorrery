//! Browser state and what each action does to it. There is no terminal in
//! here, so every behaviour is tested directly. Opening a vault needs the
//! terminal (the passphrase prompt), so the app only asks for it
//! ([`Request`]) and the event loop does it.

use std::path::PathBuf;
use std::time::Duration;

use ratatui::widgets::TableState;
use sourceorrery_core::{AuditEvent, DeletedSecret, SecretError, SecretProperties, timestamp};
use time::OffsetDateTime;

use super::search::Query;
use super::session::Session;
use crate::output;

/// The views, in tab order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Secrets,
    Deleted,
    Audit,
    Vaults,
}

impl Tab {
    pub const ALL: [Tab; 5] = [
        Tab::Overview,
        Tab::Secrets,
        Tab::Deleted,
        Tab::Audit,
        Tab::Vaults,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Secrets => "Secrets",
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
}

/// Work only the event loop can do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Unlock and open this vault (may prompt for a passphrase).
    Open(String),
    /// List the vaults in the home directory again.
    ListVaults,
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
}

#[derive(Debug)]
pub struct App {
    pub vaults: Vec<VaultEntry>,
    pub session: Option<Session>,
    pub tab: Tab,
    lists: [ListState; 5],
    /// The secret whose details are shown, on the Secrets or Deleted view.
    pub detail: Option<String>,
    /// Selection in the details' version list.
    pub versions: TableState,
    /// Keys go to the search box.
    pub editing: bool,
    pub help: bool,
    pub message: Option<Message>,
    request: Option<Request>,
    quit: bool,
    /// Lock the open vault after this long without a key.
    lock_after: Option<Duration>,
    /// The vault that was locked, to unlock again with Enter.
    pub locked: Option<Locked>,
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
            message: None,
            request: None,
            quit: false,
            lock_after: None,
            locked: None,
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
        self.vaults = vaults;
        self.clamp();
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

    pub fn selected_vault(&self) -> Option<&VaultEntry> {
        self.selected_index()
            .and_then(|i| self.shown_vaults().get(i).copied())
    }

    pub fn update(&mut self, action: Action) {
        if self.help {
            match action {
                Action::Help | Action::Back => self.help = false,
                Action::Quit => self.quit = true,
                _ => {}
            }
            return;
        }
        match action {
            Action::Quit => self.quit = true,
            Action::Help => self.help = true,
            Action::Back => self.back(),
            Action::Search => {
                self.detail = None;
                self.editing = true;
            }
            Action::Input(c) => {
                self.list_mut(self.tab).query.push(c);
                self.select(0);
            }
            Action::Erase => {
                self.list_mut(self.tab).query.pop();
                self.select(0);
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
        let page = self.list(self.tab).page.max(1);
        let (table, len) = if let Some(name) = &self.detail {
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
        let current = self.selected_index().unwrap_or(0);
        self.select(current);
    }

    fn show(&mut self, tab: Tab) {
        self.tab = tab;
        self.detail = None;
        self.editing = false;
        self.load_view();
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
                .and_then(|()| session.load_protectors())
                .and_then(|()| match session.verification() {
                    Some(_) => Ok(()),
                    None => session.verify().map(|_| ()),
                }),
            Tab::Deleted => session.load_deleted(),
            Tab::Audit => session.load_audit(),
            Tab::Secrets | Tab::Vaults => Ok(()),
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
        if self.editing {
            self.editing = false;
            self.list_mut(self.tab).query.clear();
            self.select(0);
        } else if self.detail.is_some() {
            self.detail = None;
        } else if !self.list(self.tab).query.is_empty() {
            self.list_mut(self.tab).query.clear();
            self.select(0);
        }
    }

    fn refresh(&mut self) {
        if self.tab == Tab::Vaults {
            self.request = Some(Request::ListVaults);
            return;
        }
        let Some(session) = &mut self.session else {
            return;
        };
        if let Err(err) = session.reload() {
            self.message = Some(failure(
                "refresh failed; showing what was read before",
                &err,
            ));
            return;
        }
        let name = session.vault.name.clone();
        self.message = Some(Message::Info(format!("reloaded vault '{name}'")));
        self.load_view();
        if let Some(detail) = self.detail.take() {
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
            }
        }
        self.clamp();
    }
}

fn failure(what: &str, err: &SecretError) -> Message {
    Message::Error(format!("{what} ({}): {err}", err.code()))
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
    fn without_a_vault_it_starts_on_the_vault_list() {
        let app = App::new(Fake::vault_entries());
        assert_eq!(app.tab, Tab::Vaults);
        assert_eq!(selected(&app).as_deref(), Some("development"));
        assert!(app.shown_secrets().is_empty());
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
        assert!(session.verification().is_some() && session.protectors().is_some());

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
        assert_eq!(selected(&app).as_deref(), Some("database-password"));
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
        assert!(app.list(Tab::Audit).query.is_empty());
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
        assert!(app.shown_secrets().is_empty());
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
        assert_eq!(app.locks_in(Duration::from_secs(900)), Some(Duration::ZERO));
        app.lock(true);
        assert!(app.locked.as_ref().is_some_and(|l| l.idle));
        assert_eq!(app.locks_in(Duration::ZERO), None);

        let mut never = app_with(&fake);
        assert_eq!(never.lock_after(), None);
        assert_eq!(never.locks_in(Duration::from_secs(86_400)), None);
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
}
