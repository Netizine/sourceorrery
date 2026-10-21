//! Browser state and what each action does to it. There is no terminal in
//! here, so every behaviour is tested directly.

use ratatui::widgets::TableState;
use sourceorrery_core::{Result, SecretProperties, VaultDescriptor};

use super::source::MetadataSource;

/// Something the user asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Up,
    Down,
    PageUp,
    PageDown,
    Top,
    Bottom,
    /// Read the vault again (audited).
    Refresh,
    Quit,
}

/// A one-line message for the status bar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Info(String),
    Error(String),
}

#[derive(Debug)]
pub struct App<'a> {
    source: &'a dyn MetadataSource,
    pub vault: VaultDescriptor,
    /// What the last successful read returned, in the vault's order.
    pub secrets: Vec<SecretProperties>,
    pub table: TableState,
    /// Rows the table showed at the last draw: the step of PageUp/PageDown.
    pub page: usize,
    pub message: Option<Message>,
    quit: bool,
}

impl<'a> App<'a> {
    /// Read the vault once and start with the first secret selected.
    pub fn load(source: &'a dyn MetadataSource) -> Result<Self> {
        let vault = source.descriptor()?;
        let secrets = source.secrets()?;
        let mut app = Self {
            source,
            vault,
            secrets,
            table: TableState::default(),
            page: 1,
            message: None,
            quit: false,
        };
        app.select(0);
        Ok(app)
    }

    pub fn should_quit(&self) -> bool {
        self.quit
    }

    pub fn selected(&self) -> Option<&SecretProperties> {
        self.table.selected().and_then(|i| self.secrets.get(i))
    }

    pub fn update(&mut self, action: Action) {
        let current = self.table.selected().unwrap_or(0);
        match action {
            Action::Up => self.select(current.saturating_sub(1)),
            Action::Down => self.select(current.saturating_add(1)),
            Action::PageUp => self.select(current.saturating_sub(self.page)),
            Action::PageDown => self.select(current.saturating_add(self.page)),
            Action::Top => self.select(0),
            Action::Bottom => self.select(usize::MAX),
            Action::Refresh => self.refresh(),
            Action::Quit => self.quit = true,
        }
    }

    /// Select row `index`, clamped to the list; nothing when it is empty.
    fn select(&mut self, index: usize) {
        let last = self.secrets.len().checked_sub(1);
        self.table.select(last.map(|last| index.min(last)));
    }

    /// Read the vault again, keeping the selected secret selected when it
    /// still exists. A failed read keeps what was shown and says why.
    fn refresh(&mut self) {
        let selected = self.selected().map(|p| p.name.clone());
        let read = self
            .source
            .descriptor()
            .and_then(|vault| Ok((vault, self.source.secrets()?)));
        match read {
            Ok((vault, secrets)) => {
                self.vault = vault;
                self.secrets = secrets;
                let index = selected
                    .and_then(|name| self.secrets.iter().position(|p| p.name == name))
                    .unwrap_or(0);
                self.select(index);
                self.message = Some(Message::Info(format!(
                    "reloaded {} secret(s)",
                    self.secrets.len()
                )));
            }
            Err(err) => {
                self.message = Some(Message::Error(format!(
                    "refresh failed ({}): {err}; showing the list from before",
                    err.code()
                )));
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::cell::{Cell, RefCell};

    use sourceorrery_core::{RecoveryLevel, SecretError, timestamp};

    use super::*;

    /// An in-memory vault that counts how often it is read.
    #[derive(Debug, Default)]
    pub struct FakeSource {
        pub names: RefCell<Vec<&'static str>>,
        pub tags: Vec<(&'static str, &'static str)>,
        pub reads: Cell<usize>,
        pub fail: Cell<bool>,
    }

    impl FakeSource {
        pub fn with(names: &[&'static str]) -> Self {
            Self {
                names: RefCell::new(names.to_vec()),
                ..Self::default()
            }
        }
    }

    impl MetadataSource for FakeSource {
        fn descriptor(&self) -> Result<VaultDescriptor> {
            Ok(VaultDescriptor {
                name: "dev".into(),
                id: "0".repeat(32),
                backend: "fake".into(),
                path: None,
                created_on: timestamp::now(),
                recovery_level: RecoveryLevel::Recoverable,
                retention_days: 90,
                protectors: vec!["passphrase".into()],
            })
        }

        fn secrets(&self) -> Result<Vec<SecretProperties>> {
            self.reads.set(self.reads.get() + 1);
            if self.fail.get() {
                return Err(SecretError::Crypto("audit chain head stale".into()));
            }
            let now = timestamp::now();
            Ok(self
                .names
                .borrow()
                .iter()
                .map(|name| SecretProperties {
                    vault: "dev".into(),
                    name: (*name).to_owned(),
                    version: "0123456789abcdef0123456789abcdef".into(),
                    enabled: true,
                    content_type: None,
                    tags: self
                        .tags
                        .iter()
                        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                        .collect(),
                    not_before: None,
                    expires_on: None,
                    created_on: now,
                    updated_on: now,
                    recovery_level: RecoveryLevel::Recoverable,
                })
                .collect())
        }
    }

    fn selected_name(app: &App<'_>) -> Option<String> {
        app.selected().map(|p| p.name.clone())
    }

    #[test]
    fn movement_stays_inside_the_list() {
        let source = FakeSource::with(&["a", "b", "c"]);
        let mut app = App::load(&source).unwrap();
        assert_eq!(selected_name(&app).as_deref(), Some("a"));
        app.update(Action::Up);
        assert_eq!(selected_name(&app).as_deref(), Some("a"));
        app.update(Action::Down);
        app.update(Action::Down);
        app.update(Action::Down);
        assert_eq!(selected_name(&app).as_deref(), Some("c"));
        app.update(Action::Top);
        assert_eq!(selected_name(&app).as_deref(), Some("a"));
        app.update(Action::Bottom);
        assert_eq!(selected_name(&app).as_deref(), Some("c"));
    }

    #[test]
    fn pages_move_by_the_rows_on_screen() {
        let source = FakeSource::with(&["a", "b", "c", "d", "e", "f", "g"]);
        let mut app = App::load(&source).unwrap();
        app.page = 3;
        app.update(Action::PageDown);
        assert_eq!(selected_name(&app).as_deref(), Some("d"));
        app.update(Action::PageDown);
        app.update(Action::PageDown);
        assert_eq!(selected_name(&app).as_deref(), Some("g"));
        app.update(Action::PageUp);
        assert_eq!(selected_name(&app).as_deref(), Some("d"));
    }

    #[test]
    fn an_empty_vault_selects_nothing() {
        let source = FakeSource::with(&[]);
        let mut app = App::load(&source).unwrap();
        for action in [Action::Down, Action::Bottom, Action::PageDown, Action::Up] {
            app.update(action);
            assert_eq!(app.table.selected(), None);
        }
    }

    #[test]
    fn only_a_refresh_reads_the_vault() {
        let source = FakeSource::with(&["a", "b"]);
        let mut app = App::load(&source).unwrap();
        assert_eq!(source.reads.get(), 1);
        for action in [Action::Down, Action::Up, Action::PageDown, Action::Bottom] {
            app.update(action);
        }
        assert_eq!(source.reads.get(), 1);
        app.update(Action::Refresh);
        assert_eq!(source.reads.get(), 2);
    }

    #[test]
    fn a_refresh_keeps_the_selected_secret() {
        let source = FakeSource::with(&["b", "c"]);
        let mut app = App::load(&source).unwrap();
        app.update(Action::Down);
        source.names.borrow_mut().insert(0, "a");
        app.update(Action::Refresh);
        assert_eq!(selected_name(&app).as_deref(), Some("c"));
        assert_eq!(
            app.message,
            Some(Message::Info("reloaded 3 secret(s)".into()))
        );

        // Gone: fall back to the first row.
        source.names.borrow_mut().retain(|n| *n != "c");
        app.update(Action::Refresh);
        assert_eq!(selected_name(&app).as_deref(), Some("a"));
    }

    #[test]
    fn a_failed_refresh_keeps_the_list_and_says_why() {
        let source = FakeSource::with(&["a", "b"]);
        let mut app = App::load(&source).unwrap();
        source.fail.set(true);
        app.update(Action::Refresh);
        assert_eq!(app.secrets.len(), 2);
        let Some(Message::Error(text)) = &app.message else {
            panic!("expected an error, got {:?}", app.message);
        };
        assert!(text.contains("(crypto)"), "{text}");
    }

    #[test]
    fn quit_stops_the_loop() {
        let source = FakeSource::with(&["a"]);
        let mut app = App::load(&source).unwrap();
        assert!(!app.should_quit());
        app.update(Action::Quit);
        assert!(app.should_quit());
    }
}
