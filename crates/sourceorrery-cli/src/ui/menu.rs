//! A flat discovery menu; commands use the same typed actions as shortcuts.
use super::app::{Action, App};
use ratatui::widgets::ListState;

#[derive(Debug)]
pub struct Item {
    pub label: String,
    pub shortcut: &'static str,
    pub action: Action,
    pub reason: Option<String>,
}
#[derive(Debug)]
pub struct Menu {
    pub title: &'static str,
    pub items: Vec<Item>,
    pub state: ListState,
    pub page: usize,
}
impl Menu {
    pub fn actions(app: &App) -> Self {
        let items = [
            ("Open details", "Enter", Action::Open),
            ("Edit metadata", "e", Action::Edit),
            ("Enable / disable version", "Space", Action::Toggle),
            ("New version / vault", "n", Action::NewVersion),
            ("Add secret", "a", Action::Add),
            ("Delete secret", "d", Action::Delete),
            ("Recover secret", "u", Action::Recover),
            ("Forget missing project", "x", Action::Unlink),
            ("Refresh metadata (audited)", "r", Action::Refresh),
            ("Vault settings", "c", Action::ChangeVault),
            ("Verify audit chain", "v", Action::Verify),
            ("Lock vault", "L", Action::Lock),
            ("Help", "?", Action::Help),
        ]
        .into_iter()
        .map(|(label, shortcut, action)| Item {
            label: label.into(),
            shortcut,
            action,
            reason: app.unavailable(action),
        })
        .collect();
        Self::new("Actions", items)
    }
    pub fn new(title: &'static str, items: Vec<Item>) -> Self {
        let selected = (!items.is_empty()).then_some(0);
        Self {
            title,
            items,
            state: ListState::default().with_selected(selected),
            page: 1,
        }
    }
    pub fn move_by(&mut self, action: Action) {
        let current = self.state.selected().unwrap_or(0);
        let index = match action {
            Action::Up => current.saturating_sub(1),
            Action::Down => current.saturating_add(1),
            Action::PageUp => current.saturating_sub(self.page),
            Action::PageDown => current.saturating_add(self.page),
            Action::Top => 0,
            Action::Bottom => usize::MAX,
            _ => current,
        };
        self.state
            .select(self.items.len().checked_sub(1).map(|last| index.min(last)));
    }
}
