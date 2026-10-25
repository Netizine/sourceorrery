//! A flat discovery menu; commands use the same typed actions as shortcuts.
use super::app::{Action, App};
use ratatui::widgets::ListState;

#[derive(Debug)]
pub struct Item {
    pub label: String,
    pub shortcut: &'static str,
    pub action: Action,
    pub reason: Option<String>,
    pub query: Option<String>,
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
            ("Inspect cached metadata", "i", Action::Inspect),
            ("Full message details", "!", Action::ErrorDetails),
            ("Open details (audited if uncached)", "Enter", Action::Open),
            ("Filter…", "f", Action::Filters),
            ("Sort…", "s", Action::Sort),
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
            query: None,
        })
        .collect();
        Self::new("Actions", items)
    }
    pub fn filters(app: &App) -> Self {
        let items = super::filters::choices(app)
            .into_iter()
            .map(|(label, query)| Item {
                label: format!("{label} — {} matching cached rows", app.count_query(&query)),
                shortcut: "",
                action: Action::ApplyFilter,
                reason: None,
                query: Some(query),
            })
            .collect();
        Self::new("Filters — same-kind facets replace; words AND", items)
    }
    pub fn sorts(app: &App) -> Self {
        use super::sort::Sort;
        let sorts: &[Sort] = if app.tab == super::app::Tab::Audit {
            &[Sort::Default, Sort::TimeAsc, Sort::TimeDesc]
        } else {
            &[
                Sort::Default,
                Sort::NameAsc,
                Sort::NameDesc,
                Sort::UpdatedAsc,
                Sort::UpdatedDesc,
                Sort::ExpiryAsc,
                Sort::ExpiryDesc,
            ]
        };
        Self::new(
            "Sort — missing dates last",
            sorts
                .iter()
                .map(|sort| Item {
                    label: if *sort == Sort::Default {
                        if app.tab == super::app::Tab::Audit {
                            "Default — newest first".into()
                        } else {
                            "Default — name ascending".into()
                        }
                    } else {
                        sort.title().into()
                    },
                    shortcut: "",
                    action: Action::SetSort(*sort),
                    reason: None,
                    query: None,
                })
                .collect(),
        )
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
