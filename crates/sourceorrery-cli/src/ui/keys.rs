//! Keys to actions.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use super::app::Action;

/// The keys the status bar advertises, in the order it shows them.
pub const HINTS: [(&str, &str); 5] = [
    ("↑↓ jk", "move"),
    ("PgUp PgDn", "page"),
    ("g G", "first/last"),
    ("r", "reload"),
    ("q", "quit"),
];

/// The action a key asks for. Releases are ignored: Windows reports them
/// too, and counting them would move the selection twice per key.
pub fn action(key: KeyEvent) -> Option<Action> {
    if key.kind == KeyEventKind::Release {
        return None;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return (key.code == KeyCode::Char('c')).then_some(Action::Quit);
    }
    Some(match key.code {
        KeyCode::Up | KeyCode::Char('k') => Action::Up,
        KeyCode::Down | KeyCode::Char('j') => Action::Down,
        KeyCode::PageUp => Action::PageUp,
        KeyCode::PageDown => Action::PageDown,
        KeyCode::Home | KeyCode::Char('g') => Action::Top,
        KeyCode::End | KeyCode::Char('G') => Action::Bottom,
        KeyCode::Char('r') => Action::Refresh,
        KeyCode::Char('q') | KeyCode::Esc => Action::Quit,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use ratatui::crossterm::event::KeyEventState;

    use super::*;

    fn key(code: KeyCode, modifiers: KeyModifiers, kind: KeyEventKind) -> KeyEvent {
        KeyEvent {
            code,
            modifiers,
            kind,
            state: KeyEventState::NONE,
        }
    }

    fn press(code: KeyCode) -> Option<Action> {
        action(key(code, KeyModifiers::NONE, KeyEventKind::Press))
    }

    #[test]
    fn vim_keys_and_arrows_agree() {
        assert_eq!(press(KeyCode::Char('j')), press(KeyCode::Down));
        assert_eq!(press(KeyCode::Char('k')), press(KeyCode::Up));
        assert_eq!(press(KeyCode::Char('g')), press(KeyCode::Home));
        assert_eq!(press(KeyCode::Char('G')), press(KeyCode::End));
    }

    #[test]
    fn a_release_does_nothing() {
        let release = key(KeyCode::Down, KeyModifiers::NONE, KeyEventKind::Release);
        assert_eq!(action(release), None);
        let repeat = key(KeyCode::Down, KeyModifiers::NONE, KeyEventKind::Repeat);
        assert_eq!(action(repeat), Some(Action::Down));
    }

    #[test]
    fn ctrl_c_quits_and_other_chords_do_nothing() {
        let ctrl = |c| {
            action(key(
                KeyCode::Char(c),
                KeyModifiers::CONTROL,
                KeyEventKind::Press,
            ))
        };
        assert_eq!(ctrl('c'), Some(Action::Quit));
        assert_eq!(ctrl('r'), None);
        assert_eq!(ctrl('j'), None);
    }

    #[test]
    fn shifted_letters_still_count() {
        let shift_g = key(KeyCode::Char('G'), KeyModifiers::SHIFT, KeyEventKind::Press);
        assert_eq!(action(shift_g), Some(Action::Bottom));
    }
}
