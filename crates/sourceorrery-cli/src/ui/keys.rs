//! Keys to actions. What a key means depends on the mode: commands, text
//! for the search box, or closing the help.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use super::app::{Action, Mode, Tab};

/// The action a key asks for. Releases are ignored: Windows reports them
/// too, and counting them would act twice per key.
pub fn action(key: KeyEvent, mode: Mode) -> Option<Action> {
    if key.kind == KeyEventKind::Release {
        return None;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return (key.code == KeyCode::Char('c')).then_some(Action::Quit);
    }
    match mode {
        Mode::Help => match key.code {
            KeyCode::Char('?') => Some(Action::Help),
            KeyCode::Esc | KeyCode::Enter => Some(Action::Back),
            KeyCode::Char('q') => Some(Action::Quit),
            _ => None,
        },
        Mode::Dialog => match key.code {
            KeyCode::Esc => Some(Action::Back),
            KeyCode::Enter => Some(Action::Commit),
            KeyCode::Backspace => Some(Action::Erase),
            KeyCode::Tab | KeyCode::Down => Some(Action::Down),
            KeyCode::BackTab | KeyCode::Up => Some(Action::Up),
            KeyCode::Char(c) => Some(Action::Input(c)),
            _ => None,
        },
        Mode::Search => match key.code {
            KeyCode::Esc => Some(Action::Back),
            KeyCode::Enter => Some(Action::Commit),
            KeyCode::Backspace => Some(Action::Erase),
            KeyCode::Char(c) => Some(Action::Input(c)),
            code => movement(code),
        },
        Mode::Normal => movement(key.code).or_else(|| command(key.code)),
    }
}

fn movement(code: KeyCode) -> Option<Action> {
    Some(match code {
        KeyCode::Up => Action::Up,
        KeyCode::Down => Action::Down,
        KeyCode::PageUp => Action::PageUp,
        KeyCode::PageDown => Action::PageDown,
        KeyCode::Home => Action::Top,
        KeyCode::End => Action::Bottom,
        _ => return None,
    })
}

fn command(code: KeyCode) -> Option<Action> {
    Some(match code {
        KeyCode::Char('k') => Action::Up,
        KeyCode::Char('j') => Action::Down,
        KeyCode::Char('g') => Action::Top,
        KeyCode::Char('G') => Action::Bottom,
        KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => Action::NextTab,
        KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => Action::PrevTab,
        KeyCode::Char(c @ '1'..='5') => {
            let index = usize::from(u8::try_from(c).ok()? - b'1');
            Action::Show(Tab::ALL[index])
        }
        KeyCode::Enter => Action::Open,
        KeyCode::Esc => Action::Back,
        KeyCode::Char('/') => Action::Search,
        KeyCode::Char('r') => Action::Refresh,
        KeyCode::Char('v') => Action::Verify,
        KeyCode::Char('L') => Action::Lock,
        KeyCode::Char(' ') => Action::Toggle,
        KeyCode::Char('e') => Action::Edit,
        KeyCode::Char('n') => Action::NewVersion,
        KeyCode::Char('a') => Action::Add,
        KeyCode::Char('d') => Action::Delete,
        KeyCode::Char('u') => Action::Recover,
        KeyCode::Char('?') => Action::Help,
        KeyCode::Char('q') => Action::Quit,
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

    fn press(code: KeyCode, mode: Mode) -> Option<Action> {
        action(key(code, KeyModifiers::NONE, KeyEventKind::Press), mode)
    }

    fn normal(code: KeyCode) -> Option<Action> {
        press(code, Mode::Normal)
    }

    #[test]
    fn vim_keys_and_arrows_agree() {
        assert_eq!(normal(KeyCode::Char('j')), normal(KeyCode::Down));
        assert_eq!(normal(KeyCode::Char('k')), normal(KeyCode::Up));
        assert_eq!(normal(KeyCode::Char('g')), normal(KeyCode::Home));
        assert_eq!(normal(KeyCode::Char('G')), normal(KeyCode::End));
        assert_eq!(normal(KeyCode::Char('l')), normal(KeyCode::Tab));
        assert_eq!(normal(KeyCode::Char('h')), normal(KeyCode::BackTab));
    }

    #[test]
    fn digits_pick_a_view() {
        assert_eq!(
            normal(KeyCode::Char('1')),
            Some(Action::Show(Tab::Overview))
        );
        assert_eq!(normal(KeyCode::Char('2')), Some(Action::Show(Tab::Secrets)));
        assert_eq!(normal(KeyCode::Char('4')), Some(Action::Show(Tab::Audit)));
        assert_eq!(normal(KeyCode::Char('5')), Some(Action::Show(Tab::Vaults)));
        assert_eq!(normal(KeyCode::Char('6')), None);
    }

    #[test]
    fn verify_and_lock_have_keys_but_lock_needs_shift() {
        assert_eq!(normal(KeyCode::Char('v')), Some(Action::Verify));
        assert_eq!(normal(KeyCode::Char('L')), Some(Action::Lock));
        assert_eq!(normal(KeyCode::Char('l')), Some(Action::NextTab));
        assert_eq!(
            press(KeyCode::Char('L'), Mode::Search),
            Some(Action::Input('L'))
        );
    }

    #[test]
    fn the_search_box_takes_letters_as_text() {
        let search = |code| press(code, Mode::Search);
        assert_eq!(search(KeyCode::Char('q')), Some(Action::Input('q')));
        assert_eq!(search(KeyCode::Char('j')), Some(Action::Input('j')));
        assert_eq!(search(KeyCode::Char('/')), Some(Action::Input('/')));
        assert_eq!(search(KeyCode::Backspace), Some(Action::Erase));
        assert_eq!(search(KeyCode::Enter), Some(Action::Commit));
        assert_eq!(search(KeyCode::Esc), Some(Action::Back));
        assert_eq!(
            search(KeyCode::Down),
            Some(Action::Down),
            "arrows still move"
        );
    }

    #[test]
    fn change_keys_and_dialogs() {
        assert_eq!(normal(KeyCode::Char(' ')), Some(Action::Toggle));
        assert_eq!(normal(KeyCode::Char('e')), Some(Action::Edit));
        assert_eq!(normal(KeyCode::Char('n')), Some(Action::NewVersion));
        assert_eq!(normal(KeyCode::Char('a')), Some(Action::Add));
        assert_eq!(normal(KeyCode::Char('d')), Some(Action::Delete));
        assert_eq!(normal(KeyCode::Char('u')), Some(Action::Recover));
        let dialog = |code| press(code, Mode::Dialog);
        assert_eq!(
            dialog(KeyCode::Char('q')),
            Some(Action::Input('q')),
            "q is text in a form"
        );
        assert_eq!(dialog(KeyCode::Char(' ')), Some(Action::Input(' ')));
        assert_eq!(dialog(KeyCode::Tab), Some(Action::Down));
        assert_eq!(dialog(KeyCode::BackTab), Some(Action::Up));
        assert_eq!(dialog(KeyCode::Enter), Some(Action::Commit));
        assert_eq!(dialog(KeyCode::Esc), Some(Action::Back));
        assert_eq!(dialog(KeyCode::Backspace), Some(Action::Erase));
    }

    #[test]
    fn the_help_closes_and_ignores_the_rest() {
        assert_eq!(press(KeyCode::Char('?'), Mode::Help), Some(Action::Help));
        assert_eq!(press(KeyCode::Esc, Mode::Help), Some(Action::Back));
        assert_eq!(press(KeyCode::Char('j'), Mode::Help), None);
        assert_eq!(press(KeyCode::Char('q'), Mode::Help), Some(Action::Quit));
    }

    #[test]
    fn a_release_does_nothing() {
        let release = key(KeyCode::Down, KeyModifiers::NONE, KeyEventKind::Release);
        assert_eq!(action(release, Mode::Normal), None);
        let repeat = key(KeyCode::Down, KeyModifiers::NONE, KeyEventKind::Repeat);
        assert_eq!(action(repeat, Mode::Normal), Some(Action::Down));
    }

    #[test]
    fn ctrl_c_quits_in_every_mode_and_other_chords_do_nothing() {
        for mode in [Mode::Normal, Mode::Search, Mode::Help, Mode::Dialog] {
            let ctrl_c = key(
                KeyCode::Char('c'),
                KeyModifiers::CONTROL,
                KeyEventKind::Press,
            );
            assert_eq!(action(ctrl_c, mode), Some(Action::Quit));
        }
        let ctrl_r = key(
            KeyCode::Char('r'),
            KeyModifiers::CONTROL,
            KeyEventKind::Press,
        );
        assert_eq!(action(ctrl_r, Mode::Normal), None);
    }

    #[test]
    fn shifted_letters_still_count() {
        let shift_g = key(KeyCode::Char('G'), KeyModifiers::SHIFT, KeyEventKind::Press);
        assert_eq!(action(shift_g, Mode::Normal), Some(Action::Bottom));
        let typed = key(KeyCode::Char('A'), KeyModifiers::SHIFT, KeyEventKind::Press);
        assert_eq!(action(typed, Mode::Search), Some(Action::Input('A')));
    }
}
