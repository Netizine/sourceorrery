//! `sourceorrery setup` and `sourceorrery vault create [NAME]` on a terminal
//! (ADR 0009, section 7): a vault created, or an existing one changed, on
//! screens. Start, Name, View check (Password, Authenticator), Recovery
//! key, Storage (Connections), Review, Done.
//!
//! The wizard ([`wizard::Wizard`]) is a state machine over a
//! [`backend::Backend`]; the screens ([`view`]) are a function of its
//! state. Nothing is written before the review, which commits the whole of
//! it in one transaction (`SqliteVault::change_settings`; a new vault that
//! cannot take it is removed again). Opening a vault to change it never
//! prompts: this machine's key is tried, else the recovery key is typed on
//! the screen, and then the vault's view check is asked there, since
//! without it anyone at this machine could switch the check off.

pub mod backend;
#[cfg(test)]
pub mod fake;
#[cfg(test)]
mod tests;
pub mod view;
pub mod wizard;

use anyhow::anyhow;
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use self::backend::Live;
use self::wizard::{Action, Wizard};
use super::theme::Theme;
use crate::cli::UiTheme;
use crate::context::Ctx;
use crate::output;

/// The screens, for the vault `name` names (created when new, changed when
/// it exists) or from the start screen. The caller has checked that stdin
/// and stdout are a terminal.
pub fn run(ctx: &Ctx, name: Option<&str>, theme: UiTheme) -> anyhow::Result<()> {
    let theme = Theme::detect(theme);
    let mut wizard = wizard(ctx, name)?;

    let mut terminal = match ratatui::try_init() {
        Ok(terminal) => terminal,
        Err(err) => {
            ratatui::restore();
            return Err(anyhow!("cannot start the terminal UI: {err}"));
        }
    };
    let result = event_loop(&mut terminal, &mut wizard, &theme);
    ratatui::restore();
    result?;

    if let Some(committed) = &wizard.committed {
        let name = output::sanitize(&committed.name);
        output::success(&format!(
            "Vault '{name}' {}\n  {}",
            if wizard.creating() {
                "created"
            } else {
                "changed"
            },
            output::sanitize(&committed.path)
        ));
        eprintln!("  view check: {}", committed.view.describe());
        eprintln!("next:\n  sourceorrery ui --vault {name}\n  sourceorrery init --vault {name}");
    }
    Ok(())
}

/// The screens on a terminal the browser already holds, in its theme: for
/// `c` (the vault `name`) and `n` (a new vault). The name of the vault
/// created or changed, when the review committed.
pub fn run_on(
    ctx: &Ctx,
    terminal: &mut DefaultTerminal,
    name: Option<&str>,
    theme: &Theme,
) -> anyhow::Result<Option<String>> {
    let mut wizard = wizard(ctx, name)?;
    event_loop(terminal, &mut wizard, theme)?;
    Ok(wizard.committed.map(|committed| committed.name))
}

/// The wizard over this machine's vaults, on its first screen.
fn wizard<'a>(ctx: &'a Ctx, name: Option<&str>) -> anyhow::Result<Wizard<Live<'a>>> {
    if let Some(name) = name {
        sourceorrery_core::validate_vault_name(name)?;
    }
    let mut wizard = Wizard::new(Live::new(ctx));
    wizard.begin(name).map_err(|err| anyhow!(err))?;
    Ok(wizard)
}

fn event_loop(
    terminal: &mut DefaultTerminal,
    wizard: &mut Wizard<Live<'_>>,
    theme: &Theme,
) -> anyhow::Result<()> {
    while !wizard.should_quit() {
        terminal.draw(|frame| view::draw(frame, wizard, theme))?;
        if let Event::Key(key) = event::read()?
            && let Some(action) = action(key)
        {
            wizard.update(action);
        }
    }
    Ok(())
}

/// The action a key asks for. Releases are ignored (Windows reports them
/// too). Letters are text: the controls are reached with Tab, Enter and
/// Space, so nothing typed into a field is taken for a command.
fn action(key: KeyEvent) -> Option<Action> {
    if key.kind == KeyEventKind::Release {
        return None;
    }
    if key.kind == KeyEventKind::Repeat
        && !matches!(
            key.code,
            KeyCode::Up | KeyCode::Down | KeyCode::Backspace | KeyCode::Char(_)
        )
    {
        return None;
    }
    if key.kind == KeyEventKind::Repeat && key.code == KeyCode::Char(' ') {
        return None;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return (key.code == KeyCode::Char('c')).then_some(Action::Quit);
    }
    Some(match key.code {
        KeyCode::Esc => Action::Back,
        KeyCode::Enter => Action::Enter,
        KeyCode::Tab | KeyCode::Down => Action::Next,
        KeyCode::BackTab | KeyCode::Up => Action::Prev,
        KeyCode::Backspace => Action::Erase,
        KeyCode::Char(c) => Action::Input(c),
        _ => return None,
    })
}

#[cfg(test)]
mod key_tests {
    use super::*;
    #[test]
    fn review_and_commit_require_fresh_presses() {
        for code in [KeyCode::Enter, KeyCode::Char(' '), KeyCode::Esc] {
            assert!(
                action(KeyEvent::new_with_kind(
                    code,
                    KeyModifiers::NONE,
                    KeyEventKind::Repeat
                ))
                .is_none()
            );
            assert!(
                action(KeyEvent::new_with_kind(
                    code,
                    KeyModifiers::NONE,
                    KeyEventKind::Press
                ))
                .is_some()
            );
        }
        assert!(
            action(KeyEvent::new_with_kind(
                KeyCode::Down,
                KeyModifiers::NONE,
                KeyEventKind::Repeat
            ))
            .is_some()
        );
    }
}
