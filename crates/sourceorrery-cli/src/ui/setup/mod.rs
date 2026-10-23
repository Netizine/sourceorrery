//! `sourceorrery setup`: the guided first run, from a vault to `run`, as
//! screens in the terminal.
//!
//! The wizard ([`wizard::Wizard`]) is a state machine over a
//! [`backend::Backend`]; the screens ([`view`]) are a function of its state.
//! The real backend ([`backend::Live`]) creates the vault, stores the first
//! secret, issues recovery codes, enrols the second factor, sets the guard
//! and writes the manifest, each through the same storage calls the
//! commands use, so the wizard has no semantics of its own.
//!
//! A passphrase or value typed on these screens lives in a zeroising
//! buffer, is drawn as dots, and goes to the vault as [`SecretBytes`]; the
//! screens never hold or show a stored value. The two things shown once,
//! behind a "written down" gate, are a generated passphrase (the user must
//! know it) and the recovery codes.
//!
//! [`SecretBytes`]: sourceorrery_core::SecretBytes

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
use self::wizard::{Action, Request, Wizard};
use super::theme::Theme;
use crate::cli::SetupArgs;
use crate::context::Ctx;

/// The vault the wizard creates when `--vault` names none.
pub const DEFAULT_VAULT: &str = "development";

/// The screens. The caller has checked that stdin and stdout are a
/// terminal; `commands::setup` prints the steps as commands otherwise.
pub fn run(ctx: &Ctx, args: &SetupArgs) -> anyhow::Result<()> {
    let theme = Theme::detect(args.theme);
    let vault_name = ctx
        .vault_flag
        .clone()
        .unwrap_or_else(|| DEFAULT_VAULT.to_owned());
    let backend = Live::new(ctx, args.path.as_deref(), args.project_name.as_deref());
    let mut wizard = Wizard::new(backend, &vault_name, &args.secret);

    let mut terminal = match ratatui::try_init() {
        Ok(terminal) => terminal,
        Err(err) => {
            ratatui::restore();
            return Err(anyhow!("cannot start the terminal UI: {err}"));
        }
    };
    let result = event_loop(&mut terminal, &mut wizard, &theme);
    ratatui::restore();
    result
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
        if let Some(Request::OpenExisting(name)) = wizard.take_request() {
            // The unlock may prompt for a passphrase: the ordinary prompt,
            // with the screen out of the way.
            super::suspend()?;
            eprintln!(
                "Opening vault '{}' for setup…",
                crate::output::sanitize(&name)
            );
            wizard.open_existing(&name);
            super::resume(terminal)?;
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
