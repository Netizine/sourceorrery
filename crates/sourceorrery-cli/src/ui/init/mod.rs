//! `sourceorrery init`'s screens (ADR 0009, section 6): which vault, the
//! project, the vault's secrets with an **All** toggle, a loop adding new
//! secrets to the vault, and a review that writes `sourceorrery.toml` and
//! records the folder.
//!
//! The wizard ([`wizard::Wizard`]) is a state machine over a
//! [`backend::Backend`]; the screens ([`view`]) are a function of its
//! state. The real backend ([`backend::Live`]) reads the catalog, stores a
//! new secret through the vault's storage routing and writes the manifest
//! with `commands::init`'s own edit, so the screens have no semantics of
//! their own. `init` reads the vault without the view check: it needs
//! names, never values. Opening a vault may prompt for its recovery key, so
//! it happens before the screen starts, or with the screen suspended.

pub mod backend;
#[cfg(test)]
pub mod fake;
#[cfg(test)]
mod tests;
pub mod view;
pub mod wizard;

use std::path::Path;

use anyhow::anyhow;
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use sourceorrery_core::MANIFEST_FILE_NAME;

use self::backend::Live;
use self::wizard::{Action, Request, Start, Wizard};
use super::theme::Theme;
use crate::cli::InitArgs;
use crate::commands::init;
use crate::context::Ctx;
use crate::output;

/// The screens. The caller has checked that stdin and stdout are a
/// terminal and that no secret was picked with a flag.
pub fn run(ctx: &Ctx, args: &InitArgs, path: &Path) -> anyhow::Result<()> {
    let existing = init::read_existing(path)?;
    let asked = args.target_vault.clone().or_else(|| ctx.vault_flag.clone());
    if let Some((_, manifest)) = &existing {
        init::manifest_vault(ctx, path, manifest, asked.as_deref())?;
        if let Some(name) = &args.project_name
            && *name != manifest.project.name
        {
            return Err(anyhow!(
                "{} names the project '{}'; change it there, not with --project-name",
                path.display(),
                manifest.project.name
            ));
        }
    }
    let project = match (&existing, &args.project_name) {
        (Some((_, manifest)), _) => manifest.project.name.clone(),
        (None, Some(name)) => name.clone(),
        (None, None) => init::default_project_name(&init::project_folder(path)?),
    };
    let manifest_path = match (&args.path, &existing) {
        (Some(_), _) | (None, Some(_)) => path.display().to_string(),
        (None, None) => MANIFEST_FILE_NAME.to_owned(),
    };
    let theme = Theme::detect(args.theme);
    let mut wizard = Wizard::new(
        Live::new(ctx),
        Start {
            project,
            manifest_path,
            existing: existing.map(|(_, manifest)| manifest),
        },
    );
    // Before the screen: opening the vault may prompt.
    wizard.begin(asked.as_deref()).map_err(|err| anyhow!(err))?;

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

    if let Some(saved) = &wizard.saved {
        output::success(&format!(
            "Wrote {}: {} secret(s)",
            saved.manifest.display(),
            saved.secrets
        ));
        eprintln!("next:\n  sourceorrery check\n  sourceorrery run -- <your command>");
    }
    let stored = wizard.stored_without_manifest();
    if !stored.is_empty() {
        output::note(&format!(
            "stored {} in the vault, where they stay for any project; no manifest was written",
            output::sanitize(&stored.join(", "))
        ));
    }
    Ok(())
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
        if let Some(Request::Open(name)) = wizard.take_request() {
            // The unlock may prompt for the recovery key: the ordinary
            // prompt, with the screen out of the way.
            super::suspend()?;
            eprintln!("Opening vault '{}'…", output::sanitize(&name));
            wizard.open(&name);
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
