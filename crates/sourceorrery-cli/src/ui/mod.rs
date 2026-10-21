//! `sourceorrery ui`: the interactive vault browser.
//!
//! The browser sees a vault only through [`source::MetadataSource`], which
//! has no operation that returns a value: it can show names, versions,
//! status and tags, never a secret. Every metadata read is audited by the
//! vault (`secret_list`, `secret_inspect`), so the browser reads once, keeps
//! what it read, and reads again only when asked to (`r`); moving the
//! selection or redrawing never touches the vault.
//!
//! The vault is unlocked before the terminal is taken over, with the same
//! unlock order and passphrase prompt as every other command.

mod app;
mod keys;
#[cfg(test)]
mod snapshot;
mod source;
mod theme;
mod view;

use std::io::IsTerminal;

use anyhow::anyhow;
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event};

use self::app::App;
use self::theme::Theme;
use crate::cli::UiArgs;
use crate::context::Ctx;

pub fn run(ctx: &Ctx, args: &UiArgs) -> anyhow::Result<()> {
    // Both checks come before the unlock, so nothing is prompted for or
    // audited when the browser cannot start.
    if ctx.json() {
        return Err(anyhow!(
            "`sourceorrery ui` is interactive and has no JSON output; \
             use `secret list -o json` or `audit -o json`"
        ));
    }
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(anyhow!(
            "`sourceorrery ui` needs an interactive terminal; \
             in scripts use `secret list` or `audit`"
        ));
    }
    let vault = ctx.open_default()?;
    let mut app = App::load(&vault)?;
    let theme = Theme::detect(args.theme);

    let mut terminal = match ratatui::try_init() {
        Ok(terminal) => terminal,
        Err(err) => {
            ratatui::restore();
            return Err(anyhow!("cannot start the terminal UI: {err}"));
        }
    };
    let result = event_loop(&mut terminal, &mut app, &theme);
    ratatui::restore();
    result
}

fn event_loop(
    terminal: &mut DefaultTerminal,
    app: &mut App<'_>,
    theme: &Theme,
) -> anyhow::Result<()> {
    while !app.should_quit() {
        terminal.draw(|frame| view::draw(frame, app, theme))?;
        if let Event::Key(key) = event::read()?
            && let Some(action) = keys::action(key)
        {
            app.update(action);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use sourceorrery_core::{
        AuditOperation, AuditQuery, SecretBytes, SecretClient, SetSecretOptions,
    };
    use sourceorrery_crypto::Argon2Params;
    use sourceorrery_storage::{CreateVaultOptions, ProtectorSpec, SqliteVault};

    use super::app::{Action, App};
    use super::theme::Theme;
    use super::view;

    const CANARY: &str = "ui-canary-4f1c-value";

    fn vault(dir: &tempfile::TempDir) -> SqliteVault {
        let spec = ProtectorSpec::Passphrase {
            passphrase: SecretBytes::from("ui-test-passphrase"),
            params: Argon2Params::TESTING,
        };
        let path = dir.path().join("dev.sorvault");
        let vault = SqliteVault::create(&path, "dev", CreateVaultOptions::default(), spec).unwrap();
        for name in ["api-key", "database-password", "signing-key"] {
            vault
                .set_secret(name, SecretBytes::from(CANARY), SetSecretOptions::default())
                .unwrap();
        }
        vault
    }

    fn reads(vault: &SqliteVault) -> usize {
        vault
            .audit_events(AuditQuery::default())
            .unwrap()
            .iter()
            .filter(|e| {
                matches!(
                    e.operation,
                    AuditOperation::SecretList
                        | AuditOperation::SecretInspect
                        | AuditOperation::SecretGet
                )
            })
            .count()
    }

    fn screen(terminal: &Terminal<TestBackend>) -> String {
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect()
    }

    /// The browser reads the vault once to start and once per refresh, never
    /// for moving or drawing, and never reads a value.
    #[test]
    fn reads_once_per_load_and_never_a_value() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(&dir);
        let before = reads(&vault);

        let mut app = App::load(&vault).unwrap();
        assert_eq!(reads(&vault), before + 1, "loading is one secret_list");

        let mut terminal = Terminal::new(TestBackend::new(100, 20)).unwrap();
        for action in [
            Action::Down,
            Action::Down,
            Action::PageDown,
            Action::Top,
            Action::Bottom,
            Action::Up,
        ] {
            app.update(action);
            terminal
                .draw(|frame| view::draw(frame, &mut app, &Theme::plain()))
                .unwrap();
        }
        assert_eq!(reads(&vault), before + 1, "moving and drawing read nothing");

        app.update(Action::Refresh);
        assert_eq!(reads(&vault), before + 2, "a refresh is one secret_list");

        let events = vault.audit_events(AuditQuery::default()).unwrap();
        assert!(
            !events
                .iter()
                .any(|e| e.operation == AuditOperation::SecretGet),
            "the browser never reads a value"
        );
        terminal
            .draw(|frame| view::draw(frame, &mut app, &Theme::plain()))
            .unwrap();
        let text = screen(&terminal);
        assert!(text.contains("database-password"), "{text}");
        assert!(!text.contains(CANARY), "a value reached the screen");
    }
}
