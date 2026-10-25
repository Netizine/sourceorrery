//! `sourceorrery ui`: the interactive vault browser.
//!
//! The browser sees a vault only through [`source::MetadataSource`], which
//! has no operation that returns a value: it can show names, versions,
//! status, tags, deleted secrets and the audit log, never a secret. Every
//! metadata read is audited by the vault (`secret_list`, `secret_inspect`),
//! so the browser reads each thing once, when it is first shown, keeps it,
//! and reads again only when asked to (`r`); moving, searching and
//! redrawing never touch the vault.
//!
//! Vaults are opened for inspection, as `audit` opens them: a vault blocked
//! by an unacknowledged audit-log truncation still shows its audit log,
//! and refuses everything else. Opening may prompt for the recovery key
//! and the view check (the password, an authenticator code), so it
//! happens outside the screen: before the browser starts for the vault
//! the command names, and with the screen suspended for one picked from
//! the vault list.
//!
//! After `--lock-after` minutes without a key the browser drops the open
//! vault, which zeroises its key; `L` does the same at once, and `Enter`
//! unlocks it again.
//!
//! Changes go through [`editor::MetadataEditor`], never through the views,
//! and only once confirmed (`ui::edit`); `--read-only` refuses them all. A
//! new value is read at the ordinary hidden prompt with the screen
//! suspended and passed straight to the vault: it is never drawn, and the
//! browser keeps nothing of it. The vault's own settings (its view check,
//! recovery key and storage) change on the setup screens, which `c` and,
//! on the Vaults view, `n` show in place of the browser.
//!
//! Vaults open through [`Routed`], as `run` and `secret` open them: a
//! secret a connection stores is listed and changed at its provider.

mod app;
mod edit;
mod editor;
#[cfg(test)]
mod fake;
pub(crate) mod init;
mod keys;
mod menu;
mod search;
mod session;
pub(crate) mod setup;
#[cfg(test)]
mod snapshot;
mod source;
mod stats;
mod theme;
mod view;
mod viewport;

use std::io::{IsTerminal, Write as _};
use std::time::{Duration, Instant};

use anyhow::anyhow;
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyEventKind};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use sourceorrery_core::{SecretBytes, SecretError};
use sourceorrery_provider::Routed;
use time::OffsetDateTime;

use self::app::{App, Request, VaultEntry};
use self::session::Session;
use self::theme::Theme;
use crate::cli::UiArgs;
use crate::context::Ctx;
use crate::prompt;

pub fn run(ctx: &Ctx, args: &UiArgs) -> anyhow::Result<()> {
    // These checks come before any unlock, so nothing is prompted for or
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
    let theme = Theme::detect(args.theme);
    let lock_after =
        (args.lock_after > 0).then(|| Duration::from_secs(u64::from(args.lock_after) * 60));
    let mut app = App::new(list_vaults(ctx)?)
        .with_lock_after(lock_after)
        .with_read_only(args.read_only);
    // A vault named by --vault or the manifest is opened before the screen
    // is taken over, and a failure ends the command as it would any other.
    if let Some(name) = ctx.selected_vault()? {
        let vault = ctx.inspect(&name)?;
        ctx.check_view(&vault)?;
        app.set_session(Session::open(Box::new(Routed::new(vault)))?);
    }

    let mut terminal = match ratatui::try_init() {
        Ok(terminal) => terminal,
        Err(err) => {
            ratatui::restore();
            return Err(anyhow!("cannot start the terminal UI: {err}"));
        }
    };
    let result = event_loop(ctx, &mut terminal, &mut app, &theme);
    ratatui::restore();
    result
}

fn event_loop(
    ctx: &Ctx,
    terminal: &mut DefaultTerminal,
    app: &mut App,
    theme: &Theme,
) -> anyhow::Result<()> {
    let mut last_key = Instant::now();
    while !app.should_quit() {
        terminal.draw(|frame| view::draw(frame, app, theme))?;
        // Wait for input, but no longer than the idle lock allows.
        let input = match app.locks_in(last_key.elapsed()) {
            Some(left) => event::poll(left)?,
            None => true,
        };
        if !input {
            app.lock(true);
            continue;
        }
        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Release {
                last_key = Instant::now();
            }
            if let Some(action) = keys::action(key, app.mode()) {
                app.update(action);
            }
        }
        match app.take_request() {
            Some(Request::Open(name)) => {
                suspend()?;
                let opened = open(ctx, &name);
                resume(terminal)?;
                app.opened(&name, opened);
                last_key = Instant::now();
            }
            Some(Request::ReadValue(name)) => {
                suspend()?;
                let value = read_value(&name);
                resume(terminal)?;
                app.write_version(value);
                last_key = Instant::now();
            }
            Some(Request::Setup(name)) => {
                // The setup screens take the terminal over and give it back.
                let result = setup::run_on(ctx, terminal, name.as_deref(), theme)
                    .map_err(|err| format!("{err:#}"));
                terminal.clear()?;
                match list_vaults(ctx) {
                    Ok(vaults) => app.set_vaults(vaults),
                    Err(err) => {
                        app.message =
                            Some(app::Message::Error(format!("listing vaults failed: {err}")));
                    }
                }
                app.set_up(result);
                last_key = Instant::now();
            }
            Some(Request::ListVaults) => match list_vaults(ctx) {
                Ok(vaults) => app.set_vaults(vaults),
                Err(err) => {
                    app.message =
                        Some(app::Message::Error(format!("listing vaults failed: {err}")));
                }
            },
            None => {}
        }
    }
    Ok(())
}

/// Open and read a vault picked in the browser, with the screen
/// suspended so the recovery-key and view-check prompts (if any) are
/// the ordinary ones.
fn open(ctx: &Ctx, name: &str) -> Result<Session, String> {
    let mut stderr = std::io::stderr();
    let _ = writeln!(stderr, "Opening vault '{name}' for the browser…");
    let vault = ctx.inspect(name).map_err(|err| describe(&err))?;
    ctx.check_view(&vault).map_err(|err| describe(&err))?;
    Session::open(Box::new(Routed::new(vault))).map_err(|err| format!("{err} ({})", err.code()))
}

/// A new value for `name`, typed twice at the hidden prompt with the screen
/// suspended. It goes from here to the vault and nowhere else.
fn read_value(name: &str) -> Result<SecretBytes, String> {
    let mut stderr = std::io::stderr();
    let _ = writeln!(
        stderr,
        "New version of secret '{}'. The value is not echoed, is stored as typed and is \
         never shown.",
        crate::output::sanitize(name)
    );
    let first = prompt::read_hidden("Value: ").map_err(|err| err.to_string())?;
    if first.is_empty() {
        return Err("the value is empty".to_owned());
    }
    let second = prompt::read_hidden("Confirm value: ").map_err(|err| err.to_string())?;
    if first != second {
        return Err("the two values differ".to_owned());
    }
    Ok(first)
}

fn describe(err: &anyhow::Error) -> String {
    let code = err
        .downcast_ref::<SecretError>()
        .map_or("cli", SecretError::code);
    format!("{err:#} ({code})")
}

pub(crate) fn suspend() -> anyhow::Result<()> {
    disable_raw_mode()?;
    execute!(std::io::stdout(), LeaveAlternateScreen)?;
    Ok(())
}

pub(crate) fn resume(terminal: &mut DefaultTerminal) -> anyhow::Result<()> {
    execute!(std::io::stdout(), EnterAlternateScreen)?;
    enable_raw_mode()?;
    terminal.clear()?;
    Ok(())
}

/// The vault files in the home directory. Listing needs no unlock.
fn list_vaults(ctx: &Ctx) -> anyhow::Result<Vec<VaultEntry>> {
    let mut vaults = Vec::new();
    for name in ctx.registry.list()? {
        let path = ctx.registry.vault_path(&name)?;
        let meta = std::fs::metadata(&path).ok();
        vaults.push(VaultEntry {
            size: meta.as_ref().map(std::fs::Metadata::len),
            modified: meta
                .and_then(|m| m.modified().ok())
                .map(OffsetDateTime::from),
            name,
            path,
        });
    }
    Ok(vaults)
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use sourceorrery_core::ConnectionSettings;
    use sourceorrery_core::{
        AuditOperation, AuditOutcome, AuditQuery, SecretBytes, SecretClient, SetSecretOptions,
    };
    use sourceorrery_provider::{ConnectionClient, Routed};
    use sourceorrery_storage::{
        CreateVaultOptions, CredentialStore, NoStore, SecretStorage, SqliteVault, StaticRecoveryKey,
    };

    use super::app::{Action, App, Request, Tab};
    use super::session::{ProjectStatus, Session};

    /// No credential store: these vaults open with their recovery keys, and
    /// a test never touches the real OS store.
    fn no_store() -> std::sync::Arc<dyn CredentialStore> {
        std::sync::Arc::new(NoStore)
    }
    use super::theme::Theme;
    use super::view;

    const CANARY: &str = "ui-canary-4f1c-value";

    /// The test vault, routed as the browser opens it.
    fn vault(dir: &tempfile::TempDir) -> Routed {
        Routed::new(vault_and_key(dir).0)
    }

    /// The test vault and the recovery key that opens it again.
    fn vault_and_key(dir: &tempfile::TempDir) -> (SqliteVault, String) {
        let path = dir.path().join("dev.sorvault");
        let created =
            SqliteVault::create(&path, "dev", CreateVaultOptions::default(), no_store()).unwrap();
        let key = created.recovery_key.to_string();
        let vault = created.vault;
        for name in ["api-key", "database-password", "signing-key", "retired"] {
            vault
                .set_secret(name, SecretBytes::from(CANARY), SetSecretOptions::default())
                .unwrap();
        }
        vault.delete_secret("retired").unwrap();
        (vault, key)
    }

    /// Audited reads so far, by operation.
    fn reads(vault: &Routed, operation: AuditOperation) -> usize {
        vault
            .audit_events(AuditQuery {
                operation: Some(operation),
                ..AuditQuery::default()
            })
            .unwrap()
            .len()
    }

    fn draw(terminal: &mut Terminal<TestBackend>, app: &mut App) -> String {
        terminal
            .draw(|frame| view::draw(frame, app, &Theme::plain()))
            .unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect()
    }

    /// Against a real vault: what each view costs in audit rows, and that
    /// no value is read or drawn on any of them.
    #[test]
    fn each_thing_is_read_once_and_never_a_value() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Rc::new(vault(&dir));
        let (lists, inspects) = (
            reads(&vault, AuditOperation::SecretList),
            reads(&vault, AuditOperation::SecretInspect),
        );
        let mut app = App::new(Vec::new());
        app.set_session(Session::open(Box::new(Rc::clone(&vault))).unwrap());
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        let mut screens = vec![draw(&mut terminal, &mut app)];
        assert_eq!(app.tab, Tab::Overview);
        assert_eq!(
            reads(&vault, AuditOperation::SecretList),
            lists + 2,
            "opening reads the secret list, and the overview the deleted list"
        );
        assert!(screens[0].contains("AUDIT CHAIN  intact"), "{}", screens[0]);

        app.update(Action::Verify);
        app.update(Action::Show(Tab::Secrets));
        for action in [
            Action::Down,
            Action::PageDown,
            Action::Top,
            Action::Bottom,
            Action::Up,
        ] {
            app.update(action);
            screens.push(draw(&mut terminal, &mut app));
        }
        assert_eq!(
            reads(&vault, AuditOperation::SecretList),
            lists + 2,
            "moving and verifying read nothing"
        );

        app.update(Action::Open);
        screens.push(draw(&mut terminal, &mut app));
        app.update(Action::Back);
        app.update(Action::Open);
        screens.push(draw(&mut terminal, &mut app));
        assert_eq!(
            reads(&vault, AuditOperation::SecretInspect),
            inspects + 1,
            "details read the versions once"
        );

        app.update(Action::Show(Tab::Deleted));
        screens.push(draw(&mut terminal, &mut app));
        app.update(Action::Open);
        screens.push(draw(&mut terminal, &mut app));
        assert_eq!(
            reads(&vault, AuditOperation::SecretList),
            lists + 2,
            "the deleted list was read for the overview"
        );

        for tab in [
            Tab::Audit,
            Tab::Vaults,
            Tab::Overview,
            Tab::Deleted,
            Tab::Secrets,
        ] {
            app.update(Action::Show(tab));
            screens.push(draw(&mut terminal, &mut app));
        }
        app.update(Action::Search);
        app.update(Action::Input('d'));
        screens.push(draw(&mut terminal, &mut app));
        assert_eq!(
            reads(&vault, AuditOperation::SecretList),
            lists + 2,
            "held views are not read again"
        );
        assert_eq!(reads(&vault, AuditOperation::SecretInspect), inspects + 1);

        app.update(Action::Commit);
        app.update(Action::Refresh);
        assert_eq!(
            reads(&vault, AuditOperation::SecretList),
            lists + 3,
            "a refresh reads the list again"
        );

        assert_eq!(
            reads(&vault, AuditOperation::SecretGet),
            0,
            "the browser never reads a value"
        );
        assert!(screens.iter().any(|s| s.contains("database-password")));
        assert!(screens.iter().any(|s| s.contains("retired")));
        assert!(screens.iter().any(|s| s.contains("secret_set")));
        assert!(
            screens.iter().all(|s| !s.contains(CANARY)),
            "a value reached the screen"
        );
    }

    /// Locking drops the real vault handle (and so its key) at once.
    #[test]
    fn locking_drops_the_vault_handle() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Rc::new(vault(&dir));
        let mut app = App::new(Vec::new());
        app.set_session(Session::open(Box::new(Rc::clone(&vault))).unwrap());
        assert_eq!(Rc::strong_count(&vault), 2);
        app.update(Action::Lock);
        assert_eq!(
            Rc::strong_count(&vault),
            1,
            "the browser holds nothing of the vault"
        );
        let mut terminal = Terminal::new(TestBackend::new(120, 20)).unwrap();
        let screen = draw(&mut terminal, &mut app);
        assert!(screen.contains("Vault 'dev' is locked."), "{screen}");
        assert!(
            !screen.contains("database-password"),
            "nothing read is kept: {screen}"
        );
    }

    /// A vault whose audit log lost its newest rows opens for inspection,
    /// shows its audit log, and is never asked for a secret: each refused
    /// request would put another failure on its log.
    #[test]
    fn a_truncated_vault_shows_its_log_and_is_not_asked_for_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dev.sorvault");
        let (vault, key) = vault_and_key(&dir);
        drop(vault);
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute(
                "DELETE FROM audit_events WHERE id > (SELECT MAX(id) FROM audit_events) - 2",
                [],
            )
            .unwrap();
        }
        let vault = Rc::new(Routed::new(
            SqliteVault::open_with(
                &path,
                no_store(),
                &StaticRecoveryKey::new(key),
                sourceorrery_storage::OpenOptions {
                    allow_quarantined: true,
                },
            )
            .unwrap(),
        ));
        let failures = |vault: &Routed| {
            vault
                .audit_events(AuditQuery::default())
                .unwrap()
                .iter()
                .filter(|e| e.outcome == AuditOutcome::Failure)
                .count()
        };
        let before = failures(&vault);

        let mut app = App::new(Vec::new());
        app.set_session(Session::open(Box::new(Rc::clone(&vault))).unwrap());
        assert_eq!(app.tab, Tab::Audit);
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        let mut screen = draw(&mut terminal, &mut app);
        for tab in Tab::ALL {
            app.update(Action::Show(tab));
            app.update(Action::Open);
            screen.push_str(&draw(&mut terminal, &mut app));
        }
        app.update(Action::Refresh);
        assert!(screen.contains("BLOCKED"), "{screen}");
        assert!(screen.contains("audit_verify"), "{screen}");
        assert_eq!(
            failures(&vault),
            before,
            "nothing was refused, so nothing was recorded"
        );
        assert_eq!(reads(&vault, AuditOperation::SecretGet), 0);
    }

    /// Changes against a real vault: each is one audited operation, none is
    /// refused (each was checked first), no value is read, and a new value
    /// typed at the prompt never reaches the screen.
    #[test]
    fn changes_are_recorded_once_and_a_new_value_is_never_shown() {
        const NEW_VALUE: &str = "ui-new-value-7d2e";
        let dir = tempfile::tempdir().unwrap();
        let vault = Rc::new(vault(&dir));
        let count = |op| reads(&vault, op);
        let mut app = App::new(Vec::new());
        app.set_session(Session::open(Box::new(Rc::clone(&vault))).unwrap());
        app.update(Action::Show(Tab::Secrets));
        let name = app.selected_secret().unwrap().name.clone();
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        let mut screens = Vec::new();

        app.update(Action::Toggle);
        screens.push(draw(&mut terminal, &mut app));
        app.update(Action::Commit);
        assert_eq!(count(AuditOperation::SecretUpdate), 1);
        assert!(!app.selected_secret().unwrap().enabled);

        app.update(Action::Edit);
        for _ in 0..2 {
            app.update(Action::Down);
        }
        for c in "env=ci".chars() {
            app.update(Action::Input(c));
        }
        app.update(Action::Commit);
        screens.push(draw(&mut terminal, &mut app));
        app.update(Action::Commit);
        assert_eq!(count(AuditOperation::SecretUpdate), 2);

        app.update(Action::NewVersion);
        app.update(Action::Commit);
        screens.push(draw(&mut terminal, &mut app));
        app.update(Action::Commit);
        assert_eq!(app.take_request(), Some(Request::ReadValue(name.clone())));
        app.write_version(Ok(SecretBytes::from(NEW_VALUE)));
        screens.push(draw(&mut terminal, &mut app));
        assert_eq!(
            count(AuditOperation::SecretSet),
            5,
            "four from the fixture, one new"
        );
        assert_eq!(
            vault
                .list_properties_of_secret_versions(&name)
                .unwrap()
                .len(),
            2
        );

        app.update(Action::Open);
        screens.push(draw(&mut terminal, &mut app));
        app.update(Action::Back);
        app.update(Action::Delete);
        screens.push(draw(&mut terminal, &mut app));
        app.update(Action::Commit);
        assert_eq!(
            count(AuditOperation::SecretDelete),
            2,
            "the fixture's and this one"
        );
        app.update(Action::Show(Tab::Deleted));
        let i = app
            .shown_deleted()
            .iter()
            .position(|d| d.properties.name == name)
            .unwrap();
        app.update(Action::Top);
        for _ in 0..i {
            app.update(Action::Down);
        }
        app.update(Action::Recover);
        app.update(Action::Commit);
        screens.push(draw(&mut terminal, &mut app));
        assert_eq!(count(AuditOperation::SecretRecover), 1);

        let refused = vault
            .audit_events(AuditQuery::default())
            .unwrap()
            .into_iter()
            .filter(|e| e.outcome != AuditOutcome::Success)
            .count();
        assert_eq!(refused, 0, "every change was checked before it was sent");
        assert_eq!(count(AuditOperation::SecretGet), 0, "no value was read");
        assert!(
            screens
                .iter()
                .all(|s| !s.contains(NEW_VALUE) && !s.contains(CANARY)),
            "a value reached the screen"
        );
    }

    /// A vault with a secret at a connection (a second vault file stands in
    /// for the provider) and two project folders, one of them gone: the
    /// browser lists the secret with its storage, adds one there, shows the
    /// projects as the disk has them and forgets the one that is gone.
    #[test]
    #[allow(clippy::too_many_lines)] // one vault, its storage and its projects
    fn storage_and_projects_are_shown_and_changed_through_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _) = vault_and_key(&dir);
        let provider_path = dir.path().join("provider.sorvault");
        let created = SqliteVault::create(
            &provider_path,
            "provider",
            CreateVaultOptions::default(),
            no_store(),
        )
        .unwrap();
        let provider_key = created.recovery_key.to_string();
        drop(created);
        let connection = vault
            .add_connection(
                &ConnectionSettings::HashicorpVault {
                    address: "https://vault.example.com:8200".to_owned(),
                    mount: "secret".to_owned(),
                    namespace: None,
                },
                None,
            )
            .unwrap()
            .id;
        let found = tempfile::tempdir().unwrap();
        std::fs::write(
            found.path().join("sourceorrery.toml"),
            "[project]\nname = \"shop\"\nvault = \"dev\"\n\n[secrets.api-key]\n\n[secrets.remote-token]\n",
        )
        .unwrap();
        let gone = tempfile::tempdir().unwrap();
        let gone_path = gone.path().to_path_buf();
        vault.link_project(found.path(), "shop").unwrap();
        vault.link_project(&gone_path, "old-site").unwrap();
        drop(gone);
        let routed = Routed::with_opener(vault, move |_, _, _| {
            let provider = SqliteVault::open(
                &provider_path,
                no_store(),
                &StaticRecoveryKey::new(provider_key.as_str()),
            )?;
            let client: ConnectionClient = Box::new(provider);
            Ok(client)
        });
        routed
            .set_secret_in(
                &SecretStorage::Connection(connection.clone()),
                "remote-token",
                SecretBytes::from(CANARY),
                SetSecretOptions::default(),
            )
            .unwrap();
        let vault = Rc::new(routed);

        let mut app = App::new(Vec::new());
        app.set_session(Session::open(Box::new(Rc::clone(&vault))).unwrap());
        let session = app.session.as_ref().unwrap();
        assert_eq!(session.storage.get("remote-token"), Some(&connection));
        assert!(session.secrets.iter().any(|p| p.name == "remote-token"));
        assert_eq!(session.projects.len(), 2);
        assert!(matches!(
            session.projects[0].status,
            ProjectStatus::Found { ref secrets, .. } if secrets.len() == 2
        ));
        assert_eq!(session.projects[1].status, ProjectStatus::Missing);
        assert_eq!(session.projects_using("remote-token").len(), 1);

        let mut terminal = Terminal::new(TestBackend::new(140, 40)).unwrap();
        let mut screens = vec![draw(&mut terminal, &mut app)];
        for text in [
            "password",
            "storage: SourceOrrery, HashiCorp Vault",
            "HashiCorp",
        ] {
            assert!(screens[0].contains(text), "{text}: {}", screens[0]);
        }
        app.update(Action::Show(Tab::Secrets));
        screens.push(draw(&mut terminal, &mut app));
        assert!(screens[1].contains("STORAGE"), "{}", screens[1]);

        // A new secret at the connection, its value from the prompt.
        app.update(Action::Add);
        for c in "second-token".chars() {
            app.update(Action::Input(c));
        }
        app.update(Action::Down);
        app.update(Action::Input(' '));
        app.update(Action::Commit);
        screens.push(draw(&mut terminal, &mut app));
        app.update(Action::Commit);
        assert_eq!(
            app.take_request(),
            Some(Request::ReadValue("second-token".to_owned()))
        );
        app.write_version(Ok(SecretBytes::from(CANARY)));
        assert!(
            matches!(app.message, Some(super::app::Message::Info(_))),
            "{:?}",
            app.message
        );
        assert_eq!(
            vault.vault().storage_of("second-token").unwrap(),
            Some(SecretStorage::Connection(connection.clone()))
        );

        // The project that is gone is forgotten; the one there is not.
        app.update(Action::Show(Tab::Projects));
        screens.push(draw(&mut terminal, &mut app));
        assert!(screens.last().unwrap().contains("✗ gone"));
        app.update(Action::Unlink);
        assert!(matches!(app.message, Some(super::app::Message::Error(_))));
        app.update(Action::Down);
        app.update(Action::Open);
        screens.push(draw(&mut terminal, &mut app));
        app.update(Action::Unlink);
        app.update(Action::Commit);
        assert_eq!(vault.vault().projects().unwrap().len(), 1);
        assert_eq!(reads(&vault, AuditOperation::ProjectUnlink), 1);
        app.update(Action::Back);
        app.update(Action::Top);
        app.update(Action::Open);
        screens.push(draw(&mut terminal, &mut app));
        assert!(
            screens.last().unwrap().contains("remote-token"),
            "{}",
            screens.last().unwrap()
        );

        assert_eq!(reads(&vault, AuditOperation::SecretGet), 0);
        assert!(
            screens.iter().all(|s| !s.contains(CANARY)),
            "a value reached the screen"
        );
    }
}
