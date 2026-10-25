//! `init`'s screens driven against the fake backend: what they ask the
//! backend for, what they refuse, the plan the review writes, and that no
//! value typed reaches the screen.

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use sourceorrery_core::Manifest;
use sourceorrery_storage::SecretStorage;

use super::fake::Fake;
use super::view;
use super::wizard::{Action, Control, Message, Request, Row, Start, Step, Wizard};
use crate::commands::init::Change;
use crate::ui::theme::Theme;

const VALUE: &str = "Tq8#mv2!Lp9&zR4wXe7-a-value";

/// A manifest path in a directory of its own, so no file is in the way.
fn start(dir: &tempfile::TempDir) -> Start {
    Start {
        project: "demo".to_owned(),
        manifest_path: dir.path().join("sourceorrery.toml").display().to_string(),
        existing: None,
    }
}

fn draw(terminal: &mut Terminal<TestBackend>, wizard: &Wizard<Fake>) -> String {
    terminal
        .draw(|frame| view::draw(frame, wizard, &Theme::plain()))
        .unwrap();
    terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(ratatui::buffer::Cell::symbol)
        .collect()
}

fn type_text(wizard: &mut Wizard<Fake>, text: &str) {
    for c in text.chars() {
        wizard.update(Action::Input(c));
    }
}

fn erase_all(wizard: &mut Wizard<Fake>) {
    for _ in 0..200 {
        wizard.update(Action::Erase);
    }
}

/// Move the focus to `control` (it must be on the current screen).
fn focus(wizard: &mut Wizard<Fake>, control: Control) {
    let controls = wizard.controls();
    assert!(
        controls.contains(&control),
        "{control:?} is not on {:?}: {controls:?}",
        wizard.step
    );
    for _ in 0..controls.len() {
        if wizard.focused() == control {
            return;
        }
        wizard.update(Action::Next);
    }
}

fn press(wizard: &mut Wizard<Fake>, control: Control) {
    focus(wizard, control);
    wizard.update(Action::Enter);
}

fn error(wizard: &Wizard<Fake>) -> String {
    match &wizard.message {
        Some(Message::Error(text)) => text.clone(),
        other => panic!("expected an error message, got {other:?}"),
    }
}

fn index(wizard: &Wizard<Fake>, name: &str) -> usize {
    wizard
        .rows
        .iter()
        .position(|row| row.name == name)
        .unwrap_or_else(|| panic!("no row {name}"))
}

fn row<'a>(wizard: &'a Wizard<Fake>, name: &str) -> &'a Row {
    &wizard.rows[index(wizard, name)]
}

/// Type a value and its confirmation into the new-secret form.
fn type_value(wizard: &mut Wizard<Fake>, value: &str) {
    focus(wizard, Control::Value);
    type_text(wizard, value);
    focus(wizard, Control::Confirm);
    type_text(wizard, value);
}

#[test]
fn one_vault_opens_at_once_and_all_ticks_and_unticks_every_secret() {
    let dir = tempfile::tempdir().unwrap();
    let mut wizard = Wizard::new(Fake::one_vault(), start(&dir));
    wizard.begin(None).unwrap();
    assert_eq!(wizard.backend().opened, ["dev"]);
    assert_eq!(wizard.step, Step::Project);
    let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    assert!(draw(&mut terminal, &wizard).contains("demo"));

    press(&mut wizard, Control::Continue);
    assert_eq!(wizard.step, Step::Secrets);
    assert!(wizard.rows.iter().all(|row| !row.ticked));
    let screen = draw(&mut terminal, &wizard);
    for shown in [
        "database-password",
        "Database authentication",
        "HashiCorp Vault",
        "API_KEY",
        "0 of 2 ticked",
    ] {
        assert!(screen.contains(shown), "{shown}");
    }

    press(&mut wizard, Control::All);
    assert!(wizard.rows.iter().all(|row| row.ticked));
    press(&mut wizard, Control::All);
    assert!(wizard.rows.iter().all(|row| !row.ticked));
    let db = index(&wizard, "database-password");
    focus(&mut wizard, Control::Row(db));
    wizard.update(Action::Input(' '));
    assert!(row(&wizard, "database-password").ticked);

    press(&mut wizard, Control::Continue);
    assert_eq!(wizard.step, Step::AddNew);
    press(&mut wizard, Control::NoMore);
    assert_eq!(wizard.step, Step::Review);
    press(&mut wizard, Control::Write);
    assert_eq!(wizard.step, Step::Done);
    let plan = wizard.backend().written.clone().unwrap();
    assert_eq!(plan.project, "demo");
    assert_eq!(plan.vault, "dev");
    assert_eq!(
        plan.changes,
        [Change::Add {
            name: "database-password".to_owned(),
            required: true,
            purpose: Some("Database authentication".to_owned()),
            env: None,
        }]
    );
    assert!(draw(&mut terminal, &wizard).contains("records this folder as project demo"));
    assert_eq!(wizard.stored_without_manifest(), &[] as &[String]);
}

#[test]
fn the_filter_narrows_the_list_and_all_ticks_only_what_it_shows() {
    let dir = tempfile::tempdir().unwrap();
    let mut wizard = Wizard::new(Fake::one_vault(), start(&dir));
    wizard.begin(None).unwrap();
    press(&mut wizard, Control::Continue);
    // `/` from anywhere on the list goes to the filter.
    focus(&mut wizard, Control::Continue);
    wizard.update(Action::Input('/'));
    assert_eq!(wizard.focused(), Control::Filter);
    type_text(&mut wizard, "DATA");
    assert_eq!(wizard.visible_rows(), [index(&wizard, "database-password")]);
    press(&mut wizard, Control::All);
    focus(&mut wizard, Control::Filter);
    erase_all(&mut wizard);
    assert_eq!(wizard.visible_rows().len(), 2);
    assert!(row(&wizard, "database-password").ticked);
    assert!(!row(&wizard, "api-key").ticked);
}

#[test]
#[allow(clippy::too_many_lines)] // one loop of new secrets, every screen drawn
fn new_secrets_are_stored_in_a_loop_and_their_value_never_reaches_the_screen() {
    let dir = tempfile::tempdir().unwrap();
    let mut wizard = Wizard::new(Fake::one_vault(), start(&dir));
    wizard.begin(None).unwrap();
    let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    let mut screens = Vec::new();
    press(&mut wizard, Control::Continue);
    press(&mut wizard, Control::Continue);
    press(&mut wizard, Control::AddSecret);
    assert_eq!(wizard.step, Step::NewSecret);

    // A name the vault has, and one that breaks the rules, are refused.
    type_text(&mut wizard, "api-key");
    assert!(
        wizard
            .name_problem()
            .unwrap()
            .contains("tick it in the list")
    );
    screens.push(draw(&mut terminal, &wizard));
    press(&mut wizard, Control::Store);
    assert!(error(&wizard).contains("tick it in the list"));
    focus(&mut wizard, Control::Name);
    erase_all(&mut wizard);
    type_text(&mut wizard, "bad_name");
    assert!(wizard.name_problem().is_some());
    erase_all(&mut wizard);
    type_text(&mut wizard, "stripe-key");
    assert_eq!(wizard.name_problem(), None);
    assert_eq!(wizard.env, "STRIPE_KEY", "the variable follows the name");

    focus(&mut wizard, Control::Value);
    type_text(&mut wizard, VALUE);
    focus(&mut wizard, Control::Confirm);
    type_text(&mut wizard, &format!("{VALUE}x"));
    assert_eq!(wizard.confirm_state(), Some(false));
    screens.push(draw(&mut terminal, &wizard));
    press(&mut wizard, Control::Store);
    assert!(error(&wizard).contains("does not match"));
    focus(&mut wizard, Control::Confirm);
    wizard.update(Action::Erase);
    assert_eq!(wizard.confirm_state(), Some(true));
    assert_eq!(wizard.hidden_len(Control::Value), VALUE.chars().count());
    focus(&mut wizard, Control::Storage);
    wizard.update(Action::Input(' '));
    assert_eq!(wizard.storage_label(), "HashiCorp Vault");
    focus(&mut wizard, Control::Description);
    type_text(&mut wizard, "Payment key");
    screens.push(draw(&mut terminal, &wizard));
    press(&mut wizard, Control::Store);
    assert_eq!(wizard.step, Step::AddNew, "{:?}", wizard.message);
    assert_eq!(
        wizard.backend().stored,
        [(
            "stripe-key".to_owned(),
            VALUE.len(),
            SecretStorage::Connection("c1".to_owned()),
            Some("Payment key".to_owned()),
        )]
    );
    let stored = row(&wizard, "stripe-key");
    assert!(stored.ticked && stored.stored_now && stored.in_vault());
    screens.push(draw(&mut terminal, &wizard));

    // And again: a second secret, kept in the vault file.
    press(&mut wizard, Control::AddSecret);
    type_text(&mut wizard, "second-key");
    type_value(&mut wizard, "v2");
    screens.push(draw(&mut terminal, &wizard));
    press(&mut wizard, Control::Store);
    assert_eq!(wizard.backend().stored.len(), 2);
    assert_eq!(wizard.backend().stored[1].2, SecretStorage::Vault);
    assert_eq!(wizard.stored, ["stripe-key", "second-key"]);

    press(&mut wizard, Control::NoMore);
    let review = draw(&mut terminal, &wizard);
    assert!(review.contains("stored now"), "{review}");
    screens.push(review);
    press(&mut wizard, Control::Write);
    let plan = wizard.backend().written.clone().unwrap();
    assert_eq!(
        plan.changes,
        [
            Change::Add {
                name: "second-key".to_owned(),
                required: true,
                purpose: None,
                env: None,
            },
            Change::Add {
                name: "stripe-key".to_owned(),
                required: true,
                purpose: Some("Payment key".to_owned()),
                env: None,
            },
        ]
    );
    screens.push(draw(&mut terminal, &wizard));
    for screen in &screens {
        assert!(!screen.contains(VALUE), "a value reached the screen");
        assert!(
            !screen.contains("Tq8#"),
            "part of a value reached the screen"
        );
    }
}

#[test]
fn leaving_before_the_review_writes_no_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let mut wizard = Wizard::new(Fake::one_vault(), start(&dir));
    wizard.begin(None).unwrap();
    press(&mut wizard, Control::Continue);
    press(&mut wizard, Control::Continue);
    press(&mut wizard, Control::AddSecret);
    type_text(&mut wizard, "new-key");
    type_value(&mut wizard, VALUE);
    press(&mut wizard, Control::Store);
    wizard.update(Action::Quit);
    assert!(wizard.should_quit());
    assert_eq!(wizard.backend().written, None);
    assert_eq!(wizard.stored_without_manifest(), ["new-key"]);
}

#[test]
fn a_variable_another_secret_uses_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut wizard = Wizard::new(Fake::one_vault(), start(&dir));
    wizard.begin(None).unwrap();
    press(&mut wizard, Control::Continue);
    press(&mut wizard, Control::All);
    press(&mut wizard, Control::Continue);
    press(&mut wizard, Control::AddSecret);
    type_text(&mut wizard, "db-copy");
    focus(&mut wizard, Control::Env);
    erase_all(&mut wizard);
    type_text(&mut wizard, "database_password");
    type_value(&mut wizard, "v");
    press(&mut wizard, Control::Store);
    assert!(
        error(&wizard).contains("variable of 'database-password'"),
        "{}",
        error(&wizard)
    );
    assert_eq!(wizard.backend().stored, Vec::new());
}

#[test]
fn an_existing_manifest_opens_on_its_vault_with_its_secrets_ticked() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = Manifest::parse(
        "[project]\nname = \"app\"\nvault = \"dev\"\n\n[secrets.database-password]\nenv = \
         \"DB_PASS\"\n\n[secrets.missing-one]\npurpose = \"Old key\"\n",
    )
    .unwrap();
    let mut wizard = Wizard::new(
        Fake::one_vault(),
        Start {
            project: "app".to_owned(),
            manifest_path: dir.path().join("sourceorrery.toml").display().to_string(),
            existing: Some(manifest),
        },
    );
    wizard
        .begin(Some("ignored: the manifest names the vault"))
        .unwrap();
    assert_eq!(wizard.backend().opened, ["dev"]);
    assert_eq!(wizard.step, Step::Secrets);
    assert!(!row(&wizard, "api-key").ticked);
    assert!(row(&wizard, "database-password").ticked);
    assert_eq!(row(&wizard, "database-password").env, "DB_PASS");
    let missing = row(&wizard, "missing-one");
    assert!(missing.ticked && !missing.in_vault());
    let mut terminal = Terminal::new(TestBackend::new(140, 40)).unwrap();
    assert!(draw(&mut terminal, &wizard).contains("not in the vault"));

    // Its value is added through the same form, the name filled in.
    let missing = index(&wizard, "missing-one");
    press(&mut wizard, Control::Row(missing));
    assert_eq!(wizard.step, Step::NewSecret);
    assert_eq!(wizard.new_name, "missing-one");
    assert_eq!(wizard.description, "Old key");
    assert_eq!(wizard.focused(), Control::Value);
    type_value(&mut wizard, VALUE);
    press(&mut wizard, Control::Store);
    assert!(row(&wizard, "missing-one").in_vault());
    assert_eq!(
        wizard.step,
        Step::Secrets,
        "back to where the form was opened"
    );

    // Untick one, tick another as optional; the review shows the removal.
    let db = index(&wizard, "database-password");
    focus(&mut wizard, Control::Row(db));
    wizard.update(Action::Input(' '));
    let key = index(&wizard, "api-key");
    focus(&mut wizard, Control::Row(key));
    wizard.update(Action::Input(' '));
    press(&mut wizard, Control::Continue);
    press(&mut wizard, Control::NoMore);
    let review = draw(&mut terminal, &wizard);
    assert!(
        review.contains("Taken out of the manifest: database-password"),
        "{review}"
    );
    focus(&mut wizard, Control::Required(key));
    wizard.update(Action::Input(' '));
    press(&mut wizard, Control::Write);
    assert_eq!(
        wizard.backend().written.clone().unwrap().changes,
        [
            Change::Add {
                name: "api-key".to_owned(),
                required: false,
                purpose: None,
                env: None,
            },
            Change::Remove("database-password".to_owned()),
        ]
    );
}

#[test]
fn several_vaults_are_listed_and_the_one_chosen_is_opened() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake {
        vaults: vec!["dev".to_owned(), "prod".to_owned()],
        ..Fake::one_vault()
    };
    let mut wizard = Wizard::new(fake, start(&dir));
    wizard.begin(None).unwrap();
    assert_eq!(wizard.step, Step::Vault);
    assert_eq!(wizard.backend().opened, Vec::<String>::new());
    let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    let screen = draw(&mut terminal, &wizard);
    assert!(screen.contains("dev") && screen.contains("prod"));

    press(&mut wizard, Control::Vault(1));
    assert_eq!(
        wizard.take_request(),
        Some(Request::Open("prod".to_owned()))
    );
    wizard.open("prod");
    assert_eq!(wizard.step, Step::Project);
    assert_eq!(wizard.backend().opened, ["prod"]);
    wizard.update(Action::Back);
    assert_eq!(wizard.step, Step::Vault, "back to the list of vaults");
}

#[test]
fn a_refused_open_is_shown_and_no_vault_says_how_to_make_one() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake {
        vaults: vec!["dev".to_owned(), "prod".to_owned()],
        refuse_open: Some("vault is locked".to_owned()),
        ..Fake::default()
    };
    let mut wizard = Wizard::new(fake, start(&dir));
    wizard.begin(None).unwrap();
    press(&mut wizard, Control::Vault(0));
    let request = wizard.take_request().unwrap();
    let Request::Open(name) = request;
    wizard.open(&name);
    assert_eq!(wizard.step, Step::Vault);
    assert!(error(&wizard).contains("locked"));

    let mut empty = Wizard::new(Fake::default(), start(&dir));
    empty.begin(None).unwrap();
    assert_eq!(empty.controls(), [Control::Leave]);
    let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    assert!(draw(&mut terminal, &empty).contains("sourceorrery vault create NAME"));
    empty.update(Action::Enter);
    assert!(empty.should_quit());
}

#[test]
fn a_long_list_scrolls_to_keep_the_focused_secret_in_view() {
    let dir = tempfile::tempdir().unwrap();
    let mut fake = Fake::one_vault();
    fake.catalog = (0..60)
        .map(|i| sourceorrery_storage::CatalogEntry {
            name: format!("secret-{i:02}"),
            storage: SecretStorage::Vault,
            description: None,
        })
        .collect();
    let mut wizard = Wizard::new(fake, start(&dir));
    wizard.begin(None).unwrap();
    press(&mut wizard, Control::Continue);
    focus(&mut wizard, Control::Row(59));
    let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
    let screen = draw(&mut terminal, &wizard);
    assert!(screen.contains("secret-59"), "the focused row is drawn");
}

/// The live backend against a real vault in a temporary home: the catalog
/// it opens on, a secret it stores at `[ Store ]`, and the manifest and
/// folder record the review writes.
#[test]
fn the_live_backend_opens_stores_and_writes_through_the_vault() {
    use std::sync::Arc;

    use sourceorrery_core::{SecretBytes, SecretClient as _, SetSecretOptions};
    use sourceorrery_storage::{CreateVaultOptions, MemoryStore, VaultRegistry};

    use super::backend::{Backend as _, Live, Plan};
    use crate::cli::OutputFormat;
    use crate::context::Ctx;

    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    // This machine's key, in memory: a recovery key in the environment (CI's
    // fixture sets one for another vault) is never consulted.
    let registry = VaultRegistry::with_root(home.path()).with_store(Arc::new(MemoryStore::new()));
    let created = registry
        .create("dev", CreateVaultOptions::default())
        .unwrap();
    created
        .vault
        .set_secret(
            "api-key",
            SecretBytes::from("k"),
            SetSecretOptions::default(),
        )
        .unwrap();
    drop(created);
    let ctx = Ctx {
        registry,
        output: OutputFormat::Table,
        vault_flag: None,
        recovery_key_file: None,
        password_file: None,
        verbose: 0,
        code: None,
    };

    let mut live = Live::new(&ctx);
    assert_eq!(live.vaults().unwrap(), ["dev"]);
    let opened = live.open("dev").unwrap();
    assert_eq!(opened.catalog.len(), 1);
    assert_eq!(opened.storages[0].label, "SourceOrrery vault");
    live.store(
        "new-key",
        SecretBytes::from(VALUE),
        &SecretStorage::Vault,
        Some("A new key"),
    )
    .unwrap();
    let path = project.path().join("sourceorrery.toml");
    let saved = live
        .write(&Plan {
            path: path.clone(),
            project: "demo".to_owned(),
            vault: "dev".to_owned(),
            changes: vec![Change::Add {
                name: "new-key".to_owned(),
                required: true,
                purpose: Some("A new key".to_owned()),
                env: None,
            }],
        })
        .unwrap();
    assert_eq!(saved.secrets, 1);
    let manifest = Manifest::parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(manifest.project.vault, "dev");
    assert_eq!(
        manifest.secrets["new-key"].purpose.as_deref(),
        Some("A new key")
    );
    drop(live);

    let vault = ctx.open_local("dev").unwrap();
    assert_eq!(
        vault.get_secret("new-key", None).unwrap().value.expose(),
        VALUE.as_bytes()
    );
    assert_eq!(
        vault.description_of("new-key").unwrap().as_deref(),
        Some("A new key")
    );
    let projects = vault.projects().unwrap();
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0].name, "demo");
}
