//! The setup wizard driven against the fake backend: what it asks the
//! backend for, what it refuses, the plan the review commits, and that
//! nothing typed into a hidden field reaches the screen.

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use sourceorrery_core::{ConnectionSettings, Credentials, Provider, timestamp};
use sourceorrery_crypto::{Argon2Params, TotpSecret};
use sourceorrery_storage::{
    AuthenticatorChange, ConnectionChange, CredentialSource, PasswordChange, RecoveryKey, ViewCheck,
};

use super::backend::Backend;
use super::fake::{self, Fake};
use super::view;
use super::wizard::{Action, Control, Field, Message, PROVIDERS, Step, Wizard};
use crate::ui::theme::Theme;

/// A password that rates "good" and is typed, never shown.
const TYPED: &str = "Tq8#mv2!Lp9&zR4wXe7-typed";
/// A token typed for a connection, never shown.
const TOKEN: &str = "hvs.typed-token-never-drawn";

const BOTH: ViewCheck = ViewCheck {
    password: true,
    authenticator: true,
};
const PASSWORD_ONLY: ViewCheck = ViewCheck {
    password: true,
    authenticator: false,
};

fn wizard(fake: Fake, name: Option<&str>) -> Wizard<Fake> {
    let mut wizard = Wizard::new(fake);
    wizard.params = Argon2Params::TESTING;
    wizard.begin(name).unwrap();
    wizard
}

fn draw<B: Backend>(wizard: &Wizard<B>) -> String {
    let mut terminal = Terminal::new(TestBackend::new(120, 48)).unwrap();
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

fn type_text<B: Backend>(wizard: &mut Wizard<B>, text: &str) {
    for c in text.chars() {
        wizard.update(Action::Input(c));
    }
}

/// Move the focus to `control` (it must be on the current screen).
fn focus<B: Backend>(wizard: &mut Wizard<B>, control: Control) {
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

fn press<B: Backend>(wizard: &mut Wizard<B>, control: Control) {
    focus(wizard, control);
    wizard.update(Action::Enter);
}

fn fill<B: Backend>(wizard: &mut Wizard<B>, control: Control, text: &str) {
    focus(wizard, control);
    type_text(wizard, text);
}

fn error<B: Backend>(wizard: &Wizard<B>) -> String {
    match &wizard.message {
        Some(Message::Error(text)) => text.clone(),
        other => panic!("expected an error message, got {other:?}"),
    }
}

fn current_code<B: Backend>(wizard: &Wizard<B>) -> String {
    let (key, _) = wizard
        .enrolment()
        .expect("an authenticator is being enrolled");
    let now = u64::try_from(timestamp::now().unix_timestamp()).unwrap();
    TotpSecret::from_base32(&key).unwrap().code_at(now)
}

fn form(wizard: &Wizard<Fake>, provider: Provider) -> usize {
    wizard
        .forms
        .iter()
        .position(|f| f.provider == provider)
        .expect("a form for the provider")
}

fn provider(provider: Provider) -> Control {
    Control::Provider(PROVIDERS.iter().position(|p| *p == provider).unwrap())
}

/// A new vault `dev` up to the view-check screen.
fn to_view_check() -> Wizard<Fake> {
    let mut w = wizard(Fake::default(), None);
    assert_eq!(w.step, Step::Start);
    press(&mut w, Control::CreateNew);
    assert_eq!(w.step, Step::Name);
    fill(&mut w, Control::Name, "dev");
    press(&mut w, Control::Continue);
    assert_eq!(w.step, Step::ViewCheck);
    w
}

#[test]
#[allow(clippy::too_many_lines)] // one walk through every screen of a create
fn a_new_vault_is_committed_whole_at_the_review() {
    let mut w = to_view_check();
    w.update(Action::Input(' '));
    assert!(w.ask_password);
    focus(&mut w, Control::AskCode);
    w.update(Action::Input(' '));
    press(&mut w, Control::Continue);
    assert_eq!(w.step, Step::Password);

    // A weak password is refused; a good one, confirmed, is taken.
    fill(&mut w, Control::Password, "password1");
    press(&mut w, Control::Continue);
    assert!(error(&w).contains("rates"), "{}", error(&w));
    focus(&mut w, Control::Password);
    for _ in 0..9 {
        w.update(Action::Erase);
    }
    type_text(&mut w, TYPED);
    fill(&mut w, Control::Confirm, TYPED);
    assert_eq!(w.confirm_state(), Some(true));
    fill(&mut w, Control::Hint, "the long one");
    let screen = draw(&w);
    assert!(!screen.contains(TYPED), "{screen}");
    assert!(screen.contains("matches"), "{screen}");
    press(&mut w, Control::Continue);
    assert_eq!(w.step, Step::Authenticator);

    // The QR code and the key are shown; Continue waits for a code.
    let (key, _) = w.enrolment().unwrap();
    let key = view::key_groups(&key);
    let screen = draw(&w);
    assert!(screen.contains(&key), "{screen}");
    assert!(screen.contains('█'), "the QR code is drawn: {screen}");
    press(&mut w, Control::Continue);
    assert!(error(&w).contains("verify"), "{}", error(&w));
    let code = current_code(&w);
    fill(&mut w, Control::Code, &code);
    press(&mut w, Control::Verify);
    assert!(w.verified());
    assert!(!draw(&w).contains(&key), "the key goes once verified");
    press(&mut w, Control::Continue);
    assert_eq!(w.step, Step::RecoveryKey);

    // The recovery key is shown once and must be ticked as written down.
    let shown = w.recovery.as_ref().unwrap().as_str().to_owned();
    assert!(draw(&w).contains(&shown));
    press(&mut w, Control::Continue);
    assert!(error(&w).contains("write the recovery key down"));
    press(&mut w, Control::RecoveryWritten);
    press(&mut w, Control::Continue);
    assert_eq!(w.step, Step::Storage);

    // HashiCorp Vault with this machine's sign-in, tested.
    focus(&mut w, provider(Provider::HashicorpVault));
    w.update(Action::Input(' '));
    press(&mut w, Control::Continue);
    assert_eq!(w.step, Step::Connections);
    let i = form(&w, Provider::HashicorpVault);
    press(&mut w, Control::Continue);
    assert!(error(&w).contains("HashiCorp Vault"), "{}", error(&w));
    fill(
        &mut w,
        Control::Form(i, Field::Location),
        "https://vault.example.com:8200",
    );
    press(&mut w, Control::Form(i, Field::Test));
    assert_eq!(w.forms[i].tested, Some(Ok(())));
    assert!(draw(&w).contains("reached"));
    press(&mut w, Control::Continue);
    assert_eq!(w.step, Step::Review);
    let screen = draw(&w);
    for text in ["Create vault", "the password typed", "HashiCorp Vault"] {
        assert!(screen.contains(text), "{text}: {screen}");
    }
    assert_eq!(w.backend().plans.len(), 0, "nothing is written before");

    press(&mut w, Control::Commit);
    assert_eq!(w.step, Step::Done);
    let fake = w.backend();
    assert_eq!(fake.tests.len(), 1);
    assert_eq!(fake.tests[0].1, "ambient");
    assert_eq!(fake.plans.len(), 1);
    let plan = fake.plan();
    assert!(plan.create);
    assert_eq!(plan.name, "dev");
    match &plan.change.password {
        PasswordChange::Set { password, hint, .. } => {
            assert_eq!(password.expose(), TYPED.as_bytes());
            assert_eq!(hint.as_deref(), Some("the long one"));
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        plan.change.authenticator,
        AuthenticatorChange::Verified { .. }
    ));
    assert_eq!(
        plan.change.recovery_key.as_ref().map(RecoveryKey::as_str),
        Some(shown.as_str())
    );
    match plan.change.connections.as_slice() {
        [
            ConnectionChange::Add {
                settings: ConnectionSettings::HashicorpVault { address, mount, .. },
                credentials: None,
            },
        ] => {
            assert_eq!(address, "https://vault.example.com:8200");
            assert_eq!(mount, "secret");
        }
        other => panic!("{other:?}"),
    }

    // What was shown once is gone; the last screen names the next steps.
    assert!(w.recovery.is_none());
    assert!(w.enrolment().is_none());
    let screen = draw(&w);
    assert!(!screen.contains(&shown));
    for text in [
        "sourceorrery ui --vault dev",
        "sourceorrery init --vault dev",
    ] {
        assert!(screen.contains(text), "{text}: {screen}");
    }
    w.update(Action::Enter);
    assert!(w.should_quit());
}

#[test]
fn a_vault_without_a_view_check_needs_only_its_recovery_key() {
    let mut w = to_view_check();
    press(&mut w, Control::Continue);
    assert_eq!(w.step, Step::RecoveryKey);
    press(&mut w, Control::RecoveryWritten);
    press(&mut w, Control::Continue);
    press(&mut w, Control::Continue);
    assert_eq!(w.step, Step::Review);
    assert!(draw(&w).contains("none"));
    press(&mut w, Control::Commit);
    let plan = w.backend().plan();
    assert!(matches!(plan.change.password, PasswordChange::Keep));
    assert!(matches!(
        plan.change.authenticator,
        AuthenticatorChange::Keep
    ));
    assert!(plan.change.recovery_key.is_some());
    assert_eq!(plan.change.connections.len(), 0);

    // Back from the review goes the way it came.
    let mut w = to_view_check();
    press(&mut w, Control::Continue);
    press(&mut w, Control::RecoveryWritten);
    press(&mut w, Control::Continue);
    press(&mut w, Control::Continue);
    for step in [
        Step::Storage,
        Step::RecoveryKey,
        Step::ViewCheck,
        Step::Name,
    ] {
        w.update(Action::Back);
        assert_eq!(w.step, step);
    }
    assert_eq!(w.name, "dev");
}

#[test]
fn a_generated_password_is_shown_once_and_must_be_written_down() {
    let mut w = to_view_check();
    w.update(Action::Input(' '));
    press(&mut w, Control::Continue);
    press(&mut w, Control::Generate);
    let generated = w.generated.as_ref().unwrap().as_str().to_owned();
    assert!(draw(&w).contains(&generated));
    assert!(!w.controls().contains(&Control::Password));
    press(&mut w, Control::Continue);
    assert!(error(&w).contains("tick the box"), "{}", error(&w));
    press(&mut w, Control::Written);
    // A hint that gives the password away is refused.
    fill(&mut w, Control::Hint, &generated);
    press(&mut w, Control::Continue);
    assert!(error(&w).contains("give the password away"));
    focus(&mut w, Control::Hint);
    for _ in 0..generated.len() {
        w.update(Action::Erase);
    }
    press(&mut w, Control::Continue);
    assert_eq!(w.step, Step::RecoveryKey);
    press(&mut w, Control::RecoveryWritten);
    press(&mut w, Control::Continue);
    press(&mut w, Control::Continue);
    press(&mut w, Control::Commit);
    match &w.backend().plan().change.password {
        PasswordChange::Set { password, hint, .. } => {
            assert_eq!(password.expose(), generated.as_bytes());
            assert_eq!(*hint, None);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn three_wrong_codes_make_a_new_authenticator_key() {
    let mut w = to_view_check();
    w.update(Action::Input(' '));
    focus(&mut w, Control::AskCode);
    w.update(Action::Input(' '));
    press(&mut w, Control::Continue);
    press(&mut w, Control::Generate);
    press(&mut w, Control::Written);
    press(&mut w, Control::Continue);
    assert_eq!(w.step, Step::Authenticator);
    let (first, _) = w.enrolment().unwrap();
    let wrong = if current_code(&w) == "000000" {
        "111111"
    } else {
        "000000"
    };
    for attempt in 1..=3 {
        fill(&mut w, Control::Code, wrong);
        press(&mut w, Control::Verify);
        if attempt < 3 {
            assert!(
                error(&w).contains(&format!("{attempt} of 3")),
                "{}",
                error(&w)
            );
        }
    }
    assert!(error(&w).contains("a new key was made"), "{}", error(&w));
    let (second, _) = w.enrolment().unwrap();
    assert_ne!(first.as_str(), second.as_str());
    assert!(!w.verified());
}

#[test]
fn a_name_taken_or_invalid_is_refused_as_it_is_typed() {
    let mut w = wizard(Fake::one_vault(ViewCheck::default()), None);
    press(&mut w, Control::CreateNew);
    fill(&mut w, Control::Name, "DEV");
    assert!(w.name_problem().unwrap().contains("exists"));
    assert!(draw(&w).contains("vault 'dev' exists"));
    press(&mut w, Control::Continue);
    assert_eq!(w.step, Step::Name);
    focus(&mut w, Control::Name);
    for _ in 0..3 {
        w.update(Action::Erase);
    }
    type_text(&mut w, "-bad");
    assert!(w.name_problem().is_some());
    press(&mut w, Control::Continue);
    assert_eq!(w.step, Step::Name);
}

#[test]
fn a_name_given_opens_that_vault_or_creates_it() {
    let w = wizard(Fake::one_vault(ViewCheck::default()), Some("DEV"));
    assert_eq!(w.step, Step::ViewCheck);
    assert_eq!(w.editing.as_ref().unwrap().name, "dev");
    assert_eq!(w.backend().opens, vec![("dev".to_owned(), false)]);

    let w = wizard(Fake::one_vault(ViewCheck::default()), Some("staging"));
    assert_eq!(w.step, Step::Name);
    assert_eq!(w.name, "staging");
    assert!(w.creating());
}

#[test]
fn changing_a_vault_asks_its_view_check_first() {
    let mut w = wizard(Fake::one_vault(BOTH), None);
    press(&mut w, Control::Vault(0));
    assert_eq!(w.step, Step::Unlock);
    assert_eq!(
        w.controls(),
        vec![
            Control::UnlockPassword,
            Control::UnlockCode,
            Control::OpenVault
        ]
    );
    assert!(draw(&w).contains("the long one"), "the hint is shown");
    fill(&mut w, Control::UnlockPassword, "wrong password");
    fill(&mut w, Control::UnlockCode, fake::CODE);
    press(&mut w, Control::OpenVault);
    assert!(error(&w).contains("not passed"));
    assert_eq!(w.step, Step::Unlock);
    fill(&mut w, Control::UnlockPassword, fake::PASSWORD);
    assert!(!draw(&w).contains(fake::PASSWORD));
    fill(&mut w, Control::UnlockCode, fake::CODE);
    press(&mut w, Control::OpenVault);
    assert_eq!(w.step, Step::ViewCheck);
    assert_eq!(
        w.backend().checks,
        vec![
            (14, Some(fake::CODE.to_owned())),
            (fake::PASSWORD.len(), Some(fake::CODE.to_owned()))
        ]
    );
    // The screens start from what the vault has.
    assert!(w.ask_password && w.ask_code);
    assert!(w.is_ticked(Provider::HashicorpVault));
    assert!(matches!(w.message, Some(Message::Info(_))));
}

#[test]
fn a_vault_this_machine_cannot_open_takes_its_recovery_key_on_the_screen() {
    let mut fake = Fake::one_vault(BOTH);
    fake.locked = Some("dev".to_owned());
    let mut w = wizard(fake, Some("dev"));
    assert_eq!(w.step, Step::Unlock);
    assert_eq!(w.controls(), vec![Control::UnlockKey, Control::OpenVault]);
    fill(&mut w, Control::UnlockKey, "SORK-NOT-THE-KEY");
    press(&mut w, Control::OpenVault);
    assert!(error(&w).contains("does not open"));
    assert_eq!(
        w.hidden_len(Control::UnlockKey),
        0,
        "a key tried is forgotten"
    );
    fill(&mut w, Control::UnlockKey, fake::RECOVERY_KEY);
    assert!(!draw(&w).contains(fake::RECOVERY_KEY));
    press(&mut w, Control::OpenVault);
    // The recovery key passes the view check by itself; the screens start
    // from the check the vault has.
    assert_eq!(w.step, Step::ViewCheck);
    assert_eq!(w.backend().checks, Vec::new());
    assert!(w.ask_password && w.ask_code);
    assert_eq!(w.backend().opens, vec![("dev".to_owned(), true)]);
}

/// The vault `dev` (with `view`) opened for changes, on the view-check
/// screen.
fn editing(view: ViewCheck) -> Wizard<Fake> {
    let mut w = wizard(Fake::one_vault(view), Some("dev"));
    if w.step == Step::Unlock {
        fill(&mut w, Control::UnlockPassword, fake::PASSWORD);
        if view.authenticator {
            fill(&mut w, Control::UnlockCode, fake::CODE);
        }
        press(&mut w, Control::OpenVault);
    }
    assert_eq!(w.step, Step::ViewCheck);
    w
}

#[test]
fn a_change_keeps_what_is_not_touched() {
    let mut w = editing(BOTH);
    press(&mut w, Control::Continue);
    assert_eq!(w.step, Step::Password);
    assert_eq!(w.controls(), vec![Control::KeepPassword, Control::Continue]);
    press(&mut w, Control::Continue);
    assert_eq!(w.step, Step::Authenticator);
    assert!(w.enrolment().is_none(), "the enrolled app is kept");
    press(&mut w, Control::Continue);
    assert_eq!(w.step, Step::RecoveryKey);
    assert!(w.recovery.is_none(), "the recovery key is kept");
    press(&mut w, Control::Continue);
    press(&mut w, Control::Continue);
    assert_eq!(w.step, Step::Connections);
    let i = form(&w, Provider::HashicorpVault);
    assert_eq!(w.forms[i].location, "https://vault.example.com:8200");
    assert!(w.forms[i].stored && w.forms[i].keeps_credentials());
    assert!(draw(&w).contains("empty keeps the stored ones"));
    press(&mut w, Control::Form(i, Field::Test));
    assert_eq!(w.backend().tests[0].1, "kept");
    press(&mut w, Control::Continue);
    assert_eq!(w.step, Step::Review);
    assert!(draw(&w).contains("Save changes"));
    press(&mut w, Control::Commit);
    let plan = w.backend().plan();
    assert!(!plan.create);
    assert!(plan.change.is_empty(), "{:?}", plan.change);
}

#[test]
fn a_change_can_clear_the_check_replace_the_key_and_drop_a_connection() {
    let mut w = editing(BOTH);
    w.update(Action::Input(' '));
    assert!(!w.ask_password && !w.ask_code);
    press(&mut w, Control::Continue);
    assert_eq!(w.step, Step::RecoveryKey);
    press(&mut w, Control::NewRecoveryKey);
    let shown = w.recovery.as_ref().unwrap().as_str().to_owned();
    let screen = draw(&w);
    assert!(screen.contains(&shown) && screen.contains("stops working"));
    press(&mut w, Control::Continue);
    assert!(error(&w).contains("write the recovery key down"));
    press(&mut w, Control::RecoveryWritten);
    press(&mut w, Control::Continue);
    focus(&mut w, provider(Provider::HashicorpVault));
    w.update(Action::Input(' '));
    press(&mut w, Control::Continue);
    assert_eq!(w.step, Step::Review);
    let screen = draw(&w);
    for text in [
        "the password is removed",
        "the connection is removed",
        "a new key",
    ] {
        assert!(screen.contains(text), "{text}: {screen}");
    }
    press(&mut w, Control::Commit);
    let change = &w.backend().plan().change;
    assert!(matches!(change.password, PasswordChange::Clear));
    assert_eq!(
        change.recovery_key.as_ref().map(RecoveryKey::as_str),
        Some(shown.as_str())
    );
    assert!(matches!(
        change.connections.as_slice(),
        [ConnectionChange::Remove { id }] if id == "c1"
    ));
    assert_eq!(w.committed.as_ref().unwrap().view, ViewCheck::default());
}

#[test]
fn a_change_can_add_the_authenticator_and_a_new_token() {
    let mut w = editing(PASSWORD_ONLY);
    focus(&mut w, Control::AskCode);
    w.update(Action::Input(' '));
    press(&mut w, Control::Continue);
    press(&mut w, Control::Continue);
    assert_eq!(w.step, Step::Authenticator);
    assert_eq!(
        w.controls(),
        vec![Control::Code, Control::Verify, Control::Continue]
    );
    let code = current_code(&w);
    fill(&mut w, Control::Code, &code);
    press(&mut w, Control::Verify);
    press(&mut w, Control::Continue);
    press(&mut w, Control::Continue);
    press(&mut w, Control::Continue);
    let i = form(&w, Provider::HashicorpVault);
    fill(&mut w, Control::Form(i, Field::Secret), TOKEN);
    assert!(!w.forms[i].keeps_credentials());
    let screen = draw(&w);
    assert!(!screen.contains(TOKEN), "{screen}");
    assert!(screen.contains(&"•".repeat(TOKEN.len())));
    press(&mut w, Control::Form(i, Field::Test));
    assert_eq!(w.backend().tests[0].1, "given");
    press(&mut w, Control::Continue);
    assert!(!draw(&w).contains(TOKEN));
    press(&mut w, Control::Commit);
    let change = &w.backend().plan().change;
    assert!(matches!(change.password, PasswordChange::Keep));
    assert!(matches!(
        change.authenticator,
        AuthenticatorChange::Verified { .. }
    ));
    match change.connections.as_slice() {
        [
            ConnectionChange::Credentials {
                id,
                credentials: Some(Credentials::VaultToken(token)),
            },
        ] => {
            assert_eq!(id, "c1");
            assert_eq!(token.expose(), TOKEN.as_bytes());
        }
        other => panic!("{other:?}"),
    }
    assert!(
        w.forms.iter().all(|f| f.secret_len() == 0),
        "typed credentials go at the review"
    );
}

#[test]
fn stored_credentials_are_checked_before_the_review() {
    let mut w = to_view_check();
    press(&mut w, Control::Continue);
    press(&mut w, Control::RecoveryWritten);
    press(&mut w, Control::Continue);
    focus(&mut w, provider(Provider::AzureKeyVault));
    w.update(Action::Input(' '));
    press(&mut w, Control::Continue);
    let i = form(&w, Provider::AzureKeyVault);
    fill(
        &mut w,
        Control::Form(i, Field::Location),
        "https://dev.vault.azure.net",
    );
    focus(&mut w, Control::Form(i, Field::Source));
    w.update(Action::Input(' '));
    assert!(w.forms[i].stored);
    assert!(w.controls().contains(&Control::Form(i, Field::SecondId)));
    press(&mut w, Control::Continue);
    assert!(
        error(&w).contains("Azure Key Vault credentials"),
        "{}",
        error(&w)
    );
    fill(
        &mut w,
        Control::Form(i, Field::FirstId),
        "00000000-0000-0000-0000-000000000001",
    );
    fill(
        &mut w,
        Control::Form(i, Field::SecondId),
        "00000000-0000-0000-0000-000000000002",
    );
    fill(&mut w, Control::Form(i, Field::Secret), TOKEN);
    press(&mut w, Control::Continue);
    assert_eq!(w.step, Step::Review, "{:?}", w.message);
    press(&mut w, Control::Commit);
    match w.backend().plan().change.connections.as_slice() {
        [
            ConnectionChange::Add {
                credentials: Some(Credentials::AzureClientSecret { client_secret, .. }),
                ..
            },
        ] => assert_eq!(client_secret.expose(), TOKEN.as_bytes()),
        other => panic!("{other:?}"),
    }
    let committed = w.committed.as_ref().unwrap();
    assert_eq!(
        committed.connections[0].credentials,
        CredentialSource::Stored
    );
}

#[test]
fn providers_not_in_this_build_are_shown_and_cannot_be_ticked() {
    let fake = Fake {
        providers: vec![Provider::HashicorpVault],
        ..Fake::default()
    };
    let mut w = wizard(fake, Some("dev"));
    press(&mut w, Control::Continue);
    press(&mut w, Control::Continue);
    press(&mut w, Control::RecoveryWritten);
    press(&mut w, Control::Continue);
    assert_eq!(w.step, Step::Storage);
    assert_eq!(
        w.controls(),
        vec![provider(Provider::HashicorpVault), Control::Continue]
    );
    let screen = draw(&w);
    assert_eq!(screen.matches("not in this build").count(), 2, "{screen}");
}

#[test]
fn a_refused_commit_stays_on_the_review_and_can_be_tried_again() {
    let mut w = to_view_check();
    press(&mut w, Control::Continue);
    let shown = w.recovery.as_ref().unwrap().as_str().to_owned();
    press(&mut w, Control::RecoveryWritten);
    press(&mut w, Control::Continue);
    press(&mut w, Control::Continue);
    w.backend_mut().refuse_commit = Some("the disk is full".to_owned());
    press(&mut w, Control::Commit);
    assert_eq!(w.step, Step::Review);
    assert!(error(&w).contains("the disk is full"));
    assert!(draw(&w).contains("Create vault"));
    w.backend_mut().refuse_commit = None;
    press(&mut w, Control::Commit);
    assert_eq!(w.step, Step::Done);
    // The same key went both times: the one written down.
    let plans = &w.backend().plans;
    assert_eq!(plans.len(), 2);
    for plan in plans {
        assert_eq!(
            plan.change.recovery_key.as_ref().map(RecoveryKey::as_str),
            Some(shown.as_str())
        );
    }
}

#[test]
fn leaving_from_the_start_writes_nothing() {
    let mut w = wizard(Fake::one_vault(ViewCheck::default()), None);
    let screen = draw(&w);
    for text in ["dev", "Create a new vault", "Windows Credential Manager"] {
        assert!(screen.contains(text), "{text}: {screen}");
    }
    w.update(Action::Back);
    assert!(w.should_quit());
    assert_eq!(w.backend().plans.len(), 0);
    assert_eq!(w.backend().opens, Vec::new());

    // Back from the name screen forgets what was typed.
    let mut w = wizard(Fake::default(), None);
    assert!(draw(&w).contains("no vault on this machine yet"));
    press(&mut w, Control::CreateNew);
    fill(&mut w, Control::Name, "dev");
    w.update(Action::Back);
    assert_eq!(w.step, Step::Start);
    assert_eq!(w.name, "");
}

/// The live backend against real vaults in a temporary home, which this
/// machine (a memory store) opens: a vault created at the review with a
/// password, opened again behind its view check and changed, and opened
/// with its recovery key where this machine has no key for it.
#[test]
#[allow(clippy::too_many_lines)] // one vault's life through the screens
fn the_live_backend_creates_and_changes_a_vault_in_one_transaction() {
    use std::sync::Arc;

    use sourceorrery_storage::{
        CredentialStore, MemoryStore, NoInteraction, StaticRecoveryKey, VaultRegistry,
    };

    use super::backend::Live;
    use crate::cli::OutputFormat;
    use crate::context::Ctx;

    let home = tempfile::tempdir().unwrap();
    let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
    let ctx = |store: Arc<dyn CredentialStore>| Ctx {
        registry: VaultRegistry::with_root(home.path()).with_store(store),
        output: OutputFormat::Table,
        vault_flag: None,
        recovery_key_file: None,
        password_file: None,
        verbose: 0,
        code: None,
    };
    let machine = ctx(store.clone());
    // No key for the vault in this store: only its recovery key opens it.
    let elsewhere = ctx(Arc::new(MemoryStore::new()));

    let mut w = Wizard::new(Live::new(&machine));
    w.params = Argon2Params::TESTING;
    w.begin(None).unwrap();
    press(&mut w, Control::CreateNew);
    fill(&mut w, Control::Name, "dev");
    press(&mut w, Control::Continue);
    w.update(Action::Input(' '));
    press(&mut w, Control::Continue);
    fill(&mut w, Control::Password, TYPED);
    fill(&mut w, Control::Confirm, TYPED);
    press(&mut w, Control::Continue);
    let first_key = w.recovery.as_ref().unwrap().as_str().to_owned();
    press(&mut w, Control::RecoveryWritten);
    press(&mut w, Control::Continue);
    press(&mut w, Control::Continue);
    press(&mut w, Control::Commit);
    assert_eq!(w.step, Step::Done, "{:?}", w.message);
    let committed = w.committed.clone().unwrap();
    assert_eq!(committed.name, "dev");
    assert!(committed.this_machine);
    assert_eq!(committed.view, PASSWORD_ONLY);
    drop(w);
    let vault = elsewhere
        .registry
        .open("dev", &StaticRecoveryKey::new(first_key.as_str()))
        .unwrap();
    assert!(vault.view_check().unwrap().password);
    drop(vault);

    // Changed: the view check is asked first, then cleared, and the
    // recovery key replaced.
    let mut w = Wizard::new(Live::new(&machine));
    w.begin(Some("dev")).unwrap();
    assert_eq!(w.step, Step::Unlock);
    fill(&mut w, Control::UnlockPassword, "not the password");
    press(&mut w, Control::OpenVault);
    assert!(matches!(w.message, Some(Message::Error(_))));
    fill(&mut w, Control::UnlockPassword, TYPED);
    press(&mut w, Control::OpenVault);
    assert_eq!(w.step, Step::ViewCheck, "{:?}", w.message);
    w.update(Action::Input(' '));
    press(&mut w, Control::Continue);
    press(&mut w, Control::NewRecoveryKey);
    let second_key = w.recovery.as_ref().unwrap().as_str().to_owned();
    press(&mut w, Control::RecoveryWritten);
    press(&mut w, Control::Continue);
    press(&mut w, Control::Continue);
    press(&mut w, Control::Commit);
    assert_eq!(w.step, Step::Done, "{:?}", w.message);
    assert_eq!(w.committed.as_ref().unwrap().view, ViewCheck::default());
    drop(w);
    assert_eq!(
        elsewhere
            .registry
            .open("dev", &StaticRecoveryKey::new(first_key.as_str()))
            .map(drop)
            .unwrap_err()
            .code(),
        "locked"
    );

    // Elsewhere it opens with the recovery key typed on the screen, which
    // passes the view check by itself.
    assert_eq!(
        elsewhere
            .registry
            .open("dev", &NoInteraction)
            .map(drop)
            .unwrap_err()
            .code(),
        "locked"
    );
    let mut w = Wizard::new(Live::new(&elsewhere));
    w.begin(Some("dev")).unwrap();
    assert_eq!(w.step, Step::Unlock);
    assert!(w.needs_key);
    fill(&mut w, Control::UnlockKey, &first_key);
    press(&mut w, Control::OpenVault);
    assert!(error(&w).contains("does not open"), "{}", error(&w));
    fill(&mut w, Control::UnlockKey, &second_key);
    press(&mut w, Control::OpenVault);
    assert_eq!(w.step, Step::ViewCheck, "{:?}", w.message);
    assert_eq!(w.editing.as_ref().unwrap().name, "dev");
}

#[test]
fn qr_fits_whole_or_manual_key_stays_reachable_on_short_screens() {
    let mut w = to_view_check();
    w.update(Action::Input(' '));
    focus(&mut w, Control::AskCode);
    w.update(Action::Input(' '));
    press(&mut w, Control::Continue);
    fill(&mut w, Control::Password, TYPED);
    fill(&mut w, Control::Confirm, TYPED);
    press(&mut w, Control::Continue);
    assert_eq!(w.step, Step::Authenticator);
    for (width, height) in [(80, 24), (60, 18)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        w.update(Action::Scroll(crate::ui::app::Action::Top));
        let mut seen = String::new();
        for _ in 0..8 {
            terminal
                .draw(|frame| view::draw(frame, &w, &Theme::plain()))
                .unwrap();
            let screen: String = terminal
                .backend()
                .buffer()
                .content()
                .iter()
                .map(ratatui::buffer::Cell::symbol)
                .collect();
            if height == 18 {
                assert!(!screen.contains('█'), "clipped QR must be omitted");
            }
            seen.push_str(&screen);
            w.update(Action::Scroll(crate::ui::app::Action::PageDown));
        }
        assert!(
            seen.contains("Cannot scan?") && seen.contains("hand:"),
            "{seen}"
        );
        for group in view::key_groups(&w.enrolment().unwrap().0).split_whitespace() {
            assert!(seen.contains(group));
        }
        assert!(seen.contains("Esc"));
        assert!(!seen.contains(TYPED));
    }
    w.update(Action::Back);
    assert!(w.committed.is_none());
}
