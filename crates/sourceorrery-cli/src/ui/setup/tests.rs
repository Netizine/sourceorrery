//! The wizard driven through every step against the fake backend: what it
//! asks the backend for, what it refuses, and that no secret reaches the
//! screen.

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use sourceorrery_storage::RevealGuard;

use super::fake::{self, Fake};
use super::view;
use super::wizard::{Action, Control, Request, Step, Wizard};
use crate::ui::theme::Theme;

const PASSPHRASE: &str = "orbit lantern copper nine 42";
const WEAK: &str = "password1";
const VALUE: &str = "Tq8#mv2!Lp9&zR4wXe7";

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

/// Move the focus to `control` (it must be on the current step).
fn focus(wizard: &mut Wizard<Fake>, control: Control) {
    let controls = wizard.controls();
    assert!(
        controls.contains(&control),
        "{control:?} is not on step {:?}: {controls:?}",
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
        Some(super::wizard::Message::Error(text)) => text.clone(),
        other => panic!("expected an error message, got {other:?}"),
    }
}

#[test]
#[allow(clippy::too_many_lines)] // one run through every step
fn the_whole_run_with_a_typed_passphrase_and_a_generated_secret() {
    let mut wizard = Wizard::new(Fake::with_keyring(), "development", "database-password");
    let mut terminal = Terminal::new(TestBackend::new(120, 44)).unwrap();
    let mut screens = vec![draw(&mut terminal, &wizard)];
    assert_eq!(wizard.step, Step::Welcome);
    assert!(screens[0].contains("six short steps"));

    wizard.update(Action::Enter);
    assert_eq!(wizard.step, Step::Vault);
    assert!(
        wizard.keyring,
        "the keyring is offered and ticked by default"
    );

    // A weak passphrase is refused with the estimate's words.
    focus(&mut wizard, Control::Passphrase);
    type_text(&mut wizard, WEAK);
    screens.push(draw(&mut terminal, &wizard));
    assert!(
        screens
            .last()
            .unwrap()
            .contains("•".repeat(WEAK.len()).as_str())
    );
    press(&mut wizard, Control::CreateVault);
    assert_eq!(wizard.step, Step::Vault);
    assert!(error(&wizard).contains("needs good"), "{}", error(&wizard));

    // Replace it with a strong one, mistype the confirmation, then fix it.
    focus(&mut wizard, Control::Passphrase);
    for _ in 0..WEAK.len() {
        wizard.update(Action::Erase);
    }
    type_text(&mut wizard, PASSPHRASE);
    assert!(wizard.passphrase_estimate.as_ref().unwrap().acceptable());
    focus(&mut wizard, Control::PassphraseConfirm);
    type_text(&mut wizard, "orbit lantern");
    screens.push(draw(&mut terminal, &wizard));
    assert!(screens.last().unwrap().contains("does not match"));
    press(&mut wizard, Control::CreateVault);
    assert!(error(&wizard).contains("confirmation"));
    focus(&mut wizard, Control::PassphraseConfirm);
    type_text(&mut wizard, " copper nine 42");
    screens.push(draw(&mut terminal, &wizard));
    assert!(screens.last().unwrap().contains("matches"));
    // Untick the keyring: passphrase only.
    focus(&mut wizard, Control::Keyring);
    wizard.update(Action::Input(' '));
    assert!(!wizard.keyring);
    press(&mut wizard, Control::CreateVault);
    assert_eq!(wizard.step, Step::Secret, "{:?}", wizard.message);
    screens.push(draw(&mut terminal, &wizard));
    assert_eq!(
        wizard.hidden_len(Control::Passphrase),
        0,
        "typed buffers are dropped"
    );

    // The secret: a weak value is refused; a generated one is stored unseen.
    focus(&mut wizard, Control::SecretValue);
    type_text(&mut wizard, "summer");
    press(&mut wizard, Control::StoreSecret);
    assert!(error(&wizard).contains("database password needs good"));
    press(&mut wizard, Control::GenerateSecret);
    assert!(wizard.secret_generated);
    screens.push(draw(&mut terminal, &wizard));
    press(&mut wizard, Control::StoreSecret);
    assert_eq!(wizard.step, Step::Recovery, "{:?}", wizard.message);
    assert_eq!(wizard.stored.as_deref(), Some("database-password"));

    // Recovery codes: shown once, gated on the tick, gone afterwards.
    press(&mut wizard, Control::FinishRecovery);
    assert_eq!(wizard.step, Step::SecondFactor, "codes are optional");
    assert_eq!(wizard.recovery.unwrap().codes, 0);
    // Go back through a fresh wizard section: enrol first, the rest later.
    press(&mut wizard, Control::Enrol);
    screens.push(draw(&mut terminal, &wizard));
    let shown = screens.last().unwrap();
    assert!(shown.contains(fake::KEY), "the key is offered for typing");
    assert!(shown.contains('█'), "the QR code is drawn");
    focus(&mut wizard, Control::Code);
    type_text(&mut wizard, "12x345");
    assert_eq!(wizard.code, "12345", "only digits are taken");
    press(&mut wizard, Control::Verify);
    assert!(error(&wizard).contains("six digits"));
    focus(&mut wizard, Control::Code);
    type_text(&mut wizard, "0");
    press(&mut wizard, Control::Verify);
    assert!(error(&wizard).contains("did not match (1 of 3)"));
    assert_eq!(wizard.code, "");
    focus(&mut wizard, Control::Code);
    type_text(&mut wizard, fake::CODE);
    press(&mut wizard, Control::Verify);
    assert_eq!(wizard.step, Step::Guard, "{:?}", wizard.message);
    assert!(
        wizard.enrolment.is_none(),
        "the key is dropped once verified"
    );

    // The guard offers both, and defaults to it.
    assert_eq!(wizard.guard_options().len(), 3);
    screens.push(draw(&mut terminal, &wizard));
    assert!(
        screens
            .last()
            .unwrap()
            .contains("(•) The passphrase and a code")
    );
    press(&mut wizard, Control::SetGuard);
    assert_eq!(wizard.step, Step::Project, "{:?}", wizard.message);
    let project = wizard.project.as_ref().unwrap();
    assert!(project.written && project.ok, "{project:?}");
    screens.push(draw(&mut terminal, &wizard));
    assert!(screens.last().unwrap().contains("DATABASE_PASSWORD"));
    press(&mut wizard, Control::Finish);
    assert_eq!(wizard.step, Step::Done);
    screens.push(draw(&mut terminal, &wizard));
    let done = screens.last().unwrap();
    assert!(done.contains("enrolled and verified"), "{done}");
    assert!(done.contains("passphrase and second-factor"), "{done}");
    assert!(
        done.contains("sourceorrery run -- <your command>"),
        "{done}"
    );
    wizard.update(Action::Input('q'));
    assert!(wizard.should_quit());

    let fake = &wizard_backend(&wizard);
    assert_eq!(fake.created, Some(("development".to_owned(), false)));
    assert_eq!(fake.passphrase_len, PASSPHRASE.len());
    assert_eq!(fake.secrets, vec![("database-password".to_owned(), 24)]);
    assert!(fake.verified);
    assert_eq!(
        fake.guard,
        Some(RevealGuard {
            passphrase: true,
            second_factor: true
        })
    );
    assert_eq!(
        fake.project_written_for.as_deref(),
        Some("database-password")
    );
    for screen in &screens {
        assert!(!screen.contains(PASSPHRASE), "the passphrase was drawn");
        assert!(
            !screen.contains("orbit"),
            "part of the passphrase was drawn"
        );
        assert!(!screen.contains("summer"), "the typed value was drawn");
    }
}

#[test]
fn a_generated_passphrase_is_shown_once_behind_the_gate_and_codes_too() {
    let mut wizard = Wizard::new(Fake::default(), "development", "database-password");
    let mut terminal = Terminal::new(TestBackend::new(120, 44)).unwrap();
    wizard.update(Action::Enter);
    assert!(
        !wizard.controls().contains(&Control::Keyring),
        "no keyring, no checkbox"
    );
    press(&mut wizard, Control::GeneratePassphrase);
    let generated = wizard.generated_passphrase.clone().unwrap();
    assert_eq!(generated.len(), 20);
    let screen = draw(&mut terminal, &wizard);
    assert!(screen.contains(generated.as_str()), "shown once: {screen}");
    assert!(screen.contains("shown once"));
    press(&mut wizard, Control::CreateVault);
    assert!(error(&wizard).contains("write the passphrase down"));
    press(&mut wizard, Control::PassphraseWritten);
    assert!(wizard.passphrase_written);
    press(&mut wizard, Control::CreateVault);
    assert_eq!(wizard.step, Step::Secret, "{:?}", wizard.message);
    assert!(wizard.generated_passphrase.is_none());
    let screen = draw(&mut terminal, &wizard);
    assert!(!screen.contains(generated.as_str()), "shown again");
    assert_eq!(wizard_backend(&wizard).passphrase_len, 20);

    // A typed strong value, confirmed.
    focus(&mut wizard, Control::SecretValue);
    type_text(&mut wizard, VALUE);
    focus(&mut wizard, Control::SecretConfirm);
    type_text(&mut wizard, VALUE);
    press(&mut wizard, Control::StoreSecret);
    assert_eq!(wizard.step, Step::Recovery, "{:?}", wizard.message);
    assert_eq!(
        wizard_backend(&wizard).secrets,
        vec![("database-password".to_owned(), VALUE.len())]
    );

    press(&mut wizard, Control::ShowCodes);
    let codes: Vec<String> = wizard
        .codes
        .as_ref()
        .unwrap()
        .iter()
        .map(|c| c.to_string())
        .collect();
    assert_eq!(codes.len(), 5);
    let screen = draw(&mut terminal, &wizard);
    assert!(
        codes.iter().all(|c| screen.contains(c.as_str())),
        "{screen}"
    );
    press(&mut wizard, Control::FinishRecovery);
    assert!(error(&wizard).contains("tick the box"));
    assert_eq!(wizard.step, Step::Recovery);
    press(&mut wizard, Control::CodesWritten);
    focus(&mut wizard, Control::Hint);
    type_text(&mut wizard, "the usual phrase, with the year");
    press(&mut wizard, Control::FinishRecovery);
    assert_eq!(wizard.step, Step::SecondFactor, "{:?}", wizard.message);
    assert!(
        wizard.codes.is_none(),
        "the codes are dropped with the step"
    );
    let screen = draw(&mut terminal, &wizard);
    assert!(codes.iter().all(|c| !screen.contains(c.as_str())));
    let fake = wizard_backend(&wizard);
    assert_eq!(fake.codes_issued, 5);
    assert_eq!(
        fake.hint.as_deref(),
        Some("the usual phrase, with the year")
    );
    assert!(!screen.contains(VALUE));
}

#[test]
fn skipping_the_second_factor_narrows_the_guard_and_three_misses_cancel_an_enrolment() {
    let mut wizard = Wizard::new(Fake::default(), "development", "api-key");
    wizard.update(Action::Enter);
    press(&mut wizard, Control::GeneratePassphrase);
    press(&mut wizard, Control::PassphraseWritten);
    press(&mut wizard, Control::CreateVault);
    press(&mut wizard, Control::GenerateSecret);
    press(&mut wizard, Control::StoreSecret);
    press(&mut wizard, Control::FinishRecovery);
    assert_eq!(wizard.step, Step::SecondFactor);

    press(&mut wizard, Control::Enrol);
    for attempt in 1..=3 {
        focus(&mut wizard, Control::Code);
        type_text(&mut wizard, "000000");
        press(&mut wizard, Control::Verify);
        if attempt < 3 {
            assert!(wizard.enrolment.is_some());
        }
    }
    assert!(wizard.enrolment.is_none(), "removed after three misses");
    assert!(error(&wizard).contains("enrolment was removed"));
    assert_eq!(wizard_backend(&wizard).cancelled, 1);
    assert!(!wizard_backend(&wizard).enrolled);

    // Enrol again and skip: the enrolment is cancelled too.
    press(&mut wizard, Control::Enrol);
    press(&mut wizard, Control::SkipSecondFactor);
    assert_eq!(wizard.step, Step::Guard);
    assert_eq!(wizard.second_factor, Some(false));
    assert_eq!(wizard_backend(&wizard).cancelled, 2);
    let options = wizard.guard_options();
    assert_eq!(options.len(), 2);
    assert!(options.iter().all(|(g, _)| !g.second_factor));
    // Space cycles the choice: passphrase, nothing, passphrase.
    focus(&mut wizard, Control::GuardChoice);
    wizard.update(Action::Input(' '));
    assert_eq!(wizard.guard_choice, 1);
    wizard.update(Action::Input(' '));
    assert_eq!(wizard.guard_choice, 0);
    press(&mut wizard, Control::SetGuard);
    assert_eq!(
        wizard_backend(&wizard).guard,
        Some(RevealGuard {
            passphrase: true,
            second_factor: false
        })
    );
    assert_eq!(wizard.step, Step::Project);
    assert_eq!(
        wizard_backend(&wizard).project_written_for.as_deref(),
        Some("api-key")
    );
}

#[test]
fn an_existing_vault_is_opened_through_the_event_loop() {
    let mut fake = Fake::default();
    fake.existing.push("development".to_owned());
    let mut wizard = Wizard::new(fake, "development", "database-password");
    wizard.update(Action::Enter);
    assert!(wizard.vault_exists());
    assert_eq!(
        wizard.controls(),
        vec![Control::VaultName, Control::CreateVault],
        "no passphrase is asked for an existing vault"
    );
    press(&mut wizard, Control::CreateVault);
    assert_eq!(
        wizard.take_request(),
        Some(Request::OpenExisting("development".to_owned()))
    );
    assert_eq!(
        wizard.step,
        Step::Vault,
        "nothing moves until the loop answers"
    );
    wizard.open_existing("development");
    assert_eq!(wizard.step, Step::Secret);
    assert!(!wizard.vault.as_ref().unwrap().created);
    assert_eq!(
        wizard_backend(&wizard).opened.as_deref(),
        Some("development")
    );

    // Another name creates instead.
    let mut fake = Fake::default();
    fake.existing.push("development".to_owned());
    fake.refuse_open =
        Some("vault 'development' is locked: no passphrase supplied (locked)".into());
    let mut wizard = Wizard::new(fake, "development", "database-password");
    wizard.update(Action::Enter);
    press(&mut wizard, Control::CreateVault);
    wizard.take_request();
    wizard.open_existing("development");
    assert_eq!(wizard.step, Step::Vault);
    assert!(error(&wizard).contains("locked"));
    focus(&mut wizard, Control::VaultName);
    type_text(&mut wizard, "-2");
    assert_eq!(wizard.vault_name, "development-2");
    assert!(!wizard.vault_exists());
    assert!(wizard.controls().contains(&Control::Passphrase));
}

#[test]
fn names_are_validated_and_leaving_is_only_from_the_ends() {
    let mut wizard = Wizard::new(Fake::default(), "Dev Vault", "database-password");
    wizard.update(Action::Enter);
    press(&mut wizard, Control::GeneratePassphrase);
    press(&mut wizard, Control::PassphraseWritten);
    press(&mut wizard, Control::CreateVault);
    assert_eq!(wizard.step, Step::Vault);
    assert!(error(&wizard).contains("lowercase"), "{}", error(&wizard));
    // Esc dismisses the message first, and does not leave mid-way.
    wizard.update(Action::Back);
    assert!(wizard.message.is_none());
    wizard.update(Action::Back);
    assert!(!wizard.should_quit());
    wizard.update(Action::Input('q'));
    assert!(!wizard.should_quit(), "q is text on a form");
    assert_eq!(wizard.vault_name, "Dev Vault");
    wizard.update(Action::Quit);
    assert!(wizard.should_quit());

    let mut wizard = Wizard::new(Fake::default(), "development", "database-password");
    wizard.update(Action::Back);
    assert!(wizard.should_quit(), "Esc on the welcome screen leaves");
}

fn wizard_backend(wizard: &Wizard<Fake>) -> &Fake {
    wizard.backend()
}
