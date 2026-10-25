use std::rc::Rc;

use ratatui::Terminal;
use ratatui::backend::TestBackend;

use super::*;
use crate::ui::app::tests::app_with;
use crate::ui::app::{Action, Tab};
use crate::ui::fake::Fake;
use crate::ui::session::Session;

fn render(app: &mut App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal
        .draw(|frame| draw(frame, app, &Theme::plain()))
        .unwrap();
    let buffer = terminal.backend().buffer();
    let width = usize::from(buffer.area.width);
    buffer
        .content()
        .chunks(width)
        .map(|row| {
            row.iter()
                .map(ratatui::buffer::Cell::symbol)
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// A browser on the fake vault's secret list.
fn app(names: &[&'static str]) -> (Rc<Fake>, App) {
    let fake = Fake::with(names);
    let mut app = app_with(&fake);
    app.update(Action::Show(Tab::Secrets));
    (fake, app)
}

#[test]
fn draws_the_vault_its_views_and_its_secrets() {
    let (_, mut app) = app(&["api-key", "database-password"]);
    let screen = render(&mut app, 120, 16);
    assert!(screen.contains("SourceOrrery"), "{screen}");
    assert!(screen.contains("vault development"), "{screen}");
    assert!(
        screen.contains("no view check  ·  storage: SourceOrrery"),
        "{screen}"
    );
    assert!(screen.contains("2 Secrets 2"), "{screen}");
    assert!(
        screen.contains("3 Projects 0   4 Deleted 0   5 Audit log 4   6 Vaults 2"),
        "the overview read them all: {screen}"
    );
    assert!(screen.contains("SECRETS  2"), "{screen}");
    assert!(screen.contains("▌ api-key"), "{screen}");
    assert!(screen.contains("database-password"), "{screen}");
    assert!(screen.contains("01234567 "), "short version: {screen}");
    assert!(screen.contains("Enter details"), "{screen}");
    assert!(screen.contains(REASSURANCE.trim_end()), "{screen}");
}

#[test]
fn tables_are_ruled_above_below_and_under_the_headings() {
    let (_, mut app) = app(&["a", "b"]);
    let screen = render(&mut app, 100, 16);
    let lines: Vec<&str> = screen.lines().collect();
    let ruled = |i: usize| lines[i].trim().chars().all(|c| c == '─');
    // header, tabs, gap, label, rule, headings, rule, a, b, rule
    assert!(lines[3].contains("SECRETS"), "{screen}");
    assert!(ruled(4) && ruled(6) && ruled(9), "{screen}");
    assert!(
        lines[5].contains("NAME") && lines[5].contains("TAGS"),
        "{screen}"
    );
    assert!(!screen.contains('│'), "no vertical lines: {screen}");
}

#[test]
fn a_search_shows_its_query_and_what_is_left() {
    let (_, mut app) = app(&["api-key", "database-password", "db-url"]);
    app.update(Action::Search);
    for c in "db".chars() {
        app.update(Action::Input(c));
    }
    let screen = render(&mut app, 120, 16);
    assert!(screen.contains("SECRETS  1 of 3    / db▌"), "{screen}");
    assert!(screen.contains("db-url"), "{screen}");
    assert!(!screen.contains("api-key"), "{screen}");
    assert!(screen.contains("type to filter"), "{screen}");

    app.update(Action::Input('x'));
    let screen = render(&mut app, 120, 16);
    assert!(
        screen.contains("Nothing matches the search. Esc clears it."),
        "{screen}"
    );
}

#[test]
fn details_show_fields_versions_and_activity() {
    let (_, mut app) = app(&["database-password"]);
    app.update(Action::Open);
    let screen = render(&mut app, 120, 30);
    assert!(screen.contains("database-password  enabled"), "{screen}");
    assert!(
        screen.contains("0123456789abcdef0123456789abcdef  "),
        "{screen}"
    );
    assert!(
        screen.contains(
            "reference      sourceorrery://development/database-password/0123456789abcdef0123456789abcdef"
        ),
        "the whole reference: {screen}"
    );
    assert!(screen.contains("VERSIONS  2"), "{screen}");
    assert!(
        screen.contains("▌ 0123456789abcdef0123456789abcdef  newest"),
        "{screen}"
    );
    assert!(
        screen.contains("fedcba9876543210fedcba9876543210"),
        "{screen}"
    );
    assert!(screen.contains("RECENT ACTIVITY  1"), "{screen}");
    assert!(screen.contains("secret_set"), "{screen}");
    assert!(screen.contains("Esc back"), "{screen}");
}

#[test]
fn deleted_secrets_show_their_purge_date() {
    let fake = Fake::with(&["a"]);
    fake.deleted_names.borrow_mut().push("retired-token");
    let mut app = app_with(&fake);
    app.update(Action::Show(Tab::Deleted));
    let screen = render(&mut app, 120, 16);
    assert!(screen.contains("4 Deleted 1"), "{screen}");
    assert!(screen.contains("▌ retired-token"), "{screen}");
    assert!(
        screen.contains("88 days") || screen.contains("89 days"),
        "{screen}"
    );

    app.update(Action::Open);
    let screen = render(&mut app, 120, 24);
    assert!(screen.contains("retired-token  deleted"), "{screen}");
    assert!(screen.contains("purge after"), "{screen}");
    assert!(
        !screen.contains("VERSIONS"),
        "a deleted secret's versions are not read: {screen}"
    );
}

#[test]
fn the_audit_log_marks_failures() {
    let (_, mut app) = app(&["a"]);
    app.update(Action::Show(Tab::Audit));
    let screen = render(&mut app, 130, 16);
    assert!(screen.contains("AUDIT LOG  3"), "{screen}");
    assert!(screen.contains("vault_open"), "{screen}");
    assert!(screen.contains("failure"), "{screen}");
    assert!(screen.contains("locked"), "{screen}");
    assert!(screen.contains("secret_set"), "{screen}");
}

#[test]
fn the_vault_list_marks_the_open_vault() {
    let (_, mut app) = app(&["a"]);
    app.update(Action::Show(Tab::Vaults));
    let screen = render(&mut app, 120, 14);
    assert!(screen.contains("▌ development  open"), "{screen}");
    assert!(screen.contains("staging"), "{screen}");
    assert!(screen.contains("64 KiB"), "{screen}");
    assert!(screen.contains("Enter open"), "{screen}");
}

#[test]
fn without_a_vault_the_other_views_point_at_the_vault_list() {
    let mut app = App::new(Fake::vault_entries());
    let screen = render(&mut app, 120, 12);
    assert!(screen.contains("no vault open"), "{screen}");
    assert!(screen.contains("VAULTS  2"), "{screen}");
    app.update(Action::Show(Tab::Secrets));
    let screen = render(&mut app, 120, 12);
    assert!(screen.contains("No vault is open."), "{screen}");
}

#[test]
fn a_blocked_vault_says_why_and_how_to_unblock() {
    let (fake, _) = app(&["a"]);
    fake.blocked.set(true);
    let mut app = app_with(&fake);
    let screen = render(&mut app, 120, 20);
    assert!(screen.contains("BLOCKED"), "{screen}");
    assert!(screen.contains("event 42: rows removed after"), "{screen}");
    assert!(
        screen.contains("2 Secrets   3 Projects   4 Deleted"),
        "nothing was read, so no counts: {screen}"
    );
    assert!(
        screen.contains("sourceorrery audit --acknowledge"),
        "{screen}"
    );
    assert!(
        screen.contains("AUDIT LOG"),
        "the log is still shown: {screen}"
    );
    app.update(Action::Show(Tab::Secrets));
    let screen = render(&mut app, 120, 20);
    assert!(screen.contains("BLOCKED"), "{screen}");
    assert!(!screen.contains("SECRETS"), "{screen}");
}

#[test]
fn messages_are_callouts() {
    let (_, mut app) = app(&["a"]);
    app.message = Some(Message::Info("reloaded vault 'development'".into()));
    assert!(render(&mut app, 100, 14).contains("▌ NOTE  reloaded vault 'development'"));
    app.message = Some(Message::Error("refresh failed (crypto): x".into()));
    assert!(render(&mut app, 100, 14).contains("▌ ERROR  refresh failed (crypto): x"));
}

#[test]
fn the_help_lists_the_keys_and_what_is_recorded() {
    let (_, mut app) = app(&["a"]);
    app.update(Action::Help);
    let screen = render(&mut app, 110, 46);
    assert!(screen.contains("KEYS"), "{screen}");
    assert!(screen.contains("on the setup screens"), "{screen}");
    assert!(screen.contains("switch view"), "{screen}");
    assert!(screen.contains("tag:env=prod"), "{screen}");
    assert!(screen.contains("WHAT THE VAULT RECORDS"), "{screen}");
    assert!(screen.contains("Esc ? close"), "{screen}");
}

#[test]
fn the_page_is_the_rows_on_screen() {
    let (_, mut app) = app(&["a"; 40]);
    // header, tabs, gap and footer, then five rows of table chrome
    render(&mut app, 80, 20);
    assert_eq!(app.list(Tab::Secrets).page, 11);
    app.message = Some(Message::Info("x".into()));
    render(&mut app, 80, 20);
    assert_eq!(app.list(Tab::Secrets).page, 10);
    render(&mut app, 80, 4);
    assert_eq!(app.list(Tab::Secrets).page, 1);
}

#[test]
fn a_narrow_footer_drops_the_reassurance_not_the_keys() {
    let (_, mut app) = app(&["a"]);
    let screen = render(&mut app, 80, 12);
    assert!(screen.contains("q quit"), "{screen}");
    assert!(!screen.contains("never shown"), "{screen}");
}

#[test]
fn stored_control_characters_are_drawn_escaped() {
    let fake = Rc::new(Fake {
        tags: vec![("note", "a\u{1b}[2Kb\u{202e}c")],
        ..Fake::default()
    });
    fake.names.borrow_mut().push("api-key");
    let mut app = app_with(&fake);
    app.update(Action::Show(Tab::Secrets));
    let screen = render(&mut app, 140, 12);
    assert!(screen.contains(r"note=a\u{1b}[2Kb\u{202e}c"), "{screen}");
    assert!(!screen.contains('\u{1b}'), "raw ESC reached the screen");
    assert!(
        !screen.contains('\u{202e}'),
        "raw bidi override reached the screen"
    );
}

#[test]
fn the_overview_shows_status_expiry_chain_activity_and_keys() {
    let fake = Fake::with(&["api-key", "database-password"]);
    fake.deleted_names.borrow_mut().push("old");
    let mut app = app_with(&fake);
    let screen = render(&mut app, 130, 30);
    assert!(screen.contains("1 Overview"), "{screen}");
    assert!(screen.contains("SECRETS  2 live · 1 deleted"), "{screen}");
    assert!(screen.contains("enabled     2  █"), "{screen}");
    assert!(
        screen.contains("next purge  in 88 days") || screen.contains("next purge  in 89 days"),
        "{screen}"
    );
    assert!(screen.contains("EXPIRY"), "{screen}");
    assert!(screen.contains("never           2"), "{screen}");
    assert!(screen.contains("AUDIT CHAIN  intact"), "{screen}");
    assert!(
        screen.contains("rows            4 · 1 before unlock"),
        "{screen}"
    );
    assert!(screen.contains("UPCOMING  0"), "{screen}");
    assert!(
        screen.contains("Nothing is due to expire or activate."),
        "{screen}"
    );
    assert!(
        screen.contains("ACTIVITY · 14 DAYS  4 events · 0 denied · 1 failures"),
        "{screen}"
    );
    assert!(screen.contains("last failed unlock"), "{screen}");
    assert!(screen.contains("opens with recovery key"), "{screen}");
    for text in [
        "VIEW CHECK",
        "password  none",
        "STORAGE  1",
        "vault      the file · 2 secrets",
        "PROJECTS  0",
        "none yet: run",
    ] {
        assert!(screen.contains(text), "{text}: {screen}");
    }
    assert!(screen.contains("v verify chain"), "{screen}");
}

#[test]
fn a_broken_chain_is_not_intact() {
    let fake = Fake::with(&["a"]);
    fake.broken.set(true);
    let mut app = app_with(&fake);
    let screen = render(&mut app, 130, 30);
    assert!(screen.contains("AUDIT CHAIN  NOT INTACT"), "{screen}");
    assert!(screen.contains("first break     event 2"), "{screen}");
}

#[test]
fn a_blocked_vaults_overview_says_what_it_did_not_read() {
    let fake = Fake::with(&["a"]);
    fake.blocked.set(true);
    let mut app = app_with(&fake);
    app.update(Action::Show(Tab::Overview));
    let screen = render(&mut app, 130, 34);
    assert!(screen.contains("BLOCKED"), "{screen}");
    assert!(
        screen.contains("not read: the vault is blocked"),
        "{screen}"
    );
    assert!(screen.contains("1 · 1 unacknowledged"), "{screen}");
}

#[test]
fn a_locked_browser_says_so_and_how_to_unlock() {
    let (_, mut app) = app(&["a"]);
    app.update(Action::Lock);
    let screen = render(&mut app, 120, 14);
    assert!(screen.contains("vault development  ·  locked"), "{screen}");
    assert!(
        screen.contains("Vault 'development' is locked."),
        "{screen}"
    );
    assert!(screen.contains("Enter unlocks it again"), "{screen}");
    assert!(screen.contains("Enter unlock"), "{screen}");
    assert!(
        screen.contains("▌ NOTE  locked vault 'development'"),
        "{screen}"
    );
}

#[test]
fn a_form_shows_its_fields_the_focused_hint_and_errors() {
    let (_, mut app) = app(&["database-password"]);
    app.update(Action::Edit);
    let screen = render(&mut app, 120, 30);
    assert!(
        screen.contains("CHANGE VERSION 01234567 OF 'database-password'"),
        "{screen}"
    );
    assert!(
        screen.contains("enabled        yes   space switches yes and no"),
        "{screen}"
    );
    assert!(screen.contains("content type"), "{screen}");
    assert!(screen.contains("Tab next field"), "{screen}");
    for _ in 0..4 {
        app.update(Action::Down);
    }
    for c in "soon".chars() {
        app.update(Action::Input(c));
    }
    app.update(Action::Commit);
    let screen = render(&mut app, 120, 30);
    assert!(screen.contains("expires        soon▌"), "{screen}");
    assert!(
        screen.contains("ERROR  expires: 'soon' is not an RFC 3339 timestamp"),
        "{screen}"
    );
}

#[test]
fn a_confirmation_says_what_will_happen() {
    let (_, mut app) = app(&["database-password"]);
    app.update(Action::Toggle);
    let screen = render(&mut app, 120, 24);
    assert!(screen.contains("DISABLE VERSION"), "{screen}");
    assert!(
        screen.contains("can no longer be read, by anyone"),
        "{screen}"
    );
    assert!(screen.contains("Enter confirm"), "{screen}");
}

#[test]
fn deleting_for_good_shows_what_to_type() {
    let fake = Fake::with(&["db"]);
    fake.purgeable.set(true);
    let mut app = app_with(&fake);
    app.update(Action::Show(Tab::Secrets));
    app.update(Action::Delete);
    for c in "d".chars() {
        app.update(Action::Input(c));
    }
    let screen = render(&mut app, 120, 24);
    assert!(screen.contains("DELETE FOR GOOD"), "{screen}");
    assert!(screen.contains("This cannot be undone."), "{screen}");
    assert!(screen.contains("type 'db' to confirm  d▌"), "{screen}");
}

#[test]
fn change_keys_show_only_where_changes_are_possible() {
    let (_, mut app) = app(&["a"]);
    let screen = render(&mut app, 130, 14);
    assert!(
        screen.contains("e edit") && screen.contains("d delete"),
        "{screen}"
    );

    let fake = Fake::with(&["a"]);
    let mut read_only = App::new(Vec::new()).with_read_only(true);
    read_only.set_session(Session::open(Box::new(Rc::clone(&fake))).unwrap());
    read_only.update(Action::Show(Tab::Secrets));
    let screen = render(&mut read_only, 130, 14);
    assert!(screen.contains("·  read-only"), "{screen}");
    assert!(!screen.contains("e edit"), "{screen}");
    read_only.update(Action::Help);
    let screen = render(&mut read_only, 130, 44);
    assert!(
        screen.contains("None: this browser is read-only"),
        "{screen}"
    );
}
