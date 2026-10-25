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
    app.update(Action::Open);
    assert!(
        render(&mut app, 120, 24).contains("01234567"),
        "full version reachable in details"
    );
    assert!(screen.contains("Enter details"), "{screen}");
    assert!(
        render(&mut app, 160, 24).contains(REASSURANCE.trim_end()),
        "reassurance fits after the action hints at wide sizes"
    );
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
    assert!(
        screen.contains("▌ development") && screen.contains("open"),
        "{screen}"
    );
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
    let screen = render(&mut app, 130, 42);
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

#[test]
fn help_is_scrollable_at_ordinary_and_compact_sizes_without_reads() {
    let (fake, mut app) = app(&["a"]);
    let reads = (
        fake.lists.get(),
        fake.inspects.get(),
        fake.audit_reads.get(),
    );
    app.update(Action::Help);
    for (w, h) in [(80, 24), (60, 18)] {
        app.update(Action::Top);
        let first = render(&mut app, w, h);
        assert!(first.contains("CURRENT VIEW"), "{first}");
        assert!(first.contains("Esc close"), "{first}");
        let mut seen = first;
        for _ in 0..10 {
            app.update(Action::PageDown);
            seen.push_str(&render(&mut app, w, h));
        }
        assert!(seen.contains("WHAT THE VAULT RECORDS"), "{seen}");
        assert!(seen.contains("SEARCH"));
        app.update(Action::Bottom);
        assert!(render(&mut app, w, h).contains("Esc close"));
    }
    assert_eq!(
        (
            fake.lists.get(),
            fake.inspects.get(),
            fake.audit_reads.get()
        ),
        reads
    );
    app.update(Action::Back);
    assert!(!app.help);
}

#[test]
fn fifty_project_declarations_are_reachable_without_reads() {
    use crate::ui::session::{Project, ProjectStatus};
    let (fake, mut app) = app(&["a"]);
    let project = Project {
        link: sourceorrery_storage::ProjectLink {
            id: "project-id".into(),
            name: "fixture".into(),
            path: "/synthetic/界/e\u{301}".into(),
            linked_on: sourceorrery_core::timestamp::now(),
        },
        status: ProjectStatus::Found {
            vault: "development".into(),
            secrets: (0..50).map(|i| format!("declared-{i:02}")).collect(),
        },
    };
    app.session.as_mut().unwrap().projects.push(project);
    app.update(Action::Show(Tab::Projects));
    app.update(Action::Open);
    let reads = (
        fake.lists.get(),
        fake.inspects.get(),
        fake.audit_reads.get(),
    );
    let mut seen = String::new();
    for _ in 0..50 {
        seen.push_str(&render(&mut app, 80, 24));
        app.update(Action::Down);
    }
    for i in 0..50 {
        assert!(seen.contains(&format!("declared-{i:02}")));
    }
    assert!(seen.contains("of 50"));
    app.update(Action::Top);
    app.update(Action::PageDown);
    assert!(app.declarations.selected().unwrap() > 0);
    app.update(Action::Back);
    assert_eq!(app.selected_project().unwrap().link.id, "project-id");
    assert_eq!(
        (
            fake.lists.get(),
            fake.inspects.get(),
            fake.audit_reads.get()
        ),
        reads
    );
}

#[test]
fn bounded_forms_and_reviews_keep_controls_and_long_targets_reachable() {
    let (fake, mut app) = app(&["a"]);
    app.update(Action::Edit);
    if let Some(Dialog::Form(form)) = app.dialog.as_mut() {
        form.fields[2].value = "env=word heavy metadata 界e\u{301}, ".repeat(30);
        form.focus = form.fields.len() - 1;
        form.error =
            Some("Check the expiry: word heavy validation detail ".repeat(25) + "END-ERROR");
    }
    for (w, h) in [(80, 24), (60, 18)] {
        let screen = render(&mut app, w, h);
        assert!(screen.contains("expires"), "{screen}");
        assert!(screen.contains("Esc cancel"), "{screen}");
        app.update(Action::Bottom);
        let screen = render(&mut app, w, h);
        assert!(screen.contains("END-ERROR"), "{screen}");
        assert!(screen.contains("Enter review"));
    }
    assert!(fake.writes.borrow().is_empty());
    app.update(Action::Back);
    app.update(Action::Toggle);
    if let Some(Dialog::Confirm(c)) = app.dialog.as_mut() {
        c.lines = vec!["Full confirmation target ".repeat(60) + "END-TARGET"];
    }
    render(&mut app, 60, 18);
    app.update(Action::Bottom);
    let screen = render(&mut app, 60, 18);
    assert!(screen.contains("END-TARGET"), "{screen}");
    assert!(screen.contains("Enter confirm"));
    app.update(Action::Back);
    assert!(fake.writes.borrow().is_empty());
}

#[test]
fn responsive_width_matrix_keeps_names_status_and_metadata_overflow_without_reads() {
    let (fake, mut app) = app(&["selected-secret-with-a-long-name", "second"]);
    let reads = (
        fake.lists.get(),
        fake.inspects.get(),
        fake.audit_reads.get(),
    );
    app.session.as_mut().unwrap().secrets[0]
        .tags
        .insert("long".into(), "界e\u{301}".repeat(80));
    for width in [60, 80, 100, 120, 160] {
        let screen = render(&mut app, width, 24);
        assert!(
            screen.contains("NAME") && screen.contains("STATUS"),
            "{screen}"
        );
        assert!(screen.contains("enabled"), "{screen}");
        assert!(
            screen.contains("selected") || screen.contains("…"),
            "{screen}"
        );
        assert!(
            screen.contains("help") || screen.contains("keys"),
            "{screen}"
        );
    }
    assert_eq!(
        (
            fake.lists.get(),
            fake.inspects.get(),
            fake.audit_reads.get()
        ),
        reads
    );
}

#[test]
fn compact_overview_reaches_every_section_and_resize_keeps_active_tab_and_state() {
    let fake = Fake::with(&["a"]);
    let mut app = app_with(&fake).with_read_only(true);
    let reads = (
        fake.lists.get(),
        fake.inspects.get(),
        fake.audit_reads.get(),
    );
    let mut seen = String::new();
    for _ in 0..12 {
        seen.push_str(&render(&mut app, 80, 24));
        app.update(Action::PageDown);
    }
    for title in [
        "AUDIT CHAIN",
        "EXPIRY",
        "SECRETS",
        "VAULT",
        "VIEW CHECK",
        "STORAGE",
        "PROJECTS",
        "ACTIVITY",
    ] {
        assert!(seen.to_uppercase().contains(title), "{title}: {seen}");
    }
    for width in [60, 80, 100, 120, 160] {
        for tab in Tab::ALL {
            app.update(Action::Show(tab));
            let screen = render(&mut app, width, 18);
            assert!(
                screen.contains(tab.title().split_whitespace().next().unwrap()),
                "{screen}"
            );
            assert!(screen.contains("read-only"), "{screen}");
            assert!(screen.contains("help") || screen.contains("keys"));
        }
    }
    assert_eq!(
        (
            fake.lists.get(),
            fake.inspects.get(),
            fake.audit_reads.get()
        ),
        reads
    );
}

#[test]
fn actions_menu_is_bounded_pure_and_revalidates_before_execution() {
    let (fake, mut app) = app(&["a"]);
    app.update(Action::Open);
    app.update(Action::Down);
    let reads = (
        fake.lists.get(),
        fake.inspects.get(),
        fake.audit_reads.get(),
        fake.capability_reads.get(),
    );
    app.update(Action::Actions);
    for (w, h) in [(80, 24), (60, 18), (120, 40)] {
        for a in [
            Action::Top,
            Action::Down,
            Action::PageDown,
            Action::Bottom,
            Action::PageUp,
        ] {
            app.update(a);
            let screen = render(&mut app, w, h);
            assert!(screen.contains("Esc back"), "{screen}");
        }
    }
    assert!(fake.writes.borrow().is_empty());
    assert_eq!(
        (
            fake.lists.get(),
            fake.inspects.get(),
            fake.audit_reads.get(),
            fake.capability_reads.get()
        ),
        reads
    );
    // Availability is checked again after the menu was constructed.
    let edit = app
        .menu
        .as_ref()
        .unwrap()
        .items
        .iter()
        .position(|i| i.action == Action::Edit)
        .unwrap();
    app.menu.as_mut().unwrap().state.select(Some(edit));
    app.session.as_mut().unwrap().secrets.clear();
    app.versions.select(None);
    app.update(Action::Commit);
    assert!(app.dialog.is_none());
    assert!(app.menu.is_some());
    app.update(Action::Back);
    assert_eq!(app.detail.as_deref(), Some("a"));
}

#[test]
fn read_only_menu_discloses_reasons_and_overview_does_not_open_empty_search() {
    let fake = Fake::with(&[]);
    let mut app = app_with(&fake).with_read_only(true);
    app.update(Action::Search);
    assert!(!app.editing);
    app.update(Action::Show(Tab::Secrets));
    assert!(!render(&mut app, 80, 24).contains("a adds one"));
    app.update(Action::Actions);
    let menu = app.menu.as_ref().unwrap();
    assert!(
        menu.items
            .iter()
            .filter(|i| matches!(i.action, Action::Edit | Action::Add | Action::Delete))
            .all(|i| i.reason.as_ref().is_some_and(|s| s.contains("read-only")))
    );
    app.update(Action::Down);
    app.update(Action::Commit);
    assert!(fake.writes.borrow().is_empty());
    assert!(app.dialog.is_none());
}

#[test]
fn cached_inspection_reads_complete_metadata_and_restores_exact_state() {
    use crate::ui::session::{Project, ProjectStatus};
    let (fake, mut app) = app(&["a", "b"]);
    app.session.as_mut().unwrap().secrets[0]
        .tags
        .insert("note".into(), "界e\u{301} ".repeat(90) + "\u{1b}END-TAG");
    app.apply_query("status:enabled".into());
    render(&mut app, 80, 24);
    let before = (
        app.list(Tab::Secrets).query.clone(),
        app.list(Tab::Secrets).table,
        app.detail.clone(),
    );
    let reads = (
        fake.lists.get(),
        fake.inspects.get(),
        fake.audit_reads.get(),
        fake.capability_reads.get(),
    );
    app.update(Action::Inspect);
    let mut seen = String::new();
    for _ in 0..30 {
        seen.push_str(&render(&mut app, 60, 18));
        app.update(Action::PageDown);
    }
    assert!(seen.contains("END-TAG"), "{seen}");
    assert!(!seen.contains('\u{1b}'));
    assert!(seen.contains(r"\u{1b}"));
    app.update(Action::Back);
    assert_eq!(
        (
            app.list(Tab::Secrets).query.clone(),
            app.list(Tab::Secrets).table,
            app.detail.clone()
        ),
        before
    );
    // Long project paths and errors have the same cached inspection route.
    app.session.as_mut().unwrap().projects.push(Project {
        link: sourceorrery_storage::ProjectLink {
            id: "p".into(),
            name: "project".into(),
            path: std::path::PathBuf::from("/界/e\u{301}/".repeat(60) + "END-PATH"),
            linked_on: sourceorrery_core::timestamp::now(),
        },
        status: ProjectStatus::Unreadable("safe manifest error".into()),
    });
    app.update(Action::Show(Tab::Projects));
    app.update(Action::Inspect);
    render(&mut app, 80, 24);
    app.update(Action::Bottom);
    assert!(render(&mut app, 80, 24).contains("END-PATH"));
    app.update(Action::Back);
    app.message = Some(Message::Error(
        "safe provider failure ".repeat(90) + "END-ERROR",
    ));
    assert!(render(&mut app, 80, 24).contains("! details"));
    app.update(Action::ErrorDetails);
    render(&mut app, 80, 24);
    app.update(Action::Bottom);
    assert!(render(&mut app, 80, 24).contains("END-ERROR"));
    app.update(Action::Back);
    app.update(Action::Show(Tab::Vaults));
    app.vaults[0].path = std::path::PathBuf::from("/synthetic/".repeat(60) + "END-VAULT");
    app.update(Action::Inspect);
    render(&mut app, 60, 18);
    app.update(Action::Bottom);
    let screen = render(&mut app, 60, 18);
    assert!(
        screen
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '│')
            .collect::<String>()
            .contains("END-VAULT"),
        "{screen}"
    );
    app.update(Action::Back);
    app.update(Action::Show(Tab::Audit));
    app.update(Action::Inspect);
    assert!(
        app.inspection
            .as_ref()
            .unwrap()
            .lines
            .iter()
            .any(|s| s.starts_with("Actor:"))
    );
    app.update(Action::Back);
    assert_eq!(
        (
            fake.lists.get(),
            fake.inspects.get(),
            fake.audit_reads.get(),
            fake.capability_reads.get()
        ),
        reads
    );
}

#[test]
fn highlighted_spans_reconstruct_sanitised_metadata_in_every_selection_style() {
    use crate::cli::UiTheme;
    let raw = "İstanbul 界e\u{301}\u{1b}b";
    for choice in [UiTheme::Dark, UiTheme::Light, UiTheme::Terminal] {
        for color in [true, false] {
            for selected in [true, false] {
                let theme = Theme::new(choice, color, true);
                let line = highlighted(raw, "i b", &theme, selected);
                assert_eq!(
                    line.spans
                        .iter()
                        .map(|s| s.content.as_ref())
                        .collect::<String>(),
                    output::sanitize(raw)
                );
                for span in line.spans.iter().filter(|s| {
                    s.style
                        .add_modifier
                        .contains(ratatui::style::Modifier::UNDERLINED)
                }) {
                    if selected && theme.selected.fg.is_some() {
                        assert_eq!(span.style.fg, theme.selected.fg);
                    }
                }
            }
        }
    }
}

#[test]
fn zero_and_tiny_render_areas_are_safe_and_cancel_still_works() {
    let (_, mut app) = app(&["a"]);
    for (w, h) in [(0, 0), (1, 1), (20, 6)] {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        for tab in Tab::ALL {
            app.update(Action::Show(tab));
            terminal
                .draw(|frame| draw(frame, &mut app, &Theme::plain()))
                .unwrap();
        }
        for action in [Action::Help, Action::Actions, Action::Inspect] {
            app.update(action);
            terminal
                .draw(|frame| draw(frame, &mut app, &Theme::plain()))
                .unwrap();
            app.update(Action::Back);
        }
    }
}

#[test]
fn long_unicode_audit_actor_and_detail_are_fully_cached_and_inspectable() {
    let fake = Rc::new(Fake {
        audit_actor: Some(sourceorrery_core::Principal::new(
            sourceorrery_core::PrincipalKind::Workload,
            "界e\u{301}".repeat(120) + "END-ACTOR",
        )),
        audit_detail: Some("safe cached detail ".repeat(80) + "END-DETAIL"),
        ..Fake::default()
    });
    let mut app = app_with(&fake);
    app.update(Action::Show(Tab::Audit));
    assert!(render(&mut app, 160, 24).contains('…'));
    let reads = (
        fake.lists.get(),
        fake.inspects.get(),
        fake.audit_reads.get(),
    );
    app.update(Action::Inspect);
    let mut seen = String::new();
    for _ in 0..30 {
        seen.push_str(&render(&mut app, 80, 24));
        app.update(Action::PageDown);
    }
    let seen = seen
        .chars()
        .filter(|c| !c.is_whitespace() && !matches!(c, '│' | '┌' | '┐' | '└' | '┘' | '─'))
        .collect::<String>();
    assert!(seen.contains("END-ACTOR") && seen.contains("END-DETAIL"));
    app.update(Action::Back);
    assert_eq!(
        (
            fake.lists.get(),
            fake.inspects.get(),
            fake.audit_reads.get()
        ),
        reads
    );
}
