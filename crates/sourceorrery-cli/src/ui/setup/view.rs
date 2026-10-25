//! Drawing the setup wizard. A function of its state: nothing here reads a
//! vault, and the hidden fields are drawn as dots from their length alone.
//! What is shown once by design (a generated password, the authenticator
//! key and its QR code, a new recovery key) is drawn from the wizard's
//! memory until the review commits it.
//!
//! The look is the browser's and `init`'s: the header bar, an uppercase step
//! rail, a title and a few lines of explanation per screen, the controls as
//! a form (the focused one on the selection colour with the accent bar),
//! messages as callouts, a footer of keys. The authenticator screen has two
//! columns: the QR code on the left, the key, the code field and the buttons
//! on the right, so the controls stay on a small screen.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Margin, Rect};
use ratatui::style::Style;
use ratatui::symbols::border;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use sourceorrery_core::Provider;
use sourceorrery_storage::CredentialSource;

use super::backend::Backend;
use super::wizard::{Control, Field, Form, Message, PROVIDERS, Step, Wizard};
use crate::output::sanitize;
use crate::strength::{Estimate, Score};
use crate::ui::theme::{Callout, Theme};

/// Width of a form's label column.
const LABEL_WIDTH: usize = 20;
/// Cells in the strength meter.
const METER: usize = 10;
/// The footer's last words, where they fit.
const NOTE: &str = "nothing is saved until the review";

pub fn draw<B: Backend>(frame: &mut Frame<'_>, wizard: &Wizard<B>, theme: &Theme) {
    frame.render_widget(Block::new().style(theme.screen), frame.area());
    let qr = qr_lines(wizard, theme);
    // Beside the QR code the message goes in the right column, so the code
    // keeps every row a 24-line terminal has.
    let message_below = qr.is_none();
    let message_height = u16::from(message_below && wizard.message.is_some()) * 2;
    let [header, rail, _, body, message, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(message_height),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    frame.render_widget(header_bar(wizard, theme), header);
    frame.render_widget(rail_line(wizard, theme), rail);

    let mut area = body.inner(Margin::new(2, 0));
    if let Some(qr) = qr {
        let width = qr.iter().map(Line::width).max().unwrap_or(0) + 2;
        let [left, right] = Layout::horizontal([
            Constraint::Length(u16::try_from(width).unwrap_or(u16::MAX)),
            Constraint::Min(0),
        ])
        .areas(area);
        frame.render_widget(Paragraph::new(qr), left);
        area = right;
    }
    let (mut lines, focus_line) = body_lines(wizard, theme);
    if !message_below && let Some(message) = &wizard.message {
        lines.push(Line::from(""));
        lines.push(callout_line(message, theme));
    }
    let scroll = scroll_for(&lines, focus_line, area);
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        area,
    );
    if message_below && let Some(text) = &wizard.message {
        frame.render_widget(callout(text, theme), message);
    }
    frame.render_widget(footer_line(wizard, theme, footer.width), footer);
}

/// The rows to scroll by so the focused line is on screen: none while it
/// fits, else enough to bring it to the bottom edge.
fn scroll_for(lines: &[Line<'_>], focus_line: Option<usize>, area: Rect) -> u16 {
    let (Some(focus), true) = (focus_line, area.width > 0) else {
        return 0;
    };
    let width = usize::from(area.width);
    let rows_through: usize = lines
        .iter()
        .take(focus + 1)
        .map(|line| line.width().div_ceil(width).max(1))
        .sum();
    let height = usize::from(area.height);
    u16::try_from(rows_through.saturating_sub(height)).unwrap_or(u16::MAX)
}

/// The vault's name, once there is one to show.
fn vault_name<B: Backend>(wizard: &Wizard<B>) -> Option<&str> {
    if let Some(editing) = &wizard.editing {
        return Some(&editing.name);
    }
    if let Some(chosen) = &wizard.chosen {
        return Some(chosen);
    }
    (!matches!(wizard.step, Step::Start | Step::Name) && !wizard.name.is_empty())
        .then_some(wizard.name.as_str())
}

fn header_bar<B: Backend>(wizard: &Wizard<B>, theme: &Theme) -> Paragraph<'static> {
    let mut spans = vec![
        Span::styled(" SourceOrrery ", theme.title),
        Span::styled(" setup", theme.muted),
    ];
    if let Some(name) = vault_name(wizard) {
        spans.push(Span::styled("  ·  vault ", theme.muted));
        spans.push(Span::styled(sanitize(name).into_owned(), theme.vault));
        let doing = match (&wizard.editing, wizard.step) {
            (_, Step::Done) => "",
            (Some(_), _) => "  ·  changing",
            (None, Step::Unlock) => "  ·  opening",
            (None, _) => "  ·  new",
        };
        spans.push(Span::styled(doing, theme.muted));
    }
    Paragraph::new(Line::from(spans)).style(theme.bar)
}

fn rail_line<B: Backend>(wizard: &Wizard<B>, theme: &Theme) -> Line<'static> {
    let mut spans = vec![Span::raw(" ")];
    for (i, step) in Step::RAIL.into_iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        let (mark, style) = if step == wizard.step.rail_step() {
            ("▶", theme.tab)
        } else if wizard.step.is_past(step) {
            ("✓", theme.muted)
        } else {
            (" ", Style::new())
        };
        spans.push(Span::styled(format!("{mark} {} ", i + 1), theme.muted));
        spans.push(Span::styled(step.title(), style));
    }
    Line::from(spans)
}

fn footer_line<B: Backend>(wizard: &Wizard<B>, theme: &Theme, width: u16) -> Line<'static> {
    let pairs: &[(&str, &str)] = match wizard.step {
        Step::Done => &[("Enter Esc", "leave")],
        Step::Start => &[("Tab ↓ ↑", "move"), ("Enter", "open"), ("Esc", "leave")],
        _ => &[
            ("Tab ↓ ↑", "move"),
            ("Space", "tick"),
            ("Enter", "next / press"),
            ("Esc", "back"),
            ("Ctrl-C", "leave"),
        ],
    };
    let mut spans = vec![Span::raw(" ")];
    for (keys, what) in pairs {
        spans.push(Span::styled((*keys).to_owned(), theme.key));
        spans.push(Span::styled(format!(" {what}   "), theme.muted));
    }
    let used: usize = spans.iter().map(Span::width).sum();
    if wizard.step != Step::Done && used + NOTE.len() <= usize::from(width) {
        spans.push(Span::styled(NOTE, theme.muted));
    }
    Line::from(spans).style(theme.bar)
}

fn callout_block(style: &Callout) -> Block<'static> {
    Block::new()
        .borders(Borders::LEFT)
        .border_set(border::Set {
            vertical_left: "▌",
            ..border::PLAIN
        })
        .border_style(style.bar)
        .style(style.panel)
}

fn callout(message: &Message, theme: &Theme) -> Paragraph<'static> {
    let (style, title, text) = match message {
        Message::Info(text) => (theme.info, "NOTE", text),
        Message::Error(text) => (theme.error, "ERROR", text),
    };
    Paragraph::new(Line::from(vec![
        Span::styled(format!(" {title}  "), style.title),
        Span::raw(sanitize(text).into_owned()),
    ]))
    .wrap(Wrap { trim: false })
    .block(callout_block(&style))
}

fn callout_line(message: &Message, theme: &Theme) -> Line<'static> {
    let (style, title, text) = match message {
        Message::Info(text) => (theme.info, "NOTE", text),
        Message::Error(text) => (theme.error, "ERROR", text),
    };
    Line::from(vec![
        Span::styled(format!(" {title} "), style.title),
        Span::styled(format!(" {}", sanitize(text)), style.panel),
    ])
}

/// The QR code of the authenticator being enrolled, while it waits for a
/// code.
fn qr_lines<B: Backend>(wizard: &Wizard<B>, theme: &Theme) -> Option<Vec<Line<'static>>> {
    if wizard.step != Step::Authenticator || wizard.keeps_authenticator() || wizard.verified() {
        return None;
    }
    let (_, uri) = wizard.enrolment()?;
    Some(match crate::qr::render(&uri) {
        Ok(rows) => rows
            .into_iter()
            .map(|row| Line::from(Span::styled(row, theme.screen)))
            .collect(),
        Err(err) => vec![Line::from(Span::styled(
            format!("cannot draw the QR code: {err}"),
            theme.error.title,
        ))],
    })
}

// ---------------------------------------------------------------------------
// The body of each screen
// ---------------------------------------------------------------------------

/// The body's lines, and which of them holds the focused control.
fn body_lines<B: Backend>(
    wizard: &Wizard<B>,
    theme: &Theme,
) -> (Vec<Line<'static>>, Option<usize>) {
    let title = match wizard.step {
        Step::Start => "VAULT".to_owned(),
        Step::Unlock => "OPEN THE VAULT".to_owned(),
        Step::Password => "VIEW CHECK  ·  PASSWORD".to_owned(),
        Step::Authenticator => "VIEW CHECK  ·  AUTHENTICATOR".to_owned(),
        Step::Connections => "STORAGE  ·  CONNECTIONS".to_owned(),
        step => step.title().to_uppercase(),
    };
    let mut lines = vec![Line::from(Span::styled(title, theme.label)), Line::from("")];
    match wizard.step {
        Step::Start => start(wizard, &mut lines, theme),
        Step::Unlock => unlock(wizard, &mut lines, theme),
        Step::Name => name(wizard, &mut lines, theme),
        Step::ViewCheck => view_check(&mut lines, theme),
        Step::Password => password(wizard, &mut lines, theme),
        Step::Authenticator => authenticator(wizard, &mut lines, theme),
        Step::RecoveryKey => recovery_key(wizard, &mut lines, theme),
        Step::Storage => storage(wizard, &mut lines, theme),
        Step::Connections => prose(
            &mut lines,
            theme,
            &[
                "How each provider is reached. Credentials are this machine's sign-in (the",
                "provider's own: environment, CLI login, workload identity) or stored in the",
                "vault, sealed under its key. Typed ones are dots and go to the vault at review.",
            ],
        ),
        Step::Review => review(wizard, &mut lines, theme),
        Step::Done => done(wizard, &mut lines, theme),
    }
    lines.push(Line::from(""));
    let mut focus_line = None;
    let focused = wizard.focused();
    for control in wizard.controls() {
        if let Some(heading) = control_heading(wizard, control, theme) {
            lines.extend(heading);
        }
        if control == focused {
            focus_line = Some(lines.len());
        }
        lines.push(control_line(wizard, control, theme));
        if let Some(extra) = control_extra(wizard, control, theme) {
            lines.extend(extra);
        }
    }
    (lines, focus_line)
}

/// One paragraph, from `text`'s pieces joined by spaces; the screen wraps
/// it to its width.
fn prose(lines: &mut Vec<Line<'static>>, theme: &Theme, text: &[&str]) {
    lines.push(Line::from(Span::styled(text.join(" "), theme.muted)));
}

/// An authenticator key in groups of four, as apps take it typed.
pub fn key_groups(key: &str) -> String {
    key.as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn row(lines: &mut Vec<Line<'static>>, theme: &Theme, label: &str, value: String) {
    lines.push(Line::from(vec![
        Span::styled(format!("{label:<LABEL_WIDTH$}"), theme.muted),
        Span::raw(value),
    ]));
}

fn this_machine<B: Backend>(wizard: &Wizard<B>, lines: &mut Vec<Line<'static>>, theme: &Theme) {
    let line = match &wizard.store {
        Some(store) => Line::from(vec![
            Span::styled(format!("{} ", sanitize(store)), theme.vault),
            Span::styled(
                "keeps this machine's key, so this machine opens the vault without asking.",
                theme.muted,
            ),
        ]),
        None => Line::from(Span::styled(
            "This machine has no credential store: the vault opens with its recovery key.",
            theme.caution,
        )),
    };
    lines.push(line);
}

fn start<B: Backend>(wizard: &Wizard<B>, lines: &mut Vec<Line<'static>>, theme: &Theme) {
    if wizard.vaults.is_empty() {
        prose(
            lines,
            theme,
            &[
                "There is no vault on this machine yet. A vault is one encrypted file in your home",
                "directory holding your secrets, or the catalog of those a provider keeps.",
            ],
        );
    } else {
        prose(
            lines,
            theme,
            &[
                "Pick a vault to change its view check, its recovery key or where its secrets",
                "are kept, or create a new one.",
            ],
        );
    }
    lines.push(Line::from(""));
    this_machine(wizard, lines, theme);
}

fn unlock<B: Backend>(wizard: &Wizard<B>, lines: &mut Vec<Line<'static>>, theme: &Theme) {
    let name = sanitize(wizard.chosen.as_deref().unwrap_or_default()).into_owned();
    if wizard.needs_key {
        lines.push(Line::from(vec![
            Span::styled("This machine cannot open ", theme.muted),
            Span::styled(name, theme.vault),
            Span::styled(
                " by itself. Type its recovery key: it opens the vault and passes",
                theme.muted,
            ),
        ]));
        prose(
            lines,
            theme,
            &["the view check by itself. It is checked and forgotten, never kept."],
        );
        return;
    }
    lines.push(Line::from(vec![
        Span::styled("Changing ", theme.muted),
        Span::styled(name, theme.vault),
        Span::styled(
            " asks its view check first: without it anyone at this machine",
            theme.muted,
        ),
    ]));
    prose(lines, theme, &["could switch the check off."]);
    if let Some(hint) = wizard.pending_hint() {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("Hint  ", theme.muted),
            Span::raw(sanitize(hint).into_owned()),
        ]));
    }
}

fn name<B: Backend>(wizard: &Wizard<B>, lines: &mut Vec<Line<'static>>, theme: &Theme) {
    prose(
        lines,
        theme,
        &[
            "The new vault's name: letters, digits, hyphens and underscores, up to 64. It is",
            "how commands, sourceorrery.toml and the SDKs name it.",
        ],
    );
    lines.push(Line::from(""));
    this_machine(wizard, lines, theme);
}

fn view_check(lines: &mut Vec<Line<'static>>, theme: &Theme) {
    prose(
        lines,
        theme,
        &[
            "The view check is asked before a person sees a value or the vault's contents:",
            "`secret get --reveal`, `ui`, `audit`. It is a check, not encryption. `run`, `check`,",
            "`init` and the SDKs never ask it, so programs start without a prompt while a key",
            "read out at the keyboard, by you or by an agent, asks for more.",
        ],
    );
}

fn password<B: Backend>(wizard: &Wizard<B>, lines: &mut Vec<Line<'static>>, theme: &Theme) {
    prose(
        lines,
        theme,
        &[
            "Type a password that rates \"good\" or better, or let the wizard generate one. It is",
            "hashed with Argon2id and sealed in the vault; the hint is shown when it is asked.",
        ],
    );
    if wizard.had().password && wizard.keep_password {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Untick to set a new password.",
            theme.muted,
        )));
    }
}

fn authenticator<B: Backend>(wizard: &Wizard<B>, lines: &mut Vec<Line<'static>>, theme: &Theme) {
    if wizard.keeps_authenticator() {
        prose(
            lines,
            theme,
            &[
                "The vault asks for a code from the authenticator app enrolled. Untick to",
                "enrol another app: the one enrolled stops working at the review.",
            ],
        );
        return;
    }
    if wizard.verified() {
        lines.push(Line::from(Span::styled(
            "The app's code matched: the key is saved with the vault at the review.",
            theme.status("enabled"),
        )));
        return;
    }
    lines.push(Line::from(Span::styled(
        "Scan the code with an authenticator app, then type the code it shows.",
        theme.caution,
    )));
    if let Some((key, _)) = wizard.enrolment() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Cannot scan? Enter this key by hand:",
            theme.muted,
        )));
        lines.push(Line::from(Span::styled(
            format!(" {} ", key_groups(&key)),
            theme.code,
        )));
    }
}

fn recovery_key<B: Backend>(wizard: &Wizard<B>, lines: &mut Vec<Line<'static>>, theme: &Theme) {
    prose(
        lines,
        theme,
        &[
            "The recovery key opens the vault on any machine and passes the view check by",
            "itself. Nothing else can recover the vault when this machine's key is gone:",
            "write it down and keep it apart from this machine.",
        ],
    );
    lines.push(Line::from(""));
    let Some(key) = &wizard.recovery else {
        lines.push(Line::from(Span::styled(
            "The vault keeps its recovery key.",
            theme.muted,
        )));
        return;
    };
    lines.push(Line::from(Span::styled(
        "YOUR RECOVERY KEY  ·  shown once",
        theme.label,
    )));
    lines.push(Line::from(vec![
        Span::raw("    "),
        Span::styled(format!(" {} ", key.as_str()), theme.code),
    ]));
    if !wizard.creating() {
        lines.push(Line::from(Span::styled(
            "The current key stops working at the review.",
            theme.caution,
        )));
    }
}

fn storage<B: Backend>(wizard: &Wizard<B>, lines: &mut Vec<Line<'static>>, theme: &Theme) {
    prose(
        lines,
        theme,
        &[
            "Where this vault's secrets may be kept. The vault itself is always one; each",
            "provider ticked becomes a connection, and a secret picks its storage when it is set.",
        ],
    );
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::raw("  [x] "),
        Span::raw(format!("{:<LABEL_WIDTH$}", "SourceOrrery vault")),
        Span::styled("always: the encrypted file", theme.muted),
    ]));
    for provider in PROVIDERS {
        if !wizard.available.contains(&provider) {
            lines.push(Line::from(vec![
                Span::styled("  [-] ", theme.muted),
                Span::styled(
                    format!("{:<LABEL_WIDTH$}", provider.display_name()),
                    theme.muted,
                ),
                Span::styled("not in this build", theme.muted),
            ]));
        }
    }
}

/// What the view check will ask for, as the review describes it.
fn view_summary<B: Backend>(wizard: &Wizard<B>) -> String {
    let had = wizard.had();
    if !wizard.ask_password {
        return if had.password {
            "none (the password is removed)".to_owned()
        } else {
            "none".to_owned()
        };
    }
    let password = if had.password && wizard.keep_password {
        "the current password"
    } else if wizard.generated.is_some() {
        "the generated password"
    } else {
        "the password typed"
    };
    let code = match (
        wizard.ask_code,
        had.authenticator,
        wizard.keeps_authenticator(),
    ) {
        (false, true, _) => " (the authenticator is removed)",
        (false, false, _) => "",
        (true, _, true) => " and a code from the enrolled app",
        (true, _, false) => " and a code from the app verified",
    };
    format!("{password}{code}")
}

fn connection_summary(form: &Form) -> (String, String) {
    let settings = form.settings();
    let place = match &settings {
        sourceorrery_core::ConnectionSettings::HashicorpVault { address, mount, .. } => {
            format!("{address}, mount {mount}")
        }
        sourceorrery_core::ConnectionSettings::AwsSecretsManager { region, .. } => region.clone(),
        sourceorrery_core::ConnectionSettings::AzureKeyVault { vault_url } => vault_url.clone(),
    };
    let credentials = if form.stored {
        "credentials stored in the vault"
    } else {
        "this machine's sign-in"
    };
    let what = match &form.existing {
        None => "new",
        Some(info)
            if info.settings == settings
                && (info.credentials == CredentialSource::Stored) == form.stored
                && (!form.stored || form.keeps_credentials()) =>
        {
            "as it is"
        }
        Some(_) => "changed",
    };
    (
        format!("{} ({what})", form.provider.display_name()),
        format!("  {}, {credentials}", sanitize(&place)),
    )
}

fn review<B: Backend>(wizard: &Wizard<B>, lines: &mut Vec<Line<'static>>, theme: &Theme) {
    let name = sanitize(vault_name(wizard).unwrap_or_default()).into_owned();
    if wizard.creating() {
        prose(
            lines,
            theme,
            &[
                "Nothing has been written yet. [ Create vault ] makes it, with all of this, at once.",
            ],
        );
    } else {
        prose(
            lines,
            theme,
            &["Nothing has been changed yet. [ Save changes ] makes every change at once."],
        );
    }
    lines.push(Line::from(""));
    row(lines, theme, "vault", name);
    if let Some(editing) = &wizard.editing {
        row(lines, theme, "file", sanitize(&editing.path).into_owned());
    } else {
        row(
            lines,
            theme,
            "this machine",
            wizard.store.as_ref().map_or_else(
                || "no credential store: it opens with the recovery key".to_owned(),
                |store| format!("opens it without asking ({})", sanitize(store)),
            ),
        );
    }
    row(lines, theme, "view check", view_summary(wizard));
    row(
        lines,
        theme,
        "recovery key",
        match (wizard.creating(), wizard.new_recovery) {
            (true, _) => "the key shown, which you wrote down".to_owned(),
            (false, true) => "a new key; the current one stops working".to_owned(),
            (false, false) => "kept".to_owned(),
        },
    );
    row(lines, theme, "storage", "SourceOrrery vault".to_owned());
    for form in &wizard.forms {
        if wizard.is_ticked(form.provider) {
            let (provider, how) = connection_summary(form);
            row(lines, theme, "", provider);
            row(lines, theme, "", how);
        } else if form.existing.is_some() {
            lines.push(Line::from(vec![
                Span::raw(format!("{:<LABEL_WIDTH$}", "")),
                Span::styled(
                    format!(
                        "{}: the connection is removed",
                        form.provider.display_name()
                    ),
                    theme.caution,
                ),
            ]));
        }
    }
}

fn done<B: Backend>(wizard: &Wizard<B>, lines: &mut Vec<Line<'static>>, theme: &Theme) {
    let Some(committed) = &wizard.committed else {
        return;
    };
    let name = sanitize(&committed.name).into_owned();
    row(lines, theme, "vault", name.clone());
    row(lines, theme, "file", sanitize(&committed.path).into_owned());
    row(
        lines,
        theme,
        "view check",
        committed.view.describe().to_owned(),
    );
    row(
        lines,
        theme,
        "this machine",
        if committed.this_machine {
            "opens it without asking".to_owned()
        } else {
            "opens it with the recovery key".to_owned()
        },
    );
    let mut storages = vec!["SourceOrrery vault".to_owned()];
    storages.extend(
        committed
            .connections
            .iter()
            .map(|c| c.settings.provider().display_name().to_owned()),
    );
    row(lines, theme, "storage", storages.join(", "));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("NEXT", theme.label)));
    for (what, command) in [
        (
            "browse the vault, add and change secrets",
            format!("sourceorrery ui --vault {name}"),
        ),
        (
            "declare a project's secrets in sourceorrery.toml",
            format!("sourceorrery init --vault {name}"),
        ),
    ] {
        lines.push(Line::from(Span::styled(what.to_owned(), theme.muted)));
        lines.push(Line::from(vec![
            Span::raw("    "),
            Span::styled(format!(" {command} "), theme.code),
        ]));
    }
}

// ---------------------------------------------------------------------------
// Controls
// ---------------------------------------------------------------------------

fn label(control: Control) -> &'static str {
    match control {
        Control::UnlockKey => "Recovery key",
        Control::UnlockPassword | Control::Password => "Password",
        Control::UnlockCode | Control::Code => "Code from the app",
        Control::Name => "Vault name",
        Control::Confirm => "Confirm",
        Control::Hint => "Hint",
        _ => "",
    }
}

fn button_text<B: Backend>(wizard: &Wizard<B>, control: Control) -> &'static str {
    match control {
        Control::CreateNew => "Create a new vault",
        Control::Leave | Control::Exit => "Leave",
        Control::OpenVault => "Open",
        Control::Continue => "Continue",
        Control::Generate if wizard.generated.is_some() => "Type one instead",
        Control::Generate => "Generate a password for me",
        Control::Verify => "Verify the code",
        Control::Commit if wizard.creating() => "Create vault",
        Control::Commit => "Save changes",
        Control::Form(_, Field::Test) => "Test connection",
        _ => "",
    }
}

fn tick(on: bool) -> &'static str {
    if on { "[x]" } else { "[ ]" }
}

fn toggle_text<B: Backend>(wizard: &Wizard<B>, control: Control) -> String {
    let (on, text) = match control {
        Control::AskPassword => (wizard.ask_password, "Ask for a password"),
        Control::AskCode => (
            wizard.ask_code,
            "And a code from an authenticator app, on top of the password",
        ),
        Control::KeepPassword => (wizard.keep_password, "Keep the current password"),
        Control::Written => (
            wizard.generated_written,
            "I have written the password down or kept it in a password manager",
        ),
        Control::KeepAuthenticator => (
            wizard.keep_authenticator,
            "Keep the authenticator app enrolled",
        ),
        Control::NewRecoveryKey => (
            wizard.new_recovery,
            "Make a new recovery key (the current one stops working)",
        ),
        Control::RecoveryWritten => (
            wizard.recovery_written,
            "I have written it down and will keep it apart from this machine",
        ),
        Control::Provider(i) => {
            let provider = PROVIDERS[i];
            return format!(
                "{} {:<LABEL_WIDTH$}{}",
                tick(wizard.ticked[i]),
                provider.display_name(),
                provider_note(wizard, provider)
            );
        }
        _ => (false, ""),
    };
    format!("{} {text}", tick(on))
}

fn provider_note<B: Backend>(wizard: &Wizard<B>, provider: Provider) -> &'static str {
    let connected = wizard.editing.as_ref().is_some_and(|e| {
        e.connections
            .iter()
            .any(|c| c.settings.provider() == provider)
    });
    match (connected, provider) {
        (true, _) => "connected",
        (false, Provider::HashicorpVault) => "KV v2 on a Vault server",
        (false, Provider::AwsSecretsManager) => "a region of an AWS account",
        (false, Provider::AzureKeyVault) => "one Key Vault",
    }
}

fn control_line<B: Backend>(wizard: &Wizard<B>, control: Control, theme: &Theme) -> Line<'static> {
    let focused = wizard.focused() == control;
    let mut spans = vec![Span::styled(
        if focused { "▌ " } else { "  " },
        theme.marker,
    )];
    if control.is_text() {
        text_spans(wizard, control, focused, theme, &mut spans);
    } else if control.is_toggle() {
        match control {
            Control::Form(i, Field::Source) => source_spans(&wizard.forms[i], theme, &mut spans),
            _ => spans.push(Span::raw(toggle_text(wizard, control))),
        }
    } else {
        match control {
            Control::Vault(i) => spans.push(Span::styled(
                sanitize(&wizard.vaults[i]).into_owned(),
                theme.vault,
            )),
            _ => spans.push(Span::styled(
                format!("[ {} ]", button_text(wizard, control)),
                theme.key,
            )),
        }
        if let Control::Form(i, Field::Test) = control {
            match &wizard.forms[i].tested {
                Some(Ok(())) => {
                    spans.push(Span::styled("   reached", theme.status("enabled")));
                }
                Some(Err(err)) => spans.push(Span::styled(
                    format!("   {}", sanitize(err)),
                    theme.status("expired"),
                )),
                None => {}
            }
        }
    }
    let line = Line::from(spans);
    if focused {
        line.style(theme.selected)
    } else {
        line
    }
}

fn source_spans(form: &Form, theme: &Theme, spans: &mut Vec<Span<'static>>) {
    spans.push(Span::styled(
        format!("{:<LABEL_WIDTH$}", form.label(Field::Source)),
        theme.muted,
    ));
    let (ambient, stored) = if form.stored {
        ("( )", "(•)")
    } else {
        ("(•)", "( )")
    };
    spans.push(Span::raw(format!(
        "{ambient} this machine's sign-in  {stored} stored in the vault"
    )));
}

/// The label, the text (dots for a hidden field) and what is said about
/// it, for a text control.
fn text_spans<B: Backend>(
    wizard: &Wizard<B>,
    control: Control,
    focused: bool,
    theme: &Theme,
    spans: &mut Vec<Span<'static>>,
) {
    let label = match control {
        Control::Form(i, field) => wizard.forms[i].label(field),
        _ => label(control),
    };
    spans.push(Span::styled(format!("{label:<LABEL_WIDTH$}"), theme.muted));
    let text = if control.is_hidden() {
        "•".repeat(wizard.hidden_len(control))
    } else {
        let shown = match control {
            Control::UnlockCode => &wizard.unlock_code,
            Control::Name => &wizard.name,
            Control::Hint => &wizard.hint,
            Control::Code => &wizard.code,
            Control::Form(i, field) => wizard.forms[i].text(field),
            _ => "",
        };
        sanitize(shown).into_owned()
    };
    spans.push(Span::raw(text));
    if focused {
        spans.push(Span::styled("▌", theme.key));
    }
    match control {
        Control::Confirm => match wizard.confirm_state() {
            Some(true) => spans.push(Span::styled("   matches", theme.status("enabled"))),
            Some(false) => {
                spans.push(Span::styled("   does not match", theme.status("expired")));
            }
            None => {}
        },
        Control::Name => {
            if let Some(problem) = wizard.name_problem() {
                spans.push(Span::styled(
                    format!("   {}", sanitize(&problem)),
                    theme.caution,
                ));
            }
        }
        Control::Hint if wizard.hint.is_empty() => {
            spans.push(Span::styled(
                "optional: shown when the password is asked",
                theme.muted,
            ));
        }
        Control::Form(i, field) => {
            let form = &wizard.forms[i];
            let note = match field {
                Field::Third | Field::Second if form.text(field).is_empty() => "optional",
                Field::Secret if form.keeps_credentials() => "empty keeps the stored ones",
                _ => "",
            };
            spans.push(Span::styled(note, theme.muted));
        }
        _ => {}
    }
}

/// Lines drawn before a control: a provider's name over its form.
fn control_heading<B: Backend>(
    wizard: &Wizard<B>,
    control: Control,
    theme: &Theme,
) -> Option<Vec<Line<'static>>> {
    let Control::Form(i, Field::Location) = control else {
        return None;
    };
    let form = &wizard.forms[i];
    let mut spans = vec![Span::styled(
        form.provider.display_name().to_uppercase(),
        theme.label,
    )];
    if let Some(existing) = &form.existing {
        spans.push(Span::styled(
            format!("  ·  connection {}", sanitize(&existing.id)),
            theme.muted,
        ));
    }
    Some(vec![Line::from(""), Line::from(spans)])
}

/// Lines drawn under a control: the strength meter, the generated
/// password.
fn control_extra<B: Backend>(
    wizard: &Wizard<B>,
    control: Control,
    theme: &Theme,
) -> Option<Vec<Line<'static>>> {
    match control {
        Control::Password => Some(meter_lines(wizard.estimate.as_ref(), theme)),
        Control::Generate => {
            let generated = wizard.generated.as_ref()?;
            Some(vec![
                Line::from(vec![
                    Span::raw(format!("  {:<LABEL_WIDTH$}", "Your password")),
                    Span::styled(format!(" {} ", generated.as_str()), theme.code),
                    Span::styled("   shown once", theme.caution),
                ]),
                Line::from(Span::styled(
                    format!(
                        "  {:<LABEL_WIDTH$}{}",
                        "", "letters, digits and symbols from the OS random source; about 125 bits"
                    ),
                    theme.muted,
                )),
            ])
        }
        _ => None,
    }
}

fn meter_lines(estimate: Option<&Estimate>, theme: &Theme) -> Vec<Line<'static>> {
    let Some(estimate) = estimate else {
        return vec![Line::from(Span::styled(
            format!(
                "  {:<LABEL_WIDTH$}{}  needs \"{}\": a long phrase of unrelated words, or letters, digits and symbols",
                "strength",
                "░".repeat(METER),
                Score::REQUIRED.label()
            ),
            theme.muted,
        ))];
    };
    let filled = (estimate.score as usize + 1) * METER / 5;
    let style = match estimate.score {
        Score::Guessable | Score::Weak => theme.status("expired"),
        Score::Fair => theme.caution,
        Score::Good | Score::Strong => theme.status("enabled"),
    };
    let mut lines = vec![Line::from(vec![
        Span::styled(format!("  {:<LABEL_WIDTH$}", "strength"), theme.muted),
        Span::styled("█".repeat(filled), style),
        Span::styled("░".repeat(METER - filled), theme.muted),
        Span::styled(
            format!(
                "  {}  (about {} bits)",
                estimate.score.label(),
                estimate.bits
            ),
            style,
        ),
        Span::styled(
            if estimate.acceptable() {
                ""
            } else {
                "  not yet enough"
            },
            theme.muted,
        ),
    ])];
    if !estimate.warnings.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("  {:<LABEL_WIDTH$}{}", "", estimate.warnings.join("; ")),
            theme.muted,
        )));
    }
    lines
}
