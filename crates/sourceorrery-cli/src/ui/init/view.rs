//! Drawing `init`'s screens. A function of the wizard's state: nothing here
//! reads a vault, and the hidden fields are drawn as dots from their length
//! alone.
//!
//! The look is the browser's and the setup wizard's: the header bar, an
//! uppercase step rail, a title and a few lines of explanation per screen,
//! the controls as a form (the focused one on the selection colour with the
//! accent bar), messages as callouts, a footer of keys. A list longer than
//! the screen scrolls to keep the focused line in view.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Margin};
use ratatui::style::Style;
use ratatui::symbols::border;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use super::backend::Backend;
use super::wizard::{Control, Message, Row, Step, Wizard};
use crate::output::sanitize;
use crate::ui::theme::{Callout, Theme};

/// Width of a form's label column.
const LABEL_WIDTH: usize = 22;
/// Widest name and storage column in the lists.
const NAME_WIDTH: usize = 32;
const STORAGE_WIDTH: usize = 22;

pub fn draw<B: Backend>(frame: &mut Frame<'_>, wizard: &Wizard<B>, theme: &Theme) {
    frame.render_widget(Block::new().style(theme.screen), frame.area());
    let message_height = u16::from(wizard.message.is_some()) * 2;
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
    let full = rail_line(wizard, theme);
    let rail_text = if full.width() > usize::from(rail.width) {
        Line::from(format!(
            "Step {} of {} — {}",
            Step::RAIL
                .iter()
                .position(|s| *s == wizard.step)
                .unwrap_or(0)
                + 1,
            Step::RAIL.len(),
            wizard.step.title()
        ))
        .style(theme.tab)
    } else {
        full
    };
    frame.render_widget(rail_text, rail);

    let area = body.inner(Margin::new(2, 0));
    let (mut lines, focus_line) = body_lines(wizard, theme);
    if let Some(text) = &wizard.message {
        let text = match text {
            Message::Info(text) | Message::Error(text) => text,
        };
        lines.push(Line::from(format!("Details: {}", sanitize(text))));
    }
    let focus = crate::ui::viewport::focus_row(&lines, focus_line, area.width);
    let lines = crate::ui::viewport::reflow(&lines, area.width);
    let mut viewport = wizard.viewport.borrow_mut();
    viewport.fit(lines.len(), usize::from(area.height), focus);
    frame.render_widget(
        Paragraph::new(lines).scroll((u16::try_from(viewport.offset).unwrap_or(u16::MAX), 0)),
        area,
    );
    if let Some(text) = &wizard.message {
        frame.render_widget(callout(text, theme), message);
    }
    let full_footer = footer_line(wizard, theme);
    let footer_text = if full_footer.width() > usize::from(footer.width) {
        Line::from("Esc back/cancel · Enter next · Tab field · PgUp/Dn scroll").style(theme.bar)
    } else {
        full_footer
    };
    let mut footer_text = footer_text;
    if viewport.total > viewport.page && footer.width >= 60 {
        footer_text = Line::from(format!(
            "Esc cancel · Enter next · PgUp/Dn · {}",
            viewport.position()
        ))
        .style(theme.bar);
    }
    frame.render_widget(footer_text, footer);
}

fn header_bar<B: Backend>(wizard: &Wizard<B>, theme: &Theme) -> Paragraph<'static> {
    let mut spans = vec![
        Span::styled(" SourceOrrery ", theme.title),
        Span::styled(" init", theme.muted),
    ];
    if let Some(vault) = &wizard.vault {
        spans.push(Span::styled("  ·  vault ", theme.muted));
        spans.push(Span::styled(
            sanitize(&vault.name).into_owned(),
            theme.vault,
        ));
    }
    if wizard.step != Step::Vault && !wizard.project.is_empty() {
        spans.push(Span::styled("  ·  project ", theme.muted));
        spans.push(Span::raw(sanitize(&wizard.project).into_owned()));
    }
    Paragraph::new(Line::from(spans)).style(theme.bar)
}

fn rail_line<B: Backend>(wizard: &Wizard<B>, theme: &Theme) -> Line<'static> {
    let mut spans = vec![Span::raw(" ")];
    for (i, step) in Step::RAIL.into_iter().enumerate() {
        let current =
            step == wizard.step || (step == Step::AddNew && wizard.step == Step::NewSecret);
        let (mark, style) = if current {
            ("▶", theme.tab)
        } else if wizard.step.is_past(step) {
            ("✓", theme.muted)
        } else {
            (" ", Style::new())
        };
        spans.push(Span::styled(format!("{mark} {} ", i + 1), theme.muted));
        spans.push(Span::styled(step.title(), style));
        spans.push(Span::raw("    "));
    }
    Line::from(spans)
}

fn footer_line<B: Backend>(wizard: &Wizard<B>, theme: &Theme) -> Line<'static> {
    let pairs: &[(&str, &str)] = match wizard.step {
        Step::Done => &[("Enter Esc q", "leave")],
        Step::Vault => &[("Tab ↓ ↑", "move"), ("Enter", "open"), ("Esc q", "leave")],
        Step::Secrets => &[
            ("Tab ↓ ↑", "move"),
            ("Space", "tick"),
            ("/", "filter"),
            ("Enter", "next / add a value"),
            ("Esc", "back"),
            ("Ctrl-C", "leave"),
        ],
        _ => &[
            ("Tab ↓ ↑", "move"),
            ("Space", "tick / choose"),
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
    spans.push(Span::styled(
        "a value typed here goes to the vault and nowhere else",
        theme.muted,
    ));
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

// ---------------------------------------------------------------------------
// The body of each screen
// ---------------------------------------------------------------------------

/// The body's lines, and which of them holds the focused control.
fn body_lines<B: Backend>(
    wizard: &Wizard<B>,
    theme: &Theme,
) -> (Vec<Line<'static>>, Option<usize>) {
    let title = match wizard.step {
        Step::NewSecret => "NEW SECRET".to_owned(),
        step => step.title().to_uppercase(),
    };
    let mut lines = vec![Line::from(Span::styled(title, theme.label)), Line::from("")];
    match wizard.step {
        Step::Vault => vault(wizard, &mut lines, theme),
        Step::Project => prose(
            &mut lines,
            theme,
            &[
                "The project's name, and where its manifest goes. The manifest names the vault",
                "and the secrets the project uses; it never holds a value.",
            ],
        ),
        Step::Secrets => secrets(wizard, &mut lines, theme),
        Step::AddNew => add_new(wizard, &mut lines, theme),
        Step::NewSecret => prose(
            &mut lines,
            theme,
            &[
                "Its value is typed twice and drawn as dots. It goes to the vault at [ Store ]",
                "and leaves this screen's memory; any value is accepted, as an API key is",
                "whatever its issuer made.",
            ],
        ),
        Step::Review => review(wizard, &mut lines, theme),
        Step::Done => done(wizard, &mut lines, theme),
    }
    lines.push(Line::from(""));
    let mut focus_line = None;
    let focused = wizard.focused();
    for control in wizard.controls() {
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

fn prose(lines: &mut Vec<Line<'static>>, theme: &Theme, text: &[&str]) {
    for t in text {
        lines.push(Line::from(Span::styled((*t).to_owned(), theme.muted)));
    }
}

fn vault<B: Backend>(wizard: &Wizard<B>, lines: &mut Vec<Line<'static>>, theme: &Theme) {
    if wizard.vaults.is_empty() {
        prose(
            lines,
            theme,
            &[
                "There is no vault on this machine yet. A project's secrets come from a vault:",
                "create one, store the secrets in it, then run init again.",
            ],
        );
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            " sourceorrery vault create NAME ",
            theme.code,
        )));
        return;
    }
    prose(
        lines,
        theme,
        &[
            "Which vault do this project's secrets come from? Opening it may ask for its",
            "recovery key, where this machine cannot open it by itself.",
        ],
    );
}

fn secrets<B: Backend>(wizard: &Wizard<B>, lines: &mut Vec<Line<'static>>, theme: &Theme) {
    prose(
        lines,
        theme,
        &[
            "Tick the secrets this project uses. The manifest declares them by name; `run`",
            "fetches their values from the vault. One the vault lacks can be given a value.",
        ],
    );
    if wizard.rows.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "The vault has no secrets yet: continue to add the first.",
            theme.caution,
        )));
    }
}

fn add_new<B: Backend>(wizard: &Wizard<B>, lines: &mut Vec<Line<'static>>, theme: &Theme) {
    lines.push(Line::from(
        "Add a new secret to the vault for this project?",
    ));
    if !wizard.stored.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("Stored on this run: ", theme.muted),
            Span::raw(sanitize(&wizard.stored.join(", ")).into_owned()),
        ]));
    }
}

fn review<B: Backend>(wizard: &Wizard<B>, lines: &mut Vec<Line<'static>>, theme: &Theme) {
    let ticked = wizard.rows.iter().filter(|row| row.ticked).count();
    lines.push(Line::from(vec![
        Span::raw(sanitize(wizard.manifest_path.trim()).into_owned()),
        Span::styled(
            format!(
                " will declare {ticked} secret(s); Space on one makes it optional or required."
            ),
            theme.muted,
        ),
    ]));
    let removed: Vec<&str> = wizard
        .rows
        .iter()
        .filter(|row| row.declared.is_some() && !row.ticked)
        .map(|row| row.name.as_str())
        .collect();
    if !removed.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Taken out of the manifest: ", theme.caution),
            Span::raw(sanitize(&removed.join(", ")).into_owned()),
            Span::styled(" (with any rotation hooks they have)", theme.muted),
        ]));
    }
    if !wizard.stored.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Stored in the vault on this run: ", theme.muted),
            Span::raw(sanitize(&wizard.stored.join(", ")).into_owned()),
        ]));
        lines.push(Line::from(Span::styled(
            "Leaving now writes no manifest; the secrets stored stay in the vault for any project.",
            theme.muted,
        )));
    }
}

fn done<B: Backend>(wizard: &Wizard<B>, lines: &mut Vec<Line<'static>>, theme: &Theme) {
    if let Some(saved) = &wizard.saved {
        lines.push(Line::from(vec![
            Span::raw("Wrote "),
            Span::raw(sanitize(&saved.manifest.display().to_string()).into_owned()),
            Span::raw(format!(": {} secret(s)", saved.secrets)),
        ]));
    }
    if let Some(vault) = &wizard.vault {
        lines.push(Line::from(vec![
            Span::styled("The vault ", theme.muted),
            Span::styled(sanitize(&vault.name).into_owned(), theme.vault),
            Span::styled(" records this folder as project ", theme.muted),
            Span::raw(sanitize(&wizard.project).into_owned()),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("NEXT", theme.label)));
    for command in ["sourceorrery run -- <your command>", "sourceorrery check"] {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(format!(" {command} "), theme.code),
        ]));
    }
}

// ---------------------------------------------------------------------------
// Controls
// ---------------------------------------------------------------------------

fn label(control: Control) -> &'static str {
    match control {
        Control::ProjectName => "Project name",
        Control::ManifestPath => "Manifest",
        Control::Filter => "Filter by name",
        Control::Name => "Secret name",
        Control::Value => "Value",
        Control::Confirm => "Confirm",
        Control::Storage => "Kept in",
        Control::Description => "Description",
        Control::Env => "Environment variable",
        _ => "",
    }
}

fn button_text<B: Backend>(wizard: &Wizard<B>, control: Control) -> String {
    match control {
        Control::Leave | Control::Exit => "Leave".to_owned(),
        Control::Continue => "Continue".to_owned(),
        Control::AddSecret => "Add a secret".to_owned(),
        Control::NoMore => "No, continue".to_owned(),
        Control::Store => "Store".to_owned(),
        Control::Cancel => "Cancel".to_owned(),
        Control::Write => format!(
            "Write {}",
            std::path::Path::new(wizard.manifest_path.trim())
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("the manifest")
        ),
        Control::BackToList => "Back to the list".to_owned(),
        _ => String::new(),
    }
}

fn tick(on: bool) -> &'static str {
    if on { "[x]" } else { "[ ]" }
}

fn pad(text: &str, width: usize) -> String {
    let text = sanitize(text);
    let count = text.chars().count();
    if count > width {
        let cut: String = text.chars().take(width.saturating_sub(1)).collect();
        format!("{cut}…")
    } else {
        format!("{text}{}", " ".repeat(width - count))
    }
}

fn row_spans(row: &Row, theme: &Theme) -> Vec<Span<'static>> {
    let mut spans = vec![
        Span::raw(format!("{} ", pad(&row.name, NAME_WIDTH))),
        match &row.storage {
            Some(storage) => Span::styled(format!("{} ", pad(storage, STORAGE_WIDTH)), theme.muted),
            None => Span::styled(
                format!("{} ", pad("not in the vault", STORAGE_WIDTH)),
                theme.caution,
            ),
        },
        Span::styled(format!("{:<24} ", sanitize(&row.env)), theme.code),
    ];
    if let Some(description) = &row.description {
        spans.push(Span::styled(
            sanitize(description).into_owned(),
            theme.muted,
        ));
    }
    spans
}

fn control_line<B: Backend>(wizard: &Wizard<B>, control: Control, theme: &Theme) -> Line<'static> {
    let focused = wizard.focused() == control;
    let mut spans = vec![Span::styled(
        if focused { "▌ " } else { "  " },
        theme.marker,
    )];
    if control.is_text() {
        text_spans(wizard, control, focused, theme, &mut spans);
    } else {
        match control {
            Control::Vault(i) => spans.push(Span::styled(
                sanitize(&wizard.vaults[i]).into_owned(),
                theme.vault,
            )),
            Control::All => {
                let shown = wizard.visible_rows();
                let ticked = shown.iter().filter(|&&i| wizard.rows[i].ticked).count();
                let all = !shown.is_empty() && ticked == shown.len();
                spans.push(Span::raw(format!("{} All", tick(all))));
                spans.push(Span::styled(
                    format!("   {ticked} of {} ticked", shown.len()),
                    theme.muted,
                ));
            }
            Control::Row(i) => {
                let row = &wizard.rows[i];
                spans.push(Span::raw(format!("{} ", tick(row.ticked))));
                spans.extend(row_spans(row, theme));
            }
            Control::Storage => {
                spans.push(Span::styled(
                    format!("{:<LABEL_WIDTH$}", label(control)),
                    theme.muted,
                ));
                spans.push(Span::raw(format!(
                    "(•) {}",
                    sanitize(wizard.storage_label())
                )));
                spans.push(Span::styled("   Space for the next", theme.muted));
            }
            Control::Required(i) => {
                let row = &wizard.rows[i];
                spans.push(Span::raw(format!("{} required  ", tick(row.required))));
                spans.extend(row_spans(row, theme));
                let note = match (row.declared, row.stored_now) {
                    (_, true) => "  stored now",
                    (None, false) => "  new to the manifest",
                    (Some(_), false) => "",
                };
                spans.push(Span::styled(note, theme.muted));
            }
            _ => spans.push(Span::styled(
                format!("[ {} ]", button_text(wizard, control)),
                theme.key,
            )),
        }
    }
    let line = Line::from(spans);
    if focused {
        line.style(theme.selected)
    } else {
        line
    }
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
    spans.push(Span::styled(
        format!("{:<LABEL_WIDTH$}", label(control)),
        theme.muted,
    ));
    let text = if control.is_hidden() {
        "•".repeat(wizard.hidden_len(control))
    } else {
        let shown = match control {
            Control::ProjectName => &wizard.project,
            Control::ManifestPath => &wizard.manifest_path,
            Control::Filter => &wizard.filter,
            Control::Name => &wizard.new_name,
            Control::Description => &wizard.description,
            Control::Env => &wizard.env,
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
        Control::Description if wizard.description.is_empty() => {
            spans.push(Span::styled("optional: it becomes `purpose`", theme.muted));
        }
        _ => {}
    }
}

/// Lines drawn under a control: what a row that the vault lacks offers.
fn control_extra<B: Backend>(
    wizard: &Wizard<B>,
    control: Control,
    theme: &Theme,
) -> Option<Vec<Line<'static>>> {
    match control {
        Control::Row(i) if !wizard.rows[i].in_vault() && wizard.focused() == control => {
            Some(vec![Line::from(Span::styled(
                "      the manifest declares it and the vault does not have it: Enter adds its value",
                theme.caution,
            ))])
        }
        _ => None,
    }
}
