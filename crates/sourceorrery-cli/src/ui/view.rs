//! Drawing. Everything here is a function of the browser state; nothing
//! reads the vault.
//!
//! The layout follows the documentation site: a header bar, an uppercase
//! section label, a table in the booktabs manner (rules above and below,
//! a thin rule under the headings, no vertical lines), the selected row on
//! the site's selection colour with the accent bar the sidebar uses for the
//! current page, messages drawn as callouts, and a footer bar.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Margin, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, HighlightSpacing, Paragraph, Row, Table};
use sourceorrery_core::{RecoveryLevel, SecretProperties, timestamp};
use time::macros::format_description;
use time::{OffsetDateTime, UtcOffset};

use super::app::{App, Message};
use super::keys::HINTS;
use super::theme::Theme;
use crate::output;

/// Characters of a version id shown in the list; the id is 32 hex digits.
const SHORT_VERSION: usize = 8;

/// Widest the name column grows; longer names are cut at the column edge.
const MAX_NAME_WIDTH: usize = 48;

/// Rows around the table: label, top rule, headings, heading rule, bottom
/// rule.
const TABLE_CHROME: u16 = 5;

/// Said in the footer whenever there is room.
const REASSURANCE: &str = "metadata only · values are never shown ";

pub fn draw(frame: &mut Frame<'_>, app: &mut App<'_>, theme: &Theme) {
    frame.render_widget(Block::new().style(theme.screen), frame.area());
    let message_height = u16::from(app.message.is_some());
    let [header, _, body, message, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(message_height),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    frame.render_widget(header_bar(app, theme), header);
    draw_secrets(frame, app, theme, body.inner(Margin::new(2, 0)));
    if let Some(text) = &app.message {
        frame.render_widget(callout(text, theme), message);
    }
    draw_footer(frame, theme, footer);
}

fn header_bar(app: &App<'_>, theme: &Theme) -> Paragraph<'static> {
    let vault = &app.vault;
    let deletion = match vault.recovery_level {
        RecoveryLevel::Recoverable => format!("recoverable for {} days", vault.retention_days),
        RecoveryLevel::Purgeable => "purgeable".to_owned(),
    };
    let protectors = match vault.protectors.len() {
        1 => "1 protector".to_owned(),
        n => format!("{n} protectors"),
    };
    let line = Line::from(vec![
        Span::styled(" SourceOrrery ", theme.title),
        Span::styled("  vault ", theme.muted),
        Span::styled(output::sanitize(&vault.name).into_owned(), theme.vault),
        Span::styled(format!("  ·  {deletion}  ·  {protectors}"), theme.muted),
    ]);
    Paragraph::new(line).style(theme.bar)
}

fn draw_secrets(frame: &mut Frame<'_>, app: &mut App<'_>, theme: &Theme, area: Rect) {
    let count = app.secrets.len();
    let label = Line::from(vec![
        Span::styled("SECRETS", theme.label),
        Span::styled(format!("  {count}"), theme.muted),
    ]);
    frame.render_widget(label, row(area, 0));
    let rule = |frame: &mut Frame<'_>, offset: u16, style| {
        let line = "─".repeat(usize::from(area.width));
        frame.render_widget(Paragraph::new(line).style(style), row(area, offset));
    };
    rule(frame, 1, theme.rule);

    if count == 0 {
        app.page = 1;
        let name = output::sanitize(&app.vault.name).into_owned();
        let lines = vec![
            Line::from(""),
            Line::from(format!("No secrets in vault '{name}'.")),
            Line::from(vec![
                Span::styled("Add one with  ", theme.muted),
                Span::styled(
                    format!(" sourceorrery secret set <name> --vault {name} "),
                    theme.code,
                ),
            ]),
            Line::from(""),
        ];
        let height = u16::try_from(lines.len()).unwrap_or(u16::MAX);
        frame.render_widget(Paragraph::new(lines), rows(area, 2, height));
        rule(frame, 2 + height, theme.rule);
        return;
    }

    let visible = area.height.saturating_sub(TABLE_CHROME);
    let visible = visible.min(u16::try_from(count).unwrap_or(u16::MAX));
    app.page = usize::from(visible).max(1);

    let now = timestamp::now();
    let selected = app.table.selected();
    let name_width = app
        .secrets
        .iter()
        .map(|p| output::sanitize(&p.name).chars().count())
        .max()
        .unwrap_or(0)
        .clamp(4, MAX_NAME_WIDTH);
    let widths = [
        Constraint::Length(u16::try_from(name_width).unwrap_or(u16::MAX)),
        Constraint::Length(8),
        Constraint::Length(u16::try_from(SHORT_VERSION).unwrap_or(u16::MAX)),
        Constraint::Length(16),
        Constraint::Length(16),
        Constraint::Fill(1),
    ];
    let header = Row::new([
        "NAME",
        "STATUS",
        "VERSION",
        "UPDATED UTC",
        "EXPIRES UTC",
        "TAGS",
    ])
    .style(theme.label)
    .bottom_margin(1);
    let rows_ = app
        .secrets
        .iter()
        .enumerate()
        .map(|(i, p)| secret_row(p, now, theme, selected == Some(i)));
    let table = Table::new(rows_, widths)
        .header(header)
        .column_spacing(2)
        .row_highlight_style(theme.selected)
        .highlight_symbol(Span::styled("▎ ", theme.marker))
        .highlight_spacing(HighlightSpacing::Always);
    frame.render_stateful_widget(table, rows(area, 2, 2 + visible), &mut app.table);
    // The headings' bottom margin carries the thin rule.
    rule(frame, 3, theme.header_rule);
    rule(frame, 4 + visible, theme.rule);
}

fn secret_row(
    p: &SecretProperties,
    now: OffsetDateTime,
    theme: &Theme,
    selected: bool,
) -> Row<'static> {
    let status = output::status(p, now);
    let muted = |text: String| Span::styled(text, theme.cell(theme.muted, selected));
    let or_dash = |text: Option<String>| text.map_or_else(|| muted("-".to_owned()), Span::raw);
    let tags = p
        .tags
        .iter()
        .map(|(k, v)| format!("{}={}", output::sanitize(k), output::sanitize(v)))
        .collect::<Vec<_>>()
        .join(", ");
    Row::new([
        Cell::from(output::sanitize(&p.name).into_owned()),
        Cell::from(Span::styled(
            status,
            theme.cell(theme.status(status), selected),
        )),
        Cell::from(muted(
            output::sanitize(&p.version)
                .chars()
                .take(SHORT_VERSION)
                .collect(),
        )),
        Cell::from(muted(short_time(p.updated_on))),
        Cell::from(or_dash(p.expires_on.map(short_time))),
        Cell::from(or_dash((!tags.is_empty()).then_some(tags))),
    ])
}

/// `2026-10-21 12:07`, in UTC: minutes are enough to read a list by, and
/// the columns say UTC.
fn short_time(ts: OffsetDateTime) -> String {
    ts.to_offset(UtcOffset::UTC)
        .format(format_description!("[year]-[month]-[day] [hour]:[minute]"))
        .unwrap_or_else(|_| output::fmt_time(ts))
}

/// A message drawn like the site's callouts: bar, uppercase title, text.
fn callout(message: &Message, theme: &Theme) -> Paragraph<'static> {
    let (style, title, text) = match message {
        Message::Info(text) => (theme.info, "NOTE", text),
        Message::Error(text) => (theme.error, "ERROR", text),
    };
    let line = Line::from(vec![
        Span::styled(" ▌", style.bar),
        Span::styled(format!(" {title} "), style.title),
        Span::raw(format!(" {}", output::sanitize(text))),
    ]);
    Paragraph::new(line).style(style.panel)
}

fn draw_footer(frame: &mut Frame<'_>, theme: &Theme, area: Rect) {
    let mut spans = vec![Span::raw(" ")];
    for (keys, what) in HINTS {
        spans.push(Span::styled(keys, theme.key));
        spans.push(Span::raw(format!(" {what}   ")));
    }
    let hints = Line::from(spans);
    let room = usize::from(area.width);
    let needed = hints.width() + REASSURANCE.chars().count();
    let [left, right] = if needed <= room {
        let width = u16::try_from(REASSURANCE.chars().count()).unwrap_or(0);
        Layout::horizontal([Constraint::Min(0), Constraint::Length(width)]).areas(area)
    } else {
        [area, Rect::default()]
    };
    frame.render_widget(Paragraph::new(hints).style(theme.bar), left);
    frame.render_widget(
        Paragraph::new(REASSURANCE)
            .alignment(Alignment::Right)
            .style(theme.bar),
        right,
    );
}

/// Row `offset` of `area`, or nothing when it is outside.
fn row(area: Rect, offset: u16) -> Rect {
    rows(area, offset, 1)
}

/// `height` rows of `area` from `offset`, cut at its bottom edge.
fn rows(area: Rect, offset: u16, height: u16) -> Rect {
    let top = area.y.saturating_add(offset).min(area.bottom());
    let bottom = top.saturating_add(height).min(area.bottom());
    Rect {
        y: top,
        height: bottom - top,
        ..area
    }
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::super::app::tests::FakeSource;
    use super::*;

    fn render(app: &mut App<'_>, width: u16, height: u16) -> String {
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

    #[test]
    fn draws_the_vault_and_its_secrets() {
        let source = FakeSource::with(&["api-key", "database-password"]);
        let mut app = App::load(&source).unwrap();
        let screen = render(&mut app, 120, 14);
        assert!(screen.contains("SourceOrrery"), "{screen}");
        assert!(screen.contains("vault dev"), "{screen}");
        assert!(
            screen.contains("recoverable for 90 days  ·  1 protector"),
            "{screen}"
        );
        assert!(screen.contains("SECRETS  2"), "{screen}");
        assert!(screen.contains("▎ api-key"), "{screen}");
        assert!(screen.contains("database-password"), "{screen}");
        assert!(screen.contains("enabled"), "{screen}");
        assert!(screen.contains("01234567 "), "short version: {screen}");
        assert!(!screen.contains("0123456789abcdef0123"), "{screen}");
        assert!(screen.contains("q quit"), "{screen}");
        assert!(screen.contains(REASSURANCE.trim_end()), "{screen}");
    }

    #[test]
    fn the_table_is_ruled_above_below_and_under_the_headings() {
        let source = FakeSource::with(&["a", "b"]);
        let mut app = App::load(&source).unwrap();
        let screen = render(&mut app, 100, 14);
        let lines: Vec<&str> = screen.lines().collect();
        let ruled = |i: usize| lines[i].trim().chars().all(|c| c == '─');
        // header, gap, label, rule, headings, rule, a, b, rule
        assert!(lines[2].contains("SECRETS"), "{screen}");
        assert!(ruled(3) && ruled(5) && ruled(8), "{screen}");
        assert!(
            lines[4].contains("NAME") && lines[4].contains("TAGS"),
            "{screen}"
        );
        assert!(!screen.contains('│'), "no vertical lines: {screen}");
    }

    #[test]
    fn an_empty_vault_says_how_to_add_a_secret() {
        let source = FakeSource::with(&[]);
        let mut app = App::load(&source).unwrap();
        let screen = render(&mut app, 100, 12);
        assert!(screen.contains("SECRETS  0"), "{screen}");
        assert!(screen.contains("No secrets in vault 'dev'"), "{screen}");
        assert!(
            screen.contains("sourceorrery secret set <name> --vault dev"),
            "{screen}"
        );
    }

    #[test]
    fn messages_are_callouts() {
        let source = FakeSource::with(&["a"]);
        let mut app = App::load(&source).unwrap();
        app.message = Some(Message::Info("reloaded 1 secret(s)".into()));
        assert!(render(&mut app, 100, 12).contains("▌ NOTE  reloaded 1 secret(s)"));
        app.message = Some(Message::Error("refresh failed (crypto): x".into()));
        assert!(render(&mut app, 100, 12).contains("▌ ERROR  refresh failed (crypto): x"));
    }

    #[test]
    fn the_page_is_the_rows_on_screen() {
        let source = FakeSource::with(&["a"; 40]);
        let mut app = App::load(&source).unwrap();
        // header + gap + footer, then five rows of table chrome
        render(&mut app, 80, 20);
        assert_eq!(app.page, 12);
        app.message = Some(Message::Info("x".into()));
        render(&mut app, 80, 20);
        assert_eq!(app.page, 11);
        render(&mut app, 80, 4);
        assert_eq!(app.page, 1);
    }

    #[test]
    fn a_narrow_footer_drops_the_reassurance_not_the_keys() {
        let source = FakeSource::with(&["a"]);
        let mut app = App::load(&source).unwrap();
        let screen = render(&mut app, 70, 10);
        assert!(screen.contains("q quit"), "{screen}");
        assert!(!screen.contains("never shown"), "{screen}");
    }

    #[test]
    fn stored_control_characters_are_drawn_escaped() {
        let source = FakeSource {
            tags: vec![("note", "a\u{1b}[2Kb\u{202e}c")],
            ..FakeSource::with(&["api-key"])
        };
        let mut app = App::load(&source).unwrap();
        let screen = render(&mut app, 140, 10);
        assert!(screen.contains(r"note=a\u{1b}[2Kb\u{202e}c"), "{screen}");
        assert!(!screen.contains('\u{1b}'), "raw ESC reached the screen");
        assert!(
            !screen.contains('\u{202e}'),
            "raw bidi override reached the screen"
        );
    }
}
