//! Drawing. Everything here is a function of the browser state; nothing
//! reads the vault.
//!
//! The layout follows the documentation site: a header bar, the views as
//! tabs, an uppercase section label, tables in the booktabs manner (rules
//! above and below, a thin rule under the headings, no vertical lines), the
//! selected row on the site's selection colour with the accent bar the
//! sidebar uses for the current page, messages drawn as callouts, and a
//! footer bar.

mod columns;
mod dialog;
mod lists;
mod overview;
mod projects;
mod secrets;

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Margin, Rect};
use ratatui::style::Style;
use ratatui::symbols::border;
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Clear, HighlightSpacing, Padding, Paragraph, Row, Table, TableState, Wrap,
};
use sourceorrery_core::RecoveryLevel;
use time::macros::format_description;
use time::{OffsetDateTime, UtcOffset};

use super::app::{App, Message, Tab};
use super::edit::Dialog;
use super::session::Session;
use super::theme::{Callout, Theme};
use crate::output;

/// Said in the footer whenever there is room.
const REASSURANCE: &str = "metadata only · values are never shown ";

/// Rows a ruled table spends on chrome: label, top rule, headings, heading
/// rule, bottom rule.
const TABLE_CHROME: u16 = 5;

/// What drawing a list changes in the app: where its table scrolled to
/// and how many rows fit.
struct Drawn {
    table: TableState,
    page: usize,
}

pub fn draw(frame: &mut Frame<'_>, app: &mut App, theme: &Theme) {
    frame.render_widget(Block::new().style(theme.screen), frame.area());
    let message_height = u16::from(app.message.is_some());
    let [header, tabs, _, body, message, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(message_height),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    frame.render_widget(header_bar(app, theme, header.width), header);
    frame.render_widget(tab_bar(app, theme, tabs.width), tabs);

    let drawn = draw_body(frame, app, theme, body.inner(Margin::new(2, 0)));
    if let Some(drawn) = drawn {
        if app.detail.is_some() && app.tab == Tab::Projects {
            app.declarations = drawn.table;
            app.declaration_page = drawn.page;
        } else if app.detail.is_some() {
            app.versions = drawn.table;
        } else {
            app.list_mut(app.tab).table = drawn.table;
        }
        app.list_mut(app.tab).page = drawn.page;
    }

    if let Some(text) = &app.message {
        frame.render_widget(callout(text, theme), message);
    }
    draw_footer(frame, app, theme, footer);
    if let Some(open) = &app.dialog {
        dialog::draw(frame, open, theme, &mut app.dialog_view);
    }
    if app.help {
        draw_help(frame, app, theme);
    }
}

fn draw_body(frame: &mut Frame<'_>, app: &App, theme: &Theme, area: Rect) -> Option<Drawn> {
    if app.tab == Tab::Vaults {
        return Some(lists::vaults(frame, app, theme, area));
    }
    let Some(session) = &app.session else {
        frame.render_widget(Paragraph::new(closed_lines(app, theme)), area);
        return None;
    };
    match app.tab {
        Tab::Overview => {
            let used = if session.is_blocked() {
                draw_blocked(frame, session, theme, area) + 1
            } else {
                0
            };
            overview::draw(
                frame,
                session,
                theme,
                rows(area, used, area.height),
                &app.overview_view,
            );
            None
        }
        Tab::Secrets | Tab::Projects | Tab::Deleted if session.is_blocked() => {
            draw_blocked(frame, session, theme, area);
            None
        }
        Tab::Projects if app.detail.is_some() => projects::detail(frame, app, theme, area),
        Tab::Projects => Some(projects::list(frame, app, theme, area)),
        Tab::Secrets | Tab::Deleted if app.detail.is_some() => {
            secrets::detail(frame, app, theme, area)
        }
        Tab::Secrets => Some(secrets::list(frame, app, theme, area)),
        Tab::Deleted => Some(lists::deleted(frame, app, theme, area)),
        Tab::Audit | Tab::Vaults => {
            let used = if session.is_blocked() {
                draw_blocked(frame, session, theme, area) + 1
            } else {
                0
            };
            Some(lists::audit(
                frame,
                app,
                theme,
                rows(area, used, area.height),
            ))
        }
    }
}

/// What the views say with no vault open: locked, or never opened.
fn closed_lines(app: &App, theme: &Theme) -> Vec<Line<'static>> {
    let vaults = vec![
        Span::styled("6", theme.key),
        Span::styled(" lists the vaults.", theme.muted),
    ];
    match &app.locked {
        Some(locked) => {
            let name = output::sanitize(&locked.vault).into_owned();
            let why = if locked.idle {
                let minutes = app.lock_after().map_or(0, |d| d.as_secs() / 60);
                let unit = if minutes == 1 { "minute" } else { "minutes" };
                format!("Vault '{name}' was locked after {minutes} {unit} without a key.")
            } else {
                format!("Vault '{name}' is locked.")
            };
            vec![
                Line::from(why),
                Line::from(Span::styled(
                    "Its key and everything read from it are gone from memory.",
                    theme.muted,
                )),
                Line::from(""),
                Line::from(
                    [
                        vec![
                            Span::styled("Enter", theme.key),
                            Span::styled(
                                " unlocks it again (asking its recovery key and view check where \
                                 it has them); ",
                                theme.muted,
                            ),
                        ],
                        vaults,
                    ]
                    .concat(),
                ),
            ]
        }
        None => vec![
            Line::from("No vault is open."),
            Line::from(vec![
                Span::styled("Pick one in ", theme.muted),
                Span::styled("6 Vaults", theme.key),
                Span::styled(", or start with ", theme.muted),
                Span::styled(" sourceorrery ui --vault NAME ", theme.code),
            ]),
        ],
    }
}

fn header_bar(app: &App, theme: &Theme, width: u16) -> Paragraph<'static> {
    if width < 110 {
        let (name, state) = match &app.session {
            Some(s) => (
                s.vault.name.as_str(),
                if s.is_blocked() {
                    "BLOCKED"
                } else if app.is_read_only() {
                    "read-only"
                } else {
                    ""
                },
            ),
            None => app
                .locked
                .as_ref()
                .map_or(("—", "closed"), |l| (l.vault.as_str(), "locked")),
        };
        let remaining = width.saturating_sub(u16::try_from(26 + state.len()).unwrap_or(u16::MAX));
        let name = crate::ui::viewport::clip(&output::sanitize(name), remaining);
        return Paragraph::new(Line::from(vec![
            Span::styled(" SourceOrrery  vault ", theme.title),
            Span::styled(name, theme.vault),
            Span::styled(format!(" · {state}"), theme.key),
        ]))
        .style(theme.bar);
    }
    let mut spans = vec![Span::styled(" SourceOrrery ", theme.title)];
    match &app.session {
        Some(session) => {
            let vault = &session.vault;
            spans.push(Span::styled("  vault ", theme.muted));
            spans.push(Span::styled(
                output::sanitize(&vault.name).into_owned(),
                theme.vault,
            ));
            if !session.is_blocked() && width >= 110 {
                let check = match (
                    session.view.check.password,
                    session.view.check.authenticator,
                ) {
                    (false, _) => "no view check",
                    (true, false) => "password",
                    (true, true) => "password + authenticator",
                };
                spans.push(Span::styled(
                    format!("  ·  {check}  ·  storage: {}", storages(session)),
                    theme.muted,
                ));
            }
            if session.is_blocked() {
                spans.push(Span::styled(" · BLOCKED", theme.error.title));
            }
            if app.is_read_only() {
                spans.push(Span::styled("  ·  read-only", theme.muted));
            }
        }
        None => match &app.locked {
            Some(locked) => {
                spans.push(Span::styled("  vault ", theme.muted));
                spans.push(Span::styled(
                    output::sanitize(&locked.vault).into_owned(),
                    theme.vault,
                ));
                spans.push(Span::styled("  ·  locked", theme.muted));
            }
            None => spans.push(Span::styled("  no vault open", theme.muted)),
        },
    }
    Paragraph::new(Line::from(spans)).style(theme.bar)
}

/// The storages the vault keeps secrets in: `SourceOrrery, Azure Key Vault`.
fn storages(session: &Session) -> String {
    let mut names = vec!["SourceOrrery".to_owned()];
    names.extend(
        session
            .connections
            .iter()
            .map(|c| c.settings.provider().display_name().to_owned()),
    );
    names.join(", ")
}

/// How a deleted secret is kept: `recoverable for 90 days`, `purgeable`.
fn deletion(session: &Session) -> String {
    match session.vault.recovery_level {
        RecoveryLevel::Recoverable => {
            format!("soft, {} days", session.vault.retention_days)
        }
        RecoveryLevel::Purgeable => "at once (purgeable)".to_owned(),
    }
}

fn tab_bar(app: &App, theme: &Theme, width: u16) -> Line<'static> {
    let labels = [
        "Overview", "Secrets", "Projects", "Deleted", "Audit", "Vaults",
    ];
    if width < 72 {
        let index = Tab::ALL.iter().position(|t| *t == app.tab).unwrap_or(0) + 1;
        return Line::from(vec![
            Span::styled(format!(" {index} {} ", app.tab.title()), theme.tab),
            Span::styled(" Tab ← → views", theme.muted),
        ]);
    }
    let mut spans = vec![Span::raw(" ")];
    for (i, tab) in Tab::ALL.into_iter().enumerate() {
        let style = if tab == app.tab {
            theme.tab
        } else {
            Style::new()
        };
        spans.push(Span::styled(format!("{} ", i + 1), theme.muted));
        spans.push(Span::styled(
            if width < 110 { labels[i] } else { tab.title() },
            style,
        ));
        if width >= 110
            && let Some(total) = app.total(tab)
        {
            spans.push(Span::styled(format!(" {total}"), theme.muted));
        }
        spans.push(Span::raw(if width < 110 { "  " } else { "   " }));
    }
    Line::from(spans)
}

/// A list in the booktabs manner.
struct Ruled<'a> {
    label: Line<'a>,
    headings: Row<'a>,
    widths: Vec<Constraint>,
    rows: Vec<Row<'a>>,
    /// Shown between the rules when there are no rows.
    empty: Vec<Line<'a>>,
    /// The selected row is marked and highlighted.
    selectable: bool,
}

/// Draw `table` from the top of `area`: label, rule, headings, thin rule,
/// rows, rule. At most `max_rows` rows, or as many as fit. Returns the
/// rows used in total and the table rows shown.
fn ruled_table(
    frame: &mut Frame<'_>,
    area: Rect,
    theme: &Theme,
    table: Ruled<'_>,
    state: &mut TableState,
    max_rows: Option<u16>,
) -> (u16, u16) {
    frame.render_widget(table.label, row(area, 0));
    rule(frame, area, 1, theme.rule);
    if table.rows.is_empty() {
        let height = u16::try_from(table.empty.len()).unwrap_or(0);
        frame.render_widget(Paragraph::new(table.empty), rows(area, 2, height));
        rule(frame, area, 2 + height, theme.rule);
        return (3 + height, 0);
    }
    let count = u16::try_from(table.rows.len()).unwrap_or(u16::MAX);
    let room = area.height.saturating_sub(TABLE_CHROME);
    let shown = count.min(room).min(max_rows.unwrap_or(u16::MAX));
    let mut widget = Table::new(table.rows, table.widths)
        .header(table.headings.style(theme.label).bottom_margin(1))
        .column_spacing(2);
    if table.selectable {
        widget = widget
            .row_highlight_style(theme.selected)
            .highlight_symbol(Span::styled("▌ ", theme.marker))
            .highlight_spacing(HighlightSpacing::Always);
    } else {
        widget = widget
            .highlight_symbol("  ")
            .highlight_spacing(HighlightSpacing::Always);
    }
    frame.render_stateful_widget(widget, rows(area, 2, 2 + shown), state);
    // The headings' bottom margin carries the thin rule.
    rule(frame, area, 3, theme.header_rule);
    rule(frame, area, 4 + shown, theme.rule);
    if count > shown {
        let first = state.offset().min(usize::from(count));
        let range = format!(
            " {}–{} of {} ",
            first + 1,
            (first + usize::from(shown)).min(usize::from(count)),
            count
        );
        frame.render_widget(
            Paragraph::new(range)
                .alignment(Alignment::Right)
                .style(theme.muted),
            row(area, 4 + shown),
        );
    }
    (TABLE_CHROME + shown, shown)
}

/// `TITLE  6`, or with a filter `TITLE  2 of 6   / query`.
fn label(title: &str, app: &App, tab: Tab, shown: usize, theme: &Theme) -> Line<'static> {
    let list = app.list(tab);
    let total = app.total(tab).unwrap_or(0);
    let filtered = !list.query.is_empty() || (app.editing && app.tab == tab);
    let count = if filtered {
        format!("  {shown} of {total}")
    } else {
        format!("  {total}")
    };
    let mut spans = vec![
        Span::styled(title.to_uppercase(), theme.label),
        Span::styled(count, theme.muted),
    ];
    if filtered {
        spans.push(Span::styled("    / ", theme.key));
        spans.push(Span::styled(
            output::sanitize(&list.query).into_owned(),
            theme.search_match,
        ));
        if app.editing {
            spans.push(Span::styled("▌", theme.key));
        }
    }
    Line::from(spans)
}

/// The callout a blocked vault shows in place of its secrets. Returns the
/// rows it used.
fn draw_blocked(frame: &mut Frame<'_>, session: &Session, theme: &Theme, area: Rect) -> u16 {
    let events = session
        .blocked
        .iter()
        .map(|e| {
            format!(
                "event {}: {}",
                e.id,
                output::sanitize(e.detail.as_deref().unwrap_or("no detail"))
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    let name = output::sanitize(&session.vault.name).into_owned();
    let text = vec![
        Line::from(Span::styled("BLOCKED", theme.error.title)),
        Line::from(format!(
            "Vault '{name}' refuses every operation: its audit log was found truncated ({events})."
        )),
        Line::from(vec![
            Span::raw("Review the audit log, ideally against an exported copy, then run "),
            Span::styled(" sourceorrery audit --acknowledge ", theme.code),
            Span::raw(" in a terminal."),
        ]),
    ];
    // Inside the bar and its padding, each line wraps onto as many rows as
    // its width needs.
    let inner = usize::from(area.width.saturating_sub(3)).max(1);
    let needed: usize = text
        .iter()
        .map(|line| line.width().div_ceil(inner).max(1))
        .sum();
    let height = u16::try_from(needed).unwrap_or(u16::MAX).min(area.height);
    let paragraph = Paragraph::new(text)
        .wrap(Wrap { trim: true })
        .block(callout_block(&theme.error));
    frame.render_widget(paragraph, rows(area, 0, height));
    height
}

/// A tinted panel with a coloured bar on the left, like the site's callouts.
fn callout_block(style: &Callout) -> Block<'static> {
    Block::new()
        .borders(Borders::LEFT)
        .border_set(border::Set {
            vertical_left: "▌",
            ..border::PLAIN
        })
        .border_style(style.bar)
        .padding(Padding::horizontal(1))
        .style(style.panel)
}

/// A one-line message: bar, uppercase title, text.
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

fn hints(app: &App) -> &'static [(&'static str, &'static str)] {
    let changes = !app.is_read_only() && app.session.as_ref().is_some_and(|s| !s.is_blocked());
    if app.help {
        &[("Esc ?", "close"), ("q", "quit")]
    } else if let Some(open) = &app.dialog {
        match open {
            Dialog::Form(_) => &[
                ("Tab", "next field"),
                ("Enter", "review"),
                ("Esc", "cancel"),
            ],
            Dialog::Confirm(_) => &[("Enter", "confirm"), ("Esc", "cancel")],
        }
    } else if app.editing {
        &[
            ("type", "to filter"),
            ("Enter", "keep"),
            ("Esc", "clear"),
            ("↑↓", "move"),
        ]
    } else if app.session.is_none() && app.locked.is_some() && app.tab != Tab::Vaults {
        &[
            ("Enter", "unlock"),
            ("6", "vaults"),
            ("?", "help"),
            ("q", "quit"),
        ]
    } else if app.detail.is_some() && app.tab == Tab::Projects {
        &[
            ("x", "forget if gone"),
            ("Esc", "back"),
            ("?", "keys"),
            ("q", "quit"),
        ]
    } else if app.detail.is_some() && changes && app.tab == Tab::Secrets {
        &[
            ("↑↓", "versions"),
            ("space", "on/off"),
            ("e", "edit"),
            ("n", "new version"),
            ("Esc", "back"),
            ("?", "keys"),
        ]
    } else if app.detail.is_some() && changes {
        &[
            ("u", "recover"),
            ("Esc", "back"),
            ("r", "reload"),
            ("?", "keys"),
            ("q", "quit"),
        ]
    } else if app.detail.is_some() {
        &[
            ("↑↓", "versions"),
            ("Esc", "back"),
            ("r", "reload"),
            ("?", "help"),
            ("q", "quit"),
        ]
    } else {
        view_hints(app, changes)
    }
}

/// The keys a view (not a dialog, search or details) offers.
fn view_hints(app: &App, changes: bool) -> &'static [(&'static str, &'static str)] {
    if changes && app.tab == Tab::Overview {
        &[
            ("v", "verify chain"),
            ("a", "add secret"),
            ("c", "settings"),
            ("L", "lock"),
            ("Tab", "views"),
            ("?", "keys"),
            ("q", "quit"),
        ]
    } else if changes && app.tab == Tab::Secrets {
        &[
            ("↑↓", "move"),
            ("Enter", "details"),
            ("/", "search"),
            ("e", "edit"),
            ("d", "delete"),
            ("?", "keys"),
            ("q", "quit"),
        ]
    } else if changes && app.tab == Tab::Projects {
        &[
            ("↑↓", "move"),
            ("Enter", "manifest"),
            ("x", "forget if gone"),
            ("/", "search"),
            ("?", "keys"),
            ("q", "quit"),
        ]
    } else if !app.is_read_only() && app.tab == Tab::Vaults {
        &[
            ("↑↓", "move"),
            ("Enter", "open"),
            ("n", "new vault"),
            ("c", "settings"),
            ("/", "search"),
            ("r", "rescan"),
            ("?", "keys"),
            ("q", "quit"),
        ]
    } else if changes && app.tab == Tab::Deleted {
        &[
            ("↑↓", "move"),
            ("Enter", "details"),
            ("u", "recover"),
            ("/", "search"),
            ("?", "keys"),
            ("q", "quit"),
        ]
    } else {
        match app.tab {
            Tab::Overview => &[
                ("v", "verify chain"),
                ("L", "lock"),
                ("Tab", "views"),
                ("r", "reload"),
                ("?", "help"),
                ("q", "quit"),
            ],
            Tab::Vaults => &[
                ("↑↓", "move"),
                ("Enter", "open"),
                ("/", "search"),
                ("Tab", "views"),
                ("r", "rescan"),
                ("?", "help"),
                ("q", "quit"),
            ],
            Tab::Audit => &[
                ("↑↓", "move"),
                ("/", "search"),
                ("Tab", "views"),
                ("r", "reload"),
                ("?", "help"),
                ("q", "quit"),
            ],
            Tab::Secrets | Tab::Projects | Tab::Deleted => &[
                ("↑↓", "move"),
                ("Enter", "details"),
                ("/", "search"),
                ("Tab", "views"),
                ("r", "reload"),
                ("?", "help"),
                ("q", "quit"),
            ],
        }
    }
}

fn draw_footer(frame: &mut Frame<'_>, app: &App, theme: &Theme, area: Rect) {
    let all = hints(app);
    let mut pairs = all.to_vec();
    let normal = app.mode() == crate::ui::app::Mode::Normal;
    if normal {
        // F2 is wired in B08; leave the space budget for it now.
        pairs.retain(|(key, _)| !matches!(*key, "?" | "q" | "Esc"));
        pairs.push(("?", "help"));
        pairs.push((
            if app.detail.is_some() { "Esc" } else { "q" },
            if app.detail.is_some() { "back" } else { "quit" },
        ));
    }
    let essential: usize = if normal {
        pairs.len().saturating_sub(2)
    } else {
        pairs.len()
    };
    let tail = if normal { &pairs[essential..] } else { &[] };
    let tail_width: usize = tail
        .iter()
        .map(|(k, v)| k.chars().count() + v.chars().count() + 4)
        .sum();
    let mut spans = vec![Span::raw(" ")];
    let mut used = 1;
    for (keys, what) in &pairs[..essential] {
        let needed = Line::from(format!("{keys} {what}   ")).width();
        if used + needed + tail_width > usize::from(area.width) {
            continue;
        }
        spans.push(Span::styled(*keys, theme.key));
        spans.push(Span::raw(format!(" {what}   ")));
        used += needed;
    }
    for (keys, what) in tail {
        spans.push(Span::styled(*keys, theme.key));
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

const HELP_KEYS: [(&str, &str); 13] = [
    ("↑ ↓  k j", "move"),
    ("PgUp PgDn", "move a screenful"),
    ("g G  Home End", "first, last"),
    ("Tab Shift-Tab ← → 1-6", "switch view"),
    ("Enter", "details · a manifest · open the vault"),
    ("Esc", "back · clear the search"),
    ("/", "search"),
    ("r", "read the vault again"),
    ("v", "verify the audit chain"),
    ("L", "lock now: wipe the vault key"),
    ("?", "this help"),
    ("q  Ctrl-C", "quit"),
    ("", ""),
];

const HELP_CHANGES: [(&str, &str); 9] = [
    ("space", "enable or disable the selected version"),
    ("e", "change its metadata"),
    ("n", "new version: the value at a hidden prompt"),
    ("a", "new secret, in the storage you pick"),
    ("d", "delete the secret"),
    ("u", "recover a deleted secret (Deleted view)"),
    ("x", "forget a project whose folder is gone"),
    ("c", "change the vault on the setup screens"),
    ("n  (Vaults)", "a new vault on the setup screens"),
];

fn draw_help(frame: &mut Frame<'_>, app: &mut App, theme: &Theme) {
    let mut lines: Vec<Line<'_>> = HELP_KEYS
        .iter()
        .map(|(keys, what)| {
            Line::from(vec![
                Span::styled(format!("{keys:<23}"), theme.key),
                Span::raw(*what),
            ])
        })
        .collect();
    lines.push(Line::from(Span::styled("CHANGES", theme.label)));
    if app.is_read_only() {
        lines.push(Line::from("None: this browser is read-only (--read-only)."));
    } else {
        for (keys, what) in HELP_CHANGES {
            lines.push(Line::from(vec![
                Span::styled(format!("{keys:<23}"), theme.key),
                Span::raw(what),
            ]));
        }
        lines.push(Line::from(Span::styled(
            "Each is confirmed first and recorded by the vault.",
            theme.muted,
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("SEARCH", theme.label)));
    lines.push(Line::from(
        "Words match anywhere. Secrets: tag:env=prod  status:expired",
    ));
    lines.push(Line::from(
        "type:json  expires:<30d. Audit log: op:secret_get",
    ));
    lines.push(Line::from("outcome:failure  secret:NAME  actor:TEXT."));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "WHAT THE VAULT RECORDS",
        theme.label,
    )));
    lines.push(Line::from(
        "Its secret list when it opens and on r (secret_list, and one",
    ));
    lines.push(Line::from(
        "listing at each provider that stores some), the deleted list",
    ));
    lines.push(Line::from(
        "once, a secret's versions the first time its details open",
    ));
    lines.push(Line::from(
        "(secret_inspect). Moving, searching, verifying, the audit log",
    ));
    lines.push(Line::from(
        "and a project's manifest on disk read nothing of the vault.",
    ));
    lines.insert(0, Line::from(format!("CURRENT VIEW — {}", app.tab.title())));
    for (key, description) in view_hints(
        app,
        !app.is_read_only() && app.session.as_ref().is_some_and(|s| !s.is_blocked()),
    ) {
        lines.insert(1, Line::from(format!("{key}  {description}")));
    }
    let area = frame.area().inner(Margin::new(1, 1));
    let block = Block::bordered()
        .border_style(theme.rule)
        .title(Span::styled(" KEYS ", theme.label))
        .style(theme.panel);
    let inner = block.inner(area);
    let content = rows(inner, 0, inner.height.saturating_sub(1));
    let lines = crate::ui::viewport::reflow(&lines, content.width);
    app.help_view
        .fit(lines.len(), usize::from(content.height), None);
    frame.render_widget(Clear, area);
    frame.render_widget(block, area);
    frame.render_widget(
        Paragraph::new(lines).scroll((u16::try_from(app.help_view.offset).unwrap_or(u16::MAX), 0)),
        content,
    );
    frame.render_widget(
        Line::from(format!(
            "Esc close · ↑↓ PgUp/PgDn Home/End · {}",
            app.help_view.position()
        )),
        rows(inner, inner.height.saturating_sub(1), 1),
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

fn rule(frame: &mut Frame<'_>, area: Rect, offset: u16, style: Style) {
    let line = "─".repeat(usize::from(area.width));
    frame.render_widget(Paragraph::new(line).style(style), row(area, offset));
}

/// `2026-10-21 12:07`, in UTC: minutes are enough to read a list by, and
/// the columns say UTC.
fn short_time(ts: OffsetDateTime) -> String {
    ts.to_offset(UtcOffset::UTC)
        .format(format_description!("[year]-[month]-[day] [hour]:[minute]"))
        .unwrap_or_else(|_| output::fmt_time(ts))
}

/// `2026-10-21 12:07:33`, in UTC.
fn long_time(ts: OffsetDateTime) -> String {
    ts.to_offset(UtcOffset::UTC)
        .format(format_description!(
            "[year]-[month]-[day] [hour]:[minute]:[second]"
        ))
        .unwrap_or_else(|_| output::fmt_time(ts))
}

/// `-` in the muted style, for a missing value.
fn dash(theme: &Theme, selected: bool) -> Span<'static> {
    Span::styled("-", theme.cell(theme.disabled_action, selected))
}

#[cfg(test)]
mod tests;
