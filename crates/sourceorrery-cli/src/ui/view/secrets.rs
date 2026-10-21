//! The Secrets view: the list, and a secret's details (live or deleted).

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Row, Table, TableState};
use sourceorrery_core::{AuditEvent, DeletedSecret, SecretProperties, timestamp};
use time::OffsetDateTime;

use super::{
    Drawn, Ruled, TABLE_CHROME, dash, label, long_time, row, rows, rule, ruled_table, short_time,
};
use crate::output::{self, sanitize};
use crate::ui::app::{App, Tab};
use crate::ui::theme::Theme;

/// Characters of a version id shown in the list; the id is 32 hex digits.
const SHORT_VERSION: usize = 8;

/// Widest the name column grows; longer names are cut at the column edge.
const MAX_NAME_WIDTH: usize = 48;

/// Rows the activity list keeps for itself below the versions.
const ACTIVITY_ROWS: u16 = 3;

pub(super) fn list(frame: &mut Frame<'_>, app: &App, theme: &Theme, area: Rect) -> Drawn {
    let shown = app.shown_secrets();
    let now = timestamp::now();
    let selected = app.list(Tab::Secrets).table.selected();
    let name_width = shown
        .iter()
        .map(|p| sanitize(&p.name).chars().count())
        .max()
        .unwrap_or(0)
        .clamp(4, MAX_NAME_WIDTH);
    let vault = app
        .session
        .as_ref()
        .map(|s| sanitize(&s.vault.name).into_owned())
        .unwrap_or_default();
    let empty = if app.total(Tab::Secrets) == Some(0) {
        vec![
            Line::from(""),
            Line::from(format!("No secrets in vault '{vault}'.")),
            Line::from(vec![
                Span::styled("Add one with  ", theme.muted),
                Span::styled(
                    format!(" sourceorrery secret set <name> --vault {vault} "),
                    theme.code,
                ),
            ]),
            Line::from(""),
        ]
    } else {
        no_match(theme)
    };
    let table = Ruled {
        label: label("Secrets", app, Tab::Secrets, shown.len(), theme),
        headings: Row::new([
            "NAME",
            "STATUS",
            "VERSION",
            "UPDATED UTC",
            "EXPIRES UTC",
            "TAGS",
        ]),
        widths: vec![
            Constraint::Length(u16::try_from(name_width).unwrap_or(u16::MAX)),
            Constraint::Length(8),
            Constraint::Length(u16::try_from(SHORT_VERSION).unwrap_or(u16::MAX)),
            Constraint::Length(16),
            Constraint::Length(16),
            Constraint::Fill(1),
        ],
        rows: shown
            .iter()
            .enumerate()
            .map(|(i, p)| secret_row(p, now, theme, selected == Some(i)))
            .collect(),
        empty,
        selectable: true,
    };
    let mut state = app.list(Tab::Secrets).table;
    let (_, page) = ruled_table(frame, area, theme, table, &mut state, None);
    Drawn {
        table: state,
        page: usize::from(page).max(1),
    }
}

/// What a filtered list shows when nothing is left.
pub(super) fn no_match(theme: &Theme) -> Vec<Line<'static>> {
    vec![
        Line::from(""),
        Line::from(vec![
            Span::raw("Nothing matches the search. "),
            Span::styled("Esc", theme.key),
            Span::styled(" clears it.", theme.muted),
        ]),
        Line::from(""),
    ]
}

fn secret_row(
    p: &SecretProperties,
    now: OffsetDateTime,
    theme: &Theme,
    selected: bool,
) -> Row<'static> {
    let status = output::status(p, now);
    let muted = |text: String| Span::styled(text, theme.cell(theme.muted, selected));
    Row::new([
        Cell::from(sanitize(&p.name).into_owned()),
        Cell::from(Span::styled(
            status,
            theme.cell(theme.status(status), selected),
        )),
        Cell::from(muted(
            sanitize(&p.version).chars().take(SHORT_VERSION).collect(),
        )),
        Cell::from(muted(short_time(p.updated_on))),
        Cell::from(
            p.expires_on
                .map_or_else(|| dash(theme, selected), |t| Span::raw(short_time(t))),
        ),
        Cell::from(tags(p).map_or_else(|| dash(theme, selected), Span::raw)),
    ])
}

/// `key=value, key=value`, or nothing when there are no tags.
pub(super) fn tags(p: &SecretProperties) -> Option<String> {
    (!p.tags.is_empty()).then(|| {
        p.tags
            .iter()
            .map(|(k, v)| format!("{}={}", sanitize(k), sanitize(v)))
            .collect::<Vec<_>>()
            .join(", ")
    })
}

/// A secret's details: its fields, every version (a live secret), and its
/// recent audit events.
pub(super) fn detail(frame: &mut Frame<'_>, app: &App, theme: &Theme, area: Rect) -> Option<Drawn> {
    let session = app.session.as_ref()?;
    let name = app.detail.as_deref()?;
    let detail = session.detail(name)?;
    let deleted = if app.tab == Tab::Deleted {
        session
            .deleted()
            .and_then(|list| list.iter().find(|d| d.properties.name == name))
    } else {
        None
    };
    let props = match (&detail.versions, deleted) {
        (Some(versions), _) if !versions.is_empty() => &versions[0],
        (_, Some(d)) => &d.properties,
        _ => session.secrets.iter().find(|p| p.name == name)?,
    };
    let now = timestamp::now();
    let status = if deleted.is_some() {
        "deleted"
    } else {
        output::status(props, now)
    };

    let title = Line::from(vec![
        Span::styled(sanitize(name).into_owned(), theme.vault),
        Span::raw("  "),
        Span::styled(status, theme.status(status)),
    ]);
    frame.render_widget(title, row(area, 0));
    rule(frame, area, 1, theme.rule);
    let used = 2 + draw_fields(
        frame,
        theme,
        rows(area, 2, area.height),
        props,
        status,
        deleted,
        now,
    );
    rule(frame, area, used, theme.rule);
    let mut used = used + 2;

    let mut drawn = None;
    if let Some(versions) = &detail.versions {
        let room = area.height.saturating_sub(used);
        let max_rows = room
            .saturating_sub(2 * TABLE_CHROME + 1 + ACTIVITY_ROWS)
            .max(2);
        let mut state = app.versions;
        let (height, shown) = ruled_table(
            frame,
            rows(area, used, room),
            theme,
            version_table(versions, app.versions.selected(), now, theme),
            &mut state,
            Some(max_rows),
        );
        used += height + 1;
        drawn = Some(Drawn {
            table: state,
            page: usize::from(shown).max(1),
        });
    }
    let room = area.height.saturating_sub(used);
    ruled_table(
        frame,
        rows(area, used, room),
        theme,
        activity_table(&detail.activity, theme),
        &mut TableState::default(),
        None,
    );
    drawn
}

/// The field block under a secret's name. Returns the rows it used.
fn draw_fields(
    frame: &mut Frame<'_>,
    theme: &Theme,
    area: Rect,
    p: &SecretProperties,
    status: &'static str,
    deleted: Option<&DeletedSecret>,
    now: OffsetDateTime,
) -> u16 {
    let key = |text: &'static str| Cell::from(Span::styled(text, theme.muted));
    let time_or_dash = |t: Option<OffsetDateTime>| {
        Cell::from(t.map_or_else(|| dash(theme, false), |t| Span::raw(long_time(t))))
    };
    let mut lines = vec![
        Row::new([
            key("status"),
            Cell::from(Span::styled(status, theme.status(status))),
            key("created"),
            Cell::from(long_time(p.created_on)),
        ]),
        Row::new([
            key("version"),
            Cell::from(sanitize(&p.version).into_owned()),
            key("updated"),
            Cell::from(long_time(p.updated_on)),
        ]),
        Row::new([
            key("content type"),
            Cell::from(p.content_type.as_deref().map_or_else(
                || dash(theme, false),
                |t| Span::raw(sanitize(t).into_owned()),
            )),
            key("not before"),
            time_or_dash(p.not_before),
        ]),
        Row::new([
            key("tags"),
            Cell::from(tags(p).map_or_else(|| dash(theme, false), Span::raw)),
            key("expires"),
            time_or_dash(p.expires_on),
        ]),
    ];
    if let Some(d) = deleted {
        let purge = d.scheduled_purge_on.map_or_else(
            || "-".to_owned(),
            |at| {
                format!(
                    "{} (in {} days)",
                    long_time(at),
                    (at - now).whole_days().max(0)
                )
            },
        );
        lines.push(Row::new([
            key("deleted"),
            Cell::from(long_time(d.deleted_on)),
            key("purge after"),
            Cell::from(purge),
        ]));
    }
    let height = u16::try_from(lines.len()).unwrap_or(0);
    let widths = [
        Constraint::Length(13),
        Constraint::Fill(3),
        Constraint::Length(12),
        Constraint::Fill(2),
    ];
    frame.render_widget(
        Table::new(lines, widths).column_spacing(2),
        rows(area, 0, height),
    );
    if deleted.is_some() {
        return height;
    }
    // The reference is long; it gets the whole width, aligned with the values.
    let reference = Line::from(vec![
        Span::styled(format!("{:<15}", "reference"), theme.muted),
        Span::raw(sanitize(&p.reference().to_string()).into_owned()),
    ]);
    frame.render_widget(reference, row(area, height));
    height + 1
}

fn version_table(
    versions: &[SecretProperties],
    selected: Option<usize>,
    now: OffsetDateTime,
    theme: &Theme,
) -> Ruled<'static> {
    let rows = versions
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let is_selected = selected == Some(i);
            let status = output::status(v, now);
            let mut id = vec![Span::raw(sanitize(&v.version).into_owned())];
            if i == 0 {
                id.push(Span::styled(
                    "  newest",
                    theme.cell(theme.muted, is_selected),
                ));
            }
            let time_or_dash = |t: Option<OffsetDateTime>| {
                Cell::from(t.map_or_else(|| dash(theme, is_selected), |t| Span::raw(short_time(t))))
            };
            Row::new([
                Cell::from(Line::from(id)),
                Cell::from(Span::styled(
                    status,
                    theme.cell(theme.status(status), is_selected),
                )),
                Cell::from(short_time(v.created_on)),
                time_or_dash(v.not_before),
                time_or_dash(v.expires_on),
            ])
        })
        .collect();
    Ruled {
        label: Line::from(vec![
            Span::styled("VERSIONS", theme.label),
            Span::styled(format!("  {}", versions.len()), theme.muted),
        ]),
        headings: Row::new([
            "VERSION",
            "STATUS",
            "CREATED UTC",
            "NOT BEFORE UTC",
            "EXPIRES UTC",
        ]),
        widths: vec![
            Constraint::Length(40),
            Constraint::Length(8),
            Constraint::Length(16),
            Constraint::Length(16),
            Constraint::Fill(1),
        ],
        rows,
        empty: vec![Line::from("")],
        selectable: true,
    }
}

fn activity_table(events: &[AuditEvent], theme: &Theme) -> Ruled<'static> {
    Ruled {
        label: Line::from(vec![
            Span::styled("RECENT ACTIVITY", theme.label),
            Span::styled(format!("  {}", events.len()), theme.muted),
        ]),
        headings: Row::new([
            "TIME UTC",
            "ACTOR",
            "OPERATION",
            "VERSION",
            "OUTCOME",
            "DETAIL",
        ]),
        widths: vec![
            Constraint::Length(19),
            Constraint::Length(24),
            Constraint::Length(15),
            Constraint::Length(8),
            Constraint::Length(7),
            Constraint::Fill(1),
        ],
        rows: events
            .iter()
            .map(|e| super::lists::event_cells(e, theme, false, false))
            .collect(),
        empty: vec![Line::from(Span::styled("No audit events.", theme.muted))],
        selectable: false,
    }
}
