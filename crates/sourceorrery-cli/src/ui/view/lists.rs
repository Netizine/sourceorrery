//! The Deleted, Audit log and Vaults views.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Row};
use sourceorrery_core::{AuditEvent, AuditOutcome, RecoveryLevel, timestamp};

use super::columns::Columns;
use super::secrets::{no_match, tags};
use super::{Drawn, Ruled, dash, label, long_time, ruled_table, short_time};
use crate::output::sanitize;
use crate::ui::app::{App, Tab};
use crate::ui::session::AUDIT_LIMIT;
use crate::ui::theme::Theme;

fn drawn(
    frame: &mut Frame<'_>,
    app: &App,
    tab: Tab,
    area: Rect,
    theme: &Theme,
    table: Ruled<'_>,
) -> Drawn {
    let mut state = app.list(tab).table;
    let (_, page) = ruled_table(frame, area, theme, table, &mut state, None);
    Drawn {
        table: state,
        page: usize::from(page).max(1),
    }
}

pub(super) fn deleted(frame: &mut Frame<'_>, app: &App, theme: &Theme, area: Rect) -> Drawn {
    let shown = app.shown_deleted();
    let now = timestamp::now();
    let selected = app.list(Tab::Deleted).table.selected();
    let session = app.session.as_ref();
    let vault = session
        .map(|s| sanitize(&s.vault.name).into_owned())
        .unwrap_or_default();
    let purgeable = session.is_some_and(|s| s.vault.recovery_level == RecoveryLevel::Purgeable);
    let indices: &[usize] = if area.width >= 90 {
        &[0, 1, 2, 3, 4]
    } else if area.width >= 65 {
        &[0, 2, 3]
    } else {
        &[0, 3]
    };
    let columns = Columns::new(
        area.width,
        indices,
        &["NAME", "DELETED UTC", "PURGE AFTER UTC", "LEFT", "TAGS"],
        &[0, 16, 16, 8, 16],
    );
    let empty = if app.total(Tab::Deleted) == Some(0) {
        let text = if purgeable {
            format!(
                "Vault '{vault}' is purgeable: deleting a secret removes it at once, so nothing \
                 waits here."
            )
        } else {
            format!("No deleted secrets in vault '{vault}'.")
        };
        vec![Line::from(""), Line::from(text), Line::from("")]
    } else {
        no_match(theme)
    };
    let rows = shown
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let is_selected = selected == Some(i);
            let p = &d.properties;
            let remaining = d
                .scheduled_purge_on
                .map(|at| (at - now).whole_days().max(0));
            columns.row([
                Cell::from(columns.text(0, &p.name)),
                Cell::from(short_time(d.deleted_on)),
                Cell::from(
                    d.scheduled_purge_on
                        .map_or_else(|| dash(theme, is_selected), |at| Span::raw(short_time(at))),
                ),
                Cell::from(remaining.map_or_else(
                    || dash(theme, is_selected),
                    |days| {
                        Span::styled(format!("{days} days"), theme.cell(theme.muted, is_selected))
                    },
                )),
                Cell::from(tags(p).map_or_else(
                    || dash(theme, is_selected),
                    |t| Span::raw(columns.text(4, &t)),
                )),
            ])
        })
        .collect();
    let table = Ruled {
        label: label("Deleted", app, Tab::Deleted, shown.len(), theme),
        headings: columns.headings(),
        widths: columns.widths.clone(),
        rows,
        empty,
        selectable: true,
    };
    drawn(frame, app, Tab::Deleted, area, theme, table)
}

pub(super) fn audit(frame: &mut Frame<'_>, app: &App, theme: &Theme, area: Rect) -> Drawn {
    let shown = app.shown_events();
    let selected = app.list(Tab::Audit).table.selected();
    let indices: &[usize] = if area.width >= 110 {
        &[0, 1, 2, 3, 4, 5, 6]
    } else if area.width >= 90 {
        &[1, 2, 3, 4, 5]
    } else if area.width >= 65 {
        &[1, 3, 4, 5]
    } else {
        &[3, 4, 5]
    };
    let columns = Columns::new(
        area.width,
        indices,
        &[
            "ID",
            "TIME UTC",
            "ACTOR",
            "OPERATION",
            "SECRET",
            "OUTCOME",
            "DETAIL",
        ],
        &[5, 19, 16, 16, 0, 7, 18],
    );
    let mut title = label("Audit log", app, Tab::Audit, shown.len(), theme);
    if app.total(Tab::Audit) == Some(AUDIT_LIMIT) {
        title.push_span(Span::styled(
            format!("   newest {AUDIT_LIMIT}"),
            theme.muted,
        ));
    }
    let empty = if app.total(Tab::Audit) == Some(0) {
        vec![
            Line::from(""),
            Line::from("No audit events."),
            Line::from(""),
        ]
    } else {
        no_match(theme)
    };
    let table = Ruled {
        label: title,
        headings: columns.headings(),
        widths: columns.widths.clone(),
        rows: shown
            .iter()
            .enumerate()
            .map(|(i, e)| {
                columns.row(event_cell_values(
                    e,
                    theme,
                    selected == Some(i),
                    true,
                    Some(&columns),
                ))
            })
            .collect(),
        empty,
        selectable: true,
    };
    drawn(frame, app, Tab::Audit, area, theme, table)
}

/// One audit event as a row. `full` (the audit log) has the id and the
/// secret; otherwise (a secret's activity) the version takes their place.
pub(super) fn event_cells(
    e: &AuditEvent,
    theme: &Theme,
    selected: bool,
    full: bool,
) -> Row<'static> {
    Row::new(event_cell_values(e, theme, selected, full, None))
}

fn event_cell_values(
    e: &AuditEvent,
    theme: &Theme,
    selected: bool,
    full: bool,
    columns: Option<&Columns>,
) -> Vec<Cell<'static>> {
    let outcome = match e.outcome {
        AuditOutcome::Success => Style::new(),
        AuditOutcome::Pending => theme.muted,
        AuditOutcome::Denied => theme.caution,
        AuditOutcome::Failure | AuditOutcome::Unknown => theme.error.bar,
    };
    let text_or_dash = |text: Option<&str>| {
        Cell::from(text.map_or_else(
            || dash(theme, selected),
            |t| Span::raw(sanitize(t).into_owned()),
        ))
    };
    let mut cells = Vec::with_capacity(7);
    if full {
        cells.push(Cell::from(Span::styled(
            e.id.to_string(),
            theme.cell(theme.muted, selected),
        )));
    }
    cells.push(Cell::from(long_time(e.occurred_on)));
    let actor = e.actor.to_string();
    cells.push(Cell::from(columns.map_or_else(
        || sanitize(&actor).into_owned(),
        |c| c.text(2, &actor),
    )));
    cells.push(Cell::from(e.operation.as_str()));
    if full {
        cells.push(Cell::from(e.secret_name.as_deref().map_or_else(
            || dash(theme, selected),
            |s| Span::raw(columns.map_or_else(|| sanitize(s).into_owned(), |c| c.text(4, s))),
        )));
    } else {
        let short = e
            .version
            .as_deref()
            .map(|v| v.chars().take(8).collect::<String>());
        cells.push(text_or_dash(short.as_deref()));
    }
    cells.push(Cell::from(Span::styled(
        e.outcome.as_str(),
        theme.cell(outcome, selected),
    )));
    cells.push(Cell::from(e.detail.as_deref().map_or_else(
        || dash(theme, selected),
        |s| Span::raw(columns.map_or_else(|| sanitize(s).into_owned(), |c| c.text(6, s))),
    )));
    cells
}

pub(super) fn vaults(frame: &mut Frame<'_>, app: &App, theme: &Theme, area: Rect) -> Drawn {
    let shown = app.shown_vaults();
    let selected = app.list(Tab::Vaults).table.selected();
    let open = app.session.as_ref().map(|s| s.vault.name.as_str());
    let indices: &[usize] = if area.width >= 90 {
        &[0, 1, 2, 3, 4]
    } else if area.width >= 65 {
        &[0, 1, 2, 4]
    } else {
        &[0, 1, 4]
    };
    let columns = Columns::new(
        area.width,
        indices,
        &["NAME", "STATE", "SIZE", "MODIFIED UTC", "FILE"],
        &[20, 5, 9, 16, 0],
    );
    let empty = if app.vaults.is_empty() {
        vec![
            Line::from(""),
            Line::from("No vaults in this home directory."),
            Line::from(vec![
                Span::styled("n", theme.key),
                Span::styled(" creates one on the setup screens, as  ", theme.muted),
                Span::styled(" sourceorrery setup ", theme.code),
                Span::styled("  does.", theme.muted),
            ]),
            Line::from(""),
        ]
    } else {
        no_match(theme)
    };
    let rows = shown
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let is_selected = selected == Some(i);
            let state = if open == Some(v.name.as_str()) {
                Span::styled("open", theme.cell(theme.key, is_selected))
            } else {
                dash(theme, is_selected)
            };
            columns.row([
                Cell::from(columns.text(0, &v.name)),
                Cell::from(state),
                Cell::from(
                    v.size
                        .map_or_else(|| dash(theme, is_selected), |s| Span::raw(size(s))),
                ),
                Cell::from(
                    v.modified
                        .map_or_else(|| dash(theme, is_selected), |t| Span::raw(short_time(t))),
                ),
                Cell::from(Span::styled(
                    columns.text(4, &v.path.display().to_string()),
                    theme.cell(theme.muted, is_selected),
                )),
            ])
        })
        .collect();
    let table = Ruled {
        label: label("Vaults", app, Tab::Vaults, shown.len(), theme),
        headings: columns.headings(),
        widths: columns.widths.clone(),
        rows,
        empty,
        selectable: true,
    };
    drawn(frame, app, Tab::Vaults, area, theme, table)
}

/// `64 KiB`, `1.2 MiB`.
fn size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    if bytes < KIB {
        format!("{bytes} B")
    } else if bytes < KIB * KIB {
        format!("{} KiB", bytes.div_ceil(KIB))
    } else {
        let tenths = (bytes * 10).div_ceil(KIB * KIB);
        format!("{}.{} MiB", tenths / 10, tenths % 10)
    }
}

#[cfg(test)]
mod tests {
    use super::size;

    #[test]
    fn sizes_read_like_a_file_manager() {
        assert_eq!(size(512), "512 B");
        assert_eq!(size(65_536), "64 KiB");
        assert_eq!(size(65_537), "65 KiB");
        assert_eq!(size(1_258_291), "1.2 MiB");
    }
}
