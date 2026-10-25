//! The Projects view: the folders the vault records, each checked on disk
//! when the vault was read (✓ its manifest is there, ✗ the folder or the
//! manifest is gone), and a project's manifest with whether each secret it
//! declares resolves in the vault, as `check` would say from metadata.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Row};

use super::secrets::no_match;
use super::{Drawn, Ruled, dash, label, long_time, row, rows, rule, ruled_table, short_time};
use crate::output::sanitize;
use crate::ui::app::{App, Tab};
use crate::ui::session::{Project, ProjectStatus, Session};
use crate::ui::theme::Theme;

/// The status column: a mark and a word, styled.
fn status_span(project: &Project, vault: &str, theme: &Theme, selected: bool) -> Span<'static> {
    match &project.status {
        ProjectStatus::Found { vault: named, .. } if named != vault => Span::styled(
            format!("✓ names vault '{}'", sanitize(named)),
            theme.cell(theme.caution, selected),
        ),
        ProjectStatus::Found { .. } => {
            Span::styled("✓ found", theme.cell(theme.status("enabled"), selected))
        }
        ProjectStatus::Missing => Span::styled("✗ gone", theme.cell(theme.error.bar, selected)),
        ProjectStatus::Unreadable(_) => {
            Span::styled("✗ unreadable", theme.cell(theme.caution, selected))
        }
    }
}

pub(super) fn list(frame: &mut Frame<'_>, app: &App, theme: &Theme, area: Rect) -> Drawn {
    let shown = app.shown_projects();
    let selected = app.list(Tab::Projects).table.selected();
    let vault = app
        .session
        .as_ref()
        .map(|s| s.vault.name.clone())
        .unwrap_or_default();
    let path_width = shown
        .iter()
        .map(|p| sanitize(&p.link.path.display().to_string()).chars().count())
        .max()
        .unwrap_or(0)
        .clamp(4, 60);
    let empty = if app.total(Tab::Projects) == Some(0) {
        vec![
            Line::from(""),
            Line::from(format!("No project uses vault '{}' yet.", sanitize(&vault))),
            Line::from(vec![
                Span::styled("In a project's folder,  ", theme.muted),
                Span::styled(" sourceorrery init ", theme.code),
                Span::styled(
                    "  writes its manifest and records the folder here.",
                    theme.muted,
                ),
            ]),
            Line::from(""),
        ]
    } else {
        no_match(theme)
    };
    let rows = shown
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let is_selected = selected == Some(i);
            let secrets = p.secrets().len();
            Row::new([
                Cell::from(sanitize(&p.link.path.display().to_string()).into_owned()),
                Cell::from(sanitize(&p.link.name).into_owned()),
                Cell::from(if secrets == 0 {
                    dash(theme, is_selected)
                } else {
                    Span::raw(secrets.to_string())
                }),
                Cell::from(status_span(p, &vault, theme, is_selected)),
                Cell::from(Span::styled(
                    short_time(p.link.linked_on),
                    theme.cell(theme.muted, is_selected),
                )),
            ])
        })
        .collect();
    let table = Ruled {
        label: label("Projects", app, Tab::Projects, shown.len(), theme),
        headings: Row::new(["PATH", "NAME", "SECRETS", "STATUS", "RECORDED UTC"]),
        widths: vec![
            Constraint::Length(u16::try_from(path_width).unwrap_or(60)),
            Constraint::Length(24),
            Constraint::Length(8),
            Constraint::Length(22),
            Constraint::Fill(1),
        ],
        rows,
        empty,
        selectable: true,
    };
    let mut state = app.list(Tab::Projects).table;
    let (_, page) = ruled_table(frame, area, theme, table, &mut state, None);
    Drawn {
        table: state,
        page: usize::from(page).max(1),
    }
}

/// Whether the secret a manifest declares resolves in the vault, as
/// metadata says: live and readable, disabled, deleted, or not there.
fn resolves(session: &Session, name: &str) -> (&'static str, &'static str) {
    let now = sourceorrery_core::timestamp::now();
    if let Some(p) = session.secrets.iter().find(|p| p.name == name) {
        let status = crate::output::status(p, now);
        return (status, status);
    }
    if session
        .deleted()
        .is_some_and(|d| d.iter().any(|d| d.properties.name == name))
    {
        return ("deleted", "deleted");
    }
    if let Some(id) = session.storage.get(name)
        && session.unreachable.iter().any(|u| u.connection == *id)
    {
        return ("unreachable", "expired");
    }
    ("not in the vault", "expired")
}

/// A project's details: where it is, what its manifest declares and how
/// each resolves.
pub(super) fn detail(frame: &mut Frame<'_>, app: &App, theme: &Theme, area: Rect) -> Option<Drawn> {
    let (Some(session), Some(project)) = (app.session.as_ref(), app.project_detail()) else {
        return None;
    };
    let title = Line::from(vec![
        Span::styled(sanitize(&project.link.name).into_owned(), theme.vault),
        Span::raw("  "),
        status_span(project, &session.vault.name, theme, false),
    ]);
    frame.render_widget(title, row(area, 0));
    rule(frame, area, 1, theme.rule);
    let key = |text: &str| Span::styled(format!("{text:<15}"), theme.muted);
    let mut lines = vec![
        Line::from(vec![
            key("folder"),
            Span::raw(sanitize(&project.link.path.display().to_string()).into_owned()),
        ]),
        Line::from(vec![
            key("recorded"),
            Span::raw(long_time(project.link.linked_on)),
        ]),
    ];
    match &project.status {
        ProjectStatus::Missing => lines.push(Line::from(vec![
            key("manifest"),
            Span::styled("gone: ", theme.error.bar),
            Span::styled("x", theme.key),
            Span::styled(" forgets the project", theme.muted),
        ])),
        ProjectStatus::Unreadable(why) => lines.push(Line::from(vec![
            key("manifest"),
            Span::styled(format!("cannot be read: {}", sanitize(why)), theme.caution),
        ])),
        ProjectStatus::Found { vault, .. } => lines.push(Line::from(vec![
            key("manifest"),
            Span::raw(format!("sourceorrery.toml, vault '{}'", sanitize(vault))),
        ])),
    }
    let height = u16::try_from(lines.len()).unwrap_or(0);
    frame.render_widget(
        ratatui::widgets::Paragraph::new(lines),
        rows(area, 2, height),
    );
    let used = 2 + height + 1;
    rule(frame, area, used - 1, theme.rule);

    let declared = project.secrets();
    let table = Ruled {
        label: Line::from(vec![
            Span::styled("DECLARED SECRETS", theme.label),
            Span::styled(format!("  {}", declared.len()), theme.muted),
        ]),
        headings: Row::new(["SECRET", "IN THE VAULT", "KEPT IN"]),
        widths: vec![
            Constraint::Length(40),
            Constraint::Length(18),
            Constraint::Fill(1),
        ],
        rows: declared
            .iter()
            .map(|name| {
                let (text, style) = resolves(session, name);
                let kept = session.connection_of(name).map_or_else(
                    || "the vault".to_owned(),
                    |c| c.settings.provider().display_name().to_owned(),
                );
                Row::new([
                    Cell::from(sanitize(name).into_owned()),
                    Cell::from(Span::styled(text, theme.status(style))),
                    Cell::from(Span::styled(kept, theme.muted)),
                ])
            })
            .collect(),
        empty: vec![Line::from(Span::styled(
            "The manifest declares no secret, or could not be read.",
            theme.muted,
        ))],
        selectable: true,
    };
    let mut state = app.declarations;
    let (_, page) = ruled_table(
        frame,
        rows(area, used + 1, area.height.saturating_sub(used + 1)),
        theme,
        table,
        &mut state,
        None,
    );
    Some(Drawn {
        table: state,
        page: usize::from(page).max(1),
    })
}
