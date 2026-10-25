//! The Overview: the vault at a glance. Everything here comes from what the
//! session already holds (the secret and deleted lists, the audit log, the
//! chain verification, the vault's keys, its view check, connections and
//! project folders), so drawing it reads nothing.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use sourceorrery_core::timestamp;
use time::OffsetDateTime;

use super::{deletion, long_time, rows, rule, short_time};
use crate::output::sanitize;
use crate::ui::session::{AUDIT_LIMIT, ProjectStatus, Session};
use crate::ui::stats::{self, Change};
use crate::ui::theme::Theme;

/// Days the activity chart covers.
const ACTIVITY_DAYS: u16 = 14;

/// Rows the activity chart's bars take.
const CHART_ROWS: u16 = 5;

/// Width of the key column in a panel.
const KEY_WIDTH: usize = 16;

/// Width of the key column under the activity chart, whose keys are longer.
const ACTIVITY_KEY_WIDTH: usize = 20;

/// Width of the key column in the narrower panels of the bottom row.
const NARROW_KEY_WIDTH: usize = 11;

pub(super) fn draw(frame: &mut Frame<'_>, session: &Session, theme: &Theme, area: Rect) {
    let now = timestamp::now();
    let [top, _, middle, _, bottom] = Layout::vertical([
        Constraint::Length(8),
        Constraint::Length(1),
        Constraint::Length(CHART_ROWS + 5),
        Constraint::Length(1),
        Constraint::Min(0),
    ])
    .areas(area);

    let [secrets, _, expiry, _, chain] = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(3),
        Constraint::Fill(1),
        Constraint::Length(3),
        Constraint::Fill(1),
    ])
    .areas(top);
    panel(
        frame,
        theme,
        secrets,
        secrets_title(session, theme),
        secret_lines(session, theme, secrets.width, now),
    );
    panel(
        frame,
        theme,
        expiry,
        title("Expiry", None, theme),
        expiry_lines(session, theme, now),
    );
    panel(
        frame,
        theme,
        chain,
        chain_title(session, theme),
        chain_lines(session, theme),
    );

    let [upcoming, _, activity] = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(3),
        Constraint::Fill(1),
    ])
    .areas(middle);
    let next = if session.is_blocked() {
        Vec::new()
    } else {
        stats::upcoming(&session.secrets, now)
    };
    panel(
        frame,
        theme,
        upcoming,
        title("Upcoming", Some(next.len()), theme),
        upcoming_lines(&next, theme, now),
    );
    draw_activity(frame, session, theme, activity, now);

    let [vault, _, check, _, storage, _, projects] = Layout::horizontal([
        Constraint::Fill(4),
        Constraint::Length(3),
        Constraint::Fill(4),
        Constraint::Length(3),
        Constraint::Fill(7),
        Constraint::Length(3),
        Constraint::Fill(3),
    ])
    .areas(bottom);
    panel(
        frame,
        theme,
        vault,
        title("Vault", None, theme),
        vault_lines(session, theme),
    );
    panel(
        frame,
        theme,
        check,
        title("View check", None, theme),
        check_lines(session, theme),
    );
    panel(
        frame,
        theme,
        storage,
        title("Storage", Some(1 + session.connections.len()), theme),
        storage_lines(session, theme),
    );
    panel(
        frame,
        theme,
        projects,
        title("Projects", Some(session.projects.len()), theme),
        project_lines(session, theme),
    );
}

/// A panel: label, rule, lines.
fn panel(
    frame: &mut Frame<'_>,
    theme: &Theme,
    area: Rect,
    title: Line<'static>,
    lines: Vec<Line<'static>>,
) {
    frame.render_widget(title, rows(area, 0, 1));
    rule(frame, area, 1, theme.rule);
    frame.render_widget(Paragraph::new(lines), rows(area, 2, area.height));
}

fn title(text: &str, count: Option<usize>, theme: &Theme) -> Line<'static> {
    let mut spans = vec![Span::styled(text.to_uppercase(), theme.label)];
    if let Some(count) = count {
        spans.push(Span::styled(format!("  {count}"), theme.muted));
    }
    Line::from(spans)
}

/// `key             value`, the key muted.
fn field(key: &str, value: Vec<Span<'static>>, theme: &Theme) -> Line<'static> {
    field_in(KEY_WIDTH, key, value, theme)
}

/// [`field`] with a key column `width` wide.
fn field_in(width: usize, key: &str, value: Vec<Span<'static>>, theme: &Theme) -> Line<'static> {
    let mut spans = vec![Span::styled(format!("{key:<width$}"), theme.muted)];
    spans.extend(value);
    Line::from(spans)
}

fn unread(theme: &Theme) -> Vec<Line<'static>> {
    vec![Line::from(Span::styled(
        "not read: the vault is blocked",
        theme.muted,
    ))]
}

fn secrets_title(session: &Session, theme: &Theme) -> Line<'static> {
    let mut line = title("Secrets", None, theme);
    if session.is_blocked() {
        return line;
    }
    let deleted = session.deleted().map_or(0, <[_]>::len);
    line.push_span(Span::styled(
        format!("  {} live · {deleted} deleted", session.secrets.len()),
        theme.muted,
    ));
    line
}

fn secret_lines(
    session: &Session,
    theme: &Theme,
    width: u16,
    now: OffsetDateTime,
) -> Vec<Line<'static>> {
    if session.is_blocked() {
        return unread(theme);
    }
    let counts = stats::status_counts(&session.secrets, now);
    let rows = [
        ("enabled", counts.enabled),
        ("disabled", counts.disabled),
        ("pending", counts.pending),
        ("expired", counts.expired),
    ];
    let most = rows.iter().map(|(_, n)| *n).max().unwrap_or(0).max(1);
    let room = usize::from(width).saturating_sub(15).max(1);
    let mut lines: Vec<Line<'static>> = rows
        .iter()
        .map(|(status, n)| {
            let bar = if *n == 0 {
                0
            } else {
                (n * room).div_ceil(most)
            };
            Line::from(vec![
                Span::styled(format!("{status:<10}"), theme.muted),
                Span::raw(format!("{n:>3}  ")),
                Span::styled("█".repeat(bar), theme.status(status)),
            ])
        })
        .collect();
    let next_purge = session
        .deleted()
        .into_iter()
        .flatten()
        .filter_map(|d| d.scheduled_purge_on.map(|at| (at, d)))
        .min_by_key(|(at, _)| *at);
    if let Some((at, d)) = next_purge {
        lines.push(Line::from(vec![
            Span::styled("next purge  ", theme.muted),
            Span::raw(format!("in {} days", (at - now).whole_days().max(0))),
            Span::styled(format!(" ({})", sanitize(&d.properties.name)), theme.muted),
        ]));
    }
    lines.push(storage_counts(session, theme));
    lines
}

/// `vault 5 · HashiCorp Vault 2`: the live secrets by where they are kept.
fn storage_counts(session: &Session, theme: &Theme) -> Line<'static> {
    let at_connections = session
        .secrets
        .iter()
        .filter(|p| session.storage.contains_key(&p.name))
        .count();
    let mut spans = vec![
        Span::styled("kept in     ", theme.muted),
        Span::raw(format!("vault {}", session.secrets.len() - at_connections)),
    ];
    for connection in &session.connections {
        let n = session
            .secrets
            .iter()
            .filter(|p| session.storage.get(&p.name) == Some(&connection.id))
            .count();
        spans.push(Span::styled(" · ", theme.muted));
        spans.push(Span::raw(format!(
            "{} {n}",
            short_provider(connection.settings.provider())
        )));
    }
    Line::from(spans)
}

/// A provider in a few letters, for a crowded line.
pub(super) fn short_provider(provider: sourceorrery_core::Provider) -> &'static str {
    match provider {
        sourceorrery_core::Provider::HashicorpVault => "HashiCorp",
        sourceorrery_core::Provider::AwsSecretsManager => "AWS",
        sourceorrery_core::Provider::AzureKeyVault => "Azure",
    }
}

fn expiry_lines(session: &Session, theme: &Theme, now: OffsetDateTime) -> Vec<Line<'static>> {
    if session.is_blocked() {
        return unread(theme);
    }
    let b = stats::expiry_buckets(&session.secrets, now);
    let count = |n: usize, warn: Style| {
        vec![Span::styled(
            n.to_string(),
            if n > 0 { warn } else { Style::new() },
        )]
    };
    vec![
        field("expired", count(b.expired, theme.error.bar), theme),
        field("within 7 days", count(b.week, theme.caution), theme),
        field("within 30 days", count(b.month, Style::new()), theme),
        field("within 90 days", count(b.quarter, Style::new()), theme),
        field("later", count(b.later, Style::new()), theme),
        field(
            "never",
            vec![Span::styled(b.never.to_string(), theme.muted)],
            theme,
        ),
    ]
}

fn chain_title(session: &Session, theme: &Theme) -> Line<'static> {
    let mut line = title("Audit chain", None, theme);
    let verdict = match session.verification() {
        None => Span::styled("  not checked", theme.muted),
        Some(v) if v.result.is_intact() => Span::styled("  intact", theme.status("enabled")),
        Some(_) => Span::styled("  NOT INTACT", theme.error.title),
    };
    line.push_span(verdict);
    line
}

fn chain_lines(session: &Session, theme: &Theme) -> Vec<Line<'static>> {
    let Some(v) = session.verification() else {
        return vec![Line::from(vec![
            Span::styled("v", theme.key),
            Span::styled(" checks it", theme.muted),
        ])];
    };
    let r = &v.result;
    let bad = |yes: bool, text: String| {
        Span::styled(text, if yes { theme.error.bar } else { Style::new() })
    };
    vec![
        field(
            "rows",
            vec![
                Span::raw(r.rows.to_string()),
                Span::styled(format!(" · {} before unlock", r.unkeyed), theme.muted),
            ],
            theme,
        ),
        field(
            "head",
            vec![bad(
                !r.head_valid,
                if r.head_valid { "valid" } else { "stale" }.to_owned(),
            )],
            theme,
        ),
        field(
            "first break",
            vec![bad(
                r.first_broken.is_some(),
                r.first_broken
                    .map_or_else(|| "-".to_owned(), |id| format!("event {id}")),
            )],
            theme,
        ),
        field(
            "truncations",
            vec![
                bad(r.unacknowledged > 0, r.truncations.to_string()),
                Span::styled(
                    format!(" · {} unacknowledged", r.unacknowledged),
                    theme.muted,
                ),
            ],
            theme,
        ),
        field(
            "checked",
            vec![
                Span::raw(long_time(v.at)),
                Span::styled("  v", theme.key),
                Span::styled(" again", theme.muted),
            ],
            theme,
        ),
    ]
}

fn upcoming_lines(
    next: &[(&sourceorrery_core::SecretProperties, Change, OffsetDateTime)],
    theme: &Theme,
    now: OffsetDateTime,
) -> Vec<Line<'static>> {
    if next.is_empty() {
        return vec![Line::from(Span::styled(
            "Nothing is due to expire or activate.",
            theme.muted,
        ))];
    }
    let width = next
        .iter()
        .map(|(p, _, _)| sanitize(&p.name).chars().count())
        .max()
        .unwrap_or(0)
        .min(32);
    next.iter()
        .map(|(p, change, at)| {
            let days = (*at - now).whole_days();
            let (what, style) = match change {
                Change::Expires if days < 7 => ("expires", theme.caution),
                Change::Expires => ("expires", Style::new()),
                Change::Activates => ("activates", theme.status("pending")),
            };
            Line::from(vec![
                Span::raw(format!("{:<width$}  ", sanitize(&p.name))),
                Span::styled(format!("{what:<10}"), style),
                Span::raw(short_time(*at)),
                Span::styled(format!("  in {days} days"), theme.muted),
            ])
        })
        .collect()
}

fn draw_activity(
    frame: &mut Frame<'_>,
    session: &Session,
    theme: &Theme,
    area: Rect,
    now: OffsetDateTime,
) {
    let events = session.audit().unwrap_or_default();
    let a = stats::activity(events, now, ACTIVITY_DAYS);
    let mut heading = title(&format!("Activity · {ACTIVITY_DAYS} days"), None, theme);
    heading.push_span(Span::styled(
        format!(
            "  {} events · {} denied · {} failures",
            a.events, a.denied, a.failures
        ),
        theme.muted,
    ));
    if events.len() >= AUDIT_LIMIT {
        heading.push_span(Span::styled(
            format!(" (newest {AUDIT_LIMIT})"),
            theme.muted,
        ));
    }
    frame.render_widget(heading, rows(area, 0, 1));
    rule(frame, area, 1, theme.rule);

    // Bars two cells wide with a one-cell gap, in full and half blocks
    // (every console font has both), coloured by the day's worst outcome.
    let most = a.days.iter().map(|d| d.events).max().unwrap_or(0).max(1);
    let halves = |events: u64| {
        if events == 0 {
            0
        } else {
            (events * u64::from(CHART_ROWS) * 2).div_ceil(most)
        }
    };
    let style = |d: &stats::Day| {
        if d.failures > 0 {
            theme.error.bar
        } else if d.denied > 0 {
            theme.caution
        } else {
            theme.marker
        }
    };
    let mut lines: Vec<Line<'static>> = (0..CHART_ROWS)
        .map(|row| {
            let level = u64::from(CHART_ROWS - 1 - row);
            let mut spans = Vec::new();
            for d in &a.days {
                let h = halves(d.events);
                let cell = if h >= 2 * (level + 1) {
                    "██"
                } else if h == 2 * level + 1 {
                    "▄▄"
                } else {
                    "  "
                };
                spans.push(Span::styled(cell, style(d)));
                spans.push(Span::raw(" "));
            }
            Line::from(spans)
        })
        .collect();
    let today = a.days.last().map(|d| d.date);
    lines.push(Line::from(
        a.days
            .iter()
            .flat_map(|d| {
                let label_style = if Some(d.date) == today {
                    theme.key
                } else {
                    theme.muted
                };
                [
                    Span::styled(format!("{:02}", d.date.day()), label_style),
                    Span::raw(" "),
                ]
            })
            .collect::<Vec<_>>(),
    ));
    let when = |e: Option<&sourceorrery_core::AuditEvent>| match e {
        Some(e) => vec![
            Span::raw(long_time(e.occurred_on)),
            Span::styled(
                format!(
                    "  {} {}",
                    sanitize(e.secret_name.as_deref().unwrap_or("")),
                    sanitize(&e.actor.to_string())
                ),
                theme.muted,
            ),
        ],
        None => vec![Span::styled("not in the log", theme.muted)],
    };
    let at = ACTIVITY_KEY_WIDTH;
    lines.push(field_in(
        at,
        "last value read",
        when(a.last_value_read),
        theme,
    ));
    lines.push(field_in(
        at,
        "last failed unlock",
        when(a.last_failed_unlock),
        theme,
    ));
    frame.render_widget(Paragraph::new(lines), rows(area, 2, area.height));
}

fn narrow(key: &str, value: Vec<Span<'static>>, theme: &Theme) -> Line<'static> {
    field_in(NARROW_KEY_WIDTH, key, value, theme)
}

/// `2026-10-21`.
fn date(at: OffsetDateTime) -> String {
    short_time(at).chars().take(10).collect()
}

fn vault_lines(session: &Session, theme: &Theme) -> Vec<Line<'static>> {
    let vault = &session.vault;
    let mut lines = vec![
        narrow("created", vec![Span::raw(date(vault.created_on))], theme),
        narrow(
            "file",
            vec![Span::raw(
                vault
                    .path
                    .as_deref()
                    .map(|p| sanitize(&p.display().to_string()).into_owned())
                    .unwrap_or_default(),
            )],
            theme,
        ),
        narrow("deleting", vec![Span::raw(deletion(session))], theme),
    ];
    for key in session.keys().unwrap_or_default() {
        let opens = match key.kind.as_str() {
            "this-machine" => "this machine".to_owned(),
            "recovery" => "recovery key".to_owned(),
            other => sanitize(other).into_owned(),
        };
        lines.push(narrow("opens with", vec![Span::raw(opens)], theme));
    }
    lines
}

fn check_lines(session: &Session, theme: &Theme) -> Vec<Line<'static>> {
    if session.is_blocked() {
        return unread(theme);
    }
    let view = &session.view;
    let check =
        |key: &str, value: Vec<Span<'static>>, theme: &Theme| field_in(10, key, value, theme);
    let yes_no = |on: bool, yes: &str| {
        if on {
            Span::raw(yes.to_owned())
        } else {
            Span::styled("none", theme.muted)
        }
    };
    let mut lines = vec![
        check("password", vec![yes_no(view.check.password, "set")], theme),
        check(
            "hint",
            vec![yes_no(view.check.password && view.hint, "set")],
            theme,
        ),
        check(
            "code",
            vec![match &view.authenticator {
                Some(a) if a.verified => Span::raw("app, verified"),
                Some(_) => Span::styled("not verified", theme.caution),
                None => Span::styled("none", theme.muted),
            }],
            theme,
        ),
    ];
    if let Some(key) = session
        .keys()
        .unwrap_or_default()
        .iter()
        .find(|k| k.kind == "recovery")
    {
        lines.push(check(
            "recovery",
            vec![Span::raw(date(key.created_on))],
            theme,
        ));
    }
    lines.push(Line::from(vec![
        Span::styled("c", theme.key),
        Span::styled(" changes it", theme.muted),
    ]));
    lines
}

fn storage_lines(session: &Session, theme: &Theme) -> Vec<Line<'static>> {
    if session.is_blocked() {
        return unread(theme);
    }
    let count = |id: Option<&str>| {
        session
            .secrets
            .iter()
            .filter(|p| session.storage.get(&p.name).map(String::as_str) == id)
            .count()
    };
    let secrets = |n: usize| {
        if n == 1 {
            "1 secret".to_owned()
        } else {
            format!("{n} secrets")
        }
    };
    let mut lines = vec![narrow(
        "vault",
        vec![Span::raw(format!("the file · {}", secrets(count(None))))],
        theme,
    )];
    for c in &session.connections {
        let provider = c.settings.provider();
        let target = match &c.settings {
            sourceorrery_core::ConnectionSettings::HashicorpVault { address, .. } => address,
            sourceorrery_core::ConnectionSettings::AwsSecretsManager { region, .. } => region,
            sourceorrery_core::ConnectionSettings::AzureKeyVault { vault_url } => vault_url,
        };
        let unreachable = session.unreachable.iter().find(|u| u.connection == c.id);
        let test = match (&c.last_test, unreachable) {
            (_, Some(u)) => Span::styled(format!("unreachable ({})", u.code), theme.error.bar),
            (Some(t), None) if t.outcome == "ok" => Span::styled(
                format!("tested {}", date(t.tested_on)),
                theme.status("enabled"),
            ),
            (Some(t), None) => Span::styled(
                format!("test failed: {}", sanitize(&t.outcome)),
                theme.caution,
            ),
            (None, None) => Span::styled("untested", theme.muted),
        };
        let signs_in = match c.credentials {
            sourceorrery_storage::CredentialSource::Stored => "stored",
            sourceorrery_storage::CredentialSource::Ambient => "sign-in",
        };
        lines.push(narrow(
            short_provider(provider),
            vec![
                Span::raw(format!(
                    "{} · {signs_in} · ",
                    secrets(count(Some(c.id.as_str())))
                )),
                test,
            ],
            theme,
        ));
        lines.push(narrow(
            "",
            vec![Span::styled(sanitize(target).into_owned(), theme.muted)],
            theme,
        ));
    }
    lines
}

fn project_lines(session: &Session, theme: &Theme) -> Vec<Line<'static>> {
    if session.is_blocked() {
        return unread(theme);
    }
    if session.projects.is_empty() {
        return vec![
            Line::from(Span::styled("none yet: run", theme.muted)),
            Line::from(vec![
                Span::styled("sourceorrery init", theme.code),
                Span::styled(" in a folder", theme.muted),
            ]),
        ];
    }
    let missing = session
        .projects
        .iter()
        .filter(|p| p.status == ProjectStatus::Missing)
        .count();
    let unreadable = session
        .projects
        .iter()
        .filter(|p| matches!(p.status, ProjectStatus::Unreadable(_)))
        .count();
    let found = session.projects.len() - missing - unreadable;
    let mut lines = vec![
        narrow(
            "found",
            vec![Span::styled(format!("✓ {found}"), theme.status("enabled"))],
            theme,
        ),
        narrow(
            "missing",
            vec![Span::styled(
                format!("✗ {missing}"),
                if missing > 0 {
                    theme.error.bar
                } else {
                    theme.muted
                },
            )],
            theme,
        ),
    ];
    if unreadable > 0 {
        lines.push(narrow(
            "unreadable",
            vec![Span::styled(unreadable.to_string(), theme.caution)],
            theme,
        ));
    }
    lines.push(Line::from(vec![
        Span::styled("3", theme.key),
        Span::styled(" lists them", theme.muted),
    ]));
    lines
}
