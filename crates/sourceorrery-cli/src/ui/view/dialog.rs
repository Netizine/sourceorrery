//! Forms and confirmations, drawn over the views like the help: a panel in
//! the site's card colour.

use ratatui::Frame;
use ratatui::layout::Margin;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph};

use crate::output::sanitize;
use crate::ui::edit::{Confirm, Dialog, FieldKey, Form};
use crate::ui::theme::Theme;

/// Widest a dialog grows.
const WIDTH: u16 = 86;

/// Width of a form's label column.
const LABEL_WIDTH: usize = 15;

pub(super) fn draw(
    frame: &mut Frame<'_>,
    dialog: &Dialog,
    theme: &Theme,
    viewport: &mut crate::ui::viewport::Viewport,
) {
    let (title, mut lines, focus, action) = match dialog {
        Dialog::Form(form) => (
            form.title.clone(),
            form_lines(form, theme),
            Some(form.focus),
            "Enter review",
        ),
        Dialog::Confirm(confirm) => (
            confirm.title.clone(),
            confirm_lines(confirm, theme),
            None,
            "Enter confirm",
        ),
    };
    lines.pop(); // Controls live in the fixed footer, outside the viewport.
    let mut area = frame.area().inner(Margin::new(1, 1));
    area.width = area.width.min(WIDTH);
    area.x = frame.area().x + frame.area().width.saturating_sub(area.width) / 2;
    let block = Block::bordered()
        .border_style(theme.rule)
        .title(Span::styled(format!(" {title} "), theme.label))
        .style(theme.panel);
    let inner = block.inner(area);
    let content = super::rows(inner, 0, inner.height.saturating_sub(1));
    let focus = crate::ui::viewport::focus_row(&lines, focus, content.width);
    let lines = crate::ui::viewport::reflow(&lines, content.width);
    viewport.fit(lines.len(), usize::from(content.height), focus);
    frame.render_widget(Clear, area);
    frame.render_widget(block, area);
    frame.render_widget(
        Paragraph::new(lines).scroll((u16::try_from(viewport.offset).unwrap_or(u16::MAX), 0)),
        content,
    );
    frame.render_widget(
        Line::from(format!(
            "Esc cancel · {action} · PgUp/Dn · {}",
            viewport.position()
        ))
        .style(theme.key),
        super::rows(inner, inner.height.saturating_sub(1), 1),
    );
}

fn form_lines(form: &Form, theme: &Theme) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for (i, field) in form.fields.iter().enumerate() {
        let focused = i == form.focus;
        let mut spans = vec![
            Span::styled(
                format!("{:<LABEL_WIDTH$}", field.key.label()),
                theme.cell(theme.muted, focused),
            ),
            Span::raw(sanitize(&field.value).into_owned()),
        ];
        if focused {
            // A choice switches with space; only text has a cursor.
            if !matches!(field.key, FieldKey::Enabled | FieldKey::Storage) {
                spans.push(Span::styled("▌", theme.cell(theme.key, focused)));
            }
            spans.push(Span::styled(
                format!("   {}", field.key.hint()),
                theme.cell(theme.muted, focused),
            ));
        }
        let line = Line::from(spans);
        lines.push(if focused {
            line.style(theme.focused)
        } else {
            line
        });
    }
    lines.push(Line::from(""));
    if let Some(error) = &form.error {
        lines.push(error_line(error, theme));
    }
    lines.push(keys(
        &[
            ("Tab", "next field"),
            ("Enter", "review"),
            ("Esc", "cancel"),
        ],
        theme,
    ));
    lines
}

fn confirm_lines(confirm: &Confirm, theme: &Theme) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = confirm
        .lines
        .iter()
        .map(|l| Line::from(l.clone()))
        .collect();
    lines.push(Line::from(""));
    if let Some(name) = &confirm.must_type {
        lines.push(
            Line::from(vec![
                Span::styled(
                    format!("type '{}' to confirm  ", sanitize(name)),
                    theme.muted,
                ),
                Span::raw(sanitize(&confirm.typed).into_owned()),
                Span::styled("▌", theme.key),
            ])
            .style(theme.focused),
        );
        lines.push(Line::from(""));
    }
    if let Some(error) = &confirm.error {
        lines.push(error_line(error, theme));
    }
    lines.push(keys(&[("Enter", "confirm"), ("Esc", "cancel")], theme));
    lines
}

fn error_line(error: &str, theme: &Theme) -> Line<'static> {
    Line::from(vec![
        Span::styled("ERROR  ", theme.error.title),
        Span::raw(sanitize(error).into_owned()),
    ])
}

fn keys(pairs: &[(&'static str, &'static str)], theme: &Theme) -> Line<'static> {
    let mut spans = Vec::new();
    for (key, what) in pairs {
        spans.push(Span::styled(*key, theme.key));
        spans.push(Span::styled(format!(" {what}   "), theme.muted));
    }
    Line::from(spans)
}
