//! Forms and confirmations, drawn over the views like the help: a panel in
//! the site's card colour.

use ratatui::Frame;
use ratatui::layout::{Constraint, Flex, Layout};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Padding, Paragraph, Wrap};

use crate::output::sanitize;
use crate::ui::edit::{Confirm, Dialog, FieldKey, Form};
use crate::ui::theme::Theme;

/// Widest a dialog grows.
const WIDTH: u16 = 86;

/// Width of a form's label column.
const LABEL_WIDTH: usize = 15;

pub(super) fn draw(frame: &mut Frame<'_>, dialog: &Dialog, theme: &Theme) {
    let (title, lines) = match dialog {
        Dialog::Form(form) => (form.title.clone(), form_lines(form, theme)),
        Dialog::Confirm(confirm) => (confirm.title.clone(), confirm_lines(confirm, theme)),
    };
    let width = WIDTH.min(frame.area().width.saturating_sub(4)).max(20);
    // Inside the border and padding, each line wraps onto as many rows as
    // its width needs.
    let inner = usize::from(width.saturating_sub(6)).max(1);
    let rows: usize = lines
        .iter()
        .map(|line| line.width().div_ceil(inner).max(1))
        .sum();
    let height = u16::try_from(rows).unwrap_or(u16::MAX).saturating_add(4);
    let [area] = Layout::vertical([Constraint::Length(height)])
        .flex(Flex::Center)
        .areas(frame.area());
    let [area] = Layout::horizontal([Constraint::Length(width)])
        .flex(Flex::Center)
        .areas(area);
    let block = Block::bordered()
        .border_style(theme.rule)
        .title(Span::styled(format!(" {title} "), theme.label))
        .padding(Padding::new(2, 2, 1, 1))
        .style(theme.panel);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        area,
    );
}

fn form_lines(form: &Form, theme: &Theme) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for (i, field) in form.fields.iter().enumerate() {
        let focused = i == form.focus;
        let mut spans = vec![
            Span::styled(format!("{:<LABEL_WIDTH$}", field.key.label()), theme.muted),
            Span::raw(sanitize(&field.value).into_owned()),
        ];
        if focused {
            // A choice switches with space; only text has a cursor.
            if !matches!(field.key, FieldKey::Enabled | FieldKey::Storage) {
                spans.push(Span::styled("▌", theme.key));
            }
            spans.push(Span::styled(
                format!("   {}", field.key.hint()),
                theme.muted,
            ));
        }
        let line = Line::from(spans);
        lines.push(if focused {
            line.style(theme.selected)
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
            .style(theme.selected),
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
