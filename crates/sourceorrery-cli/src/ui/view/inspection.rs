use crate::{
    output::sanitize,
    ui::{inspection::Inspection, theme::Theme, viewport},
};
use ratatui::{
    Frame,
    layout::Margin,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};
pub(super) fn draw(frame: &mut Frame<'_>, inspection: &mut Inspection, theme: &Theme) {
    let area = frame.area().inner(Margin::new(1, 1));
    let block = Block::bordered()
        .title(Span::styled(format!(" {} ", inspection.title), theme.label))
        .border_style(theme.rule)
        .style(theme.panel);
    let inner = block.inner(area);
    let content = super::rows(inner, 0, inner.height.saturating_sub(1));
    let lines: Vec<_> = inspection
        .lines
        .iter()
        .map(|s| Line::from(sanitize(s).into_owned()))
        .collect();
    let lines = viewport::reflow(&lines, content.width);
    inspection
        .viewport
        .fit(lines.len(), usize::from(content.height), None);
    frame.render_widget(Clear, area);
    frame.render_widget(block, area);
    frame.render_widget(
        Paragraph::new(lines).scroll((
            u16::try_from(inspection.viewport.offset).unwrap_or(u16::MAX),
            0,
        )),
        content,
    );
    frame.render_widget(
        Line::from(format!(
            "Esc back · ↑↓ PgUp/Dn Home/End · {}",
            inspection.viewport.position()
        ))
        .style(theme.key),
        super::rows(inner, inner.height.saturating_sub(1), 1),
    );
}
