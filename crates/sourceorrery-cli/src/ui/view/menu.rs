use crate::ui::{menu::Menu, theme::Theme, viewport};
use ratatui::{
    Frame,
    layout::Margin,
    text::{Line, Span},
    widgets::{Block, Clear, List, ListItem},
};
pub(super) fn draw(frame: &mut Frame<'_>, menu: &mut Menu, theme: &Theme) {
    let mut area = frame.area().inner(Margin::new(1, 1));
    area.width = area.width.min(86);
    area.x = frame.area().x + frame.area().width.saturating_sub(area.width) / 2;
    let block = Block::bordered()
        .title(Span::styled(format!(" {} ", menu.title), theme.label))
        .border_style(theme.rule)
        .style(theme.panel);
    let inner = block.inner(area);
    let content = super::rows(inner, 0, inner.height.saturating_sub(1));
    let items: Vec<_> = menu
        .items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let selected = menu.state.selected() == Some(i);
            let style = theme.cell(
                if item.reason.is_some() {
                    theme.disabled_action
                } else {
                    theme.screen
                },
                selected,
            );
            let mut lines = vec![Line::from(vec![
                Span::styled(item.label.clone(), style),
                Span::styled(
                    format!("  {}", item.shortcut),
                    theme.cell(theme.key, selected),
                ),
            ])];
            if let Some(reason) = &item.reason {
                lines.push(Line::from(Span::styled(
                    format!("  Unavailable: {reason}"),
                    style,
                )));
            }
            ListItem::new(viewport::reflow(&lines, content.width.saturating_sub(2)))
        })
        .collect();
    menu.page = usize::from(content.height / 2).max(1);
    frame.render_widget(Clear, area);
    frame.render_widget(block, area);
    frame.render_stateful_widget(
        List::new(items)
            .highlight_style(theme.selected)
            .highlight_symbol("▌ "),
        content,
        &mut menu.state,
    );
    frame.render_widget(
        Line::from(format!(
            "Esc back · Enter choose · ↑↓ PgUp/Dn · {}/{}",
            menu.state.selected().map_or(0, |i| i + 1),
            menu.items.len()
        ))
        .style(theme.key),
        super::rows(inner, inner.height.saturating_sub(1), 1),
    );
}
