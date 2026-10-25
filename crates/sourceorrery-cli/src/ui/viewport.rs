//! Presentation-only scrolling. Reflow once at word/grapheme boundaries and draw
//! those exact rows without a second widget wrapping policy.
use super::app::Action;
use ratatui::{
    style::Style,
    text::{Line, Span},
};

#[derive(Debug, Default)]
pub struct Viewport {
    pub offset: usize,
    pub page: usize,
    pub total: usize,
    focus: Option<usize>,
    manual: bool,
}
impl Viewport {
    pub fn move_by(&mut self, action: Action) {
        self.manual = true;
        self.offset = match action {
            Action::Up => self.offset.saturating_sub(1),
            Action::Down => self.offset.saturating_add(1),
            Action::PageUp => self.offset.saturating_sub(self.page.max(1)),
            Action::PageDown => self.offset.saturating_add(self.page.max(1)),
            Action::Top => 0,
            Action::Bottom => usize::MAX,
            _ => self.offset,
        }
        .min(self.total.saturating_sub(self.page));
    }
    pub fn fit(&mut self, total: usize, page: usize, focus: Option<usize>) {
        self.total = total;
        self.page = page.max(1);
        if focus != self.focus {
            self.manual = false;
            self.focus = focus;
        }
        if !self.manual
            && let Some(row) = focus
        {
            if row < self.offset {
                self.offset = row;
            }
            if row >= self.offset + self.page {
                self.offset = row.saturating_sub(self.page - 1);
            }
        }
        self.offset = self.offset.min(total.saturating_sub(self.page));
    }
    pub fn position(&self) -> String {
        format!(
            "{}–{} of {}",
            (self.offset + 1).min(self.total),
            (self.offset + self.page).min(self.total),
            self.total
        )
    }
}

pub fn reflow(lines: &[Line<'_>], width: u16) -> Vec<Line<'static>> {
    if width == 0 {
        return Vec::new();
    }
    let width = usize::from(width);
    let mut result = Vec::new();
    for line in lines {
        let mut spans = Vec::new();
        let mut used = 0;
        let graphemes: Vec<_> = line.styled_graphemes(Style::default()).collect();
        let mut start = 0;
        while start < graphemes.len() {
            let space = graphemes[start].symbol.chars().all(char::is_whitespace);
            let end = (start + 1..graphemes.len())
                .find(|&i| graphemes[i].symbol.chars().all(char::is_whitespace) != space)
                .unwrap_or(graphemes.len());
            let token = &graphemes[start..end];
            let token_width: usize = token.iter().map(|g| Span::raw(g.symbol).width()).sum();
            if !space && token_width <= width && used + token_width > width && !spans.is_empty() {
                result.push(Line::from(std::mem::take(&mut spans)));
                used = 0;
            }
            for g in token {
                let cells = Span::raw(g.symbol).width();
                if used + cells > width && !spans.is_empty() {
                    result.push(Line::from(std::mem::take(&mut spans)));
                    used = 0;
                }
                spans.push(Span::styled(g.symbol.to_owned(), g.style));
                used += cells;
            }
            start = end;
        }
        result.push(Line::from(spans));
    }
    result
}

pub fn focus_row(lines: &[Line<'_>], focus: Option<usize>, width: u16) -> Option<usize> {
    focus.map(|i| reflow(&lines[..i.min(lines.len())], width).len())
}

pub fn clip(text: &str, width: u16) -> String {
    let span = Span::raw(text);
    let width = usize::from(width);
    if span.width() <= width {
        return text.to_owned();
    }
    if width == 0 {
        return String::new();
    }
    let mut result = String::new();
    let mut used = 0;
    for g in span.styled_graphemes(ratatui::style::Style::default()) {
        let cells = Span::raw(g.symbol).width();
        if used + cells >= width {
            break;
        }
        result.push_str(g.symbol);
        used += cells;
    }
    result.push('…');
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reflow_preserves_unicode_styles_and_measures_actual_rows() {
        let lines = vec![Line::from("word heavy error 界e\u{301} next")];
        let rows = reflow(&lines, 8);
        assert!(rows.iter().all(|l| l.width() <= 8));
        let text: String = rows
            .iter()
            .flat_map(|l| l.spans.iter().map(|s| s.content.as_ref()))
            .collect();
        assert_eq!(text, "word heavy error 界e\u{301} next");
        let mut v = Viewport::default();
        v.fit(rows.len(), 2, Some(rows.len() - 1));
        assert_eq!(v.offset, rows.len() - 2);
        v.move_by(Action::Top);
        assert_eq!(v.offset, 0);
        v.fit(rows.len(), 10, None);
        assert_eq!(v.offset, 0);
    }
}
