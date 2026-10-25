//! A chosen column specification drives headings, widths and cells together.
use crate::output::sanitize;
use crate::ui::viewport::clip;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    widgets::{Cell, Row},
};

pub(super) struct Columns {
    indices: Vec<usize>,
    headings: Vec<&'static str>,
    pub widths: Vec<Constraint>,
    actual: Vec<u16>,
}
impl Columns {
    pub fn new(width: u16, indices: &[usize], headings: &[&'static str], sizes: &[u16]) -> Self {
        let widths: Vec<_> = indices
            .iter()
            .map(|&i| {
                if sizes[i] == 0 {
                    Constraint::Fill(1)
                } else {
                    Constraint::Length(sizes[i])
                }
            })
            .collect();
        let rects = Layout::horizontal(widths.clone())
            .spacing(2)
            .split(Rect::new(0, 0, width.saturating_sub(2), 1));
        let mut actual = vec![0; headings.len()];
        for (&i, r) in indices.iter().zip(rects.iter()) {
            actual[i] = r.width;
        }
        Self {
            indices: indices.to_vec(),
            headings: headings.to_vec(),
            widths,
            actual,
        }
    }
    pub fn headings(&self) -> Row<'static> {
        Row::new(
            self.indices
                .iter()
                .map(|&i| Cell::from(self.text(i, self.headings[i])))
                .collect::<Vec<_>>(),
        )
    }
    pub fn row(&self, cells: impl IntoIterator<Item = Cell<'static>>) -> Row<'static> {
        let cells: Vec<_> = cells.into_iter().collect();
        Row::new(
            self.indices
                .iter()
                .map(|&i| cells[i].clone())
                .collect::<Vec<_>>(),
        )
    }
    pub fn text(&self, index: usize, text: &str) -> String {
        clip(&sanitize(text), self.actual[index])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::text::Span;
    #[test]
    fn overflow_keeps_graphemes_and_distinguishes_absent_data() {
        assert_eq!(clip("界e\u{301}abc", 4), "界e\u{301}…");
        assert_eq!(clip("", 4), "");
        assert!(Span::raw(clip("界界界", 3)).width() <= 3);
    }
}
