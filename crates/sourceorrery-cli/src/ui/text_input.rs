//! Cursor state only for non-secret fields. Backspace/Delete operate on
//! grapheme clusters (a base plus combining marks is one editing unit).
use crate::output::sanitize;
use ratatui::{style::Style, text::Span};
use std::cell::Cell;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Edit {
    Left,
    Right,
    Home,
    End,
    Delete,
}
#[derive(Clone, Debug, Default)]
pub struct Cursor {
    pub byte: usize,
    left: Cell<usize>,
}
fn boundaries(text: &str) -> Vec<usize> {
    if text.chars().any(char::is_control) {
        return text
            .char_indices()
            .map(|(i, _)| i)
            .chain(std::iter::once(text.len()))
            .collect();
    }
    let mut result = vec![0];
    let mut byte = 0;
    for g in Span::raw(text).styled_graphemes(Style::default()) {
        byte += g.symbol.len();
        result.push(byte);
    }
    result
}
impl Cursor {
    pub fn end(text: &str) -> Self {
        Self {
            byte: text.len(),
            left: Cell::new(0),
        }
    }
    fn position(&self, text: &str) -> usize {
        boundaries(text)
            .into_iter()
            .take_while(|&i| i <= self.byte.min(text.len()))
            .last()
            .unwrap_or(0)
    }
    pub fn insert(&mut self, text: &mut String, c: char) {
        if c.is_control() {
            return;
        }
        self.byte = self.position(text);
        text.insert(self.byte, c);
        self.byte += c.len_utf8();
        self.byte = boundaries(text)
            .into_iter()
            .find(|&i| i >= self.byte)
            .unwrap_or(text.len());
    }
    pub fn erase(&mut self, text: &mut String) {
        let end = self.position(text);
        let start = boundaries(text)
            .into_iter()
            .take_while(|&i| i < end)
            .last()
            .unwrap_or(0);
        text.replace_range(start..end, "");
        self.byte = start;
    }
    pub fn edit(&mut self, text: &mut String, action: Edit) {
        let pos = self.position(text);
        let bounds = boundaries(text);
        match action {
            Edit::Home => {
                self.byte = 0;
                self.left.set(0);
            }
            Edit::End => self.byte = text.len(),
            Edit::Left => {
                self.byte = bounds
                    .iter()
                    .copied()
                    .take_while(|&i| i < pos)
                    .last()
                    .unwrap_or(0)
            }
            Edit::Right => {
                self.byte = bounds
                    .iter()
                    .copied()
                    .find(|&i| i > pos)
                    .unwrap_or(text.len())
            }
            Edit::Delete => {
                let end = bounds.iter().copied().find(|&i| i > pos).unwrap_or(pos);
                text.replace_range(pos..end, "");
                self.byte = pos;
            }
        }
    }
    pub fn render(&self, text: &str, width: u16) -> String {
        if width == 0 {
            return String::new();
        }
        if width <= 2 {
            return "▌".into();
        }
        let pos = self.position(text);
        let bounds = boundaries(text);
        let mut left = bounds
            .iter()
            .copied()
            .take_while(|&i| i <= self.left.get().min(pos))
            .last()
            .unwrap_or(0);
        let budget = usize::from(width.saturating_sub(3));
        while Span::raw(sanitize(&text[left..pos])).width() > budget {
            left = bounds.iter().copied().find(|&i| i > left).unwrap_or(pos);
        }
        self.left.set(left);
        let rendered = format!(
            "{}{}▌{}",
            if left > 0 { "…" } else { "" },
            sanitize(&text[left..pos]),
            sanitize(&text[pos..])
        );
        super::viewport::clip(&rendered, width)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn middle_edits_preserve_suffix_and_remove_whole_combining_clusters() {
        let mut text = "prefix-界e\u{301}-suffix".to_owned();
        let mut c = Cursor::end(&text);
        c.edit(&mut text, Edit::Home);
        c.insert(&mut text, 'X');
        assert_eq!(text, "Xprefix-界e\u{301}-suffix");
        for _ in 0..8 {
            c.edit(&mut text, Edit::Right);
        }
        c.edit(&mut text, Edit::Delete);
        assert_eq!(text, "Xprefix-界-suffix");
        c.erase(&mut text);
        assert_eq!(text, "Xprefix--suffix");
        for width in [4, 8, 20] {
            let shown = c.render(&text, width);
            assert!(shown.contains('▌'));
            assert!(Span::raw(shown).width() <= usize::from(width));
        }
    }
}
