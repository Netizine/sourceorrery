//! Text from outside the vault before it reaches a message.
//!
//! A provider's error string, a server's reported mount type or a service's
//! diagnostic is written by someone else and read on a terminal or in a
//! log: it must not drive the terminal (control characters, escape
//! sequences) nor fill the log (an unbounded body). [`foreign`] bounds it
//! and replaces every control and invisible formatting character before
//! it is interpolated into an error. The CLI escapes its own output once
//! more; the SDKs and the C ABI print messages as they are, so the
//! cleaning happens where the text enters.

/// Characters of foreign text kept in a message.
pub const MAX_FOREIGN_TEXT: usize = 200;

/// `text` bounded to [`MAX_FOREIGN_TEXT`] characters (with an ellipsis when
/// cut), every control character and every invisible formatting character
/// (bidirectional controls, zero-width characters, tag characters)
/// replaced by U+FFFD.
pub fn foreign(text: &str) -> String {
    foreign_bounded(text, MAX_FOREIGN_TEXT)
}

/// [`foreign`] with another bound.
pub fn foreign_bounded(text: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(text.len().min(max_chars * 4 + 3));
    for (i, c) in text.chars().enumerate() {
        if i >= max_chars {
            out.push('…');
            break;
        }
        if c.is_control() || is_invisible_format(c) {
            out.push('\u{fffd}');
        } else {
            out.push(c);
        }
    }
    out
}

/// Format characters that render as nothing or reorder what is shown and
/// have no place in a name: the soft hyphen, the Arabic letter mark and
/// the Mongolian vowel separator, the zero-width space, the bidirectional
/// marks, embeddings, overrides and isolates, the word joiner and the
/// invisible operators, the byte-order mark, the interlinear annotation
/// marks, and the tag characters. The zero-width joiner and non-joiner
/// are not among them: scripts need them, so they are shown as typed.
pub fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{00ad}'
            | '\u{061c}'
            | '\u{180e}'
            | '\u{200b}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{e0000}'..='\u{e007f}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controls_and_invisible_formatting_are_replaced_and_length_bounded() {
        assert_eq!(foreign("permission denied"), "permission denied");
        assert_eq!(
            foreign("a\u{1b}[2Jb\u{202e}c\u{200b}d\u{e0041}e\u{feff}f\rg"),
            "a\u{fffd}[2Jb\u{fffd}c\u{fffd}d\u{fffd}e\u{fffd}f\u{fffd}g"
        );
        let long = "x".repeat(MAX_FOREIGN_TEXT + 50);
        let shown = foreign(&long);
        assert_eq!(shown.chars().count(), MAX_FOREIGN_TEXT + 1);
        assert!(shown.ends_with('…'));
        assert_eq!(foreign_bounded("héllo", 2), "hé…");
        assert_eq!(foreign(""), "");
    }
}
