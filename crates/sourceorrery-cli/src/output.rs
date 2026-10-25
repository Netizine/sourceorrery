//! Terminal output: tables, JSON, status lines. Nothing here ever receives a
//! secret value except [`print_revealed`], which exists so the disclosure is
//! a single, deliberate call site.
//!
//! Text read from a vault file is not trusted to be printable: labels,
//! audit actors and details, and key-wrap metadata can be edited by anyone
//! who can write the file, before or without unlocking it. Human-readable
//! output therefore goes through [`sanitize`]: every table cell, and every
//! status, note and error line. JSON needs no such pass (serde escapes
//! control characters) and revealed values must stay byte-exact.

use std::borrow::Cow;
use std::io::Write;

use owo_colors::{OwoColorize, Stream};
use serde::Serialize;
use sourceorrery_core::{AuditOutcome, SecretBytes, SecretProperties, policy, timestamp};
use time::OffsetDateTime;

use crate::cli::OutputFormat;

/// Make text safe to write to a terminal: every C0 control (ESC, TAB, CR and
/// LF included), DEL, every C1 control and every bidirectional formatting
/// character is replaced by a visible escape such as `\u{1b}`. Stored text
/// can then neither drive the terminal (move the cursor, erase lines, set
/// the clipboard with OSC 52) nor reorder what is shown. Borrows when
/// nothing needs escaping.
pub fn sanitize(text: &str) -> Cow<'_, str> {
    escape_unsafe(text, false)
}

/// [`sanitize`] for a message that may span lines: line feeds are kept,
/// everything else is escaped the same way.
pub fn sanitize_lines(text: &str) -> Cow<'_, str> {
    escape_unsafe(text, true)
}

fn escape_unsafe(text: &str, keep_line_feeds: bool) -> Cow<'_, str> {
    let escaped = |c: char| is_unsafe(c) && !(keep_line_feeds && c == '\n');
    if !text.chars().any(escaped) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 16);
    for c in text.chars() {
        if escaped(c) {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// Characters a terminal acts on instead of showing, or shows as nothing:
/// the `Cc` category (U+0000–U+001F, U+007F–U+009F), Unicode's
/// `Bidi_Control` set (the embeddings, overrides and isolates, plus the
/// ALM, LRM and RLM marks), and the invisible formatting characters that
/// let planted text hide inside a name (zero-width characters, joiners,
/// the byte-order mark, the tag characters): the set
/// [`sourceorrery_core::text`] replaces in foreign text.
fn is_unsafe(c: char) -> bool {
    c.is_control() || sourceorrery_core::text::is_invisible_format(c)
}

/// [`sanitize`] for an owned string, reusing it when nothing changes.
fn sanitize_owned(text: String) -> String {
    let escaped = match sanitize(&text) {
        Cow::Borrowed(_) => None,
        Cow::Owned(escaped) => Some(escaped),
    };
    escaped.unwrap_or(text)
}

/// Print `✓ message` to stderr so stdout stays clean for data.
pub fn success(message: &str) {
    let tick = "✓"
        .if_supports_color(Stream::Stderr, |t| t.green())
        .to_string();
    eprintln!("{tick} {}", sanitize_lines(message));
}

/// Print `! message` to stderr.
pub fn note(message: &str) {
    let mark = "!"
        .if_supports_color(Stream::Stderr, |t| t.yellow())
        .to_string();
    eprintln!("{mark} {}", sanitize_lines(message));
}

/// Print an error to stderr in the selected format.
pub fn print_error(format: OutputFormat, code: &str, message: &str) {
    match format {
        OutputFormat::Json => {
            let body = serde_json::json!({ "error": { "code": code, "message": message } });
            eprintln!("{body}");
        }
        OutputFormat::Table => {
            let label = "error"
                .if_supports_color(Stream::Stderr, |t| t.red())
                .to_string();
            eprintln!("{label}: {}", sanitize_lines(message));
            if code == "locked" {
                eprintln!(
                    "hint: where this machine cannot open the vault, give its recovery key \
                     at the prompt, with --recovery-key-file or in SOURCEORRERY_RECOVERY_KEY"
                );
            }
        }
    }
}

/// Print any serialisable value as pretty JSON on stdout.
pub fn json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, value)?;
    stdout.write_all(b"\n")?;
    Ok(())
}

/// One table cell: text from anywhere, shown through [`sanitize`], and a
/// tone the table applies after padding, so colour is neither escaped nor
/// counted towards the column width.
#[derive(Debug)]
pub struct Cell {
    text: String,
    tone: Tone,
}

#[derive(Clone, Copy, Debug)]
enum Tone {
    Plain,
    Warning,
    Error,
}

impl From<String> for Cell {
    fn from(text: String) -> Self {
        Self {
            text,
            tone: Tone::Plain,
        }
    }
}

impl Cell {
    fn push_to(&self, line: &mut String) {
        use std::fmt::Write as _;
        let text = self.text.as_str();
        // Writing to a String cannot fail.
        let _ = match self.tone {
            Tone::Plain => line.write_str(text),
            Tone::Warning => write!(
                line,
                "{}",
                text.if_supports_color(Stream::Stdout, |t| t.yellow())
            ),
            Tone::Error => write!(
                line,
                "{}",
                text.if_supports_color(Stream::Stdout, |t| t.red())
            ),
        };
    }
}

/// A simple left-aligned text table. Every cell is sanitised as it is
/// added, so no caller can put a control character on the terminal.
#[derive(Debug, Default)]
pub struct Table {
    headers: Vec<Cell>,
    rows: Vec<Vec<Cell>>,
}

impl Table {
    pub fn new<const N: usize>(headers: [&str; N]) -> Self {
        Self {
            headers: headers
                .iter()
                .map(|h| Cell::from(sanitize(h).into_owned()))
                .collect(),
            rows: Vec::new(),
        }
    }

    pub fn row<const N: usize, C: Into<Cell>>(&mut self, cells: [C; N]) -> &mut Self {
        self.rows.push(
            cells
                .into_iter()
                .map(|cell| {
                    let cell = cell.into();
                    Cell {
                        text: sanitize_owned(cell.text),
                        tone: cell.tone,
                    }
                })
                .collect(),
        );
        self
    }

    fn widths(&self) -> Vec<usize> {
        let mut widths: Vec<usize> = self
            .headers
            .iter()
            .map(|h| h.text.chars().count())
            .collect();
        for row in &self.rows {
            for (i, cell) in row.iter().enumerate() {
                widths[i] = widths[i].max(cell.text.chars().count());
            }
        }
        widths
    }

    pub fn print(&self) -> anyhow::Result<()> {
        let widths = self.widths();
        let mut out = std::io::stdout().lock();
        let header = format_row(&self.headers, &widths);
        writeln!(
            out,
            "{}",
            header.if_supports_color(Stream::Stdout, |t| t.bold())
        )?;
        for row in &self.rows {
            writeln!(out, "{}", format_row(row, &widths))?;
        }
        Ok(())
    }
}

fn format_row(cells: &[Cell], widths: &[usize]) -> String {
    let mut line = String::new();
    let last = cells.len().saturating_sub(1);
    for (i, cell) in cells.iter().enumerate() {
        cell.push_to(&mut line);
        if i != last {
            let pad = widths[i] - cell.text.chars().count();
            line.extend(std::iter::repeat_n(' ', pad + 2));
        }
    }
    line.trim_end().to_owned()
}

/// Human status of a version at `now`.
pub fn status(props: &SecretProperties, now: OffsetDateTime) -> &'static str {
    match policy::evaluate_access(props, now) {
        Ok(()) => "enabled",
        Err(err) => match err.code() {
            "disabled" => "disabled",
            "not_yet_valid" => "pending",
            "expired" => "expired",
            _ => "unavailable",
        },
    }
}

pub fn fmt_time(ts: OffsetDateTime) -> String {
    timestamp::format(ts)
}

pub fn fmt_opt_time(ts: Option<OffsetDateTime>) -> String {
    ts.map_or_else(|| "-".to_owned(), fmt_time)
}

pub fn outcome_cell(outcome: AuditOutcome) -> Cell {
    Cell {
        text: outcome.as_str().to_owned(),
        tone: match outcome {
            AuditOutcome::Success => Tone::Plain,
            AuditOutcome::Denied => Tone::Warning,
            AuditOutcome::Failure => Tone::Error,
        },
    }
}

/// Print a secret's metadata as a key/value block.
pub fn properties_block(props: &SecretProperties) -> anyhow::Result<()> {
    let now = timestamp::now();
    let mut t = Table::new(["FIELD", "VALUE"]);
    t.row(["name".into(), props.name.clone()]);
    t.row(["vault".into(), props.vault.clone()]);
    t.row(["version".into(), props.version.clone()]);
    t.row(["status".into(), status(props, now).to_owned()]);
    t.row([
        "content-type".into(),
        props.content_type.clone().unwrap_or_else(|| "-".into()),
    ]);
    t.row(["not-before".into(), fmt_opt_time(props.not_before)]);
    t.row(["expires".into(), fmt_opt_time(props.expires_on)]);
    t.row(["created".into(), fmt_time(props.created_on)]);
    t.row(["updated".into(), fmt_time(props.updated_on)]);
    let tags = if props.tags.is_empty() {
        "-".to_owned()
    } else {
        props
            .tags
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    t.row(["tags".into(), tags]);
    t.row(["reference".into(), props.id()]);
    t.print()
}

/// The one place a secret value reaches stdout.
pub fn print_revealed(value: &SecretBytes, raw: bool) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(value.expose())?;
    if !raw {
        stdout.write_all(b"\n")?;
    }
    stdout.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_printable(text: &str) {
        assert!(
            !text.chars().any(is_unsafe),
            "unsafe character left in {text:?}"
        );
    }

    #[test]
    fn plain_text_is_borrowed_unchanged() {
        for text in ["", "dev-only", "passphrase-3f2a", "a b  c", "x=1, y=2"] {
            assert!(matches!(sanitize(text), Cow::Borrowed(t) if t == text));
        }
    }

    #[test]
    fn non_ascii_letters_are_unchanged() {
        for text in ["Jürgen", "日本語のラベル", "مفتاح", "κλειδί", "✓ ready"]
        {
            assert!(matches!(sanitize(text), Cow::Borrowed(t) if t == text));
        }
    }

    #[test]
    fn invisible_formatting_characters_are_shown_escaped() {
        // Zero-width space, word joiner, byte-order mark, a tag character:
        // planted text that would read as another name.
        assert_eq!(sanitize("de\u{200b}v"), "de\\u{200b}v");
        assert_eq!(sanitize("a\u{2060}b\u{feff}c"), "a\\u{2060}b\\u{feff}c");
        assert_eq!(sanitize("x\u{e0069}y"), "x\\u{e0069}y");
        assert_eq!(sanitize("soft\u{ad}hyphen"), "soft\\u{ad}hyphen");
    }

    #[test]
    fn escape_and_csi_sequences_are_shown_escaped() {
        assert_eq!(sanitize("\x1b"), "\\u{1b}");
        // Cursor up, erase line: what would hide the audit row above.
        assert_eq!(sanitize("x\x1b[1A\x1b[2K"), "x\\u{1b}[1A\\u{1b}[2K");
        // The 8-bit CSI introducer.
        assert_eq!(sanitize("\u{9b}2K"), "\\u{9b}2K");
    }

    #[test]
    fn osc_52_clipboard_writes_are_shown_escaped() {
        let osc = "\x1b]52;c;ZWNobyBwd25lZA==\x07";
        let shown = sanitize(osc);
        assert_eq!(shown, "\\u{1b}]52;c;ZWNobyBwd25lZA==\\u{7}");
        assert_printable(&shown);
        // String terminator form, 8-bit OSC and ST.
        assert_eq!(
            sanitize("\x1b]52;c;eA==\x1b\\"),
            "\\u{1b}]52;c;eA==\\u{1b}\\"
        );
        assert_eq!(sanitize("\u{9d}52;c;eA==\u{9c}"), "\\u{9d}52;c;eA==\\u{9c}");
    }

    #[test]
    fn every_c0_and_c1_control_and_del_is_escaped() {
        let controls = (0u32..0x20).chain(0x7f..=0x9f).filter_map(char::from_u32);
        for c in controls {
            let text = format!("a{c}b");
            let shown = sanitize(&text);
            assert_eq!(shown, format!("a{}b", c.escape_unicode()), "{c:?}");
            assert_printable(&shown);
        }
        assert_eq!(sanitize("a\tb\r\nc"), "a\\u{9}b\\u{d}\\u{a}c");
    }

    #[test]
    fn bidi_controls_are_escaped() {
        // "Trojan Source": an override that makes the shown order lie.
        assert_eq!(sanitize("user\u{202e}nimda"), "user\\u{202e}nimda");
        let bidi = ['\u{061c}', '\u{200e}', '\u{200f}']
            .into_iter()
            .chain('\u{202a}'..='\u{202e}')
            .chain('\u{2066}'..='\u{2069}');
        for c in bidi {
            assert_printable(&sanitize(&format!("a{c}b")));
        }
        // Neighbours of those ranges are ordinary text.
        for c in ['\u{2029}', '\u{202f}', '\u{2065}', '\u{206a}', '\u{200d}'] {
            let text = format!("a{c}b");
            assert!(matches!(sanitize(&text), Cow::Borrowed(_)), "{c:?}");
        }
    }

    #[test]
    fn messages_keep_line_feeds_only() {
        let text = "cannot start:\n  a (locked)\n  b\x1b[2K\r";
        assert_eq!(
            sanitize_lines(text),
            "cannot start:\n  a (locked)\n  b\\u{1b}[2K\\u{d}"
        );
        assert!(matches!(sanitize_lines("one\ntwo"), Cow::Borrowed(_)));
    }

    #[test]
    fn table_cells_are_escaped_and_aligned_on_the_escaped_text() {
        let mut table = Table::new(["LABEL", "KIND"]);
        table.row(["evil\x1b[2K".to_owned(), "passphrase".to_owned()]);
        table.row(["plain".to_owned(), "os-keyring".to_owned()]);
        let widths = table.widths();
        let evil = format_row(&table.rows[0], &widths);
        let plain = format_row(&table.rows[1], &widths);
        assert_eq!(evil, "evil\\u{1b}[2K  passphrase");
        assert_printable(&evil);
        assert_eq!(evil.find("passphrase"), plain.find("os-keyring"));
    }

    #[test]
    fn toned_cells_are_padded_by_their_text_not_their_colour() {
        let mut table = Table::new(["O", "D"]);
        table.row([
            outcome_cell(AuditOutcome::Denied),
            Cell::from("x".to_owned()),
        ]);
        table.row([
            outcome_cell(AuditOutcome::Failure),
            Cell::from("y".to_owned()),
        ]);
        assert_eq!(table.widths(), [7, 1]);
    }
}
