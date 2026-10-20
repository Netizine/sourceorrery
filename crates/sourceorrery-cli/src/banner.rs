//! The text logo shown when `sourceorrery` runs with no arguments.
//!
//! The wordmark is a set of tiny bitmaps rendered with Unicode half blocks
//! (`▀ ▄ █`), the same technique Ratatui uses for its logo, so the CLI needs
//! no image support and the art scales with the terminal font.
//!
//! Colour is deliberately conservative so the banner reads on **both dark and
//! light** backgrounds: bright blue for "Source", cyan for "Orrery", bold, and
//! nothing that depends on the background colour (no white, black, yellow or
//! background fills). Colour follows the usual conventions (`NO_COLOR`,
//! `FORCE_COLOR`, non-TTY → off) through `owo-colors`.
//!
//! When stdout is not a terminal the banner degrades to plain ASCII text so
//! it can be piped or logged without escape sequences.

use std::fmt::Write as _;
use std::io::{self, IsTerminal, Write};

use owo_colors::{OwoColorize, Stream, Style};

/// Project tagline.
pub const TAGLINE: &str = "Secrets belong to the runtime, not the repository.";
/// Documentation site.
pub const SITE_URL: &str = "https://sourceorrery.ai";
/// Short label for [`SITE_URL`].
pub const SITE_LABEL: &str = "sourceorrery.ai";

/// Environment variable to force a banner style (`unicode` or `plain`).
pub const STYLE_ENV: &str = "SOURCEORRERY_BANNER";

/// How the banner is drawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BannerStyle {
    /// Half-block bitmap art, colour (when supported) and an OSC 8 hyperlink.
    Unicode,
    /// Plain ASCII, no escape sequences.
    Plain,
}

impl BannerStyle {
    /// Pick a style for stdout: Unicode on a terminal, plain otherwise,
    /// overridable with `SOURCEORRERY_BANNER=unicode|plain`.
    pub fn detect() -> Self {
        match std::env::var(STYLE_ENV).ok().as_deref() {
            Some("unicode") => return Self::Unicode,
            Some("plain") => return Self::Plain,
            _ => {}
        }
        let dumb = std::env::var("TERM").is_ok_and(|t| t == "dumb");
        if io::stdout().is_terminal() && !dumb {
            Self::Unicode
        } else {
            Self::Plain
        }
    }
}

// ---------------------------------------------------------------------------
// Bitmaps
// ---------------------------------------------------------------------------

/// Pixel height of every glyph: two rows above the x-height, four rows of
/// x-height, two rows of descender. Rendered as four text lines.
const GLYPH_ROWS: usize = 8;

/// A glyph bitmap: `#` is lit, anything else is dark. All rows share a width.
struct Glyph([&'static str; GLYPH_ROWS]);

impl Glyph {
    fn width(&self) -> usize {
        self.0[0].len()
    }

    fn lit(&self, row: usize, col: usize) -> bool {
        self.0[row].as_bytes().get(col) == Some(&b'#')
    }
}

const UPPER_S: Glyph = Glyph([
    ".####", "#....", ".###.", "....#", "....#", "####.", ".....", ".....",
]);

const UPPER_O: Glyph = Glyph([
    ".###.", "#...#", "#...#", "#...#", "#...#", ".###.", ".....", ".....",
]);

const LOWER_O: Glyph = Glyph([
    "....", "....", ".##.", "#..#", "#..#", ".##.", "....", "....",
]);
const LOWER_U: Glyph = Glyph([
    "....", "....", "#..#", "#..#", "#..#", ".###", "....", "....",
]);
const LOWER_R: Glyph = Glyph([
    "....", "....", "#.##", "##..", "#...", "#...", "....", "....",
]);
const LOWER_C: Glyph = Glyph([
    "....", "....", ".###", "#...", "#...", ".###", "....", "....",
]);
const LOWER_E: Glyph = Glyph([
    "....", "....", ".##.", "####", "#...", ".###", "....", "....",
]);
const LOWER_Y: Glyph = Glyph([
    "....", "....", "#..#", "#..#", "#..#", ".###", "...#", ".##.",
]);

/// A run of glyphs drawn in one colour.
struct Segment {
    glyphs: &'static [&'static Glyph],
    style: Style,
}

/// The wordmark: navy "Source", cyan "Orrery" in the brand asset; here the
/// nearest colours that stay legible on dark and light backgrounds.
fn segments() -> [Segment; 2] {
    [
        Segment {
            glyphs: &[&UPPER_S, &LOWER_O, &LOWER_U, &LOWER_R, &LOWER_C, &LOWER_E],
            style: Style::new().bright_blue().bold(),
        },
        Segment {
            glyphs: &[&UPPER_O, &LOWER_R, &LOWER_R, &LOWER_E, &LOWER_R, &LOWER_Y],
            style: Style::new().cyan().bold(),
        },
    ]
}

/// Gap between glyphs of one segment, in columns.
const GLYPH_GAP: usize = 1;
/// Gap between segments, in columns.
const SEGMENT_GAP: usize = 2;

/// Render one segment's text row (two pixel rows) with half blocks.
fn segment_row(segment: &Segment, text_row: usize) -> String {
    let top = text_row * 2;
    let bottom = top + 1;
    let mut line = String::new();
    for (i, glyph) in segment.glyphs.iter().enumerate() {
        if i > 0 {
            line.extend(std::iter::repeat_n(' ', GLYPH_GAP));
        }
        for col in 0..glyph.width() {
            line.push(match (glyph.lit(top, col), glyph.lit(bottom, col)) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
    }
    line
}

/// The four text rows of the logo, each as a list of `(text, style)` runs,
/// with trailing blanks trimmed off the last run.
fn logo_rows() -> Vec<Vec<(String, Style)>> {
    let segments = segments();
    (0..GLYPH_ROWS / 2)
        .map(|row| {
            let mut runs: Vec<(String, Style)> = segments
                .iter()
                .enumerate()
                .map(|(i, segment)| {
                    let mut text = String::new();
                    if i > 0 {
                        text.extend(std::iter::repeat_n(' ', SEGMENT_GAP));
                    }
                    text.push_str(&segment_row(segment, row));
                    (text, segment.style)
                })
                .collect();
            if let Some((last, _)) = runs.last_mut() {
                let trimmed = last.trim_end().len();
                last.truncate(trimmed);
            }
            runs
        })
        .collect()
}

/// Width in columns of the Unicode logo.
pub fn logo_width() -> usize {
    logo_rows()
        .iter()
        .map(|runs| runs.iter().map(|(t, _)| t.chars().count()).sum::<usize>())
        .max()
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// OSC 8 hyperlink when `enabled`, else the bare URL.
fn hyperlink(label: &str, url: &str, enabled: bool) -> String {
    if enabled {
        format!("\x1b]8;;{url}\x1b\\{label}\x1b]8;;\x1b\\")
    } else {
        url.to_owned()
    }
}

fn styled(text: &str, style: Style) -> String {
    text.if_supports_color(Stream::Stdout, |t| t.style(style))
        .to_string()
}

/// The full banner as a string.
pub fn render(style: BannerStyle) -> String {
    let version = env!("CARGO_PKG_VERSION");
    let mut out = String::new();

    match style {
        BannerStyle::Unicode => {
            for runs in logo_rows() {
                for (text, run_style) in runs {
                    out.push_str(&styled(&text, run_style));
                }
                out.push('\n');
            }
            // The site label sits centred under the wordmark, as in the logo.
            let link_ok = std::env::var_os("NO_COLOR").is_none();
            let visible = if link_ok { SITE_LABEL } else { SITE_URL };
            let pad = logo_width().saturating_sub(visible.len()) / 2;
            out.extend(std::iter::repeat_n(' ', pad));
            out.push_str(&styled(
                &hyperlink(SITE_LABEL, SITE_URL, link_ok),
                Style::new().dimmed(),
            ));
            out.push('\n');
            out.push('\n');
            let _ = writeln!(out, "  {TAGLINE}  v{version}");
        }
        BannerStyle::Plain => {
            out.push_str("SourceOrrery\n");
            let _ = writeln!(out, "{TAGLINE}\n{SITE_URL}  v{version}");
        }
    }

    out.push('\n');
    out.push_str("Quick start\n");
    out.push_str("  sourceorrery vault create development\n");
    out.push_str("  sourceorrery secret set database-password --vault development\n");
    out.push_str("  sourceorrery init && sourceorrery run -- <your command>\n");
    out.push('\n');
    out.push_str("Run `sourceorrery --help` for all commands.\n");
    out
}

/// Print the banner to stdout in the detected style.
pub fn print() -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(render(BannerStyle::detect()).as_bytes())?;
    stdout.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glyphs_are_rectangular_and_eight_rows_tall() {
        let all: [&Glyph; 8] = [
            &UPPER_S, &UPPER_O, &LOWER_O, &LOWER_U, &LOWER_R, &LOWER_C, &LOWER_E, &LOWER_Y,
        ];
        for glyph in all {
            let width = glyph.width();
            assert!(width > 0);
            for row in glyph.0 {
                assert_eq!(row.len(), width, "ragged glyph row {row:?}");
                assert!(row.bytes().all(|b| b == b'#' || b == b'.'));
            }
        }
    }

    #[test]
    fn logo_has_four_rows_and_fits_eighty_columns() {
        let rows = logo_rows();
        assert_eq!(rows.len(), 4);
        assert!(logo_width() <= 80, "logo is {} columns wide", logo_width());
        assert!(logo_width() >= 50, "logo unexpectedly narrow");
        // Every row has some ink.
        for runs in &rows {
            let text: String = runs.iter().map(|(t, _)| t.as_str()).collect();
            assert!(
                text.chars().any(|c| "▀▄█".contains(c)),
                "blank row: {text:?}"
            );
        }
    }

    #[test]
    fn plain_banner_has_no_escape_sequences() {
        let text = render(BannerStyle::Plain);
        assert!(!text.contains('\x1b'));
        assert!(text.contains("SourceOrrery"));
        assert!(text.contains(SITE_URL));
        assert!(text.contains(TAGLINE));
        assert!(text.contains("Quick start"));
    }

    #[test]
    fn unicode_banner_mentions_site_and_version() {
        let text = render(BannerStyle::Unicode);
        assert!(text.contains(SITE_LABEL));
        assert!(text.contains(env!("CARGO_PKG_VERSION")));
        assert!(text.contains('█'));
    }

    #[test]
    fn hyperlink_wraps_label() {
        let link = hyperlink("x", "https://example.com", true);
        assert!(link.starts_with("\x1b]8;;https://example.com\x1b\\x"));
        assert_eq!(
            hyperlink("x", "https://example.com", false),
            "https://example.com"
        );
    }
}
