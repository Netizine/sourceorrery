//! Colours.
//!
//! `dark` and `light` are the documentation site's "paper" palettes
//! (`site/src/styles/paper.css`): warm charcoal or paper stock, navy ink,
//! the callout colours for status and messages, and the site's text
//! selection colour for the selected row. They paint the whole screen, so
//! they look the same whatever the terminal's own colours are. Terminals
//! without 24-bit colour get the nearest colours of the xterm 256 table.
//!
//! `terminal` keeps the terminal's background and uses its named colours,
//! like the banner. `NO_COLOR` turns colour off in every theme and keeps
//! bold, dim and reverse.

use ratatui::style::{Color, Modifier, Style};

use crate::cli::UiTheme;

type Rgb = [u8; 3];

/// One of the site's palettes, as `[r, g, b]`.
struct Paper {
    bg: Rgb,
    nav: Rgb,
    text: Rgb,
    heading: Rgb,
    heading_2: Rgb,
    accent: Rgb,
    gray_2: Rgb,
    gray_3: Rgb,
    gray_4: Rgb,
    gray_5: Rgb,
    selection: Rgb,
    code: Rgb,
    green: Rgb,
    blue: Rgb,
    red: Rgb,
    blue_bg: Rgb,
    red_bg: Rgb,
    taupe: Rgb,
    panel: Rgb,
}

/// `:root` in paper.css.
const DARK: Paper = Paper {
    bg: [0x17, 0x16, 0x13],
    nav: [0x1c, 0x1a, 0x16],
    text: [0xd9, 0xd3, 0xc6],
    heading: [0xec, 0xe7, 0xdc],
    heading_2: [0xb7, 0xcd, 0xee],
    accent: [0x9f, 0xbd, 0xe6],
    gray_2: [0xbf, 0xb8, 0xaa],
    gray_3: [0x8f, 0x88, 0x79],
    gray_4: [0x5f, 0x5a, 0x50],
    gray_5: [0x3b, 0x38, 0x32],
    selection: [0x2f, 0x4a, 0x73],
    code: [0x2a, 0x27, 0x22],
    green: [0x7f, 0xa1, 0x74],
    blue: [0x6f, 0x93, 0xc8],
    red: [0xd6, 0x81, 0x77],
    blue_bg: [0x1f, 0x2a, 0x3b],
    red_bg: [0x35, 0x22, 0x1f],
    taupe: [0xa7, 0x9a, 0x82],
    panel: [0x1e, 0x1c, 0x18],
};

/// `:root[data-theme='light']` in paper.css.
const LIGHT: Paper = Paper {
    bg: [0xf5, 0xf2, 0xec],
    nav: [0xf0, 0xec, 0xe4],
    text: [0x2a, 0x27, 0x23],
    heading: [0x16, 0x30, 0x4f],
    heading_2: [0x2a, 0x4b, 0x7c],
    accent: [0x1f, 0x3f, 0x73],
    gray_2: [0x45, 0x41, 0x3b],
    gray_3: [0x6a, 0x65, 0x5c],
    gray_4: [0x9b, 0x94, 0x88],
    gray_5: [0xc9, 0xc2, 0xb4],
    selection: [0xd6, 0xe1, 0xf0],
    code: [0xe9, 0xe4, 0xd9],
    green: [0x45, 0x64, 0x3e],
    blue: [0x3b, 0x5d, 0x93],
    red: [0x88, 0x3e, 0x36],
    blue_bg: [0xe2, 0xe9, 0xf3],
    red_bg: [0xf1, 0xe1, 0xdc],
    taupe: [0x6b, 0x58, 0x3c],
    panel: [0xfa, 0xf8, 0xf3],
};

/// A message line drawn like the site's callouts: a tinted panel with a
/// coloured bar and a small uppercase title.
#[derive(Clone, Copy, Debug)]
pub struct Callout {
    pub panel: Style,
    pub bar: Style,
    pub title: Style,
}

#[derive(Clone, Copy, Debug)]
pub struct Theme {
    /// The whole screen: background and body text.
    pub screen: Style,
    /// The header and footer bars.
    pub bar: Style,
    pub title: Style,
    pub vault: Style,
    /// Section labels and column headings.
    pub label: Style,
    pub muted: Style,
    /// Booktabs rules above and below the table.
    pub rule: Style,
    /// The thinner rule under the column headings.
    pub header_rule: Style,
    pub selected: Style,
    pub focused: Style,
    pub search_match: Style,
    pub disabled_action: Style,
    /// The bar in front of the selected row (the site marks the current
    /// page the same way).
    pub marker: Style,
    pub key: Style,
    /// A command shown inline, like the site's inline code.
    pub code: Style,
    /// The selected view in the tab bar.
    pub tab: Style,
    /// Overlays such as the help: the site's card colour.
    pub panel: Style,
    /// Caution: denied audit outcomes (the site's taupe callout).
    pub caution: Style,
    pub info: Callout,
    pub error: Callout,
    enabled: Style,
    pending: Style,
    disabled: Style,
    unavailable: Style,
    /// The selection is reverse video: coloured text in a selected row
    /// would become a block of colour, so status colours are dropped there.
    reverse_selection: bool,
    color: bool,
    truecolor: bool,
}

impl Theme {
    /// `choice`, unless `NO_COLOR` is set.
    pub fn detect(choice: UiTheme) -> Self {
        let color = std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
        Self::new(choice, color, truecolor())
    }

    /// No colour at all: what `NO_COLOR` gets.
    #[cfg(test)]
    pub fn plain() -> Self {
        Self::new(UiTheme::Terminal, false, false)
    }

    pub fn new(choice: UiTheme, color: bool, truecolor: bool) -> Self {
        if !color {
            return Self::mono();
        }
        let mut theme = match choice {
            UiTheme::Dark => Self::paper(&DARK, truecolor),
            UiTheme::Light => Self::paper(&LIGHT, truecolor),
            UiTheme::Terminal => Self::named(),
        };
        theme.truecolor = truecolor;
        theme
    }

    pub fn choosing(&self, choice: UiTheme) -> Self {
        Self::new(choice, self.color, self.truecolor)
    }

    /// Style for a status from [`crate::output::status`].
    pub fn status(&self, status: &str) -> Style {
        match status {
            "enabled" => self.enabled,
            "pending" => self.pending,
            "disabled" => self.disabled,
            _ => self.unavailable,
        }
    }

    /// `style` for text in a table row. In a reverse-video selection,
    /// colour and dim would turn into patches of background, so the
    /// selected row is drawn plain.
    pub fn cell(&self, style: Style, selected: bool) -> Style {
        if selected {
            if self.reverse_selection {
                Style::new()
            } else {
                Style::new().fg(self.selected.fg.unwrap_or(Color::Reset))
            }
        } else {
            style
        }
    }

    fn paper(p: &Paper, truecolor: bool) -> Self {
        let c = |rgb| color(rgb, truecolor);
        let fg = |rgb| Style::new().fg(c(rgb));
        let bold = Modifier::BOLD;
        let callout = |bar, panel| Callout {
            panel: Style::new().fg(c(p.text)).bg(c(panel)),
            bar: fg(bar),
            title: fg(p.heading).add_modifier(bold),
        };
        Self {
            screen: Style::new().fg(c(p.text)).bg(c(p.bg)),
            bar: Style::new().fg(c(p.gray_3)).bg(c(p.nav)),
            title: fg(p.heading).add_modifier(bold),
            vault: fg(p.heading_2).add_modifier(bold),
            label: fg(p.gray_2).add_modifier(bold),
            muted: fg(p.gray_3),
            rule: fg(p.gray_4),
            header_rule: fg(p.gray_5),
            selected: Style::new().fg(c(p.text)).bg(c(p.selection)),
            focused: fg(p.text)
                .bg(c(p.selection))
                .add_modifier(bold | Modifier::UNDERLINED),
            search_match: fg(p.heading).add_modifier(bold | Modifier::UNDERLINED),
            disabled_action: fg(p.gray_3),
            marker: fg(p.accent),
            key: fg(p.accent).add_modifier(bold),
            code: fg(p.heading).bg(c(p.code)),
            tab: fg(p.accent).add_modifier(bold | Modifier::UNDERLINED),
            panel: Style::new().fg(c(p.text)).bg(c(p.panel)),
            caution: fg(p.taupe),
            info: callout(p.blue, p.blue_bg),
            error: callout(p.red, p.red_bg),
            enabled: fg(p.green),
            pending: fg(p.blue),
            disabled: fg(p.gray_3),
            unavailable: fg(p.red),
            reverse_selection: false,
            color: true,
            truecolor,
        }
    }

    /// The terminal's own colours, chosen like the banner's to read on dark
    /// and light backgrounds: no white, black or yellow, no fills.
    fn named() -> Self {
        let fg = |color| Style::new().fg(color);
        let callout = |color| Callout {
            panel: Style::new(),
            bar: fg(color),
            title: fg(color).add_modifier(Modifier::BOLD),
        };
        Self {
            screen: Style::new(),
            bar: Style::new(),
            title: fg(Color::LightBlue).add_modifier(Modifier::BOLD),
            vault: fg(Color::Cyan).add_modifier(Modifier::BOLD),
            label: Style::new().add_modifier(Modifier::BOLD),
            muted: Style::new().add_modifier(Modifier::DIM),
            rule: fg(Color::DarkGray),
            header_rule: fg(Color::DarkGray),
            selected: Style::new().add_modifier(Modifier::REVERSED),
            focused: Style::new().add_modifier(Modifier::REVERSED | Modifier::UNDERLINED),
            search_match: Style::new().add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            disabled_action: Style::new().add_modifier(Modifier::DIM),
            marker: Style::new(),
            key: fg(Color::LightBlue),
            code: fg(Color::Cyan),
            tab: fg(Color::LightBlue).add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            panel: Style::new(),
            caution: fg(Color::Magenta),
            info: callout(Color::Blue),
            error: callout(Color::Red),
            enabled: fg(Color::Green),
            pending: fg(Color::Blue),
            disabled: Style::new().add_modifier(Modifier::DIM),
            unavailable: fg(Color::Red),
            reverse_selection: true,
            color: true,
            truecolor: true,
        }
    }

    fn mono() -> Self {
        let bold = Style::new().add_modifier(Modifier::BOLD);
        let dim = Style::new().add_modifier(Modifier::DIM);
        let callout = Callout {
            panel: Style::new(),
            bar: Style::new(),
            title: bold,
        };
        Self {
            screen: Style::new(),
            bar: Style::new(),
            title: bold,
            vault: bold,
            label: bold,
            muted: dim,
            rule: dim,
            header_rule: dim,
            selected: Style::new().add_modifier(Modifier::REVERSED),
            focused: Style::new().add_modifier(Modifier::REVERSED | Modifier::UNDERLINED),
            search_match: Style::new().add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            disabled_action: Style::new().add_modifier(Modifier::DIM),
            marker: Style::new(),
            key: bold,
            code: bold,
            tab: bold.add_modifier(Modifier::UNDERLINED),
            panel: Style::new(),
            caution: bold,
            info: callout,
            error: callout,
            enabled: Style::new(),
            pending: Style::new(),
            disabled: dim,
            unavailable: bold,
            reverse_selection: true,
            color: false,
            truecolor: false,
        }
    }
}

/// True when the terminal shows 24-bit colour. Windows' console and
/// terminal do; elsewhere the terminal says so in `COLORTERM`, and macOS
/// Terminal is known not to.
fn truecolor() -> bool {
    let var = |key| std::env::var(key).unwrap_or_default();
    if matches!(var("COLORTERM").as_str(), "truecolor" | "24bit") {
        return true;
    }
    if var("TERM_PROGRAM") == "Apple_Terminal" {
        return false;
    }
    cfg!(windows) || var("TERM").ends_with("-direct")
}

/// A palette colour as a terminal colour: itself, or the nearest colour of
/// the xterm 256 table when the terminal has no 24-bit colour.
fn color([r, g, b]: Rgb, truecolor: bool) -> Color {
    if truecolor {
        Color::Rgb(r, g, b)
    } else {
        Color::Indexed(xterm_index(r, g, b))
    }
}

/// Nearest entry of the xterm 256-colour table outside the sixteen
/// terminal-defined ones: the 6×6×6 cube or the grey ramp.
fn xterm_index(r: u8, g: u8, b: u8) -> u8 {
    const LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];
    let nearest = |v: u8| -> u8 {
        let mut best = 0;
        for (i, level) in (0u8..).zip(LEVELS) {
            if level.abs_diff(v) < LEVELS[usize::from(best)].abs_diff(v) {
                best = i;
            }
        }
        best
    };
    let distance = |(r2, g2, b2): (u8, u8, u8)| {
        [(r, r2), (g, g2), (b, b2)]
            .iter()
            .map(|(a, b)| u32::from(a.abs_diff(*b)).pow(2))
            .sum::<u32>()
    };
    let (ri, gi, bi) = (nearest(r), nearest(g), nearest(b));
    let cube = (
        LEVELS[usize::from(ri)],
        LEVELS[usize::from(gi)],
        LEVELS[usize::from(bi)],
    );
    let average = (u16::from(r) + u16::from(g) + u16::from(b)) / 3;
    // Grey ramp: 232 + n is the grey 8 + 10n, n in 0..24.
    let step = u8::try_from((average.saturating_sub(3) / 10).min(23)).unwrap_or(23);
    let level = 8 + 10 * step;
    if distance((level, level, level)) < distance(cube) {
        232 + step
    } else {
        16 + 36 * ri + 6 * gi + bi
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rgb(c: Color) -> [u8; 3] {
        match c {
            Color::Rgb(r, g, b) => [r, g, b],
            Color::Indexed(i) if i >= 232 => [8 + 10 * (i - 232); 3],
            Color::Indexed(i) if i >= 16 => {
                let n = i - 16;
                let levels = [0, 95, 135, 175, 215, 255];
                [
                    levels[usize::from(n / 36)],
                    levels[usize::from((n / 6) % 6)],
                    levels[usize::from(n % 6)],
                ]
            }
            _ => panic!("controlled palette expected"),
        }
    }
    fn contrast(a: Color, b: Color) -> f64 {
        let luminance = |c| {
            let [r, g, b] = rgb(c).map(|v| {
                let v = f64::from(v) / 255.0;
                if v <= 0.04045 {
                    v / 12.92
                } else {
                    ((v + 0.055) / 1.055).powf(2.4)
                }
            });
            0.2126 * r + 0.7152 * g + 0.0722 * b
        };
        let (a, b) = (luminance(a), luminance(b));
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }
    #[test]
    fn meaningful_paper_text_and_selected_combinations_meet_readability_target() {
        for choice in [UiTheme::Dark, UiTheme::Light] {
            for truecolor in [true, false] {
                let t = Theme::new(choice, true, truecolor);
                for style in [
                    t.screen,
                    t.label,
                    t.muted,
                    t.key,
                    t.caution,
                    t.status("enabled"),
                    t.status("disabled"),
                    t.status("expired"),
                    t.search_match,
                    t.disabled_action,
                ] {
                    let ratio = contrast(style.fg.unwrap(), t.screen.bg.unwrap());
                    assert!(ratio >= 4.5, "{choice:?} {truecolor} {style:?}: {ratio}");
                    assert!(
                        contrast(t.cell(style, true).fg.unwrap(), t.selected.bg.unwrap()) >= 4.5
                    );
                }
                for c in [t.info, t.error] {
                    assert!(
                        contrast(c.title.fg.unwrap(), c.panel.bg.unwrap()) >= 4.5,
                        "{choice:?} callout"
                    );
                }
                assert!(contrast(t.focused.fg.unwrap(), t.focused.bg.unwrap()) >= 4.5);
            }
        }
    }

    #[test]
    fn paper_colours_are_the_sites() {
        let dark = Theme::new(UiTheme::Dark, true, true);
        assert_eq!(dark.screen.bg, Some(Color::Rgb(0x17, 0x16, 0x13)));
        assert_eq!(dark.selected.bg, Some(Color::Rgb(0x2f, 0x4a, 0x73)));
        let light = Theme::new(UiTheme::Light, true, true);
        assert_eq!(light.screen.bg, Some(Color::Rgb(0xf5, 0xf2, 0xec)));
        assert_eq!(light.key.fg, Some(Color::Rgb(0x1f, 0x3f, 0x73)));
    }

    #[test]
    fn no_colour_means_no_colour_in_any_theme() {
        for choice in [UiTheme::Dark, UiTheme::Light, UiTheme::Terminal] {
            let theme = Theme::new(choice, false, true);
            for style in [
                theme.screen,
                theme.bar,
                theme.title,
                theme.key,
                theme.selected,
            ] {
                assert_eq!((style.fg, style.bg), (None, None), "{choice:?}");
            }
            assert_eq!(theme.status("expired").fg, None);
        }
    }

    #[test]
    fn without_truecolor_the_nearest_xterm_colour_is_used() {
        assert_eq!(xterm_index(0, 0, 0), 16);
        assert_eq!(xterm_index(255, 255, 255), 231);
        assert_eq!(xterm_index(255, 0, 0), 196);
        assert_eq!(xterm_index(128, 128, 128), 244); // grey 128 exactly
        assert_eq!(xterm_index(0x17, 0x16, 0x13), 233); // warm charcoal -> grey 18
        assert_eq!(xterm_index(0x7f, 0xa1, 0x74), 108); // green -> 135,175,135
        let dark = Theme::new(UiTheme::Dark, true, false);
        assert!(matches!(dark.screen.bg, Some(Color::Indexed(_))));
    }

    #[test]
    fn a_reverse_video_selection_is_drawn_plain() {
        let terminal = Theme::new(UiTheme::Terminal, true, true);
        let enabled = terminal.status("enabled");
        assert_eq!(enabled.fg, Some(Color::Green));
        assert_eq!(terminal.cell(enabled, false), enabled);
        assert_eq!(terminal.cell(enabled, true), Style::new());
        assert_eq!(terminal.cell(terminal.muted, true), Style::new());
        let dark = Theme::new(UiTheme::Dark, true, true);
        assert_eq!(dark.cell(dark.muted, true).fg, dark.selected.fg);
    }
}
