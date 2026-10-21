//! Design snapshots: the browser drawn into a test terminal and written out
//! as HTML, cell by cell, so a change to the look can be reviewed (and
//! screenshotted) without a terminal. Not part of the normal test run:
//!
//! ```text
//! cargo test -p sourceorrery-cli ui::snapshot -- --ignored
//! ```
//!
//! Files go to `$SOURCEORRERY_UI_SNAPSHOTS`, else `target/ui-snapshots`:
//! one page per screen, and `index.html` with all of them.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};
use sourceorrery_core::{
    SecretBytes, SecretClient, SetSecretOptions, UpdateSecretProperties, timestamp,
};
use sourceorrery_crypto::Argon2Params;
use sourceorrery_storage::{
    CreateVaultOptions, OpenOptions, ProtectorSpec, SqliteVault, StaticPassphrase,
};
use time::{Duration, OffsetDateTime};

use super::app::{Action, App, Message, Tab, VaultEntry};
use super::session::Session;
use super::theme::Theme;
use super::view;
use crate::cli::UiTheme;

const PASSPHRASE: &str = "snapshot-passphrase";

const WIDTH: u16 = 120;

/// A terminal's own colours: what `Reset` and the sixteen named colours
/// look like there.
struct Palette {
    name: &'static str,
    fg: &'static str,
    bg: &'static str,
    ansi: [&'static str; 16],
}

/// Windows Terminal's default scheme (Campbell).
const DARK_TERMINAL: Palette = Palette {
    name: "dark terminal",
    fg: "#cccccc",
    bg: "#0c0c0c",
    ansi: [
        "#0c0c0c", "#c50f1f", "#13a10e", "#c19c00", "#0037da", "#881798", "#3a96dd", "#cccccc",
        "#767676", "#e74856", "#16c60c", "#f9f1a5", "#3b78ff", "#b4009e", "#61d6d6", "#f2f2f2",
    ],
};

/// A common light scheme (One Half Light).
const LIGHT_TERMINAL: Palette = Palette {
    name: "light terminal",
    fg: "#383a42",
    bg: "#fafafa",
    ansi: [
        "#383a42", "#e45649", "#50a14f", "#c18301", "#0184bc", "#a626a4", "#0997b3", "#fafafa",
        "#4f525d", "#df6c75", "#98c379", "#e4c07a", "#61afef", "#c577dd", "#56b5c1", "#ffffff",
    ],
};

fn css(color: Color, default: &str, palette: &Palette) -> String {
    let named = |i: usize| palette.ansi[i].to_owned();
    match color {
        Color::Reset => default.to_owned(),
        Color::Black => named(0),
        Color::Red => named(1),
        Color::Green => named(2),
        Color::Yellow => named(3),
        Color::Blue => named(4),
        Color::Magenta => named(5),
        Color::Cyan => named(6),
        Color::Gray => named(7),
        Color::DarkGray => named(8),
        Color::LightRed => named(9),
        Color::LightGreen => named(10),
        Color::LightYellow => named(11),
        Color::LightBlue => named(12),
        Color::LightMagenta => named(13),
        Color::LightCyan => named(14),
        Color::White => named(15),
        Color::Rgb(r, g, b) => format!("#{r:02x}{g:02x}{b:02x}"),
        Color::Indexed(i) => xterm(i, palette),
    }
}

/// The xterm 256-colour table.
fn xterm(index: u8, palette: &Palette) -> String {
    const LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];
    match index {
        0..=15 => palette.ansi[usize::from(index)].to_owned(),
        16..=231 => {
            let i = index - 16;
            let (r, g, b) = (
                LEVELS[usize::from(i / 36)],
                LEVELS[usize::from(i / 6 % 6)],
                LEVELS[usize::from(i % 6)],
            );
            format!("#{r:02x}{g:02x}{b:02x}")
        }
        232..=255 => {
            let v = 8 + 10 * (index - 232);
            format!("#{v:02x}{v:02x}{v:02x}")
        }
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// One screen as a `<pre>`: runs of cells with the same look become one
/// `<span>`.
fn to_html(buffer: &Buffer, palette: &Palette) -> String {
    let width = usize::from(buffer.area.width);
    let mut out = String::new();
    for row in buffer.content().chunks(width) {
        let mut run_style = String::new();
        let mut run_text = String::new();
        for cell in row {
            let mut fg = css(cell.fg, palette.fg, palette);
            let mut bg = css(cell.bg, palette.bg, palette);
            if cell.modifier.contains(Modifier::REVERSED) {
                std::mem::swap(&mut fg, &mut bg);
            }
            let mut style = format!("color:{fg};background:{bg};");
            if cell.modifier.contains(Modifier::BOLD) {
                style.push_str("font-weight:700;");
            }
            if cell.modifier.contains(Modifier::DIM) {
                style.push_str("opacity:.6;");
            }
            if cell.modifier.contains(Modifier::ITALIC) {
                style.push_str("font-style:italic;");
            }
            if cell.modifier.contains(Modifier::UNDERLINED) {
                style.push_str("text-decoration:underline;");
            }
            if style != run_style && !run_text.is_empty() {
                let _ = write!(
                    out,
                    "<span style=\"{run_style}\">{}</span>",
                    escape(&run_text)
                );
                run_text.clear();
            }
            run_style = style;
            run_text.push_str(cell.symbol());
        }
        let _ = write!(
            out,
            "<span style=\"{run_style}\">{}</span>",
            escape(&run_text)
        );
        out.push('\n');
    }
    format!(
        "<pre style=\"background:{bg};color:{fg};width:{w}ch\">{out}</pre>",
        bg = palette.bg,
        fg = palette.fg,
        w = width
    )
}

fn page(title: &str, body: &str, background: &str) -> String {
    format!(
        "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>{title}</title><style>\n\
         body {{ margin: 0; padding: 24px; background: {background}; \
         font-family: 'Segoe UI', system-ui, sans-serif; color: #8f8879; }}\n\
         pre {{ margin: 0 0 8px; padding: 12px 16px; font: 15px/19px Consolas, \
         'Cascadia Mono', monospace; box-sizing: content-box; }}\n\
         pre span {{ display: inline-block; height: 19px; vertical-align: top; }}\n\
         h2 {{ font-size: 13px; font-weight: 600; letter-spacing: .12em; \
         text-transform: uppercase; margin: 28px 0 8px; }}\n\
         </style></head><body>\n{body}</body></html>\n"
    )
}

fn spec() -> ProtectorSpec {
    ProtectorSpec::Passphrase {
        passphrase: SecretBytes::from(PASSPHRASE),
        params: Argon2Params::TESTING,
    }
}

/// A vault with a secret in every state the views show, a second version,
/// a deleted secret and a refused read in its audit log.
fn sample_vault(dir: &Path) -> SqliteVault {
    let vault = SqliteVault::create(
        &dir.join("development.sorvault"),
        "development",
        CreateVaultOptions::default(),
        spec(),
    )
    .unwrap();
    let now = timestamp::now();
    let tags = |pairs: &[(&str, &str)]| {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    };
    let secrets = [
        (
            "database-password",
            SetSecretOptions {
                content_type: Some("text/plain".into()),
                tags: tags(&[("env", "dev"), ("owner", "platform")]),
                ..SetSecretOptions::default()
            },
        ),
        ("github-webhook-secret", SetSecretOptions::default()),
        (
            "legacy-token",
            SetSecretOptions {
                enabled: false,
                tags: tags(&[("deprecated", "yes")]),
                ..SetSecretOptions::default()
            },
        ),
        ("old-cert", SetSecretOptions::default()),
        (
            "signing-key",
            SetSecretOptions {
                not_before: Some(now + Duration::days(60)),
                ..SetSecretOptions::default()
            },
        ),
        (
            "stripe-api-key",
            SetSecretOptions {
                expires_on: Some(now + Duration::days(15)),
                tags: tags(&[("env", "dev"), ("team", "payments")]),
                ..SetSecretOptions::default()
            },
        ),
        ("retired-api-key", SetSecretOptions::default()),
    ];
    for (name, options) in secrets {
        vault
            .set_secret(name, SecretBytes::from("snapshot"), options)
            .unwrap();
    }
    vault
        .set_secret(
            "database-password",
            SecretBytes::from("snapshot"),
            SetSecretOptions {
                content_type: Some("text/plain".into()),
                tags: tags(&[("env", "dev"), ("owner", "platform")]),
                ..SetSecretOptions::default()
            },
        )
        .unwrap();
    vault
        .update_secret_properties(
            "old-cert",
            None,
            UpdateSecretProperties {
                expires_on: Some(Some(now - Duration::days(20))),
                ..UpdateSecretProperties::default()
            },
        )
        .unwrap();
    vault.delete_secret("retired-api-key").unwrap();
    // A refused read, so the audit log shows a denied outcome.
    let _ = vault.get_secret("legacy-token", None);
    vault
}

/// A vault whose audit log lost its newest rows: blocked until
/// acknowledged, opened for inspection as the browser opens vaults.
fn blocked_vault(dir: &Path) -> SqliteVault {
    let path = dir.join("production.sorvault");
    {
        let vault = SqliteVault::create(&path, "production", CreateVaultOptions::default(), spec())
            .unwrap();
        for name in ["api-key", "payments-webhook"] {
            vault
                .set_secret(
                    name,
                    SecretBytes::from("snapshot"),
                    SetSecretOptions::default(),
                )
                .unwrap();
        }
    }
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute(
        "DELETE FROM audit_events WHERE id > (SELECT MAX(id) FROM audit_events) - 1",
        [],
    )
    .unwrap();
    drop(conn);
    SqliteVault::open_with(
        &path,
        &StaticPassphrase::new(PASSPHRASE),
        OpenOptions {
            allow_quarantined: true,
            ..OpenOptions::default()
        },
    )
    .unwrap()
}

fn entries(dir: &Path) -> Vec<VaultEntry> {
    let mut entries: Vec<VaultEntry> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "sorvault"))
        .map(|e| {
            let path = e.path();
            let meta = std::fs::metadata(&path).ok();
            VaultEntry {
                name: path.file_stem().unwrap().to_string_lossy().into_owned(),
                size: meta.as_ref().map(std::fs::Metadata::len),
                modified: meta
                    .and_then(|m| m.modified().ok())
                    .map(OffsetDateTime::from),
                path: PathBuf::from("C:/Users/you/AppData/Local/sourceorrery/vaults")
                    .join(path.file_name().unwrap()),
            }
        })
        .collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    entries
}

fn draw(app: &mut App, theme: &Theme, height: u16) -> Buffer {
    let mut terminal = Terminal::new(TestBackend::new(WIDTH, height)).unwrap();
    terminal
        .draw(|frame| view::draw(frame, app, theme))
        .unwrap();
    terminal.backend().buffer().clone()
}

/// The looks to snapshot: a theme and the terminal it is shown in.
fn looks() -> Vec<(&'static str, Theme, &'static Palette)> {
    vec![
        (
            "dark",
            Theme::new(UiTheme::Dark, true, true),
            &DARK_TERMINAL,
        ),
        (
            "light",
            Theme::new(UiTheme::Light, true, true),
            &LIGHT_TERMINAL,
        ),
        (
            "dark-256",
            Theme::new(UiTheme::Dark, true, false),
            &DARK_TERMINAL,
        ),
        (
            "terminal-dark",
            Theme::new(UiTheme::Terminal, true, true),
            &DARK_TERMINAL,
        ),
        (
            "terminal-light",
            Theme::new(UiTheme::Terminal, true, true),
            &LIGHT_TERMINAL,
        ),
        ("no-color", Theme::plain(), &DARK_TERMINAL),
    ]
}

/// Every screen worth reviewing, drawn in one look.
fn screens(theme: &Theme) -> Vec<(&'static str, Buffer)> {
    let dir = tempfile::tempdir().unwrap();
    let vault = sample_vault(dir.path());
    let staging = SqliteVault::create(
        &dir.path().join("staging.sorvault"),
        "staging",
        CreateVaultOptions::default(),
        spec(),
    )
    .unwrap();
    let production = blocked_vault(dir.path());
    let vaults = entries(dir.path());
    let type_text = |app: &mut App, text: &str| {
        app.update(Action::Search);
        for c in text.chars() {
            app.update(Action::Input(c));
        }
    };

    let mut out = Vec::new();
    let mut app = App::new(vaults.clone());
    app.set_session(Session::open(Box::new(vault)).unwrap());
    app.update(Action::Down);
    out.push(("secrets", draw(&mut app, theme, 18)));
    type_text(&mut app, "tag:env");
    out.push(("search", draw(&mut app, theme, 18)));
    app.update(Action::Back);
    app.update(Action::Top);
    app.update(Action::Open);
    out.push(("detail", draw(&mut app, theme, 30)));
    app.update(Action::Back);
    app.update(Action::Show(Tab::Deleted));
    out.push(("deleted", draw(&mut app, theme, 14)));
    app.update(Action::Show(Tab::Audit));
    out.push(("audit", draw(&mut app, theme, 30)));
    app.update(Action::Show(Tab::Vaults));
    out.push(("vaults", draw(&mut app, theme, 14)));
    app.update(Action::Show(Tab::Secrets));
    app.update(Action::Help);
    out.push(("help", draw(&mut app, theme, 36)));
    app.update(Action::Help);
    app.update(Action::Refresh);
    out.push(("reloaded", draw(&mut app, theme, 18)));
    app.message = Some(Message::Error(
        "refresh failed; showing what was read before (crypto): audit chain head stale \
         (head was event 41)"
            .into(),
    ));
    out.push(("error", draw(&mut app, theme, 18)));

    let mut app = App::new(vaults.clone());
    app.set_session(Session::open(Box::new(staging)).unwrap());
    out.push(("empty", draw(&mut app, theme, 14)));

    let mut app = App::new(vaults.clone());
    app.set_session(Session::open(Box::new(production)).unwrap());
    out.push(("blocked", draw(&mut app, theme, 22)));

    let mut app = App::new(vaults);
    out.push(("no-vault", draw(&mut app, theme, 14)));
    out
}

#[test]
#[ignore = "writes design snapshots; run with --ignored"]
fn write_design_snapshots() {
    let out = std::env::var_os("SOURCEORRERY_UI_SNAPSHOTS").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/ui-snapshots"),
        PathBuf::from,
    );
    std::fs::create_dir_all(&out).unwrap();
    let mut index = String::new();
    for (look, theme, palette) in looks() {
        for (state, buffer) in screens(&theme) {
            let name = format!("{look}-{state}");
            let html = to_html(&buffer, palette);
            std::fs::write(
                out.join(format!("{name}.html")),
                page(&name, &html, palette.bg),
            )
            .unwrap();
            let _ = write!(
                index,
                "<h2>{look} · {state} · {}</h2>\n{html}\n",
                palette.name
            );
        }
    }
    std::fs::write(
        out.join("index.html"),
        page("sourceorrery ui", &index, "#171613"),
    )
    .unwrap();
    eprintln!("snapshots written to {}", out.display());
}
