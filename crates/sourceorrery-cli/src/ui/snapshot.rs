//! Design snapshots: the browser, `init`'s screens and the setup screens
//! drawn into a test terminal and written out as HTML, cell by cell, so a
//! change to the look can be reviewed (and screenshotted) without a
//! terminal. Not part of the normal test run:
//!
//! ```text
//! cargo test -p sourceorrery-cli ui::snapshot -- --ignored
//! ```
//!
//! Files go to `$SOURCEORRERY_UI_SNAPSHOTS`, else `target/ui-snapshots`:
//! one page per screen, and `index.html` with all of them. The docs'
//! walkthroughs are copied from them (`npm --prefix site run
//! walkthroughs`), so every screen shows a made-up person (`PERSON`), never
//! the machine that drew it.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};
use sourceorrery_core::{
    ConnectionSettings, SecretBytes, SecretClient, SetSecretOptions, UpdateSecretProperties,
    timestamp,
};
use sourceorrery_crypto::{Argon2Params, TotpSecret, totp};
use sourceorrery_provider::{ConnectionClient, Routed};
use sourceorrery_storage::{
    AuthenticatorChange, ConnectionChange, CreateVaultOptions, CredentialStore, NoStore,
    OpenOptions, PasswordChange, SecretStorage, SettingsChange, SqliteVault, StaticRecoveryKey,
    ViewCheck,
};
use time::{Duration, OffsetDateTime};

/// No credential store: a test never touches the real OS store, and these
/// vaults open with their recovery keys.
fn no_store() -> std::sync::Arc<dyn CredentialStore> {
    std::sync::Arc::new(NoStore)
}

use super::app::{Action, App, Message, Tab, VaultEntry};
use super::editor::MetadataEditor;
use super::session::Session;
use super::setup::fake::VAULTS_DIR;
use super::source::{MetadataSource, ViewSettings};
use super::theme::Theme;
use super::view;
use crate::cli::UiTheme;

// ---------------------------------------------------------------------------
// Whose machine the snapshots show
// ---------------------------------------------------------------------------

/// The person every snapshot shows. The snapshots are published in the
/// docs, so no screen carries the name or the folders of the machine that
/// drew it.
const PERSON: &str = "alex";
/// Where `PERSON` keeps their projects; their vaults are where the setup
/// fake keeps them. A Windows home, as the setup fake's credential store
/// is Windows's, whatever machine draws the snapshots.
const PROJECTS_DIR: &str = r"C:\Users\alex\code";

/// `file`, as if it were in `dir`.
fn moved_to(dir: &str, file: &Path) -> PathBuf {
    PathBuf::from(format!(
        r"{dir}\{}",
        file.file_name().unwrap().to_string_lossy()
    ))
}

/// A vault seen as `PERSON`'s: its file under their home and their name on
/// every audit event a person made. Everything else passes through.
#[derive(Debug)]
struct AsPerson(Routed);

fn by_person(mut event: sourceorrery_core::AuditEvent) -> sourceorrery_core::AuditEvent {
    if event.actor.kind == sourceorrery_core::PrincipalKind::User {
        PERSON.clone_into(&mut event.actor.id);
    }
    event
}

impl MetadataSource for AsPerson {
    fn descriptor(&self) -> sourceorrery_core::Result<sourceorrery_core::VaultDescriptor> {
        let mut descriptor = self.0.descriptor()?;
        descriptor.path = descriptor.path.map(|p| moved_to(VAULTS_DIR, &p));
        Ok(descriptor)
    }
    fn truncations(&self) -> sourceorrery_core::Result<Vec<sourceorrery_core::AuditEvent>> {
        Ok(self.0.truncations()?.into_iter().map(by_person).collect())
    }
    fn secrets(&self) -> sourceorrery_core::Result<Vec<sourceorrery_core::SecretProperties>> {
        MetadataSource::secrets(&self.0)
    }
    fn secrets_at(
        &self,
        id: &str,
    ) -> sourceorrery_core::Result<Vec<sourceorrery_core::SecretProperties>> {
        MetadataSource::secrets_at(&self.0, id)
    }
    fn versions(
        &self,
        name: &str,
    ) -> sourceorrery_core::Result<Vec<sourceorrery_core::SecretProperties>> {
        MetadataSource::versions(&self.0, name)
    }
    fn deleted(&self) -> sourceorrery_core::Result<Vec<sourceorrery_core::DeletedSecret>> {
        MetadataSource::deleted(&self.0)
    }
    fn deleted_at(
        &self,
        id: &str,
    ) -> sourceorrery_core::Result<Vec<sourceorrery_core::DeletedSecret>> {
        MetadataSource::deleted_at(&self.0, id)
    }
    fn audit(
        &self,
        query: sourceorrery_core::AuditQuery,
    ) -> sourceorrery_core::Result<Vec<sourceorrery_core::AuditEvent>> {
        Ok(MetadataSource::audit(&self.0, query)?
            .into_iter()
            .map(by_person)
            .collect())
    }
    fn verify(&self) -> sourceorrery_core::Result<sourceorrery_storage::AuditVerification> {
        MetadataSource::verify(&self.0)
    }
    fn keys(&self) -> sourceorrery_core::Result<Vec<sourceorrery_storage::WrapInfo>> {
        MetadataSource::keys(&self.0)
    }
    fn connections(&self) -> sourceorrery_core::Result<Vec<sourceorrery_storage::ConnectionInfo>> {
        MetadataSource::connections(&self.0)
    }
    fn stored_at(&self, id: &str) -> sourceorrery_core::Result<Vec<String>> {
        MetadataSource::stored_at(&self.0, id)
    }
    fn view_settings(&self) -> sourceorrery_core::Result<ViewSettings> {
        MetadataSource::view_settings(&self.0)
    }
    // The real folders, so the browser's check on disk finds what is there;
    // `disguise` moves them under `PERSON`'s home once they are checked.
    fn projects(&self) -> sourceorrery_core::Result<Vec<sourceorrery_storage::ProjectLink>> {
        MetadataSource::projects(&self.0)
    }
    fn capabilities_of(
        &self,
        name: &str,
    ) -> sourceorrery_core::Result<&'static [sourceorrery_core::Capability]> {
        MetadataSource::capabilities_of(&self.0, name)
    }
}

impl MetadataEditor for AsPerson {
    fn update(
        &self,
        name: &str,
        version: &str,
        update: UpdateSecretProperties,
    ) -> sourceorrery_core::Result<sourceorrery_core::SecretProperties> {
        MetadataEditor::update(&self.0, name, version, update)
    }
    fn delete(&self, name: &str) -> sourceorrery_core::Result<sourceorrery_core::DeletedSecret> {
        MetadataEditor::delete(&self.0, name)
    }
    fn recover(
        &self,
        name: &str,
    ) -> sourceorrery_core::Result<sourceorrery_core::SecretProperties> {
        MetadataEditor::recover(&self.0, name)
    }
    fn add_version(
        &self,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
    ) -> sourceorrery_core::Result<sourceorrery_core::SecretProperties> {
        MetadataEditor::add_version(&self.0, name, value, options)
    }
    fn add_secret(
        &self,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
        storage: &SecretStorage,
    ) -> sourceorrery_core::Result<sourceorrery_core::SecretProperties> {
        MetadataEditor::add_secret(&self.0, name, value, options, storage)
    }
    fn unlink_project(&self, id: &str) -> sourceorrery_core::Result<()> {
        MetadataEditor::unlink_project(&self.0, id)
    }
}

/// Open `vault` in `app` as `PERSON`'s.
fn show(app: &mut App, vault: Routed) {
    app.set_session(Session::open(Box::new(AsPerson(vault))).unwrap());
    disguise(app);
}

/// Move the project folders the session has checked under `PERSON`'s home.
/// After every read of them: a refresh reads the real folders again.
fn disguise(app: &mut App) {
    for project in &mut app.session.as_mut().unwrap().projects {
        project.link.path = moved_to(PROJECTS_DIR, &project.link.path);
    }
}

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

/// A vault with a secret in every state the views show, a second version,
/// a deleted secret and a refused read in its audit log; a password and an
/// authenticator; a HashiCorp Vault connection (a second vault file stands
/// in for the server) storing one secret; and two project folders, one of
/// them gone.
#[allow(clippy::too_many_lines)] // one vault with something in every panel
fn sample_vault(dir: &Path) -> Routed {
    let vault = SqliteVault::create(
        &dir.join("development.sorvault"),
        "development",
        CreateVaultOptions::default(),
        no_store(),
    )
    .unwrap()
    .vault;
    let now_unix = u64::try_from(timestamp::now().unix_timestamp()).unwrap();
    vault
        .change_settings(&SettingsChange {
            password: PasswordChange::Set {
                password: SecretBytes::from("orbit lantern copper nine 42"),
                hint: Some("the long one".to_owned()),
                params: Argon2Params::TESTING,
            },
            authenticator: AuthenticatorChange::Verified {
                secret: TotpSecret::generate().unwrap(),
                counter: totp::counter_at(now_unix),
            },
            connections: vec![ConnectionChange::Add {
                settings: ConnectionSettings::HashicorpVault {
                    address: "https://vault.example.com:8200".to_owned(),
                    mount: "secret".to_owned(),
                    namespace: None,
                },
                credentials: None,
            }],
            ..SettingsChange::default()
        })
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

    let projects = dir.join("projects");
    let shop = projects.join("shop");
    std::fs::create_dir_all(&shop).unwrap();
    std::fs::write(
        shop.join("sourceorrery.toml"),
        "[project]\nname = \"shop\"\nvault = \"development\"\n\n\
         [secrets.database-password]\n\n[secrets.stripe-api-key]\n\n\
         [secrets.payments-api-token]\n",
    )
    .unwrap();
    vault.link_project(&shop, "shop").unwrap();
    let gone = projects.join("old-site");
    std::fs::create_dir_all(&gone).unwrap();
    vault.link_project(&gone, "old-site").unwrap();
    std::fs::remove_dir_all(&gone).unwrap();

    let connection = vault.connections().unwrap()[0].id.clone();
    // Apart from the vaults, so the Vaults view does not list it.
    let providers = dir.join("providers");
    std::fs::create_dir_all(&providers).unwrap();
    let provider_path = providers.join("hashicorp.sorvault");
    let created = SqliteVault::create(
        &provider_path,
        "hashicorp",
        CreateVaultOptions::default(),
        no_store(),
    )
    .unwrap();
    let provider_key = created.recovery_key.to_string();
    drop(created);
    let routed = Routed::with_opener(vault, move |_, _, _| {
        let provider = SqliteVault::open(
            &provider_path,
            no_store(),
            &StaticRecoveryKey::new(provider_key.as_str()),
        )?;
        let client: ConnectionClient = Box::new(provider);
        Ok(client)
    });
    routed
        .set_secret_in(
            &SecretStorage::Connection(connection),
            "payments-api-token",
            SecretBytes::from("snapshot"),
            SetSecretOptions::default(),
        )
        .unwrap();
    routed
}

/// A vault whose audit log lost its newest rows: blocked until
/// acknowledged, opened for inspection as the browser opens vaults.
fn blocked_vault(dir: &Path) -> SqliteVault {
    let path = dir.join("production.sorvault");
    let key;
    {
        let created = SqliteVault::create(
            &path,
            "production",
            CreateVaultOptions::default(),
            no_store(),
        )
        .unwrap();
        key = created.recovery_key.to_string();
        let vault = created.vault;
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
        no_store(),
        &StaticRecoveryKey::new(key),
        OpenOptions {
            allow_quarantined: true,
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
                path: moved_to(VAULTS_DIR, &path),
            }
        })
        .collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    entries
}

fn draw(app: &mut App, theme: &Theme, height: u16) -> Buffer {
    draw_at(app, theme, WIDTH, height)
}

fn draw_at(app: &mut App, theme: &Theme, width: u16, height: u16) -> Buffer {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
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
#[allow(clippy::too_many_lines)] // every screen of the browser, in order
fn screens(theme: &Theme) -> Vec<(&'static str, Buffer)> {
    let dir = tempfile::tempdir().unwrap();
    let vault = sample_vault(dir.path());
    let staging = SqliteVault::create(
        &dir.path().join("staging.sorvault"),
        "staging",
        CreateVaultOptions::default(),
        no_store(),
    )
    .unwrap()
    .vault;
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
    show(&mut app, vault);
    out.push(("overview", draw(&mut app, theme, 40)));
    out.push(("overview-80", draw_at(&mut app, theme, 80, 24)));
    app.update(Action::Bottom);
    out.push(("overview-60-end", draw_at(&mut app, theme, 60, 18)));
    app.update(Action::Top);
    app.update(Action::Add);
    for c in "github-app-key".chars() {
        app.update(Action::Input(c));
    }
    app.update(Action::Down);
    app.update(Action::Input(' '));
    out.push(("add-secret", draw(&mut app, theme, 24)));
    app.update(Action::Back);
    app.update(Action::Show(Tab::Projects));
    out.push(("projects", draw(&mut app, theme, 14)));
    app.update(Action::Open);
    out.push(("project-detail", draw(&mut app, theme, 20)));
    app.update(Action::Back);
    app.update(Action::Down);
    app.update(Action::Unlink);
    out.push(("confirm-forget-project", draw(&mut app, theme, 20)));
    app.update(Action::Back);
    app.update(Action::Show(Tab::Secrets));
    app.update(Action::Down);
    out.push(("secrets", draw(&mut app, theme, 18)));
    out.push(("secrets-80", draw_at(&mut app, theme, 80, 24)));
    out.push(("secrets-60", draw_at(&mut app, theme, 60, 18)));
    app.update(Action::Edit);
    app.update(Action::Down);
    app.update(Action::Down);
    out.push(("edit-form", draw(&mut app, theme, 26)));
    out.push(("edit-form-60", draw_at(&mut app, theme, 60, 18)));
    app.update(Action::Back);
    app.update(Action::Toggle);
    out.push(("confirm-disable", draw(&mut app, theme, 22)));
    app.update(Action::Back);
    app.update(Action::NewVersion);
    app.update(Action::Commit);
    out.push(("confirm-new-version", draw(&mut app, theme, 26)));
    app.update(Action::Back);
    app.update(Action::Delete);
    out.push(("confirm-delete", draw(&mut app, theme, 22)));
    app.update(Action::Back);
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
    out.push(("help", draw(&mut app, theme, 46)));
    out.push(("help-80", draw_at(&mut app, theme, 80, 24)));
    app.update(Action::Bottom);
    out.push(("help-60-end", draw_at(&mut app, theme, 60, 18)));
    app.update(Action::Help);
    app.update(Action::Refresh);
    disguise(&mut app);
    out.push(("reloaded", draw(&mut app, theme, 18)));
    app.message = Some(Message::Error(
        "refresh failed; showing what was read before (crypto): audit chain head stale \
         (head was event 41)"
            .into(),
    ));
    out.push(("error", draw(&mut app, theme, 18)));
    app.update(Action::Lock);
    out.push(("locked", draw(&mut app, theme, 14)));

    let mut app = App::new(vaults.clone());
    show(&mut app, Routed::new(staging));
    out.push(("empty", draw(&mut app, theme, 14)));

    let mut app = App::new(vaults.clone());
    show(&mut app, Routed::new(production));
    out.push(("blocked", draw(&mut app, theme, 22)));
    app.update(Action::Show(Tab::Overview));
    out.push(("blocked-overview", draw(&mut app, theme, 36)));

    let mut app = App::new(vaults.clone()).with_read_only(true);
    let dir2 = tempfile::tempdir().unwrap();
    show(&mut app, sample_vault(dir2.path()));
    app.update(Action::Show(Tab::Secrets));
    out.push(("read-only", draw(&mut app, theme, 18)));

    let mut app = App::new(vaults);
    out.push(("no-vault", draw(&mut app, theme, 14)));
    out.extend(init_screens(theme));
    out.extend(setup_screens(theme));
    out
}

// ---------------------------------------------------------------------------
// `init`'s screens and the setup screens, over their fakes
// ---------------------------------------------------------------------------

/// Height the wizards are drawn at: a common terminal.
const WIZARD_HEIGHT: u16 = 30;

macro_rules! drive {
    ($wizard:ty, $control:ty, $action:ident) => {
        fn focus(wizard: &mut $wizard, control: $control) {
            for _ in 0..wizard.controls().len() {
                if wizard.focused() == control {
                    return;
                }
                wizard.update($action::Next);
            }
            panic!("{control:?} is not on this screen");
        }

        fn press(wizard: &mut $wizard, control: $control) {
            focus(wizard, control);
            wizard.update($action::Enter);
        }

        fn type_into(wizard: &mut $wizard, control: $control, text: &str) {
            focus(wizard, control);
            for c in text.chars() {
                wizard.update($action::Input(c));
            }
        }
    };
}

fn init_screens(theme: &Theme) -> Vec<(&'static str, Buffer)> {
    use crate::ui::init::fake::Fake;
    use crate::ui::init::view;
    use crate::ui::init::wizard::{Action, Control, Start, Wizard};

    drive!(Wizard<Fake>, Control, Action);
    let draw = |wizard: &Wizard<Fake>| {
        let mut terminal = Terminal::new(TestBackend::new(WIDTH, WIZARD_HEIGHT)).unwrap();
        terminal
            .draw(|frame| view::draw(frame, wizard, theme))
            .unwrap();
        terminal.backend().buffer().clone()
    };
    let start = || Start {
        project: "shop".to_owned(),
        manifest_path: "sourceorrery.toml".to_owned(),
        existing: None,
    };
    let mut out = Vec::new();
    let mut fake = Fake::one_vault();
    fake.vaults.push("staging".to_owned());
    let mut wizard = Wizard::new(fake, start());
    wizard.begin(None).unwrap();
    out.push(("init-vault", draw(&wizard)));

    let mut wizard = Wizard::new(Fake::one_vault(), start());
    wizard.begin(None).unwrap();
    out.push(("init-project", draw(&wizard)));
    press(&mut wizard, Control::Continue);
    focus(&mut wizard, Control::Row(1));
    wizard.update(Action::Input(' '));
    out.push(("init-secrets", draw(&wizard)));
    press(&mut wizard, Control::Continue);
    out.push(("init-add-new", draw(&wizard)));
    press(&mut wizard, Control::AddSecret);
    type_into(&mut wizard, Control::Name, "stripe-api-key");
    type_into(&mut wizard, Control::Value, "snapshot-value");
    type_into(&mut wizard, Control::Confirm, "snapshot-value");
    type_into(&mut wizard, Control::Description, "Card payments");
    out.push(("init-new-secret", draw(&wizard)));
    press(&mut wizard, Control::Store);
    press(&mut wizard, Control::NoMore);
    out.push(("init-review", draw(&wizard)));
    press(&mut wizard, Control::Write);
    out.push(("init-done", draw(&wizard)));
    out
}

fn setup_screens(theme: &Theme) -> Vec<(&'static str, Buffer)> {
    use crate::ui::setup::fake::{self, Fake};
    use crate::ui::setup::view;
    use crate::ui::setup::wizard::{Action, Control, Field, Wizard};

    drive!(Wizard<Fake>, Control, Action);
    let draw = |wizard: &Wizard<Fake>, height: u16| {
        let mut terminal = Terminal::new(TestBackend::new(WIDTH, height)).unwrap();
        terminal
            .draw(|frame| view::draw(frame, wizard, theme))
            .unwrap();
        terminal.backend().buffer().clone()
    };
    let wizard_on = |fake: Fake, name: Option<&str>| {
        let mut wizard = Wizard::new(fake);
        wizard.params = Argon2Params::TESTING;
        wizard.begin(name).unwrap();
        wizard
    };
    let mut out = Vec::new();

    let mut wizard = wizard_on(Fake::default(), None);
    out.push(("setup-first-vault", draw(&wizard, WIZARD_HEIGHT)));
    let both = ViewCheck {
        password: true,
        authenticator: true,
    };
    let wizard_with = wizard_on(Fake::one_vault(both), None);
    out.push(("setup-start", draw(&wizard_with, WIZARD_HEIGHT)));

    press(&mut wizard, Control::CreateNew);
    type_into(&mut wizard, Control::Name, "development");
    out.push(("setup-name", draw(&wizard, WIZARD_HEIGHT)));
    press(&mut wizard, Control::Continue);
    wizard.update(Action::Input(' '));
    focus(&mut wizard, Control::AskCode);
    wizard.update(Action::Input(' '));
    out.push(("setup-view-check", draw(&wizard, WIZARD_HEIGHT)));
    press(&mut wizard, Control::Continue);
    type_into(&mut wizard, Control::Password, "Tq8#mv2!Lp9&zR4wXe7");
    type_into(&mut wizard, Control::Confirm, "Tq8#mv2!Lp9&zR4wXe7");
    type_into(&mut wizard, Control::Hint, "the long one");
    out.push(("setup-password", draw(&wizard, WIZARD_HEIGHT)));
    press(&mut wizard, Control::Continue);
    out.push(("setup-authenticator-80x24", {
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| view::draw(frame, &wizard, theme))
            .unwrap();
        terminal.backend().buffer().clone()
    }));
    out.push(("setup-authenticator", draw(&wizard, WIZARD_HEIGHT)));
    let (key, _) = wizard.enrolment().unwrap();
    let now = u64::try_from(timestamp::now().unix_timestamp()).unwrap();
    let code = TotpSecret::from_base32(&key).unwrap().code_at(now);
    type_into(&mut wizard, Control::Code, &code);
    press(&mut wizard, Control::Verify);
    press(&mut wizard, Control::Continue);
    out.push(("setup-recovery-key", draw(&wizard, WIZARD_HEIGHT)));
    press(&mut wizard, Control::RecoveryWritten);
    press(&mut wizard, Control::Continue);
    focus(&mut wizard, Control::Provider(1));
    wizard.update(Action::Input(' '));
    out.push(("setup-storage", draw(&wizard, WIZARD_HEIGHT)));
    press(&mut wizard, Control::Continue);
    let i = wizard
        .forms
        .iter()
        .position(|f| f.provider == sourceorrery_core::Provider::AwsSecretsManager)
        .unwrap();
    type_into(&mut wizard, Control::Form(i, Field::Location), "eu-west-1");
    focus(&mut wizard, Control::Form(i, Field::Source));
    wizard.update(Action::Input(' '));
    type_into(&mut wizard, Control::Form(i, Field::FirstId), "AKIAEXAMPLE");
    type_into(
        &mut wizard,
        Control::Form(i, Field::Secret),
        "snapshot-secret",
    );
    press(&mut wizard, Control::Form(i, Field::Test));
    out.push(("setup-connections", draw(&wizard, WIZARD_HEIGHT)));
    press(&mut wizard, Control::Continue);
    out.push(("setup-review", draw(&wizard, WIZARD_HEIGHT)));
    press(&mut wizard, Control::Commit);
    out.push(("setup-done", draw(&wizard, WIZARD_HEIGHT)));

    // Changing a vault: its view check first, then what it has.
    let mut wizard = wizard_on(Fake::one_vault(both), Some("dev"));
    out.push(("setup-unlock", draw(&wizard, WIZARD_HEIGHT)));
    type_into(&mut wizard, Control::UnlockPassword, fake::PASSWORD);
    type_into(&mut wizard, Control::UnlockCode, fake::CODE);
    press(&mut wizard, Control::OpenVault);
    out.push(("setup-change", draw(&wizard, WIZARD_HEIGHT)));
    let mut locked = Fake::one_vault(both);
    locked.locked = Some("dev".to_owned());
    let wizard = wizard_on(locked, Some("dev"));
    out.push(("setup-recovery-key-open", draw(&wizard, WIZARD_HEIGHT)));
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
