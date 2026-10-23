//! Drawing the wizard. A function of its state: nothing here reads a
//! vault, and hidden fields are drawn as dots from their length alone.
//!
//! The look is the browser's: the site's header bar, an uppercase step
//! rail, a title and a few lines of explanation per step, the controls as a
//! form (the focused one on the selection colour with the accent bar),
//! messages as callouts, a footer of keys.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Margin};
use ratatui::style::Style;
use ratatui::symbols::border;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use super::backend::Backend;
use super::wizard::{Control, Message, RECOVERY_CODES, Step, Wizard};
use crate::output::sanitize;
use crate::strength::{Estimate, Score};
use crate::ui::theme::{Callout, Theme};

/// Width of a form's label column.
const LABEL_WIDTH: usize = 22;

/// Cells in the strength meter.
const METER: usize = 10;

pub fn draw<B: Backend>(frame: &mut Frame<'_>, wizard: &Wizard<B>, theme: &Theme) {
    frame.render_widget(Block::new().style(theme.screen), frame.area());
    let message_height = u16::from(wizard.message.is_some()) * 2;
    let [header, rail, _, body, message, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(message_height),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    frame.render_widget(header_bar(wizard, theme), header);
    frame.render_widget(rail_line(wizard, theme), rail);

    let lines = body_lines(wizard, theme);
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }),
        body.inner(Margin::new(2, 0)),
    );
    if let Some(text) = &wizard.message {
        frame.render_widget(callout(text, theme), message);
    }
    frame.render_widget(footer_line(wizard, theme), footer);
}

fn header_bar<B: Backend>(wizard: &Wizard<B>, theme: &Theme) -> Paragraph<'static> {
    let mut spans = vec![
        Span::styled(" SourceOrrery ", theme.title),
        Span::styled(" setup", theme.muted),
    ];
    if let Some(vault) = &wizard.vault {
        spans.push(Span::styled("  ·  vault ", theme.muted));
        spans.push(Span::styled(
            sanitize(&vault.name).into_owned(),
            theme.vault,
        ));
        if vault.keyring {
            spans.push(Span::styled("  ·  OS keyring + passphrase", theme.muted));
        } else {
            spans.push(Span::styled("  ·  passphrase", theme.muted));
        }
    }
    Paragraph::new(Line::from(spans)).style(theme.bar)
}

fn rail_line<B: Backend>(wizard: &Wizard<B>, theme: &Theme) -> Line<'static> {
    let mut spans = vec![Span::raw(" ")];
    for (i, step) in Step::RAIL.into_iter().enumerate() {
        let (mark, style) = if step == wizard.step {
            ("▶", theme.tab)
        } else if wizard.step.is_past(step) {
            ("✓", theme.muted)
        } else {
            (" ", Style::new())
        };
        spans.push(Span::styled(format!("{mark} {} ", i + 1), theme.muted));
        spans.push(Span::styled(step.title(), style));
        spans.push(Span::raw("    "));
    }
    Line::from(spans)
}

fn footer_line<B: Backend>(wizard: &Wizard<B>, theme: &Theme) -> Line<'static> {
    let pairs: &[(&str, &str)] = match wizard.step {
        Step::Welcome => &[("Enter", "begin"), ("Esc q", "leave")],
        Step::Done => &[("Enter Esc q", "leave")],
        _ => &[
            ("Tab ↓ ↑", "move"),
            ("Space", "tick / choose"),
            ("Enter", "next / press"),
            ("Esc", "dismiss"),
            ("Ctrl-C", "leave"),
        ],
    };
    let mut spans = vec![Span::raw(" ")];
    for (keys, what) in pairs {
        spans.push(Span::styled((*keys).to_owned(), theme.key));
        spans.push(Span::styled(format!(" {what}   "), theme.muted));
    }
    spans.push(Span::styled(
        "values typed here go to the vault and nowhere else",
        theme.muted,
    ));
    Line::from(spans).style(theme.bar)
}

fn callout_block(style: &Callout) -> Block<'static> {
    Block::new()
        .borders(Borders::LEFT)
        .border_set(border::Set {
            vertical_left: "▌",
            ..border::PLAIN
        })
        .border_style(style.bar)
        .style(style.panel)
}

fn callout(message: &Message, theme: &Theme) -> Paragraph<'static> {
    let (style, title, text) = match message {
        Message::Info(text) => (theme.info, "NOTE", text),
        Message::Error(text) => (theme.error, "ERROR", text),
    };
    Paragraph::new(Line::from(vec![
        Span::styled(format!(" {title}  "), style.title),
        Span::raw(sanitize(text).into_owned()),
    ]))
    .wrap(Wrap { trim: false })
    .block(callout_block(&style))
}

// ---------------------------------------------------------------------------
// The body of each step
// ---------------------------------------------------------------------------

fn body_lines<B: Backend>(wizard: &Wizard<B>, theme: &Theme) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(Span::styled(
            wizard.step.title().to_uppercase(),
            theme.label,
        )),
        Line::from(""),
    ];
    match wizard.step {
        Step::Welcome => welcome(&mut lines, theme),
        Step::Vault => vault(wizard, &mut lines, theme),
        Step::Secret => secret(wizard, &mut lines, theme),
        Step::Recovery => recovery(wizard, &mut lines, theme),
        Step::SecondFactor => second_factor(wizard, &mut lines, theme),
        Step::Guard => guard(wizard, &mut lines, theme),
        Step::Project => project(wizard, &mut lines, theme),
        Step::Done => done(wizard, &mut lines, theme),
    }
    lines.push(Line::from(""));
    for control in wizard.controls() {
        lines.push(control_line(wizard, control, theme));
        if let Some(extra) = control_extra(wizard, control, theme) {
            lines.extend(extra);
        }
    }
    lines
}

fn prose(lines: &mut Vec<Line<'static>>, theme: &Theme, text: &[&str]) {
    for t in text {
        lines.push(Line::from(Span::styled((*t).to_owned(), theme.muted)));
    }
}

fn welcome(lines: &mut Vec<Line<'static>>, theme: &Theme) {
    lines.push(Line::from(
        "From the first vault to the first run, in six short steps:",
    ));
    lines.push(Line::from(""));
    for (i, (what, why)) in [
        (
            "Vault",
            "an encrypted file for this machine, with a strong passphrase",
        ),
        (
            "First secret",
            "a database password, typed with a strength meter or generated",
        ),
        (
            "Recovery",
            "codes that unlock the vault if the passphrase is lost, and a hint",
        ),
        (
            "Second factor",
            "an authenticator app, enrolled from a QR code",
        ),
        (
            "Reveal guard",
            "what showing a value or exporting the vault must ask for",
        ),
        (
            "Project",
            "the manifest that replaces .env, checked, and the run command",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        lines.push(Line::from(vec![
            Span::styled(format!("  {}  ", i + 1), theme.key),
            Span::raw(format!("{what:<14}")),
            Span::styled(why, theme.muted),
        ]));
    }
    lines.push(Line::from(""));
    prose(
        lines,
        theme,
        &[
            "Nothing you type as a secret is echoed or kept by this screen; it goes to the vault.",
            "Every step can be redone later with a command; the summary at the end names them.",
        ],
    );
}

fn vault<B: Backend>(wizard: &Wizard<B>, lines: &mut Vec<Line<'static>>, theme: &Theme) {
    prose(
        lines,
        theme,
        &[
            "A vault is one encrypted file in your home directory. Its passphrase derives the",
            "key, so it must be strong and it cannot be recovered: the next step gives you",
            "recovery codes for the day it is forgotten.",
        ],
    );
    if wizard.vault_exists() {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("A vault named ", theme.caution),
            Span::styled(sanitize(&wizard.vault_name).into_owned(), theme.vault),
            Span::styled(
                " exists already: continue to use it (it may ask for its passphrase), or type \
                 another name.",
                theme.caution,
            ),
        ]));
    } else if let Some(store) = wizard.keyring_store {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled(format!("{store} "), theme.vault),
            Span::styled(
                "can hold a second key on this machine, so day-to-day use does not prompt; \
                 the passphrase stays the way in everywhere else.",
                theme.muted,
            ),
        ]));
    }
}

fn secret<B: Backend>(wizard: &Wizard<B>, lines: &mut Vec<Line<'static>>, theme: &Theme) {
    prose(
        lines,
        theme,
        &[
            "The first secret is your database password. A database password cannot be weak:",
            "type one and watch the meter until it reads \"good\", or let the wizard generate",
            "one and store it without ever showing it (read it later with",
        ],
    );
    lines.push(Line::from(vec![
        Span::styled(
            format!(
                " sourceorrery secret get {} --reveal ",
                sanitize(&wizard.secret_name)
            ),
            theme.code,
        ),
        Span::styled(" or hand it to your program with ", theme.muted),
        Span::styled(" sourceorrery run ", theme.code),
        Span::styled(").", theme.muted),
    ]));
}

fn recovery<B: Backend>(wizard: &Wizard<B>, lines: &mut Vec<Line<'static>>, theme: &Theme) {
    prose(
        lines,
        theme,
        &[
            "Nothing can recover a lost passphrase: the key is derived from it. What can be",
            "done is to have other ways in, made now. Each recovery code unlocks the vault once",
            "typed at the passphrase prompt (case and hyphens do not matter); together they",
            "are a second passphrase, so keep them apart from this machine.",
        ],
    );
    if let Some(codes) = &wizard.codes {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("YOUR {} RECOVERY CODES  ·  shown once", codes.len()),
            theme.label,
        )));
        for code in codes {
            lines.push(Line::from(vec![
                Span::raw("    "),
                Span::styled(format!(" {} ", code.as_str()), theme.code),
            ]));
        }
    } else {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!(
                "The hint is optional: a reminder shown at the prompt, stored in clear in the \
                 vault file. {RECOVERY_CODES} codes are issued; run `vault recovery codes` to replace them."
            ),
            theme.muted,
        )));
    }
}

fn second_factor<B: Backend>(wizard: &Wizard<B>, lines: &mut Vec<Line<'static>>, theme: &Theme) {
    let Some(enrolment) = &wizard.enrolment else {
        prose(
            lines,
            theme,
            &[
                "An authenticator app (any that speaks TOTP) can be asked for a six-digit code",
                "before a value is shown or the vault exported. The key is sealed inside the vault,",
                "so it travels with the file and never through a server.",
            ],
        );
        return;
    };
    // The code needs the rows: the explanation makes way for it.
    lines.pop();
    lines.push(Line::from(Span::styled(
        "Scan this with the authenticator app, then type the code it shows.",
        theme.caution,
    )));
    {
        match crate::qr::render(&enrolment.uri) {
            Ok(rows) => {
                for row in rows {
                    lines.push(Line::from(vec![
                        Span::raw("    "),
                        Span::styled(row, theme.qr),
                    ]));
                }
            }
            Err(err) => lines.push(Line::from(Span::styled(
                format!("cannot draw the QR code: {err}"),
                theme.error.title,
            ))),
        }
        lines.push(Line::from(vec![
            Span::styled("Cannot scan? Enter this key by hand:  ", theme.muted),
            Span::styled(format!(" {} ", *enrolment.key), theme.code),
        ]));
    }
}

fn guard<B: Backend>(wizard: &Wizard<B>, lines: &mut Vec<Line<'static>>, theme: &Theme) {
    prose(
        lines,
        theme,
        &[
            "Unlocking the vault lets your program read its secrets. The reveal guard is a",
            "second check for the moments a person asks to see one: `secret get --reveal`,",
            "`backup`, and every change to how the vault unlocks. It never applies to `run`,",
            "`check` or the SDKs, so your application keeps starting without a prompt while",
            "an API key read out at the keyboard, by you or by an agent, asks for more.",
        ],
    );
    lines.push(Line::from(""));
    let what = match wizard.second_factor {
        Some(true) => "The second factor is enrolled, so a code can be asked for too.",
        _ => "No second factor was enrolled, so only the passphrase can be asked for.",
    };
    lines.push(Line::from(Span::styled(what, theme.muted)));
}

fn project<B: Backend>(wizard: &Wizard<B>, lines: &mut Vec<Line<'static>>, theme: &Theme) {
    prose(
        lines,
        theme,
        &[
            "The manifest, sourceorrery.toml, declares which secrets your project needs and",
            "which vault holds them. It never holds a value, so it is safe to commit.",
        ],
    );
    lines.push(Line::from(""));
    let Some(project) = &wizard.project else {
        lines.push(Line::from(Span::styled(
            "The manifest could not be written; press Finish to try again.",
            theme.caution,
        )));
        return;
    };
    lines.push(Line::from(vec![
        Span::styled(
            if project.written {
                "Wrote "
            } else {
                "Kept the existing "
            },
            theme.muted,
        ),
        Span::styled(format!(" {} ", project.manifest.display()), theme.code),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("{:<24}{:<28}{}", "SECRET", "ENVIRONMENT VARIABLE", "STATUS"),
        theme.label,
    )));
    for row in &project.rows {
        let style = if row.status == "ok" {
            theme.status("enabled")
        } else {
            theme.status("expired")
        };
        lines.push(Line::from(vec![
            Span::raw(format!(
                "{:<24}{:<28}",
                sanitize(&row.name),
                sanitize(&row.env)
            )),
            Span::styled(sanitize(&row.status).into_owned(), style),
        ]));
    }
}

fn done<B: Backend>(wizard: &Wizard<B>, lines: &mut Vec<Line<'static>>, theme: &Theme) {
    let vault = wizard
        .vault
        .as_ref()
        .map_or("development", |v| v.name.as_str());
    let vault = sanitize(vault).into_owned();
    let secret = sanitize(wizard.stored.as_deref().unwrap_or("database-password")).into_owned();
    let mut row = |label: &str, value: String| {
        lines.push(Line::from(vec![
            Span::styled(format!("{label:<LABEL_WIDTH$}"), theme.muted),
            Span::raw(value),
        ]));
    };
    row(
        "vault",
        wizard.vault.as_ref().map_or_else(
            || "none".to_owned(),
            |v| {
                format!(
                    "{}  ({})",
                    v.name,
                    if v.keyring {
                        "OS keyring and passphrase"
                    } else {
                        "passphrase"
                    }
                )
            },
        ),
    );
    row(
        "file",
        wizard
            .vault
            .as_ref()
            .map_or_else(|| "none".to_owned(), |v| v.path.clone()),
    );
    row("first secret", secret.clone());
    row(
        "recovery",
        match wizard.recovery {
            Some(r) => format!(
                "{} recovery code{}{}",
                r.codes,
                if r.codes == 1 { "" } else { "s" },
                if r.hint { ", a passphrase hint" } else { "" }
            ),
            None => "none".to_owned(),
        },
    );
    row(
        "second factor",
        match wizard.second_factor {
            Some(true) => "enrolled and verified".to_owned(),
            _ => "not enrolled  (sourceorrery vault 2fa enable)".to_owned(),
        },
    );
    row(
        "reveal guard",
        wizard
            .guard
            .map_or_else(|| "unchanged".to_owned(), |g| g.describe().to_owned()),
    );
    row(
        "manifest",
        wizard.project.as_ref().map_or_else(
            || "not written  (sourceorrery init)".to_owned(),
            |p| p.manifest.display().to_string(),
        ),
    );
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("NEXT", theme.label)));
    let commands: [(&str, String); 4] = [
        (
            "start your program with the secret in its environment",
            "sourceorrery run -- <your command>".to_owned(),
        ),
        (
            "see a value (the guard asks for what you chose)",
            format!("sourceorrery secret get {secret} --vault {vault} --reveal"),
        ),
        (
            "add a secret, browse, or check before a deploy",
            format!(
                "sourceorrery secret set NAME --vault {vault}   ·   sourceorrery ui   ·   sourceorrery check"
            ),
        ),
        (
            "headless (WSL, Docker, CI): the passphrase from a file",
            "SOURCEORRERY_PASSPHRASE_FILE=/run/secrets/vault sourceorrery run -- <command>"
                .to_owned(),
        ),
    ];
    for (what, command) in commands {
        lines.push(Line::from(Span::styled(what.to_owned(), theme.muted)));
        lines.push(Line::from(vec![
            Span::raw("    "),
            Span::styled(format!(" {command} "), theme.code),
        ]));
    }
}

// ---------------------------------------------------------------------------
// Controls
// ---------------------------------------------------------------------------

fn label(control: Control) -> &'static str {
    match control {
        Control::VaultName => "Vault name",
        Control::Keyring => "Also unlock with",
        Control::Passphrase => "Passphrase",
        Control::PassphraseConfirm | Control::SecretConfirm => "Confirm",
        Control::SecretName => "Secret name",
        Control::SecretValue => "Value",
        Control::Hint => "Passphrase hint",
        Control::Code => "Code from the app",
        Control::GuardChoice => "Ask for",
        _ => "",
    }
}

fn button_text<B: Backend>(wizard: &Wizard<B>, control: Control) -> &'static str {
    match control {
        Control::Start => "Begin",
        Control::GeneratePassphrase if wizard.generated_passphrase.is_some() => "Type one instead",
        Control::GeneratePassphrase => "Generate a passphrase for me",
        Control::CreateVault if wizard.vault_exists() => "Use this vault",
        Control::CreateVault => "Create the vault",
        Control::GenerateSecret if wizard.secret_generated => "Type one instead",
        Control::GenerateSecret => "Generate a strong value for me",
        Control::StoreSecret => "Store the secret",
        Control::ShowCodes => "Show my recovery codes",
        Control::FinishRecovery => "Continue",
        Control::Enrol => "Enrol an authenticator app",
        Control::Verify => "Verify the code",
        Control::SkipSecondFactor => "Skip",
        Control::SetGuard => "Set the guard",
        Control::Finish => "Finish",
        Control::Exit => "Leave",
        _ => "",
    }
}

fn control_line<B: Backend>(wizard: &Wizard<B>, control: Control, theme: &Theme) -> Line<'static> {
    let focused = wizard.focused() == control;
    let marker = Span::styled(if focused { "▌ " } else { "  " }, theme.marker);
    let mut spans = vec![marker];
    if control.is_text() {
        spans.push(Span::styled(
            format!("{:<LABEL_WIDTH$}", label(control)),
            theme.muted,
        ));
        let text = if control.is_hidden() {
            "•".repeat(wizard.hidden_len(control))
        } else {
            match control {
                Control::VaultName => sanitize(&wizard.vault_name).into_owned(),
                Control::SecretName => sanitize(&wizard.secret_name).into_owned(),
                Control::Hint => sanitize(&wizard.hint).into_owned(),
                Control::Code => wizard.code.clone(),
                _ => String::new(),
            }
        };
        spans.push(Span::raw(text));
        if focused {
            spans.push(Span::styled("▌", theme.key));
        }
        match wizard.confirm_state(control) {
            Some(true) => spans.push(Span::styled("   matches", theme.status("enabled"))),
            Some(false) => spans.push(Span::styled("   does not match", theme.status("expired"))),
            None => {}
        }
    } else {
        match control {
            Control::Keyring => {
                spans.push(Span::styled(
                    format!("{:<LABEL_WIDTH$}", label(control)),
                    theme.muted,
                ));
                spans.push(Span::raw(format!(
                    "[{}] {}",
                    if wizard.keyring { "x" } else { " " },
                    wizard.keyring_store.unwrap_or("the OS credential store")
                )));
            }
            Control::PassphraseWritten => spans.push(Span::raw(format!(
                "[{}] I have written the passphrase down or stored it in a password manager",
                if wizard.passphrase_written { "x" } else { " " }
            ))),
            Control::CodesWritten => spans.push(Span::raw(format!(
                "[{}] I have written these codes down and will keep them apart from this machine",
                if wizard.codes_written { "x" } else { " " }
            ))),
            Control::GuardChoice => {
                spans.push(Span::styled(
                    format!("{:<LABEL_WIDTH$}", label(control)),
                    theme.muted,
                ));
                let options = wizard.guard_options();
                let (_, chosen) = options[wizard.guard_choice.min(options.len() - 1)];
                spans.push(Span::raw(format!("(•) {chosen}")));
                spans.push(Span::styled("   Space for the next choice", theme.muted));
            }
            _ => {
                spans.push(Span::styled(
                    format!("[ {} ]", button_text(wizard, control)),
                    theme.key,
                ));
            }
        }
    }
    let line = Line::from(spans);
    if focused {
        line.style(theme.selected)
    } else {
        line
    }
}

/// Lines drawn under a control: the strength meter, the generated
/// passphrase, the choices not chosen.
fn control_extra<B: Backend>(
    wizard: &Wizard<B>,
    control: Control,
    theme: &Theme,
) -> Option<Vec<Line<'static>>> {
    match control {
        Control::Passphrase => Some(meter_lines(wizard.passphrase_estimate.as_ref(), theme)),
        Control::SecretValue => Some(meter_lines(wizard.secret_estimate.as_ref(), theme)),
        Control::GeneratePassphrase => {
            let generated = wizard.generated_passphrase.as_ref()?;
            Some(vec![
                Line::from(vec![
                    Span::raw(format!("  {:<LABEL_WIDTH$}", "Your passphrase")),
                    Span::styled(format!(" {} ", generated.as_str()), theme.code),
                    Span::styled("   shown once", theme.caution),
                ]),
                Line::from(Span::styled(
                    format!(
                        "  {:<LABEL_WIDTH$}{}",
                        "", "letters, digits and symbols from the OS random source; about 125 bits"
                    ),
                    theme.muted,
                )),
            ])
        }
        Control::GenerateSecret if wizard.secret_generated => Some(vec![Line::from(Span::styled(
            format!(
                "  {:<LABEL_WIDTH$}a 24-character value will be generated and stored; it is never shown here",
                ""
            ),
            theme.muted,
        ))]),
        Control::GuardChoice => {
            let options = wizard.guard_options();
            Some(
                options
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != wizard.guard_choice)
                    .map(|(_, (_, text))| {
                        Line::from(Span::styled(
                            format!("  {:<LABEL_WIDTH$}( ) {text}", ""),
                            theme.muted,
                        ))
                    })
                    .collect(),
            )
        }
        _ => None,
    }
}

fn meter_lines(estimate: Option<&Estimate>, theme: &Theme) -> Vec<Line<'static>> {
    let Some(estimate) = estimate else {
        return vec![Line::from(Span::styled(
            format!(
                "  {:<LABEL_WIDTH$}{}  needs \"{}\": a long phrase of unrelated words, or letters, digits and symbols",
                "strength",
                "░".repeat(METER),
                Score::REQUIRED.label()
            ),
            theme.muted,
        ))];
    };
    let filled = (estimate.score as usize + 1) * METER / 5;
    let style = match estimate.score {
        Score::Guessable | Score::Weak => theme.status("expired"),
        Score::Fair => theme.caution,
        Score::Good | Score::Strong => theme.status("enabled"),
    };
    let mut lines = vec![Line::from(vec![
        Span::styled(format!("  {:<LABEL_WIDTH$}", "strength"), theme.muted),
        Span::styled("█".repeat(filled), style),
        Span::styled("░".repeat(METER - filled), theme.muted),
        Span::styled(
            format!(
                "  {}  (about {} bits)",
                estimate.score.label(),
                estimate.bits
            ),
            style,
        ),
        Span::styled(
            if estimate.acceptable() {
                ""
            } else {
                "  not yet enough"
            },
            theme.muted,
        ),
    ])];
    if !estimate.warnings.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("  {:<LABEL_WIDTH$}{}", "", estimate.warnings.join("; ")),
            theme.muted,
        )));
    }
    lines
}
