//! `sourceorrery setup`: the guided first run. On a terminal, the screens
//! (`ui::setup`, Cargo feature `ui`); anywhere else, or with `--guide`, the
//! same six steps as commands on stderr, so a script, a pipe or a minimal
//! build gets the plan rather than a refusal.

use crate::cli::SetupArgs;
use crate::context::Ctx;
use crate::output;

/// The vault the steps name when `--vault` names none.
const DEFAULT_VAULT: &str = "development";

pub fn run(ctx: &Ctx, args: &SetupArgs) -> anyhow::Result<()> {
    #[cfg(feature = "ui")]
    if !args.guide && !ctx.json() && {
        use std::io::IsTerminal as _;
        std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
    } {
        return crate::ui::setup::run(ctx, args);
    }
    guide(ctx, args)
}

/// One step of the guide.
#[derive(serde::Serialize)]
struct GuideStep {
    step: usize,
    title: &'static str,
    what: &'static str,
    commands: Vec<String>,
}

fn steps(vault: &str, secret: &str) -> Vec<GuideStep> {
    let step = |step, title, what, commands: Vec<String>| GuideStep {
        step,
        title,
        what,
        commands,
    };
    vec![
        step(
            1,
            "Vault",
            "an encrypted file for this machine, unlocked by a strong passphrase; the OS \
             credential store can hold a second key so day-to-day use does not prompt",
            vec![
                format!("sourceorrery vault create {vault} --protector passphrase"),
                "sourceorrery vault passphrase generate      # a passphrase to type, if you want one made".to_owned(),
                format!("sourceorrery vault protector add --kind os-keyring --vault {vault}   # optional"),
            ],
        ),
        step(
            2,
            "First secret",
            "the database password, typed at a hidden prompt (it must rate \"good\") or generated \
             and piped in; never a command-line argument",
            vec![
                format!("sourceorrery secret set {secret} --vault {vault}"),
                format!(
                    "sourceorrery vault passphrase generate --length 24 | sourceorrery secret set {secret} --vault {vault}"
                ),
            ],
        ),
        step(
            3,
            "Recovery",
            "codes that unlock the vault in place of the passphrase, shown once; an optional \
             hint shown at the prompt",
            vec![
                format!("sourceorrery vault recovery codes --vault {vault}"),
                format!("sourceorrery vault passphrase hint \"the usual phrase\" --vault {vault}"),
            ],
        ),
        step(
            4,
            "Second factor",
            "an authenticator app enrolled from a QR code and proven with one code",
            vec![format!("sourceorrery vault 2fa enable --vault {vault}")],
        ),
        step(
            5,
            "Reveal guard",
            "what `secret get --reveal` and `backup` must ask for again: the passphrase, a \
             code, both or nothing; `run`, `check` and the SDKs are untouched",
            vec![format!(
                "sourceorrery vault guard --reveal passphrase,second-factor --vault {vault}"
            )],
        ),
        step(
            6,
            "Project",
            "the manifest that replaces .env, checked, and the command that starts your \
             program with the secret in its environment",
            vec![
                format!("sourceorrery init --vault-name {vault}"),
                "sourceorrery check".to_owned(),
                "sourceorrery run -- <your command>".to_owned(),
            ],
        ),
    ]
}

/// The steps as commands, on stderr (or as JSON on stdout).
pub fn guide(ctx: &Ctx, args: &SetupArgs) -> anyhow::Result<()> {
    let vault = ctx.vault_flag.as_deref().unwrap_or(DEFAULT_VAULT);
    let steps = steps(vault, &args.secret);
    if ctx.json() {
        return output::json(&serde_json::json!({ "vault": vault, "steps": steps }));
    }
    eprintln!("SourceOrrery setup: from the first vault to the first run, in six steps.");
    if cfg!(feature = "ui") && !args.guide {
        eprintln!(
            "(The guided screens need an interactive terminal; these are the same steps as commands.)"
        );
    }
    for step in steps {
        eprintln!();
        eprintln!("{}. {}", step.step, step.title);
        eprintln!("   {}", step.what);
        for command in &step.commands {
            eprintln!("     {command}");
        }
    }
    eprintln!();
    eprintln!("Details: docs/getting-started.md and `sourceorrery <command> --help`.");
    Ok(())
}
