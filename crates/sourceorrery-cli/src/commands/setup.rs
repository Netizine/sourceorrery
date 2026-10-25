//! `sourceorrery setup`: on a terminal, the setup screens (`ui::setup`),
//! which create a vault or change one. With `--guide`, without a terminal
//! or as JSON, the one `vault create` command that does the same without
//! them, with its flags, on stderr (or as JSON on stdout).

use crate::cli::SetupArgs;
use crate::context::Ctx;
use crate::output;

/// The vault the guide names when `--vault` names none.
const DEFAULT_VAULT: &str = "development";

pub fn run(ctx: &Ctx, args: &SetupArgs) -> anyhow::Result<()> {
    #[cfg(feature = "ui")]
    if !args.guide && !ctx.json() && crate::commands::on_a_terminal() {
        return crate::ui::setup::run(ctx, ctx.vault_flag.as_deref(), args.theme);
    }
    #[cfg(not(feature = "ui"))]
    let _ = args;
    guide(ctx)
}

/// One optional flag set of the command.
#[derive(serde::Serialize)]
struct GuideOption {
    flags: &'static str,
    what: &'static str,
}

fn options() -> Vec<GuideOption> {
    let option = |flags, what| GuideOption { flags, what };
    vec![
        option(
            "--password-file FILE",
            "the view check's password, asked before anyone views the vault or reveals a value; \
             `run`, `check`, `init` and the SDKs never ask it",
        ),
        option(
            "--hashicorp-vault ADDRESS [--hashicorp-vault-mount MOUNT] \
             [--hashicorp-vault-namespace NAMESPACE] [--hashicorp-vault-token-file FILE]",
            "a connection to a HashiCorp Vault server",
        ),
        option(
            "--aws-secrets-manager REGION [--aws-secrets-manager-prefix PREFIX] \
             [--aws-access-key-id ID --aws-secret-access-key-file FILE]",
            "a connection to AWS Secrets Manager",
        ),
        option(
            "--azure-key-vault URL [--azure-tenant-id ID --azure-client-id ID \
             --azure-client-secret-file FILE]",
            "a connection to an Azure Key Vault",
        ),
    ]
}

/// The command, the flags it may take, and what comes after it, on stderr
/// (or as JSON on stdout).
pub fn guide(ctx: &Ctx) -> anyhow::Result<()> {
    let vault = ctx.vault_flag.as_deref().unwrap_or(DEFAULT_VAULT);
    let command =
        format!("sourceorrery vault create {vault} --recovery-key-out {vault}.recovery-key");
    let then = [
        format!("sourceorrery secret set NAME --vault {vault}"),
        format!("sourceorrery init --vault {vault}"),
        "sourceorrery run -- <your command>".to_owned(),
    ];
    let options = options();
    if ctx.json() {
        return output::json(&serde_json::json!({
            "vault": vault,
            "command": command,
            "options": options,
            "then": then,
        }));
    }
    eprintln!("SourceOrrery setup without the screens: one command creates the vault, with");
    eprintln!("its view check's password and its connections, at once.");
    eprintln!();
    eprintln!("  {command}");
    eprintln!();
    eprintln!("  The recovery key goes to that file, readable by you only (without the flag it");
    eprintln!("  is printed once): it opens the vault wherever this machine's key cannot.");
    eprintln!();
    eprintln!("Optional, on the same command:");
    for option in &options {
        eprintln!("  {}", option.flags);
        eprintln!("      {}", option.what);
    }
    eprintln!("  A connection uses this machine's sign-in for the provider, or the credentials");
    eprintln!("  in the files named, sealed in the vault. A secret value is never a flag.");
    eprintln!();
    eprintln!("Then:");
    for command in &then {
        eprintln!("  {command}");
    }
    eprintln!();
    eprintln!("In a terminal, `sourceorrery setup` does the same on screens, and enrols an");
    eprintln!("authenticator app for the view check.");
    Ok(())
}
