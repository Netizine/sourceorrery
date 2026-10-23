//! The reveal guard and the commands around it: `vault 2fa`, `vault guard`,
//! `vault recovery codes`, `vault passphrase set|hint`.
//!
//! [`enforce`] is what the guarded commands call once the vault is open:
//! it asks for what the vault's guard says (the passphrase again, a
//! second-factor code, both) and lets the vault check it. A refusal is
//! `permission_denied`; the vault has already audited it. The guard covers
//! the interactive paths only (`secret get --reveal`, `backup`, the
//! protector and guard changes); `run`, `check` and the SDKs read values
//! for the application and are not asked.
//!
//! Nothing here prints a value, a TOTP secret (outside the enrolment it
//! exists to show, once) or a code.

use std::io::{IsTerminal, Write as _};

use anyhow::anyhow;
use sourceorrery_core::{SecretBytes, SecretClient, SecretError, timestamp};
use sourceorrery_crypto::{Argon2Params, TotpSecret, random};
use sourceorrery_storage::{RECOVERY_LABEL_PREFIX, RevealGuard, SqliteVault};

use crate::cli::{
    GuardArgs, PassphraseHintArgs, PassphraseSetArgs, RecoveryCodesArgs, RecoveryCommand,
    TwoFactorCommand, TwoFactorEnableArgs,
};
use crate::context::{Ctx, PASSPHRASE_ENV};
use crate::output::{self, Table};
use crate::{prompt, qr};

/// Attempts at a code before an enrolment is abandoned.
const ENROL_ATTEMPTS: u32 = 3;

fn denied(action: &str, reason: &str) -> anyhow::Error {
    SecretError::PermissionDenied(format!("the reveal guard refused to {action}: {reason}")).into()
}

/// Ask for what the guard says and have the vault check it.
pub fn enforce(ctx: &Ctx, vault: &SqliteVault, action: &str) -> anyhow::Result<()> {
    let guard = vault.reveal_guard()?;
    if guard.passphrase {
        check_passphrase(ctx, vault, action)?;
    }
    if guard.second_factor {
        check_code(ctx, vault, action)?;
    }
    Ok(())
}

/// The passphrase, from where the unlock would take it, checked in place.
fn check_passphrase(ctx: &Ctx, vault: &SqliteVault, action: &str) -> anyhow::Result<()> {
    let passphrase = match ctx.passphrase_from_sources()? {
        Some(pass) => pass,
        None if std::io::stdin().is_terminal() => prompt::read_hidden(&format!(
            "Passphrase of vault '{}' to {action}: ",
            vault.vault_name()
        ))?,
        None => {
            return Err(denied(
                action,
                &format!(
                    "the guard asks for the passphrase and stdin is not a terminal; set \
                     {PASSPHRASE_ENV} or --passphrase-file"
                ),
            ));
        }
    };
    if vault.verify_passphrase(&passphrase)? {
        Ok(())
    } else {
        Err(denied(action, "incorrect passphrase"))
    }
}

/// A code from `--code` / `SOURCEORRERY_TOTP`, else the prompt; checked by
/// the vault. A script passes the code, it is never read from a pipe (a
/// command that waited on stdin would hang a pipeline).
fn check_code(ctx: &Ctx, vault: &SqliteVault, action: &str) -> anyhow::Result<()> {
    let Some(code) = read_code(ctx, "Second-factor code: ")? else {
        return Err(denied(
            action,
            "the guard asks for a second-factor code; pass --code or set SOURCEORRERY_TOTP",
        ));
    };
    if vault.verify_second_factor(&code, timestamp::now())? {
        Ok(())
    } else {
        Err(denied(action, "incorrect or already used code"))
    }
}

fn read_code(ctx: &Ctx, prompt_text: &str) -> anyhow::Result<Option<String>> {
    if let Some(code) = &ctx.code {
        return Ok(Some(code.clone()));
    }
    if std::io::stdin().is_terminal() {
        return Ok(Some(prompt::read_line(prompt_text)?));
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// vault 2fa
// ---------------------------------------------------------------------------

pub fn two_factor(ctx: &Ctx, cmd: &TwoFactorCommand) -> anyhow::Result<()> {
    match cmd {
        TwoFactorCommand::Enable(args) => enable(ctx, args),
        TwoFactorCommand::Verify => verify(ctx),
        TwoFactorCommand::Disable => disable(ctx),
        TwoFactorCommand::Status => status(ctx),
    }
}

/// Show the enrolment on stderr: the QR code, what to do, and on request
/// the URI and key for an app that cannot scan.
fn show_enrolment(vault: &str, secret: &TotpSecret, show_uri: bool) -> anyhow::Result<()> {
    let uri = secret.otpauth_uri("SourceOrrery", &format!("vault {vault}"));
    let mut err = std::io::stderr().lock();
    writeln!(err)?;
    writeln!(
        err,
        "Scan this with an authenticator app (Aegis, Google Authenticator, 1Password, ...):"
    )?;
    writeln!(err)?;
    for line in qr::render(&uri)? {
        writeln!(err, "    {line}")?;
    }
    writeln!(err)?;
    if show_uri {
        writeln!(err, "  key: {}", secret.to_base32())?;
        writeln!(err, "  uri: {uri}")?;
        writeln!(err)?;
    } else {
        writeln!(
            err,
            "  (cannot scan? run again with --show-uri to type the key instead)"
        )?;
    }
    Ok(())
}

fn enable(ctx: &Ctx, args: &TwoFactorEnableArgs) -> anyhow::Result<()> {
    let vault = ctx.open_local_default("vault 2fa")?;
    // Replacing an enrolment is a guarded change (the passphrase, when the
    // guard asks for it; an existing verified enrolment is refused below).
    enforce(ctx, &vault, "enrol a second factor")?;
    let name = vault.vault_name().to_owned();
    let secret = vault.enrol_second_factor()?;
    if ctx.json() {
        let mut body = serde_json::json!({
            "vault": name,
            "key": secret.to_base32(),
            "uri": secret.otpauth_uri("SourceOrrery", &name),
            "verified": false,
        });
        if args.no_verify {
            return output::json(&body);
        }
        let Some(code) = read_code(ctx, "Code from the app: ")? else {
            vault.disable_second_factor()?;
            return Err(anyhow!(
                "no code to verify the enrolment with; pass --code, or use --no-verify and \
                 `vault 2fa verify --code` later"
            ));
        };
        if !vault.verify_second_factor(&code, timestamp::now())? {
            vault.disable_second_factor()?;
            return Err(denied("enable the second factor", "the code did not match"));
        }
        body["verified"] = serde_json::Value::Bool(true);
        return output::json(&body);
    }
    show_enrolment(&name, &secret, args.show_uri)?;
    drop(secret);
    if args.no_verify {
        output::note(&format!(
            "enrolled but not yet verified: run `sourceorrery vault 2fa verify --vault {name}` \
             with a code from the app; until then the guard cannot ask for it"
        ));
        return Ok(());
    }
    for attempt in 1..=ENROL_ATTEMPTS {
        let Some(code) = read_code(ctx, "Code from the app: ")? else {
            break;
        };
        if vault.verify_second_factor(&code, timestamp::now())? {
            output::success(&format!(
                "Second factor enabled for vault '{name}'. Ask for it on reveal and export \
                 with: sourceorrery vault guard --reveal passphrase,second-factor --vault {name}"
            ));
            return Ok(());
        }
        if attempt < ENROL_ATTEMPTS {
            output::note(&format!(
                "that code did not match ({attempt} of {ENROL_ATTEMPTS}); wait for the next one \
                 and try again"
            ));
        }
        if ctx.code.is_some() {
            break; // a --code that failed is not asked for again
        }
    }
    vault.disable_second_factor()?;
    Err(denied(
        "enable the second factor",
        "no code matched, so the enrolment was removed; run `vault 2fa enable` again",
    ))
}

fn verify(ctx: &Ctx) -> anyhow::Result<()> {
    let vault = ctx.open_local_default("vault 2fa")?;
    let Some(info) = vault.second_factor()? else {
        return Err(anyhow!(
            "no second factor is enrolled for vault '{}'; run `vault 2fa enable`",
            vault.vault_name()
        ));
    };
    let Some(code) = read_code(ctx, "Code from the app: ")? else {
        return Err(anyhow!(
            "no code given; pass --code or set SOURCEORRERY_TOTP"
        ));
    };
    let ok = vault.verify_second_factor(&code, timestamp::now())?;
    if ctx.json() {
        output::json(&serde_json::json!({
            "vault": vault.vault_name(),
            "accepted": ok,
            "verified": ok || info.verified,
        }))?;
    } else if ok {
        output::success(&format!(
            "Code accepted; the second factor of vault '{}' is verified",
            vault.vault_name()
        ));
    }
    if ok {
        Ok(())
    } else {
        Err(denied(
            "verify the second factor",
            "incorrect or already used code",
        ))
    }
}

fn disable(ctx: &Ctx) -> anyhow::Result<()> {
    let vault = ctx.open_local_default("vault 2fa")?;
    let Some(info) = vault.second_factor()? else {
        return Err(anyhow!(
            "no second factor is enrolled for vault '{}'",
            vault.vault_name()
        ));
    };
    // The passphrase, when the guard asks for it, and one code while the
    // enrolment is verified: removing the second factor proves both.
    if vault.reveal_guard()?.passphrase {
        check_passphrase(ctx, &vault, "disable the second factor")?;
    }
    if info.verified {
        check_code(ctx, &vault, "disable the second factor")?;
    }
    vault.disable_second_factor()?;
    if ctx.json() {
        return output::json(&serde_json::json!({
            "vault": vault.vault_name(),
            "second_factor": false,
            "guard": vault.reveal_guard()?,
        }));
    }
    output::success(&format!(
        "Second factor disabled for vault '{}'; the guard now asks for: {}",
        vault.vault_name(),
        vault.reveal_guard()?.describe()
    ));
    Ok(())
}

fn status(ctx: &Ctx) -> anyhow::Result<()> {
    let vault = ctx.open_local_default("vault 2fa")?;
    let info = vault.second_factor()?;
    let guard = vault.reveal_guard()?;
    if ctx.json() {
        return output::json(&serde_json::json!({
            "vault": vault.vault_name(),
            "enrolled": info.is_some(),
            "verified": info.as_ref().is_some_and(|i| i.verified),
            "enrolled_on": info.as_ref().map(|i| timestamp::format(i.enrolled_on)),
            "guard": guard,
        }));
    }
    let mut table = Table::new(["FIELD", "VALUE"]);
    table.row([
        "second factor".to_owned(),
        match &info {
            None => "not enrolled".to_owned(),
            Some(i) if i.verified => format!("enrolled {}", output::fmt_time(i.enrolled_on)),
            Some(i) => format!(
                "enrolled {} but not verified (run `vault 2fa verify`)",
                output::fmt_time(i.enrolled_on)
            ),
        },
    ]);
    table.row(["guard asks for".to_owned(), guard.describe().to_owned()]);
    table.print()
}

// ---------------------------------------------------------------------------
// vault guard
// ---------------------------------------------------------------------------

fn parse_guard(text: &str) -> anyhow::Result<RevealGuard> {
    let mut guard = RevealGuard::default();
    for part in text.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match part {
            "none" => return Ok(RevealGuard::default()),
            "passphrase" => guard.passphrase = true,
            "second-factor" | "2fa" | "totp" => guard.second_factor = true,
            other => {
                return Err(anyhow!(
                    "'{}' is not something the guard can ask for; use passphrase, \
                     second-factor, passphrase,second-factor or none",
                    output::sanitize(other)
                ));
            }
        }
    }
    Ok(guard)
}

pub fn guard(ctx: &Ctx, args: &GuardArgs) -> anyhow::Result<()> {
    let vault = ctx.open_local_default("vault guard")?;
    let current = vault.reveal_guard()?;
    let Some(wanted) = &args.reveal else {
        if ctx.json() {
            return output::json(&serde_json::json!({
                "vault": vault.vault_name(),
                "reveal": current,
                "second_factor_verified": vault.second_factor()?.is_some_and(|i| i.verified),
            }));
        }
        eprintln!(
            "vault '{}': revealing a secret or exporting the vault asks for: {}",
            vault.vault_name(),
            current.describe()
        );
        return Ok(());
    };
    let wanted = parse_guard(wanted)?;
    // Changing the guard passes the current one first.
    enforce(ctx, &vault, "change the guard")?;
    let set = vault.set_reveal_guard(wanted)?;
    if ctx.json() {
        return output::json(&serde_json::json!({
            "vault": vault.vault_name(),
            "reveal": set,
        }));
    }
    output::success(&format!(
        "Vault '{}': revealing a secret or exporting the vault now asks for: {}",
        vault.vault_name(),
        set.describe()
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// vault recovery codes
// ---------------------------------------------------------------------------

pub fn recovery(ctx: &Ctx, cmd: &RecoveryCommand) -> anyhow::Result<()> {
    match cmd {
        RecoveryCommand::Codes(args) => recovery_codes(ctx, args),
    }
}

fn recovery_codes(ctx: &Ctx, args: &RecoveryCodesArgs) -> anyhow::Result<()> {
    if !(1..=7).contains(&args.count) {
        return Err(anyhow!("--count is 1 to 7"));
    }
    let vault = ctx.open_local_default("vault recovery")?;
    // New ways to unlock the vault: a guarded change.
    enforce(ctx, &vault, "replace the recovery codes")?;
    let mut shown = Vec::with_capacity(args.count);
    let mut installed = Vec::with_capacity(args.count);
    for _ in 0..args.count {
        let code = random::recovery_code()?;
        installed.push(SecretBytes::from_string(
            random::normalise_recovery_code(&code).to_string(),
        ));
        shown.push(code);
    }
    let replaced = vault.recovery_codes()?.len();
    let infos = vault.replace_recovery_codes(installed, Argon2Params::default())?;
    let name = vault.vault_name().to_owned();
    if ctx.json() {
        return output::json(&serde_json::json!({
            "vault": name,
            "codes": shown.iter().map(|c| c.as_str().to_owned()).collect::<Vec<_>>(),
            "labels": infos.iter().map(|i| i.label.clone()).collect::<Vec<_>>(),
            "replaced": replaced,
        }));
    }
    let mut stdout = std::io::stdout().lock();
    for code in &shown {
        writeln!(stdout, "{}", code.as_str())?;
    }
    stdout.flush()?;
    drop(stdout);
    output::note(&format!(
        "{} recovery code(s) for vault '{name}' shown once{}: each unlocks the vault in place \
         of the passphrase (type it at the passphrase prompt; case and hyphens do not matter). \
         Write them down and keep them apart from the vault file; run this again to replace them.",
        shown.len(),
        if replaced > 0 {
            format!(" (the {replaced} earlier code(s) no longer work)")
        } else {
            String::new()
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// vault passphrase set | hint
// ---------------------------------------------------------------------------

pub fn passphrase_set(ctx: &Ctx, args: &PassphraseSetArgs) -> anyhow::Result<()> {
    let vault = ctx.open_local_default("vault passphrase")?;
    // The current passphrase proves who is changing it, whatever the guard
    // says; the guard's second factor is asked for too when it is on.
    let current = match ctx.passphrase_from_sources()? {
        Some(pass) => pass,
        None if std::io::stdin().is_terminal() => prompt::read_hidden("Current passphrase: ")?,
        None => {
            return Err(anyhow!(
                "the current passphrase is needed: set {PASSPHRASE_ENV} or --passphrase-file, \
                 or run interactively"
            ));
        }
    };
    if vault.reveal_guard()?.second_factor {
        check_code(ctx, &vault, "change the passphrase")?;
    }
    let new = match &args.new_from_file {
        Some(file) => Ctx::passphrase_from_file(file)?,
        None => Ctx::prompt_new_passphrase("to replace the current one", args.allow_weak)?,
    };
    if new == current {
        return Err(anyhow!("the new passphrase is the same as the current one"));
    }
    let info = vault.replace_passphrase(&current, new, Argon2Params::default())?;
    drop(current);
    if ctx.json() {
        return output::json(&info);
    }
    output::success(&format!(
        "Passphrase of vault '{}' changed (protector '{}'); recovery codes are unchanged",
        vault.vault_name(),
        info.label
    ));
    Ok(())
}

pub fn passphrase_hint(ctx: &Ctx, args: &PassphraseHintArgs) -> anyhow::Result<()> {
    let vault = ctx.open_local_default("vault passphrase")?;
    let name = vault.vault_name().to_owned();
    if args.clear {
        vault.set_passphrase_hint(None)?;
        if ctx.json() {
            return output::json(&serde_json::json!({ "vault": name, "hint": null }));
        }
        output::success(&format!("Passphrase hint of vault '{name}' cleared"));
        return Ok(());
    }
    if let Some(text) = &args.text {
        vault.set_passphrase_hint(Some(text))?;
        if ctx.json() {
            return output::json(&serde_json::json!({ "vault": name, "hint": text.trim() }));
        }
        output::success(&format!(
            "Passphrase hint of vault '{name}' set; it is stored in clear in the vault file \
             and shown at the prompt"
        ));
        return Ok(());
    }
    let hint = ctx.registry.passphrase_hint(&name)?;
    if ctx.json() {
        return output::json(&serde_json::json!({ "vault": name, "hint": hint }));
    }
    match hint {
        Some(hint) => eprintln!("hint: {}", output::sanitize(&hint)),
        None => eprintln!("vault '{name}' has no passphrase hint"),
    }
    Ok(())
}

/// Rows for `vault info`.
pub fn info_rows(vault: &SqliteVault, table: &mut Table) -> anyhow::Result<()> {
    let guard = vault.reveal_guard()?;
    table.row(["guard asks for".into(), guard.describe().to_owned()]);
    table.row([
        "second factor".into(),
        match vault.second_factor()? {
            None => "not enrolled".to_owned(),
            Some(i) if i.verified => "enrolled".to_owned(),
            Some(_) => "enrolled, not verified".to_owned(),
        },
    ]);
    table.row([
        "recovery codes".into(),
        vault.recovery_codes()?.len().to_string(),
    ]);
    table.row([
        "passphrase hint".into(),
        match vault.passphrase_hint() {
            Some(hint) => output::sanitize(&hint).into_owned(),
            None => "-".to_owned(),
        },
    ]);
    Ok(())
}

/// The recovery-code protectors, for `vault info`'s JSON.
pub fn recovery_labels(vault: &SqliteVault) -> anyhow::Result<Vec<String>> {
    Ok(vault
        .recovery_codes()?
        .into_iter()
        .map(|p| p.label)
        .filter(|l| l.starts_with(RECOVERY_LABEL_PREFIX))
        .collect())
}
