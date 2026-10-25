//! `sourceorrery vault ...`: create (or, on the setup screens, change),
//! list, export, import and destroy (ADR 0009, section 7). A vault's view
//! check, recovery key and connections change on the setup screens
//! (`ui::setup`), and its details show in the `ui` browser.

use std::io::Write as _;
use std::path::Path;

use anyhow::anyhow;
use sourceorrery_core::{RecoveryLevel, SecretClient as _};
use sourceorrery_storage::{
    Argon2Params, ConnectionChange, CreateVaultOptions, PasswordChange, SettingsChange,
};

use crate::cli::{
    VaultCommand, VaultCreateArgs, VaultDestroyArgs, VaultExportArgs, VaultImportArgs,
};
use crate::commands::connections;
use crate::context::Ctx;
use crate::output::{self, Table};
use crate::prompt;

pub fn run(ctx: &Ctx, cmd: &VaultCommand) -> anyhow::Result<()> {
    match cmd {
        VaultCommand::Create(args) => create(ctx, args),
        VaultCommand::List => list(ctx),
        VaultCommand::Export(args) => export(ctx, args),
        VaultCommand::Import(args) => import(ctx, args),
        VaultCommand::Destroy(args) => destroy(ctx, args),
    }
}

/// Write a recovery key to `path`, readable by the current user only. The
/// file is created new: an existing one is never overwritten.
fn write_recovery_key(path: &Path, key: &str) -> anyhow::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|err| anyhow!("cannot create {}: {err}", path.display()))?;
    file.write_all(key.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

/// Show a recovery key once: into `out` when given, else on stdout (or in
/// the JSON body).
fn show_recovery_key(
    ctx: &Ctx,
    vault: &str,
    key: &str,
    out: Option<&Path>,
    body: &mut serde_json::Value,
) -> anyhow::Result<()> {
    if let Some(path) = out {
        write_recovery_key(path, key)?;
        body["recovery_key_file"] = serde_json::Value::String(path.display().to_string());
        if !ctx.json() {
            output::note(&format!(
                "the recovery key of vault '{vault}' is in {} (readable by you only); keep a copy \
                 apart from this machine and delete the file",
                path.display()
            ));
        }
        return Ok(());
    }
    if ctx.json() {
        body["recovery_key"] = serde_json::Value::String(key.to_owned());
        return Ok(());
    }
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{key}")?;
    stdout.flush()?;
    drop(stdout);
    output::note(&format!(
        "that is the recovery key of vault '{vault}', shown once: it opens the vault wherever \
         this machine's key cannot (WSL, a container, CI, another machine, an exported copy) \
         and passes its view check. Write it down and keep it apart from this machine."
    ));
    Ok(())
}

/// `vault create` shows the setup screens: on a terminal, without JSON, and
/// without any flag of a non-interactive create.
#[cfg(feature = "ui")]
fn on_screens(ctx: &Ctx, args: &VaultCreateArgs) -> bool {
    !ctx.json()
        && args.recovery_key_out.is_none()
        && !args.no_keyring
        && !args.purgeable
        // The flag's default: the screens create vaults that way.
        && args.retention_days == 90
        && ctx.password_file.is_none()
        && args.connections.is_empty()
        && crate::commands::on_a_terminal()
}

/// What a non-interactive create gives the new vault: the password from
/// `--password-file` and a connection per provider flag set.
fn created_settings(ctx: &Ctx, args: &VaultCreateArgs) -> anyhow::Result<SettingsChange> {
    let password = ctx
        .password_file
        .as_deref()
        .map(Ctx::password_from_file)
        .transpose()?;
    Ok(SettingsChange {
        password: password.map_or(PasswordChange::Keep, |password| PasswordChange::Set {
            password,
            hint: None,
            params: Argon2Params::default(),
        }),
        connections: connections::requested(&args.connections)?
            .into_iter()
            .map(|(settings, credentials)| ConnectionChange::Add {
                settings,
                credentials,
            })
            .collect(),
        ..SettingsChange::default()
    })
}

/// `vault create`: the setup screens, or a vault created at once with what
/// the flags give it, in one transaction (a vault that cannot take its
/// password or a connection is removed again).
fn create(ctx: &Ctx, args: &VaultCreateArgs) -> anyhow::Result<()> {
    #[cfg(feature = "ui")]
    if on_screens(ctx, args) {
        return crate::ui::setup::run(ctx, args.name.as_deref(), args.theme);
    }
    let Some(name) = args.name.as_deref() else {
        return Err(anyhow!(
            "name the vault to create: `sourceorrery vault create NAME` (in a terminal, without \
             flags, it shows the setup screens; `sourceorrery setup --guide` shows the flags)"
        ));
    };
    let options = CreateVaultOptions {
        recovery_level: if args.purgeable {
            RecoveryLevel::Purgeable
        } else {
            RecoveryLevel::Recoverable
        },
        retention_days: args.retention_days,
        this_machine: !args.no_keyring,
    };
    if let Some(path) = &args.recovery_key_out
        && path.exists()
    {
        return Err(anyhow!(
            "{} exists already; the recovery key is never written over a file",
            path.display()
        ));
    }
    // Read before the vault exists, so a wrong flag or file creates nothing.
    let change = created_settings(ctx, args)?;
    let created = ctx.registry.create(name, options)?;
    if let Err(err) = created.vault.change_settings(&change) {
        // No half-made vault is left behind: it goes again.
        drop(created);
        let _ = ctx.registry.destroy(name, false);
        return Err(anyhow!("vault '{name}' was not created: {err}"));
    }
    drop(change);
    let descriptor = created.vault.descriptor()?;
    let check = created.vault.view_check()?;
    let added = created.vault.connections()?;
    // The keys that open it, by kind and id (never a credential-store
    // account): what a script checks the credential store against.
    let keys = created.vault.wraps()?;
    let mut body = serde_json::json!({
        "vault": descriptor,
        "this_machine": created.this_machine,
        "keys": keys,
        "view_check": check,
        "connections": added,
    });
    if !ctx.json() {
        output::success(&format!(
            "Vault '{}' created\n  {}",
            descriptor.name,
            descriptor
                .path
                .as_deref()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        ));
        if created.this_machine {
            eprintln!(
                "  this machine opens it without asking ({})",
                ctx.registry.store().name()
            );
        } else if !args.no_keyring {
            output::note(&format!(
                "{} is not available{}; the vault opens with its recovery key only",
                ctx.registry.store().name(),
                ctx.registry
                    .store()
                    .unavailable_reason()
                    .map(|r| format!(" ({r})"))
                    .unwrap_or_default()
            ));
        }
        if !check.is_none() {
            eprintln!("  view check: {}", check.describe());
        }
        for connection in &added {
            eprintln!(
                "  connection {}: {}",
                connection.id,
                connections::describe(connection)
            );
        }
    }
    show_recovery_key(
        ctx,
        &descriptor.name,
        created.recovery_key.as_str(),
        args.recovery_key_out.as_deref(),
        &mut body,
    )?;
    if ctx.json() {
        return output::json(&body);
    }
    Ok(())
}

/// `vault export`: no view check is asked, since the copy opens with the
/// recovery key only. What the copy leaves out is read before it is made,
/// to say so.
fn export(ctx: &Ctx, args: &VaultExportArgs) -> anyhow::Result<()> {
    let name = match &args.name {
        Some(name) => name.clone(),
        None => ctx.vault_name()?,
    };
    let vault = ctx.open_local(&name)?;
    let check = vault.view_check()?;
    let left_out: Vec<&str> = [
        (
            vault
                .wraps()?
                .iter()
                .any(|wrap| wrap.kind == "this-machine"),
            "this machine's key",
        ),
        (check.password, "the password"),
        (vault.password_hint()?.is_some(), "its hint"),
        (check.authenticator, "the authenticator"),
    ]
    .into_iter()
    .filter_map(|(present, what)| present.then_some(what))
    .collect();
    vault.export_to(&args.out)?;
    let name = vault.vault_name();
    if ctx.json() {
        return output::json(&serde_json::json!({
            "vault": name,
            "file": args.out.display().to_string(),
            "left_out": left_out,
        }));
    }
    output::success(&format!(
        "Vault '{name}' exported to {}",
        args.out.display()
    ));
    eprintln!("  the copy opens with the recovery key only");
    if !left_out.is_empty() {
        eprintln!("  left out of it: {}", left_out.join(", "));
    }
    Ok(())
}

/// `vault import`: the copy opens with its recovery key only (the
/// environment, `--recovery-key-file` or the prompt), and the vault comes
/// with no view check. `--password-file` sets one at once; otherwise the
/// output says how.
fn import(ctx: &Ctx, args: &VaultImportArgs) -> anyhow::Result<()> {
    let unlocker = ctx.unlocker();
    let imported = ctx
        .registry
        .import_from(&args.file, &unlocker, args.name.as_deref())?;
    let vault = imported.vault;
    let name = vault.vault_name().to_owned();
    if let Some(file) = &ctx.password_file {
        let set = Ctx::password_from_file(file).and_then(|password| {
            Ok(vault.set_password(&password, None, Argon2Params::default())?)
        });
        if let Err(err) = set {
            return Err(anyhow!(
                "vault '{name}' was imported, but its password was not set: {err}"
            ));
        }
    }
    let descriptor = vault.descriptor()?;
    let check = vault.view_check()?;
    let connected = vault.connections()?;
    if ctx.json() {
        return output::json(&serde_json::json!({
            "vault": descriptor,
            "renamed_from": imported.renamed_from,
            "this_machine": imported.this_machine,
            "view_check": check,
            "connections": connected,
        }));
    }
    output::success(&format!(
        "Vault '{name}' imported\n  {}",
        descriptor
            .path
            .as_deref()
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    ));
    if let Some(original) = &imported.renamed_from {
        eprintln!("  exported as '{}'", output::sanitize(original));
    }
    if imported.this_machine {
        eprintln!(
            "  this machine opens it without asking ({})",
            ctx.registry.store().name()
        );
    } else {
        output::note(&format!(
            "{} is not available; the vault opens with its recovery key only",
            ctx.registry.store().name()
        ));
    }
    for connection in &connected {
        eprintln!(
            "  connection {}: {}",
            connection.id,
            connections::describe(connection)
        );
    }
    if check.is_none() {
        output::note(&format!(
            "it has no view check; set one on the setup screens: sourceorrery vault create {name}"
        ));
    } else {
        eprintln!("  viewing it asks for: {}", check.describe());
    }
    Ok(())
}

/// One line of `vault list`: a vault file in the home directory.
#[derive(serde::Serialize)]
struct VaultRow {
    name: String,
    kind: &'static str,
    path: std::path::PathBuf,
}

fn list(ctx: &Ctx) -> anyhow::Result<()> {
    let rows: Vec<VaultRow> = ctx
        .registry
        .list()?
        .into_iter()
        .map(|name| {
            Ok(VaultRow {
                path: ctx.registry.vault_path(&name)?,
                name,
                kind: "local",
            })
        })
        .collect::<anyhow::Result<_>>()?;
    if ctx.json() {
        return output::json(&rows);
    }
    if rows.is_empty() {
        eprintln!(
            "no vaults in {}\ncreate one with: sourceorrery vault create development",
            ctx.registry.root().display()
        );
        return Ok(());
    }
    let mut table = Table::new(["NAME", "KIND", "LOCATION"]);
    for row in rows {
        table.row([
            row.name,
            row.kind.to_owned(),
            row.path.display().to_string(),
        ]);
    }
    table.print()
}

fn destroy(ctx: &Ctx, args: &VaultDestroyArgs) -> anyhow::Result<()> {
    if !ctx.registry.exists(&args.name) {
        return Err(sourceorrery_core::SecretError::VaultNotFound {
            name: args.name.clone(),
        }
        .into());
    }
    if !args.yes
        && !prompt::confirm(&format!(
            "Permanently destroy vault '{}' and every secret in it?",
            args.name
        ))?
    {
        return Err(anyhow!("aborted"));
    }
    let report = ctx.registry.destroy(&args.name, args.keep_os_key)?;
    if ctx.json() {
        return output::json(&serde_json::json!({ "destroyed": args.name, "keyring": report }));
    }
    output::success(&format!("Vault '{}' destroyed", args.name));
    // Account names come from the file's key records, unverified.
    for account in &report.removed_keys {
        eprintln!("  removed OS-keyring entry {}", output::sanitize(account));
    }
    for (account, reason) in &report.kept_keys {
        output::note(&format!(
            "kept OS-keyring entry {}: {reason}",
            output::sanitize(account)
        ));
    }
    Ok(())
}
