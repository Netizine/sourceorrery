//! `sourceorrery vault ...`

use anyhow::anyhow;
use sourceorrery_core::RecoveryLevel;
use sourceorrery_storage::{CreateVaultOptions, ProtectorSpec, keystore};

use crate::cli::{ProtectorAddArgs, ProtectorCommand, ProtectorRemoveArgs};
use crate::cli::{
    ProtectorChoice, VaultCommand, VaultCreateArgs, VaultDestroyArgs, VaultMigrateArgs,
};
use crate::context::Ctx;
use crate::output::{self, Table};
use crate::prompt;

pub fn run(ctx: &Ctx, cmd: &VaultCommand) -> anyhow::Result<()> {
    match cmd {
        VaultCommand::Create(args) => create(ctx, args),
        VaultCommand::List => list(ctx),
        VaultCommand::Info => info(ctx),
        VaultCommand::Protector(cmd) => protector(ctx, cmd),
        VaultCommand::Destroy(args) => destroy(ctx, args),
        VaultCommand::Migrate(args) => migrate(ctx, args),
    }
}

fn migrate(ctx: &Ctx, args: &VaultMigrateArgs) -> anyhow::Result<()> {
    Ctx::refuse_remote(&args.name, "vault migrate")?;
    let unlocker = ctx.unlocker();
    let vault = ctx.registry.migrate(&args.name, &unlocker)?;
    let descriptor = vault.descriptor()?;
    if ctx.json() {
        return output::json(&descriptor);
    }
    output::success(&format!(
        "Vault '{}' is at the current on-disk format (schema {})",
        descriptor.name,
        sourceorrery_storage::SCHEMA_VERSION
    ));
    Ok(())
}

fn choose_protector(ctx: &Ctx, choice: Option<ProtectorChoice>) -> anyhow::Result<ProtectorSpec> {
    let choice = match choice {
        Some(c) => c,
        None if keystore::available() => ProtectorChoice::OsKeyring,
        None => {
            output::note(&format!(
                "{} is not available{}; falling back to a passphrase protector",
                keystore::STORE_NAME,
                keystore::unavailable_reason()
                    .map(|r| format!(" ({r})"))
                    .unwrap_or_default()
            ));
            ProtectorChoice::Passphrase
        }
    };
    match choice {
        ProtectorChoice::OsKeyring => Ok(ProtectorSpec::OsKeyring),
        ProtectorChoice::Passphrase => {
            let passphrase = ctx.new_passphrase("for this vault")?;
            Ok(ProtectorSpec::passphrase(passphrase))
        }
    }
}

fn create(ctx: &Ctx, args: &VaultCreateArgs) -> anyhow::Result<()> {
    let options = CreateVaultOptions {
        recovery_level: if args.purgeable {
            RecoveryLevel::Purgeable
        } else {
            RecoveryLevel::Recoverable
        },
        retention_days: args.retention_days,
    };
    let spec = choose_protector(ctx, args.protector)?;
    let kind = spec.kind_label();
    let vault = ctx.registry.create(&args.name, options, spec)?;
    let descriptor = vault.descriptor()?;
    if ctx.json() {
        return output::json(&descriptor);
    }
    let how = match kind {
        "os-keyring" => format!("key protected by {}", keystore::STORE_NAME),
        _ => "key protected by passphrase".to_owned(),
    };
    output::success(&format!(
        "Vault '{}' created ({how})\n  {}",
        descriptor.name,
        descriptor
            .path
            .as_deref()
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    ));
    if kind == "os-keyring" {
        eprintln!(
            "  tip: add a passphrase protector for WSL, Docker or CI:\n  \
             sourceorrery vault protector add --kind passphrase --vault {}",
            descriptor.name
        );
    }
    Ok(())
}

/// One line of `vault list`: a vault file in the home directory, or a
/// remote vault the nearest manifest declares.
#[derive(serde::Serialize)]
struct VaultRow {
    name: String,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<std::path::PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<sourceorrery_core::Provider>,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<String>,
}

fn list(ctx: &Ctx) -> anyhow::Result<()> {
    let mut rows: Vec<VaultRow> = ctx
        .registry
        .list()?
        .into_iter()
        .map(|name| {
            Ok(VaultRow {
                path: Some(ctx.registry.vault_path(&name)?),
                name,
                kind: "local",
                provider: None,
                location: None,
            })
        })
        .collect::<anyhow::Result<_>>()?;
    for (name, remote) in Ctx::remote_vaults()? {
        rows.push(VaultRow {
            name,
            kind: "remote",
            path: None,
            provider: Some(remote.provider()),
            location: Some(remote.location()),
        });
    }
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
        let kind = match row.provider {
            Some(provider) => provider.name().to_owned(),
            None => row.kind.to_owned(),
        };
        let location = row
            .path
            .map(|p| p.display().to_string())
            .or(row.location)
            .unwrap_or_default();
        table.row([row.name, kind, location]);
    }
    table.print()
}

fn info(ctx: &Ctx) -> anyhow::Result<()> {
    let vault = ctx.open_default()?;
    let descriptor = vault.descriptor()?;
    let protectors = match vault.local() {
        Some(local) => local.protectors()?,
        None => Vec::new(),
    };
    if ctx.json() {
        return output::json(&serde_json::json!({
            "vault": descriptor,
            "protectors": protectors,
        }));
    }
    let mut table = Table::new(["FIELD", "VALUE"]);
    table.row(["name".into(), descriptor.name.clone()]);
    table.row(["id".into(), descriptor.id.clone()]);
    table.row(["backend".into(), descriptor.backend.clone()]);
    table.row([
        "path".into(),
        descriptor
            .path
            .as_deref()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
    ]);
    table.row(["created".into(), output::fmt_time(descriptor.created_on)]);
    table.row([
        "recovery".into(),
        format!("{:?}", descriptor.recovery_level).to_lowercase(),
    ]);
    table.row([
        "retention".into(),
        format!("{} days", descriptor.retention_days),
    ]);
    table.print()?;
    if vault.local().is_none() {
        return Ok(());
    }
    println!();
    protector_table(&protectors)
}

fn protector_table(protectors: &[sourceorrery_storage::ProtectorInfo]) -> anyhow::Result<()> {
    let mut table = Table::new(["PROTECTOR", "KIND", "ID", "ADDED"]);
    for p in protectors {
        table.row([
            p.label.clone(),
            p.kind.clone(),
            p.id.clone(),
            output::fmt_time(p.created_on),
        ]);
    }
    table.print()
}

fn protector(ctx: &Ctx, cmd: &ProtectorCommand) -> anyhow::Result<()> {
    match cmd {
        ProtectorCommand::List => {
            let vault = ctx.open_local_default("vault protector")?;
            let protectors = vault.protectors()?;
            if ctx.json() {
                return output::json(&protectors);
            }
            protector_table(&protectors)
        }
        ProtectorCommand::Add(ProtectorAddArgs { kind, label }) => {
            let vault = ctx.open_local_default("vault protector")?;
            let spec = match kind {
                ProtectorChoice::OsKeyring => ProtectorSpec::OsKeyring,
                ProtectorChoice::Passphrase => {
                    ProtectorSpec::passphrase(ctx.new_passphrase("for the new protector")?)
                }
            };
            let info = vault.add_protector(spec, label.as_deref())?;
            if ctx.json() {
                return output::json(&info);
            }
            output::success(&format!(
                "Protector '{}' ({}) added to vault '{}'",
                info.label,
                info.kind,
                vault.descriptor()?.name
            ));
            Ok(())
        }
        ProtectorCommand::Remove(ProtectorRemoveArgs { protector }) => {
            let vault = ctx.open_local_default("vault protector")?;
            let note = vault.remove_protector(protector)?;
            if ctx.json() {
                return output::json(&serde_json::json!({ "removed": protector, "note": note }));
            }
            output::success(&format!("Protector '{protector}' removed"));
            if let Some(note) = note {
                output::note(&note);
            }
            Ok(())
        }
    }
}

fn destroy(ctx: &Ctx, args: &VaultDestroyArgs) -> anyhow::Result<()> {
    Ctx::refuse_remote(&args.name, "vault destroy")?;
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
    // Account names come from the file's protector records, unverified.
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
