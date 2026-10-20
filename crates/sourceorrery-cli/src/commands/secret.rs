//! `sourceorrery secret ...`

use anyhow::anyhow;
use sourceorrery_core::{SecretClient, SetSecretOptions, UpdateSecretProperties, timestamp};

use crate::cli::{
    SecretCommand, SecretGetArgs, SecretListArgs, SecretNameArgs, SecretPurgeArgs, SecretSetArgs,
    SecretUpdateArgs,
};
use crate::commands::parse_tags;
use crate::context::Ctx;
use crate::output::{self, Table};
use crate::prompt;

pub fn run(ctx: &Ctx, cmd: &SecretCommand) -> anyhow::Result<()> {
    match cmd {
        SecretCommand::Set(args) => set(ctx, args),
        SecretCommand::Get(args) => get(ctx, args),
        SecretCommand::List(args) => list(ctx, args),
        SecretCommand::Versions(args) => versions(ctx, args),
        SecretCommand::Update(args) => update(ctx, args),
        SecretCommand::Delete(args) => delete(ctx, args),
        SecretCommand::Recover(args) => recover(ctx, args),
        SecretCommand::Purge(args) => purge(ctx, args),
    }
}

fn set(ctx: &Ctx, args: &SecretSetArgs) -> anyhow::Result<()> {
    let options = SetSecretOptions {
        content_type: args.content_type.clone(),
        tags: parse_tags(&args.tags)?,
        enabled: !args.disabled,
        not_before: args
            .not_before
            .as_deref()
            .map(timestamp::parse)
            .transpose()?,
        expires_on: args.expires.as_deref().map(timestamp::parse).transpose()?,
    };
    options.validate()?;
    // Open the vault first so a wrong passphrase is reported before we ask
    // for the value.
    let vault = ctx.open_default()?;
    let value = prompt::read_secret_value(args)?;
    let props = vault.set_secret(&args.name, value, options)?;
    if ctx.json() {
        return output::json(&props);
    }
    output::success(&format!(
        "Stored '{}' as version {} in vault '{}'",
        props.name, props.version, props.vault
    ));
    Ok(())
}

fn get(ctx: &Ctx, args: &SecretGetArgs) -> anyhow::Result<()> {
    let vault = ctx.open_default()?;
    if !args.reveal {
        let props = vault.get_secret_properties(&args.name, args.version.as_deref())?;
        if ctx.json() {
            return output::json(&props);
        }
        output::properties_block(&props)?;
        eprintln!("(value not shown; pass --reveal to print it)");
        return Ok(());
    }
    let secret = vault.get_secret(&args.name, args.version.as_deref())?;
    if ctx.json() {
        let mut body = serde_json::to_value(&secret.properties)?;
        match secret.value.expose_utf8() {
            Some(text) => body["value"] = serde_json::Value::String(text.to_owned()),
            None => {
                body["value_hex"] = serde_json::Value::String(hex_encode(secret.value.expose()));
            }
        }
        return output::json(&body);
    }
    output::print_revealed(&secret.value, args.raw)
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

fn list(ctx: &Ctx, args: &SecretListArgs) -> anyhow::Result<()> {
    let vault = ctx.open_default()?;
    if args.deleted {
        let deleted = vault.list_deleted_secrets()?;
        if ctx.json() {
            return output::json(&deleted);
        }
        if deleted.is_empty() {
            eprintln!("no deleted secrets in vault '{}'", vault.vault_name());
            return Ok(());
        }
        let mut table = Table::new(["NAME", "DELETED", "PURGE AFTER", "VERSION"]);
        for d in deleted {
            table.row([
                d.properties.name.clone(),
                output::fmt_time(d.deleted_on),
                output::fmt_opt_time(d.scheduled_purge_on),
                d.properties.version.clone(),
            ]);
        }
        return table.print();
    }

    let secrets = vault.list_properties_of_secrets()?;
    if ctx.json() {
        return output::json(&secrets);
    }
    if secrets.is_empty() {
        eprintln!(
            "no secrets in vault '{}'\nadd one with: sourceorrery secret set <name> --vault {}",
            vault.vault_name(),
            vault.vault_name()
        );
        return Ok(());
    }
    let now = timestamp::now();
    let mut table = Table::new(["NAME", "STATUS", "VERSION", "UPDATED", "EXPIRES"]);
    for p in secrets {
        table.row([
            p.name.clone(),
            output::status(&p, now).to_owned(),
            p.version.clone(),
            output::fmt_time(p.updated_on),
            output::fmt_opt_time(p.expires_on),
        ]);
    }
    table.print()
}

fn versions(ctx: &Ctx, args: &SecretNameArgs) -> anyhow::Result<()> {
    let vault = ctx.open_default()?;
    let versions = vault.list_properties_of_secret_versions(&args.name)?;
    if ctx.json() {
        return output::json(&versions);
    }
    let now = timestamp::now();
    let mut table = Table::new(["VERSION", "STATUS", "CREATED", "NOT BEFORE", "EXPIRES"]);
    for (i, p) in versions.iter().enumerate() {
        let marker = if i == 0 { " (newest)" } else { "" };
        table.row([
            format!("{}{marker}", p.version),
            output::status(p, now).to_owned(),
            output::fmt_time(p.created_on),
            output::fmt_opt_time(p.not_before),
            output::fmt_opt_time(p.expires_on),
        ]);
    }
    table.print()
}

fn update(ctx: &Ctx, args: &SecretUpdateArgs) -> anyhow::Result<()> {
    let mut update = UpdateSecretProperties::default();
    if args.enable {
        update.enabled = Some(true);
    } else if args.disable {
        update.enabled = Some(false);
    }
    if args.clear_content_type {
        update.content_type = Some(None);
    } else if let Some(ct) = &args.content_type {
        update.content_type = Some(Some(ct.clone()));
    }
    if args.clear_tags {
        update.tags = Some(std::collections::BTreeMap::new());
    } else if !args.tags.is_empty() {
        update.tags = Some(parse_tags(&args.tags)?);
    }
    if args.clear_not_before {
        update.not_before = Some(None);
    } else if let Some(t) = &args.not_before {
        update.not_before = Some(Some(timestamp::parse(t)?));
    }
    if args.clear_expires {
        update.expires_on = Some(None);
    } else if let Some(t) = &args.expires {
        update.expires_on = Some(Some(timestamp::parse(t)?));
    }
    if update.is_empty() {
        return Err(anyhow!(
            "nothing to update: pass --enable/--disable, --content-type, --tag, --not-before or --expires"
        ));
    }
    let vault = ctx.open_default()?;
    let props = vault.update_secret_properties(&args.name, args.version.as_deref(), update)?;
    if ctx.json() {
        return output::json(&props);
    }
    output::success(&format!(
        "Updated '{}' version {} ({})",
        props.name,
        props.version,
        output::status(&props, timestamp::now())
    ));
    Ok(())
}

fn delete(ctx: &Ctx, args: &SecretNameArgs) -> anyhow::Result<()> {
    let vault = ctx.open_default()?;
    let deleted = vault.delete_secret(&args.name)?;
    if ctx.json() {
        return output::json(&deleted);
    }
    if deleted.recovery_id.is_empty() {
        output::success(&format!(
            "Secret '{}' permanently deleted (vault is purgeable)",
            deleted.properties.name
        ));
    } else {
        output::success(&format!(
            "Secret '{}' deleted; recoverable until {} with: sourceorrery secret recover {}",
            deleted.properties.name,
            output::fmt_opt_time(deleted.scheduled_purge_on),
            deleted.properties.name
        ));
    }
    Ok(())
}

fn recover(ctx: &Ctx, args: &SecretNameArgs) -> anyhow::Result<()> {
    let vault = ctx.open_default()?;
    let props = vault.recover_deleted_secret(&args.name)?;
    if ctx.json() {
        return output::json(&props);
    }
    output::success(&format!(
        "Secret '{}' recovered (newest version {})",
        props.name, props.version
    ));
    Ok(())
}

fn purge(ctx: &Ctx, args: &SecretPurgeArgs) -> anyhow::Result<()> {
    let vault = ctx.open_default()?;
    if !args.yes
        && !prompt::confirm(&format!(
            "Permanently purge deleted secret '{}'? This cannot be undone.",
            args.name
        ))?
    {
        return Err(anyhow!("aborted"));
    }
    vault.purge_deleted_secret(&args.name)?;
    if ctx.json() {
        return output::json(&serde_json::json!({ "purged": args.name }));
    }
    output::success(&format!("Secret '{}' purged", args.name));
    Ok(())
}
