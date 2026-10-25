//! `sourceorrery secret ...`

use anyhow::anyhow;
use sourceorrery_core::{
    ContinuationToken, ListOptions, SecretClient, SetSecretOptions, UpdateSecretProperties,
    timestamp,
};

use crate::cli::{
    SecretCommand, SecretGetArgs, SecretListArgs, SecretNameArgs, SecretPurgeArgs, SecretSetArgs,
    SecretUpdateArgs,
};
use sourceorrery_storage::SecretStorage;

use crate::commands::{connections, parse_tags};
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
        SecretCommand::Rotate(args) => crate::commands::rotate::rotate(ctx, args),
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
    if let Some(description) = &args.description {
        sourceorrery_storage::validate_description(description)?;
    }
    // Open the vault, and find the storage, first, so that what cannot be
    // done is reported before we ask for the value.
    let vault = ctx.open_default()?;
    let storage = args
        .storage
        .as_deref()
        .map(|value| connections::storage(vault.vault(), value))
        .transpose()?;
    let value = prompt::read_secret_value(args)?;
    let props = match &storage {
        Some(storage) => vault.set_secret_in(storage, &args.name, value, options)?,
        None => vault.set_secret(&args.name, value, options)?,
    };
    if let Some(description) = &args.description {
        vault
            .vault()
            .set_description(&props.name, Some(description))?;
    }
    if ctx.json() {
        let mut body = serde_json::to_value(&props)?;
        if let Some(description) = &args.description {
            body["description"] = serde_json::Value::String(description.clone());
        }
        return output::json(&body);
    }
    let at = match vault.vault().storage_of(&props.name)? {
        Some(SecretStorage::Connection(id)) => vault
            .vault()
            .connection(&id)
            .map(|c| format!(" (kept at {})", c.settings.provider().display_name()))
            .unwrap_or_default(),
        _ => String::new(),
    };
    output::success(&format!(
        "Stored '{}' as version {} in vault '{}'{at}",
        props.name, props.version, props.vault
    ));
    Ok(())
}

fn get(ctx: &Ctx, args: &SecretGetArgs) -> anyhow::Result<()> {
    let vault = ctx.open_default()?;
    // Viewing a secret, and above all revealing it, is what the view
    // check is for; the application's reads (`run`, the SDKs) are not
    // asked.
    ctx.check_view_opened(&vault)?;
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
    ctx.check_view_opened(&vault)?;
    // Without --limit or --after the whole listing is one call and, in JSON,
    // one array, as before; with either, one page and its continuation.
    let paged = args.limit.is_some() || args.after.is_some();
    let options = ListOptions {
        max_results: args.limit,
        continuation: args.after.clone().map(ContinuationToken::new),
    };
    if args.deleted {
        let page = vault.list_deleted_secrets_page(options)?;
        if ctx.json() {
            return if paged {
                output::json(&page)
            } else {
                output::json(&page.items)
            };
        }
        if page.items.is_empty() && page.continuation.is_none() {
            if paged {
                eprintln!("no more deleted secrets in vault '{}'", vault.vault_name());
            } else {
                eprintln!("no deleted secrets in vault '{}'", vault.vault_name());
            }
            return Ok(());
        }
        if !page.items.is_empty() {
            let mut table = Table::new(["NAME", "DELETED", "PURGE AFTER", "VERSION"]);
            for d in &page.items {
                table.row([
                    d.properties.name.clone(),
                    output::fmt_time(d.deleted_on),
                    output::fmt_opt_time(d.scheduled_purge_on),
                    d.properties.version.clone(),
                ]);
            }
            table.print()?;
        }
        continuation_hint(page.continuation.as_ref(), args.limit, "--deleted ");
        return Ok(());
    }

    let page = vault.list_properties_of_secrets_page(options)?;
    if ctx.json() {
        return if paged {
            output::json(&page)
        } else {
            output::json(&page.items)
        };
    }
    if page.items.is_empty() && page.continuation.is_none() {
        if paged {
            eprintln!("no more secrets in vault '{}'", vault.vault_name());
        } else {
            eprintln!(
                "no secrets in vault '{}'\nadd one with: sourceorrery secret set <name> --vault {}",
                vault.vault_name(),
                vault.vault_name()
            );
        }
        return Ok(());
    }
    if !page.items.is_empty() {
        let now = timestamp::now();
        let mut table = Table::new(["NAME", "STATUS", "VERSION", "UPDATED", "EXPIRES"]);
        for p in &page.items {
            table.row([
                p.name.clone(),
                output::status(p, now).to_owned(),
                p.version.clone(),
                output::fmt_time(p.updated_on),
                output::fmt_opt_time(p.expires_on),
            ]);
        }
        table.print()?;
    }
    continuation_hint(page.continuation.as_ref(), args.limit, "");
    Ok(())
}

/// After a page that is not the last, say how to get the next one. (A page
/// can be empty and still have a token: the names after it may all belong
/// to the other listing.)
fn continuation_hint(token: Option<&ContinuationToken>, limit: Option<usize>, flags: &str) {
    if let Some(token) = token {
        let limit = limit.map(|n| format!("--limit {n} ")).unwrap_or_default();
        output::note(&format!(
            "more secrets follow; continue with: sourceorrery secret list {flags}{limit}--after {token}"
        ));
    }
}
fn versions(ctx: &Ctx, args: &SecretNameArgs) -> anyhow::Result<()> {
    let vault = ctx.open_default()?;
    ctx.check_view_opened(&vault)?;
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
