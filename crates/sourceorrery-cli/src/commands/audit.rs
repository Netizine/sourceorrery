//! `sourceorrery audit`
//!
//! The one command that opens a vault *for inspection*: a vault blocked by
//! an unacknowledged audit-log truncation is unlocked here too, so its owner
//! can read the log, verify the chain and acknowledge the truncation. Every
//! other command, and every secret or protector operation, stays refused
//! until that acknowledgement is on the chain.

use anyhow::anyhow;
use sourceorrery_core::{AuditEvent, AuditOperation, AuditQuery, SecretClient, timestamp};
use sourceorrery_storage::{AuditVerification, SqliteVault};

use crate::cli::AuditArgs;
use crate::context::Ctx;
use crate::output::{self, Cell, Table};
use crate::prompt;

pub fn run(ctx: &Ctx, args: &AuditArgs) -> anyhow::Result<()> {
    if args.verify {
        return verify(ctx);
    }
    if args.acknowledge {
        return acknowledge(ctx, args.yes);
    }
    let operation = match &args.operation {
        Some(op) => Some(op.parse::<AuditOperation>().map_err(|err| {
            anyhow!(
                "{err}; valid operations: {}",
                AuditOperation::ALL
                    .iter()
                    .map(|o| o.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?),
        None => None,
    };
    let query = AuditQuery {
        secret_name: args.secret.clone(),
        operation,
        since: args.since.as_deref().map(timestamp::parse).transpose()?,
        limit: Some(args.limit),
    };
    let vault = ctx.inspect_default()?;
    warn_if_blocked(&vault)?;
    let events = vault.audit_events(query)?;
    if ctx.json() {
        return output::json(&events);
    }
    if events.is_empty() {
        eprintln!("no matching audit events");
        return Ok(());
    }
    print_events(&events)
}

fn print_events(events: &[AuditEvent]) -> anyhow::Result<()> {
    let mut table = Table::new([
        "ID",
        "TIME",
        "ACTOR",
        "OPERATION",
        "SECRET",
        "VERSION",
        "OUTCOME",
        "DETAIL",
    ]);
    // Actor, secret, version and detail are text from the file; rows written
    // before unlock can be forged outright. The table escapes them.
    for e in events {
        table.row([
            Cell::from(e.id.to_string()),
            output::fmt_time(e.occurred_on).into(),
            e.actor.to_string().into(),
            e.operation.as_str().to_owned().into(),
            e.secret_name.clone().unwrap_or_else(|| "-".into()).into(),
            e.version.clone().unwrap_or_else(|| "-".into()).into(),
            output::outcome_cell(e.outcome),
            e.detail.clone().unwrap_or_default().into(),
        ]);
    }
    table.print()
}

/// Say on stderr when the vault is blocked by an unacknowledged truncation:
/// besides the `ui` browser's audit view, this command is the only way such
/// a vault opens.
fn warn_if_blocked(vault: &SqliteVault) -> anyhow::Result<()> {
    let pending = vault.unacknowledged_truncations()?;
    if pending.is_empty() {
        return Ok(());
    }
    output::note(&format!(
        "audit log truncation detected and not acknowledged ({}); vault '{}' refuses every \
         other command until you review the surviving history and run \
         `sourceorrery audit --acknowledge`",
        describe_truncations(&pending),
        vault.vault_name()
    ));
    Ok(())
}

fn describe_truncations(events: &[AuditEvent]) -> String {
    events
        .iter()
        .map(|e| {
            format!(
                "event {}: {}",
                e.id,
                output::sanitize(e.detail.as_deref().unwrap_or("no detail"))
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// `audit --verify`: check the hash chain and report. The result is always
/// printed; a chain that is not intact additionally fails the command.
fn verify(ctx: &Ctx) -> anyhow::Result<()> {
    let vault = ctx.inspect_default()?;
    let result = vault.verify_audit_chain()?;
    if ctx.json() {
        output::json(&result)?;
    } else {
        print_verification(&result)?;
    }
    if result.is_intact() {
        return Ok(());
    }
    Err(anyhow!("audit chain is not intact: {}", describe(&result)))
}

/// `audit --acknowledge`: show what was detected, ask, and record the
/// owner's acknowledgement so the vault accepts operations again.
fn acknowledge(ctx: &Ctx, yes: bool) -> anyhow::Result<()> {
    let vault = ctx.inspect_default()?;
    let name = vault.vault_name().to_owned();
    let pending = vault.unacknowledged_truncations()?;
    if pending.is_empty() {
        if ctx.json() {
            return output::json(&serde_json::json!({
                "acknowledged": false,
                "truncations": [],
            }));
        }
        output::note(&format!(
            "vault '{name}' has no unacknowledged audit-log truncation; nothing to do"
        ));
        return Ok(());
    }
    if !ctx.json() {
        eprintln!(
            "The audit log of vault '{name}' was found truncated {} time(s):",
            pending.len()
        );
        print_events(&pending)?;
        output::note(
            "whatever the missing events recorded is gone for good; the surviving history \
             becomes authoritative once acknowledged. Compare it with a backup first.",
        );
    }
    if !yes
        && !prompt::confirm(&format!(
            "Acknowledge {} truncation(s) and unblock vault '{name}'?",
            pending.len()
        ))?
    {
        return Err(anyhow!(
            "aborted; vault '{name}' stays blocked (pass --yes to acknowledge without a prompt)"
        ));
    }
    let ids: Vec<u64> = pending.iter().map(|e| e.id).collect();
    let ack = vault.acknowledge_truncations(&ids)?;
    if ctx.json() {
        return output::json(&ack);
    }
    output::success(&format!(
        "Acknowledged {} truncation(s) of vault '{name}' as event {}; the vault accepts \
         operations again",
        ack.truncations.len(),
        ack.event_id
    ));
    Ok(())
}

fn print_verification(result: &AuditVerification) -> anyhow::Result<()> {
    let mut t = Table::new(["FIELD", "VALUE"]);
    t.row(["rows".into(), result.rows.to_string()]);
    t.row(["keyed".into(), result.keyed.to_string()]);
    t.row(["unkeyed".into(), result.unkeyed.to_string()]);
    t.row([
        "first-broken".into(),
        result
            .first_broken
            .map_or_else(|| "-".to_owned(), |id| id.to_string()),
    ]);
    t.row(["truncations".into(), result.truncations.to_string()]);
    t.row(["unacknowledged".into(), result.unacknowledged.to_string()]);
    t.row([
        "head-valid".into(),
        if result.head_valid { "yes" } else { "no" }.to_owned(),
    ]);
    t.row([
        "result".into(),
        if result.is_intact() {
            "intact".to_owned()
        } else {
            "BROKEN".to_owned()
        },
    ]);
    t.print()?;
    if result.unkeyed > 0 {
        output::note(&format!(
            "{} row(s) were written before the vault was unlocked (failed unlock attempts) \
             and are chained without the vault key; they can be forged but not silently removed",
            result.unkeyed
        ));
    }
    Ok(())
}

fn describe(result: &AuditVerification) -> String {
    let mut parts = Vec::new();
    if let Some(id) = result.first_broken {
        parts.push(format!("chain breaks at event {id}"));
    }
    if result.truncations > 0 {
        parts.push(format!(
            "rows were removed from the end of the log {} time(s); see audit_verify events",
            result.truncations
        ));
    }
    if result.unacknowledged > 0 {
        parts.push(format!(
            "{} of them unacknowledged, so the vault refuses every operation until \
             `sourceorrery audit --acknowledge`",
            result.unacknowledged
        ));
    }
    if !result.head_valid {
        parts.push("chain head does not match the newest keyed row".to_owned());
    }
    parts.join("; ")
}
