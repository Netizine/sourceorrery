//! `sourceorrery audit`

use anyhow::anyhow;
use sourceorrery_core::{AuditOperation, AuditQuery, SecretClient, timestamp};
use sourceorrery_storage::AuditVerification;

use crate::cli::AuditArgs;
use crate::context::Ctx;
use crate::output::{self, Table};

pub fn run(ctx: &Ctx, args: &AuditArgs) -> anyhow::Result<()> {
    if args.verify {
        return verify(ctx);
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
    let vault = ctx.open_default()?;
    let events = vault.audit_events(query)?;
    if ctx.json() {
        return output::json(&events);
    }
    if events.is_empty() {
        eprintln!("no matching audit events");
        return Ok(());
    }
    let mut table = Table::new([
        "TIME",
        "ACTOR",
        "OPERATION",
        "SECRET",
        "VERSION",
        "OUTCOME",
        "DETAIL",
    ]);
    for e in events {
        table.row([
            output::fmt_time(e.occurred_on),
            e.actor.to_string(),
            e.operation.as_str().to_owned(),
            e.secret_name.unwrap_or_else(|| "-".into()),
            e.version.unwrap_or_else(|| "-".into()),
            output::fmt_outcome(e.outcome),
            e.detail.unwrap_or_default(),
        ]);
    }
    table.print()
}

/// `audit --verify`: check the hash chain and report. The result is always
/// printed; a chain that is not intact additionally fails the command.
fn verify(ctx: &Ctx) -> anyhow::Result<()> {
    let vault = ctx.open_default()?;
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
    if !result.head_valid {
        parts.push("chain head does not match the newest keyed row".to_owned());
    }
    parts.join("; ")
}
