//! `sourceorrery audit`

use anyhow::anyhow;
use sourceorrery_core::{AuditOperation, AuditQuery, SecretClient, timestamp};

use crate::cli::AuditArgs;
use crate::context::Ctx;
use crate::output::{self, Table};

pub fn run(ctx: &Ctx, args: &AuditArgs) -> anyhow::Result<()> {
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
