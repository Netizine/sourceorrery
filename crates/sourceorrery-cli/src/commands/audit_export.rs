//! `sourceorrery audit export`: the local vault's audit log for a collector.
//!
//! The log goes out oldest first, every event as the metadata-only record
//! `audit` shows, followed by the chain verification, so a collector can
//! tell a complete export from a truncated log. JSON Lines on stdout is the
//! format Vector, Fluent Bit and their kind read without help; OTLP/HTTP
//! (feature `otlp`) posts the same records to a collector that speaks it.
//! `--follow` keeps looking at the log and exports what is new.
//!
//! Reading the log is not itself audited, so following it adds nothing to
//! it; the unlock that opens the vault writes its `vault_open` row as always.

use std::io::Write;
use std::time::Duration;

#[cfg(not(feature = "otlp"))]
use anyhow::anyhow;
use serde::Serialize;
use sourceorrery_core::{AuditEvent, AuditQuery, SecretClient, timestamp};
use sourceorrery_storage::{AuditVerification, SqliteVault};
use time::OffsetDateTime;

use crate::cli::{AuditExportArgs, AuditFormat};
use crate::context::Ctx;

/// One exported event: the audit record with the vault it belongs to.
#[derive(Serialize)]
struct Line<'a> {
    vault: &'a str,
    #[serde(flatten)]
    event: &'a AuditEvent,
}

/// The last line of an export: how many events went out and whether the
/// chain they came from is intact.
#[derive(Serialize)]
struct Trailer<'a> {
    vault: &'a str,
    events: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_id: Option<u64>,
    intact: bool,
    verification: &'a AuditVerification,
}

/// Where exported records go.
trait Sink {
    fn event(&mut self, vault: &str, event: &AuditEvent) -> anyhow::Result<()>;
    fn verification(
        &mut self,
        vault: &str,
        events: u64,
        last_id: Option<u64>,
        verification: &AuditVerification,
    ) -> anyhow::Result<()>;
    /// Send what is buffered.
    fn flush(&mut self) -> anyhow::Result<()>;
}

/// The reader went away (a closed pipe): the export ends quietly.
#[derive(Debug)]
struct Closed;

impl std::fmt::Display for Closed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("output closed")
    }
}

impl std::error::Error for Closed {}

fn io_result(result: std::io::Result<()>) -> anyhow::Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => Err(Closed.into()),
        Err(err) => Err(err.into()),
    }
}

/// JSON Lines on stdout, one object per event, written as they come.
struct Jsonl {
    out: std::io::Stdout,
}

impl Jsonl {
    fn write<T: Serialize>(&mut self, value: &T) -> anyhow::Result<()> {
        let mut line = serde_json::to_vec(value)?;
        line.push(b'\n');
        io_result(self.out.lock().write_all(&line))
    }
}

impl Sink for Jsonl {
    fn event(&mut self, vault: &str, event: &AuditEvent) -> anyhow::Result<()> {
        self.write(&Line { vault, event })
    }

    fn verification(
        &mut self,
        vault: &str,
        events: u64,
        last_id: Option<u64>,
        verification: &AuditVerification,
    ) -> anyhow::Result<()> {
        self.write(&Trailer {
            vault,
            events,
            last_id,
            intact: verification.is_intact(),
            verification,
        })
    }

    fn flush(&mut self) -> anyhow::Result<()> {
        io_result(self.out.lock().flush())
    }
}

pub fn run(ctx: &Ctx, args: &AuditExportArgs) -> anyhow::Result<()> {
    let name = ctx.vault_name()?;
    let since = args.since.as_deref().map(timestamp::parse).transpose()?;
    let vault = ctx.inspect_default()?;
    ctx.check_view(&vault)?;
    let mut sink: Box<dyn Sink> = match args.format {
        AuditFormat::Jsonl => Box::new(Jsonl {
            out: std::io::stdout(),
        }),
        AuditFormat::Otlp => otlp_sink(&name, args)?,
    };
    match export(&vault, &name, since, args, sink.as_mut()) {
        Ok(()) => Ok(()),
        Err(err) if err.is::<Closed>() => Ok(()),
        Err(err) => Err(err),
    }
}

#[cfg(feature = "otlp")]
fn otlp_sink(vault: &str, args: &AuditExportArgs) -> anyhow::Result<Box<dyn Sink>> {
    Ok(Box::new(otlp::Exporter::new(vault, args)?))
}

#[cfg(not(feature = "otlp"))]
fn otlp_sink(_vault: &str, _args: &AuditExportArgs) -> anyhow::Result<Box<dyn Sink>> {
    Err(anyhow!(
        "this build of SourceOrrery has no OTLP exporter (Cargo feature `otlp`); use \
         --format jsonl and a collector that reads JSON Lines"
    ))
}

/// The events at or after `since`, newer than `after_id`, oldest first.
fn fetch(
    vault: &SqliteVault,
    since: Option<OffsetDateTime>,
    after_id: Option<u64>,
) -> anyhow::Result<Vec<AuditEvent>> {
    let mut events = vault.audit_events(AuditQuery {
        since,
        // The backend caps an unbounded query; ask for everything.
        limit: Some(usize::MAX),
        ..AuditQuery::default()
    })?;
    events.reverse();
    if let Some(after) = after_id {
        events.retain(|e| e.id > after);
    }
    Ok(events)
}

fn export(
    vault: &SqliteVault,
    name: &str,
    since: Option<OffsetDateTime>,
    args: &AuditExportArgs,
    sink: &mut dyn Sink,
) -> anyhow::Result<()> {
    let mut count: u64 = 0;
    // The newest event written so far: new ones have a greater id and a
    // time no earlier than its, so the follow-up query asks from that time
    // and drops what it has already seen.
    let mut last: Option<(u64, OffsetDateTime)> = None;
    for event in fetch(vault, since, None)? {
        sink.event(name, &event)?;
        count += 1;
        last = Some((event.id, event.occurred_on));
    }
    let verification = vault.verify_audit_chain()?;
    sink.verification(name, count, last.map(|l| l.0), &verification)?;
    sink.flush()?;
    if !args.follow {
        return Ok(());
    }
    let interval = Duration::from_secs(args.interval.max(1));
    loop {
        std::thread::sleep(interval);
        let fresh = fetch(
            vault,
            last.map(|l| l.1).or(since),
            Some(last.map_or(0, |l| l.0)),
        )?;
        for event in fresh {
            sink.event(name, &event)?;
            last = Some((event.id, event.occurred_on));
        }
        sink.flush()?;
    }
}

/// OTLP/HTTP with the JSON encoding (OpenTelemetry Protocol 1.x,
/// `ExportLogsServiceRequest` at `/v1/logs`), built by hand: the records
/// are small and flat, and a collector that speaks OTLP reads them as log
/// records with the audit fields as attributes.
#[cfg(feature = "otlp")]
mod otlp {
    use std::time::Duration;

    use anyhow::{Context as _, anyhow};
    use serde_json::{Value, json};
    use sourceorrery_core::{AuditEvent, AuditOutcome, timestamp};
    use sourceorrery_storage::AuditVerification;
    use time::OffsetDateTime;

    use super::Sink;
    use crate::cli::AuditExportArgs;
    use crate::output;

    pub struct Exporter {
        client: reqwest::blocking::Client,
        endpoint: String,
        headers: Vec<(String, String)>,
        resource: Value,
        batch: usize,
        pending: Vec<Value>,
    }

    impl Exporter {
        pub fn new(vault: &str, args: &AuditExportArgs) -> anyhow::Result<Self> {
            let endpoint = match &args.endpoint {
                Some(url) => url.clone(),
                None => std::env::var("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
                    .ok()
                    .filter(|v| !v.is_empty())
                    .or_else(|| {
                        std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                            .ok()
                            .filter(|v| !v.is_empty())
                            .map(|base| format!("{}/v1/logs", base.trim_end_matches('/')))
                    })
                    .ok_or_else(|| {
                        anyhow!(
                            "no collector endpoint: pass --endpoint URL or set \
                             OTEL_EXPORTER_OTLP_LOGS_ENDPOINT (or OTEL_EXPORTER_OTLP_ENDPOINT)"
                        )
                    })?,
            };
            if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
                return Err(anyhow!(
                    "the collector endpoint must be an http:// or https:// URL"
                ));
            }
            let mut headers = Vec::new();
            if let Ok(env) = std::env::var("OTEL_EXPORTER_OTLP_HEADERS") {
                for pair in env.split(',').filter(|p| !p.trim().is_empty()) {
                    headers.push(parse_header(pair)?);
                }
            }
            for pair in &args.headers {
                headers.push(parse_header(pair)?);
            }
            let client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .context("cannot build the HTTP client")?;
            Ok(Self {
                client,
                endpoint,
                headers,
                resource: json!({
                    "attributes": [
                        attr("service.name", str_value("sourceorrery")),
                        attr("service.version", str_value(env!("CARGO_PKG_VERSION"))),
                        attr("sourceorrery.vault", str_value(vault)),
                    ]
                }),
                batch: args.batch.max(1),
                pending: Vec::new(),
            })
        }

        fn post(&mut self) -> anyhow::Result<()> {
            if self.pending.is_empty() {
                return Ok(());
            }
            let records = std::mem::take(&mut self.pending);
            let body = json!({
                "resourceLogs": [{
                    "resource": self.resource,
                    "scopeLogs": [{
                        "scope": { "name": "sourceorrery.audit", "version": env!("CARGO_PKG_VERSION") },
                        "logRecords": records,
                    }],
                }],
            });
            let mut request = self
                .client
                .post(&self.endpoint)
                .header("Content-Type", "application/json");
            for (key, value) in &self.headers {
                request = request.header(key.as_str(), value.as_str());
            }
            let response = request
                .body(serde_json::to_vec(&body)?)
                .send()
                .with_context(|| format!("cannot reach the collector at {}", self.endpoint))?;
            let status = response.status();
            if !status.is_success() {
                let text = response.text().unwrap_or_default();
                let snippet: String = text.chars().take(200).collect();
                return Err(anyhow!(
                    "the collector at {} answered {status}: {}",
                    self.endpoint,
                    output::sanitize(&snippet)
                ));
            }
            Ok(())
        }
    }

    fn parse_header(pair: &str) -> anyhow::Result<(String, String)> {
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| anyhow!("header '{}' is not KEY=VALUE", output::sanitize(pair)))?;
        let key = key.trim();
        if key.is_empty() {
            return Err(anyhow!("a header needs a name"));
        }
        Ok((key.to_owned(), value.trim().to_owned()))
    }

    fn attr(key: &str, value: Value) -> Value {
        let mut pair = serde_json::Map::with_capacity(2);
        pair.insert("key".to_owned(), Value::String(key.to_owned()));
        pair.insert("value".to_owned(), value);
        Value::Object(pair)
    }

    fn str_value(text: &str) -> Value {
        json!({ "stringValue": text })
    }

    fn int_value(n: u64) -> Value {
        // OTLP/JSON carries 64-bit integers as decimal strings.
        json!({ "intValue": n.to_string() })
    }

    fn bool_value(b: bool) -> Value {
        json!({ "boolValue": b })
    }

    fn severity(outcome: AuditOutcome) -> (u8, &'static str) {
        match outcome {
            AuditOutcome::Success => (9, "INFO"),
            AuditOutcome::Denied => (13, "WARN"),
            AuditOutcome::Failure => (17, "ERROR"),
        }
    }

    fn record(
        time: OffsetDateTime,
        severity: (u8, &str),
        body: &str,
        attributes: Vec<Value>,
    ) -> Value {
        json!({
            "timeUnixNano": timestamp::to_unix_nanos(time).to_string(),
            "observedTimeUnixNano": timestamp::to_unix_nanos(timestamp::now()).to_string(),
            "severityNumber": severity.0,
            "severityText": severity.1,
            "body": str_value(body),
            "attributes": Value::Array(attributes),
        })
    }

    impl Sink for Exporter {
        fn event(&mut self, vault: &str, event: &AuditEvent) -> anyhow::Result<()> {
            let mut attributes = vec![
                attr("sourceorrery.vault", str_value(vault)),
                attr("sourceorrery.event.id", int_value(event.id)),
                attr(
                    "sourceorrery.operation",
                    str_value(event.operation.as_str()),
                ),
                attr("sourceorrery.outcome", str_value(event.outcome.as_str())),
                attr("sourceorrery.actor", str_value(&event.actor.to_string())),
            ];
            if let Some(secret) = &event.secret_name {
                attributes.push(attr("sourceorrery.secret", str_value(secret)));
            }
            if let Some(version) = &event.version {
                attributes.push(attr("sourceorrery.version", str_value(version)));
            }
            if let Some(detail) = &event.detail {
                attributes.push(attr("sourceorrery.detail", str_value(detail)));
            }
            let body = match &event.secret_name {
                Some(secret) => format!("{} {} {secret}", event.operation, event.outcome),
                None => format!("{} {}", event.operation, event.outcome),
            };
            self.pending.push(record(
                event.occurred_on,
                severity(event.outcome),
                &body,
                attributes,
            ));
            if self.pending.len() >= self.batch {
                self.post()?;
            }
            Ok(())
        }

        fn verification(
            &mut self,
            vault: &str,
            events: u64,
            last_id: Option<u64>,
            verification: &AuditVerification,
        ) -> anyhow::Result<()> {
            let intact = verification.is_intact();
            let mut attributes = vec![
                attr("sourceorrery.vault", str_value(vault)),
                attr("sourceorrery.audit.intact", bool_value(intact)),
                attr("sourceorrery.audit.rows", int_value(verification.rows)),
                attr("sourceorrery.audit.keyed", int_value(verification.keyed)),
                attr(
                    "sourceorrery.audit.unkeyed",
                    int_value(verification.unkeyed),
                ),
                attr(
                    "sourceorrery.audit.truncations",
                    int_value(verification.truncations),
                ),
                attr(
                    "sourceorrery.audit.unacknowledged",
                    int_value(verification.unacknowledged),
                ),
                attr(
                    "sourceorrery.audit.head_valid",
                    bool_value(verification.head_valid),
                ),
                attr("sourceorrery.audit.exported", int_value(events)),
            ];
            if let Some(id) = verification.first_broken {
                attributes.push(attr("sourceorrery.audit.first_broken", int_value(id)));
            }
            if let Some(id) = last_id {
                attributes.push(attr("sourceorrery.audit.last_id", int_value(id)));
            }
            let (level, text) = if intact {
                ("intact", (9, "INFO"))
            } else {
                ("broken", (17, "ERROR"))
            };
            self.pending.push(record(
                timestamp::now(),
                text,
                &format!("audit chain verification: {level}"),
                attributes,
            ));
            Ok(())
        }

        fn flush(&mut self) -> anyhow::Result<()> {
            self.post()
        }
    }
}
