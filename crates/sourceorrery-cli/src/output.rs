//! Terminal output: tables, JSON, status lines. Nothing here ever receives a
//! secret value except [`print_revealed`], which exists so the disclosure is
//! a single, deliberate call site.

use std::io::Write;

use owo_colors::{OwoColorize, Stream};
use serde::Serialize;
use sourceorrery_core::{AuditOutcome, SecretBytes, SecretProperties, policy, timestamp};
use time::OffsetDateTime;

use crate::cli::OutputFormat;

/// Print `✓ message` to stderr so stdout stays clean for data.
pub fn success(message: &str) {
    let tick = "✓"
        .if_supports_color(Stream::Stderr, |t| t.green())
        .to_string();
    eprintln!("{tick} {message}");
}

/// Print `! message` to stderr.
pub fn note(message: &str) {
    let mark = "!"
        .if_supports_color(Stream::Stderr, |t| t.yellow())
        .to_string();
    eprintln!("{mark} {message}");
}

/// Print an error to stderr in the selected format.
pub fn print_error(format: OutputFormat, code: &str, message: &str) {
    match format {
        OutputFormat::Json => {
            let body = serde_json::json!({ "error": { "code": code, "message": message } });
            eprintln!("{body}");
        }
        OutputFormat::Table => {
            let label = "error"
                .if_supports_color(Stream::Stderr, |t| t.red())
                .to_string();
            eprintln!("{label}: {message}");
            if code == "locked" {
                eprintln!(
                    "hint: unlock with the OS credential store, a passphrase prompt, \
                     --passphrase-file, or SOURCEORRERY_PASSPHRASE"
                );
            }
        }
    }
}

/// Print any serialisable value as pretty JSON on stdout.
pub fn json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, value)?;
    stdout.write_all(b"\n")?;
    Ok(())
}

/// A simple left-aligned text table.
#[derive(Debug, Default)]
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    pub fn new<const N: usize>(headers: [&str; N]) -> Self {
        Self {
            headers: headers.iter().map(|h| (*h).to_owned()).collect(),
            rows: Vec::new(),
        }
    }

    pub fn row<const N: usize>(&mut self, cells: [String; N]) -> &mut Self {
        self.rows.push(cells.into_iter().collect());
        self
    }

    pub fn print(&self) -> anyhow::Result<()> {
        let mut widths: Vec<usize> = self.headers.iter().map(|h| h.chars().count()).collect();
        for row in &self.rows {
            for (i, cell) in row.iter().enumerate() {
                widths[i] = widths[i].max(cell.chars().count());
            }
        }
        let mut out = std::io::stdout().lock();
        let header = format_row(&self.headers, &widths);
        writeln!(
            out,
            "{}",
            header.if_supports_color(Stream::Stdout, |t| t.bold())
        )?;
        for row in &self.rows {
            writeln!(out, "{}", format_row(row, &widths))?;
        }
        Ok(())
    }
}

fn format_row(cells: &[String], widths: &[usize]) -> String {
    let mut line = String::new();
    let last = cells.len().saturating_sub(1);
    for (i, cell) in cells.iter().enumerate() {
        if i == last {
            line.push_str(cell);
        } else {
            let pad = widths[i] - cell.chars().count();
            line.push_str(cell);
            line.extend(std::iter::repeat_n(' ', pad + 2));
        }
    }
    line.trim_end().to_owned()
}

/// Human status of a version at `now`.
pub fn status(props: &SecretProperties, now: OffsetDateTime) -> &'static str {
    match policy::evaluate_access(props, now) {
        Ok(()) => "enabled",
        Err(err) => match err.code() {
            "disabled" => "disabled",
            "not_yet_valid" => "pending",
            "expired" => "expired",
            _ => "unavailable",
        },
    }
}

pub fn fmt_time(ts: OffsetDateTime) -> String {
    timestamp::format(ts)
}

pub fn fmt_opt_time(ts: Option<OffsetDateTime>) -> String {
    ts.map_or_else(|| "-".to_owned(), fmt_time)
}

pub fn fmt_outcome(outcome: AuditOutcome) -> String {
    let text = outcome.as_str();
    match outcome {
        AuditOutcome::Success => text.to_owned(),
        AuditOutcome::Denied => text
            .if_supports_color(Stream::Stdout, |t| t.yellow())
            .to_string(),
        AuditOutcome::Failure => text
            .if_supports_color(Stream::Stdout, |t| t.red())
            .to_string(),
    }
}

/// Print a secret's metadata as a key/value block.
pub fn properties_block(props: &SecretProperties) -> anyhow::Result<()> {
    let now = timestamp::now();
    let mut t = Table::new(["FIELD", "VALUE"]);
    t.row(["name".into(), props.name.clone()]);
    t.row(["vault".into(), props.vault.clone()]);
    t.row(["version".into(), props.version.clone()]);
    t.row(["status".into(), status(props, now).to_owned()]);
    t.row([
        "content-type".into(),
        props.content_type.clone().unwrap_or_else(|| "-".into()),
    ]);
    t.row(["not-before".into(), fmt_opt_time(props.not_before)]);
    t.row(["expires".into(), fmt_opt_time(props.expires_on)]);
    t.row(["created".into(), fmt_time(props.created_on)]);
    t.row(["updated".into(), fmt_time(props.updated_on)]);
    let tags = if props.tags.is_empty() {
        "-".to_owned()
    } else {
        props
            .tags
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    t.row(["tags".into(), tags]);
    t.row(["reference".into(), props.id()]);
    t.print()
}

/// The one place a secret value reaches stdout.
pub fn print_revealed(value: &SecretBytes, raw: bool) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(value.expose())?;
    if !raw {
        stdout.write_all(b"\n")?;
    }
    stdout.flush()?;
    Ok(())
}
