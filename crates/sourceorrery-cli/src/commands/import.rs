//! `sourceorrery import`: move a `.env` file into a vault.
//!
//! Every value goes from the file straight into the vault as a secret; the
//! command prints key names, secret names and outcomes, never a value, so a
//! person or a coding agent can migrate a project without the values
//! passing through a terminal, a log or a model's context. Each key is
//! declared in `sourceorrery.toml`, with an explicit `env` when the default
//! name would not deliver the original variable.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, anyhow};
use serde::Serialize;
use sourceorrery_core::manifest::{explicit_env_for, secret_name_for_env};
use sourceorrery_core::{
    MANIFEST_FILE_NAME, Manifest, SecretClient, SecretError, SetSecretOptions,
};
use sourceorrery_storage::SqliteVault;
use zeroize::Zeroizing;

use crate::cli::ImportArgs;
use crate::commands::project::MANIFEST_HEADER;
use crate::context::Ctx;
use crate::dotenv::{self, Assignment};
use crate::output::{self, Table};

/// What happened to one key.
#[derive(Serialize)]
struct Row {
    key: String,
    line: usize,
    secret: Option<String>,
    env: Option<String>,
    vault: Cow<'static, str>,
    manifest: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    #[serde(skip)]
    failed: bool,
}

/// Where the manifest is and what it already declares.
struct ManifestPlan {
    path: PathBuf,
    /// `None` when the file does not exist yet.
    existing: Option<(String, Manifest)>,
}

pub fn run(ctx: &Ctx, args: &ImportArgs) -> anyhow::Result<()> {
    let assignments = read_file(&args.file)?;
    check_duplicates(&assignments)?;
    let selected = select(&assignments, &args.only, &args.exclude)?;
    let source = args
        .file
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(".env")
        .to_owned();

    let manifest = if args.no_manifest {
        None
    } else {
        Some(locate_manifest(args.manifest.as_deref())?)
    };
    let vault_name = ctx
        .vault_flag
        .clone()
        .or_else(|| {
            manifest
                .as_ref()
                .and_then(|m| m.existing.as_ref())
                .map(|(_, parsed)| parsed.project.vault.clone())
        })
        .unwrap_or_else(|| "development".to_owned());

    let mut rows = plan_rows(&selected, manifest.as_ref())?;
    check_secret_collisions(&rows)?;
    // Validate the manifest as it would end up before anything is stored,
    // so a conflict leaves both the vault and the file untouched.
    if let Some(plan) = &manifest {
        let candidate: Vec<&Row> = rows.iter().filter(|r| r.manifest == "add").collect();
        render_manifest(plan, &vault_name, &candidate, &source)?;
    }

    let vault = if args.manifest_only {
        None
    } else {
        open_vault(ctx, &vault_name, args.dry_run)?
    };
    for (row, assignment) in rows.iter_mut().zip(&selected) {
        store(row, assignment, vault.as_ref(), args, &vault_name, &source);
    }

    let mut manifest_written = None;
    if let Some(plan) = &manifest {
        let additions: Vec<&Row> = rows
            .iter()
            .filter(|r| r.manifest == "add" && !r.failed && r.vault != "skipped")
            .collect();
        let text = if !args.dry_run && (!additions.is_empty() || plan.existing.is_none()) {
            Some(render_manifest(plan, &vault_name, &additions, &source)?)
        } else {
            None
        };
        for row in &mut rows {
            if row.manifest == "add" {
                row.manifest = if row.failed || row.vault == "skipped" {
                    "-"
                } else if args.dry_run {
                    "would add"
                } else {
                    "added"
                };
            }
        }
        if let Some(text) = text {
            std::fs::write(&plan.path, text)
                .with_context(|| format!("cannot write {}", plan.path.display()))?;
            manifest_written = Some(plan.path.clone());
        }
    }

    report(
        ctx,
        args,
        &rows,
        &vault_name,
        manifest.as_ref(),
        manifest_written.as_deref(),
    )
}

fn read_file(path: &Path) -> anyhow::Result<Vec<Assignment>> {
    let bytes = Zeroizing::new(
        std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?,
    );
    let text =
        std::str::from_utf8(&bytes).map_err(|_| anyhow!("{} is not UTF-8 text", path.display()))?;
    dotenv::parse(text).map_err(|err| anyhow!("{}: {err}", path.display()))
}

fn check_duplicates(assignments: &[Assignment]) -> anyhow::Result<()> {
    let mut lines: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for a in assignments {
        lines.entry(&a.key).or_default().push(a.line);
    }
    let duplicates: Vec<String> = lines
        .into_iter()
        .filter(|(_, l)| l.len() > 1)
        .map(|(key, l)| {
            let l: Vec<String> = l.iter().map(ToString::to_string).collect();
            format!("{key} (lines {})", l.join(", "))
        })
        .collect();
    if duplicates.is_empty() {
        return Ok(());
    }
    Err(anyhow!(
        "these keys are assigned more than once, and loaders disagree on which one wins: {}. \
         Keep one assignment of each and import again",
        duplicates.join("; ")
    ))
}

fn select<'a>(
    assignments: &'a [Assignment],
    only: &[String],
    exclude: &[String],
) -> anyhow::Result<Vec<&'a Assignment>> {
    let present: BTreeSet<&str> = assignments.iter().map(|a| a.key.as_str()).collect();
    let unknown: Vec<&str> = only
        .iter()
        .chain(exclude)
        .map(String::as_str)
        .filter(|k| !present.contains(k))
        .collect();
    if !unknown.is_empty() {
        return Err(anyhow!("not in the file: {}", unknown.join(", ")));
    }
    Ok(assignments
        .iter()
        .filter(|a| only.is_empty() || only.contains(&a.key))
        .filter(|a| !exclude.contains(&a.key))
        .collect())
}

fn locate_manifest(explicit: Option<&Path>) -> anyhow::Result<ManifestPlan> {
    let cwd = std::env::current_dir().context("cannot determine current directory")?;
    let path = match explicit {
        Some(path) => path.to_path_buf(),
        None => Manifest::discover(&cwd).unwrap_or_else(|| cwd.join(MANIFEST_FILE_NAME)),
    };
    let existing = if path.is_file() {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        let parsed = Manifest::load(&path)?;
        Some((text, parsed))
    } else {
        None
    };
    Ok(ManifestPlan { path, existing })
}

fn plan_rows(
    selected: &[&Assignment],
    manifest: Option<&ManifestPlan>,
) -> anyhow::Result<Vec<Row>> {
    let declared = manifest
        .and_then(|m| m.existing.as_ref())
        .map(|(_, parsed)| parsed.entries())
        .transpose()?
        .unwrap_or_default();
    Ok(selected
        .iter()
        .map(|a| {
            let mut row = Row {
                key: a.key.clone(),
                line: a.line,
                secret: None,
                env: None,
                vault: Cow::Borrowed(""),
                manifest: if manifest.is_some() { "add" } else { "-" },
                note: None,
                failed: false,
            };
            let Some(secret) = secret_name_for_env(&a.key) else {
                row.vault = Cow::Borrowed("skipped");
                row.manifest = "-";
                row.note = Some(invalid_key_reason(&a.key));
                return row;
            };
            if let Some(entry) = declared.iter().find(|e| e.name == secret) {
                row.manifest = "already declared";
                if entry.env != a.key {
                    row.note = Some(format!(
                        "the manifest delivers this secret as {}, not {}",
                        entry.env, a.key
                    ));
                }
            } else if let Some(entry) = declared.iter().find(|e| e.env == a.key) {
                row.manifest = "already declared";
                row.note = Some(format!(
                    "{} is already delivered from the secret {}",
                    a.key, entry.name
                ));
            }
            row.env = explicit_env_for(&secret, &a.key);
            row.secret = Some(secret);
            if a.references_variable {
                row.note = Some(
                    "the value contains ${...}; it is stored as written, not expanded".to_owned(),
                );
            }
            row
        })
        .collect())
}

fn invalid_key_reason(key: &str) -> String {
    if key
        .to_ascii_uppercase()
        .starts_with(sourceorrery_core::manifest::RESERVED_ENV_PREFIX)
    {
        "names starting with SOURCEORRERY_ belong to SourceOrrery".to_owned()
    } else if key.len() > 127 {
        "longer than a secret name may be (127 characters)".to_owned()
    } else {
        "not a valid environment variable name (letters, digits and _, not starting with a digit)"
            .to_owned()
    }
}

fn check_secret_collisions(rows: &[Row]) -> anyhow::Result<()> {
    let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
    for row in rows {
        if let Some(secret) = &row.secret
            && let Some(previous) = seen.insert(secret, &row.key)
        {
            return Err(anyhow!(
                "{previous} and {} would both become the secret '{secret}' (names are compared \
                 case-insensitively); rename one and import again",
                row.key
            ));
        }
    }
    Ok(())
}

/// Open the vault; in a dry run a vault that does not exist yet is not an error.
fn open_vault(ctx: &Ctx, name: &str, dry_run: bool) -> anyhow::Result<Option<SqliteVault>> {
    match ctx.open(name) {
        Ok(vault) => Ok(Some(vault)),
        Err(err) => match err.downcast_ref::<SecretError>() {
            Some(SecretError::VaultNotFound { .. }) if dry_run => {
                output::note(&format!(
                    "vault '{name}' does not exist yet; create it with `sourceorrery vault create {name}`"
                ));
                Ok(None)
            }
            Some(SecretError::VaultNotFound { .. }) => Err(err.context(format!(
                "create it first with `sourceorrery vault create {name}`, or pass --vault"
            ))),
            _ => Err(err),
        },
    }
}

fn store(
    row: &mut Row,
    assignment: &Assignment,
    vault: Option<&SqliteVault>,
    args: &ImportArgs,
    vault_name: &str,
    source: &str,
) {
    let Some(secret) = row.secret.clone() else {
        return;
    };
    if args.manifest_only {
        row.vault = Cow::Borrowed("not stored (--manifest-only)");
        return;
    }
    if assignment.value.is_empty() {
        row.vault = Cow::Borrowed("skipped");
        row.note = Some("the value is empty".to_owned());
        return;
    }
    let Some(vault) = vault else {
        row.vault = Cow::Owned(format!("would store in '{vault_name}'"));
        return;
    };
    match vault.get_secret_properties(&secret, None) {
        Ok(_) if !args.overwrite => {
            row.vault = Cow::Borrowed("already in vault");
            if row.note.is_none() {
                row.note =
                    Some("left as it is; pass --overwrite to store a new version".to_owned());
            }
            return;
        }
        Ok(_) | Err(SecretError::NotFound { .. }) => {}
        Err(err) => {
            row.vault = Cow::Borrowed(err.code());
            row.note = Some(err.to_string());
            row.failed = true;
            return;
        }
    }
    if args.dry_run {
        row.vault = Cow::Borrowed(if args.overwrite {
            "would store a new version"
        } else {
            "would store"
        });
        return;
    }
    let options = SetSecretOptions {
        tags: BTreeMap::from([("imported-from".to_owned(), source.to_owned())]),
        ..SetSecretOptions::default()
    };
    match vault.set_secret(&secret, assignment.value.clone(), options) {
        Ok(_) => row.vault = Cow::Borrowed("stored"),
        Err(err) => {
            row.vault = Cow::Borrowed(err.code());
            row.note = Some(err.to_string());
            row.failed = true;
        }
    }
}

/// The manifest text with `rows` declared: the existing file with entries
/// appended (its comments and layout kept), or a new manifest. The result
/// is parsed before it is returned.
fn render_manifest(
    plan: &ManifestPlan,
    vault: &str,
    rows: &[&Row],
    source: &str,
) -> anyhow::Result<String> {
    let mut text = match &plan.existing {
        Some((text, _)) => text.clone(),
        None => format!(
            "{MANIFEST_HEADER}[project]\nname = {}\nvault = {}\n",
            toml::Value::from(project_name(&plan.path)),
            toml::Value::from(vault)
        ),
    };
    if !text.ends_with('\n') {
        text.push('\n');
    }
    for row in rows {
        let Some(secret) = &row.secret else { continue };
        writeln!(text, "\n[secrets.{secret}]")?;
        if let Some(env) = &row.env {
            writeln!(text, "env = {}", toml::Value::from(env.as_str()))?;
        }
        writeln!(
            text,
            "purpose = {}",
            toml::Value::from(format!("Imported from {source}"))
        )?;
    }
    Manifest::parse(&text).map_err(|err| {
        anyhow!(
            "{}: the updated manifest would be invalid: {err}",
            plan.path.display()
        )
    })?;
    Ok(text)
}

fn project_name(manifest_path: &Path) -> String {
    manifest_path
        .parent()
        .and_then(Path::file_name)
        .and_then(|n| n.to_str())
        .unwrap_or("my-application")
        .to_owned()
}

fn report(
    ctx: &Ctx,
    args: &ImportArgs,
    rows: &[Row],
    vault: &str,
    manifest: Option<&ManifestPlan>,
    written: Option<&Path>,
) -> anyhow::Result<()> {
    let failed = rows.iter().filter(|r| r.failed).count();
    let skipped = rows.iter().filter(|r| r.vault == "skipped").count();
    if ctx.json() {
        output::json(&serde_json::json!({
            "file": args.file,
            "vault": if args.manifest_only { None } else { Some(vault) },
            "manifest": manifest.map(|m| &m.path),
            "dry_run": args.dry_run,
            "keys": rows,
            "failed": failed,
            "skipped": skipped,
        }))?;
    } else {
        let mut table = Table::new(["KEY", "SECRET", "VAULT", "MANIFEST", "NOTE"]);
        for row in rows {
            let secret = match (&row.secret, &row.env) {
                (Some(s), Some(env)) => format!("{s} (env {env})"),
                (Some(s), None) => s.clone(),
                (None, _) => "-".to_owned(),
            };
            table.row([
                row.key.clone(),
                secret,
                row.vault.to_string(),
                row.manifest.to_owned(),
                row.note.clone().unwrap_or_default(),
            ]);
        }
        table.print()?;
        if let Some(path) = written {
            output::success(&format!("Updated {}", path.display()));
        }
        if args.dry_run {
            output::note("dry run: nothing was stored or written");
        } else if failed == 0 {
            eprintln!(
                "next:\n  sourceorrery check\n  update the code that reads these variables \
                 (or start it with `sourceorrery run -- <command>`)\n  then delete {} and keep \
                 .env files out of git",
                args.file.display()
            );
        }
    }
    if failed > 0 {
        return Err(anyhow!("{failed} key(s) could not be stored"));
    }
    Ok(())
}
