//! `sourceorrery backup` and `sourceorrery restore`: an encrypted export of
//! a vault's secrets, and its import into a vault.
//!
//! Values travel from the vault into the sealed file and back without
//! being printed: the commands report names and counts only. The backup
//! passphrase is never a command-line argument; it comes from
//! `SOURCEORRERY_BACKUP_PASSPHRASE` or a hidden prompt.

use std::io::IsTerminal as _;
use std::path::Path;

use anyhow::{Context as _, anyhow};
use serde::Serialize;
use sourceorrery_core::{
    ExportOptions, RestoreOptions, RestoreReport, SecretBytes, SecretClient, SkipReason, Snapshot,
    VaultBackup,
};
use sourceorrery_storage::{Argon2Params, backup};

use crate::cli::{BackupArgs, RestoreArgs};
use crate::context::Ctx;
use crate::output::{self, Table};
use crate::prompt;

/// Environment variable holding the backup passphrase, for scripts.
pub const BACKUP_PASSPHRASE_ENV: &str = "SOURCEORRERY_BACKUP_PASSPHRASE";

fn passphrase_from_env() -> Option<SecretBytes> {
    std::env::var(BACKUP_PASSPHRASE_ENV)
        .ok()
        .filter(|v| !v.is_empty())
        .map(SecretBytes::from_string)
}

/// The passphrase a new backup is sealed under: the environment, or a
/// prompt answered twice.
fn new_backup_passphrase() -> anyhow::Result<SecretBytes> {
    if let Some(pass) = passphrase_from_env() {
        return Ok(pass);
    }
    if !std::io::stdin().is_terminal() {
        return Err(anyhow!(
            "cannot prompt for the backup passphrase: stdin is not a terminal. Set {BACKUP_PASSPHRASE_ENV}."
        ));
    }
    let first = prompt::read_hidden("Choose a passphrase for the backup: ")?;
    let second = prompt::read_hidden("Confirm passphrase: ")?;
    if first != second {
        return Err(anyhow!("passphrases do not match"));
    }
    if first.is_empty() {
        return Err(anyhow!("passphrase must not be empty"));
    }
    Ok(first)
}

/// The passphrase of an existing backup: the environment, or one prompt.
fn existing_backup_passphrase() -> anyhow::Result<SecretBytes> {
    if let Some(pass) = passphrase_from_env() {
        return Ok(pass);
    }
    if !std::io::stdin().is_terminal() {
        return Err(anyhow!(
            "cannot prompt for the backup passphrase: stdin is not a terminal. Set {BACKUP_PASSPHRASE_ENV}."
        ));
    }
    prompt::read_hidden("Backup passphrase: ")
}

#[derive(Serialize)]
struct BackedUp {
    name: String,
    versions: usize,
    deleted: bool,
}

#[derive(Serialize)]
struct BackupReport {
    vault: String,
    file: String,
    secrets: Vec<BackedUp>,
}

pub fn backup(ctx: &Ctx, args: &BackupArgs) -> anyhow::Result<()> {
    if args.out.exists() && !args.force {
        return Err(anyhow!(
            "{} exists; pass --force to replace it",
            args.out.display()
        ));
    }
    let vault = ctx.open_local_default("backup")?;
    let passphrase = new_backup_passphrase()?;
    let snapshot = vault.export(&ExportOptions {
        secrets: (!args.secret.is_empty()).then(|| args.secret.clone()),
        include_deleted: args.include_deleted,
    })?;
    let bytes = backup::seal(&snapshot, &passphrase, Argon2Params::default())?;
    drop(passphrase);
    write_private(&args.out, &bytes)?;

    let report = BackupReport {
        vault: vault.vault_name().to_owned(),
        file: args.out.display().to_string(),
        secrets: snapshot
            .secrets
            .iter()
            .map(|s| BackedUp {
                name: s.name.clone(),
                versions: s.versions.len(),
                deleted: s.deleted.is_some(),
            })
            .collect(),
    };
    drop(snapshot);
    if ctx.json() {
        return output::json(&report);
    }
    let mut table = Table::new(["NAME", "VERSIONS", "STATE"]);
    for s in &report.secrets {
        table.row([
            s.name.clone(),
            s.versions.to_string(),
            if s.deleted { "deleted" } else { "live" }.to_owned(),
        ]);
    }
    table.print()?;
    output::success(&format!(
        "Backed up {} secret(s), {} version(s), from vault '{}' to {}",
        report.secrets.len(),
        report.secrets.iter().map(|s| s.versions).sum::<usize>(),
        report.vault,
        report.file
    ));
    output::note("the file is as sensitive as the vault: only its passphrase protects it");
    Ok(())
}

/// Write the file for the current user only (0600 on Unix), replacing any
/// existing file in one step.
fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot write {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[derive(Serialize)]
struct RestoreOutput<'a> {
    vault: String,
    file: String,
    source_vault: String,
    #[serde(with = "time::serde::rfc3339")]
    backup_created_on: time::OffsetDateTime,
    dry_run: bool,
    #[serde(flatten)]
    report: &'a RestoreReport,
}

pub fn restore(ctx: &Ctx, args: &RestoreArgs) -> anyhow::Result<()> {
    let bytes = std::fs::read(&args.file)
        .with_context(|| format!("cannot read {}", args.file.display()))?;
    let info = backup::inspect(&bytes)?;
    let vault = ctx.open_local_default("restore")?;
    let passphrase = existing_backup_passphrase()?;
    let snapshot = backup::open(&bytes, &passphrase)?;
    drop(passphrase);
    drop(bytes);

    let options = RestoreOptions {
        only: (!args.only.is_empty()).then(|| args.only.clone()),
        overwrite: args.overwrite,
        keep_deleted: args.keep_deleted,
    };
    let report = if args.dry_run {
        plan(&vault, &snapshot, &options)?
    } else {
        vault.restore(&snapshot, &options)?
    };
    drop(snapshot);

    if ctx.json() {
        return output::json(&RestoreOutput {
            vault: vault.vault_name().to_owned(),
            file: args.file.display().to_string(),
            source_vault: info.vault,
            backup_created_on: info.created_on,
            dry_run: args.dry_run,
            report: &report,
        });
    }
    let mut table = Table::new(["NAME", "VERSIONS", "RESULT"]);
    for r in &report.restored {
        let result = match (args.dry_run, r.deleted) {
            (true, true) => "would restore, then delete",
            (true, false) => "would restore",
            (false, true) => "restored, then deleted",
            (false, false) => "restored",
        };
        table.row([r.name.clone(), r.versions.to_string(), result.to_owned()]);
    }
    for s in &report.skipped {
        let result = match s.reason {
            SkipReason::Exists => "skipped: exists (--overwrite adds the versions)",
            SkipReason::Deleted => "skipped: deleted in this vault (recover or purge it first)",
        };
        table.row([s.name.clone(), "-".to_owned(), result.to_owned()]);
    }
    table.print()?;
    let verb = if args.dry_run {
        "Would restore"
    } else {
        "Restored"
    };
    output::success(&format!(
        "{verb} {} secret(s) from the backup of vault '{}' ({}) into vault '{}'; {} skipped",
        report.restored.len(),
        info.vault,
        output::fmt_time(info.created_on),
        vault.vault_name(),
        report.skipped.len()
    ));
    Ok(())
}

/// What `restore` would do, from the names the target holds. Reads
/// metadata only (two listings).
fn plan(
    vault: &impl SecretClient,
    snapshot: &Snapshot,
    options: &RestoreOptions,
) -> anyhow::Result<RestoreReport> {
    use sourceorrery_core::{RestoredSecret, SkippedSecret};
    let live: Vec<String> = vault
        .list_properties_of_secrets()?
        .into_iter()
        .map(|p| p.name)
        .collect();
    let deleted: Vec<String> = vault
        .list_deleted_secrets()?
        .into_iter()
        .map(|d| d.properties.name)
        .collect();
    let mut report = RestoreReport::default();
    for secret in &snapshot.secrets {
        if options
            .only
            .as_ref()
            .is_some_and(|only| !only.contains(&secret.name))
        {
            continue;
        }
        if deleted.contains(&secret.name) {
            report.skipped.push(SkippedSecret {
                name: secret.name.clone(),
                reason: SkipReason::Deleted,
            });
        } else if live.contains(&secret.name) && !options.overwrite {
            report.skipped.push(SkippedSecret {
                name: secret.name.clone(),
                reason: SkipReason::Exists,
            });
        } else {
            report.restored.push(RestoredSecret {
                name: secret.name.clone(),
                versions: secret.versions.len(),
                deleted: options.keep_deleted && secret.deleted.is_some(),
            });
        }
    }
    Ok(report)
}
