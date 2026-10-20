//! `sourceorrery init`, `check` and `run`: the manifest-driven replacement
//! for `.env` files.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context as _, anyhow};
use sourceorrery_core::manifest::ManifestEntry;
use sourceorrery_core::{
    MANIFEST_FILE_NAME, Manifest, SecretBytes, SecretClient, SecretError, policy, timestamp,
};
use sourceorrery_storage::SqliteVault;

use crate::cli::{CheckArgs, InitArgs, RunArgs};
use crate::context::Ctx;
use crate::output::{self, Table};

pub fn init(ctx: &Ctx, args: &InitArgs) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let path = args
        .path
        .clone()
        .unwrap_or_else(|| cwd.join(MANIFEST_FILE_NAME));
    if path.exists() && !args.force {
        return Err(anyhow!(
            "{} already exists (pass --force to overwrite)",
            path.display()
        ));
    }
    let project_name = args.project_name.clone().unwrap_or_else(|| {
        cwd.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("my-application")
            .to_owned()
    });
    let vault = args
        .vault_name
        .clone()
        .or_else(|| ctx.vault_flag.clone())
        .unwrap_or_else(|| "development".to_owned());
    let manifest = Manifest::template(&project_name, &vault);
    let text = format!(
        "# SourceOrrery project manifest — safe to commit.\n\
         # Declares which secrets this project needs. It can never hold a secret:\n\
         # a `value` key is rejected. Store values with `sourceorrery secret set`.\n\n{}",
        manifest.to_toml()?
    );
    std::fs::write(&path, text).with_context(|| format!("cannot write {}", path.display()))?;
    if ctx.json() {
        return output::json(&serde_json::json!({ "manifest": path, "vault": vault }));
    }
    output::success(&format!("Wrote {}", path.display()));
    eprintln!(
        "next:\n  sourceorrery vault create {vault}\n  \
         sourceorrery secret set database-password\n  \
         sourceorrery run -- <your command>"
    );
    Ok(())
}

fn load_manifest(explicit: Option<&Path>) -> anyhow::Result<(PathBuf, Manifest)> {
    let path = if let Some(p) = explicit {
        p.to_path_buf()
    } else {
        let cwd = std::env::current_dir()?;
        Manifest::discover(&cwd).ok_or_else(|| {
            anyhow!(
                "no {MANIFEST_FILE_NAME} found in {} or its parents (run `sourceorrery init`)",
                cwd.display()
            )
        })?
    };
    let manifest = Manifest::load(&path)?;
    Ok((path, manifest))
}

/// Opens each distinct vault once.
struct VaultCache<'a> {
    ctx: &'a Ctx,
    vaults: BTreeMap<String, SqliteVault>,
}

impl<'a> VaultCache<'a> {
    fn new(ctx: &'a Ctx) -> Self {
        Self {
            ctx,
            vaults: BTreeMap::new(),
        }
    }

    fn get(&mut self, name: &str) -> anyhow::Result<&SqliteVault> {
        if !self.vaults.contains_key(name) {
            let vault = self.ctx.open(name)?;
            self.vaults.insert(name.to_owned(), vault);
        }
        Ok(&self.vaults[name])
    }
}

/// Apply `--vault` as an override of the manifest's default vault.
fn effective_entries(ctx: &Ctx, manifest: &Manifest) -> anyhow::Result<Vec<ManifestEntry>> {
    let mut entries = manifest.entries()?;
    if let Some(override_vault) = &ctx.vault_flag {
        for entry in &mut entries {
            if entry.reference.vault == manifest.project.vault {
                entry.reference.vault.clone_from(override_vault);
            }
        }
    }
    Ok(entries)
}

#[derive(serde::Serialize)]
struct CheckRow {
    name: String,
    env: String,
    reference: String,
    required: bool,
    status: String,
    version: Option<String>,
}

pub fn check(ctx: &Ctx, args: &CheckArgs) -> anyhow::Result<()> {
    let (path, manifest) = load_manifest(args.manifest.as_deref())?;
    let entries = effective_entries(ctx, &manifest)?;
    let mut cache = VaultCache::new(ctx);
    let now = timestamp::now();
    let mut rows = Vec::new();
    let mut failures = 0usize;

    for entry in &entries {
        let outcome: Result<String, SecretError> = (|| {
            let vault = cache
                .get(&entry.reference.vault)
                .map_err(|err| SecretError::Locked(err.to_string()))?;
            // Metadata only: no value is read and no secret_get audit event is written.
            let versions = vault.list_properties_of_secret_versions(&entry.reference.name)?;
            let chosen = match &entry.reference.version {
                Some(v) => versions
                    .iter()
                    .find(|p| &p.version == v)
                    .ok_or_else(|| SecretError::VersionNotFound {
                        name: entry.reference.name.clone(),
                        version: v.clone(),
                    })
                    .and_then(|p| policy::evaluate_access(p, now).map(|()| p))?,
                None => policy::select_latest_accessible(&entry.reference.name, &versions, now)?,
            };
            Ok(chosen.version.clone())
        })();
        let (status, version) = match outcome {
            Ok(version) => ("ok".to_owned(), Some(version)),
            Err(err) => {
                if entry.required {
                    failures += 1;
                }
                (err.code().to_owned(), None)
            }
        };
        rows.push(CheckRow {
            name: entry.name.clone(),
            env: entry.env.clone(),
            reference: entry.reference.to_string(),
            required: entry.required,
            status,
            version,
        });
    }

    if ctx.json() {
        output::json(&serde_json::json!({
            "manifest": path,
            "ok": failures == 0,
            "secrets": rows,
        }))?;
    } else {
        let mut table = Table::new(["SECRET", "ENV", "REQUIRED", "STATUS", "VERSION"]);
        for r in &rows {
            table.row([
                r.name.clone(),
                r.env.clone(),
                if r.required { "yes" } else { "no" }.to_owned(),
                r.status.clone(),
                r.version.clone().unwrap_or_else(|| "-".into()),
            ]);
        }
        table.print()?;
    }
    if failures > 0 {
        return Err(anyhow!(
            "{failures} required secret(s) are missing or inaccessible"
        ));
    }
    if !ctx.json() {
        output::success(&format!(
            "{} secret(s) ready ({})",
            rows.len(),
            path.display()
        ));
    }
    Ok(())
}

pub fn run(ctx: &Ctx, args: &RunArgs) -> ExitCode {
    match run_inner(ctx, args) {
        Ok(code) => code,
        Err(err) => {
            let code = err
                .downcast_ref::<SecretError>()
                .map_or("cli", SecretError::code);
            output::print_error(ctx.output, code, &format!("{err:#}"));
            ExitCode::from(1)
        }
    }
}

fn run_inner(ctx: &Ctx, args: &RunArgs) -> anyhow::Result<ExitCode> {
    let (program, program_args) = args
        .command
        .split_first()
        .ok_or_else(|| anyhow!("no command given"))?;
    let (_, manifest) = load_manifest(args.manifest.as_deref())?;
    let entries = effective_entries(ctx, &manifest)?;
    let mut cache = VaultCache::new(ctx);

    let mut env: Vec<(String, SecretBytes)> = Vec::with_capacity(entries.len());
    let mut missing: Vec<String> = Vec::new();
    for entry in &entries {
        let vault = cache.get(&entry.reference.vault)?;
        match vault.resolve(&entry.reference) {
            Ok(secret) => env.push((entry.env.clone(), secret.value)),
            Err(err) if entry.required => {
                missing.push(format!("{} ({})", entry.reference, err.code()));
            }
            Err(err) => {
                if ctx.verbose > 0 {
                    output::note(&format!(
                        "optional secret {} not injected: {err}",
                        entry.reference
                    ));
                }
            }
        }
    }
    if !missing.is_empty() {
        return Err(anyhow!(
            "cannot start: required secrets unavailable:\n  {}",
            missing.join("\n  ")
        ));
    }
    drop(cache);

    let mut command = std::process::Command::new(program);
    command.args(program_args);
    for (key, value) in &env {
        let text = value.expose_utf8().ok_or_else(|| {
            anyhow!("secret for {key} is not valid UTF-8 and cannot be an environment variable")
        })?;
        command.env(key, text);
    }
    command.env("SOURCEORRERY_PROJECT", &manifest.project.name);

    let status = command
        .status()
        .with_context(|| format!("failed to start {}", program.to_string_lossy()))?;
    drop(env);

    let code = status
        .code()
        .and_then(|c| u8::try_from(c).ok())
        .unwrap_or(1);
    Ok(ExitCode::from(code))
}
