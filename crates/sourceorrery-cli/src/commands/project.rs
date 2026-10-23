//! `sourceorrery init`, `check` and `run`: the manifest-driven replacement
//! for `.env` files.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context as _, anyhow};
use sourceorrery_core::manifest::ManifestEntry;
use sourceorrery_core::{
    MANIFEST_FILE_NAME, Manifest, Secret, SecretBytes, SecretClient, SecretError, policy, timestamp,
};

use crate::cli::{CheckArgs, InitArgs, IntegrationChoice, RunArgs, SkillScope};
use crate::context::{Ctx, Opened};
use crate::integrations::{self, Agent, Outcome};
use crate::output::{self, Table};

/// Comment at the top of every manifest SourceOrrery writes.
pub const MANIFEST_HEADER: &str = "# SourceOrrery project manifest — safe to commit.\n\
     # Declares which secrets this project needs. It can never hold a secret:\n\
     # a `value` key is rejected. Store values with `sourceorrery secret set`.\n\n";

pub fn init(ctx: &Ctx, args: &InitArgs) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let path = args
        .path
        .clone()
        .unwrap_or_else(|| cwd.join(MANIFEST_FILE_NAME));
    if !args.integrations.is_empty() {
        return init_integrations(ctx, args, &cwd, &path);
    }
    if path.exists() && !args.force {
        return Err(anyhow!(
            "{} already exists (pass --force to overwrite)",
            path.display()
        ));
    }
    let vault = write_manifest(ctx, args, &cwd, &path)?;
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

/// Write the starter manifest and return its vault.
fn write_manifest(ctx: &Ctx, args: &InitArgs, cwd: &Path, path: &Path) -> anyhow::Result<String> {
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
    let text = format!("{MANIFEST_HEADER}{}", manifest.to_toml()?);
    std::fs::write(path, text).with_context(|| format!("cannot write {}", path.display()))?;
    Ok(vault)
}

#[derive(serde::Serialize)]
struct InstalledIntegration {
    agent: Agent,
    title: &'static str,
    directory: PathBuf,
    files: Vec<InstalledFile>,
    next_step: &'static str,
}

#[derive(serde::Serialize)]
struct InstalledFile {
    path: PathBuf,
    outcome: Outcome,
}

/// `init --integration`: the skills for each agent, and the manifest unless
/// it exists already or the skills go outside the project.
fn init_integrations(ctx: &Ctx, args: &InitArgs, cwd: &Path, path: &Path) -> anyhow::Result<()> {
    let agents: Vec<Agent> = if args.integrations.contains(&IntegrationChoice::All) {
        Agent::ALL.to_vec()
    } else {
        let mut agents: Vec<Agent> = Vec::new();
        for agent in args.integrations.iter().filter_map(|c| agent_for(*c)) {
            if !agents.contains(&agent) {
                agents.push(agent);
            }
        }
        agents
    };

    let in_project = args.skills_dir.is_none() && args.scope == SkillScope::Project;
    let manifest = if !in_project {
        "untouched"
    } else if path.exists() && !args.force {
        "kept"
    } else {
        let existed = path.exists();
        write_manifest(ctx, args, cwd, path)?;
        if existed { "replaced" } else { "created" }
    };

    let root = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| cwd.to_path_buf(), Path::to_path_buf);
    let home = if args.skills_dir.is_none() && args.scope == SkillScope::User {
        Some(std::env::home_dir().ok_or_else(|| anyhow!("cannot determine your home directory"))?)
    } else {
        None
    };

    let mut installed = Vec::new();
    for agent in agents {
        let directory = match (&args.skills_dir, &home) {
            (Some(dir), _) => dir.clone(),
            (None, Some(home)) => agent.user_skills_dir(home),
            (None, None) => root.join(agent.project_skills_dir()),
        };
        let planned = integrations::plan(agent, &directory, args.skills_dir.is_none());
        let results = integrations::install(&planned).with_context(|| {
            format!(
                "cannot write the {} skills to {}",
                agent.title(),
                directory.display()
            )
        })?;
        installed.push(InstalledIntegration {
            agent,
            title: agent.title(),
            directory,
            files: results
                .into_iter()
                .map(|(path, outcome)| InstalledFile { path, outcome })
                .collect(),
            next_step: agent.next_step(),
        });
    }

    if ctx.json() {
        return output::json(&serde_json::json!({
            "manifest": { "path": path, "status": manifest },
            "integrations": installed,
        }));
    }
    print_integrations(path, manifest, &root, &installed);
    Ok(())
}

/// The table-mode report of `init --integration`.
fn print_integrations(
    path: &Path,
    manifest: &str,
    root: &Path,
    installed: &[InstalledIntegration],
) {
    match manifest {
        "created" | "replaced" => output::success(&format!("Wrote {}", path.display())),
        "kept" => output::note(&format!("{} already exists; kept it", path.display())),
        _ => {}
    }
    let shown = |p: &Path| {
        p.strip_prefix(root)
            .unwrap_or(p)
            .display()
            .to_string()
            .replace('\\', "/")
    };
    for integration in installed {
        let count = |outcome: Outcome| {
            integration
                .files
                .iter()
                .filter(|f| f.outcome == outcome)
                .count()
        };
        let mut parts = Vec::new();
        for (outcome, label) in [
            (Outcome::Created, "created"),
            (Outcome::Updated, "updated"),
            (Outcome::Unchanged, "unchanged"),
            (Outcome::Kept, "kept"),
        ] {
            let n = count(outcome);
            if n > 0 {
                parts.push(format!("{n} {label}"));
            }
        }
        output::success(&format!(
            "{}: skills in {} ({})",
            integration.title,
            shown(&integration.directory),
            parts.join(", ")
        ));
        // A skill or subagent someone else wrote is left whole: name it once.
        let mut kept: Vec<String> = Vec::new();
        for file in integration
            .files
            .iter()
            .filter(|f| f.outcome == Outcome::Kept)
        {
            let relative = file
                .path
                .strip_prefix(&integration.directory)
                .unwrap_or(&file.path);
            let item = match relative.components().next() {
                Some(first) if file.path.starts_with(&integration.directory) => {
                    integration.directory.join(first)
                }
                _ => file.path.clone(),
            };
            let item = shown(&item);
            if !kept.contains(&item) {
                kept.push(item);
            }
        }
        for item in kept {
            output::note(&format!(
                "left {item} as it is: SourceOrrery did not write it (remove it to install ours)"
            ));
        }
        eprintln!("  {}", integration.next_step);
    }
}

/// The agent a choice names; `None` for `all`.
fn agent_for(choice: IntegrationChoice) -> Option<Agent> {
    Some(match choice {
        IntegrationChoice::Claude => Agent::Claude,
        IntegrationChoice::Gemini => Agent::Gemini,
        IntegrationChoice::Copilot => Agent::Copilot,
        IntegrationChoice::Antigravity => Agent::Antigravity,
        IntegrationChoice::Cline => Agent::Cline,
        IntegrationChoice::Codex => Agent::Codex,
        IntegrationChoice::Cursor => Agent::Cursor,
        IntegrationChoice::Hermes => Agent::Hermes,
        IntegrationChoice::Kilocode => Agent::Kilocode,
        IntegrationChoice::Kimi => Agent::Kimi,
        IntegrationChoice::Kiro => Agent::Kiro,
        IntegrationChoice::Opencode => Agent::Opencode,
        IntegrationChoice::All => return None,
    })
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
    vaults: BTreeMap<String, Opened>,
}

impl<'a> VaultCache<'a> {
    fn new(ctx: &'a Ctx) -> Self {
        Self {
            ctx,
            vaults: BTreeMap::new(),
        }
    }

    fn get(&mut self, name: &str) -> anyhow::Result<&Opened> {
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
            // A vault that cannot be opened reports its own code (a remote
            // vault this build lacks, an older on-disk format); anything
            // else that stops the unlock is `locked`.
            let vault = cache.get(&entry.reference.vault).map_err(|err| {
                match err.downcast::<SecretError>() {
                    Ok(core) => core,
                    Err(other) => SecretError::Locked(other.to_string()),
                }
            })?;
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
        // The child's status is passed on whole. `ExitCode` only carries a
        // byte, which would turn a Windows status such as 3010 into 1, so
        // the process ends here; every plaintext buffer was already dropped
        // inside `run_inner`.
        Ok(status) => std::process::exit(status),
        Err(err) => {
            let code = err
                .downcast_ref::<SecretError>()
                .map_or("cli", SecretError::code);
            output::print_error(ctx.output, code, &format!("{err:#}"));
            ExitCode::from(1)
        }
    }
}

/// The exit status to report for a finished child: its exit code, or the
/// shell convention `128 + signal` when a Unix child was killed by a signal.
fn child_status(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    1
}

fn run_inner(ctx: &Ctx, args: &RunArgs) -> anyhow::Result<i32> {
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
        // A vault that does not exist is an ordinary "secret unavailable" for
        // an optional entry. Any other vault failure (locked, corrupt) is
        // reported regardless, because it is a problem the user must see.
        let resolved: Result<Secret, SecretError> = match cache.get(&entry.reference.vault) {
            Ok(vault) => vault.resolve(&entry.reference),
            Err(err) => match err.downcast_ref::<SecretError>() {
                Some(SecretError::VaultNotFound { name }) => {
                    Err(SecretError::VaultNotFound { name: name.clone() })
                }
                _ => return Err(err),
            },
        };
        match resolved {
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
    // The child gets the declared secrets and nothing that unlocks the vault:
    // a passphrase in our environment must not become a passphrase in theirs.
    for var in crate::context::UNLOCK_ENV_VARS {
        command.env_remove(var);
    }
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
    // Both hold copies of the values: release them before the process exits
    // without running destructors.
    drop(command);
    drop(env);

    Ok(child_status(status))
}
