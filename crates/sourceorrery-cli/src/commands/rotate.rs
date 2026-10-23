//! `sourceorrery secret rotate`: the rotation workflow of
//! `sourceorrery_core::rotation`, with the issuer's side as commands from
//! the manifest's `[rotation.<secret>]` table.
//!
//! Hooks run the way `run` runs a program: the program and its arguments as
//! an array (no shell), the value only in the child's environment, never on
//! its command line or in anything this module prints. The issue command's
//! standard output is the new value and is read straight into
//! [`SecretBytes`]. The variables that unlock a vault are stripped from the
//! hook's environment like from `run`'s child.

use std::collections::BTreeMap;
use std::process::{Command, ExitStatus, Stdio};

use anyhow::{Context as _, anyhow};
use sourceorrery_core::manifest::default_env_name;
use sourceorrery_core::rotation::{self, State};
use sourceorrery_core::{
    Manifest, RotationSection, SecretBytes, SecretClient, SecretError, SecretProperties, timestamp,
};
use time::Duration;

use crate::cli::{RotationStep, SecretRotateArgs};
use crate::context::{Ctx, Opened, UNLOCK_ENV_VARS};
use crate::output::{self, Table};
use crate::prompt::{self, ValueSource};

/// Everything a rotation needs to know about its secret before a vault is
/// opened: resolved once from the arguments and the manifest, if any.
struct Plan {
    name: String,
    vault: String,
    /// The environment variable a hook receives the value in.
    env: String,
    project: Option<String>,
    hooks: RotationSection,
    grace: Option<Duration>,
}

impl Plan {
    fn load(ctx: &Ctx, args: &SecretRotateArgs) -> anyhow::Result<Self> {
        let manifest = match &args.manifest {
            Some(path) => Some(Manifest::load(path)?),
            None => std::env::current_dir()
                .ok()
                .and_then(|cwd| Manifest::discover(&cwd))
                .map(|path| Manifest::load(&path))
                .transpose()?,
        };
        let entry = manifest
            .as_ref()
            .map(Manifest::entries)
            .transpose()?
            .and_then(|entries| entries.into_iter().find(|e| e.name == args.name));
        let vault = match (&ctx.vault_flag, &entry, &manifest) {
            // `--vault` overrides the manifest's default vault, as in `run`,
            // never a vault an entry names explicitly.
            (Some(flag), Some(entry), Some(manifest))
                if entry.reference.vault == manifest.project.vault =>
            {
                flag.clone()
            }
            (_, Some(entry), _) => entry.reference.vault.clone(),
            _ => ctx.vault_name()?,
        };
        let hooks = manifest
            .as_ref()
            .and_then(|m| m.rotation(&args.name))
            .cloned()
            .unwrap_or_default();
        let grace = args
            .retire_after
            .as_deref()
            .or(hooks.retire_after.as_deref())
            .map(rotation::parse_grace)
            .transpose()?;
        Ok(Self {
            name: args.name.clone(),
            vault,
            env: entry.map_or_else(|| default_env_name(&args.name), |e| e.env),
            project: manifest.map(|m| m.project.name),
            hooks,
            grace,
        })
    }

    /// Run a hook with `value` in the secret's environment variable and
    /// `extra` beside it. Returns the exit status and, when `capture`, what
    /// the hook wrote to standard output.
    fn run_hook(
        &self,
        step: &str,
        command_line: &[String],
        value: Option<&SecretBytes>,
        extra: &[(&str, &str)],
        capture: bool,
    ) -> anyhow::Result<(ExitStatus, Vec<u8>)> {
        let (program, program_args) = command_line
            .split_first()
            .ok_or_else(|| anyhow!("the {step} command of '{}' names no program", self.name))?;
        let mut command = Command::new(program);
        command.args(program_args);
        for var in UNLOCK_ENV_VARS {
            command.env_remove(var);
        }
        command.env("SOURCEORRERY_SECRET", &self.name);
        command.env("SOURCEORRERY_ROTATION_STEP", step);
        if let Some(project) = &self.project {
            command.env("SOURCEORRERY_PROJECT", project);
        }
        for (key, value) in extra {
            command.env(key, value);
        }
        if let Some(value) = value {
            let text = value.expose_utf8().ok_or_else(|| {
                anyhow!(
                    "the value of '{}' is not valid UTF-8 and cannot be an environment variable",
                    self.name
                )
            })?;
            command.env(&self.env, text);
        }
        command.stdin(Stdio::null());
        command.stdout(if capture {
            Stdio::piped()
        } else {
            Stdio::inherit()
        });
        command.stderr(Stdio::inherit());
        let output = command
            .output()
            .with_context(|| format!("failed to start the {step} command {program}"))?;
        // `command` holds a copy of the value in its environment.
        drop(command);
        Ok((output.status, output.stdout))
    }
}

fn exit_code(status: ExitStatus) -> String {
    status
        .code()
        .map_or_else(|| "a signal".to_owned(), |c| format!("status {c}"))
}

fn rotation_error(name: &str, reason: String) -> anyhow::Error {
    SecretError::Rotation {
        name: name.to_owned(),
        reason,
    }
    .into()
}

/// What one run did, for the JSON and text reports.
#[derive(Default, serde::Serialize)]
struct Report {
    secret: String,
    vault: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    candidate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous: Option<String>,
    validated: bool,
    activated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    retire_on: Option<String>,
    retired: bool,
}

pub fn rotate(ctx: &Ctx, args: &SecretRotateArgs) -> anyhow::Result<()> {
    let plan = Plan::load(ctx, args)?;
    let vault = ctx.open(&plan.vault)?;
    let mut report = Report {
        secret: plan.name.clone(),
        vault: plan.vault.clone(),
        ..Report::default()
    };
    match args.step {
        RotationStep::Rotate => rotate_now(ctx, args, &plan, &vault, &mut report)?,
        RotationStep::Activate => {
            let status = rotation::status(&vault, &plan.name)?;
            let candidate = status.candidate.ok_or_else(|| {
                rotation_error(
                    &plan.name,
                    "no candidate is waiting for activation".to_owned(),
                )
            })?;
            report.candidate = Some(candidate.version.clone());
            report.validated = State::of(&candidate) == Some(State::Validated);
            activate(ctx, &plan, &vault, &candidate.version, &mut report)?;
        }
        RotationStep::Retire => retire(ctx, &plan, &vault, args.now, &mut report)?,
        RotationStep::Status => return status(ctx, &plan, &vault),
    }
    if ctx.json() {
        return output::json(&report);
    }
    Ok(())
}

fn rotate_now(
    ctx: &Ctx,
    args: &SecretRotateArgs,
    plan: &Plan,
    vault: &Opened,
    report: &mut Report,
) -> anyhow::Result<()> {
    let now = timestamp::now();
    let value = match &plan.hooks.issue {
        Some(command_line) => {
            // The issuer may need the current credential to mint the next
            // one; it gets it the way `run` would deliver it.
            let current = match vault.get_secret(&plan.name, None) {
                Ok(secret) => Some(secret.value),
                Err(SecretError::NotFound { .. }) => None,
                Err(err) if err.is_transient() => return Err(err.into()),
                // Disabled or expired: there is nothing accessible to pass.
                Err(_) => None,
            };
            let (status, mut stdout) =
                plan.run_hook("issue", command_line, current.as_ref(), &[], true)?;
            drop(current);
            if !status.success() {
                stdout.clear();
                return Err(rotation_error(
                    &plan.name,
                    format!(
                        "the issue command exited with {}; nothing was written",
                        exit_code(status)
                    ),
                ));
            }
            if !args.keep_trailing_newline {
                prompt::strip_trailing_newline(&mut stdout);
            }
            if stdout.is_empty() && !args.allow_empty {
                return Err(rotation_error(
                    &plan.name,
                    "the issue command produced an empty value (pass --allow-empty to accept it)"
                        .to_owned(),
                ));
            }
            SecretBytes::new(stdout)
        }
        None => prompt::read_value(&ValueSource {
            from_file: args.from_file.as_deref(),
            stdin: args.stdin,
            keep_trailing_newline: args.keep_trailing_newline,
            confirm: false,
            allow_empty: args.allow_empty,
        })?,
    };

    // The validator needs the candidate, and a disabled version cannot be
    // read back, so the value stays in memory until validation is done.
    let candidate_value = value.clone();
    let issued = rotation::issue(vault, &plan.name, value, now)?;
    let candidate = issued.candidate.version.clone();
    report.candidate = Some(candidate.clone());
    report.previous = issued.previous.as_ref().map(|p| p.version.clone());
    if !ctx.json() {
        output::note(&format!(
            "Issued version {candidate} of '{}' (disabled until activated)",
            plan.name
        ));
    }

    if let Some(command_line) = &plan.hooks.validate {
        let (status, _) = plan.run_hook(
            "validate",
            command_line,
            Some(&candidate_value),
            &[("SOURCEORRERY_VERSION", candidate.as_str())],
            false,
        )?;
        if !status.success() {
            drop(candidate_value);
            rotation::fail(vault, &plan.name, &candidate)?;
            let current = issued.previous.as_ref().map_or_else(
                || "no version was accessible before and none is now".to_owned(),
                |p| format!("version {} stays current", p.version),
            );
            return Err(rotation_error(
                &plan.name,
                format!(
                    "the validate command exited with {}; version {candidate} is marked failed \
                     and stays disabled, {current}",
                    exit_code(status)
                ),
            ));
        }
    }
    drop(candidate_value);
    rotation::validated(vault, &plan.name, &candidate)?;
    report.validated = true;

    if args.no_activate {
        if !ctx.json() {
            output::success(&format!(
                "Validated version {candidate} of '{}'; it stays disabled until `sourceorrery \
                 secret rotate {} --step activate`",
                plan.name, plan.name
            ));
        }
        return Ok(());
    }
    activate(ctx, plan, vault, &candidate, report)
}

fn activate(
    ctx: &Ctx,
    plan: &Plan,
    vault: &Opened,
    candidate: &str,
    report: &mut Report,
) -> anyhow::Result<()> {
    let now = timestamp::now();
    let activated = rotation::activate(vault, &plan.name, candidate, plan.grace, now)?;
    report.activated = true;
    report.previous = activated.previous.as_ref().map(|p| p.version.clone());
    report.retire_on = activated.retire_on.map(timestamp::format);
    if !ctx.json() {
        match &activated.previous {
            Some(previous) => output::success(&format!(
                "Activated version {candidate} of '{}'; version {} is disabled",
                plan.name, previous.version
            )),
            None => output::success(&format!("Activated version {candidate} of '{}'", plan.name)),
        }
    }
    match (activated.previous, activated.retire_on) {
        (Some(_), None) => retire(ctx, plan, vault, true, report),
        (Some(previous), Some(retire_on)) => {
            if !ctx.json() {
                output::note(&format!(
                    "Version {} is retired after {}: run `sourceorrery secret rotate {} --step \
                     retire` then",
                    previous.version,
                    timestamp::format(retire_on),
                    plan.name
                ));
            }
            Ok(())
        }
        (None, _) => Ok(()),
    }
}

fn retire(
    ctx: &Ctx,
    plan: &Plan,
    vault: &Opened,
    force: bool,
    report: &mut Report,
) -> anyhow::Result<()> {
    let now = timestamp::now();
    let pending = rotation::retirement(vault, &plan.name, now, force)?;
    if let Some(command_line) = &plan.hooks.retire {
        // The hook revokes the previous credential at the issuer; it
        // authenticates with the current one.
        let current = vault
            .get_secret(&plan.name, Some(&pending.current.version))?
            .value;
        let (status, _) = plan.run_hook(
            "retire",
            command_line,
            Some(&current),
            &[
                ("SOURCEORRERY_VERSION", pending.current.version.as_str()),
                (
                    "SOURCEORRERY_RETIRED_VERSION",
                    pending.previous.version.as_str(),
                ),
            ],
            false,
        )?;
        drop(current);
        if !status.success() {
            return Err(rotation_error(
                &plan.name,
                format!(
                    "the retire command exited with {}; version {} stays superseded and can be \
                     retired again",
                    exit_code(status),
                    pending.previous.version
                ),
            ));
        }
    }
    let done = rotation::retire(vault, &plan.name, &pending, now)?;
    report.previous = Some(done.previous.version.clone());
    report.retired = true;
    if !ctx.json() {
        output::success(&format!(
            "Retired version {} of '{}'; version {} is current",
            done.previous.version, plan.name, done.current.version
        ));
    }
    Ok(())
}

fn status(ctx: &Ctx, plan: &Plan, vault: &Opened) -> anyhow::Result<()> {
    let versions = match vault.list_properties_of_secret_versions(&plan.name) {
        Ok(versions) => versions,
        Err(SecretError::NotFound { .. }) => Vec::new(),
        Err(err) => return Err(err.into()),
    };
    let status = rotation::status(vault, &plan.name)?;
    if ctx.json() {
        let awaiting = status.awaiting_retirement.as_ref().map(|(p, retire_on)| {
            serde_json::json!({
                "version": p.version,
                "retire_on": retire_on.map(timestamp::format),
            })
        });
        return output::json(&serde_json::json!({
            "secret": plan.name,
            "vault": plan.vault,
            "candidate": status.candidate.as_ref().map(|p| p.version.clone()),
            "current": status.current.as_ref().map(|p| p.version.clone()),
            "awaiting_retirement": awaiting,
            "grace": plan.grace.map(rotation::format_grace),
            "versions": versions.iter().map(version_row).collect::<Vec<_>>(),
        }));
    }
    if versions.is_empty() {
        eprintln!("'{}' has no versions in vault '{}'", plan.name, plan.vault);
        return Ok(());
    }
    let now = timestamp::now();
    let mut table = Table::new(["VERSION", "STATUS", "ROTATION", "REPLACES", "RETIRE ON"]);
    for props in &versions {
        table.row([
            props.version.clone(),
            output::status(props, now).to_owned(),
            State::of(props).map_or("-", State::as_str).to_owned(),
            props
                .tags
                .get(rotation::PREVIOUS_TAG)
                .cloned()
                .unwrap_or_else(|| "-".to_owned()),
            props
                .tags
                .get(rotation::RETIRE_ON_TAG)
                .cloned()
                .unwrap_or_else(|| "-".to_owned()),
        ]);
    }
    table.print()?;
    if let Some(candidate) = &status.candidate {
        eprintln!(
            "candidate {} is {}: {}",
            candidate.version,
            State::of(candidate).map_or("-", State::as_str),
            if State::of(candidate) == Some(State::Validated) {
                "activate it with --step activate"
            } else {
                "it was never validated and will be marked failed by the next rotation"
            }
        );
    }
    if let Some((previous, retire_on)) = &status.awaiting_retirement {
        match retire_on {
            Some(t) if *t > now => eprintln!(
                "version {} awaits retirement after {} (--step retire --now to retire earlier)",
                previous.version,
                timestamp::format(*t)
            ),
            _ => eprintln!(
                "version {} is due for retirement: run --step retire",
                previous.version
            ),
        }
    }
    Ok(())
}

fn version_row(props: &SecretProperties) -> serde_json::Value {
    let tags: BTreeMap<&str, &str> = props
        .tags
        .iter()
        .filter(|(k, _)| k.starts_with(rotation::TAG_PREFIX))
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    serde_json::json!({
        "version": props.version,
        "enabled": props.enabled,
        "state": State::of(props).map(State::as_str),
        "tags": tags,
    })
}
