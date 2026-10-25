//! `sourceorrery init` (ADR 0009, section 6): the vault is the source of
//! truth. `init` needs a vault on this machine and reads its catalog (names,
//! storage and descriptions; never a value, and no view check), writes the
//! secrets picked into `sourceorrery.toml` by name (`purpose` from the
//! description) and records the folder in the vault. This module is the
//! flag path (`--all`, `--secret NAME …`) and what it shares with `init`'s
//! screens (`ui::init`): reading, editing and saving the manifest.
//!
//! An existing manifest is edited in place with `toml_edit`: a new
//! `[secrets.<name>]` lands after the ones the file declares, a removed one
//! goes with its `[rotation.<name>]`, and every other byte (comments, `env`
//! overrides, `version` pins, `required` flags) stays as it was. Its vault
//! and project name are kept. A value is never a command-line argument, so
//! the flag path picks only secrets the vault has; the screens can store a
//! new one first.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, anyhow};
use serde::Serialize;
use sourceorrery_core::Manifest;
use sourceorrery_storage::{CatalogEntry, ProjectLink, SqliteVault};
use toml_edit::{DocumentMut, Item, Table, Value, value};

use crate::cli::InitArgs;
use crate::commands::project::MANIFEST_HEADER;
use crate::context::Ctx;
use crate::output;

/// What `init` wrote and recorded.
#[derive(Debug, Serialize)]
pub struct Written {
    /// The manifest's path.
    pub manifest: PathBuf,
    /// True when `init` created the file, false when it added to one.
    pub created: bool,
    /// The vault the manifest names.
    pub vault: String,
    /// The project's name.
    pub project: String,
    /// The secrets this run added to the manifest.
    pub added: Vec<String>,
    /// The picked secrets the manifest declared already.
    pub declared: Vec<String>,
    /// Secrets the manifest declares that the vault does not have.
    pub missing: Vec<String>,
    /// The folder's record in the vault.
    pub linked: ProjectLink,
}

/// One change `init` makes to a manifest's `[secrets]`. Only the screens
/// take an entry out or change one, so a build without them adds only.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(not(feature = "ui"), allow(dead_code))]
pub enum Change {
    /// Declare a secret; nothing happens when the manifest declares it.
    Add {
        name: String,
        required: bool,
        purpose: Option<String>,
        /// An environment variable other than the default one.
        env: Option<String>,
    },
    /// Stop declaring a secret: its table goes, with its rotation table.
    Remove(String),
    /// Change whether a declared secret is required.
    Required { name: String, required: bool },
}

/// True when the arguments pick secrets, so that the flag path runs.
pub fn picks_secrets(args: &InitArgs) -> bool {
    args.all || !args.secrets.is_empty()
}

/// The manifest at `path`, as text and parsed, when there is one.
pub fn read_existing(path: &Path) -> anyhow::Result<Option<(String, Manifest)>> {
    if !path.exists() {
        return Ok(None);
    }
    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let manifest = Manifest::parse(&text).map_err(|err| anyhow!("{}: {err}", path.display()))?;
    Ok(Some((text, manifest)))
}

/// A new manifest's text before its secrets: the header and `[project]`.
pub fn new_manifest_text(project: &str, vault: &str) -> String {
    format!(
        "{MANIFEST_HEADER}[project]\nname = {}\nvault = {}\n",
        toml::Value::from(project),
        toml::Value::from(vault)
    )
}

/// The project name a folder gives when none is named.
pub fn default_project_name(folder: &Path) -> String {
    folder
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("my-application")
        .to_owned()
}

/// Check `text` is a valid manifest, write it to `path` unless `previous`
/// is the same text, and record the folder in `vault` as `project`.
pub fn save(
    vault: &SqliteVault,
    path: &Path,
    previous: Option<&str>,
    text: &str,
    project: &str,
) -> anyhow::Result<ProjectLink> {
    Manifest::parse(text)
        .map_err(|err| anyhow!("{}: the manifest would be invalid: {err}", path.display()))?;
    if previous != Some(text) {
        std::fs::write(path, text).with_context(|| format!("cannot write {}", path.display()))?;
    }
    let folder = project_folder(path)?;
    vault.link_project(&folder, project).map_err(|err| {
        anyhow!(
            "{} was written, but the vault did not record the folder: {err}",
            path.display()
        )
    })
}

/// Write or extend the manifest at `path` from the vault, as the flags
/// pick, and record the folder. Nothing is printed.
pub fn write(ctx: &Ctx, args: &InitArgs, path: &Path) -> anyhow::Result<Written> {
    if !picks_secrets(args) {
        return Err(anyhow!(
            "pick the secrets for this project: --all for every secret in the vault, or --secret \
             NAME (repeatable). A secret the vault does not have yet is stored first with \
             `sourceorrery secret set NAME --stdin`"
        ));
    }
    let existing = read_existing(path)?;
    let manifest = existing.as_ref().map(|(_, manifest)| manifest);
    let vault_name = choose_vault(ctx, args, path, manifest)?;
    let project = match manifest {
        Some(manifest) => {
            if let Some(asked) = &args.project_name
                && *asked != manifest.project.name
            {
                return Err(anyhow!(
                    "{} names the project '{}'; change it there, not with --project-name",
                    path.display(),
                    manifest.project.name
                ));
            }
            manifest.project.name.clone()
        }
        None => match &args.project_name {
            Some(name) => name.clone(),
            None => default_project_name(&project_folder(path)?),
        },
    };

    // No view check: init needs names, never values.
    let vault = ctx.open_local(&vault_name)?;
    let catalog = vault.catalog()?;
    let picked = pick(&catalog, args, &vault_name)?;
    let declared_already = |name: &str| manifest.is_some_and(|m| m.secrets.contains_key(name));
    let (declared, added): (Vec<&CatalogEntry>, Vec<&CatalogEntry>) =
        picked.into_iter().partition(|e| declared_already(&e.name));
    let missing: Vec<String> = manifest
        .map(|manifest| {
            manifest
                .secrets
                .keys()
                .filter(|name| !catalog.iter().any(|entry| &entry.name == *name))
                .cloned()
                .collect()
        })
        .unwrap_or_default();

    let previous = existing.as_ref().map(|(text, _)| text.as_str());
    let base = previous.map_or_else(|| new_manifest_text(&project, &vault_name), str::to_owned);
    let changes: Vec<Change> = added
        .iter()
        .map(|entry| Change::Add {
            name: entry.name.clone(),
            required: true,
            purpose: entry.description.clone(),
            env: None,
        })
        .collect();
    let text = edit_secrets(&base, &changes)
        .with_context(|| format!("cannot add to {}", path.display()))?;
    let linked = save(&vault, path, previous, &text, &project)?;
    Ok(Written {
        manifest: path.to_path_buf(),
        created: existing.is_none(),
        vault: vault_name,
        project,
        added: added.iter().map(|e| e.name.clone()).collect(),
        declared: declared.iter().map(|e| e.name.clone()).collect(),
        missing,
        linked,
    })
}

/// Say what [`write`] did.
pub fn report(ctx: &Ctx, written: &Written) -> anyhow::Result<()> {
    if ctx.json() {
        return output::json(written);
    }
    let path = written.manifest.display();
    let vault = &written.vault;
    if written.created {
        output::success(&format!(
            "Wrote {path}: {} secret(s) from vault '{vault}'",
            written.added.len()
        ));
    } else if written.added.is_empty() {
        output::success(&format!("{path} declares every secret picked already"));
    } else {
        output::success(&format!(
            "Added {} secret(s) from vault '{vault}' to {path}: {}",
            written.added.len(),
            written.added.join(", ")
        ));
    }
    eprintln!(
        "  vault '{vault}' records this folder as project '{}'",
        output::sanitize(&written.project)
    );
    for name in &written.missing {
        output::note(&format!(
            "{path} declares '{name}', which vault '{vault}' does not have; store it with: \
             sourceorrery secret set {name} --vault {vault}"
        ));
    }
    eprintln!("next:\n  sourceorrery check\n  sourceorrery run -- <your command>");
    Ok(())
}

/// The vault a manifest that exists names, checked against the one asked
/// for (`asked`) and against this machine's vaults.
pub fn manifest_vault(
    ctx: &Ctx,
    path: &Path,
    manifest: &Manifest,
    asked: Option<&str>,
) -> anyhow::Result<String> {
    let named = &manifest.project.vault;
    if let Some(asked) = asked
        && !asked.eq_ignore_ascii_case(named)
    {
        return Err(anyhow!(
            "{} names vault '{named}': init adds to it from that vault, not from '{asked}'",
            path.display()
        ));
    }
    if !ctx.registry.exists(named) {
        return Err(anyhow!(
            "the vault '{named}' that {} names is not on this machine: bring it here with \
             `sourceorrery vault import FILE`, or create it with `sourceorrery vault create \
             {named}`",
            path.display()
        ));
    }
    Ok(named.clone())
}

/// The vault this run reads: the manifest's when there is one (another
/// one asked for is refused), else the one named, else the only vault in
/// the home directory.
fn choose_vault(
    ctx: &Ctx,
    args: &InitArgs,
    path: &Path,
    manifest: Option<&Manifest>,
) -> anyhow::Result<String> {
    let asked = args.target_vault.clone().or_else(|| ctx.vault_flag.clone());
    if let Some(manifest) = manifest {
        return manifest_vault(ctx, path, manifest, asked.as_deref());
    }
    if let Some(asked) = asked {
        return Ok(asked);
    }
    let vaults = ctx.registry.list()?;
    match vaults.as_slice() {
        [] => Err(anyhow!(
            "there is no vault yet: create one with `sourceorrery vault create NAME`, store the \
             project's secrets in it, then run init again"
        )),
        [only] => Ok(only.clone()),
        several => Err(anyhow!(
            "there are {} vaults ({}): name the one this project uses, as in `sourceorrery init \
             {}`",
            several.len(),
            several.join(", "),
            several[0]
        )),
    }
}

/// The catalog entries the arguments pick, in name order: every one for
/// `--all`, else each `--secret`, which the vault must have.
fn pick<'a>(
    catalog: &'a [CatalogEntry],
    args: &InitArgs,
    vault: &str,
) -> anyhow::Result<Vec<&'a CatalogEntry>> {
    if args.all {
        return Ok(catalog.iter().collect());
    }
    let mut picked: Vec<&CatalogEntry> = Vec::with_capacity(args.secrets.len());
    for name in &args.secrets {
        let entry = catalog
            .iter()
            .find(|entry| &entry.name == name)
            .ok_or_else(|| {
                anyhow!(
                    "vault '{vault}' has no secret '{}'; store it first with: sourceorrery \
                     secret set {} --vault {vault} --stdin",
                    output::sanitize(name),
                    output::sanitize(name)
                )
            })?;
        if !picked.iter().any(|p| p.name == entry.name) {
            picked.push(entry);
        }
    }
    picked.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(picked)
}

/// `text` with `changes` made to its `[secrets]`. A table added is placed
/// after the ones the file declares; nothing else in the text moves.
pub fn edit_secrets(text: &str, changes: &[Change]) -> anyhow::Result<String> {
    let mut doc: DocumentMut = text.parse().context("the manifest is not TOML")?;
    for change in changes {
        if let Change::Remove(name) = change
            && let Some(rotation) = doc.get_mut("rotation").and_then(Item::as_table_mut)
        {
            rotation.remove(name);
        }
    }
    let secrets = doc
        .entry("secrets")
        .or_insert_with(|| {
            let mut table = Table::new();
            table.set_implicit(true);
            Item::Table(table)
        })
        .as_table_mut()
        .ok_or_else(|| {
            anyhow!(
                "its [secrets] is not a table of its own; write each secret as \
                 [secrets.<name>] so init can change it"
            )
        })?;
    for change in changes {
        match change {
            Change::Add {
                name,
                required,
                purpose,
                env,
            } => {
                if secrets.contains_key(name) {
                    continue;
                }
                let mut table = Table::new();
                table.insert("required", value(*required));
                if let Some(purpose) = purpose {
                    table.insert("purpose", value(purpose.as_str()));
                }
                if let Some(env) = env {
                    table.insert("env", value(env.as_str()));
                }
                table.decor_mut().set_prefix("\n");
                secrets.insert(name, Item::Table(table));
            }
            Change::Remove(name) => {
                secrets.remove(name);
            }
            Change::Required { name, required } => {
                let entry = secrets
                    .get_mut(name)
                    .and_then(Item::as_table_mut)
                    .ok_or_else(|| anyhow!("[secrets.{name}] is not a table init can change"))?;
                match entry.get_mut("required").and_then(Item::as_value_mut) {
                    // The comment after the old value stays with the new one.
                    Some(old) => {
                        let decor = old.decor().clone();
                        *old = Value::from(*required);
                        *old.decor_mut() = decor;
                    }
                    None if *required => {}
                    None => {
                        entry.insert("required", value(false));
                    }
                }
            }
        }
    }
    Ok(doc.to_string())
}

/// The folder the manifest at `path` sits in, as the vault records it:
/// canonical, and on Windows without the `\\?\` prefix of that form.
pub fn project_folder(path: &Path) -> anyhow::Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let canonical = std::fs::canonicalize(parent)
        .with_context(|| format!("cannot find the folder {}", parent.display()))?;
    Ok(plain_path(canonical))
}

#[cfg(windows)]
fn plain_path(path: PathBuf) -> PathBuf {
    match path.to_str() {
        Some(text) => {
            if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
                PathBuf::from(format!(r"\\{rest}"))
            } else if let Some(rest) = text.strip_prefix(r"\\?\") {
                PathBuf::from(rest)
            } else {
                path
            }
        }
        None => path,
    }
}

#[cfg(not(windows))]
fn plain_path(path: PathBuf) -> PathBuf {
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add(name: &str, purpose: Option<&str>) -> Change {
        Change::Add {
            name: name.to_owned(),
            required: true,
            purpose: purpose.map(str::to_owned),
            env: None,
        }
    }

    const ORIGINAL: &str = "# my notes\n[project]\nname = \"app\"   # kept\nvault = \"dev\"\n\n\
                            [secrets.database-password]\nenv = \"DB_PASS\"\nversion = \"abc123\"\n\
                            required = false # for now\n\n[rotation.database-password]\n\
                            retire_after = \"7d\"\n";

    #[test]
    fn a_new_manifest_declares_each_pick_with_its_purpose() {
        let base = new_manifest_text("demo", "dev");
        let text = edit_secrets(
            &base,
            &[
                add("api-key", None),
                add("database-password", Some("Database authentication")),
            ],
        )
        .unwrap();
        assert!(text.starts_with(&base), "{text}");
        assert!(
            text.ends_with(
                "\n[secrets.api-key]\nrequired = true\n\n[secrets.database-password]\nrequired = \
             true\npurpose = \"Database authentication\"\n"
            ),
            "{text}"
        );
        let manifest = Manifest::parse(&text).unwrap();
        assert_eq!(manifest.secrets.len(), 2);
        assert!(manifest.secrets["api-key"].required);
    }

    #[test]
    fn an_existing_manifest_keeps_every_byte_outside_the_new_entries() {
        let text = edit_secrets(
            ORIGINAL,
            &[
                add("api-key", Some("Payment API key")),
                add("database-password", Some("ignored: declared already")),
            ],
        )
        .unwrap();
        let new_entry = "\n[secrets.api-key]\nrequired = true\npurpose = \"Payment API key\"\n";
        // The new entry sits after the declared secret, before the rotation
        // table, and the rest is the original text.
        let at = ORIGINAL.find("\n[rotation").unwrap();
        assert_eq!(
            text,
            format!("{}{new_entry}{}", &ORIGINAL[..at], &ORIGINAL[at..]),
            "{text}"
        );
        let manifest = Manifest::parse(&text).unwrap();
        assert_eq!(
            manifest.secrets["database-password"].env.as_deref(),
            Some("DB_PASS")
        );
        // Nothing to change: the same text.
        assert_eq!(edit_secrets(ORIGINAL, &[]).unwrap(), ORIGINAL);
    }

    #[test]
    fn a_new_entry_can_name_its_variable() {
        let text = edit_secrets(
            &new_manifest_text("demo", "dev"),
            &[Change::Add {
                name: "api-key".to_owned(),
                required: false,
                purpose: None,
                env: Some("PAYMENT_KEY".to_owned()),
            }],
        )
        .unwrap();
        let manifest = Manifest::parse(&text).unwrap();
        assert!(!manifest.secrets["api-key"].required);
        assert_eq!(
            manifest.secrets["api-key"].env.as_deref(),
            Some("PAYMENT_KEY")
        );
    }

    #[test]
    fn a_removed_entry_takes_its_rotation_table_and_nothing_else() {
        let with_key = edit_secrets(ORIGINAL, &[add("api-key", None)]).unwrap();
        let text =
            edit_secrets(&with_key, &[Change::Remove("database-password".to_owned())]).unwrap();
        let manifest = Manifest::parse(&text).unwrap();
        assert_eq!(manifest.secrets.keys().collect::<Vec<_>>(), ["api-key"]);
        assert!(manifest.rotation.is_empty());
        assert!(
            text.starts_with("# my notes\n[project]\nname = \"app\"   # kept\n"),
            "{text}"
        );
    }

    #[test]
    fn required_changes_in_place_and_keeps_its_comment() {
        let text = edit_secrets(
            ORIGINAL,
            &[Change::Required {
                name: "database-password".to_owned(),
                required: true,
            }],
        )
        .unwrap();
        assert_eq!(
            text,
            ORIGINAL.replace("required = false # for now", "required = true # for now")
        );
        let base = edit_secrets(&new_manifest_text("demo", "dev"), &[add("api-key", None)])
            .unwrap()
            .replace("required = true\n", "");
        let text = edit_secrets(
            &base,
            &[Change::Required {
                name: "api-key".to_owned(),
                required: false,
            }],
        )
        .unwrap();
        assert!(!Manifest::parse(&text).unwrap().secrets["api-key"].required);
    }

    #[test]
    fn a_purpose_with_quotes_reads_back_as_written() {
        let text = edit_secrets(
            &new_manifest_text("app", "dev"),
            &[add("api-key", Some(r#"The "billing" key, it's live"#))],
        )
        .unwrap();
        assert_eq!(
            Manifest::parse(&text).unwrap().secrets["api-key"]
                .purpose
                .as_deref(),
            Some(r#"The "billing" key, it's live"#)
        );
    }

    #[test]
    fn an_inline_secrets_table_is_not_rewritten() {
        let original = "secrets = { a = {} }\n[project]\nname = \"app\"\nvault = \"dev\"\n";
        let err = edit_secrets(original, &[add("api-key", None)]).unwrap_err();
        assert!(err.to_string().contains("[secrets.<name>]"), "{err}");
    }
}
