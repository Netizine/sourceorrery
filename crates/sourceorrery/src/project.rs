//! Loading the secrets a `sourceorrery.toml` manifest declares.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sourceorrery_core::{MANIFEST_FILE_NAME, Manifest, SecretError};

use crate::error::{Context, Error, ErrorKind, Result};
use crate::reader::{OpenOptions, SecretReader};
use crate::{SecretBytes, SecretProperties, SecretReference};

/// One secret resolved from the manifest.
#[derive(Debug)]
pub struct ProjectSecret {
    /// Name as written in the manifest.
    pub name: String,
    /// Environment variable the manifest delivers it in.
    pub env: String,
    /// Reference that was resolved.
    pub reference: SecretReference,
    /// Whether the manifest marks it required.
    pub required: bool,
    /// Metadata of the version that was read.
    pub properties: SecretProperties,
    /// The value.
    pub value: SecretBytes,
}

/// The secrets declared by a project manifest, resolved.
///
/// Mirrors `sourceorrery run`: every required secret must resolve or loading
/// fails before any value is handed out; an optional secret that is missing,
/// blocked by policy or whose vault does not exist is left out. A vault that
/// exists but cannot be unlocked fails the load even for optional secrets,
/// because that is a problem the user must see.
#[derive(Debug)]
pub struct Project {
    name: String,
    manifest_path: PathBuf,
    secrets: Vec<ProjectSecret>,
}

impl Project {
    /// Load the manifest at `manifest`, or the nearest `sourceorrery.toml`
    /// above the current directory when `None`, and resolve every entry.
    pub fn load(manifest: Option<&Path>, options: &OpenOptions) -> Result<Self> {
        let path = if let Some(path) = manifest {
            path.to_path_buf()
        } else {
            let cwd = std::env::current_dir()
                .map_err(|err| manifest_error(format!("cannot read working directory: {err}")))?;
            Manifest::discover(&cwd).ok_or_else(|| {
                manifest_error(format!(
                    "no {MANIFEST_FILE_NAME} found in {} or its parents (run `sourceorrery init`)",
                    cwd.display()
                ))
            })?
        };
        let parsed = Manifest::load(&path).map_err(|err| Error::new(&err, &Context::default()))?;
        let entries = parsed
            .entries()
            .map_err(|err| Error::new(&err, &Context::default()))?;

        let mut readers: BTreeMap<String, SecretReader> = BTreeMap::new();
        let mut secrets = Vec::with_capacity(entries.len());
        let mut missing: Vec<(SecretReference, Error)> = Vec::new();
        for entry in entries {
            let vault = entry.reference.vault.clone();
            if !readers.contains_key(&vault) {
                match SecretReader::open_with(&vault, options) {
                    Ok(reader) => {
                        readers.insert(vault.clone(), reader);
                    }
                    Err(err) if err.kind() == ErrorKind::VaultNotFound => {
                        if entry.required {
                            missing.push((entry.reference, err));
                        }
                        continue;
                    }
                    Err(err) => return Err(err),
                }
            }
            match readers[&vault].resolve_reference(&entry.reference) {
                Ok(secret) => secrets.push(ProjectSecret {
                    name: entry.name,
                    env: entry.env,
                    reference: entry.reference,
                    required: entry.required,
                    properties: secret.properties,
                    value: secret.value,
                }),
                Err(err) if entry.required => missing.push((entry.reference, err)),
                Err(_) => {}
            }
        }
        drop(readers);

        if let Some((first_ref, first)) = missing.first() {
            let message = if missing.len() == 1 {
                format!("required secret {first_ref}: {}", first.message())
            } else {
                let list: Vec<String> = missing
                    .iter()
                    .map(|(reference, err)| format!("{reference} ({})", err.code()))
                    .collect();
                format!(
                    "{} required secrets are unavailable: {}; first failure: {}",
                    missing.len(),
                    list.join(", "),
                    first.message()
                )
            };
            return Err(first.clone().with_message(message));
        }

        Ok(Self {
            name: parsed.project.name,
            manifest_path: path,
            secrets,
        })
    }

    /// `[project].name` from the manifest.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The manifest file that was loaded.
    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    /// Every secret that resolved, in manifest order.
    pub fn secrets(&self) -> &[ProjectSecret] {
        &self.secrets
    }

    /// The secret declared as `[secrets.<name>]`, if it resolved.
    pub fn get(&self, name: &str) -> Option<&ProjectSecret> {
        self.secrets.iter().find(|s| s.name == name)
    }

    /// The value delivered in environment variable `env`, if it resolved.
    pub fn env(&self, env: &str) -> Option<&SecretBytes> {
        self.secrets.iter().find(|s| s.env == env).map(|s| &s.value)
    }

    /// Consume the project into `(environment variable, value)` pairs.
    pub fn into_env(self) -> Vec<(String, SecretBytes)> {
        self.secrets.into_iter().map(|s| (s.env, s.value)).collect()
    }
}

fn manifest_error(message: String) -> Error {
    Error::new(&SecretError::Manifest(message), &Context::default())
}
