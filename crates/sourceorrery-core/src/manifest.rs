//! The no-secret project manifest (`sourceorrery.toml`).
//!
//! A manifest declares which secrets a project needs and how they are
//! delivered to the runtime. It is safe to commit because it *cannot* hold a
//! value: every section rejects unknown fields, so `value = "..."` is a parse
//! error, not a leak.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Result, SecretError};
use crate::secret::{SecretReference, validate_secret_name, validate_version_id};
use crate::vault::validate_vault_name;

/// Conventional manifest file name.
pub const MANIFEST_FILE_NAME: &str = "sourceorrery.toml";

/// A parsed `sourceorrery.toml`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Project-wide settings.
    pub project: ProjectSection,
    /// Secrets the project requires, keyed by secret name.
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretRequirement>,
}

/// `[project]` section.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectSection {
    /// Human-readable project name.
    pub name: String,
    /// Default vault the secrets are resolved from.
    pub vault: String,
}

/// `[secrets.<name>]` entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRequirement {
    /// Whether the runtime must refuse to start without it (default `true`).
    #[serde(default = "default_true")]
    pub required: bool,
    /// Why the project needs it. Documentation only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Environment variable to deliver it in. Defaults to the secret name in
    /// `UPPER_SNAKE_CASE` (`database-password` → `DATABASE_PASSWORD`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    /// Pin to a specific version instead of the newest accessible one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Resolve from a different vault than `[project].vault`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
}

impl Default for SecretRequirement {
    fn default() -> Self {
        Self {
            required: true,
            purpose: None,
            env: None,
            version: None,
            vault: None,
        }
    }
}

fn default_true() -> bool {
    true
}

/// One resolved line of the manifest: where to fetch and where to deliver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestEntry {
    /// Secret name as written in the manifest.
    pub name: String,
    /// Reference to resolve.
    pub reference: SecretReference,
    /// Environment variable to populate.
    pub env: String,
    /// Whether absence is fatal.
    pub required: bool,
}

impl Manifest {
    /// Parse TOML text.
    pub fn parse(text: &str) -> Result<Self> {
        let manifest: Self = toml::from_str(text)
            .map_err(|err| SecretError::Manifest(redact_toml_error(text, &err)))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Read and parse a manifest file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|err| {
            SecretError::Manifest(format!("cannot read {}: {err}", path.display()))
        })?;
        Self::parse(&text)
            .map_err(|err| SecretError::Manifest(format!("{}: {err}", path.display())))
    }

    /// Serialise to TOML.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|err| SecretError::Manifest(err.to_string()))
    }

    /// Walk up from `start` looking for [`MANIFEST_FILE_NAME`].
    pub fn discover(start: &Path) -> Option<PathBuf> {
        let mut dir = if start.is_file() {
            start.parent()?
        } else {
            start
        };
        loop {
            let candidate = dir.join(MANIFEST_FILE_NAME);
            if candidate.is_file() {
                return Some(candidate);
            }
            dir = dir.parent()?;
        }
    }

    /// A starter manifest for `sourceorrery init`.
    pub fn template(project_name: &str, vault: &str) -> Self {
        let mut secrets = BTreeMap::new();
        secrets.insert(
            "database-password".to_owned(),
            SecretRequirement {
                purpose: Some("Database authentication".to_owned()),
                ..Default::default()
            },
        );
        Self {
            project: ProjectSection {
                name: project_name.to_owned(),
                vault: vault.to_owned(),
            },
            secrets,
        }
    }

    /// Check names, vaults, versions and environment variable names.
    pub fn validate(&self) -> Result<()> {
        if self.project.name.trim().is_empty() {
            return Err(SecretError::Manifest(
                "[project].name must not be empty".to_owned(),
            ));
        }
        validate_vault_name(&self.project.vault)
            .map_err(|err| SecretError::Manifest(format!("[project].vault: {err}")))?;
        let mut seen_env = BTreeMap::new();
        for (name, requirement) in &self.secrets {
            validate_secret_name(name)
                .map_err(|err| SecretError::Manifest(format!("[secrets.{name}]: {err}")))?;
            if let Some(vault) = &requirement.vault {
                validate_vault_name(vault).map_err(|err| {
                    SecretError::Manifest(format!("[secrets.{name}].vault: {err}"))
                })?;
            }
            if let Some(version) = &requirement.version {
                validate_version_id(version).map_err(|err| {
                    SecretError::Manifest(format!("[secrets.{name}].version: {err}"))
                })?;
            }
            let env = env_name_for(name, requirement);
            validate_env_name(&env)
                .map_err(|err| SecretError::Manifest(format!("[secrets.{name}].env: {err}")))?;
            // Windows resolves environment names case-insensitively, so two
            // entries differing only in case would silently overwrite each
            // other there. Portable manifests reject that everywhere.
            if let Some(previous) = seen_env.insert(env.to_ascii_uppercase(), name.clone()) {
                return Err(SecretError::Manifest(format!(
                    "secrets '{previous}' and '{name}' both map to environment variable {env} \
                     (names are compared case-insensitively for portability)"
                )));
            }
        }
        Ok(())
    }

    /// Every secret the manifest asks for, with its reference and target
    /// environment variable.
    pub fn entries(&self) -> Result<Vec<ManifestEntry>> {
        self.secrets
            .iter()
            .map(|(name, requirement)| {
                let vault = requirement.vault.as_deref().unwrap_or(&self.project.vault);
                let mut reference = SecretReference::new(vault, name.as_str())?;
                if let Some(version) = &requirement.version {
                    reference = reference.with_version(version.as_str())?;
                }
                Ok(ManifestEntry {
                    name: name.clone(),
                    reference,
                    env: env_name_for(name, requirement),
                    required: requirement.required,
                })
            })
            .collect()
    }
}

/// Default environment variable name for a secret: `UPPER_SNAKE_CASE`.
pub fn default_env_name(secret_name: &str) -> String {
    secret_name
        .chars()
        .map(|c| {
            if c == '-' {
                '_'
            } else {
                c.to_ascii_uppercase()
            }
        })
        .collect()
}

/// The secret name an environment variable is stored under when a `.env`
/// file is imported: lower case, underscores as hyphens
/// (`DATABASE_PASSWORD` → `database-password`), so that
/// [`default_env_name`] gives the variable back whenever it was written in
/// `UPPER_SNAKE_CASE`. `None` when `key` cannot be a manifest entry: not a
/// valid environment variable name, reserved for SourceOrrery, or longer
/// than a secret name may be.
pub fn secret_name_for_env(key: &str) -> Option<String> {
    validate_env_name(key).ok()?;
    let name: String = key
        .chars()
        .map(|c| {
            if c == '_' {
                '-'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();
    validate_secret_name(&name).ok()?;
    Some(name)
}

/// The `env` a manifest entry for `key` needs: `None` when the secret
/// name's default ([`default_env_name`]) already is `key`.
pub fn explicit_env_for(secret_name: &str, key: &str) -> Option<String> {
    (default_env_name(secret_name) != key).then(|| key.to_owned())
}

fn env_name_for(name: &str, requirement: &SecretRequirement) -> String {
    requirement
        .env
        .clone()
        .unwrap_or_else(|| default_env_name(name))
}

/// Prefix reserved for SourceOrrery's own variables; a manifest may not
/// deliver a secret under such a name, so project metadata can never shadow
/// or expose the tool's unlock configuration.
pub const RESERVED_ENV_PREFIX: &str = "SOURCEORRERY_";

/// TOML error messages that mention only key names, which are safe to repeat.
const KEYS_ONLY_MESSAGES: [&str; 3] = ["unknown field", "missing field", "duplicate key"];

/// Describe a TOML error without quoting the document.
///
/// `toml`'s `Display` output includes the offending source line, which would
/// echo a value someone wrongly pasted into the manifest into terminals, JSON
/// errors and CI logs. Only messages that name keys are repeated; everything
/// else becomes a category plus a line and column.
fn redact_toml_error(text: &str, err: &toml::de::Error) -> String {
    let location = err
        .span()
        .map(|span| {
            let start = span.start.min(text.len());
            let line = text[..start].matches('\n').count() + 1;
            let column = text[..start].rsplit('\n').next().map_or(0, str::len) + 1;
            format!(" at line {line}, column {column}")
        })
        .unwrap_or_default();
    let message = err.message();
    if KEYS_ONLY_MESSAGES
        .iter()
        .any(|prefix| message.starts_with(prefix))
    {
        format!("{message}{location}")
    } else {
        format!(
            "invalid TOML syntax or value type{location} \
             (the offending text is not repeated, in case it is a secret)"
        )
    }
}

fn validate_env_name(env: &str) -> Result<()> {
    if env.to_ascii_uppercase().starts_with(RESERVED_ENV_PREFIX) {
        return Err(SecretError::InvalidArgument(format!(
            "'{env}' is reserved: names starting with {RESERVED_ENV_PREFIX} belong to SourceOrrery"
        )));
    }
    let mut chars = env.chars();
    let valid_start = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    let valid_rest = chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid_start || !valid_rest {
        return Err(SecretError::InvalidArgument(format!(
            "'{env}' is not a valid environment variable name"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
[project]
name = "my-application"
vault = "development"

[secrets.database-password]
required = true
purpose = "Database authentication"

[secrets.payment-api-key]
required = false
purpose = "Payments sandbox"
env = "STRIPE_KEY"
version = "abc123"
vault = "payments-sandbox"
"#;

    #[test]
    fn parses_the_documented_example() {
        let manifest = Manifest::parse(EXAMPLE).unwrap();
        assert_eq!(manifest.project.vault, "development");
        let entries = manifest.entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].env, "DATABASE_PASSWORD");
        assert_eq!(
            entries[0].reference.to_string(),
            "sourceorrery://development/database-password"
        );
        assert_eq!(entries[1].env, "STRIPE_KEY");
        assert!(!entries[1].required);
        assert_eq!(
            entries[1].reference.to_string(),
            "sourceorrery://payments-sandbox/payment-api-key/abc123"
        );
    }

    #[test]
    fn a_manifest_cannot_carry_a_value() {
        let text = r#"
[project]
name = "x"
vault = "dev"

[secrets.database-password]
value = "hunter2"
"#;
        let err = Manifest::parse(text).unwrap_err();
        assert_eq!(err.code(), "manifest");
        assert!(err.to_string().contains("value"));
    }

    #[test]
    fn rejects_env_collisions_and_bad_names() {
        let text = r#"
[project]
name = "x"
vault = "dev"

[secrets.a-b]
[secrets.a_b]
"#;
        assert!(Manifest::parse(text).is_err());

        let text = r#"
[project]
name = "x"
vault = "dev"

[secrets.a-b]
env = "1BAD"
"#;
        assert!(Manifest::parse(text).is_err());
    }

    #[test]
    fn errors_never_echo_the_document() {
        const CANARY: &str = "REJECTED_VALUE_CANARY_9f1c";
        let head = "[project]\nname = \"x\"\nvault = \"dev\"\n\n";
        let cases = [
            // Unknown field carrying the value.
            format!("{head}[secrets.db]\nvalue = \"{CANARY}\"\n"),
            // Wrong type: a secret pasted where a boolean belongs.
            format!("{head}[secrets.db]\nrequired = \"{CANARY}\"\n"),
            // Syntax error on a line that contains the value.
            format!("{head}[secrets.db]\npurpose = {CANARY}\n"),
            // Unknown top-level table.
            format!("{head}[values]\ndb = \"{CANARY}\"\n"),
        ];
        for text in cases {
            let err = Manifest::parse(&text).unwrap_err();
            assert_eq!(err.code(), "manifest");
            let shown = err.to_string();
            assert!(
                !shown.contains(CANARY),
                "diagnostic echoed the value: {shown}"
            );
            assert!(
                shown.contains("line "),
                "diagnostic lacks a location: {shown}"
            );
        }
    }

    #[test]
    fn env_collisions_are_case_insensitive_and_reserved_names_rejected() {
        let head = "[project]\nname = \"x\"\nvault = \"dev\"\n\n";
        let text = format!(
            "{head}[secrets.a-one]\nenv = \"SAME_KEY\"\n\n[secrets.a-two]\nenv = \"same_key\"\n"
        );
        let err = Manifest::parse(&text).unwrap_err();
        assert!(err.to_string().contains("case-insensitively"), "{err}");

        let text = format!("{head}[secrets.a-one]\nenv = \"sourceorrery_passphrase\"\n");
        let err = Manifest::parse(&text).unwrap_err();
        assert!(err.to_string().contains("reserved"), "{err}");
    }

    #[test]
    fn template_round_trips() {
        let manifest = Manifest::template("demo", "development");
        let text = manifest.to_toml().unwrap();
        assert_eq!(Manifest::parse(&text).unwrap(), manifest);
        assert!(text.contains("database-password"));
    }

    #[test]
    fn discovers_upwards() {
        let dir =
            std::env::temp_dir().join(format!("sourceorrery-manifest-{}", std::process::id()));
        let nested = dir.join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            dir.join(MANIFEST_FILE_NAME),
            Manifest::template("demo", "development").to_toml().unwrap(),
        )
        .unwrap();
        let found = Manifest::discover(&nested).unwrap();
        assert_eq!(found, dir.join(MANIFEST_FILE_NAME));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn default_env_names() {
        assert_eq!(default_env_name("database-password"), "DATABASE_PASSWORD");
        assert_eq!(default_env_name("ApiKey2"), "APIKEY2");
    }

    #[test]
    fn env_keys_map_to_secret_names_and_back() {
        for (key, name, env) in [
            ("DATABASE_PASSWORD", "database-password", None),
            ("STRIPE_KEY_2", "stripe-key-2", None),
            ("_PRIVATE", "-private", None),
            ("apiKey", "apikey", Some("apiKey")),
            ("npm_token", "npm-token", Some("npm_token")),
        ] {
            let secret = secret_name_for_env(key).unwrap();
            assert_eq!(secret, name, "{key}");
            assert_eq!(explicit_env_for(&secret, key).as_deref(), env, "{key}");
            let delivered = env.map_or_else(|| default_env_name(&secret), str::to_owned);
            assert_eq!(delivered, key, "the manifest entry delivers {key} back");
        }
        for key in [
            "",
            "2FA",
            "WITH-DASH",
            "a.b",
            "SOURCEORRERY_HOME",
            &"K".repeat(128),
        ] {
            assert_eq!(secret_name_for_env(key), None, "{key}");
        }
    }
}
