//! What the wizard does to the world, behind one trait, so the screens can
//! be driven in tests (and drawn for the design snapshots) with a fake that
//! creates nothing.
//!
//! Every value the wizard hands over arrives as [`SecretBytes`] and goes
//! straight to the vault; nothing here returns one. What comes back is
//! what the screens may show: names, paths, a store's name, the one-time
//! recovery codes and the enrolment (the authenticator's key and URI, which
//! the user is about to scan), and outcomes.

use std::path::{Path, PathBuf};

use sourceorrery_core::manifest::SecretRequirement;
use sourceorrery_core::{
    MANIFEST_FILE_NAME, Manifest, SecretBytes, SecretClient, SecretError, SetSecretOptions, policy,
    timestamp,
};
use sourceorrery_crypto::{Argon2Params, random};
use sourceorrery_storage::{CreateVaultOptions, ProtectorSpec, RevealGuard, SqliteVault, keystore};
use zeroize::Zeroizing;

use crate::commands::project::MANIFEST_HEADER;
use crate::context::Ctx;

/// A vault the wizard created or opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultReady {
    pub name: String,
    /// Where the file is, for the summary.
    pub path: String,
    /// Whether the OS credential store unlocks it too.
    pub keyring: bool,
    /// Created now, or an existing vault opened.
    pub created: bool,
}

/// An authenticator enrolment, shown once as a QR code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enrolment {
    pub uri: String,
    pub key: String,
}

/// One manifest entry as the setup check saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckRow {
    pub name: String,
    pub env: String,
    pub status: String,
}

/// The project step's outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectReady {
    pub manifest: PathBuf,
    /// Written now, or an existing manifest kept.
    pub written: bool,
    pub rows: Vec<CheckRow>,
    /// Every required entry resolved.
    pub ok: bool,
}

/// The world as the wizard sees it.
pub trait Backend {
    /// The OS credential store's name when it can hold a key here.
    fn keyring(&self) -> Option<&'static str>;
    /// A vault file of this name exists already.
    fn vault_exists(&self, name: &str) -> bool;
    /// Create the vault with a passphrase protector, and the OS keyring as
    /// a second way in when asked.
    fn create_vault(
        &mut self,
        name: &str,
        passphrase: SecretBytes,
        keyring: bool,
    ) -> Result<VaultReady, String>;
    /// Open an existing vault (may prompt: the caller suspends the screen).
    fn open_vault(&mut self, name: &str) -> Result<VaultReady, String>;
    fn set_secret(&mut self, name: &str, value: SecretBytes) -> Result<(), String>;
    /// Replace the recovery codes; the new codes, to show once.
    fn recovery_codes(&mut self, count: usize) -> Result<Vec<Zeroizing<String>>, String>;
    fn set_hint(&mut self, hint: &str) -> Result<(), String>;
    fn enrol(&mut self) -> Result<Enrolment, String>;
    fn verify_code(&mut self, code: &str) -> Result<bool, String>;
    fn cancel_enrolment(&mut self) -> Result<(), String>;
    fn set_guard(&mut self, guard: RevealGuard) -> Result<RevealGuard, String>;
    /// Write the manifest (unless one exists) declaring `secret`, and check
    /// every entry it holds against the vault.
    fn write_project(&mut self, secret: &str) -> Result<ProjectReady, String>;
}

/// The real thing: the vault registry and one vault file.
pub struct Live<'a> {
    ctx: &'a Ctx,
    vault: Option<SqliteVault>,
    manifest: PathBuf,
    project_name: String,
}

impl<'a> Live<'a> {
    pub fn new(ctx: &'a Ctx, manifest: Option<&Path>, project_name: Option<&str>) -> Self {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let project_name = project_name.map_or_else(
            || {
                cwd.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("my-application")
                    .to_owned()
            },
            str::to_owned,
        );
        Self {
            ctx,
            vault: None,
            manifest: manifest.map_or_else(|| cwd.join(MANIFEST_FILE_NAME), Path::to_path_buf),
            project_name,
        }
    }

    fn vault(&self) -> Result<&SqliteVault, String> {
        self.vault
            .as_ref()
            .ok_or_else(|| "no vault is open yet".to_owned())
    }

    fn ready(vault: &SqliteVault, created: bool) -> Result<VaultReady, String> {
        let descriptor = vault.descriptor().map_err(|err| describe(&err))?;
        let protectors = vault.protectors().map_err(|err| describe(&err))?;
        Ok(VaultReady {
            name: descriptor.name,
            path: descriptor
                .path
                .as_deref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            keyring: protectors.iter().any(|p| p.kind == "os-keyring"),
            created,
        })
    }
}

fn describe(err: &SecretError) -> String {
    format!("{err} ({})", err.code())
}

impl Backend for Live<'_> {
    fn keyring(&self) -> Option<&'static str> {
        keystore::available().then_some(keystore::STORE_NAME)
    }

    fn vault_exists(&self, name: &str) -> bool {
        self.ctx.registry.exists(name)
    }

    fn create_vault(
        &mut self,
        name: &str,
        passphrase: SecretBytes,
        keyring: bool,
    ) -> Result<VaultReady, String> {
        let vault = self
            .ctx
            .registry
            .create(
                name,
                CreateVaultOptions::default(),
                ProtectorSpec::passphrase(passphrase),
            )
            .map_err(|err| describe(&err))?;
        if keyring {
            vault
                .add_protector(ProtectorSpec::OsKeyring, None)
                .map_err(|err| describe(&err))?;
        }
        let ready = Self::ready(&vault, true)?;
        self.vault = Some(vault);
        Ok(ready)
    }

    fn open_vault(&mut self, name: &str) -> Result<VaultReady, String> {
        let vault = self
            .ctx
            .open_local(name, "setup")
            .map_err(|err| format!("{err:#}"))?;
        let ready = Self::ready(&vault, false)?;
        self.vault = Some(vault);
        Ok(ready)
    }

    fn set_secret(&mut self, name: &str, value: SecretBytes) -> Result<(), String> {
        self.vault()?
            .set_secret(name, value, SetSecretOptions::default())
            .map(drop)
            .map_err(|err| describe(&err))
    }

    fn recovery_codes(&mut self, count: usize) -> Result<Vec<Zeroizing<String>>, String> {
        let vault = self.vault()?;
        let mut shown = Vec::with_capacity(count);
        let mut installed = Vec::with_capacity(count);
        for _ in 0..count {
            let code = random::recovery_code().map_err(|err| err.to_string())?;
            installed.push(SecretBytes::from_string(
                random::normalise_recovery_code(&code).to_string(),
            ));
            shown.push(code);
        }
        vault
            .replace_recovery_codes(installed, Argon2Params::default())
            .map_err(|err| describe(&err))?;
        Ok(shown)
    }

    fn set_hint(&mut self, hint: &str) -> Result<(), String> {
        self.vault()?
            .set_passphrase_hint(Some(hint))
            .map_err(|err| describe(&err))
    }

    fn enrol(&mut self) -> Result<Enrolment, String> {
        let vault = self.vault()?;
        let secret = vault.enrol_second_factor().map_err(|err| describe(&err))?;
        Ok(Enrolment {
            uri: secret.otpauth_uri("SourceOrrery", vault.vault_name()),
            key: secret.to_base32(),
        })
    }

    fn verify_code(&mut self, code: &str) -> Result<bool, String> {
        self.vault()?
            .verify_second_factor(code, timestamp::now())
            .map_err(|err| describe(&err))
    }

    fn cancel_enrolment(&mut self) -> Result<(), String> {
        self.vault()?
            .disable_second_factor()
            .map_err(|err| describe(&err))
    }

    fn set_guard(&mut self, guard: RevealGuard) -> Result<RevealGuard, String> {
        self.vault()?
            .set_reveal_guard(guard)
            .map_err(|err| describe(&err))
    }

    fn write_project(&mut self, secret: &str) -> Result<ProjectReady, String> {
        let vault = self.vault()?;
        let name = vault.vault_name().to_owned();
        let written = !self.manifest.exists();
        if written {
            let mut manifest = Manifest::template(&self.project_name, &name);
            manifest.secrets.clear();
            manifest
                .secrets
                .insert(secret.to_owned(), SecretRequirement::default());
            let text = format!(
                "{MANIFEST_HEADER}{}",
                manifest.to_toml().map_err(|err| describe(&err))?
            );
            std::fs::write(&self.manifest, text)
                .map_err(|err| format!("cannot write {}: {err}", self.manifest.display()))?;
        }
        let manifest = Manifest::load(&self.manifest).map_err(|err| describe(&err))?;
        let now = timestamp::now();
        let mut ok = true;
        let rows = manifest
            .entries()
            .map_err(|err| describe(&err))?
            .into_iter()
            .map(|entry| {
                let status = if entry.reference.vault == name {
                    // Metadata only, as `check` does it: no value is read.
                    let outcome = vault
                        .list_properties_of_secret_versions(&entry.reference.name)
                        .and_then(|versions| {
                            policy::select_latest_accessible(&entry.reference.name, &versions, now)
                                .map(|_| ())
                        });
                    match outcome {
                        Ok(()) => "ok".to_owned(),
                        Err(err) => {
                            if entry.required {
                                ok = false;
                            }
                            err.code().to_owned()
                        }
                    }
                } else {
                    format!("in vault '{}', not checked", entry.reference.vault)
                };
                CheckRow {
                    name: entry.name,
                    env: entry.env,
                    status,
                }
            })
            .collect();
        Ok(ProjectReady {
            manifest: self.manifest.clone(),
            written,
            rows,
            ok,
        })
    }
}
