//! A backend that creates nothing: what the wizard asked for, recorded, and
//! fixed answers so the screens can be drawn and tested without a vault.

use sourceorrery_core::SecretBytes;
use sourceorrery_storage::RevealGuard;
use zeroize::Zeroizing;

use super::backend::{Backend, CheckRow, Enrolment, ProjectReady, VaultReady};

/// The code the fake accepts.
pub const CODE: &str = "492039";
/// The key the fake enrols with (the RFC 6238 test secret).
pub const KEY: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

const CODES: [&str; 5] = [
    "7K3QD-2M9RX-HT4VN-8WPB5-J6FGA",
    "C2N8M-R4XKQ-9TB7W-P5DHJ-3VZ6Y",
    "XQ4JF-8PNM2-T6RWB-D9HK3-5VZC7",
    "M9T2K-W6XRQ-4JPNB-H8DF3-Z5V7C",
    "R5H8W-K2QXM-7TNJ4-P9DB6-V3ZF8",
];

#[derive(Debug, Default)]
pub struct Fake {
    pub keyring: Option<&'static str>,
    /// Vault names that exist already.
    pub existing: Vec<String>,
    /// Refuse to open an existing vault with this message.
    pub refuse_open: Option<String>,
    /// `(name, keyring)` of the vault created.
    pub created: Option<(String, bool)>,
    /// Length of the passphrase the vault was created with.
    pub passphrase_len: usize,
    pub opened: Option<String>,
    /// `(name, value length)` of each secret stored.
    pub secrets: Vec<(String, usize)>,
    pub codes_issued: usize,
    pub hint: Option<String>,
    pub enrolled: bool,
    pub verified: bool,
    pub cancelled: usize,
    pub guard: Option<RevealGuard>,
    pub project_written_for: Option<String>,
    /// Make `write_project` report an existing manifest.
    pub manifest_exists: bool,
}

impl Fake {
    pub fn with_keyring() -> Self {
        Self {
            keyring: Some("macOS Keychain"),
            ..Self::default()
        }
    }
}

impl Backend for Fake {
    fn keyring(&self) -> Option<&'static str> {
        self.keyring
    }

    fn vault_exists(&self, name: &str) -> bool {
        self.existing.iter().any(|n| n == name)
    }

    fn create_vault(
        &mut self,
        name: &str,
        passphrase: SecretBytes,
        keyring: bool,
    ) -> Result<VaultReady, String> {
        if self.vault_exists(name) {
            return Err(format!("vault '{name}' already exists (vault_exists)"));
        }
        self.created = Some((name.to_owned(), keyring));
        self.passphrase_len = passphrase.len();
        Ok(VaultReady {
            name: name.to_owned(),
            path: format!("C:/Users/you/AppData/Local/sourceorrery/vaults/{name}.sorvault"),
            keyring,
            created: true,
        })
    }

    fn open_vault(&mut self, name: &str) -> Result<VaultReady, String> {
        if let Some(refusal) = &self.refuse_open {
            return Err(refusal.clone());
        }
        self.opened = Some(name.to_owned());
        Ok(VaultReady {
            name: name.to_owned(),
            path: format!("C:/Users/you/AppData/Local/sourceorrery/vaults/{name}.sorvault"),
            keyring: self.keyring.is_some(),
            created: false,
        })
    }

    fn set_secret(&mut self, name: &str, value: SecretBytes) -> Result<(), String> {
        self.secrets.push((name.to_owned(), value.len()));
        Ok(())
    }

    fn recovery_codes(&mut self, count: usize) -> Result<Vec<Zeroizing<String>>, String> {
        self.codes_issued = count;
        Ok(CODES
            .iter()
            .take(count)
            .map(|c| Zeroizing::new((*c).to_owned()))
            .collect())
    }

    fn set_hint(&mut self, hint: &str) -> Result<(), String> {
        if hint.len() > 120 {
            return Err("a hint has at most 120 characters (invalid_argument)".to_owned());
        }
        self.hint = Some(hint.to_owned());
        Ok(())
    }

    fn enrol(&mut self) -> Result<Enrolment, String> {
        self.enrolled = true;
        self.verified = false;
        Ok(Enrolment {
            uri: Zeroizing::new(format!(
                "otpauth://totp/SourceOrrery:development?secret={KEY}&issuer=SourceOrrery"
            )),
            key: Zeroizing::new(KEY.to_owned()),
        })
    }

    fn verify_code(&mut self, code: &str) -> Result<bool, String> {
        if !self.enrolled {
            return Err("no second factor is enrolled".to_owned());
        }
        self.verified = code == CODE;
        Ok(self.verified)
    }

    fn cancel_enrolment(&mut self) -> Result<(), String> {
        self.enrolled = false;
        self.verified = false;
        self.cancelled += 1;
        Ok(())
    }

    fn set_guard(&mut self, guard: RevealGuard) -> Result<RevealGuard, String> {
        if guard.second_factor && !self.verified {
            return Err(
                "the guard cannot ask for a second factor until one is enrolled and \
                        verified (invalid_argument)"
                    .to_owned(),
            );
        }
        self.guard = Some(guard);
        Ok(guard)
    }

    fn write_project(&mut self, secret: &str) -> Result<ProjectReady, String> {
        self.project_written_for = Some(secret.to_owned());
        let rows = vec![CheckRow {
            name: secret.to_owned(),
            env: secret.to_uppercase().replace('-', "_"),
            status: if self.secrets.iter().any(|(n, _)| n == secret) {
                "ok".to_owned()
            } else {
                "secret_not_found".to_owned()
            },
        }];
        Ok(ProjectReady {
            manifest: "C:/code/my-application/sourceorrery.toml".into(),
            written: !self.manifest_exists,
            ok: rows.iter().all(|r| r.status == "ok"),
            rows,
        })
    }
}
