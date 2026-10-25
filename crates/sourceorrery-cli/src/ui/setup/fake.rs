//! A backend that touches no vault: fixed vaults, a view check and a
//! recovery key to answer, and what the screens asked for, recorded, so
//! they can be driven and drawn in tests.

use sourceorrery_core::{ConnectionSettings, Provider, SecretBytes, timestamp};
use sourceorrery_storage::{
    AuthenticatorChange, ConnectionChange, ConnectionInfo, CredentialSource, PasswordChange,
    ViewCheck,
};

use super::backend::{Backend, Committed, OpenOutcome, Opened, Plan, TestCredentials};

/// Where the made-up person the fakes show keeps vaults, never the machine
/// running them: the design snapshots draw these screens for the docs.
pub const VAULTS_DIR: &str = r"C:\Users\alex\AppData\Local\sourceorrery\vaults";
/// The password that passes the fake vaults' view check.
pub const PASSWORD: &str = "orbit lantern copper nine 42";
/// The code that passes it, when the vault asks for one.
pub const CODE: &str = "123456";
/// The recovery key that opens a locked fake vault.
pub const RECOVERY_KEY: &str = "SORK-FAKE-RECOVERY-KEY";

#[derive(Debug)]
pub struct Fake {
    pub vaults: Vec<Opened>,
    pub store: Option<String>,
    pub providers: Vec<Provider>,
    /// The vault this machine cannot open without [`RECOVERY_KEY`].
    pub locked: Option<String>,
    /// The vaults opened, in order, and whether with a recovery key.
    pub opens: Vec<(String, bool)>,
    /// Answers to the view check, in order: the password's length and the code.
    pub checks: Vec<(usize, Option<String>)>,
    /// The connection tests: the settings, and `ambient`, `given` or `kept`.
    pub tests: Vec<(ConnectionSettings, &'static str)>,
    pub refuse_test: Option<String>,
    pub refuse_commit: Option<String>,
    /// The plans committed (or refused), in order.
    pub plans: Vec<Plan>,
}

impl Default for Fake {
    fn default() -> Self {
        Self {
            vaults: Vec::new(),
            store: Some("Windows Credential Manager".to_owned()),
            providers: Provider::ALL.to_vec(),
            locked: None,
            opens: Vec::new(),
            checks: Vec::new(),
            tests: Vec::new(),
            refuse_test: None,
            refuse_commit: None,
            plans: Vec::new(),
        }
    }
}

pub fn hashicorp(id: &str) -> ConnectionInfo {
    ConnectionInfo {
        id: id.to_owned(),
        settings: ConnectionSettings::HashicorpVault {
            address: "https://vault.example.com:8200".to_owned(),
            mount: "secret".to_owned(),
            namespace: None,
        },
        credentials: CredentialSource::Stored,
        created_on: timestamp::now(),
        last_test: None,
    }
}

impl Fake {
    /// One vault, `dev`, with `view` and a HashiCorp Vault connection whose
    /// token it stores.
    pub fn one_vault(view: ViewCheck) -> Self {
        Self {
            vaults: vec![Opened {
                name: "dev".to_owned(),
                path: format!(r"{VAULTS_DIR}\dev.sorvault"),
                view,
                passed: false,
                hint: view.password.then(|| "the long one".to_owned()),
                connections: vec![hashicorp("c1")],
            }],
            ..Self::default()
        }
    }

    fn find(&self, name: &str) -> Option<&Opened> {
        self.vaults
            .iter()
            .find(|v| v.name.eq_ignore_ascii_case(name))
    }

    /// The last plan the review sent.
    pub fn plan(&self) -> &Plan {
        self.plans.last().expect("a plan was committed")
    }
}

impl Backend for Fake {
    fn vaults(&self) -> Result<Vec<String>, String> {
        Ok(self.vaults.iter().map(|v| v.name.clone()).collect())
    }

    fn store(&self) -> Option<String> {
        self.store.clone()
    }

    fn providers(&self) -> Vec<Provider> {
        self.providers.clone()
    }

    fn open(
        &mut self,
        name: &str,
        recovery_key: Option<SecretBytes>,
    ) -> Result<OpenOutcome, String> {
        let mut opened = self.find(name).ok_or("no such vault")?.clone();
        let with_key = recovery_key.is_some();
        if self.locked.as_deref() == Some(opened.name.as_str()) {
            match recovery_key {
                // The recovery key passes the check by itself.
                Some(key) if key.expose() == RECOVERY_KEY.as_bytes() => opened.passed = true,
                _ => return Ok(OpenOutcome::NeedsRecoveryKey),
            }
        }
        self.opens.push((opened.name.clone(), with_key));
        Ok(OpenOutcome::Opened(opened))
    }

    fn check_view(&mut self, password: SecretBytes, code: Option<String>) -> Result<(), String> {
        self.checks.push((password.expose().len(), code.clone()));
        let asked = self
            .opens
            .last()
            .and_then(|(name, _)| self.find(name))
            .map(|v| v.view)
            .unwrap_or_default();
        let code_ok = !asked.authenticator || code.as_deref() == Some(CODE);
        if password.expose() == PASSWORD.as_bytes() && code_ok {
            Ok(())
        } else {
            Err("the view check was not passed".to_owned())
        }
    }

    fn test_connection(
        &mut self,
        settings: &ConnectionSettings,
        credentials: &TestCredentials,
    ) -> Result<(), String> {
        let kind = match credentials {
            TestCredentials::Ambient => "ambient",
            TestCredentials::Given(_) => "given",
            TestCredentials::Kept(_) => "kept",
        };
        self.tests.push((settings.clone(), kind));
        self.refuse_test.clone().map_or(Ok(()), Err)
    }

    fn commit(&mut self, plan: Plan) -> Result<Committed, String> {
        let before = self.find(&plan.name).cloned();
        let had = before.as_ref().map(|v| v.view).unwrap_or_default();
        let password = match plan.change.password {
            PasswordChange::Keep => had.password,
            PasswordChange::Set { .. } => true,
            PasswordChange::Clear => false,
        };
        let authenticator = password
            && match plan.change.authenticator {
                AuthenticatorChange::Keep => had.authenticator,
                AuthenticatorChange::Remove => false,
                AuthenticatorChange::Verified { .. } => true,
            };
        let mut connections = before.map(|v| v.connections).unwrap_or_default();
        for (i, change) in plan.change.connections.iter().enumerate() {
            match change {
                ConnectionChange::Add {
                    settings,
                    credentials,
                } => connections.push(ConnectionInfo {
                    id: format!("n{i}"),
                    settings: settings.clone(),
                    credentials: if credentials.is_some() {
                        CredentialSource::Stored
                    } else {
                        CredentialSource::Ambient
                    },
                    created_on: timestamp::now(),
                    last_test: None,
                }),
                ConnectionChange::Remove { id } => connections.retain(|c| c.id != *id),
                ConnectionChange::Settings { .. } | ConnectionChange::Credentials { .. } => {}
            }
        }
        let refused = self.refuse_commit.clone();
        let committed = Committed {
            name: plan.name.clone(),
            path: format!(r"{VAULTS_DIR}\{}.sorvault", plan.name),
            view: ViewCheck {
                password,
                authenticator,
            },
            this_machine: self.store.is_some(),
            connections,
        };
        self.plans.push(plan);
        refused.map_or(Ok(committed), Err)
    }
}
