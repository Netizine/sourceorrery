//! The identity the provider signs in with: the service principal a
//! connection stores ([`Chain::from_credentials`]), or else the first Azure
//! SDK credential the process's environment provides, in this order.
//!
//! 1. A service principal: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and
//!    `AZURE_CLIENT_SECRET`.
//! 2. Workload identity federation: `AZURE_FEDERATED_TOKEN_FILE` with
//!    `AZURE_TENANT_ID` and `AZURE_CLIENT_ID` (Kubernetes, GitHub Actions).
//! 3. The developer tools: the Azure CLI, then the Azure Developer CLI.
//! 4. A managed identity (`AZURE_CLIENT_ID` names a user-assigned one).
//!
//! The developer tools come before the managed identity so a workstation
//! never waits on the instance metadata endpoint. `AZURE_AUTHORITY_HOST`
//! names another cloud's (or an emulator's) sign-in authority, for a stored
//! service principal too.

use std::fmt;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use azure_core::cloud::{CloudConfiguration, CustomConfiguration};
use azure_core::credentials::{AccessToken, TokenCredential, TokenRequestOptions};
use azure_core::error::ErrorKind;
use azure_core::http::ClientOptions;
use azure_identity::{
    ClientAssertionCredentialOptions, ClientSecretCredential, ClientSecretCredentialOptions,
    DeveloperToolsCredential, ManagedIdentityCredential, ManagedIdentityCredentialOptions,
    UserAssignedId, WorkloadIdentityCredential, WorkloadIdentityCredentialOptions,
};
use sourceorrery_core::{Credentials, Provider, Result, SecretError};

const AUTHORITY_HOST: &str = "AZURE_AUTHORITY_HOST";

/// The cloud `AZURE_AUTHORITY_HOST` names; Azure's public cloud when it is
/// unset or empty. Every client is given this explicitly, because without
/// one the SDK reads the variable itself and fails on an empty value.
pub fn cloud_from_env() -> Result<Arc<CloudConfiguration>> {
    let Some(host) = env(AUTHORITY_HOST) else {
        return Ok(Arc::new(CloudConfiguration::AzurePublic));
    };
    if !host.starts_with("https://") {
        return Err(SecretError::InvalidArgument(format!(
            "{AUTHORITY_HOST} must be an https:// URL"
        )));
    }
    let mut custom = CustomConfiguration::default();
    custom.authority_host = host;
    Ok(Arc::new(custom.into()))
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn client_options(cloud: &Arc<CloudConfiguration>) -> ClientOptions {
    ClientOptions {
        cloud: Some(Arc::clone(cloud)),
        ..ClientOptions::default()
    }
}

/// One way of signing in, or why the environment does not offer it.
enum Source {
    Ready(Arc<dyn TokenCredential>),
    /// Usable only where the instance metadata endpoint answers: off Azure
    /// the SDK's own retries would wait over a minute to find nothing.
    IfMetadataEndpoint(Arc<dyn TokenCredential>),
    Unavailable(String),
}

/// Azure's instance metadata endpoint, which a virtual machine's managed
/// identity signs in through.
const METADATA_ENDPOINT: &str = "169.254.169.254:80";

/// True when the metadata endpoint accepts a connection within a second,
/// the probe the other Azure SDKs make before using it.
async fn metadata_endpoint_answers() -> bool {
    matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            tokio::net::TcpStream::connect(METADATA_ENDPOINT),
        )
        .await,
        Ok(Ok(_))
    )
}

/// The credentials of the module documentation, tried in order until one
/// gives a token; that one is used from then on.
pub struct Chain {
    sources: Vec<(&'static str, Source)>,
    chosen: OnceLock<usize>,
}

impl fmt::Debug for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.sources.iter().map(|(name, _)| *name).collect();
        f.debug_struct("Chain")
            .field("sources", &names)
            .field("chosen", &self.chosen.get().map(|i| names[*i]))
            .finish()
    }
}

impl Chain {
    /// The chain this process's environment configures.
    pub fn from_env(cloud: &Arc<CloudConfiguration>) -> Self {
        let tenant = env("AZURE_TENANT_ID");
        let client = env("AZURE_CLIENT_ID");
        let mut sources = Vec::new();

        let service_principal = match (&tenant, &client, env("AZURE_CLIENT_SECRET")) {
            (Some(tenant), Some(client), Some(secret)) => ClientSecretCredential::new(
                tenant,
                client.clone(),
                secret.into(),
                Some(ClientSecretCredentialOptions {
                    client_options: client_options(cloud),
                }),
            )
            .map_or_else(
                |err| Source::Unavailable(describe(&err)),
                |c| Source::Ready(c),
            ),
            _ => Source::Unavailable(
                "AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET are not all set"
                    .to_owned(),
            ),
        };
        sources.push(("service principal", service_principal));

        let workload = if env("AZURE_FEDERATED_TOKEN_FILE").is_some() {
            WorkloadIdentityCredential::new(Some(WorkloadIdentityCredentialOptions {
                credential_options: ClientAssertionCredentialOptions {
                    client_options: client_options(cloud),
                },
                ..WorkloadIdentityCredentialOptions::default()
            }))
            .map_or_else(
                |err| Source::Unavailable(describe(&err)),
                |c| Source::Ready(c),
            )
        } else {
            Source::Unavailable("AZURE_FEDERATED_TOKEN_FILE is not set".to_owned())
        };
        sources.push(("workload identity", workload));

        let tools = DeveloperToolsCredential::new(None).map_or_else(
            |err| Source::Unavailable(describe(&err)),
            |c| Source::Ready(c),
        );
        sources.push(("Azure CLI or Azure Developer CLI", tools));

        // App Service, Functions, Container Apps and Arc name their endpoint;
        // a virtual machine's is the metadata endpoint, probed when needed.
        let named_endpoint = env("IDENTITY_ENDPOINT").is_some() || env("MSI_ENDPOINT").is_some();
        let managed = ManagedIdentityCredential::new(Some(ManagedIdentityCredentialOptions {
            user_assigned_id: client.map(UserAssignedId::ClientId),
            client_options: client_options(cloud),
        }))
        .map_or_else(
            |err| Source::Unavailable(describe(&err)),
            |c| {
                if named_endpoint {
                    Source::Ready(c)
                } else {
                    Source::IfMetadataEndpoint(c)
                }
            },
        );
        sources.push(("managed identity", managed));

        Self {
            sources,
            chosen: OnceLock::new(),
        }
    }

    /// The service principal a connection stores, alone: the environment's
    /// identities are not tried. Credentials for another provider are
    /// `invalid_argument`.
    pub fn from_credentials(
        credentials: &Credentials,
        cloud: &Arc<CloudConfiguration>,
    ) -> Result<Self> {
        let Credentials::AzureClientSecret {
            tenant_id,
            client_id,
            client_secret,
        } = credentials
        else {
            return Err(SecretError::InvalidArgument(format!(
                "the connection stores credentials for {}, not Azure Key Vault",
                credentials.provider().display_name()
            )));
        };
        let secret = client_secret.expose_utf8().ok_or_else(|| {
            SecretError::InvalidArgument("the stored client secret is not text".to_owned())
        })?;
        let credential = ClientSecretCredential::new(
            tenant_id,
            client_id.clone(),
            secret.to_owned().into(),
            Some(ClientSecretCredentialOptions {
                client_options: client_options(cloud),
            }),
        )
        .map_err(|err| SecretError::InvalidArgument(describe(&err)))?;
        Ok(Self {
            sources: vec![("stored service principal", Source::Ready(credential))],
            chosen: OnceLock::new(),
        })
    }

    /// A token for `scope`, so a process without an identity is refused
    /// before any request reaches the vault.
    pub async fn check(&self, scope: &str) -> Result<()> {
        self.get_token(&[scope], None)
            .await
            .map(drop)
            .map_err(|err| SecretError::Unauthenticated {
                provider: Provider::AzureKeyVault.name().to_owned(),
                reason: describe(&err),
            })
    }
}

#[async_trait]
impl TokenCredential for Chain {
    async fn get_token(
        &self,
        scopes: &[&str],
        options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        if let Some(index) = self.chosen.get()
            && let (_, Source::Ready(credential) | Source::IfMetadataEndpoint(credential)) =
                &self.sources[*index]
        {
            return credential.get_token(scopes, options).await;
        }
        let mut failures = Vec::new();
        for (index, (name, source)) in self.sources.iter().enumerate() {
            let credential = match source {
                Source::Ready(credential) => credential,
                Source::IfMetadataEndpoint(credential) => {
                    if !metadata_endpoint_answers().await {
                        failures.push(format!(
                            "{name}: no instance metadata endpoint answered within a second"
                        ));
                        continue;
                    }
                    credential
                }
                Source::Unavailable(reason) => {
                    failures.push(format!("{name}: {reason}"));
                    continue;
                }
            };
            match credential.get_token(scopes, options.clone()).await {
                Ok(token) => {
                    let _ = self.chosen.set(index);
                    return Ok(token);
                }
                Err(err) => failures.push(format!("{name}: {}", describe(&err))),
            }
        }
        Err(azure_core::Error::with_message(
            ErrorKind::Credential,
            format!("no Azure identity signed in ({})", failures.join("; ")),
        ))
    }
}

/// A credential error's text, bounded and without control characters. The
/// Azure SDK never puts a secret or token in these messages.
pub fn describe(err: &azure_core::Error) -> String {
    sourceorrery_core::text::foreign(&err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public() -> Arc<CloudConfiguration> {
        Arc::new(CloudConfiguration::AzurePublic)
    }

    #[test]
    fn the_chain_names_its_sources_and_never_a_credential() {
        let chain = Chain::from_env(&public());
        let shown = format!("{chain:?}");
        for name in [
            "service principal",
            "workload identity",
            "Azure CLI",
            "managed identity",
        ] {
            assert!(shown.contains(name), "{shown}");
        }
        assert!(!shown.contains("secret:"), "{shown}");
    }

    #[test]
    fn a_stored_service_principal_is_the_only_source() {
        let stored = Credentials::AzureClientSecret {
            tenant_id: "00000000-0000-0000-0000-000000000001".to_owned(),
            client_id: "00000000-0000-0000-0000-000000000002".to_owned(),
            client_secret: sourceorrery_core::SecretBytes::from("hunter2"),
        };
        let chain = Chain::from_credentials(&stored, &public()).unwrap();
        let shown = format!("{chain:?}");
        assert!(shown.contains("stored service principal"), "{shown}");
        assert!(!shown.contains("Azure CLI"), "{shown}");
        assert!(!shown.contains("hunter2"), "{shown}");

        let aws = Credentials::AwsAccessKey {
            access_key_id: "AKIAEXAMPLE".to_owned(),
            secret_access_key: sourceorrery_core::SecretBytes::from("hunter2"),
        };
        let err = Chain::from_credentials(&aws, &public()).unwrap_err();
        assert_eq!(err.code(), "invalid_argument");
        assert!(!err.to_string().contains("hunter2"), "{err}");
    }
}
