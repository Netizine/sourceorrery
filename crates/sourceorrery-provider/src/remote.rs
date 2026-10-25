//! Opening the provider a connection reaches.

use std::fmt;

use sourceorrery_core::{
    ConnectionSettings, Credentials, Provider, Result, SecretClient, SecretError, VaultDescriptor,
};

/// An open connection: a synchronous client (a [`crate::Blocking`]
/// adapter over the provider's async client) and what the provider says
/// about the vault.
pub struct Remote {
    /// The vault, behind the contract.
    pub client: Box<dyn SecretClient + Send + Sync>,
    /// Name, backend and location as the provider reports them.
    pub descriptor: VaultDescriptor,
}

impl fmt::Debug for Remote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Remote")
            .field("descriptor", &self.descriptor)
            .finish_non_exhaustive()
    }
}

/// Open the provider `settings` reach, as the vault `name`.
///
/// With `credentials` (a connection's stored credentials) the provider signs
/// in with those alone. Without, it uses its own chain: the environment,
/// platform identity or credential file, as its SDK or CLI would find them.
/// Settings that fail [`ConnectionSettings::validate`] and credentials for
/// another provider are [`SecretError::InvalidArgument`]; a provider that
/// finds no credentials is [`SecretError::Unauthenticated`]; one that cannot
/// be reached is [`SecretError::ProviderUnavailable`].
///
/// A provider this build leaves out (its Cargo feature off) is
/// `unsupported`, naming the provider.
pub fn open_connection(
    name: &str,
    settings: &ConnectionSettings,
    credentials: Option<&Credentials>,
) -> Result<Remote> {
    settings.validate()?;
    if let Some(credentials) = credentials {
        credentials.check_for(settings)?;
    }
    match settings.provider() {
        #[cfg(feature = "provider-vault")]
        Provider::HashicorpVault => {
            use sourceorrery_provider_vault::{Auth, Settings, VaultClient};
            let settings = Settings::from_connection(settings)?;
            let auth = Auth::from_credentials(credentials)?;
            let client = crate::Blocking::connect(|| VaultClient::connect(name, &settings, auth))?;
            let descriptor = client.inner().descriptor().clone();
            Ok(Remote {
                client: Box::new(client),
                descriptor,
            })
        }
        #[cfg(feature = "provider-aws")]
        Provider::AwsSecretsManager => {
            use sourceorrery_provider_aws::{AwsClient, Settings};
            let settings = Settings::from_connection(settings)?;
            let client =
                crate::Blocking::connect(|| AwsClient::connect(name, &settings, credentials))?;
            let descriptor = client.inner().descriptor().clone();
            Ok(Remote {
                client: Box::new(client),
                descriptor,
            })
        }
        #[cfg(feature = "provider-azure")]
        Provider::AzureKeyVault => {
            use sourceorrery_provider_azure::{AzureClient, Settings};
            let settings = Settings::from_connection(settings)?;
            let client =
                crate::Blocking::connect(|| AzureClient::connect(name, &settings, credentials))?;
            let descriptor = client.inner().descriptor().clone();
            Ok(Remote {
                client: Box::new(client),
                descriptor,
            })
        }
        #[cfg(not(all(
            feature = "provider-vault",
            feature = "provider-aws",
            feature = "provider-azure"
        )))]
        provider => Err(not_built_in(name, provider)),
    }
}

/// The error for a provider this build does not include.
pub fn not_built_in(vault: &str, provider: Provider) -> SecretError {
    SecretError::Unsupported(format!(
        "vault '{vault}' is served by {} (provider {provider}), which this build of SourceOrrery \
         does not include",
        provider.display_name()
    ))
}
