//! Opening the vault a `[vaults.<name>]` manifest table describes.

use std::fmt;

use sourceorrery_core::{
    Provider, RemoteVault, Result, SecretClient, SecretError, VaultDescriptor,
};

/// An open remote vault: a synchronous client (a [`crate::Blocking`]
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

/// Open the remote vault `name`, as its manifest table `config` describes.
///
/// Credentials come from the provider's own environment, platform identity
/// or credential file, as its SDK or CLI would find them; nothing is read
/// from the manifest besides the address. A provider this build does not
/// include is [`SecretError::Unsupported`]; a provider that finds no
/// credentials is [`SecretError::Unauthenticated`]; one that cannot be
/// reached is [`SecretError::ProviderUnavailable`].
///
/// A provider this build leaves out (its Cargo feature off) is
/// `unsupported`, naming the provider.
pub fn open_remote(name: &str, config: &RemoteVault) -> Result<Remote> {
    match config.provider() {
        #[cfg(feature = "provider-vault")]
        Provider::HashicorpVault => {
            use sourceorrery_provider_vault::{Auth, Settings, VaultClient};
            let settings = Settings::from_manifest(config)?;
            let auth = Auth::from_env()?;
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
            let settings = Settings::from_manifest(config)?;
            let client = crate::Blocking::connect(|| AwsClient::connect(name, &settings))?;
            let descriptor = client.inner().descriptor().clone();
            Ok(Remote {
                client: Box::new(client),
                descriptor,
            })
        }
        #[cfg(not(all(feature = "provider-vault", feature = "provider-aws")))]
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
