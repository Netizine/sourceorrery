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
/// No provider is built in yet: every call returns `unsupported` until the
/// first provider crate lands (milestone 4.3). The plumbing that resolves a
/// vault name through the manifest and reaches this point is complete and
/// tested, so a provider plugs in here alone.
pub fn open_remote(name: &str, config: &RemoteVault) -> Result<Remote> {
    Err(not_built_in(name, config.provider()))
}

/// The error for a provider this build does not include.
pub fn not_built_in(vault: &str, provider: Provider) -> SecretError {
    SecretError::Unsupported(format!(
        "vault '{vault}' is served by {} (provider {provider}), which this build of SourceOrrery \
         does not include",
        provider.display_name()
    ))
}
