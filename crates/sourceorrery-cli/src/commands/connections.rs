//! A vault's connections from the command line: the `vault create` flags
//! that add them, the `--storage` value that picks one, and how they are
//! shown. A credential is read from a file only, never from an argument,
//! and goes straight to the vault, sealed.

use anyhow::anyhow;
use sourceorrery_core::{ConnectionSettings, Credentials, Provider};
use sourceorrery_storage::{ConnectionInfo, SecretStorage, SqliteVault};

use crate::cli::ConnectionArgs;
use crate::context::read_secret_file;

/// The `--storage` value for the vault file.
pub const VAULT_FILE_STORAGE: &str = "sourceorrery";

/// The connections `args` ask for, each checked (settings and credentials)
/// so that nothing is created when one is wrong.
pub fn requested(
    args: &ConnectionArgs,
) -> anyhow::Result<Vec<(ConnectionSettings, Option<Credentials>)>> {
    let mut connections = Vec::new();
    if let Some(address) = &args.hashicorp_vault {
        let settings = ConnectionSettings::HashicorpVault {
            address: address.clone(),
            mount: args
                .hashicorp_vault_mount
                .clone()
                .unwrap_or_else(|| "secret".to_owned()),
            namespace: args.hashicorp_vault_namespace.clone(),
        };
        let credentials = args
            .hashicorp_vault_token_file
            .as_deref()
            .map(|file| read_secret_file(file, "Vault token").map(Credentials::VaultToken))
            .transpose()?;
        connections.push((settings, credentials));
    }
    if let Some(region) = &args.aws_secrets_manager {
        let settings = ConnectionSettings::AwsSecretsManager {
            region: region.clone(),
            prefix: args.aws_secrets_manager_prefix.clone(),
            endpoint_url: args.aws_secrets_manager_endpoint.clone(),
        };
        let credentials = match (&args.aws_access_key_id, &args.aws_secret_access_key_file) {
            (Some(id), Some(file)) => Some(Credentials::AwsAccessKey {
                access_key_id: id.clone(),
                secret_access_key: read_secret_file(file, "secret access key")?,
            }),
            _ => None,
        };
        connections.push((settings, credentials));
    }
    if let Some(url) = &args.azure_key_vault {
        let settings = ConnectionSettings::AzureKeyVault {
            vault_url: url.clone(),
        };
        let credentials = match (
            &args.azure_tenant_id,
            &args.azure_client_id,
            &args.azure_client_secret_file,
        ) {
            (Some(tenant), Some(client), Some(file)) => Some(Credentials::AzureClientSecret {
                tenant_id: tenant.clone(),
                client_id: client.clone(),
                client_secret: read_secret_file(file, "client secret")?,
            }),
            _ => None,
        };
        connections.push((settings, credentials));
    }
    for (settings, credentials) in &connections {
        let provider = settings.provider().display_name();
        settings
            .validate()
            .map_err(|err| anyhow!("the {provider} connection: {err}"))?;
        if let Some(credentials) = credentials {
            credentials
                .validate()
                .and_then(|()| credentials.check_for(settings))
                .map_err(|err| anyhow!("the {provider} connection's credentials: {err}"))?;
        }
    }
    Ok(connections)
}

/// The storage a `--storage` value names: `sourceorrery` for the vault
/// file, a provider's name for the vault's connection to it, or a
/// connection's id.
pub fn storage(vault: &SqliteVault, value: &str) -> anyhow::Result<SecretStorage> {
    if value == VAULT_FILE_STORAGE {
        return Ok(SecretStorage::Vault);
    }
    let connections = vault.connections()?;
    let found = match Provider::from_name(value) {
        Some(provider) => connections
            .iter()
            .find(|c| c.settings.provider() == provider),
        None => connections.iter().find(|c| c.id == value),
    };
    if let Some(connection) = found {
        return Ok(SecretStorage::Connection(connection.id.clone()));
    }
    let mut choices = vec![VAULT_FILE_STORAGE.to_owned()];
    choices.extend(
        connections
            .iter()
            .map(|c| c.settings.provider().name().to_owned()),
    );
    Err(anyhow!(
        "vault '{}' has no storage '{value}'; it has: {} (a connection is added with the \
         provider's flags of `sourceorrery vault create`)",
        sourceorrery_core::SecretClient::vault_name(vault),
        choices.join(", ")
    ))
}

/// One line about a connection: its provider, where it reaches and where its
/// credentials come from. Never a credential.
pub fn describe(connection: &ConnectionInfo) -> String {
    format!(
        "{} {} ({} credentials)",
        connection.settings.provider().name(),
        connection.settings.location(),
        connection.credentials.as_str()
    )
}
