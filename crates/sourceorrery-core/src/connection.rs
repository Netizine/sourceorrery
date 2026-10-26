//! Connections: how a vault reaches a secrets service of another vendor.
//!
//! A vault keeps each of its secrets either in its own file or at a
//! provider (ADR 0009). A **connection** is what it needs to reach a
//! provider: [`ConnectionSettings`], the provider and how to address it,
//! and a credential source. The source is *ambient*, the provider's own
//! chain as its SDK or CLI would find it (environment, CLI login, workload
//! or managed identity), or *stored*: [`Credentials`] sealed in the vault.
//! Settings never hold a credential, and their addresses are checked so
//! that a credential is sent over TLS, or in clear text to this machine
//! only.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{Result, SecretError};
use crate::secret::SecretBytes;
use crate::traits::Capability;

/// A remote secrets service SourceOrrery can serve behind its contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Provider {
    /// HashiCorp Vault, KV version 2 secrets engine.
    HashicorpVault,
    /// AWS Secrets Manager.
    AwsSecretsManager,
    /// Azure Key Vault (secrets).
    AzureKeyVault,
}

impl Provider {
    /// Every provider, in the order they are documented.
    pub const ALL: [Self; 3] = [
        Self::HashicorpVault,
        Self::AwsSecretsManager,
        Self::AzureKeyVault,
    ];

    /// The settings' `provider = "..."` value and the Cargo feature suffix.
    pub fn name(self) -> &'static str {
        match self {
            Self::HashicorpVault => "hashicorp-vault",
            Self::AwsSecretsManager => "aws-secrets-manager",
            Self::AzureKeyVault => "azure-key-vault",
        }
    }

    /// The provider whose [`Self::name`] is `name`.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == name)
    }

    /// The product's own name, for messages.
    pub fn display_name(self) -> &'static str {
        match self {
            Self::HashicorpVault => "HashiCorp Vault",
            Self::AwsSecretsManager => "AWS Secrets Manager",
            Self::AzureKeyVault => "Azure Key Vault",
        }
    }

    /// Where the provider keeps its own audit trail; the hint `audit_events`
    /// gives for a secret a connection stores.
    pub fn audit_location(self) -> &'static str {
        match self {
            Self::HashicorpVault => "the Vault server's audit devices",
            Self::AwsSecretsManager => "AWS CloudTrail",
            Self::AzureKeyVault => "Azure Monitor (Key Vault diagnostic logs)",
        }
    }

    /// What of the contract the provider's service can express; its client
    /// reports the same from `capabilities` (ADR 0008, `docs/providers/`).
    pub fn capabilities(self) -> &'static [Capability] {
        match self {
            Self::HashicorpVault => Capability::ALL,
            // Properties are per secret; the time window lives in tags, so
            // it can be removed.
            Self::AwsSecretsManager => &[Capability::ClearableTimeWindow],
            // Properties are per version; a time window can be replaced but
            // not removed.
            Self::AzureKeyVault => &[Capability::PerVersionProperties],
        }
    }
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A provider and how to reach it.
///
/// Each variant carries only addressing keys. There is no credential key in
/// any of them, and unknown keys are a parse error, so a token pasted among
/// the settings is refused rather than kept.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "provider", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ConnectionSettings {
    /// `provider = "hashicorp-vault"`.
    HashicorpVault {
        /// The server, `https://vault.example.com:8200`.
        address: String,
        /// The KV v2 secrets engine's mount path (`secret`).
        mount: String,
        /// Vault Enterprise namespace.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        namespace: Option<String>,
    },
    /// `provider = "aws-secrets-manager"`.
    AwsSecretsManager {
        /// The region the secrets live in (`eu-west-1`).
        region: String,
        /// A path prefix every secret name is placed under (`myapp/`), so one
        /// account can hold several vaults.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
        /// The service endpoint, for a private endpoint or an emulator such
        /// as LocalStack (`http://localhost:4566`). Default: the region's.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        endpoint_url: Option<String>,
    },
    /// `provider = "azure-key-vault"`.
    AzureKeyVault {
        /// The vault's URL, `https://<name>.vault.azure.net` (another cloud's
        /// suffix, or an emulator's, works the same way).
        vault_url: String,
    },
}

impl ConnectionSettings {
    /// Which provider these settings reach.
    pub fn provider(&self) -> Provider {
        match self {
            Self::HashicorpVault { .. } => Provider::HashicorpVault,
            Self::AwsSecretsManager { .. } => Provider::AwsSecretsManager,
            Self::AzureKeyVault { .. } => Provider::AzureKeyVault,
        }
    }

    /// Where the provider is, for listings: the address, region or URL.
    pub fn location(&self) -> String {
        match self {
            Self::HashicorpVault {
                address,
                mount,
                namespace,
            } => match namespace {
                Some(ns) => format!("{address} {ns}/{mount}"),
                None => format!("{address} {mount}"),
            },
            Self::AwsSecretsManager {
                region,
                prefix,
                endpoint_url,
            } => {
                let mut location = region.clone();
                if let Some(endpoint) = endpoint_url {
                    location.push(' ');
                    location.push_str(endpoint);
                }
                if let Some(prefix) = prefix {
                    location.push(' ');
                    location.push_str(prefix);
                }
                location
            }
            Self::AzureKeyVault { vault_url } => vault_url.clone(),
        }
    }

    /// Check the addressing keys (`invalid_argument`, naming the key).
    /// Messages never repeat a value that looks like it could be a secret.
    pub fn validate(&self) -> Result<()> {
        let invalid =
            |key: &str, reason: &str| SecretError::InvalidArgument(format!("{key}: {reason}"));
        match self {
            Self::HashicorpVault {
                address,
                mount,
                namespace,
            } => {
                validate_url(address).map_err(|reason| invalid("address", reason))?;
                if mount.is_empty() || mount.starts_with('/') || mount.ends_with('/') {
                    return Err(invalid(
                        "mount",
                        "must be the engine's mount path without leading or trailing slashes",
                    ));
                }
                if namespace.as_deref() == Some("") {
                    return Err(invalid("namespace", "must not be empty when given"));
                }
            }
            Self::AwsSecretsManager {
                region,
                prefix,
                endpoint_url,
            } => {
                if let Some(endpoint) = endpoint_url {
                    validate_url(endpoint).map_err(|reason| invalid("endpoint_url", reason))?;
                }
                let shape_ok = !region.is_empty()
                    && region
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    && !region.starts_with('-')
                    && !region.ends_with('-');
                if !shape_ok {
                    return Err(invalid(
                        "region",
                        "must be an AWS region name such as eu-west-1",
                    ));
                }
                if prefix.as_deref() == Some("") {
                    return Err(invalid("prefix", "must not be empty when given"));
                }
            }
            Self::AzureKeyVault { vault_url } => {
                validate_url(vault_url).map_err(|reason| invalid("vault_url", reason))?;
                // Key Vault is served over TLS only, an emulator included.
                if !vault_url.starts_with("https://") {
                    return Err(invalid("vault_url", "must start with https://"));
                }
            }
        }
        Ok(())
    }
}

/// Credentials kept for a connection, sealed in the vault, used instead of
/// the provider's ambient chain. Each secret part is a [`SecretBytes`]:
/// zeroised on drop, redacted in `Debug`, never serialised.
#[derive(Clone)]
pub enum Credentials {
    /// A HashiCorp Vault token.
    VaultToken(SecretBytes),
    /// An AWS access key.
    AwsAccessKey {
        /// The access key id (`AKIA…`).
        access_key_id: String,
        /// The secret access key.
        secret_access_key: SecretBytes,
    },
    /// An Azure service principal and its client secret.
    AzureClientSecret {
        /// The directory (tenant) id.
        tenant_id: String,
        /// The application (client) id.
        client_id: String,
        /// The client secret.
        client_secret: SecretBytes,
    },
}

impl Credentials {
    /// The provider these credentials are for.
    pub fn provider(&self) -> Provider {
        match self {
            Self::VaultToken(_) => Provider::HashicorpVault,
            Self::AwsAccessKey { .. } => Provider::AwsSecretsManager,
            Self::AzureClientSecret { .. } => Provider::AzureKeyVault,
        }
    }

    /// Check the parts (`invalid_argument`, naming the part, never its
    /// value): none may be empty, and an id is text without whitespace or
    /// control characters.
    pub fn validate(&self) -> Result<()> {
        let invalid =
            |part: &str, reason: &str| SecretError::InvalidArgument(format!("{part}: {reason}"));
        let (ids, secret): (&[(&str, &str)], (&str, &SecretBytes)) = match self {
            Self::VaultToken(token) => (&[], ("token", token)),
            Self::AwsAccessKey {
                access_key_id,
                secret_access_key,
            } => (
                &[("access_key_id", access_key_id.as_str())],
                ("secret_access_key", secret_access_key),
            ),
            Self::AzureClientSecret {
                tenant_id,
                client_id,
                client_secret,
            } => (
                &[
                    ("tenant_id", tenant_id.as_str()),
                    ("client_id", client_id.as_str()),
                ],
                ("client_secret", client_secret),
            ),
        };
        for (part, id) in ids {
            if id.is_empty() {
                return Err(invalid(part, "must not be empty"));
            }
            if id.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err(invalid(
                    part,
                    "must not contain whitespace or control characters",
                ));
            }
        }
        if secret.1.is_empty() {
            return Err(invalid(secret.0, "must not be empty"));
        }
        Ok(())
    }

    /// Refuse credentials of another provider than `settings` reach.
    pub fn check_for(&self, settings: &ConnectionSettings) -> Result<()> {
        if self.provider() == settings.provider() {
            return Ok(());
        }
        Err(SecretError::InvalidArgument(format!(
            "the credentials are for {}, but the connection reaches {}",
            self.provider().display_name(),
            settings.provider().display_name()
        )))
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VaultToken(_) => f.write_str("VaultToken([REDACTED])"),
            Self::AwsAccessKey { access_key_id, .. } => f
                .debug_struct("AwsAccessKey")
                .field("access_key_id", access_key_id)
                .field("secret_access_key", &"[REDACTED]")
                .finish(),
            Self::AzureClientSecret {
                tenant_id,
                client_id,
                ..
            } => f
                .debug_struct("AzureClientSecret")
                .field("tenant_id", tenant_id)
                .field("client_id", client_id)
                .field("client_secret", &"[REDACTED]")
                .finish(),
        }
    }
}

/// An `https://` URL (or `http://` to the local machine) with a host and
/// nothing suspicious: no user info (a `user:password@host` URL is a
/// credential) and no query. A credential travels with every request, so
/// clear text is accepted only where it cannot leave the machine.
fn validate_url(url: &str) -> std::result::Result<(), &'static str> {
    let Some(rest) = ["http://", "https://"]
        .iter()
        .find_map(|s| url.strip_prefix(s))
    else {
        return Err("must start with http:// or https://");
    };
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() {
        return Err("must name a host");
    }
    if authority.contains('@') {
        return Err("must not carry user information (credentials never go in an address)");
    }
    if rest.contains('?') || rest.contains('#') {
        return Err("must not carry a query or fragment");
    }
    if url.starts_with("http://") && !is_loopback_url(url) {
        return Err(
            "must use https:// (http:// is accepted for localhost only: a credential is sent \
             with every request)",
        );
    }
    Ok(())
}

/// True when `url` addresses the local machine (`localhost`, `127.0.0.0/8`
/// or `::1`), where clear text cannot leave the host. The host must be one
/// of these literally, an address in its plain dotted or bracketed form: a
/// DNS name that merely begins with `127.` resolves wherever its owner
/// points it.
pub fn is_loopback_url(url: &str) -> bool {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or_default();
    if let Some(bracketed) = authority.strip_prefix('[') {
        return bracketed
            .split_once(']')
            .filter(|(_, port)| port.is_empty() || port.starts_with(':'))
            .and_then(|(host, _)| host.parse::<std::net::Ipv6Addr>().ok())
            .is_some_and(|ip| ip.is_loopback());
    }
    let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_names_round_trip() {
        for provider in Provider::ALL {
            let json = serde_json::to_string(&provider).unwrap();
            assert_eq!(json, format!("\"{}\"", provider.name()));
            assert_eq!(serde_json::from_str::<Provider>(&json).unwrap(), provider);
            assert_eq!(provider.to_string(), provider.name());
            assert_eq!(Provider::from_name(provider.name()), Some(provider));
        }
        assert_eq!(Provider::from_name("Vault"), None);
    }

    #[test]
    fn urls_are_checked_without_echoing_them() {
        let bad = [
            ("vault.example.com", "must start with"),
            ("https://", "must name a host"),
            ("https://user:hunter2@vault.example.com", "user information"),
            ("https://vault.example.com/?token=hunter2", "query"),
        ];
        for (address, expected) in bad {
            let vault = ConnectionSettings::HashicorpVault {
                address: address.to_owned(),
                mount: "secret".to_owned(),
                namespace: None,
            };
            let err = vault.validate().unwrap_err();
            assert_eq!(err.code(), "invalid_argument");
            let text = err.to_string();
            assert!(text.contains(expected), "{address}: {text}");
            assert!(!text.contains("hunter2"), "{text}");
        }
    }

    #[test]
    fn clear_text_goes_only_to_names_that_are_this_machine() {
        // A DNS name that merely begins with "127." can resolve anywhere.
        for address in [
            "http://127.attacker.example:8200",
            "http://127.0.0.1.nip.io:8200",
            "http://127.0.0.1%2eexample.com",
            "http://127.0.0.1.:8200",
            "http://localhost.example.com",
        ] {
            assert!(!is_loopback_url(address), "{address}");
            let vault = ConnectionSettings::HashicorpVault {
                address: address.to_owned(),
                mount: "secret".to_owned(),
                namespace: None,
            };
            assert_eq!(vault.validate().unwrap_err().code(), "invalid_argument");
            let aws = ConnectionSettings::AwsSecretsManager {
                region: "us-east-1".to_owned(),
                prefix: None,
                endpoint_url: Some(address.to_owned()),
            };
            assert_eq!(aws.validate().unwrap_err().code(), "invalid_argument");
        }
        for address in [
            "http://localhost:8200",
            "http://LocalHost",
            "http://127.0.0.1:8200",
            "http://127.1.2.3/",
            "http://[::1]:8200",
        ] {
            assert!(is_loopback_url(address), "{address}");
            let vault = ConnectionSettings::HashicorpVault {
                address: address.to_owned(),
                mount: "secret".to_owned(),
                namespace: None,
            };
            vault.validate().unwrap();
        }
    }

    #[test]
    fn locations_summarise_the_address() {
        let vault = ConnectionSettings::HashicorpVault {
            address: "https://v:8200".to_owned(),
            mount: "kv".to_owned(),
            namespace: Some("team".to_owned()),
        };
        assert_eq!(vault.location(), "https://v:8200 team/kv");
        assert_eq!(vault.provider(), Provider::HashicorpVault);
        let aws = ConnectionSettings::AwsSecretsManager {
            region: "eu-west-1".to_owned(),
            prefix: Some("app/".to_owned()),
            endpoint_url: None,
        };
        assert_eq!(aws.location(), "eu-west-1 app/");
        assert!(aws.validate().is_ok());
        assert!(
            ConnectionSettings::AwsSecretsManager {
                region: "EU West".to_owned(),
                prefix: None,
                endpoint_url: None,
            }
            .validate()
            .is_err()
        );
        let local = ConnectionSettings::AwsSecretsManager {
            region: "us-east-1".to_owned(),
            prefix: None,
            endpoint_url: Some("http://localhost:4566".to_owned()),
        };
        assert_eq!(local.location(), "us-east-1 http://localhost:4566");
        assert!(local.validate().is_ok());
        assert!(
            ConnectionSettings::AwsSecretsManager {
                region: "us-east-1".to_owned(),
                prefix: None,
                endpoint_url: Some("localhost:4566".to_owned()),
            }
            .validate()
            .unwrap_err()
            .to_string()
            .contains("endpoint_url")
        );
        assert!(
            ConnectionSettings::HashicorpVault {
                address: "http://127.0.0.1:8200".to_owned(),
                mount: "/secret".to_owned(),
                namespace: None,
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn key_vault_urls_are_https_only() {
        let azure = |url: &str| ConnectionSettings::AzureKeyVault {
            vault_url: url.to_owned(),
        };
        let vault = azure("https://myapp-kv.vault.azure.net");
        assert_eq!(vault.provider(), Provider::AzureKeyVault);
        assert_eq!(vault.location(), "https://myapp-kv.vault.azure.net");
        assert!(vault.validate().is_ok());
        assert!(
            azure("https://kv.vault.azure.localhost.localstack.cloud:4566/")
                .validate()
                .is_ok()
        );
        // Not even for localhost: the service and its emulator speak TLS only.
        for url in ["http://localhost:4566", "http://kv.vault.azure.net"] {
            let err = azure(url).validate().unwrap_err().to_string();
            assert!(err.contains("vault_url"), "{url}: {err}");
        }
        let err = azure("https://user:hunter2@kv.vault.azure.net")
            .validate()
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("user information") && !err.contains("hunter2"),
            "{err}"
        );
    }

    #[test]
    fn credentials_never_show_their_secret_and_match_one_provider() {
        let creds = [
            Credentials::VaultToken(SecretBytes::from("hunter2")),
            Credentials::AwsAccessKey {
                access_key_id: "AKIAEXAMPLE".to_owned(),
                secret_access_key: SecretBytes::from("hunter2"),
            },
            Credentials::AzureClientSecret {
                tenant_id: "tenant".to_owned(),
                client_id: "client".to_owned(),
                client_secret: SecretBytes::from("hunter2"),
            },
        ];
        let settings = [
            ConnectionSettings::HashicorpVault {
                address: "https://v".to_owned(),
                mount: "secret".to_owned(),
                namespace: None,
            },
            ConnectionSettings::AwsSecretsManager {
                region: "eu-west-1".to_owned(),
                prefix: None,
                endpoint_url: None,
            },
            ConnectionSettings::AzureKeyVault {
                vault_url: "https://kv.vault.azure.net".to_owned(),
            },
        ];
        for (i, cred) in creds.iter().enumerate() {
            let shown = format!("{cred:?}");
            assert!(!shown.contains("hunter2"), "{shown}");
            assert!(shown.contains("REDACTED"), "{shown}");
            for (j, target) in settings.iter().enumerate() {
                assert_eq!(
                    cred.check_for(target).is_ok(),
                    i == j,
                    "{shown} for {target:?}"
                );
            }
        }
    }

    #[test]
    fn credentials_are_checked_without_echoing_them() {
        let good = Credentials::AwsAccessKey {
            access_key_id: "AKIAEXAMPLE".to_owned(),
            secret_access_key: SecretBytes::from("hunter2"),
        };
        assert!(good.validate().is_ok());
        let bad = [
            (Credentials::VaultToken(SecretBytes::from("")), "token"),
            (
                Credentials::AwsAccessKey {
                    access_key_id: "AKIA EXAMPLE".to_owned(),
                    secret_access_key: SecretBytes::from("hunter2"),
                },
                "access_key_id",
            ),
            (
                Credentials::AzureClientSecret {
                    tenant_id: "tenant".to_owned(),
                    client_id: String::new(),
                    client_secret: SecretBytes::from("hunter2"),
                },
                "client_id",
            ),
            (
                Credentials::AzureClientSecret {
                    tenant_id: "tenant".to_owned(),
                    client_id: "client".to_owned(),
                    client_secret: SecretBytes::from(""),
                },
                "client_secret",
            ),
        ];
        for (credentials, part) in bad {
            let err = credentials.validate().unwrap_err();
            assert_eq!(err.code(), "invalid_argument");
            let text = err.to_string();
            assert!(text.contains(part), "{text}");
            assert!(!text.contains("hunter2"), "{text}");
        }
    }

    #[test]
    fn capabilities_are_the_providers() {
        assert_eq!(Provider::HashicorpVault.capabilities(), Capability::ALL);
        for provider in [Provider::AwsSecretsManager, Provider::AzureKeyVault] {
            assert_eq!(provider.capabilities().len(), 1, "{provider}");
        }
    }
}
