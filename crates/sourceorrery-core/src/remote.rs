//! Remote vaults: where a `[vaults.<name>]` manifest table points.
//!
//! A remote vault is a secrets service of another vendor served behind the
//! same contract (ADR 0008). The manifest names the provider and how to
//! address it, nothing more: the credentials come from the provider's own
//! environment, platform identity or credential file, and no key for one
//! exists here, so a manifest can never hold one.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{Result, SecretError};

/// A remote secrets service SourceOrrery can serve behind its contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Provider {
    /// HashiCorp Vault, KV version 2 secrets engine.
    HashicorpVault,
    /// AWS Secrets Manager.
    AwsSecretsManager,
}

impl Provider {
    /// Every provider, in the order they are documented.
    pub const ALL: [Self; 2] = [Self::HashicorpVault, Self::AwsSecretsManager];

    /// The manifest's `provider = "..."` value and the Cargo feature suffix.
    pub fn name(self) -> &'static str {
        match self {
            Self::HashicorpVault => "hashicorp-vault",
            Self::AwsSecretsManager => "aws-secrets-manager",
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
        }
    }

    /// Where the provider keeps its own audit trail; the hint `audit_events`
    /// gives on a remote vault.
    pub fn audit_location(self) -> &'static str {
        match self {
            Self::HashicorpVault => "the Vault server's audit devices",
            Self::AwsSecretsManager => "AWS CloudTrail",
        }
    }
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A `[vaults.<name>]` manifest table: the provider and how to reach it.
///
/// Each variant carries only addressing keys. There is no credential key in
/// any of them, and unknown keys are a parse error, so a token pasted into a
/// manifest is refused rather than committed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "provider", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RemoteVault {
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
}

impl RemoteVault {
    /// Which provider serves this vault.
    pub fn provider(&self) -> Provider {
        match self {
            Self::HashicorpVault { .. } => Provider::HashicorpVault,
            Self::AwsSecretsManager { .. } => Provider::AwsSecretsManager,
        }
    }

    /// Where the vault is, for listings: the address, region or URL.
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
        }
    }

    /// Check the addressing keys. Messages name the key, never repeat a
    /// value that looks like it could be a secret.
    pub fn validate(&self) -> Result<()> {
        let invalid = |key: &str, reason: &str| SecretError::Manifest(format!("{key}: {reason}"));
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
        }
        Ok(())
    }
}

/// An `http://` or `https://` URL with a host and nothing suspicious: no
/// user info (a `user:password@host` URL is a credential) and no query.
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
        return Err("must not carry user information (credentials never go in the manifest)");
    }
    if rest.contains('?') || rest.contains('#') {
        return Err("must not carry a query or fragment");
    }
    Ok(())
}

/// How a vault named in the manifest is reached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultConfig {
    /// A vault file in the SourceOrrery home directory: every name without
    /// a `[vaults.<name>]` table.
    Local,
    /// A remote provider, as its `[vaults.<name>]` table says.
    Remote(RemoteVault),
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
            let vault = RemoteVault::HashicorpVault {
                address: address.to_owned(),
                mount: "secret".to_owned(),
                namespace: None,
            };
            let err = vault.validate().unwrap_err();
            let text = err.to_string();
            assert!(text.contains(expected), "{address}: {text}");
            assert!(!text.contains("hunter2"), "{text}");
        }
    }

    #[test]
    fn locations_summarise_the_address() {
        let vault = RemoteVault::HashicorpVault {
            address: "https://v:8200".to_owned(),
            mount: "kv".to_owned(),
            namespace: Some("team".to_owned()),
        };
        assert_eq!(vault.location(), "https://v:8200 team/kv");
        assert_eq!(vault.provider(), Provider::HashicorpVault);
        let aws = RemoteVault::AwsSecretsManager {
            region: "eu-west-1".to_owned(),
            prefix: Some("app/".to_owned()),
            endpoint_url: None,
        };
        assert_eq!(aws.location(), "eu-west-1 app/");
        assert!(aws.validate().is_ok());
        assert!(
            RemoteVault::AwsSecretsManager {
                region: "EU West".to_owned(),
                prefix: None,
                endpoint_url: None,
            }
            .validate()
            .is_err()
        );
        let local = RemoteVault::AwsSecretsManager {
            region: "us-east-1".to_owned(),
            prefix: None,
            endpoint_url: Some("http://localhost:4566".to_owned()),
        };
        assert_eq!(local.location(), "us-east-1 http://localhost:4566");
        assert!(local.validate().is_ok());
        assert!(
            RemoteVault::AwsSecretsManager {
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
            RemoteVault::HashicorpVault {
                address: "http://127.0.0.1:8200".to_owned(),
                mount: "/secret".to_owned(),
                namespace: None,
            }
            .validate()
            .is_err()
        );
    }
}
