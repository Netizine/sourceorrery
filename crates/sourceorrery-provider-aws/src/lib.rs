//! # AWS Secrets Manager behind the SourceOrrery contract
//!
//! [`AwsClient`] implements `AsyncSecretClient` over Secrets Manager with
//! the official AWS SDK. Applications do not use it directly: the
//! `sourceorrery` crate opens it for a vault that `sourceorrery.toml`
//! declares with `provider = "aws-secrets-manager"`, and the CLI, the C ABI
//! and every SDK reach it through the `Blocking` adapter of
//! `sourceorrery-provider`.
//!
//! Secrets Manager keeps metadata per secret, not per version, so
//! `enabled`, `content_type`, `not_before` and `expires_on` apply to the
//! whole secret and `update_secret_properties` accepts only the newest
//! version (`unsupported` otherwise). The mapping is in [`mapping`]; every
//! difference is documented in `docs/providers/aws-secrets-manager.md`.

#![forbid(unsafe_code)]

pub mod mapping;

use std::collections::BTreeMap;
use std::fmt;

use async_trait::async_trait;
use aws_sdk_secretsmanager::Client;
use aws_sdk_secretsmanager::config::{BehaviorVersion, ProvideCredentials, Region};
use aws_sdk_secretsmanager::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_secretsmanager::operation::describe_secret::DescribeSecretOutput;
use aws_sdk_secretsmanager::primitives::Blob;
use aws_sdk_secretsmanager::types::{Filter, FilterNameStringType};
use sourceorrery_core::{
    AsyncSecretClient, AuditEvent, AuditQuery, DeletedSecret, Provider, RecoveryLevel, RemoteVault,
    Result, Secret, SecretBytes, SecretError, SecretProperties, SetSecretOptions,
    UpdateSecretProperties, VaultDescriptor, policy, timestamp, validate_secret_name,
};
use time::OffsetDateTime;

use crate::mapping::{CURRENT, RECOVERY_WINDOW_DAYS, SecretProps, Version};

/// How a client reaches Secrets Manager: the manifest's `[vaults.<name>]`
/// table.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The region.
    pub region: String,
    /// The prefix every secret name is placed under (`myapp/`); empty for
    /// none.
    pub prefix: String,
    /// A service endpoint other than the region's (a private endpoint, an
    /// emulator).
    pub endpoint_url: Option<String>,
}

impl Settings {
    /// Settings for a manifest table.
    pub fn from_manifest(remote: &RemoteVault) -> Result<Self> {
        let RemoteVault::AwsSecretsManager {
            region,
            prefix,
            endpoint_url,
        } = remote
        else {
            return Err(SecretError::InvalidArgument(format!(
                "the vault is served by {}, not AWS Secrets Manager",
                remote.provider()
            )));
        };
        Ok(Self {
            region: region.clone(),
            prefix: prefix.clone().unwrap_or_default(),
            endpoint_url: endpoint_url.clone(),
        })
    }
}

/// Secrets under one prefix in one region, served as a SourceOrrery vault.
pub struct AwsClient {
    client: Client,
    prefix: String,
    vault_name: String,
    descriptor: VaultDescriptor,
}

impl fmt::Debug for AwsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsClient")
            .field("vault", &self.vault_name)
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

fn unauthenticated(reason: String) -> SecretError {
    SecretError::Unauthenticated {
        provider: Provider::AwsSecretsManager.name().to_owned(),
        reason,
    }
}

/// Map a service error code (and its message) to a `SecretError`. `what`
/// names the secret for `not_found`.
fn classify(code: Option<&str>, message: Option<&str>, what: &str) -> SecretError {
    let detail = message.unwrap_or("no message");
    let code_text = code.unwrap_or("unknown error");
    match code {
        Some("ResourceNotFoundException") => SecretError::NotFound {
            name: what.to_owned(),
        },
        Some("AccessDeniedException") => SecretError::PermissionDenied(format!(
            "{} refused the request: {detail}",
            Provider::AwsSecretsManager.display_name()
        )),
        Some(
            "UnrecognizedClientException"
            | "InvalidSignatureException"
            | "ExpiredTokenException"
            | "ExpiredToken"
            | "InvalidClientTokenId"
            | "AuthFailure"
            | "IncompleteSignature"
            | "InvalidIdentityToken",
        ) => unauthenticated(format!("{code_text}: {detail}")),
        Some(
            "ThrottlingException"
            | "InternalServiceError"
            | "InternalFailure"
            | "ServiceUnavailable"
            | "RequestTimeout"
            | "RequestTimeoutException",
        ) => SecretError::ProviderUnavailable {
            provider: Provider::AwsSecretsManager.name().to_owned(),
            reason: format!("{code_text}: {detail}"),
        },
        Some(
            "InvalidRequestException"
            | "InvalidParameterException"
            | "ValidationException"
            | "LimitExceededException"
            | "ResourceExistsException"
            | "PreconditionNotMetException"
            | "InvalidNextTokenException",
        ) => SecretError::InvalidArgument(format!(
            "{} rejected the request ({code_text}): {detail}",
            Provider::AwsSecretsManager.display_name()
        )),
        _ => SecretError::Storage(format!(
            "{} answered {code_text}: {detail}",
            Provider::AwsSecretsManager.display_name()
        )),
    }
}

/// Map any SDK error. Bodies never appear: the SDK's messages carry the
/// service's error code and text, which name secrets and parameters, never
/// values.
fn map_error<E, R>(err: SdkError<E, R>, what: &str) -> SecretError
where
    E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
    R: fmt::Debug,
{
    match err {
        SdkError::ServiceError(service) => {
            let inner = service.err();
            classify(inner.code(), inner.message(), what)
        }
        SdkError::ConstructionFailure(err) => {
            SecretError::Storage(format!("the request could not be built: {err:?}"))
        }
        SdkError::TimeoutError(_) => SecretError::ProviderUnavailable {
            provider: Provider::AwsSecretsManager.name().to_owned(),
            reason: "the request timed out".to_owned(),
        },
        SdkError::DispatchFailure(failure) => {
            let reason = failure.as_connector_error().map_or_else(
                || "the request could not be sent".to_owned(),
                std::string::ToString::to_string,
            );
            SecretError::ProviderUnavailable {
                provider: Provider::AwsSecretsManager.name().to_owned(),
                reason,
            }
        }
        // The raw response is never formatted.
        SdkError::ResponseError(_) => SecretError::ProviderUnavailable {
            provider: Provider::AwsSecretsManager.name().to_owned(),
            reason: "the response could not be read".to_owned(),
        },
        other => SecretError::Storage(format!(
            "{} failed: {other}",
            Provider::AwsSecretsManager.display_name()
        )),
    }
}

impl AwsClient {
    /// Connect as the vault `vault_name`: load the SDK configuration (the
    /// default credential chain, `settings.region`, the endpoint when
    /// given) and resolve credentials once, so a process with none fails
    /// here with `unauthenticated` and no request is made.
    pub async fn connect(vault_name: &str, settings: &Settings) -> Result<Self> {
        let mut loader = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(settings.region.clone()));
        if let Some(url) = &settings.endpoint_url {
            loader = loader.endpoint_url(url);
        }
        let config = loader.load().await;
        let provider = config.credentials_provider().ok_or_else(|| {
            unauthenticated("the SDK configuration has no credentials provider".to_owned())
        })?;
        provider.provide_credentials().await.map_err(|err| {
            unauthenticated(format!(
                "no credentials were found by the AWS default chain: {err}"
            ))
        })?;
        Ok(Self {
            client: Client::new(&config),
            prefix: settings.prefix.clone(),
            vault_name: vault_name.to_owned(),
            descriptor: VaultDescriptor {
                name: vault_name.to_owned(),
                id: format!("{}:{}", settings.region, settings.prefix),
                backend: Provider::AwsSecretsManager.name().to_owned(),
                path: None,
                created_on: OffsetDateTime::UNIX_EPOCH,
                recovery_level: RecoveryLevel::Recoverable,
                retention_days: RECOVERY_WINDOW_DAYS,
                protectors: Vec::new(),
            },
        })
    }

    /// Name, backend, region and prefix as id. Secrets Manager has no
    /// creation time for a region, so `created_on` is the Unix epoch.
    pub fn descriptor(&self) -> &VaultDescriptor {
        &self.descriptor
    }

    fn secret_id(&self, name: &str) -> String {
        format!("{}{name}", self.prefix)
    }

    /// The secret's description, or `None` when there is no such secret.
    async fn describe(&self, name: &str) -> Result<Option<DescribeSecretOutput>> {
        match self
            .client
            .describe_secret()
            .secret_id(self.secret_id(name))
            .send()
            .await
        {
            Ok(output) => Ok(Some(output)),
            Err(err) => match map_error(err, name) {
                SecretError::NotFound { .. } => Ok(None),
                other => Err(other),
            },
        }
    }

    /// The description of a live secret: `not_found` when there is none,
    /// `deleted` when it is scheduled for deletion.
    async fn describe_live(&self, name: &str) -> Result<DescribeSecretOutput> {
        let described = self
            .describe(name)
            .await?
            .ok_or_else(|| SecretError::NotFound {
                name: name.to_owned(),
            })?;
        if described.deleted_date().is_some() {
            return Err(SecretError::Deleted {
                name: name.to_owned(),
            });
        }
        Ok(described)
    }

    /// Every version of `name`, newest first, deprecated (unlabelled) ones
    /// included.
    async fn versions(&self, name: &str) -> Result<Vec<Version>> {
        let mut stream = self
            .client
            .list_secret_version_ids()
            .secret_id(self.secret_id(name))
            .include_deprecated(true)
            .into_paginator()
            .send();
        let mut versions = Vec::new();
        while let Some(page) = stream.next().await {
            let page = page.map_err(|err| map_error(err, name))?;
            for entry in page.versions() {
                let Some(id) = entry.version_id() else {
                    continue;
                };
                versions.push(Version {
                    id: id.to_owned(),
                    created_on: mapping::from_aws(entry.created_date()),
                    current: entry.version_stages().iter().any(|s| s == CURRENT),
                });
            }
        }
        mapping::sort_newest_first(&mut versions);
        Ok(versions)
    }

    /// The versions of `name` as properties, newest first.
    fn properties_of(
        &self,
        name: &str,
        props: &SecretProps,
        versions: &[Version],
    ) -> Vec<SecretProperties> {
        versions
            .iter()
            .map(|v| props.properties(&self.vault_name, name, &v.id, v.created_on))
            .collect()
    }

    /// Replace the secret's tags with `wanted`: tags no longer present are
    /// removed, the rest written.
    async fn write_tags(
        &self,
        name: &str,
        current: &[aws_sdk_secretsmanager::types::Tag],
        wanted: &BTreeMap<String, String>,
    ) -> Result<()> {
        let id = self.secret_id(name);
        let stale: Vec<String> = current
            .iter()
            .filter_map(|t| t.key())
            .filter(|k| !wanted.contains_key(*k))
            .map(str::to_owned)
            .collect();
        if !stale.is_empty() {
            self.client
                .untag_resource()
                .secret_id(&id)
                .set_tag_keys(Some(stale))
                .send()
                .await
                .map_err(|err| map_error(err, name))?;
        }
        if !wanted.is_empty() {
            self.client
                .tag_resource()
                .secret_id(&id)
                .set_tags(Some(mapping::tags_of(wanted)))
                .send()
                .await
                .map_err(|err| map_error(err, name))?;
        }
        Ok(())
    }

    /// Read one version's value.
    async fn read_value(&self, name: &str, version: &str) -> Result<SecretBytes> {
        let output = self
            .client
            .get_secret_value()
            .secret_id(self.secret_id(name))
            .version_id(version)
            .send()
            .await
            .map_err(|err| match map_error(err, name) {
                SecretError::NotFound { .. } | SecretError::InvalidArgument(_) => {
                    SecretError::VersionNotFound {
                        name: name.to_owned(),
                        version: version.to_owned(),
                    }
                }
                other => other,
            })?;
        if let Some(text) = output.secret_string() {
            return Ok(SecretBytes::new(text.as_bytes().to_vec()));
        }
        if let Some(blob) = output.secret_binary() {
            return Ok(SecretBytes::new(blob.as_ref().to_vec()));
        }
        Err(SecretError::Storage(format!(
            "version {version} of '{name}' holds neither a string nor binary value"
        )))
    }

    /// The deleted-secret view of a described, scheduled-for-deletion secret.
    async fn deleted_view(
        &self,
        name: &str,
        described: &DescribeSecretOutput,
    ) -> Result<DeletedSecret> {
        let deleted_on = mapping::from_aws(described.deleted_date());
        let props = SecretProps::from_tags(described.tags())?;
        // The versions of a secret scheduled for deletion can still be
        // listed; should that be refused, the current version named by the
        // description and the secret's own creation time stand in.
        let newest = match self.versions(name).await {
            Ok(versions) if !versions.is_empty() => versions.into_iter().next(),
            _ => described
                .version_ids_to_stages()
                .and_then(|map| {
                    map.iter()
                        .find(|(_, stages)| stages.iter().any(|s| s == CURRENT))
                        .map(|(id, _)| id.clone())
                })
                .map(|id| Version {
                    id,
                    created_on: mapping::from_aws(described.created_date()),
                    current: true,
                }),
        }
        .ok_or_else(|| SecretError::Storage(format!("'{name}' has no versions")))?;
        Ok(DeletedSecret {
            properties: props.properties(&self.vault_name, name, &newest.id, newest.created_on),
            deleted_on,
            scheduled_purge_on: Some(
                deleted_on + time::Duration::days(i64::from(RECOVERY_WINDOW_DAYS)),
            ),
            recovery_id: format!("sourceorrery://{}/deletedsecrets/{name}", self.vault_name),
        })
    }

    /// Every secret under the prefix (deleted ones included) with its
    /// SourceOrrery name.
    async fn list_entries(
        &self,
    ) -> Result<Vec<(String, aws_sdk_secretsmanager::types::SecretListEntry)>> {
        let mut request = self.client.list_secrets().include_planned_deletion(true);
        if !self.prefix.is_empty() {
            request = request.filters(
                Filter::builder()
                    .key(FilterNameStringType::Name)
                    .values(&self.prefix)
                    .build(),
            );
        }
        let mut stream = request.into_paginator().send();
        let mut entries = Vec::new();
        while let Some(page) = stream.next().await {
            let page = page.map_err(|err| map_error(err, "the listing"))?;
            for entry in page.secret_list() {
                let Some(full) = entry.name() else {
                    continue;
                };
                let Some(name) = full.strip_prefix(self.prefix.as_str()) else {
                    continue;
                };
                if validate_secret_name(name).is_ok() {
                    entries.push((name.to_owned(), entry.clone()));
                }
            }
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(entries)
    }

    fn current_of(name: &str, versions: &[Version]) -> Result<Version> {
        versions
            .first()
            .cloned()
            .ok_or_else(|| SecretError::NotFound {
                name: name.to_owned(),
            })
    }
}

#[async_trait]
impl AsyncSecretClient for AwsClient {
    fn vault_name(&self) -> &str {
        &self.vault_name
    }

    async fn set_secret(
        &self,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
    ) -> Result<SecretProperties> {
        validate_secret_name(name)?;
        options.validate()?;
        let existing = self.describe(name).await?;
        if let Some(described) = &existing
            && described.deleted_date().is_some()
        {
            return Err(SecretError::DeletedConflict {
                name: name.to_owned(),
            });
        }
        let id = self.secret_id(name);
        let version = mapping::new_version_id();
        let text = std::str::from_utf8(value.expose())
            .ok()
            .filter(|t| !t.contains('\0'))
            .map(str::to_owned);
        // Properties apply to the secret; the newest `set` defines them. User
        // tags are replaced only when the options carry some.
        let previous = existing
            .as_ref()
            .map(|d| SecretProps::from_tags(d.tags()))
            .transpose()?
            .unwrap_or_default();
        let props = SecretProps {
            disabled: !options.enabled,
            content_type: options.content_type.clone(),
            not_before: options.not_before,
            expires_on: options.expires_on,
            updated_on: None,
            tags: if options.tags.is_empty() {
                previous.tags.clone()
            } else {
                options.tags.clone()
            },
        };
        let wanted = props.to_tags();
        if let Some(described) = &existing {
            let mut request = self
                .client
                .put_secret_value()
                .secret_id(&id)
                .client_request_token(&version);
            request = match (&text, value.expose()) {
                (Some(text), _) => request.secret_string(text),
                (None, bytes) => request.secret_binary(Blob::new(bytes.to_vec())),
            };
            request.send().await.map_err(|err| map_error(err, name))?;
            drop(value);
            self.write_tags(name, described.tags(), &wanted).await?;
        } else {
            let mut request = self
                .client
                .create_secret()
                .name(&id)
                .client_request_token(&version)
                .set_tags(Some(mapping::tags_of(&wanted)));
            request = match (&text, value.expose()) {
                (Some(text), _) => request.secret_string(text),
                (None, bytes) => request.secret_binary(Blob::new(bytes.to_vec())),
            };
            request.send().await.map_err(|err| map_error(err, name))?;
            drop(value);
        }
        let versions = self.versions(name).await?;
        let created_on = versions
            .iter()
            .find(|v| v.id == version)
            .map_or_else(timestamp::now, |v| v.created_on);
        Ok(props.properties(&self.vault_name, name, &version, created_on))
    }

    async fn get_secret(&self, name: &str, version: Option<&str>) -> Result<Secret> {
        validate_secret_name(name)?;
        let described = self.describe_live(name).await?;
        let props = SecretProps::from_tags(described.tags())?;
        let versions = self.versions(name).await?;
        let all = self.properties_of(name, &props, &versions);
        let now = timestamp::now();
        let properties = if let Some(wanted) = version {
            let found = all
                .into_iter()
                .find(|p| p.version == wanted)
                .ok_or_else(|| SecretError::VersionNotFound {
                    name: name.to_owned(),
                    version: wanted.to_owned(),
                })?;
            policy::evaluate_access(&found, now)?;
            found
        } else {
            policy::select_latest_accessible(name, &all, now)?.clone()
        };
        let value = self.read_value(name, &properties.version).await?;
        Ok(Secret { properties, value })
    }

    async fn get_secret_properties(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<SecretProperties> {
        validate_secret_name(name)?;
        let described = self.describe_live(name).await?;
        let props = SecretProps::from_tags(described.tags())?;
        let versions = self.versions(name).await?;
        let all = self.properties_of(name, &props, &versions);
        match version {
            None => all.into_iter().next().ok_or_else(|| SecretError::NotFound {
                name: name.to_owned(),
            }),
            Some(wanted) => all
                .into_iter()
                .find(|p| p.version == wanted)
                .ok_or_else(|| SecretError::VersionNotFound {
                    name: name.to_owned(),
                    version: wanted.to_owned(),
                }),
        }
    }

    async fn list_properties_of_secrets(&self) -> Result<Vec<SecretProperties>> {
        let mut listed = Vec::new();
        for (name, entry) in self.list_entries().await? {
            if entry.deleted_date().is_some() {
                continue;
            }
            let props = SecretProps::from_tags(entry.tags())?;
            let versions = self.versions(&name).await?;
            if let Some(current) = versions.first() {
                listed.push(props.properties(
                    &self.vault_name,
                    &name,
                    &current.id,
                    current.created_on,
                ));
            }
        }
        Ok(listed)
    }

    async fn list_properties_of_secret_versions(
        &self,
        name: &str,
    ) -> Result<Vec<SecretProperties>> {
        validate_secret_name(name)?;
        let described = self.describe_live(name).await?;
        let props = SecretProps::from_tags(described.tags())?;
        let versions = self.versions(name).await?;
        Ok(self.properties_of(name, &props, &versions))
    }

    async fn update_secret_properties(
        &self,
        name: &str,
        version: Option<&str>,
        update: UpdateSecretProperties,
    ) -> Result<SecretProperties> {
        validate_secret_name(name)?;
        if update.is_empty() {
            return Err(SecretError::InvalidArgument("nothing to update".to_owned()));
        }
        let described = self.describe_live(name).await?;
        let props = SecretProps::from_tags(described.tags())?;
        let versions = self.versions(name).await?;
        let current = Self::current_of(name, &versions)?;
        if let Some(wanted) = version
            && wanted != current.id
        {
            if !versions.iter().any(|v| v.id == wanted) {
                return Err(SecretError::VersionNotFound {
                    name: name.to_owned(),
                    version: wanted.to_owned(),
                });
            }
            return Err(SecretError::Unsupported(format!(
                "{} keeps properties per secret, not per version: update the newest version \
                 ({}) of '{name}', which applies to every version",
                Provider::AwsSecretsManager.display_name(),
                current.id
            )));
        }
        let mut properties =
            props.properties(&self.vault_name, name, &current.id, current.created_on);
        update.apply(&mut properties, timestamp::now())?;
        let next = SecretProps::from_properties(&properties, current.created_on);
        self.write_tags(name, described.tags(), &next.to_tags())
            .await?;
        Ok(properties)
    }

    async fn delete_secret(&self, name: &str) -> Result<DeletedSecret> {
        validate_secret_name(name)?;
        self.describe_live(name).await?;
        self.client
            .delete_secret()
            .secret_id(self.secret_id(name))
            .recovery_window_in_days(i64::from(RECOVERY_WINDOW_DAYS))
            .send()
            .await
            .map_err(|err| map_error(err, name))?;
        let described = self
            .describe(name)
            .await?
            .ok_or_else(|| SecretError::NotFound {
                name: name.to_owned(),
            })?;
        self.deleted_view(name, &described).await
    }

    async fn get_deleted_secret(&self, name: &str) -> Result<DeletedSecret> {
        validate_secret_name(name)?;
        let described = self
            .describe(name)
            .await?
            .filter(|d| d.deleted_date().is_some())
            .ok_or_else(|| SecretError::NotFound {
                name: name.to_owned(),
            })?;
        self.deleted_view(name, &described).await
    }

    async fn list_deleted_secrets(&self) -> Result<Vec<DeletedSecret>> {
        let mut listed = Vec::new();
        for (name, entry) in self.list_entries().await? {
            if entry.deleted_date().is_none() {
                continue;
            }
            let Some(described) = self.describe(&name).await? else {
                continue;
            };
            listed.push(self.deleted_view(&name, &described).await?);
        }
        Ok(listed)
    }

    async fn recover_deleted_secret(&self, name: &str) -> Result<SecretProperties> {
        validate_secret_name(name)?;
        let described = self
            .describe(name)
            .await?
            .ok_or_else(|| SecretError::NotFound {
                name: name.to_owned(),
            })?;
        if described.deleted_date().is_none() {
            return Err(SecretError::NotDeleted {
                name: name.to_owned(),
            });
        }
        self.client
            .restore_secret()
            .secret_id(self.secret_id(name))
            .send()
            .await
            .map_err(|err| map_error(err, name))?;
        let props = SecretProps::from_tags(described.tags())?;
        let versions = self.versions(name).await?;
        let current = Self::current_of(name, &versions)?;
        Ok(props.properties(&self.vault_name, name, &current.id, current.created_on))
    }

    async fn purge_deleted_secret(&self, name: &str) -> Result<()> {
        validate_secret_name(name)?;
        let described = self
            .describe(name)
            .await?
            .ok_or_else(|| SecretError::NotFound {
                name: name.to_owned(),
            })?;
        if described.deleted_date().is_none() {
            return Err(SecretError::NotDeleted {
                name: name.to_owned(),
            });
        }
        self.client
            .delete_secret()
            .secret_id(self.secret_id(name))
            .force_delete_without_recovery(true)
            .send()
            .await
            .map_err(|err| map_error(err, name))?;
        Ok(())
    }

    async fn audit_events(&self, _query: AuditQuery) -> Result<Vec<AuditEvent>> {
        Err(SecretError::Unsupported(format!(
            "the audit trail of an {} vault is kept by {}; `audit` reads local vaults only",
            Provider::AwsSecretsManager.display_name(),
            Provider::AwsSecretsManager.audit_location()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_error_codes_map_to_stable_codes() {
        let cases = [
            ("ResourceNotFoundException", "not_found"),
            ("AccessDeniedException", "permission_denied"),
            ("UnrecognizedClientException", "unauthenticated"),
            ("ExpiredTokenException", "unauthenticated"),
            ("ThrottlingException", "provider_unavailable"),
            ("InternalServiceError", "provider_unavailable"),
            ("InvalidRequestException", "invalid_argument"),
            ("InvalidParameterException", "invalid_argument"),
            ("LimitExceededException", "invalid_argument"),
            ("SomethingNew", "storage"),
        ];
        for (aws, code) in cases {
            let err = classify(Some(aws), Some("detail"), "k");
            assert_eq!(err.code(), code, "{aws}");
            if code != "not_found" {
                assert!(err.to_string().contains("detail"), "{aws}: {err}");
            }
        }
        assert_eq!(classify(None, None, "k").code(), "storage");
        assert!(classify(Some("ThrottlingException"), None, "k").is_transient());
    }

    #[test]
    fn settings_come_from_the_manifest_table_only() {
        let settings = Settings::from_manifest(&RemoteVault::AwsSecretsManager {
            region: "eu-west-1".to_owned(),
            prefix: Some("app/".to_owned()),
            endpoint_url: Some("http://localhost:4566".to_owned()),
        })
        .unwrap();
        assert_eq!(settings.region, "eu-west-1");
        assert_eq!(settings.prefix, "app/");
        assert_eq!(
            settings.endpoint_url.as_deref(),
            Some("http://localhost:4566")
        );
        let err = Settings::from_manifest(&RemoteVault::HashicorpVault {
            address: "https://vault.example.com".to_owned(),
            mount: "secret".to_owned(),
            namespace: None,
        })
        .unwrap_err();
        assert_eq!(err.code(), "invalid_argument");
    }
}
