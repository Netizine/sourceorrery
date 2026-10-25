//! # Azure Key Vault behind the SourceOrrery contract
//!
//! [`AzureClient`] implements `AsyncSecretClient` over Key Vault's secrets
//! with the official Azure SDK. Applications do not use it directly:
//! `sourceorrery-provider` opens it for a connection with
//! `provider = "azure-key-vault"`, and the CLI, the C ABI and every SDK
//! reach it through that crate's `Blocking` adapter.
//!
//! Key Vault's secret model is the one the contract follows, so versions,
//! `enabled`, `not_before`, `expires_on`, `content_type`, tags, soft delete,
//! recovery and purge map one to one ([`mapping`]). What differs is
//! documented in `docs/providers/azure-key-vault.md`: a version's time
//! window can be replaced but not removed, values are text (other bytes are
//! stored as base64), and a version holds at most 15 tags. The identity is
//! the service principal a connection stores, or else the first one the
//! environment provides ([`credential`]).

#![forbid(unsafe_code)]

pub mod credential;
pub mod mapping;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use azure_core::error::ErrorKind;
use azure_core::http::{ClientOptions, Url};
use azure_security_keyvault_secrets::models::{
    SecretAttributes, SecretClientGetSecretOptions, SecretClientListSecretPropertiesOptions,
    SecretClientUpdateSecretPropertiesOptions, SetSecretParameters,
    UpdateSecretPropertiesParameters,
};
use azure_security_keyvault_secrets::{SecretClient, SecretClientOptions};
use futures::TryStreamExt;
use serde::Deserialize;
use sourceorrery_core::{
    AsyncSecretClient, AuditEvent, AuditQuery, Capability, ConnectionSettings, Credentials,
    DeletedSecret, Provider, RecoveryLevel, Result, Secret, SecretBytes, SecretError,
    SecretProperties, SetSecretOptions, UpdateSecretProperties, VaultDescriptor, policy, timestamp,
    validate_secret_name, validate_version_id,
};
use time::OffsetDateTime;

use crate::credential::{Chain, describe};

/// How a client reaches the vault: a connection's settings.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The vault's URL, `https://<name>.vault.azure.net`.
    pub vault_url: String,
}

impl Settings {
    /// Settings for a connection.
    pub fn from_connection(remote: &ConnectionSettings) -> Result<Self> {
        let ConnectionSettings::AzureKeyVault { vault_url } = remote else {
            return Err(SecretError::InvalidArgument(format!(
                "the vault is served by {}, not Azure Key Vault",
                remote.provider()
            )));
        };
        Ok(Self {
            vault_url: vault_url.clone(),
        })
    }
}

/// One Key Vault, served as a SourceOrrery vault.
pub struct AzureClient {
    client: SecretClient,
    vault_name: String,
    descriptor: VaultDescriptor,
}

impl fmt::Debug for AzureClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AzureClient")
            .field("vault", &self.vault_name)
            .field("url", &self.descriptor.id)
            .finish_non_exhaustive()
    }
}

/// One version as read from Key Vault, with what the contract leaves out.
#[derive(Debug, Clone)]
struct Version {
    properties: SecretProperties,
    base64: bool,
}

/// What a request was about, for errors that name it.
#[derive(Debug, Clone, Copy)]
enum Subject<'a> {
    Secret(&'a str),
    Version(&'a str, &'a str),
    Listing,
}

/// The `error` object of a Key Vault error response.
#[derive(Debug, Default, Deserialize)]
struct ErrorBody {
    #[serde(default)]
    error: ErrorDetail,
}

#[derive(Debug, Default, Deserialize)]
struct ErrorDetail {
    code: Option<String>,
    message: Option<String>,
    #[serde(rename = "innererror")]
    inner: Option<Box<ErrorDetail>>,
}

/// The start of the reason of a request refused because the secret is
/// still being deleted, recovered or purged: transient, and retried.
const BUSY: &str = "the secret is still changing state";

fn unauthenticated(reason: String) -> SecretError {
    SecretError::Unauthenticated {
        provider: Provider::AzureKeyVault.name().to_owned(),
        reason,
    }
}

fn unavailable(reason: String) -> SecretError {
    SecretError::ProviderUnavailable {
        provider: Provider::AzureKeyVault.name().to_owned(),
        reason,
    }
}

fn is_busy(err: &SecretError) -> bool {
    matches!(err, SecretError::ProviderUnavailable { reason, .. } if reason.starts_with(BUSY))
}

/// Map an HTTP status and Key Vault's error code, inner code and message.
fn classify(
    status: u16,
    code: Option<&str>,
    inner: Option<&str>,
    message: Option<&str>,
    subject: Subject<'_>,
) -> SecretError {
    // The service's own text, on one line, bounded and without control
    // characters. Key Vault's messages name secrets and versions, never
    // values.
    let one_line = message
        .unwrap_or("no message")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let detail = sourceorrery_core::text::foreign(&one_line);
    let code_text = sourceorrery_core::text::foreign_bounded(code.unwrap_or("no code"), 60);
    let name = match subject {
        Subject::Secret(name) | Subject::Version(name, _) => Some(name),
        Subject::Listing => None,
    };
    let lower = detail.to_ascii_lowercase();
    match status {
        401 => unauthenticated(format!("{code_text}: {detail}")),
        403 => match (inner, subject) {
            (Some("SecretDisabled"), Subject::Version(name, version)) => SecretError::Disabled {
                name: name.to_owned(),
                version: version.to_owned(),
            },
            _ => SecretError::PermissionDenied(format!(
                "{} refused the request ({code_text}): {detail}",
                Provider::AzureKeyVault.display_name()
            )),
        },
        404 => match subject {
            Subject::Version(name, version) => SecretError::VersionNotFound {
                name: name.to_owned(),
                version: version.to_owned(),
            },
            Subject::Secret(name) => SecretError::NotFound {
                name: name.to_owned(),
            },
            Subject::Listing => SecretError::Storage(format!(
                "{} answered 404 to a listing: {detail}",
                Provider::AzureKeyVault.display_name()
            )),
        },
        409 if [
            "being deleted",
            "being recovered",
            "being purged",
            "in progress",
        ]
        .iter()
        .any(|s| lower.contains(s)) =>
        {
            unavailable(format!("{BUSY}: {detail}"))
        }
        409 if lower.contains("deleted") && name.is_some() => SecretError::DeletedConflict {
            name: name.unwrap_or_default().to_owned(),
        },
        400 | 409 => SecretError::InvalidArgument(format!(
            "{} rejected the request ({code_text}): {detail}",
            Provider::AzureKeyVault.display_name()
        )),
        408 | 429 | 500..=599 => unavailable(format!("{status} {code_text}: {detail}")),
        _ => SecretError::Storage(format!(
            "{} answered {status} {code_text}: {detail}",
            Provider::AzureKeyVault.display_name()
        )),
    }
}

/// Map an Azure SDK error. Of a response only Key Vault's error code and
/// message are read; the raw response, which can carry a body, is never
/// formatted.
fn map_error(err: &azure_core::Error, subject: Subject<'_>) -> SecretError {
    match err.kind() {
        ErrorKind::HttpResponse {
            status,
            error_code,
            raw_response,
        } => {
            let body: ErrorBody = raw_response
                .as_ref()
                .and_then(|raw| serde_json::from_slice(raw.body().as_ref()).ok())
                .unwrap_or_default();
            let code = body.error.code.as_deref().or(error_code.as_deref());
            let inner = body.error.inner.as_ref().and_then(|i| i.code.as_deref());
            classify(
                u16::from(*status),
                code,
                inner,
                body.error.message.as_deref(),
                subject,
            )
        }
        ErrorKind::Credential => unauthenticated(describe(err)),
        ErrorKind::Connection | ErrorKind::Io => unavailable(describe(err)),
        ErrorKind::DataConversion => SecretError::Storage(format!(
            "{}'s answer could not be read: {}",
            Provider::AzureKeyVault.display_name(),
            describe(err)
        )),
        ErrorKind::Other => SecretError::Storage(format!(
            "{} failed: {}",
            Provider::AzureKeyVault.display_name(),
            describe(err)
        )),
    }
}

/// The token scope of the vault's cloud: its host without the first label
/// (`https://vault.azure.net/.default` in Azure's public cloud).
fn scope_for(vault_url: &str) -> Result<String> {
    let invalid = || SecretError::InvalidArgument("vault_url is not a Key Vault URL".to_owned());
    let url = Url::parse(vault_url).map_err(|_| invalid())?;
    let host = url.host_str().ok_or_else(invalid)?;
    let (_, suffix) = host.split_once('.').ok_or_else(invalid)?;
    let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
    Ok(format!("https://{suffix}{port}/.default"))
}

/// Retry `op` while the secret is still being deleted, recovered or purged:
/// Key Vault finishes those in the background, for up to about a minute.
async fn settled<T, F, Fut>(mut op: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut wait = Duration::from_millis(250);
    let mut waited = Duration::ZERO;
    loop {
        match op().await {
            Err(err) if is_busy(&err) && waited < Duration::from_secs(60) => {
                tokio::time::sleep(wait).await;
                waited += wait;
                wait = (wait * 2).min(Duration::from_secs(5));
            }
            other => return other,
        }
    }
}

impl AzureClient {
    /// Connect as the vault `vault_name`: sign in with the service principal
    /// a connection stores, or else the first identity the environment
    /// provides ([`credential`]), and get a token once, so a process with
    /// none fails here with `unauthenticated` and no request reaches the
    /// vault. Credentials for another provider are `invalid_argument`.
    pub async fn connect(
        vault_name: &str,
        settings: &Settings,
        credentials: Option<&Credentials>,
    ) -> Result<Self> {
        let scope = scope_for(&settings.vault_url)?;
        let cloud = credential::cloud_from_env()?;
        let chain = Arc::new(match credentials {
            None => Chain::from_env(&cloud),
            Some(stored) => Chain::from_credentials(stored, &cloud)?,
        });
        chain.check(&scope).await?;
        let client = SecretClient::new(
            &settings.vault_url,
            chain,
            Some(SecretClientOptions {
                client_options: ClientOptions {
                    cloud: Some(cloud),
                    ..ClientOptions::default()
                },
                ..SecretClientOptions::default()
            }),
        )
        .map_err(|err| SecretError::InvalidArgument(format!("vault_url: {}", describe(&err))))?;
        let mut connected = Self {
            client,
            vault_name: vault_name.to_owned(),
            descriptor: VaultDescriptor {
                name: vault_name.to_owned(),
                id: settings.vault_url.clone(),
                backend: Provider::AzureKeyVault.name().to_owned(),
                path: None,
                created_on: OffsetDateTime::UNIX_EPOCH,
                recovery_level: RecoveryLevel::Recoverable,
                retention_days: mapping::DEFAULT_RETENTION_DAYS,
                protectors: Vec::new(),
            },
        };
        connected.read_retention().await;
        Ok(connected)
    }

    /// Name, backend and the vault URL as id. Key Vault's data plane does
    /// not report when a vault was created, so `created_on` is the epoch.
    pub fn descriptor(&self) -> &VaultDescriptor {
        &self.descriptor
    }

    /// The vault's soft-delete retention, as any of its secrets reports it.
    /// The vault's own setting is not readable from the data plane, so a
    /// vault that holds no secret yet (or an identity that cannot list
    /// them) keeps Key Vault's default.
    async fn read_retention(&mut self) {
        let Ok(mut pager) =
            self.client
                .list_secret_properties(Some(SecretClientListSecretPropertiesOptions {
                    maxresults: Some(1),
                    ..SecretClientListSecretPropertiesOptions::default()
                }))
        else {
            return;
        };
        if let Ok(Some(first)) = pager.try_next().await
            && let Some(days) = first.attributes.and_then(|a| a.recoverable_days)
            && let Ok(days) = u32::try_from(days)
        {
            self.descriptor.retention_days = days;
        }
    }

    fn version_of(
        &self,
        name: &str,
        item: &azure_security_keyvault_secrets::models::SecretProperties,
    ) -> Result<Version> {
        let version = mapping::version_of(item.id.as_deref())?;
        Ok(Version {
            properties: mapping::properties(
                &self.vault_name,
                name,
                &version,
                item.attributes.as_ref(),
                item.content_type.as_deref(),
                item.tags.as_ref(),
            )?,
            base64: mapping::is_base64(item.tags.as_ref()),
        })
    }

    /// Every version of `name`, newest first; empty when there is no live
    /// secret of that name.
    async fn versions(&self, name: &str) -> Result<Vec<Version>> {
        let mut pager = self
            .client
            .list_secret_properties_versions(name, None)
            .map_err(|err| map_error(&err, Subject::Secret(name)))?;
        let mut versions = Vec::new();
        loop {
            match pager.try_next().await {
                Ok(Some(item)) => versions.push(self.version_of(name, &item)?),
                Ok(None) => break,
                Err(err) => match map_error(&err, Subject::Secret(name)) {
                    SecretError::NotFound { .. } => return Ok(Vec::new()),
                    other => return Err(other),
                },
            }
        }
        versions.sort_by(|a, b| {
            b.properties
                .created_on
                .cmp(&a.properties.created_on)
                .then_with(|| b.properties.version.cmp(&a.properties.version))
        });
        Ok(versions)
    }

    /// The versions of a live secret: `deleted` when it is soft-deleted,
    /// `not_found` when there is none.
    async fn live_versions(&self, name: &str) -> Result<Vec<Version>> {
        let versions = self.versions(name).await?;
        if versions.is_empty() {
            return Err(self.absent(name).await);
        }
        Ok(versions)
    }

    /// The error for a name with no live secret.
    async fn absent(&self, name: &str) -> SecretError {
        match self.client.get_deleted_secret(name, None).await {
            Ok(_) => SecretError::Deleted {
                name: name.to_owned(),
            },
            Err(err) => match map_error(&err, Subject::Secret(name)) {
                SecretError::NotFound { .. } => SecretError::NotFound {
                    name: name.to_owned(),
                },
                other => other,
            },
        }
    }

    /// Read one version's value.
    async fn read_value(&self, name: &str, version: &str) -> Result<SecretBytes> {
        let secret = self
            .client
            .get_secret(
                name,
                Some(SecretClientGetSecretOptions {
                    secret_version: Some(version.to_owned()),
                    ..SecretClientGetSecretOptions::default()
                }),
            )
            .await
            .map_err(|err| map_error(&err, Subject::Version(name, version)))?
            .into_model()
            .map_err(|err| map_error(&err, Subject::Version(name, version)))?;
        let tags = secret.tags;
        let text = secret.value.ok_or_else(|| {
            SecretError::Storage(format!("version {version} of '{name}' has no value"))
        })?;
        mapping::decode_value(text, tags.as_ref())
    }

    /// The deleted-secret view of what Key Vault returns for one.
    fn deleted_view(
        &self,
        name: &str,
        deleted: &azure_security_keyvault_secrets::models::DeletedSecret,
    ) -> Result<DeletedSecret> {
        let version = mapping::version_of(deleted.id.as_deref())?;
        Ok(DeletedSecret {
            properties: mapping::properties(
                &self.vault_name,
                name,
                &version,
                deleted.attributes.as_ref(),
                deleted.content_type.as_deref(),
                deleted.tags.as_ref(),
            )?,
            deleted_on: deleted.deleted_date.unwrap_or(OffsetDateTime::UNIX_EPOCH),
            scheduled_purge_on: deleted.scheduled_purge_date,
            recovery_id: format!("sourceorrery://{}/deletedsecrets/{name}", self.vault_name),
        })
    }

    async fn get_deleted(&self, name: &str) -> Result<DeletedSecret> {
        let deleted = self
            .client
            .get_deleted_secret(name, None)
            .await
            .map_err(|err| map_error(&err, Subject::Secret(name)))?
            .into_model()
            .map_err(|err| map_error(&err, Subject::Secret(name)))?;
        self.deleted_view(name, &deleted)
    }

    /// `not_deleted` when a live secret has the name, else `not_found`:
    /// for recovery and purge of a name that has no deleted secret.
    async fn not_deleted(&self, name: &str) -> SecretError {
        match self.versions(name).await {
            Ok(versions) if !versions.is_empty() => SecretError::NotDeleted {
                name: name.to_owned(),
            },
            Ok(_) => SecretError::NotFound {
                name: name.to_owned(),
            },
            Err(err) => err,
        }
    }

    /// A deleted secret's view, or the error recovery and purge give when
    /// there is none.
    async fn deleted_or_refusal(&self, name: &str) -> Result<DeletedSecret> {
        match self.get_deleted(name).await {
            Err(SecretError::NotFound { .. }) => Err(self.not_deleted(name).await),
            other => other,
        }
    }

    /// Names of the live (or, with `deleted`, soft-deleted) secrets, sorted.
    async fn names(&self, deleted: bool) -> Result<Vec<String>> {
        let mut names = Vec::new();
        if deleted {
            let mut pager = self
                .client
                .list_deleted_secret_properties(None)
                .map_err(|err| map_error(&err, Subject::Listing))?;
            while let Some(item) = pager
                .try_next()
                .await
                .map_err(|err| map_error(&err, Subject::Listing))?
            {
                // A deleted secret's id is its live id (`/secrets/<name>`).
                names.extend(mapping::name_of(item.id.as_deref()));
            }
        } else {
            let mut pager = self
                .client
                .list_secret_properties(None)
                .map_err(|err| map_error(&err, Subject::Listing))?;
            while let Some(item) = pager
                .try_next()
                .await
                .map_err(|err| map_error(&err, Subject::Listing))?
            {
                names.extend(mapping::name_of(item.id.as_deref()));
            }
        }
        names.retain(|n| validate_secret_name(n).is_ok());
        names.sort();
        names.dedup();
        Ok(names)
    }
}

/// Key Vault's attributes for a version's switch and time window.
fn attributes_of(
    enabled: bool,
    not_before: Option<OffsetDateTime>,
    expires_on: Option<OffsetDateTime>,
) -> SecretAttributes {
    SecretAttributes {
        enabled: Some(enabled),
        not_before,
        expires: expires_on,
        ..SecretAttributes::default()
    }
}

fn request_error(err: &azure_core::Error) -> SecretError {
    SecretError::Storage(format!("the request could not be built: {}", describe(err)))
}

#[async_trait]
impl AsyncSecretClient for AzureClient {
    fn vault_name(&self) -> &str {
        &self.vault_name
    }

    /// Key Vault keeps properties per version. A time window can be
    /// replaced but not removed.
    fn capabilities(&self) -> &'static [Capability] {
        Provider::AzureKeyVault.capabilities()
    }

    async fn set_secret(
        &self,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
    ) -> Result<SecretProperties> {
        validate_secret_name(name)?;
        options.validate()?;
        mapping::check_user_tags(&options.tags)?;
        let (text, base64) = mapping::encode_value(&value)?;
        drop(value);
        let created_on = timestamp::now();
        let parameters = SetSecretParameters {
            value: Some(text),
            content_type: options.content_type.clone(),
            secret_attributes: Some(attributes_of(
                options.enabled,
                options.not_before,
                options.expires_on,
            )),
            tags: Some(mapping::tags_for(&options.tags, created_on, None, base64)),
        };
        let content = parameters.try_into().map_err(|err| request_error(&err))?;
        let written = settled(|| {
            let content = Clone::clone(&content);
            async move {
                self.client
                    .set_secret(name, content, None)
                    .await
                    .map_err(|err| map_error(&err, Subject::Secret(name)))
            }
        })
        .await?
        .into_model()
        .map_err(|err| map_error(&err, Subject::Secret(name)))?;
        let version = mapping::version_of(written.id.as_deref())?;
        mapping::properties(
            &self.vault_name,
            name,
            &version,
            written.attributes.as_ref(),
            written.content_type.as_deref(),
            written.tags.as_ref(),
        )
    }

    async fn get_secret(&self, name: &str, version: Option<&str>) -> Result<Secret> {
        validate_secret_name(name)?;
        if let Some(version) = version {
            validate_version_id(version)?;
        }
        let all: Vec<SecretProperties> = self
            .live_versions(name)
            .await?
            .into_iter()
            .map(|v| v.properties)
            .collect();
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
        if let Some(version) = version {
            validate_version_id(version)?;
        }
        let mut all = self
            .live_versions(name)
            .await?
            .into_iter()
            .map(|v| v.properties);
        match version {
            None => all.next().ok_or_else(|| SecretError::NotFound {
                name: name.to_owned(),
            }),
            Some(wanted) => {
                all.find(|p| p.version == wanted)
                    .ok_or_else(|| SecretError::VersionNotFound {
                        name: name.to_owned(),
                        version: wanted.to_owned(),
                    })
            }
        }
    }

    async fn list_properties_of_secrets(&self) -> Result<Vec<SecretProperties>> {
        let mut listed = Vec::new();
        for name in self.names(false).await? {
            // A listing item names the secret but not its version, so the
            // newest version comes from the version listing.
            if let Some(newest) = self.versions(&name).await?.into_iter().next() {
                listed.push(newest.properties);
            }
        }
        Ok(listed)
    }

    async fn list_properties_of_secret_versions(
        &self,
        name: &str,
    ) -> Result<Vec<SecretProperties>> {
        validate_secret_name(name)?;
        Ok(self
            .live_versions(name)
            .await?
            .into_iter()
            .map(|v| v.properties)
            .collect())
    }

    async fn update_secret_properties(
        &self,
        name: &str,
        version: Option<&str>,
        update: UpdateSecretProperties,
    ) -> Result<SecretProperties> {
        validate_secret_name(name)?;
        if let Some(version) = version {
            validate_version_id(version)?;
        }
        if update.is_empty() {
            return Err(SecretError::InvalidArgument("nothing to update".to_owned()));
        }
        let versions = self.live_versions(name).await?;
        let target = match version {
            None => versions.into_iter().next(),
            Some(wanted) => versions
                .into_iter()
                .find(|v| v.properties.version == wanted),
        }
        .ok_or_else(|| SecretError::VersionNotFound {
            name: name.to_owned(),
            version: version.unwrap_or_default().to_owned(),
        })?;
        let removes = |field: &Option<Option<OffsetDateTime>>, current: Option<OffsetDateTime>| {
            matches!(field, Some(None)) && current.is_some()
        };
        if removes(&update.not_before, target.properties.not_before)
            || removes(&update.expires_on, target.properties.expires_on)
        {
            return Err(SecretError::Unsupported(format!(
                "{} can replace a version's not-before and expiry times but not remove them; \
                 write a new version of '{name}' without them",
                Provider::AzureKeyVault.display_name()
            )));
        }
        let mut properties = target.properties.clone();
        update.apply(&mut properties, timestamp::now())?;
        mapping::check_user_tags(&properties.tags)?;
        let parameters = UpdateSecretPropertiesParameters {
            // An empty content type is how Key Vault clears one.
            content_type: Some(properties.content_type.clone().unwrap_or_default()),
            secret_attributes: Some(attributes_of(
                properties.enabled,
                properties.not_before,
                properties.expires_on,
            )),
            tags: Some(mapping::tags_for(
                &properties.tags,
                properties.created_on,
                Some(properties.updated_on),
                target.base64,
            )),
        };
        let version = properties.version.clone();
        let updated = self
            .client
            .update_secret_properties(
                name,
                parameters.try_into().map_err(|err| request_error(&err))?,
                Some(SecretClientUpdateSecretPropertiesOptions {
                    secret_version: Some(version.clone()),
                    ..SecretClientUpdateSecretPropertiesOptions::default()
                }),
            )
            .await
            .map_err(|err| map_error(&err, Subject::Version(name, &version)))?
            .into_model()
            .map_err(|err| map_error(&err, Subject::Version(name, &version)))?;
        mapping::properties(
            &self.vault_name,
            name,
            &version,
            updated.attributes.as_ref(),
            updated.content_type.as_deref(),
            updated.tags.as_ref(),
        )
    }

    async fn delete_secret(&self, name: &str) -> Result<DeletedSecret> {
        validate_secret_name(name)?;
        let deleted = match self.client.delete_secret(name, None).await {
            Ok(response) => response
                .into_model()
                .map_err(|err| map_error(&err, Subject::Secret(name)))?,
            Err(err) => {
                return Err(match map_error(&err, Subject::Secret(name)) {
                    SecretError::NotFound { .. } => self.absent(name).await,
                    other => other,
                });
            }
        };
        self.deleted_view(name, &deleted)
    }

    async fn get_deleted_secret(&self, name: &str) -> Result<DeletedSecret> {
        validate_secret_name(name)?;
        self.get_deleted(name).await
    }

    async fn list_deleted_secrets(&self) -> Result<Vec<DeletedSecret>> {
        let mut listed = Vec::new();
        for name in self.names(true).await? {
            // The listing names the secret; its version comes with the
            // secret itself.
            match self.get_deleted(&name).await {
                Ok(deleted) => listed.push(deleted),
                Err(SecretError::NotFound { .. }) => {}
                Err(other) => return Err(other),
            }
        }
        Ok(listed)
    }

    async fn recover_deleted_secret(&self, name: &str) -> Result<SecretProperties> {
        validate_secret_name(name)?;
        self.deleted_or_refusal(name).await?;
        let recovered = settled(|| async {
            self.client
                .recover_deleted_secret(name, None)
                .await
                .map_err(|err| map_error(&err, Subject::Secret(name)))
        })
        .await?
        .into_model()
        .map_err(|err| map_error(&err, Subject::Secret(name)))?;
        let version = mapping::version_of(recovered.id.as_deref())?;
        // Key Vault finishes a recovery in the background: wait until the
        // secret reads as live again, as the contract's next call expects.
        settled(|| async {
            match self.versions(name).await {
                Ok(versions) if versions.is_empty() => Err(unavailable(format!(
                    "{BUSY}: recovery of '{name}' has not finished"
                ))),
                other => other.map(drop),
            }
        })
        .await?;
        mapping::properties(
            &self.vault_name,
            name,
            &version,
            recovered.attributes.as_ref(),
            recovered.content_type.as_deref(),
            recovered.tags.as_ref(),
        )
    }

    async fn purge_deleted_secret(&self, name: &str) -> Result<()> {
        validate_secret_name(name)?;
        self.deleted_or_refusal(name).await?;
        settled(|| async {
            self.client
                .purge_deleted_secret(name, None)
                .await
                .map(drop)
                .map_err(|err| map_error(&err, Subject::Secret(name)))
        })
        .await
    }

    async fn audit_events(&self, _query: AuditQuery) -> Result<Vec<AuditEvent>> {
        Err(SecretError::Unsupported(format!(
            "the audit trail of an {} vault is kept by {}; `audit` reads local vaults only",
            Provider::AzureKeyVault.display_name(),
            Provider::AzureKeyVault.audit_location()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_answers_map_to_stable_codes() {
        let version = Subject::Version("k", "abc");
        let secret = Subject::Secret("k");
        let cases = [
            (401, None, None, "no token", secret, "unauthenticated"),
            (
                403,
                Some("Forbidden"),
                None,
                "denied",
                secret,
                "permission_denied",
            ),
            (
                403,
                Some("Forbidden"),
                Some("SecretDisabled"),
                "disabled",
                version,
                "disabled",
            ),
            (
                404,
                Some("SecretNotFound"),
                None,
                "missing",
                secret,
                "not_found",
            ),
            (
                404,
                Some("SecretNotFound"),
                None,
                "missing",
                version,
                "version_not_found",
            ),
            (
                409,
                Some("Conflict"),
                None,
                "Secret k is currently in a deleted but recoverable state",
                secret,
                "deleted_conflict",
            ),
            (
                409,
                Some("Conflict"),
                None,
                "Secret is currently being deleted.",
                secret,
                "provider_unavailable",
            ),
            (
                400,
                Some("BadParameter"),
                None,
                "bad",
                secret,
                "invalid_argument",
            ),
            (
                429,
                Some("Throttled"),
                None,
                "slow down",
                secret,
                "provider_unavailable",
            ),
            (
                503,
                None,
                None,
                "down",
                Subject::Listing,
                "provider_unavailable",
            ),
            (418, None, None, "teapot", secret, "storage"),
        ];
        for (status, code, inner, message, subject, expected) in cases {
            let err = classify(status, code, inner, Some(message), subject);
            assert_eq!(err.code(), expected, "{status} {code:?} {inner:?}");
        }
        let busy = classify(409, None, None, Some("purge in progress"), secret);
        assert!(is_busy(&busy) && busy.is_transient());
        let foreign = classify(400, Some("x\u{1b}[31m"), None, Some("bad\u{7}"), secret);
        assert!(!foreign.to_string().contains('\u{1b}'), "{foreign}");
    }

    #[test]
    fn scopes_follow_the_vaults_cloud() {
        let cases = [
            (
                "https://kv.vault.azure.net",
                "https://vault.azure.net/.default",
            ),
            (
                "https://kv.vault.azure.net/",
                "https://vault.azure.net/.default",
            ),
            (
                "https://kv.vault.usgovcloudapi.net",
                "https://vault.usgovcloudapi.net/.default",
            ),
            (
                "https://kv.vault.azure.cn",
                "https://vault.azure.cn/.default",
            ),
            (
                "https://kv.vault.azure.localhost.localstack.cloud:4566/",
                "https://vault.azure.localhost.localstack.cloud:4566/.default",
            ),
        ];
        for (url, scope) in cases {
            assert_eq!(scope_for(url).unwrap(), scope, "{url}");
        }
        assert!(scope_for("https://localhost").is_err());
        assert!(scope_for("not a url").is_err());
    }

    #[test]
    fn settings_come_from_the_connection_only() {
        let settings = Settings::from_connection(&ConnectionSettings::AzureKeyVault {
            vault_url: "https://kv.vault.azure.net".to_owned(),
        })
        .unwrap();
        assert_eq!(settings.vault_url, "https://kv.vault.azure.net");
        let err = Settings::from_connection(&ConnectionSettings::HashicorpVault {
            address: "https://vault.example.com".to_owned(),
            mount: "secret".to_owned(),
            namespace: None,
        })
        .unwrap_err();
        assert_eq!(err.code(), "invalid_argument");
    }

    #[tokio::test]
    async fn credentials_of_another_provider_are_refused_before_any_request() {
        let settings = Settings::from_connection(&ConnectionSettings::AzureKeyVault {
            vault_url: "https://kv.vault.azure.net".to_owned(),
        })
        .unwrap();
        let token = Credentials::VaultToken(SecretBytes::from("hunter2"));
        let err = AzureClient::connect("v", &settings, Some(&token))
            .await
            .unwrap_err();
        assert_eq!(err.code(), "invalid_argument");
        assert!(!err.to_string().contains("hunter2"), "{err}");
    }
}
