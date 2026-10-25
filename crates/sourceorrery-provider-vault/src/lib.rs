//! # HashiCorp Vault behind the SourceOrrery contract
//!
//! [`VaultClient`] implements `AsyncSecretClient` over a Vault server's KV
//! version 2 secrets engine. Applications do not use it directly:
//! `sourceorrery-provider` opens it for a connection with
//! `provider = "hashicorp-vault"`, and the CLI, the C ABI and every SDK
//! reach it through that crate's `Blocking` adapter.
//!
//! The mapping of secrets, versions, properties and soft delete onto KV v2
//! is in [`kv`]; how a token is found is in [`auth`]. The transport never
//! logs a body, a value crosses the crate only as `SecretBytes`, and every
//! message names paths and statuses, never what a response held.

#![forbid(unsafe_code)]

pub mod auth;
mod http;
pub mod kv;

use std::collections::BTreeMap;
use std::fmt;

use async_trait::async_trait;
use reqwest::{Method, StatusCode};
use sourceorrery_core::text;
use sourceorrery_core::{
    AsyncSecretClient, AuditEvent, AuditQuery, Capability, ConnectionSettings, DeletedSecret,
    Provider, RecoveryLevel, Result, Secret, SecretBytes, SecretError, SecretProperties,
    SetSecretOptions, UpdateSecretProperties, VaultDescriptor, policy, timestamp,
    validate_secret_name,
};
use time::OffsetDateTime;

pub use auth::{Auth, Environment, Token};

use crate::http::{Reply, Transport, default_error};
use crate::kv::{
    DELETED_KEY, DeletedMarker, ListResponse, Metadata, MetadataResponse, MountResponse,
    ReadResponse, VersionProps, WriteResponse, properties_key,
};

/// A Vault server's KV v2 mount, served as a SourceOrrery vault.
pub struct VaultClient {
    transport: Transport,
    token: Token,
    mount: String,
    vault_name: String,
    descriptor: VaultDescriptor,
}

impl fmt::Debug for VaultClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultClient")
            .field("vault", &self.vault_name)
            .field("address", &self.transport.address())
            .field("mount", &self.mount)
            .finish_non_exhaustive()
    }
}

/// How a client reaches its server: a connection's settings plus what the
/// environment adds.
#[derive(Debug, Clone)]
pub struct Settings {
    /// `https://host:8200`.
    pub address: String,
    /// The KV v2 engine's mount path.
    pub mount: String,
    /// Vault Enterprise namespace; `VAULT_NAMESPACE` when the settings have
    /// none.
    pub namespace: Option<String>,
    /// A PEM root certificate for a private CA (`VAULT_CACERT`).
    pub ca_pem: Option<Vec<u8>>,
}

impl Settings {
    /// Settings for a connection, completed from the environment
    /// (`VAULT_NAMESPACE`, `VAULT_CACERT`).
    pub fn from_connection(remote: &ConnectionSettings) -> Result<Self> {
        let ConnectionSettings::HashicorpVault {
            address,
            mount,
            namespace,
        } = remote
        else {
            return Err(SecretError::InvalidArgument(format!(
                "the vault is served by {}, not HashiCorp Vault",
                remote.provider()
            )));
        };
        let env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        let ca_pem = match env("VAULT_CACERT") {
            Some(path) => Some(std::fs::read(&path).map_err(|err| {
                SecretError::Io(format!("cannot read VAULT_CACERT {path}: {err}"))
            })?),
            None => None,
        };
        Ok(Self {
            address: address.clone(),
            mount: mount.trim_matches('/').to_owned(),
            namespace: namespace.clone().or_else(|| env("VAULT_NAMESPACE")),
            ca_pem,
        })
    }
}

impl VaultClient {
    /// Connect to the mount `settings` names as the vault `vault_name`,
    /// logging in with `auth` and checking that the mount is a KV v2 engine.
    pub async fn connect(vault_name: &str, settings: &Settings, auth: Auth) -> Result<Self> {
        let transport = Transport::new(
            &settings.address,
            settings.namespace.clone(),
            settings.ca_pem.as_deref(),
        )?;
        let token = auth.login(&transport).await?;
        let mut client = Self {
            transport,
            token,
            mount: settings.mount.clone(),
            vault_name: vault_name.to_owned(),
            descriptor: VaultDescriptor {
                name: vault_name.to_owned(),
                id: String::new(),
                backend: Provider::HashicorpVault.name().to_owned(),
                path: None,
                created_on: OffsetDateTime::UNIX_EPOCH,
                recovery_level: RecoveryLevel::Recoverable,
                retention_days: kv::RETENTION_DAYS,
                protectors: Vec::new(),
            },
        };
        client.check_mount().await?;
        Ok(client)
    }

    /// Name, backend, mount accessor as id. Vault does not report when a
    /// mount was created, so `created_on` is the Unix epoch.
    pub fn descriptor(&self) -> &VaultDescriptor {
        &self.descriptor
    }

    /// The server address and mount, for listings.
    pub fn location(&self) -> String {
        format!("{} {}", self.transport.address(), self.mount)
    }

    /// Confirm the mount exists and is KV version 2.
    ///
    /// `sys/internal/ui/mounts/<mount>` answers any token with a capability
    /// on the mount, and 403 both when there is no such mount and when the
    /// token has no capability there. On 403 the KV v2 `config` endpoint
    /// tells the two apart: a route Vault has no handler for is a missing
    /// mount; a token that may not read the config either is let through,
    /// and its first secret call decides.
    async fn check_mount(&mut self) -> Result<()> {
        let path = format!("sys/internal/ui/mounts/{}", self.mount);
        let reply = self
            .transport
            .call(Method::GET, &path, Some(&self.token), None)
            .await?;
        match reply.status {
            StatusCode::OK => {
                let mount: MountResponse = reply.json(&path)?;
                let version = mount
                    .data
                    .options
                    .as_ref()
                    .and_then(|o| o.get("version"))
                    .map(|v| v.as_str().map_or_else(|| v.to_string(), str::to_owned));
                if mount.data.kind != "kv" || version.as_deref() != Some("2") {
                    // What the server says about itself is its text.
                    return Err(SecretError::InvalidArgument(format!(
                        "mount '{}' is {}{}, not a KV version 2 secrets engine",
                        self.mount,
                        if mount.data.kind.is_empty() {
                            "unknown".to_owned()
                        } else {
                            text::foreign_bounded(&mount.data.kind, 40)
                        },
                        version
                            .map(|v| format!(" version {}", text::foreign_bounded(&v, 40)))
                            .unwrap_or_default()
                    )));
                }
                self.descriptor.id = mount.data.accessor;
                Ok(())
            }
            StatusCode::NOT_FOUND => Err(SecretError::VaultNotFound {
                name: self.vault_name.clone(),
            }),
            StatusCode::FORBIDDEN => self.probe_mount().await,
            status => Err(default_error(&path, status, &reply.vault_errors())),
        }
    }

    async fn probe_mount(&self) -> Result<()> {
        let path = format!("{}/config", self.mount);
        let reply = self
            .transport
            .call(Method::GET, &path, Some(&self.token), None)
            .await?;
        match reply.status {
            StatusCode::OK | StatusCode::FORBIDDEN => Ok(()),
            StatusCode::NOT_FOUND if reply.vault_errors().contains("no handler for route") => {
                Err(SecretError::VaultNotFound {
                    name: self.vault_name.clone(),
                })
            }
            StatusCode::NOT_FOUND => Err(SecretError::InvalidArgument(format!(
                "mount '{}' is not a KV version 2 secrets engine",
                self.mount
            ))),
            status => Err(default_error(&path, status, &reply.vault_errors())),
        }
    }

    fn path(&self, kind: &str, name: &str) -> String {
        format!("{}/{kind}/{name}", self.mount)
    }

    /// One authenticated call. A 403 is classified as `unauthenticated`
    /// (the token itself is refused) or `permission_denied` (a capability
    /// is missing); every other status comes back for the caller.
    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<Reply> {
        let reply = self
            .transport
            .call(method, path, Some(&self.token), body)
            .await?;
        if reply.status == StatusCode::FORBIDDEN {
            return Err(self.classify_forbidden(path).await);
        }
        Ok(reply)
    }

    async fn classify_forbidden(&self, path: &str) -> SecretError {
        let lookup = self
            .transport
            .call(
                Method::GET,
                "auth/token/lookup-self",
                Some(&self.token),
                None,
            )
            .await;
        match lookup {
            Ok(reply) if reply.status == StatusCode::FORBIDDEN => SecretError::Unauthenticated {
                provider: Provider::HashicorpVault.name().to_owned(),
                reason: "the token is invalid or has expired".to_owned(),
            },
            Ok(_) => SecretError::PermissionDenied(format!(
                "{} refused {path}: the token lacks a capability on it",
                Provider::HashicorpVault.display_name()
            )),
            Err(err) => err,
        }
    }

    /// `send`, with every non-2xx an error: 404 as `not_found` for `name`,
    /// the rest by the default rules.
    async fn send_ok(
        &self,
        method: Method,
        path: &str,
        body: Option<&serde_json::Value>,
        name: &str,
    ) -> Result<Reply> {
        let reply = self.send(method, path, body).await?;
        match reply.status {
            status if status.is_success() => Ok(reply),
            StatusCode::NOT_FOUND => Err(SecretError::NotFound {
                name: name.to_owned(),
            }),
            status => Err(default_error(path, status, &reply.vault_errors())),
        }
    }

    /// The metadata of `name`; `None` when there is no such secret.
    async fn metadata(&self, name: &str) -> Result<Option<Metadata>> {
        let path = self.path("metadata", name);
        let reply = self.send(Method::GET, &path, None).await?;
        match reply.status {
            StatusCode::OK => {
                let parsed: MetadataResponse = reply.json(&path)?;
                Ok(Some(parsed.data))
            }
            StatusCode::NOT_FOUND => Ok(None),
            status => Err(default_error(&path, status, &reply.vault_errors())),
        }
    }

    /// The metadata of `name`, or `not_found`; `deleted` when the secret is
    /// soft-deleted.
    async fn live_metadata(&self, name: &str) -> Result<Metadata> {
        let meta = self
            .metadata(name)
            .await?
            .ok_or_else(|| SecretError::NotFound {
                name: name.to_owned(),
            })?;
        if meta.deleted_marker()?.is_some() {
            return Err(SecretError::Deleted {
                name: name.to_owned(),
            });
        }
        Ok(meta)
    }

    /// Replace the custom metadata of `name`.
    async fn write_custom(&self, name: &str, custom: &BTreeMap<String, String>) -> Result<()> {
        let path = self.path("metadata", name);
        let body = serde_json::json!({ "custom_metadata": custom });
        self.send_ok(Method::POST, &path, Some(&body), name).await?;
        Ok(())
    }

    /// Every live version of `name` as properties, newest first.
    fn versions_of(&self, name: &str, meta: &Metadata) -> Result<Vec<SecretProperties>> {
        meta.live_versions()
            .into_iter()
            .map(|v| meta.properties(&self.vault_name, name, v))
            .collect()
    }

    /// The properties of `version` (`None`: the newest live one).
    fn pick_version(
        &self,
        name: &str,
        meta: &Metadata,
        version: Option<&str>,
    ) -> Result<SecretProperties> {
        let versions = self.versions_of(name, meta)?;
        match version {
            None => versions
                .into_iter()
                .next()
                .ok_or_else(|| SecretError::NotFound {
                    name: name.to_owned(),
                }),
            Some(wanted) => versions
                .into_iter()
                .find(|p| p.version == wanted)
                .ok_or_else(|| SecretError::VersionNotFound {
                    name: name.to_owned(),
                    version: wanted.to_owned(),
                }),
        }
    }

    /// Read the value of one version.
    async fn read_value(&self, properties: &mut SecretProperties) -> Result<SecretBytes> {
        let path = format!(
            "{}?version={}",
            self.path("data", &properties.name),
            properties.version
        );
        let reply = self
            .send_ok(Method::GET, &path, None, &properties.name)
            .await?;
        let parsed: ReadResponse = reply.json(&path)?;
        let Some(data) = parsed.data.data else {
            return Err(SecretError::VersionNotFound {
                name: properties.name.clone(),
                version: properties.version.clone(),
            });
        };
        let (value, implied_type) = kv::decode_value(data, &properties.name)?;
        if properties.content_type.is_none() {
            properties.content_type = implied_type.map(str::to_owned);
        }
        Ok(value)
    }

    /// Every secret name under the mount's root. Folders and names that
    /// are not SourceOrrery secret names are left out.
    async fn names(&self) -> Result<Vec<String>> {
        let path = format!("{}/metadata/", self.mount);
        let method = Method::from_bytes(b"LIST").expect("LIST is a token");
        let reply = self.send(method, &path, None).await?;
        let mut names: Vec<String> = match reply.status {
            StatusCode::OK => {
                let parsed: ListResponse = reply.json(&path)?;
                parsed
                    .data
                    .keys
                    .into_iter()
                    .filter(|k| validate_secret_name(k).is_ok())
                    .collect()
            }
            StatusCode::NOT_FOUND => Vec::new(),
            status => return Err(default_error(&path, status, &reply.vault_errors())),
        };
        names.sort();
        Ok(names)
    }

    /// The deleted-secret view of `name`, or why there is none.
    async fn deleted_view(&self, name: &str) -> Result<DeletedSecret> {
        let meta = self
            .metadata(name)
            .await?
            .ok_or_else(|| SecretError::NotFound {
                name: name.to_owned(),
            })?;
        match meta.deleted_marker()? {
            Some(marker) => meta.deleted_secret(&self.vault_name, name, &marker),
            None => Err(SecretError::NotDeleted {
                name: name.to_owned(),
            }),
        }
    }
}

#[async_trait]
impl AsyncSecretClient for VaultClient {
    fn vault_name(&self) -> &str {
        &self.vault_name
    }

    fn capabilities(&self) -> &'static [Capability] {
        Provider::HashicorpVault.capabilities()
    }

    async fn set_secret(
        &self,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
    ) -> Result<SecretProperties> {
        validate_secret_name(name)?;
        options.validate()?;
        let existing = self.metadata(name).await?;
        if let Some(meta) = &existing
            && meta.deleted_marker()?.is_some()
        {
            return Err(SecretError::DeletedConflict {
                name: name.to_owned(),
            });
        }
        let path = self.path("data", name);
        let body = serde_json::json!({ "data": kv::encode_value(&value), "options": {} });
        drop(value);
        let reply = self.send_ok(Method::POST, &path, Some(&body), name).await?;
        let written: WriteResponse = reply.json(&path)?;
        let created_on = kv::parse_time(&written.data.created_time, "created_time")?;
        let properties = SecretProperties {
            vault: self.vault_name.clone(),
            name: name.to_owned(),
            version: written.data.version.to_string(),
            enabled: options.enabled,
            content_type: options.content_type,
            tags: options.tags,
            not_before: options.not_before,
            expires_on: options.expires_on,
            created_on,
            updated_on: created_on,
            recovery_level: RecoveryLevel::Recoverable,
        };
        let props = VersionProps::from_properties(&properties, created_on);
        if !props.is_default() {
            let mut custom = existing.map(|m| m.custom()).unwrap_or_default();
            custom.insert(
                properties_key(written.data.version),
                serde_json::to_string(&props)
                    .map_err(|err| SecretError::Storage(err.to_string()))?,
            );
            self.write_custom(name, &custom).await?;
        }
        Ok(properties)
    }

    async fn get_secret(&self, name: &str, version: Option<&str>) -> Result<Secret> {
        validate_secret_name(name)?;
        let meta = self.live_metadata(name).await?;
        let now = timestamp::now();
        let mut properties = if let Some(wanted) = version {
            let props = self.pick_version(name, &meta, Some(wanted))?;
            policy::evaluate_access(&props, now)?;
            props
        } else {
            let versions = self.versions_of(name, &meta)?;
            policy::select_latest_accessible(name, &versions, now)?.clone()
        };
        let value = self.read_value(&mut properties).await?;
        Ok(Secret { properties, value })
    }

    async fn get_secret_properties(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<SecretProperties> {
        validate_secret_name(name)?;
        let meta = self.live_metadata(name).await?;
        self.pick_version(name, &meta, version)
    }

    async fn list_properties_of_secrets(&self) -> Result<Vec<SecretProperties>> {
        let mut listed = Vec::new();
        for name in self.names().await? {
            let Some(meta) = self.metadata(&name).await? else {
                continue;
            };
            if meta.deleted_marker()?.is_some() {
                continue;
            }
            if let Some(newest) = meta.live_versions().first() {
                listed.push(meta.properties(&self.vault_name, &name, *newest)?);
            }
        }
        Ok(listed)
    }

    async fn list_properties_of_secret_versions(
        &self,
        name: &str,
    ) -> Result<Vec<SecretProperties>> {
        validate_secret_name(name)?;
        let meta = self.live_metadata(name).await?;
        self.versions_of(name, &meta)
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
        let meta = self.live_metadata(name).await?;
        let mut properties = self.pick_version(name, &meta, version)?;
        let created_on = properties.created_on;
        update.apply(&mut properties, timestamp::now())?;
        // The creation time is the server's clock, the update this
        // machine's: an update never reads as earlier than the version.
        properties.updated_on = properties.updated_on.max(created_on);
        let number: u64 = properties
            .version
            .parse()
            .map_err(|_| SecretError::VersionNotFound {
                name: name.to_owned(),
                version: properties.version.clone(),
            })?;
        let props = VersionProps::from_properties(&properties, created_on);
        let mut custom = meta.custom();
        if props.is_default() {
            custom.remove(&properties_key(number));
        } else {
            custom.insert(
                properties_key(number),
                serde_json::to_string(&props)
                    .map_err(|err| SecretError::Storage(err.to_string()))?,
            );
        }
        self.write_custom(name, &custom).await?;
        Ok(properties)
    }

    async fn delete_secret(&self, name: &str) -> Result<DeletedSecret> {
        validate_secret_name(name)?;
        let meta = self.live_metadata(name).await?;
        let versions = meta.live_versions();
        let newest = *versions.first().ok_or_else(|| SecretError::NotFound {
            name: name.to_owned(),
        })?;
        let properties = meta.properties(&self.vault_name, name, newest)?;
        let deleted_on = timestamp::now();
        let path = self.path("delete", name);
        let body = serde_json::json!({ "versions": versions });
        self.send_ok(Method::POST, &path, Some(&body), name).await?;
        let marker = DeletedMarker {
            deleted_on: kv::format_time(deleted_on),
            versions,
        };
        let mut custom = meta.custom();
        custom.insert(
            DELETED_KEY.to_owned(),
            serde_json::to_string(&marker).map_err(|err| SecretError::Storage(err.to_string()))?,
        );
        self.write_custom(name, &custom).await?;
        Ok(DeletedSecret {
            properties,
            deleted_on,
            scheduled_purge_on: Some(
                deleted_on + time::Duration::days(i64::from(kv::RETENTION_DAYS)),
            ),
            recovery_id: format!("sourceorrery://{}/deletedsecrets/{name}", self.vault_name),
        })
    }

    async fn get_deleted_secret(&self, name: &str) -> Result<DeletedSecret> {
        validate_secret_name(name)?;
        match self.deleted_view(name).await {
            Err(SecretError::NotDeleted { name }) => Err(SecretError::NotFound { name }),
            other => other,
        }
    }

    async fn list_deleted_secrets(&self) -> Result<Vec<DeletedSecret>> {
        let mut listed = Vec::new();
        for name in self.names().await? {
            let Some(meta) = self.metadata(&name).await? else {
                continue;
            };
            if let Some(marker) = meta.deleted_marker()? {
                listed.push(meta.deleted_secret(&self.vault_name, &name, &marker)?);
            }
        }
        Ok(listed)
    }

    async fn recover_deleted_secret(&self, name: &str) -> Result<SecretProperties> {
        validate_secret_name(name)?;
        let meta = self
            .metadata(name)
            .await?
            .ok_or_else(|| SecretError::NotFound {
                name: name.to_owned(),
            })?;
        let marker = meta
            .deleted_marker()?
            .ok_or_else(|| SecretError::NotDeleted {
                name: name.to_owned(),
            })?;
        let path = self.path("undelete", name);
        let body = serde_json::json!({ "versions": marker.versions });
        self.send_ok(Method::POST, &path, Some(&body), name).await?;
        let mut custom = meta.custom();
        custom.remove(DELETED_KEY);
        self.write_custom(name, &custom).await?;
        let newest = marker.versions.iter().copied().max().ok_or_else(|| {
            SecretError::Storage(format!("the deletion marker of '{name}' lists no versions"))
        })?;
        meta.properties(&self.vault_name, name, newest)
    }

    async fn purge_deleted_secret(&self, name: &str) -> Result<()> {
        validate_secret_name(name)?;
        self.deleted_view(name).await?;
        let path = self.path("metadata", name);
        self.send_ok(Method::DELETE, &path, None, name).await?;
        Ok(())
    }

    async fn audit_events(&self, _query: AuditQuery) -> Result<Vec<AuditEvent>> {
        Err(SecretError::Unsupported(format!(
            "the audit trail of a {} vault is kept by {}; `audit` reads local vaults only",
            Provider::HashicorpVault.display_name(),
            Provider::HashicorpVault.audit_location()
        )))
    }
}
