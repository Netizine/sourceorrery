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
//!
//! A new version is published so that it is never readable under a looser
//! policy than it was written with (ADR 0011): its properties go in first,
//! as this writer's intent, the data is written with check-and-set, and one
//! merge patch commits them. Every `custom_metadata` change is a merge patch
//! of its own keys, so writers never drop each other's. A failure once
//! something may have changed is `outcome_unknown`.

#![forbid(unsafe_code)]

pub mod auth;
mod http;
pub mod kv;

use std::fmt;
use std::hash::{BuildHasher, Hasher};

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
    ReadResponse, VersionProps, WriteResponse, intent_key, properties_key,
};

/// A change of some `custom_metadata` keys: a value sets one, `null`
/// removes it.
type Changes = serde_json::Map<String, serde_json::Value>;

/// 16 hex digits that tell this write's intent from another writer's.
fn nonce() -> String {
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        time::OffsetDateTime::now_utc()
            .unix_timestamp_nanos()
            .cast_unsigned(),
    );
    hasher.write_u32(std::process::id());
    format!("{:016x}", hasher.finish())
}

/// The result of a change of which part may have been made (ADR 0011).
fn unknown(reason: String) -> SecretError {
    SecretError::OutcomeUnknown {
        at: Provider::HashicorpVault.name().to_owned(),
        reason,
    }
}

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
        let merge = method == Method::PATCH;
        let reply = self
            .transport
            .call(method, path, Some(&self.token), body)
            .await?;
        if reply.status == StatusCode::FORBIDDEN {
            return Err(self.classify_forbidden(path, merge).await);
        }
        Ok(reply)
    }

    async fn classify_forbidden(&self, path: &str, merge: bool) -> SecretError {
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
                "{} refused {path}: the token lacks a capability on it{}",
                Provider::HashicorpVault.display_name(),
                if merge {
                    " (properties are written with `patch`)"
                } else {
                    ""
                }
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

    /// Change the `custom_metadata` keys of `name` that `changes` names,
    /// and no other: one JSON merge patch, so a key another writer set in
    /// between survives.
    async fn patch_custom(&self, name: &str, changes: Changes) -> Result<()> {
        let path = self.path("metadata", name);
        let body = serde_json::json!({ "custom_metadata": changes });
        self.send_ok(Method::PATCH, &path, Some(&body), name)
            .await?;
        Ok(())
    }

    /// Create the metadata of a secret that has none, so its keys can be
    /// patched before its first version: a `POST` that sets only
    /// `max_versions` to the mount's default and leaves `custom_metadata`
    /// alone, should another writer have created it in between.
    async fn create_metadata(&self, name: &str) -> Result<()> {
        let path = self.path("metadata", name);
        let body = serde_json::json!({ "max_versions": 0 });
        self.send_ok(Method::POST, &path, Some(&body), name).await?;
        Ok(())
    }

    /// Write `value` as version `current + 1` of `name` with check-and-set,
    /// `intent` (when there is one) already patched in: the answer, or the
    /// error [`Self::failed_write`] makes of a failure.
    async fn write_data(
        &self,
        name: &str,
        value: SecretBytes,
        current: u64,
        intent: Option<&str>,
    ) -> Result<WriteResponse> {
        let next = current + 1;
        let path = self.path("data", name);
        let body = serde_json::json!({
            "data": kv::encode_value(&value),
            "options": { "cas": current },
        });
        drop(value);
        let err = match self.send(Method::POST, &path, Some(&body)).await {
            Ok(reply) if reply.status.is_success() => {
                drop(body);
                return reply.json(&path).map_err(|err| {
                    unknown(format!(
                        "version {next} of '{name}' was written, but the answer could not be \
                         read: {err}"
                    ))
                });
            }
            Ok(reply)
                if reply.status == StatusCode::BAD_REQUEST
                    && reply.vault_errors().contains("check-and-set") =>
            {
                SecretError::InvalidArgument(format!(
                    "another writer added version {next} of '{name}' at the same moment; \
                     nothing was written"
                ))
            }
            Ok(reply) if reply.status == StatusCode::NOT_FOUND => SecretError::NotFound {
                name: name.to_owned(),
            },
            Ok(reply) => default_error(&path, reply.status, &reply.vault_errors()),
            Err(err) => err,
        };
        drop(body);
        Err(self.failed_write(name, next, intent, err).await)
    }

    /// What a data write that failed with `err` returns, its intent removed
    /// when nothing was written: a refusal as it is (another writer's
    /// version taking the number as its own `invalid_argument`), anything
    /// else `outcome_unknown` with the intent left to bind the version.
    async fn failed_write(
        &self,
        name: &str,
        version: u64,
        intent: Option<&str>,
        err: SecretError,
    ) -> SecretError {
        if !err.is_refusal() {
            return unknown(format!(
                "version {version} of '{name}' may have been written ({err}){}",
                if intent.is_some() {
                    "; it is held at least as restricted as asked"
                } else {
                    ""
                }
            ));
        }
        if let Some(key) = intent {
            // Best effort: a leftover intent only restricts.
            let mut changes = Changes::new();
            changes.insert(key.to_owned(), serde_json::Value::Null);
            let _ = self.patch_custom(name, changes).await;
        }
        err
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
        let current = existing.as_ref().map_or(0, |meta| meta.current_version);
        let next = current + 1;
        let props = VersionProps::asked(
            options.enabled,
            options.content_type.clone(),
            options.tags.clone(),
            options.not_before,
            options.expires_on,
        );
        let document = props.document()?;
        // What the commit removes: keys for `next` left by an attempt that
        // stopped (a writer still in flight for it loses its check-and-set).
        let mut commit = Changes::new();
        for key in existing.iter().flat_map(|meta| meta.keys_for(next)) {
            commit.insert(key, serde_json::Value::Null);
        }
        // The properties go in first, as this writer's intent for `next`:
        // whatever fails from here on, the version is never readable under
        // a looser policy than asked (ADR 0011).
        let intent = if props.is_default() {
            None
        } else {
            let key = intent_key(next, &nonce());
            if existing.is_none() {
                self.create_metadata(name).await?;
            }
            let mut changes = Changes::new();
            changes.insert(key.clone(), serde_json::Value::String(document.clone()));
            self.patch_custom(name, changes).await?;
            Some(key)
        };
        let written = self
            .write_data(name, value, current, intent.as_deref())
            .await?;
        let version = written.data.version;
        if let Some(key) = &intent {
            commit.insert(key.clone(), serde_json::Value::Null);
        }
        if !props.is_default() {
            commit.insert(properties_key(version), serde_json::Value::String(document));
        }
        if !commit.is_empty() {
            self.patch_custom(name, commit).await.map_err(|err| {
                unknown(format!(
                    "version {version} of '{name}' was written{}, but its properties were not \
                     recorded: {err}",
                    if intent.is_some() {
                        " and is held at least as restricted as asked"
                    } else {
                        ""
                    }
                ))
            })?;
        }
        // The change is made: an unreadable creation time is not a failure.
        let created_on = kv::parse_time(&written.data.created_time, "created_time")
            .unwrap_or_else(|_| timestamp::now());
        Ok(SecretProperties {
            vault: self.vault_name.clone(),
            name: name.to_owned(),
            version: version.to_string(),
            enabled: options.enabled,
            content_type: options.content_type,
            tags: options.tags,
            not_before: options.not_before,
            expires_on: options.expires_on,
            created_on,
            updated_on: created_on,
            recovery_level: RecoveryLevel::Recoverable,
        })
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
        // One patch: the version's committed properties, and its intents
        // gone, since this decision supersedes them.
        let mut changes = Changes::new();
        for (key, _) in meta.intents_for(number)? {
            changes.insert(key, serde_json::Value::Null);
        }
        changes.insert(
            properties_key(number),
            if props.is_default() {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(props.document()?)
            },
        );
        self.patch_custom(name, changes).await?;
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
        // The marker first: once it is there SourceOrrery treats the secret
        // as deleted, whether or not KV's delete then lands, and a delete
        // that stops here can be recovered or purged.
        let marker = DeletedMarker {
            deleted_on: kv::format_time(deleted_on),
            versions: versions.clone(),
        };
        let mut changes = Changes::new();
        changes.insert(
            DELETED_KEY.to_owned(),
            serde_json::Value::String(
                serde_json::to_string(&marker)
                    .map_err(|err| SecretError::Storage(err.to_string()))?,
            ),
        );
        self.patch_custom(name, changes).await?;
        let path = self.path("delete", name);
        let body = serde_json::json!({ "versions": versions });
        self.send_ok(Method::POST, &path, Some(&body), name)
            .await
            .map_err(|err| {
                unknown(format!(
                    "'{name}' is marked deleted, but its versions were not deleted in KV: {err}"
                ))
            })?;
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
        // KV's undelete first: while the marker stays, SourceOrrery still
        // treats the secret as deleted, and a recovery that stops here can
        // be asked again.
        let path = self.path("undelete", name);
        let body = serde_json::json!({ "versions": marker.versions });
        self.send_ok(Method::POST, &path, Some(&body), name).await?;
        let mut changes = Changes::new();
        changes.insert(DELETED_KEY.to_owned(), serde_json::Value::Null);
        self.patch_custom(name, changes).await.map_err(|err| {
            unknown(format!(
                "the versions of '{name}' were restored in KV, but it is still marked deleted: \
                 {err}"
            ))
        })?;
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
