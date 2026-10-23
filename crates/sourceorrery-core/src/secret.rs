//! Secrets, versions, properties and references.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::OffsetDateTime;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::REFERENCE_SCHEME;
use crate::error::{Result, SecretError};
use crate::vault::validate_vault_name;

/// Maximum length of a secret name (portable to the managed cloud secrets services).
pub const MAX_SECRET_NAME_LEN: usize = 127;

/// Maximum length of a version identifier.
pub const MAX_VERSION_ID_LEN: usize = 64;

/// A secret value.
///
/// * Zeroised on drop.
/// * `Debug` prints `[REDACTED]`.
/// * Deliberately has **no** `Serialize` implementation, so a secret can never
///   leak through a casual `serde_json::to_string`. Callers that must emit the
///   value (`get --reveal`, SDK bindings) do so explicitly via [`expose`].
///
/// [`expose`]: SecretBytes::expose
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wrap raw bytes. The caller's buffer is moved, not copied.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Wrap a UTF-8 string. The string's buffer is moved, not copied.
    pub fn from_string(value: String) -> Self {
        Self(value.into_bytes())
    }

    /// Borrow the plaintext. Keep the borrow as short as possible.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Borrow the plaintext as UTF-8, if it is valid UTF-8.
    pub fn expose_utf8(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True for an empty value.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

impl PartialEq for SecretBytes {
    /// Constant-time comparison for equal-length inputs.
    fn eq(&self, other: &Self) -> bool {
        if self.0.len() != other.0.len() {
            return false;
        }
        let diff = self
            .0
            .iter()
            .zip(other.0.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        diff == 0
    }
}

impl Eq for SecretBytes {}

impl From<Vec<u8>> for SecretBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<String> for SecretBytes {
    fn from(value: String) -> Self {
        Self::from_string(value)
    }
}

impl From<&str> for SecretBytes {
    fn from(value: &str) -> Self {
        Self(value.as_bytes().to_vec())
    }
}

/// What happens to a secret when it is deleted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryLevel {
    /// Deletion is soft: the secret can be recovered until its retention
    /// period ends, and purged early by a privileged operation.
    #[default]
    Recoverable,
    /// Deletion is immediate and permanent.
    Purgeable,
}

impl RecoveryLevel {
    /// True when deleted secrets are retained for recovery.
    pub fn soft_delete_enabled(self) -> bool {
        matches!(self, Self::Recoverable)
    }
}

/// Metadata about one version of a secret. Never contains the value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretProperties {
    /// Vault the secret lives in.
    pub vault: String,
    /// Secret name (see [`validate_secret_name`]).
    pub name: String,
    /// Opaque version identifier, unique within the secret.
    pub version: String,
    /// Disabled versions cannot be retrieved.
    pub enabled: bool,
    /// Free-form content type hint (`text/plain`, `application/json`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Caller-defined, non-sensitive tags.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tags: BTreeMap<String, String>,
    /// The version cannot be retrieved before this time.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub not_before: Option<OffsetDateTime>,
    /// The version cannot be retrieved after this time.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub expires_on: Option<OffsetDateTime>,
    /// When this version was created. Immutable.
    #[serde(with = "time::serde::rfc3339")]
    pub created_on: OffsetDateTime,
    /// When this version's metadata last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_on: OffsetDateTime,
    /// Deletion behaviour inherited from the vault.
    #[serde(default)]
    pub recovery_level: RecoveryLevel,
}

impl SecretProperties {
    /// Reference to exactly this version.
    pub fn reference(&self) -> SecretReference {
        SecretReference {
            vault: self.vault.clone(),
            name: self.name.clone(),
            version: Some(self.version.clone()),
        }
    }

    /// Fully qualified identifier (`sourceorrery://vault/name/version`).
    pub fn id(&self) -> String {
        self.reference().to_string()
    }
}

/// A secret version together with its value.
#[derive(Debug)]
pub struct Secret {
    /// Metadata.
    pub properties: SecretProperties,
    /// Plaintext value.
    pub value: SecretBytes,
}

/// Options for creating a new secret version.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetSecretOptions {
    /// Content type hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Non-sensitive tags.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tags: BTreeMap<String, String>,
    /// Whether the new version is immediately usable (default `true`).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Activation time.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub not_before: Option<OffsetDateTime>,
    /// Expiry time.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub expires_on: Option<OffsetDateTime>,
}

impl Default for SetSecretOptions {
    fn default() -> Self {
        Self {
            content_type: None,
            tags: BTreeMap::new(),
            enabled: true,
            not_before: None,
            expires_on: None,
        }
    }
}

impl SetSecretOptions {
    /// Reject contradictory options (e.g. expiry before activation).
    pub fn validate(&self) -> Result<()> {
        validate_window(self.not_before, self.expires_on)?;
        validate_tags(&self.tags)
    }
}

fn default_true() -> bool {
    true
}

/// A partial update to a version's metadata.
///
/// `None` leaves a field unchanged. For clearable fields the inner option
/// distinguishes "set to X" (`Some(Some(x))`) from "clear" (`Some(None)`),
/// which serialises as JSON `null`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateSecretProperties {
    /// Enable or disable the version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Replace or clear the content type.
    #[serde(
        default,
        deserialize_with = "double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub content_type: Option<Option<String>>,
    /// Replace the whole tag set (an empty map clears all tags).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,
    /// Replace or clear the activation time.
    #[serde(
        default,
        with = "double_rfc3339",
        skip_serializing_if = "Option::is_none"
    )]
    pub not_before: Option<Option<OffsetDateTime>>,
    /// Replace or clear the expiry time.
    #[serde(
        default,
        with = "double_rfc3339",
        skip_serializing_if = "Option::is_none"
    )]
    pub expires_on: Option<Option<OffsetDateTime>>,
}

impl UpdateSecretProperties {
    /// True when the update changes nothing.
    pub fn is_empty(&self) -> bool {
        self.enabled.is_none()
            && self.content_type.is_none()
            && self.tags.is_none()
            && self.not_before.is_none()
            && self.expires_on.is_none()
    }

    /// Apply this update to `props`, validating the result.
    ///
    /// `updated_on` is set to `now`. `created_on`, `name`, `version` and
    /// `vault` are never touched.
    pub fn apply(&self, props: &mut SecretProperties, now: OffsetDateTime) -> Result<()> {
        let mut next = props.clone();
        if let Some(enabled) = self.enabled {
            next.enabled = enabled;
        }
        if let Some(content_type) = &self.content_type {
            next.content_type.clone_from(content_type);
        }
        if let Some(tags) = &self.tags {
            validate_tags(tags)?;
            next.tags = tags.clone();
        }
        if let Some(not_before) = self.not_before {
            next.not_before = not_before;
        }
        if let Some(expires_on) = self.expires_on {
            next.expires_on = expires_on;
        }
        validate_window(next.not_before, next.expires_on)?;
        next.updated_on = now;
        *props = next;
        Ok(())
    }
}

fn double_option<'de, T, D>(deserializer: D) -> std::result::Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

mod double_rfc3339 {
    use super::{Deserializer, OffsetDateTime, Serializer};

    #[allow(clippy::ref_option)] // signature dictated by serde's `with`
    pub fn serialize<S: Serializer>(
        value: &Option<Option<OffsetDateTime>>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match value {
            Some(Some(ts)) => time::serde::rfc3339::serialize(ts, serializer),
            _ => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Option<Option<OffsetDateTime>>, D::Error> {
        time::serde::rfc3339::option::deserialize(deserializer).map(Some)
    }
}

/// A soft-deleted secret awaiting recovery or purge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletedSecret {
    /// Properties of the latest version at deletion time.
    pub properties: SecretProperties,
    /// When the secret was deleted.
    #[serde(with = "time::serde::rfc3339")]
    pub deleted_on: OffsetDateTime,
    /// When the backend will purge it automatically, if retention applies.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub scheduled_purge_on: Option<OffsetDateTime>,
    /// Identifier to pass to `recover_deleted_secret`.
    pub recovery_id: String,
}

/// A secret identifier that contains no secret material:
/// `sourceorrery://<vault>/<name>[/<version>]`.
///
/// Safe to commit, log and embed in configuration. Resolution happens only
/// inside an authorised runtime.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SecretReference {
    /// Vault name.
    pub vault: String,
    /// Secret name.
    pub name: String,
    /// Specific version, or `None` for the latest accessible version.
    pub version: Option<String>,
}

impl SecretReference {
    /// Build and validate a reference to the latest version.
    pub fn new(vault: impl Into<String>, name: impl Into<String>) -> Result<Self> {
        let vault = vault.into();
        let name = name.into();
        validate_vault_name(&vault)?;
        validate_secret_name(&name)?;
        Ok(Self {
            vault,
            name,
            version: None,
        })
    }

    /// Pin the reference to a version.
    pub fn with_version(mut self, version: impl Into<String>) -> Result<Self> {
        let version = version.into();
        validate_version_id(&version)?;
        self.version = Some(version);
        Ok(self)
    }

    /// Parse `sourceorrery://vault/name[/version]`.
    pub fn parse(input: &str) -> Result<Self> {
        let prefix = format!("{REFERENCE_SCHEME}://");
        let rest = input.strip_prefix(&prefix).ok_or_else(|| {
            SecretError::InvalidArgument(format!(
                "'{input}' is not a secret reference (expected {prefix}vault/name[/version])"
            ))
        })?;
        let mut parts = rest.split('/');
        let vault = parts.next().unwrap_or_default();
        let name = parts.next().ok_or_else(|| {
            SecretError::InvalidArgument(format!("'{input}' is missing a secret name"))
        })?;
        let version = parts.next();
        if parts.next().is_some() {
            return Err(SecretError::InvalidArgument(format!(
                "'{input}' has too many path segments"
            )));
        }
        let reference = Self::new(vault, name)?;
        match version {
            Some(v) if !v.is_empty() => reference.with_version(v),
            _ => Ok(reference),
        }
    }
}

impl fmt::Display for SecretReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{REFERENCE_SCHEME}://{}/{}", self.vault, self.name)?;
        if let Some(version) = &self.version {
            write!(f, "/{version}")?;
        }
        Ok(())
    }
}

impl FromStr for SecretReference {
    type Err = SecretError;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl Serialize for SecretReference {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for SecretReference {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// Validate a secret name.
///
/// Rules are the common denominator of the managed cloud secrets services, so names port without change: 1–127 ASCII
/// letters, digits or hyphens.
pub fn validate_secret_name(name: &str) -> Result<()> {
    let invalid = |reason: &str| SecretError::InvalidName {
        name: name.to_owned(),
        reason: reason.to_owned(),
    };
    if name.is_empty() {
        return Err(invalid("must not be empty"));
    }
    if name.len() > MAX_SECRET_NAME_LEN {
        return Err(invalid("must be at most 127 characters"));
    }
    if name.contains('_') {
        return Err(invalid(
            "underscores are not allowed; use hyphens (e.g. database-password)",
        ));
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(invalid(
            "may contain only ASCII letters, digits and hyphens",
        ));
    }
    Ok(())
}

/// Validate a version identifier: 1–64 ASCII letters or digits.
pub fn validate_version_id(version: &str) -> Result<()> {
    if version.is_empty()
        || version.len() > MAX_VERSION_ID_LEN
        || !version.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return Err(SecretError::InvalidArgument(format!(
            "'{version}' is not a valid version identifier"
        )));
    }
    Ok(())
}

fn validate_window(
    not_before: Option<OffsetDateTime>,
    expires_on: Option<OffsetDateTime>,
) -> Result<()> {
    if let (Some(nb), Some(exp)) = (not_before, expires_on)
        && exp <= nb
    {
        return Err(SecretError::InvalidArgument(
            "expires_on must be later than not_before".to_owned(),
        ));
    }
    Ok(())
}

fn validate_tags(tags: &BTreeMap<String, String>) -> Result<()> {
    const MAX_TAGS: usize = 50;
    const MAX_KEY: usize = 256;
    const MAX_VALUE: usize = 256;
    if tags.len() > MAX_TAGS {
        return Err(SecretError::InvalidArgument(format!(
            "at most {MAX_TAGS} tags are allowed"
        )));
    }
    for (key, value) in tags {
        if key.is_empty() || key.len() > MAX_KEY {
            return Err(SecretError::InvalidArgument(format!(
                "tag key '{key}' must be 1-{MAX_KEY} characters"
            )));
        }
        if value.len() > MAX_VALUE {
            return Err(SecretError::InvalidArgument(format!(
                "value of tag '{key}' must be at most {MAX_VALUE} characters"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn props() -> SecretProperties {
        SecretProperties {
            vault: "development".into(),
            name: "database-password".into(),
            version: "0123456789abcdef0123456789abcdef".into(),
            enabled: true,
            content_type: Some("text/plain".into()),
            tags: BTreeMap::from([("env".to_owned(), "dev".to_owned())]),
            not_before: None,
            expires_on: None,
            created_on: datetime!(2026-10-20 00:00 UTC),
            updated_on: datetime!(2026-10-20 00:00 UTC),
            recovery_level: RecoveryLevel::Recoverable,
        }
    }

    #[test]
    fn secret_bytes_redacts_debug() {
        let secret = SecretBytes::from("hunter2");
        let dbg = format!("{secret:?}");
        assert!(!dbg.contains("hunter2"));
        assert_eq!(dbg, "SecretBytes([REDACTED])");
        let wrapped = Secret {
            properties: props(),
            value: secret,
        };
        assert!(!format!("{wrapped:?}").contains("hunter2"));
    }

    #[test]
    fn secret_bytes_equality() {
        assert_eq!(SecretBytes::from("a"), SecretBytes::from("a"));
        assert_ne!(SecretBytes::from("a"), SecretBytes::from("b"));
        assert_ne!(SecretBytes::from("a"), SecretBytes::from("ab"));
    }

    #[test]
    fn names_follow_key_vault_rules() {
        assert!(validate_secret_name("database-password").is_ok());
        assert!(validate_secret_name("ApiKey2").is_ok());
        assert!(validate_secret_name("").is_err());
        assert!(validate_secret_name("has_underscore").is_err());
        assert!(validate_secret_name("has space").is_err());
        assert!(validate_secret_name("dots.not.ok").is_err());
        assert!(validate_secret_name(&"a".repeat(128)).is_err());
    }

    #[test]
    fn properties_serialise_without_value_fields() {
        let json = serde_json::to_string(&props()).unwrap();
        assert!(json.contains("\"name\":\"database-password\""));
        assert!(json.contains("2026-10-20T00:00:00Z"));
        assert!(!json.contains("value"));
        let back: SecretProperties = serde_json::from_str(&json).unwrap();
        assert_eq!(back, props());
    }

    #[test]
    fn update_distinguishes_clear_from_unchanged() {
        let json = r#"{"content_type":null,"enabled":false}"#;
        let update: UpdateSecretProperties = serde_json::from_str(json).unwrap();
        assert_eq!(update.content_type, Some(None));
        assert_eq!(update.enabled, Some(false));
        assert!(update.expires_on.is_none());

        let mut p = props();
        update
            .apply(&mut p, datetime!(2026-10-21 00:00 UTC))
            .unwrap();
        assert!(!p.enabled);
        assert_eq!(p.content_type, None);
        assert_eq!(p.updated_on, datetime!(2026-10-21 00:00 UTC));
        assert_eq!(p.created_on, datetime!(2026-10-20 00:00 UTC));

        let round = serde_json::to_string(&update).unwrap();
        assert!(round.contains("\"content_type\":null"));
    }

    #[test]
    fn policy_inputs_reject_unknown_fields() {
        // A binding that misspells a policy field must fail loudly rather
        // than silently create a secret with default policy.
        for json in [
            r#"{"expiresOn":"2030-01-01T00:00:00Z"}"#,
            r#"{"notBefore":"2030-01-01T00:00:00Z"}"#,
            r#"{"enable":false}"#,
        ] {
            assert!(
                serde_json::from_str::<SetSecretOptions>(json).is_err(),
                "{json}"
            );
            assert!(
                serde_json::from_str::<UpdateSecretProperties>(json).is_err(),
                "{json}"
            );
        }
        assert!(serde_json::from_str::<SetSecretOptions>(r#"{"enabled":false}"#).is_ok());
    }

    #[test]
    fn update_rejects_inverted_window() {
        let update = UpdateSecretProperties {
            not_before: Some(Some(datetime!(2027-01-01 00:00 UTC))),
            expires_on: Some(Some(datetime!(2026-01-01 00:00 UTC))),
            ..Default::default()
        };
        assert!(
            update
                .apply(&mut props(), datetime!(2026-10-21 00:00 UTC))
                .is_err()
        );
    }

    #[test]
    fn references_round_trip() {
        let r = SecretReference::parse("sourceorrery://development/database-password").unwrap();
        assert_eq!(r.vault, "development");
        assert_eq!(r.name, "database-password");
        assert_eq!(r.version, None);
        assert_eq!(
            r.to_string(),
            "sourceorrery://development/database-password"
        );

        let pinned = SecretReference::parse("sourceorrery://dev/key/abc123").unwrap();
        assert_eq!(pinned.version.as_deref(), Some("abc123"));
        assert_eq!(props().reference().to_string().matches('/').count(), 4);

        assert!(SecretReference::parse("https://dev/key").is_err());
        assert!(SecretReference::parse("sourceorrery://dev").is_err());
        assert!(SecretReference::parse("sourceorrery://dev/key/v/extra").is_err());
        assert!(SecretReference::parse("sourceorrery://Dev/key").is_err());
    }
}
