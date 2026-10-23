//! The mapping of SourceOrrery's model onto Secrets Manager's.
//!
//! * A secret is `<prefix><name>`. Its versions are Secrets Manager
//!   versions; the version id is the `VersionId`. Versions this crate
//!   writes get a time-ordered 32-hex-digit id (the `ClientRequestToken`),
//!   so they sort without relying on timestamps; versions written by other
//!   tools keep whatever id they have and sort by creation time.
//! * The value is `SecretString` when the bytes are UTF-8 without NUL,
//!   `SecretBinary` otherwise. Nothing is wrapped around it.
//! * Properties live in the secret's tags under `sourceorrery:` keys and
//!   apply to the whole secret (Secrets Manager has no per-version
//!   metadata); every other tag is a user tag.
//! * Soft delete is `DeleteSecret` with the 30-day recovery window, recovery
//!   is `RestoreSecret`, purge is `DeleteSecret` without recovery.

use std::collections::BTreeMap;
use std::hash::{BuildHasher, Hasher};

use aws_sdk_secretsmanager::types::Tag;
use sourceorrery_core::{Result, SecretError, SecretProperties};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Tag key prefix of the properties this crate stores.
pub const TAG_PREFIX: &str = "sourceorrery:";
/// The recovery window given to `DeleteSecret`: the longest Secrets
/// Manager allows.
pub const RECOVERY_WINDOW_DAYS: u32 = 30;
/// The staging label of the newest version.
pub const CURRENT: &str = "AWSCURRENT";

const TAG_DISABLED: &str = "sourceorrery:disabled";
const TAG_CONTENT_TYPE: &str = "sourceorrery:content_type";
const TAG_NOT_BEFORE: &str = "sourceorrery:not_before";
const TAG_EXPIRES_ON: &str = "sourceorrery:expires_on";
const TAG_UPDATED_ON: &str = "sourceorrery:updated_on";

/// The properties of a secret, as its tags carry them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecretProps {
    pub disabled: bool,
    pub content_type: Option<String>,
    pub not_before: Option<OffsetDateTime>,
    pub expires_on: Option<OffsetDateTime>,
    pub updated_on: Option<OffsetDateTime>,
    pub tags: BTreeMap<String, String>,
}

impl SecretProps {
    /// Read the properties out of a secret's tags.
    pub fn from_tags(tags: &[Tag]) -> Result<Self> {
        let mut props = Self::default();
        for tag in tags {
            let (Some(key), Some(value)) = (tag.key(), tag.value()) else {
                continue;
            };
            match key {
                TAG_DISABLED => props.disabled = value == "true",
                TAG_CONTENT_TYPE => props.content_type = Some(value.to_owned()),
                TAG_NOT_BEFORE => props.not_before = Some(parse_time(value, key)?),
                TAG_EXPIRES_ON => props.expires_on = Some(parse_time(value, key)?),
                TAG_UPDATED_ON => props.updated_on = Some(parse_time(value, key)?),
                other if other.starts_with(TAG_PREFIX) => {}
                other => {
                    props.tags.insert(other.to_owned(), value.to_owned());
                }
            }
        }
        Ok(props)
    }

    /// The properties `properties` carries, for storing.
    pub fn from_properties(properties: &SecretProperties, created_on: OffsetDateTime) -> Self {
        Self {
            disabled: !properties.enabled,
            content_type: properties.content_type.clone(),
            not_before: properties.not_before,
            expires_on: properties.expires_on,
            updated_on: (properties.updated_on != created_on).then_some(properties.updated_on),
            tags: properties.tags.clone(),
        }
    }

    /// Every tag the secret should carry: the user tags and the
    /// `sourceorrery:` ones that are not at their default.
    pub fn to_tags(&self) -> BTreeMap<String, String> {
        let mut tags = self.tags.clone();
        if self.disabled {
            tags.insert(TAG_DISABLED.to_owned(), "true".to_owned());
        }
        if let Some(content_type) = &self.content_type {
            tags.insert(TAG_CONTENT_TYPE.to_owned(), content_type.clone());
        }
        if let Some(t) = self.not_before {
            tags.insert(TAG_NOT_BEFORE.to_owned(), format_time(t));
        }
        if let Some(t) = self.expires_on {
            tags.insert(TAG_EXPIRES_ON.to_owned(), format_time(t));
        }
        if let Some(t) = self.updated_on {
            tags.insert(TAG_UPDATED_ON.to_owned(), format_time(t));
        }
        tags
    }

    /// `SecretProperties` for one version of the secret.
    pub fn properties(
        &self,
        vault: &str,
        name: &str,
        version: &str,
        created_on: OffsetDateTime,
    ) -> SecretProperties {
        SecretProperties {
            vault: vault.to_owned(),
            name: name.to_owned(),
            version: version.to_owned(),
            enabled: !self.disabled,
            content_type: self.content_type.clone(),
            tags: self.tags.clone(),
            not_before: self.not_before,
            expires_on: self.expires_on,
            created_on,
            updated_on: self.updated_on.map_or(created_on, |u| u.max(created_on)),
            recovery_level: sourceorrery_core::RecoveryLevel::Recoverable,
        }
    }
}

/// `Tag` values for a tag map.
pub fn tags_of(map: &BTreeMap<String, String>) -> Vec<Tag> {
    map.iter()
        .map(|(k, v)| Tag::builder().key(k).value(v).build())
        .collect()
}

/// RFC 3339 at full precision.
pub fn format_time(ts: OffsetDateTime) -> String {
    ts.to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .unwrap_or_else(|_| ts.unix_timestamp().to_string())
}

/// Parse a timestamp this crate wrote into a tag.
pub fn parse_time(text: &str, what: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(text, &Rfc3339).map_err(|err| {
        SecretError::Storage(format!("tag {what} is not an RFC 3339 timestamp: {err}"))
    })
}

/// A Secrets Manager `DateTime` as an `OffsetDateTime`.
pub fn from_aws(ts: Option<&aws_sdk_secretsmanager::primitives::DateTime>) -> OffsetDateTime {
    ts.and_then(|t| OffsetDateTime::from_unix_timestamp_nanos(t.as_nanos()).ok())
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

/// A new version id: 32 hex digits, time-ordered (nanoseconds since the
/// epoch, then 64 random bits), valid as a `ClientRequestToken`.
pub fn new_version_id() -> String {
    let nanos = OffsetDateTime::now_utc().unix_timestamp_nanos();
    let nanos = u64::try_from(nanos).unwrap_or(0);
    let random = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    format!("{nanos:016x}{random:016x}")
}

/// One version of a secret, as listed.
#[derive(Debug, Clone)]
pub struct Version {
    pub id: String,
    pub created_on: OffsetDateTime,
    pub current: bool,
}

/// Sort versions newest first: the current one, then by creation time,
/// then by id (time-ordered for the ids this crate makes).
pub fn sort_newest_first(versions: &mut [Version]) {
    versions.sort_by(|a, b| {
        b.current
            .cmp(&a.current)
            .then_with(|| b.created_on.cmp(&a.created_on))
            .then_with(|| b.id.cmp(&a.id))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_round_trip_properties_and_keep_user_tags_apart() {
        let aws_tags = vec![
            Tag::builder().key("env").value("prod").build(),
            Tag::builder().key(TAG_DISABLED).value("true").build(),
            Tag::builder()
                .key(TAG_NOT_BEFORE)
                .value("2026-01-01T00:00:00Z")
                .build(),
            Tag::builder()
                .key("sourceorrery:future-key")
                .value("x")
                .build(),
        ];
        let props = SecretProps::from_tags(&aws_tags).unwrap();
        assert!(props.disabled);
        assert_eq!(
            props.tags,
            BTreeMap::from([("env".to_owned(), "prod".to_owned())])
        );
        assert!(props.not_before.is_some());
        let back = props.to_tags();
        assert_eq!(back["env"], "prod");
        assert_eq!(back[TAG_DISABLED], "true");
        assert!(!back.contains_key("sourceorrery:future-key"));
        let enabled = SecretProps::default().to_tags();
        assert!(enabled.is_empty());
    }

    #[test]
    fn version_ids_are_time_ordered_hex() {
        let a = new_version_id();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = new_version_id();
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert!(b > a);
        let mut versions = vec![
            Version {
                id: a.clone(),
                created_on: OffsetDateTime::UNIX_EPOCH,
                current: false,
            },
            Version {
                id: "foreign-uuid".to_owned(),
                created_on: OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(5),
                current: false,
            },
            Version {
                id: b.clone(),
                created_on: OffsetDateTime::UNIX_EPOCH,
                current: true,
            },
        ];
        sort_newest_first(&mut versions);
        let ids: Vec<&str> = versions.iter().map(|v| v.id.as_str()).collect();
        assert_eq!(ids, [b.as_str(), "foreign-uuid", a.as_str()]);
    }

    #[test]
    fn properties_carry_updated_on_only_when_changed() {
        let created = OffsetDateTime::UNIX_EPOCH + time::Duration::days(1);
        let props = SecretProps::default().properties("v", "k", "id", created);
        assert_eq!(props.updated_on, created);
        let later = created + time::Duration::hours(1);
        let mut changed = props.clone();
        changed.updated_on = later;
        changed.enabled = false;
        let stored = SecretProps::from_properties(&changed, created);
        assert_eq!(stored.updated_on, Some(later));
        assert!(stored.disabled);
        let unchanged = SecretProps::from_properties(&props, created);
        assert_eq!(unchanged.updated_on, None);
    }
}
