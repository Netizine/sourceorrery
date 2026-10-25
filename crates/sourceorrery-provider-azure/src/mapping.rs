//! The mapping of SourceOrrery's model onto Key Vault's.
//!
//! * A vault is one Key Vault; a secret is the Key Vault secret of the same
//!   name (the name rules are the same). Versions are Key Vault versions,
//!   with the ids Key Vault gives them.
//! * `enabled`, `not_before`, `expires_on`, `content_type` and tags belong
//!   to one version in both models and map one to one.
//! * Key Vault's times are whole seconds. Every version this crate writes
//!   carries its creation time at full precision in the reserved tag
//!   `sourceorrery:created_on`, and an update records its time in
//!   `sourceorrery:updated_on`, so versions written within one second keep
//!   their order. Versions written by other tools sort by Key Vault's time,
//!   then id.
//! * Values are text in Key Vault. Bytes that are not UTF-8 are stored as
//!   base64 and marked with `sourceorrery:encoding = base64`.
//! * Every other tag is a user tag. A version holds at most 15 tags, so
//!   user tags are limited to [`MAX_USER_TAGS`]; `sourceorrery:` keys are
//!   refused in them.
//! * Soft delete is Key Vault's own (every vault has it); recovery and purge
//!   are its operations, and the deletion and purge times are its own.

use std::collections::{BTreeMap, HashMap};
use std::hash::BuildHasher;

use azure_security_keyvault_secrets::models::{DeletionRecoveryLevel, SecretAttributes};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sourceorrery_core::{RecoveryLevel, Result, SecretBytes, SecretError, SecretProperties};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Tag key prefix of the properties this crate stores.
pub const TAG_PREFIX: &str = "sourceorrery:";
const TAG_CREATED_ON: &str = "sourceorrery:created_on";
const TAG_UPDATED_ON: &str = "sourceorrery:updated_on";
const TAG_ENCODING: &str = "sourceorrery:encoding";
const BASE64: &str = "base64";

/// Key Vault's limit of tags on one version.
pub const MAX_TAGS: usize = 15;
/// Tags left for the caller once the reserved ones are counted.
pub const MAX_USER_TAGS: usize = MAX_TAGS - 3;
/// Key Vault's limit on the length of a tag value.
pub const MAX_TAG_VALUE_LEN: usize = 256;
/// Key Vault's limit on the size of a stored value, in bytes.
pub const MAX_VALUE_LEN: usize = 25 * 1024;
/// Key Vault's default soft-delete retention, used when no secret says
/// otherwise.
pub const DEFAULT_RETENTION_DAYS: u32 = 90;

/// Refuse tags Key Vault would refuse, or that would collide with the
/// reserved ones.
pub fn check_user_tags(tags: &BTreeMap<String, String>) -> Result<()> {
    if tags.len() > MAX_USER_TAGS {
        return Err(SecretError::InvalidArgument(format!(
            "Azure Key Vault holds {MAX_TAGS} tags on a version and SourceOrrery keeps 3 of \
             them, so at most {MAX_USER_TAGS} tags can be given ({} were)",
            tags.len()
        )));
    }
    if let Some(key) = tags.keys().find(|k| k.starts_with(TAG_PREFIX)) {
        return Err(SecretError::InvalidArgument(format!(
            "tag '{}' uses the reserved prefix '{TAG_PREFIX}'",
            sourceorrery_core::text::foreign_bounded(key, 80)
        )));
    }
    if let Some(key) = tags
        .iter()
        .find(|(_, v)| v.chars().count() > MAX_TAG_VALUE_LEN)
        .map(|(k, _)| k)
    {
        return Err(SecretError::InvalidArgument(format!(
            "the value of tag '{}' is longer than Azure Key Vault's {MAX_TAG_VALUE_LEN} \
             characters",
            sourceorrery_core::text::foreign_bounded(key, 80)
        )));
    }
    Ok(())
}

/// A value as Key Vault text: itself when it is UTF-8, else base64 (the
/// `bool` says which). Refused when Key Vault could not hold it.
pub fn encode_value(value: &SecretBytes) -> Result<(String, bool)> {
    let (text, base64) = match std::str::from_utf8(value.expose()) {
        Ok(text) => (text.to_owned(), false),
        Err(_) => (STANDARD.encode(value.expose()), true),
    };
    if text.len() > MAX_VALUE_LEN {
        return Err(SecretError::InvalidArgument(format!(
            "Azure Key Vault holds values of up to {} KiB{}",
            MAX_VALUE_LEN / 1024,
            if base64 {
                " (a value that is not UTF-8 is stored as base64, a third larger)"
            } else {
                ""
            }
        )));
    }
    Ok((text, base64))
}

/// The bytes a version's text stands for.
pub fn decode_value<S: BuildHasher>(
    text: String,
    tags: Option<&HashMap<String, String, S>>,
) -> Result<SecretBytes> {
    if !is_base64(tags) {
        return Ok(SecretBytes::new(text.into_bytes()));
    }
    let bytes = STANDARD.decode(text.as_bytes()).map_err(|_| {
        SecretError::Storage("a value marked as base64 does not decode as base64".to_owned())
    });
    drop(text);
    Ok(SecretBytes::new(bytes?))
}

/// Every tag a version should carry: the user tags and the reserved ones.
pub fn tags_for(
    user: &BTreeMap<String, String>,
    created_on: OffsetDateTime,
    updated_on: Option<OffsetDateTime>,
    base64: bool,
) -> HashMap<String, String> {
    let mut tags: HashMap<String, String> =
        user.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    tags.insert(TAG_CREATED_ON.to_owned(), format_time(created_on));
    if let Some(updated_on) = updated_on {
        tags.insert(TAG_UPDATED_ON.to_owned(), format_time(updated_on));
    }
    if base64 {
        tags.insert(TAG_ENCODING.to_owned(), BASE64.to_owned());
    }
    tags
}

/// True when a version's value is stored as base64.
pub fn is_base64<S: BuildHasher>(tags: Option<&HashMap<String, String, S>>) -> bool {
    tags.and_then(|t| t.get(TAG_ENCODING))
        .is_some_and(|e| e == BASE64)
}

/// `SecretProperties` for one version, from what Key Vault returns for it.
pub fn properties<S: BuildHasher>(
    vault: &str,
    name: &str,
    version: &str,
    attributes: Option<&SecretAttributes>,
    content_type: Option<&str>,
    tags: Option<&HashMap<String, String, S>>,
) -> Result<SecretProperties> {
    let service_created = attributes.and_then(|a| a.created);
    let service_updated = attributes.and_then(|a| a.updated);
    let mut user = BTreeMap::new();
    let mut created_tag = None;
    let mut updated_tag = None;
    for (key, value) in tags.into_iter().flatten() {
        match key.as_str() {
            TAG_CREATED_ON => created_tag = Some(parse_time(value, key)?),
            TAG_UPDATED_ON => updated_tag = Some(parse_time(value, key)?),
            other if other.starts_with(TAG_PREFIX) => {}
            other => {
                user.insert(other.to_owned(), value.clone());
            }
        }
    }
    let created_on = created_tag
        .or(service_created)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    // Key Vault's own update time counts only when someone changed the
    // version after writing it; it is whole seconds, so it can trail the
    // precise creation time of an untouched version.
    let changed = match (service_created, service_updated) {
        (Some(created), Some(updated)) => (updated > created).then_some(updated),
        _ => None,
    };
    let updated_on = [Some(created_on), updated_tag, changed]
        .into_iter()
        .flatten()
        .max()
        .unwrap_or(created_on);
    Ok(SecretProperties {
        vault: vault.to_owned(),
        name: name.to_owned(),
        version: version.to_owned(),
        enabled: attributes.and_then(|a| a.enabled).unwrap_or(true),
        // An empty content type is how Key Vault clears one.
        content_type: content_type.filter(|c| !c.is_empty()).map(str::to_owned),
        tags: user,
        not_before: attributes.and_then(|a| a.not_before),
        expires_on: attributes.and_then(|a| a.expires),
        created_on,
        updated_on,
        recovery_level: recovery_level(attributes.and_then(|a| a.recovery_level.as_ref())),
    })
}

/// The contract's recovery level for Key Vault's.
pub fn recovery_level(level: Option<&DeletionRecoveryLevel>) -> RecoveryLevel {
    match level {
        Some(level) if !level.as_ref().contains("Recoverable") => RecoveryLevel::Purgeable,
        _ => RecoveryLevel::Recoverable,
    }
}

/// Sort versions newest first: by creation time, then by id.
pub fn sort_newest_first(versions: &mut [SecretProperties]) {
    versions.sort_by(|a, b| {
        b.created_on
            .cmp(&a.created_on)
            .then_with(|| b.version.cmp(&a.version))
    });
}

/// The version id at the end of a Key Vault secret id
/// (`https://<vault>/secrets/<name>/<version>`).
pub fn version_of(id: Option<&str>) -> Result<String> {
    id.and_then(|id| {
        let mut parts = id.trim_end_matches('/').rsplit('/');
        let version = parts.next()?;
        let _name = parts.next()?;
        (parts.next()? == "secrets").then(|| version.to_owned())
    })
    .ok_or_else(|| {
        SecretError::Storage("Key Vault returned a secret without a version id".to_owned())
    })
}

/// The secret name at the end of a Key Vault secret id without a version
/// (`https://<vault>/secrets/<name>`, as listings return it).
pub fn name_of(id: Option<&str>) -> Option<String> {
    let mut parts = id?.trim_end_matches('/').rsplit('/');
    let name = parts.next()?;
    (parts.next()? == "secrets").then(|| name.to_owned())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn attributes(created: i64, updated: i64) -> SecretAttributes {
        SecretAttributes {
            created: OffsetDateTime::from_unix_timestamp(created).ok(),
            updated: OffsetDateTime::from_unix_timestamp(updated).ok(),
            enabled: Some(true),
            ..SecretAttributes::default()
        }
    }

    #[test]
    fn reserved_tags_carry_precise_times_and_stay_apart_from_user_tags() {
        let created = OffsetDateTime::from_unix_timestamp_nanos(1_792_814_186_123_456_789).unwrap();
        let user = BTreeMap::from([("env".to_owned(), "prod".to_owned())]);
        let tags = tags_for(&user, created, None, false);
        assert_eq!(tags.len(), 2);
        let props = properties(
            "v",
            "db",
            "abc",
            Some(&attributes(1_792_814_186, 1_792_814_186)),
            Some("text/plain"),
            Some(&tags),
        )
        .unwrap();
        assert_eq!(props.created_on, created);
        assert_eq!(props.updated_on, created, "untouched: updated is created");
        assert_eq!(props.tags, user);
        assert_eq!(props.content_type.as_deref(), Some("text/plain"));

        // An update records its own time, which wins over Key Vault's seconds.
        let later = created + time::Duration::milliseconds(300);
        let updated = tags_for(&user, created, Some(later), true);
        let props = properties(
            "v",
            "db",
            "abc",
            Some(&attributes(1_792_814_186, 1_792_814_186)),
            Some(""),
            Some(&updated),
        )
        .unwrap();
        assert_eq!(props.updated_on, later);
        assert_eq!(props.content_type, None, "an empty content type is none");
        assert!(is_base64(Some(&updated)));
        assert!(!props.tags.keys().any(|k| k.starts_with(TAG_PREFIX)));
    }

    #[test]
    fn versions_from_other_tools_use_key_vaults_times() {
        let props = properties::<std::hash::RandomState>(
            "v",
            "db",
            "abc",
            Some(&attributes(100, 160)),
            None,
            None,
        )
        .unwrap();
        assert_eq!(props.created_on.unix_timestamp(), 100);
        assert_eq!(props.updated_on.unix_timestamp(), 160);
        let mut versions = vec![
            properties::<std::hash::RandomState>(
                "v",
                "db",
                "aaa",
                Some(&attributes(100, 100)),
                None,
                None,
            )
            .unwrap(),
            properties::<std::hash::RandomState>(
                "v",
                "db",
                "bbb",
                Some(&attributes(100, 100)),
                None,
                None,
            )
            .unwrap(),
            properties::<std::hash::RandomState>(
                "v",
                "db",
                "ccc",
                Some(&attributes(200, 200)),
                None,
                None,
            )
            .unwrap(),
        ];
        sort_newest_first(&mut versions);
        let order: Vec<&str> = versions.iter().map(|v| v.version.as_str()).collect();
        assert_eq!(order, ["ccc", "bbb", "aaa"]);
    }

    #[test]
    fn values_round_trip_as_text_or_base64() {
        let text = SecretBytes::from("hello");
        let (stored, base64) = encode_value(&text).unwrap();
        assert_eq!((stored.as_str(), base64), ("hello", false));
        assert_eq!(
            decode_value::<std::hash::RandomState>(stored, None)
                .unwrap()
                .expose(),
            b"hello"
        );

        let binary = SecretBytes::new(vec![0xff, 0x00, 0x80]);
        let (stored, base64) = encode_value(&binary).unwrap();
        assert!(base64);
        let tags = tags_for(&BTreeMap::new(), OffsetDateTime::UNIX_EPOCH, None, true);
        assert_eq!(
            decode_value(stored, Some(&tags)).unwrap().expose(),
            &[0xff, 0x00, 0x80]
        );
        let err = decode_value("not base64!".to_owned(), Some(&tags)).unwrap_err();
        assert_eq!(err.code(), "storage");
        assert!(!err.to_string().contains("not base64!"));

        let big = SecretBytes::new(vec![b'a'; MAX_VALUE_LEN + 1]);
        assert_eq!(encode_value(&big).unwrap_err().code(), "invalid_argument");
    }

    #[test]
    fn user_tags_respect_key_vaults_limits() {
        let many: BTreeMap<String, String> = (0..=MAX_USER_TAGS)
            .map(|i| (format!("k{i}"), "v".to_owned()))
            .collect();
        assert_eq!(
            check_user_tags(&many).unwrap_err().code(),
            "invalid_argument"
        );
        let reserved = BTreeMap::from([("sourceorrery:created_on".to_owned(), "x".to_owned())]);
        assert!(
            check_user_tags(&reserved)
                .unwrap_err()
                .to_string()
                .contains("reserved")
        );
        let long = BTreeMap::from([("k".to_owned(), "v".repeat(MAX_TAG_VALUE_LEN + 1))]);
        assert!(check_user_tags(&long).is_err());
        let rotation = BTreeMap::from([(
            "sourceorrery.rotation.state".to_owned(),
            "issued".to_owned(),
        )]);
        assert!(
            check_user_tags(&rotation).is_ok(),
            "rotation tags are user tags"
        );
    }

    #[test]
    fn ids_name_the_secret_and_version() {
        let id = "https://kv.vault.azure.net/secrets/db/02787a59eb9147ff8edde532637321cc";
        assert_eq!(
            version_of(Some(id)).unwrap(),
            "02787a59eb9147ff8edde532637321cc"
        );
        assert_eq!(
            name_of(Some("https://kv.vault.azure.net/secrets/db")).as_deref(),
            Some("db")
        );
        assert!(version_of(Some("https://kv.vault.azure.net/keys/k/1")).is_err());
        assert!(version_of(None).is_err());
        assert_eq!(
            name_of(Some("https://kv.vault.azure.net/deletedsecrets/db")),
            None
        );
    }

    #[test]
    fn recovery_levels_map_to_the_contracts_two() {
        assert_eq!(
            recovery_level(Some(&DeletionRecoveryLevel::CustomizedRecoverablePurgeable)),
            RecoveryLevel::Recoverable
        );
        assert_eq!(
            recovery_level(Some(&DeletionRecoveryLevel::Purgeable)),
            RecoveryLevel::Purgeable
        );
        assert_eq!(recovery_level(None), RecoveryLevel::Recoverable);
    }
}
