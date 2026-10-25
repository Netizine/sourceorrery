//! The KV version 2 API shapes and the mapping of SourceOrrery's model onto
//! them.
//!
//! * A secret is a KV path `<mount>/data/<name>`; its KV versions (1, 2,
//!   …) are the version ids, as decimal strings.
//! * The value is the `value` field of the KV data (`value_base64` when
//!   the bytes are not UTF-8). A KV secret written by something else, with
//!   other fields, is read whole as a JSON object with content type
//!   `application/json`.
//! * Per-version properties (`enabled`, content type, tags, the time
//!   window, `updated_on`) live in the secret's `custom_metadata` under one
//!   key per version, `sourceorrery.v<N>`, as a compact JSON document: the
//!   version's committed properties. A version with default properties has
//!   no key. KV v2 has no per-version metadata of its own, and
//!   `custom_metadata` is the one place that can be changed without writing
//!   a new version.
//! * An intent, `sourceorrery.v<N>~<nonce>`, is what one writer asked for
//!   version `N` before writing it (ADR 0011). Every reader applies a
//!   version's committed properties restricted by each of its intents
//!   ([`Metadata::effective_props`]), so a version is never readable under
//!   a looser policy than its writer asked for, whatever request fails.
//! * Soft delete is KV's `delete` of every live version plus a
//!   `sourceorrery.deleted` marker (when, which versions); recovery is
//!   `undelete` of those versions and removing the marker; purge deletes the
//!   metadata, and with it every version.

use std::collections::BTreeMap;
use std::io::Write;

use base64::Engine;
use serde::{Deserialize, Serialize};
use sourceorrery_core::{
    DeletedSecret, RecoveryLevel, Result, SecretBytes, SecretError, SecretProperties,
};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::{Zeroize, Zeroizing};

/// `custom_metadata` key prefix of a version's properties.
pub const PROPERTIES_PREFIX: &str = "sourceorrery.v";
/// `custom_metadata` key of the soft-delete marker.
pub const DELETED_KEY: &str = "sourceorrery.deleted";
/// What separates a version's number from a writer's nonce in an intent's
/// key.
pub const INTENT_SEPARATOR: char = '~';
/// Days a deleted secret is reported recoverable for. Informational: Vault
/// does not purge a deleted secret by itself.
pub const RETENTION_DAYS: u32 = 90;

/// `GET <mount>/metadata/<name>`.
#[derive(Debug, Deserialize)]
pub struct MetadataResponse {
    pub data: Metadata,
}

/// A secret's KV metadata.
#[derive(Debug, Default, Deserialize)]
pub struct Metadata {
    #[serde(default)]
    pub current_version: u64,
    #[serde(default)]
    pub custom_metadata: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub versions: BTreeMap<String, VersionMeta>,
}

/// One KV version's metadata.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct VersionMeta {
    #[serde(default)]
    pub created_time: String,
    #[serde(default)]
    pub deletion_time: String,
    #[serde(default)]
    pub destroyed: bool,
}

impl VersionMeta {
    /// Readable: neither destroyed nor soft-deleted in KV.
    pub fn is_live(&self) -> bool {
        !self.destroyed && self.deletion_time.is_empty()
    }
}

/// `POST <mount>/data/<name>`.
#[derive(Debug, Deserialize)]
pub struct WriteResponse {
    pub data: WrittenVersion,
}

/// The version a write created.
#[derive(Debug, Deserialize)]
pub struct WrittenVersion {
    pub version: u64,
    #[serde(default)]
    pub created_time: String,
}

/// `GET <mount>/data/<name>?version=N`.
#[derive(Debug, Deserialize)]
pub struct ReadResponse {
    pub data: ReadData,
}

/// The data of one version. `data` is `None` for a deleted or destroyed
/// version.
#[derive(Debug, Deserialize)]
pub struct ReadData {
    #[serde(default)]
    pub data: Option<serde_json::Map<String, serde_json::Value>>,
}

/// `LIST <mount>/metadata/`.
#[derive(Debug, Deserialize)]
pub struct ListResponse {
    pub data: ListKeys,
}

/// The keys under a path; a key ending in `/` is a folder.
#[derive(Debug, Default, Deserialize)]
pub struct ListKeys {
    #[serde(default)]
    pub keys: Vec<String>,
}

/// `GET sys/internal/ui/mounts/<mount>`.
#[derive(Debug, Deserialize)]
pub struct MountResponse {
    pub data: MountInfo,
}

/// What a mount is.
#[derive(Debug, Default, Deserialize)]
pub struct MountInfo {
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub accessor: String,
    #[serde(default)]
    pub options: Option<BTreeMap<String, serde_json::Value>>,
}

/// A version's properties as stored in `custom_metadata`. Every field is
/// omitted when it has its default, so a default version has no document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct VersionProps {
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub tags: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_on: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_on: Option<String>,
}

impl VersionProps {
    /// True when nothing differs from a fresh version.
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// The properties a new version is asked for: no `updated_on`, since it
    /// has not been changed since it was written.
    pub fn asked(
        enabled: bool,
        content_type: Option<String>,
        tags: BTreeMap<String, String>,
        not_before: Option<OffsetDateTime>,
        expires_on: Option<OffsetDateTime>,
    ) -> Self {
        Self {
            disabled: !enabled,
            content_type,
            tags,
            not_before: not_before.map(format_time),
            expires_on: expires_on.map(format_time),
            updated_on: None,
        }
    }

    /// The compact JSON document stored for these properties.
    pub fn document(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|err| SecretError::Storage(err.to_string()))
    }

    /// Restrict the policy to `other`'s as well: disabled if either is, the
    /// later `not_before`, the earlier `expires_on`. The content type, the
    /// tags and `updated_on` stay this document's.
    fn restrict_to(&mut self, other: &Self) -> Result<()> {
        self.disabled |= other.disabled;
        self.not_before = pick(
            self.not_before.as_deref(),
            other.not_before.as_deref(),
            "not_before",
            OffsetDateTime::max,
        )?;
        self.expires_on = pick(
            self.expires_on.as_deref(),
            other.expires_on.as_deref(),
            "expires_on",
            OffsetDateTime::min,
        )?;
        Ok(())
    }

    /// The properties `properties` carries beyond what KV knows.
    pub fn from_properties(properties: &SecretProperties, created_on: OffsetDateTime) -> Self {
        Self {
            disabled: !properties.enabled,
            content_type: properties.content_type.clone(),
            tags: properties.tags.clone(),
            not_before: properties.not_before.map(format_time),
            expires_on: properties.expires_on.map(format_time),
            updated_on: (properties.updated_on != created_on)
                .then(|| format_time(properties.updated_on)),
        }
    }
}

/// Of two optional stored times, the one `choose` picks; either alone when
/// the other is absent.
fn pick(
    a: Option<&str>,
    b: Option<&str>,
    what: &str,
    choose: fn(OffsetDateTime, OffsetDateTime) -> OffsetDateTime,
) -> Result<Option<String>> {
    Ok(match (a, b) {
        (None, None) => None,
        (Some(t), None) | (None, Some(t)) => Some(t.to_owned()),
        (Some(a), Some(b)) => Some(format_time(choose(
            parse_time(a, what)?,
            parse_time(b, what)?,
        ))),
    })
}

/// The soft-delete marker.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletedMarker {
    pub deleted_on: String,
    pub versions: Vec<u64>,
}

/// The key of version `version`'s properties.
pub fn properties_key(version: u64) -> String {
    format!("{PROPERTIES_PREFIX}{version}")
}

/// The key of a writer's intent for version `version`.
pub fn intent_key(version: u64, nonce: &str) -> String {
    format!("{PROPERTIES_PREFIX}{version}{INTENT_SEPARATOR}{nonce}")
}

/// The version an intent's key names, or `None` for any other key.
fn intent_version(key: &str) -> Option<u64> {
    let (version, nonce) = key
        .strip_prefix(PROPERTIES_PREFIX)?
        .split_once(INTENT_SEPARATOR)?;
    (!nonce.is_empty()).then_some(())?;
    version.parse().ok()
}

/// RFC 3339 with the full precision Vault and this crate use.
pub fn format_time(ts: OffsetDateTime) -> String {
    ts.to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .unwrap_or_else(|_| ts.unix_timestamp().to_string())
}

/// Parse a timestamp Vault or this crate wrote.
pub fn parse_time(text: &str, what: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(text, &Rfc3339)
        .map_err(|err| SecretError::Storage(format!("{what} is not an RFC 3339 timestamp: {err}")))
}

impl Metadata {
    /// The custom metadata, owned, for a read-modify-write.
    pub fn custom(&self) -> BTreeMap<String, String> {
        self.custom_metadata.clone().unwrap_or_default()
    }

    /// Version numbers that are live in KV, newest first.
    pub fn live_versions(&self) -> Vec<u64> {
        let mut versions: Vec<u64> = self
            .versions
            .iter()
            .filter(|(_, meta)| meta.is_live())
            .filter_map(|(number, _)| number.parse().ok())
            .collect();
        versions.sort_unstable_by(|a, b| b.cmp(a));
        versions
    }

    /// The committed properties of `version`, if any were stored.
    pub fn version_props(&self, version: u64) -> Result<Option<VersionProps>> {
        let key = properties_key(version);
        self.custom_metadata
            .as_ref()
            .and_then(|custom| custom.get(&key))
            .map(|text| parse_props(text, &key))
            .transpose()
    }

    /// The intents for `version`, by key in key order.
    pub fn intents_for(&self, version: u64) -> Result<Vec<(String, VersionProps)>> {
        self.custom_metadata
            .iter()
            .flatten()
            .filter(|(key, _)| intent_version(key) == Some(version))
            .map(|(key, text)| Ok((key.clone(), parse_props(text, key)?)))
            .collect()
    }

    /// Every key that bears on `version`'s properties: its committed
    /// document and its intents.
    pub fn keys_for(&self, version: u64) -> Vec<String> {
        let committed = properties_key(version);
        self.custom_metadata
            .iter()
            .flatten()
            .map(|(key, _)| key)
            .filter(|key| **key == committed || intent_version(key) == Some(version))
            .cloned()
            .collect()
    }

    /// The properties every SourceOrrery reader applies to `version` (ADR
    /// 0011): its committed document, or the defaults without one,
    /// restricted by every intent for it. The content type, the tags and
    /// `updated_on` are the committed document's, or else the first
    /// intent's.
    pub fn effective_props(&self, version: u64) -> Result<VersionProps> {
        let intents = self.intents_for(version)?;
        let mut props = match self.version_props(version)? {
            Some(committed) => committed,
            None => intents
                .first()
                .map(|(_, intent)| intent.clone())
                .unwrap_or_default(),
        };
        for (_, intent) in &intents {
            props.restrict_to(intent)?;
        }
        Ok(props)
    }

    /// The soft-delete marker, when the secret is deleted.
    pub fn deleted_marker(&self) -> Result<Option<DeletedMarker>> {
        let Some(text) = self
            .custom_metadata
            .as_ref()
            .and_then(|custom| custom.get(DELETED_KEY))
        else {
            return Ok(None);
        };
        serde_json::from_str(text).map(Some).map_err(|err| {
            SecretError::Storage(format!(
                "custom_metadata {DELETED_KEY} is not a deletion marker: {err}"
            ))
        })
    }

    /// The `SecretProperties` of `version`, from KV's version metadata and
    /// the stored properties.
    pub fn properties(&self, vault: &str, name: &str, version: u64) -> Result<SecretProperties> {
        let meta = self.versions.get(&version.to_string()).ok_or_else(|| {
            SecretError::VersionNotFound {
                name: name.to_owned(),
                version: version.to_string(),
            }
        })?;
        let created_on = parse_time(&meta.created_time, "created_time")?;
        let props = self.effective_props(version)?;
        Ok(SecretProperties {
            vault: vault.to_owned(),
            name: name.to_owned(),
            version: version.to_string(),
            enabled: !props.disabled,
            content_type: props.content_type,
            tags: props.tags,
            not_before: props
                .not_before
                .as_deref()
                .map(|t| parse_time(t, "not_before"))
                .transpose()?,
            expires_on: props
                .expires_on
                .as_deref()
                .map(|t| parse_time(t, "expires_on"))
                .transpose()?,
            created_on,
            // `updated_on` is the writer's clock, `created_on` the server's:
            // a skew between them never puts the update before the version.
            updated_on: match props.updated_on.as_deref() {
                Some(t) => parse_time(t, "updated_on")?.max(created_on),
                None => created_on,
            },
            recovery_level: RecoveryLevel::Recoverable,
        })
    }

    /// The deleted-secret view of a secret whose marker is `marker`.
    pub fn deleted_secret(
        &self,
        vault: &str,
        name: &str,
        marker: &DeletedMarker,
    ) -> Result<DeletedSecret> {
        let newest = marker.versions.iter().copied().max().ok_or_else(|| {
            SecretError::Storage(format!("the deletion marker of '{name}' lists no versions"))
        })?;
        let deleted_on = parse_time(&marker.deleted_on, "deleted_on")?;
        Ok(DeletedSecret {
            properties: self.properties(vault, name, newest)?,
            deleted_on,
            scheduled_purge_on: Some(
                deleted_on
                    .checked_add(time::Duration::days(i64::from(RETENTION_DAYS)))
                    .ok_or_else(|| {
                        SecretError::Storage(format!(
                            "the deletion marker of '{name}' carries a date out of range"
                        ))
                    })?,
            ),
            recovery_id: format!("sourceorrery://{vault}/deletedsecrets/{name}"),
        })
    }
}

/// A properties document read from `key`.
fn parse_props(text: &str, key: &str) -> Result<VersionProps> {
    serde_json::from_str(text).map_err(|err| {
        SecretError::Storage(format!(
            "custom_metadata {key} is not a properties document: {err}"
        ))
    })
}

/// Wipe every string in `value`, nested ones included: the copies of a
/// secret a JSON document held, before it is dropped.
pub fn wipe(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => text.zeroize(),
        serde_json::Value::Array(items) => items.iter_mut().for_each(wipe),
        serde_json::Value::Object(map) => map.values_mut().for_each(wipe),
        _ => {}
    }
}

/// A writer into a buffer that is wiped on drop and, when it grows, moves
/// into a new buffer and wipes the old: serialised JSON that carries a value
/// leaves no copy in freed memory.
struct Wiped(Zeroizing<Vec<u8>>);

impl Write for Wiped {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let needed = self.0.len() + bytes.len();
        if needed > self.0.capacity() {
            let capacity = needed.max(self.0.capacity().saturating_mul(2)).max(256);
            let mut grown = Zeroizing::new(Vec::with_capacity(capacity));
            grown.extend_from_slice(&self.0);
            self.0 = grown;
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// `value` serialised as JSON into a wiping buffer.
pub fn to_wiped_json(value: &serde_json::Value) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Wiped(Zeroizing::new(Vec::new()));
    serde_json::to_writer(&mut out, value).map_err(|err| SecretError::Storage(err.to_string()))?;
    Ok(out.0)
}

/// The KV data object that stores `value`. It holds a copy of the value:
/// the caller [`wipe`]s it once the request is sent.
pub fn encode_value(value: &SecretBytes) -> serde_json::Value {
    match std::str::from_utf8(value.expose()) {
        Ok(text) if !text.contains('\0') => serde_json::json!({ "value": text }),
        _ => serde_json::json!({
            "value_base64": base64::engine::general_purpose::STANDARD.encode(value.expose())
        }),
    }
}

/// The value a KV data object holds, and the content type it implies when
/// the object was not written by SourceOrrery (`application/json`).
pub fn decode_value(
    mut data: serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Result<(SecretBytes, Option<&'static str>)> {
    if let Some(serde_json::Value::String(text)) = data.remove("value") {
        return Ok((SecretBytes::new(text.into_bytes()), None));
    }
    if let Some(serde_json::Value::String(text)) = data.remove("value_base64") {
        let mut text = Zeroizing::new(text);
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(text.as_bytes())
            .map_err(|_| {
                SecretError::Storage(format!("the value_base64 field of '{name}' is not base64"))
            });
        text.zeroize();
        return Ok((SecretBytes::new(bytes?), None));
    }
    // An object another client wrote is the value whole: serialised into a
    // wiping buffer, and the parsed fields wiped once copied.
    let mut object = serde_json::Value::Object(data);
    let json = to_wiped_json(&object);
    wipe(&mut object);
    let mut json = json.map_err(|err| {
        SecretError::Storage(format!("cannot serialise the fields of '{name}': {err}"))
    })?;
    Ok((
        SecretBytes::new(std::mem::take(&mut *json)),
        Some("application/json"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_copies_of_a_value_are_serialised_and_wiped() {
        let mut document = serde_json::json!({
            "data": { "value": "s3cret", "list": ["s3cret", { "deep": "s3cret" }] },
            "options": { "cas": 1 },
        });
        let bytes = to_wiped_json(&document).unwrap();
        assert_eq!(
            &bytes[..],
            br#"{"data":{"list":["s3cret",{"deep":"s3cret"}],"value":"s3cret"},"options":{"cas":1}}"#
        );
        wipe(&mut document);
        assert!(!document.to_string().contains("s3cret"), "{document}");
        assert_eq!(document["options"]["cas"], 1, "numbers stay");
    }

    #[test]
    fn values_round_trip_as_text_base64_or_whole_objects() {
        let text = SecretBytes::from("hello");
        let encoded = encode_value(&text);
        assert_eq!(encoded["value"], "hello");
        let (back, ct) = decode_value(encoded.as_object().unwrap().clone(), "k").unwrap();
        assert_eq!(back.expose(), b"hello");
        assert_eq!(ct, None);

        let binary = SecretBytes::new(vec![0, 159, 146, 150]);
        let encoded = encode_value(&binary);
        assert!(encoded.get("value").is_none());
        let (back, _) = decode_value(encoded.as_object().unwrap().clone(), "k").unwrap();
        assert_eq!(back.expose(), &[0, 159, 146, 150]);

        let foreign = serde_json::json!({ "username": "app", "password": "x" });
        let (back, ct) = decode_value(foreign.as_object().unwrap().clone(), "k").unwrap();
        assert_eq!(back.expose(), br#"{"password":"x","username":"app"}"#);
        assert_eq!(ct, Some("application/json"));
    }

    #[test]
    fn default_properties_store_nothing_and_others_round_trip() {
        assert!(VersionProps::default().is_default());
        assert_eq!(
            serde_json::to_string(&VersionProps::default()).unwrap(),
            "{}"
        );
        let props = VersionProps {
            disabled: true,
            content_type: Some("text/plain".into()),
            tags: BTreeMap::from([("env".to_owned(), "dev".to_owned())]),
            not_before: Some("2026-01-01T00:00:00Z".into()),
            expires_on: None,
            updated_on: Some("2026-01-02T00:00:00.5Z".into()),
        };
        let json = serde_json::to_string(&props).unwrap();
        assert!(!json.contains("expires_on"));
        assert_eq!(serde_json::from_str::<VersionProps>(&json).unwrap(), props);
    }

    #[test]
    fn an_update_stamped_by_a_slower_clock_is_never_before_the_version() {
        // The server created version 1 at 10:00:00.200 by its clock; the
        // client that updated it a moment later had 10:00:00.150 on its own.
        let text = r#"{"data":{"created_time":"2026-10-23T10:00:00.2Z","current_version":1,
            "custom_metadata":{"sourceorrery.v1":"{\"content_type\":\"text/plain\",\"updated_on\":\"2026-10-23T10:00:00.15Z\"}"},
            "oldest_version":1,"updated_time":"2026-10-23T10:00:00.2Z",
            "versions":{"1":{"created_time":"2026-10-23T10:00:00.2Z","deletion_time":"","destroyed":false}}}}"#;
        let meta: MetadataResponse = serde_json::from_str(text).unwrap();
        let v1 = meta.data.properties("prod", "k", 1).unwrap();
        assert_eq!(v1.content_type.as_deref(), Some("text/plain"));
        assert_eq!(v1.updated_on, v1.created_on);
    }

    fn metadata(custom: &[(&str, &str)]) -> Metadata {
        let live = VersionMeta {
            created_time: "2026-10-25T10:00:00Z".to_owned(),
            ..VersionMeta::default()
        };
        Metadata {
            current_version: 2,
            custom_metadata: Some(
                custom
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect(),
            ),
            versions: BTreeMap::from([("1".to_owned(), live.clone()), ("2".to_owned(), live)]),
        }
    }

    #[test]
    fn intents_restrict_a_version_and_never_loosen_it() {
        // An intent alone: its properties apply, before anything commits.
        let meta = metadata(&[(
            "sourceorrery.v2~aaaa",
            r#"{"disabled":true,"tags":{"k":"a"}}"#,
        )]);
        let v2 = meta.properties("prod", "s", 2).unwrap();
        assert!(!v2.enabled);
        assert_eq!(v2.tags["k"], "a");
        assert!(meta.properties("prod", "s", 1).unwrap().enabled, "only v2");

        // A committed document that is looser does not lift an intent's
        // restriction; the committed tags stay.
        let meta = metadata(&[
            ("sourceorrery.v2", r#"{"tags":{"k":"committed"}}"#),
            ("sourceorrery.v2~aaaa", r#"{"disabled":true}"#),
        ]);
        let v2 = meta.properties("prod", "s", 2).unwrap();
        assert!(!v2.enabled);
        assert_eq!(v2.tags["k"], "committed");

        // Two writers' intents: disabled if either is, the later start,
        // the earlier end.
        let meta = metadata(&[
            (
                "sourceorrery.v2~aaaa",
                r#"{"not_before":"2026-11-01T00:00:00Z","expires_on":"2027-01-01T00:00:00Z"}"#,
            ),
            (
                "sourceorrery.v2~bbbb",
                r#"{"not_before":"2026-12-01T00:00:00Z","expires_on":"2026-12-31T00:00:00Z"}"#,
            ),
        ]);
        let v2 = meta.properties("prod", "s", 2).unwrap();
        assert!(v2.enabled);
        assert_eq!(
            v2.not_before,
            Some(parse_time("2026-12-01T00:00:00Z", "t").unwrap())
        );
        assert_eq!(
            v2.expires_on,
            Some(parse_time("2026-12-31T00:00:00Z", "t").unwrap())
        );

        // Keys that are not intents for the version are not taken for one.
        let meta = metadata(&[
            ("sourceorrery.v2~", r#"{"disabled":true}"#),
            ("sourceorrery.v22~aaaa", r#"{"disabled":true}"#),
            ("other~x", r#"{"disabled":true}"#),
        ]);
        assert!(meta.properties("prod", "s", 2).unwrap().enabled);
        assert_eq!(meta.intents_for(22).unwrap().len(), 1);
        let meta = metadata(&[
            ("sourceorrery.v2", "{}"),
            ("sourceorrery.v2~aaaa", "{}"),
            ("sourceorrery.v1", "{}"),
        ]);
        assert_eq!(
            meta.keys_for(2),
            vec![
                "sourceorrery.v2".to_owned(),
                "sourceorrery.v2~aaaa".to_owned()
            ]
        );
        assert_eq!(intent_key(7, "00ff"), "sourceorrery.v7~00ff");
    }

    #[test]
    fn metadata_maps_to_properties_and_deleted_secrets() {
        let text = r#"{"data":{"created_time":"2026-10-23T10:00:00.123456789Z","current_version":3,
            "custom_metadata":{"sourceorrery.v2":"{\"disabled\":true,\"tags\":{\"a\":\"b\"}}",
                               "sourceorrery.deleted":"{\"deleted_on\":\"2026-10-23T12:00:00Z\",\"versions\":[2,3]}"},
            "oldest_version":1,"updated_time":"2026-10-23T11:00:00Z",
            "versions":{"1":{"created_time":"2026-10-23T10:00:00Z","deletion_time":"","destroyed":true},
                        "2":{"created_time":"2026-10-23T10:30:00Z","deletion_time":"2026-10-23T12:00:00Z","destroyed":false},
                        "3":{"created_time":"2026-10-23T11:00:00Z","deletion_time":"2026-10-23T12:00:00Z","destroyed":false}}}}"#;
        let meta: MetadataResponse = serde_json::from_str(text).unwrap();
        let meta = meta.data;
        assert_eq!(meta.live_versions(), Vec::<u64>::new());
        let v2 = meta.properties("prod", "k", 2).unwrap();
        assert!(!v2.enabled);
        assert_eq!(v2.tags["a"], "b");
        assert_eq!(v2.version, "2");
        assert_eq!(v2.updated_on, v2.created_on);
        let v3 = meta.properties("prod", "k", 3).unwrap();
        assert!(v3.enabled);
        assert_eq!(
            meta.properties("prod", "k", 9).unwrap_err().code(),
            "version_not_found"
        );
        let marker = meta.deleted_marker().unwrap().unwrap();
        let deleted = meta.deleted_secret("prod", "k", &marker).unwrap();
        assert_eq!(deleted.properties.version, "3");
        assert_eq!(deleted.recovery_id, "sourceorrery://prod/deletedsecrets/k");
        assert!(deleted.scheduled_purge_on.unwrap() > deleted.deleted_on);
        assert_eq!(properties_key(7), "sourceorrery.v7");
    }
}
