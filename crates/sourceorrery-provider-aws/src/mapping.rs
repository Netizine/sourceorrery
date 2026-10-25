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
//! * Tags, content types and values are checked against Secrets Manager's
//!   rules before any request ([`check_user_tags`], [`check_content_type`],
//!   [`check_value`], [`check_tag_count`]), and tags change in an order that
//!   never loosens the policy below where it is going ([`TagPlan`], ADR
//!   0011).

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

/// The tags that decide whether a version may be read.
const POLICY_TAGS: [&str; 3] = [TAG_DISABLED, TAG_NOT_BEFORE, TAG_EXPIRES_ON];

/// Tag key prefix Secrets Manager keeps for AWS's own tags, which cannot be
/// changed and do not count against the limit.
pub const AWS_PREFIX: &str = "aws:";
/// Secrets Manager's limit of tags on one secret, AWS's own not counted.
pub const MAX_TAGS: usize = 50;
/// Secrets Manager's limit on a tag key, in characters.
pub const MAX_TAG_KEY_LEN: usize = 128;
/// Secrets Manager's limit on a tag value, in characters.
pub const MAX_TAG_VALUE_LEN: usize = 256;
/// Secrets Manager's limit on a value (`SecretString` or `SecretBinary`),
/// in bytes.
pub const MAX_VALUE_LEN: usize = 65_536;

/// True for a key of AWS's own (`aws:` in any case).
pub fn is_aws_key(key: &str) -> bool {
    key.get(..AWS_PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(AWS_PREFIX))
}

/// True for a key whose tag decides whether a version may be read.
pub fn is_policy_key(key: &str) -> bool {
    POLICY_TAGS.contains(&key)
}

/// The characters AWS allows in tag keys and values: letters, digits and
/// white space in any script, and `_ . : / = + - @` (AWS's tagging
/// reference; Secrets Manager's own page omits the colon, which its `aws:`
/// keys and every timestamp here use).
fn allowed(c: char) -> bool {
    c.is_alphanumeric() || c.is_whitespace() || "_.:/=+-@".contains(c)
}

fn bounded(text: &str) -> String {
    sourceorrery_core::text::foreign_bounded(text, 80)
}

fn invalid(reason: String) -> SecretError {
    SecretError::InvalidArgument(reason)
}

/// Refuse a tag value Secrets Manager would refuse; `what` names it.
fn check_tag_value(value: &str, what: &str) -> Result<()> {
    if value.chars().count() > MAX_TAG_VALUE_LEN {
        return Err(invalid(format!(
            "{what} is longer than the {MAX_TAG_VALUE_LEN} characters an AWS Secrets Manager tag \
             value holds"
        )));
    }
    if let Some(c) = value.chars().find(|c| !allowed(*c)) {
        return Err(invalid(format!(
            "{what} has a character AWS Secrets Manager does not allow in a tag value ({}): \
             letters, digits, spaces and _ . : / = + - @ only",
            c.escape_unicode()
        )));
    }
    Ok(())
}

/// Refuse user tags Secrets Manager would refuse, or that would collide
/// with the reserved ones: before any request, so nothing is sent for
/// input the service would turn down after the value was published.
pub fn check_user_tags(tags: &BTreeMap<String, String>) -> Result<()> {
    for (key, value) in tags {
        let shown = bounded(key);
        if key.is_empty() || key.chars().count() > MAX_TAG_KEY_LEN {
            return Err(invalid(format!(
                "tag '{shown}': an AWS Secrets Manager tag key has 1 to {MAX_TAG_KEY_LEN} \
                 characters"
            )));
        }
        if is_aws_key(key) {
            return Err(invalid(format!(
                "tag '{shown}' uses the prefix '{AWS_PREFIX}', which AWS keeps for its own tags"
            )));
        }
        if key
            .get(..TAG_PREFIX.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(TAG_PREFIX))
        {
            return Err(invalid(format!(
                "tag '{shown}' uses the reserved prefix '{TAG_PREFIX}'"
            )));
        }
        if let Some(c) = key.chars().find(|c| !allowed(*c)) {
            return Err(invalid(format!(
                "tag '{shown}' has a character AWS Secrets Manager does not allow in a tag key \
                 ({}): letters, digits, spaces and _ . : / = + - @ only",
                c.escape_unicode()
            )));
        }
        check_tag_value(value, &format!("the value of tag '{shown}'"))?;
    }
    Ok(())
}

/// Refuse a content type that cannot be a tag value (it is stored as one).
pub fn check_content_type(content_type: Option<&str>) -> Result<()> {
    content_type.map_or(Ok(()), |ct| check_tag_value(ct, "the content type"))
}

/// Refuse a value larger than Secrets Manager holds.
pub fn check_value(value: &[u8]) -> Result<()> {
    if value.len() > MAX_VALUE_LEN {
        return Err(invalid(format!(
            "AWS Secrets Manager holds values of up to {} KiB",
            MAX_VALUE_LEN / 1024
        )));
    }
    Ok(())
}

/// Refuse a change whose tags would, at some moment, exceed what one
/// secret holds: `peak` is the most the secret carries at once.
pub fn check_tag_count(peak: usize) -> Result<()> {
    if peak > MAX_TAGS {
        return Err(invalid(format!(
            "the secret would carry {peak} tags at once and AWS Secrets Manager holds \
             {MAX_TAGS}; SourceOrrery keeps up to 5 of them (its properties), so give fewer tags"
        )));
    }
    Ok(())
}

/// The tags `tags` holds, by key.
pub fn tag_map(tags: &[Tag]) -> BTreeMap<String, String> {
    tags.iter()
        .filter_map(|t| {
            Some((
                t.key()?.to_owned(),
                t.value().unwrap_or_default().to_owned(),
            ))
        })
        .collect()
}

/// How a secret's tags go from what they are to what they should be, in an
/// order that never loosens the policy below the target (ADR 0011): stale
/// tags that are not policy go first, then every wanted tag that differs
/// is written (adding a restriction or replacing one), and stale policy
/// tags (a restriction no longer wanted) go last. AWS's own tags are never
/// touched.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TagPlan {
    /// Keys to remove first: no longer wanted, and not policy.
    pub untag_first: Vec<String>,
    /// Tags to write.
    pub tag: BTreeMap<String, String>,
    /// Keys to remove last: policy no longer wanted.
    pub untag_last: Vec<String>,
}

impl TagPlan {
    /// The plan from `current` to `wanted`.
    pub fn to(current: &BTreeMap<String, String>, wanted: &BTreeMap<String, String>) -> Self {
        let (untag_last, untag_first) = current
            .keys()
            .filter(|key| !is_aws_key(key) && !wanted.contains_key(*key))
            .cloned()
            .partition(|key| is_policy_key(key));
        let tag = wanted
            .iter()
            .filter(|(key, value)| current.get(*key) != Some(*value))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        Self {
            untag_first,
            tag,
            untag_last,
        }
    }

    /// True when nothing changes.
    pub fn is_empty(&self) -> bool {
        self.untag_first.is_empty() && self.tag.is_empty() && self.untag_last.is_empty()
    }

    /// The most tags (AWS's own not counted) the secret carries at once
    /// while the plan runs from `current`.
    pub fn peak(&self, current: &BTreeMap<String, String>) -> usize {
        let mut keys: std::collections::BTreeSet<&str> = current
            .keys()
            .map(String::as_str)
            .filter(|key| !is_aws_key(key))
            .collect();
        let mut peak = keys.len();
        for key in &self.untag_first {
            keys.remove(key.as_str());
        }
        keys.extend(self.tag.keys().map(String::as_str));
        peak = peak.max(keys.len());
        peak
    }

    /// The tags after each step, `current` first: what a reader may see.
    pub fn states(&self, current: &BTreeMap<String, String>) -> Vec<BTreeMap<String, String>> {
        let mut state = current.clone();
        let mut states = vec![state.clone()];
        for key in &self.untag_first {
            state.remove(key);
        }
        states.push(state.clone());
        state.extend(self.tag.iter().map(|(k, v)| (k.clone(), v.clone())));
        states.push(state.clone());
        for key in &self.untag_last {
            state.remove(key);
        }
        states.push(state);
        states
    }
}

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
                // AWS's own tags are not the user's, and cannot be written.
                other if other.starts_with(TAG_PREFIX) || is_aws_key(other) => {}
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

    /// The policy of both: disabled if either is, the later `not_before`,
    /// the earlier `expires_on`. The other properties are this one's.
    #[must_use]
    pub fn meet(&self, other: &Self) -> Self {
        Self {
            disabled: self.disabled || other.disabled,
            not_before: self.not_before.max(other.not_before),
            expires_on: match (self.expires_on, other.expires_on) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            },
            ..self.clone()
        }
    }

    /// True when this policy refuses at least whatever `other`'s refuses:
    /// disabled if `other` is, starting no earlier and ending no later.
    pub fn at_least_as_strict_as(&self, other: &Self) -> bool {
        (self.disabled || !other.disabled)
            && other
                .not_before
                .is_none_or(|t| self.not_before.is_some_and(|s| s >= t))
            && other
                .expires_on
                .is_none_or(|t| self.expires_on.is_some_and(|s| s <= t))
    }

    /// The policy tags alone (see [`is_policy_key`]).
    pub fn policy_tags(&self) -> BTreeMap<String, String> {
        self.to_tags()
            .into_iter()
            .filter(|(key, _)| is_policy_key(key))
            .collect()
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

    fn tags(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn user_tags_content_types_and_values_are_checked_before_any_request() {
        let ok = tags(&[
            ("team", "payments"),
            ("cost-center", "4711"),
            ("owner", "a.b@example.com"),
            ("path", "/srv/app:main"),
            ("Ünïcode Ключ", "値 1+1=2"),
            ("empty", ""),
        ]);
        check_user_tags(&ok).unwrap();
        let long_key = "k".repeat(MAX_TAG_KEY_LEN + 1);
        let long_value = "v".repeat(MAX_TAG_VALUE_LEN + 1);
        let refused = [
            ("aws:cloudformation:stack-name", "x", "AWS keeps"),
            ("AWS:Thing", "x", "AWS keeps"),
            ("sourceorrery:disabled", "false", "reserved prefix"),
            ("SourceOrrery:anything", "x", "reserved prefix"),
            ("", "x", "1 to 128"),
            (long_key.as_str(), "x", "1 to 128"),
            ("semi;colon", "x", "does not allow in a tag key"),
            ("quote\"", "x", "does not allow in a tag key"),
            ("fine", long_value.as_str(), "longer than"),
            ("fine", "a;b", "does not allow in a tag value"),
            ("fine", "line\u{0}break", "does not allow in a tag value"),
        ];
        for (key, value, says) in refused {
            let err = check_user_tags(&tags(&[(key, value)])).unwrap_err();
            assert_eq!(err.code(), "invalid_argument", "{key}");
            assert!(err.to_string().contains(says), "{key}: {err}");
        }
        check_content_type(Some("application/json")).unwrap();
        check_content_type(None).unwrap();
        let err = check_content_type(Some("text/plain; charset=utf-8")).unwrap_err();
        assert!(err.to_string().contains("content type"), "{err}");
        check_value(&vec![0; MAX_VALUE_LEN]).unwrap();
        assert_eq!(
            check_value(&vec![0; MAX_VALUE_LEN + 1]).unwrap_err().code(),
            "invalid_argument"
        );
        check_tag_count(MAX_TAGS).unwrap();
        assert!(
            check_tag_count(MAX_TAGS + 1)
                .unwrap_err()
                .to_string()
                .contains("51")
        );
        // The internal tags are in the allowed set.
        let when = OffsetDateTime::UNIX_EPOCH + time::Duration::nanoseconds(1_234_567_891);
        let internal = SecretProps {
            disabled: true,
            content_type: Some("application/json".to_owned()),
            not_before: Some(when),
            expires_on: Some(when),
            updated_on: Some(when),
            tags: BTreeMap::new(),
        }
        .to_tags();
        for (key, value) in &internal {
            assert!(key.chars().all(allowed), "{key}");
            check_tag_value(value, key).unwrap();
        }
    }

    #[test]
    fn the_meet_is_the_stricter_policy_of_both() {
        let t = |s: i64| Some(OffsetDateTime::UNIX_EPOCH + time::Duration::days(s));
        let old = SecretProps {
            not_before: t(10),
            expires_on: t(30),
            ..SecretProps::default()
        };
        let new = SecretProps {
            disabled: true,
            not_before: t(5),
            expires_on: None,
            content_type: Some("text/plain".to_owned()),
            ..SecretProps::default()
        };
        let meet = old.meet(&new);
        assert!(meet.disabled);
        assert_eq!(meet.not_before, t(10));
        assert_eq!(meet.expires_on, t(30));
        assert!(meet.at_least_as_strict_as(&old) && meet.at_least_as_strict_as(&new));
        assert!(!old.at_least_as_strict_as(&new));
        assert!(!new.at_least_as_strict_as(&old));
        assert!(SecretProps::default().at_least_as_strict_as(&SecretProps::default()));
        assert_eq!(meet.policy_tags().len(), 3);
    }

    #[test]
    fn a_tag_plan_never_loosens_below_its_target_and_keeps_aws_tags() {
        let t = |s: i64| Some(OffsetDateTime::UNIX_EPOCH + time::Duration::days(s));
        let props = |disabled, nb, exp| SecretProps {
            disabled,
            not_before: nb,
            expires_on: exp,
            ..SecretProps::default()
        };
        // Every pair of these as old and new: no state the plan passes
        // through is looser than both its start and its target (the order
        // that removed stale tags first went from disabled to a future
        // `not_before` through enabled with no window).
        let policies = [
            props(false, None, None),
            props(true, None, None),
            props(false, t(5), None),
            props(false, t(9), t(20)),
            props(true, None, t(3)),
        ];
        for old in &policies {
            for new in &policies {
                let mut current = old.to_tags();
                current.insert("aws:cloudformation:stack-name".to_owned(), "s".to_owned());
                current.insert("team".to_owned(), "a".to_owned());
                let mut wanted = new.to_tags();
                wanted.insert("owner".to_owned(), "b".to_owned());
                let plan = TagPlan::to(&current, &wanted);
                assert!(
                    !plan
                        .untag_first
                        .iter()
                        .chain(&plan.untag_last)
                        .any(|k| is_aws_key(k))
                );
                for state in plan.states(&current) {
                    let seen = SecretProps::from_tags(&tags_of(&state)).unwrap();
                    assert!(
                        seen.at_least_as_strict_as(old) || seen.at_least_as_strict_as(new),
                        "{old:?} -> {new:?} passed through {seen:?}"
                    );
                }
                let end = plan.states(&current).pop().unwrap();
                let mut expected = wanted.clone();
                expected.insert("aws:cloudformation:stack-name".to_owned(), "s".to_owned());
                assert_eq!(end, expected);
            }
        }
        // The peak counts every tag present at once, AWS's own excepted.
        let current = tags(&[("aws:x", "1"), ("a", "1"), (TAG_DISABLED, "true")]);
        let wanted = tags(&[("b", "1"), ("c", "1")]);
        let plan = TagPlan::to(&current, &wanted);
        assert_eq!(plan.untag_first, vec!["a".to_owned()]);
        assert_eq!(plan.untag_last, vec![TAG_DISABLED.to_owned()]);
        assert_eq!(plan.peak(&current), 3, "b, c and the disabled tag");
        assert!(TagPlan::to(&wanted, &wanted).is_empty());
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

    /// Bounded fuzz (B31): whatever tags Secrets Manager returns (anyone
    /// with `TagResource` can write them) are read as properties or an
    /// error, never a panic, and a value marked as base64 decodes or fails.
    #[test]
    fn whatever_tags_come_back_are_properties_or_an_error_never_a_panic() {
        let seeds = [
            ("env", "prod"),
            (TAG_DISABLED, "true"),
            (TAG_NOT_BEFORE, "2026-01-01T00:00:00Z"),
            (TAG_EXPIRES_ON, "2027-06-30T00:00:00.123456789Z"),
            (TAG_CONTENT_TYPE, "text/plain"),
            ("aws:cloudformation:stack-name", "s"),
        ];
        let mut m = sourceorrery_conformance::fuzz::Mutator::new(0x5EED_0A35);
        for _ in 0..5000 {
            let tags: Vec<Tag> = seeds
                .iter()
                .map(|(key, value)| {
                    let key = if m.below(3) == 0 {
                        m.mutate(key)
                    } else {
                        (*key).to_owned()
                    };
                    Tag::builder().key(key).value(m.mutate(value)).build()
                })
                .collect();
            if let Ok(props) = SecretProps::from_tags(&tags) {
                let _ = props.to_tags();
            }
        }
    }
}
