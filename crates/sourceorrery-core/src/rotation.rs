//! Rotation as a recorded workflow over any [`SecretClient`]:
//! issue → validate → activate → retire.
//!
//! A rotation writes the new value as a **disabled** candidate version next
//! to the current one, has it validated, then enables the candidate and
//! disables the version it replaces, in that order, so there is always one
//! accessible version. Retirement, once a grace period has ended, is when
//! the issuer is told the previous credential is no longer needed; the
//! retired version stays in the vault, disabled, because versions are
//! immutable history and the contract has no per-version delete.
//!
//! The state lives in the versions' tags (`sourceorrery.rotation.*`), so a
//! rotation survives a crash, resumes from what was recorded, and is visible
//! in `secret versions`. Every step is an ordinary audited operation
//! (`secret_set`, `secret_update`). Nothing here runs a program or reads a
//! value: the issuer, the validator and the retire hook are the caller's
//! (the CLI runs them the way `sourceorrery run` runs a command), and the
//! candidate value only ever passes through as [`SecretBytes`].
//!
//! Because a disabled version cannot be read back through the contract, the
//! candidate must be validated by the process that issued it. A candidate
//! left in the `issued` state by a crash can therefore never be activated;
//! the next rotation marks it failed and moves on.
//!
//! The workflow needs [`Capability::PerVersionProperties`]: a backend whose
//! properties belong to the secret cannot hold a disabled candidate next to
//! an enabled current version, and [`issue`] refuses it with `unsupported`.

use std::collections::BTreeMap;

use time::{Duration, OffsetDateTime};

use crate::error::{Result, SecretError};
use crate::policy;
use crate::secret::{SecretBytes, SecretProperties, SetSecretOptions, UpdateSecretProperties};
use crate::timestamp;
use crate::traits::{Capability, SecretClient};

/// Every tag the workflow writes starts with this.
pub const TAG_PREFIX: &str = "sourceorrery.rotation.";
/// The version's place in a rotation ([`State`]).
pub const STATE_TAG: &str = "sourceorrery.rotation.state";
/// On a candidate or the version it became: the version it replaces.
pub const PREVIOUS_TAG: &str = "sourceorrery.rotation.previous";
/// On a superseded version: the version that replaced it.
pub const SUPERSEDED_BY_TAG: &str = "sourceorrery.rotation.superseded-by";
/// On an activated version: when it was enabled (RFC 3339).
pub const ACTIVATED_ON_TAG: &str = "sourceorrery.rotation.activated-on";
/// On an activated version whose predecessor awaits retirement: when the
/// grace period ends (RFC 3339).
pub const RETIRE_ON_TAG: &str = "sourceorrery.rotation.retire-on";
/// On a retired version: when it was retired (RFC 3339).
pub const RETIRED_ON_TAG: &str = "sourceorrery.rotation.retired-on";

/// A version's place in a rotation, as recorded in [`STATE_TAG`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum State {
    /// Written disabled by [`issue`]; not yet validated. Never activated:
    /// only the issuing process holds the value to validate.
    Issued,
    /// Validated by the caller ([`validated`]); waiting for [`activate`].
    Validated,
    /// Validation failed, or the candidate was abandoned. Stays disabled.
    Failed,
    /// Enabled by [`activate`]; its predecessor awaits retirement.
    Active,
    /// Enabled, with no predecessor left to retire.
    Complete,
    /// Disabled by [`activate`] in favour of [`SUPERSEDED_BY_TAG`].
    Superseded,
    /// Retired: the issuer was told the credential is no longer needed.
    Retired,
}

impl State {
    /// The tag value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Validated => "validated",
            Self::Failed => "failed",
            Self::Active => "active",
            Self::Complete => "complete",
            Self::Superseded => "superseded",
            Self::Retired => "retired",
        }
    }

    /// The state a tag value names.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "issued" => Some(Self::Issued),
            "validated" => Some(Self::Validated),
            "failed" => Some(Self::Failed),
            "active" => Some(Self::Active),
            "complete" => Some(Self::Complete),
            "superseded" => Some(Self::Superseded),
            "retired" => Some(Self::Retired),
            _ => None,
        }
    }

    /// The state recorded on a version, if any.
    pub fn of(props: &SecretProperties) -> Option<Self> {
        props.tags.get(STATE_TAG).and_then(|v| Self::parse(v))
    }
}

/// Parse a grace period: a positive whole number of days, hours or minutes
/// (`7d`, `12h`, `30m`).
pub fn parse_grace(text: &str) -> Result<Duration> {
    let invalid = || {
        SecretError::InvalidArgument(format!(
            "'{text}' is not a grace period; use a whole number of days, hours or minutes, such \
             as 7d, 12h or 30m"
        ))
    };
    // The unit is the last character, which need not be one byte: the text
    // comes from a manifest anyone with the repository can write.
    let unit = text.chars().next_back().ok_or_else(invalid)?;
    let digits = &text[..text.len() - unit.len_utf8()];
    let amount: i64 = digits.parse().map_err(|_| invalid())?;
    if amount <= 0 {
        return Err(SecretError::InvalidArgument(format!(
            "'{text}' is not a grace period; it must be positive (omit it to retire at once)"
        )));
    }
    match unit {
        'd' => Ok(Duration::days(amount)),
        'h' => Ok(Duration::hours(amount)),
        'm' => Ok(Duration::minutes(amount)),
        _ => Err(invalid()),
    }
}

/// The shortest of the forms [`parse_grace`] accepts for `grace`.
pub fn format_grace(grace: Duration) -> String {
    let minutes = grace.whole_minutes();
    if minutes % (24 * 60) == 0 {
        format!("{}d", minutes / (24 * 60))
    } else if minutes % 60 == 0 {
        format!("{}h", minutes / 60)
    } else {
        format!("{minutes}m")
    }
}

/// The outcome of [`issue`].
#[derive(Clone, Debug)]
pub struct Issued {
    /// The new version: disabled, in state [`State::Issued`].
    pub candidate: SecretProperties,
    /// The version it will replace: the one accessible when it was issued,
    /// if any.
    pub previous: Option<SecretProperties>,
}

/// The outcome of [`activate`].
#[derive(Clone, Debug)]
pub struct Activated {
    /// The candidate, now enabled.
    pub current: SecretProperties,
    /// The version it replaced, now disabled and [`State::Superseded`].
    pub previous: Option<SecretProperties>,
    /// When the previous version may be retired, when there is one and a
    /// grace period was given.
    pub retire_on: Option<OffsetDateTime>,
}

/// A retirement that is due ([`retirement`]) or done ([`retire`]).
#[derive(Clone, Debug)]
pub struct Retirement {
    /// The active version.
    pub current: SecretProperties,
    /// The version to retire: the one `current` replaced.
    pub previous: SecretProperties,
    /// The end of the grace period, when one was recorded.
    pub retire_on: Option<OffsetDateTime>,
}

/// Where a secret's rotation stands ([`status`]).
#[derive(Clone, Debug, Default)]
pub struct Status {
    /// A candidate that was issued or validated and not yet activated.
    pub candidate: Option<SecretProperties>,
    /// The version an earlier rotation activated, if the newest rotation
    /// record is one.
    pub current: Option<SecretProperties>,
    /// The version awaiting retirement, with the end of its grace period.
    pub awaiting_retirement: Option<(SecretProperties, Option<OffsetDateTime>)>,
}

fn rotation_error(name: &str, reason: String) -> SecretError {
    SecretError::Rotation {
        name: name.to_owned(),
        reason,
    }
}

/// The tags a user set, without the workflow's own.
fn user_tags(tags: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    tags.iter()
        .filter(|(k, _)| !k.starts_with(TAG_PREFIX))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// `tags` with `set` applied and `remove` taken out.
fn with_tags(
    tags: &BTreeMap<String, String>,
    set: &[(&str, String)],
    remove: &[&str],
) -> BTreeMap<String, String> {
    let mut next = tags.clone();
    for key in remove {
        next.remove(*key);
    }
    for (key, value) in set {
        next.insert((*key).to_owned(), value.clone());
    }
    next
}

fn versions_or_empty(client: &dyn SecretClient, name: &str) -> Result<Vec<SecretProperties>> {
    match client.list_properties_of_secret_versions(name) {
        Ok(versions) => Ok(versions),
        Err(SecretError::NotFound { .. }) => Ok(Vec::new()),
        Err(err) => Err(err),
    }
}

fn find<'a>(versions: &'a [SecretProperties], version: &str) -> Option<&'a SecretProperties> {
    versions.iter().find(|v| v.version == version)
}

fn mark(
    client: &dyn SecretClient,
    name: &str,
    props: &SecretProperties,
    enabled: Option<bool>,
    set: &[(&str, String)],
    remove: &[&str],
) -> Result<SecretProperties> {
    client.update_secret_properties(
        name,
        Some(&props.version),
        UpdateSecretProperties {
            enabled,
            tags: Some(with_tags(&props.tags, set, remove)),
            ..UpdateSecretProperties::default()
        },
    )
}

/// Write `value` as a disabled candidate version of `name`.
///
/// The candidate takes the content type and the user's tags of the version
/// it will replace (the one accessible now), and records that version in
/// [`PREVIOUS_TAG`]. A candidate left in [`State::Issued`] by an earlier
/// run is marked failed first; one in [`State::Validated`] is refused,
/// because it is waiting for [`activate`]. A backend without
/// [`Capability::PerVersionProperties`] is refused with `unsupported`.
pub fn issue(
    client: &dyn SecretClient,
    name: &str,
    value: SecretBytes,
    now: OffsetDateTime,
) -> Result<Issued> {
    if !client
        .capabilities_of(name)?
        .contains(&Capability::PerVersionProperties)
    {
        return Err(SecretError::Unsupported(format!(
            "vault '{}' keeps properties per secret, not per version, so a disabled candidate \
             cannot be written next to the current version; rotate '{name}' with the provider's \
             own mechanism",
            client.vault_name()
        )));
    }
    let versions = versions_or_empty(client, name)?;
    for version in &versions {
        match State::of(version) {
            Some(State::Validated) => {
                return Err(rotation_error(
                    name,
                    format!(
                        "version {} is a validated candidate waiting for activation; activate it \
                         first",
                        version.version
                    ),
                ));
            }
            Some(State::Issued) => {
                // Issued by a run that did not get to validate it: nobody
                // holds its value any more, so it can never be activated.
                mark(
                    client,
                    name,
                    version,
                    Some(false),
                    &[(STATE_TAG, State::Failed.as_str().to_owned())],
                    &[],
                )?;
            }
            _ => {}
        }
    }
    let previous = policy::select_latest_accessible(name, &versions, now)
        .ok()
        .cloned();
    let mut tags = previous
        .as_ref()
        .map(|p| user_tags(&p.tags))
        .unwrap_or_default();
    tags.insert(STATE_TAG.to_owned(), State::Issued.as_str().to_owned());
    if let Some(previous) = &previous {
        tags.insert(PREVIOUS_TAG.to_owned(), previous.version.clone());
    }
    let options = SetSecretOptions {
        content_type: previous.as_ref().and_then(|p| p.content_type.clone()),
        tags,
        enabled: false,
        not_before: None,
        expires_on: None,
    };
    let candidate = client.set_secret(name, value, options)?;
    Ok(Issued {
        candidate,
        previous,
    })
}

/// Record that the caller validated the candidate `version`.
pub fn validated(client: &dyn SecretClient, name: &str, version: &str) -> Result<SecretProperties> {
    let props = expect_state(client, name, version, State::Issued, "an issued candidate")?;
    mark(
        client,
        name,
        &props,
        Some(false),
        &[(STATE_TAG, State::Validated.as_str().to_owned())],
        &[],
    )
}

/// Record that the candidate `version` failed validation or was abandoned.
/// It stays disabled; the current version is untouched.
pub fn fail(client: &dyn SecretClient, name: &str, version: &str) -> Result<SecretProperties> {
    let versions = client.list_properties_of_secret_versions(name)?;
    let props = find(&versions, version).ok_or_else(|| SecretError::VersionNotFound {
        name: name.to_owned(),
        version: version.to_owned(),
    })?;
    match State::of(props) {
        Some(State::Issued | State::Validated) => mark(
            client,
            name,
            props,
            Some(false),
            &[(STATE_TAG, State::Failed.as_str().to_owned())],
            &[],
        ),
        other => Err(rotation_error(
            name,
            format!(
                "version {version} is not a candidate (state: {})",
                other.map_or("none", State::as_str)
            ),
        )),
    }
}

fn expect_state(
    client: &dyn SecretClient,
    name: &str,
    version: &str,
    state: State,
    what: &str,
) -> Result<SecretProperties> {
    let versions = client.list_properties_of_secret_versions(name)?;
    let props = find(&versions, version).ok_or_else(|| SecretError::VersionNotFound {
        name: name.to_owned(),
        version: version.to_owned(),
    })?;
    if State::of(props) == Some(state) {
        Ok(props.clone())
    } else {
        Err(rotation_error(
            name,
            format!(
                "version {version} is not {what} (state: {})",
                State::of(props).map_or("none", State::as_str)
            ),
        ))
    }
}

/// Enable the validated candidate `version`, then disable the version it
/// replaces, in that order. With `grace`, the previous version's retirement
/// is due `grace` from `now` and recorded in [`RETIRE_ON_TAG`]; without it,
/// the caller retires at once ([`retirement`] with `force`).
pub fn activate(
    client: &dyn SecretClient,
    name: &str,
    version: &str,
    grace: Option<Duration>,
    now: OffsetDateTime,
) -> Result<Activated> {
    let candidate = expect_state(
        client,
        name,
        version,
        State::Validated,
        "a validated candidate",
    )?;
    let versions = client.list_properties_of_secret_versions(name)?;
    let previous = candidate
        .tags
        .get(PREVIOUS_TAG)
        .and_then(|id| find(&versions, id))
        .cloned();
    let retire_on = match (&previous, grace) {
        (Some(_), Some(grace)) => Some(now + grace),
        _ => None,
    };
    let state = if previous.is_some() {
        State::Active
    } else {
        State::Complete
    };
    let mut set = vec![
        (STATE_TAG, state.as_str().to_owned()),
        (ACTIVATED_ON_TAG, timestamp::format(now)),
    ];
    if let Some(retire_on) = retire_on {
        set.push((RETIRE_ON_TAG, timestamp::format(retire_on)));
    }
    let current = mark(client, name, &candidate, Some(true), &set, &[RETIRE_ON_TAG])?;
    let previous = previous
        .map(|previous| {
            mark(
                client,
                name,
                &previous,
                Some(false),
                &[
                    (STATE_TAG, State::Superseded.as_str().to_owned()),
                    (SUPERSEDED_BY_TAG, version.to_owned()),
                ],
                &[],
            )
        })
        .transpose()?;
    Ok(Activated {
        current,
        previous,
        retire_on,
    })
}

/// The retirement that is due for `name`: the active version and the one it
/// replaced. Refused while the grace period runs, unless `force`.
pub fn retirement(
    client: &dyn SecretClient,
    name: &str,
    now: OffsetDateTime,
    force: bool,
) -> Result<Retirement> {
    let versions = client.list_properties_of_secret_versions(name)?;
    let current = versions
        .iter()
        .find(|v| State::of(v) == Some(State::Active))
        .ok_or_else(|| rotation_error(name, "no rotation is awaiting retirement".to_owned()))?;
    let previous = current
        .tags
        .get(PREVIOUS_TAG)
        .and_then(|id| find(&versions, id))
        .ok_or_else(|| {
            rotation_error(
                name,
                format!(
                    "version {} records no previous version to retire",
                    current.version
                ),
            )
        })?;
    let retire_on = current
        .tags
        .get(RETIRE_ON_TAG)
        .map(|t| timestamp::parse(t))
        .transpose()?;
    if let Some(retire_on) = retire_on
        && now < retire_on
        && !force
    {
        return Err(rotation_error(
            name,
            format!(
                "the grace period runs until {}; retire then, or now with --now",
                timestamp::format(retire_on)
            ),
        ));
    }
    Ok(Retirement {
        current: current.clone(),
        previous: previous.clone(),
        retire_on,
    })
}

/// Record a retirement the caller carried out: the previous version becomes
/// [`State::Retired`] (and stays disabled), the current one
/// [`State::Complete`].
pub fn retire(
    client: &dyn SecretClient,
    name: &str,
    pending: &Retirement,
    now: OffsetDateTime,
) -> Result<Retirement> {
    let previous = mark(
        client,
        name,
        &pending.previous,
        Some(false),
        &[
            (STATE_TAG, State::Retired.as_str().to_owned()),
            (RETIRED_ON_TAG, timestamp::format(now)),
        ],
        &[],
    )?;
    let current = mark(
        client,
        name,
        &pending.current,
        None,
        &[(STATE_TAG, State::Complete.as_str().to_owned())],
        &[RETIRE_ON_TAG],
    )?;
    Ok(Retirement {
        current,
        previous,
        retire_on: pending.retire_on,
    })
}

/// Where the rotation of `name` stands, from the versions' tags.
pub fn status(client: &dyn SecretClient, name: &str) -> Result<Status> {
    let versions = versions_or_empty(client, name)?;
    let mut status = Status::default();
    for version in &versions {
        match State::of(version) {
            Some(State::Issued | State::Validated) if status.candidate.is_none() => {
                status.candidate = Some(version.clone());
            }
            Some(State::Active | State::Complete) if status.current.is_none() => {
                status.current = Some(version.clone());
                if State::of(version) == Some(State::Active) {
                    let previous = version
                        .tags
                        .get(PREVIOUS_TAG)
                        .and_then(|id| find(&versions, id))
                        .cloned();
                    let retire_on = version
                        .tags
                        .get(RETIRE_ON_TAG)
                        .map(|t| timestamp::parse(t))
                        .transpose()?;
                    status.awaiting_retirement = previous.map(|p| (p, retire_on));
                }
            }
            _ => {}
        }
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grace_periods_parse_and_print() {
        assert_eq!(parse_grace("7d").unwrap(), Duration::days(7));
        assert_eq!(parse_grace("12h").unwrap(), Duration::hours(12));
        assert_eq!(parse_grace("30m").unwrap(), Duration::minutes(30));
        // A unit that is not one byte is refused, not split inside (found
        // by the bounded fuzz test, B31: it panicked).
        for bad in [
            "",
            "d",
            "7",
            "7w",
            "-1d",
            "0h",
            "1.5d",
            "7 d",
            "7é",
            "é",
            "7\u{FFFD}",
        ] {
            let err = parse_grace(bad).unwrap_err();
            assert_eq!(err.code(), "invalid_argument", "{bad}");
        }
        assert_eq!(format_grace(Duration::days(7)), "7d");
        assert_eq!(format_grace(Duration::hours(36)), "36h");
        assert_eq!(format_grace(Duration::minutes(90)), "90m");
    }

    #[test]
    fn states_round_trip_through_their_tag_value() {
        for state in [
            State::Issued,
            State::Validated,
            State::Failed,
            State::Active,
            State::Complete,
            State::Superseded,
            State::Retired,
        ] {
            assert_eq!(State::parse(state.as_str()), Some(state));
        }
        assert_eq!(State::parse("rotating"), None);
    }

    #[test]
    fn user_tags_survive_and_workflow_tags_are_replaced() {
        let mut tags = BTreeMap::new();
        tags.insert("team".to_owned(), "payments".to_owned());
        tags.insert(STATE_TAG.to_owned(), "active".to_owned());
        tags.insert(RETIRE_ON_TAG.to_owned(), "t".to_owned());
        let kept = user_tags(&tags);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept["team"], "payments");
        let next = with_tags(
            &tags,
            &[(STATE_TAG, "complete".to_owned())],
            &[RETIRE_ON_TAG],
        );
        assert_eq!(next[STATE_TAG], "complete");
        assert!(!next.contains_key(RETIRE_ON_TAG));
        assert_eq!(next["team"], "payments");
    }
}
