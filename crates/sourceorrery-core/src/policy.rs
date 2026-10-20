//! Access and lifecycle policy, evaluated identically by every backend.

use time::{Duration, OffsetDateTime};

use crate::audit::AuditOperation;
use crate::error::{Result, SecretError};
use crate::identity::Principal;
use crate::secret::SecretProperties;
use crate::timestamp;

/// Check whether a version may be retrieved at `now`.
///
/// Unlike Azure Key Vault, where `not_before` and `expires` are advisory in
/// some paths, SourceOrrery always enforces them.
pub fn evaluate_access(props: &SecretProperties, now: OffsetDateTime) -> Result<()> {
    if !props.enabled {
        return Err(SecretError::Disabled {
            name: props.name.clone(),
            version: props.version.clone(),
        });
    }
    if let Some(not_before) = props.not_before
        && now < not_before
    {
        return Err(SecretError::NotYetValid {
            name: props.name.clone(),
            version: props.version.clone(),
            not_before: timestamp::format(not_before),
        });
    }
    if let Some(expires_on) = props.expires_on
        && now >= expires_on
    {
        return Err(SecretError::Expired {
            name: props.name.clone(),
            version: props.version.clone(),
            expires_on: timestamp::format(expires_on),
        });
    }
    Ok(())
}

/// Convenience predicate over [`evaluate_access`].
pub fn is_accessible(props: &SecretProperties, now: OffsetDateTime) -> bool {
    evaluate_access(props, now).is_ok()
}

/// Choose the version a caller gets when they ask for a secret without a
/// version: the newest version that passes [`evaluate_access`].
///
/// `versions` must be ordered newest first. If no version is accessible the
/// error explains why the *newest* one was rejected, which is what a human
/// debugging a rotation most wants to know. An empty slice yields `NotFound`.
pub fn select_latest_accessible<'a>(
    name: &str,
    versions: &'a [SecretProperties],
    now: OffsetDateTime,
) -> Result<&'a SecretProperties> {
    let Some(newest) = versions.first() else {
        return Err(SecretError::NotFound {
            name: name.to_owned(),
        });
    };
    match versions.iter().find(|v| is_accessible(v, now)) {
        Some(found) => Ok(found),
        None => Err(evaluate_access(newest, now)
            .err()
            .unwrap_or_else(|| SecretError::NotFound {
                name: name.to_owned(),
            })),
    }
}

/// Soft-delete retention for a vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SoftDeletePolicy {
    /// How long a deleted secret stays recoverable.
    pub retention_days: u32,
}

impl SoftDeletePolicy {
    /// Shortest retention accepted (matches Azure Key Vault).
    pub const MIN_RETENTION_DAYS: u32 = 7;
    /// Longest retention accepted (matches Azure Key Vault).
    pub const MAX_RETENTION_DAYS: u32 = 90;

    /// Build a policy, rejecting out-of-range retention.
    pub fn new(retention_days: u32) -> Result<Self> {
        if !(Self::MIN_RETENTION_DAYS..=Self::MAX_RETENTION_DAYS).contains(&retention_days) {
            return Err(SecretError::InvalidArgument(format!(
                "retention must be between {} and {} days",
                Self::MIN_RETENTION_DAYS,
                Self::MAX_RETENTION_DAYS
            )));
        }
        Ok(Self { retention_days })
    }

    /// When a secret deleted at `deleted_on` becomes eligible for purge.
    pub fn scheduled_purge_on(self, deleted_on: OffsetDateTime) -> OffsetDateTime {
        deleted_on + Duration::days(i64::from(self.retention_days))
    }
}

impl Default for SoftDeletePolicy {
    fn default() -> Self {
        Self { retention_days: 90 }
    }
}

/// Outcome of an authorisation check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// The operation may proceed.
    Allow,
    /// The operation is refused; the string is a human-readable reason that
    /// is safe to show the caller and to record in the audit log.
    Deny(String),
}

impl Decision {
    /// Convert a denial into an error.
    pub fn into_result(self) -> Result<()> {
        match self {
            Self::Allow => Ok(()),
            Self::Deny(reason) => Err(SecretError::PermissionDenied(reason)),
        }
    }
}

/// Who may do what.
///
/// Backends consult an `AccessPolicy` before every operation. The local
/// encrypted vault uses [`AllowAll`]: whoever can unlock the vault is its
/// administrator. The broker and remote backends will supply real policies
/// evaluated against verified identities.
pub trait AccessPolicy: Send + Sync {
    /// Decide whether `principal` may perform `operation` on `secret_name`.
    fn authorize(
        &self,
        principal: &Principal,
        operation: AuditOperation,
        secret_name: Option<&str>,
    ) -> Decision;
}

/// Policy for a single-user local vault: unlocking the vault is the boundary.
#[derive(Clone, Copy, Debug, Default)]
pub struct AllowAll;

impl AccessPolicy for AllowAll {
    fn authorize(
        &self,
        _principal: &Principal,
        _operation: AuditOperation,
        _secret_name: Option<&str>,
    ) -> Decision {
        Decision::Allow
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use time::macros::datetime;

    use super::*;
    use crate::secret::RecoveryLevel;

    fn version(id: &str, enabled: bool) -> SecretProperties {
        SecretProperties {
            vault: "v".into(),
            name: "s".into(),
            version: id.into(),
            enabled,
            content_type: None,
            tags: BTreeMap::new(),
            not_before: None,
            expires_on: None,
            created_on: datetime!(2026-01-01 00:00 UTC),
            updated_on: datetime!(2026-01-01 00:00 UTC),
            recovery_level: RecoveryLevel::Recoverable,
        }
    }

    const NOW: OffsetDateTime = datetime!(2026-06-01 00:00 UTC);

    #[test]
    fn disabled_is_rejected() {
        let err = evaluate_access(&version("a", false), NOW).unwrap_err();
        assert_eq!(err.code(), "disabled");
    }

    #[test]
    fn time_window_is_enforced() {
        let mut v = version("a", true);
        v.not_before = Some(datetime!(2026-07-01 00:00 UTC));
        assert_eq!(
            evaluate_access(&v, NOW).unwrap_err().code(),
            "not_yet_valid"
        );

        let mut v = version("a", true);
        v.expires_on = Some(datetime!(2026-05-01 00:00 UTC));
        assert_eq!(evaluate_access(&v, NOW).unwrap_err().code(), "expired");

        let mut v = version("a", true);
        v.expires_on = Some(NOW);
        assert_eq!(evaluate_access(&v, NOW).unwrap_err().code(), "expired");

        let mut v = version("a", true);
        v.not_before = Some(datetime!(2026-05-01 00:00 UTC));
        v.expires_on = Some(datetime!(2026-07-01 00:00 UTC));
        assert!(evaluate_access(&v, NOW).is_ok());
    }

    #[test]
    fn latest_accessible_skips_disabled_newest() {
        let versions = [version("new", false), version("old", true)];
        let chosen = select_latest_accessible("s", &versions, NOW).unwrap();
        assert_eq!(chosen.version, "old");
    }

    #[test]
    fn latest_accessible_reports_newest_failure() {
        let versions = [version("new", false), version("old", false)];
        let err = select_latest_accessible("s", &versions, NOW).unwrap_err();
        assert!(matches!(err, SecretError::Disabled { ref version, .. } if version == "new"));
        assert_eq!(
            select_latest_accessible("s", &[], NOW).unwrap_err().code(),
            "not_found"
        );
    }

    #[test]
    fn retention_bounds() {
        assert!(SoftDeletePolicy::new(6).is_err());
        assert!(SoftDeletePolicy::new(91).is_err());
        let p = SoftDeletePolicy::new(7).unwrap();
        assert_eq!(
            p.scheduled_purge_on(datetime!(2026-01-01 00:00 UTC)),
            datetime!(2026-01-08 00:00 UTC)
        );
    }

    #[test]
    fn allow_all_allows() {
        let decision =
            AllowAll.authorize(&Principal::system(), AuditOperation::SecretGet, Some("s"));
        assert_eq!(decision, Decision::Allow);
        assert!(Decision::Deny("no".into()).into_result().is_err());
    }
}
