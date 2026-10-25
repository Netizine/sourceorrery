//! The overview's numbers: plain functions of what the browser already
//! holds, so the dashboard reads nothing of its own.

use sourceorrery_core::{AuditEvent, AuditOperation, AuditOutcome, SecretProperties};
use time::{Date, Duration, OffsetDateTime, UtcOffset};

use crate::output;

/// Live secrets by status, as the list shows it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatusCounts {
    pub enabled: usize,
    pub disabled: usize,
    pub pending: usize,
    pub expired: usize,
}

pub fn status_counts(secrets: &[SecretProperties], now: OffsetDateTime) -> StatusCounts {
    let mut counts = StatusCounts::default();
    for p in secrets {
        match output::status(p, now) {
            "enabled" => counts.enabled += 1,
            "disabled" => counts.disabled += 1,
            "pending" => counts.pending += 1,
            _ => counts.expired += 1,
        }
    }
    counts
}

/// Live secrets by when they expire.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExpiryBuckets {
    pub expired: usize,
    pub week: usize,
    pub month: usize,
    pub quarter: usize,
    pub later: usize,
    pub never: usize,
}

pub fn expiry_buckets(secrets: &[SecretProperties], now: OffsetDateTime) -> ExpiryBuckets {
    let mut buckets = ExpiryBuckets::default();
    for p in secrets {
        match p.expires_on {
            None => buckets.never += 1,
            Some(at) if at <= now => buckets.expired += 1,
            Some(at) if at <= now + Duration::days(7) => buckets.week += 1,
            Some(at) if at <= now + Duration::days(30) => buckets.month += 1,
            Some(at) if at <= now + Duration::days(90) => buckets.quarter += 1,
            Some(_) => buckets.later += 1,
        }
    }
    buckets
}

/// Something that will happen to a secret by itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// Its newest version expires.
    Expires,
    /// Its newest version becomes valid (`not_before`).
    Activates,
}

/// What happens next, soonest first: expiries and activations still ahead.
pub fn upcoming(
    secrets: &[SecretProperties],
    now: OffsetDateTime,
) -> Vec<(&SecretProperties, Change, OffsetDateTime)> {
    let mut out: Vec<_> = secrets
        .iter()
        .flat_map(|p| {
            [
                p.expires_on.map(|at| (p, Change::Expires, at)),
                p.not_before.map(|at| (p, Change::Activates, at)),
            ]
        })
        .flatten()
        .filter(|(_, _, at)| *at > now)
        .collect();
    out.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.0.name.cmp(&b.0.name)));
    out
}

/// Audit events on one UTC day.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Day {
    pub date: Date,
    pub events: u64,
    pub denied: u64,
    pub failures: u64,
}

/// The audit log over the last few days.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Activity<'a> {
    /// Oldest first, today last.
    pub days: Vec<Day>,
    pub events: u64,
    pub denied: u64,
    pub failures: u64,
    /// The newest successful `secret_get`: a value disclosed.
    pub last_value_read: Option<&'a AuditEvent>,
    /// The newest failed or denied `vault_open`.
    pub last_failed_unlock: Option<&'a AuditEvent>,
}

/// `events` (newest first) over the `days` UTC days up to and including
/// today.
pub fn activity(events: &[AuditEvent], now: OffsetDateTime, days: u16) -> Activity<'_> {
    let today = now.to_offset(UtcOffset::UTC).date();
    let first = today - Duration::days(i64::from(days.saturating_sub(1)));
    let mut out = Activity {
        days: (0..i64::from(days))
            .map(|i| Day {
                date: first + Duration::days(i),
                events: 0,
                denied: 0,
                failures: 0,
            })
            .collect(),
        events: 0,
        denied: 0,
        failures: 0,
        last_value_read: None,
        last_failed_unlock: None,
    };
    for e in events {
        let date = e.occurred_on.to_offset(UtcOffset::UTC).date();
        if let Some(day) = out.days.iter_mut().find(|d| d.date == date) {
            day.events += 1;
            out.events += 1;
            match e.outcome {
                // An attempt is completed by the event that follows it.
                AuditOutcome::Success | AuditOutcome::Pending => {}
                AuditOutcome::Denied => {
                    day.denied += 1;
                    out.denied += 1;
                }
                AuditOutcome::Failure | AuditOutcome::Unknown => {
                    day.failures += 1;
                    out.failures += 1;
                }
            }
        }
        if out.last_value_read.is_none()
            && e.operation == AuditOperation::SecretGet
            && e.outcome == AuditOutcome::Success
        {
            out.last_value_read = Some(e);
        }
        if out.last_failed_unlock.is_none()
            && e.operation == AuditOperation::VaultOpen
            && e.outcome != AuditOutcome::Success
        {
            out.last_failed_unlock = Some(e);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use sourceorrery_core::{Principal, RecoveryLevel, timestamp};

    use super::*;

    fn secret(
        name: &str,
        enabled: bool,
        not_before: Option<i64>,
        expires: Option<i64>,
    ) -> SecretProperties {
        let now = timestamp::now();
        SecretProperties {
            vault: "dev".into(),
            name: name.into(),
            version: "0".repeat(32),
            enabled,
            content_type: None,
            tags: BTreeMap::new(),
            not_before: not_before.map(|d| now + Duration::days(d)),
            expires_on: expires.map(|d| now + Duration::days(d)),
            created_on: now,
            updated_on: now,
            recovery_level: RecoveryLevel::Recoverable,
        }
    }

    fn event(days_ago: i64, op: AuditOperation, outcome: AuditOutcome) -> AuditEvent {
        AuditEvent {
            id: 1,
            occurred_on: timestamp::now() - Duration::days(days_ago),
            actor: Principal::local_user(),
            operation: op,
            secret_name: None,
            version: None,
            outcome,
            detail: None,
        }
    }

    #[test]
    fn statuses_are_counted_as_the_list_shows_them() {
        let secrets = [
            secret("a", true, None, None),
            secret("b", true, None, Some(5)),
            secret("c", false, None, None),
            secret("d", true, Some(3), None),
            secret("e", true, None, Some(-1)),
        ];
        let counts = status_counts(&secrets, timestamp::now());
        assert_eq!(
            counts,
            StatusCounts {
                enabled: 2,
                disabled: 1,
                pending: 1,
                expired: 1
            }
        );
    }

    #[test]
    fn expiry_falls_into_one_bucket() {
        let secrets = [
            secret("a", true, None, Some(-1)),
            secret("b", true, None, Some(3)),
            secret("c", true, None, Some(20)),
            secret("d", true, None, Some(60)),
            secret("e", true, None, Some(400)),
            secret("f", true, None, None),
            secret("g", false, None, Some(2)),
        ];
        let buckets = expiry_buckets(&secrets, timestamp::now());
        assert_eq!(
            buckets,
            ExpiryBuckets {
                expired: 1,
                week: 2,
                month: 1,
                quarter: 1,
                later: 1,
                never: 1
            }
        );
    }

    #[test]
    fn upcoming_lists_what_is_still_ahead_soonest_first() {
        let secrets = [
            secret("cert", true, None, Some(30)),
            secret("old", true, None, Some(-3)),
            secret("key", true, Some(10), Some(400)),
        ];
        let next = upcoming(&secrets, timestamp::now());
        let order: Vec<_> = next.iter().map(|(p, c, _)| (p.name.as_str(), *c)).collect();
        assert_eq!(
            order,
            [
                ("key", Change::Activates),
                ("cert", Change::Expires),
                ("key", Change::Expires)
            ]
        );
    }

    #[test]
    fn activity_counts_days_outcomes_and_the_last_value_read() {
        let events = [
            event(0, AuditOperation::SecretGet, AuditOutcome::Denied),
            event(0, AuditOperation::SecretGet, AuditOutcome::Success),
            event(1, AuditOperation::VaultOpen, AuditOutcome::Failure),
            event(3, AuditOperation::SecretList, AuditOutcome::Success),
            event(40, AuditOperation::SecretGet, AuditOutcome::Success),
        ];
        let now = timestamp::now();
        let a = activity(&events, now, 14);
        assert_eq!(a.days.len(), 14);
        assert_eq!(a.days.last().map(|d| d.date), Some(now.date()));
        assert_eq!(
            (a.events, a.denied, a.failures),
            (4, 1, 1),
            "the 40-day-old event is outside"
        );
        assert_eq!(a.days[13].events, 2);
        assert_eq!(a.days[12].failures, 1);
        assert_eq!(a.days[10].events, 1);
        assert_eq!(a.last_value_read, Some(&events[1]), "the newest success");
        assert_eq!(a.last_failed_unlock, Some(&events[2]));
    }

    #[test]
    fn no_events_no_activity() {
        let a = activity(&[], timestamp::now(), 7);
        assert_eq!(a.days.len(), 7);
        assert_eq!(a.events, 0);
        assert!(a.last_value_read.is_none() && a.last_failed_unlock.is_none());
    }
}
