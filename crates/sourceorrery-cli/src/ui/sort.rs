//! Typed ordering of cached rows; source records remain in their original order.
use sourceorrery_core::{AuditEvent, SecretProperties};
use std::cmp::Ordering;
use time::OffsetDateTime;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Sort {
    #[default]
    Default,
    NameAsc,
    NameDesc,
    UpdatedAsc,
    UpdatedDesc,
    ExpiryAsc,
    ExpiryDesc,
    TimeAsc,
    TimeDesc,
}
impl Sort {
    pub fn title(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::NameAsc => "name ↑",
            Self::NameDesc => "name ↓",
            Self::UpdatedAsc => "updated ↑",
            Self::UpdatedDesc => "updated ↓",
            Self::ExpiryAsc => "expiry ↑",
            Self::ExpiryDesc => "expiry ↓",
            Self::TimeAsc => "time ↑",
            Self::TimeDesc => "time ↓",
        }
    }
    pub fn secret(self, a: &SecretProperties, b: &SecretProperties) -> Ordering {
        let primary = match self {
            Self::NameAsc => a.name.cmp(&b.name),
            Self::NameDesc => b.name.cmp(&a.name),
            Self::UpdatedAsc => a.updated_on.cmp(&b.updated_on),
            Self::UpdatedDesc => b.updated_on.cmp(&a.updated_on),
            Self::ExpiryAsc => dates(a.expires_on, b.expires_on, false),
            Self::ExpiryDesc => dates(a.expires_on, b.expires_on, true),
            _ => return Ordering::Equal,
        };
        primary
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.version.cmp(&b.version))
    }
    pub fn event(self, a: &AuditEvent, b: &AuditEvent) -> Ordering {
        match self {
            Self::TimeAsc => a
                .occurred_on
                .cmp(&b.occurred_on)
                .then_with(|| a.id.cmp(&b.id)),
            Self::TimeDesc => b
                .occurred_on
                .cmp(&a.occurred_on)
                .then_with(|| a.id.cmp(&b.id)),
            _ => Ordering::Equal,
        }
    }
}
fn dates(a: Option<OffsetDateTime>, b: Option<OffsetDateTime>, descending: bool) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) => {
            if descending {
                b.cmp(&a)
            } else {
                a.cmp(&b)
            }
        }
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_dates_are_last_in_both_directions_and_dates_are_instants() {
        let a = OffsetDateTime::from_unix_timestamp(2).unwrap();
        let b = OffsetDateTime::from_unix_timestamp(10).unwrap();
        assert_eq!(dates(Some(a), Some(b), false), Ordering::Less);
        assert_eq!(dates(Some(a), Some(b), true), Ordering::Greater);
        for desc in [false, true] {
            assert_eq!(dates(None, Some(a), desc), Ordering::Greater);
            assert_eq!(dates(None, None, desc), Ordering::Equal);
        }
    }
}
