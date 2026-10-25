//! The search box (`/`). Matching runs over what the browser already holds,
//! so searching never reads the vault.
//!
//! Words match anywhere in a row (every word must, in any order, case
//! ignored). Qualifiers narrow by one field; several of one kind mean any
//! of them, different kinds must all hold:
//!
//! * secrets: `tag:KEY` or `tag:KEY=VALUE`, `status:STATUS` (enabled,
//!   disabled, pending, expired), `type:TEXT` (content type),
//!   `expires:<30d` (expires within that many days, or has expired);
//! * the audit log: `op:TEXT`, `outcome:success|denied|failure`,
//!   `secret:TEXT`, `actor:TEXT`.
//!
//! A qualifier of the other kind matches nothing, so a search typed in the
//! wrong view says so with an empty list rather than quietly ignoring it.

use sourceorrery_core::{AuditEvent, SecretProperties};
use time::{Duration, OffsetDateTime};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Query {
    words: Vec<String>,
    tags: Vec<(String, Option<String>)>,
    statuses: Vec<String>,
    types: Vec<String>,
    expires_within: Option<Duration>,
    ops: Vec<String>,
    outcomes: Vec<String>,
    secrets: Vec<String>,
    actors: Vec<String>,
}

impl Query {
    pub fn parse(text: &str) -> Self {
        let mut query = Self::default();
        for token in text.split_whitespace() {
            let token = token.to_lowercase();
            let Some((key, value)) = token.split_once(':').filter(|(_, v)| !v.is_empty()) else {
                query.words.push(token);
                continue;
            };
            let value = value.to_owned();
            match key {
                "tag" => query.tags.push(match value.split_once('=') {
                    Some((k, v)) => (k.to_owned(), Some(v.to_owned())),
                    None => (value, None),
                }),
                "status" => query.statuses.push(value),
                "type" => query.types.push(value),
                "expires" => match parse_days(&value) {
                    Some(days) => query.expires_within = Some(days),
                    None => query.words.push(token.clone()),
                },
                "op" => query.ops.push(value),
                "outcome" => query.outcomes.push(value),
                "secret" => query.secrets.push(value),
                "actor" => query.actors.push(value),
                _ => query.words.push(token.clone()),
            }
        }
        query
    }

    /// Matching ranges in the ORIGINAL sanitised text. Case expansion is mapped
    /// back to each original scalar, never reused as a UTF-8 byte offset.
    pub fn ranges(&self, text: &str) -> Vec<std::ops::Range<usize>> {
        let mut folded = String::new();
        let mut original = Vec::new();
        for (start, c) in text.char_indices() {
            let end = start + c.len_utf8();
            for lower in c.to_lowercase() {
                folded.push(lower);
                original.extend(std::iter::repeat_n((start, end), lower.len_utf8()));
            }
        }
        let mut ranges = Vec::new();
        for word in &self.words {
            for (start, matched) in folded.match_indices(word) {
                if !matched.is_empty() {
                    ranges.push(original[start].0..original[start + matched.len() - 1].1);
                }
            }
        }
        ranges.sort_by_key(|r| r.start);
        let mut merged: Vec<std::ops::Range<usize>> = Vec::new();
        for range in ranges {
            if let Some(last) = merged.last_mut()
                && range.start <= last.end
            {
                last.end = last.end.max(range.end);
            } else {
                merged.push(range);
            }
        }
        merged
    }

    fn has_event_qualifiers(&self) -> bool {
        !(self.ops.is_empty()
            && self.outcomes.is_empty()
            && self.secrets.is_empty()
            && self.actors.is_empty())
    }

    fn has_secret_qualifiers(&self) -> bool {
        !(self.tags.is_empty()
            && self.statuses.is_empty()
            && self.types.is_empty()
            && self.expires_within.is_none())
    }

    /// Does a secret (live or deleted) with this `status` match?
    pub fn secret(&self, p: &SecretProperties, status: &str, now: OffsetDateTime) -> bool {
        if self.has_event_qualifiers() {
            return false;
        }
        let tags_text: Vec<String> = p.tags.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let text = format!(
            "{} {} {} {}",
            p.name,
            status,
            p.content_type.as_deref().unwrap_or(""),
            tags_text.join(" ")
        )
        .to_lowercase();
        let content_type = p.content_type.as_deref().unwrap_or("").to_lowercase();
        self.words.iter().all(|w| text.contains(w.as_str()))
            && any_or_none(&self.statuses, |s| s == status)
            && any_or_none(&self.types, |t| content_type.contains(t.as_str()))
            && any_or_none(&self.tags, |(key, value)| {
                p.tags.iter().any(|(k, v)| {
                    k.to_lowercase() == *key
                        && value
                            .as_ref()
                            .is_none_or(|value| v.to_lowercase() == *value)
                })
            })
            && self
                .expires_within
                .is_none_or(|within| p.expires_on.is_some_and(|at| at <= now + within))
    }

    /// Does an audit event match?
    pub fn event(&self, e: &AuditEvent) -> bool {
        if self.has_secret_qualifiers() {
            return false;
        }
        let actor = e.actor.to_string().to_lowercase();
        let secret = e.secret_name.as_deref().unwrap_or("").to_lowercase();
        let text = format!(
            "{} {} {} {} {} {}",
            e.id,
            actor,
            e.operation.as_str(),
            secret,
            e.outcome.as_str(),
            e.detail.as_deref().unwrap_or("")
        )
        .to_lowercase();
        self.words.iter().all(|w| text.contains(w.as_str()))
            && any_or_none(&self.ops, |op| e.operation.as_str().contains(op.as_str()))
            && any_or_none(&self.outcomes, |o| e.outcome.as_str() == o)
            && any_or_none(&self.secrets, |s| secret.contains(s.as_str()))
            && any_or_none(&self.actors, |a| actor.contains(a.as_str()))
    }

    /// Does a vault name match? Only words apply.
    pub fn vault(&self, name: &str) -> bool {
        !self.has_secret_qualifiers()
            && !self.has_event_qualifiers()
            && self
                .words
                .iter()
                .all(|w| name.to_lowercase().contains(w.as_str()))
    }
}

/// `<30d`, `30d` or `30`: that many days.
fn parse_days(value: &str) -> Option<Duration> {
    let digits = value.trim_start_matches('<').trim_end_matches('d');
    digits
        .parse::<u16>()
        .ok()
        .map(|d| Duration::days(i64::from(d)))
}

fn any_or_none<T>(wanted: &[T], matches: impl Fn(&T) -> bool) -> bool {
    wanted.is_empty() || wanted.iter().any(matches)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use sourceorrery_core::{AuditOperation, AuditOutcome, Principal, RecoveryLevel, timestamp};

    use super::*;

    fn secret(name: &str, tags: &[(&str, &str)], expires_in_days: Option<i64>) -> SecretProperties {
        let now = timestamp::now();
        SecretProperties {
            vault: "dev".into(),
            name: name.into(),
            version: "0".repeat(32),
            enabled: true,
            content_type: Some("application/json".into()),
            tags: tags
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect::<BTreeMap<_, _>>(),
            not_before: None,
            expires_on: expires_in_days.map(|d| now + Duration::days(d)),
            created_on: now,
            updated_on: now,
            recovery_level: RecoveryLevel::Recoverable,
        }
    }

    fn event(op: AuditOperation, outcome: AuditOutcome, secret: Option<&str>) -> AuditEvent {
        AuditEvent {
            id: 7,
            occurred_on: timestamp::now(),
            actor: Principal::local_user(),
            operation: op,
            secret_name: secret.map(str::to_owned),
            version: None,
            outcome,
            detail: Some("locked".into()),
        }
    }

    fn matches(query: &str, p: &SecretProperties, status: &str) -> bool {
        Query::parse(query).secret(p, status, timestamp::now())
    }

    #[test]
    fn unicode_expansion_offsets_reconstruct_original_display_text() {
        for (query, text) in [
            ("i", "İstanbul 界e\u{301}"),
            ("σ", "Σίσυφος"),
            ("界", "界界"),
            ("b", "a\\u{1b}b"),
        ] {
            let q = Query::parse(query);
            let ranges = q.ranges(text);
            let mut result = String::new();
            let mut pos = 0;
            for r in ranges {
                assert!(text.is_char_boundary(r.start) && text.is_char_boundary(r.end));
                result.push_str(&text[pos..r.start]);
                result.push_str(&text[r.clone()]);
                pos = r.end;
            }
            result.push_str(&text[pos..]);
            assert_eq!(result, text);
        }
    }

    #[test]
    fn an_empty_query_matches_everything() {
        assert_eq!(Query::parse("  "), Query::default());
        assert!(matches("", &secret("a", &[], None), "enabled"));
    }

    #[test]
    fn words_match_name_status_type_and_tags_in_any_order() {
        let p = secret("Stripe-API-Key", &[("team", "payments")], None);
        assert!(matches("stripe", &p, "enabled"));
        assert!(matches("key stripe", &p, "enabled"));
        assert!(matches("payments", &p, "enabled"));
        assert!(matches("team=pay", &p, "enabled"));
        assert!(matches("json", &p, "enabled"));
        assert!(matches("enabled", &p, "enabled"));
        assert!(!matches("stripe github", &p, "enabled"));
    }

    #[test]
    fn tag_qualifiers_match_the_key_or_the_pair() {
        let p = secret("a", &[("env", "Prod")], None);
        assert!(matches("tag:env", &p, "enabled"));
        assert!(matches("tag:env=prod", &p, "enabled"));
        assert!(!matches("tag:env=dev", &p, "enabled"));
        assert!(
            matches("tag:env=dev tag:env=prod", &p, "enabled"),
            "any of one kind"
        );
        assert!(!matches("tag:team", &p, "enabled"));
    }

    #[test]
    fn status_type_and_expiry_qualifiers() {
        let soon = secret("a", &[], Some(10));
        let later = secret("b", &[], Some(90));
        let never = secret("c", &[], None);
        assert!(matches("status:expired", &soon, "expired"));
        assert!(!matches("status:expired", &soon, "enabled"));
        assert!(matches("type:json", &soon, "enabled"));
        assert!(!matches("type:xml", &soon, "enabled"));
        assert!(matches("expires:<30d", &soon, "enabled"));
        assert!(!matches("expires:<30d", &later, "enabled"));
        assert!(!matches("expires:<30d", &never, "enabled"));
        assert!(matches("expires:120", &later, "enabled"));
    }

    #[test]
    fn event_qualifiers() {
        let e = event(
            AuditOperation::SecretGet,
            AuditOutcome::Denied,
            Some("db-password"),
        );
        let q = |text: &str| Query::parse(text).event(&e);
        assert!(q("op:secret_get"));
        assert!(q("op:get"));
        assert!(!q("op:secret_set"));
        assert!(q("outcome:denied"));
        assert!(!q("outcome:failure"));
        assert!(q("secret:db"));
        assert!(q("locked"), "detail is searched");
        assert!(q("7"), "the id is searched");
        let actor = format!("actor:{}", Principal::local_user().id);
        assert!(q(&actor));
    }

    #[test]
    fn a_qualifier_of_the_other_kind_matches_nothing() {
        let p = secret("a", &[], None);
        assert!(!matches("op:secret_get", &p, "enabled"));
        let e = event(AuditOperation::SecretGet, AuditOutcome::Success, None);
        assert!(!Query::parse("tag:env").event(&e));
        assert!(!Query::parse("status:enabled").vault("dev"));
        assert!(Query::parse("de").vault("dev"));
    }

    #[test]
    fn unknown_qualifiers_are_words() {
        let p = secret("a", &[("note", "x:y")], None);
        assert!(matches("note=x:y", &p, "enabled"));
        assert_eq!(Query::parse("foo:bar"), Query::parse("foo:bar"));
        assert_ne!(Query::parse("foo:bar"), Query::default());
    }
}
