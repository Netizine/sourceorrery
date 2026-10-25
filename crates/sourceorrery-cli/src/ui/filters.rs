//! Facets are ordinary queries, composed with the existing search grammar.
use super::app::{App, Tab};
use std::collections::BTreeSet;

pub fn replace(query: &str, prefix: &str, token: &str) -> String {
    query
        .split_whitespace()
        .filter(|t| !t.to_lowercase().starts_with(prefix))
        .chain(std::iter::once(token))
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}
pub fn choices(app: &App) -> Vec<(String, String)> {
    let query = &app.list(app.tab).query;
    let mut out = vec![("Clear filters".into(), String::new())];
    match app.tab {
        Tab::Secrets | Tab::Deleted => {
            for (label, token) in [
                ("Enabled", "status:enabled"),
                ("Disabled", "status:disabled"),
                ("Expired", "status:expired"),
            ] {
                out.push((label.into(), replace(query, "status:", token)));
            }
            out.push((
                "Due within 30 days (includes expired)".into(),
                replace(query, "expires:", "expires:<30d"),
            ));
            let mut tags = BTreeSet::new();
            if let Some(s) = &app.session {
                for p in &s.secrets {
                    tags.extend(
                        p.tags
                            .keys()
                            .filter(|k| !k.chars().any(char::is_whitespace))
                            .cloned(),
                    );
                }
                for d in s.deleted().unwrap_or_default() {
                    tags.extend(
                        d.properties
                            .tags
                            .keys()
                            .filter(|k| !k.chars().any(char::is_whitespace))
                            .cloned(),
                    );
                }
            }
            for tag in tags {
                out.push((
                    format!("Tag: {tag}"),
                    replace(query, "tag:", &format!("tag:{tag}")),
                ));
            }
        }
        Tab::Audit => {
            for (label, token) in [
                ("Failures", "outcome:failure"),
                ("Denied", "outcome:denied"),
                ("Successful", "outcome:success"),
                ("Value reads", "op:secret_get"),
            ] {
                let prefix = if token.starts_with("op:") {
                    "op:"
                } else {
                    "outcome:"
                };
                out.push((label.into(), replace(query, prefix, token)));
            }
        }
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn facet_replaces_its_kind_and_preserves_and_terms() {
        assert_eq!(
            replace(
                "payment status:expired status:disabled tag:env=prod",
                "status:",
                "status:enabled"
            ),
            "payment tag:env=prod status:enabled"
        );
    }
}
