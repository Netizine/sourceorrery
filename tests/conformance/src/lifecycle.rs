//! The lifecycle scenarios every backend must pass.
//!
//! Each scenario is a function over `&dyn SecretClient`, so the same code
//! judges the local vault, the adapter pair of `sourceorrery-provider` and
//! every remote provider (through its `Blocking` adapter). A scenario asks
//! only what the contract on `SecretClient` promises: nothing about files,
//! protectors, version-id shapes or the audit log, which are the backend's
//! own tests. A scenario fails by panicking; [`lifecycle`] runs them all and
//! reports every failure at once.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

use sourceorrery_core::{
    ContinuationToken, ListOptions, SecretBytes, SecretClient, SecretProperties, SecretReference,
    SetSecretOptions, UpdateSecretProperties, timestamp,
};
use time::Duration;

/// One lifecycle scenario.
#[derive(Debug, Clone, Copy)]
pub struct Scenario {
    /// What the scenario proves, as a test name.
    pub name: &'static str,
    /// The scenario; it panics on a violation and needs a client with no
    /// secrets in it.
    pub run: fn(&dyn SecretClient),
}

/// Every lifecycle scenario.
pub static SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "set_creates_a_new_immutable_version_each_time",
        run: set_creates_a_new_immutable_version_each_time,
    },
    Scenario {
        name: "get_returns_latest_accessible_version",
        run: get_returns_latest_accessible_version,
    },
    Scenario {
        name: "time_window_is_enforced_on_retrieval",
        run: time_window_is_enforced_on_retrieval,
    },
    Scenario {
        name: "update_changes_metadata_never_the_value",
        run: update_changes_metadata_never_the_value,
    },
    Scenario {
        name: "list_returns_metadata_for_live_secrets_only",
        run: list_returns_metadata_for_live_secrets_only,
    },
    Scenario {
        name: "listings_are_paged_by_name_without_gaps_or_repeats",
        run: listings_are_paged_by_name_without_gaps_or_repeats,
    },
    Scenario {
        name: "pages_follow_the_name_order_through_changes",
        run: pages_follow_the_name_order_through_changes,
    },
    Scenario {
        name: "delete_recover_and_purge",
        run: delete_recover_and_purge,
    },
    Scenario {
        name: "names_and_versions_are_validated",
        run: names_and_versions_are_validated,
    },
    Scenario {
        name: "references_resolve_within_their_vault",
        run: references_resolve_within_their_vault,
    },
    Scenario {
        name: "many_versions_are_listed_and_read_correctly",
        run: many_versions_are_listed_and_read_correctly,
    },
    Scenario {
        name: "errors_and_debug_output_never_carry_a_value",
        run: errors_and_debug_output_never_carry_a_value,
    },
];

/// Run every scenario, each on a fresh client from `fresh` (called with the
/// scenario's name), and panic naming every scenario that failed.
///
/// A backend passes the lifecycle conformance suite when this returns.
pub fn lifecycle(fresh: &mut dyn FnMut(&str) -> Box<dyn SecretClient>) {
    let mut failed = Vec::new();
    for scenario in SCENARIOS {
        let client = fresh(scenario.name);
        if catch_unwind(AssertUnwindSafe(|| (scenario.run)(client.as_ref()))).is_err() {
            failed.push(scenario.name);
        }
    }
    assert!(
        failed.is_empty(),
        "{} of {} lifecycle scenarios failed: {}",
        failed.len(),
        SCENARIOS.len(),
        failed.join(", ")
    );
}

/// Store `value` under `name` with default options.
pub fn set(client: &dyn SecretClient, name: &str, value: &str) -> SecretProperties {
    client
        .set_secret(name, SecretBytes::from(value), SetSecretOptions::default())
        .expect("set")
}

fn disable(client: &dyn SecretClient, name: &str, version: Option<&str>) {
    client
        .update_secret_properties(
            name,
            version,
            UpdateSecretProperties {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
}

fn set_creates_a_new_immutable_version_each_time(client: &dyn SecretClient) {
    let v1 = set(client, "db-password", "one");
    let v2 = set(client, "db-password", "two");
    assert_ne!(v1.version, v2.version);
    assert_ne!(v1.version, "", "a version has an id");
    assert_eq!(v1.vault, client.vault_name());

    let versions = client
        .list_properties_of_secret_versions("db-password")
        .unwrap();
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].version, v2.version, "newest first");
    assert_eq!(versions[1].version, v1.version);

    let latest = client.get_secret("db-password", None).unwrap();
    assert_eq!(latest.properties.version, v2.version);
    assert_eq!(latest.value.expose(), b"two");

    let old = client.get_secret("db-password", Some(&v1.version)).unwrap();
    assert_eq!(old.value.expose(), b"one", "old versions are immutable");
}

fn get_returns_latest_accessible_version(client: &dyn SecretClient) {
    let v1 = set(client, "api-key", "old");
    let v2 = set(client, "api-key", "new");

    // Disabling the newest version falls back to the previous one.
    disable(client, "api-key", None);
    let got = client.get_secret("api-key", None).unwrap();
    assert_eq!(got.properties.version, v1.version);
    assert_eq!(got.value.expose(), b"old");

    // Asking for the disabled version explicitly is refused.
    let err = client.get_secret("api-key", Some(&v2.version)).unwrap_err();
    assert_eq!(err.code(), "disabled");

    // Metadata of the disabled version is still inspectable.
    let props = client
        .get_secret_properties("api-key", Some(&v2.version))
        .unwrap();
    assert!(!props.enabled);

    // Disabling both leaves nothing accessible; the newest failure is reported.
    disable(client, "api-key", Some(&v1.version));
    let err = client.get_secret("api-key", None).unwrap_err();
    assert_eq!(err.code(), "disabled");
}

fn time_window_is_enforced_on_retrieval(client: &dyn SecretClient) {
    let now = timestamp::now();

    client
        .set_secret(
            "expired",
            SecretBytes::from("x"),
            SetSecretOptions {
                expires_on: Some(now - Duration::minutes(1)),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        client.get_secret("expired", None).unwrap_err().code(),
        "expired"
    );

    client
        .set_secret(
            "pending",
            SecretBytes::from("x"),
            SetSecretOptions {
                not_before: Some(now + Duration::hours(1)),
                ..Default::default()
            },
        )
        .unwrap();
    let err = client.get_secret("pending", None).unwrap_err();
    assert_eq!(err.code(), "not_yet_valid");
    assert!(err.is_transient());

    // Clearing the expiry makes the secret readable again.
    client
        .update_secret_properties(
            "expired",
            None,
            UpdateSecretProperties {
                expires_on: Some(None),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(client.get_secret("expired", None).is_ok());

    // An inverted window is rejected up front.
    let err = client
        .set_secret(
            "bad",
            SecretBytes::from("x"),
            SetSecretOptions {
                not_before: Some(now + Duration::hours(2)),
                expires_on: Some(now + Duration::hours(1)),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
}

fn update_changes_metadata_never_the_value(client: &dyn SecretClient) {
    let created = set(client, "token", "value");

    let updated = client
        .update_secret_properties(
            "token",
            None,
            UpdateSecretProperties {
                content_type: Some(Some("text/plain".into())),
                tags: Some(BTreeMap::from([("env".to_owned(), "dev".to_owned())])),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        updated.version, created.version,
        "same version, not a new one"
    );
    assert_eq!(updated.content_type.as_deref(), Some("text/plain"));
    assert_eq!(updated.tags.get("env").map(String::as_str), Some("dev"));
    assert_eq!(updated.created_on, created.created_on);
    assert!(updated.updated_on >= created.updated_on);

    let got = client.get_secret("token", None).unwrap();
    assert_eq!(got.value.expose(), b"value");
    assert_eq!(got.properties, updated);

    let err = client
        .update_secret_properties("token", None, UpdateSecretProperties::default())
        .unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
}

fn list_returns_metadata_for_live_secrets_only(client: &dyn SecretClient) {
    set(client, "alpha", "1");
    set(client, "beta", "2");
    set(client, "beta", "3");
    set(client, "gamma", "4");
    client.delete_secret("gamma").unwrap();

    let listed = client.list_properties_of_secrets().unwrap();
    let names: Vec<&str> = listed.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, vec!["alpha", "beta"]);
    let beta = listed.iter().find(|p| p.name == "beta").unwrap();
    assert_eq!(
        beta.version,
        client.get_secret("beta", None).unwrap().properties.version,
        "list shows the newest version"
    );
    let json = serde_json::to_string(&listed).unwrap();
    for value in ["\"1\"", "\"2\"", "\"3\""] {
        assert!(!json.contains(value), "metadata must not carry values");
    }
}

/// Fill an empty client with 23 live secrets created out of name order and
/// five deleted ones interleaved. Returns both name lists, sorted.
pub fn seed_paged(client: &dyn SecretClient) -> (Vec<String>, Vec<String>) {
    let mut live: Vec<String> = (0..23)
        .map(|i| format!("live-{:02}", (i * 7) % 23))
        .collect();
    let mut gone = Vec::new();
    for (i, name) in live.iter().enumerate() {
        set(client, name, "v");
        if i % 5 == 0 {
            let name = format!("gone-{i:02}");
            set(client, &name, "x");
            client.delete_secret(&name).unwrap();
            gone.push(name);
        }
    }
    live.sort();
    gone.sort();
    (live, gone)
}

/// Walk a paged listing to the end, returning every name in the order seen
/// and the number of pages it took. Every page with a token is full; the
/// page after the last token may hold fewer items, even none, when the
/// names that remained belonged to the other listing.
pub fn walk_pages(client: &dyn SecretClient, size: usize, deleted: bool) -> (Vec<String>, usize) {
    let mut options = ListOptions::first(size);
    let mut seen = Vec::new();
    let mut pages = 0;
    loop {
        let (names, continuation) = if deleted {
            let page = client.list_deleted_secrets_page(options.clone()).unwrap();
            let names: Vec<String> = page
                .items
                .iter()
                .map(|d| d.properties.name.clone())
                .collect();
            (names, page.continuation)
        } else {
            let page = client
                .list_properties_of_secrets_page(options.clone())
                .unwrap();
            let names: Vec<String> = page.items.iter().map(|p| p.name.clone()).collect();
            (names, page.continuation)
        };
        pages += 1;
        if let Some(token) = continuation {
            assert_eq!(names.len(), size, "a page with a token is full");
            assert_eq!(
                Some(token.as_str()),
                names.last().map(String::as_str),
                "the token is the name of the page's last item"
            );
            seen.extend(names);
            options.continuation = Some(token);
        } else {
            assert!(
                names.len() <= size,
                "{} items for a limit of {size}",
                names.len()
            );
            seen.extend(names);
            break;
        }
    }
    (seen, pages)
}

fn listings_are_paged_by_name_without_gaps_or_repeats(client: &dyn SecretClient) {
    let (live, gone) = seed_paged(client);

    let full: Vec<String> = client
        .list_properties_of_secrets()
        .unwrap()
        .into_iter()
        .map(|p| p.name)
        .collect();
    assert_eq!(full, live, "the full listing is in name order");

    for size in [1, 7, 23, 100] {
        let (seen, pages) = walk_pages(client, size, false);
        assert_eq!(seen, live, "pages of {size}");
        // Nothing sorts after the last live name, so no extra final page.
        assert_eq!(pages, live.len().div_ceil(size), "pages of {size}");
        let (seen, pages) = walk_pages(client, size, true);
        assert_eq!(seen, gone, "deleted pages of {size}");
        // Live names sort after the last deleted one, so when a page ends
        // exactly on it one more, empty, final page follows.
        let full_pages = gone.len().div_ceil(size);
        assert!(
            pages == full_pages || pages == full_pages + 1,
            "deleted pages of {size}: {pages}"
        );
    }

    // No limit after a token: everything that sorts after it, in one page.
    let rest = client
        .list_properties_of_secrets_page(ListOptions {
            max_results: None,
            continuation: Some(ContinuationToken::new("live-19")),
        })
        .unwrap();
    let names: Vec<&str> = rest.items.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["live-20", "live-21", "live-22"]);
    assert_eq!(rest.continuation, None);

    // A full page that happens to be the last carries no token.
    let exact = client
        .list_properties_of_secrets_page(ListOptions {
            max_results: Some(3),
            continuation: Some(ContinuationToken::new("live-19")),
        })
        .unwrap();
    assert_eq!(exact.items.len(), 3);
    assert_eq!(exact.continuation, None);
}

fn pages_follow_the_name_order_through_changes(client: &dyn SecretClient) {
    seed_paged(client);

    // The listing is ordered by name, so a change between pages shows up
    // only where its name sorts: a new name before the token is not
    // returned by later pages, a new name after it is.
    let first = client
        .list_properties_of_secrets_page(ListOptions::first(10))
        .unwrap();
    let token = first.continuation.clone().unwrap();
    assert_eq!(token.as_str(), "live-09");
    set(client, "live-00-added", "v");
    set(client, "zz-added", "v");
    client.delete_secret("live-15").unwrap();
    let mut options = ListOptions::first(10);
    options.continuation = Some(token);
    let mut later = Vec::new();
    loop {
        let page = client
            .list_properties_of_secrets_page(options.clone())
            .unwrap();
        later.extend(page.items.into_iter().map(|p| p.name));
        match page.continuation {
            Some(token) => options.continuation = Some(token),
            None => break,
        }
    }
    assert!(!later.contains(&"live-00-added".to_owned()));
    assert!(!later.contains(&"live-15".to_owned()));
    assert_eq!(later.last().map(String::as_str), Some("zz-added"));
    assert_eq!(later.len(), 23 - 10 - 1 + 1);

    // A rejected request is an error, not an empty page.
    assert_eq!(
        client
            .list_properties_of_secrets_page(ListOptions::first(0))
            .unwrap_err()
            .code(),
        "invalid_argument"
    );
    assert_eq!(
        client
            .list_deleted_secrets_page(ListOptions {
                max_results: Some(5),
                continuation: Some(ContinuationToken::new("not a secret name")),
            })
            .unwrap_err()
            .code(),
        "invalid_argument"
    );

    let json = serde_json::to_string(&first).unwrap();
    assert!(json.contains("\"continuation\":\"live-09\""));
    assert!(!json.contains("\"v\""), "a page must not carry values");
}

fn delete_recover_and_purge(client: &dyn SecretClient) {
    set(client, "db", "secret");

    let deleted = client.delete_secret("db").unwrap();
    assert_eq!(deleted.properties.name, "db");
    assert!(deleted.scheduled_purge_on.unwrap() > deleted.deleted_on);
    assert_eq!(
        deleted.recovery_id,
        format!("sourceorrery://{}/deletedsecrets/db", client.vault_name())
    );

    assert_eq!(client.get_secret("db", None).unwrap_err().code(), "deleted");
    assert_eq!(client.list_properties_of_secrets().unwrap().len(), 0);
    assert_eq!(client.list_deleted_secrets().unwrap().len(), 1);
    assert_eq!(client.get_deleted_secret("db").unwrap(), deleted);

    let err = client
        .set_secret(
            "db",
            SecretBytes::from("again"),
            SetSecretOptions::default(),
        )
        .unwrap_err();
    assert_eq!(err.code(), "deleted_conflict");

    assert_eq!(
        client.purge_deleted_secret("other").unwrap_err().code(),
        "not_found"
    );
    assert_eq!(
        client.recover_deleted_secret("other").unwrap_err().code(),
        "not_found"
    );

    let recovered = client.recover_deleted_secret("db").unwrap();
    assert_eq!(recovered.name, "db");
    assert_eq!(
        client.get_secret("db", None).unwrap().value.expose(),
        b"secret"
    );
    assert_eq!(
        client.recover_deleted_secret("db").unwrap_err().code(),
        "not_deleted"
    );
    assert_eq!(
        client.purge_deleted_secret("db").unwrap_err().code(),
        "not_deleted"
    );

    client.delete_secret("db").unwrap();
    client.purge_deleted_secret("db").unwrap();
    assert_eq!(
        client.get_secret("db", None).unwrap_err().code(),
        "not_found"
    );
    assert_eq!(client.list_deleted_secrets().unwrap().len(), 0);

    // The name is free again after a purge.
    set(client, "db", "fresh");
    assert_eq!(
        client.get_secret("db", None).unwrap().value.expose(),
        b"fresh"
    );
}

fn names_and_versions_are_validated(client: &dyn SecretClient) {
    for bad in [
        "",
        "has_underscore",
        "has space",
        "dots.no",
        &"x".repeat(128),
    ] {
        let err = client
            .set_secret(bad, SecretBytes::from("v"), SetSecretOptions::default())
            .unwrap_err();
        assert_eq!(err.code(), "invalid_name", "{bad:?}");
    }
    assert_eq!(
        client.get_secret("missing", None).unwrap_err().code(),
        "not_found"
    );
    set(client, "present", "v");
    assert_eq!(
        client
            .get_secret("present", Some("nope"))
            .unwrap_err()
            .code(),
        "version_not_found"
    );
}

fn references_resolve_within_their_vault(client: &dyn SecretClient) {
    let vault = client.vault_name();
    let v1 = set(client, "k", "one");
    set(client, "k", "two");

    let latest = SecretReference::parse(&format!("sourceorrery://{vault}/k")).unwrap();
    assert_eq!(client.resolve(&latest).unwrap().value.expose(), b"two");

    let pinned = latest.clone().with_version(v1.version.clone()).unwrap();
    assert_eq!(client.resolve(&pinned).unwrap().value.expose(), b"one");

    let other = if vault == "other-vault" {
        "another-vault"
    } else {
        "other-vault"
    };
    let foreign = SecretReference::parse(&format!("sourceorrery://{other}/k")).unwrap();
    assert_eq!(
        client.resolve(&foreign).unwrap_err().code(),
        "invalid_argument"
    );
}

fn many_versions_are_listed_and_read_correctly(client: &dyn SecretClient) {
    // A secret with a long history must list newest first, summarise to its
    // newest version and return any one version by id.
    const VERSIONS: usize = 50;
    let created: Vec<String> = (0..VERSIONS)
        .map(|i| set(client, "rotated", &format!("value-{i}")).version)
        .collect();

    let listed = client
        .list_properties_of_secret_versions("rotated")
        .unwrap();
    assert_eq!(listed.len(), VERSIONS);
    let listed_ids: Vec<&str> = listed.iter().map(|p| p.version.as_str()).collect();
    let newest_first: Vec<&str> = created.iter().rev().map(String::as_str).collect();
    assert_eq!(listed_ids, newest_first);

    let summary = client.list_properties_of_secrets().unwrap();
    assert_eq!(summary.len(), 1);
    assert_eq!(summary[0].version, created[VERSIONS - 1]);

    let latest = client.get_secret("rotated", None).unwrap();
    assert_eq!(latest.properties.version, created[VERSIONS - 1]);
    assert_eq!(
        latest.value.expose(),
        format!("value-{}", VERSIONS - 1).as_bytes()
    );

    for i in [0, 1, VERSIONS / 2, VERSIONS - 2, VERSIONS - 1] {
        let version = created[i].as_str();
        let got = client.get_secret("rotated", Some(version)).unwrap();
        assert_eq!(got.properties.version, version);
        assert_eq!(got.value.expose(), format!("value-{i}").as_bytes());
        let props = client
            .get_secret_properties("rotated", Some(version))
            .unwrap();
        assert_eq!(props.version, version);
    }
}

/// A value that no error, listing or `Debug` output may ever show.
pub const CANARY: &str = "CANARY-7f3a9c1e-value-that-must-never-leak";

fn errors_and_debug_output_never_carry_a_value(client: &dyn SecretClient) {
    client
        .set_secret(
            "canary",
            SecretBytes::from(CANARY),
            SetSecretOptions::default(),
        )
        .unwrap();
    let secret = client.get_secret("canary", None).unwrap();
    assert_eq!(secret.value.expose(), CANARY.as_bytes());
    let dbg = format!("{secret:?}");
    assert!(!dbg.contains(CANARY), "Debug of a secret shows its value");
    assert!(dbg.contains("REDACTED"));

    let errors = [
        client.get_secret("canary", Some("deadbeef")).unwrap_err(),
        client
            .set_secret(
                "bad_name",
                SecretBytes::from(CANARY),
                SetSecretOptions::default(),
            )
            .unwrap_err(),
        client
            .set_secret(
                "canary",
                SecretBytes::from(CANARY),
                SetSecretOptions {
                    not_before: Some(timestamp::now() + Duration::hours(2)),
                    expires_on: Some(timestamp::now() + Duration::hours(1)),
                    ..Default::default()
                },
            )
            .unwrap_err(),
    ];
    for err in errors {
        assert!(!err.to_string().contains(CANARY), "{}", err.code());
        assert!(!format!("{err:?}").contains(CANARY), "{}", err.code());
    }

    disable(client, "canary", None);
    let err = client.get_secret("canary", None).unwrap_err();
    assert!(!err.to_string().contains(CANARY));

    let listed = client.list_properties_of_secrets().unwrap();
    let versions = client.list_properties_of_secret_versions("canary").unwrap();
    let page = client
        .list_properties_of_secrets_page(ListOptions::first(10))
        .unwrap();
    for json in [
        serde_json::to_string(&listed).unwrap(),
        serde_json::to_string(&versions).unwrap(),
        serde_json::to_string(&page).unwrap(),
        format!("{listed:?}{versions:?}{page:?}"),
    ] {
        assert!(!json.contains(CANARY), "metadata carries the value");
    }
}

#[cfg(test)]
mod tests {
    use sourceorrery_core::{
        AuditEvent, AuditQuery, DeletedSecret, Result, Secret, SecretError, SecretProperties,
    };

    use super::*;

    /// A backend that refuses everything.
    struct Broken;

    impl Broken {
        const VAULT: &'static str = "broken";
    }

    impl SecretClient for Broken {
        fn vault_name(&self) -> &str {
            Self::VAULT
        }
        fn set_secret(
            &self,
            _: &str,
            _: SecretBytes,
            _: SetSecretOptions,
        ) -> Result<SecretProperties> {
            Err(SecretError::Unsupported("broken".into()))
        }
        fn get_secret(&self, _: &str, _: Option<&str>) -> Result<Secret> {
            Err(SecretError::Unsupported("broken".into()))
        }
        fn get_secret_properties(&self, _: &str, _: Option<&str>) -> Result<SecretProperties> {
            Err(SecretError::Unsupported("broken".into()))
        }
        fn list_properties_of_secrets(&self) -> Result<Vec<SecretProperties>> {
            Err(SecretError::Unsupported("broken".into()))
        }
        fn list_properties_of_secret_versions(&self, _: &str) -> Result<Vec<SecretProperties>> {
            Err(SecretError::Unsupported("broken".into()))
        }
        fn update_secret_properties(
            &self,
            _: &str,
            _: Option<&str>,
            _: UpdateSecretProperties,
        ) -> Result<SecretProperties> {
            Err(SecretError::Unsupported("broken".into()))
        }
        fn delete_secret(&self, _: &str) -> Result<DeletedSecret> {
            Err(SecretError::Unsupported("broken".into()))
        }
        fn get_deleted_secret(&self, _: &str) -> Result<DeletedSecret> {
            Err(SecretError::Unsupported("broken".into()))
        }
        fn list_deleted_secrets(&self) -> Result<Vec<DeletedSecret>> {
            Err(SecretError::Unsupported("broken".into()))
        }
        fn recover_deleted_secret(&self, _: &str) -> Result<SecretProperties> {
            Err(SecretError::Unsupported("broken".into()))
        }
        fn purge_deleted_secret(&self, _: &str) -> Result<()> {
            Err(SecretError::Unsupported("broken".into()))
        }
        fn audit_events(&self, _: AuditQuery) -> Result<Vec<AuditEvent>> {
            Err(SecretError::Unsupported("broken".into()))
        }
    }

    #[test]
    fn a_failing_backend_is_reported_with_every_failing_scenario() {
        let mut labels = Vec::new();
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            lifecycle(&mut |label| {
                labels.push(label.to_owned());
                Box::new(Broken)
            });
        }));
        let message = outcome
            .unwrap_err()
            .downcast::<String>()
            .expect("a formatted message");
        let total = SCENARIOS.len();
        assert!(
            message.starts_with(&format!("{total} of {total} lifecycle scenarios failed: ")),
            "{message}"
        );
        for scenario in SCENARIOS {
            assert!(message.contains(scenario.name), "{message}");
            assert!(labels.iter().any(|l| l == scenario.name));
        }
    }
}
