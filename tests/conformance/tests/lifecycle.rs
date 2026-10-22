//! Lifecycle conformance: the semantics every `SecretClient` must honour.
//!
//! These scenarios are the reference for every SDK binding. If a binding
//! cannot pass the equivalent of each test here, it does not implement
//! SourceOrrery.

use std::collections::BTreeMap;

use sourceorrery_conformance::{FIXTURE_PASSPHRASE, Fixture};
use sourceorrery_core::{
    AuditOperation, AuditOutcome, AuditQuery, ContinuationToken, ListOptions, RecoveryLevel,
    SecretBytes, SecretClient, SecretReference, SetSecretOptions, UpdateSecretProperties,
    timestamp,
};
use sourceorrery_crypto::Argon2Params;
use sourceorrery_storage::{CreateVaultOptions, ProtectorSpec, SqliteVault, StaticPassphrase};
use time::Duration;

fn set(vault: &impl SecretClient, name: &str, value: &str) -> sourceorrery_core::SecretProperties {
    vault
        .set_secret(name, SecretBytes::from(value), SetSecretOptions::default())
        .expect("set")
}

#[test]
fn set_creates_a_new_immutable_version_each_time() {
    let fx = Fixture::new();
    let vault = fx.create_vault("dev");

    let v1 = set(&vault, "db-password", "one");
    let v2 = set(&vault, "db-password", "two");
    assert_ne!(v1.version, v2.version);
    assert_eq!(v1.version.len(), 32);

    let versions = vault
        .list_properties_of_secret_versions("db-password")
        .unwrap();
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].version, v2.version, "newest first");
    assert_eq!(versions[1].version, v1.version);

    let latest = vault.get_secret("db-password", None).unwrap();
    assert_eq!(latest.properties.version, v2.version);
    assert_eq!(latest.value.expose(), b"two");

    let old = vault.get_secret("db-password", Some(&v1.version)).unwrap();
    assert_eq!(old.value.expose(), b"one", "old versions are immutable");
}

#[test]
fn get_returns_latest_accessible_version() {
    let fx = Fixture::new();
    let vault = fx.create_vault("dev");
    let v1 = set(&vault, "api-key", "old");
    let v2 = set(&vault, "api-key", "new");

    // Disabling the newest version falls back to the previous one.
    vault
        .update_secret_properties(
            "api-key",
            None,
            UpdateSecretProperties {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    let got = vault.get_secret("api-key", None).unwrap();
    assert_eq!(got.properties.version, v1.version);
    assert_eq!(got.value.expose(), b"old");

    // Asking for the disabled version explicitly is refused.
    let err = vault.get_secret("api-key", Some(&v2.version)).unwrap_err();
    assert_eq!(err.code(), "disabled");

    // Metadata of the disabled version is still inspectable.
    let props = vault
        .get_secret_properties("api-key", Some(&v2.version))
        .unwrap();
    assert!(!props.enabled);

    // Disabling both leaves nothing accessible; the newest failure is reported.
    vault
        .update_secret_properties(
            "api-key",
            Some(&v1.version),
            UpdateSecretProperties {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    let err = vault.get_secret("api-key", None).unwrap_err();
    assert_eq!(err.code(), "disabled");
}

#[test]
fn time_window_is_enforced_on_retrieval() {
    let fx = Fixture::new();
    let vault = fx.create_vault("dev");
    let now = timestamp::now();

    vault
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
        vault.get_secret("expired", None).unwrap_err().code(),
        "expired"
    );

    vault
        .set_secret(
            "pending",
            SecretBytes::from("x"),
            SetSecretOptions {
                not_before: Some(now + Duration::hours(1)),
                ..Default::default()
            },
        )
        .unwrap();
    let err = vault.get_secret("pending", None).unwrap_err();
    assert_eq!(err.code(), "not_yet_valid");
    assert!(err.is_transient());

    // Clearing the expiry makes the secret readable again.
    vault
        .update_secret_properties(
            "expired",
            None,
            UpdateSecretProperties {
                expires_on: Some(None),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(vault.get_secret("expired", None).is_ok());

    // An inverted window is rejected up front.
    let err = vault
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

#[test]
fn update_changes_metadata_never_the_value() {
    let fx = Fixture::new();
    let vault = fx.create_vault("dev");
    let created = set(&vault, "token", "value");

    let updated = vault
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

    let got = vault.get_secret("token", None).unwrap();
    assert_eq!(got.value.expose(), b"value");
    assert_eq!(got.properties, updated);

    let err = vault
        .update_secret_properties("token", None, UpdateSecretProperties::default())
        .unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
}

#[test]
fn list_returns_metadata_for_live_secrets_only() {
    let fx = Fixture::new();
    let vault = fx.create_vault("dev");
    set(&vault, "alpha", "1");
    set(&vault, "beta", "2");
    set(&vault, "beta", "3");
    set(&vault, "gamma", "4");
    vault.delete_secret("gamma").unwrap();

    let listed = vault.list_properties_of_secrets().unwrap();
    let names: Vec<&str> = listed.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, vec!["alpha", "beta"]);
    let beta = listed.iter().find(|p| p.name == "beta").unwrap();
    assert_eq!(
        beta.version,
        vault.get_secret("beta", None).unwrap().properties.version,
        "list shows the newest version"
    );
    let json = serde_json::to_string(&listed).unwrap();
    for value in ["\"1\"", "\"2\"", "\"3\""] {
        assert!(!json.contains(value), "metadata must not carry values");
    }
}

/// A vault with 23 live secrets created out of name order and five deleted
/// ones interleaved, with both name lists sorted. Keep the whole struct
/// alive while the vault is used: `fx` owns the vault's directory.
struct PagedFixture {
    _fx: Fixture,
    vault: SqliteVault,
    live: Vec<String>,
    gone: Vec<String>,
}

fn paged_fixture() -> PagedFixture {
    let fx = Fixture::new();
    let vault = fx.create_vault("dev");
    let mut live: Vec<String> = (0..23)
        .map(|i| format!("live-{:02}", (i * 7) % 23))
        .collect();
    let mut gone = Vec::new();
    for (i, name) in live.iter().enumerate() {
        set(&vault, name, "v");
        if i % 5 == 0 {
            let name = format!("gone-{i:02}");
            set(&vault, &name, "x");
            vault.delete_secret(&name).unwrap();
            gone.push(name);
        }
    }
    live.sort();
    gone.sort();
    PagedFixture {
        _fx: fx,
        vault,
        live,
        gone,
    }
}

/// Walk a paged listing to the end, returning every name in the order seen
/// and the number of pages it took. Every page with a token is full; the
/// page after the last token may hold fewer items, even none, when the
/// names that remained belonged to the other listing.
fn walk_pages(vault: &impl SecretClient, size: usize, deleted: bool) -> (Vec<String>, usize) {
    let mut options = ListOptions::first(size);
    let mut seen = Vec::new();
    let mut pages = 0;
    loop {
        let (names, continuation) = if deleted {
            let page = vault.list_deleted_secrets_page(options.clone()).unwrap();
            let names: Vec<String> = page
                .items
                .iter()
                .map(|d| d.properties.name.clone())
                .collect();
            (names, page.continuation)
        } else {
            let page = vault
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

#[test]
fn listings_are_paged_by_name_without_gaps_or_repeats() {
    let fixture = paged_fixture();
    let (vault, live, gone) = (&fixture.vault, &fixture.live, &fixture.gone);

    let full: Vec<String> = vault
        .list_properties_of_secrets()
        .unwrap()
        .into_iter()
        .map(|p| p.name)
        .collect();
    assert_eq!(&full, live, "the full listing is in name order");

    for size in [1, 7, 23, 100] {
        let (seen, pages) = walk_pages(vault, size, false);
        assert_eq!(&seen, live, "pages of {size}");
        // Nothing sorts after the last live name, so no extra final page.
        assert_eq!(pages, live.len().div_ceil(size), "pages of {size}");
        let (seen, pages) = walk_pages(vault, size, true);
        assert_eq!(&seen, gone, "deleted pages of {size}");
        // Live names sort after the last deleted one, so when a page ends
        // exactly on it one more, empty, final page follows.
        let full_pages = gone.len().div_ceil(size);
        assert!(
            pages == full_pages || pages == full_pages + 1,
            "deleted pages of {size}: {pages}"
        );
    }

    // No limit after a token: everything that sorts after it, in one page.
    let rest = vault
        .list_properties_of_secrets_page(ListOptions {
            max_results: None,
            continuation: Some(ContinuationToken::new("live-19")),
        })
        .unwrap();
    let names: Vec<&str> = rest.items.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["live-20", "live-21", "live-22"]);
    assert_eq!(rest.continuation, None);

    // A full page that happens to be the last carries no token.
    let exact = vault
        .list_properties_of_secrets_page(ListOptions {
            max_results: Some(3),
            continuation: Some(ContinuationToken::new("live-19")),
        })
        .unwrap();
    assert_eq!(exact.items.len(), 3);
    assert_eq!(exact.continuation, None);
}

#[test]
fn pages_follow_the_name_order_through_changes_and_are_audited() {
    let fixture = paged_fixture();
    let vault = &fixture.vault;

    // The listing is ordered by name, so a change between pages shows up
    // only where its name sorts: a new name before the token is not
    // returned by later pages, a new name after it is.
    let first = vault
        .list_properties_of_secrets_page(ListOptions::first(10))
        .unwrap();
    let token = first.continuation.clone().unwrap();
    assert_eq!(token.as_str(), "live-09");
    set(vault, "live-00-added", "v");
    set(vault, "zz-added", "v");
    vault.delete_secret("live-15").unwrap();
    let mut options = ListOptions::first(10);
    options.continuation = Some(token);
    let mut later = Vec::new();
    loop {
        let page = vault
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

    // Every page is one `secret_list` event, successes and failures alike,
    // and a rejected request is recorded before anything is read.
    let count = |outcome: AuditOutcome| {
        vault
            .audit_events(AuditQuery::default())
            .unwrap()
            .into_iter()
            .filter(|e| e.operation == AuditOperation::SecretList && e.outcome == outcome)
            .count()
    };
    let successes = count(AuditOutcome::Success);
    let failures = count(AuditOutcome::Failure);
    let (_, pages) = walk_pages(vault, 7, false);
    assert_eq!(count(AuditOutcome::Success), successes + pages);
    assert_eq!(
        vault
            .list_properties_of_secrets_page(ListOptions::first(0))
            .unwrap_err()
            .code(),
        "invalid_argument"
    );
    assert_eq!(
        vault
            .list_deleted_secrets_page(ListOptions {
                max_results: Some(5),
                continuation: Some(ContinuationToken::new("not a secret name")),
            })
            .unwrap_err()
            .code(),
        "invalid_argument"
    );
    assert_eq!(count(AuditOutcome::Failure), failures + 2);

    let json = serde_json::to_string(&first).unwrap();
    assert!(json.contains("\"continuation\":\"live-09\""));
    assert!(!json.contains("\"v\""), "a page must not carry values");
}

#[test]
fn delete_recover_and_purge() {
    let fx = Fixture::new();
    let vault = fx.create_vault("dev");
    set(&vault, "db", "secret");

    let deleted = vault.delete_secret("db").unwrap();
    assert_eq!(deleted.properties.name, "db");
    assert!(deleted.scheduled_purge_on.unwrap() > deleted.deleted_on);
    assert_eq!(deleted.recovery_id, "sourceorrery://dev/deletedsecrets/db");

    assert_eq!(vault.get_secret("db", None).unwrap_err().code(), "deleted");
    assert_eq!(vault.list_properties_of_secrets().unwrap().len(), 0);
    assert_eq!(vault.list_deleted_secrets().unwrap().len(), 1);
    assert_eq!(vault.get_deleted_secret("db").unwrap(), deleted);

    let err = vault
        .set_secret(
            "db",
            SecretBytes::from("again"),
            SetSecretOptions::default(),
        )
        .unwrap_err();
    assert_eq!(err.code(), "deleted_conflict");

    assert_eq!(
        vault.purge_deleted_secret("other").unwrap_err().code(),
        "not_found"
    );
    assert_eq!(
        vault.recover_deleted_secret("other").unwrap_err().code(),
        "not_found"
    );

    let recovered = vault.recover_deleted_secret("db").unwrap();
    assert_eq!(recovered.name, "db");
    assert_eq!(
        vault.get_secret("db", None).unwrap().value.expose(),
        b"secret"
    );
    assert_eq!(
        vault.recover_deleted_secret("db").unwrap_err().code(),
        "not_deleted"
    );
    assert_eq!(
        vault.purge_deleted_secret("db").unwrap_err().code(),
        "not_deleted"
    );

    vault.delete_secret("db").unwrap();
    vault.purge_deleted_secret("db").unwrap();
    assert_eq!(
        vault.get_secret("db", None).unwrap_err().code(),
        "not_found"
    );
    assert_eq!(vault.list_deleted_secrets().unwrap().len(), 0);

    // The name is free again after a purge.
    set(&vault, "db", "fresh");
    assert_eq!(
        vault.get_secret("db", None).unwrap().value.expose(),
        b"fresh"
    );
}

#[test]
fn purgeable_vaults_delete_immediately() {
    let fx = Fixture::new();
    let vault = fx.create_vault_with(
        "scratch",
        CreateVaultOptions {
            recovery_level: RecoveryLevel::Purgeable,
            retention_days: 7,
        },
    );
    let props = set(&vault, "tmp", "x");
    assert_eq!(props.recovery_level, RecoveryLevel::Purgeable);
    let deleted = vault.delete_secret("tmp").unwrap();
    assert_eq!(deleted.recovery_id, "");
    assert_eq!(
        vault.get_secret("tmp", None).unwrap_err().code(),
        "not_found"
    );
    assert_eq!(vault.list_deleted_secrets().unwrap().len(), 0);
}

#[test]
fn names_and_options_are_validated() {
    let fx = Fixture::new();
    let vault = fx.create_vault("dev");
    for bad in [
        "",
        "has_underscore",
        "has space",
        "dots.no",
        &"x".repeat(128),
    ] {
        let err = vault
            .set_secret(bad, SecretBytes::from("v"), SetSecretOptions::default())
            .unwrap_err();
        assert_eq!(err.code(), "invalid_name", "{bad:?}");
    }
    assert_eq!(
        vault.get_secret("missing", None).unwrap_err().code(),
        "not_found"
    );
    set(&vault, "present", "v");
    assert_eq!(
        vault
            .get_secret("present", Some("nope"))
            .unwrap_err()
            .code(),
        "version_not_found"
    );

    let err = fx
        .registry
        .create(
            "bad-retention",
            CreateVaultOptions {
                recovery_level: RecoveryLevel::Recoverable,
                retention_days: 3,
            },
            ProtectorSpec::Passphrase {
                passphrase: SecretBytes::from(FIXTURE_PASSPHRASE),
                params: Argon2Params::TESTING,
            },
        )
        .unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    assert!(!fx.registry.exists("bad-retention"));
}

#[test]
fn audit_trail_records_every_operation_without_values() {
    let fx = Fixture::new();
    let vault = fx.create_vault("dev");
    let props = set(&vault, "k", "plaintext-value-123");
    vault.get_secret("k", None).unwrap();
    vault
        .update_secret_properties(
            "k",
            None,
            UpdateSecretProperties {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    let _ = vault.get_secret("k", None);
    let _ = vault.get_secret("missing", None);
    vault.list_properties_of_secrets().unwrap();

    let events = vault.audit_events(AuditQuery::default()).unwrap();
    let ops: Vec<(AuditOperation, AuditOutcome)> =
        events.iter().map(|e| (e.operation, e.outcome)).collect();
    assert!(ops.contains(&(AuditOperation::VaultCreate, AuditOutcome::Success)));
    assert!(ops.contains(&(AuditOperation::SecretSet, AuditOutcome::Success)));
    assert!(ops.contains(&(AuditOperation::SecretGet, AuditOutcome::Success)));
    assert!(ops.contains(&(AuditOperation::SecretUpdate, AuditOutcome::Success)));
    assert!(ops.contains(&(AuditOperation::SecretGet, AuditOutcome::Denied)));
    assert!(ops.contains(&(AuditOperation::SecretGet, AuditOutcome::Failure)));
    assert!(ops.contains(&(AuditOperation::SecretList, AuditOutcome::Success)));

    let denied = events
        .iter()
        .find(|e| e.operation == AuditOperation::SecretGet && e.outcome == AuditOutcome::Denied)
        .unwrap();
    assert_eq!(denied.detail.as_deref(), Some("disabled"));
    assert_eq!(denied.secret_name.as_deref(), Some("k"));

    let successful_get = events
        .iter()
        .find(|e| e.operation == AuditOperation::SecretGet && e.outcome == AuditOutcome::Success)
        .unwrap();
    assert_eq!(
        successful_get.version.as_deref(),
        Some(props.version.as_str())
    );

    // Newest first, and filters work.
    assert!(events.windows(2).all(|w| w[0].id > w[1].id));
    let only_gets = vault
        .audit_events(AuditQuery {
            operation: Some(AuditOperation::SecretGet),
            ..Default::default()
        })
        .unwrap();
    assert!(
        only_gets
            .iter()
            .all(|e| e.operation == AuditOperation::SecretGet)
    );
    let only_k = vault
        .audit_events(AuditQuery {
            secret_name: Some("k".into()),
            limit: Some(2),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(only_k.len(), 2);
    assert!(only_k.iter().all(|e| e.secret_name.as_deref() == Some("k")));

    let dump = serde_json::to_string(&events).unwrap();
    assert!(!dump.contains("plaintext-value-123"));
}

#[test]
fn protectors_can_be_added_and_removed() {
    let fx = Fixture::new();
    let vault = fx.create_vault("dev");
    set(&vault, "k", "v");

    let added = vault
        .add_protector(
            ProtectorSpec::Passphrase {
                passphrase: SecretBytes::from("second-passphrase"),
                params: Argon2Params::TESTING,
            },
            Some("ci"),
        )
        .unwrap();
    assert_eq!(added.label, "ci");
    assert_eq!(vault.protectors().unwrap().len(), 2);
    drop(vault);

    let via_second = fx
        .registry
        .open("dev", &StaticPassphrase::new("second-passphrase"))
        .unwrap();
    assert_eq!(
        via_second.get_secret("k", None).unwrap().value.expose(),
        b"v"
    );

    via_second.remove_protector("passphrase").unwrap();
    assert_eq!(via_second.protectors().unwrap().len(), 1);
    let err = via_second.remove_protector("ci").unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    drop(via_second);

    let err = fx
        .registry
        .open("dev", &StaticPassphrase::new(FIXTURE_PASSPHRASE))
        .unwrap_err();
    assert_eq!(err.code(), "locked");
    assert!(
        fx.registry
            .open("dev", &StaticPassphrase::new("second-passphrase"))
            .is_ok()
    );
}

#[test]
fn references_resolve_within_their_vault() {
    let fx = Fixture::new();
    let vault = fx.create_vault("dev");
    let v1 = set(&vault, "k", "one");
    set(&vault, "k", "two");

    let latest = SecretReference::parse("sourceorrery://dev/k").unwrap();
    assert_eq!(vault.resolve(&latest).unwrap().value.expose(), b"two");

    let pinned = latest.clone().with_version(v1.version.clone()).unwrap();
    assert_eq!(vault.resolve(&pinned).unwrap().value.expose(), b"one");

    let foreign = SecretReference::parse("sourceorrery://prod/k").unwrap();
    assert_eq!(
        vault.resolve(&foreign).unwrap_err().code(),
        "invalid_argument"
    );
}

#[test]
fn registry_lists_and_destroys_vaults() {
    let fx = Fixture::new();
    assert_eq!(fx.registry.list().unwrap().len(), 0);
    fx.create_vault("b-vault");
    fx.create_vault("a-vault");
    assert_eq!(fx.registry.list().unwrap(), vec!["a-vault", "b-vault"]);
    assert!(fx.registry.exists("a-vault"));

    let err = fx
        .registry
        .create(
            "a-vault",
            CreateVaultOptions::default(),
            ProtectorSpec::passphrase("x"),
        )
        .unwrap_err();
    assert_eq!(err.code(), "vault_exists");
    assert_eq!(
        fx.registry.vault_path("../escape").unwrap_err().code(),
        "invalid_name"
    );

    fx.registry.destroy("a-vault", false).unwrap();
    assert_eq!(fx.registry.list().unwrap(), vec!["b-vault"]);
    assert_eq!(
        fx.registry.destroy("a-vault", false).unwrap_err().code(),
        "vault_not_found"
    );
}

#[test]
fn reopening_preserves_everything() {
    let fx = Fixture::new();
    {
        let vault = fx.create_vault("dev");
        vault
            .set_secret(
                "k",
                SecretBytes::from("v"),
                SetSecretOptions {
                    content_type: Some("text/plain".into()),
                    tags: BTreeMap::from([("team".to_owned(), "platform".to_owned())]),
                    ..Default::default()
                },
            )
            .unwrap();
    }
    let vault = fx.open_vault("dev");
    let secret = vault.get_secret("k", None).unwrap();
    assert_eq!(secret.value.expose(), b"v");
    assert_eq!(
        secret.properties.content_type.as_deref(),
        Some("text/plain")
    );
    assert_eq!(secret.properties.tags["team"], "platform");
    let descriptor = vault.descriptor().unwrap();
    assert_eq!(descriptor.name, "dev");
    assert_eq!(descriptor.backend, "encrypted-sqlite");
    assert_eq!(descriptor.protectors, vec!["passphrase"]);
}

/// Every `SecretClient` operation adds exactly one audit event of its own
/// operation, success or failure, metadata reads included.
#[test]
#[allow(clippy::too_many_lines)] // one block per API operation, deliberately exhaustive
fn every_operation_leaves_exactly_one_audit_event() {
    let fx = Fixture::new();
    let vault = fx.create_vault("dev");
    let count = |vault: &sourceorrery_storage::SqliteVault| {
        vault
            .audit_events(AuditQuery {
                limit: Some(10_000),
                ..Default::default()
            })
            .unwrap()
            .len()
    };
    let newest = |vault: &sourceorrery_storage::SqliteVault| {
        vault
            .audit_events(AuditQuery {
                limit: Some(1),
                ..Default::default()
            })
            .unwrap()
            .remove(0)
    };
    let expect = |label: &str, op: AuditOperation, outcome: AuditOutcome, before: usize| {
        let after = count(&vault);
        assert_eq!(
            after,
            before + 1,
            "{label}: expected exactly one new audit event"
        );
        let event = newest(&vault);
        assert_eq!(
            (event.operation, event.outcome),
            (op, outcome),
            "{label}: {event:?}"
        );
    };

    let mut n = count(&vault);
    set(&vault, "k", "v");
    expect("set", AuditOperation::SecretSet, AuditOutcome::Success, n);
    n += 1;
    vault.get_secret_properties("k", None).unwrap();
    expect(
        "get_properties",
        AuditOperation::SecretInspect,
        AuditOutcome::Success,
        n,
    );
    n += 1;
    vault.list_properties_of_secret_versions("k").unwrap();
    expect(
        "versions",
        AuditOperation::SecretInspect,
        AuditOutcome::Success,
        n,
    );
    n += 1;
    assert!(vault.get_secret_properties("missing", None).is_err());
    expect(
        "get_properties missing",
        AuditOperation::SecretInspect,
        AuditOutcome::Failure,
        n,
    );
    n += 1;
    assert!(
        vault
            .list_properties_of_secret_versions("bad_name")
            .is_err()
    );
    let event = newest(&vault);
    assert_eq!(
        event.secret_name, None,
        "invalid names are not recorded: {event:?}"
    );
    expect(
        "versions invalid name",
        AuditOperation::SecretInspect,
        AuditOutcome::Failure,
        n,
    );
    n += 1;
    vault.get_secret("k", None).unwrap();
    expect("get", AuditOperation::SecretGet, AuditOutcome::Success, n);
    n += 1;
    vault.list_properties_of_secrets().unwrap();
    expect("list", AuditOperation::SecretList, AuditOutcome::Success, n);
    n += 1;
    vault.delete_secret("k").unwrap();
    expect(
        "delete",
        AuditOperation::SecretDelete,
        AuditOutcome::Success,
        n,
    );
    n += 1;
    vault.get_deleted_secret("k").unwrap();
    expect(
        "get_deleted",
        AuditOperation::SecretInspect,
        AuditOutcome::Success,
        n,
    );
    n += 1;
    vault.list_deleted_secrets().unwrap();
    expect(
        "list_deleted",
        AuditOperation::SecretList,
        AuditOutcome::Success,
        n,
    );
    n += 1;
    vault.recover_deleted_secret("k").unwrap();
    expect(
        "recover",
        AuditOperation::SecretRecover,
        AuditOutcome::Success,
        n,
    );
    n += 1;
    vault
        .update_secret_properties(
            "k",
            None,
            UpdateSecretProperties {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    expect(
        "update",
        AuditOperation::SecretUpdate,
        AuditOutcome::Success,
        n,
    );
    n += 1;
    vault.delete_secret("k").unwrap();
    n += 1;
    vault.purge_deleted_secret("k").unwrap();
    expect(
        "purge",
        AuditOperation::SecretPurge,
        AuditOutcome::Success,
        n,
    );
    n += 1;
    // Reading the log and verifying the chain are read-only.
    vault.verify_audit_chain().unwrap();
    assert_eq!(count(&vault), n, "verification must not write events");
}

#[test]
fn many_versions_are_listed_and_read_correctly() {
    // A sanity check, not a benchmark: a secret with a long history must
    // list newest first, summarise to its newest version and return any one
    // version by id, before and after a reopen.
    const VERSIONS: usize = 200;
    let fx = Fixture::new();
    let created: Vec<String> = {
        let vault = fx.create_vault("dev");
        let created: Vec<String> = (0..VERSIONS)
            .map(|i| set(&vault, "rotated", &format!("value-{i}")).version)
            .collect();

        let listed = vault.list_properties_of_secret_versions("rotated").unwrap();
        assert_eq!(listed.len(), VERSIONS);
        let listed_ids: Vec<&str> = listed.iter().map(|p| p.version.as_str()).collect();
        let newest_first: Vec<&str> = created.iter().rev().map(String::as_str).collect();
        assert_eq!(listed_ids, newest_first);

        let summary = vault.list_properties_of_secrets().unwrap();
        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0].version, created[VERSIONS - 1]);

        let latest = vault.get_secret("rotated", None).unwrap();
        assert_eq!(latest.properties.version, created[VERSIONS - 1]);
        assert_eq!(
            latest.value.expose(),
            format!("value-{}", VERSIONS - 1).as_bytes()
        );
        created
    };

    let vault = fx.open_vault("dev");
    assert_eq!(
        vault
            .list_properties_of_secret_versions("rotated")
            .unwrap()
            .len(),
        VERSIONS
    );
    for i in [0, 1, VERSIONS / 2, VERSIONS - 2, VERSIONS - 1] {
        let version = created[i].as_str();
        let got = vault.get_secret("rotated", Some(version)).unwrap();
        assert_eq!(got.properties.version, version);
        assert_eq!(got.value.expose(), format!("value-{i}").as_bytes());
        let props = vault
            .get_secret_properties("rotated", Some(version))
            .unwrap();
        assert_eq!(props.version, version);
    }
}
