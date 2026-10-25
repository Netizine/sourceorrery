//! Lifecycle conformance: the semantics every `SecretClient` must honour.
//!
//! The backend-independent scenarios live in `sourceorrery_conformance::
//! lifecycle` and run here against the SQLite vault, directly and through
//! the `Blocking<AsyncLocal<_>>` adapter pair. The tests in this file are
//! what the local vault adds on top: version-id shape, purgeable vaults,
//! the audit log, its keys, the registry and reopening. Together
//! they are the reference for every SDK binding: if a binding cannot pass
//! the equivalent of each scenario, it does not implement SourceOrrery.

use std::collections::BTreeMap;
use std::sync::Arc;

use sourceorrery_conformance::Fixture;
use sourceorrery_conformance::lifecycle::{self, seed_paged, set, walk_pages};
use sourceorrery_core::{
    AuditOperation, AuditOutcome, AuditQuery, ContinuationToken, ListOptions, RecoveryLevel,
    SecretBytes, SecretClient, SetSecretOptions, UpdateSecretProperties,
};
use sourceorrery_provider::{AsyncLocal, Blocking};
use sourceorrery_storage::{
    CreateVaultOptions, MemoryStore, NoInteraction, StaticRecoveryKey, VaultRegistry,
};

/// The lifecycle scenarios, each on a fresh vault.
#[test]
fn sqlite_vault_passes_the_lifecycle_scenarios() {
    let fx = Fixture::new();
    let mut n = 0;
    lifecycle::lifecycle(&mut |_| {
        n += 1;
        Box::new(fx.create_vault(&format!("scenario-{n}")))
    });
}

/// The same scenarios through `Blocking<AsyncLocal<SqliteVault>>`: the
/// adapter pair of `sourceorrery-provider` is proven on the local vault
/// before any remote provider uses it.
#[test]
fn the_adapter_pair_passes_the_lifecycle_scenarios() {
    let fx = Fixture::new();
    let mut n = 0;
    lifecycle::lifecycle(&mut |_| {
        n += 1;
        let vault = fx.create_vault(&format!("adapted-{n}"));
        Box::new(Blocking::new(AsyncLocal::new(vault)).expect("runtime"))
    });
}

#[test]
fn version_ids_are_32_hex_characters() {
    let fx = Fixture::new();
    let vault = fx.create_vault("dev");
    let v1 = set(&vault, "db-password", "one");
    assert_eq!(v1.version.len(), 32);
    assert!(v1.version.bytes().all(|b| b.is_ascii_hexdigit()));
}

/// Every page is one `secret_list` event, successes and failures alike,
/// and a rejected request is recorded before anything is read.
#[test]
fn every_page_is_one_audited_listing() {
    let fx = Fixture::new();
    let vault = fx.create_vault("dev");
    seed_paged(&vault);
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
    let (_, pages) = walk_pages(&vault, 7, false);
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
}

#[test]
fn vault_retention_is_validated() {
    let fx = Fixture::new();
    let err = fx
        .registry
        .create(
            "bad-retention",
            CreateVaultOptions {
                recovery_level: RecoveryLevel::Recoverable,
                retention_days: 3,
                ..CreateVaultOptions::default()
            },
        )
        .unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    assert!(!fx.registry.exists("bad-retention"));
}

#[test]
fn many_versions_survive_a_reopen() {
    const VERSIONS: usize = 200;
    let fx = Fixture::new();
    let created: Vec<String> = {
        let vault = fx.create_vault("dev");
        (0..VERSIONS)
            .map(|i| set(&vault, "rotated", &format!("value-{i}")).version)
            .collect()
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
    }
}

#[test]
fn purgeable_vaults_delete_immediately() {
    let fx = Fixture::new();
    let vault = fx.create_vault_with(
        "scratch",
        CreateVaultOptions {
            recovery_level: RecoveryLevel::Purgeable,
            retention_days: 7,
            ..CreateVaultOptions::default()
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

/// A replaced recovery key opens the vault and the one before it no longer
/// does; the vault's keys are listed by kind, never by value.
#[test]
fn the_recovery_key_can_be_replaced() {
    let fx = Fixture::new();
    let vault = fx.create_vault("dev");
    set(&vault, "k", "v");
    let kinds: Vec<String> = vault.wraps().unwrap().into_iter().map(|w| w.kind).collect();
    assert_eq!(
        kinds,
        ["recovery"],
        "no credential store: the recovery key only"
    );

    let new_key = vault.replace_recovery_key().unwrap();
    assert_eq!(vault.wraps().unwrap().len(), 1);
    drop(vault);

    let err = fx.registry.open("dev", &fx.unlock("dev")).unwrap_err();
    assert_eq!(
        err.code(),
        "locked",
        "the replaced key still opens the vault"
    );
    let reopened = fx
        .registry
        .open("dev", &StaticRecoveryKey::new(new_key.as_str()))
        .unwrap();
    assert_eq!(reopened.get_secret("k", None).unwrap().value.expose(), b"v");
}

/// With a credential store, the vault opens on this machine without being
/// asked anything, and with its recovery key where the store's key is gone.
#[test]
fn this_machine_opens_the_vault_without_asking() {
    let fx = Fixture::new();
    let store = Arc::new(MemoryStore::new());
    let registry = VaultRegistry::with_root(fx.home.path()).with_store(store.clone());
    let created = registry
        .create("dev", CreateVaultOptions::default())
        .unwrap();
    assert!(created.this_machine);
    set(&created.vault, "k", "v");
    let kinds: Vec<String> = created
        .vault
        .wraps()
        .unwrap()
        .into_iter()
        .map(|w| w.kind)
        .collect();
    assert_eq!(kinds.len(), 2);
    assert!(kinds.iter().any(|k| k == "this-machine"));
    assert!(kinds.iter().any(|k| k == "recovery"));
    let key = created.recovery_key.to_string();
    drop(created);

    let opened = registry.open("dev", &NoInteraction).unwrap();
    assert_eq!(opened.get_secret("k", None).unwrap().value.expose(), b"v");
    drop(opened);

    // Another machine (no store) is asked for the recovery key.
    let elsewhere = VaultRegistry::with_root(fx.home.path())
        .with_store(Arc::new(sourceorrery_storage::NoStore));
    assert_eq!(
        elsewhere.open("dev", &NoInteraction).unwrap_err().code(),
        "locked"
    );
    assert!(elsewhere.open("dev", &StaticRecoveryKey::new(key)).is_ok());
    assert_eq!(store.accounts().len(), 1);
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
        .create("a-vault", CreateVaultOptions::default())
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
    assert_eq!(descriptor.protectors, vec!["recovery"]);
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
