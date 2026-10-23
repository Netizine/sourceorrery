//! Lifecycle conformance: the semantics every `SecretClient` must honour.
//!
//! The backend-independent scenarios live in `sourceorrery_conformance::
//! lifecycle` and run here against the SQLite vault, directly and through
//! the `Blocking<AsyncLocal<_>>` adapter pair. The tests in this file are
//! what the local vault adds on top: version-id shape, purgeable vaults,
//! the audit log, protectors, the registry, reopening and backups. Together
//! they are the reference for every SDK binding: if a binding cannot pass
//! the equivalent of each scenario, it does not implement SourceOrrery.

use std::collections::BTreeMap;

use sourceorrery_conformance::lifecycle::{self, seed_paged, set, walk_pages};
use sourceorrery_conformance::{FIXTURE_PASSPHRASE, Fixture};
use sourceorrery_core::{
    AuditOperation, AuditOutcome, AuditQuery, ContinuationToken, ExportOptions, ListOptions,
    RESTORED_CREATED_ON_TAG, RESTORED_FROM_TAG, RecoveryLevel, RestoreOptions, SecretBytes,
    SecretClient, SetSecretOptions, SkipReason, UpdateSecretProperties, VaultBackup, timestamp,
};
use sourceorrery_crypto::Argon2Params;
use sourceorrery_provider::{AsyncLocal, Blocking};
use sourceorrery_storage::backup;
use sourceorrery_storage::{CreateVaultOptions, ProtectorSpec, SqliteVault, StaticPassphrase};

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

fn count_events(vault: &impl SecretClient, op: AuditOperation, outcome: AuditOutcome) -> usize {
    vault
        .audit_events(AuditQuery::default())
        .unwrap()
        .into_iter()
        .filter(|e| e.operation == op && e.outcome == outcome)
        .count()
}

/// A vault worth backing up: `db-password` with three versions, the middle
/// one disabled with a content type, tags and a window (which `get` would
/// refuse, a backup must still carry); `api-key`; and `gone`, deleted.
/// Returns the vault and the disabled version's properties.
fn vault_to_back_up(fx: &Fixture) -> (SqliteVault, sourceorrery_core::SecretProperties) {
    let source = fx.create_vault("dev");
    set(&source, "db-password", "one");
    let disabled = source
        .set_secret(
            "db-password",
            SecretBytes::from("two"),
            SetSecretOptions {
                content_type: Some("text/plain".into()),
                tags: BTreeMap::from([("env".to_owned(), "ci".to_owned())]),
                enabled: false,
                not_before: Some(timestamp::parse("2020-01-01T00:00:00Z").unwrap()),
                expires_on: Some(timestamp::parse("2100-01-01T00:00:00Z").unwrap()),
            },
        )
        .unwrap();
    set(&source, "db-password", "three");
    set(&source, "api-key", "k");
    set(&source, "gone", "x");
    source.delete_secret("gone").unwrap();
    (source, disabled)
}

fn everything() -> ExportOptions {
    ExportOptions {
        secrets: None,
        include_deleted: true,
    }
}

#[test]
fn export_reads_every_version_whatever_its_policy_and_is_audited_per_secret() {
    let fx = Fixture::new();
    let (source, disabled) = vault_to_back_up(&fx);

    // Live secrets only by default; deleted ones on request.
    let live = source.export(&ExportOptions::default()).unwrap();
    let names: Vec<&str> = live.secrets.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["api-key", "db-password"], "name order, live only");
    let snapshot = source.export(&everything()).unwrap();
    assert_eq!(snapshot.secrets.len(), 3);
    assert_eq!(snapshot.vault, "dev");
    assert_eq!(snapshot.version_count(), 5);
    let db = snapshot
        .secrets
        .iter()
        .find(|s| s.name == "db-password")
        .unwrap();
    let values: Vec<&[u8]> = db.versions.iter().map(|v| v.value.expose()).collect();
    assert_eq!(
        values,
        [b"one".as_slice(), b"two", b"three"],
        "oldest first, disabled included"
    );
    assert_eq!(db.versions[1].version, disabled.version);
    assert!(!db.versions[1].enabled);
    assert_eq!(db.versions[1].content_type.as_deref(), Some("text/plain"));
    assert_eq!(db.versions[1].tags["env"], "ci");
    assert_eq!(db.versions[1].not_before, disabled.not_before);
    let gone = snapshot.secrets.iter().find(|s| s.name == "gone").unwrap();
    assert!(gone.deleted.is_some());
    // One `vault_backup` event per secret exported.
    assert_eq!(
        count_events(&source, AuditOperation::VaultBackup, AuditOutcome::Success),
        2 + 3
    );
    let only = source
        .export(&ExportOptions {
            secrets: Some(vec!["api-key".into()]),
            include_deleted: false,
        })
        .unwrap();
    assert_eq!(only.secrets.len(), 1);
    assert_eq!(
        source
            .export(&ExportOptions {
                secrets: Some(vec!["nope".into()]),
                include_deleted: false,
            })
            .unwrap_err()
            .code(),
        "not_found"
    );
}

#[test]
fn backup_round_trip_restores_every_version_with_its_metadata() {
    let fx = Fixture::new();
    let (source, disabled) = vault_to_back_up(&fx);
    let snapshot = source.export(&everything()).unwrap();

    let passphrase = SecretBytes::from("backup-passphrase");
    let bytes = backup::seal(&snapshot, &passphrase, Argon2Params::TESTING).unwrap();
    let info = backup::inspect(&bytes).unwrap();
    assert_eq!(
        (info.vault.as_str(), info.format),
        ("dev", backup::BACKUP_FORMAT)
    );
    let from_file = backup::open(&bytes, &passphrase).unwrap();
    let target = fx.create_vault("copy");
    let report = target
        .restore(&from_file, &RestoreOptions::default())
        .unwrap();
    assert_eq!(report.skipped, vec![]);
    let restored: Vec<(&str, usize, bool)> = report
        .restored
        .iter()
        .map(|r| (r.name.as_str(), r.versions, r.deleted))
        .collect();
    assert_eq!(
        restored,
        [
            ("api-key", 1, false),
            ("db-password", 3, false),
            ("gone", 1, false)
        ]
    );

    // Newest stays newest; the disabled version is still disabled with its
    // metadata; every version remembers where it came from.
    let newest = target.get_secret("db-password", None).unwrap();
    assert_eq!(newest.value.expose(), b"three");
    let versions = target
        .list_properties_of_secret_versions("db-password")
        .unwrap();
    assert_eq!(versions.len(), 3);
    let middle = &versions[1];
    assert!(!middle.enabled);
    assert_eq!(middle.content_type.as_deref(), Some("text/plain"));
    assert_eq!(middle.tags["env"], "ci");
    assert_eq!(middle.tags[RESTORED_FROM_TAG], disabled.version);
    assert_eq!(
        middle.tags[RESTORED_CREATED_ON_TAG],
        timestamp::format(disabled.created_on)
    );
    assert_ne!(
        middle.version, disabled.version,
        "a restored version is a new version"
    );
    assert_eq!(
        target
            .get_secret("db-password", Some(&middle.version))
            .unwrap_err()
            .code(),
        "disabled"
    );
    assert_eq!(
        target.get_secret("gone", None).unwrap().value.expose(),
        b"x"
    );
    assert_eq!(
        count_events(
            &target,
            AuditOperation::SecretRestore,
            AuditOutcome::Success
        ),
        5
    );
    assert!(target.verify_audit_chain().unwrap().is_intact());
}

#[test]
fn restore_skips_existing_secrets_adds_on_request_and_can_keep_deleted() {
    let fx = Fixture::new();
    let (source, _) = vault_to_back_up(&fx);
    let snapshot = source.export(&everything()).unwrap();
    let target = fx.create_vault("copy");
    target
        .restore(&snapshot, &RestoreOptions::default())
        .unwrap();

    // Restoring again skips what exists; `overwrite` adds versions on top.
    let again = target
        .restore(&snapshot, &RestoreOptions::default())
        .unwrap();
    assert_eq!(again.restored, vec![]);
    assert_eq!(again.skipped.len(), 3);
    assert!(again.skipped.iter().all(|s| s.reason == SkipReason::Exists));
    let over = target
        .restore(
            &snapshot,
            &RestoreOptions {
                only: Some(vec!["api-key".into()]),
                overwrite: true,
                keep_deleted: false,
            },
        )
        .unwrap();
    assert_eq!(over.restored.len(), 1);
    assert_eq!(
        target
            .list_properties_of_secret_versions("api-key")
            .unwrap()
            .len(),
        2
    );

    // `keep_deleted` puts a deleted secret back into the deleted state, and
    // a deleted name in the target is never written to.
    let fresh = fx.create_vault("fresh");
    let kept = fresh
        .restore(
            &snapshot,
            &RestoreOptions {
                only: Some(vec!["gone".into()]),
                overwrite: false,
                keep_deleted: true,
            },
        )
        .unwrap();
    assert!(kept.restored[0].deleted);
    assert_eq!(
        fresh.get_secret("gone", None).unwrap_err().code(),
        "deleted"
    );
    assert_eq!(fresh.list_deleted_secrets().unwrap().len(), 1);
    let blocked = fresh
        .restore(
            &snapshot,
            &RestoreOptions {
                only: Some(vec!["gone".into()]),
                overwrite: true,
                keep_deleted: false,
            },
        )
        .unwrap();
    assert_eq!(blocked.skipped[0].reason, SkipReason::Deleted);
    assert_eq!(blocked.restored, vec![]);
}
