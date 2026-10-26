//! Security conformance: what must never happen.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Barrier};

use sourceorrery_conformance::Fixture;
use sourceorrery_core::{
    AuditEvent, AuditOperation, AuditOutcome, AuditQuery, ContinuationToken, ListOptions, Manifest,
    SecretBytes, SecretClient, SetSecretOptions, UpdateSecretProperties, timestamp,
};
use sourceorrery_crypto::Argon2Params;
use sourceorrery_storage::{
    CreateVaultOptions, CredentialStore, MemoryStore, NoInteraction, NoStore, SqliteVault,
    StaticRecoveryKey, VaultRegistry,
};
use time::Duration;

/// No credential store: a test never touches the real OS store, and these
/// vaults open with their recovery keys.
fn no_store() -> Arc<dyn CredentialStore> {
    Arc::new(NoStore)
}

const CANARY: &str = "CANARY-7f3a9c2e-plaintext-must-never-appear";

fn canary_bytes() -> Vec<u8> {
    CANARY.as_bytes().to_vec()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn vault_file_never_contains_plaintext_or_the_recovery_key() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    {
        let vault = fx.create_vault("dev");
        vault
            .set_secret(
                "canary",
                SecretBytes::from(CANARY),
                SetSecretOptions::default(),
            )
            .unwrap();
        vault
            .set_secret(
                "canary",
                SecretBytes::from(CANARY),
                SetSecretOptions::default(),
            )
            .unwrap();
        vault.get_secret("canary", None).unwrap();
        vault.delete_secret("canary").unwrap();
        vault.recover_deleted_secret("canary").unwrap();
    }
    let bytes = std::fs::read(&path).unwrap();
    assert!(
        bytes.len() > 4096,
        "vault file should be a populated SQLite database"
    );
    assert!(
        !contains(&bytes, &canary_bytes()),
        "plaintext found in vault file"
    );
    let key = fx.recovery_key("dev");
    let folded: String = key.chars().filter(char::is_ascii_alphanumeric).collect();
    assert!(
        !contains(&bytes, key.as_bytes()) && !contains(&bytes, folded.as_bytes()),
        "recovery key found in vault file"
    );
    // Also check UTF-16LE, in case a platform API re-encoded the value.
    let utf16: Vec<u8> = CANARY.encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert!(!contains(&bytes, &utf16));
}

#[test]
fn audit_log_and_errors_never_contain_values() {
    let fx = Fixture::new();
    let vault = fx.create_vault("dev");
    vault
        .set_secret(
            "canary",
            SecretBytes::from(CANARY),
            SetSecretOptions::default(),
        )
        .unwrap();
    vault.get_secret("canary", None).unwrap();
    let err = vault.get_secret("canary", Some("deadbeef")).unwrap_err();
    assert!(!err.to_string().contains(CANARY));
    let err = vault
        .set_secret(
            "bad_name",
            SecretBytes::from(CANARY),
            SetSecretOptions::default(),
        )
        .unwrap_err();
    assert!(!err.to_string().contains(CANARY));

    let events = vault.audit_events(AuditQuery::default()).unwrap();
    let dump = serde_json::to_string(&events).unwrap();
    assert!(!dump.contains(CANARY));
    assert!(!dump.contains(&fx.recovery_key("dev")));
}

#[test]
fn debug_output_redacts_values() {
    let fx = Fixture::new();
    let vault = fx.create_vault("dev");
    vault
        .set_secret(
            "canary",
            SecretBytes::from(CANARY),
            SetSecretOptions::default(),
        )
        .unwrap();
    let secret = vault.get_secret("canary", None).unwrap();
    let dbg = format!("{secret:?}");
    assert!(!dbg.contains(CANARY));
    assert!(dbg.contains("REDACTED"));
    assert!(!format!("{vault:?}").contains(CANARY));
}

#[test]
fn ciphertext_moved_between_records_is_rejected() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    {
        let vault = fx.create_vault("dev");
        vault
            .set_secret(
                "alpha",
                SecretBytes::from("alpha-value"),
                SetSecretOptions::default(),
            )
            .unwrap();
        vault
            .set_secret(
                "beta",
                SecretBytes::from("beta-value"),
                SetSecretOptions::default(),
            )
            .unwrap();
    }

    // Copy beta's ciphertext+nonce over alpha's row: same key, valid AEAD
    // output, wrong location. AAD binding must make this fail.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE secret_versions
             SET nonce = (SELECT nonce FROM secret_versions WHERE name = 'beta'),
                 ciphertext = (SELECT ciphertext FROM secret_versions WHERE name = 'beta')
             WHERE name = 'alpha'",
            [],
        )
        .unwrap();
    }

    let vault = fx.open_vault("dev");
    let err = vault.get_secret("alpha", None).unwrap_err();
    assert_eq!(err.code(), "crypto");
    assert_eq!(
        vault.get_secret("beta", None).unwrap().value.expose(),
        b"beta-value"
    );
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    {
        let vault = fx.create_vault("dev");
        vault
            .set_secret(
                "alpha",
                SecretBytes::from("alpha-value"),
                SetSecretOptions::default(),
            )
            .unwrap();
    }
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let mut blob: Vec<u8> = conn
            .query_row(
                "SELECT ciphertext FROM secret_versions WHERE name = 'alpha'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        blob[0] ^= 0x01;
        conn.execute(
            "UPDATE secret_versions SET ciphertext = ?1 WHERE name = 'alpha'",
            [blob],
        )
        .unwrap();
    }
    let vault = fx.open_vault("dev");
    assert_eq!(
        vault.get_secret("alpha", None).unwrap_err().code(),
        "crypto"
    );
}

#[test]
fn wrong_recovery_key_is_refused_and_recorded() {
    let fx = Fixture::new();
    fx.create_vault("dev");
    let err = fx
        .registry
        .open("dev", &StaticRecoveryKey::new("not-the-recovery-key"))
        .unwrap_err();
    assert_eq!(err.code(), "locked");

    let vault = fx.open_vault("dev");
    let events = vault.audit_events(AuditQuery::default()).unwrap();
    let denied = events
        .iter()
        .filter(|e| {
            e.operation == sourceorrery_core::AuditOperation::VaultOpen
                && e.outcome == sourceorrery_core::AuditOutcome::Denied
        })
        .count();
    assert!(denied >= 1, "failed unlock attempts must be audited");
}

#[test]
fn manifest_cannot_smuggle_a_value() {
    let text =
        format!("[project]\nname = \"x\"\nvault = \"dev\"\n\n[secrets.db]\nvalue = \"{CANARY}\"\n");
    assert!(Manifest::parse(&text).is_err());
    let text = format!(
        "[project]\nname = \"x\"\nvault = \"dev\"\n\n[secrets.db]\npurpose = \"ok\"\n\n[values]\ndb = \"{CANARY}\"\n"
    );
    assert!(Manifest::parse(&text).is_err());
}

// ---------------------------------------------------------------------------
// Metadata integrity (schema 2): plaintext metadata is authenticated
// ---------------------------------------------------------------------------

/// Create a vault, let `setup` populate it, run `sql` against the closed
/// file as an attacker with write access would, and re-open it.
fn tampered(fx: &Fixture, setup: impl FnOnce(&SqliteVault), sql: &str) -> SqliteVault {
    let path = fx.registry.vault_path("dev").unwrap();
    {
        let vault = fx.create_vault("dev");
        setup(&vault);
    }
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(sql).unwrap();
    }
    fx.open_vault("dev")
}

fn set_with(vault: &SqliteVault, name: &str, value: &str, options: SetSecretOptions) {
    vault
        .set_secret(name, SecretBytes::from(value), options)
        .unwrap();
}

fn events_of(vault: &SqliteVault, op: AuditOperation, outcome: AuditOutcome) -> Vec<AuditEvent> {
    vault
        .audit_events(AuditQuery::default())
        .unwrap()
        .into_iter()
        .filter(|e| e.operation == op && e.outcome == outcome)
        .collect()
}

#[test]
fn re_enabled_version_is_rejected() {
    let fx = Fixture::new();
    let vault = tampered(
        &fx,
        |v| {
            set_with(
                v,
                "k",
                CANARY,
                SetSecretOptions {
                    enabled: false,
                    ..Default::default()
                },
            );
        },
        "UPDATE secret_versions SET enabled = 1 WHERE name = 'k'",
    );
    let err = vault.get_secret("k", None).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert!(err.to_string().contains("integrity"), "{err}");
    assert!(!err.to_string().contains(CANARY));

    // Metadata-only reads refuse the row too.
    assert_eq!(
        vault.get_secret_properties("k", None).unwrap_err().code(),
        "crypto"
    );
    assert_eq!(
        vault
            .list_properties_of_secret_versions("k")
            .unwrap_err()
            .code(),
        "crypto"
    );
    assert_eq!(
        vault.list_properties_of_secrets().unwrap_err().code(),
        "crypto"
    );

    // Every refusal is on the record, and the record itself is intact.
    let mut failures = events_of(&vault, AuditOperation::SecretGet, AuditOutcome::Failure);
    failures.extend(events_of(
        &vault,
        AuditOperation::SecretInspect,
        AuditOutcome::Failure,
    ));
    failures.extend(events_of(
        &vault,
        AuditOperation::SecretList,
        AuditOutcome::Failure,
    ));
    assert!(failures.len() >= 4, "{failures:?}");
    assert!(
        failures
            .iter()
            .all(|e| e.detail.as_deref() == Some("crypto") && !format!("{e:?}").contains(CANARY))
    );
    assert!(vault.verify_audit_chain().unwrap().is_intact());
}

#[test]
fn extended_expiry_is_rejected() {
    let fx = Fixture::new();
    let vault = tampered(
        &fx,
        |v| {
            set_with(
                v,
                "k",
                "v",
                SetSecretOptions {
                    expires_on: Some(timestamp::now() + Duration::hours(1)),
                    ..Default::default()
                },
            );
        },
        // One day later, in nanoseconds.
        "UPDATE secret_versions SET expires_on = expires_on + 86400000000000 WHERE name = 'k'",
    );
    assert_eq!(vault.get_secret("k", None).unwrap_err().code(), "crypto");
}

#[test]
fn edited_not_before_or_tags_are_rejected() {
    let fx = Fixture::new();
    let vault = tampered(
        &fx,
        |v| {
            set_with(
                v,
                "k",
                "v",
                SetSecretOptions {
                    not_before: Some(timestamp::now() + Duration::hours(1)),
                    ..Default::default()
                },
            );
        },
        "UPDATE secret_versions SET not_before = NULL WHERE name = 'k'",
    );
    assert_eq!(vault.get_secret("k", None).unwrap_err().code(), "crypto");

    let fx = Fixture::new();
    let vault = tampered(
        &fx,
        |v| {
            set_with(
                v,
                "k",
                "v",
                SetSecretOptions {
                    tags: BTreeMap::from([("env".to_owned(), "test".to_owned())]),
                    ..Default::default()
                },
            );
        },
        "UPDATE secret_versions SET tags_json = '{\"env\":\"production\"}' WHERE name = 'k'",
    );
    assert_eq!(
        vault.get_secret_properties("k", None).unwrap_err().code(),
        "crypto"
    );
}

#[test]
fn undeleted_secret_is_rejected() {
    let fx = Fixture::new();
    let vault = tampered(
        &fx,
        |v| {
            set_with(v, "k", CANARY, SetSecretOptions::default());
            v.delete_secret("k").unwrap();
        },
        "UPDATE secrets SET deleted_on = NULL, scheduled_purge_on = NULL, recovery_id = NULL
         WHERE name = 'k'",
    );
    let err = vault.get_secret("k", None).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert_eq!(
        vault.list_properties_of_secrets().unwrap_err().code(),
        "crypto"
    );
    assert_eq!(
        vault.recover_deleted_secret("k").unwrap_err().code(),
        "crypto"
    );
}

#[test]
fn faked_deletion_is_neither_honoured_nor_purged() {
    // Marking a live secret as deleted with a purge time in the past would
    // otherwise have the vault purge it on open and blame "retention".
    let fx = Fixture::new();
    let vault = tampered(
        &fx,
        |v| set_with(v, "k", "v", SetSecretOptions::default()),
        "UPDATE secrets SET deleted_on = 1, scheduled_purge_on = 2,
             recovery_id = 'sourceorrery://dev/deletedsecrets/k' WHERE name = 'k'",
    );
    assert_eq!(vault.get_secret("k", None).unwrap_err().code(), "crypto");
    assert_eq!(
        vault.get_deleted_secret("k").unwrap_err().code(),
        "crypto",
        "a forged deletion must not be served as a real one"
    );
    assert!(
        events_of(&vault, AuditOperation::SecretPurge, AuditOutcome::Success).is_empty(),
        "nothing may be purged on the strength of unauthenticated metadata"
    );
    assert_eq!(
        events_of(&vault, AuditOperation::SecretPurge, AuditOutcome::Failure).len(),
        1
    );
}

#[test]
fn swapped_version_rows_are_rejected() {
    // Give the disabled old version the enabled new version's flags by
    // copying whole columns across rows: each tag binds its own row.
    let fx = Fixture::new();
    let vault = tampered(
        &fx,
        |v| {
            set_with(
                v,
                "k",
                "old",
                SetSecretOptions {
                    enabled: false,
                    ..Default::default()
                },
            );
            set_with(v, "k", "new", SetSecretOptions::default());
        },
        "UPDATE secret_versions
         SET enabled = 1,
             tag = (SELECT tag FROM secret_versions WHERE name = 'k' AND seq = 2)
         WHERE name = 'k' AND seq = 1",
    );
    assert_eq!(vault.get_secret("k", None).unwrap_err().code(), "crypto");
}

// ---------------------------------------------------------------------------
// Audit log integrity: the keyed hash chain
// ---------------------------------------------------------------------------

/// Ids of every audit event, oldest first.
fn event_ids(vault: &SqliteVault) -> Vec<u64> {
    let mut ids: Vec<u64> = vault
        .audit_events(AuditQuery::default())
        .unwrap()
        .iter()
        .map(|e| e.id)
        .collect();
    ids.sort_unstable();
    ids
}

#[test]
fn fresh_vault_chain_is_intact_and_counts_unkeyed_rows() {
    let fx = Fixture::new();
    {
        let vault = fx.create_vault("dev");
        set_with(&vault, "k", "v", SetSecretOptions::default());
        vault.get_secret("k", None).unwrap();
    }
    // Two rows written before unlock: the denied attempt and the failure.
    assert!(
        fx.registry
            .open("dev", &StaticRecoveryKey::new("wrong"))
            .is_err()
    );
    let vault = fx.open_vault("dev");
    let check = vault.verify_audit_chain().unwrap();
    assert!(check.is_intact(), "{check:?}");
    assert_eq!(check.unkeyed, 2);
    assert_eq!(check.rows, check.keyed + check.unkeyed);
    assert_eq!(check.truncations, 0);
    assert!(check.head_valid);
    assert_eq!(check.first_broken, None);
}

/// A row removed from the middle of the log leaves the head naming the
/// newest row, so the head alone would not notice. The unlock walks the
/// chain, finds the row after the gap no longer following its
/// predecessor, records the break and blocks the vault like a truncation.
#[test]
fn deleted_middle_audit_row_is_detected_at_unlock() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    let ids = {
        let vault = fx.create_vault("dev");
        set_with(&vault, "k", "v", SetSecretOptions::default());
        vault.get_secret("k", None).unwrap();
        set_with(&vault, "k2", "v", SetSecretOptions::default());
        event_ids(&vault)
    };
    assert!(ids.len() >= 4);
    let victim = i64::try_from(ids[1]).unwrap();
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("DELETE FROM audit_events WHERE id = ?1", [victim])
            .unwrap();
    }
    let unlock = fx.unlock("dev");
    let err = fx.registry.open("dev", &unlock).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert_blocked(&fx.registry.open("dev", &unlock).unwrap_err());
    let vault = fx.inspect_vault("dev");
    let check = vault.verify_audit_chain().unwrap();
    assert!(!check.is_intact());
    assert_eq!(
        check.first_broken,
        Some(ids[2]),
        "the row after the gap no longer links to its predecessor: {check:?}"
    );
    assert_eq!(check.truncations, 1, "{check:?}");
    assert_eq!(check.unacknowledged, 1, "{check:?}");
    assert!(check.head_valid, "the detection re-anchored the head");
    assert_blocked(&vault.get_secret("k2", None).unwrap_err());
    drop(vault);

    // Acknowledged, the vault serves again. The break stays on record,
    // and the secret whose checkpoint was removed is refused: no checkpoint
    // means no row state can be judged, not "take the row as found".
    fx.acknowledge_truncations("dev");
    let vault = fx.open_vault("dev");
    vault.get_secret("k2", None).unwrap();
    assert_eq!(vault.get_secret("k", None).unwrap_err().code(), "crypto");
    let check = vault.verify_audit_chain().unwrap();
    assert_eq!(check.first_broken, Some(ids[2]), "{check:?}");
    assert_eq!(check.unacknowledged, 0, "{check:?}");
}

/// Removing the record of a detected truncation does not lift the block:
/// the row written after it no longer follows its predecessor, and the
/// head's count of keyed rows is one short.
#[test]
fn deleting_the_truncation_record_is_detected_as_another_break() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    let ids = {
        let vault = fx.create_vault("dev");
        set_with(&vault, "k", "v", SetSecretOptions::default());
        vault.get_secret("k", None).unwrap();
        vault.get_secret("k", None).unwrap();
        event_ids(&vault)
    };
    truncate_after(&path, ids[ids.len() - 3]);
    let unlock = fx.unlock("dev");
    assert_eq!(
        fx.registry.open("dev", &unlock).unwrap_err().code(),
        "crypto"
    );
    let detection = {
        let vault = fx.inspect_vault("dev");
        events_of(&vault, AuditOperation::AuditVerify, AuditOutcome::Failure)[0].id
    };
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "DELETE FROM audit_events WHERE id = ?1",
            [i64::try_from(detection).unwrap()],
        )
        .unwrap();
    }
    let err = fx.registry.open("dev", &unlock).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert!(
        err.to_string()
            .contains("removed or altered inside the log")
            || err.to_string().contains("audit chain broken"),
        "{err}"
    );
    let vault = fx.inspect_vault("dev");
    let check = vault.verify_audit_chain().unwrap();
    assert!(check.unacknowledged >= 1, "{check:?}");
    assert_blocked(&vault.get_secret("k", None).unwrap_err());
}

/// A version's checkpoint row removed from the middle of the log, with the
/// version itself: without the walk the previous version would come back as
/// current without a trace. With it the unlock is refused and the break is
/// on record. Once the owner has acknowledged it, the surviving history is
/// what the vault goes by (known gap 6): the older version is served then,
/// as the record shows.
#[test]
fn deleting_a_versions_checkpoint_row_refuses_the_unlock() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    let (newest_row, newest_version) = {
        let vault = fx.create_vault("dev");
        set_with(&vault, "k", "one", SetSecretOptions::default());
        let newest = vault
            .set_secret("k", SecretBytes::from("two"), SetSecretOptions::default())
            .unwrap()
            .version;
        let row = events_of(&vault, AuditOperation::SecretSet, AuditOutcome::Success)[0].id;
        (row, newest)
    };
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "DELETE FROM audit_events WHERE id = ?1",
            [i64::try_from(newest_row).unwrap()],
        )
        .unwrap();
        conn.execute(
            "DELETE FROM secret_versions WHERE name = 'k' AND version = ?1",
            [&newest_version],
        )
        .unwrap();
    }
    let unlock = fx.unlock("dev");
    let err = fx.registry.open("dev", &unlock).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert_blocked(&fx.registry.open("dev", &unlock).unwrap_err());
    fx.acknowledge_truncations("dev");
    let vault = fx.open_vault("dev");
    let served = vault.get_secret("k", None).unwrap();
    assert_ne!(served.properties.version, newest_version);
    let check = vault.verify_audit_chain().unwrap();
    assert_eq!(check.truncations, 1, "{check:?}");
    assert_eq!(check.unacknowledged, 0, "{check:?}");
}

/// Rows removed while a handle is open are caught by the next operation:
/// the head counts the keyed rows, so a keyed row missing from the middle
/// fails the check every operation starts with.
#[test]
fn keyed_rows_removed_while_the_vault_is_open_are_caught_by_the_next_operation() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    let vault = fx.create_vault("dev");
    set_with(&vault, "k", "v", SetSecretOptions::default());
    vault.get_secret("k", None).unwrap();
    let victim = events_of(&vault, AuditOperation::SecretGet, AuditOutcome::Success)[0].id;
    vault.list_properties_of_secrets().unwrap();
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "DELETE FROM audit_events WHERE id = ?1",
            [i64::try_from(victim).unwrap()],
        )
        .unwrap();
    }
    let err = vault.get_secret("k", None).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert!(
        err.to_string()
            .contains("removed or altered inside the log"),
        "{err}"
    );
    assert_blocked(&vault.get_secret("k", None).unwrap_err());
}

#[test]
fn edited_audit_row_breaks_the_chain() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    let denied_id = {
        let vault = fx.create_vault("dev");
        set_with(
            &vault,
            "k",
            "v",
            SetSecretOptions {
                enabled: false,
                ..Default::default()
            },
        );
        assert_eq!(vault.get_secret("k", None).unwrap_err().code(), "disabled");
        events_of(&vault, AuditOperation::SecretGet, AuditOutcome::Denied)[0].id
    };
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE audit_events SET outcome = 'success', detail = NULL WHERE id = ?1",
            [i64::try_from(denied_id).unwrap()],
        )
        .unwrap();
    }
    // The edited row's hash no longer verifies: the unlock finds it, records
    // it and blocks the vault until the owner has acknowledged it.
    let unlock = fx.unlock("dev");
    let err = fx.registry.open("dev", &unlock).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert!(
        err.to_string().contains(&format!("event {denied_id}")),
        "{err}"
    );
    let vault = fx.inspect_vault("dev");
    let check = vault.verify_audit_chain().unwrap();
    assert_eq!(check.first_broken, Some(denied_id), "{check:?}");
    assert_eq!(check.unacknowledged, 1, "{check:?}");
    drop(vault);
    fx.acknowledge_truncations("dev");
    fx.open_vault("dev");
}

/// Remove every audit row newer than `keep_up_to`, as an attacker with
/// write access to the file would.
fn truncate_after(path: &Path, keep_up_to: u64) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute(
        "DELETE FROM audit_events WHERE id > ?1",
        [i64::try_from(keep_up_to).unwrap()],
    )
    .unwrap();
}

/// The refusal a vault gives while a detected truncation is unacknowledged.
fn assert_blocked(err: &sourceorrery_core::SecretError) {
    assert_eq!(err.code(), "crypto", "{err}");
    assert!(err.to_string().contains("unacknowledged"), "{err}");
    assert!(err.to_string().contains("audit --acknowledge"), "{err}");
}

/// Refused unlocks on the record with exactly this detail.
fn open_refusals(vault: &SqliteVault, detail: &str) -> usize {
    events_of(vault, AuditOperation::VaultOpen, AuditOutcome::Failure)
        .iter()
        .filter(|e| e.detail.as_deref() == Some(detail))
        .count()
}

#[test]
fn removed_tail_rows_are_detected_on_the_next_write() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    let ids = {
        let vault = fx.create_vault("dev");
        set_with(&vault, "k", "v", SetSecretOptions::default());
        vault.get_secret("k", None).unwrap();
        vault.get_secret("k", None).unwrap();
        event_ids(&vault)
    };
    truncate_after(&path, ids[ids.len() - 3]);
    // The next unlock finds the head stale. Row state is judged against the
    // chain, so a shortened chain cannot be consulted: the unlock is refused,
    // and recording the refusal puts the detection itself on the chain and
    // re-anchors the head.
    let unlock = fx.unlock("dev");
    let err = fx.registry.open("dev", &unlock).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert!(
        err.to_string().contains("rows removed after event"),
        "{err}"
    );

    // From then on only an inspection unlock gets a handle, and that handle
    // serves the log and nothing else, with the truncation on record.
    assert_blocked(&fx.registry.open("dev", &unlock).unwrap_err());
    let vault = fx.inspect_vault("dev");
    let check = vault.verify_audit_chain().unwrap();
    assert!(!check.is_intact(), "{check:?}");
    assert_eq!(check.first_broken, None, "remaining rows still link");
    assert_eq!(check.truncations, 1);
    assert_eq!(check.unacknowledged, 1);
    assert!(check.head_valid, "the detection re-anchored the head");
    let detections = events_of(&vault, AuditOperation::AuditVerify, AuditOutcome::Failure);
    assert_eq!(detections.len(), 1);
    let detail = detections[0].detail.clone().unwrap_or_default();
    assert!(detail.contains("rows removed after event"), "{detail}");
    assert_eq!(open_refusals(&vault, "audit log truncated"), 1);
    assert_eq!(open_refusals(&vault, "truncation unacknowledged"), 1);
    assert_blocked(&vault.get_secret("k", None).unwrap_err());
    drop(vault);

    // Acknowledged, the vault is usable again, with the truncation
    // permanently on record ...
    fx.acknowledge_truncations("dev");
    let vault = fx.open_vault("dev");
    vault.get_secret("k", None).unwrap();
    let check = vault.verify_audit_chain().unwrap();
    assert_eq!(check.truncations, 1);
    assert_eq!(check.unacknowledged, 0);
    assert!(!check.is_intact());
    drop(vault);

    // ... and removing the evidence is just another truncation: refused,
    // blocked, and back on record once acknowledged again.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "DELETE FROM audit_events
             WHERE id >= (SELECT MIN(id) FROM audit_events WHERE operation = 'audit_verify')",
            [],
        )
        .unwrap();
    }
    assert_eq!(
        fx.registry.open("dev", &unlock).unwrap_err().code(),
        "crypto"
    );
    assert_blocked(&fx.registry.open("dev", &unlock).unwrap_err());
    fx.acknowledge_truncations("dev");
    let vault = fx.open_vault("dev");
    let check = vault.verify_audit_chain().unwrap();
    assert_eq!(check.truncations, 1, "{check:?}");
    assert_eq!(check.unacknowledged, 0);
    assert!(!check.is_intact());
}

#[test]
fn deleted_chain_head_is_detected() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    {
        let vault = fx.create_vault("dev");
        set_with(&vault, "k", "v", SetSecretOptions::default());
    }
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("DELETE FROM vault_meta WHERE key = 'audit_head'", [])
            .unwrap();
    }
    let unlock = fx.unlock("dev");
    let err = fx.registry.open("dev", &unlock).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert!(err.to_string().contains("head missing"), "{err}");
    assert_blocked(&fx.registry.open("dev", &unlock).unwrap_err());

    let vault = fx.inspect_vault("dev");
    let check = vault.verify_audit_chain().unwrap();
    assert_eq!(check.truncations, 1, "{check:?}");
    assert_eq!(check.unacknowledged, 1);
    let detections = events_of(&vault, AuditOperation::AuditVerify, AuditOutcome::Failure);
    assert_eq!(
        detections[0].detail.as_deref(),
        Some("audit chain head missing")
    );
    assert_blocked(&vault.list_properties_of_secrets().unwrap_err());
    drop(vault);

    fx.acknowledge_truncations("dev");
    let vault = fx.open_vault("dev");
    assert_eq!(vault.get_secret("k", None).unwrap().value.expose(), b"v");
    assert_eq!(vault.verify_audit_chain().unwrap().unacknowledged, 0);
}

// ---------------------------------------------------------------------------
// Files from other releases are refused; there is no migration
// ---------------------------------------------------------------------------

#[test]
fn a_vault_from_an_earlier_release_is_refused_and_never_migrated() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    {
        let vault = fx.create_vault("dev");
        set_with(&vault, "k", CANARY, SetSecretOptions::default());
    }
    for older in ["1", "2", "3", "4"] {
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute(
                "UPDATE vault_meta SET value = ?1 WHERE key = 'schema_version'",
                [older],
            )
            .unwrap();
        }
        let before = std::fs::read(&path).unwrap();
        let err = fx.registry.open("dev", &fx.unlock("dev")).unwrap_err();
        assert_eq!(err.code(), "migration_required", "{err}");
        // The way out keeps the file: it is moved aside, never destroyed.
        let message = err.to_string();
        assert!(message.contains("has not changed it"), "{err}");
        assert!(
            message.contains("moving it out of the vaults folder"),
            "{err}"
        );
        assert!(!message.contains(CANARY));
        // Nothing was converted or written: the file is byte for byte as it was.
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(schema_marker(&path), older);
    }
}

#[test]
fn newer_schema_is_refused_cleanly() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    fx.create_vault("dev");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE vault_meta SET value = '99' WHERE key = 'schema_version'",
            [],
        )
        .unwrap();
    }
    let err = fx.registry.open("dev", &fx.unlock("dev")).unwrap_err();
    assert_eq!(err.code(), "storage");
    assert!(err.to_string().contains("newer than this build"), "{err}");
}

// ---------------------------------------------------------------------------
// Audit log: removing everything is not a fresh start
// ---------------------------------------------------------------------------

#[test]
fn removing_all_audit_rows_and_the_head_is_detected() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    {
        let vault = fx.create_vault("dev");
        set_with(&vault, "k", "v", SetSecretOptions::default());
        vault.get_secret("k", None).unwrap();
    }
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "DELETE FROM audit_events; DELETE FROM vault_meta WHERE key = 'audit_head';",
        )
        .unwrap();
    }
    let unlock = fx.unlock("dev");
    let err = fx.registry.open("dev", &unlock).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert!(err.to_string().contains("history missing"), "{err}");
    assert_blocked(&fx.registry.open("dev", &unlock).unwrap_err());

    let vault = fx.inspect_vault("dev");
    let check = vault.verify_audit_chain().unwrap();
    assert!(!check.is_intact(), "{check:?}");
    assert_eq!(check.truncations, 1, "{check:?}");
    assert_eq!(check.unacknowledged, 1);
    let detections = events_of(&vault, AuditOperation::AuditVerify, AuditOutcome::Failure);
    assert!(
        detections[0]
            .detail
            .as_deref()
            .is_some_and(|d| d.contains("history missing")),
        "{detections:?}"
    );
    drop(vault);

    // Acknowledged, the vault opens again; but the surviving history records
    // no secret at all, so the orphaned rows stay refused.
    fx.acknowledge_truncations("dev");
    let vault = fx.open_vault("dev");
    assert_eq!(vault.get_secret("k", None).unwrap_err().code(), "crypto");
    assert_eq!(vault.verify_audit_chain().unwrap().unacknowledged, 0);
}

// ---------------------------------------------------------------------------
// Vault settings are authenticated
// ---------------------------------------------------------------------------

fn settings_tamper(sql: &str) -> sourceorrery_core::SecretError {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    {
        let vault = fx.create_vault("dev");
        set_with(&vault, "k", "v", SetSecretOptions::default());
        vault.delete_secret("k").unwrap();
    }
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(sql).unwrap();
    }
    fx.registry.open("dev", &fx.unlock("dev")).unwrap_err()
}

#[test]
fn shortened_retention_or_changed_recovery_level_is_refused() {
    for sql in [
        "UPDATE vault_meta SET value = '0' WHERE key = 'retention_days'",
        "UPDATE vault_meta SET value = '7' WHERE key = 'retention_days'",
        "UPDATE vault_meta SET value = '\"purgeable\"' WHERE key = 'recovery_level'",
        "UPDATE vault_meta SET value = 'other' WHERE key = 'name'",
        "DELETE FROM vault_meta WHERE key = 'settings_tag'",
    ] {
        let err = settings_tamper(sql);
        assert_eq!(err.code(), "crypto", "{sql}: {err}");
        assert!(err.to_string().contains("settings"), "{sql}: {err}");
    }
}

// ---------------------------------------------------------------------------
// Destroying a vault must not reach into another vault's keyring entry
// ---------------------------------------------------------------------------

fn schema_marker(path: &Path) -> String {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.query_row(
        "SELECT value FROM vault_meta WHERE key = 'schema_version'",
        [],
        |r| r.get(0),
    )
    .unwrap()
}

fn vault_id(path: &Path) -> String {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.query_row("SELECT value FROM vault_meta WHERE key = 'id'", [], |r| {
        r.get(0)
    })
    .unwrap()
}

fn insert_this_machine_wrap_row(path: &Path, wrap_id: &str, account: &str) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute(
        "INSERT INTO key_wraps (id, kind_json, wrapped_nonce, wrapped_key, created_on)
         VALUES (?1, ?2, zeroblob(24), zeroblob(48), 0)",
        rusqlite::params![
            wrap_id,
            format!(
                "{{\"kind\":\"this-machine\",\"service\":\"sourceorrery\",\"account\":\"{account}\"}}"
            ),
        ],
    )
    .unwrap();
}

#[test]
fn destroy_keeps_keyring_entries_it_cannot_prove_it_owns() {
    let fx = Fixture::new();
    fx.create_vault("dev");
    fx.create_vault("other");
    let dev = fx.registry.vault_path("dev").unwrap();
    let other = fx.registry.vault_path("other").unwrap();
    let other_id = vault_id(&other);
    let dev_id = vault_id(&dev);

    // 1. An account that names another vault's identity (plain substitution).
    insert_this_machine_wrap_row(&dev, "aaaaaaaa", &format!("vault/{other_id}/aaaaaaaa"));
    // 2. An account that matches this vault's identity but is also listed by
    //    a sibling vault file (a cloned vault).
    let shared = format!("vault/{dev_id}/bbbbbbbb");
    insert_this_machine_wrap_row(&dev, "bbbbbbbb", &shared);
    insert_this_machine_wrap_row(&other, "bbbbbbbb", &shared);

    let report = fx.registry.destroy("dev", false).unwrap();
    assert!(report.removed_keys.is_empty(), "{report:?}");
    let kept: Vec<&str> = report.kept_keys.iter().map(|(a, _)| a.as_str()).collect();
    assert!(
        kept.contains(&format!("vault/{other_id}/aaaaaaaa").as_str()),
        "{report:?}"
    );
    assert!(kept.contains(&shared.as_str()), "{report:?}");
    assert!(!fx.registry.exists("dev"));
    assert!(fx.registry.exists("other"));

    // --keep-os-key never touches the store at all.
    insert_this_machine_wrap_row(&other, "cccccccc", &format!("vault/{other_id}/cccccccc"));
    let report = fx.registry.destroy("other", true).unwrap();
    assert!(report.removed_keys.is_empty(), "{report:?}");
    assert!(
        report
            .kept_keys
            .iter()
            .all(|(_, why)| why.contains("request")),
        "{report:?}"
    );
}

// ---------------------------------------------------------------------------
// Replay of authentic older rows: row state is bound to the audit chain
// ---------------------------------------------------------------------------
//
// A row tag proves a row was written by the vault at some point, not that it
// is current. Since schema 3 every change records the row's resulting tag in
// its audit event, and reads require the stored tag to equal the newest such
// checkpoint, so an attacker with an earlier copy of a row and write access
// to the file can no longer put the old policy back.

/// Keep a copy of `name`'s rows in `table`, to replay them later.
fn stash(path: &Path, table: &str, name: &str) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch(&format!(
        "DROP TABLE IF EXISTS stash_{table};
         CREATE TABLE stash_{table} AS SELECT * FROM {table} WHERE name = '{name}';"
    ))
    .unwrap();
}

/// Put the stashed rows back exactly as they were, tags included.
fn replay(path: &Path, table: &str, name: &str) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch(&format!(
        "PRAGMA foreign_keys = OFF;
         DELETE FROM {table} WHERE name = '{name}';
         INSERT INTO {table} SELECT * FROM stash_{table};
         DROP TABLE stash_{table};"
    ))
    .unwrap();
}

fn disable(vault: &SqliteVault, name: &str) {
    vault
        .update_secret_properties(
            name,
            None,
            UpdateSecretProperties {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
}

fn assert_replay_refused(vault: &SqliteVault, name: &str) {
    let err = vault.get_secret(name, None).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert!(err.to_string().contains("audit log"), "{err}");
    assert_eq!(
        vault.get_secret_properties(name, None).unwrap_err().code(),
        "crypto"
    );
    assert_eq!(
        vault.list_properties_of_secrets().unwrap_err().code(),
        "crypto"
    );
    // The attack touched no audit row, so the chain still verifies: that is
    // exactly why rows have to be bound to it.
    assert!(vault.verify_audit_chain().unwrap().is_intact());
    let refusals = events_of(vault, AuditOperation::SecretGet, AuditOutcome::Failure);
    assert!(
        refusals.iter().any(
            |e| e.secret_name.as_deref() == Some(name) && e.detail.as_deref() == Some("crypto")
        ),
        "the refusal must be audited: {refusals:?}"
    );
}

#[test]
fn replayed_version_row_from_before_disable_is_rejected() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    {
        let vault = fx.create_vault("dev");
        set_with(&vault, "k", CANARY, SetSecretOptions::default());
    }
    stash(&path, "secret_versions", "k");
    {
        let vault = fx.open_vault("dev");
        disable(&vault, "k");
        assert_eq!(vault.get_secret("k", None).unwrap_err().code(), "disabled");
    }
    replay(&path, "secret_versions", "k");
    let vault = fx.open_vault("dev");
    assert_replay_refused(&vault, "k");
}

#[test]
fn replayed_version_row_from_before_a_window_change_is_rejected() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    {
        let vault = fx.create_vault("dev");
        set_with(&vault, "k", CANARY, SetSecretOptions::default());
    }
    stash(&path, "secret_versions", "k");
    {
        let vault = fx.open_vault("dev");
        vault
            .update_secret_properties(
                "k",
                None,
                UpdateSecretProperties {
                    not_before: Some(Some(timestamp::now() + Duration::days(1))),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            vault.get_secret("k", None).unwrap_err().code(),
            "not_yet_valid"
        );
    }
    replay(&path, "secret_versions", "k");
    let vault = fx.open_vault("dev");
    assert_replay_refused(&vault, "k");
}

#[test]
fn replayed_secret_row_from_before_soft_delete_is_rejected() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    {
        let vault = fx.create_vault("dev");
        set_with(&vault, "k", CANARY, SetSecretOptions::default());
    }
    stash(&path, "secrets", "k");
    {
        let vault = fx.open_vault("dev");
        vault.delete_secret("k").unwrap();
        assert_eq!(vault.get_secret("k", None).unwrap_err().code(), "deleted");
    }
    replay(&path, "secrets", "k");
    let vault = fx.open_vault("dev");
    assert_replay_refused(&vault, "k");
    assert_eq!(vault.get_deleted_secret("k").unwrap_err().code(), "crypto");
    assert_eq!(vault.list_deleted_secrets().unwrap_err().code(), "crypto");
    assert_eq!(
        vault.recover_deleted_secret("k").unwrap_err().code(),
        "crypto"
    );
}

#[test]
fn resurrected_purged_secret_is_rejected_until_honestly_recreated() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    {
        let vault = fx.create_vault("dev");
        set_with(&vault, "k", CANARY, SetSecretOptions::default());
    }
    stash(&path, "secrets", "k");
    stash(&path, "secret_versions", "k");
    {
        let vault = fx.open_vault("dev");
        vault.delete_secret("k").unwrap();
        vault.purge_deleted_secret("k").unwrap();
        assert_eq!(vault.get_secret("k", None).unwrap_err().code(), "not_found");
    }
    // Both rows come back from the attacker's backup, tags intact.
    replay(&path, "secrets", "k");
    replay(&path, "secret_versions", "k");
    let vault = fx.open_vault("dev");
    assert_replay_refused(&vault, "k");
    // The chain says the name is absent, so a new secret cannot be layered
    // on top of the resurrected rows either.
    assert_eq!(
        vault
            .set_secret("k", SecretBytes::from("fresh"), SetSecretOptions::default())
            .unwrap_err()
            .code(),
        "crypto"
    );
    drop(vault);

    // Once the foreign rows are gone the name is simply free again.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON; DELETE FROM secrets WHERE name = 'k';")
            .unwrap();
    }
    let vault = fx.open_vault("dev");
    assert_eq!(vault.get_secret("k", None).unwrap_err().code(), "not_found");
    set_with(&vault, "k", "fresh", SetSecretOptions::default());
    assert_eq!(
        vault.get_secret("k", None).unwrap().value.expose(),
        b"fresh"
    );
    assert_eq!(vault.list_properties_of_secrets().unwrap().len(), 1);
}

#[test]
fn version_row_removed_out_of_band_is_rejected() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    let newest = {
        let vault = fx.create_vault("dev");
        set_with(&vault, "k", "old-value", SetSecretOptions::default());
        set_with(&vault, "k", CANARY, SetSecretOptions::default());
        vault.get_secret("k", None).unwrap().properties.version
    };
    // Dropping the newest version would quietly make the old value current.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("DELETE FROM secret_versions WHERE version = ?1", [&newest])
            .unwrap();
    }
    let vault = fx.open_vault("dev");
    let err = vault.get_secret("k", None).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert!(err.to_string().contains("missing"), "{err}");
    assert_eq!(
        vault
            .list_properties_of_secret_versions("k")
            .unwrap_err()
            .code(),
        "crypto"
    );
}

#[test]
fn secret_row_removed_out_of_band_is_rejected_not_not_found() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    {
        let vault = fx.create_vault("dev");
        set_with(&vault, "k", CANARY, SetSecretOptions::default());
        set_with(&vault, "other", "v", SetSecretOptions::default());
    }
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON; DELETE FROM secrets WHERE name = 'k';")
            .unwrap();
    }
    let vault = fx.open_vault("dev");
    let err = vault.get_secret("k", None).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert!(err.to_string().contains("missing"), "{err}");
    // Listings look for every name the chain records, not just the rows left.
    assert_eq!(
        vault.list_properties_of_secrets().unwrap_err().code(),
        "crypto"
    );
}

#[test]
fn a_tampered_row_refuses_the_page_that_holds_it_and_no_other() {
    let fx = Fixture::new();
    let vault = tampered(
        &fx,
        |v| {
            for name in ["a", "b", "c", "d", "e"] {
                set_with(v, name, CANARY, SetSecretOptions::default());
            }
        },
        "PRAGMA foreign_keys = ON; DELETE FROM secrets WHERE name = 'd';",
    );
    // The chain still records `d`, so every window that includes `d` is
    // refused, and no other window is.
    let first = vault
        .list_properties_of_secrets_page(ListOptions::first(2))
        .unwrap();
    let names: Vec<&str> = first.items.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["a", "b"]);
    let second = vault.list_properties_of_secrets_page(ListOptions {
        max_results: Some(2),
        continuation: first.continuation.clone(),
    });
    assert_eq!(second.unwrap_err().code(), "crypto");
    let after = vault
        .list_properties_of_secrets_page(ListOptions {
            max_results: Some(2),
            continuation: Some(ContinuationToken::new("d")),
        })
        .unwrap();
    let names: Vec<&str> = after.items.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["e"]);
    assert_eq!(after.continuation, None);
    assert_eq!(
        vault.list_properties_of_secrets().unwrap_err().code(),
        "crypto"
    );
    assert_eq!(
        vault.list_deleted_secrets().unwrap_err().code(),
        "crypto",
        "a deleted listing judges the same rows"
    );
}

#[test]
fn forged_checkpoint_rows_do_not_count() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    {
        let vault = fx.create_vault("dev");
        set_with(&vault, "k", CANARY, SetSecretOptions::default());
    }
    stash(&path, "secrets", "k");
    stash(&path, "secret_versions", "k");
    {
        let vault = fx.open_vault("dev");
        vault.delete_secret("k").unwrap();
        vault.purge_deleted_secret("k").unwrap();
    }
    replay(&path, "secrets", "k");
    replay(&path, "secret_versions", "k");

    // An unkeyed row is forgeable by design, so it is never a checkpoint;
    // one with a hash that does not verify breaks the chain, which the
    // unlock finds and records, and once acknowledged it still counts for
    // nothing.
    let forge = |keyed: i64| {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO audit_events
                (occurred_on, actor, operation, secret_name, version, outcome, detail,
                 prev_hash, hash, keyed, state_tag, version_tag)
             SELECT s.created_on, 'user:attacker', 'secret_recover', 'k', v.version, 'success',
                    NULL, zeroblob(32), zeroblob(32), ?1, s.tag, v.tag
             FROM secrets s JOIN secret_versions v ON v.name = s.name WHERE s.name = 'k'",
            [keyed],
        )
        .unwrap();
    };
    forge(0);
    let unlock = fx.unlock("dev");
    assert_eq!(
        fx.registry.open("dev", &unlock).unwrap_err().code(),
        "crypto"
    );
    assert_blocked(&fx.registry.open("dev", &unlock).unwrap_err());
    fx.acknowledge_truncations("dev");
    let vault = fx.open_vault("dev");
    assert_eq!(vault.get_secret("k", None).unwrap_err().code(), "crypto");
    drop(vault);

    // A row flagged keyed without the key has no valid hash. Appending it
    // also leaves the head stale, so the next unlock is refused and the
    // forgery is recorded as a truncation that blocks the vault; once the
    // owner has acknowledged it the row is still not a checkpoint.
    forge(1);
    assert_eq!(
        fx.registry.open("dev", &unlock).unwrap_err().code(),
        "crypto"
    );
    assert_blocked(&fx.registry.open("dev", &unlock).unwrap_err());
    fx.acknowledge_truncations("dev");
    let vault = fx.open_vault("dev");
    let err = vault.get_secret("k", None).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert!(err.to_string().contains("does not verify"), "{err}");
    let check = vault.verify_audit_chain().unwrap();
    assert!(check.first_broken.is_some(), "{check:?}");
    assert_eq!(check.truncations, 2, "one per forgery: {check:?}");
}

/// Removing the audit rows that checkpointed a change *and* replaying the
/// rows from before it is a partial snapshot rollback. It cannot be told
/// from the surviving history alone, but it cannot be done quietly: the
/// head is stale, so the next unlock is refused, the truncation is recorded
/// in the chain for good, and the vault is blocked until its owner has
/// reviewed the surviving history and acknowledged the truncation. See the
/// threat model's known gaps.
#[test]
fn truncating_the_log_to_replay_a_row_is_blocked_until_acknowledged() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    {
        let vault = fx.create_vault("dev");
        set_with(&vault, "k", CANARY, SetSecretOptions::default());
    }
    stash(&path, "secret_versions", "k");
    let before_disable = {
        let vault = fx.open_vault("dev");
        let last = *event_ids(&vault).last().unwrap();
        disable(&vault, "k");
        last
    };
    replay(&path, "secret_versions", "k");
    truncate_after(&path, before_disable);
    let unlock = fx.unlock("dev");
    let err = fx.registry.open("dev", &unlock).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert!(
        err.to_string().contains("rows removed after event"),
        "{err}"
    );

    // The replayed row is served through no door while the truncation is
    // unacknowledged: not a plain unlock, not an inspection handle.
    assert_blocked(&fx.registry.open("dev", &unlock).unwrap_err());
    let vault = fx.inspect_vault("dev");
    assert_blocked(&vault.get_secret("k", None).unwrap_err());
    assert_blocked(&vault.get_secret_properties("k", None).unwrap_err());
    let check = vault.verify_audit_chain().unwrap();
    assert_eq!(check.truncations, 1, "{check:?}");
    assert_eq!(check.unacknowledged, 1);
    assert!(!check.is_intact());
    drop(vault);

    // Once the owner has acknowledged it, the surviving history says the
    // version is enabled, and that is what the vault goes by: the limit of
    // what the file alone can prove.
    fx.acknowledge_truncations("dev");
    let vault = fx.open_vault("dev");
    assert!(vault.get_secret("k", None).is_ok());
    let check = vault.verify_audit_chain().unwrap();
    assert_eq!(check.truncations, 1);
    assert_eq!(check.unacknowledged, 0);
    assert!(!check.is_intact());
}

/// The history before an acknowledgement is no longer walked for links, but
/// it still decides which checkpoint is newest: a file writer who hides an
/// older event's checkpoint there, to put back the row from before it, is
/// refused like any other edit of the log.
#[test]
fn a_checkpoint_hidden_after_an_acknowledgement_is_still_refused() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    {
        let vault = fx.create_vault("dev");
        set_with(&vault, "k", CANARY, SetSecretOptions::default());
    }
    stash(&path, "secret_versions", "k");
    let (disabled_at, ids) = {
        let vault = fx.open_vault("dev");
        disable(&vault, "k");
        vault.get_secret_properties("k", None).unwrap();
        let updates = events_of(&vault, AuditOperation::SecretUpdate, AuditOutcome::Success);
        (updates[0].id, event_ids(&vault))
    };
    // Any truncation the owner acknowledges will do.
    truncate_after(&path, ids[ids.len() - 2]);
    let unlock = fx.unlock("dev");
    assert_eq!(
        fx.registry.open("dev", &unlock).unwrap_err().code(),
        "crypto"
    );
    fx.acknowledge_truncations("dev");
    let vault = fx.open_vault("dev");
    assert_eq!(vault.get_secret("k", None).unwrap_err().code(), "disabled");
    drop(vault);

    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE audit_events SET version_tag = NULL WHERE id = ?1",
            [i64::try_from(disabled_at).unwrap()],
        )
        .unwrap();
    }
    replay(&path, "secret_versions", "k");
    let err = fx.registry.open("dev", &unlock).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert!(
        err.to_string().contains(&format!("event {disabled_at}")),
        "{err}"
    );
    let vault = fx.inspect_vault("dev");
    assert_blocked(&vault.get_secret("k", None).unwrap_err());
    let pending = vault.unacknowledged_truncations().unwrap();
    assert_eq!(pending.len(), 1, "{pending:?}");
}

/// A row an acknowledgement accepted although its hash did not verify is
/// accepted as it was shown only: edited again, it is refused like any
/// other edit of the log.
#[test]
fn a_row_accepted_as_unverifiable_is_refused_once_edited_again() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    let read = {
        let vault = fx.create_vault("dev");
        set_with(&vault, "k", CANARY, SetSecretOptions::default());
        vault.get_secret("k", None).unwrap();
        events_of(&vault, AuditOperation::SecretGet, AuditOutcome::Success)[0].id
    };
    let edit = |detail: &str| {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE audit_events SET detail = ?2 WHERE id = ?1",
            rusqlite::params![i64::try_from(read).unwrap(), detail],
        )
        .unwrap();
    };
    edit("edited");
    let unlock = fx.unlock("dev");
    assert_eq!(
        fx.registry.open("dev", &unlock).unwrap_err().code(),
        "crypto"
    );
    let ack = fx.acknowledge_truncations("dev");
    let acks = events_of(
        &fx.inspect_vault("dev"),
        AuditOperation::AuditVerify,
        AuditOutcome::Success,
    );
    let detail = acks
        .iter()
        .find(|e| e.id == ack.event_id)
        .and_then(|e| e.detail.clone())
        .unwrap_or_default();
    assert!(
        detail.contains(&format!("unverifiable rows {read}:")),
        "{detail}"
    );
    fx.open_vault("dev").get_secret("k", None).unwrap();

    edit("edited again");
    let err = fx.registry.open("dev", &unlock).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert!(err.to_string().contains(&format!("event {read}")), "{err}");
}

/// An edit made while a truncation waits for its acknowledgement is not
/// accepted with it unseen: the acknowledgement puts it on record and is
/// refused, and the owner is shown it before acknowledging again.
#[test]
fn an_edit_made_while_a_truncation_waits_is_shown_before_it_is_acknowledged() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    {
        let vault = fx.create_vault("dev");
        set_with(&vault, "k", CANARY, SetSecretOptions::default());
    }
    stash(&path, "secret_versions", "k");
    let (disabled_at, ids) = {
        let vault = fx.open_vault("dev");
        disable(&vault, "k");
        vault.get_secret_properties("k", None).unwrap();
        let updates = events_of(&vault, AuditOperation::SecretUpdate, AuditOutcome::Success);
        (updates[0].id, event_ids(&vault))
    };
    truncate_after(&path, ids[ids.len() - 2]);
    let unlock = fx.unlock("dev");
    assert_eq!(
        fx.registry.open("dev", &unlock).unwrap_err().code(),
        "crypto"
    );
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE audit_events SET version_tag = NULL WHERE id = ?1",
            [i64::try_from(disabled_at).unwrap()],
        )
        .unwrap();
    }
    replay(&path, "secret_versions", "k");

    let vault = fx.inspect_vault("dev");
    let shown: Vec<u64> = vault
        .unacknowledged_truncations()
        .unwrap()
        .iter()
        .map(|e| e.id)
        .collect();
    assert_eq!(shown.len(), 1, "{shown:?}");
    let err = vault.acknowledge_truncations(&shown).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert!(
        err.to_string().contains(&format!("event {disabled_at}")),
        "{err}"
    );
    let pending = vault.unacknowledged_truncations().unwrap();
    assert_eq!(pending.len(), 2, "the edit is now on record: {pending:?}");
    let detail = pending[1].detail.clone().unwrap_or_default();
    assert!(detail.contains(&disabled_at.to_string()), "{detail}");
    assert!(
        events_of(&vault, AuditOperation::AuditVerify, AuditOutcome::Success).is_empty(),
        "nothing was acknowledged"
    );
    let ids: Vec<u64> = pending.iter().map(|e| e.id).collect();
    let ack = vault.acknowledge_truncations(&ids).unwrap();
    assert_eq!(ack.truncations.len(), 2);
}

// ---------------------------------------------------------------------------
// A detected truncation blocks the vault until it is acknowledged
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines)] // every door into the vault is tried, deliberately exhaustive
fn truncation_blocks_every_unlock_and_operation_until_acknowledged() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    let ids = {
        let vault = fx.create_vault("dev");
        set_with(&vault, "k", CANARY, SetSecretOptions::default());
        vault.get_secret("k", None).unwrap();
        vault.get_secret("k", None).unwrap();
        event_ids(&vault)
    };
    truncate_after(&path, ids[ids.len() - 3]);

    // The unlock that finds the stale head is refused and records the
    // detection; the second and third are refused because nobody has
    // acknowledged it, and say so.
    let unlock = fx.unlock("dev");
    let err = fx.registry.open("dev", &unlock).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert!(
        err.to_string().contains("rows removed after event"),
        "{err}"
    );
    assert!(err.to_string().contains("audit --acknowledge"), "{err}");
    for _ in 0..2 {
        assert_blocked(&fx.registry.open("dev", &unlock).unwrap_err());
    }

    // An inspection unlock gets a handle that shows what was detected ...
    let vault = fx.inspect_vault("dev");
    let pending = vault.unacknowledged_truncations().unwrap();
    assert_eq!(pending.len(), 1, "{pending:?}");
    let detection = &pending[0];
    assert_eq!(detection.operation, AuditOperation::AuditVerify);
    assert_eq!(detection.outcome, AuditOutcome::Failure);
    assert!(
        detection
            .detail
            .as_deref()
            .is_some_and(|d| d.contains("rows removed after event")),
        "{detection:?}"
    );
    assert!(!format!("{pending:?}").contains(CANARY));
    let err = fx.registry.open("dev", &unlock).unwrap_err();
    assert!(
        err.to_string().contains(&format!("event {}", detection.id)),
        "the refusal names the detection: {err}"
    );

    // ... and refuses every secret, key and view-check change ...
    let refused: Vec<(&str, sourceorrery_core::SecretError)> = vec![
        ("get", vault.get_secret("k", None).unwrap_err()),
        (
            "properties",
            vault.get_secret_properties("k", None).unwrap_err(),
        ),
        ("list", vault.list_properties_of_secrets().unwrap_err()),
        (
            "versions",
            vault.list_properties_of_secret_versions("k").unwrap_err(),
        ),
        (
            "set",
            vault
                .set_secret("k2", SecretBytes::from("v"), SetSecretOptions::default())
                .unwrap_err(),
        ),
        (
            "update",
            vault
                .update_secret_properties(
                    "k",
                    None,
                    UpdateSecretProperties {
                        enabled: Some(false),
                        ..Default::default()
                    },
                )
                .unwrap_err(),
        ),
        ("delete", vault.delete_secret("k").unwrap_err()),
        ("deleted", vault.get_deleted_secret("k").unwrap_err()),
        ("list-deleted", vault.list_deleted_secrets().unwrap_err()),
        ("recover", vault.recover_deleted_secret("k").unwrap_err()),
        ("purge", vault.purge_deleted_secret("k").unwrap_err()),
        (
            "recovery-key",
            vault.replace_recovery_key().map(drop).unwrap_err(),
        ),
        (
            "password",
            vault
                .set_password(&SecretBytes::from("another"), None, Argon2Params::TESTING)
                .unwrap_err(),
        ),
    ];
    for (what, err) in &refused {
        assert_eq!(err.code(), "crypto", "{what}: {err}");
        assert!(err.to_string().contains("unacknowledged"), "{what}: {err}");
        assert!(!err.to_string().contains(CANARY), "{what}");
    }
    assert_eq!(vault.wraps().unwrap().len(), 1, "nothing changed");
    assert!(vault.view_check().unwrap().is_none(), "nothing changed");

    // ... while inspection itself works and every refusal is on the record.
    let check = vault.verify_audit_chain().unwrap();
    assert_eq!(check.truncations, 1, "{check:?}");
    assert_eq!(check.unacknowledged, 1);
    assert!(check.head_valid);
    assert_eq!(check.first_broken, None);
    assert!(!check.is_intact());
    assert_eq!(open_refusals(&vault, "audit log truncated"), 1);
    assert_eq!(
        open_refusals(&vault, "truncation unacknowledged"),
        3,
        "two plain unlocks and the unlock after inspection"
    );
    let inspections = events_of(&vault, AuditOperation::VaultOpen, AuditOutcome::Success)
        .iter()
        .filter(|e| e.detail.as_deref() == Some("inspection (truncation unacknowledged)"))
        .count();
    assert_eq!(inspections, 1);
    let get_refusals = events_of(&vault, AuditOperation::SecretGet, AuditOutcome::Failure);
    assert!(
        get_refusals
            .iter()
            .any(|e| e.detail.as_deref() == Some("crypto")),
        "{get_refusals:?}"
    );
    assert_eq!(
        vault.verify_audit_chain().unwrap().truncations,
        1,
        "refusals are not new truncations"
    );
}

#[test]
fn acknowledgement_records_one_keyed_success_row_and_unblocks_the_vault() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    let ids = {
        let vault = fx.create_vault("dev");
        set_with(&vault, "k", CANARY, SetSecretOptions::default());
        vault.get_secret("k", None).unwrap();
        vault.get_secret("k", None).unwrap();
        event_ids(&vault)
    };
    truncate_after(&path, ids[ids.len() - 2]);
    let unlock = fx.unlock("dev");
    assert_eq!(
        fx.registry.open("dev", &unlock).unwrap_err().code(),
        "crypto"
    );

    let vault = fx.inspect_vault("dev");
    let pending = vault.unacknowledged_truncations().unwrap();
    assert_eq!(pending.len(), 1, "{pending:?}");
    let detection_id = pending[0].id;

    // An acknowledgement must name exactly what was shown, and a refused one
    // writes nothing.
    let err = vault.acknowledge_truncations(&[]).unwrap_err();
    assert_eq!(err.code(), "invalid_argument", "{err}");
    let err = vault
        .acknowledge_truncations(&[detection_id + 1])
        .unwrap_err();
    assert_eq!(err.code(), "invalid_argument", "{err}");
    assert!(err.to_string().contains(&detection_id.to_string()), "{err}");
    assert!(
        events_of(&vault, AuditOperation::AuditVerify, AuditOutcome::Success).is_empty(),
        "a refused acknowledgement writes nothing"
    );
    assert_blocked(&vault.get_secret("k", None).unwrap_err());

    // The real one: exactly one keyed success row, naming the detection,
    // after which the same handle and a plain unlock both work.
    let ack = vault.acknowledge_truncations(&[detection_id]).unwrap();
    assert_eq!(ack.truncations.len(), 1);
    assert_eq!(ack.truncations[0].id, detection_id);
    let acks = events_of(&vault, AuditOperation::AuditVerify, AuditOutcome::Success);
    assert_eq!(acks.len(), 1, "{acks:?}");
    assert_eq!(acks[0].id, ack.event_id);
    assert!(ack.event_id > detection_id);
    let detail = acks[0].detail.clone().unwrap_or_default();
    assert!(detail.starts_with("truncation acknowledged"), "{detail}");
    assert!(detail.contains(&detection_id.to_string()), "{detail}");
    assert!(!format!("{ack:?}").contains(CANARY));
    let pending = vault.unacknowledged_truncations().unwrap();
    assert!(pending.is_empty(), "{pending:?}");
    assert_eq!(
        vault.get_secret("k", None).unwrap().value.expose(),
        CANARY.as_bytes()
    );
    drop(vault);

    let vault = fx.open_vault("dev");
    set_with(&vault, "k2", "v", SetSecretOptions::default());
    assert_eq!(vault.list_properties_of_secrets().unwrap().len(), 2);
    let check = vault.verify_audit_chain().unwrap();
    assert_eq!(check.truncations, 1, "the detection stays on record");
    assert_eq!(check.unacknowledged, 0);
    assert!(check.head_valid);
    assert_eq!(check.first_broken, None);
    assert!(
        !check.is_intact(),
        "an acknowledged truncation is still a truncation"
    );

    // Nothing left to acknowledge: refused, and nothing written.
    let err = vault.acknowledge_truncations(&[detection_id]).unwrap_err();
    assert_eq!(err.code(), "invalid_argument", "{err}");
    assert_eq!(
        events_of(&vault, AuditOperation::AuditVerify, AuditOutcome::Success).len(),
        1
    );
    assert_eq!(
        vault.acknowledge_truncations(&[]).unwrap_err().code(),
        "invalid_argument"
    );
    drop(vault);

    // The acknowledgement is chained like everything else: removing it is a
    // second truncation, and it takes the first one's acknowledgement with
    // it, so both are back in front of the owner.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "DELETE FROM audit_events WHERE id >= ?1",
            [i64::try_from(ack.event_id).unwrap()],
        )
        .unwrap();
    }
    assert_eq!(
        fx.registry.open("dev", &unlock).unwrap_err().code(),
        "crypto"
    );
    assert_blocked(&fx.registry.open("dev", &unlock).unwrap_err());
    let again = fx.acknowledge_truncations("dev");
    assert_eq!(again.truncations.len(), 2, "{again:?}");
    assert_eq!(again.truncations[0].id, detection_id);
    let vault = fx.open_vault("dev");
    let check = vault.verify_audit_chain().unwrap();
    assert_eq!(check.truncations, 2, "{check:?}");
    assert_eq!(check.unacknowledged, 0);
    assert_eq!(
        events_of(&vault, AuditOperation::AuditVerify, AuditOutcome::Success).len(),
        1
    );
}

/// A truncation detected by another process between listing and
/// acknowledging is never acknowledged unseen.
#[test]
fn acknowledgement_refuses_a_truncation_it_was_not_shown() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    let ids = {
        let vault = fx.create_vault("dev");
        set_with(&vault, "k", "v", SetSecretOptions::default());
        vault.get_secret("k", None).unwrap();
        vault.get_secret("k", None).unwrap();
        event_ids(&vault)
    };
    truncate_after(&path, ids[ids.len() - 2]);
    let unlock = fx.unlock("dev");
    assert_eq!(
        fx.registry.open("dev", &unlock).unwrap_err().code(),
        "crypto"
    );
    let owner = fx.inspect_vault("dev");
    let shown: Vec<u64> = owner
        .unacknowledged_truncations()
        .unwrap()
        .iter()
        .map(|e| e.id)
        .collect();
    assert_eq!(shown.len(), 1);

    // Meanwhile the log loses its tail again and another unlock records it.
    let newest = *event_ids(&owner).last().unwrap();
    truncate_after(&path, newest - 1);
    assert_eq!(
        fx.registry.open("dev", &unlock).unwrap_err().code(),
        "crypto"
    );

    // The owner's acknowledgement names only what it saw: refused, nothing
    // written, and the vault stays blocked.
    let err = owner.acknowledge_truncations(&shown).unwrap_err();
    assert_eq!(err.code(), "invalid_argument", "{err}");
    let acks = events_of(&owner, AuditOperation::AuditVerify, AuditOutcome::Success);
    assert!(acks.is_empty(), "nothing may be written: {acks:?}");
    assert_blocked(&fx.registry.open("dev", &unlock).unwrap_err());
    let pending = owner.unacknowledged_truncations().unwrap();
    assert_eq!(pending.len(), 2, "{pending:?}");

    // Listed afresh, both can be acknowledged. A stale head at that moment
    // is recorded and refused rather than swept in.
    let newest = *event_ids(&owner).last().unwrap();
    truncate_after(&path, newest - 1);
    let ids: Vec<u64> = pending.iter().map(|e| e.id).collect();
    let err = owner.acknowledge_truncations(&ids).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert!(
        err.to_string().contains("rows removed after event"),
        "{err}"
    );
    assert_eq!(owner.unacknowledged_truncations().unwrap().len(), 3);
    let ack = fx.acknowledge_truncations("dev");
    assert_eq!(ack.truncations.len(), 3);
    assert!(fx.registry.open("dev", &unlock).is_ok());
}

// ---------------------------------------------------------------------------
// Vault creation reserves the path (review R2)
// ---------------------------------------------------------------------------

#[test]
fn concurrent_creation_yields_exactly_one_vault_that_survives() {
    const CREATORS: usize = 8;
    let fx = Fixture::new();
    std::fs::create_dir_all(fx.registry.vaults_dir()).unwrap();
    let path = fx.registry.vault_path("race").unwrap();
    let barrier = Arc::new(Barrier::new(CREATORS));
    let workers: Vec<_> = (0..CREATORS)
        .map(|i| {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                SqliteVault::create(&path, "race", CreateVaultOptions::default(), no_store())
                    .map(|created| (i, created.recovery_key.to_string()))
                    .map_err(|err| err.code().to_owned())
            })
        })
        .collect();
    let results: Vec<Result<(usize, String), String>> =
        workers.into_iter().map(|w| w.join().unwrap()).collect();

    let winners: Vec<(usize, String)> = results.iter().filter_map(|r| r.clone().ok()).collect();
    assert_eq!(winners.len(), 1, "{results:?}");
    assert!(
        results
            .iter()
            .filter(|r| r.is_err())
            .all(|r| *r == Err("vault_exists".to_owned())),
        "{results:?}"
    );
    assert!(path.is_file(), "a losing creator removed the winner's file");

    // The winner's vault reopens with the winner's recovery key and holds
    // exactly the winner's key wrap.
    let (_, key) = &winners[0];
    let vault = fx
        .registry
        .open("race", &StaticRecoveryKey::new(key.as_str()))
        .unwrap();
    assert_eq!(vault.wraps().unwrap().len(), 1);
    assert!(vault.verify_audit_chain().unwrap().is_intact());
}

// ---------------------------------------------------------------------------
// Rejected operations are audited failures (review R5)
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines)] // one block per rejected input kind, deliberately exhaustive
fn rejected_operations_are_audited_failures() {
    let fx = Fixture::new();
    let vault = fx.create_vault("dev");
    set_with(&vault, "k", "v", SetSecretOptions::default());
    let failures = |op| events_of(&vault, op, AuditOutcome::Failure);
    let newest = || {
        vault
            .audit_events(AuditQuery {
                limit: Some(1),
                ..Default::default()
            })
            .unwrap()
            .remove(0)
    };
    let now = timestamp::now();
    let backwards = (Some(now + Duration::days(2)), Some(now + Duration::days(1)));

    // A rejected time window on set: audited, and nothing created.
    let err = vault
        .set_secret(
            "w",
            SecretBytes::from("v"),
            SetSecretOptions {
                not_before: backwards.0,
                expires_on: backwards.1,
                ..Default::default()
            },
        )
        .unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    let set_failures = failures(AuditOperation::SecretSet);
    assert_eq!(set_failures.len(), 1, "{set_failures:?}");
    assert_eq!(set_failures[0].secret_name.as_deref(), Some("w"));
    assert_eq!(set_failures[0].detail.as_deref(), Some("invalid_argument"));
    assert_eq!(vault.list_properties_of_secrets().unwrap().len(), 1);

    // A rejected window on update, and an empty update.
    let err = vault
        .update_secret_properties(
            "k",
            None,
            UpdateSecretProperties {
                not_before: Some(backwards.0),
                expires_on: Some(backwards.1),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    assert_eq!(failures(AuditOperation::SecretUpdate).len(), 1);
    let err = vault
        .update_secret_properties("k", None, UpdateSecretProperties::default())
        .unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    assert_eq!(failures(AuditOperation::SecretUpdate).len(), 2);
    assert_eq!(newest().secret_name.as_deref(), Some("k"));

    // An invalid name on every mutation: audited without the name, which is
    // arbitrary input.
    let bad = "not_a_name";
    let attempts: Vec<(AuditOperation, sourceorrery_core::SecretError)> = vec![
        (
            AuditOperation::SecretSet,
            vault
                .set_secret(bad, SecretBytes::from("v"), SetSecretOptions::default())
                .unwrap_err(),
        ),
        (
            AuditOperation::SecretGet,
            vault.get_secret(bad, None).unwrap_err(),
        ),
        (
            AuditOperation::SecretUpdate,
            vault
                .update_secret_properties(
                    bad,
                    None,
                    UpdateSecretProperties {
                        enabled: Some(false),
                        ..Default::default()
                    },
                )
                .unwrap_err(),
        ),
        (
            AuditOperation::SecretDelete,
            vault.delete_secret(bad).unwrap_err(),
        ),
        (
            AuditOperation::SecretRecover,
            vault.recover_deleted_secret(bad).unwrap_err(),
        ),
        (
            AuditOperation::SecretPurge,
            vault.purge_deleted_secret(bad).unwrap_err(),
        ),
    ];
    for (op, err) in attempts {
        assert_eq!(err.code(), "invalid_name", "{op:?}");
        // Events come newest first.
        let recorded = failures(op);
        let newest = recorded
            .first()
            .unwrap_or_else(|| panic!("{op:?} failure not audited"));
        assert_eq!(newest.detail.as_deref(), Some("invalid_name"), "{op:?}");
        assert_eq!(newest.secret_name, None, "{op:?} must not record the input");
    }

    // Rejected view-check changes: an authenticator without a password,
    // and removing one that is not there.
    assert_eq!(
        vault.enrol_authenticator().map(drop).unwrap_err().code(),
        "invalid_argument"
    );
    assert_eq!(
        vault.remove_authenticator().unwrap_err().code(),
        "invalid_argument"
    );
    assert_eq!(failures(AuditOperation::Guard).len(), 2);
    assert!(vault.view_check().unwrap().is_none());

    // None of it touched the secret, and the chain is whole.
    assert_eq!(vault.get_secret("k", None).unwrap().value.expose(), b"v");
    assert!(vault.verify_audit_chain().unwrap().is_intact());
}

// ---------------------------------------------------------------------------
// Values are read one version at a time
// ---------------------------------------------------------------------------

#[test]
fn damaged_value_on_one_version_does_not_affect_the_others() {
    // Metadata tags do not cover the ciphertext, so a damaged value is only
    // discovered on decryption. That must happen for the one version being
    // returned, after it has been selected on metadata, and never for the
    // other versions of the secret: listing, inspecting and reading the
    // intact versions must not touch the damaged ones.
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    let (old, mid, new) = {
        let vault = fx.create_vault("dev");
        let version = |value: &str| {
            vault
                .set_secret("k", SecretBytes::from(value), SetSecretOptions::default())
                .unwrap()
                .version
        };
        (
            version("old-value"),
            version("mid-value"),
            version("new-value"),
        )
    };
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        // A flipped ciphertext byte fails authentication on decryption...
        let mut blob: Vec<u8> = conn
            .query_row(
                "SELECT ciphertext FROM secret_versions WHERE version = ?1",
                [&old],
                |row| row.get(0),
            )
            .unwrap();
        blob[0] ^= 0x01;
        conn.execute(
            "UPDATE secret_versions SET ciphertext = ?2 WHERE version = ?1",
            rusqlite::params![&old, blob],
        )
        .unwrap();
        // ...and a nonce of the wrong length cannot even be parsed.
        conn.execute(
            "UPDATE secret_versions SET nonce = X'' WHERE version = ?1",
            [&mid],
        )
        .unwrap();
    }
    let vault = fx.open_vault("dev");

    // The intact version is unaffected, selected by policy or by id.
    assert_eq!(
        vault.get_secret("k", None).unwrap().value.expose(),
        b"new-value"
    );
    assert_eq!(
        vault.get_secret("k", Some(&new)).unwrap().value.expose(),
        b"new-value"
    );

    // The damaged versions fail with `crypto`, and only when asked for;
    // their metadata is intact and still inspectable.
    for version in [&old, &mid] {
        let err = vault.get_secret("k", Some(version)).unwrap_err();
        assert_eq!(err.code(), "crypto", "{err}");
        assert_eq!(
            vault
                .get_secret_properties("k", Some(version))
                .unwrap()
                .version,
            *version
        );
    }
    assert_eq!(
        vault.list_properties_of_secret_versions("k").unwrap().len(),
        3
    );
    assert_eq!(vault.list_properties_of_secrets().unwrap().len(), 1);

    // Selection happens on metadata first: with the newest version disabled,
    // policy picks `mid`, and that version's damaged value is what fails.
    vault
        .update_secret_properties(
            "k",
            Some(&new),
            UpdateSecretProperties {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    let err = vault.get_secret("k", None).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    let failures = events_of(&vault, AuditOperation::SecretGet, AuditOutcome::Failure);
    assert!(
        failures
            .iter()
            .any(|e| e.version.as_deref() == Some(mid.as_str())
                && e.detail.as_deref() == Some("crypto")),
        "the refusal names the version whose value failed: {failures:?}"
    );
    // Nothing above touched the metadata or the audit log.
    assert!(vault.verify_audit_chain().unwrap().is_intact());
}

/// A file found under one vault's name that holds another vault.
fn assert_mismatch(err: &sourceorrery_core::SecretError, requested: &str, found: &str) {
    assert_eq!(err.code(), "vault_mismatch", "{err}");
    assert_eq!(
        err.to_string(),
        format!("the file for vault '{requested}' holds the vault '{found}'")
    );
}

#[test]
fn a_vault_file_under_another_name_is_refused() {
    let fx = Fixture::new();
    set_with(
        &fx.create_vault("dev"),
        "db-password",
        "dev-value",
        SetSecretOptions::default(),
    );
    let dev_path = fx.registry.vault_path("dev").unwrap();
    let prod_path = fx.registry.vault_path("prod").unwrap();
    std::fs::copy(&dev_path, &prod_path).unwrap();
    let unlock = fx.unlock("dev");

    // Every way of opening by name refuses the copy once its stored name
    // is authenticated: it unlocks, but it is not the vault asked for.
    assert_mismatch(
        &fx.registry.open("prod", &unlock).unwrap_err(),
        "prod",
        "dev",
    );
    assert_mismatch(
        &fx.registry
            .open_for_inspection("prod", &unlock)
            .unwrap_err(),
        "prod",
        "dev",
    );

    // Each refusal is on the copy's own log; the original never saw them.
    {
        let copy = SqliteVault::open(&prod_path, no_store(), &unlock).unwrap();
        assert_eq!(open_refusals(&copy, "opened as vault 'prod'"), 2);
        assert!(copy.verify_audit_chain().unwrap().is_intact());
        let dev = fx.open_vault("dev");
        assert_eq!(open_refusals(&dev, "opened as vault 'prod'"), 0);
        assert_eq!(
            dev.get_secret("db-password", None).unwrap().value.expose(),
            b"dev-value"
        );
    }

    // Moved back under its own name, the file is the vault it says it is.
    std::fs::remove_file(&dev_path).unwrap();
    std::fs::rename(&prod_path, &dev_path).unwrap();
    assert_eq!(
        fx.open_vault("dev")
            .get_secret("db-password", None)
            .unwrap()
            .value
            .expose(),
        b"dev-value"
    );
}

#[test]
fn swapped_vault_files_are_not_served_under_each_others_names() {
    let fx = Fixture::new();
    let registry =
        VaultRegistry::with_root(fx.home.path()).with_store(Arc::new(MemoryStore::new()));
    for (name, value) in [("dev", "dev-value"), ("prod", "prod-value")] {
        let created = registry
            .create(name, CreateVaultOptions::default())
            .unwrap();
        assert!(created.this_machine);
        set_with(
            &created.vault,
            "db-password",
            value,
            SetSecretOptions::default(),
        );
    }
    let dev = registry.vault_path("dev").unwrap();
    let prod = registry.vault_path("prod").unwrap();
    let parked = dev.with_extension("parked");
    std::fs::rename(&prod, &parked).unwrap();
    std::fs::rename(&dev, &prod).unwrap();
    std::fs::rename(&parked, &dev).unwrap();

    // This machine's store opens both files without asking: only the name
    // check stands between an application asking for `prod` and the
    // development secrets.
    assert_mismatch(
        &registry.open("prod", &NoInteraction).unwrap_err(),
        "prod",
        "dev",
    );
    assert_mismatch(
        &registry.open("dev", &NoInteraction).unwrap_err(),
        "dev",
        "prod",
    );
}
