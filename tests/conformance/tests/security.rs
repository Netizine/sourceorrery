//! Security conformance: what must never happen.

use std::collections::BTreeMap;
use std::path::Path;

use sourceorrery_conformance::{FIXTURE_PASSPHRASE, Fixture};
use sourceorrery_core::{
    AuditEvent, AuditOperation, AuditOutcome, AuditQuery, Manifest, SecretBytes, SecretClient,
    SetSecretOptions, timestamp,
};
use sourceorrery_crypto::{Argon2Params, SymmetricKey, aead, envelope, kdf, random};
use sourceorrery_storage::{SqliteVault, StaticPassphrase};
use time::Duration;

const CANARY: &str = "CANARY-7f3a9c2e-plaintext-must-never-appear";

fn canary_bytes() -> Vec<u8> {
    CANARY.as_bytes().to_vec()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn vault_file_never_contains_plaintext_or_passphrase() {
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
    assert!(
        !contains(&bytes, FIXTURE_PASSPHRASE.as_bytes()),
        "passphrase found in vault file"
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
    assert!(!dump.contains(FIXTURE_PASSPHRASE));
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
fn wrong_passphrase_is_refused_and_recorded() {
    let fx = Fixture::new();
    fx.create_vault("dev");
    let err = fx
        .registry
        .open("dev", &StaticPassphrase::new("not-the-passphrase"))
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
            .open("dev", &StaticPassphrase::new("wrong"))
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

#[test]
fn deleted_middle_audit_row_breaks_the_chain() {
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
    let vault = fx.open_vault("dev");
    let check = vault.verify_audit_chain().unwrap();
    assert!(!check.is_intact());
    assert_eq!(
        check.first_broken,
        Some(ids[2]),
        "the row after the gap no longer links to its predecessor: {check:?}"
    );
    assert_eq!(check.truncations, 0);
    assert!(check.head_valid);
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
    let vault = fx.open_vault("dev");
    let check = vault.verify_audit_chain().unwrap();
    assert_eq!(check.first_broken, Some(denied_id), "{check:?}");
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
    let keep_up_to = i64::try_from(ids[ids.len() - 3]).unwrap();
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("DELETE FROM audit_events WHERE id > ?1", [keep_up_to])
            .unwrap();
    }
    // Opening appends a keyed row; that write finds the head stale and
    // records it before re-anchoring the chain.
    let vault = fx.open_vault("dev");
    let check = vault.verify_audit_chain().unwrap();
    assert!(!check.is_intact(), "{check:?}");
    assert_eq!(check.first_broken, None, "remaining rows still link");
    assert_eq!(check.truncations, 1);
    assert!(check.head_valid, "the detection re-anchored the head");
    let detections = events_of(&vault, AuditOperation::AuditVerify, AuditOutcome::Failure);
    assert_eq!(detections.len(), 1);
    let detail = detections[0].detail.clone().unwrap_or_default();
    assert!(detail.contains("rows removed after event"), "{detail}");

    // The evidence is itself chained: it survives further use ...
    vault.get_secret("k", None).unwrap();
    let check = vault.verify_audit_chain().unwrap();
    assert_eq!(check.truncations, 1);
    assert!(!check.is_intact());
    drop(vault);

    // ... and removing it is just another truncation.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "DELETE FROM audit_events
             WHERE id >= (SELECT MIN(id) FROM audit_events WHERE operation = 'audit_verify')",
            [],
        )
        .unwrap();
    }
    let vault = fx.open_vault("dev");
    let check = vault.verify_audit_chain().unwrap();
    assert_eq!(check.truncations, 1, "{check:?}");
    assert!(!check.is_intact());
}

#[test]
fn deleted_chain_head_is_detected() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    fx.create_vault("dev");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("DELETE FROM vault_meta WHERE key = 'audit_head'", [])
            .unwrap();
    }
    let vault = fx.open_vault("dev");
    let check = vault.verify_audit_chain().unwrap();
    assert_eq!(check.truncations, 1, "{check:?}");
    let detections = events_of(&vault, AuditOperation::AuditVerify, AuditOutcome::Failure);
    assert_eq!(
        detections[0].detail.as_deref(),
        Some("audit chain head missing")
    );
}

// ---------------------------------------------------------------------------
// Schema 1 vaults migrate forward on first unlock
// ---------------------------------------------------------------------------

/// The milestone 1 on-disk schema, verbatim.
const SCHEMA_V1: &str = "
CREATE TABLE vault_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE key_protectors (
    id TEXT PRIMARY KEY, label TEXT NOT NULL UNIQUE, kind_json TEXT NOT NULL,
    wrapped_nonce BLOB NOT NULL, wrapped_dek BLOB NOT NULL, created_on INTEGER NOT NULL);
CREATE TABLE secrets (
    name TEXT PRIMARY KEY, created_on INTEGER NOT NULL, deleted_on INTEGER,
    scheduled_purge_on INTEGER, recovery_id TEXT);
CREATE TABLE secret_versions (
    name TEXT NOT NULL REFERENCES secrets(name) ON DELETE CASCADE, version TEXT NOT NULL,
    seq INTEGER NOT NULL UNIQUE, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
    content_type TEXT, tags_json TEXT NOT NULL, enabled INTEGER NOT NULL,
    not_before INTEGER, expires_on INTEGER, created_on INTEGER NOT NULL,
    updated_on INTEGER NOT NULL, PRIMARY KEY (name, version));
CREATE INDEX secret_versions_by_seq ON secret_versions(name, seq DESC);
CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_on INTEGER NOT NULL, actor TEXT NOT NULL,
    operation TEXT NOT NULL, secret_name TEXT, version TEXT, outcome TEXT NOT NULL, detail TEXT);
CREATE INDEX audit_events_by_secret ON audit_events(secret_name, id DESC);
";

struct LegacyVault {
    alpha_old: String,
    alpha_new: String,
}

/// Writes schema 1 rows the way the milestone 1 build did.
struct V1Writer<'a> {
    conn: &'a rusqlite::Connection,
    dek: SymmetricKey,
    vault_id: String,
    now: i64,
    seq: i64,
}

impl V1Writer<'_> {
    /// Install a passphrase protector for [`FIXTURE_PASSPHRASE`] with
    /// testing KDF parameters, wrapping the DEK under the schema 1 AAD.
    fn protector(&self) {
        let protector_id = random::random_hex(8).unwrap();
        let salt = random::random_bytes::<{ sourceorrery_crypto::SALT_LEN }>().unwrap();
        let params = Argon2Params::TESTING;
        let kek = kdf::derive_key(FIXTURE_PASSPHRASE.as_bytes(), &salt, params).unwrap();
        let wrapped = envelope::wrap_key(
            &kek,
            &self.dek,
            format!("sourceorrery/v1/protector/{}/{protector_id}", self.vault_id).as_bytes(),
        )
        .unwrap();
        let kind_json = format!(
            "{{\"kind\":\"passphrase\",\"salt\":\"{}\",\"params\":{{\"memory_kib\":{},\"iterations\":{},\"parallelism\":{}}}}}",
            hex::encode(salt),
            params.memory_kib,
            params.iterations,
            params.parallelism
        );
        self.conn
            .execute(
                "INSERT INTO key_protectors
                    (id, label, kind_json, wrapped_nonce, wrapped_dek, created_on)
                 VALUES (?1, 'passphrase', ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    protector_id,
                    kind_json,
                    wrapped.nonce.as_slice(),
                    wrapped.bytes,
                    self.now
                ],
            )
            .unwrap();
    }

    /// Encrypt `value` under the schema 1 value AAD and insert a version row.
    fn version(
        &mut self,
        name: &str,
        value: &str,
        enabled: bool,
        expires_on: Option<i64>,
    ) -> String {
        self.seq += 1;
        let version = random::random_hex(16).unwrap();
        let ct = aead::seal(
            &self.dek,
            format!("sourceorrery/v1/value/{}/{name}/{version}", self.vault_id).as_bytes(),
            value.as_bytes(),
        )
        .unwrap();
        self.conn
            .execute(
                "INSERT INTO secret_versions
                    (name, version, seq, nonce, ciphertext, content_type, tags_json, enabled,
                     not_before, expires_on, created_on, updated_on)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, '{}', ?6, NULL, ?7, ?8, ?8)",
                rusqlite::params![
                    name,
                    version,
                    self.seq,
                    ct.nonce.as_slice(),
                    ct.bytes,
                    i64::from(enabled),
                    expires_on,
                    self.now
                ],
            )
            .unwrap();
        version
    }

    /// Insert a schema 1 audit row (no chain columns).
    fn audit(
        &self,
        op: &str,
        name: Option<&str>,
        ver: Option<&str>,
        outcome: &str,
        detail: Option<&str>,
    ) {
        self.conn
            .execute(
                "INSERT INTO audit_events
                    (occurred_on, actor, operation, secret_name, version, outcome, detail)
                 VALUES (?1, 'user:legacy', ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![self.now, op, name, ver, outcome, detail],
            )
            .unwrap();
    }
}

/// Write a schema 1 vault file by hand, exactly as the milestone 1 build
/// did (`*.sorvault` fixtures are git-ignored by policy, so the fixture is
/// constructed rather than checked in). Passphrase: [`FIXTURE_PASSPHRASE`].
fn craft_schema_1_vault(path: &Path) -> LegacyVault {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch(SCHEMA_V1).unwrap();
    let vault_id = random::random_hex(16).unwrap();
    let now = i64::try_from(timestamp::to_unix_nanos(timestamp::now())).unwrap();
    for (key, value) in [
        ("schema_version", "1".to_owned()),
        ("name", "legacy".to_owned()),
        ("id", vault_id.clone()),
        ("created_on", now.to_string()),
        ("recovery_level", "\"recoverable\"".to_owned()),
        ("retention_days", "90".to_owned()),
    ] {
        conn.execute(
            "INSERT INTO vault_meta (key, value) VALUES (?1, ?2)",
            [key, value.as_str()],
        )
        .unwrap();
    }
    for name in ["alpha", "beta"] {
        conn.execute(
            "INSERT INTO secrets (name, created_on) VALUES (?1, ?2)",
            rusqlite::params![name, now],
        )
        .unwrap();
    }

    let mut w = V1Writer {
        conn: &conn,
        dek: SymmetricKey::generate().unwrap(),
        vault_id,
        now,
        seq: 0,
    };
    w.protector();
    let alpha_old = w.version("alpha", "alpha-old", false, None);
    let alpha_new = w.version("alpha", "alpha-new", true, None);
    let fifty_years = 50 * 365 * 24 * 3600 * 1_000_000_000i64;
    let beta = w.version("beta", "beta-value", true, Some(now + fifty_years));

    w.audit(
        "vault_create",
        None,
        None,
        "success",
        Some("encrypted-sqlite"),
    );
    w.audit(
        "secret_set",
        Some("alpha"),
        Some(&alpha_old),
        "success",
        None,
    );
    w.audit(
        "secret_set",
        Some("alpha"),
        Some(&alpha_new),
        "success",
        None,
    );
    w.audit("secret_set", Some("beta"), Some(&beta), "success", None);
    w.audit(
        "vault_open",
        None,
        None,
        "denied",
        Some("incorrect passphrase"),
    );
    w.audit("vault_open", None, None, "failure", Some("locked"));
    LegacyVault {
        alpha_old,
        alpha_new,
    }
}

fn migrations(vault: &SqliteVault) -> usize {
    events_of(vault, AuditOperation::VaultMigrate, AuditOutcome::Success).len()
}

#[test]
fn schema_1_vault_is_migrated_forward_and_protected() {
    let fx = Fixture::new();
    std::fs::create_dir_all(fx.registry.vaults_dir()).unwrap();
    let path = fx.registry.vault_path("legacy").unwrap();
    let legacy = craft_schema_1_vault(&path);

    // A legacy file is never opened silently: migration is an explicit step.
    let err = fx
        .registry
        .open("legacy", &StaticPassphrase::new(FIXTURE_PASSPHRASE))
        .unwrap_err();
    assert_eq!(err.code(), "migration_required", "{err}");

    // The explicit migration unlocks, converts, and leaves data and policy unchanged.
    let vault = fx.migrate_vault("legacy");
    let alpha = vault.get_secret("alpha", None).unwrap();
    assert_eq!(alpha.properties.version, legacy.alpha_new);
    assert_eq!(alpha.value.expose(), b"alpha-new");
    assert_eq!(
        vault
            .get_secret("alpha", Some(&legacy.alpha_old))
            .unwrap_err()
            .code(),
        "disabled"
    );
    assert_eq!(
        vault.get_secret("beta", None).unwrap().value.expose(),
        b"beta-value"
    );
    assert_eq!(vault.list_properties_of_secrets().unwrap().len(), 2);
    assert_eq!(migrations(&vault), 1);

    // Historical audit rows are chained under the vault key.
    let check = vault.verify_audit_chain().unwrap();
    assert!(check.is_intact(), "{check:?}");
    assert_eq!(check.unkeyed, 0);
    let events = vault.audit_events(AuditQuery::default()).unwrap();
    assert_eq!(check.rows, u64::try_from(events.len()).unwrap());
    assert!(
        events
            .iter()
            .any(|e| e.operation == AuditOperation::VaultOpen && e.outcome == AuditOutcome::Denied),
        "pre-migration rows survive"
    );
    drop(vault);

    // The file now says schema 2, and a second unlock does not migrate again.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let schema: String = conn
            .query_row(
                "SELECT value FROM vault_meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(schema, "2");
    }
    let vault = fx.open_vault("legacy");
    assert_eq!(migrations(&vault), 1);
    assert!(vault.verify_audit_chain().unwrap().is_intact());
    drop(vault);

    // Migrated rows are protected exactly like new ones.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE secret_versions SET enabled = 1 WHERE version = ?1",
            [&legacy.alpha_old],
        )
        .unwrap();
    }
    let vault = fx.open_vault("legacy");
    assert_eq!(
        vault
            .get_secret("alpha", Some(&legacy.alpha_old))
            .unwrap_err()
            .code(),
        "crypto"
    );
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
    let err = fx
        .registry
        .open("dev", &StaticPassphrase::new(FIXTURE_PASSPHRASE))
        .unwrap_err();
    assert_eq!(err.code(), "storage");
    assert!(err.to_string().contains("not supported"), "{err}");
}

// ---------------------------------------------------------------------------
// Format boundary: a rolled-back schema marker is not a legacy vault
// ---------------------------------------------------------------------------

/// The attack from the review: take a schema 2 vault, edit policy and
/// history, strip the integrity data and set the marker back to 1, then let
/// the owner unlock it so the migration re-authenticates the edits.
fn roll_back_to_schema_1(path: &Path) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch(
        "UPDATE vault_meta SET value = '1' WHERE key = 'schema_version';
         DELETE FROM vault_meta WHERE key IN ('audit_head', 'settings_tag');
         UPDATE secret_versions SET enabled = 1, tag = NULL;
         UPDATE secrets SET tag = NULL;
         UPDATE audit_events SET outcome = 'success', prev_hash = NULL, hash = NULL, keyed = 0;",
    )
    .unwrap();
}

#[test]
fn rolled_back_schema_marker_is_refused_by_open_and_by_migrate() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    {
        let vault = fx.create_vault("dev");
        set_with(
            &vault,
            "k",
            CANARY,
            SetSecretOptions {
                enabled: false,
                ..Default::default()
            },
        );
        assert_eq!(vault.get_secret("k", None).unwrap_err().code(), "disabled");
    }
    roll_back_to_schema_1(&path);

    // Plain open never migrates.
    let unlock = StaticPassphrase::new(FIXTURE_PASSPHRASE);
    let err = fx.registry.open("dev", &unlock).unwrap_err();
    assert_eq!(err.code(), "migration_required", "{err}");

    // The explicit migration sees a key bound to schema 2 and refuses.
    let err = fx.registry.migrate("dev", &unlock).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert!(
        err.to_string().contains("rolled back") || err.to_string().contains("altered"),
        "{err}"
    );

    // Nothing was laundered: the disabled secret is still unreadable.
    let still_locked = fx.registry.open("dev", &unlock).unwrap_err();
    assert_eq!(still_locked.code(), "migration_required");
}

#[test]
fn migrated_legacy_vault_cannot_be_rolled_back_again() {
    let fx = Fixture::new();
    std::fs::create_dir_all(fx.registry.vaults_dir()).unwrap();
    let path = fx.registry.vault_path("legacy").unwrap();
    let legacy = craft_schema_1_vault(&path);

    // Genuine legacy file: the explicit migration is allowed once.
    let vault = fx.migrate_vault("legacy");
    assert_eq!(
        vault
            .get_secret("alpha", Some(&legacy.alpha_old))
            .unwrap_err()
            .code(),
        "disabled"
    );
    drop(vault);

    // The migration re-wrapped the unlocking key under schema 2, so the same
    // trick no longer works on this file.
    roll_back_to_schema_1(&path);
    let err = fx
        .registry
        .migrate("legacy", &StaticPassphrase::new(FIXTURE_PASSPHRASE))
        .unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
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
    let vault = fx.open_vault("dev");
    let check = vault.verify_audit_chain().unwrap();
    assert!(!check.is_intact(), "{check:?}");
    assert_eq!(check.truncations, 1, "{check:?}");
    let detections = events_of(&vault, AuditOperation::AuditVerify, AuditOutcome::Failure);
    assert!(
        detections[0]
            .detail
            .as_deref()
            .is_some_and(|d| d.contains("history missing")),
        "{detections:?}"
    );
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
    fx.registry
        .open("dev", &StaticPassphrase::new(FIXTURE_PASSPHRASE))
        .unwrap_err()
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
// Resource ceilings before authentication
// ---------------------------------------------------------------------------

#[test]
fn oversized_kdf_parameters_are_skipped_not_run() {
    let fx = Fixture::new();
    let path = fx.registry.vault_path("dev").unwrap();
    fx.create_vault("dev");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE key_protectors SET kind_json = replace(kind_json, '\"iterations\":1', '\"iterations\":100000')",
            [],
        )
        .unwrap();
    }
    let started = std::time::Instant::now();
    let err = fx
        .registry
        .open("dev", &StaticPassphrase::new(FIXTURE_PASSPHRASE))
        .unwrap_err();
    assert_eq!(err.code(), "locked", "{err}");
    assert!(err.to_string().contains("limits"), "{err}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "unlock ran the oversized KDF"
    );
}

// ---------------------------------------------------------------------------
// Destroying a vault must not reach into another vault's keyring entry
// ---------------------------------------------------------------------------

fn vault_id(path: &Path) -> String {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.query_row("SELECT value FROM vault_meta WHERE key = 'id'", [], |r| {
        r.get(0)
    })
    .unwrap()
}

fn insert_keyring_protector_row(path: &Path, protector_id: &str, account: &str) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute(
        "INSERT INTO key_protectors (id, label, kind_json, wrapped_nonce, wrapped_dek, created_on)
         VALUES (?1, ?2, ?3, zeroblob(24), zeroblob(48), 0)",
        rusqlite::params![
            protector_id,
            format!("fake-{protector_id}"),
            format!(
                "{{\"kind\":\"os-keyring\",\"service\":\"sourceorrery\",\"account\":\"{account}\"}}"
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
    insert_keyring_protector_row(&dev, "aaaaaaaa", &format!("vault/{other_id}/aaaaaaaa"));
    // 2. An account that matches this vault's identity but is also listed by
    //    a sibling vault file (a cloned vault).
    let shared = format!("vault/{dev_id}/bbbbbbbb");
    insert_keyring_protector_row(&dev, "bbbbbbbb", &shared);
    insert_keyring_protector_row(&other, "bbbbbbbb", &shared);

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
    insert_keyring_protector_row(&other, "cccccccc", &format!("vault/{other_id}/cccccccc"));
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
