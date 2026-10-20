//! Security conformance: what must never happen.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Barrier};

use sourceorrery_conformance::{FIXTURE_PASSPHRASE, Fixture};
use sourceorrery_core::{
    AuditEvent, AuditOperation, AuditOutcome, AuditQuery, Manifest, SecretBytes, SecretClient,
    SetSecretOptions, UpdateSecretProperties, timestamp,
};
use sourceorrery_crypto::{Argon2Params, SymmetricKey, aead, envelope, kdf, random};
use sourceorrery_storage::{CreateVaultOptions, ProtectorSpec, SqliteVault, StaticPassphrase};
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
    // The next unlock finds the head stale. Row state is judged against the
    // chain, so a shortened chain cannot be consulted: the unlock is refused,
    // and recording the refusal puts the detection itself on the chain and
    // re-anchors the head.
    let unlock = StaticPassphrase::new(FIXTURE_PASSPHRASE);
    let err = fx.registry.open("dev", &unlock).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert!(
        err.to_string().contains("rows removed after event"),
        "{err}"
    );

    // The vault is usable again, with the truncation permanently on record.
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
    let refusals = events_of(&vault, AuditOperation::VaultOpen, AuditOutcome::Failure);
    assert!(
        refusals
            .iter()
            .any(|e| e.detail.as_deref() == Some("audit log truncated")),
        "{refusals:?}"
    );

    // The evidence is itself chained: it survives further use ...
    vault.get_secret("k", None).unwrap();
    let check = vault.verify_audit_chain().unwrap();
    assert_eq!(check.truncations, 1);
    assert!(!check.is_intact());
    drop(vault);

    // ... and removing it is just another truncation: refused once more,
    // then back on record.
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
    let err = fx
        .registry
        .open("dev", &StaticPassphrase::new(FIXTURE_PASSPHRASE))
        .unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert!(err.to_string().contains("head missing"), "{err}");
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

/// Completed migrations: the summary `vault_migrate` rows, not the
/// per-row checkpoints a migration also records.
fn migrations(vault: &SqliteVault) -> usize {
    events_of(vault, AuditOperation::VaultMigrate, AuditOutcome::Success)
        .iter()
        .filter(|e| e.secret_name.is_none())
        .count()
}

/// Checkpoint rows a migration recorded: one per secret and per version.
fn migration_checkpoints(vault: &SqliteVault) -> usize {
    events_of(vault, AuditOperation::VaultMigrate, AuditOutcome::Success)
        .iter()
        .filter(|e| e.secret_name.is_some() && e.detail.as_deref() == Some("checkpoint"))
        .count()
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
    assert_eq!(
        migration_checkpoints(&vault),
        2 + 3,
        "every secret and version row is checkpointed"
    );

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

    // The file now says schema 3, and a second unlock does not migrate again.
    assert_eq!(schema_marker(&path), "3");
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
    let err = fx
        .registry
        .open("dev", &StaticPassphrase::new(FIXTURE_PASSPHRASE))
        .unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert!(err.to_string().contains("history missing"), "{err}");
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

    // An unkeyed row is forgeable by design, so it is never a checkpoint.
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
    let vault = fx.open_vault("dev");
    assert_eq!(vault.get_secret("k", None).unwrap_err().code(), "crypto");
    drop(vault);

    // A row flagged keyed without the key has no valid hash. Appending it
    // also leaves the head stale, so the next unlock is refused and the
    // forgery is recorded; after that the row is still not a checkpoint.
    forge(1);
    let unlock = StaticPassphrase::new(FIXTURE_PASSPHRASE);
    assert_eq!(
        fx.registry.open("dev", &unlock).unwrap_err().code(),
        "crypto"
    );
    let vault = fx.open_vault("dev");
    let err = vault.get_secret("k", None).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert!(err.to_string().contains("does not verify"), "{err}");
    let check = vault.verify_audit_chain().unwrap();
    assert!(check.first_broken.is_some(), "{check:?}");
    assert_eq!(check.truncations, 1, "{check:?}");
}

/// Removing the audit rows that checkpointed a change *and* replaying the
/// rows from before it is a partial snapshot rollback. It cannot be told
/// from the surviving history alone, but it cannot be done quietly: the
/// head is stale, so the next unlock is refused and the truncation is
/// recorded in the chain for good. See the threat model's known gaps.
#[test]
fn truncating_the_log_to_replay_a_row_is_refused_once_and_recorded() {
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
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "DELETE FROM audit_events WHERE id > ?1",
            [i64::try_from(before_disable).unwrap()],
        )
        .unwrap();
    }
    let unlock = StaticPassphrase::new(FIXTURE_PASSPHRASE);
    let err = fx.registry.open("dev", &unlock).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert!(
        err.to_string().contains("rows removed after event"),
        "{err}"
    );

    let vault = fx.open_vault("dev");
    let check = vault.verify_audit_chain().unwrap();
    assert_eq!(check.truncations, 1, "{check:?}");
    assert!(!check.is_intact());
    // The surviving history says the version is enabled, and it is what the
    // vault now goes by: the limit of what the file alone can prove.
    assert!(vault.get_secret("k", None).is_ok());
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
                SqliteVault::create(
                    &path,
                    "race",
                    CreateVaultOptions::default(),
                    ProtectorSpec::Passphrase {
                        passphrase: SecretBytes::from(format!("pass-{i}")),
                        params: Argon2Params::TESTING,
                    },
                )
                .map(|vault| {
                    drop(vault);
                    i
                })
                .map_err(|err| err.code().to_owned())
            })
        })
        .collect();
    let results: Vec<Result<usize, String>> =
        workers.into_iter().map(|w| w.join().unwrap()).collect();

    let winners: Vec<usize> = results.iter().filter_map(|r| r.clone().ok()).collect();
    assert_eq!(winners.len(), 1, "{results:?}");
    assert!(
        results
            .iter()
            .filter(|r| r.is_err())
            .all(|r| *r == Err("vault_exists".to_owned())),
        "{results:?}"
    );
    assert!(path.is_file(), "a losing creator removed the winner's file");

    // The winner's vault reopens with the winner's passphrase and holds
    // exactly the winner's protector.
    let winner = winners[0];
    let vault = fx
        .registry
        .open("race", &StaticPassphrase::new(format!("pass-{winner}")))
        .unwrap();
    assert_eq!(vault.protectors().unwrap().len(), 1);
    assert!(vault.verify_audit_chain().unwrap().is_intact());
    drop(vault);
    let loser = (0..CREATORS).find(|i| *i != winner).unwrap();
    assert_eq!(
        fx.registry
            .open("race", &StaticPassphrase::new(format!("pass-{loser}")))
            .unwrap_err()
            .code(),
        "locked"
    );
}

// ---------------------------------------------------------------------------
// Every accepted protector can unlock (review R4)
// ---------------------------------------------------------------------------

#[test]
fn passphrase_protectors_are_capped_at_what_unlock_will_try() {
    let fx = Fixture::new();
    let vault = fx.create_vault("dev");
    set_with(&vault, "k", "v", SetSecretOptions::default());
    let extra = |i: usize| format!("extra-{i}");
    for i in 1..8 {
        vault
            .add_protector(
                ProtectorSpec::Passphrase {
                    passphrase: SecretBytes::from(extra(i)),
                    params: Argon2Params::TESTING,
                },
                Some(&extra(i)),
            )
            .unwrap();
    }
    assert_eq!(vault.protectors().unwrap().len(), 8);

    let err = vault
        .add_protector(
            ProtectorSpec::Passphrase {
                passphrase: SecretBytes::from(extra(8)),
                params: Argon2Params::TESTING,
            },
            Some(&extra(8)),
        )
        .unwrap_err();
    assert_eq!(err.code(), "invalid_argument", "{err}");
    assert!(err.to_string().contains("at most 8"), "{err}");
    assert_eq!(
        vault.protectors().unwrap().len(),
        8,
        "a rejected addition installs nothing"
    );
    assert_eq!(
        events_of(&vault, AuditOperation::ProtectorAdd, AuditOutcome::Failure).len(),
        1
    );
    drop(vault);

    // Every accepted protector unlocks the vault; the rejected one does not.
    for passphrase in std::iter::once(FIXTURE_PASSPHRASE.to_owned()).chain((1..8).map(extra)) {
        let vault = fx
            .registry
            .open("dev", &StaticPassphrase::new(passphrase.clone()))
            .unwrap_or_else(|err| panic!("{passphrase} must unlock: {err}"));
        assert_eq!(vault.get_secret("k", None).unwrap().value.expose(), b"v");
    }
    assert_eq!(
        fx.registry
            .open("dev", &StaticPassphrase::new(extra(8)))
            .unwrap_err()
            .code(),
        "locked"
    );
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

    // Rejected protector management.
    let err = vault
        .add_protector(
            ProtectorSpec::Passphrase {
                passphrase: SecretBytes::from("another"),
                params: Argon2Params::TESTING,
            },
            Some("passphrase"),
        )
        .unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    assert_eq!(failures(AuditOperation::ProtectorAdd).len(), 1);
    assert_eq!(
        vault.remove_protector("nope").unwrap_err().code(),
        "invalid_argument"
    );
    assert_eq!(
        vault.remove_protector("passphrase").unwrap_err().code(),
        "invalid_argument"
    );
    assert_eq!(failures(AuditOperation::ProtectorRemove).len(), 2);
    assert_eq!(vault.protectors().unwrap().len(), 1);

    // None of it touched the secret, and the chain is whole.
    assert_eq!(vault.get_secret("k", None).unwrap().value.expose(), b"v");
    assert!(vault.verify_audit_chain().unwrap().is_intact());
}

// ---------------------------------------------------------------------------
// Schema 2 vaults migrate forward and gain checkpoints
// ---------------------------------------------------------------------------

/// The schema 2 table layout, as the 20 October 2026 hardening release
/// wrote it.
const SCHEMA_V2: &str = "
CREATE TABLE vault_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE key_protectors (
    id TEXT PRIMARY KEY, label TEXT NOT NULL UNIQUE, kind_json TEXT NOT NULL,
    wrapped_nonce BLOB NOT NULL, wrapped_dek BLOB NOT NULL, created_on INTEGER NOT NULL);
CREATE TABLE secrets (
    name TEXT PRIMARY KEY, created_on INTEGER NOT NULL, deleted_on INTEGER,
    scheduled_purge_on INTEGER, recovery_id TEXT, tag BLOB);
CREATE TABLE secret_versions (
    name TEXT NOT NULL REFERENCES secrets(name) ON DELETE CASCADE, version TEXT NOT NULL,
    seq INTEGER NOT NULL UNIQUE, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
    content_type TEXT, tags_json TEXT NOT NULL, enabled INTEGER NOT NULL,
    not_before INTEGER, expires_on INTEGER, created_on INTEGER NOT NULL,
    updated_on INTEGER NOT NULL, tag BLOB, PRIMARY KEY (name, version));
CREATE INDEX secret_versions_by_seq ON secret_versions(name, seq DESC);
CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_on INTEGER NOT NULL, actor TEXT NOT NULL,
    operation TEXT NOT NULL, secret_name TEXT, version TEXT, outcome TEXT NOT NULL, detail TEXT,
    prev_hash BLOB, hash BLOB, keyed INTEGER NOT NULL DEFAULT 0);
CREATE INDEX audit_events_by_secret ON audit_events(secret_name, id DESC);
";

/// The canonical encoding from `docs/vault-format.md`, written out
/// independently of the storage crate.
#[derive(Default)]
struct Canon(Vec<u8>);

impl Canon {
    fn new(domain: &str, vault_id: &str) -> Self {
        Self::default().str(domain).str(vault_id)
    }
    fn bytes(mut self, b: &[u8]) -> Self {
        self.0
            .extend_from_slice(&u64::try_from(b.len()).unwrap().to_be_bytes());
        self.0.extend_from_slice(b);
        self
    }
    fn str(self, s: &str) -> Self {
        self.bytes(s.as_bytes())
    }
    fn int(mut self, i: i64) -> Self {
        self.0.extend_from_slice(&i.to_be_bytes());
        self
    }
    fn flag(mut self, b: bool) -> Self {
        self.0.push(u8::from(b));
        self
    }
    fn opt_str(self, s: Option<&str>) -> Self {
        match s {
            Some(s) => self.flag(true).str(s),
            None => self.flag(false),
        }
    }
    fn opt_int(self, i: Option<i64>) -> Self {
        match i {
            Some(i) => self.flag(true).int(i),
            None => self.flag(false),
        }
    }
}

/// Writes schema 2 rows the way the schema 2 build did: tagged rows, a keyed
/// audit chain with its head, authenticated settings and a key wrapped under
/// the schema 2 AAD.
struct V2Writer<'a> {
    conn: &'a rusqlite::Connection,
    dek: SymmetricKey,
    meta_key: SymmetricKey,
    vault_id: String,
    now: i64,
    seq: i64,
    prev: [u8; 32],
    head: Option<(i64, [u8; 32])>,
}

impl V2Writer<'_> {
    fn protector(&self) {
        let protector_id = random::random_hex(8).unwrap();
        let salt = random::random_bytes::<{ sourceorrery_crypto::SALT_LEN }>().unwrap();
        let params = Argon2Params::TESTING;
        let kek = kdf::derive_key(FIXTURE_PASSPHRASE.as_bytes(), &salt, params).unwrap();
        let wrapped = envelope::wrap_key(
            &kek,
            &self.dek,
            format!("sourceorrery/v2/protector/{}/{protector_id}", self.vault_id).as_bytes(),
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

    fn secret(&self, name: &str) {
        let tag = sourceorrery_crypto::mac(
            &self.meta_key,
            &Canon::new("sourceorrery/v2/secret", &self.vault_id)
                .str(name)
                .int(self.now)
                .opt_int(None)
                .opt_int(None)
                .opt_str(None)
                .0,
        );
        self.conn
            .execute(
                "INSERT INTO secrets (name, created_on, tag) VALUES (?1, ?2, ?3)",
                rusqlite::params![name, self.now, tag.as_slice()],
            )
            .unwrap();
    }

    fn version(&mut self, name: &str, value: &str, enabled: bool) -> String {
        self.seq += 1;
        let version = random::random_hex(16).unwrap();
        let ct = aead::seal(
            &self.dek,
            format!("sourceorrery/v1/value/{}/{name}/{version}", self.vault_id).as_bytes(),
            value.as_bytes(),
        )
        .unwrap();
        let tag = sourceorrery_crypto::mac(
            &self.meta_key,
            &Canon::new("sourceorrery/v2/version", &self.vault_id)
                .str(name)
                .str(&version)
                .int(self.seq)
                .flag(enabled)
                .opt_str(None)
                .str("{}")
                .opt_int(None)
                .opt_int(None)
                .int(self.now)
                .int(self.now)
                .0,
        );
        self.conn
            .execute(
                "INSERT INTO secret_versions
                    (name, version, seq, nonce, ciphertext, content_type, tags_json, enabled,
                     not_before, expires_on, created_on, updated_on, tag)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, '{}', ?6, NULL, NULL, ?7, ?7, ?8)",
                rusqlite::params![
                    name,
                    version,
                    self.seq,
                    ct.nonce.as_slice(),
                    ct.bytes,
                    i64::from(enabled),
                    self.now,
                    tag.as_slice()
                ],
            )
            .unwrap();
        version
    }

    /// Append a keyed, chained audit row and move the head to it.
    fn audit(&mut self, op: &str, name: Option<&str>, ver: Option<&str>, outcome: &str) {
        self.conn
            .execute(
                "INSERT INTO audit_events
                    (occurred_on, actor, operation, secret_name, version, outcome, detail,
                     prev_hash, keyed)
                 VALUES (?1, 'user:legacy', ?2, ?3, ?4, ?5, NULL, ?6, 1)",
                rusqlite::params![self.now, op, name, ver, outcome, self.prev.as_slice()],
            )
            .unwrap();
        let id = self.conn.last_insert_rowid();
        let hash = sourceorrery_crypto::mac(
            &self.meta_key,
            &Canon::new("sourceorrery/v2/audit", &self.vault_id)
                .bytes(&self.prev)
                .int(id)
                .int(self.now)
                .str("user:legacy")
                .str(op)
                .opt_str(name)
                .opt_str(ver)
                .str(outcome)
                .opt_str(None)
                .flag(true)
                .0,
        );
        self.conn
            .execute(
                "UPDATE audit_events SET hash = ?2 WHERE id = ?1",
                rusqlite::params![id, hash.as_slice()],
            )
            .unwrap();
        self.prev = hash;
        self.head = Some((id, hash));
    }

    fn finish(&self) {
        let (id, hash) = self.head.unwrap();
        let head_mac = sourceorrery_crypto::mac(
            &self.meta_key,
            &Canon::new("sourceorrery/v2/audit-head", &self.vault_id)
                .int(id)
                .bytes(&hash)
                .0,
        );
        let settings = sourceorrery_crypto::mac(
            &self.meta_key,
            &Canon::new("sourceorrery/v2/settings", &self.vault_id)
                .int(2)
                .str("legacy2")
                .int(self.now)
                .str("\"recoverable\"")
                .int(90)
                .0,
        );
        for (key, value) in [
            ("audit_head", format!("{id}:{}", hex::encode(head_mac))),
            ("settings_tag", hex::encode(settings)),
        ] {
            self.conn
                .execute(
                    "INSERT INTO vault_meta (key, value) VALUES (?1, ?2)",
                    [key, value.as_str()],
                )
                .unwrap();
        }
    }
}

/// Write a schema 2 vault named `legacy2` by hand, from the documented
/// format (`*.sorvault` fixtures are git-ignored by policy).
fn craft_schema_2_vault(path: &Path) -> LegacyVault {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch(SCHEMA_V2).unwrap();
    let vault_id = random::random_hex(16).unwrap();
    let now = i64::try_from(timestamp::to_unix_nanos(timestamp::now())).unwrap();
    for (key, value) in [
        ("schema_version", "2".to_owned()),
        ("name", "legacy2".to_owned()),
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
    let dek = SymmetricKey::generate().unwrap();
    let meta_key = sourceorrery_crypto::derive_subkey(
        &dek,
        sourceorrery_storage::integrity::METADATA_KEY_LABEL,
    );
    let mut w = V2Writer {
        conn: &conn,
        dek,
        meta_key,
        vault_id,
        now,
        seq: 0,
        prev: [0u8; 32],
        head: None,
    };
    w.protector();
    w.secret("alpha");
    w.secret("beta");
    let alpha_old = w.version("alpha", "alpha-old", false);
    let alpha_new = w.version("alpha", "alpha-new", true);
    let beta = w.version("beta", "beta-value", true);
    w.audit("vault_create", None, None, "success");
    w.audit("secret_set", Some("alpha"), Some(&alpha_old), "success");
    w.audit("secret_set", Some("alpha"), Some(&alpha_new), "success");
    w.audit("secret_set", Some("beta"), Some(&beta), "success");
    w.finish();
    LegacyVault {
        alpha_old,
        alpha_new,
    }
}

#[test]
fn schema_2_vault_is_migrated_forward_and_its_rows_become_checkpointed() {
    let fx = Fixture::new();
    std::fs::create_dir_all(fx.registry.vaults_dir()).unwrap();
    let path = fx.registry.vault_path("legacy2").unwrap();
    let legacy = craft_schema_2_vault(&path);

    let unlock = StaticPassphrase::new(FIXTURE_PASSPHRASE);
    let err = fx.registry.open("legacy2", &unlock).unwrap_err();
    assert_eq!(err.code(), "migration_required", "{err}");
    assert!(err.to_string().contains("schema 2"), "{err}");

    // The crafted file is accepted as genuine schema 2: its head, chain,
    // tags and settings all verify (a wrong encoding here would be refused).
    let vault = fx.migrate_vault("legacy2");
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
    assert_eq!(
        vault
            .list_properties_of_secret_versions("alpha")
            .unwrap()
            .len(),
        2
    );
    assert_eq!(migrations(&vault), 1);
    assert_eq!(migration_checkpoints(&vault), 2 + 3);
    let summary = events_of(&vault, AuditOperation::VaultMigrate, AuditOutcome::Success)
        .into_iter()
        .find(|e| e.secret_name.is_none())
        .unwrap();
    assert_eq!(summary.detail.as_deref(), Some("schema 2 -> 3"));
    let check = vault.verify_audit_chain().unwrap();
    assert!(check.is_intact(), "{check:?}");
    assert_eq!(check.unkeyed, 0);
    drop(vault);
    assert_eq!(schema_marker(&path), "3");

    // A second unlock is an ordinary open.
    let vault = fx.open_vault("legacy2");
    assert_eq!(migrations(&vault), 1);
    drop(vault);

    // Migrated rows are bound to the chain exactly like new ones.
    stash(&path, "secret_versions", "alpha");
    {
        let vault = fx.open_vault("legacy2");
        disable(&vault, "alpha");
        assert_eq!(
            vault.get_secret("alpha", None).unwrap_err().code(),
            "disabled"
        );
    }
    replay(&path, "secret_versions", "alpha");
    let vault = fx.open_vault("legacy2");
    assert_eq!(
        vault.get_secret("alpha", None).unwrap_err().code(),
        "crypto"
    );
}

#[test]
fn schema_3_marker_rolled_back_to_2_is_refused() {
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
    }
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "UPDATE vault_meta SET value = '2' WHERE key = 'schema_version';
             UPDATE secret_versions SET enabled = 1;",
        )
        .unwrap();
    }
    let unlock = StaticPassphrase::new(FIXTURE_PASSPHRASE);
    assert_eq!(
        fx.registry.open("dev", &unlock).unwrap_err().code(),
        "migration_required"
    );
    // The key is bound to schema 3, so the "schema 2" file is not migrated.
    let err = fx.registry.migrate("dev", &unlock).unwrap_err();
    assert_eq!(err.code(), "crypto", "{err}");
    assert!(err.to_string().contains("altered"), "{err}");
    assert_eq!(schema_marker(&path), "2", "nothing was laundered");
}
