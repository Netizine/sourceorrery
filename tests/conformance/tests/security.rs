//! Security conformance: what must never happen.

use sourceorrery_conformance::{FIXTURE_PASSPHRASE, Fixture};
use sourceorrery_core::{AuditQuery, Manifest, SecretBytes, SecretClient, SetSecretOptions};
use sourceorrery_storage::StaticPassphrase;

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
