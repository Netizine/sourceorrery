//! Unit tests for the vault module.

use sourceorrery_crypto::Argon2Params;

use super::*;

fn spec() -> ProtectorSpec {
    ProtectorSpec::Passphrase {
        passphrase: SecretBytes::from("correct horse battery staple"),
        params: Argon2Params::TESTING,
    }
}

#[test]
fn create_open_and_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dev.sorvault");
    {
        let vault =
            SqliteVault::create(&path, "dev", CreateVaultOptions::default(), spec()).unwrap();
        vault
            .set_secret(
                "database-password",
                SecretBytes::from("hunter2"),
                SetSecretOptions::default(),
            )
            .unwrap();
    }
    let unlock = crate::unlock::StaticPassphrase::new("correct horse battery staple");
    let vault = SqliteVault::open(&path, &unlock).unwrap();
    let secret = vault.get_secret("database-password", None).unwrap();
    assert_eq!(secret.value.expose(), b"hunter2");
    assert_eq!(vault.descriptor().unwrap().protectors, vec!["passphrase"]);
}

#[test]
fn wrong_passphrase_is_locked_and_audited() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dev.sorvault");
    SqliteVault::create(&path, "dev", CreateVaultOptions::default(), spec()).unwrap();
    let unlock = crate::unlock::StaticPassphrase::new("nope");
    let err = SqliteVault::open(&path, &unlock).unwrap_err();
    assert_eq!(err.code(), "locked");

    let vault = SqliteVault::open(
        &path,
        &crate::unlock::StaticPassphrase::new("correct horse battery staple"),
    )
    .unwrap();
    let events = vault.audit_events(AuditQuery::default()).unwrap();
    assert!(events.iter().any(|e| {
        e.operation == AuditOperation::VaultOpen && e.outcome == AuditOutcome::Denied
    }));

    // The pre-unlock rows are unkeyed but the chain is still intact.
    let check = vault.verify_audit_chain().unwrap();
    assert!(check.is_intact(), "{check:?}");
    assert_eq!(check.unkeyed, 2, "one denied attempt and one failure row");
    assert_eq!(check.rows, check.keyed + check.unkeyed);
}

#[test]
fn failed_create_leaves_no_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dev.sorvault");
    let err = SqliteVault::create(
        &path,
        "dev",
        CreateVaultOptions::default(),
        ProtectorSpec::Passphrase {
            passphrase: SecretBytes::from(""),
            params: Argon2Params::TESTING,
        },
    )
    .unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    assert!(!path.exists());
}

#[test]
fn failed_operations_keep_their_audit_row() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dev.sorvault");
    let vault = SqliteVault::create(&path, "dev", CreateVaultOptions::default(), spec()).unwrap();
    assert_eq!(
        vault.recover_deleted_secret("missing").unwrap_err().code(),
        "not_found"
    );
    assert_eq!(
        vault
            .update_secret_properties(
                "missing",
                None,
                UpdateSecretProperties {
                    enabled: Some(false),
                    ..Default::default()
                },
            )
            .unwrap_err()
            .code(),
        "not_found"
    );
    let events = vault.audit_events(AuditQuery::default()).unwrap();
    let failures: Vec<_> = events
        .iter()
        .filter(|e| e.outcome == AuditOutcome::Failure)
        .map(|e| e.operation)
        .collect();
    assert!(failures.contains(&AuditOperation::SecretRecover));
    assert!(failures.contains(&AuditOperation::SecretUpdate));
    assert!(vault.verify_audit_chain().unwrap().is_intact());
}
