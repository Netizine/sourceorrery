//! Unit tests for the vault module.

use std::sync::atomic::{AtomicUsize, Ordering};

use rusqlite::trace::{TraceEvent, TraceEventCodes};
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

static STATEMENTS: AtomicUsize = AtomicUsize::new(0);

// `trace_v2` takes a plain `fn(TraceEvent)`, so the event is by value.
#[allow(clippy::needless_pass_by_value)]
fn count_statement(event: TraceEvent<'_>) {
    if let TraceEvent::Stmt(..) = event {
        STATEMENTS.fetch_add(1, Ordering::SeqCst);
    }
}

/// How many SQL statements listing a vault of `secrets` secrets (three
/// versions each, the first one deleted) runs: `(live listing, deleted
/// listing)`.
fn statements_to_list(secrets: usize) -> (usize, usize) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dev.sorvault");
    let vault = SqliteVault::create(&path, "dev", CreateVaultOptions::default(), spec()).unwrap();
    for i in 0..secrets {
        let name = format!("secret-{i:03}");
        for v in 0..3 {
            vault
                .set_secret(
                    &name,
                    SecretBytes::from(format!("value-{v}")),
                    SetSecretOptions::default(),
                )
                .unwrap();
        }
    }
    vault.delete_secret("secret-000").unwrap();

    vault
        .conn
        .lock()
        .unwrap()
        .trace_v2(TraceEventCodes::SQLITE_TRACE_STMT, Some(count_statement));
    STATEMENTS.store(0, Ordering::SeqCst);
    assert_eq!(
        vault.list_properties_of_secrets().unwrap().len(),
        secrets - 1
    );
    let live = STATEMENTS.swap(0, Ordering::SeqCst);
    assert_eq!(vault.list_deleted_secrets().unwrap().len(), 1);
    let deleted = STATEMENTS.swap(0, Ordering::SeqCst);
    vault
        .conn
        .lock()
        .unwrap()
        .trace_v2(TraceEventCodes::empty(), None);
    (live, deleted)
}

/// A listing reads its window in a fixed number of statements: the
/// checkpoints of every secret in one scan, then the names, rows and
/// versions of the window in one statement each (plus the audit-head
/// check and the audit row every operation has). The count must not grow
/// with the number of secrets or versions.
#[test]
fn listing_cost_does_not_grow_with_the_number_of_secrets() {
    let (small_live, small_deleted) = statements_to_list(4);
    let (large_live, large_deleted) = statements_to_list(60);
    assert_eq!(
        small_live, large_live,
        "listing 60 secrets ran {large_live} statements, 4 secrets {small_live}"
    );
    assert_eq!(
        small_deleted, large_deleted,
        "listing deleted secrets ran {large_deleted} statements vs {small_deleted}"
    );
    assert!(large_live <= 16, "a listing ran {large_live} statements");
}
