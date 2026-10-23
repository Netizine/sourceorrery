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

mod guard {
    //! The reveal guard, the second factor and the passphrase hint.

    use super::*;
    use crate::RevealGuard;
    use crate::unlock::StaticPassphrase;

    const PASSPHRASE: &str = "correct horse battery staple";

    fn fresh(dir: &tempfile::TempDir) -> (std::path::PathBuf, SqliteVault) {
        let path = dir.path().join("dev.sorvault");
        let vault =
            SqliteVault::create(&path, "dev", CreateVaultOptions::default(), spec()).unwrap();
        (path, vault)
    }

    fn reopen(path: &Path) -> SqliteVault {
        SqliteVault::open(path, &StaticPassphrase::new(PASSPHRASE)).unwrap()
    }

    fn guard_events(vault: &SqliteVault) -> Vec<(AuditOutcome, String)> {
        vault
            .audit_events(AuditQuery {
                operation: Some(AuditOperation::Guard),
                limit: Some(100),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .map(|e| (e.outcome, e.detail.unwrap_or_default()))
            .collect()
    }

    #[test]
    fn a_vault_starts_with_no_guard_no_second_factor_and_no_hint() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault) = fresh(&dir);
        assert_eq!(vault.reveal_guard().unwrap(), RevealGuard::default());
        assert!(vault.reveal_guard().unwrap().is_none());
        assert!(vault.second_factor().unwrap().is_none());
        assert!(vault.passphrase_hint().is_none());
        assert!(
            crate::sqlite::read_passphrase_hint(&path)
                .unwrap()
                .is_none()
        );
        // The settings tag of such a vault has the shape it always had.
        drop(vault);
        let vault = reopen(&path);
        assert_eq!(guard_events(&vault), Vec::new());
    }

    #[test]
    fn the_second_factor_is_enrolled_verified_replay_proof_and_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault) = fresh(&dir);
        let now = timestamp::now();
        let unix = u64::try_from(now.unix_timestamp()).unwrap();

        // No enrolment: nothing to verify, and the guard cannot ask for it.
        assert_eq!(
            vault
                .verify_second_factor("000000", now)
                .unwrap_err()
                .code(),
            "invalid_argument"
        );
        let err = vault
            .set_reveal_guard(RevealGuard {
                passphrase: false,
                second_factor: true,
            })
            .unwrap_err();
        assert_eq!(err.code(), "invalid_argument");

        // Enrolled, but unverified until one code is accepted.
        let secret = vault.enrol_second_factor().unwrap();
        let info = vault.second_factor().unwrap().unwrap();
        assert!(!info.verified);
        assert!(!format!("{secret:?}").contains(&secret.to_base32()));
        assert!(!vault.verify_second_factor("123456", now).unwrap());
        assert!(
            vault
                .set_reveal_guard(RevealGuard {
                    passphrase: false,
                    second_factor: true,
                })
                .is_err(),
            "an unverified enrolment does not count"
        );
        let code = secret.code_at(unix);
        assert!(vault.verify_second_factor(&code, now).unwrap());
        assert!(vault.second_factor().unwrap().unwrap().verified);
        // The same code is refused from now on; the next step's is accepted.
        assert!(!vault.verify_second_factor(&code, now).unwrap());
        let next = secret.code_at(unix + 30);
        assert!(vault.verify_second_factor(&next, now).unwrap());
        // A second enrolment needs the first disabled.
        assert_eq!(
            vault.enrol_second_factor().unwrap_err().code(),
            "invalid_argument"
        );

        // The guard can ask for it now, and survives a reopen with the
        // replay state.
        let guard = RevealGuard {
            passphrase: true,
            second_factor: true,
        };
        assert_eq!(vault.set_reveal_guard(guard).unwrap(), guard);
        drop(vault);
        let vault = reopen(&path);
        assert_eq!(vault.reveal_guard().unwrap(), guard);
        assert_eq!(
            vault.reveal_guard().unwrap().describe(),
            "passphrase and second-factor"
        );
        assert!(vault.second_factor().unwrap().unwrap().verified);
        assert!(
            !vault.verify_second_factor(&next, now).unwrap(),
            "replay after reopen"
        );
        assert!(
            vault
                .verify_second_factor(
                    &secret.code_at(unix + 60),
                    now + time::Duration::seconds(60)
                )
                .unwrap()
        );

        // Disabling drops the enrolment and the guard's demand for it.
        vault.disable_second_factor().unwrap();
        assert!(vault.second_factor().unwrap().is_none());
        assert_eq!(
            vault.reveal_guard().unwrap(),
            RevealGuard {
                passphrase: true,
                second_factor: false,
            }
        );
        assert_eq!(
            vault.disable_second_factor().unwrap_err().code(),
            "invalid_argument"
        );
        vault.set_reveal_guard(RevealGuard::default()).unwrap();
        assert!(vault.reveal_guard().unwrap().is_none());

        // Everything was audited, nothing of the secret or the codes shown.
        let events = guard_events(&vault);
        let text = format!("{events:?}");
        assert!(
            text.contains("second factor enrolled (unverified)"),
            "{text}"
        );
        assert!(text.contains("second factor verified"), "{text}");
        assert!(text.contains("second-factor code refused"), "{text}");
        assert!(text.contains("second factor disabled"), "{text}");
        assert!(
            text.contains("reveal guard set: passphrase and second-factor"),
            "{text}"
        );
        assert!(!text.contains(&secret.to_base32()));
        assert!(!text.contains(&code));
        assert!(events.iter().any(|(o, _)| *o == AuditOutcome::Denied));
    }

    #[test]
    fn a_tampered_guard_setting_is_refused_at_open() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault) = fresh(&dir);
        let secret = vault.enrol_second_factor().unwrap();
        let now = timestamp::now();
        let unix = u64::try_from(now.unix_timestamp()).unwrap();
        assert!(
            vault
                .verify_second_factor(&secret.code_at(unix), now)
                .unwrap()
        );
        vault
            .set_reveal_guard(RevealGuard {
                passphrase: true,
                second_factor: true,
            })
            .unwrap();
        drop(vault);

        // Switching the guard off in the file breaks the settings tag.
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE vault_meta SET value = '{\"passphrase\":false,\"second_factor\":false}' \
             WHERE key = 'reveal_guard'",
            [],
        )
        .unwrap();
        drop(conn);
        let err = SqliteVault::open(&path, &StaticPassphrase::new(PASSPHRASE)).unwrap_err();
        assert_eq!(err.code(), "crypto", "{err}");

        // So does removing the enrolment.
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE vault_meta SET value = '{\"passphrase\":true,\"second_factor\":true}' \
             WHERE key = 'reveal_guard'",
            [],
        )
        .unwrap();
        conn.execute("DELETE FROM vault_meta WHERE key = 'second_factor'", [])
            .unwrap();
        drop(conn);
        let err = SqliteVault::open(&path, &StaticPassphrase::new(PASSPHRASE)).unwrap_err();
        assert_eq!(err.code(), "crypto", "{err}");
    }

    #[test]
    fn the_passphrase_is_verified_in_place_and_audited() {
        let dir = tempfile::tempdir().unwrap();
        let (_path, vault) = fresh(&dir);
        assert!(
            vault
                .verify_passphrase(&SecretBytes::from(PASSPHRASE))
                .unwrap()
        );
        assert!(!vault.verify_passphrase(&SecretBytes::from("nope")).unwrap());
        assert!(!vault.verify_passphrase(&SecretBytes::from("")).unwrap());
        // A second passphrase protector (a recovery code) verifies too.
        vault
            .add_protector(
                ProtectorSpec::Passphrase {
                    passphrase: SecretBytes::from("7K3QXM9ZT2ABCDEFGHJKMNPQR"),
                    params: Argon2Params::TESTING,
                },
                Some("recovery-1"),
            )
            .unwrap();
        assert!(
            vault
                .verify_passphrase(&SecretBytes::from("7K3QXM9ZT2ABCDEFGHJKMNPQR"))
                .unwrap()
        );
        assert!(
            vault
                .passphrase_unlocks_quietly(&SecretBytes::from(PASSPHRASE))
                .unwrap()
        );
        let events = guard_events(&vault);
        assert_eq!(
            events
                .iter()
                .filter(|(o, d)| *o == AuditOutcome::Denied && d == "incorrect passphrase")
                .count(),
            2
        );
        assert_eq!(
            events
                .iter()
                .filter(|(o, d)| *o == AuditOutcome::Success && d == "passphrase verified")
                .count(),
            2
        );
    }

    #[test]
    fn the_hint_is_stored_in_clear_readable_before_unlock_and_never_the_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault) = fresh(&dir);
        vault
            .set_passphrase_hint(Some("  the usual four words  "))
            .unwrap();
        assert_eq!(
            vault.passphrase_hint().as_deref(),
            None,
            "the handle keeps what it opened with"
        );
        assert_eq!(
            crate::sqlite::read_passphrase_hint(&path)
                .unwrap()
                .as_deref(),
            Some("the usual four words")
        );
        drop(vault);
        let vault = reopen(&path);
        assert_eq!(
            vault.passphrase_hint().as_deref(),
            Some("the usual four words")
        );

        for bad in [
            "",
            "   ",
            "a\u{7}bell",
            &"x".repeat(crate::MAX_HINT_LEN + 1),
        ] {
            assert_eq!(
                vault.set_passphrase_hint(Some(bad)).unwrap_err().code(),
                "invalid_argument",
                "{bad:?}"
            );
        }
        let err = vault.set_passphrase_hint(Some(PASSPHRASE)).unwrap_err();
        assert_eq!(err.code(), "invalid_argument");
        assert!(err.to_string().contains("passphrase itself"), "{err}");
        assert!(!err.to_string().contains(PASSPHRASE));
        assert_eq!(
            crate::sqlite::read_passphrase_hint(&path)
                .unwrap()
                .as_deref(),
            Some("the usual four words"),
            "a refused hint changes nothing"
        );

        vault.set_passphrase_hint(None).unwrap();
        assert!(
            crate::sqlite::read_passphrase_hint(&path)
                .unwrap()
                .is_none()
        );
        let events = guard_events(&vault);
        let text = format!("{events:?}");
        assert!(text.contains("passphrase hint set"), "{text}");
        assert!(text.contains("passphrase hint cleared"), "{text}");
        assert!(
            text.contains("hint refused: it unlocks the vault"),
            "{text}"
        );
        assert!(
            !text.contains("four words"),
            "the hint is not in the log: {text}"
        );
    }
}
