//! Unit tests for the vault module.

use std::sync::atomic::{AtomicUsize, Ordering};

use rusqlite::trace::{TraceEvent, TraceEventCodes};
use sourceorrery_crypto::Argon2Params;

use super::*;
use crate::keystore::{MemoryStore, NoStore};
use crate::unlock::{NoInteraction, StaticRecoveryKey};

/// No credential store: a test never touches the real OS store, and these
/// vaults open with their recovery key.
fn no_store() -> Arc<dyn CredentialStore> {
    Arc::new(NoStore)
}

/// A vault in a temporary directory, opening with its recovery key only.
fn create(dir: &tempfile::TempDir) -> (PathBuf, SqliteVault, Zeroizing<String>) {
    let path = dir.path().join("dev.sorvault");
    let created =
        SqliteVault::create(&path, "dev", CreateVaultOptions::default(), no_store()).unwrap();
    assert!(!created.this_machine);
    (path, created.vault, created.recovery_key)
}

fn reopen(path: &Path, key: &str) -> SqliteVault {
    SqliteVault::open(path, no_store(), &StaticRecoveryKey::new(key)).unwrap()
}

/// A credential store that says it is available and then refuses to keep
/// anything, to make creation fail after the file is reserved.
#[derive(Debug)]
struct RefusingStore;

impl CredentialStore for RefusingStore {
    fn name(&self) -> &'static str {
        "refusing store"
    }
    fn available(&self) -> bool {
        true
    }
    fn unavailable_reason(&self) -> Option<String> {
        None
    }
    fn store_key(&self, _account: &str, _key: &SymmetricKey) -> Result<()> {
        Err(SecretError::Storage("refused".to_owned()))
    }
    fn load_key(&self, _account: &str) -> Result<Option<SymmetricKey>> {
        Ok(None)
    }
    fn delete_key(&self, _account: &str) -> Result<()> {
        Ok(())
    }
}

#[test]
fn create_open_and_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let (path, vault, key) = create(&dir);
    vault
        .set_secret(
            "database-password",
            SecretBytes::from("hunter2"),
            SetSecretOptions::default(),
        )
        .unwrap();
    drop(vault);
    let vault = reopen(&path, &key);
    assert!(vault.opened_with_recovery_key());
    let secret = vault.get_secret("database-password", None).unwrap();
    assert_eq!(secret.value.expose(), b"hunter2");
    assert_eq!(vault.descriptor().unwrap().protectors, vec!["recovery"]);
    // The recovery key is 25 characters of the code alphabet in five groups.
    assert_eq!(key.len(), 29);
    assert_eq!(key.matches('-').count(), 4);
}

#[test]
fn the_recovery_key_opens_however_it_is_typed_and_a_wrong_one_is_audited() {
    let dir = tempfile::tempdir().unwrap();
    let (path, vault, key) = create(&dir);
    drop(vault);
    // Case, hyphens, spaces and look-alikes do not matter.
    let loose = key.to_lowercase().replace('-', " ").replace('0', "o");
    drop(reopen(&path, &loose));

    for wrong in ["not a recovery key", "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA"] {
        let err = SqliteVault::open(&path, no_store(), &StaticRecoveryKey::new(wrong)).unwrap_err();
        assert_eq!(err.code(), "locked", "{wrong}");
        assert!(!err.to_string().contains(wrong));
    }
    let err = SqliteVault::open(&path, no_store(), &NoInteraction).unwrap_err();
    assert_eq!(err.code(), "locked");
    assert!(
        err.to_string().contains("no recovery key supplied"),
        "{err}"
    );

    let vault = reopen(&path, &key);
    let denied = vault
        .audit_events(AuditQuery {
            operation: Some(AuditOperation::VaultOpen),
            limit: Some(50),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .filter(|e| {
            e.outcome == AuditOutcome::Denied
                && e.detail.as_deref() == Some("incorrect recovery key")
        })
        .count();
    assert_eq!(denied, 2);
    // The rows written before opening are unkeyed but the chain holds.
    let check = vault.verify_audit_chain().unwrap();
    assert!(check.is_intact(), "{check:?}");
    assert_eq!(check.rows, check.keyed + check.unkeyed);
}

#[test]
fn this_machine_opens_without_asking_and_another_machine_needs_the_recovery_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dev.sorvault");
    let here: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
    let created =
        SqliteVault::create(&path, "dev", CreateVaultOptions::default(), here.clone()).unwrap();
    assert!(created.this_machine);
    let key = created.recovery_key.clone();
    let mut kinds = created.vault.descriptor().unwrap().protectors;
    kinds.sort();
    assert_eq!(kinds, vec!["recovery", "this-machine"]);
    drop(created);

    let vault = SqliteVault::open(&path, here.clone(), &NoInteraction).unwrap();
    assert!(!vault.opened_with_recovery_key());
    drop(vault);

    // Another machine's store holds no key for it.
    let elsewhere: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
    let err = SqliteVault::open(&path, elsewhere.clone(), &NoInteraction).unwrap_err();
    assert_eq!(err.code(), "locked");
    assert!(err.to_string().contains("no entry"), "{err}");
    let vault = SqliteVault::open(&path, elsewhere, &StaticRecoveryKey::new(key.as_str())).unwrap();
    assert!(vault.opened_with_recovery_key());

    // The account it owns is the one it made.
    let accounts = SqliteVault::keyring_accounts(&path).unwrap();
    assert_eq!(accounts.len(), 1);
    assert!(accounts[0].1, "{accounts:?}");
}

#[test]
fn a_switched_off_store_or_a_choice_leaves_only_the_recovery_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dev.sorvault");
    let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
    let created = SqliteVault::create(
        &path,
        "dev",
        CreateVaultOptions {
            this_machine: false,
            ..CreateVaultOptions::default()
        },
        store.clone(),
    )
    .unwrap();
    assert!(!created.this_machine);
    assert_eq!(created.vault.wraps().unwrap().len(), 1);
    // This machine can be added later, once.
    created.vault.add_this_machine_key().unwrap();
    assert_eq!(
        created.vault.add_this_machine_key().unwrap_err().code(),
        "invalid_argument"
    );
    drop(created);
    drop(SqliteVault::open(&path, store, &NoInteraction).unwrap());
}

#[test]
fn failed_create_leaves_no_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dev.sorvault");
    let err = SqliteVault::create(
        &path,
        "dev",
        CreateVaultOptions::default(),
        Arc::new(RefusingStore),
    )
    .unwrap_err();
    assert_eq!(err.code(), "storage");
    assert!(!path.exists());
}

#[test]
fn the_recovery_key_is_replaced_in_one_step() {
    let dir = tempfile::tempdir().unwrap();
    let (path, vault, old) = create(&dir);
    let new = vault.replace_recovery_key().unwrap();
    assert_ne!(old.as_str(), new.as_str());
    assert_eq!(vault.wraps().unwrap().len(), 1);
    drop(vault);
    assert_eq!(
        SqliteVault::open(&path, no_store(), &StaticRecoveryKey::new(old.as_str()))
            .unwrap_err()
            .code(),
        "locked"
    );
    let vault = reopen(&path, &new);
    let replaced = vault
        .audit_events(AuditQuery {
            operation: Some(AuditOperation::ProtectorAdd),
            limit: Some(10),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(replaced[0].detail.as_deref(), Some("recovery key replaced"));
}

#[test]
fn failed_operations_keep_their_audit_row() {
    let dir = tempfile::tempdir().unwrap();
    let (_path, vault, _key) = create(&dir);
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
    let (_path, vault, _key) = create(&dir);
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
    // The head check counts the keyed rows once per operation now.
    assert!(large_live <= 20, "a listing ran {large_live} statements");
}

mod view_check {
    //! The view check: password, hint, authenticator, the wait after
    //! repeated wrong answers, and the recovery key that passes it.

    use super::*;
    use crate::FREE_FAILURES;

    const PASSWORD: &str = "a decent long password";

    fn guard_events(vault: &SqliteVault) -> Vec<(AuditOutcome, String)> {
        vault
            .audit_events(AuditQuery {
                operation: Some(AuditOperation::Guard),
                limit: Some(200),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .map(|e| (e.outcome, e.detail.unwrap_or_default()))
            .collect()
    }

    fn answers(password: Option<&str>, code: Option<&str>) -> ViewAnswers {
        ViewAnswers {
            password: password.map(SecretBytes::from),
            code: code.map(str::to_owned),
            recovery_key: None,
        }
    }

    /// A vault with a password, opened again by this machine (a memory
    /// store) so the recovery key does not pass the check for it.
    fn with_password(dir: &tempfile::TempDir) -> (PathBuf, SqliteVault, Arc<dyn CredentialStore>) {
        let path = dir.path().join("dev.sorvault");
        let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
        let created =
            SqliteVault::create(&path, "dev", CreateVaultOptions::default(), store.clone())
                .unwrap();
        created
            .vault
            .set_password(
                &SecretBytes::from(PASSWORD),
                Some("the long one"),
                Argon2Params::TESTING,
            )
            .unwrap();
        (path, created.vault, store)
    }

    #[test]
    fn a_vault_starts_without_a_view_check() {
        let dir = tempfile::tempdir().unwrap();
        let (_path, vault, _key) = create(&dir);
        let check = vault.view_check().unwrap();
        assert!(check.is_none());
        assert_eq!(check.describe(), "none");
        assert!(vault.password_hint().unwrap().is_none());
        assert!(vault.authenticator().unwrap().is_none());
        vault
            .check_view(&ViewAnswers::default(), timestamp::now())
            .unwrap();
        assert_eq!(guard_events(&vault), Vec::new());
    }

    #[test]
    fn the_password_is_asked_for_checked_and_never_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault, store) = with_password(&dir);
        let now = timestamp::now();
        assert_eq!(vault.view_check().unwrap().describe(), "password");
        assert_eq!(
            vault.password_hint().unwrap().as_deref(),
            Some("the long one")
        );

        let missing = vault.check_view(&answers(None, None), now).unwrap_err();
        assert_eq!(missing.code(), "permission_denied");
        assert!(missing.to_string().contains("not given"), "{missing}");
        let wrong = vault
            .check_view(&answers(Some("nope"), None), now)
            .unwrap_err();
        assert_eq!(wrong.code(), "permission_denied");
        vault
            .check_view(&answers(Some(PASSWORD), None), now)
            .unwrap();

        // Nothing of the password or the hint is in the file or the log.
        drop(vault);
        let bytes = std::fs::read(&path).unwrap();
        for needle in [PASSWORD.as_bytes(), b"the long one".as_slice()] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "found {:?} in the file",
                String::from_utf8_lossy(needle)
            );
        }
        let vault = SqliteVault::open(&path, store, &NoInteraction).unwrap();
        let text = format!("{:?}", guard_events(&vault));
        assert!(text.contains("password set"), "{text}");
        assert!(
            text.contains("view check refused: incorrect password"),
            "{text}"
        );
        assert!(text.contains("view check passed"), "{text}");
        assert!(!text.contains(PASSWORD));
    }

    /// SR11 of the 2026-10-25 review: a handle opened before another
    /// process changed the view check asks, and weighs, what the vault asks
    /// now, not what it asked when the handle opened.
    #[test]
    fn a_handle_follows_the_view_check_another_process_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dev.sorvault");
        let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
        let created =
            SqliteVault::create(&path, "dev", CreateVaultOptions::default(), store.clone())
                .unwrap();
        let recovery_key = created.recovery_key.as_str().to_owned();
        let first = created.vault;
        let other = SqliteVault::open(&path, store.clone(), &NoInteraction).unwrap();
        let by_recovery_key = reopen(&path, &recovery_key);
        let now = timestamp::now();
        assert!(first.view_check().unwrap().is_none());

        // Set elsewhere: asked here, with the hint.
        other
            .set_password(
                &SecretBytes::from(PASSWORD),
                Some("the long one"),
                Argon2Params::TESTING,
            )
            .unwrap();
        assert_eq!(first.view_check().unwrap().describe(), "password");
        assert_eq!(
            first.password_hint().unwrap().as_deref(),
            Some("the long one")
        );
        let err = first.check_view(&answers(None, None), now).unwrap_err();
        assert_eq!(err.code(), "permission_denied");
        first
            .check_view(&answers(Some(PASSWORD), None), now)
            .unwrap();
        // The recovery key that opened a handle still passes it (documented).
        by_recovery_key
            .check_view(&ViewAnswers::default(), now)
            .unwrap();

        // Replaced elsewhere: the old password no longer passes here.
        other
            .set_password(
                &SecretBytes::from("another long password"),
                None,
                Argon2Params::TESTING,
            )
            .unwrap();
        assert!(first.password_hint().unwrap().is_none());
        let err = first
            .check_view(&answers(Some(PASSWORD), None), now)
            .unwrap_err();
        assert_eq!(err.code(), "permission_denied");
        first
            .check_view(&answers(Some("another long password"), None), now)
            .unwrap();

        // An authenticator enrolled and verified elsewhere is asked for.
        let unix = u64::try_from(now.unix_timestamp()).unwrap();
        let secret = other.enrol_authenticator().unwrap();
        assert!(
            other
                .verify_authenticator(&secret.code_at(unix), now)
                .unwrap()
        );
        assert!(first.view_check().unwrap().authenticator);
        assert!(first.authenticator().unwrap().unwrap().verified);
        let err = first
            .check_view(&answers(Some("another long password"), None), now)
            .unwrap_err();
        assert!(err.to_string().contains("authenticator"), "{err}");
        other.remove_authenticator().unwrap();
        assert!(!first.view_check().unwrap().authenticator);
        assert!(first.authenticator().unwrap().is_none());

        // Wrong answers counted elsewhere make this handle wait too.
        for _ in 0..FREE_FAILURES {
            let _ = other.check_view(&answers(Some("wrong"), None), now);
        }
        let err = first
            .check_view(&answers(Some("another long password"), None), now)
            .unwrap_err();
        assert!(err.to_string().contains("try again"), "{err}");

        // Cleared elsewhere: nothing is asked here.
        other.clear_view_check().unwrap();
        assert!(first.view_check().unwrap().is_none());
        first.check_view(&ViewAnswers::default(), now).unwrap();
    }

    #[test]
    fn a_hint_must_not_give_the_password_away() {
        let dir = tempfile::tempdir().unwrap();
        let (_path, vault, _key) = create(&dir);
        for bad in [
            "starts with a decent long password",
            "A DECENT LONG PASSWORD",
            "a\u{7}bell",
            &"x".repeat(crate::MAX_HINT_LEN + 1),
        ] {
            let err = vault
                .set_password(
                    &SecretBytes::from(PASSWORD),
                    Some(bad),
                    Argon2Params::TESTING,
                )
                .unwrap_err();
            assert_eq!(err.code(), "invalid_argument", "{bad:?}");
            assert!(!err.to_string().contains(PASSWORD));
        }
        assert!(vault.view_check().unwrap().is_none(), "nothing was set");
        assert_eq!(
            vault
                .set_password(&SecretBytes::from(""), None, Argon2Params::TESTING)
                .unwrap_err()
                .code(),
            "invalid_argument"
        );
    }

    #[test]
    fn the_authenticator_is_a_second_check_on_top_of_the_password() {
        let dir = tempfile::tempdir().unwrap();
        let (_unused, bare, _key) = create(&dir);
        assert_eq!(
            bare.enrol_authenticator().unwrap_err().code(),
            "invalid_argument",
            "no password yet"
        );
        drop(bare);

        let dir = tempfile::tempdir().unwrap();
        let (path, vault, store) = with_password(&dir);
        let now = timestamp::now();
        let unix = u64::try_from(now.unix_timestamp()).unwrap();
        let secret = vault.enrol_authenticator().unwrap();
        assert!(!vault.authenticator().unwrap().unwrap().verified);
        assert_eq!(
            vault.view_check().unwrap().describe(),
            "password",
            "an unverified enrolment does not count"
        );
        assert!(!vault.verify_authenticator("000000", now).unwrap());
        let code = secret.code_at(unix);
        assert!(vault.verify_authenticator(&code, now).unwrap());
        assert_eq!(
            vault.view_check().unwrap().describe(),
            "password and authenticator"
        );
        assert_eq!(
            vault.enrol_authenticator().unwrap_err().code(),
            "invalid_argument",
            "a verified enrolment must be removed first"
        );

        // The password alone is not enough now; the code it gave is spent.
        let later = now + time::Duration::seconds(30);
        assert!(
            vault
                .check_view(&answers(Some(PASSWORD), None), later)
                .is_err()
        );
        assert!(
            vault
                .check_view(&answers(Some(PASSWORD), Some(&code)), later)
                .is_err()
        );
        let next = secret.code_at(unix + 30);
        assert!(
            vault
                .check_view(&answers(Some("nope"), Some(&next)), later)
                .is_err(),
            "a wrong password does not spend the code"
        );
        vault
            .check_view(&answers(Some(PASSWORD), Some(&next)), later)
            .unwrap();
        assert!(
            vault
                .check_view(&answers(Some(PASSWORD), Some(&next)), later)
                .is_err(),
            "a code is good once"
        );

        // The replay state survives a reopen through another handle.
        let other = SqliteVault::open(&path, store, &NoInteraction).unwrap();
        assert!(
            other
                .check_view(&answers(Some(PASSWORD), Some(&next)), later)
                .is_err()
        );
        vault.remove_authenticator().unwrap();
        assert_eq!(vault.view_check().unwrap().describe(), "password");
        assert_eq!(
            vault.remove_authenticator().unwrap_err().code(),
            "invalid_argument"
        );
        let text = format!("{:?}", guard_events(&vault));
        assert!(!text.contains(secret.to_base32().as_str()));
        assert!(!text.contains(&code));
    }

    #[test]
    fn the_recovery_key_passes_the_check() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dev.sorvault");
        let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
        let created =
            SqliteVault::create(&path, "dev", CreateVaultOptions::default(), store.clone())
                .unwrap();
        let key = created.recovery_key.clone();
        created
            .vault
            .set_password(&SecretBytes::from(PASSWORD), None, Argon2Params::TESTING)
            .unwrap();
        let now = timestamp::now();
        // Opened by this machine: the key given as an answer passes; a
        // wrong one is a wrong answer.
        let vault = created.vault;
        let wrong = ViewAnswers {
            recovery_key: Some(SecretBytes::from("AAAAA-AAAAA-AAAAA-AAAAA-AAAAA")),
            ..ViewAnswers::default()
        };
        assert!(vault.check_view(&wrong, now).is_err());
        let right = ViewAnswers {
            recovery_key: Some(SecretBytes::from(key.as_str())),
            ..ViewAnswers::default()
        };
        vault.check_view(&right, now).unwrap();
        drop(vault);
        // Opened with the recovery key: it has been presented already.
        let vault = SqliteVault::open(
            &path,
            Arc::new(NoStore),
            &StaticRecoveryKey::new(key.as_str()),
        )
        .unwrap();
        vault
            .check_view(&ViewAnswers::default(), timestamp::now())
            .unwrap();
        assert!(format!("{:?}", guard_events(&vault)).contains("opened with the recovery key"));
    }

    #[test]
    fn repeated_wrong_answers_make_the_next_one_wait_across_handles() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault, store) = with_password(&dir);
        let start = timestamp::now();
        for _ in 0..FREE_FAILURES {
            assert!(
                vault
                    .check_view(&answers(Some("nope"), None), start)
                    .is_err()
            );
        }
        // Another handle on the same file sees the count: even the right
        // password is not weighed until the wait is over.
        let other = SqliteVault::open(&path, store, &NoInteraction).unwrap();
        let err = other
            .check_view(
                &answers(Some(PASSWORD), None),
                start + time::Duration::seconds(5),
            )
            .unwrap_err();
        assert_eq!(err.code(), "permission_denied");
        assert!(err.to_string().contains("try again in 25 seconds"), "{err}");
        // After the wait the right answer passes and the count starts again.
        let later = start + time::Duration::seconds(31);
        other
            .check_view(&answers(Some(PASSWORD), None), later)
            .unwrap();
        for _ in 0..FREE_FAILURES - 1 {
            assert!(
                other
                    .check_view(&answers(Some("nope"), None), later)
                    .is_err()
            );
        }
        assert!(
            other
                .check_view(&answers(Some(PASSWORD), None), later)
                .is_ok(),
            "four wrong answers in a row do not make anyone wait"
        );
        // The wait doubles with each wrong answer weighed after it.
        for _ in 0..FREE_FAILURES {
            assert!(
                other
                    .check_view(&answers(Some("nope"), None), later)
                    .is_err()
            );
        }
        let after_wait = later + time::Duration::seconds(31);
        assert!(
            other
                .check_view(&answers(Some("nope"), None), after_wait)
                .is_err()
        );
        let err = other
            .check_view(
                &answers(Some(PASSWORD), None),
                after_wait + time::Duration::seconds(5),
            )
            .unwrap_err();
        assert!(err.to_string().contains("try again in 55 seconds"), "{err}");
        let text = format!("{:?}", guard_events(&other));
        assert!(
            text.contains("waiting after repeated wrong answers"),
            "{text}"
        );
    }

    #[test]
    fn a_tampered_view_check_is_refused_at_open() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault, store) = with_password(&dir);
        drop(vault);
        // Removing the password from the file breaks the settings tag.
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("DELETE FROM vault_meta WHERE key = 'password'", [])
            .unwrap();
        drop(conn);
        let err = SqliteVault::open(&path, store.clone(), &NoInteraction).unwrap_err();
        assert_eq!(err.code(), "crypto", "{err}");
    }

    #[test]
    fn clearing_removes_the_password_the_hint_and_the_authenticator() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault, store) = with_password(&dir);
        let now = timestamp::now();
        let unix = u64::try_from(now.unix_timestamp()).unwrap();
        let secret = vault.enrol_authenticator().unwrap();
        assert!(
            vault
                .verify_authenticator(&secret.code_at(unix), now)
                .unwrap()
        );
        vault.clear_view_check().unwrap();
        assert!(vault.view_check().unwrap().is_none());
        assert!(vault.password_hint().unwrap().is_none());
        assert!(vault.authenticator().unwrap().is_none());
        drop(vault);
        let vault = SqliteVault::open(&path, store, &NoInteraction).unwrap();
        assert!(vault.view_check().unwrap().is_none());
        vault
            .check_view(&ViewAnswers::default(), timestamp::now())
            .unwrap();
    }

    /// A vault blocked by an unacknowledged truncation still weighs the
    /// view check, so its owner can pass it to read the log and acknowledge;
    /// changing the check stays refused like every other change.
    #[test]
    fn a_blocked_vault_still_weighs_the_view_check() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault, store) = with_password(&dir);
        vault
            .set_secret("k", SecretBytes::from("v"), SetSecretOptions::default())
            .unwrap();
        vault.get_secret("k", None).unwrap();
        drop(vault);
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "DELETE FROM audit_events WHERE id = (SELECT MAX(id) FROM audit_events)",
            [],
        )
        .unwrap();
        drop(conn);
        assert_eq!(
            SqliteVault::open(&path, store.clone(), &NoInteraction)
                .unwrap_err()
                .code(),
            "crypto"
        );

        let blocked = SqliteVault::open_with(
            &path,
            store,
            &NoInteraction,
            OpenOptions {
                allow_quarantined: true,
            },
        )
        .unwrap();
        let now = timestamp::now();
        let err = blocked
            .check_view(&answers(Some("nope"), None), now)
            .unwrap_err();
        assert_eq!(err.code(), "permission_denied", "{err}");
        blocked
            .check_view(&answers(Some(PASSWORD), None), now)
            .unwrap();
        let err = blocked
            .set_password(&SecretBytes::from("another"), None, Argon2Params::TESTING)
            .unwrap_err();
        assert_eq!(err.code(), "crypto", "{err}");
        assert!(err.to_string().contains("unacknowledged"), "{err}");
        assert_eq!(blocked.get_secret("k", None).unwrap_err().code(), "crypto");
    }
}

mod export_import {
    //! Exports open with the recovery key only and carry no view check;
    //! imports verify the copy, never write the file they are given and
    //! leave nothing behind when they fail.

    use super::*;
    use crate::VaultRegistry;

    const PASSWORD: &str = "a decent long password";
    const VIEW_CHECK_KEYS: [&str; 4] = [
        "password",
        "password_hint",
        "second_factor",
        "check_failures",
    ];

    fn registry(dir: &tempfile::TempDir, store: Arc<dyn CredentialStore>) -> VaultRegistry {
        VaultRegistry::with_root(dir.path()).with_store(store)
    }

    fn raw_meta(path: &Path, key: &str) -> Option<String> {
        rusqlite::Connection::open(path)
            .unwrap()
            .query_row(
                "SELECT value FROM vault_meta WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .ok()
    }

    fn events(vault: &SqliteVault, operation: AuditOperation) -> Vec<(AuditOutcome, String)> {
        vault
            .audit_events(AuditQuery {
                operation: Some(operation),
                limit: Some(200),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .map(|e| (e.outcome, e.detail.unwrap_or_default()))
            .collect()
    }

    fn vault_files(registry: &VaultRegistry) -> Vec<String> {
        std::fs::read_dir(registry.vaults_dir())
            .map(|dir| {
                dir.map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// A vault this machine opens, with a value, a password with a hint and
    /// a verified authenticator; returns it with its recovery key.
    fn checked_vault(
        path: &Path,
        store: &Arc<dyn CredentialStore>,
    ) -> (SqliteVault, Zeroizing<String>) {
        let created =
            SqliteVault::create(path, "dev", CreateVaultOptions::default(), store.clone()).unwrap();
        assert!(created.this_machine);
        let vault = created.vault;
        vault
            .set_secret(
                "database-password",
                SecretBytes::from("hunter2"),
                SetSecretOptions::default(),
            )
            .unwrap();
        vault
            .set_password(
                &SecretBytes::from(PASSWORD),
                Some("the long one"),
                Argon2Params::TESTING,
            )
            .unwrap();
        let now = timestamp::now();
        let code = vault
            .enrol_authenticator()
            .unwrap()
            .code_at(u64::try_from(now.unix_timestamp()).unwrap());
        assert!(vault.verify_authenticator(&code, now).unwrap());
        (vault, created.recovery_key)
    }

    #[test]
    fn an_export_opens_with_the_recovery_key_and_carries_no_view_check() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dev.sorvault");
        let here: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
        let (vault, key) = checked_vault(&path, &here);
        let sealed: Vec<String> = VIEW_CHECK_KEYS[..3]
            .iter()
            .map(|k| raw_meta(&path, k).unwrap())
            .collect();

        let export = dir.path().join("dev-export.sorvault");
        vault.export_to(&export).unwrap();
        let detail = "copy made; left out: this machine's key, the password, its hint, the \
                      authenticator";
        assert_eq!(
            events(&vault, AuditOperation::VaultExport),
            vec![(AuditOutcome::Success, detail.to_owned())]
        );
        assert_eq!(
            vault.view_check().unwrap().describe(),
            "password and authenticator"
        );
        drop(vault);

        // Nothing of the view check is in the copy, not even in a free page.
        for key in VIEW_CHECK_KEYS {
            assert_eq!(raw_meta(&export, key), None, "{key}");
        }
        let bytes = std::fs::read(&export).unwrap();
        for record in &sealed {
            let found = bytes.windows(record.len()).any(|w| w == record.as_bytes());
            assert!(!found, "a sealed view-check record is in the export");
        }

        // This machine's key does not open the copy; the recovery key does.
        let err = SqliteVault::open(&export, here.clone(), &NoInteraction).unwrap_err();
        assert_eq!(err.code(), "locked");
        let copy = SqliteVault::open(&export, here.clone(), &StaticRecoveryKey::new(key.as_str()))
            .unwrap();
        assert_eq!(copy.descriptor().unwrap().protectors, vec!["recovery"]);
        assert!(copy.view_check().unwrap().is_none());
        assert!(copy.password_hint().unwrap().is_none());
        assert!(copy.authenticator().unwrap().is_none());
        let secret = copy.get_secret("database-password", None).unwrap();
        assert_eq!(secret.value.expose(), b"hunter2");
        assert_eq!(
            events(&copy, AuditOperation::VaultExport),
            vec![(AuditOutcome::Success, detail.to_owned())],
            "the copy's own row; the vault's was written after the copy was made"
        );
        let chain = copy.verify_audit_chain().unwrap();
        assert!(chain.is_intact(), "{chain:?}");
        drop(copy);

        // The vault itself keeps its key and its check.
        let vault = SqliteVault::open(&path, here, &NoInteraction).unwrap();
        assert_eq!(
            vault.view_check().unwrap().describe(),
            "password and authenticator"
        );
        assert!(vault.verify_audit_chain().unwrap().is_intact());
    }

    #[test]
    fn an_export_never_replaces_a_file_and_a_blocked_vault_is_not_exported() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault, key) = create(&dir);
        let taken = dir.path().join("taken.sorvault");
        std::fs::write(&taken, b"keep me").unwrap();
        let err = vault.export_to(&taken).unwrap_err();
        assert_eq!(err.code(), "invalid_argument", "{err}");
        assert_eq!(std::fs::read(&taken).unwrap(), b"keep me");
        assert_eq!(
            events(&vault, AuditOperation::VaultExport),
            vec![(AuditOutcome::Failure, "invalid_argument".to_owned())]
        );
        drop(vault);

        // Rows removed from the end of the log block the vault, and a
        // blocked vault is not copied.
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "DELETE FROM audit_events WHERE id = (SELECT MAX(id) FROM audit_events)",
            [],
        )
        .unwrap();
        drop(conn);
        let blocked = SqliteVault::open_with(
            &path,
            no_store(),
            &StaticRecoveryKey::new(key.as_str()),
            OpenOptions {
                allow_quarantined: true,
            },
        )
        .unwrap();
        let export = dir.path().join("export.sorvault");
        assert_eq!(blocked.export_to(&export).unwrap_err().code(), "crypto");
        assert!(!export.exists());
    }

    #[test]
    fn an_import_verifies_the_copy_and_makes_it_this_machines() {
        let here = tempfile::tempdir().unwrap();
        let there = tempfile::tempdir().unwrap();
        let source = registry(&here, Arc::new(MemoryStore::new()));
        let created = source
            .create("Dev_Team", CreateVaultOptions::default())
            .unwrap();
        created
            .vault
            .set_secret(
                "api-key",
                SecretBytes::from("k3y"),
                SetSecretOptions::default(),
            )
            .unwrap();
        let export = here.path().join("handover.sorvault");
        created.vault.export_to(&export).unwrap();
        let key = created.recovery_key.clone();
        drop(created);
        let exported = std::fs::read(&export).unwrap();

        let target = registry(&there, Arc::new(MemoryStore::new()));
        let imported = target
            .import_from(&export, &StaticRecoveryKey::new(key.as_str()), None)
            .unwrap();
        assert!(imported.this_machine);
        assert_eq!(imported.renamed_from, None);
        assert_eq!(imported.vault.vault_name(), "Dev_Team");
        drop(imported);
        assert_eq!(
            std::fs::read(&export).unwrap(),
            exported,
            "the copy is only read"
        );
        assert_eq!(vault_files(&target), vec!["Dev_Team.sorvault".to_owned()]);

        // This machine opens it now, without asking.
        let vault = target.open("dev_team", &NoInteraction).unwrap();
        assert!(!vault.opened_with_recovery_key());
        assert_eq!(
            vault.get_secret("api-key", None).unwrap().value.expose(),
            b"k3y"
        );
        assert_eq!(
            events(&vault, AuditOperation::VaultImport),
            vec![(
                AuditOutcome::Success,
                "imported; this machine can open it".to_owned()
            )]
        );
        assert!(vault.verify_audit_chain().unwrap().is_intact());
        drop(vault);

        // An import never replaces a vault, whatever the case of the name.
        for name in [None, Some("DEV_TEAM")] {
            let err = target
                .import_from(&export, &StaticRecoveryKey::new(key.as_str()), name)
                .unwrap_err();
            assert_eq!(err.code(), "vault_exists", "{name:?}");
        }
        assert_eq!(target.list().unwrap(), vec!["Dev_Team".to_owned()]);
    }

    #[test]
    fn a_failed_import_leaves_nothing_behind() {
        let here = tempfile::tempdir().unwrap();
        let (_path, vault, key) = create(&here);
        let export = here.path().join("export.sorvault");
        vault.export_to(&export).unwrap();
        drop(vault);
        let there = tempfile::tempdir().unwrap();
        let target = registry(&there, Arc::new(MemoryStore::new()));

        for unlock in [
            &StaticRecoveryKey::new("AAAAA-AAAAA-AAAAA-AAAAA-AAAAA") as &dyn UnlockProvider,
            &NoInteraction,
        ] {
            let err = target.import_from(&export, unlock, None).unwrap_err();
            assert_eq!(err.code(), "locked", "{err}");
            assert_eq!(vault_files(&target), Vec::<String>::new());
        }

        let missing = here.path().join("missing.sorvault");
        let err = target
            .import_from(&missing, &StaticRecoveryKey::new(key.as_str()), None)
            .unwrap_err();
        assert_eq!(err.code(), "io", "{err}");
        assert!(!missing.exists(), "a missing copy is not created");

        // A copy whose name was edited is refused once its settings are
        // checked, and so is one taken over under a new name.
        rusqlite::Connection::open(&export)
            .unwrap()
            .execute(
                "UPDATE vault_meta SET value = 'prod' WHERE key = 'name'",
                [],
            )
            .unwrap();
        for name in [None, Some("staging")] {
            let err = target
                .import_from(&export, &StaticRecoveryKey::new(key.as_str()), name)
                .unwrap_err();
            assert_eq!(err.code(), "crypto", "{err}");
            assert_eq!(vault_files(&target), Vec::<String>::new());
        }
    }

    #[test]
    fn an_import_under_a_new_name_renames_the_vault_and_its_deleted_secrets() {
        let here = tempfile::tempdir().unwrap();
        let (_path, vault, key) = create(&here);
        for name in ["kept", "gone"] {
            vault
                .set_secret(name, SecretBytes::from("v"), SetSecretOptions::default())
                .unwrap();
        }
        let deleted = vault.delete_secret("gone").unwrap();
        assert_eq!(
            deleted.recovery_id,
            "sourceorrery://dev/deletedsecrets/gone"
        );
        let export = here.path().join("export.sorvault");
        vault.export_to(&export).unwrap();
        drop(vault);

        // No credential store there: the vault opens with its recovery key.
        let there = tempfile::tempdir().unwrap();
        let target = registry(&there, no_store());
        let imported = target
            .import_from(&export, &StaticRecoveryKey::new(key.as_str()), Some("prod"))
            .unwrap();
        assert!(!imported.this_machine);
        assert_eq!(imported.renamed_from.as_deref(), Some("dev"));
        let vault = imported.vault;
        assert_eq!(vault.vault_name(), "prod");
        assert_eq!(
            vault.get_deleted_secret("gone").unwrap().recovery_id,
            "sourceorrery://prod/deletedsecrets/gone"
        );
        let changes = vault
            .audit_events(AuditQuery {
                operation: Some(AuditOperation::VaultChange),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].secret_name.as_deref(), Some("gone"));
        let imports = events(&vault, AuditOperation::VaultImport);
        assert_eq!(imports.len(), 1);
        assert!(
            imports[0].1.starts_with(
                "imported as 'prod' (exported as 'dev'); it opens with the \
                                      recovery key only"
            ),
            "{imports:?}"
        );
        drop(vault);

        // The new name is the authenticated one, and the deleted secret's
        // new state is the one the chain records.
        assert_eq!(target.list().unwrap(), vec!["prod".to_owned()]);
        let vault = target
            .open("prod", &StaticRecoveryKey::new(key.as_str()))
            .unwrap();
        assert_eq!(vault.descriptor().unwrap().name, "prod");
        vault.recover_deleted_secret("gone").unwrap();
        assert_eq!(vault.get_secret("kept", None).unwrap().value.expose(), b"v");
        assert!(vault.verify_audit_chain().unwrap().is_intact());
    }

    #[test]
    fn a_raw_copy_is_imported_with_a_key_of_its_own() {
        // A vault file copied as it is still names this machine's key; the
        // import does not use that key, and the copy gets one of its own.
        let here = tempfile::tempdir().unwrap();
        let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
        let path = here.path().join("dev.sorvault");
        let created =
            SqliteVault::create(&path, "dev", CreateVaultOptions::default(), store.clone())
                .unwrap();
        let key = created.recovery_key.clone();
        drop(created);
        let copy = here.path().join("copy.sorvault");
        std::fs::copy(&path, &copy).unwrap();

        let there = tempfile::tempdir().unwrap();
        let target = registry(&there, store.clone());
        let err = target.import_from(&copy, &NoInteraction, None).unwrap_err();
        assert_eq!(err.code(), "locked", "only the recovery key opens a copy");
        let imported = target
            .import_from(&copy, &StaticRecoveryKey::new(key.as_str()), None)
            .unwrap();
        let mut kinds = imported.vault.descriptor().unwrap().protectors;
        kinds.sort();
        assert_eq!(kinds, vec!["recovery", "this-machine"]);
        let detail = &events(&imported.vault, AuditOperation::VaultImport)[0].1;
        assert_eq!(
            detail,
            "imported; another machine's key removed; this machine can open it"
        );
        drop(imported);

        // Each file has its own key in the store, and both open here.
        let accounts = SqliteVault::keyring_accounts(&target.vault_path("dev").unwrap()).unwrap();
        let original = SqliteVault::keyring_accounts(&path).unwrap();
        assert_ne!(accounts, original);
        drop(target.open("dev", &NoInteraction).unwrap());
        drop(SqliteVault::open(&path, store, &NoInteraction).unwrap());
    }
}

mod connections {
    //! Connections: settings, sealed credentials, one per provider, the last
    //! test, and the integrity of each row and of the set of rows.

    use sourceorrery_core::{ConnectionSettings, Credentials};

    use super::*;
    use crate::{CatalogChange, ConnectionInfo, CredentialSource, SecretStorage};

    const TOKEN: &str = "hvs.stored-token-value";

    fn vault_settings() -> ConnectionSettings {
        ConnectionSettings::HashicorpVault {
            address: "https://vault.example.com:8200".to_owned(),
            mount: "secret".to_owned(),
            namespace: None,
        }
    }

    fn aws_settings() -> ConnectionSettings {
        ConnectionSettings::AwsSecretsManager {
            region: "eu-west-1".to_owned(),
            prefix: Some("app/".to_owned()),
            endpoint_url: None,
        }
    }

    fn token() -> Credentials {
        Credentials::VaultToken(SecretBytes::from(TOKEN))
    }

    /// Events of `operation`, oldest first.
    fn events(vault: &SqliteVault, operation: AuditOperation) -> Vec<(AuditOutcome, String)> {
        let mut events: Vec<_> = vault
            .audit_events(AuditQuery {
                operation: Some(operation),
                limit: Some(200),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .map(|e| (e.outcome, e.detail.unwrap_or_default()))
            .collect();
        events.reverse();
        events
    }

    fn contains(haystack: &[u8], needle: &str) -> bool {
        haystack
            .windows(needle.len())
            .any(|w| w == needle.as_bytes())
    }

    /// A vault with a HashiCorp Vault connection storing [`TOKEN`].
    fn with_connection(dir: &tempfile::TempDir) -> (PathBuf, Zeroizing<String>, ConnectionInfo) {
        let (path, vault, key) = create(dir);
        let info = vault
            .add_connection(&vault_settings(), Some(&token()))
            .unwrap();
        (path, key, info)
    }

    #[test]
    fn connections_keep_their_settings_and_seal_their_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault, key) = create(&dir);
        assert_eq!(vault.connections().unwrap(), Vec::new());
        let stored = vault
            .add_connection(&vault_settings(), Some(&token()))
            .unwrap();
        assert_eq!(stored.settings, vault_settings());
        assert_eq!(stored.credentials, CredentialSource::Stored);
        assert_eq!(stored.last_test, None);
        let ambient = vault.add_connection(&aws_settings(), None).unwrap();
        assert_eq!(ambient.credentials, CredentialSource::Ambient);
        assert_ne!(stored.id, ambient.id);
        drop(vault);

        // The token is sealed: it is not in the file.
        assert!(!contains(&std::fs::read(&path).unwrap(), TOKEN));

        let vault = reopen(&path, &key);
        let listed = vault.connections().unwrap();
        assert_eq!(listed, vec![stored.clone(), ambient.clone()]);
        assert_eq!(vault.connection(&ambient.id).unwrap(), ambient);
        for shown in [
            format!("{listed:?}"),
            serde_json::to_string(&listed).unwrap(),
        ] {
            assert!(!shown.contains(TOKEN), "{shown}");
        }
        match vault.connection_credentials(&stored.id).unwrap() {
            Some(Credentials::VaultToken(token)) => assert_eq!(token.expose(), TOKEN.as_bytes()),
            other => panic!("{other:?}"),
        }
        assert!(vault.connection_credentials(&ambient.id).unwrap().is_none());

        let changes = events(&vault, AuditOperation::VaultChange);
        assert_eq!(
            changes,
            vec![
                (
                    AuditOutcome::Success,
                    format!(
                        "connection {} added: hashicorp-vault, stored credentials",
                        stored.id
                    )
                ),
                (
                    AuditOutcome::Success,
                    format!(
                        "connection {} added: aws-secrets-manager, ambient credentials",
                        ambient.id
                    )
                ),
            ]
        );
        assert!(vault.verify_audit_chain().unwrap().is_intact());
    }

    #[test]
    fn one_connection_per_provider_with_credentials_for_it_only() {
        let dir = tempfile::tempdir().unwrap();
        let (_path, vault, _key) = create(&dir);
        let first = vault.add_connection(&vault_settings(), None).unwrap();
        let aws_key = Credentials::AwsAccessKey {
            access_key_id: "AKIAEXAMPLE".to_owned(),
            secret_access_key: SecretBytes::from("hunter2"),
        };
        let refused = [
            (
                vault_settings(),
                None,
                "already has a connection to HashiCorp Vault",
            ),
            (aws_settings(), Some(token()), "are for HashiCorp Vault"),
            (
                ConnectionSettings::HashicorpVault {
                    address: "http://vault.example.com".to_owned(),
                    mount: "secret".to_owned(),
                    namespace: None,
                },
                None,
                "address: must use https://",
            ),
            (
                aws_settings(),
                Some(Credentials::AwsAccessKey {
                    access_key_id: "AKIAEXAMPLE".to_owned(),
                    secret_access_key: SecretBytes::from(""),
                }),
                "secret_access_key: must not be empty",
            ),
        ];
        for (settings, credentials, expected) in &refused {
            let err = vault
                .add_connection(settings, credentials.as_ref())
                .unwrap_err();
            assert_eq!(err.code(), "invalid_argument", "{err}");
            assert!(err.to_string().contains(expected), "{err}");
        }
        assert_eq!(vault.connections().unwrap(), vec![first]);
        let changes = events(&vault, AuditOperation::VaultChange);
        assert_eq!(changes.len(), 1 + refused.len());
        for (outcome, detail) in &changes[1..] {
            assert_eq!(
                (outcome, detail.as_str()),
                (&AuditOutcome::Failure, "invalid_argument")
            );
        }
        // Another provider's connection takes its own credentials.
        let aws = vault
            .add_connection(&aws_settings(), Some(&aws_key))
            .unwrap();
        assert_eq!(aws.credentials, CredentialSource::Stored);
    }

    #[test]
    fn a_test_is_kept_until_the_settings_or_credentials_change() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault, key) = create(&dir);
        let id = vault.add_connection(&vault_settings(), None).unwrap().id;

        let passed = vault.record_connection_test(&id, Ok(())).unwrap();
        assert!(passed.passed());
        assert_eq!(vault.connection(&id).unwrap().last_test, Some(passed));
        let refusal = SecretError::Unauthenticated {
            provider: "hashicorp-vault".to_owned(),
            reason: "the server refused hvs.not-shown".to_owned(),
        };
        let failed = vault.record_connection_test(&id, Err(&refusal)).unwrap();
        assert_eq!(failed.outcome, "unauthenticated");
        assert!(!failed.passed());
        assert_eq!(
            events(&vault, AuditOperation::ConnectionTest),
            vec![
                (AuditOutcome::Success, format!("connection {id} tested: ok")),
                (
                    AuditOutcome::Failure,
                    format!("connection {id} tested: unauthenticated")
                ),
            ]
        );
        drop(vault);
        let vault = reopen(&path, &key);
        assert_eq!(vault.connection(&id).unwrap().last_test, Some(failed));

        // New settings for the same provider; another provider is refused.
        let moved = ConnectionSettings::HashicorpVault {
            address: "https://vault2.example.com".to_owned(),
            mount: "kv".to_owned(),
            namespace: Some("team".to_owned()),
        };
        let changed = vault.set_connection_settings(&id, &moved).unwrap();
        assert_eq!(changed.settings, moved);
        assert_eq!(changed.last_test, None);
        let err = vault
            .set_connection_settings(&id, &aws_settings())
            .unwrap_err();
        assert_eq!(err.code(), "invalid_argument");
        assert!(err.to_string().contains("of their own"), "{err}");

        // Stored, then ambient again.
        vault.record_connection_test(&id, Ok(())).unwrap();
        let stored = vault
            .set_connection_credentials(&id, Some(&token()))
            .unwrap();
        assert_eq!(stored.credentials, CredentialSource::Stored);
        assert_eq!(stored.last_test, None);
        assert!(vault.connection_credentials(&id).unwrap().is_some());
        let aws_key = Credentials::AwsAccessKey {
            access_key_id: "AKIAEXAMPLE".to_owned(),
            secret_access_key: SecretBytes::from("hunter2"),
        };
        let err = vault
            .set_connection_credentials(&id, Some(&aws_key))
            .unwrap_err();
        assert_eq!(err.code(), "invalid_argument");
        let ambient = vault.set_connection_credentials(&id, None).unwrap();
        assert_eq!(ambient.credentials, CredentialSource::Ambient);
        assert!(vault.connection_credentials(&id).unwrap().is_none());
        assert_eq!(
            events(&vault, AuditOperation::VaultChange)
                .into_iter()
                .filter(|(outcome, _)| *outcome == AuditOutcome::Success)
                .map(|(_, detail)| detail)
                .collect::<Vec<_>>()[1..],
            [
                format!("connection {id}: settings changed"),
                format!("connection {id}: credentials stored"),
                format!("connection {id}: credentials ambient, none stored"),
            ]
        );
        drop(vault);
        assert!(!contains(&std::fs::read(&path).unwrap(), TOKEN));
    }

    #[test]
    fn a_removed_connection_takes_its_credentials_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let (path, key, info) = with_connection(&dir);
        let vault = reopen(&path, &key);
        vault.remove_connection(&info.id).unwrap();
        assert_eq!(vault.connections().unwrap(), Vec::new());
        for err in [
            vault.remove_connection(&info.id).unwrap_err(),
            vault.connection(&info.id).unwrap_err(),
            vault.connection_credentials(&info.id).unwrap_err(),
            vault.record_connection_test(&info.id, Ok(())).unwrap_err(),
            vault
                .set_connection_credentials(&info.id, None)
                .unwrap_err(),
        ] {
            assert_eq!(err.code(), "invalid_argument", "{err}");
            assert!(err.to_string().contains("has no connection"), "{err}");
        }
        assert!(events(&vault, AuditOperation::VaultChange).contains(&(
            AuditOutcome::Success,
            format!("connection {} removed", info.id)
        )));
        // The vault opens with no connection, and a new one can be added.
        drop(vault);
        let vault = reopen(&path, &key);
        vault.add_connection(&vault_settings(), None).unwrap();
        assert!(vault.verify_audit_chain().unwrap().is_intact());
    }

    #[test]
    fn an_edited_row_is_refused_when_read() {
        let dir = tempfile::tempdir().unwrap();
        let (path, key, info) = with_connection(&dir);
        // Credentials pointed at another server.
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE connections
                 SET settings_json = replace(settings_json, 'vault.example.com', 'evil.example')",
                [],
            )
            .unwrap();
        let vault = reopen(&path, &key);
        for err in [
            vault.connections().unwrap_err(),
            vault.connection_credentials(&info.id).unwrap_err(),
            vault.add_connection(&aws_settings(), None).unwrap_err(),
        ] {
            assert_eq!(err.code(), "crypto", "{err}");
            assert!(
                err.to_string().contains(&format!("connection {}", info.id)),
                "{err}"
            );
        }
        assert!(
            events(&vault, AuditOperation::VaultChange)
                .contains(&(AuditOutcome::Failure, "crypto".to_owned()))
        );
    }

    #[test]
    fn a_removed_added_or_older_row_is_refused_at_open() {
        let dir = tempfile::tempdir().unwrap();
        let (path, key, info) = with_connection(&dir);
        let raw = |path: &Path| {
            rusqlite::Connection::open(path)
                .unwrap()
                .query_row(
                    "SELECT settings_json, tag FROM connections WHERE id = ?1",
                    params![info.id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .unwrap()
        };
        let older = raw(&path);
        let moved = ConnectionSettings::HashicorpVault {
            address: "https://vault2.example.com".to_owned(),
            mount: "secret".to_owned(),
            namespace: None,
        };
        reopen(&path, &key)
            .set_connection_settings(&info.id, &moved)
            .unwrap();
        assert_ne!(raw(&path), older);

        let tampering = [
            "DELETE FROM connections",
            "INSERT INTO connections
             SELECT 'ffffffffffffffff', kind, settings_json, credential_source,
                    sealed_credentials, created_on, last_test_on, last_test_outcome, tag
             FROM connections",
            "UPDATE connections SET settings_json = ?1, tag = ?2",
        ];
        for (n, sql) in tampering.iter().enumerate() {
            let copy = dir.path().join(format!("tampered-{n}.sorvault"));
            std::fs::copy(&path, &copy).unwrap();
            let conn = rusqlite::Connection::open(&copy).unwrap();
            if sql.contains("?1") {
                conn.execute(sql, params![older.0, older.1]).unwrap();
            } else {
                conn.execute(sql, []).unwrap();
            }
            drop(conn);
            let err = SqliteVault::open(&copy, no_store(), &StaticRecoveryKey::new(key.as_str()))
                .unwrap_err();
            assert_eq!(err.code(), "crypto", "{sql}: {err}");
            assert!(err.to_string().contains("a connection"), "{sql}: {err}");
        }
        // The untouched file still opens.
        assert_eq!(
            reopen(&path, &key).connection(&info.id).unwrap().settings,
            moved
        );
    }

    /// Catalogue `name` at `connection`, as a set there would.
    fn catalogue(vault: &SqliteVault, connection: &str, name: &str) {
        vault
            .record_at_connection(
                connection,
                AuditOperation::SecretSet,
                Some(name),
                Some("1"),
                Ok(()),
                CatalogChange::Add,
                None,
            )
            .unwrap();
    }

    #[test]
    fn a_secret_at_a_connection_is_catalogued_and_refused_locally() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault, key) = create(&dir);
        let id = vault.add_connection(&vault_settings(), None).unwrap().id;
        catalogue(&vault, &id, "remote-token");
        vault
            .set_secret(
                "local-one",
                SecretBytes::from("value"),
                SetSecretOptions::default(),
            )
            .unwrap();
        assert_eq!(
            vault.storage_of("remote-token").unwrap(),
            Some(SecretStorage::Connection(id.clone()))
        );
        assert_eq!(
            vault.storage_of("local-one").unwrap(),
            Some(SecretStorage::Vault)
        );
        assert_eq!(vault.storage_of("nothing-here").unwrap(), None);
        assert_eq!(vault.secrets_at(&id).unwrap(), vec!["remote-token"]);

        // The file has no value for it, so no local operation serves it.
        let name = "remote-token";
        let refusals = [
            vault.get_secret(name, None).map(drop),
            vault.get_secret_properties(name, None).map(drop),
            vault.list_properties_of_secret_versions(name).map(drop),
            vault
                .update_secret_properties(
                    name,
                    None,
                    UpdateSecretProperties {
                        enabled: Some(false),
                        ..Default::default()
                    },
                )
                .map(drop),
            vault
                .set_secret(name, SecretBytes::from("x"), SetSecretOptions::default())
                .map(drop),
            vault.delete_secret(name).map(drop),
            vault.get_deleted_secret(name).map(drop),
            vault.recover_deleted_secret(name).map(drop),
            vault.purge_deleted_secret(name),
        ];
        for refused in refusals {
            let err = refused.unwrap_err();
            assert_eq!(err.code(), "unsupported", "{err}");
            assert!(
                err.to_string().contains(&format!("connection {id}")),
                "{err}"
            );
        }
        let listed: Vec<String> = vault
            .list_properties_of_secrets()
            .unwrap()
            .into_iter()
            .map(|p| p.name)
            .collect();
        assert_eq!(listed, vec!["local-one"]);
        assert_eq!(vault.list_deleted_secrets().unwrap(), Vec::new());
        assert!(
            events(&vault, AuditOperation::SecretSet)
                .contains(&(AuditOutcome::Success, format!("at connection {id}")))
        );
        drop(vault);

        // It stays catalogued, and an export carries the catalog.
        let vault = reopen(&path, &key);
        assert_eq!(vault.secrets_at(&id).unwrap(), vec!["remote-token"]);
        let export = dir.path().join("dev-export.sorvault");
        vault.export_to(&export).unwrap();
        assert!(vault.verify_audit_chain().unwrap().is_intact());
        drop(vault);
        assert_eq!(
            reopen(&export, &key).storage_of("remote-token").unwrap(),
            Some(SecretStorage::Connection(id))
        );
    }

    #[test]
    fn a_connection_that_stores_a_secret_cannot_be_removed() {
        let dir = tempfile::tempdir().unwrap();
        let (_path, vault, _key) = create(&dir);
        let id = vault.add_connection(&vault_settings(), None).unwrap().id;
        for name in ["a", "b"] {
            catalogue(&vault, &id, name);
        }
        let err = vault.remove_connection(&id).unwrap_err();
        assert_eq!(err.code(), "invalid_argument");
        assert!(
            err.to_string()
                .contains("still stores 2 secret(s) ('a', 'b')"),
            "{err}"
        );
        assert_eq!(vault.connections().unwrap().len(), 1);

        // Purged there, each entry goes; the connection can go once none is
        // left.
        for (name, left) in [("a", 1), ("b", 0)] {
            vault
                .record_at_connection(
                    &id,
                    AuditOperation::SecretPurge,
                    Some(name),
                    None,
                    Ok(()),
                    CatalogChange::Remove,
                    None,
                )
                .unwrap();
            assert_eq!(vault.storage_of(name).unwrap(), None);
            assert_eq!(vault.secrets_at(&id).unwrap().len(), left);
        }
        vault.remove_connection(&id).unwrap();
        assert_eq!(vault.connections().unwrap(), Vec::new());
        assert!(vault.verify_audit_chain().unwrap().is_intact());
    }

    #[test]
    fn the_catalog_follows_only_what_happened() {
        let dir = tempfile::tempdir().unwrap();
        let (_path, vault, _key) = create(&dir);
        let id = vault.add_connection(&vault_settings(), None).unwrap().id;
        let record = |name: &str, result: std::result::Result<(), &SecretError>, change| {
            vault.record_at_connection(
                &id,
                AuditOperation::SecretSet,
                Some(name),
                None,
                result,
                change,
                None,
            )
        };

        // A set that failed there catalogues nothing, and says why.
        let unreachable = SecretError::ProviderUnavailable {
            provider: "hashicorp-vault".to_owned(),
            reason: "connection refused".to_owned(),
        };
        record("new-one", Err(&unreachable), CatalogChange::Add).unwrap();
        assert_eq!(vault.storage_of("new-one").unwrap(), None);
        assert_eq!(
            events(&vault, AuditOperation::SecretSet).last().unwrap(),
            &(
                AuditOutcome::Failure,
                format!("at connection {id}: provider_unavailable")
            )
        );

        catalogue(&vault, &id, "kept");
        vault
            .set_secret("local", SecretBytes::from("v"), SetSecretOptions::default())
            .unwrap();
        let disabled = SecretError::Disabled {
            name: "kept".to_owned(),
            version: "1".to_owned(),
        };
        record("kept", Err(&disabled), CatalogChange::Keep).unwrap();
        assert_eq!(
            events(&vault, AuditOperation::SecretSet).last().unwrap().0,
            AuditOutcome::Denied
        );
        record("kept", Err(&unreachable), CatalogChange::Remove).unwrap();
        assert_eq!(vault.secrets_at(&id).unwrap(), vec!["kept"]);

        let refused = [
            (record("missing", Ok(()), CatalogChange::Keep), "not_found"),
            (
                record("kept", Ok(()), CatalogChange::Add),
                "invalid_argument",
            ),
            (
                record("local", Ok(()), CatalogChange::Add),
                "invalid_argument",
            ),
            (
                record("local", Ok(()), CatalogChange::Keep),
                "invalid_argument",
            ),
            (
                vault.record_at_connection(
                    "ffffffffffffffff",
                    AuditOperation::SecretGet,
                    Some("kept"),
                    None,
                    Ok(()),
                    CatalogChange::Keep,
                    None,
                ),
                "invalid_argument",
            ),
            (
                vault.record_at_connection(
                    &id,
                    AuditOperation::SecretPurge,
                    None,
                    None,
                    Ok(()),
                    CatalogChange::Remove,
                    None,
                ),
                "invalid_argument",
            ),
        ];
        for (result, code) in refused {
            let err = result.unwrap_err();
            assert_eq!(err.code(), code, "{err}");
        }
        assert_eq!(
            vault.storage_of("local").unwrap(),
            Some(SecretStorage::Vault)
        );
        assert_eq!(vault.secrets_at(&id).unwrap(), vec!["kept"]);
        assert!(vault.verify_audit_chain().unwrap().is_intact());
    }

    #[test]
    fn a_storage_changed_in_the_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault, key) = create(&dir);
        let id = vault.add_connection(&vault_settings(), None).unwrap().id;
        catalogue(&vault, &id, "remote-token");
        vault
            .set_secret("local", SecretBytes::from("v"), SetSecretOptions::default())
            .unwrap();
        drop(vault);
        // The catalog entry claims the file holds it, and the local secret
        // claims a provider does.
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE secrets SET storage = NULL WHERE name = 'remote-token'",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE secrets SET storage = ?1 WHERE name = 'local'",
            params![id],
        )
        .unwrap();
        drop(conn);
        let vault = reopen(&path, &key);
        for name in ["remote-token", "local"] {
            assert_eq!(vault.storage_of(name).unwrap_err().code(), "crypto");
            assert_eq!(vault.get_secret(name, None).unwrap_err().code(), "crypto");
        }
    }

    #[test]
    fn an_export_keeps_the_connections_and_their_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let (path, key, info) = with_connection(&dir);
        let export = dir.path().join("dev-export.sorvault");
        reopen(&path, &key).export_to(&export).unwrap();
        assert!(!contains(&std::fs::read(&export).unwrap(), TOKEN));
        let copy = reopen(&export, &key);
        assert_eq!(copy.connections().unwrap(), vec![info.clone()]);
        assert!(matches!(
            copy.connection_credentials(&info.id).unwrap(),
            Some(Credentials::VaultToken(token)) if token.expose() == TOKEN.as_bytes()
        ));
    }
}

mod catalog_and_projects {
    //! Descriptions in the catalog, and the project folders the vault
    //! records: each authenticated, audited, and carried by an export.

    use sourceorrery_core::ConnectionSettings;

    use super::*;
    use crate::{CatalogChange, CatalogEntry, ProjectLink, SecretStorage};

    const PATH_CANARY: &str = "folder-canary-7f3a";
    const NAME_CANARY: &str = "project-canary-2c9e";

    fn events(vault: &SqliteVault, operation: AuditOperation) -> Vec<(AuditOutcome, String)> {
        let mut events: Vec<_> = vault
            .audit_events(AuditQuery {
                operation: Some(operation),
                limit: Some(200),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .map(|e| (e.outcome, e.detail.unwrap_or_default()))
            .collect();
        events.reverse();
        events
    }

    fn contains(haystack: &[u8], needle: &str) -> bool {
        haystack
            .windows(needle.len())
            .any(|w| w == needle.as_bytes())
    }

    fn set(vault: &SqliteVault, name: &str) {
        vault
            .set_secret(name, SecretBytes::from("v"), SetSecretOptions::default())
            .unwrap();
    }

    #[test]
    fn a_description_belongs_to_the_catalog_and_is_audited_without_its_text() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault, key) = create(&dir);
        set(&vault, "db-password");
        assert_eq!(vault.description_of("db-password").unwrap(), None);
        vault
            .set_description("db-password", Some("Database authentication"))
            .unwrap();
        // A secret a connection stores takes one the same way.
        let id = vault
            .add_connection(
                &ConnectionSettings::HashicorpVault {
                    address: "https://vault.example.com".to_owned(),
                    mount: "secret".to_owned(),
                    namespace: None,
                },
                None,
            )
            .unwrap()
            .id;
        vault
            .record_at_connection(
                &id,
                AuditOperation::SecretSet,
                Some("llm-key"),
                Some("1"),
                Ok(()),
                CatalogChange::Add,
                None,
            )
            .unwrap();
        vault
            .set_description("llm-key", Some("Model provider key"))
            .unwrap();
        drop(vault);

        let vault = reopen(&path, &key);
        assert_eq!(
            vault.description_of("db-password").unwrap().as_deref(),
            Some("Database authentication")
        );
        assert_eq!(
            vault.description_of("llm-key").unwrap().as_deref(),
            Some("Model provider key")
        );
        // A new version keeps it; taking it away leaves none.
        set(&vault, "db-password");
        assert_eq!(
            vault.description_of("db-password").unwrap().as_deref(),
            Some("Database authentication")
        );
        vault.set_description("db-password", None).unwrap();
        assert_eq!(vault.description_of("db-password").unwrap(), None);

        for (name, description, code) in [
            ("db-password", Some("two\nlines"), "invalid_argument"),
            ("db-password", Some(""), "invalid_argument"),
            ("missing", Some("x"), "not_found"),
            ("bad_name", Some("x"), "invalid_name"),
        ] {
            let err = vault.set_description(name, description).unwrap_err();
            assert_eq!(err.code(), code, "{name}: {err}");
        }
        set(&vault, "gone");
        vault.delete_secret("gone").unwrap();
        assert_eq!(
            vault.set_description("gone", Some("x")).unwrap_err().code(),
            "deleted"
        );
        assert_eq!(vault.description_of("gone").unwrap_err().code(), "deleted");

        let updates = events(&vault, AuditOperation::SecretUpdate);
        assert!(updates.contains(&(AuditOutcome::Success, "description set".to_owned())));
        assert!(updates.contains(&(AuditOutcome::Success, "description removed".to_owned())));
        assert!(updates.contains(&(AuditOutcome::Failure, "invalid_argument".to_owned())));
        let all = vault.audit_events(AuditQuery::default()).unwrap();
        assert!(
            !format!("{all:?}").contains("Database authentication"),
            "the audit log never carries a description"
        );
        assert!(vault.verify_audit_chain().unwrap().is_intact());
    }

    #[test]
    fn an_edited_or_replayed_description_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault, key) = create(&dir);
        set(&vault, "api-key");
        vault.set_description("api-key", Some("first")).unwrap();
        let raw = |path: &Path| {
            rusqlite::Connection::open(path)
                .unwrap()
                .query_row(
                    "SELECT description, tag FROM secrets WHERE name = 'api-key'",
                    [],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .unwrap()
        };
        let older = raw(&path);
        vault.set_description("api-key", Some("second")).unwrap();
        drop(vault);
        for (n, (sql, older)) in [
            (
                "UPDATE secrets SET description = 'edited' WHERE name = 'api-key'",
                None,
            ),
            (
                "UPDATE secrets SET description = ?1, tag = ?2 WHERE name = 'api-key'",
                Some(&older),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let copy = dir.path().join(format!("tampered-{n}.sorvault"));
            std::fs::copy(&path, &copy).unwrap();
            let conn = rusqlite::Connection::open(&copy).unwrap();
            match older {
                Some((description, tag)) => conn.execute(sql, params![description, tag]),
                None => conn.execute(sql, []),
            }
            .unwrap();
            drop(conn);
            let vault = reopen(&copy, &key);
            assert_eq!(
                vault.description_of("api-key").unwrap_err().code(),
                "crypto",
                "{sql}"
            );
            assert_eq!(
                vault.get_secret("api-key", None).unwrap_err().code(),
                "crypto",
                "{sql}"
            );
        }
        assert_eq!(
            reopen(&path, &key)
                .description_of("api-key")
                .unwrap()
                .as_deref(),
            Some("second")
        );
    }

    #[test]
    fn a_project_folder_is_sealed_recorded_once_and_audited_by_id() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault, key) = create(&dir);
        assert_eq!(vault.projects().unwrap(), Vec::new());
        let app = dir.path().join(PATH_CANARY);
        let other = dir.path().join("other");
        let first = vault.link_project(&app, NAME_CANARY).unwrap();
        assert_eq!(first.path, app);
        assert_eq!(first.name, NAME_CANARY);
        let second = vault.link_project(&other, "other").unwrap();
        assert_ne!(first.id, second.id);
        // The same folder again: kept, then renamed under the same id.
        assert_eq!(vault.link_project(&app, NAME_CANARY).unwrap(), first);
        let renamed = vault.link_project(&app, "renamed").unwrap();
        assert_eq!(
            renamed,
            ProjectLink {
                name: "renamed".to_owned(),
                ..first.clone()
            }
        );
        for (bad, name, code) in [
            (Path::new("relative"), "x", "invalid_argument"),
            (other.as_path(), "", "invalid_argument"),
        ] {
            assert_eq!(vault.link_project(bad, name).unwrap_err().code(), code);
        }
        drop(vault);

        let bytes = std::fs::read(&path).unwrap();
        for canary in [PATH_CANARY, NAME_CANARY] {
            assert!(!contains(&bytes, canary), "{canary} is in the file");
        }
        let vault = reopen(&path, &key);
        assert_eq!(
            vault.projects().unwrap(),
            vec![renamed.clone(), second.clone()]
        );
        vault.unlink_project(&second.id).unwrap();
        assert_eq!(vault.projects().unwrap(), vec![renamed.clone()]);
        assert_eq!(
            vault.unlink_project(&second.id).unwrap_err().code(),
            "invalid_argument"
        );

        assert_eq!(
            events(&vault, AuditOperation::ProjectLink),
            vec![
                (
                    AuditOutcome::Success,
                    format!("project {} linked", first.id)
                ),
                (
                    AuditOutcome::Success,
                    format!("project {} linked", second.id)
                ),
                (
                    AuditOutcome::Success,
                    format!("project {} linked already", first.id)
                ),
                (
                    AuditOutcome::Success,
                    format!("project {} renamed", first.id)
                ),
                (AuditOutcome::Failure, "invalid_argument".to_owned()),
                (AuditOutcome::Failure, "invalid_argument".to_owned()),
            ]
        );
        assert_eq!(
            events(&vault, AuditOperation::ProjectUnlink),
            vec![
                (
                    AuditOutcome::Success,
                    format!("project {} unlinked", second.id)
                ),
                (AuditOutcome::Failure, "invalid_argument".to_owned()),
            ]
        );
        let all = format!("{:?}", vault.audit_events(AuditQuery::default()).unwrap());
        for canary in [PATH_CANARY, NAME_CANARY] {
            assert!(!all.contains(canary), "{canary} is in the audit log");
        }
        assert!(vault.verify_audit_chain().unwrap().is_intact());
    }

    #[test]
    fn an_edited_removed_added_or_older_project_row_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault, key) = create(&dir);
        let app = dir.path().join("app");
        let linked = vault.link_project(&app, "first").unwrap();
        let raw = |path: &Path| {
            rusqlite::Connection::open(path)
                .unwrap()
                .query_row("SELECT sealed, tag FROM projects", [], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .unwrap()
        };
        let older = raw(&path);
        vault.link_project(&app, "second").unwrap();
        drop(vault);

        // A sealed record moved under another tag-listed row is caught when
        // it is read.
        let copy = dir.path().join("edited.sorvault");
        std::fs::copy(&path, &copy).unwrap();
        rusqlite::Connection::open(&copy)
            .unwrap()
            .execute("UPDATE projects SET linked_on = linked_on + 1", [])
            .unwrap();
        let err = reopen(&copy, &key).projects().unwrap_err();
        assert_eq!(err.code(), "crypto", "{err}");
        assert!(
            err.to_string().contains(&format!("project {}", linked.id)),
            "{err}"
        );

        for (n, sql) in [
            "DELETE FROM projects",
            "INSERT INTO projects
             SELECT 'ffffffffffffffff', zeroblob(32), sealed, linked_on, tag FROM projects",
            "UPDATE projects SET sealed = ?1, tag = ?2",
        ]
        .into_iter()
        .enumerate()
        {
            let copy = dir.path().join(format!("tampered-{n}.sorvault"));
            std::fs::copy(&path, &copy).unwrap();
            let conn = rusqlite::Connection::open(&copy).unwrap();
            if sql.contains("?1") {
                conn.execute(sql, params![older.0, older.1]).unwrap();
            } else {
                conn.execute(sql, []).unwrap();
            }
            drop(conn);
            let err = SqliteVault::open(&copy, no_store(), &StaticRecoveryKey::new(key.as_str()))
                .unwrap_err();
            assert_eq!(err.code(), "crypto", "{sql}: {err}");
            assert!(err.to_string().contains("a project"), "{sql}: {err}");
        }
        assert_eq!(reopen(&path, &key).projects().unwrap()[0].name, "second");
    }

    #[test]
    fn an_export_keeps_the_projects_and_the_descriptions() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault, key) = create(&dir);
        set(&vault, "db-password");
        vault
            .set_description("db-password", Some("Database authentication"))
            .unwrap();
        let linked = vault
            .link_project(&dir.path().join(PATH_CANARY), NAME_CANARY)
            .unwrap();
        let export = dir.path().join("dev-export.sorvault");
        vault.export_to(&export).unwrap();
        drop(vault);
        let bytes = std::fs::read(&export).unwrap();
        assert!(!contains(&bytes, PATH_CANARY));
        let copy = reopen(&export, &key);
        assert_eq!(copy.projects().unwrap(), vec![linked]);
        assert_eq!(
            copy.description_of("db-password").unwrap().as_deref(),
            Some("Database authentication")
        );
        drop(copy);
        reopen(&path, &key);
    }

    #[test]
    fn the_catalog_lists_live_secrets_wherever_they_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault, key) = create(&dir);
        assert_eq!(vault.catalog().unwrap(), Vec::new());
        set(&vault, "db-password");
        vault
            .set_description("db-password", Some("Database authentication"))
            .unwrap();
        set(&vault, "gone");
        vault.delete_secret("gone").unwrap();
        let id = vault
            .add_connection(
                &ConnectionSettings::HashicorpVault {
                    address: "https://vault.example.com".to_owned(),
                    mount: "secret".to_owned(),
                    namespace: None,
                },
                None,
            )
            .unwrap()
            .id;
        vault
            .record_at_connection(
                &id,
                AuditOperation::SecretSet,
                Some("llm-key"),
                Some("1"),
                Ok(()),
                CatalogChange::Add,
                None,
            )
            .unwrap();
        assert_eq!(
            vault.catalog().unwrap(),
            vec![
                CatalogEntry {
                    name: "db-password".to_owned(),
                    storage: SecretStorage::Vault,
                    description: Some("Database authentication".to_owned()),
                },
                CatalogEntry {
                    name: "llm-key".to_owned(),
                    storage: SecretStorage::Connection(id),
                    description: None,
                },
            ]
        );
        assert!(
            events(&vault, AuditOperation::SecretList)
                .contains(&(AuditOutcome::Success, "catalog".to_owned()))
        );
        drop(vault);

        // A row edited out of band is refused, not listed or left out.
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE secrets SET deleted_on = NULL WHERE name = 'gone'",
                [],
            )
            .unwrap();
        assert_eq!(reopen(&path, &key).catalog().unwrap_err().code(), "crypto");
    }
}

mod settings_change {
    //! The setup wizard's review: a vault's settings changed in one
    //! transaction, each part recorded as it is when made alone.

    use sourceorrery_core::ConnectionSettings;
    use sourceorrery_crypto::{TotpSecret, totp};

    use super::*;
    use crate::{
        AuthenticatorChange, ConnectionChange, PasswordChange, RecoveryKey, SettingsChange,
        VaultRegistry,
    };

    const PASSWORD: &str = "orbit lantern copper nine 42";

    fn settings() -> ConnectionSettings {
        ConnectionSettings::HashicorpVault {
            address: "https://vault.example.com:8200".to_owned(),
            mount: "secret".to_owned(),
            namespace: None,
        }
    }

    fn events(vault: &SqliteVault, operation: AuditOperation) -> Vec<(AuditOutcome, String)> {
        let mut events: Vec<_> = vault
            .audit_events(AuditQuery {
                operation: Some(operation),
                limit: Some(200),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .map(|e| (e.outcome, e.detail.unwrap_or_default()))
            .collect();
        events.reverse();
        events
    }

    fn answers(code: String) -> ViewAnswers {
        ViewAnswers {
            password: Some(SecretBytes::from(PASSWORD)),
            code: Some(code),
            recovery_key: None,
        }
    }

    fn set_password() -> PasswordChange {
        PasswordChange::Set {
            password: SecretBytes::from(PASSWORD),
            hint: Some("the long one".to_owned()),
            params: Argon2Params::TESTING,
        }
    }

    #[test]
    fn a_new_vault_takes_the_recovery_key_its_owner_was_shown() {
        let dir = tempfile::tempdir().unwrap();
        let registry = VaultRegistry::with_root(dir.path()).with_store(no_store());
        let key = RecoveryKey::generate().unwrap();
        let shown = key.as_str().to_owned();
        assert!(!format!("{key:?}").contains(&shown));
        let created = registry
            .create_with_recovery_key("dev", CreateVaultOptions::default(), key)
            .unwrap();
        assert_eq!(created.recovery_key.as_str(), shown);
        drop(created);
        registry
            .open("dev", &StaticRecoveryKey::new(shown.as_str()))
            .unwrap();
        let again = registry
            .create_with_recovery_key(
                "DEV",
                CreateVaultOptions::default(),
                RecoveryKey::generate().unwrap(),
            )
            .unwrap_err();
        assert_eq!(again.code(), "vault_exists");
    }

    #[test]
    fn every_part_is_made_in_one_transaction_and_recorded_as_alone() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault, old_key) = create(&dir);
        let secret = TotpSecret::generate().unwrap();
        let now = timestamp::now();
        let counter = totp::counter_at(u64::try_from(now.unix_timestamp()).unwrap());
        let new_key = RecoveryKey::generate().unwrap();
        let new_text = new_key.as_str().to_owned();
        vault
            .change_settings(&SettingsChange {
                password: set_password(),
                authenticator: AuthenticatorChange::Verified {
                    secret: TotpSecret::from_bytes(secret.expose().to_vec()).unwrap(),
                    counter,
                },
                recovery_key: Some(new_key),
                connections: vec![ConnectionChange::Add {
                    settings: settings(),
                    credentials: None,
                }],
            })
            .unwrap();
        let check = vault.view_check().unwrap();
        assert!(check.password && check.authenticator);
        assert_eq!(
            vault.password_hint().unwrap().as_deref(),
            Some("the long one")
        );
        let connections = vault.connections().unwrap();
        assert_eq!(connections.len(), 1);

        // The code the owner verified with is not accepted again; the next
        // one is.
        let later = now + time::Duration::seconds(30);
        assert_eq!(
            vault
                .check_view(&answers(secret.code(counter)), now)
                .unwrap_err()
                .code(),
            "permission_denied"
        );
        vault
            .check_view(&answers(secret.code(counter + 1)), later)
            .unwrap();

        let guard = events(&vault, AuditOperation::Guard);
        for detail in ["password set", "authenticator enrolled and verified"] {
            assert!(
                guard.contains(&(AuditOutcome::Success, detail.to_owned())),
                "{guard:?}"
            );
        }
        assert!(
            events(&vault, AuditOperation::ProtectorAdd)
                .contains(&(AuditOutcome::Success, "recovery key replaced".to_owned()))
        );
        assert!(events(&vault, AuditOperation::VaultChange).contains(&(
            AuditOutcome::Success,
            format!(
                "connection {} added: hashicorp-vault, ambient credentials",
                connections[0].id
            )
        )));
        assert!(vault.verify_audit_chain().unwrap().is_intact());
        drop(vault);

        // The old recovery key stops working; the new one opens.
        assert_eq!(
            SqliteVault::open(&path, no_store(), &StaticRecoveryKey::new(old_key.as_str()))
                .unwrap_err()
                .code(),
            "locked"
        );
        reopen(&path, &new_text);
    }

    #[test]
    fn a_part_refused_leaves_every_other_as_it_was() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault, old_key) = create(&dir);
        // An authenticator without a password is refused, after the
        // connection and the recovery key were made in the same transaction.
        let err = vault
            .change_settings(&SettingsChange {
                authenticator: AuthenticatorChange::Verified {
                    secret: TotpSecret::generate().unwrap(),
                    counter: 1,
                },
                recovery_key: Some(RecoveryKey::generate().unwrap()),
                connections: vec![ConnectionChange::Add {
                    settings: settings(),
                    credentials: None,
                }],
                ..SettingsChange::default()
            })
            .unwrap_err();
        assert_eq!(err.code(), "invalid_argument");
        assert!(err.to_string().contains("set a password first"), "{err}");
        assert_eq!(vault.connections().unwrap(), Vec::new());
        assert!(vault.view_check().unwrap().is_none());
        assert_eq!(
            events(&vault, AuditOperation::VaultChange),
            vec![(AuditOutcome::Failure, "invalid_argument".to_owned())]
        );
        assert_eq!(events(&vault, AuditOperation::ProtectorAdd), Vec::new());
        assert!(vault.verify_audit_chain().unwrap().is_intact());
        drop(vault);
        reopen(&path, &old_key);
    }

    #[test]
    fn clearing_the_check_takes_the_authenticator_and_the_hint() {
        let dir = tempfile::tempdir().unwrap();
        let (_path, vault, _key) = create(&dir);
        vault
            .change_settings(&SettingsChange {
                password: set_password(),
                authenticator: AuthenticatorChange::Verified {
                    secret: TotpSecret::generate().unwrap(),
                    counter: 1,
                },
                ..SettingsChange::default()
            })
            .unwrap();
        assert!(SettingsChange::default().is_empty());
        vault
            .change_settings(&SettingsChange {
                password: PasswordChange::Clear,
                ..SettingsChange::default()
            })
            .unwrap();
        assert!(vault.view_check().unwrap().is_none());
        assert_eq!(vault.authenticator().unwrap(), None);
        assert_eq!(vault.password_hint().unwrap(), None);
        assert!(
            events(&vault, AuditOperation::Guard)
                .contains(&(AuditOutcome::Success, "view check cleared".to_owned()))
        );
    }
}

mod settings_record {
    //! The settings record is checkpointed on the audit chain as a row is:
    //! every change records the tag it leaves, and a record that is not
    //! the one the chain records last is refused, even though its own tag
    //! verifies.

    use sourceorrery_core::ConnectionSettings;

    use super::*;
    use crate::{ConnectionChange, FREE_FAILURES, PasswordChange, SettingsChange};

    const PASSWORD: &str = "a decent long password";

    /// The `vault_meta` keys of the record that change after creation.
    const RECORD_KEYS: &str =
        "('password', 'password_hint', 'second_factor', 'check_failures', 'settings_tag')";

    fn settings() -> ConnectionSettings {
        ConnectionSettings::HashicorpVault {
            address: "https://vault.example.com:8200".to_owned(),
            mount: "secret".to_owned(),
            namespace: None,
        }
    }

    fn wrong() -> ViewAnswers {
        ViewAnswers {
            password: Some(SecretBytes::from("nope")),
            ..ViewAnswers::default()
        }
    }

    /// A copy of the file at `path` as it is now, named after `label`.
    fn snapshot(dir: &tempfile::TempDir, path: &Path, label: &str) -> PathBuf {
        let copy = dir.path().join(format!("{label}.sorvault"));
        std::fs::copy(path, &copy).unwrap();
        copy
    }

    /// Put the whole settings record of the file at `older` back into the
    /// file at `path`: its `vault_meta` keys with the `connections` and
    /// `projects` rows it lists, all authentic, and nothing of the log.
    fn put_back(path: &Path, older: &Path) {
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute(
            "ATTACH DATABASE ?1 AS older",
            params![older.to_str().unwrap()],
        )
        .unwrap();
        conn.execute_batch(&format!(
            "DELETE FROM vault_meta WHERE key IN {RECORD_KEYS};
             INSERT INTO vault_meta SELECT key, value FROM older.vault_meta
                 WHERE key IN {RECORD_KEYS};
             DELETE FROM connections;
             INSERT INTO connections SELECT * FROM older.connections;
             DELETE FROM projects;
             INSERT INTO projects SELECT * FROM older.projects;"
        ))
        .unwrap();
    }

    fn open(path: &Path, key: &str) -> Result<SqliteVault> {
        SqliteVault::open(path, no_store(), &StaticRecoveryKey::new(key))
    }

    fn assert_replay_refused(err: &SecretError, what: &str) {
        assert_eq!(err.code(), "crypto", "{what}: {err}");
        assert!(
            err.to_string().contains("older authentic copy"),
            "{what}: {err}"
        );
    }

    #[test]
    fn an_older_settings_record_put_back_is_refused_at_open() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault, key) = create(&dir);
        // Each change below is undone by putting back the record from
        // before it.
        let no_password = snapshot(&dir, &path, "no-password");
        vault
            .set_password(&SecretBytes::from(PASSWORD), None, Argon2Params::TESTING)
            .unwrap();
        let no_failures = snapshot(&dir, &path, "no-failures");
        let now = timestamp::now();
        for _ in 0..FREE_FAILURES {
            assert!(vault.check_view(&wrong(), now).is_err());
        }
        let id = vault.add_connection(&settings(), None).unwrap().id;
        let with_connection = snapshot(&dir, &path, "with-connection");
        vault.remove_connection(&id).unwrap();
        drop(vault);

        for (n, (older, what)) in [
            (&no_password, "the record from before the password"),
            (&no_failures, "the record from before the wrong answers"),
            (&with_connection, "the record with the removed connection"),
        ]
        .into_iter()
        .enumerate()
        {
            let tampered = snapshot(&dir, &path, &format!("tampered-{n}"));
            put_back(&tampered, older);
            assert_replay_refused(&open(&tampered, &key).unwrap_err(), what);
            // The refusal is on the tampered file's own log.
            let detail: String = rusqlite::Connection::open(&tampered)
                .unwrap()
                .query_row(
                    "SELECT detail FROM audit_events ORDER BY id DESC LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(
                detail.starts_with("settings integrity check failed"),
                "{what}: {detail}"
            );
        }
        // The untouched file still opens, with what it recorded last.
        let vault = open(&path, &key).unwrap();
        assert_eq!(vault.view_check().unwrap().describe(), "password");
        assert_eq!(vault.connections().unwrap(), Vec::new());
    }

    #[test]
    fn a_record_put_back_under_an_open_handle_is_never_built_on() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault, key) = create(&dir);
        let no_password = snapshot(&dir, &path, "no-password");
        vault
            .set_password(&SecretBytes::from(PASSWORD), None, Argon2Params::TESTING)
            .unwrap();
        put_back(&path, &no_password);
        let now = timestamp::now();
        for (err, what) in [
            (
                vault.check_view(&ViewAnswers::default(), now).unwrap_err(),
                "check",
            ),
            (vault.connections().unwrap_err(), "connections"),
            (
                vault.add_connection(&settings(), None).unwrap_err(),
                "add a connection",
            ),
            (
                vault
                    .set_password(&SecretBytes::from("another"), None, Argon2Params::TESTING)
                    .unwrap_err(),
                "set the password",
            ),
        ] {
            assert_replay_refused(&err, what);
        }
        drop(vault);
        // No change was made over it, so it is still not the newest record.
        assert_replay_refused(&open(&path, &key).unwrap_err(), "reopened");
    }

    #[test]
    fn every_change_to_the_record_is_checkpointed() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault, key) = create(&dir);
        let opens = |what: &str| {
            open(&path, &key).unwrap_or_else(|err| panic!("after {what}: {err}"));
        };
        opens("creation");
        let now = timestamp::now();
        let unix = u64::try_from(now.unix_timestamp()).unwrap();
        vault
            .set_password(&SecretBytes::from(PASSWORD), None, Argon2Params::TESTING)
            .unwrap();
        opens("password set");
        assert!(vault.check_view(&wrong(), now).is_err());
        opens("a wrong answer");
        let right = ViewAnswers {
            password: Some(SecretBytes::from(PASSWORD)),
            ..ViewAnswers::default()
        };
        vault.check_view(&right, now).unwrap();
        opens("a right answer");
        let secret = vault.enrol_authenticator().unwrap();
        opens("enrolment");
        assert!(
            vault
                .verify_authenticator(&secret.code_at(unix), now)
                .unwrap()
        );
        opens("a code accepted");
        let id = vault.add_connection(&settings(), None).unwrap().id;
        opens("a connection added");
        vault
            .record_connection_test(&id, Err(&SecretError::Storage("unreachable".to_owned())))
            .unwrap();
        opens("a failed test");
        vault.remove_connection(&id).unwrap();
        opens("a connection removed");
        let project = vault.link_project(dir.path(), "demo").unwrap();
        opens("a project linked");
        vault.unlink_project(&project.id).unwrap();
        opens("a project unlinked");
        vault
            .change_settings(&SettingsChange {
                password: PasswordChange::Clear,
                connections: vec![ConnectionChange::Add {
                    settings: settings(),
                    credentials: None,
                }],
                ..SettingsChange::default()
            })
            .unwrap();
        opens("the setup screens' change");
        let copy = dir.path().join("copy.sorvault");
        vault.export_to(&copy).unwrap();
        open(&copy, &key).unwrap_or_else(|err| panic!("the export: {err}"));
        drop(vault);
        assert!(
            open(&path, &key)
                .unwrap()
                .verify_audit_chain()
                .unwrap()
                .is_intact()
        );
    }

    /// The missing events of a truncation may have held the newest
    /// settings checkpoint; the acknowledgement records the record as it
    /// stands, so the vault opens again once its owner has accepted what
    /// survived.
    #[test]
    fn an_acknowledged_truncation_keeps_the_settings_the_vault_has() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault, key) = create(&dir);
        vault
            .set_password(&SecretBytes::from(PASSWORD), None, Argon2Params::TESTING)
            .unwrap();
        // The wrong answer is the last event, and its checkpoint the newest.
        assert!(vault.check_view(&wrong(), timestamp::now()).is_err());
        drop(vault);
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute(
                "DELETE FROM audit_events WHERE id = (SELECT MAX(id) FROM audit_events)",
                [],
            )
            .unwrap();
        assert_eq!(open(&path, &key).unwrap_err().code(), "crypto");

        let blocked = SqliteVault::open_with(
            &path,
            no_store(),
            &StaticRecoveryKey::new(key.as_str()),
            OpenOptions {
                allow_quarantined: true,
            },
        )
        .unwrap();
        let ids: Vec<u64> = blocked
            .unacknowledged_truncations()
            .unwrap()
            .iter()
            .map(|event| event.id)
            .collect();
        blocked.acknowledge_truncations(&ids).unwrap();
        drop(blocked);
        let vault = open(&path, &key).unwrap();
        assert_eq!(vault.view_check().unwrap().describe(), "password");
    }

    /// Put the `key_wraps` rows of the file at `older` back into the file
    /// at `path`, replacing the ones it has, and nothing else.
    fn put_back_wraps(path: &Path, older: &Path) {
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute(
            "ATTACH DATABASE ?1 AS older",
            params![older.to_str().unwrap()],
        )
        .unwrap();
        conn.execute_batch(
            "DELETE FROM key_wraps;
             INSERT INTO key_wraps SELECT * FROM older.key_wraps;",
        )
        .unwrap();
    }

    /// SR01 of the 2026-10-25 review: the old recovery wrap put back into
    /// the current file, with the old key, must not open it or return a
    /// value written after the replacement (ADR 0010).
    #[test]
    fn an_old_recovery_wrap_put_back_does_not_open_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault, old_key) = create(&dir);
        let before = snapshot(&dir, &path, "before");
        let new_key = vault.replace_recovery_key().unwrap();
        vault
            .set_secret(
                "after",
                SecretBytes::from("written after the replacement"),
                SetSecretOptions::default(),
            )
            .unwrap();
        drop(vault);

        // The wrap row alone, the current settings and log untouched.
        let wrap_only = snapshot(&dir, &path, "wrap-only");
        put_back_wraps(&wrap_only, &before);
        let err = open(&wrap_only, &old_key).unwrap_err();
        assert_eq!(err.code(), "crypto", "{err}");
        assert!(err.to_string().contains("key wrap"), "{err}");

        // The wrap row and the whole settings record from before.
        let with_record = snapshot(&dir, &path, "with-record");
        put_back_wraps(&with_record, &before);
        put_back(&with_record, &before);
        assert_replay_refused(
            &open(&with_record, &old_key).unwrap_err(),
            "the old wrap with the old record",
        );

        // The untouched file: the old key is refused, the new one reads.
        assert_eq!(open(&path, &old_key).unwrap_err().code(), "locked");
        let vault = open(&path, &new_key).unwrap();
        assert_eq!(
            vault.get_secret("after", None).unwrap().value.expose(),
            b"written after the replacement"
        );
    }

    #[test]
    fn a_wrap_row_added_or_swapped_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault, key) = create(&dir);
        drop(vault);
        // A second, authentic copy of the recovery wrap under another id.
        let added = snapshot(&dir, &path, "added");
        rusqlite::Connection::open(&added)
            .unwrap()
            .execute_batch(
                "INSERT INTO key_wraps
                 SELECT 'ffffffffffffffff', kind_json, wrapped_nonce, wrapped_key, created_on
                 FROM key_wraps",
            )
            .unwrap();
        assert_eq!(open(&added, &key).unwrap_err().code(), "crypto");
        // The same row with another creation time.
        let edited = snapshot(&dir, &path, "edited");
        rusqlite::Connection::open(&edited)
            .unwrap()
            .execute_batch("UPDATE key_wraps SET created_on = created_on + 1")
            .unwrap();
        assert_eq!(open(&edited, &key).unwrap_err().code(), "crypto");
        // The untouched file opens.
        open(&path, &key).unwrap();
    }

    #[test]
    fn every_change_to_the_wraps_leaves_a_vault_that_opens() {
        let dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
        // Created with this machine's key and a recovery key.
        let path = dir.path().join("dev.sorvault");
        let created =
            SqliteVault::create(&path, "dev", CreateVaultOptions::default(), store.clone())
                .unwrap();
        assert!(created.this_machine);
        let key = created.recovery_key;
        drop(created.vault);
        let vault = SqliteVault::open(&path, store.clone(), &NoInteraction).unwrap();
        // The recovery key replaced on the setup screens' path.
        let replacement = RecoveryKey::generate().unwrap();
        vault
            .change_settings(&SettingsChange {
                recovery_key: Some(replacement.clone()),
                ..SettingsChange::default()
            })
            .unwrap();
        drop(vault);
        assert_eq!(open(&path, &key).unwrap_err().code(), "locked");
        let vault = open(&path, replacement.as_str()).unwrap();
        drop(vault);
        // Replaced again directly, then this machine's key on a vault
        // that had none.
        let other = dir.path().join("other.sorvault");
        let created =
            SqliteVault::create(&other, "other", CreateVaultOptions::default(), no_store())
                .unwrap();
        let other_key = created.vault.replace_recovery_key().unwrap();
        drop(created.vault);
        let vault = SqliteVault::open(
            &other,
            store.clone(),
            &StaticRecoveryKey::new(other_key.as_str()),
        )
        .unwrap();
        vault.add_this_machine_key().unwrap();
        drop(vault);
        SqliteVault::open(&other, store, &NoInteraction).unwrap();
    }

    #[test]
    fn a_file_of_an_earlier_schema_is_refused_without_being_changed() {
        let dir = tempfile::tempdir().unwrap();
        let (path, vault, key) = create(&dir);
        drop(vault);
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE vault_meta SET value = '4' WHERE key = 'schema_version'",
                [],
            )
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        let err = open(&path, &key).unwrap_err();
        assert_eq!(err.code(), "migration_required", "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}
