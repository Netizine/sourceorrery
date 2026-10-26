//! `Routed` over the vault file and over a connection.
//!
//! The provider behind a connection here is a second vault file, a complete
//! `SecretClient`, so the lifecycle scenarios run with every capability and
//! no network; the providers' own live tests run them against each service.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use sourceorrery_conformance::lifecycle::{self, set};
use sourceorrery_core::audit::{AuditOperation, AuditOutcome, AuditQuery};
use sourceorrery_core::{
    Capability, ConnectionSettings, Credentials, SecretBytes, SecretClient, SecretError,
    SetSecretOptions, rotation, timestamp,
};
use sourceorrery_provider::{ConnectionClient, MissingSecret, Routed};
use sourceorrery_storage::{
    CreateVaultOptions, NoStore, SecretStorage, SqliteVault, StaticRecoveryKey,
};
use tempfile::TempDir;

const TOKEN: &str = "hvs.routed-token";

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

/// A new vault named `dev` at `dir/file`, opening with its recovery key.
fn create(dir: &Path, file: &str) -> (PathBuf, SqliteVault, String) {
    let path = dir.join(file);
    let created = SqliteVault::create(
        &path,
        "dev",
        CreateVaultOptions::default(),
        Arc::new(NoStore),
    )
    .unwrap();
    let key = created.recovery_key.as_str().to_owned();
    (path, created.vault, key)
}

fn open(path: &Path, key: &str) -> SqliteVault {
    SqliteVault::open(path, Arc::new(NoStore), &StaticRecoveryKey::new(key)).unwrap()
}

/// A vault with one connection, `settings`, whose provider is the vault file
/// `provider.sorvault`; new secrets go to the connection.
struct Fixture {
    _dir: TempDir,
    routed: Routed,
    connection: String,
    /// The provider, as another client sees it.
    provider: SqliteVault,
    /// How often the connection was opened, and with which credentials.
    opened: Arc<AtomicUsize>,
}

fn fixture(settings: &ConnectionSettings, credentials: Option<&Credentials>) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (_, vault, _) = create(dir.path(), "dev.sorvault");
    let (provider_path, provider, provider_key) = create(dir.path(), "provider.sorvault");
    let connection = vault.add_connection(settings, credentials).unwrap().id;
    let opened = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&opened);
    let expected = credentials.map(|c| format!("{c:?}"));
    let routed = Routed::with_opener(vault, move |name, _settings, credentials| {
        assert_eq!(name, "dev");
        assert_eq!(credentials.map(|c| format!("{c:?}")), expected);
        if let Some(Credentials::VaultToken(token)) = credentials {
            assert_eq!(token.expose(), TOKEN.as_bytes());
        }
        count.fetch_add(1, Ordering::SeqCst);
        let client: ConnectionClient = Box::new(open(&provider_path, &provider_key));
        Ok(client)
    })
    .storing_new_in(SecretStorage::Connection(connection.clone()))
    .unwrap();
    Fixture {
        _dir: dir,
        routed,
        connection,
        provider,
        opened,
    }
}

/// Events of `operation` in the vault's log, oldest first.
fn events(client: &dyn SecretClient, operation: AuditOperation) -> Vec<(AuditOutcome, String)> {
    let mut events: Vec<_> = client
        .audit_events(AuditQuery {
            operation: Some(operation),
            limit: Some(500),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .map(|e| (e.outcome, e.detail.unwrap_or_default()))
        .collect();
    events.reverse();
    events
}

fn names(client: &dyn SecretClient) -> Vec<String> {
    client
        .list_properties_of_secrets()
        .unwrap()
        .into_iter()
        .map(|p| p.name)
        .collect()
}

#[test]
fn routed_over_the_vault_file_passes_the_lifecycle_scenarios() {
    let mut dirs = Vec::new();
    lifecycle::lifecycle(&mut |_| {
        let dir = tempfile::tempdir().unwrap();
        let (_, vault, _) = create(dir.path(), "dev.sorvault");
        dirs.push(dir);
        Box::new(Routed::new(vault))
    });
}

#[test]
fn routed_over_a_connection_passes_the_lifecycle_scenarios() {
    let mut dirs = Vec::new();
    lifecycle::lifecycle(&mut |_| {
        let Fixture {
            _dir: dir, routed, ..
        } = fixture(&vault_settings(), None);
        dirs.push(dir);
        Box::new(routed)
    });
}

#[test]
fn the_catalog_and_the_provider_agree() {
    let f = fixture(
        &vault_settings(),
        Some(&Credentials::VaultToken(TOKEN.into())),
    );
    let (routed, id) = (&f.routed, f.connection.as_str());
    set(routed, "remote-a", "one");
    routed
        .set_secret_in(
            &SecretStorage::Vault,
            "local-b",
            SecretBytes::from("two"),
            SetSecretOptions::default(),
        )
        .unwrap();
    let at = Some(SecretStorage::Connection(id.to_owned()));
    assert_eq!(routed.vault().storage_of("remote-a").unwrap(), at);
    assert_eq!(
        routed.vault().storage_of("local-b").unwrap(),
        Some(SecretStorage::Vault)
    );
    // Each value is where its storage says, and nowhere else.
    assert_eq!(names(&f.provider), vec!["remote-a"]);
    assert_eq!(names(routed.vault()), vec!["local-b"]);
    assert_eq!(names(routed), vec!["local-b", "remote-a"]);
    assert_eq!(
        routed.get_secret("remote-a", None).unwrap().value.expose(),
        b"one"
    );

    // A new version goes where the secret is.
    let err = routed
        .set_secret_in(
            &SecretStorage::Vault,
            "remote-a",
            SecretBytes::from("x"),
            SetSecretOptions::default(),
        )
        .unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    set(routed, "remote-a", "newer");
    assert_eq!(
        f.provider
            .list_properties_of_secret_versions("remote-a")
            .unwrap()
            .len(),
        2
    );

    // Delete and recover there; the catalog keeps the entry.
    routed.delete_secret("remote-a").unwrap();
    assert!(f.provider.get_deleted_secret("remote-a").is_ok());
    assert_eq!(routed.vault().storage_of("remote-a").unwrap(), at);
    let deleted: Vec<String> = routed
        .list_deleted_secrets()
        .unwrap()
        .into_iter()
        .map(|d| d.properties.name)
        .collect();
    assert_eq!(deleted, vec!["remote-a"]);
    assert_eq!(names(routed), vec!["local-b"]);
    routed.recover_deleted_secret("remote-a").unwrap();
    assert_eq!(names(routed), vec!["local-b", "remote-a"]);

    // The connection cannot go while it stores the secret; purged, it can.
    let err = routed.vault().remove_connection(id).unwrap_err();
    assert!(
        err.to_string().contains("still stores 1 secret(s)"),
        "{err}"
    );
    routed.delete_secret("remote-a").unwrap();
    routed.purge_deleted_secret("remote-a").unwrap();
    assert_eq!(routed.vault().storage_of("remote-a").unwrap(), None);
    assert_eq!(names(&f.provider), Vec::<String>::new());
    assert_eq!(f.provider.list_deleted_secrets().unwrap(), Vec::new());

    // What happened at the provider is in the vault's own log; each change
    // as an attempt recorded before it was sent, and the event completing it.
    let at = format!("at connection {id}");
    for operation in [
        AuditOperation::SecretSet,
        AuditOperation::SecretGet,
        AuditOperation::SecretList,
        AuditOperation::SecretDelete,
        AuditOperation::SecretRecover,
        AuditOperation::SecretPurge,
    ] {
        let recorded = events(routed, operation);
        assert!(
            recorded.iter().any(|(outcome, detail)| {
                *outcome == AuditOutcome::Success
                    && (*detail == at || detail.starts_with(&format!("{at} (attempt ")))
            }),
            "{operation}: {recorded:?}"
        );
        let attempted = recorded.contains(&(AuditOutcome::Pending, format!("{at}: sent")));
        assert_eq!(attempted, operation.changes_a_secret(), "{operation}");
    }
    assert_eq!(routed.vault().unresolved_attempts().unwrap(), Vec::new());
    routed.vault().remove_connection(id).unwrap();
    assert!(routed.vault().verify_audit_chain().unwrap().is_intact());
    assert_eq!(f.opened.load(Ordering::SeqCst), 1, "opened once, then kept");
}

/// A connection changed through another handle (the setup screens beside
/// an open browser) is opened again from the vault: no later call goes to
/// the endpoint it left or with the credentials it replaced.
#[test]
fn a_connection_changed_elsewhere_is_opened_again_before_its_next_call() {
    let dir = tempfile::tempdir().unwrap();
    let (path, vault, key) = create(dir.path(), "dev.sorvault");
    let (provider_path, _, provider_key) = create(dir.path(), "provider.sorvault");
    let id = vault
        .add_connection(
            &vault_settings(),
            Some(&Credentials::VaultToken(SecretBytes::from(TOKEN))),
        )
        .unwrap()
        .id;
    let opened = Arc::new(Mutex::new(Vec::new()));
    let routed = Routed::with_opener(vault, {
        let opened = Arc::clone(&opened);
        move |_, settings, credentials| {
            opened
                .lock()
                .unwrap()
                .push((settings.location(), credentials.is_some()));
            let client: ConnectionClient = Box::new(open(&provider_path, &provider_key));
            Ok(client)
        }
    })
    .storing_new_in(SecretStorage::Connection(id.clone()))
    .unwrap();
    set(&routed, "api-key", "one");
    routed.get_secret("api-key", None).unwrap();
    assert_eq!(opened.lock().unwrap().len(), 1, "kept while unchanged");

    let elsewhere = open(&path, &key);
    let moved = ConnectionSettings::HashicorpVault {
        address: "https://vault2.example.com".to_owned(),
        mount: "secret".to_owned(),
        namespace: None,
    };
    elsewhere.set_connection_settings(&id, &moved).unwrap();
    elsewhere.set_connection_credentials(&id, None).unwrap();

    set(&routed, "api-key", "two");
    routed.list_properties_of_secrets().unwrap();
    assert_eq!(
        *opened.lock().unwrap(),
        vec![
            (vault_settings().location(), true),
            (moved.location(), false),
        ],
        "opened again once, from the connection as it is now"
    );
}

#[test]
fn a_secret_removed_at_the_provider_is_reported_not_hidden() {
    let f = fixture(&vault_settings(), None);
    let routed = &f.routed;
    set(routed, "kept", "one");
    set(routed, "gone", "two");
    // Out of band: deleted and purged at the provider itself.
    f.provider.delete_secret("gone").unwrap();
    f.provider.purge_deleted_secret("gone").unwrap();

    assert_eq!(
        routed.missing().unwrap(),
        vec![MissingSecret {
            name: "gone".to_owned(),
            connection: f.connection.clone(),
        }]
    );
    assert_eq!(names(routed), vec!["kept"]);
    let err = routed.get_secret("gone", None).unwrap_err();
    assert_eq!(err.code(), "not_found");
    assert!(events(routed, AuditOperation::SecretGet).contains(&(
        AuditOutcome::Failure,
        format!("at connection {}: not_found", f.connection)
    )));

    let err = routed.forget_missing("kept").unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    routed.forget_missing("gone").unwrap();
    assert_eq!(routed.missing().unwrap(), Vec::new());
    assert_eq!(routed.vault().storage_of("gone").unwrap(), None);
    assert!(routed.vault().verify_audit_chain().unwrap().is_intact());
}

#[test]
fn capabilities_follow_the_storage() {
    let f = fixture(&aws_settings(), None);
    let routed = &f.routed;
    assert_eq!(routed.capabilities(), &[Capability::ClearableTimeWindow]);
    assert_eq!(
        routed.capabilities_of("not-yet").unwrap(),
        &[Capability::ClearableTimeWindow]
    );
    set(routed, "at-aws", "one");
    routed
        .set_secret_in(
            &SecretStorage::Vault,
            "local",
            SecretBytes::from("two"),
            SetSecretOptions::default(),
        )
        .unwrap();
    assert_eq!(routed.capabilities_of("local").unwrap(), Capability::ALL);
    assert_eq!(
        routed.capabilities_of("at-aws").unwrap(),
        &[Capability::ClearableTimeWindow]
    );

    // Rotation needs per-version properties: refused where the secret is
    // kept per secret, allowed in the vault file.
    let now = timestamp::now();
    let err = rotation::issue(routed, "at-aws", SecretBytes::from("new"), now).unwrap_err();
    assert_eq!(err.code(), "unsupported");
    rotation::issue(routed, "local", SecretBytes::from("new"), now).unwrap();
}

#[test]
fn a_connection_that_cannot_be_opened_is_recorded_and_catalogues_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (_, vault, _) = create(dir.path(), "dev.sorvault");
    let id = vault.add_connection(&vault_settings(), None).unwrap().id;
    let routed = Routed::with_opener(vault, |_, _, _| {
        Err(SecretError::Unauthenticated {
            provider: "hashicorp-vault".to_owned(),
            reason: "no token".to_owned(),
        })
    })
    .storing_new_in(SecretStorage::Connection(id.clone()))
    .unwrap();
    let err = routed
        .set_secret(
            "new-one",
            SecretBytes::from("v"),
            SetSecretOptions::default(),
        )
        .unwrap_err();
    assert_eq!(err.code(), "unauthenticated");
    assert_eq!(routed.vault().storage_of("new-one").unwrap(), None);
    assert_eq!(
        events(&routed, AuditOperation::SecretSet),
        vec![(
            AuditOutcome::Failure,
            format!("at connection {id}: unauthenticated")
        )]
    );
    // Nothing is stored there, so listing the vault never opens it.
    assert_eq!(names(&routed), Vec::<String>::new());
    // New secrets cannot be sent to a connection the vault does not have.
    let (_, other, _) = create(dir.path(), "other.sorvault");
    let err = Routed::new(other)
        .storing_new_in(SecretStorage::Connection("ffffffffffffffff".to_owned()))
        .unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
}

/// Something a test runs at the provider while a change is being made.
type During = Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>;

/// What a test does to the provider behind a connection: every call is
/// counted, so a test can tell whether anything was sent; changes can be
/// refused, or made with their answer lost; and something can run while a
/// change is being made.
#[derive(Clone, Default)]
struct Faults {
    calls: Arc<AtomicUsize>,
    refuse: Arc<AtomicBool>,
    lose_answers: Arc<AtomicBool>,
    during: During,
}

/// A provider client over a vault file, with [`Faults`].
struct Counting {
    inner: SqliteVault,
    faults: Faults,
}

impl Counting {
    fn hit(&self) {
        self.faults.calls.fetch_add(1, Ordering::SeqCst);
    }

    /// A change: refused before it is made, or made and its answer lost,
    /// as the faults say.
    fn change<T>(
        &self,
        make: impl FnOnce(&SqliteVault) -> sourceorrery_core::Result<T>,
    ) -> sourceorrery_core::Result<T> {
        self.hit();
        if self.faults.refuse.load(Ordering::SeqCst) {
            return Err(SecretError::PermissionDenied(
                "the policy of this token does not allow it".to_owned(),
            ));
        }
        let outcome = make(&self.inner);
        if let Some(during) = self.faults.during.lock().unwrap().take() {
            during();
        }
        if self.faults.lose_answers.load(Ordering::SeqCst) {
            outcome?;
            return Err(SecretError::ProviderUnavailable {
                provider: "hashicorp-vault".to_owned(),
                reason: "the connection was reset before the answer".to_owned(),
            });
        }
        outcome
    }
}

impl SecretClient for Counting {
    fn vault_name(&self) -> &str {
        self.inner.vault_name()
    }
    fn set_secret(
        &self,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
    ) -> sourceorrery_core::Result<sourceorrery_core::SecretProperties> {
        self.change(|inner| inner.set_secret(name, value, options))
    }
    fn get_secret(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> sourceorrery_core::Result<sourceorrery_core::Secret> {
        self.hit();
        self.inner.get_secret(name, version)
    }
    fn get_secret_properties(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> sourceorrery_core::Result<sourceorrery_core::SecretProperties> {
        self.hit();
        self.inner.get_secret_properties(name, version)
    }
    fn list_properties_of_secrets(
        &self,
    ) -> sourceorrery_core::Result<Vec<sourceorrery_core::SecretProperties>> {
        self.hit();
        self.inner.list_properties_of_secrets()
    }
    fn list_properties_of_secret_versions(
        &self,
        name: &str,
    ) -> sourceorrery_core::Result<Vec<sourceorrery_core::SecretProperties>> {
        self.hit();
        self.inner.list_properties_of_secret_versions(name)
    }
    fn update_secret_properties(
        &self,
        name: &str,
        version: Option<&str>,
        update: sourceorrery_core::UpdateSecretProperties,
    ) -> sourceorrery_core::Result<sourceorrery_core::SecretProperties> {
        self.change(|inner| inner.update_secret_properties(name, version, update))
    }
    fn delete_secret(
        &self,
        name: &str,
    ) -> sourceorrery_core::Result<sourceorrery_core::DeletedSecret> {
        self.change(|inner| inner.delete_secret(name))
    }
    fn get_deleted_secret(
        &self,
        name: &str,
    ) -> sourceorrery_core::Result<sourceorrery_core::DeletedSecret> {
        self.hit();
        self.inner.get_deleted_secret(name)
    }
    fn list_deleted_secrets(
        &self,
    ) -> sourceorrery_core::Result<Vec<sourceorrery_core::DeletedSecret>> {
        self.hit();
        self.inner.list_deleted_secrets()
    }
    fn recover_deleted_secret(
        &self,
        name: &str,
    ) -> sourceorrery_core::Result<sourceorrery_core::SecretProperties> {
        self.change(|inner| inner.recover_deleted_secret(name))
    }
    fn purge_deleted_secret(&self, name: &str) -> sourceorrery_core::Result<()> {
        self.change(|inner| inner.purge_deleted_secret(name))
    }
    fn audit_events(
        &self,
        query: AuditQuery,
    ) -> sourceorrery_core::Result<Vec<sourceorrery_core::audit::AuditEvent>> {
        self.hit();
        self.inner.audit_events(query)
    }
}

/// A vault at `dir/dev.sorvault` with one connection whose provider is the
/// vault file `dir/provider.sorvault` behind [`Faults`]; new secrets go to
/// the connection. The vault's path and recovery key, so a test can open it
/// again, and the provider's key.
struct Faulty {
    routed: Routed,
    faults: Faults,
    connection: String,
    path: PathBuf,
    key: String,
    provider_path: PathBuf,
    provider_key: String,
}

fn faulty(dir: &Path) -> Faulty {
    let (path, vault, key) = create(dir, "dev.sorvault");
    let (provider_path, provider, provider_key) = create(dir, "provider.sorvault");
    drop(provider);
    let connection = vault.add_connection(&vault_settings(), None).unwrap().id;
    let faults = Faults::default();
    let (opener_faults, opener_path, opener_key) =
        (faults.clone(), provider_path.clone(), provider_key.clone());
    let routed = Routed::with_opener(vault, move |_, _, _| {
        let client: ConnectionClient = Box::new(Counting {
            inner: open(&opener_path, &opener_key),
            faults: opener_faults.clone(),
        });
        Ok(client)
    })
    .storing_new_in(SecretStorage::Connection(connection.clone()))
    .unwrap();
    Faulty {
        routed,
        faults,
        connection,
        path,
        key,
        provider_path,
        provider_key,
    }
}

impl Faulty {
    /// The provider, as another client sees it.
    fn provider(&self) -> SqliteVault {
        open(&self.provider_path, &self.provider_key)
    }

    fn versions_at_provider(&self, name: &str) -> usize {
        self.provider()
            .list_properties_of_secret_versions(name)
            .unwrap()
            .len()
    }

    fn unresolved(&self) -> Vec<(u64, AuditOperation, String)> {
        self.routed
            .vault()
            .unresolved_attempts()
            .unwrap()
            .into_iter()
            .map(|e| (e.id, e.operation, e.secret_name.unwrap_or_default()))
            .collect()
    }
}

/// The id of the newest `pending` event in the vault's log.
fn newest_attempt(client: &dyn SecretClient) -> u64 {
    client
        .audit_events(AuditQuery {
            limit: Some(500),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .find(|e| e.outcome == AuditOutcome::Pending)
        .expect("an attempt was recorded")
        .id
}

/// SR03 of the 2026-10-25 review: a vault whose audit log was cut short
/// sends nothing to a provider, through a client opened before the cut as
/// through a new one, and every refusal is the vault's own `crypto`.
#[test]
fn a_blocked_vault_sends_nothing_to_its_providers() {
    let dir = tempfile::tempdir().unwrap();
    let f = faulty(dir.path());
    let routed = &f.routed;
    // Two secrets at the provider, one of them deleted; the client is open.
    set(routed, "kept", "a value");
    set(routed, "gone", "another");
    routed.delete_secret("gone").unwrap();
    routed.get_secret("kept", None).unwrap();
    let before = f.faults.calls.load(Ordering::SeqCst);

    // The newest audit row removed: the log is cut short.
    rusqlite::Connection::open(&f.path)
        .unwrap()
        .execute(
            "DELETE FROM audit_events WHERE id = (SELECT MAX(id) FROM audit_events)",
            [],
        )
        .unwrap();
    let refused: Vec<(&str, SecretError)> = vec![
        ("get", routed.get_secret("kept", None).unwrap_err()),
        (
            "properties",
            routed.get_secret_properties("kept", None).unwrap_err(),
        ),
        (
            "versions",
            routed
                .list_properties_of_secret_versions("kept")
                .unwrap_err(),
        ),
        (
            "set",
            routed
                .set_secret(
                    "kept",
                    SecretBytes::from("new"),
                    SetSecretOptions::default(),
                )
                .unwrap_err(),
        ),
        (
            "update",
            routed
                .update_secret_properties(
                    "kept",
                    None,
                    sourceorrery_core::UpdateSecretProperties::default(),
                )
                .unwrap_err(),
        ),
        ("delete", routed.delete_secret("kept").unwrap_err()),
        ("deleted", routed.get_deleted_secret("gone").unwrap_err()),
        (
            "recover",
            routed.recover_deleted_secret("gone").unwrap_err(),
        ),
        ("purge", routed.purge_deleted_secret("gone").unwrap_err()),
        ("list", routed.list_properties_of_secrets().unwrap_err()),
        ("list deleted", routed.list_deleted_secrets().unwrap_err()),
    ];
    for (what, err) in &refused {
        assert_eq!(err.code(), "crypto", "{what}: {err}");
    }
    assert_eq!(
        f.faults.calls.load(Ordering::SeqCst),
        before,
        "a call reached the provider"
    );
    // Refused before dispatch: no attempt was recorded for any of them.
    assert_eq!(f.unresolved(), Vec::new());
    // The provider was not changed: the secret is there, the other still deleted.
    let provider = f.provider();
    assert_eq!(
        provider.get_secret("kept", None).unwrap().value.expose(),
        b"a value"
    );
    assert!(provider.get_deleted_secret("gone").is_ok());
}

/// ADR 0011: a change the provider refused is returned as it refused it,
/// recorded as completing its attempt, and leaves nothing unresolved.
#[test]
fn a_refused_change_completes_its_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let f = faulty(dir.path());
    let (routed, id) = (&f.routed, f.connection.as_str());
    set(routed, "kept", "one");
    f.faults.refuse.store(true, Ordering::SeqCst);
    let err = routed
        .set_secret(
            "kept",
            SecretBytes::from("two"),
            SetSecretOptions::default(),
        )
        .unwrap_err();
    assert_eq!(err.code(), "permission_denied", "{err}");
    let attempt = newest_attempt(routed);
    let sets = events(routed, AuditOperation::SecretSet);
    assert_eq!(
        sets[sets.len() - 2..],
        [
            (AuditOutcome::Pending, format!("at connection {id}: sent")),
            (
                AuditOutcome::Denied,
                format!("at connection {id}: permission_denied (attempt {attempt})")
            ),
        ]
    );
    assert_eq!(f.unresolved(), Vec::new());
    assert_eq!(f.versions_at_provider("kept"), 1, "nothing was made");
}

/// ADR 0011: a change whose answer was lost is `outcome_unknown`, recorded
/// as `unknown`, and stays unresolved until a later change of the secret
/// through the connection succeeds; nothing is retried.
#[test]
fn a_lost_answer_is_outcome_unknown_until_a_later_change_settles_it() {
    let dir = tempfile::tempdir().unwrap();
    let f = faulty(dir.path());
    let (routed, id) = (&f.routed, f.connection.as_str());
    set(routed, "kept", "one");
    let calls = f.faults.calls.load(Ordering::SeqCst);

    f.faults.lose_answers.store(true, Ordering::SeqCst);
    let err = routed
        .set_secret(
            "kept",
            SecretBytes::from("two"),
            SetSecretOptions::default(),
        )
        .unwrap_err();
    assert_eq!(err.code(), "outcome_unknown", "{err}");
    assert!(!err.is_transient());
    assert!(
        err.to_string().starts_with(&format!(
            "the change may have been made at connection {id}: hashicorp-vault is unavailable"
        )),
        "{err}"
    );
    assert_eq!(
        f.faults.calls.load(Ordering::SeqCst),
        calls + 1,
        "sent once, never retried"
    );
    assert_eq!(f.versions_at_provider("kept"), 2, "the provider made it");
    let attempt = newest_attempt(routed);
    assert_eq!(
        events(routed, AuditOperation::SecretSet).last(),
        Some(&(
            AuditOutcome::Unknown,
            format!("at connection {id}: outcome_unknown (attempt {attempt})")
        ))
    );
    assert_eq!(
        f.unresolved(),
        vec![(attempt, AuditOperation::SecretSet, "kept".to_owned())]
    );

    // A refused change of the same secret does not settle it ...
    f.faults.lose_answers.store(false, Ordering::SeqCst);
    f.faults.refuse.store(true, Ordering::SeqCst);
    routed.delete_secret("kept").unwrap_err();
    assert_eq!(f.unresolved().len(), 1);
    // ... a successful one does: the secret was looked at and changed again.
    f.faults.refuse.store(false, Ordering::SeqCst);
    set(routed, "kept", "three");
    assert_eq!(f.unresolved(), Vec::new());

    // A purge whose answer was lost keeps the catalog entry; once the
    // provider confirms the secret is gone, forgetting it settles that too.
    routed.delete_secret("kept").unwrap();
    f.faults.lose_answers.store(true, Ordering::SeqCst);
    let err = routed.purge_deleted_secret("kept").unwrap_err();
    assert_eq!(err.code(), "outcome_unknown");
    f.faults.lose_answers.store(false, Ordering::SeqCst);
    assert_eq!(
        routed.vault().storage_of("kept").unwrap(),
        Some(SecretStorage::Connection(id.to_owned()))
    );
    assert_eq!(f.unresolved().len(), 1);
    assert_eq!(
        routed.missing().unwrap(),
        vec![MissingSecret {
            name: "kept".to_owned(),
            connection: id.to_owned(),
        }]
    );
    routed.forget_missing("kept").unwrap();
    assert_eq!(f.unresolved(), Vec::new());
    assert!(routed.vault().verify_audit_chain().unwrap().is_intact());
}

/// ADR 0011: a change the provider made that the vault then cannot record
/// is `outcome_unknown`, never the vault's own refusal alone, and its
/// attempt stays unresolved.
#[test]
fn a_change_made_but_not_recorded_is_outcome_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let f = faulty(dir.path());
    let routed = &f.routed;
    // While the provider creates `raced`, another process keeps a secret of
    // that name in the vault file: the catalog can no longer take it.
    let (path, key) = (f.path.clone(), f.key.clone());
    *f.faults.during.lock().unwrap() = Some(Box::new(move || {
        let other = open(&path, &key);
        other
            .set_secret(
                "raced",
                SecretBytes::from("local"),
                SetSecretOptions::default(),
            )
            .unwrap();
    }));
    let err = routed
        .set_secret(
            "raced",
            SecretBytes::from("remote"),
            SetSecretOptions::default(),
        )
        .unwrap_err();
    assert_eq!(err.code(), "outcome_unknown", "{err}");
    assert!(
        err.to_string().contains(
            "the provider answered that it made the change, and this vault could not \
                       record it"
        ),
        "{err}"
    );
    assert_eq!(f.versions_at_provider("raced"), 1, "the provider made it");
    assert_eq!(
        routed.vault().storage_of("raced").unwrap(),
        Some(SecretStorage::Vault),
        "the catalog was not changed"
    );
    let attempt = newest_attempt(routed);
    assert_eq!(
        f.unresolved(),
        vec![(attempt, AuditOperation::SecretSet, "raced".to_owned())]
    );
}

/// ADR 0011: an attempt nothing completed, because the process stopped
/// after sending it, is listed when the vault is opened again; the next
/// successful change of the secret settles it.
#[test]
fn an_attempt_cut_short_by_a_restart_is_listed_when_the_vault_opens_again() {
    let dir = tempfile::tempdir().unwrap();
    let f = faulty(dir.path());
    let id = f.connection.clone();
    set(&f.routed, "kept", "one");
    let attempt = f
        .routed
        .vault()
        .attempt_at_connection(
            &id,
            AuditOperation::SecretDelete,
            "kept",
            sourceorrery_storage::CatalogChange::Keep,
        )
        .unwrap();
    // The process stops here: the change is sent, nothing records its result.
    drop(f.routed);

    let reopened = open(&f.path, &f.key);
    let unresolved = reopened.unresolved_attempts().unwrap();
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].id, attempt.event_id);
    assert_eq!(unresolved[0].operation, AuditOperation::SecretDelete);
    assert_eq!(unresolved[0].outcome, AuditOutcome::Pending);
    assert_eq!(
        unresolved[0].detail.as_deref(),
        Some(format!("at connection {id}: sent").as_str())
    );
    assert!(reopened.verify_audit_chain().unwrap().is_intact());

    let routed = Routed::with_opener(reopened, {
        let (path, key) = (f.provider_path.clone(), f.provider_key.clone());
        move |_, _, _| {
            let client: ConnectionClient = Box::new(open(&path, &key));
            Ok(client)
        }
    });
    routed.delete_secret("kept").unwrap();
    assert_eq!(routed.vault().unresolved_attempts().unwrap(), Vec::new());
}

/// No attempt, completion or `outcome_unknown` carries a value.
#[test]
fn attempts_and_unknown_outcomes_never_carry_a_value() {
    const CANARY: &str = "canary-7f3a9c-value";
    let dir = tempfile::tempdir().unwrap();
    let f = faulty(dir.path());
    let routed = &f.routed;
    set(routed, "kept", CANARY);
    f.faults.lose_answers.store(true, Ordering::SeqCst);
    let err = routed
        .set_secret(
            "kept",
            SecretBytes::from(CANARY),
            SetSecretOptions::default(),
        )
        .unwrap_err();
    assert!(!err.to_string().contains(CANARY));
    assert!(!format!("{err:?}").contains(CANARY));
    let events = routed
        .audit_events(AuditQuery {
            limit: Some(500),
            ..Default::default()
        })
        .unwrap();
    assert!(events.iter().any(|e| e.outcome == AuditOutcome::Unknown));
    for event in &events {
        assert!(!format!("{event:?}").contains(CANARY), "{event:?}");
    }
}
