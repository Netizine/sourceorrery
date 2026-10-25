//! `Routed` over the vault file and over a connection.
//!
//! The provider behind a connection here is a second vault file, a complete
//! `SecretClient`, so the lifecycle scenarios run with every capability and
//! no network; the providers' own live tests run them against each service.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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

    // What happened at the provider is in the vault's own log.
    let at_connection = (AuditOutcome::Success, format!("at connection {id}"));
    for operation in [
        AuditOperation::SecretSet,
        AuditOperation::SecretGet,
        AuditOperation::SecretList,
        AuditOperation::SecretDelete,
        AuditOperation::SecretRecover,
        AuditOperation::SecretPurge,
    ] {
        assert!(
            events(routed, operation).contains(&at_connection),
            "{operation}"
        );
    }
    routed.vault().remove_connection(id).unwrap();
    assert!(routed.vault().verify_audit_chain().unwrap().is_intact());
    assert_eq!(f.opened.load(Ordering::SeqCst), 1, "opened once, then kept");
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

/// A provider client that counts every call it is given, so a test can
/// tell whether anything was sent.
struct Counting {
    inner: SqliteVault,
    calls: Arc<AtomicUsize>,
}

impl Counting {
    fn hit(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
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
        self.hit();
        self.inner.set_secret(name, value, options)
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
        self.hit();
        self.inner.update_secret_properties(name, version, update)
    }
    fn delete_secret(
        &self,
        name: &str,
    ) -> sourceorrery_core::Result<sourceorrery_core::DeletedSecret> {
        self.hit();
        self.inner.delete_secret(name)
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
        self.hit();
        self.inner.recover_deleted_secret(name)
    }
    fn purge_deleted_secret(&self, name: &str) -> sourceorrery_core::Result<()> {
        self.hit();
        self.inner.purge_deleted_secret(name)
    }
    fn audit_events(
        &self,
        query: AuditQuery,
    ) -> sourceorrery_core::Result<Vec<sourceorrery_core::audit::AuditEvent>> {
        self.hit();
        self.inner.audit_events(query)
    }
}

/// SR03 of the 2026-10-25 review: a vault whose audit log was cut short
/// sends nothing to a provider, through a client opened before the cut as
/// through a new one, and every refusal is the vault's own `crypto`.
#[test]
fn a_blocked_vault_sends_nothing_to_its_providers() {
    let dir = tempfile::tempdir().unwrap();
    let (path, vault, _) = create(dir.path(), "dev.sorvault");
    let (provider_path, provider, provider_key) = create(dir.path(), "provider.sorvault");
    drop(provider);
    let connection = vault.add_connection(&vault_settings(), None).unwrap().id;
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let opener_key = provider_key.clone();
    let routed = Routed::with_opener(vault, move |_, _, _| {
        let client: ConnectionClient = Box::new(Counting {
            inner: open(&provider_path, &opener_key),
            calls: Arc::clone(&counter),
        });
        Ok(client)
    })
    .storing_new_in(SecretStorage::Connection(connection))
    .unwrap();
    // Two secrets at the provider, one of them deleted; the client is open.
    set(&routed, "kept", "a value");
    set(&routed, "gone", "another");
    routed.delete_secret("gone").unwrap();
    routed.get_secret("kept", None).unwrap();
    let before = calls.load(Ordering::SeqCst);

    // The newest audit row removed: the log is cut short.
    rusqlite::Connection::open(&path)
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
        calls.load(Ordering::SeqCst),
        before,
        "a call reached the provider"
    );
    // The provider was not changed: the secret is there, the other still deleted.
    let provider = open(&dir.path().join("provider.sorvault"), &provider_key);
    assert_eq!(
        provider.get_secret("kept", None).unwrap().value.expose(),
        b"a value"
    );
    assert!(provider.get_deleted_secret("gone").is_ok());
}
