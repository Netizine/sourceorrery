//! The adapters pass every operation and every error through unchanged.

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;
use sourceorrery_core::{
    AsyncSecretClient, AuditEvent, AuditQuery, DeletedSecret, ListOptions, Page, RecoveryLevel,
    Result, Secret, SecretBytes, SecretClient, SecretError, SecretProperties, SecretReference,
    SetSecretOptions, UpdateSecretProperties,
};
use time::OffsetDateTime;

use crate::{AsyncLocal, Blocking};

/// Every stable error code, with a constructor for its variant.
const CODES: &[&str] = &[
    "not_found",
    "version_not_found",
    "deleted",
    "deleted_conflict",
    "not_deleted",
    "disabled",
    "not_yet_valid",
    "expired",
    "invalid_name",
    "invalid_argument",
    "permission_denied",
    "locked",
    "vault_not_found",
    "vault_exists",
    "manifest",
    "crypto",
    "storage",
    "io",
    "unsupported",
    "migration_required",
    "backup_passphrase",
    "backup_format",
    "vault_mismatch",
    "unauthenticated",
    "provider_unavailable",
];

fn error_for(code: &str) -> SecretError {
    let name = "k".to_owned();
    let version = "v".to_owned();
    match code {
        "not_found" => SecretError::NotFound { name },
        "version_not_found" => SecretError::VersionNotFound { name, version },
        "deleted" => SecretError::Deleted { name },
        "deleted_conflict" => SecretError::DeletedConflict { name },
        "not_deleted" => SecretError::NotDeleted { name },
        "disabled" => SecretError::Disabled { name, version },
        "not_yet_valid" => SecretError::NotYetValid {
            name,
            version,
            not_before: "t".to_owned(),
        },
        "expired" => SecretError::Expired {
            name,
            version,
            expires_on: "t".to_owned(),
        },
        "invalid_name" => SecretError::InvalidName {
            name,
            reason: "r".to_owned(),
        },
        "invalid_argument" => SecretError::InvalidArgument("a".to_owned()),
        "permission_denied" => SecretError::PermissionDenied("p".to_owned()),
        "locked" => SecretError::Locked("l".to_owned()),
        "vault_not_found" => SecretError::VaultNotFound { name },
        "vault_exists" => SecretError::VaultExists { name },
        "manifest" => SecretError::Manifest("m".to_owned()),
        "crypto" => SecretError::Crypto("c".to_owned()),
        "storage" => SecretError::Storage("s".to_owned()),
        "io" => SecretError::Io("i".to_owned()),
        "unsupported" => SecretError::Unsupported("u".to_owned()),
        "migration_required" => SecretError::MigrationRequired { name, schema: 1 },
        "backup_passphrase" => SecretError::BackupPassphrase,
        "backup_format" => SecretError::BackupFormat { version: 9 },
        "vault_mismatch" => SecretError::VaultMismatch {
            requested: name,
            found: version,
        },
        "unauthenticated" => SecretError::Unauthenticated {
            provider: name,
            reason: version,
        },
        "provider_unavailable" => SecretError::ProviderUnavailable {
            provider: name,
            reason: version,
        },
        other => panic!("no constructor for code {other}"),
    }
}

#[test]
fn every_code_has_a_constructor() {
    for code in CODES {
        assert_eq!(error_for(code).code(), *code);
    }
}

fn props(name: &str) -> SecretProperties {
    let now = OffsetDateTime::UNIX_EPOCH;
    SecretProperties {
        vault: "scripted".to_owned(),
        name: name.to_owned(),
        version: "0123".to_owned(),
        enabled: true,
        content_type: None,
        tags: BTreeMap::new(),
        not_before: None,
        expires_on: None,
        created_on: now,
        updated_on: now,
        recovery_level: RecoveryLevel::Recoverable,
    }
}

fn deleted(name: &str) -> DeletedSecret {
    DeletedSecret {
        properties: props(name),
        deleted_on: OffsetDateTime::UNIX_EPOCH,
        scheduled_purge_on: None,
        recovery_id: format!("sourceorrery://scripted/deletedsecrets/{name}"),
    }
}

/// A backend that records which method was called and answers every call
/// the same way: with the scripted error, or with a fixed success.
struct Scripted {
    error: Option<&'static str>,
    calls: Mutex<Vec<&'static str>>,
}

impl Scripted {
    fn succeeding() -> Self {
        Self {
            error: None,
            calls: Mutex::new(Vec::new()),
        }
    }

    fn failing(code: &'static str) -> Self {
        Self {
            error: Some(code),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn answer<T>(&self, method: &'static str, ok: impl FnOnce() -> T) -> Result<T> {
        self.calls.lock().unwrap().push(method);
        match self.error {
            Some(code) => Err(error_for(code)),
            None => Ok(ok()),
        }
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }
}

impl Scripted {
    const VAULT: &'static str = "scripted";
}

impl SecretClient for Scripted {
    fn vault_name(&self) -> &str {
        Self::VAULT
    }
    fn set_secret(
        &self,
        name: &str,
        _: SecretBytes,
        _: SetSecretOptions,
    ) -> Result<SecretProperties> {
        self.answer("set_secret", || props(name))
    }
    fn get_secret(&self, name: &str, _: Option<&str>) -> Result<Secret> {
        self.answer("get_secret", || Secret {
            properties: props(name),
            value: SecretBytes::from("value"),
        })
    }
    fn get_secret_properties(&self, name: &str, _: Option<&str>) -> Result<SecretProperties> {
        self.answer("get_secret_properties", || props(name))
    }
    fn list_properties_of_secrets(&self) -> Result<Vec<SecretProperties>> {
        self.answer("list_properties_of_secrets", || vec![props("a")])
    }
    fn list_properties_of_secrets_page(&self, _: ListOptions) -> Result<Page<SecretProperties>> {
        self.answer("list_properties_of_secrets_page", || Page {
            items: vec![props("a")],
            continuation: None,
        })
    }
    fn list_properties_of_secret_versions(&self, name: &str) -> Result<Vec<SecretProperties>> {
        self.answer("list_properties_of_secret_versions", || vec![props(name)])
    }
    fn update_secret_properties(
        &self,
        name: &str,
        _: Option<&str>,
        _: UpdateSecretProperties,
    ) -> Result<SecretProperties> {
        self.answer("update_secret_properties", || props(name))
    }
    fn delete_secret(&self, name: &str) -> Result<DeletedSecret> {
        self.answer("delete_secret", || deleted(name))
    }
    fn get_deleted_secret(&self, name: &str) -> Result<DeletedSecret> {
        self.answer("get_deleted_secret", || deleted(name))
    }
    fn list_deleted_secrets(&self) -> Result<Vec<DeletedSecret>> {
        self.answer("list_deleted_secrets", || vec![deleted("a")])
    }
    fn list_deleted_secrets_page(&self, _: ListOptions) -> Result<Page<DeletedSecret>> {
        self.answer("list_deleted_secrets_page", || Page {
            items: vec![deleted("a")],
            continuation: None,
        })
    }
    fn recover_deleted_secret(&self, name: &str) -> Result<SecretProperties> {
        self.answer("recover_deleted_secret", || props(name))
    }
    fn purge_deleted_secret(&self, _: &str) -> Result<()> {
        self.answer("purge_deleted_secret", || ())
    }
    fn audit_events(&self, _: AuditQuery) -> Result<Vec<AuditEvent>> {
        self.answer("audit_events", Vec::new)
    }
    fn resolve(&self, reference: &SecretReference) -> Result<Secret> {
        self.answer("resolve", || Secret {
            properties: props(&reference.name),
            value: SecretBytes::from("value"),
        })
    }
}

/// The same backend in its async shape.
struct AsyncScripted(Scripted);

#[async_trait]
impl AsyncSecretClient for AsyncScripted {
    fn vault_name(&self) -> &str {
        self.0.vault_name()
    }
    async fn set_secret(
        &self,
        name: &str,
        value: SecretBytes,
        options: SetSecretOptions,
    ) -> Result<SecretProperties> {
        self.0.set_secret(name, value, options)
    }
    async fn get_secret(&self, name: &str, version: Option<&str>) -> Result<Secret> {
        self.0.get_secret(name, version)
    }
    async fn get_secret_properties(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<SecretProperties> {
        self.0.get_secret_properties(name, version)
    }
    async fn list_properties_of_secrets(&self) -> Result<Vec<SecretProperties>> {
        self.0.list_properties_of_secrets()
    }
    async fn list_properties_of_secrets_page(
        &self,
        options: ListOptions,
    ) -> Result<Page<SecretProperties>> {
        self.0.list_properties_of_secrets_page(options)
    }
    async fn list_properties_of_secret_versions(
        &self,
        name: &str,
    ) -> Result<Vec<SecretProperties>> {
        self.0.list_properties_of_secret_versions(name)
    }
    async fn update_secret_properties(
        &self,
        name: &str,
        version: Option<&str>,
        update: UpdateSecretProperties,
    ) -> Result<SecretProperties> {
        self.0.update_secret_properties(name, version, update)
    }
    async fn delete_secret(&self, name: &str) -> Result<DeletedSecret> {
        self.0.delete_secret(name)
    }
    async fn get_deleted_secret(&self, name: &str) -> Result<DeletedSecret> {
        self.0.get_deleted_secret(name)
    }
    async fn list_deleted_secrets(&self) -> Result<Vec<DeletedSecret>> {
        self.0.list_deleted_secrets()
    }
    async fn list_deleted_secrets_page(&self, options: ListOptions) -> Result<Page<DeletedSecret>> {
        self.0.list_deleted_secrets_page(options)
    }
    async fn recover_deleted_secret(&self, name: &str) -> Result<SecretProperties> {
        self.0.recover_deleted_secret(name)
    }
    async fn purge_deleted_secret(&self, name: &str) -> Result<()> {
        self.0.purge_deleted_secret(name)
    }
    async fn audit_events(&self, query: AuditQuery) -> Result<Vec<AuditEvent>> {
        self.0.audit_events(query)
    }
    async fn resolve(&self, reference: &SecretReference) -> Result<Secret> {
        self.0.resolve(reference)
    }
}

/// Every operation of the contract, in the order the forwarding tests
/// expect to see it recorded.
const OPERATIONS: &[&str] = &[
    "set_secret",
    "get_secret",
    "get_secret_properties",
    "list_properties_of_secrets",
    "list_properties_of_secrets_page",
    "list_properties_of_secret_versions",
    "update_secret_properties",
    "delete_secret",
    "get_deleted_secret",
    "list_deleted_secrets",
    "list_deleted_secrets_page",
    "recover_deleted_secret",
    "purge_deleted_secret",
    "audit_events",
    "resolve",
];

fn reference() -> SecretReference {
    SecretReference::parse("sourceorrery://scripted/k").unwrap()
}

fn code<T>(result: Result<T>) -> Option<&'static str> {
    result.err().map(|e| e.code())
}

/// Call every operation through the synchronous shape; the error code each
/// one returned, in [`OPERATIONS`] order.
fn codes_sync(client: &dyn SecretClient) -> Vec<Option<&'static str>> {
    vec![
        code(client.set_secret("k", SecretBytes::from("v"), SetSecretOptions::default())),
        code(client.get_secret("k", None)),
        code(client.get_secret_properties("k", Some("0123"))),
        code(client.list_properties_of_secrets()),
        code(client.list_properties_of_secrets_page(ListOptions::first(5))),
        code(client.list_properties_of_secret_versions("k")),
        code(client.update_secret_properties(
            "k",
            None,
            UpdateSecretProperties {
                enabled: Some(false),
                ..Default::default()
            },
        )),
        code(client.delete_secret("k")),
        code(client.get_deleted_secret("k")),
        code(client.list_deleted_secrets()),
        code(client.list_deleted_secrets_page(ListOptions::first(5))),
        code(client.recover_deleted_secret("k")),
        code(client.purge_deleted_secret("k")),
        code(client.audit_events(AuditQuery::default())),
        code(client.resolve(&reference())),
    ]
}

/// The same through the asynchronous shape.
async fn codes_async(client: &dyn AsyncSecretClient) -> Vec<Option<&'static str>> {
    vec![
        code(
            client
                .set_secret("k", SecretBytes::from("v"), SetSecretOptions::default())
                .await,
        ),
        code(client.get_secret("k", None).await),
        code(client.get_secret_properties("k", Some("0123")).await),
        code(client.list_properties_of_secrets().await),
        code(
            client
                .list_properties_of_secrets_page(ListOptions::first(5))
                .await,
        ),
        code(client.list_properties_of_secret_versions("k").await),
        code(
            client
                .update_secret_properties(
                    "k",
                    None,
                    UpdateSecretProperties {
                        enabled: Some(false),
                        ..Default::default()
                    },
                )
                .await,
        ),
        code(client.delete_secret("k").await),
        code(client.get_deleted_secret("k").await),
        code(client.list_deleted_secrets().await),
        code(
            client
                .list_deleted_secrets_page(ListOptions::first(5))
                .await,
        ),
        code(client.recover_deleted_secret("k").await),
        code(client.purge_deleted_secret("k").await),
        code(client.audit_events(AuditQuery::default()).await),
        code(client.resolve(&reference()).await),
    ]
}

#[test]
fn blocking_preserves_every_error_code() {
    for expected in CODES {
        let client = Blocking::new(AsyncScripted(Scripted::failing(expected))).unwrap();
        for (op, got) in OPERATIONS.iter().zip(codes_sync(&client)) {
            assert_eq!(got, Some(*expected), "{op} through Blocking");
        }
    }
}

#[tokio::test]
async fn async_local_preserves_every_error_code() {
    for expected in CODES {
        let client = AsyncLocal::new(Scripted::failing(expected));
        for (op, got) in OPERATIONS.iter().zip(codes_async(&client).await) {
            assert_eq!(got, Some(*expected), "{op} through AsyncLocal");
        }
    }
}

#[test]
fn blocking_forwards_each_operation_to_the_async_client() {
    let client = Blocking::new(AsyncScripted(Scripted::succeeding())).unwrap();
    assert_eq!(client.vault_name(), "scripted");
    assert!(codes_sync(&client).iter().all(Option::is_none));
    // The page methods and `resolve` reach the client's own implementations,
    // not the trait defaults built on the full listing or `get_secret`.
    assert_eq!(client.inner().0.calls(), OPERATIONS);
    let got = client.get_secret("k", None).unwrap();
    assert_eq!(got.value.expose(), b"value");
    assert_eq!(got.properties.name, "k");
}

#[tokio::test]
async fn async_local_forwards_each_operation_to_the_sync_client() {
    let client = AsyncLocal::new(Scripted::succeeding());
    assert_eq!(client.vault_name(), "scripted");
    assert!(codes_async(&client).await.iter().all(Option::is_none));
    assert_eq!(client.inner().calls(), OPERATIONS);
    let got = client.get_secret("k", None).await.unwrap();
    assert_eq!(got.value.expose(), b"value");
    // Clones share the client.
    let twin = client.clone();
    twin.purge_deleted_secret("k").await.unwrap();
    assert_eq!(client.inner().calls().len(), OPERATIONS.len() + 2);
}

#[test]
fn the_two_adapters_compose_in_both_directions() {
    // Sync → async → sync: what the conformance suite runs on the local
    // vault to prove the pair before any provider exists.
    let client = Blocking::new(AsyncLocal::new(Scripted::failing("locked"))).unwrap();
    assert!(codes_sync(&client).iter().all(|c| *c == Some("locked")));
    assert_eq!(client.inner().inner().calls(), OPERATIONS);
}

#[test]
fn blocking_can_borrow_an_application_runtime() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let client = Blocking::with_handle(
        AsyncScripted(Scripted::succeeding()),
        runtime.handle().clone(),
    );
    assert_eq!(client.get_secret("k", None).unwrap().properties.name, "k");
    let dbg = format!("{client:?}");
    assert!(dbg.contains("scripted") && dbg.contains("shared"), "{dbg}");
    let owned = Blocking::new(AsyncScripted(Scripted::succeeding())).unwrap();
    assert!(format!("{owned:?}").contains("owned"));
    assert!(format!("{:?}", AsyncLocal::new(Scripted::succeeding())).contains("scripted"));
    let _inner: AsyncScripted = owned.into_inner();
}
