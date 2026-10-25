//! The lifecycle conformance suite against Secrets Manager, or an emulator
//! of it (LocalStack in CI: `scripts/ci/localstack.sh`).
//!
//! Runs when `SOURCEORRERY_AWS_TEST_ENDPOINT` names the endpoint; the
//! credentials come from the environment as always (`AWS_ACCESS_KEY_ID`,
//! `AWS_SECRET_ACCESS_KEY`, any value for an emulator) and the region from
//! `AWS_REGION` (`us-east-1` otherwise). Each scenario gets a fresh prefix,
//! so the one account holds every scenario's secrets apart. Secrets Manager
//! keeps properties per secret, so the suite runs without
//! `PerVersionProperties` and the scenario that needs it is skipped; the
//! provider's own test below covers what happens instead. The suite runs a
//! second time through `Routed`: a vault in a temporary directory whose
//! connection, with the access key stored in it, keeps new secrets under a
//! fresh prefix.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use aws_sdk_secretsmanager::error::ProvideErrorMetadata;
use sourceorrery_conformance::lifecycle::{self, set};
use sourceorrery_core::{
    Capability, ConnectionSettings, Credentials, SecretBytes, SecretClient, SecretProperties,
    UpdateSecretProperties,
};
use sourceorrery_provider::{Blocking, ConnectionClient, Routed};
use sourceorrery_provider_aws::{AwsClient, Settings};
use sourceorrery_storage::{CreateVaultOptions, NoStore, SecretStorage, SqliteVault};

const ENDPOINT_ENV: &str = "SOURCEORRERY_AWS_TEST_ENDPOINT";

fn endpoint() -> Option<String> {
    std::env::var(ENDPOINT_ENV).ok().filter(|e| !e.is_empty())
}

fn region() -> String {
    std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_owned())
}

fn fresh(endpoint: &str, prefix: &str) -> Blocking<AwsClient> {
    let settings = Settings::from_connection(&ConnectionSettings::AwsSecretsManager {
        region: region(),
        prefix: Some(prefix.to_owned()),
        endpoint_url: Some(endpoint.to_owned()),
    })
    .unwrap();
    let vault = prefix.trim_end_matches('/').to_owned();
    Blocking::connect(|| AwsClient::connect(&vault, &settings, None)).expect("connect")
}

/// The SDK itself, for what a test does behind the provider's back.
fn sdk(endpoint: &str) -> (tokio::runtime::Runtime, aws_sdk_secretsmanager::Client) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let client = runtime.block_on(async {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region()))
            .endpoint_url(endpoint)
            .load()
            .await;
        aws_sdk_secretsmanager::Client::new(&config)
    });
    (runtime, client)
}

/// Whether the endpoint lists the versions of a secret scheduled for
/// deletion, as AWS does. LocalStack refuses (`InvalidRequestException`), so
/// the provider falls back to the secret's own creation time, which is not
/// the version's (LocalStack also gives versions whole seconds). The tests
/// then compare everything but the times, and say so in a workflow warning
/// (`cargo test -- --show-output` prints it).
fn lists_versions_of_deleted(endpoint: &str, id: &str, test: &str) -> bool {
    let (runtime, sdk) = sdk(endpoint);
    match runtime.block_on(sdk.list_secret_version_ids().secret_id(id).send()) {
        Ok(_) => true,
        Err(err) if err.code() == Some("InvalidRequestException") => {
            println!(
                "::warning title=AWS emulator divergence::{test}: the endpoint refuses \
                 ListSecretVersionIds for a secret scheduled for deletion, which AWS allows; \
                 version creation times were not compared"
            );
            false
        }
        Err(err) => panic!("listing the versions of deleted '{id}': {err:?}"),
    }
}

/// `deleted` describes the version `created` described, times included
/// unless the endpoint cannot list a deleted secret's versions.
fn assert_same_version(deleted: &SecretProperties, created: &SecretProperties, with_times: bool) {
    let mut deleted = deleted.clone();
    if !with_times {
        deleted.created_on = created.created_on;
        deleted.updated_on = created.updated_on;
    }
    assert_eq!(&deleted, created);
}

#[test]
fn secrets_manager_passes_the_lifecycle_scenarios_it_can_express() {
    let Some(endpoint) = endpoint() else {
        eprintln!("skipped: set {ENDPOINT_ENV} to run against Secrets Manager or an emulator");
        return;
    };
    let counter = AtomicUsize::new(0);
    let run = std::process::id();
    lifecycle::lifecycle_with(&[Capability::ClearableTimeWindow], &mut |_| {
        let n = counter.fetch_add(1, Ordering::Relaxed);
        Box::new(fresh(&endpoint, &format!("conformance-{run}-{n}/")))
    });
}

#[test]
fn routed_over_secrets_manager_passes_the_lifecycle_scenarios_it_can_express() {
    let Some(endpoint) = endpoint() else {
        eprintln!("skipped: set {ENDPOINT_ENV} to run against Secrets Manager or an emulator");
        return;
    };
    let var = |name: &str| std::env::var(name).unwrap_or_else(|_| "test".to_owned());
    let counter = AtomicUsize::new(0);
    let run = std::process::id();
    let mut dirs = Vec::new();
    lifecycle::lifecycle_with(&[Capability::ClearableTimeWindow], &mut |_| {
        let n = counter.fetch_add(1, Ordering::Relaxed);
        let dir = tempfile::tempdir().unwrap();
        let vault = SqliteVault::create(
            &dir.path().join("dev.sorvault"),
            "dev",
            CreateVaultOptions::default(),
            Arc::new(NoStore),
        )
        .unwrap()
        .vault;
        dirs.push(dir);
        let settings = ConnectionSettings::AwsSecretsManager {
            region: region(),
            prefix: Some(format!("routed-{run}-{n}/")),
            endpoint_url: Some(endpoint.clone()),
        };
        let stored = Credentials::AwsAccessKey {
            access_key_id: var("AWS_ACCESS_KEY_ID"),
            secret_access_key: SecretBytes::from(var("AWS_SECRET_ACCESS_KEY")),
        };
        let id = vault.add_connection(&settings, Some(&stored)).unwrap().id;
        let routed = Routed::with_opener(vault, |name, settings, credentials| {
            let settings = Settings::from_connection(settings)?;
            let client = Blocking::connect(|| AwsClient::connect(name, &settings, credentials))?;
            Ok(Box::new(client) as ConnectionClient)
        });
        Box::new(
            routed
                .storing_new_in(SecretStorage::Connection(id))
                .unwrap(),
        )
    });
}

#[test]
fn deleted_metadata_stays_stable_across_clock_ticks() {
    let Some(endpoint) = endpoint() else {
        eprintln!("skipped: set {ENDPOINT_ENV} to run against Secrets Manager or an emulator");
        return;
    };
    let prefix = format!("deleted-dates-{}/", std::process::id());
    let client = fresh(&endpoint, &prefix);
    let created = set(&client, "db", "value");
    let deleted = client.delete_secret("db").unwrap();
    let with_times = lists_versions_of_deleted(
        &endpoint,
        &format!("{prefix}db"),
        "deleted_metadata_stays_stable_across_clock_ticks",
    );

    // Read across second boundaries: metadata describes the stored version,
    // not the time of each request to the service or emulator.
    for _ in 0..2 {
        std::thread::sleep(std::time::Duration::from_millis(1_100));
        assert_eq!(client.get_deleted_secret("db").unwrap(), deleted);
        assert_eq!(
            client.list_deleted_secrets().unwrap(),
            vec![deleted.clone()]
        );
    }
    assert_same_version(&deleted.properties, &created, with_times);
    assert_eq!(deleted.deleted_on, time::OffsetDateTime::UNIX_EPOCH);
    let purge = deleted.scheduled_purge_on.unwrap();
    let now = time::OffsetDateTime::now_utc();
    assert!(purge > now + time::Duration::days(29));
    assert!(purge < now + time::Duration::days(31));
    client.purge_deleted_secret("db").unwrap();
}

#[test]
fn externally_scheduled_deletion_preserves_its_shorter_deadline() {
    let Some(endpoint) = endpoint() else {
        eprintln!("skipped: set {ENDPOINT_ENV} to run against Secrets Manager or an emulator");
        return;
    };
    let prefix = format!("external-delete-{}/", std::process::id());
    let client = fresh(&endpoint, &prefix);
    let created = set(&client, "db", "value");
    let (runtime, sdk) = sdk(&endpoint);
    let deadline = runtime.block_on(async {
        let deleted = sdk
            .delete_secret()
            .secret_id(format!("{prefix}db"))
            .recovery_window_in_days(7)
            .send()
            .await
            .unwrap();
        time::OffsetDateTime::from_unix_timestamp_nanos(deleted.deletion_date().unwrap().as_nanos())
            .unwrap()
    });
    let with_times = lists_versions_of_deleted(
        &endpoint,
        &format!("{prefix}db"),
        "externally_scheduled_deletion_preserves_its_shorter_deadline",
    );

    let deleted = client.get_deleted_secret("db").unwrap();
    assert_same_version(&deleted.properties, &created, with_times);
    assert_eq!(deleted.deleted_on, time::OffsetDateTime::UNIX_EPOCH);
    assert_eq!(deleted.scheduled_purge_on, Some(deadline));
    assert_eq!(client.list_deleted_secrets().unwrap(), vec![deleted]);
    client.purge_deleted_secret("db").unwrap();
}

#[test]
fn properties_apply_to_the_whole_secret() {
    let Some(endpoint) = endpoint() else {
        eprintln!("skipped: set {ENDPOINT_ENV} to run against Secrets Manager or an emulator");
        return;
    };
    let client = fresh(&endpoint, &format!("per-secret-{}/", std::process::id()));
    let v1 = set(&client, "api-key", "old");
    let v2 = set(&client, "api-key", "new");
    assert_ne!(v1.version, v2.version);
    assert_eq!(
        client.vault_name(),
        format!("per-secret-{}", std::process::id())
    );

    // Disabling the newest version disables the secret: no fallback.
    client
        .update_secret_properties(
            "api-key",
            None,
            UpdateSecretProperties {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        client.get_secret("api-key", None).unwrap_err().code(),
        "disabled"
    );
    assert_eq!(
        client
            .get_secret("api-key", Some(&v1.version))
            .unwrap_err()
            .code(),
        "disabled"
    );
    let versions = client
        .list_properties_of_secret_versions("api-key")
        .unwrap();
    assert_eq!(versions.len(), 2);
    assert!(versions.iter().all(|v| !v.enabled));

    // An older version cannot be updated on its own.
    let err = client
        .update_secret_properties(
            "api-key",
            Some(&v1.version),
            UpdateSecretProperties {
                enabled: Some(true),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert_eq!(err.code(), "unsupported");
    assert!(err.to_string().contains("per secret"), "{err}");
    assert_eq!(
        client
            .update_secret_properties(
                "api-key",
                Some("nope"),
                UpdateSecretProperties {
                    enabled: Some(true),
                    ..Default::default()
                },
            )
            .unwrap_err()
            .code(),
        "version_not_found"
    );

    // Re-enabling through the newest version brings every version back.
    client
        .update_secret_properties(
            "api-key",
            None,
            UpdateSecretProperties {
                enabled: Some(true),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        client
            .get_secret("api-key", Some(&v1.version))
            .unwrap()
            .value
            .expose(),
        b"old"
    );
    let descriptor = client.inner().descriptor();
    assert_eq!(descriptor.backend, "aws-secrets-manager");
    assert_eq!(descriptor.retention_days, 30);
}

#[test]
fn rotation_is_refused_before_anything_is_written() {
    let Some(endpoint) = endpoint() else {
        eprintln!("skipped: set {ENDPOINT_ENV} to run against Secrets Manager or an emulator");
        return;
    };
    let client = fresh(&endpoint, &format!("rotation-{}/", std::process::id()));
    set(&client, "api-key", "current");
    // Rotation needs a disabled candidate next to the current version, which
    // per-secret properties cannot hold: refused before anything is written.
    assert!(
        !client
            .capabilities()
            .contains(&Capability::PerVersionProperties)
    );
    let err = sourceorrery_core::rotation::issue(
        &client,
        "api-key",
        sourceorrery_core::SecretBytes::from("never-written"),
        sourceorrery_core::timestamp::now(),
    )
    .unwrap_err();
    assert_eq!(err.code(), "unsupported");
    assert!(err.to_string().contains("per secret"), "{err}");
    assert_eq!(
        client
            .list_properties_of_secret_versions("api-key")
            .unwrap()
            .len(),
        1
    );
}
