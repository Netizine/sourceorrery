//! The lifecycle conformance suite against Secrets Manager, or an emulator
//! of it (Moto in CI and locally).
//!
//! Runs when `SOURCEORRERY_AWS_TEST_ENDPOINT` names the endpoint; the
//! credentials come from the environment as always (`AWS_ACCESS_KEY_ID`,
//! `AWS_SECRET_ACCESS_KEY`, any value for an emulator) and the region from
//! `AWS_REGION` (`us-east-1` otherwise). Each scenario gets a fresh prefix,
//! so the one account holds every scenario's secrets apart. Secrets Manager
//! keeps properties per secret, so the suite runs without
//! `PerVersionProperties` and the scenario that needs it is skipped; the
//! provider's own test below covers what happens instead.

use std::sync::atomic::{AtomicUsize, Ordering};

use sourceorrery_conformance::lifecycle::{self, set};
use sourceorrery_core::{RemoteVault, SecretClient, UpdateSecretProperties};
use sourceorrery_provider::Blocking;
use sourceorrery_provider_aws::{AwsClient, Settings};

const ENDPOINT_ENV: &str = "SOURCEORRERY_AWS_TEST_ENDPOINT";

fn endpoint() -> Option<String> {
    std::env::var(ENDPOINT_ENV).ok().filter(|e| !e.is_empty())
}

fn region() -> String {
    std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_owned())
}

fn fresh(endpoint: &str, prefix: &str) -> Blocking<AwsClient> {
    let settings = Settings::from_manifest(&RemoteVault::AwsSecretsManager {
        region: region(),
        prefix: Some(prefix.to_owned()),
        endpoint_url: Some(endpoint.to_owned()),
    })
    .unwrap();
    let vault = prefix.trim_end_matches('/').to_owned();
    Blocking::connect(|| AwsClient::connect(&vault, &settings)).expect("connect")
}

#[test]
fn secrets_manager_passes_the_lifecycle_scenarios_it_can_express() {
    let Some(endpoint) = endpoint() else {
        eprintln!("skipped: set {ENDPOINT_ENV} to run against Secrets Manager or an emulator");
        return;
    };
    let counter = AtomicUsize::new(0);
    let run = std::process::id();
    lifecycle::lifecycle_with(&[], &mut |_| {
        let n = counter.fetch_add(1, Ordering::Relaxed);
        Box::new(fresh(&endpoint, &format!("conformance-{run}-{n}/")))
    });
}

#[test]
fn deleted_metadata_stays_stable_across_clock_ticks() {
    let Some(endpoint) = endpoint() else {
        eprintln!("skipped: set {ENDPOINT_ENV} to run against Secrets Manager or an emulator");
        return;
    };
    let client = fresh(&endpoint, &format!("deleted-dates-{}/", std::process::id()));
    let created = set(&client, "db", "value");
    let deleted = client.delete_secret("db").unwrap();

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
    assert_eq!(deleted.properties, created);
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
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let deadline = runtime.block_on(async {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region()))
            .endpoint_url(&endpoint)
            .load()
            .await;
        let deleted = aws_sdk_secretsmanager::Client::new(&config)
            .delete_secret()
            .secret_id(format!("{prefix}db"))
            .recovery_window_in_days(7)
            .send()
            .await
            .unwrap();
        time::OffsetDateTime::from_unix_timestamp_nanos(deleted.deletion_date().unwrap().as_nanos())
            .unwrap()
    });

    let deleted = client.get_deleted_secret("db").unwrap();
    assert_eq!(deleted.properties, created);
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
    assert_eq!(
        client.capabilities(),
        &[] as &[sourceorrery_core::Capability]
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
