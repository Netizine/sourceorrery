//! The lifecycle conformance suite against Secrets Manager, or an emulator
//! of it (LocalStack in CI, moto locally).
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
