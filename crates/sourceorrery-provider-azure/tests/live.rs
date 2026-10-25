//! The lifecycle conformance suite against an Azure Key Vault emulator
//! (LocalStack for Azure in CI: `scripts/ci/localstack.sh`).
//!
//! Runs when `SOURCEORRERY_AZURE_TEST_ENDPOINT` names the emulator's
//! management and sign-in endpoint (`https://azure.localhost.localstack.cloud:4566`).
//! The identity comes from the environment as always: `AZURE_TENANT_ID`,
//! `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` (any values the emulator
//! accepts) with `AZURE_AUTHORITY_HOST` set to the same endpoint. Key Vault
//! has no prefixes, so every scenario gets a vault of its own, created
//! through the emulator's Resource Manager; the suite does not run against
//! Azure itself. The suite runs a second time through `Routed`: a vault in
//! a temporary directory whose connection, with the service principal
//! stored in it, keeps new secrets in such a Key Vault.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use sourceorrery_conformance::lifecycle::{self, set};
use sourceorrery_core::{
    Capability, ConnectionSettings, Credentials, SecretBytes, SecretClient, SetSecretOptions,
    UpdateSecretProperties, timestamp,
};
use sourceorrery_provider::{Blocking, ConnectionClient, Routed};
use sourceorrery_provider_azure::{AzureClient, Settings};
use sourceorrery_storage::{CreateVaultOptions, NoStore, SecretStorage, SqliteVault};
use time::Duration;

const ENDPOINT_ENV: &str = "SOURCEORRERY_AZURE_TEST_ENDPOINT";
/// The emulator's one subscription.
const SUBSCRIPTION: &str = "00000000-0000-0000-0000-000000000000";
const RESOURCE_GROUP: &str = "rg-sourceorrery-tests";

fn endpoint() -> Option<String> {
    sourceorrery_conformance::live::target(ENDPOINT_ENV)
}

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name} for the Azure live tests"))
}

/// A management token for the test identity, from the emulator's authority.
fn management_token(http: &reqwest::blocking::Client, endpoint: &str) -> String {
    let response: serde_json::Value = http
        .post(format!(
            "{endpoint}/{}/oauth2/v2.0/token",
            var("AZURE_TENANT_ID")
        ))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", var("AZURE_CLIENT_ID").as_str()),
            ("client_secret", var("AZURE_CLIENT_SECRET").as_str()),
            ("scope", "https://management.azure.com/.default"),
        ])
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .expect("token from the emulator")
        .json()
        .expect("token response");
    response["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned()
}

/// A new, empty vault with a 7-day retention; its URL.
fn new_vault(endpoint: &str, name: &str) -> String {
    let http = reqwest::blocking::Client::new();
    let token = management_token(&http, endpoint);
    let group = format!("{endpoint}/subscriptions/{SUBSCRIPTION}/resourcegroups/{RESOURCE_GROUP}");
    http.put(format!("{group}?api-version=2021-04-01"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "location": "westeurope" }))
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .expect("resource group");
    let vault: serde_json::Value = http
        .put(format!(
            "{group}/providers/Microsoft.KeyVault/vaults/{name}?api-version=2023-07-01"
        ))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "location": "westeurope",
            "properties": {
                "tenantId": var("AZURE_TENANT_ID"),
                "sku": { "family": "A", "name": "standard" },
                "accessPolicies": [],
                "enableRbacAuthorization": true,
                "enableSoftDelete": true,
                "softDeleteRetentionInDays": 7,
            },
        }))
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .expect("vault")
        .json()
        .expect("vault response");
    vault["properties"]["vaultUri"]
        .as_str()
        .expect("vaultUri")
        .to_owned()
}

static VAULTS: AtomicUsize = AtomicUsize::new(0);

/// A client on a vault of its own. Vault names are 3–24 letters, digits
/// and hyphens, starting with a letter.
fn fresh(endpoint: &str) -> Blocking<AzureClient> {
    let n = VAULTS.fetch_add(1, Ordering::Relaxed);
    let name = format!("so{}-{n}", std::process::id());
    let settings = Settings {
        vault_url: new_vault(endpoint, &name),
    };
    Blocking::connect(|| AzureClient::connect(&name, &settings, None)).expect("connect")
}

#[test]
fn key_vault_passes_the_lifecycle_scenarios_it_can_express() {
    let Some(endpoint) = endpoint() else {
        eprintln!("skipped: set {ENDPOINT_ENV} to run against an Azure Key Vault emulator");
        return;
    };
    lifecycle::lifecycle_with(&[Capability::PerVersionProperties], &mut |_| {
        Box::new(fresh(&endpoint))
    });
}

#[test]
fn routed_over_key_vault_passes_the_lifecycle_scenarios_it_can_express() {
    let Some(endpoint) = endpoint() else {
        eprintln!("skipped: set {ENDPOINT_ENV} to run against an Azure Key Vault emulator");
        return;
    };
    let mut dirs = Vec::new();
    lifecycle::lifecycle_with(&[Capability::PerVersionProperties], &mut |_| {
        let n = VAULTS.fetch_add(1, Ordering::Relaxed);
        let vault_url = new_vault(&endpoint, &format!("sr{}-{n}", std::process::id()));
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
        let stored = Credentials::AzureClientSecret {
            tenant_id: var("AZURE_TENANT_ID"),
            client_id: var("AZURE_CLIENT_ID"),
            client_secret: SecretBytes::from(var("AZURE_CLIENT_SECRET")),
        };
        let id = vault
            .add_connection(
                &ConnectionSettings::AzureKeyVault { vault_url },
                Some(&stored),
            )
            .unwrap()
            .id;
        let routed = Routed::with_opener(vault, |name, settings, credentials| {
            let settings = Settings::from_connection(settings)?;
            let client = Blocking::connect(|| AzureClient::connect(name, &settings, credentials))?;
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
fn a_time_window_can_be_replaced_but_not_removed() {
    let Some(endpoint) = endpoint() else {
        eprintln!("skipped: set {ENDPOINT_ENV} to run against an Azure Key Vault emulator");
        return;
    };
    let client = fresh(&endpoint);
    let now = timestamp::now();
    client
        .set_secret(
            "token",
            SecretBytes::from("x"),
            SetSecretOptions {
                expires_on: Some(now - Duration::minutes(1)),
                ..SetSecretOptions::default()
            },
        )
        .unwrap();
    assert_eq!(
        client.get_secret("token", None).unwrap_err().code(),
        "expired"
    );
    let clear = UpdateSecretProperties {
        expires_on: Some(None),
        ..UpdateSecretProperties::default()
    };
    let err = client
        .update_secret_properties("token", None, clear.clone())
        .unwrap_err();
    assert_eq!(err.code(), "unsupported");
    assert!(err.to_string().contains("new version"), "{err}");
    // A later expiry replaces the old one and the version reads again.
    let later = now + Duration::hours(1);
    let updated = client
        .update_secret_properties(
            "token",
            None,
            UpdateSecretProperties {
                expires_on: Some(Some(later)),
                ..UpdateSecretProperties::default()
            },
        )
        .unwrap();
    assert_eq!(
        updated.expires_on.map(time::OffsetDateTime::unix_timestamp),
        Some(later.unix_timestamp())
    );
    assert!(client.get_secret("token", None).is_ok());
    // Removing what is not there changes nothing and is not refused.
    set(&client, "open", "y");
    assert!(client.update_secret_properties("open", None, clear).is_ok());
}

#[test]
fn values_and_tags_follow_key_vaults_limits() {
    let Some(endpoint) = endpoint() else {
        eprintln!("skipped: set {ENDPOINT_ENV} to run against an Azure Key Vault emulator");
        return;
    };
    let client = fresh(&endpoint);
    // Bytes that are not UTF-8 go in as base64 and come back unchanged.
    let binary = vec![0xff, 0x00, 0xfe, b'a', 0x80];
    let written = client
        .set_secret(
            "binary",
            SecretBytes::new(binary.clone()),
            SetSecretOptions::default(),
        )
        .unwrap();
    assert!(
        written.tags.is_empty(),
        "reserved tags stay hidden: {:?}",
        written.tags
    );
    assert_eq!(
        client.get_secret("binary", None).unwrap().value.expose(),
        binary.as_slice()
    );

    let too_many = SetSecretOptions {
        tags: (0..13).map(|i| (format!("k{i}"), "v".to_owned())).collect(),
        ..SetSecretOptions::default()
    };
    let err = client
        .set_secret("tagged", SecretBytes::from("x"), too_many)
        .unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    let err = client
        .set_secret(
            "big",
            SecretBytes::new(vec![b'a'; 25 * 1024 + 1]),
            SetSecretOptions::default(),
        )
        .unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
}

#[test]
fn deletion_keeps_key_vaults_dates_and_retention() {
    let Some(endpoint) = endpoint() else {
        eprintln!("skipped: set {ENDPOINT_ENV} to run against an Azure Key Vault emulator");
        return;
    };
    let client = fresh(&endpoint);
    let created = set(&client, "db", "value");
    let deleted = client.delete_secret("db").unwrap();
    assert_eq!(deleted.properties, created);
    let deleted_on = deleted.deleted_on;
    assert!(
        (timestamp::now() - deleted_on).abs() < Duration::minutes(5),
        "{deleted_on}"
    );
    let purge = deleted.scheduled_purge_on.expect("a purge date");
    assert_eq!(
        (purge - deleted_on).whole_days(),
        7,
        "the vault's retention"
    );
    assert_eq!(client.get_deleted_secret("db").unwrap(), deleted);
    assert_eq!(client.list_deleted_secrets().unwrap(), vec![deleted]);
    client.purge_deleted_secret("db").unwrap();
    assert_eq!(
        client.get_deleted_secret("db").unwrap_err().code(),
        "not_found"
    );
}
