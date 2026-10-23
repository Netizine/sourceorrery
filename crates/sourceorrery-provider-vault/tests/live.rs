//! The lifecycle conformance suite against a real Vault server.
//!
//! Runs when `SOURCEORRERY_VAULT_TEST_ADDR` names a server whose root (or
//! equivalent) token is in `VAULT_TOKEN`: `vault server -dev
//! -dev-root-token-id=root` locally, the `hashicorp/vault` container in CI.
//! Without it the test is skipped with a note. Each scenario gets a fresh
//! KV v2 mount, created here through `sys/mounts` with a version limit that
//! keeps the many-versions scenario intact (the provider never touches
//! mount configuration itself).

use std::sync::atomic::{AtomicUsize, Ordering};

use sourceorrery_conformance::lifecycle;
use sourceorrery_core::{RemoteVault, SecretClient};
use sourceorrery_provider::Blocking;
use sourceorrery_provider_vault::{Auth, Settings, Token, VaultClient};

const ADDR_ENV: &str = "SOURCEORRERY_VAULT_TEST_ADDR";

fn server() -> Option<(String, String)> {
    let address = std::env::var(ADDR_ENV).ok().filter(|a| !a.is_empty())?;
    let token = std::env::var("VAULT_TOKEN").unwrap_or_else(|_| "root".to_owned());
    Some((address, token))
}

/// Create a KV v2 mount `name` and return a connected, blocking client.
fn fresh_mount(address: &str, token: &str, name: &str) -> Box<dyn SecretClient> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let http = reqwest::Client::new();
        let response = http
            .post(format!("{address}/v1/sys/mounts/{name}"))
            .header("X-Vault-Token", token)
            .json(&serde_json::json!({
                "type": "kv",
                "options": { "version": "2" },
                "config": { "max_versions": 1000 }
            }))
            .send()
            .await
            .expect("mount request");
        assert!(
            response.status().is_success(),
            "mounting {name}: {}",
            response.status()
        );
        // The mount's version limit; the mount options above only set the
        // engine version.
        let response = http
            .post(format!("{address}/v1/{name}/config"))
            .header("X-Vault-Token", token)
            .json(&serde_json::json!({ "max_versions": 1000 }))
            .send()
            .await
            .expect("config request");
        assert!(response.status().is_success(), "{}", response.status());
    });
    drop(runtime);
    let settings = Settings::from_manifest(&RemoteVault::HashicorpVault {
        address: address.to_owned(),
        mount: name.to_owned(),
        namespace: None,
    })
    .unwrap();
    let auth = Auth::Token(Token::new(token));
    let vault_name = name.to_owned();
    Box::new(
        Blocking::connect(|| VaultClient::connect(&vault_name, &settings, auth)).expect("connect"),
    )
}

#[test]
fn vault_kv2_passes_the_lifecycle_scenarios() {
    let Some((address, token)) = server() else {
        eprintln!("skipped: set {ADDR_ENV} (and VAULT_TOKEN) to run against a Vault server");
        return;
    };
    let counter = AtomicUsize::new(0);
    let run = std::process::id();
    lifecycle::lifecycle(&mut |_| {
        let n = counter.fetch_add(1, Ordering::Relaxed);
        fresh_mount(&address, &token, &format!("conformance-{run}-{n}"))
    });
}

#[test]
fn a_mount_that_is_not_kv2_is_refused_and_a_missing_one_is_vault_not_found() {
    let Some((address, token)) = server() else {
        eprintln!("skipped: set {ADDR_ENV} (and VAULT_TOKEN) to run against a Vault server");
        return;
    };
    let settings = |mount: &str| {
        Settings::from_manifest(&RemoteVault::HashicorpVault {
            address: address.clone(),
            mount: mount.to_owned(),
            namespace: None,
        })
        .unwrap()
    };
    // `cubbyhole` is a generic engine every server has.
    let cubbyhole = settings("cubbyhole");
    let err = Blocking::connect(|| {
        VaultClient::connect("cubby", &cubbyhole, Auth::Token(Token::new(token.as_str())))
    })
    .expect_err("cubbyhole is not KV v2");
    assert_eq!(err.code(), "invalid_argument");
    assert!(err.to_string().contains("not a KV version 2"), "{err}");

    let missing = settings("no-such-mount");
    let err = Blocking::connect(|| {
        VaultClient::connect("nowhere", &missing, Auth::Token(Token::new(token.as_str())))
    })
    .expect_err("missing mount");
    assert_eq!(err.code(), "vault_not_found");

    // A token the server does not know is unauthenticated, not permission
    // denied.
    let secret = settings("secret");
    let outcome = Blocking::connect(|| {
        VaultClient::connect(
            "secret",
            &secret,
            Auth::Token(Token::new("hvs.not-a-real-token")),
        )
    })
    .and_then(|client| client.get_secret("anything", None).map(|_| ()));
    let err = outcome.expect_err("bad token");
    assert_eq!(err.code(), "unauthenticated", "{err}");
}
