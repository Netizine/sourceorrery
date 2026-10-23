//! Status and body mapping against recorded responses, served by a tiny
//! in-process HTTP server so no network or Vault binary is needed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sourceorrery_core::{RemoteVault, SecretClient};
use sourceorrery_provider::Blocking;
use sourceorrery_provider_vault::{Auth, Settings, Token, VaultClient};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A canned reply.
#[derive(Clone)]
struct Canned {
    status: u16,
    body: String,
}

fn ok(body: &str) -> Canned {
    Canned {
        status: 200,
        body: body.to_owned(),
    }
}

fn status(code: u16, body: &str) -> Canned {
    Canned {
        status: code,
        body: body.to_owned(),
    }
}

const MOUNT_OK: &str = r#"{"data":{"type":"kv","accessor":"kv_abc","options":{"version":"2"}}}"#;

/// Serve `routes` ("METHOD /v1/path" → reply) on a random port; requests are
/// recorded (method, path, body) for the test to inspect.
struct Server {
    address: String,
    seen: Arc<Mutex<Vec<(String, String, String)>>>,
    _runtime: tokio::runtime::Runtime,
}

fn serve(routes: HashMap<&'static str, Canned>) -> Server {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let seen: Arc<Mutex<Vec<(String, String, String)>>> = Arc::default();
    let listener = runtime.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let recorded = Arc::clone(&seen);
    runtime.spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let routes = routes.clone();
            let recorded = Arc::clone(&recorded);
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let Ok(n) = socket.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    buffer.extend_from_slice(&chunk[..n]);
                    if let Some(end) = find(&buffer, b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buffer[..end]).into_owned();
                        let length = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length: "))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if buffer.len() >= end + 4 + length {
                            let body =
                                String::from_utf8_lossy(&buffer[end + 4..end + 4 + length])
                                    .into_owned();
                            let mut words = head.split_whitespace();
                            let method = words.next().unwrap_or_default().to_owned();
                            let path = words.next().unwrap_or_default().to_owned();
                            let key = format!("{method} {path}");
                            recorded.lock().unwrap().push((method, path, body));
                            let reply = routes
                                .get(key.as_str())
                                .cloned()
                                .unwrap_or_else(|| status(404, r#"{"errors":[]}"#));
                            let response = format!(
                                "HTTP/1.1 {} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                                reply.status,
                                reply.body.len(),
                                reply.body
                            );
                            let _ = socket.write_all(response.as_bytes()).await;
                            let _ = socket.shutdown().await;
                            return;
                        }
                    }
                }
            });
        }
    });
    Server {
        address,
        seen,
        _runtime: runtime,
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn connect(server: &Server, token: &str) -> sourceorrery_core::Result<Blocking<VaultClient>> {
    let settings = Settings::from_manifest(&RemoteVault::HashicorpVault {
        address: server.address.clone(),
        mount: "secret".to_owned(),
        namespace: Some("team".to_owned()),
    })
    .unwrap();
    let auth = Auth::Token(Token::new(token));
    Blocking::connect(|| VaultClient::connect("prod", &settings, auth))
}

#[test]
fn statuses_map_to_codes_and_bodies_stay_out_of_messages() {
    const CANARY: &str = "hvs.CANARY-TOKEN-THAT-MUST-NOT-LEAK";
    let routes = HashMap::from([
        ("GET /v1/sys/internal/ui/mounts/secret", ok(MOUNT_OK)),
        // Metadata of a secret with one live version.
        (
            "GET /v1/secret/metadata/db",
            ok(
                r#"{"data":{"current_version":1,"custom_metadata":null,"versions":{"1":{"created_time":"2026-10-23T10:00:00Z","deletion_time":"","destroyed":false}}}}"#,
            ),
        ),
        // Its value: a 500 → provider_unavailable.
        (
            "GET /v1/secret/data/db?version=1",
            status(500, r#"{"errors":["internal failure CANARY-BODY"]}"#),
        ),
        // Forbidden, but the token is valid → permission_denied.
        (
            "GET /v1/secret/metadata/locked",
            status(
                403,
                r#"{"errors":["1 error occurred:\n\t* permission denied\n\n"]}"#,
            ),
        ),
        (
            "GET /v1/auth/token/lookup-self",
            ok(r#"{"data":{"id":"x"}}"#),
        ),
        // A 400 on write → invalid_argument with Vault's diagnostic.
        ("GET /v1/secret/metadata/toolong", status(404, "")),
        (
            "POST /v1/secret/data/toolong",
            status(
                400,
                r#"{"errors":["custom_metadata validation failed: length of value too long"]}"#,
            ),
        ),
    ]);
    let server = serve(routes);
    let client = connect(&server, CANARY).unwrap();
    assert_eq!(client.vault_name(), "prod");
    let descriptor = client.inner().descriptor();
    assert_eq!(descriptor.id, "kv_abc");
    assert_eq!(descriptor.backend, "hashicorp-vault");

    let err = client.get_secret("db", None).unwrap_err();
    assert_eq!(err.code(), "provider_unavailable");
    assert!(err.is_transient());
    assert!(err.to_string().contains("500"), "{err}");
    assert!(err.to_string().contains("internal failure"), "{err}");

    let err = client.get_secret("locked", None).unwrap_err();
    assert_eq!(err.code(), "permission_denied");

    let err = client.get_secret("missing", None).unwrap_err();
    assert_eq!(err.code(), "not_found");

    let err = client
        .set_secret(
            "toolong",
            sourceorrery_core::SecretBytes::from("v"),
            sourceorrery_core::SetSecretOptions::default(),
        )
        .unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    assert!(err.to_string().contains("custom_metadata"), "{err}");

    // The Debug output of the client and no error carries the token.
    assert!(!format!("{client:?}").contains(CANARY));
    assert!(!err.to_string().contains(CANARY));

    // Every request carried the namespace and the token header, and the
    // write sent the value in `data`.
    let seen = server.seen.lock().unwrap();
    let write = seen
        .iter()
        .find(|(m, p, _)| m == "POST" && p == "/v1/secret/data/toolong")
        .expect("the write was sent");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&write.2).unwrap()["data"]["value"],
        "v"
    );
}

#[test]
fn an_unknown_token_is_unauthenticated_and_a_wrong_engine_is_refused() {
    let routes = HashMap::from([
        ("GET /v1/sys/internal/ui/mounts/secret", ok(MOUNT_OK)),
        (
            "GET /v1/secret/metadata/db",
            status(403, r#"{"errors":["permission denied"]}"#),
        ),
        (
            "GET /v1/auth/token/lookup-self",
            status(403, r#"{"errors":["permission denied"]}"#),
        ),
    ]);
    let server = serve(routes);
    let client = connect(&server, "hvs.expired").unwrap();
    let err = client.get_secret("db", None).unwrap_err();
    assert_eq!(err.code(), "unauthenticated", "{err}");

    let routes = HashMap::from([(
        "GET /v1/sys/internal/ui/mounts/secret",
        ok(r#"{"data":{"type":"kv","accessor":"kv_v1","options":{"version":"1"}}}"#),
    )]);
    let server = serve(routes);
    let err = connect(&server, "root").expect_err("KV v1 is refused");
    assert_eq!(err.code(), "invalid_argument");
    assert!(err.to_string().contains("version 1"), "{err}");

    let routes = HashMap::from([(
        "GET /v1/sys/internal/ui/mounts/secret",
        ok(r#"{"data":{"type":"transit","accessor":"t","options":null}}"#),
    )]);
    let server = serve(routes);
    let err = connect(&server, "root").expect_err("transit is refused");
    assert!(err.to_string().contains("transit"), "{err}");
}

#[test]
fn an_unreachable_server_is_provider_unavailable() {
    // Bind a port and drop the listener so nothing answers there.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let address = runtime.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        format!("http://{}", listener.local_addr().unwrap())
    });
    drop(runtime);
    let settings = Settings::from_manifest(&RemoteVault::HashicorpVault {
        address,
        mount: "secret".to_owned(),
        namespace: None,
    })
    .unwrap();
    let err = Blocking::connect(|| {
        VaultClient::connect("prod", &settings, Auth::Token(Token::new("root")))
    })
    .expect_err("nothing listens");
    assert_eq!(err.code(), "provider_unavailable", "{err}");
    assert!(err.is_transient());
}
