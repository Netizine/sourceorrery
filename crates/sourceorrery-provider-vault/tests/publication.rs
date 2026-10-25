//! ADR 0011's invariant for HashiCorp Vault, checked against a model of
//! KV v2: a version is never readable through SourceOrrery under a looser
//! policy than its writer asked for, after every request the server
//! applies, whichever request fails or loses its answer, and with two
//! writers interleaved.
//!
//! The model is an in-process HTTP server with the KV v2 behaviours the
//! adapter relies on, each checked against Vault 2.2.1 when the design was
//! settled: metadata created before any data, check-and-set on data writes
//! (400 on a mismatch), JSON merge patches of `custom_metadata` (`null`
//! removes a key, 404 without metadata, 415 without the merge-patch type), a
//! `POST` of metadata that replaces `custom_metadata` only when it carries
//! one. After every request it applies, it keeps the secret's metadata as a
//! reader would fetch it; the test then reads each snapshot with the
//! crate's own mapping.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use sourceorrery_core::{ConnectionSettings, SecretBytes, SecretClient, SetSecretOptions};
use sourceorrery_provider::Blocking;
use sourceorrery_provider_vault::kv::MetadataResponse;
use sourceorrery_provider_vault::{Auth, Settings, Token, VaultClient};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MOUNT_OK: &str = r#"{"data":{"type":"kv","accessor":"kv_model","options":{"version":"2"}}}"#;
const CREATED: &str = "2026-10-25T10:00:00Z";

/// What the model does to one request instead of answering it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    /// 403, nothing applied.
    Refuse,
    /// 500, nothing applied.
    Fail,
    /// Applied, then the connection closed before any answer.
    Lose,
}

#[derive(Default)]
struct Version {
    data: Value,
    deleted: bool,
}

#[derive(Default)]
struct Secret {
    custom: BTreeMap<String, String>,
    versions: BTreeMap<u64, Version>,
}

impl Secret {
    fn current(&self) -> u64 {
        self.versions.keys().next_back().copied().unwrap_or(0)
    }

    fn metadata(&self) -> Value {
        let versions: serde_json::Map<String, Value> = self
            .versions
            .iter()
            .map(|(n, v)| {
                (
                    n.to_string(),
                    json!({
                        "created_time": CREATED,
                        "deletion_time": if v.deleted { CREATED } else { "" },
                        "destroyed": false,
                    }),
                )
            })
            .collect();
        json!({ "data": {
            "current_version": self.current(),
            "custom_metadata": if self.custom.is_empty() { Value::Null } else { json!(self.custom) },
            "versions": versions,
        }})
    }
}

/// The model's state, and what the test arranged.
#[derive(Default)]
struct Model {
    secrets: BTreeMap<String, Secret>,
    /// (label, occurrence, fault): the fault applies to that occurrence of a
    /// request labelled `METHOD kind` ("PATCH metadata", "POST data").
    fault: Option<(&'static str, usize, Fault)>,
    seen: HashMap<String, usize>,
    /// After each applied change: its label and the secret's metadata.
    snapshots: Vec<(String, String)>,
    /// Requests that must come in this order, as (token, label); others
    /// pass.
    order: VecDeque<(String, String)>,
}

struct Request {
    method: String,
    path: String,
    token: String,
    content_type: String,
    body: Value,
}

fn reply(status: u16, body: &str) -> (u16, String) {
    (status, body.to_owned())
}

impl Model {
    #[allow(clippy::too_many_lines)] // one arm per KV v2 endpoint
    fn handle(&mut self, request: &Request) -> (u16, String) {
        let path = request.path.trim_start_matches("/v1/");
        let (path, query) = path.split_once('?').unwrap_or((path, ""));
        match (request.method.as_str(), path) {
            ("GET", "sys/internal/ui/mounts/secret") => return reply(200, MOUNT_OK),
            ("GET", "auth/token/lookup-self") => return reply(200, r#"{"data":{}}"#),
            ("LIST", "secret/metadata/") => {
                let keys: Vec<&String> = self.secrets.keys().collect();
                return reply(200, &json!({ "data": { "keys": keys } }).to_string());
            }
            _ => {}
        }
        let Some((kind, name)) = path
            .strip_prefix("secret/")
            .and_then(|rest| rest.split_once('/'))
        else {
            return reply(404, r#"{"errors":[]}"#);
        };
        let name = name.to_owned();
        match (request.method.as_str(), kind) {
            ("GET", "metadata") => match self.secrets.get(&name) {
                Some(secret) => reply(200, &secret.metadata().to_string()),
                None => reply(404, r#"{"errors":[]}"#),
            },
            ("GET", "data") => {
                let wanted: u64 = query
                    .strip_prefix("version=")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                match self
                    .secrets
                    .get(&name)
                    .and_then(|s| s.versions.get(&wanted))
                {
                    Some(v) if !v.deleted => {
                        reply(200, &json!({ "data": { "data": v.data } }).to_string())
                    }
                    Some(_) => reply(404, r#"{"data":{"data":null}}"#),
                    None => reply(404, r#"{"errors":[]}"#),
                }
            }
            ("POST", "metadata") => {
                let custom = request.body.get("custom_metadata").cloned();
                let creates = custom.is_some() || request.body.get("max_versions").is_some();
                if creates {
                    let secret = self.secrets.entry(name).or_default();
                    if let Some(Value::Object(map)) = custom {
                        secret.custom = map
                            .into_iter()
                            .filter_map(|(k, v)| v.as_str().map(|v| (k, v.to_owned())))
                            .collect();
                    }
                }
                reply(204, "")
            }
            ("PATCH", "metadata") => {
                if request.content_type != "application/merge-patch+json" {
                    return reply(415, r#"{"errors":["PATCH requires merge-patch"]}"#);
                }
                let Some(secret) = self.secrets.get_mut(&name) else {
                    return reply(404, "");
                };
                if let Some(Value::Object(changes)) = request.body.get("custom_metadata") {
                    for (key, value) in changes {
                        match value {
                            Value::String(text) => {
                                secret.custom.insert(key.clone(), text.clone());
                            }
                            _ => {
                                secret.custom.remove(key);
                            }
                        }
                    }
                }
                reply(204, "")
            }
            ("DELETE", "metadata") => {
                self.secrets.remove(&name);
                reply(204, "")
            }
            ("POST", "data") => {
                let current = self.secrets.get(&name).map_or(0, Secret::current);
                if let Some(cas) = request.body["options"]["cas"].as_u64()
                    && cas != current
                {
                    return reply(
                        400,
                        r#"{"errors":["check-and-set parameter did not match the current version"]}"#,
                    );
                }
                let secret = self.secrets.entry(name).or_default();
                let version = current + 1;
                secret.versions.insert(
                    version,
                    Version {
                        data: request.body["data"].clone(),
                        deleted: false,
                    },
                );
                reply(
                    200,
                    &json!({ "data": { "version": version, "created_time": CREATED } }).to_string(),
                )
            }
            ("POST", "delete" | "undelete") => {
                let deleted = kind == "delete";
                let Some(secret) = self.secrets.get_mut(&name) else {
                    return reply(404, "");
                };
                for n in request.body["versions"].as_array().into_iter().flatten() {
                    if let Some(v) = n.as_u64().and_then(|n| secret.versions.get_mut(&n)) {
                        v.deleted = deleted;
                    }
                }
                reply(204, "")
            }
            _ => reply(404, r#"{"errors":[]}"#),
        }
    }
}

/// A label for a request: `METHOD kind`.
fn label(request: &Request) -> String {
    let kind = request
        .path
        .trim_start_matches("/v1/secret/")
        .split('/')
        .next()
        .unwrap_or_default();
    format!("{} {kind}", request.method)
}

fn changes(request: &Request) -> bool {
    request.method != "GET" && request.method != "LIST"
}

async fn read_request(socket: &mut TcpStream) -> Option<Request> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = socket.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..n]);
        let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") else {
            continue;
        };
        let head = String::from_utf8_lossy(&buffer[..end]).into_owned();
        let header = |name: &str| {
            head.lines()
                .find_map(|l| {
                    l.split_once(':')
                        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
                        .map(|(_, v)| v.trim().to_owned())
                })
                .unwrap_or_default()
        };
        let length: usize = header("content-length").parse().unwrap_or(0);
        if buffer.len() < end + 4 + length {
            continue;
        }
        let body = &buffer[end + 4..end + 4 + length];
        let mut words = head.split_whitespace();
        return Some(Request {
            method: words.next().unwrap_or_default().to_owned(),
            path: words.next().unwrap_or_default().to_owned(),
            token: header("x-vault-token"),
            content_type: header("content-type"),
            body: serde_json::from_slice(body).unwrap_or(Value::Null),
        });
    }
}

async fn serve_one(model: Arc<Mutex<Model>>, mut socket: TcpStream) {
    let Some(request) = read_request(&mut socket).await else {
        return;
    };
    let label = label(&request);
    // A request the test put in an order waits for its turn.
    loop {
        {
            let mut model = model.lock().unwrap();
            let mine = |(token, step): &(String, String)| *token == request.token && *step == label;
            if model.order.front().is_some_and(mine) {
                model.order.pop_front();
                break;
            }
            if !model.order.iter().any(mine) {
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    let (status, body, lose) = {
        let mut model = model.lock().unwrap();
        let occurrence = {
            let count = model.seen.entry(label.clone()).or_default();
            *count += 1;
            *count
        };
        let fault = model
            .fault
            .filter(|(l, n, _)| *l == label && *n == occurrence)
            .map(|(_, _, fault)| fault);
        match fault {
            Some(Fault::Refuse) => (403, r#"{"errors":["permission denied"]}"#.to_owned(), false),
            Some(Fault::Fail) => (500, r#"{"errors":["internal error"]}"#.to_owned(), false),
            fault => {
                let (status, body) = model.handle(&request);
                if changes(&request) && (200..300).contains(&status) {
                    let name = request.path.rsplit('/').next().unwrap_or_default();
                    let metadata = model
                        .secrets
                        .get(name)
                        .map_or_else(String::new, |s| s.metadata().to_string());
                    model.snapshots.push((label.clone(), metadata));
                }
                (status, body, fault == Some(Fault::Lose))
            }
        }
    };
    if lose {
        // Applied; the answer never arrives.
        drop(socket);
        return;
    }
    let response = format!(
        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = socket.write_all(response.as_bytes()).await;
    let _ = socket.shutdown().await;
}

struct Server {
    address: String,
    model: Arc<Mutex<Model>>,
    _runtime: tokio::runtime::Runtime,
}

fn serve() -> Server {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let listener = runtime.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let model: Arc<Mutex<Model>> = Arc::default();
    let shared = Arc::clone(&model);
    runtime.spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(serve_one(Arc::clone(&shared), socket));
        }
    });
    Server {
        address,
        model,
        _runtime: runtime,
    }
}

fn client(server: &Server, token: &str) -> Blocking<VaultClient> {
    let settings = Settings::from_connection(&ConnectionSettings::HashicorpVault {
        address: server.address.clone(),
        mount: "secret".to_owned(),
        namespace: None,
    })
    .unwrap();
    let auth = Auth::Token(Token::new(token));
    Blocking::connect(|| VaultClient::connect("model", &settings, auth)).unwrap()
}

fn disabled() -> SetSecretOptions {
    SetSecretOptions {
        enabled: false,
        ..SetSecretOptions::default()
    }
}

/// Every snapshot in which version `version` of `name` exists, read with
/// the crate's mapping: its `enabled`.
fn enabled_in_snapshots(server: &Server, name: &str, version: u64) -> Vec<(String, bool)> {
    let model = server.model.lock().unwrap();
    model
        .snapshots
        .iter()
        .filter(|(_, metadata)| !metadata.is_empty())
        .filter_map(|(label, metadata)| {
            let parsed: MetadataResponse = serde_json::from_str(metadata).unwrap();
            parsed
                .data
                .versions
                .contains_key(&version.to_string())
                .then(|| {
                    let props = parsed.data.properties("model", name, version).unwrap();
                    (label.clone(), props.enabled)
                })
        })
        .collect()
}

/// SR02 of the 2026-10-25 review: a version written disabled over an
/// enabled one, with each request of the write refused, failed, or applied
/// and its answer lost. In no state the server passed through is the new
/// version enabled, no read returns it, and the result says whether it may
/// have been written.
#[test]
fn a_disabled_version_is_never_readable_whichever_request_fails() {
    let steps = [
        ("PATCH metadata", 1),
        ("POST data", 1),
        ("PATCH metadata", 2),
    ];
    for (step, occurrence) in steps {
        for fault in [Fault::Refuse, Fault::Fail, Fault::Lose] {
            let server = serve();
            let writer = client(&server, "hvs.writer");
            writer
                .set_secret("db", SecretBytes::from("old"), SetSecretOptions::default())
                .unwrap();
            {
                let mut model = server.model.lock().unwrap();
                model.snapshots.clear();
                model.seen.clear();
                model.fault = Some((step, occurrence, fault));
            }
            let outcome = writer.set_secret("db", SecretBytes::from("new"), disabled());
            let case = format!("{fault:?} at {step} #{occurrence}");
            for (label, enabled) in enabled_in_snapshots(&server, "db", 2) {
                assert!(!enabled, "{case}: version 2 enabled after {label}");
            }
            let reader = client(&server, "hvs.reader");
            let read = reader.get_secret("db", None).unwrap();
            assert_eq!(read.value.expose(), b"old", "{case}");
            assert!(
                reader.get_secret("db", Some("2")).is_err(),
                "{case}: version 2 was readable"
            );
            // What the writer is told.
            let written = server.model.lock().unwrap().secrets["db"].current() == 2;
            match (&outcome, written) {
                (Ok(_), true) => {}
                (Err(err), false) if err.is_refusal() => {}
                (Err(err), _) if !err.is_refusal() => {
                    // A failure that does not prove nothing changed; the
                    // router records it as `outcome_unknown`.
                }
                other => panic!("{case}: {other:?}"),
            }
            if written && let Err(err) = &outcome {
                assert_eq!(err.code(), "outcome_unknown", "{case}");
            }
        }
    }
}

/// A restricted write patches its intent before the data and commits
/// after it, leaving only the committed document; refused at the intent,
/// it writes nothing.
#[test]
fn a_write_commits_its_properties_and_removes_its_intent() {
    let server = serve();
    let writer = client(&server, "hvs.writer");
    writer
        .set_secret("db", SecretBytes::from("old"), SetSecretOptions::default())
        .unwrap();
    let props = writer
        .set_secret("db", SecretBytes::from("new"), disabled())
        .unwrap();
    assert_eq!(props.version, "2");
    let model = server.model.lock().unwrap();
    let custom = &model.secrets["db"].custom;
    assert_eq!(
        custom.keys().collect::<Vec<_>>(),
        vec!["sourceorrery.v2"],
        "the intent is gone once committed"
    );
    let labels: Vec<&str> = model.snapshots.iter().map(|(l, _)| l.as_str()).collect();
    assert_eq!(
        labels,
        ["POST data", "PATCH metadata", "POST data", "PATCH metadata"],
        "a default write is one request; a restricted one patches before and after"
    );
    drop(model);

    // Refused at the intent: nothing written.
    server.model.lock().unwrap().fault = Some(("PATCH metadata", 3, Fault::Refuse));
    let err = writer
        .set_secret("db", SecretBytes::from("newer"), disabled())
        .unwrap_err();
    assert_eq!(err.code(), "permission_denied", "{err}");
    assert!(err.to_string().contains("`patch`"), "{err}");
    assert_eq!(server.model.lock().unwrap().secrets["db"].current(), 2);
}

/// A leftover intent (a writer that stopped after patching it) restricts
/// the version it names when someone else writes it, and the next
/// SourceOrrery write of that version removes it.
#[test]
fn a_leftover_intent_only_restricts_until_the_version_is_committed() {
    let server = serve();
    let writer = client(&server, "hvs.writer");
    writer
        .set_secret("db", SecretBytes::from("old"), SetSecretOptions::default())
        .unwrap();
    // A writer patched its intent for version 2 and stopped.
    server
        .model
        .lock()
        .unwrap()
        .secrets
        .get_mut("db")
        .unwrap()
        .custom
        .insert(
            "sourceorrery.v2~deadbeefdeadbeef".to_owned(),
            r#"{"disabled":true}"#.to_owned(),
        );
    let reader = client(&server, "hvs.reader");
    assert!(
        reader
            .get_secret_properties("db", Some("1"))
            .unwrap()
            .enabled,
        "version 1 is not affected"
    );
    server.model.lock().unwrap().snapshots.clear();
    let props = writer
        .set_secret("db", SecretBytes::from("new"), SetSecretOptions::default())
        .unwrap();
    assert_eq!(props.version, "2");
    // The write removed the leftover: version 2 has the defaults it asked for.
    assert!(
        reader
            .get_secret_properties("db", Some("2"))
            .unwrap()
            .enabled
    );
    assert_eq!(
        reader.get_secret("db", None).unwrap().value.expose(),
        b"new"
    );
    assert!(server.model.lock().unwrap().secrets["db"].custom.is_empty());
    // Between the data and the commit, the leftover held version 2.
    assert_eq!(
        enabled_in_snapshots(&server, "db", 2),
        vec![
            ("POST data".to_owned(), false),
            ("PATCH metadata".to_owned(), true)
        ]
    );
}

/// Two writers at once: A writes version 2 disabled while B writes it with
/// tags only. Their requests interleave as A read, B read, A intent, B
/// intent, A data, B data (refused: A took version 2), B removes its intent,
/// A commits. Version 2 is A's and is never enabled; B is told that nothing
/// was written.
#[test]
fn two_writers_never_lift_each_others_restrictions() {
    let server = serve();
    let seed = client(&server, "hvs.seed");
    seed.set_secret("db", SecretBytes::from("old"), SetSecretOptions::default())
        .unwrap();
    let a = client(&server, "hvs.a");
    let b = client(&server, "hvs.b");
    {
        let mut model = server.model.lock().unwrap();
        model.snapshots.clear();
        for (token, step) in [
            ("hvs.a", "GET metadata"),
            ("hvs.b", "GET metadata"),
            ("hvs.a", "PATCH metadata"),
            ("hvs.b", "PATCH metadata"),
            ("hvs.a", "POST data"),
            ("hvs.b", "POST data"),
            ("hvs.b", "PATCH metadata"),
            ("hvs.a", "PATCH metadata"),
        ] {
            model.order.push_back((token.to_owned(), step.to_owned()));
        }
    }
    let tagged = SetSecretOptions {
        tags: BTreeMap::from([("team".to_owned(), "payments".to_owned())]),
        ..SetSecretOptions::default()
    };
    let (outcome_a, outcome_b) = std::thread::scope(|scope| {
        let a = scope.spawn(|| a.set_secret("db", SecretBytes::from("from-a"), disabled()));
        let b = scope.spawn(|| b.set_secret("db", SecretBytes::from("from-b"), tagged));
        (a.join().unwrap(), b.join().unwrap())
    });
    assert!(
        server.model.lock().unwrap().order.is_empty(),
        "every step ran in order"
    );
    assert_eq!(outcome_a.unwrap().version, "2");
    let err = outcome_b.unwrap_err();
    assert_eq!(err.code(), "invalid_argument", "{err}");
    assert!(err.to_string().contains("another writer"), "{err}");
    let states = enabled_in_snapshots(&server, "db", 2);
    assert_eq!(states.len(), 3, "A's data, B's intent removed, A's commit");
    for (label, enabled) in states {
        assert!(!enabled, "A's version 2 enabled after {label}");
    }
    let reader = client(&server, "hvs.reader");
    assert_eq!(
        reader.get_secret("db", None).unwrap().value.expose(),
        b"old"
    );
    let custom = &server.model.lock().unwrap().secrets["db"].custom;
    assert_eq!(custom.keys().collect::<Vec<_>>(), vec!["sourceorrery.v2"]);
}

/// Delete marks first and recovery unmarks last: when the second step
/// fails the secret is still deleted for SourceOrrery, and can be
/// recovered.
#[test]
fn a_delete_or_recover_cut_short_leaves_the_secret_deleted() {
    let server = serve();
    let client = client(&server, "hvs.writer");
    client
        .set_secret("db", SecretBytes::from("v"), SetSecretOptions::default())
        .unwrap();
    server.model.lock().unwrap().fault = Some(("POST delete", 1, Fault::Fail));
    let err = client.delete_secret("db").unwrap_err();
    assert_eq!(err.code(), "outcome_unknown", "{err}");
    assert_eq!(client.get_secret("db", None).unwrap_err().code(), "deleted");
    // Recovering asks KV's undelete (harmless here) and unmarks it.
    client.recover_deleted_secret("db").unwrap();
    assert_eq!(client.get_secret("db", None).unwrap().value.expose(), b"v");

    client.delete_secret("db").unwrap();
    server.model.lock().unwrap().fault = Some(("PATCH metadata", 4, Fault::Fail));
    let err = client.recover_deleted_secret("db").unwrap_err();
    assert_eq!(err.code(), "outcome_unknown", "{err}");
    assert_eq!(client.get_secret("db", None).unwrap_err().code(), "deleted");
    client.recover_deleted_secret("db").unwrap();
    assert_eq!(client.get_secret("db", None).unwrap().value.expose(), b"v");
}
