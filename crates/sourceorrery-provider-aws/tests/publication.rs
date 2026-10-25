//! ADR 0011's invariant for AWS Secrets Manager, checked against a model
//! of the service: after every request it applies, whichever request is
//! refused, fails or loses its answer, the new version is never current
//! under a looser policy than asked, the old one never under a looser one
//! than it had, and invalid input sends nothing that writes.
//!
//! The model speaks the service's JSON protocol on a loopback port, with
//! the behaviours the adapter relies on: tags are the secret's (applied to
//! every version), `TagResource` adds or replaces keys, `UntagResource`
//! removes them, `PutSecretValue` makes the new version `AWSCURRENT` and is
//! idempotent for one `ClientRequestToken`. After every change it applies,
//! it keeps the tags and the current version; the test reads each snapshot
//! with the crate's own mapping. A real service or LocalStack runs the
//! same adapter in `live.rs`.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use sourceorrery_core::{
    ConnectionSettings, Credentials, SecretBytes, SecretClient, SetSecretOptions,
    UpdateSecretProperties, timestamp,
};
use sourceorrery_provider::Blocking;
use sourceorrery_provider_aws::mapping::{self, SecretProps};
use sourceorrery_provider_aws::{AwsClient, Settings};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// What the model does to a request instead of answering it; from the
/// chosen occurrence of an operation on, every one of them (the SDK may
/// send a request again).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    /// `AccessDeniedException`, nothing applied.
    Refuse,
    /// An internal error, nothing applied.
    Fail,
    /// Applied, then an answer that cannot be read.
    Garble,
}

struct Version {
    id: String,
    value: String,
    current: bool,
}

#[derive(Default)]
struct Secret {
    tags: BTreeMap<String, String>,
    versions: Vec<Version>,
}

impl Secret {
    fn current(&self) -> Option<&str> {
        self.versions
            .iter()
            .find(|v| v.current)
            .map(|v| v.id.as_str())
    }
}

#[derive(Default)]
struct Model {
    secrets: BTreeMap<String, Secret>,
    fault: Option<(&'static str, usize, Fault)>,
    seen: HashMap<String, usize>,
    /// Every request, by operation.
    requests: Vec<String>,
    /// After each applied change: the operation, the tags, the current
    /// version.
    snapshots: Vec<(String, BTreeMap<String, String>, Option<String>)>,
}

const WRITES: [&str; 5] = [
    "PutSecretValue",
    "CreateSecret",
    "TagResource",
    "UntagResource",
    "DeleteSecret",
];

fn error(kind: &str) -> (u16, String) {
    (
        400,
        json!({ "__type": kind, "message": "from the model" }).to_string(),
    )
}

fn tags_json(tags: &BTreeMap<String, String>) -> Value {
    Value::Array(
        tags.iter()
            .map(|(k, v)| json!({ "Key": k, "Value": v }))
            .collect(),
    )
}

impl Model {
    #[allow(clippy::too_many_lines)] // one arm per operation
    fn handle(&mut self, operation: &str, body: &Value) -> (u16, String) {
        let id = body["SecretId"]
            .as_str()
            .or_else(|| body["Name"].as_str())
            .unwrap_or_default()
            .to_owned();
        let arn = format!("arn:aws:secretsmanager:eu-west-1:000000000000:secret:{id}");
        if operation == "CreateSecret" {
            if self.secrets.contains_key(&id) {
                return error("ResourceExistsException");
            }
            let token = body["ClientRequestToken"]
                .as_str()
                .unwrap_or("v1")
                .to_owned();
            let tags = body["Tags"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|t| {
                    Some((
                        t["Key"].as_str()?.to_owned(),
                        t["Value"].as_str()?.to_owned(),
                    ))
                })
                .collect();
            self.secrets.insert(
                id.clone(),
                Secret {
                    tags,
                    versions: vec![Version {
                        id: token.clone(),
                        value: body["SecretString"].as_str().unwrap_or_default().to_owned(),
                        current: true,
                    }],
                },
            );
            return (
                200,
                json!({ "ARN": arn, "Name": id, "VersionId": token }).to_string(),
            );
        }
        let Some(secret) = self.secrets.get_mut(&id) else {
            return error("ResourceNotFoundException");
        };
        match operation {
            "DescribeSecret" => {
                let stages: serde_json::Map<String, Value> = secret
                    .versions
                    .iter()
                    .map(|v| {
                        let stages = if v.current {
                            json!(["AWSCURRENT"])
                        } else {
                            json!([])
                        };
                        (v.id.clone(), stages)
                    })
                    .collect();
                (
                    200,
                    json!({
                        "ARN": arn, "Name": id, "Tags": tags_json(&secret.tags),
                        "VersionIdsToStages": stages, "CreatedDate": 1_792_900_000.0,
                    })
                    .to_string(),
                )
            }
            "ListSecretVersionIds" => {
                let versions: Vec<Value> = secret
                    .versions
                    .iter()
                    .enumerate()
                    .map(|(i, v)| {
                        json!({
                            "VersionId": v.id,
                            "VersionStages": if v.current { json!(["AWSCURRENT"]) } else { json!([]) },
                            "CreatedDate": 1_792_900_000.0 + f64::from(u32::try_from(i).unwrap()),
                        })
                    })
                    .collect();
                (
                    200,
                    json!({ "ARN": arn, "Name": id, "Versions": versions }).to_string(),
                )
            }
            "GetSecretValue" => {
                let wanted = body["VersionId"].as_str();
                let found = secret
                    .versions
                    .iter()
                    .find(|v| wanted.map_or(v.current, |w| v.id == w));
                match found {
                    Some(v) => (
                        200,
                        json!({
                            "ARN": arn, "Name": id, "VersionId": v.id, "SecretString": v.value,
                            "CreatedDate": 1_792_900_000.0,
                        })
                        .to_string(),
                    ),
                    None => error("ResourceNotFoundException"),
                }
            }
            "PutSecretValue" => {
                let token = body["ClientRequestToken"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                if !secret.versions.iter().any(|v| v.id == token) {
                    for v in &mut secret.versions {
                        v.current = false;
                    }
                    secret.versions.push(Version {
                        id: token.clone(),
                        value: body["SecretString"].as_str().unwrap_or_default().to_owned(),
                        current: true,
                    });
                }
                (
                    200,
                    json!({ "ARN": arn, "Name": id, "VersionId": token, "VersionStages": ["AWSCURRENT"] })
                        .to_string(),
                )
            }
            "TagResource" => {
                for tag in body["Tags"].as_array().into_iter().flatten() {
                    if let (Some(k), Some(v)) = (tag["Key"].as_str(), tag["Value"].as_str()) {
                        secret.tags.insert(k.to_owned(), v.to_owned());
                    }
                }
                (200, "{}".to_owned())
            }
            "UntagResource" => {
                for key in body["TagKeys"].as_array().into_iter().flatten() {
                    if let Some(k) = key.as_str() {
                        secret.tags.remove(k);
                    }
                }
                (200, "{}".to_owned())
            }
            _ => error("InvalidRequestException"),
        }
    }
}

async fn read_request(socket: &mut TcpStream) -> Option<(String, Value)> {
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
        let operation = header("x-amz-target")
            .trim_start_matches("secretsmanager.")
            .to_owned();
        let body =
            serde_json::from_slice(&buffer[end + 4..end + 4 + length]).unwrap_or(Value::Null);
        return Some((operation, body));
    }
}

async fn serve_one(model: Arc<Mutex<Model>>, mut socket: TcpStream) {
    // One connection may carry several requests.
    while let Some((operation, body)) = read_request(&mut socket).await {
        let (status, text) = {
            let mut model = model.lock().unwrap();
            model.requests.push(operation.clone());
            let occurrence = {
                let count = model.seen.entry(operation.clone()).or_default();
                *count += 1;
                *count
            };
            let fault = model
                .fault
                .filter(|(op, from, _)| *op == operation && occurrence >= *from)
                .map(|(_, _, fault)| fault);
            match fault {
                Some(Fault::Refuse) => error("AccessDeniedException"),
                Some(Fault::Fail) => error("InternalServiceError"),
                fault => {
                    let (status, text) = model.handle(&operation, &body);
                    if WRITES.contains(&operation.as_str()) && status == 200 {
                        let id = body["SecretId"]
                            .as_str()
                            .or_else(|| body["Name"].as_str())
                            .unwrap_or_default();
                        let secret = &model.secrets[id];
                        let snapshot = (
                            operation.clone(),
                            secret.tags.clone(),
                            secret.current().map(str::to_owned),
                        );
                        model.snapshots.push(snapshot);
                    }
                    if fault == Some(Fault::Garble) {
                        (200, "{\"VersionId\":".to_owned())
                    } else {
                        (status, text)
                    }
                }
            }
        };
        let response = format!(
            "HTTP/1.1 {status} X\r\ncontent-type: application/x-amz-json-1.1\r\ncontent-length: {}\r\n\r\n{text}",
            text.len()
        );
        if socket.write_all(response.as_bytes()).await.is_err() {
            return;
        }
    }
}

struct Server {
    endpoint: String,
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
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let model: Arc<Mutex<Model>> = Arc::default();
    let shared = Arc::clone(&model);
    runtime.spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(serve_one(Arc::clone(&shared), socket));
        }
    });
    Server {
        endpoint,
        model,
        _runtime: runtime,
    }
}

fn connect(server: &Server) -> Blocking<AwsClient> {
    let settings = Settings::from_connection(&ConnectionSettings::AwsSecretsManager {
        region: "eu-west-1".to_owned(),
        prefix: None,
        endpoint_url: Some(server.endpoint.clone()),
    })
    .unwrap();
    let key = Credentials::AwsAccessKey {
        access_key_id: "AKIAMODEL".to_owned(),
        secret_access_key: SecretBytes::from("model-secret"),
    };
    Blocking::connect(|| AwsClient::connect("model", &settings, Some(&key))).unwrap()
}

fn props_of(tags: &BTreeMap<String, String>) -> SecretProps {
    SecretProps::from_tags(&mapping::tags_of(tags)).unwrap()
}

fn asked(options: &SetSecretOptions) -> SecretProps {
    SecretProps {
        disabled: !options.enabled,
        not_before: options.not_before,
        expires_on: options.expires_on,
        ..SecretProps::default()
    }
}

/// SR02 on AWS: a version written over one with another policy, with each
/// request of the write refused, failed, or applied with its answer lost.
/// In every state the model passed through, the new version is current
/// only under a policy at least as strict as asked, and before it is
/// current the old one is under one at least as strict as it had; a write
/// that may have landed is never reported as a refusal.
#[test]
fn a_new_version_is_never_current_under_a_looser_policy() {
    let now = timestamp::now();
    let enabled = SetSecretOptions::default();
    let disabled = SetSecretOptions {
        enabled: false,
        ..SetSecretOptions::default()
    };
    let later = SetSecretOptions {
        not_before: Some(now + time::Duration::days(2)),
        ..SetSecretOptions::default()
    };
    let transitions = [
        ("enabled -> disabled", &enabled, &disabled),
        ("disabled -> later", &disabled, &later),
        ("later -> enabled", &later, &enabled),
    ];
    let mut faults = vec![None];
    for operation in ["TagResource", "PutSecretValue", "UntagResource"] {
        for occurrence in 1..=2 {
            for fault in [Fault::Refuse, Fault::Fail, Fault::Garble] {
                faults.push(Some((operation, occurrence, fault)));
            }
        }
    }
    for (what, old, new) in transitions {
        for fault in &faults {
            let case = format!("{what}, {fault:?}");
            let server = serve();
            let client = connect(&server);
            client
                .set_secret("db", SecretBytes::from("old"), old.clone())
                .unwrap();
            let first = server.model.lock().unwrap().secrets["db"]
                .current()
                .unwrap()
                .to_owned();
            {
                let mut model = server.model.lock().unwrap();
                model.snapshots.clear();
                model.seen.clear();
                model.fault = *fault;
            }
            let outcome = client.set_secret("db", SecretBytes::from("new"), new.clone());
            let model = server.model.lock().unwrap();
            for (operation, tags, current) in &model.snapshots {
                let seen = props_of(tags);
                if current.as_deref() == Some(first.as_str()) {
                    assert!(
                        seen.at_least_as_strict_as(&asked(old)),
                        "{case}: the old version under {seen:?} after {operation}"
                    );
                } else {
                    assert!(
                        seen.at_least_as_strict_as(&asked(new)),
                        "{case}: the new version under {seen:?} after {operation}"
                    );
                }
            }
            let landed = model.secrets["db"].current() != Some(first.as_str());
            match &outcome {
                Ok(_) => assert!(landed, "{case}"),
                Err(err) if landed => assert_eq!(err.code(), "outcome_unknown", "{case}: {err}"),
                Err(err) if err.is_refusal() => {
                    // Nothing published: the policy is the old one again.
                    let left = props_of(&model.secrets["db"].tags);
                    assert!(
                        left.at_least_as_strict_as(&asked(old))
                            && asked(old).at_least_as_strict_as(&left),
                        "{case}: refused, but left at {left:?}"
                    );
                }
                Err(_) => {}
            }
        }
    }
}

/// The order an update used, every stale tag removed first, made a secret
/// going from disabled to a later `not_before` readable for a moment; the
/// plan never does, and a failure part way is `outcome_unknown`.
#[test]
fn an_update_never_passes_through_a_looser_policy() {
    let now = timestamp::now();
    let server = serve();
    let client = connect(&server);
    client
        .set_secret(
            "db",
            SecretBytes::from("v"),
            SetSecretOptions {
                enabled: false,
                ..SetSecretOptions::default()
            },
        )
        .unwrap();
    server.model.lock().unwrap().snapshots.clear();
    let not_before = now + time::Duration::days(2);
    client
        .update_secret_properties(
            "db",
            None,
            UpdateSecretProperties {
                enabled: Some(true),
                not_before: Some(Some(not_before)),
                ..UpdateSecretProperties::default()
            },
        )
        .unwrap();
    let old = SecretProps {
        disabled: true,
        ..SecretProps::default()
    };
    let new = SecretProps {
        not_before: Some(not_before),
        ..SecretProps::default()
    };
    let model = server.model.lock().unwrap();
    assert_eq!(model.snapshots.len(), 2, "tag, then untag");
    for (operation, tags, _) in &model.snapshots {
        let seen = props_of(tags);
        assert!(
            seen.at_least_as_strict_as(&old) || seen.at_least_as_strict_as(&new),
            "{seen:?} after {operation}"
        );
    }
    drop(model);

    server.model.lock().unwrap().fault = Some(("UntagResource", 1, Fault::Fail));
    let err = client
        .update_secret_properties(
            "db",
            None,
            UpdateSecretProperties {
                enabled: Some(false),
                not_before: Some(None),
                ..UpdateSecretProperties::default()
            },
        )
        .unwrap_err();
    assert_eq!(err.code(), "outcome_unknown", "{err}");
    // The first step refused: nothing changed, so a plain refusal.
    let server = serve();
    let client = connect(&server);
    client
        .set_secret("db", SecretBytes::from("v"), SetSecretOptions::default())
        .unwrap();
    server.model.lock().unwrap().fault = Some(("TagResource", 1, Fault::Refuse));
    let err = client
        .update_secret_properties(
            "db",
            None,
            UpdateSecretProperties {
                enabled: Some(false),
                ..UpdateSecretProperties::default()
            },
        )
        .unwrap_err();
    assert_eq!(err.code(), "permission_denied", "{err}");
}

/// REC06: tags and values the service would refuse are refused before any
/// request that writes, so nothing is published and then left half-done;
/// AWS's own tags are never written or removed.
#[test]
fn invalid_input_sends_nothing_that_writes() {
    let server = serve();
    let client = connect(&server);
    client
        .set_secret("db", SecretBytes::from("v"), SetSecretOptions::default())
        .unwrap();
    server
        .model
        .lock()
        .unwrap()
        .secrets
        .get_mut("db")
        .unwrap()
        .tags
        .insert(
            "aws:cloudformation:stack-name".to_owned(),
            "stack".to_owned(),
        );
    let invalid = [
        BTreeMap::from([("sourceorrery:disabled".to_owned(), "false".to_owned())]),
        BTreeMap::from([("aws:owner".to_owned(), "me".to_owned())]),
        BTreeMap::from([("team".to_owned(), "a;b".to_owned())]),
        (0..51).map(|i| (format!("t{i}"), "v".to_owned())).collect(),
        (0..48).map(|i| (format!("t{i}"), "v".to_owned())).collect(),
    ];
    let before = server.model.lock().unwrap().requests.len();
    for tags in invalid {
        let count = tags.len();
        let err = client
            .set_secret(
                "db",
                SecretBytes::from("new"),
                SetSecretOptions {
                    enabled: false,
                    not_before: Some(timestamp::now() + time::Duration::days(1)),
                    expires_on: Some(timestamp::now() + time::Duration::days(9)),
                    tags,
                    ..SetSecretOptions::default()
                },
            )
            .unwrap_err();
        assert_eq!(err.code(), "invalid_argument", "{count} tags: {err}");
    }
    let err = client
        .set_secret(
            "db",
            SecretBytes::new(vec![b'x'; mapping::MAX_VALUE_LEN + 1]),
            SetSecretOptions::default(),
        )
        .unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    let err = client
        .update_secret_properties(
            "db",
            None,
            UpdateSecretProperties {
                content_type: Some(Some("text/plain; charset=utf-8".to_owned())),
                ..UpdateSecretProperties::default()
            },
        )
        .unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    let model = server.model.lock().unwrap();
    let writes: Vec<&String> = model.requests[before..]
        .iter()
        .filter(|op| WRITES.contains(&op.as_str()))
        .collect();
    assert_eq!(
        writes,
        Vec::<&String>::new(),
        "nothing that writes was sent"
    );
    drop(model);

    // A valid write keeps AWS's own tag and does not count it.
    let tags: BTreeMap<String, String> =
        (0..45).map(|i| (format!("t{i}"), "v".to_owned())).collect();
    client
        .set_secret(
            "db",
            SecretBytes::from("new"),
            SetSecretOptions {
                tags,
                ..SetSecretOptions::default()
            },
        )
        .unwrap();
    let model = server.model.lock().unwrap();
    assert_eq!(
        model.secrets["db"].tags["aws:cloudformation:stack-name"],
        "stack"
    );
    assert_eq!(model.secrets["db"].tags.len(), 46);
}
