//! REC05 of the 2026-10-25 review: a reply is read chunk by chunk and
//! stopped at the cap (8 MiB), whether or not it declares its length, so an
//! oversized body is refused without being buffered whole. A raw loopback
//! server sends each shape of reply.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use sourceorrery_core::{ConnectionSettings, SecretClient};
use sourceorrery_provider::Blocking;
use sourceorrery_provider_vault::{Auth, Settings, Token, VaultClient};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MOUNT_OK: &str = r#"{"data":{"type":"kv","accessor":"kv_t","options":{"version":"2"}}}"#;
const CAP: u64 = 8 * 1024 * 1024;
const CHUNK: usize = 64 * 1024;

async fn read_head(socket: &mut TcpStream) -> Option<String> {
    let mut buffer = Vec::new();
    let mut byte = [0u8; 1];
    while !buffer.ends_with(b"\r\n\r\n") {
        if socket.read(&mut byte).await.ok()? == 0 {
            return None;
        }
        buffer.push(byte[0]);
    }
    Some(String::from_utf8_lossy(&buffer).into_owned())
}

/// Send `total` bytes of `x` as chunks, then the last chunk unless `cut`;
/// the bytes the socket accepted.
async fn chunked(socket: &mut TcpStream, total: u64, cut: bool) -> u64 {
    let head =
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n";
    if socket.write_all(head.as_bytes()).await.is_err() {
        return 0;
    }
    let block = vec![b'x'; CHUNK];
    let mut sent = 0u64;
    while sent < total {
        let size = usize::try_from((total - sent).min(CHUNK as u64)).unwrap();
        let frame = [format!("{size:x}\r\n").as_bytes(), &block[..size], b"\r\n"].concat();
        if socket.write_all(&frame).await.is_err() {
            return sent;
        }
        sent += size as u64;
    }
    if !cut {
        let _ = socket.write_all(b"0\r\n\r\n").await;
    }
    sent
}

async fn serve_one(mut socket: TcpStream, accepted: Arc<AtomicU64>) {
    let Some(head) = read_head(&mut socket).await else {
        return;
    };
    let path = head
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    match path.as_str() {
        "/v1/sys/internal/ui/mounts/secret" => {
            let reply = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{MOUNT_OK}",
                MOUNT_OK.len()
            );
            let _ = socket.write_all(reply.as_bytes()).await;
        }
        "/v1/secret/metadata/declared" => {
            // Says it is over the cap; nothing follows.
            let reply = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                CAP + 1
            );
            let _ = socket.write_all(reply.as_bytes()).await;
            let _ = socket.read(&mut [0u8; 1]).await;
        }
        "/v1/secret/metadata/endless" => {
            let sent = chunked(&mut socket, 64 * CAP, false).await;
            accepted.store(sent, Ordering::SeqCst);
        }
        "/v1/secret/metadata/exact" => {
            chunked(&mut socket, CAP, false).await;
        }
        "/v1/secret/metadata/one-over" => {
            chunked(&mut socket, CAP + 1, false).await;
        }
        "/v1/secret/metadata/cut" => {
            chunked(&mut socket, 4096, true).await;
        }
        _ => {
            let _ = socket
                .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n")
                .await;
        }
    }
    let _ = socket.shutdown().await;
}

struct Server {
    address: String,
    accepted: Arc<AtomicU64>,
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
    let accepted = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&accepted);
    runtime.spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(serve_one(socket, Arc::clone(&counter)));
        }
    });
    Server {
        address,
        accepted,
        _runtime: runtime,
    }
}

fn client(server: &Server) -> Blocking<VaultClient> {
    let settings = Settings::from_connection(&ConnectionSettings::HashicorpVault {
        address: server.address.clone(),
        mount: "secret".to_owned(),
        namespace: None,
    })
    .unwrap();
    Blocking::connect(|| VaultClient::connect("t", &settings, Auth::Token(Token::new("root"))))
        .unwrap()
}

fn too_large(err: &sourceorrery_core::SecretError) -> bool {
    err.code() == "storage" && err.to_string().contains("with more than 8388608 bytes")
}

#[test]
fn a_declared_length_over_the_cap_is_refused_before_reading() {
    let server = serve();
    let err = client(&server)
        .get_secret_properties("declared", None)
        .unwrap_err();
    assert!(too_large(&err), "{err}");
}

#[test]
fn a_body_without_a_length_is_cut_off_at_the_cap() {
    let server = serve();
    let err = client(&server)
        .get_secret_properties("endless", None)
        .unwrap_err();
    assert!(too_large(&err), "{err}");
    // The client stopped reading: the server could not hand over the 512
    // MiB it had; socket buffers hold some beyond the cap, never all.
    let mut accepted = server.accepted.load(Ordering::SeqCst);
    for _ in 0..200 {
        if accepted > 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
        accepted = server.accepted.load(Ordering::SeqCst);
    }
    assert!(accepted >= CAP, "{accepted}");
    assert!(accepted < 16 * CAP, "the whole body was read: {accepted}");
}

#[test]
fn the_cap_itself_is_allowed_and_one_more_byte_is_not() {
    let server = serve();
    let client = client(&server);
    // Exactly the cap is read whole; it is not JSON, so it fails to parse.
    let err = client.get_secret_properties("exact", None).unwrap_err();
    assert!(!too_large(&err), "{err}");
    assert!(err.to_string().contains("unexpected body"), "{err}");
    let err = client.get_secret_properties("one-over", None).unwrap_err();
    assert!(too_large(&err), "{err}");
}

#[test]
fn a_body_cut_off_by_the_server_is_unavailable_and_never_echoed() {
    let server = serve();
    let err = client(&server)
        .get_secret_properties("cut", None)
        .unwrap_err();
    assert_eq!(err.code(), "provider_unavailable", "{err}");
    assert!(!err.to_string().contains("xxxx"), "{err}");
}
