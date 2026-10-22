use super::support::*;
use hyperhub_core::config::{Config, PluginConfig, PluginKind, PluginProtocol, WebSocketCapture};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream;

fn auditing_config() -> Config {
    let mut config = Config::default();
    config.plugins.push(PluginConfig {
        id: "protocol-audit".into(),
        kind: PluginKind::Audit,
        protocols: vec![
            PluginProtocol::Http,
            PluginProtocol::Ws,
            PluginProtocol::Ssh,
        ],
        websocket_capture: WebSocketCapture::Messages,
        ..Default::default()
    });
    config.default_route.plugins.push("protocol-audit".into());
    config
}
async fn headers<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let byte = stream.read_u8().await.unwrap();
        bytes.push(byte);
        assert!(bytes.len() < 16384);
    }
    bytes
}
async fn tls_origin() -> (
    SocketAddr,
    CertificateDer<'static>,
    tokio::task::JoinHandle<()>,
) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyCertSign);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let root = ca.der().clone();
    let issuer = rcgen::Issuer::from_ca_cert_pem(&ca.pem(), ca_key).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    let certificate = params.signed_by(&key, &issuer).unwrap();
    let config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap(),
    );
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                loop {
                    let mut request = Vec::new();
                    let mut byte = [0];
                    loop {
                        match stream.read(&mut byte).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => request.push(byte[0]),
                        }
                        if request.ends_with(b"\r\n\r\n") {
                            break;
                        }
                        assert!(request.len() < 16384);
                    }
                    if stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok").await.is_err(){return;}
                }
            });
        }
    });
    (address, root, task)
}
async fn tls_client(fixture: &Fixture, id: u64, origin: SocketAddr) -> TlsStream<TcpStream> {
    let stream = fixture.connect(id, origin).await;
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut fixture.service.tls_ca_pem().as_bytes()) {
        roots.add(certificate.unwrap()).unwrap();
    }
    let config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    tokio::time::timeout(
        Duration::from_secs(10),
        tokio_rustls::TlsConnector::from(config)
            .connect(ServerName::try_from("localhost").unwrap(), stream),
    )
    .await
    .unwrap()
    .unwrap()
}
async fn http_exchange<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, port: u16) {
    stream
        .write_all(
            format!(
                "GET /worker HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: keep-alive\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(10), headers(stream))
        .await
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let mut body = [0; 2];
    stream.read_exact(&mut body).await.unwrap();
    assert_eq!(&body, b"ok");
}
async fn websocket_origin() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let request = headers(&mut stream).await;
                assert!(String::from_utf8(request)
                    .unwrap()
                    .to_ascii_lowercase()
                    .contains("upgrade: websocket"));
                stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n").await.unwrap();
                loop {
                    let mut header = [0; 2];
                    if stream.read_exact(&mut header).await.is_err() {
                        return;
                    }
                    assert_eq!(header[0], 0x82);
                    assert_ne!(header[1] & 0x80, 0);
                    let length = usize::from(header[1] & 0x7f);
                    assert!(length < 126);
                    let mut mask = [0; 4];
                    stream.read_exact(&mut mask).await.unwrap();
                    let mut payload = vec![0; length];
                    stream.read_exact(&mut payload).await.unwrap();
                    for (index, byte) in payload.iter_mut().enumerate() {
                        *byte ^= mask[index % 4];
                    }
                    stream.write_all(&[0x82, length as u8]).await.unwrap();
                    stream.write_all(&payload).await.unwrap();
                }
            });
        }
    });
    (address, task)
}
async fn websocket_client(fixture: &Fixture, id: u64, origin: SocketAddr) -> TcpStream {
    let mut stream = fixture.connect(id, origin).await;
    stream.write_all(format!("GET /socket HTTP/1.1\r\nHost: localhost:{}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",origin.port()).as_bytes()).await.unwrap();
    let response = tokio::time::timeout(Duration::from_secs(10), headers(&mut stream))
        .await
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 101"));
    stream
}
async fn websocket_exchange(stream: &mut TcpStream, payload: &[u8]) {
    let mask = [1, 2, 3, 4];
    let mut frame = vec![0x82, 0x80 | payload.len() as u8];
    frame.extend(mask);
    frame.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ mask[index % 4]),
    );
    stream.write_all(&frame).await.unwrap();
    let mut response = vec![0; 2 + payload.len()];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response[0], 0x82);
    assert_eq!(usize::from(response[1]), payload.len());
    assert_eq!(&response[2..], payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires built forwarding worker fixture or final CLI"]
async fn tls_and_websocket_sessions_drain_with_shared_original_ca_and_canonical_audit() {
    let (tls, root, tls_server) = tls_origin().await;
    let (ws, ws_server) = websocket_origin().await;
    let fixture = Fixture::start_with(auditing_config(), vec![root]).await;
    let original_ca = fixture.service.tls_ca_pem().to_owned();
    let mut old_tls = tls_client(&fixture, 1, tls).await;
    http_exchange(&mut old_tls, tls.port()).await;
    let mut old_ws = websocket_client(&fixture, 2, ws).await;
    websocket_exchange(&mut old_ws, b"old-before-switch").await;
    assert_eq!(
        fixture.manager.status().workers[0].live_connections,
        2,
        "HTTP 101 must retain its worker ownership until upgraded IO ends"
    );
    let manager = fixture.manager.clone();
    let binary = executable();
    let hash = digest(&binary);
    tokio::task::spawn_blocking(move || manager.prepare("protocol-switch", &binary, &hash))
        .await
        .unwrap()
        .unwrap();
    fixture.manager.commit("protocol-switch").unwrap();
    fixture.manager.finalize("protocol-switch").unwrap();
    let mut new_tls = tls_client(&fixture, 3, tls).await;
    let mut new_ws = websocket_client(&fixture, 4, ws).await;
    assert_eq!(fixture.service.tls_ca_pem(), original_ca);
    assert!(
        fixture
            .manager
            .status()
            .workers
            .iter()
            .all(|worker| worker.live_connections == 2),
        "each generation must retain both TLS and WebSocket connections"
    );
    for _ in 0..8 {
        http_exchange(&mut old_tls, tls.port()).await;
        http_exchange(&mut new_tls, tls.port()).await;
        websocket_exchange(&mut old_ws, b"old-after-switch").await;
        websocket_exchange(&mut new_ws, b"new-after-switch").await;
    }
    assert_eq!(
        fixture.manager.query("protocol-switch").unwrap().phase,
        "draining"
    );
    assert!(fixture
        .service
        .connections()
        .snapshot()
        .iter()
        .any(|snapshot| snapshot.phase == "tls_mitm"));
    drop((old_tls, new_tls, old_ws, new_ws));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !fixture.service.connections().snapshot().is_empty() {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut records = Vec::new();
    for date in std::fs::read_dir(&fixture.root).unwrap().flatten() {
        let path = date.path().join("audit.jsonl");
        if path.is_file() {
            for line in std::fs::read_to_string(path).unwrap().lines() {
                records.push(serde_json::from_str::<serde_json::Value>(line).unwrap());
            }
        }
    }
    assert!(!records.is_empty());
    let run = records[0]["run_id"].clone();
    for (index, record) in records.iter().enumerate() {
        assert_eq!(record["run_id"], run);
        assert_eq!(record["sequence"].as_u64(), Some(index as u64 + 1));
        assert_eq!(record["session_id"], "worker-session");
    }
    assert!(records
        .iter()
        .any(|record| record["event"] == "http_request"));
    fixture.stop().await;
    tls_server.abort();
    ws_server.abort();
}
