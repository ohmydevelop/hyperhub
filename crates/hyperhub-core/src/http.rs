use crate::audit::{AuditWriter, TranscriptMetadata};
use crate::config::{
    Config, HttpAuthScheme, PluginConfig, PluginProtocol, SecretValue, WebSocketCapture,
};
use crate::duplex::{bridge, prepare_transcript, CaptureConfig, PrefixedIo};
use crate::inspect;
use crate::policy::{ConnectionContext, PolicySnapshot, Protocol};
use crate::protection::{
    FindingKind, ProtectionConnectionState, ProtectionRequest, ProtectionSnapshot, ScanResult,
};
use crate::protocol::{run_stack, BoxedStream, HandlerContext};
use crate::trust::TrustStore;
use crate::websocket::{self, Compression};
use base64::Engine;
use http_body::{Body as HttpBodyTrait, Frame, SizeHint};
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderName, HeaderValue, CONNECTION, COOKIE, HOST, UPGRADE};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig,
    SignatureScheme,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
#[cfg(test)]
use std::fs;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration};
use tokio_rustls::{TlsAcceptor, TlsConnector};

static NEXT_UPGRADE_STREAM_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_BODY_CAPTURE_STREAM_ID: AtomicU64 = AtomicU64::new(1);

enum UpgradeCapture {
    Frames(CaptureConfig),
    Messages {
        capture: CaptureConfig,
        compression: Compression,
    },
}

pub struct TlsMitm {
    issuer: Issuer<'static, KeyPair>,
    ca_pem: String,
    ca_der: CertificateDer<'static>,
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
    outbound: Arc<ClientConfig>,
    outbound_http1: Arc<ClientConfig>,
    outbound_raw: Arc<ClientConfig>,
}

impl TlsMitm {
    pub fn generate() -> io::Result<Arc<Self>> {
        Self::generate_with_root_certificates(Vec::new())
    }

    pub fn generate_with_root_certificates(
        root_certificates: Vec<CertificateDer<'static>>,
    ) -> io::Result<Arc<Self>> {
        let key = KeyPair::generate().map_err(io::Error::other)?;
        let mut params = CertificateParams::new(Vec::<String>::new()).map_err(io::Error::other)?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.use_authority_key_identifier_extension = true;
        params
            .distinguished_name
            .push(DnType::CommonName, "HyperHub Local Inspection CA");
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        let certificate = params.self_signed(&key).map_err(io::Error::other)?;
        let ca_pem = certificate.pem();
        let ca_der = certificate.der().clone();
        let issuer = Issuer::from_ca_cert_pem(&ca_pem, key).map_err(io::Error::other)?;

        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for certificate in root_certificates {
            roots.add(certificate).map_err(|error| {
                io::Error::other(format!("root certificate could not be trusted: {error}"))
            })?;
        }
        let mut outbound = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        outbound.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let mut outbound_http1 = outbound.clone();
        outbound_http1.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut outbound_raw = outbound.clone();
        outbound_raw.alpn_protocols.clear();
        Ok(Arc::new(Self {
            issuer,
            ca_pem,
            ca_der,
            cache: Mutex::new(HashMap::new()),
            outbound: Arc::new(outbound),
            outbound_http1: Arc::new(outbound_http1),
            outbound_raw: Arc::new(outbound_raw),
        }))
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    fn server_config(&self, host: &str) -> io::Result<Arc<ServerConfig>> {
        if let Some(config) = self
            .cache
            .lock()
            .map_err(|_| io::Error::other("TLS certificate cache poisoned"))?
            .get(host)
            .cloned()
        {
            return Ok(config);
        }
        let mut params =
            rcgen::CertificateParams::new(vec![host.to_owned()]).map_err(io::Error::other)?;
        params.use_authority_key_identifier_extension = true;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        let key = KeyPair::generate().map_err(io::Error::other)?;
        let certificate = params
            .signed_by(&key, &self.issuer)
            .map_err(io::Error::other)?;
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.der().clone(), self.ca_der.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .map_err(io::Error::other)?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let config = Arc::new(config);
        self.cache
            .lock()
            .map_err(|_| io::Error::other("TLS certificate cache poisoned"))?
            .insert(host.to_owned(), config.clone());
        Ok(config)
    }
}

type OutboundBody = UnsyncBoxBody<Bytes, io::Error>;

enum RequestSender {
    Http1(hyper::client::conn::http1::SendRequest<OutboundBody>),
    Http2(hyper::client::conn::http2::SendRequest<OutboundBody>),
}

impl RequestSender {
    async fn send(
        &mut self,
        request: Request<OutboundBody>,
    ) -> Result<Response<Incoming>, hyper::Error> {
        match self {
            Self::Http1(sender) => sender.send_request(request).await,
            Self::Http2(sender) => sender.send_request(request).await,
        }
    }
}

/// TLS MITM 层服务：客户端握手 → 上游握手 → 解密后下钻协议栈。
pub(crate) async fn proxy_https<C, U>(
    client: C,
    upstream: U,
    depth: usize,
    inner: HandlerContext,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let host = inner.host.clone();
    let (client, inbound_alpn) = accept_client_tls(client, &host, &inner.mitm).await?;
    let inbound_h2 = inbound_alpn.as_deref() == Some(b"h2");
    let upstream = connect_outbound_tls(
        upstream,
        &host,
        inner.context.destination.port,
        &inner.mitm,
        inner.trust.clone(),
        inbound_alpn.as_deref(),
    )
    .await?;
    let outbound_h2 = upstream.get_ref().1.alpn_protocol() == Some(b"h2");
    serve_decrypted(
        Box::new(client) as BoxedStream,
        Box::new(upstream) as BoxedStream,
        inbound_alpn,
        inbound_h2,
        outbound_h2,
        depth,
        inner.upstream_tunneled,
        inner,
    )
    .await
}

async fn accept_client_tls<S>(
    client: S,
    host: &str,
    mitm: &TlsMitm,
) -> io::Result<(tokio_rustls::server::TlsStream<S>, Option<Vec<u8>>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let server_config = mitm.server_config(host)?;
    let client = TlsAcceptor::from(server_config)
        .accept(client)
        .await
        .map_err(|error| {
            io::Error::other(format!(
                "client TLS MITM handshake failed; target rejected or aborted the HyperHub certificate: {error}"
            ))
        })?;
    let inbound_alpn = client
        .get_ref()
        .1
        .alpn_protocol()
        .map(|value| value.to_vec());
    Ok((client, inbound_alpn))
}

#[derive(Debug)]
struct FirstUseServerVerifier {
    standard: Arc<WebPkiServerVerifier>,
    pinned: Option<CertificateDer<'static>>,
    captured: Arc<Mutex<Option<CertificateDer<'static>>>>,
}

impl ServerCertVerifier for FirstUseServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Some(pinned) = self.pinned.as_ref() {
            if pinned.as_ref() != end_entity.as_ref() {
                return Err(rustls::Error::General(
                    "TLS host certificate changed from the trusted first-use value".into(),
                ));
            }
            return verify_with_exact_certificate(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            );
        }
        match self.standard.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => Ok(verified),
            Err(_) if certificate_is_self_signed(end_entity) => {
                let verified = verify_with_exact_certificate(
                    end_entity,
                    intermediates,
                    server_name,
                    ocsp_response,
                    now,
                )?;
                *self
                    .captured
                    .lock()
                    .map_err(|_| rustls::Error::General("TLS TOFU state poisoned".into()))? =
                    Some(CertificateDer::from(end_entity.as_ref().to_vec()));
                Ok(verified)
            }
            Err(error) => Err(error),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.standard.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.standard.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.standard.supported_verify_schemes()
    }
}

fn certificate_is_self_signed(certificate: &CertificateDer<'_>) -> bool {
    x509_parser::parse_x509_certificate(certificate.as_ref()).is_ok_and(|(_, certificate)| {
        certificate.subject() == certificate.issuer() && certificate.verify_signature(None).is_ok()
    })
}

fn verify_with_exact_certificate(
    end_entity: &CertificateDer<'_>,
    _intermediates: &[CertificateDer<'_>],
    server_name: &ServerName<'_>,
    _ocsp_response: &[u8],
    now: UnixTime,
) -> Result<ServerCertVerified, rustls::Error> {
    let (_, certificate) = x509_parser::parse_x509_certificate(end_entity.as_ref())
        .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
    let now = x509_parser::time::ASN1Time::from_timestamp(now.as_secs() as i64)
        .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
    if !certificate.validity().is_valid_at(now) {
        return Err(rustls::Error::InvalidCertificate(CertificateError::Expired));
    }
    if !certificate_matches_server_name(&certificate, server_name)? {
        return Err(rustls::Error::InvalidCertificate(
            CertificateError::NotValidForName,
        ));
    }
    Ok(ServerCertVerified::assertion())
}

fn certificate_matches_server_name(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
    server_name: &ServerName<'_>,
) -> Result<bool, rustls::Error> {
    use x509_parser::extensions::GeneralName;

    let alternative_names = certificate
        .subject_alternative_name()
        .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
    match server_name {
        ServerName::DnsName(expected) => {
            let expected = expected.as_ref().trim_end_matches('.').to_ascii_lowercase();
            if let Some(names) = alternative_names {
                return Ok(names.value.general_names.iter().any(|name| {
                    matches!(name, GeneralName::DNSName(candidate) if dns_name_matches(candidate, &expected))
                }));
            }
            Ok(certificate.subject().iter_common_name().any(|name| {
                name.as_str()
                    .is_ok_and(|candidate| dns_name_matches(candidate, &expected))
            }))
        }
        ServerName::IpAddress(expected) => {
            let expected = std::net::IpAddr::from(*expected);
            Ok(alternative_names.is_some_and(|names| {
                names.value.general_names.iter().any(|name| match name {
                    GeneralName::IPAddress(bytes) if bytes.len() == 4 => {
                        expected
                            == std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                                bytes[0], bytes[1], bytes[2], bytes[3],
                            ))
                    }
                    GeneralName::IPAddress(bytes) if bytes.len() == 16 => {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(bytes);
                        expected == std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
                    }
                    _ => false,
                })
            }))
        }
        _ => Ok(false),
    }
}

fn dns_name_matches(candidate: &str, expected: &str) -> bool {
    let candidate = candidate.trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = candidate.strip_prefix("*.") {
        return expected != suffix
            && expected.ends_with(&format!(".{suffix}"))
            && expected[..expected.len() - suffix.len() - 1]
                .find('.')
                .is_none();
    }
    candidate == expected
}

async fn connect_outbound_tls<S>(
    upstream: S,
    host: &str,
    port: u16,
    mitm: &TlsMitm,
    trust: Option<Arc<TrustStore>>,
    inbound_alpn: Option<&[u8]>,
) -> io::Result<tokio_rustls::client::TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS server name"))?;
    let captured = Arc::new(Mutex::new(None));
    let outbound_config = if let Some(trust) = trust.as_ref() {
        let material = trust.tls_material(host, port)?;
        let standard = WebPkiServerVerifier::builder(material.roots)
            .build()
            .map_err(io::Error::other)?;
        let verifier = Arc::new(FirstUseServerVerifier {
            standard,
            pinned: material.host_certificate,
            captured: captured.clone(),
        });
        let mut config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        config.alpn_protocols = match inbound_alpn {
            Some(b"h2") => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            Some(b"http/1.1") => vec![b"http/1.1".to_vec()],
            _ => Vec::new(),
        };
        Arc::new(config)
    } else {
        match inbound_alpn {
            Some(b"h2") => mitm.outbound.clone(),
            Some(b"http/1.1") => mitm.outbound_http1.clone(),
            _ => mitm.outbound_raw.clone(),
        }
    };
    let stream = TlsConnector::from(outbound_config)
        .connect(server_name, upstream)
        .await
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "upstream TLS handshake failed while validating the real target certificate: {error}"
                ),
            )
        })?;
    let first_seen = captured
        .lock()
        .map_err(|_| io::Error::other("TLS TOFU state poisoned"))?
        .take();
    if let (Some(trust), Some(certificate)) = (trust, first_seen) {
        let host = host.to_owned();
        tokio::task::spawn_blocking(move || trust.trust_tls_host(&host, port, &certificate))
            .await
            .map_err(io::Error::other)??;
    }
    Ok(stream)
}

async fn connect_outbound_through_client_proxy<S>(
    proxy: S,
    host: &str,
    port: u16,
    mitm: &TlsMitm,
    trust: Option<Arc<TrustStore>>,
    inbound_alpn: Option<&[u8]>,
) -> io::Result<tokio_rustls::client::TlsStream<BoxedStream>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    connect_outbound_tls(
        Box::new(proxy) as BoxedStream,
        host,
        port,
        mitm,
        trust,
        inbound_alpn,
    )
    .await
}

/// TLS 解密后的下钻：ALPN 已协商 HTTP 时直接进入 HTTP 层（h2/h1，与既有热路径
/// 一致）；无 ALPN 时读取解密前缀（消费）交给 `run_stack` 嗅探内层协议。
pub(crate) async fn serve_decrypted(
    client: BoxedStream,
    upstream: BoxedStream,
    inbound_alpn: Option<Vec<u8>>,
    inbound_h2: bool,
    outbound_h2: bool,
    depth: usize,
    outbound_origin_form: bool,
    inner: HandlerContext,
) -> io::Result<()> {
    match inbound_alpn.as_deref() {
        Some(b"h2") | Some(b"http/1.1") => {
            let sender = outbound_sender(upstream, outbound_h2).await?;
            serve_http(
                TokioIo::new(client),
                inbound_h2,
                sender,
                inner.config,
                inner.policy,
                inner.protection,
                inner.audit,
                inner.context,
                outbound_origin_form,
            )
            .await
        }
        _ => {
            let port = inner.context.destination.port;
            let mut client = client;
            let prefix = read_decrypted_prefix(&mut client, port).await?;
            run_stack(client, upstream, prefix, depth + 1, inner).await
        }
    }
}

async fn outbound_sender<U>(upstream: U, outbound_h2: bool) -> io::Result<RequestSender>
where
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if outbound_h2 {
        let (sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(upstream))
                .await
                .map_err(io::Error::other)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(RequestSender::Http2(sender))
    } else {
        let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(upstream))
            .await
            .map_err(io::Error::other)?;
        tokio::spawn(async move {
            let _ = connection.with_upgrades().await;
        });
        Ok(RequestSender::Http1(sender))
    }
}

/// 从解密流读取有界前缀（消费），供 `run_stack` 探测内层协议。
pub(crate) async fn read_decrypted_prefix<I>(client: &mut I, port: u16) -> io::Result<Vec<u8>>
where
    I: AsyncRead + Unpin,
{
    let mut prefix = Vec::with_capacity(1024);
    let _ = timeout(Duration::from_millis(300), async {
        let mut buffer = [0u8; 1024];
        loop {
            let count = client.read(&mut buffer).await?;
            if count == 0 {
                return Ok::<(), io::Error>(());
            }
            prefix.extend_from_slice(&buffer[..count]);
            if inspect::inspect(&prefix, port).protocol != Protocol::Unknown {
                return Ok(());
            }
            if prefix.len() >= 16 * 1024 || !could_be_protocol_prefix(&prefix) {
                return Ok(());
            }
        }
    })
    .await;
    Ok(prefix)
}

fn could_be_protocol_prefix(prefix: &[u8]) -> bool {
    if prefix.is_empty() {
        return true;
    }
    const METHODS: &[&[u8]] = &[
        b"GET", b"POST", b"PUT", b"PATCH", b"DELETE", b"HEAD", b"OPTIONS", b"CONNECT", b"TRACE",
    ];
    if METHODS.iter().any(|method| {
        if prefix.len() <= method.len() {
            method.starts_with(prefix)
        } else {
            prefix.starts_with(method) && prefix.get(method.len()) == Some(&b' ')
        }
    }) {
        return true;
    }
    // TLS record header：content type 0x14..=0x17 + 0x03。
    if matches!(prefix[0], 0x14..=0x17) && (prefix.len() == 1 || prefix[1] == 0x03) {
        return true;
    }
    // SSH banner 前缀。
    if prefix.len() <= 4 && b"SSH-".starts_with(prefix) {
        return true;
    }
    // git 原生 pkt-line 十六进制长度前缀。
    if prefix.len() <= 4 && prefix.iter().all(|byte| byte.is_ascii_hexdigit()) {
        return true;
    }
    false
}
pub(crate) async fn proxy_http<C, U>(
    client: C,
    upstream: U,
    inner: HandlerContext,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(upstream))
        .await
        .map_err(io::Error::other)?;
    tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });
    serve_http(
        TokioIo::new(client),
        false,
        RequestSender::Http1(sender),
        inner.config,
        inner.policy,
        inner.protection,
        inner.audit,
        inner.context,
        inner.upstream_tunneled,
    )
    .await
}

pub(crate) async fn proxy_https_via_http_proxy<C, U>(
    mut client: C,
    mut proxy: U,
    depth: usize,
    inner: HandlerContext,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let host = inner.host.clone();
    let request = read_http_head(&mut client).await?;
    let request_line = std::str::from_utf8(&request)
        .ok()
        .and_then(|value| value.lines().next())
        .unwrap_or("");
    if !request_line
        .split_whitespace()
        .next()
        .is_some_and(|method| method.eq_ignore_ascii_case("CONNECT"))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected HTTP CONNECT for HTTPS client proxy",
        ));
    }
    // 客户端 CONNECT 头原样转发给客户端代理（保留 Proxy-Authorization 等），
    // 代理响应原样中继给客户端；2xx 后对隧道做 TLS MITM，非 2xx 直接结束。
    // 外层 HTTP 代理协议端到端保留：serve 对原对端说的协议 = 客户端说的协议。
    proxy.write_all(&request).await?;
    proxy.flush().await?;
    let response = read_http_head(&mut proxy).await?;
    client.write_all(&response).await?;
    client.flush().await?;
    let status = std::str::from_utf8(&response)
        .ok()
        .and_then(|value| value.lines().next())
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(0);
    if !(200..300).contains(&status) {
        return Ok(());
    }
    let (client, inbound_alpn) = accept_client_tls(client, &host, &inner.mitm).await?;
    let inbound_h2 = inbound_alpn.as_deref() == Some(b"h2");
    let upstream = connect_outbound_through_client_proxy(
        proxy,
        &host,
        inner.context.destination.port,
        &inner.mitm,
        inner.trust.clone(),
        inbound_alpn.as_deref(),
    )
    .await?;
    let outbound_h2 = upstream.get_ref().1.alpn_protocol() == Some(b"h2");
    serve_decrypted(
        Box::new(client) as BoxedStream,
        Box::new(upstream) as BoxedStream,
        inbound_alpn,
        inbound_h2,
        outbound_h2,
        depth,
        inner.upstream_tunneled,
        inner,
    )
    .await
}

/// HTTP CONNECT 已由 HyperHub 自回 200：upstream 是配置 upstream 建立的隧道，
/// 直接对隧道做 TLS MITM，不再把 CONNECT 转发给原客户端代理。
pub(crate) async fn proxy_https_via_tunneled_upstream<C, U>(
    client: C,
    upstream: U,
    peek: Vec<u8>,
    inner: HandlerContext,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut client = PrefixedIo::new(Box::new(client) as BoxedStream, peek);
    let request = read_http_head(&mut client).await?;
    let request_line = std::str::from_utf8(&request)
        .ok()
        .and_then(|value| value.lines().next())
        .unwrap_or("");
    if !request_line
        .split_whitespace()
        .next()
        .is_some_and(|method| method.eq_ignore_ascii_case("CONNECT"))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected HTTP CONNECT for HTTPS client proxy",
        ));
    }
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    client.flush().await?;
    let (client, remaining) = client.into_parts();
    let client = PrefixedIo::new(client, remaining);
    let mitm = inner.decision.plugins.iter().any(|plugin| {
        plugin.protocols.contains(&PluginProtocol::Http)
            || plugin.protocols.contains(&PluginProtocol::Ws)
    }) || inner
        .decision
        .protection
        .as_deref()
        .is_some_and(|id| inner.protection.profile_enabled(id));
    if mitm {
        proxy_https(client, upstream, 0, inner).await
    } else {
        bridge(client, upstream, None).await?;
        Ok(())
    }
}

pub(crate) async fn read_http_head<S>(stream: &mut S) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut output = Vec::new();
    while !output.ends_with(b"\r\n\r\n") {
        if output.len() >= 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP proxy header exceeds 64 KiB",
            ));
        }
        output.push(stream.read_u8().await?);
    }
    Ok(output)
}

/// HTTP body 捕获（每连接一份）：请求/响应体经 `CaptureBody` 流式转发时有界落盘 JSONL。
/// 分层语义：仅捕获未升级的 HTTP body；升级（WebSocket / h2 extended CONNECT）后的
/// 数据归 WS 层，由 `websocket_capture` 独立决定，`capture_body` 不兜底。
#[derive(Clone)]
struct HttpBodyCapture {
    connection_id: u64,
    up_path: PathBuf,
    down_path: PathBuf,
    limit: usize,
    sequence: Arc<AtomicU64>,
    writes: Arc<Mutex<Vec<JoinHandle<io::Result<()>>>>>,
    transcripts: Arc<Mutex<Vec<TranscriptMetadata>>>,
    bytes_up: Arc<AtomicU64>,
    bytes_down: Arc<AtomicU64>,
    client_upload: bool,
    server_response: bool,
}

impl HttpBodyCapture {
    fn next_sequence(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// 落一条已完整到手的 body 记录（空 body 快速路径，无需流式包裹）。
    async fn record_body(
        &self,
        record: BodyRecord,
        bytes: Vec<u8>,
        size: u64,
        truncated: bool,
    ) -> io::Result<()> {
        let hash = format!("{:x}", Sha256::digest(&bytes));
        let (entry, transcript) = build_body_record(self, &record, &bytes, size, truncated, &hash);
        let mut line = serde_json::to_vec(&entry).map_err(io::Error::other)?;
        line.push(b'\n');
        append_body_record(self, &record, line, transcript, size).await
    }
}

/// 按审计 profile 构造连接级 body 捕获；未开启 `capture_body` 或未配置
/// `audit.transcript_dir` 时返回 `None`。
fn http_body_capture_config(
    config: &Config,
    profile: Option<&PluginConfig>,
    context: &ConnectionContext,
) -> Option<HttpBodyCapture> {
    let profile = profile?;
    if !profile.capture_body {
        return None;
    }
    let root = config.audit.transcript_dir.clone()?;
    let capture = CaptureConfig {
        root,
        date_key: crate::retention::date_key(crate::retention::unix_timestamp_ms()),
        limit: profile.body_limit,
        session_id: context.session_id.clone(),
        connection_id: context.connection_id,
        stream_id: Some(NEXT_BODY_CAPTURE_STREAM_ID.fetch_add(1, Ordering::Relaxed)),
        client_upload: profile.transcript_client_upload,
        server_response: profile.transcript_server_response,
    };
    let (up_path, down_path) = capture.transcript_paths("jsonl");
    let prepared = (|| {
        if capture.client_upload {
            prepare_transcript(&up_path)?;
        }
        if capture.server_response {
            prepare_transcript(&down_path)?;
        }
        Ok::<_, io::Error>(())
    })();
    if prepared.is_err() {
        return None;
    }
    Some(HttpBodyCapture {
        connection_id: context.connection_id,
        up_path,
        down_path,
        limit: profile.body_limit,
        sequence: Arc::new(AtomicU64::new(0)),
        writes: Arc::new(Mutex::new(Vec::new())),
        transcripts: Arc::new(Mutex::new(Vec::new())),
        bytes_up: Arc::new(AtomicU64::new(0)),
        bytes_down: Arc::new(AtomicU64::new(0)),
        client_upload: capture.client_upload,
        server_response: capture.server_response,
    })
}

/// 单条 body 捕获记录的元数据（请求与响应共用同一 sequence 互相关联）。
#[derive(Clone)]
struct BodyRecord {
    sequence: u64,
    direction: &'static str,
    method: String,
    path: String,
    http_version: String,
    status: Option<u16>,
    content_type: Option<String>,
}

/// 已启用捕获的 body 包裹状态：`capture` 共享落盘状态 + 本条记录元数据。
struct ActiveBodyCapture {
    capture: HttpBodyCapture,
    record: BodyRecord,
}

/// 单条 body 的捕获进度（`finish` 可能由 `is_end_stream`/`poll_frame` 触发，
/// 均只持有 `&self`，故用内部可变性保护）。
struct CaptureState {
    hash: Sha256,
    bytes: Vec<u8>,
    size: u64,
    truncated: bool,
    finished: bool,
}

/// 流式包裹 Body：转发数据帧的同时按 `body_limit` 有界捕获，body 结束时把记录
/// 追加到 `-up.jsonl`（请求）或 `-down.jsonl`（响应）。`active` 为 `None` 时
/// 纯透传（未启用捕获 / 升级请求 / 空 body 已直接落记录）。
/// 结束判定：hyper 在最后一个数据帧后检查 `is_end_stream()` 便不再 poll 到
/// `None`（Content-Length 场景），因此 `is_end_stream` 与 `poll_frame` 都触发
/// `finish`，由 `finished` 标志保证只落一次。
struct CaptureBody<B> {
    inner: B,
    active: Option<ActiveBodyCapture>,
    state: Mutex<CaptureState>,
}

impl<B> CaptureBody<B> {
    fn new(inner: B, active: Option<ActiveBodyCapture>) -> Self {
        Self {
            inner,
            active,
            state: Mutex::new(CaptureState {
                hash: Sha256::new(),
                bytes: Vec::new(),
                size: 0,
                truncated: false,
                finished: false,
            }),
        }
    }

    fn capture(&self, data: &[u8]) {
        let Some(active) = &self.active else {
            return;
        };
        let mut state = self.state.lock().unwrap();
        state.hash.update(data);
        state.size = state.size.saturating_add(data.len() as u64);
        let remaining = active.capture.limit.saturating_sub(state.bytes.len());
        let count = remaining.min(data.len());
        state.bytes.extend_from_slice(&data[..count]);
        if count < data.len() {
            state.truncated = true;
        }
    }

    fn finish(&self) {
        let mut state = self.state.lock().unwrap();
        if state.finished {
            return;
        }
        state.finished = true;
        let Some(active) = &self.active else {
            return;
        };
        let hash = format!("{:x}", state.hash.clone().finalize());
        let bytes = std::mem::take(&mut state.bytes);
        let (entry, transcript) = build_body_record(
            &active.capture,
            &active.record,
            &bytes,
            state.size,
            state.truncated,
            &hash,
        );
        let Ok(mut line) = serde_json::to_vec(&entry) else {
            return;
        };
        line.push(b'\n');
        let size = state.size;
        let capture = active.capture.clone();
        let record = active.record.clone();
        let handle = tokio::spawn(async move {
            append_body_record(&capture, &record, line, transcript, size).await
        });
        active.capture.writes.lock().unwrap().push(handle);
    }
}

impl<B> http_body::Body for CaptureBody<B>
where
    B: http_body::Body + Unpin + Send + 'static,
    B::Data: AsRef<[u8]>,
{
    type Data = B::Data;
    type Error = B::Error;

    fn is_end_stream(&self) -> bool {
        let end = self.inner.is_end_stream();
        if end {
            self.finish();
        }
        end
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let poll = Pin::new(&mut self.inner).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &poll {
            if let Some(data) = frame.data_ref() {
                self.capture(data.as_ref());
            }
            if self.inner.is_end_stream() {
                self.finish();
            }
        }
        if poll.is_ready() && matches!(&poll, Poll::Ready(None)) {
            self.finish();
        }
        poll
    }
}

fn build_body_record(
    capture: &HttpBodyCapture,
    record: &BodyRecord,
    bytes: &[u8],
    size: u64,
    truncated: bool,
    hash: &str,
) -> (Value, TranscriptMetadata) {
    let mut entry = Map::new();
    entry.insert(
        "ts".into(),
        json!(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64),
    );
    entry.insert("connection_id".into(), json!(capture.connection_id));
    entry.insert("sequence".into(), json!(record.sequence));
    entry.insert("direction".into(), json!(record.direction));
    entry.insert("method".into(), json!(record.method));
    entry.insert("path".into(), json!(record.path));
    entry.insert("http_version".into(), json!(record.http_version));
    if let Some(status) = record.status {
        entry.insert("status".into(), json!(status));
    }
    if let Some(content_type) = &record.content_type {
        entry.insert("content_type".into(), json!(content_type));
    }
    entry.insert("size".into(), json!(size));
    entry.insert("captured_size".into(), json!(bytes.len()));
    entry.insert("truncated".into(), json!(truncated));
    entry.insert("sha256".into(), json!(hash));
    if !bytes.is_empty() {
        entry.insert(
            "body".into(),
            json!(base64::engine::general_purpose::STANDARD.encode(bytes)),
        );
    }
    let path = if record.direction == "request" {
        capture.up_path.clone()
    } else {
        capture.down_path.clone()
    };
    let transcript = TranscriptMetadata {
        direction: record.direction,
        path,
        sha256: hash.to_string(),
        size,
        captured_size: bytes.len() as u64,
        truncated,
    };
    (Value::Object(entry), transcript)
}

async fn append_body_record(
    capture: &HttpBodyCapture,
    record: &BodyRecord,
    line: Vec<u8>,
    transcript: TranscriptMetadata,
    size: u64,
) -> io::Result<()> {
    let path = if record.direction == "request" {
        &capture.up_path
    } else {
        &capture.down_path
    };
    let mut file = tokio::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .await
        .map_err(io::Error::other)?;
    file.write_all(&line).await?;
    file.flush().await?;
    capture.transcripts.lock().unwrap().push(transcript);
    if record.direction == "request" {
        capture.bytes_up.fetch_add(size, Ordering::Relaxed);
    } else {
        capture.bytes_down.fetch_add(size, Ordering::Relaxed);
    }
    Ok(())
}

fn content_type_header(headers: &hyper::HeaderMap) -> Option<String> {
    headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

#[derive(Clone)]
struct ActiveResponseProtection {
    protection: Arc<ProtectionSnapshot>,
    state: ProtectionConnectionState,
    profile_id: String,
    audit: AuditWriter,
    context: ConnectionContext,
    rule_id: Option<String>,
    limit: usize,
    content_encoding: Option<String>,
}

struct ProtectionBody<B> {
    inner: B,
    active: Option<ActiveResponseProtection>,
    state: Mutex<ProtectionBodyState>,
}

struct ProtectionBodyState {
    hash: Sha256,
    bytes: Vec<u8>,
    size: u64,
    truncated: bool,
    finished: bool,
}

impl<B> ProtectionBody<B> {
    fn new(inner: B, active: Option<ActiveResponseProtection>) -> Self {
        Self {
            inner,
            active,
            state: Mutex::new(ProtectionBodyState {
                hash: Sha256::new(),
                bytes: Vec::new(),
                size: 0,
                truncated: false,
                finished: false,
            }),
        }
    }

    fn capture(&self, data: &[u8]) {
        let Some(active) = &self.active else {
            return;
        };
        let mut state = self.state.lock().expect("protection body mutex poisoned");
        state.hash.update(data);
        state.size = state.size.saturating_add(data.len() as u64);
        let remaining = active.limit.saturating_sub(state.bytes.len());
        let count = remaining.min(data.len());
        state.bytes.extend_from_slice(&data[..count]);
        if count < data.len() {
            state.truncated = true;
        }
    }

    fn finish(&self) {
        let Some(active) = &self.active else {
            return;
        };
        let mut state = self.state.lock().expect("protection body mutex poisoned");
        if state.finished {
            return;
        }
        state.finished = true;
        let full_hash = format!("{:x}", state.hash.clone().finalize());
        let raw = std::mem::take(&mut state.bytes);
        let size = state.size;
        let truncated = state.truncated;
        drop(state);
        let (decoded, unscannable, decode_truncated) =
            decode_for_scan(&raw, active.content_encoding.as_deref(), active.limit);
        if let Some((source_id, mut scan)) = active.protection.observe_response(
            &active.profile_id,
            &active.state,
            &decoded,
            size,
            truncated || decode_truncated,
        ) {
            scan.sha256 = full_hash;
            if unscannable {
                scan.add(FindingKind::UnscannableBody, 1);
            }
            active.audit.connection(
                "external_input_scanned",
                &active.context,
                active.rule_id.as_deref(),
                "observe",
                "scanned",
                None,
                None,
                Some(json!({
                    "protection": active.profile_id,
                    "source_id": source_id,
                    "findings": scan.findings,
                    "sha256": scan.sha256,
                    "size": size,
                    "scanned_size": scan.scanned_size,
                    "truncated": scan.truncated,
                    "unscannable": unscannable,
                })),
            );
        }
    }
}

impl<B> http_body::Body for ProtectionBody<B>
where
    B: http_body::Body + Unpin + Send + 'static,
    B::Data: AsRef<[u8]>,
{
    type Data = B::Data;
    type Error = B::Error;

    fn is_end_stream(&self) -> bool {
        let end = self.inner.is_end_stream();
        if end {
            self.finish();
        }
        end
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let poll = Pin::new(&mut self.inner).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &poll {
            if let Some(data) = frame.data_ref() {
                self.capture(data.as_ref());
            }
            if self.inner.is_end_stream() {
                self.finish();
            }
        }
        if matches!(&poll, Poll::Ready(None)) {
            self.finish();
        }
        poll
    }
}

fn empty_outbound_body() -> OutboundBody {
    Full::new(Bytes::new())
        .map_err(|never| match never {})
        .boxed_unsync()
}

fn full_outbound_body(bytes: Bytes) -> OutboundBody {
    Full::new(bytes)
        .map_err(|never| match never {})
        .boxed_unsync()
}

fn query_parameter_names(uri: &hyper::Uri) -> Vec<String> {
    let mut names = uri
        .query()
        .into_iter()
        .flat_map(|query| query.split('&'))
        .filter_map(|part| part.split_once('=').map(|(name, _)| name).or(Some(part)))
        .filter(|name| !name.is_empty())
        .map(|name| name.chars().take(64).collect::<String>())
        .collect::<Vec<_>>();
    names.sort_unstable();
    names.dedup();
    names.truncate(32);
    names
}

fn request_has_credentials(headers: &hyper::HeaderMap) -> bool {
    ["authorization", "proxy-authorization", "cookie"]
        .iter()
        .any(|name| headers.contains_key(*name))
}

fn content_length(headers: &hyper::HeaderMap) -> Option<u64> {
    headers
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}

fn content_encoding(headers: &hyper::HeaderMap) -> Option<String> {
    headers
        .get("content-encoding")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty() && value != "identity")
}

fn decode_for_scan(bytes: &[u8], encoding: Option<&str>, limit: usize) -> (Vec<u8>, bool, bool) {
    use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
    use std::io::Read as _;

    let Some(encoding) = encoding else {
        return (bytes.to_vec(), false, false);
    };
    let mut output = Vec::new();
    let result = match encoding {
        "gzip" => GzDecoder::new(bytes)
            .take(limit.saturating_add(1) as u64)
            .read_to_end(&mut output),
        "deflate" => ZlibDecoder::new(bytes)
            .take(limit.saturating_add(1) as u64)
            .read_to_end(&mut output)
            .or_else(|_| {
                output.clear();
                DeflateDecoder::new(bytes)
                    .take(limit.saturating_add(1) as u64)
                    .read_to_end(&mut output)
            }),
        _ => return (Vec::new(), true, false),
    };
    if result.is_err() {
        return (Vec::new(), true, false);
    }
    let truncated = output.len() > limit;
    output.truncate(limit);
    (output, false, truncated)
}

async fn serve_http<I>(
    io: TokioIo<I>,
    h2: bool,
    sender: RequestSender,
    config: Arc<Config>,
    policy: Arc<PolicySnapshot>,
    protection: Arc<ProtectionSnapshot>,
    audit: AuditWriter,
    context: ConnectionContext,
    outbound_origin_form: bool,
) -> io::Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let sender = Arc::new(AsyncMutex::new(sender));
    let body_capture: Arc<AsyncMutex<Option<HttpBodyCapture>>> = Arc::new(AsyncMutex::new(None));
    let service_audit = audit.clone();
    let service_context = context.clone();
    let protection_state = protection.connection_state();
    let service_body_capture = body_capture.clone();
    let origin_form = outbound_origin_form;
    let service = service_fn(move |request: Request<Incoming>| {
        let sender = sender.clone();
        let config = config.clone();
        let policy = policy.clone();
        let protection = protection.clone();
        let protection_state = protection_state.clone();
        let audit = service_audit.clone();
        let context = service_context.clone();
        let body_capture = service_body_capture.clone();
        let origin_form = origin_form;
        async move {
            let mut request_context = derive_request_context(&context, &request);
            let method = request.method().as_str().to_string();
            let path_and_query = request
                .uri()
                .path_and_query()
                .map(|value| value.as_str())
                .unwrap_or("/");
            let git_smart =
                crate::inspect::inspect_git_http(request.method().as_str(), path_and_query);
            let git_lfs = is_git_lfs_request(request.uri().path(), request.headers());
            let git_http = git_smart.is_some() || git_lfs;
            // git-over-http(s)：请求级协议精化为 Git，TLS 解密后 Git 规则仍能
            // 按请求命中，与普通 Web 请求（Http/Tls）区分，各自注入对应凭证。
            if git_http {
                request_context.protocol = Protocol::Git;
            }
            let decision = policy.decide_http(&request_context, path_and_query);
            let http_event_audit = decision.plugins.audit_for(PluginProtocol::Http).is_some();
            let ws_event_audit = decision.plugins.audit_for(PluginProtocol::Ws).is_some();
            let request_path = crate::audit::redact_path(request.uri().path()).to_string();
            let git = git_smart;
            let upgrade_protocol = requested_upgrade_protocol(&request);
            let is_upgrade =
                upgrade_protocol.is_some() || http2_subprotocol(&request) == Some("websocket");
            let query_names = query_parameter_names(request.uri());
            let original_content_type = content_type_header(request.headers());
            let original_content_length = content_length(request.headers());
            let original_content_encoding = content_encoding(request.headers());
            let credential_present = request_has_credentials(request.headers());
            let mut request = request.map(|body| {
                body.map_err(|error| io::Error::other(error.to_string()))
                    .boxed_unsync()
            });

            if decision.deny {
                if http_event_audit {
                    audit.connection(
                        "http_request",
                        &request_context,
                        decision.rule_id.as_deref(),
                        "deny",
                        "denied",
                        None,
                        None,
                        Some(json!({
                            "method": method,
                            "path": request_path,
                            "reason": "route_policy",
                        })),
                    );
                }
                return Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("content-type", "text/plain; charset=utf-8")
                    .body(full_body(b"request denied by HyperHub\n"))
                    .map_err(io::Error::other);
            }

            let protection_profile = decision
                .protection
                .as_deref()
                .filter(|id| protection.profile_enabled(id))
                .map(str::to_owned);
            let mut protection_scan = ScanResult::default();
            let mut body_complete = request.body().is_end_stream();
            let mut unscannable = false;
            if let Some(profile_id) = protection_profile.as_deref() {
                if !is_upgrade {
                    if let Some(limit) = protection.max_scan_bytes(profile_id) {
                        let known_size =
                            original_content_length.or_else(|| request.body().size_hint().exact());
                        if request.body().is_end_stream() {
                            protection_scan = protection.scan_request(
                                profile_id,
                                &protection_state,
                                &[],
                                known_size,
                                true,
                                false,
                            );
                        } else if known_size.is_some_and(|size| size <= limit as u64) {
                            let body = std::mem::replace(request.body_mut(), empty_outbound_body());
                            let collected = body.collect().await.map_err(io::Error::other)?;
                            let bytes = collected.to_bytes();
                            let (decoded, decode_failed, decode_truncated) = decode_for_scan(
                                &bytes,
                                original_content_encoding.as_deref(),
                                limit,
                            );
                            unscannable = decode_failed;
                            body_complete = !decode_truncated;
                            protection_scan = protection.scan_request(
                                profile_id,
                                &protection_state,
                                &decoded,
                                Some(bytes.len() as u64),
                                body_complete,
                                unscannable,
                            );
                            if decode_truncated {
                                protection_scan.add(FindingKind::OversizedBody, 1);
                            }
                            *request.body_mut() = full_outbound_body(bytes);
                        } else {
                            body_complete = false;
                            protection_scan = protection.scan_request(
                                profile_id,
                                &protection_state,
                                &[],
                                known_size,
                                false,
                                original_content_encoding.is_some(),
                            );
                            protection_scan.add(FindingKind::OversizedBody, 1);
                            unscannable = original_content_encoding.is_some();
                        }
                    }
                }

                let protection_request = ProtectionRequest {
                    context: request_context.clone(),
                    rule_id: decision.rule_id.clone(),
                    method: method.clone(),
                    host: request_context.destination.authority_host(),
                    path: request_path.clone(),
                    query_names: query_names.clone(),
                    content_type: original_content_type.clone(),
                    content_length: original_content_length,
                    credential_present,
                    allow_sensitive_upload: decision.allow_sensitive_upload,
                    body_complete,
                    unscannable,
                    scan: protection_scan.clone(),
                    stage: "http_request".into(),
                    command: Vec::new(),
                    features: Vec::new(),
                };
                if protection_scan.high_confidence_secret() {
                    audit.connection(
                        "sensitive_upload_detected",
                        &request_context,
                        decision.rule_id.as_deref(),
                        "inspect",
                        "detected",
                        None,
                        None,
                        Some(json!({
                            "protection": profile_id,
                            "findings": protection_scan.findings,
                            "sha256": protection_scan.sha256,
                            "scanned_size": protection_scan.scanned_size,
                            "allow_sensitive_upload": decision.allow_sensitive_upload,
                        })),
                    );
                }
                if protection_scan.provenance_matches > 0 {
                    audit.connection(
                        "provenance_match",
                        &request_context,
                        decision.rule_id.as_deref(),
                        "inspect",
                        "matched",
                        None,
                        None,
                        Some(json!({
                            "protection": profile_id,
                            "matches": protection_scan.provenance_matches,
                            "source_ids": protection_scan.source_ids,
                        })),
                    );
                }
                let outcome = protection.evaluate(profile_id, &protection_request).await;
                audit.connection(
                    "intelligent_protection_decision",
                    &request_context,
                    decision.rule_id.as_deref(),
                    if outcome.deny { "deny" } else { "pass" },
                    if outcome.would_deny {
                        "risk_detected"
                    } else {
                        "clear"
                    },
                    None,
                    None,
                    Some(json!({
                        "protection": profile_id,
                        "mode": protection.profile_mode(profile_id),
                        "findings": protection_scan.findings,
                        "sha256": protection_scan.sha256,
                        "scanned_size": protection_scan.scanned_size,
                        "total_size": protection_scan.total_size,
                        "truncated": protection_scan.truncated,
                        "provenance_matches": protection_scan.provenance_matches,
                        "source_ids": protection_scan.source_ids,
                        "local_deny": outcome.local_deny,
                        "would_deny": outcome.would_deny,
                        "reason": outcome.reason,
                        "input_sha256": outcome.input_sha256,
                        "providers": outcome.providers,
                    })),
                );
                if outcome.deny {
                    audit.connection(
                        "request_blocked",
                        &request_context,
                        decision.rule_id.as_deref(),
                        "deny",
                        "denied",
                        None,
                        None,
                        Some(json!({
                            "protection": profile_id,
                            "source": if outcome.local_deny { "data_protection" } else { "intelligence" },
                            "reason": outcome.reason,
                        })),
                    );
                    return Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .header("content-type", "text/plain; charset=utf-8")
                        .body(full_body(b"request denied by HyperHub\n"))
                        .map_err(io::Error::other);
                }
            }

            let credential = decision.plugins.credential_for(PluginProtocol::Http);
            let injected = resolve_credential_injection(credential, git_http)?;
            apply_credential_headers(request.headers_mut(), &injected);
            if let Some((name, value)) = &injected.cookie {
                inject_cookie(request.headers_mut(), name, value)?;
            }
            if let Some((name, value)) = &injected.query_parameter {
                inject_query_parameter(request.uri_mut(), name, value)?;
            }
            let mut injected_headers = injected
                .headers
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>();
            if injected.cookie.is_some() {
                injected_headers.push("cookie");
            }
            // 升级请求（WebSocket / h2 extended CONNECT）不归 HTTP body 捕获：
            // 升级后数据由 WS 层按 websocket_capture 独立决定，capture_body 不兜底。
            // 连接级捕获配置：首个请求按审计 profile 惰性初始化一次。
            let mut capture_guard = body_capture.lock().await;
            if capture_guard.is_none() {
                *capture_guard = http_body_capture_config(
                    &config,
                    decision.plugins.audit_for(PluginProtocol::Http),
                    &request_context,
                );
            }
            let capture = capture_guard.clone();
            drop(capture_guard);
            let capture_enabled = capture.is_some() && !is_upgrade;
            let capture_upload =
                capture_enabled && capture.as_ref().is_some_and(|value| value.client_upload);
            let capture_response =
                capture_enabled && capture.as_ref().is_some_and(|value| value.server_response);
            let detail = json!({
                "method": request.method().as_str(),
                "path": request_path,
                "http_version": format!("{:?}", request.version()),
                "http2_subprotocol": http2_subprotocol(&request),
                "upgrade_protocol": upgrade_protocol.as_deref(),
                "git": git.map(|(operation, repository)| json!({"operation": operation, "repository": repository})),
                "git_lfs": git_lfs,
                "injected_headers": injected_headers,
                "removed_headers": injected
                    .removed_headers
                    .iter()
                    .map(HeaderName::as_str)
                    .collect::<Vec<_>>(),
                "injected_query_parameter": injected.query_parameter.as_ref().map(|(name, _)| name),
                "injected_scheme": injected.scheme,
                "injected_authorization_len": injected
                    .headers
                    .iter()
                    .find(|(name, _)| name.as_str().eq_ignore_ascii_case("authorization"))
                    .map(|(_, value)| value.to_str().unwrap_or_default().len()),
                "audit_plugins": decision
                    .plugins
                    .iter()
                    .map(|plugin| plugin.id.as_str())
                    .collect::<Vec<_>>(),
                "protection": protection_profile.as_deref(),
                "body_capture": capture_enabled,
                "body_capture_client_upload": capture_upload,
                "body_capture_server_response": capture_response,
            });
            // 请求体捕获：包裹 body 流式转发并落盘；空 body 直接补一条空记录。
            let capture_sequence = capture
                .as_ref()
                .filter(|_| !is_upgrade)
                .map(HttpBodyCapture::next_sequence);
            let mut active = None;
            if let (Some(capture), Some(sequence)) = (capture.as_ref(), capture_sequence) {
                if capture.client_upload {
                    let record = BodyRecord {
                        sequence,
                        direction: "request",
                        method: request.method().as_str().to_string(),
                        path: request_path.clone(),
                        http_version: format!("{:?}", request.version()),
                        status: None,
                        content_type: content_type_header(request.headers()),
                    };
                    if request.body().is_end_stream() {
                        let _ = capture.record_body(record, Vec::new(), 0, false).await;
                    } else {
                        active = Some(ActiveBodyCapture {
                            capture: capture.clone(),
                            record,
                        });
                    }
                }
            }
            let body = std::mem::replace(request.body_mut(), empty_outbound_body());
            *request.body_mut() = CaptureBody::new(body, active).boxed_unsync();
            let upgrade_version = request.version();
            let client_upgrade = upgrade_protocol
                .as_ref()
                .map(|_| hyper::upgrade::on(&mut request));
            if http_event_audit {
                audit.connection(
                    "http_request",
                    &request_context,
                    decision.rule_id.as_deref(),
                    http_action_name(decision.deny),
                    "authorized",
                    None,
                    None,
                    Some(detail),
                );
            }
            if origin_form
                && request.uri().scheme().is_some()
                && request.uri().authority().is_some()
            {
                let path_and_query = request
                    .uri()
                    .path_and_query()
                    .map(|value| value.as_str())
                    .unwrap_or("/");
                let uri = hyper::Uri::builder()
                    .path_and_query(path_and_query)
                    .build()
                    .map_err(io::Error::other)?;
                *request.uri_mut() = uri;
                request.headers_mut().remove("proxy-authorization");
                request.headers_mut().remove("proxy-connection");
            }
            let response = sender
                .lock()
                .await
                .send(request)
                .await
                .map_err(|error| io::Error::other(error.to_string()))?;
            if http_event_audit {
                if let Some(challenge) = response
                    .headers()
                    .get("www-authenticate")
                    .and_then(|value| value.to_str().ok())
                {
                    audit.connection(
                        "http_auth_challenge",
                        &request_context,
                        decision.rule_id.as_deref(),
                        http_action_name(decision.deny),
                        "observed",
                        None,
                        None,
                        Some(json!({
                            "status": response.status().as_u16(),
                            "challenge": redact_auth_challenge(challenge),
                            "selected_scheme": injected.scheme,
                            "retried": false,
                        })),
                    );
                }
            }
            // 响应体捕获：与请求共用同一 sequence，便于两条记录互相关联。
            let mut response_active = None;
            if let (Some(capture), Some(sequence)) = (capture.as_ref(), capture_sequence) {
                if capture.server_response {
                    let record = BodyRecord {
                        sequence,
                        direction: "response",
                        method: method.clone(),
                        path: request_path,
                        http_version: format!("{:?}", response.version()),
                        status: Some(response.status().as_u16()),
                        content_type: content_type_header(response.headers()),
                    };
                    if response.body().is_end_stream() {
                        let _ = capture.record_body(record, Vec::new(), 0, false).await;
                    } else {
                        response_active = Some(ActiveBodyCapture {
                            capture: capture.clone(),
                            record,
                        });
                    }
                }
            }
            let response_protection = protection_profile.as_ref().and_then(|profile_id| {
                if is_upgrade {
                    return None;
                }
                protection
                    .max_scan_bytes(profile_id)
                    .map(|limit| ActiveResponseProtection {
                        protection: protection.clone(),
                        state: protection_state.clone(),
                        profile_id: profile_id.clone(),
                        audit: audit.clone(),
                        context: request_context.clone(),
                        rule_id: decision.rule_id.clone(),
                        limit,
                        content_encoding: content_encoding(response.headers()),
                    })
            });
            let mut response = response.map(|body| {
                ProtectionBody::new(CaptureBody::new(body, response_active), response_protection)
            });
            if let (Some(protocol), Some(client_upgrade)) = (upgrade_protocol, client_upgrade) {
                if accepts_upgrade(&response, upgrade_version, &protocol) {
                    let upstream_upgrade = hyper::upgrade::on(&mut response);
                    let rule_id = decision.rule_id.clone();
                    let action = http_action_name(decision.deny);
                    let capture = websocket_capture_config(
                        &config,
                        decision.plugins.audit_for(PluginProtocol::Ws),
                        &request_context,
                        &protocol,
                        response.headers(),
                    );
                    if ws_event_audit {
                        audit.connection(
                            "http_upgrade",
                            &request_context,
                            rule_id.as_deref(),
                            action,
                            "established",
                            None,
                            None,
                            Some(json!({"protocol": protocol})),
                        );
                    }
                    tokio::spawn(forward_http_upgrade(
                        client_upgrade,
                        upstream_upgrade,
                        audit.clone(),
                        request_context.clone(),
                        rule_id,
                        action,
                        protocol,
                        capture,
                        ws_event_audit,
                    ));
                }
            }
            Ok(response.map(|body| body.boxed_unsync()))
        }
    });
    let result = if h2 {
        let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
        builder.enable_connect_protocol();
        builder
            .serve_connection(io, service)
            .await
            .map_err(|error| io::Error::other(error.to_string()))
    } else {
        hyper::server::conn::http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(io, service)
            .with_upgrades()
            .await
            .map_err(|error| io::Error::other(error.to_string()))
    };
    // 连接结束：等待 body 捕获写盘任务完成后汇总一次审计事件。
    if let Some(capture) = body_capture.lock().await.take() {
        let writes = capture.writes.lock().unwrap().drain(..).collect::<Vec<_>>();
        let mut failed = false;
        for handle in writes {
            if handle.await.map_or(true, |result| result.is_err()) {
                failed = true;
            }
        }
        let transcripts = capture.transcripts.lock().unwrap().clone();
        if !transcripts.is_empty() || failed {
            audit.connection(
                "http_capture",
                &context,
                None,
                "proxy",
                if failed { "failed" } else { "completed" },
                Some((
                    capture.bytes_up.load(Ordering::Relaxed),
                    capture.bytes_down.load(Ordering::Relaxed),
                )),
                None,
                Some(json!({"transcripts": transcripts})),
            );
        }
    }
    result
}

fn requested_upgrade_protocol(request: &Request<Incoming>) -> Option<String> {
    if request.version() == Version::HTTP_11
        && header_contains_token(request.headers(), CONNECTION, "upgrade")
    {
        return request
            .headers()
            .get(UPGRADE)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase);
    }
    if request.version() == Version::HTTP_2 && request.method() == Method::CONNECT {
        return request
            .extensions()
            .get::<hyper::ext::Protocol>()
            .map(|protocol| protocol.as_str().to_ascii_lowercase());
    }
    None
}

/// HTTP/2 子协议审计标签：gRPC（`application/grpc` content-type）、WebSocket
/// （Extended CONNECT `:protocol`）、其余 RawBody。v1 只打标签，不做载荷解析。
fn http2_subprotocol<B>(request: &Request<B>) -> Option<&'static str> {
    if request.version() != Version::HTTP_2 {
        return None;
    }
    if request.method() == Method::CONNECT
        && request.extensions().get::<hyper::ext::Protocol>().is_some()
    {
        return Some("websocket");
    }
    if request
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/grpc"))
    {
        return Some("grpc");
    }
    Some("raw")
}

fn accepts_upgrade<B>(response: &Response<B>, version: Version, protocol: &str) -> bool {
    if version == Version::HTTP_2 {
        return response.status() == StatusCode::OK;
    }
    version == Version::HTTP_11
        && response.status() == StatusCode::SWITCHING_PROTOCOLS
        && header_contains_token(response.headers(), CONNECTION, "upgrade")
        && response.headers().get_all(UPGRADE).iter().any(|value| {
            value
                .to_str()
                .is_ok_and(|value| value.trim().eq_ignore_ascii_case(protocol))
        })
}

fn header_contains_token(headers: &hyper::HeaderMap, name: HeaderName, expected: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case(expected))
        })
    })
}

async fn forward_http_upgrade(
    client_upgrade: hyper::upgrade::OnUpgrade,
    upstream_upgrade: hyper::upgrade::OnUpgrade,
    audit: AuditWriter,
    context: ConnectionContext,
    rule_id: Option<String>,
    action: &'static str,
    protocol: String,
    capture: Option<UpgradeCapture>,
    record_event: bool,
) {
    let started = Instant::now();
    let result = async {
        let (client, upstream) =
            tokio::try_join!(client_upgrade, upstream_upgrade).map_err(io::Error::other)?;
        let client = TokioIo::new(client);
        let upstream = TokioIo::new(upstream);
        match capture {
            Some(UpgradeCapture::Frames(capture)) => bridge(client, upstream, Some(capture)).await,
            Some(UpgradeCapture::Messages {
                capture,
                compression,
            }) => websocket::bridge_messages(client, upstream, capture, compression).await,
            None => bridge(client, upstream, None).await,
        }
    }
    .await;
    if !record_event {
        return;
    }
    match result {
        Ok(result) => audit.connection(
            "http_upgrade",
            &context,
            rule_id.as_deref(),
            action,
            "completed",
            Some((result.bytes_up, result.bytes_down)),
            Some(started.elapsed().as_millis()),
            Some(json!({"protocol": protocol, "transcripts": result.transcripts})),
        ),
        Err(error) => audit.connection(
            "http_upgrade",
            &context,
            rule_id.as_deref(),
            action,
            "failed",
            None,
            Some(started.elapsed().as_millis()),
            Some(json!({"protocol": protocol, "message": error.to_string()})),
        ),
    }
}

fn websocket_capture_config(
    config: &Config,
    profile: Option<&PluginConfig>,
    context: &ConnectionContext,
    protocol: &str,
    response_headers: &hyper::HeaderMap,
) -> Option<UpgradeCapture> {
    if !protocol.eq_ignore_ascii_case("websocket") {
        return None;
    }
    let profile = profile?;
    if profile.websocket_capture == WebSocketCapture::Off {
        return None;
    }
    let capture = CaptureConfig {
        root: config.audit.transcript_dir.clone()?,
        date_key: crate::retention::date_key(crate::retention::unix_timestamp_ms()),
        limit: profile.body_limit,
        session_id: context.session_id.clone(),
        connection_id: context.connection_id,
        stream_id: Some(NEXT_UPGRADE_STREAM_ID.fetch_add(1, Ordering::Relaxed)),
        client_upload: profile.transcript_client_upload,
        server_response: profile.transcript_server_response,
    };
    match profile.websocket_capture {
        WebSocketCapture::Frames => Some(UpgradeCapture::Frames(capture)),
        WebSocketCapture::Messages => Some(UpgradeCapture::Messages {
            capture,
            compression: websocket_compression(response_headers),
        }),
        WebSocketCapture::Off => None,
    }
}

fn websocket_compression(headers: &hyper::HeaderMap) -> Compression {
    for value in headers.get_all("sec-websocket-extensions") {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for extension in value.split(',') {
            let mut parts = extension.split(';').map(str::trim);
            if !parts
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case("permessage-deflate"))
            {
                continue;
            }
            let mut compression = Compression {
                enabled: true,
                ..Compression::default()
            };
            for parameter in parts {
                let name = parameter
                    .split_once('=')
                    .map_or(parameter, |(name, _)| name)
                    .trim();
                if name.eq_ignore_ascii_case("client_no_context_takeover") {
                    compression.client_no_context_takeover = true;
                } else if name.eq_ignore_ascii_case("server_no_context_takeover") {
                    compression.server_no_context_takeover = true;
                }
            }
            return compression;
        }
    }
    Compression::default()
}

fn derive_request_context(
    connection: &ConnectionContext,
    request: &Request<Incoming>,
) -> ConnectionContext {
    let authority = request
        .uri()
        .authority()
        .map(|value| value.as_str())
        .or_else(|| {
            request
                .headers()
                .get(HOST)
                .and_then(|value| value.to_str().ok())
        });
    let Some((host, port)) = authority.and_then(parse_authority) else {
        return connection.clone();
    };
    let mut context = connection.clone();
    context.destination.hostnames = vec![host];
    if let Some(port) = port {
        context.destination.port = port;
    }
    context
}

fn parse_authority(value: &str) -> Option<(String, Option<u16>)> {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('[') {
        let (host, suffix) = rest.split_once(']')?;
        let port = if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':')?.parse().ok()?)
        };
        return (!host.is_empty()).then(|| (host.to_ascii_lowercase(), port));
    }
    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, Some(port.parse().ok()?)),
        _ => (value, None),
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some((host, port))
}

type HttpBody = UnsyncBoxBody<Bytes, hyper::Error>;

fn full_body(value: &'static [u8]) -> HttpBody {
    Full::new(Bytes::from_static(value))
        .map_err(|never| match never {})
        .boxed_unsync()
}

fn http_action_name(deny: bool) -> &'static str {
    if deny {
        "deny"
    } else {
        "proxy"
    }
}

#[derive(Default)]
struct CredentialInjection {
    headers: Vec<(HeaderName, HeaderValue)>,
    removed_headers: Vec<HeaderName>,
    cookie: Option<(String, String)>,
    query_parameter: Option<(String, String)>,
    scheme: Option<&'static str>,
}

fn resolve_credential_injection(
    plugin: Option<&PluginConfig>,
    git_http: bool,
) -> io::Result<CredentialInjection> {
    match plugin {
        Some(plugin) => resolve_credential(plugin, git_http),
        None => Ok(CredentialInjection::default()),
    }
}

fn resolve_credential(
    credential: &PluginConfig,
    git_http: bool,
) -> io::Result<CredentialInjection> {
    let (headers, removed_headers) = resolve_credential_headers(&credential.headers)?;
    let mut output = CredentialInjection {
        headers,
        removed_headers,
        ..CredentialInjection::default()
    };
    if let Some(scheme) = credential.http_scheme {
        if scheme == HttpAuthScheme::CustomHeaders {
            return Ok(output);
        }
        match scheme {
            HttpAuthScheme::Basic => {
                output.scheme = Some("basic");
                let username = credential
                    .username
                    .as_deref()
                    .ok_or_else(|| io::Error::other("HTTP Basic username is missing"))?;
                let password = resolve_http_secret(credential.password.as_ref())?;
                let encoded = base64::engine::general_purpose::STANDARD
                    .encode(format!("{username}:{password}"));
                output
                    .headers
                    .push(header("authorization", &format!("Basic {encoded}"))?);
            }
            HttpAuthScheme::Bearer => {
                output.scheme = Some("bearer");
                let secret = resolve_http_secret(credential.secret.as_ref())?;
                output
                    .headers
                    .push(header("authorization", &format!("Bearer {secret}"))?);
            }
            HttpAuthScheme::Token => {
                if git_http {
                    let secret = resolve_http_secret(credential.secret.as_ref())?;
                    output.scheme = Some("basic");
                    let username = credential
                        .username
                        .as_deref()
                        .ok_or_else(|| io::Error::other("HTTP scoped token username is missing"))?;
                    let encoded = base64::engine::general_purpose::STANDARD
                        .encode(format!("{username}:{secret}"));
                    output
                        .headers
                        .push(header("authorization", &format!("Basic {encoded}"))?);
                } else {
                    let secret = resolve_http_secret(credential.secret.as_ref())?;
                    output.scheme = Some("bearer");
                    output
                        .headers
                        .push(header("authorization", &format!("Bearer {secret}"))?);
                }
            }
            HttpAuthScheme::LegacyScopedToken => {
                return Err(io::Error::other(
                    "HTTP scoped_token is no longer supported; use token",
                ));
            }
            HttpAuthScheme::XApiKey => {
                output.scheme = Some("x_api_key");
                let secret = resolve_http_secret(credential.secret.as_ref())?;
                output.headers.push(header("x-api-key", &secret)?);
            }
            HttpAuthScheme::Cookie => {
                output.scheme = Some("cookie");
                output.cookie = Some((
                    credential
                        .http_name
                        .clone()
                        .ok_or_else(|| io::Error::other("HTTP cookie name is missing"))?,
                    resolve_http_secret(credential.secret.as_ref())?,
                ));
            }
            HttpAuthScheme::QueryParameter => {
                output.scheme = Some("query_parameter");
                output.query_parameter = Some((
                    credential
                        .http_name
                        .clone()
                        .ok_or_else(|| io::Error::other("HTTP query parameter name is missing"))?,
                    resolve_http_secret(credential.secret.as_ref())?,
                ));
            }
            HttpAuthScheme::CustomHeaders => unreachable!(),
        }
    }
    Ok(output)
}

fn apply_credential_headers(target: &mut hyper::HeaderMap, injection: &CredentialInjection) {
    for name in injection
        .removed_headers
        .iter()
        .chain(injection.headers.iter().map(|(name, _)| name))
    {
        target.remove(name);
    }
    for (name, value) in &injection.headers {
        target.insert(name.clone(), value.clone());
    }
}

fn is_git_lfs_request(path: &str, headers: &hyper::HeaderMap) -> bool {
    if path.ends_with("/info/lfs") || path.contains("/info/lfs/") {
        return true;
    }
    let lfs_media_type = |name: &str| {
        headers
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .any(|value| {
                value
                    .to_ascii_lowercase()
                    .contains("application/vnd.git-lfs")
            })
    };
    lfs_media_type("content-type")
        || lfs_media_type("accept")
        || headers
            .get("user-agent")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .trim_start()
                    .to_ascii_lowercase()
                    .starts_with("git-lfs/")
            })
}

fn redact_auth_challenge(value: &str) -> serde_json::Value {
    let scheme = value.split_whitespace().next().unwrap_or("");
    let realm = value.to_ascii_lowercase().find("realm=").map(|start| {
        let value = &value[start + "realm=".len()..];
        value
            .split(',')
            .next()
            .unwrap_or(value)
            .trim()
            .trim_matches('"')
    });
    json!({"scheme": scheme, "realm": realm})
}

fn resolve_http_secret(secret: Option<&SecretValue>) -> io::Result<String> {
    secret
        .ok_or_else(|| io::Error::other("HTTP credential secret is missing"))?
        .resolve()
        .map_err(io::Error::other)
}

fn header(name: &str, value: &str) -> io::Result<(HeaderName, HeaderValue)> {
    Ok((
        HeaderName::from_bytes(name.as_bytes()).map_err(io::Error::other)?,
        HeaderValue::from_str(value).map_err(io::Error::other)?,
    ))
}

fn inject_cookie(headers: &mut hyper::HeaderMap, name: &str, value: &str) -> io::Result<()> {
    if value
        .bytes()
        .any(|byte| byte <= 0x20 || byte == b';' || byte == 0x7f)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HTTP credential contains an invalid cookie value",
        ));
    }
    let existing = headers
        .get_all(COOKIE)
        .iter()
        .map(|current| current.to_str().map_err(io::Error::other))
        .collect::<io::Result<Vec<_>>>()?
        .join("; ");
    let mut cookies = existing
        .split(';')
        .map(str::trim)
        .filter(|cookie| !cookie.is_empty())
        .filter(|cookie| cookie.split_once('=').is_none_or(|(key, _)| key != name))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    cookies.push(format!("{name}={value}"));
    headers.insert(
        COOKIE,
        HeaderValue::from_str(&cookies.join("; ")).map_err(io::Error::other)?,
    );
    Ok(())
}

fn inject_query_parameter(uri: &mut hyper::Uri, name: &str, value: &str) -> io::Result<()> {
    let encoded_name = percent_encode(name);
    let encoded_value = percent_encode(value);
    let mut parameters = uri
        .query()
        .unwrap_or("")
        .split('&')
        .filter_map(|parameter| {
            let key = parameter.split_once('=').map_or(parameter, |(key, _)| key);
            (!parameter.is_empty() && key != encoded_name).then(|| parameter.to_owned())
        })
        .collect::<Vec<_>>();
    parameters.push(format!("{encoded_name}={encoded_value}"));
    let path_and_query = format!("{}?{}", uri.path(), parameters.join("&"));
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(path_and_query.parse().map_err(io::Error::other)?);
    *uri = hyper::Uri::from_parts(parts).map_err(io::Error::other)?;
    Ok(())
}

fn percent_encode(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            output.push(byte as char);
        } else {
            use std::fmt::Write;
            let _ = write!(output, "%{byte:02X}");
        }
    }
    output
}

fn resolve_credential_headers(
    headers: &HashMap<String, SecretValue>,
) -> io::Result<(Vec<(HeaderName, HeaderValue)>, Vec<HeaderName>)> {
    let mut output = Vec::with_capacity(headers.len());
    let mut removed = Vec::new();
    for (name, value) in headers {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(io::Error::other)?;
        let value = value.resolve().map_err(io::Error::other)?;
        if value.is_empty() {
            removed.push(name);
            continue;
        }
        let value = HeaderValue::from_str(&value).map_err(io::Error::other)?;
        output.push((name, value));
    }
    Ok((output, removed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        DataProtectionConfig, PluginConfig, PluginKind, PluginProtocol, ProtectionMode,
        ProtectionProfile, RouteEndpoint, RouteRule,
    };
    use crate::policy::{Destination, ProcessInfo, Protocol};
    use crate::session::SessionRegistry;
    use http_body_util::Empty;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};

    use crate::duplex::PrefixedIo;

    fn route_endpoints(targets: &[&str]) -> Vec<RouteEndpoint> {
        targets
            .iter()
            .map(|target| RouteEndpoint {
                target: (*target).into(),
                port: None,
            })
            .collect()
    }

    fn handler_context(
        host: &str,
        mitm: Arc<TlsMitm>,
        config: Arc<Config>,
        policy: Arc<PolicySnapshot>,
        context: ConnectionContext,
    ) -> HandlerContext {
        let decision = policy.decide(&context);
        HandlerContext {
            host: host.into(),
            mitm,
            ssh_mitm_key: Arc::new(crate::ssh_mitm::server_key_from_master(b"test")),
            protection: Arc::new(crate::protection::ProtectionSnapshot::compile(&config).unwrap()),
            config,
            policy,
            audit: AuditWriter::open(None).unwrap(),
            context,
            decision,
            sessions: SessionRegistry::default(),
            trust: None,
            upstream_tunneled: false,
        }
    }

    /// 命中 localhost 的 http 审计插件：使 TLS/HTTP 层在纯 `run_stack` 下仍被 MITM。
    fn mitm_config() -> Config {
        let mut config = Config::default();
        config.plugins.push(PluginConfig {
            uuid: crate::config::new_config_uuid(),
            id: "audit".into(),
            kind: PluginKind::Audit,
            protocols: vec![PluginProtocol::Http],
            ..PluginConfig::default()
        });
        config.rules.push(RouteRule {
            uuid: crate::config::new_config_uuid(),
            id: "mitm".into(),
            enabled: true,
            priority: 1,
            endpoints: route_endpoints(&["localhost"]),
            deny: false,
            rewrite_host: None,
            rewrite_port: None,
            upstream: None,
            plugins: vec!["audit".into()],
            legacy: Default::default(),
            protection: None,
            allow_sensitive_upload: false,
        });
        config
    }

    #[tokio::test]
    async fn outbound_trusts_imported_root_certificates() {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "HyperHub Test Root");
        let ca_certificate = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_certificate.pem(), ca_key).unwrap();

        let server_key = rcgen::KeyPair::generate().unwrap();
        let mut server_params =
            rcgen::CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
                .unwrap();
        server_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "localhost");
        server_params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
        let server_certificate = server_params.signed_by(&server_key, &issuer).unwrap();
        let server_config = std::sync::Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![server_certificate.der().clone()],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()),
                    ),
                )
                .unwrap(),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            for _ in 0..2 {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let _ = tokio_rustls::TlsAcceptor::from(server_config.clone())
                    .accept(stream)
                    .await;
            }
        });

        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let imported =
            TlsMitm::generate_with_root_certificates(vec![ca_certificate.der().clone()]).unwrap();
        let stream = TcpStream::connect(address).await.unwrap();
        let connected = timeout(Duration::from_secs(5), async {
            tokio_rustls::TlsConnector::from(imported.outbound.clone())
                .connect(server_name.clone(), stream)
                .await
        })
        .await
        .expect("outbound handshake with imported CA timed out");
        assert!(
            connected.is_ok(),
            "outbound must trust the imported CA: {connected:?}"
        );

        let plain = TlsMitm::generate().unwrap();
        let stream = TcpStream::connect(address).await.unwrap();
        let rejected = timeout(Duration::from_secs(5), async {
            tokio_rustls::TlsConnector::from(plain.outbound.clone())
                .connect(server_name, stream)
                .await
        })
        .await
        .expect("rejection handshake timed out");
        assert!(
            rejected.is_err(),
            "outbound without the imported CA must reject the private CA"
        );
    }

    #[tokio::test]
    async fn client_connect_is_forwarded_to_the_http_proxy_before_tls_mitm() {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "HyperHub Via-Proxy Test Root");
        let ca_certificate = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_certificate.pem(), ca_key).unwrap();

        let server_key = rcgen::KeyPair::generate().unwrap();
        let mut server_params =
            rcgen::CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
                .unwrap();
        server_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "localhost");
        server_params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
        let server_certificate = server_params.signed_by(&server_key, &issuer).unwrap();
        let server_config = std::sync::Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![server_certificate.der().clone()],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()),
                    ),
                )
                .unwrap(),
        );

        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_server = tokio::spawn(async move {
            let (stream, _) = origin.accept().await.unwrap();
            let mut tls = tokio_rustls::TlsAcceptor::from(server_config)
                .accept(stream)
                .await
                .unwrap();
            let mut buffer = [0u8; 16];
            if let Ok(count) = tls.read(&mut buffer).await {
                let _ = tls.write_all(&buffer[..count]).await;
            }
            let _ = tls.shutdown().await;
        });

        let fake_proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = fake_proxy.local_addr().unwrap();
        let fake_proxy_task = tokio::spawn(async move {
            let (mut proxy_side, _) = fake_proxy.accept().await.unwrap();
            let request = read_headers(&mut proxy_side).await;
            let request = String::from_utf8(request).unwrap();
            assert!(
                request.starts_with("CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n"),
                "client CONNECT must arrive verbatim: {request}"
            );
            assert!(
                request.contains("Proxy-Authorization: Basic dXNlcjpwYXNz"),
                "CONNECT headers must be preserved: {request}"
            );
            let mut origin_side = TcpStream::connect(origin_address).await.unwrap();
            proxy_side
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let _ = tokio::io::copy_bidirectional(&mut proxy_side, &mut origin_side).await;
        });

        let pair = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_address = pair.local_addr().unwrap();
        let mut git_side = TcpStream::connect(client_address).await.unwrap();
        let (serve_side, _) = pair.accept().await.unwrap();
        let upstream = TcpStream::connect(proxy_address).await.unwrap();

        let mitm =
            TlsMitm::generate_with_root_certificates(vec![ca_certificate.der().clone()]).unwrap();
        let client_mitm = mitm.clone();
        let config = Arc::new(Config::default());
        let policy = Arc::new(PolicySnapshot::compile(&config).unwrap());
        let context = ConnectionContext {
            session_id: "test".into(),
            connection_id: 1,
            process: ProcessInfo {
                pid: 1,
                tid: 1,
                executable: "git".into(),
            },
            destination: Destination {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 443,
                hostnames: vec!["localhost".into()],
            },
            protocol: Protocol::Tls,
        };
        let serve_task = tokio::spawn(async move {
            proxy_https_via_http_proxy(
                serve_side,
                upstream,
                0,
                handler_context("localhost", mitm, config, policy, context),
            )
            .await
        });

        git_side
            .write_all(
                b"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            git_side.read_exact(&mut byte).await.unwrap();
            response.push(byte[0]);
        }
        let response = String::from_utf8(response).unwrap();
        assert!(
            response.contains("HTTP/1.1 200 Connection Established"),
            "upstream proxy response must be relayed: {response}"
        );

        let mut client_roots = RootCertStore::empty();
        client_roots.add(client_mitm.ca_der.clone()).unwrap();
        let client_config = std::sync::Arc::new(
            ClientConfig::builder()
                .with_root_certificates(client_roots)
                .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("localhost").unwrap();
        let mut client_tls = timeout(Duration::from_secs(5), async {
            tokio_rustls::TlsConnector::from(client_config)
                .connect(server_name, git_side)
                .await
        })
        .await
        .expect("client TLS MITM handshake timed out")
        .expect("client TLS MITM handshake failed");

        client_tls.write_all(b"ping").await.unwrap();
        let mut echo = [0u8; 4];
        timeout(Duration::from_secs(5), client_tls.read_exact(&mut echo))
            .await
            .expect("echo timed out")
            .unwrap();
        assert_eq!(&echo, b"ping");
        drop(client_tls);

        match serve_task.await.unwrap() {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::BrokenPipe
                ) => {}
            Err(error) => panic!("unexpected proxy error: {error}"),
        }
        fake_proxy_task.await.unwrap();
        origin_server.await.unwrap();
    }

    #[tokio::test]
    async fn tunneled_upstream_serves_http_connect_without_original_proxy() {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        ca_params.distinguished_name.push(
            rcgen::DnType::CommonName,
            "HyperHub Tunneled CONNECT Test Root",
        );
        let ca_certificate = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_certificate.pem(), ca_key).unwrap();

        let server_key = rcgen::KeyPair::generate().unwrap();
        let mut server_params =
            rcgen::CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
                .unwrap();
        server_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "localhost");
        server_params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
        let server_certificate = server_params.signed_by(&server_key, &issuer).unwrap();
        let server_config = std::sync::Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![server_certificate.der().clone()],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()),
                    ),
                )
                .unwrap(),
        );

        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_server = tokio::spawn(async move {
            let (stream, _) = origin.accept().await.unwrap();
            let mut tls = tokio_rustls::TlsAcceptor::from(server_config)
                .accept(stream)
                .await
                .unwrap();
            let mut buffer = [0u8; 16];
            if let Ok(count) = tls.read(&mut buffer).await {
                let _ = tls.write_all(&buffer[..count]).await;
            }
            let _ = tls.shutdown().await;
        });

        let pair = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_address = pair.local_addr().unwrap();
        let mut client = TcpStream::connect(client_address).await.unwrap();
        client
            .write_all(
                b"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n",
            )
            .await
            .unwrap();
        let (mut serve_side, _) = pair.accept().await.unwrap();
        let connect_head = read_http_head(&mut serve_side).await.unwrap();
        let upstream = TcpStream::connect(origin_address).await.unwrap();

        let mitm =
            TlsMitm::generate_with_root_certificates(vec![ca_certificate.der().clone()]).unwrap();
        let client_mitm = mitm.clone();
        let config = Arc::new(mitm_config());
        let policy = Arc::new(PolicySnapshot::compile(&config).unwrap());
        let context = ConnectionContext {
            session_id: "tunneled-connect".into(),
            connection_id: 1,
            process: ProcessInfo {
                pid: 1,
                tid: 1,
                executable: "fixture".into(),
            },
            destination: Destination {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: origin_address.port(),
                hostnames: vec!["localhost".into()],
            },
            protocol: Protocol::Tls,
        };
        let inner = handler_context("localhost", mitm, config, policy, context);
        let serve_task = tokio::spawn(async move {
            proxy_https_via_tunneled_upstream(serve_side, upstream, connect_head, inner).await
        });

        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            client.read_exact(&mut byte).await.unwrap();
            response.push(byte[0]);
        }
        assert!(String::from_utf8(response)
            .unwrap()
            .contains("HTTP/1.1 200 Connection Established"));

        let mut client_roots = RootCertStore::empty();
        client_roots.add(client_mitm.ca_der.clone()).unwrap();
        let client_config = std::sync::Arc::new(
            ClientConfig::builder()
                .with_root_certificates(client_roots)
                .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("localhost").unwrap();
        let mut client_tls = timeout(Duration::from_secs(5), async {
            tokio_rustls::TlsConnector::from(client_config)
                .connect(server_name, client)
                .await
        })
        .await
        .expect("client TLS MITM handshake timed out")
        .expect("client TLS MITM handshake failed");

        client_tls.write_all(b"ping").await.unwrap();
        let mut echo = [0u8; 4];
        timeout(Duration::from_secs(5), client_tls.read_exact(&mut echo))
            .await
            .expect("echo timed out")
            .unwrap();
        assert_eq!(&echo, b"ping");
        drop(client_tls);

        match serve_task.await.unwrap() {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::BrokenPipe
                ) => {}
            Err(error) => panic!("unexpected proxy error: {error}"),
        }
        origin_server.await.unwrap();
    }

    #[tokio::test]
    async fn run_stack_mitms_http_connect_through_client_proxy() {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        ca_params.distinguished_name.push(
            rcgen::DnType::CommonName,
            "HyperHub Stack CONNECT Test Root",
        );
        let ca_certificate = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_certificate.pem(), ca_key).unwrap();

        let server_key = rcgen::KeyPair::generate().unwrap();
        let mut server_params =
            rcgen::CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
                .unwrap();
        server_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "localhost");
        server_params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
        let server_certificate = server_params.signed_by(&server_key, &issuer).unwrap();
        let server_config = std::sync::Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![server_certificate.der().clone()],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()),
                    ),
                )
                .unwrap(),
        );

        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_server = tokio::spawn(async move {
            let (stream, _) = origin.accept().await.unwrap();
            let mut tls = tokio_rustls::TlsAcceptor::from(server_config)
                .accept(stream)
                .await
                .unwrap();
            let mut buffer = [0u8; 16];
            if let Ok(count) = tls.read(&mut buffer).await {
                let _ = tls.write_all(&buffer[..count]).await;
            }
            let _ = tls.shutdown().await;
        });

        let fake_proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = fake_proxy.local_addr().unwrap();
        let fake_proxy_task = tokio::spawn(async move {
            let (mut proxy_side, _) = fake_proxy.accept().await.unwrap();
            let request = read_headers(&mut proxy_side).await;
            let request = String::from_utf8(request).unwrap();
            assert!(
                request.starts_with("CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n"),
                "client CONNECT must arrive verbatim: {request}"
            );
            assert!(
                request.contains("Proxy-Authorization: Basic dXNlcjpwYXNz"),
                "CONNECT headers must be preserved: {request}"
            );
            let mut origin_side = TcpStream::connect(origin_address).await.unwrap();
            proxy_side
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let _ = tokio::io::copy_bidirectional(&mut proxy_side, &mut origin_side).await;
        });

        let pair = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_address = pair.local_addr().unwrap();
        let mut git_side = TcpStream::connect(client_address).await.unwrap();
        let (mut serve_side, _) = pair.accept().await.unwrap();
        let upstream = TcpStream::connect(proxy_address).await.unwrap();

        let mitm =
            TlsMitm::generate_with_root_certificates(vec![ca_certificate.der().clone()]).unwrap();
        let client_mitm = mitm.clone();
        let config = Arc::new(mitm_config());
        let policy = Arc::new(PolicySnapshot::compile(&config).unwrap());
        let context = ConnectionContext {
            session_id: "stack-connect".into(),
            connection_id: 1,
            process: ProcessInfo {
                pid: 1,
                tid: 1,
                executable: "git".into(),
            },
            destination: Destination {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 443,
                hostnames: vec!["localhost".into()],
            },
            protocol: Protocol::Tls,
        };
        let serve_task = tokio::spawn(async move {
            // 已消费的 CONNECT 头作为栈首包入栈：HttpConnectLayer 探测命中后
            // 原样转发、响应中继、2xx 后 TLS MITM 并下钻（深度 0 → 1）。
            let payload = read_headers(&mut serve_side).await;
            run_stack(
                Box::new(serve_side),
                Box::new(upstream),
                payload,
                0,
                handler_context("localhost", mitm, config, policy, context),
            )
            .await
        });

        git_side
            .write_all(
                b"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            git_side.read_exact(&mut byte).await.unwrap();
            response.push(byte[0]);
        }
        let response = String::from_utf8(response).unwrap();
        assert!(
            response.contains("HTTP/1.1 200 Connection Established"),
            "upstream proxy response must be relayed: {response}"
        );

        let mut client_roots = RootCertStore::empty();
        client_roots.add(client_mitm.ca_der.clone()).unwrap();
        let client_config = std::sync::Arc::new(
            ClientConfig::builder()
                .with_root_certificates(client_roots)
                .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("localhost").unwrap();
        let mut client_tls = timeout(Duration::from_secs(5), async {
            tokio_rustls::TlsConnector::from(client_config)
                .connect(server_name, git_side)
                .await
        })
        .await
        .expect("client TLS MITM handshake timed out")
        .expect("client TLS MITM handshake failed");

        client_tls.write_all(b"ping").await.unwrap();
        let mut echo = [0u8; 4];
        timeout(Duration::from_secs(5), client_tls.read_exact(&mut echo))
            .await
            .expect("echo timed out")
            .unwrap();
        assert_eq!(&echo, b"ping");
        drop(client_tls);

        match serve_task.await.unwrap() {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::BrokenPipe
                ) => {}
            Err(error) => panic!("unexpected proxy error: {error}"),
        }
        fake_proxy_task.await.unwrap();
        origin_server.await.unwrap();
    }

    #[tokio::test]
    async fn client_proxy_dead_tunnel_fails_without_direct_fallback() {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "HyperHub Dead-Tunnel Test Root");
        let ca_certificate = ca_params.self_signed(&ca_key).unwrap();

        // 直连目标监听器：serve 不得在客户端代理隧道死亡后静默直连它。
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_port = origin.local_addr().unwrap().port();

        // 假客户端代理：读到 CONNECT 后回 200，随即关闭连接模拟死亡隧道。
        let fake_proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = fake_proxy.local_addr().unwrap();
        let fake_proxy_task = tokio::spawn(async move {
            let (mut proxy_side, _) = fake_proxy.accept().await.unwrap();
            let request = read_headers(&mut proxy_side).await;
            assert!(
                String::from_utf8(request)
                    .unwrap()
                    .starts_with("CONNECT localhost:"),
                "client CONNECT must arrive at the proxy"
            );
            proxy_side
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let _ = proxy_side.shutdown().await;
        });

        let pair = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_address = pair.local_addr().unwrap();
        let mut git_side = TcpStream::connect(client_address).await.unwrap();
        let (serve_side, _) = pair.accept().await.unwrap();
        let upstream = TcpStream::connect(proxy_address).await.unwrap();

        let mitm =
            TlsMitm::generate_with_root_certificates(vec![ca_certificate.der().clone()]).unwrap();
        let client_mitm = mitm.clone();
        let config = Arc::new(Config::default());
        let policy = Arc::new(PolicySnapshot::compile(&config).unwrap());
        let context = ConnectionContext {
            session_id: "test".into(),
            connection_id: 1,
            process: ProcessInfo {
                pid: 1,
                tid: 1,
                executable: "git".into(),
            },
            destination: Destination {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: origin_port,
                hostnames: vec!["localhost".into()],
            },
            protocol: Protocol::Tls,
        };
        let serve_task = tokio::spawn(async move {
            proxy_https_via_http_proxy(
                serve_side,
                upstream,
                0,
                handler_context("localhost", mitm, config, policy, context),
            )
            .await
        });

        git_side
            .write_all(
                format!(
                    "CONNECT localhost:{origin_port} HTTP/1.1\r\nHost: localhost:{origin_port}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            git_side.read_exact(&mut byte).await.unwrap();
            response.push(byte[0]);
        }
        assert!(
            String::from_utf8(response)
                .unwrap()
                .contains("HTTP/1.1 200 Connection Established"),
            "proxy response must be relayed to the client"
        );

        let mut client_roots = RootCertStore::empty();
        client_roots.add(client_mitm.ca_der.clone()).unwrap();
        let client_config = std::sync::Arc::new(
            ClientConfig::builder()
                .with_root_certificates(client_roots)
                .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("localhost").unwrap();
        let client_tls = timeout(Duration::from_secs(5), async {
            tokio_rustls::TlsConnector::from(client_config)
                .connect(server_name, git_side)
                .await
        })
        .await
        .expect("client TLS MITM handshake timed out")
        .expect("client TLS MITM handshake failed");

        // 假代理隧道已死：serve 必须干净失败，绝不静默直连 CONNECT 目标重建 TLS。
        let serve_error = serve_task
            .await
            .unwrap()
            .expect_err("dead client proxy tunnel must fail cleanly");
        assert!(
            serve_error
                .to_string()
                .contains("upstream TLS handshake failed"),
            "error must surface the failed client proxy TLS path: {serve_error}"
        );
        drop(client_tls);

        // origin 不应收到任何直连连接。
        let origin_accept = timeout(Duration::from_millis(300), origin.accept()).await;
        assert!(
            matches!(origin_accept, Err(_)),
            "serve must not fall back to a direct connection"
        );
        fake_proxy_task.await.unwrap();
    }

    #[tokio::test]
    async fn http_proxy_authentication_failure_is_relayed_to_the_client() {
        let fake_proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = fake_proxy.local_addr().unwrap();
        let fake_proxy_task = tokio::spawn(async move {
            let (mut proxy_side, _) = fake_proxy.accept().await.unwrap();
            let request = read_headers(&mut proxy_side).await;
            assert!(
                String::from_utf8_lossy(&request).starts_with("CONNECT "),
                "proxy must receive the forwarded CONNECT"
            );
            proxy_side
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"hyperhub\"\r\n\r\n",
                )
                .await
                .unwrap();
        });

        let pair = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_address = pair.local_addr().unwrap();
        let mut git_side = TcpStream::connect(client_address).await.unwrap();
        let (serve_side, _) = pair.accept().await.unwrap();
        let upstream = TcpStream::connect(proxy_address).await.unwrap();

        let mitm = TlsMitm::generate().unwrap();
        let config = Arc::new(Config::default());
        let policy = Arc::new(PolicySnapshot::compile(&config).unwrap());
        let context = ConnectionContext {
            session_id: "test".into(),
            connection_id: 1,
            process: ProcessInfo {
                pid: 1,
                tid: 1,
                executable: "git".into(),
            },
            destination: Destination {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 443,
                hostnames: vec!["localhost".into()],
            },
            protocol: Protocol::Tls,
        };
        let serve_task = tokio::spawn(async move {
            proxy_https_via_http_proxy(
                serve_side,
                upstream,
                0,
                handler_context("localhost", mitm, config, policy, context),
            )
            .await
        });

        git_side
            .write_all(b"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            git_side.read_exact(&mut byte).await.unwrap();
            response.push(byte[0]);
        }
        let response = String::from_utf8(response).unwrap();
        assert!(
            response.contains(" 407 "),
            "proxy 407 must be relayed to the client: {response}"
        );
        assert!(
            response.contains("Proxy-Authenticate"),
            "proxy 407 headers must be relayed: {response}"
        );
        assert!(serve_task.await.unwrap().is_ok());
        fake_proxy_task.await.unwrap();
    }
    async fn read_headers<S>(stream: &mut S) -> Vec<u8>
    where
        S: AsyncRead + Unpin,
    {
        let mut output = Vec::new();
        while !output.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            output.push(byte[0]);
        }
        output
    }

    #[test]
    fn resolves_bearer_and_custom_headers() {
        let credential = PluginConfig {
            uuid: crate::config::new_config_uuid(),
            id: "api".into(),
            kind: PluginKind::Credential,
            protocols: vec![PluginProtocol::Http],
            http_scheme: Some(HttpAuthScheme::Bearer),
            secret: Some(SecretValue::Inline {
                value: "token".into(),
            }),
            headers: HashMap::from([(
                "X-Tenant".into(),
                SecretValue::Inline {
                    value: "tenant-1".into(),
                },
            )]),
            ..PluginConfig::default()
        };
        let injection = resolve_credential(&credential, false).unwrap();
        assert!(injection
            .headers
            .iter()
            .any(|(name, value)| name == "authorization" && value == "Bearer token"));
        assert!(injection
            .headers
            .iter()
            .any(|(name, value)| name == "x-tenant" && value == "tenant-1"));
    }

    #[test]
    fn resolves_x_api_key_header() {
        let credential = PluginConfig {
            uuid: crate::config::new_config_uuid(),
            id: "api".into(),
            kind: PluginKind::Credential,
            protocols: vec![PluginProtocol::Http],
            http_scheme: Some(HttpAuthScheme::XApiKey),
            secret: Some(SecretValue::Inline {
                value: "api-key".into(),
            }),
            ..PluginConfig::default()
        };
        let injection = resolve_credential(&credential, false).unwrap();
        assert_eq!(injection.headers.len(), 1);
        assert_eq!(injection.headers[0].0, "x-api-key");
        assert_eq!(injection.headers[0].1, "api-key");
    }

    #[test]
    fn resolves_http_basic_from_username_and_password() {
        let credential = PluginConfig {
            uuid: crate::config::new_config_uuid(),
            id: "basic".into(),
            kind: PluginKind::Credential,
            protocols: vec![PluginProtocol::Http],
            http_scheme: Some(HttpAuthScheme::Basic),
            username: Some("user".into()),
            password: Some(SecretValue::Inline {
                value: "pass".into(),
            }),
            ..PluginConfig::default()
        };
        let injection = resolve_credential(&credential, false).unwrap();
        assert_eq!(injection.headers.len(), 1);
        assert_eq!(injection.headers[0].0, "authorization");
        assert_eq!(injection.headers[0].1, "Basic dXNlcjpwYXNz");
    }

    #[test]
    fn token_selects_bearer_for_http_and_basic_for_git() {
        let credential = PluginConfig {
            uuid: crate::config::new_config_uuid(),
            id: "project".into(),
            kind: PluginKind::Credential,
            protocols: vec![PluginProtocol::Http],
            http_scheme: Some(HttpAuthScheme::Token),
            username: Some("project_bot".into()),
            secret: Some(SecretValue::Inline {
                value: "token".into(),
            }),
            headers: HashMap::from([
                (
                    "PRIVATE-TOKEN".into(),
                    SecretValue::Inline {
                        value: String::new(),
                    },
                ),
                (
                    "X-Tenant".into(),
                    SecretValue::Inline {
                        value: "trusted".into(),
                    },
                ),
            ]),
            ..PluginConfig::default()
        };
        let bearer = resolve_credential(&credential, false).unwrap();
        assert!(bearer
            .headers
            .iter()
            .any(|(name, value)| name == "authorization" && value == "Bearer token"));
        assert!(bearer
            .headers
            .iter()
            .any(|(name, value)| name == "x-tenant" && value == "trusted"));
        assert_eq!(bearer.removed_headers, ["private-token"]);
        assert_eq!(bearer.scheme, Some("bearer"));
        let basic = resolve_credential(&credential, true).unwrap();
        assert!(basic.headers.iter().any(|(name, value)| {
            name == "authorization" && value == "Basic cHJvamVjdF9ib3Q6dG9rZW4="
        }));
        assert_eq!(basic.removed_headers, ["private-token"]);
        assert_eq!(basic.scheme, Some("basic"));
    }

    #[test]
    fn credential_headers_remove_or_replace_client_values_deterministically() {
        let mut target = hyper::HeaderMap::new();
        target.insert("authorization", HeaderValue::from_static("Bearer invalid"));
        target.insert("private-token", HeaderValue::from_static("invalid"));
        target.insert("x-tenant", HeaderValue::from_static("untrusted"));
        let injection = CredentialInjection {
            headers: vec![
                header("x-tenant", "trusted").unwrap(),
                header("authorization", "Bearer trusted").unwrap(),
            ],
            removed_headers: vec![HeaderName::from_static("private-token")],
            ..CredentialInjection::default()
        };

        apply_credential_headers(&mut target, &injection);

        assert_eq!(target["authorization"], "Bearer trusted");
        assert_eq!(target["x-tenant"], "trusted");
        assert!(!target.contains_key("private-token"));

        target.insert("private-token", HeaderValue::from_static("client-kept"));
        let without_removal = CredentialInjection {
            headers: vec![header("authorization", "Bearer trusted").unwrap()],
            ..CredentialInjection::default()
        };
        apply_credential_headers(&mut target, &without_removal);
        assert_eq!(target["private-token"], "client-kept");
    }

    #[test]
    fn detects_git_lfs_by_path_media_type_and_user_agent() {
        let empty = hyper::HeaderMap::new();
        assert!(is_git_lfs_request(
            "/group/project.git/info/lfs/objects/batch",
            &empty
        ));
        let mut media = hyper::HeaderMap::new();
        media.insert(
            "content-type",
            HeaderValue::from_static("application/vnd.git-lfs+json; charset=utf-8"),
        );
        assert!(is_git_lfs_request("/objects/batch", &media));
        let mut agent = hyper::HeaderMap::new();
        agent.insert("user-agent", HeaderValue::from_static("git-lfs/3.6.0"));
        assert!(is_git_lfs_request("/download/objects/1", &agent));
        assert!(!is_git_lfs_request("/group/project", &empty));
    }

    #[test]
    fn auth_challenge_audit_keeps_only_scheme_and_realm() {
        assert_eq!(
            redact_auth_challenge(r#"Basic realm="GitLab", charset="UTF-8""#),
            json!({"scheme": "Basic", "realm": "GitLab"})
        );
        assert_eq!(
            redact_auth_challenge("Bearer error=invalid_token"),
            json!({"scheme": "Bearer", "realm": null})
        );
    }

    #[test]
    fn merges_cookie_and_replaces_the_same_cookie_name() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_static("theme=dark; session=old"));
        inject_cookie(&mut headers, "session", "new").unwrap();
        assert_eq!(headers[COOKIE], "theme=dark; session=new");
    }

    #[test]
    fn injects_encoded_query_parameter_without_losing_the_uri() {
        let mut uri: hyper::Uri = "https://example.com/path?keep=1&api_key=old"
            .parse()
            .unwrap();
        inject_query_parameter(&mut uri, "api_key", "a+b/c").unwrap();
        assert_eq!(
            uri.to_string(),
            "https://example.com/path?keep=1&api_key=a%2Bb%2Fc"
        );
    }

    fn websocket_text_frame(payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
        assert!(payload.len() <= 125);
        let mut frame = vec![0x81, payload.len() as u8];
        if let Some(mask) = mask {
            frame[1] |= 0x80;
            frame.extend_from_slice(&mask);
            frame.extend(
                payload
                    .iter()
                    .enumerate()
                    .map(|(index, byte)| byte ^ mask[index % 4]),
            );
        } else {
            frame.extend_from_slice(payload);
        }
        frame
    }

    #[test]
    fn parses_request_authority_hosts_and_ports() {
        assert_eq!(
            parse_authority("API.Example.com:8443"),
            Some(("api.example.com".into(), Some(8443)))
        );
        assert_eq!(
            parse_authority("[::1]:8080"),
            Some(("::1".into(), Some(8080)))
        );
        assert_eq!(
            parse_authority("example.com."),
            Some(("example.com".into(), None))
        );
    }

    #[test]
    fn enables_limited_websocket_frame_capture_from_the_audit_profile() {
        let mut config = Config::default();
        config.audit.transcript_dir = Some("audit/transcripts".into());
        config.plugins.push(PluginConfig {
            uuid: crate::config::new_config_uuid(),
            id: "ws".into(),
            kind: PluginKind::Audit,
            protocols: vec![PluginProtocol::Ws],
            capture_body: false,
            body_limit: 4096,
            ssh_transcript: false,
            websocket_capture: WebSocketCapture::Frames,
            transcript_client_upload: false,
            transcript_server_response: true,
            ..PluginConfig::default()
        });
        let context = ConnectionContext {
            session_id: "session".into(),
            connection_id: 42,
            process: ProcessInfo::default(),
            destination: Destination {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 443,
                hostnames: vec!["example.com".into()],
            },
            protocol: Protocol::Tls,
        };

        let capture = websocket_capture_config(
            &config,
            config.plugin("ws"),
            &context,
            "websocket",
            &hyper::HeaderMap::new(),
        )
        .expect("websocket frame capture should be enabled");
        let UpgradeCapture::Frames(capture) = capture else {
            panic!("expected raw frame capture");
        };
        assert_eq!(capture.limit, 4096);
        assert_eq!(capture.connection_id, 42);
        assert!(capture.stream_id.is_some());
        assert!(!capture.client_upload);
        assert!(capture.server_response);
        assert!(websocket_capture_config(
            &config,
            config.plugin("ws"),
            &context,
            "other",
            &hyper::HeaderMap::new(),
        )
        .is_none());
    }

    #[test]
    fn enables_http_body_capture_only_when_profile_captures_bodies() {
        let root = std::env::temp_dir().join(format!(
            "hyperhub-http-body-config-test-{}-{}",
            std::process::id(),
            NEXT_BODY_CAPTURE_STREAM_ID.load(Ordering::Relaxed)
        ));
        let mut config = Config::default();
        config.audit.transcript_dir = Some(root.clone());
        config.plugins.push(PluginConfig {
            uuid: crate::config::new_config_uuid(),
            id: "body".into(),
            kind: PluginKind::Audit,
            protocols: vec![PluginProtocol::Http],
            capture_body: true,
            body_limit: 1024,
            ssh_transcript: false,
            websocket_capture: WebSocketCapture::Off,
            transcript_client_upload: true,
            transcript_server_response: false,
            ..PluginConfig::default()
        });
        config.plugins.push(PluginConfig {
            uuid: crate::config::new_config_uuid(),
            id: "ws".into(),
            kind: PluginKind::Audit,
            protocols: vec![PluginProtocol::Ws],
            capture_body: false,
            body_limit: 1024,
            ssh_transcript: false,
            websocket_capture: WebSocketCapture::Frames,
            ..PluginConfig::default()
        });
        let context = ConnectionContext {
            session_id: "session".into(),
            connection_id: 42,
            process: ProcessInfo::default(),
            destination: Destination {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 443,
                hostnames: vec!["example.com".into()],
            },
            protocol: Protocol::Tls,
        };

        let capture = http_body_capture_config(&config, config.plugin("body"), &context)
            .expect("request-only HTTP capture should be enabled");
        assert!(capture.client_upload);
        assert!(!capture.server_response);
        assert!(capture.up_path.exists());
        assert!(!capture.down_path.exists());
        assert!(http_body_capture_config(&config, config.plugin("ws"), &context).is_none());
        assert!(http_body_capture_config(&config, None, &context).is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reads_negotiated_websocket_compression_parameters() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "sec-websocket-extensions",
            HeaderValue::from_static(
                "permessage-deflate; client_no_context_takeover; server_no_context_takeover",
            ),
        );
        let compression = websocket_compression(&headers);
        assert!(compression.enabled);
        assert!(compression.client_no_context_takeover);
        assert!(compression.server_no_context_takeover);
    }

    #[tokio::test]
    async fn preserves_unknown_decrypted_probe_bytes() {
        let payload = b"\x01custom-protocol\x00payload";
        let (mut application, mut intercepted) = tokio::io::duplex(128);
        application.write_all(payload).await.unwrap();
        let prefix = read_decrypted_prefix(&mut intercepted, 443).await.unwrap();
        assert_eq!(&prefix, payload);
        let mut replay = PrefixedIo::new(intercepted, prefix);
        let mut received = vec![0u8; payload.len()];
        replay.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, payload);
    }

    #[tokio::test]
    async fn recognizes_fragmented_http_without_losing_prefix() {
        let request = b"GET /socket HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let (mut application, mut intercepted) = tokio::io::duplex(128);
        let writer = tokio::spawn(async move {
            application.write_all(b"GE").await.unwrap();
            tokio::task::yield_now().await;
            application.write_all(&request[2..]).await.unwrap();
            application.shutdown().await.unwrap();
        });
        let prefix = read_decrypted_prefix(&mut intercepted, 443).await.unwrap();
        assert_eq!(&prefix, request);
        assert_eq!(
            crate::inspect::inspect(&prefix, 443).protocol,
            Protocol::Http
        );
        let mut replay = PrefixedIo::new(intercepted, prefix);
        let mut received = Vec::new();
        replay.read_to_end(&mut received).await.unwrap();
        assert_eq!(&received, request);
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn injects_every_http1_keep_alive_request() {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            for index in 0..2 {
                let headers = String::from_utf8(read_headers(&mut stream).await).unwrap();
                assert!(headers
                    .to_ascii_lowercase()
                    .contains("x-hyperhub: injected"));
                let connection = if index == 0 { "keep-alive" } else { "close" };
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: {connection}\r\n\r\nok"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            }
        });

        let ingress = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ingress_address = ingress.local_addr().unwrap();
        let secret = std::env::temp_dir().join(format!(
            "hyperhub-http-secret-{}-{}.txt",
            std::process::id(),
            origin_address.port()
        ));
        fs::write(&secret, "injected").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let proxy_task = tokio::spawn(async move {
            let (client, _) = ingress.accept().await.unwrap();
            let upstream = TcpStream::connect(origin_address).await.unwrap();
            let mut config = Config::default();
            config.plugins.push(PluginConfig {
                uuid: crate::config::new_config_uuid(),
                id: "http-header".into(),
                kind: PluginKind::Credential,
                protocols: vec![PluginProtocol::Http],
                headers: HashMap::from([(
                    "X-HyperHub".into(),
                    SecretValue::File {
                        file: secret.clone(),
                        prefix: String::new(),
                    },
                )]),
                ..PluginConfig::default()
            });
            config.rules.push(RouteRule {
                uuid: crate::config::new_config_uuid(),
                id: "http".into(),
                enabled: true,
                priority: 1,
                endpoints: route_endpoints(&["localhost"]),
                deny: false,
                rewrite_host: None,
                rewrite_port: None,
                upstream: None,
                plugins: vec!["http-header".into()],
                legacy: Default::default(),
                protection: None,
                allow_sensitive_upload: false,
            });
            let config = Arc::new(config);
            let policy = Arc::new(PolicySnapshot::compile(&config).unwrap());
            let context = ConnectionContext {
                session_id: "test".into(),
                connection_id: 9,
                process: ProcessInfo {
                    pid: 1,
                    tid: 1,
                    executable: "fixture".into(),
                },
                destination: Destination {
                    ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    port: origin_address.port(),
                    hostnames: vec!["localhost".into()],
                },
                protocol: Protocol::Http,
            };
            proxy_http(
                client,
                upstream,
                handler_context(
                    "localhost",
                    TlsMitm::generate().unwrap(),
                    config,
                    policy,
                    context,
                ),
            )
            .await
            .unwrap();
            let _ = fs::remove_file(secret);
        });

        let mut client = TcpStream::connect(ingress_address).await.unwrap();
        for index in 0..2 {
            let connection = if index == 0 { "keep-alive" } else { "close" };
            client
                .write_all(
                    format!(
                        "GET /{index}?token=secret HTTP/1.1\r\nHost: localhost\r\nX-HyperHub: old\r\nConnection: {connection}\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let response = read_headers(&mut client).await;
            assert!(String::from_utf8(response).unwrap().contains("200 OK"));
            let mut body = [0u8; 2];
            client.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"ok");
        }
        origin_task.await.unwrap();
        proxy_task.await.unwrap();
    }

    #[tokio::test]
    async fn tunneled_upstream_rewrites_absolute_form_to_origin() {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let headers = String::from_utf8(read_headers(&mut stream).await).unwrap();
            assert!(headers.starts_with("POST /v1/responses HTTP/1.1\r\n"));
            assert!(!headers.to_ascii_lowercase().contains("proxy-authorization"));
            assert!(!headers.to_ascii_lowercase().contains("proxy-connection"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });

        let ingress = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ingress_address = ingress.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (client, _) = ingress.accept().await.unwrap();
            let upstream = TcpStream::connect(origin_address).await.unwrap();
            let config = Arc::new(Config::default());
            let policy = Arc::new(PolicySnapshot::compile(&config).unwrap());
            let context = ConnectionContext {
                session_id: "tunneled-http".into(),
                connection_id: 1,
                process: ProcessInfo {
                    pid: 1,
                    tid: 1,
                    executable: "fixture".into(),
                },
                destination: Destination {
                    ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    port: origin_address.port(),
                    hostnames: vec!["127.0.0.1".into()],
                },
                protocol: Protocol::Http,
            };
            let mut inner = handler_context(
                "127.0.0.1",
                TlsMitm::generate().unwrap(),
                config,
                policy,
                context,
            );
            inner.upstream_tunneled = true;
            proxy_http(client, upstream, inner).await.unwrap();
        });

        let mut client = TcpStream::connect(ingress_address).await.unwrap();
        client
            .write_all(
                b"POST http://127.0.0.1:15721/v1/responses HTTP/1.1\r\nHost: 127.0.0.1:15721\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\nProxy-Connection: keep-alive\r\nContent-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();
        let response = read_headers(&mut client).await;
        assert!(String::from_utf8(response).unwrap().contains("200 OK"));
        let mut body = [0u8; 2];
        client.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"ok");
        origin_task.await.unwrap();
        proxy_task.await.unwrap();
    }

    #[tokio::test]
    async fn injects_only_matching_paths_on_one_keep_alive_connection() {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            for index in 0..3 {
                let headers = String::from_utf8(read_headers(&mut stream).await)
                    .unwrap()
                    .to_ascii_lowercase();
                match index {
                    0 => assert!(!headers.contains("authorization:")),
                    1 => {
                        assert!(headers.contains("authorization: bearer path-token"));
                        assert_eq!(headers.matches("authorization:").count(), 1, "{headers}");
                        assert!(!headers.contains("private-token:"), "{headers}");
                        assert!(headers.contains("x-tenant: trusted"), "{headers}");
                    }
                    2 => {
                        assert!(
                            headers
                                .contains("authorization: basic chjvamvjdf9ib3q6cgf0ac10b2tlbg=="),
                            "{headers}"
                        );
                        assert_eq!(headers.matches("authorization:").count(), 1, "{headers}");
                        assert!(!headers.contains("private-token:"), "{headers}");
                        assert!(headers.contains("x-tenant: trusted"), "{headers}");
                    }
                    _ => unreachable!(),
                }
                let connection = if index < 2 { "keep-alive" } else { "close" };
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: {connection}\r\n\r\nok"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            }
        });

        let ingress = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ingress_address = ingress.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (client, _) = ingress.accept().await.unwrap();
            let upstream = TcpStream::connect(origin_address).await.unwrap();
            let mut config = Config::default();
            config.plugins.push(PluginConfig {
                uuid: crate::config::new_config_uuid(),
                id: "path-token".into(),
                kind: PluginKind::Credential,
                protocols: vec![PluginProtocol::Http],
                http_scheme: Some(HttpAuthScheme::Token),
                username: Some("project_bot".into()),
                secret: Some(SecretValue::Inline {
                    value: "path-token".into(),
                }),
                headers: HashMap::from([
                    (
                        "PRIVATE-TOKEN".into(),
                        SecretValue::Inline {
                            value: String::new(),
                        },
                    ),
                    (
                        "X-Tenant".into(),
                        SecretValue::Inline {
                            value: "trusted".into(),
                        },
                    ),
                ]),
                ..PluginConfig::default()
            });
            config.rules.push(RouteRule {
                uuid: crate::config::new_config_uuid(),
                id: "private-path".into(),
                enabled: true,
                priority: 100,
                // URL 形式 target 的路径前缀限定只有 /private 命中凭证注入。
                endpoints: route_endpoints(&["localhost/private"]),
                deny: false,
                rewrite_host: None,
                rewrite_port: None,
                upstream: None,
                plugins: vec!["path-token".into()],
                legacy: Default::default(),
                protection: None,
                allow_sensitive_upload: false,
            });
            let config = Arc::new(config);
            let policy = Arc::new(PolicySnapshot::compile(&config).unwrap());
            let context = ConnectionContext {
                session_id: "test".into(),
                connection_id: 10,
                process: ProcessInfo {
                    pid: 1,
                    tid: 1,
                    executable: "fixture".into(),
                },
                destination: Destination {
                    ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    port: origin_address.port(),
                    hostnames: vec!["localhost".into()],
                },
                protocol: Protocol::Http,
            };
            proxy_http(
                client,
                upstream,
                handler_context(
                    "localhost",
                    TlsMitm::generate().unwrap(),
                    config,
                    policy,
                    context,
                ),
            )
            .await
            .unwrap();
        });

        let mut client = TcpStream::connect(ingress_address).await.unwrap();
        for (path, connection) in [
            ("/public", "keep-alive"),
            ("/private?scope=me", "keep-alive"),
            (
                "/private/repo.git/info/refs?service=git-upload-pack",
                "close",
            ),
        ] {
            let client_credentials = if path.starts_with("/private") {
                "Authorization: Bearer invalid-client-token\r\nPRIVATE-TOKEN: invalid-private-token\r\nX-Tenant: untrusted\r\n"
            } else {
                ""
            };
            client
                .write_all(
                    format!(
                        "GET {path} HTTP/1.1\r\nHost: localhost\r\n{client_credentials}Connection: {connection}\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let response = read_headers(&mut client).await;
            assert!(String::from_utf8(response).unwrap().contains("200 OK"));
            let mut body = [0u8; 2];
            client.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"ok");
        }
        origin_task.await.unwrap();
        proxy_task.await.unwrap();
    }

    #[tokio::test]
    async fn denies_one_path_without_closing_the_keep_alive_connection() {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let request = String::from_utf8(read_headers(&mut stream).await).unwrap();
            assert!(request.starts_with("GET /public HTTP/1.1"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });

        let ingress = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ingress_address = ingress.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (client, _) = ingress.accept().await.unwrap();
            let upstream = TcpStream::connect(origin_address).await.unwrap();
            let mut config = Config::default();
            config.rules.push(RouteRule {
                uuid: crate::config::new_config_uuid(),
                id: "blocked-path".into(),
                enabled: true,
                priority: 100,
                // URL 形式 target 的路径前缀限定只有 /blocked 被拒绝。
                endpoints: route_endpoints(&["localhost/blocked"]),
                deny: true,
                rewrite_host: None,
                rewrite_port: None,
                upstream: None,
                plugins: vec![],
                legacy: Default::default(),
                protection: None,
                allow_sensitive_upload: false,
            });
            let config = Arc::new(config);
            let policy = Arc::new(PolicySnapshot::compile(&config).unwrap());
            let context = ConnectionContext {
                session_id: "test".into(),
                connection_id: 11,
                process: ProcessInfo {
                    pid: 1,
                    tid: 1,
                    executable: "fixture".into(),
                },
                destination: Destination {
                    ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    port: origin_address.port(),
                    hostnames: vec!["localhost".into()],
                },
                protocol: Protocol::Http,
            };
            proxy_http(
                client,
                upstream,
                handler_context(
                    "localhost",
                    TlsMitm::generate().unwrap(),
                    config,
                    policy,
                    context,
                ),
            )
            .await
            .unwrap();
        });

        let mut client = TcpStream::connect(ingress_address).await.unwrap();
        client
            .write_all(
                b"GET /blocked HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
            )
            .await
            .unwrap();
        let denied = String::from_utf8(read_headers(&mut client).await).unwrap();
        assert!(denied.contains("403 Forbidden"));
        let mut denied_body = vec![0; b"request denied by HyperHub\n".len()];
        client.read_exact(&mut denied_body).await.unwrap();
        assert_eq!(&denied_body, b"request denied by HyperHub\n");

        client
            .write_all(b"GET /public HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let allowed = String::from_utf8(read_headers(&mut client).await).unwrap();
        assert!(allowed.contains("200 OK"));
        let mut body = [0u8; 2];
        client.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"ok");

        origin_task.await.unwrap();
        proxy_task.await.unwrap();
    }

    #[tokio::test]
    async fn data_protection_blocks_token_upload_before_upstream_send() {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let mut byte = [0u8; 1];
            match timeout(Duration::from_millis(500), stream.read(&mut byte)).await {
                Err(_) | Ok(Ok(0)) => {}
                Ok(Ok(_)) => panic!("blocked upload reached upstream"),
                Ok(Err(error)) => panic!("origin read failed: {error}"),
            }
        });

        let ingress = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ingress_address = ingress.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (client, _) = ingress.accept().await.unwrap();
            let upstream = TcpStream::connect(origin_address).await.unwrap();
            let mut config = Config::default();
            config.protections.push(ProtectionProfile {
                uuid: crate::config::new_config_uuid(),
                id: "egress".into(),
                enabled: true,
                mode: ProtectionMode::Enforce,
                data: DataProtectionConfig {
                    enabled: true,
                    ..DataProtectionConfig::default()
                },
                intelligence: Default::default(),
            });
            config.rules.push(RouteRule {
                uuid: crate::config::new_config_uuid(),
                id: "protected".into(),
                enabled: true,
                priority: 100,
                endpoints: route_endpoints(&["localhost"]),
                deny: false,
                rewrite_host: None,
                rewrite_port: None,
                upstream: None,
                plugins: vec![],
                protection: Some("egress".into()),
                allow_sensitive_upload: false,
                legacy: Default::default(),
            });
            config.validate().unwrap();
            let config = Arc::new(config);
            let policy = Arc::new(PolicySnapshot::compile(&config).unwrap());
            let context = ConnectionContext {
                session_id: "protected-upload".into(),
                connection_id: 21,
                process: ProcessInfo {
                    pid: 1,
                    tid: 1,
                    executable: "agent".into(),
                },
                destination: Destination {
                    ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    port: origin_address.port(),
                    hostnames: vec!["localhost".into()],
                },
                protocol: Protocol::Http,
            };
            proxy_http(
                client,
                upstream,
                handler_context(
                    "localhost",
                    TlsMitm::generate().unwrap(),
                    config,
                    policy,
                    context,
                ),
            )
            .await
            .unwrap();
        });

        let body = format!("ghp_{}", "a".repeat(30)).into_bytes();
        let mut client = TcpStream::connect(ingress_address).await.unwrap();
        client
            .write_all(
                format!(
                    "POST /collect HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        client.write_all(&body).await.unwrap();
        let denied = String::from_utf8(read_headers(&mut client).await).unwrap();
        assert!(denied.contains("403 Forbidden"));
        let mut denied_body = vec![0; b"request denied by HyperHub\n".len()];
        client.read_exact(&mut denied_body).await.unwrap();
        assert_eq!(&denied_body, b"request denied by HyperHub\n");
        client.shutdown().await.unwrap();
        origin_task.await.unwrap();
        proxy_task.await.unwrap();
    }

    #[tokio::test]
    async fn relays_and_decodes_http1_websocket_messages_in_both_directions() {
        let capture_root = std::env::temp_dir().join(format!(
            "hyperhub-websocket-capture-test-{}-{}",
            std::process::id(),
            NEXT_UPGRADE_STREAM_ID.load(Ordering::Relaxed)
        ));
        let capture_date = crate::retention::date_key(crate::retention::unix_timestamp_ms());
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let request = String::from_utf8(read_headers(&mut stream).await)
                .unwrap()
                .to_ascii_lowercase();
            assert!(request.starts_with("get /socket http/1.1"));
            assert!(request
                .lines()
                .any(|line| line.starts_with("connection:") && line.contains("upgrade")));
            assert!(request.contains("upgrade: websocket"));
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                )
                .await
                .unwrap();

            let expected = websocket_text_frame(b"client-message", Some([1, 2, 3, 4]));
            let mut client_frame = vec![0u8; expected.len()];
            stream.read_exact(&mut client_frame).await.unwrap();
            assert_eq!(client_frame, expected);
            stream
                .write_all(&websocket_text_frame(b"server-message", None))
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        });

        let ingress = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ingress_address = ingress.local_addr().unwrap();
        let proxy_capture_root = capture_root.clone();
        let proxy_task = tokio::spawn(async move {
            let (client, _) = ingress.accept().await.unwrap();
            let upstream = TcpStream::connect(origin_address).await.unwrap();
            let mut config = Config::default();
            config.audit.transcript_dir = Some(proxy_capture_root);
            config.plugins.push(PluginConfig {
                uuid: crate::config::new_config_uuid(),
                id: "websocket".into(),
                kind: PluginKind::Audit,
                protocols: vec![PluginProtocol::Ws],
                capture_body: false,
                body_limit: 1024,
                ssh_transcript: false,
                websocket_capture: WebSocketCapture::Messages,
                ..PluginConfig::default()
            });
            config.rules.push(RouteRule {
                uuid: crate::config::new_config_uuid(),
                id: "websocket".into(),
                enabled: true,
                priority: 1,
                endpoints: route_endpoints(&["localhost"]),
                deny: false,
                rewrite_host: None,
                rewrite_port: None,
                upstream: None,
                plugins: vec!["websocket".into()],
                legacy: Default::default(),
                protection: None,
                allow_sensitive_upload: false,
            });
            let config = Arc::new(config);
            let policy = Arc::new(PolicySnapshot::compile(&config).unwrap());
            let context = ConnectionContext {
                session_id: "upgrade-test".into(),
                connection_id: 12,
                process: ProcessInfo {
                    pid: 1,
                    tid: 1,
                    executable: "fixture".into(),
                },
                destination: Destination {
                    ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    port: origin_address.port(),
                    hostnames: vec!["localhost".into()],
                },
                protocol: Protocol::Http,
            };
            proxy_http(
                client,
                upstream,
                handler_context(
                    "localhost",
                    TlsMitm::generate().unwrap(),
                    config,
                    policy,
                    context,
                ),
            )
            .await
            .unwrap();
        });

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut client = TcpStream::connect(ingress_address).await.unwrap();
            client
                .write_all(
                    b"GET /socket HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive, Upgrade\r\nUpgrade: WebSocket\r\n\r\n",
                )
                .await
                .unwrap();
            let response = String::from_utf8(read_headers(&mut client).await).unwrap();
            assert!(response.contains("101 Switching Protocols"));
            client
                .write_all(&websocket_text_frame(
                    b"client-message",
                    Some([1, 2, 3, 4]),
                ))
                .await
                .unwrap();
            let expected = websocket_text_frame(b"server-message", None);
            let mut server_frame = vec![0u8; expected.len()];
            client.read_exact(&mut server_frame).await.unwrap();
            assert_eq!(server_frame, expected);
            client.shutdown().await.unwrap();

            origin_task.await.unwrap();
            proxy_task.await.unwrap();
        })
        .await
        .expect("HTTP/1 Upgrade tunnel timed out");

        let transcript_directory =
            crate::retention::date_partition_directory(&capture_root, capture_date)
                .join("upgrade-test");
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let complete = fs::read_dir(&transcript_directory)
                    .ok()
                    .is_some_and(|entries| {
                        let sizes = entries
                            .filter_map(Result::ok)
                            .filter_map(|entry| {
                                entry.metadata().ok().map(|metadata| metadata.len())
                            })
                            .collect::<Vec<_>>();
                        sizes.len() == 2 && sizes.iter().all(|size| *size > 0)
                    });
                if complete {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("WebSocket transcripts were not created");
        let mut transcripts = fs::read_dir(&transcript_directory)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        transcripts.sort();
        let down = transcripts
            .iter()
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .ends_with("-down.jsonl")
            })
            .unwrap();
        let up = transcripts
            .iter()
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .ends_with("-up.jsonl")
            })
            .unwrap();
        let up = fs::read_to_string(up).unwrap();
        let down = fs::read_to_string(down).unwrap();
        assert!(up.contains("\"direction\":\"client_to_target\""));
        assert!(up.contains("\"text\":\"client-message\""));
        assert!(down.contains("\"direction\":\"target_to_client\""));
        assert!(down.contains("\"text\":\"server-message\""));
        fs::remove_dir_all(capture_root).unwrap();
    }

    #[tokio::test]
    async fn captures_http_bodies_but_skips_websocket_upgrades_when_ws_capture_is_off() {
        let capture_root = std::env::temp_dir().join(format!(
            "hyperhub-http-body-capture-test-{}-{}",
            std::process::id(),
            NEXT_BODY_CAPTURE_STREAM_ID.load(Ordering::Relaxed)
        ));
        let capture_date = crate::retention::date_key(crate::retention::unix_timestamp_ms());
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let post = String::from_utf8(read_headers(&mut stream).await)
                .unwrap()
                .to_ascii_lowercase();
            assert!(post.starts_with("post /api/login http/1.1"));
            let content_length = post
                .lines()
                .find(|line| line.starts_with("content-length:"))
                .and_then(|line| line.split(':').nth(1))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .expect("POST must carry Content-Length");
            let mut request_body = vec![0u8; content_length];
            stream.read_exact(&mut request_body).await.unwrap();
            assert_eq!(&request_body, b"hello-body");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nresponse-body")
                .await
                .unwrap();

            let ping = String::from_utf8(read_headers(&mut stream).await)
                .unwrap()
                .to_ascii_lowercase();
            assert!(ping.starts_with("get /ping http/1.1"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();

            let upgrade = String::from_utf8(read_headers(&mut stream).await)
                .unwrap()
                .to_ascii_lowercase();
            assert!(upgrade.starts_with("get /socket http/1.1"));
            assert!(upgrade.contains("upgrade: websocket"));
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                )
                .await
                .unwrap();
            let expected = websocket_text_frame(b"client-message", Some([1, 2, 3, 4]));
            let mut client_frame = vec![0u8; expected.len()];
            stream.read_exact(&mut client_frame).await.unwrap();
            assert_eq!(client_frame, expected);
            stream
                .write_all(&websocket_text_frame(b"server-message", None))
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        });

        let ingress = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ingress_address = ingress.local_addr().unwrap();
        let proxy_capture_root = capture_root.clone();
        let proxy_task = tokio::spawn(async move {
            let (client, _) = ingress.accept().await.unwrap();
            let upstream = TcpStream::connect(origin_address).await.unwrap();
            let mut config = Config::default();
            config.audit.transcript_dir = Some(proxy_capture_root);
            config.plugins.push(PluginConfig {
                uuid: crate::config::new_config_uuid(),
                id: "body".into(),
                kind: PluginKind::Audit,
                protocols: vec![PluginProtocol::Http],
                capture_body: true,
                body_limit: 4,
                ssh_transcript: false,
                websocket_capture: WebSocketCapture::Off,
                ..PluginConfig::default()
            });
            config.rules.push(RouteRule {
                uuid: crate::config::new_config_uuid(),
                id: "body".into(),
                enabled: true,
                priority: 1,
                endpoints: route_endpoints(&["localhost"]),
                deny: false,
                rewrite_host: None,
                rewrite_port: None,
                upstream: None,
                plugins: vec!["body".into()],
                legacy: Default::default(),
                protection: None,
                allow_sensitive_upload: false,
            });
            let config = Arc::new(config);
            let policy = Arc::new(PolicySnapshot::compile(&config).unwrap());
            let context = ConnectionContext {
                session_id: "body-capture-test".into(),
                connection_id: 21,
                process: ProcessInfo {
                    pid: 1,
                    tid: 1,
                    executable: "fixture".into(),
                },
                destination: Destination {
                    ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    port: origin_address.port(),
                    hostnames: vec!["localhost".into()],
                },
                protocol: Protocol::Http,
            };
            proxy_http(
                client,
                upstream,
                handler_context(
                    "localhost",
                    TlsMitm::generate().unwrap(),
                    config,
                    policy,
                    context,
                ),
            )
            .await
            .unwrap();
        });

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut client = TcpStream::connect(ingress_address).await.unwrap();
            client
                .write_all(
                    b"POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\nConnection: keep-alive\r\n\r\nhello-body",
                )
                .await
                .unwrap();
            let response = String::from_utf8(read_headers(&mut client).await).unwrap();
            assert!(response.contains("200 OK"));
            let mut body = [0u8; 13];
            client.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"response-body");

            client
                .write_all(b"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n")
                .await
                .unwrap();
            let response = String::from_utf8(read_headers(&mut client).await).unwrap();
            assert!(response.contains("200 OK"));

            client
                .write_all(
                    b"GET /socket HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive, Upgrade\r\nUpgrade: WebSocket\r\n\r\n",
                )
                .await
                .unwrap();
            let upgrade = String::from_utf8(read_headers(&mut client).await).unwrap();
            assert!(upgrade.contains("101 Switching Protocols"));
            client
                .write_all(&websocket_text_frame(
                    b"client-message",
                    Some([1, 2, 3, 4]),
                ))
                .await
                .unwrap();
            let expected = websocket_text_frame(b"server-message", None);
            let mut server_frame = vec![0u8; expected.len()];
            client.read_exact(&mut server_frame).await.unwrap();
            assert_eq!(server_frame, expected);
            client.shutdown().await.unwrap();

            origin_task.await.unwrap();
            proxy_task.await.unwrap();
        })
        .await
        .expect("HTTP body capture e2e timed out");

        // websocket_capture=Off：目录里只有 body 捕获的两个文件，升级不产生任何捕获。
        let transcript_directory =
            crate::retention::date_partition_directory(&capture_root, capture_date)
                .join("body-capture-test");
        let mut transcripts = fs::read_dir(&transcript_directory)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        assert_eq!(transcripts.len(), 2);
        transcripts.sort();
        let up = transcripts
            .iter()
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .ends_with("-up.jsonl")
            })
            .unwrap();
        let down = transcripts
            .iter()
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .ends_with("-down.jsonl")
            })
            .unwrap();
        let up = fs::read_to_string(up).unwrap();
        let down = fs::read_to_string(down).unwrap();

        // 请求体捕获：hello-body 截断到 body_limit=4，base64("hell")。
        assert!(up.contains("\"direction\":\"request\""));
        assert!(up.contains("\"method\":\"POST\""));
        assert!(up.contains("\"path\":\"/api/login\""));
        assert!(up.contains("\"size\":10"));
        assert!(up.contains("\"captured_size\":4"));
        assert!(up.contains("\"truncated\":true"));
        assert!(up.contains("\"body\":\"aGVsbA==\""));
        // 空 body 快速路径：GET /ping 也有一条 size=0 的记录。
        assert!(up.contains("\"method\":\"GET\""));
        assert!(up.contains("\"path\":\"/ping\""));
        assert!(up.contains("\"size\":0"));
        assert!(up.contains("\"captured_size\":0"));
        // 响应体捕获：response-body 截断到 4 字节，base64("resp")。
        assert!(down.contains("\"direction\":\"response\""));
        assert!(down.contains("\"status\":200"));
        assert!(down.contains("\"size\":13"));
        assert!(down.contains("\"captured_size\":4"));
        assert!(down.contains("\"truncated\":true"));
        assert!(down.contains("\"body\":\"cmVzcA==\""));
        // 升级请求被跳过：两侧都只有两条记录（POST+GET），不含任何 WS 帧数据。
        assert_eq!(up.lines().count(), 2);
        assert_eq!(down.lines().count(), 2);
        assert!(!up.contains("client-message"));
        assert!(!down.contains("server-message"));
        std::fs::remove_dir_all(capture_root).unwrap();
    }

    #[tokio::test]
    async fn relays_http2_extended_connect_streams() {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin.accept().await.unwrap();
            let service = service_fn(|mut request: Request<Incoming>| async move {
                assert_eq!(request.method(), Method::CONNECT);
                assert_eq!(request.version(), Version::HTTP_2);
                assert_eq!(
                    request
                        .extensions()
                        .get::<hyper::ext::Protocol>()
                        .map(hyper::ext::Protocol::as_str),
                    Some("websocket")
                );
                let upgrade = hyper::upgrade::on(&mut request);
                tokio::spawn(async move {
                    let upgraded = upgrade.await.unwrap();
                    let mut stream = TokioIo::new(upgraded);
                    let mut client_stream = [0u8; 13];
                    stream.read_exact(&mut client_stream).await.unwrap();
                    assert_eq!(&client_stream, b"client-stream");
                    stream.write_all(b"server-stream").await.unwrap();
                    stream.shutdown().await.unwrap();
                });
                Ok::<_, std::convert::Infallible>(Response::new(Empty::<Bytes>::new()))
            });
            let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
            builder.enable_connect_protocol();
            builder
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        });

        let ingress = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ingress_address = ingress.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (client, _) = ingress.accept().await.unwrap();
            let upstream = TcpStream::connect(origin_address).await.unwrap();
            let (sender, connection) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(upstream))
                    .await
                    .unwrap();
            tokio::spawn(async move {
                let _ = connection.await;
            });
            let config = Arc::new(Config::default());
            let policy = Arc::new(PolicySnapshot::compile(&config).unwrap());
            let protection = Arc::new(ProtectionSnapshot::compile(&config).unwrap());
            let context = ConnectionContext {
                session_id: "extended-connect-test".into(),
                connection_id: 13,
                process: ProcessInfo {
                    pid: 1,
                    tid: 1,
                    executable: "fixture".into(),
                },
                destination: Destination {
                    ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    port: origin_address.port(),
                    hostnames: vec!["localhost".into()],
                },
                protocol: Protocol::Http,
            };
            serve_http(
                TokioIo::new(client),
                true,
                RequestSender::Http2(sender),
                config,
                policy,
                protection,
                AuditWriter::open(None).unwrap(),
                context,
                false,
            )
            .await
            .unwrap();
        });

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let client = TcpStream::connect(ingress_address).await.unwrap();
            let (mut sender, connection) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(client))
                    .await
                    .unwrap();
            let connection_task = tokio::spawn(async move {
                let _ = connection.await;
            });
            let mut request = Request::new(Empty::<Bytes>::new());
            *request.method_mut() = Method::CONNECT;
            *request.version_mut() = Version::HTTP_2;
            *request.uri_mut() = "http://localhost/socket".parse().unwrap();
            request
                .extensions_mut()
                .insert(hyper::ext::Protocol::from_static("websocket"));
            let mut response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let upgraded = hyper::upgrade::on(&mut response).await.unwrap();
            let mut stream = TokioIo::new(upgraded);
            stream.write_all(b"client-stream").await.unwrap();
            let mut server_stream = [0u8; 13];
            stream.read_exact(&mut server_stream).await.unwrap();
            assert_eq!(&server_stream, b"server-stream");
            stream.shutdown().await.unwrap();
            drop(stream);
            drop(response);
            drop(sender);
            origin_task.abort();
            proxy_task.abort();
            connection_task.abort();
        })
        .await
        .expect("HTTP/2 Extended CONNECT tunnel timed out");
    }

    #[test]
    fn tags_http2_subprotocols_for_audit() {
        let mut grpc = Request::new(Empty::<Bytes>::new());
        *grpc.version_mut() = Version::HTTP_2;
        grpc.headers_mut()
            .insert("content-type", HeaderValue::from_static("application/grpc"));
        assert_eq!(http2_subprotocol(&grpc), Some("grpc"));

        let mut websocket = Request::new(Empty::<Bytes>::new());
        *websocket.version_mut() = Version::HTTP_2;
        *websocket.method_mut() = Method::CONNECT;
        websocket
            .extensions_mut()
            .insert(hyper::ext::Protocol::from_static("websocket"));
        assert_eq!(http2_subprotocol(&websocket), Some("websocket"));

        let mut plain = Request::new(Empty::<Bytes>::new());
        *plain.version_mut() = Version::HTTP_2;
        assert_eq!(http2_subprotocol(&plain), Some("raw"));

        let mut http1 = Request::new(Empty::<Bytes>::new());
        *http1.version_mut() = Version::HTTP_11;
        assert_eq!(http2_subprotocol(&http1), None);
    }

    async fn read_client_hello(serve_side: &mut TcpStream) -> Vec<u8> {
        let mut buffer = vec![0u8; 16 * 1024];
        let count = timeout(Duration::from_secs(5), async {
            loop {
                let count = serve_side.peek(&mut buffer).await.unwrap();
                if crate::inspect::inspect_tls(&buffer[..count], 443).is_some() {
                    return count;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("client hello timed out");
        let mut hello = vec![0u8; count];
        serve_side.read_exact(&mut hello).await.unwrap();
        hello
    }

    #[tokio::test]
    async fn run_stack_mitms_tls_to_http1() {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "HyperHub Stack Test Root");
        let ca_certificate = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_certificate.pem(), ca_key).unwrap();

        let server_key = rcgen::KeyPair::generate().unwrap();
        let mut server_params =
            rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        server_params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
        let server_certificate = server_params.signed_by(&server_key, &issuer).unwrap();
        let server_config = std::sync::Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![server_certificate.der().clone()],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()),
                    ),
                )
                .unwrap(),
        );

        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin.accept().await.unwrap();
            let tls = tokio_rustls::TlsAcceptor::from(server_config)
                .accept(stream)
                .await
                .unwrap();
            let service = service_fn(|_request: Request<Incoming>| async move {
                Ok::<_, std::convert::Infallible>(Response::new(full_body(b"hello")))
            });
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tls), service)
                .await
                .unwrap();
        });

        let pair = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_address = pair.local_addr().unwrap();
        let app_side = TcpStream::connect(client_address).await.unwrap();
        let (mut serve_side, _) = pair.accept().await.unwrap();
        let upstream = TcpStream::connect(origin_address).await.unwrap();

        let mitm =
            TlsMitm::generate_with_root_certificates(vec![ca_certificate.der().clone()]).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(mitm.ca_der.clone()).unwrap();
        let client_config = std::sync::Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        let config = Arc::new(mitm_config());
        let policy = Arc::new(PolicySnapshot::compile(&config).unwrap());
        let context = ConnectionContext {
            session_id: "stack-h1".into(),
            connection_id: 1,
            process: ProcessInfo {
                pid: 1,
                tid: 1,
                executable: "fixture".into(),
            },
            destination: Destination {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 443,
                hostnames: vec!["localhost".into()],
            },
            protocol: Protocol::Tls,
        };

        let client_task = tokio::spawn(async move {
            let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let tls = timeout(Duration::from_secs(5), async {
                tokio_rustls::TlsConnector::from(client_config)
                    .connect(server_name, app_side)
                    .await
            })
            .await
            .expect("client TLS handshake timed out")
            .expect("client TLS handshake failed");
            let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
                .await
                .unwrap();
            tokio::spawn(async move {
                let _ = connection.await;
            });
            let response = sender
                .send_request(Request::new(Empty::<Bytes>::new()))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(&body[..], b"hello");
            drop(sender);
        });

        let serve_task = tokio::spawn(async move {
            let hello = read_client_hello(&mut serve_side).await;
            run_stack(
                Box::new(serve_side),
                Box::new(upstream),
                hello,
                0,
                handler_context("localhost", mitm, config, policy, context),
            )
            .await
        });

        client_task.await.unwrap();
        timeout(Duration::from_secs(5), serve_task)
            .await
            .expect("serve task timed out")
            .unwrap()
            .unwrap();
        origin_task.await.unwrap();
    }

    #[tokio::test]
    async fn mitms_tls_and_injects_credential_for_all_http_requests() {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::KeyCertSign);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "HyperHub Git Web Test Root");
        let ca_certificate = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_certificate.pem(), ca_key).unwrap();

        let server_key = rcgen::KeyPair::generate().unwrap();
        let mut server_params =
            rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        server_params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
        let server_certificate = server_params.signed_by(&server_key, &issuer).unwrap();
        let mut server_config = std::sync::Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![server_certificate.der().clone()],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()),
                    ),
                )
                .unwrap(),
        );
        Arc::get_mut(&mut server_config).unwrap().alpn_protocols = vec![b"http/1.1".to_vec()];

        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin.accept().await.unwrap();
            let tls = tokio_rustls::TlsAcceptor::from(server_config)
                .accept(stream)
                .await
                .unwrap();
            let mut stream = tls;
            for index in 0..2 {
                let headers = String::from_utf8(read_headers(&mut stream).await)
                    .unwrap()
                    .to_ascii_lowercase();
                let expected = "authorization: bearer shared-token";
                assert!(
                    headers.contains(expected),
                    "request {index} must carry {expected}: {headers}"
                );
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                    )
                    .await
                    .unwrap();
            }
        });

        let pair = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_address = pair.local_addr().unwrap();
        let app_side = TcpStream::connect(client_address).await.unwrap();
        let (mut serve_side, _) = pair.accept().await.unwrap();
        let upstream = TcpStream::connect(origin_address).await.unwrap();

        let mitm =
            TlsMitm::generate_with_root_certificates(vec![ca_certificate.der().clone()]).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(mitm.ca_der.clone()).unwrap();
        let mut client_config = std::sync::Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        Arc::get_mut(&mut client_config).unwrap().alpn_protocols = vec![b"http/1.1".to_vec()];

        let mut config = Config::default();
        config.plugins.push(PluginConfig {
            uuid: crate::config::new_config_uuid(),
            id: "shared".into(),
            kind: PluginKind::Credential,
            protocols: vec![PluginProtocol::Http],
            http_scheme: Some(HttpAuthScheme::Bearer),
            secret: Some(SecretValue::Inline {
                value: "shared-token".into(),
            }),
            ..PluginConfig::default()
        });
        config.rules.push(RouteRule {
            uuid: crate::config::new_config_uuid(),
            id: "web".into(),
            enabled: true,
            priority: 1,
            endpoints: route_endpoints(&["localhost"]),
            deny: false,
            rewrite_host: None,
            rewrite_port: None,
            upstream: None,
            plugins: vec!["shared".into()],
            legacy: Default::default(),
            protection: None,
            allow_sensitive_upload: false,
        });
        let config = Arc::new(config);
        let policy = Arc::new(PolicySnapshot::compile(&config).unwrap());
        let context = ConnectionContext {
            session_id: "git-web".into(),
            connection_id: 1,
            process: ProcessInfo {
                pid: 1,
                tid: 1,
                executable: "git".into(),
            },
            destination: Destination {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 443,
                hostnames: vec!["localhost".into()],
            },
            protocol: Protocol::Tls,
        };

        let client_task = tokio::spawn(async move {
            let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let mut tls = timeout(Duration::from_secs(5), async {
                tokio_rustls::TlsConnector::from(client_config)
                    .connect(server_name, app_side)
                    .await
            })
            .await
            .expect("client TLS handshake timed out")
            .expect("client TLS handshake failed");
            for path in ["/info/refs?service=git-upload-pack", "/hello"] {
                tls.write_all(
                    format!(
                        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
                let response = String::from_utf8(read_headers(&mut tls).await).unwrap();
                assert!(response.contains("200 OK"), "{response}");
                let mut body = [0u8; 2];
                tls.read_exact(&mut body).await.unwrap();
                assert_eq!(&body, b"ok");
            }
        });

        let serve_task = tokio::spawn(async move {
            let hello = read_client_hello(&mut serve_side).await;
            run_stack(
                Box::new(serve_side),
                Box::new(upstream),
                hello,
                0,
                handler_context("localhost", mitm, config, policy, context),
            )
            .await
        });

        client_task.await.unwrap();
        timeout(Duration::from_secs(5), serve_task)
            .await
            .expect("serve task timed out")
            .unwrap()
            .unwrap();
        origin_task.await.unwrap();
    }

    #[tokio::test]
    async fn run_stack_mitms_tls_to_http2() {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "HyperHub Stack Test Root");
        let ca_certificate = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_certificate.pem(), ca_key).unwrap();

        let server_key = rcgen::KeyPair::generate().unwrap();
        let mut server_params =
            rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        server_params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
        let server_certificate = server_params.signed_by(&server_key, &issuer).unwrap();
        let mut server_config = std::sync::Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![server_certificate.der().clone()],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()),
                    ),
                )
                .unwrap(),
        );
        Arc::get_mut(&mut server_config).unwrap().alpn_protocols = vec![b"h2".to_vec()];

        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin.accept().await.unwrap();
            let tls = tokio_rustls::TlsAcceptor::from(server_config)
                .accept(stream)
                .await
                .unwrap();
            let service = service_fn(|_request: Request<Incoming>| async move {
                Ok::<_, std::convert::Infallible>(Response::new(Empty::<Bytes>::new()))
            });
            let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
            builder.enable_connect_protocol();
            builder
                .serve_connection(TokioIo::new(tls), service)
                .await
                .unwrap();
        });

        let pair = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_address = pair.local_addr().unwrap();
        let app_side = TcpStream::connect(client_address).await.unwrap();
        let (mut serve_side, _) = pair.accept().await.unwrap();
        let upstream = TcpStream::connect(origin_address).await.unwrap();

        let mitm =
            TlsMitm::generate_with_root_certificates(vec![ca_certificate.der().clone()]).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(mitm.ca_der.clone()).unwrap();
        let mut client_config = std::sync::Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        Arc::get_mut(&mut client_config).unwrap().alpn_protocols = vec![b"h2".to_vec()];

        let config = Arc::new(mitm_config());
        let policy = Arc::new(PolicySnapshot::compile(&config).unwrap());
        let context = ConnectionContext {
            session_id: "stack-h2".into(),
            connection_id: 1,
            process: ProcessInfo {
                pid: 1,
                tid: 1,
                executable: "fixture".into(),
            },
            destination: Destination {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 443,
                hostnames: vec!["localhost".into()],
            },
            protocol: Protocol::Tls,
        };

        let client_task = tokio::spawn(async move {
            let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let tls = timeout(Duration::from_secs(5), async {
                tokio_rustls::TlsConnector::from(client_config)
                    .connect(server_name, app_side)
                    .await
            })
            .await
            .expect("client TLS handshake timed out")
            .expect("client TLS handshake failed");
            let (mut sender, connection) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                    .await
                    .unwrap();
            tokio::spawn(async move {
                let _ = connection.await;
            });
            let mut request = Request::new(Empty::<Bytes>::new());
            *request.uri_mut() = "http://localhost/".parse().unwrap();
            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            drop(sender);
        });

        let serve_task = tokio::spawn(async move {
            let hello = read_client_hello(&mut serve_side).await;
            run_stack(
                Box::new(serve_side),
                Box::new(upstream),
                hello,
                0,
                handler_context("localhost", mitm, config, policy, context),
            )
            .await
        });

        client_task.await.unwrap();
        timeout(Duration::from_secs(5), serve_task)
            .await
            .expect("serve task timed out")
            .unwrap()
            .unwrap();
        origin_task.await.unwrap();
    }
}
