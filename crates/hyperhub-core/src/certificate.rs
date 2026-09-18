use base64::Engine;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::net::TcpStream;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use x509_parser::parse_x509_certificate;

/// Loads every certificate in a PEM bundle, falling back to a single DER file.
pub fn load_root_certificates(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let bytes = fs::read(path).map_err(|source| {
        io::Error::new(
            source.kind(),
            format!(
                "failed to read root certificate '{}': {source}",
                path.display()
            ),
        )
    })?;
    let pem = rustls_pemfile::certs(&mut bytes.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| {
            io::Error::new(
                source.kind(),
                format!(
                    "failed to parse PEM root certificate '{}': {source}",
                    path.display()
                ),
            )
        })?;
    if !pem.is_empty() {
        return Ok(pem);
    }
    parse_x509_certificate(&bytes).map_err(|source| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "root certificate '{}' is neither a PEM bundle nor a DER certificate: {source}",
                path.display()
            ),
        )
    })?;
    Ok(vec![CertificateDer::from(bytes)])
}

/// Renders a human-readable preview of every certificate in the file.
pub fn preview_root_certificate(path: &Path) -> io::Result<String> {
    let certificates = load_root_certificates(path)?;
    let mut lines = vec![format!("文件              {}", path.display())];
    for (index, certificate) in certificates.iter().enumerate() {
        if certificates.len() > 1 {
            lines.push(format!("证书 #{}", index + 1));
        }
        lines.extend(preview_certificate(certificate)?.lines().map(str::to_owned));
    }
    Ok(lines.join("\n"))
}

/// Renders a human-readable preview of a single DER certificate.
pub fn preview_certificate(certificate: &CertificateDer<'_>) -> io::Result<String> {
    certificate_summary(certificate)
}

/// Extracts a human-friendly display name: the Common Name if present,
/// otherwise the full subject string.
pub fn certificate_name(certificate: &CertificateDer<'_>) -> io::Result<String> {
    let (_, parsed) = parse_x509_certificate(certificate.as_ref()).map_err(|source| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid DER certificate: {source}"),
        )
    })?;
    for common_name in parsed.subject().iter_common_name() {
        if let Ok(name) = common_name.as_str() {
            if !name.is_empty() {
                return Ok(name.to_owned());
            }
        }
    }
    Ok(parsed.subject().to_string())
}

/// SHA-256 fingerprint of the certificate DER, as lowercase hex.
pub fn fingerprint(certificate: &CertificateDer<'_>) -> String {
    Sha256::digest(certificate.as_ref())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// 主动连接目标 TLS 服务器并捕获其对端证书链（叶证书在前，中间证书在后）。
/// 仅用于"按主机抓取 CA"的导入入口，因此关闭证书校验。
pub fn fetch_tls_peer_certificates(
    host: &str,
    port: u16,
) -> io::Result<Vec<CertificateDer<'static>>> {
    #[derive(Debug)]
    struct CaptureVerifier {
        certificates: Arc<Mutex<Vec<CertificateDer<'static>>>>,
    }

    impl ServerCertVerifier for CaptureVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            let mut certificates = self.certificates.lock().unwrap();
            certificates.push(CertificateDer::from(end_entity.as_ref().to_vec()));
            for intermediate in intermediates {
                certificates.push(CertificateDer::from(intermediate.as_ref().to_vec()));
            }
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
            ]
        }
    }

    let address = format!("{host}:{port}");
    let mut stream = TcpStream::connect(&address)
        .map_err(|error| io::Error::new(error.kind(), format!("无法连接 {address}: {error}")))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let server_name = ServerName::try_from(host.to_owned()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("无效的 TLS 主机名 '{host}'"),
        )
    })?;
    let certificates = Arc::new(Mutex::new(Vec::new()));
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(CaptureVerifier {
            certificates: certificates.clone(),
        }))
        .with_no_client_auth();
    let mut connection =
        ClientConnection::new(Arc::new(config), server_name).map_err(io::Error::other)?;
    while connection.is_handshaking() {
        connection.complete_io(&mut stream).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("与 {address} 的 TLS 握手失败: {error}"),
            )
        })?;
    }
    let captured = certificates.lock().unwrap().clone();
    if captured.is_empty() {
        return Err(io::Error::other("TLS 握手完成但未捕获到对端证书"));
    }
    Ok(captured)
}

/// 返回对端证书链中最接近根 CA 的一张（自签叶证书时即叶证书本身）。
pub fn fetch_tls_peer_ca(host: &str, port: u16) -> io::Result<CertificateDer<'static>> {
    fetch_tls_peer_certificates(host, port)?
        .into_iter()
        .last()
        .ok_or_else(|| io::Error::other("未捕获到对端 CA 证书"))
}

/// 连接 SSH 服务器并完成传输层握手，返回主机公钥：`(key_type, base64(public key data))`。
/// 使用 russh 完成完整 KEX 协商（含 strict KEX 与扩展信息），仅用于"按主机抓取 SSH 主机密钥"。
pub fn fetch_ssh_host_key(host: &str, port: u16) -> io::Result<(String, String)> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(io::Error::other)?;
    runtime.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(15),
            fetch_ssh_host_key_async(host, port),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SSH 主机密钥抓取超时"))?
    })
}

async fn fetch_ssh_host_key_async(host: &str, port: u16) -> io::Result<(String, String)> {
    let address = format!("{host}:{port}");
    let stream = tokio::net::TcpStream::connect(&address)
        .await
        .map_err(|error| io::Error::new(error.kind(), format!("无法连接 {address}: {error}")))?;
    let capture = Arc::new(Mutex::new(None));
    let config = Arc::new(russh::client::Config {
        inactivity_timeout: Some(Duration::from_secs(10)),
        ..Default::default()
    });
    let handler = HostKeyCapture {
        key: capture.clone(),
    };
    let _session = russh::client::connect_stream(config, stream, handler)
        .await
        .map_err(|error| io::Error::other(format!("SSH 握手失败：{error}")))?;
    let key = capture
        .lock()
        .map_err(|_| io::Error::other("SSH 主机密钥捕获状态损坏"))?
        .take()
        .ok_or_else(|| io::Error::other("SSH 握手未返回主机密钥"))?;
    let key_type = key.algorithm().to_string();
    let key_blob =
        base64::engine::general_purpose::STANDARD.encode(key.to_bytes().map_err(io::Error::other)?);
    Ok((key_type, key_blob))
}

struct HostKeyCapture {
    key: Arc<Mutex<Option<russh::keys::PublicKey>>>,
}

impl russh::client::Handler for HostKeyCapture {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        *self.key.lock().unwrap() = Some(server_public_key.clone());
        Ok(true)
    }
}

/// 连接 SSH 服务器并校验其主机公钥是否与给定值一致。
pub fn ssh_host_key_matches(
    host: &str,
    port: u16,
    expected_type: &str,
    expected_blob: &str,
) -> io::Result<bool> {
    let (actual_type, actual_blob) = fetch_ssh_host_key(host, port)?;
    Ok(actual_type == expected_type && actual_blob == expected_blob)
}

/// A short, human-friendly form of a fingerprint for list display.
pub fn short_fingerprint(fingerprint: &str) -> String {
    if fingerprint.len() < 16 {
        return fingerprint.to_owned();
    }
    let bytes = fingerprint.as_bytes();
    let mut output = String::with_capacity(32);
    for (index, byte) in bytes.iter().take(16).enumerate() {
        if index > 0 && index % 2 == 0 {
            output.push(':');
        }
        output.push(*byte as char);
    }
    output.push('…');
    output
}

/// Renders subject, issuer, validity, serial, fingerprint, and CA status.
pub fn certificate_summary(certificate: &CertificateDer<'_>) -> io::Result<String> {
    let (_, parsed) = parse_x509_certificate(certificate.as_ref()).map_err(|source| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid DER certificate: {source}"),
        )
    })?;
    let fingerprint = fingerprint(certificate);
    let validity = parsed.validity();
    Ok(format!(
        "主体              {}\n签发者            {}\n生效              {}\n到期              {}\n序列号            {}\nCA                {}\nSHA-256           {fingerprint}",
        parsed.subject(),
        parsed.issuer(),
        validity.not_before,
        validity.not_after,
        parsed.raw_serial_as_string(),
        parsed.is_ca(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};

    fn generate_ca() -> rcgen::Certificate {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "HyperHub Test Root");
        params.self_signed(&key).unwrap()
    }

    #[test]
    fn loads_pem_bundle_and_der() {
        let directory =
            std::env::temp_dir().join(format!("hyperhub-cert-bundle-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let first = generate_ca();
        let second = generate_ca();
        let pem = format!("{}\n{}", first.pem(), second.pem());
        let pem_path = directory.join("roots.pem");
        fs::write(&pem_path, &pem).unwrap();
        let loaded = load_root_certificates(&pem_path).unwrap();
        assert_eq!(loaded.len(), 2);

        let der_path = directory.join("root.der");
        fs::write(&der_path, first.der()).unwrap();
        let loaded = load_root_certificates(&der_path).unwrap();
        assert_eq!(loaded.len(), 1);

        fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn rejects_files_that_are_neither_pem_nor_der() {
        let directory =
            std::env::temp_dir().join(format!("hyperhub-cert-reject-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("garbage.bin");
        fs::write(&path, b"not a certificate").unwrap();
        assert!(load_root_certificates(&path).is_err());
        fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn preview_reports_subject_and_fingerprint() {
        let directory =
            std::env::temp_dir().join(format!("hyperhub-cert-preview-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let certificate = generate_ca();
        let path = directory.join("root.pem");
        fs::write(&path, certificate.pem()).unwrap();
        let preview = preview_root_certificate(&path).unwrap();
        assert!(preview.contains("HyperHub Test Root"));
        assert!(preview.contains("SHA-256"));
        assert!(preview.contains("CA"));
        fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn fingerprint_is_stable_sha256_hex() {
        let certificate = generate_ca();
        let first = fingerprint(&certificate.der().clone());
        let second = fingerprint(&certificate.der().clone());
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let short = short_fingerprint(&first);
        let digits = short.trim_end_matches('…').replace(':', "");
        assert_eq!(digits, &first[..16]);
        assert!(short.ends_with('…'));
    }

    #[test]
    fn extracts_common_name_as_display_name() {
        let certificate = generate_ca();
        assert_eq!(
            certificate_name(&certificate.der().clone()).unwrap(),
            "HyperHub Test Root"
        );
    }
}
