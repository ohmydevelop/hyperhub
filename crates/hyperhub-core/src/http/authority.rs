//! Private worker bootstrap material. Never log it or place it in argv/env.
use super::*;
use rcgen::PublicKeyData;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TlsAuthority {
    certificate: String,
    private_key: String,
}
impl Drop for TlsAuthority {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}
impl TlsMitm {
    pub(crate) fn export_root_certificates(&self) -> Vec<Vec<u8>> {
        self.extra_roots
            .iter()
            .map(|certificate| certificate.as_ref().to_vec())
            .collect()
    }

    pub(crate) fn export_authority(&self) -> TlsAuthority {
        TlsAuthority {
            certificate: self.ca_pem.clone(),
            private_key: self.ca_key_pem.to_string(),
        }
    }
    pub(crate) fn restore_authority(
        authority: &TlsAuthority,
        roots: Vec<CertificateDer<'static>>,
    ) -> io::Result<Arc<Self>> {
        let mut certificates = rustls_pemfile::certs(&mut authority.certificate.as_bytes())
            .collect::<io::Result<Vec<_>>>()?;
        if certificates.len() != 1 {
            return Err(io::Error::other(
                "worker TLS authority must contain one certificate",
            ));
        }
        let certificate = certificates.remove(0);
        let key = KeyPair::from_pem(&authority.private_key).map_err(io::Error::other)?;
        let (_, parsed) =
            x509_parser::parse_x509_certificate(&certificate).map_err(io::Error::other)?;
        if parsed.public_key().raw != key.subject_public_key_info() {
            return Err(io::Error::other(
                "worker TLS authority certificate and key differ",
            ));
        }
        let issuer =
            Issuer::from_ca_cert_pem(&authority.certificate, key).map_err(io::Error::other)?;
        Self::with_identity(
            issuer,
            authority.certificate.clone(),
            certificate,
            Zeroizing::new(authority.private_key.clone()),
            roots,
        )
    }
    pub(super) fn with_identity(
        issuer: Issuer<'static, KeyPair>,
        ca_pem: String,
        ca_der: CertificateDer<'static>,
        ca_key_pem: Zeroizing<String>,
        root_certificates: Vec<CertificateDer<'static>>,
    ) -> io::Result<Arc<Self>> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for certificate in &root_certificates {
            roots.add(certificate.clone()).map_err(|error| {
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
            ca_key_pem,
            extra_roots: root_certificates,
            cache: Mutex::new(HashMap::new()),
            outbound: Arc::new(outbound),
            outbound_http1: Arc::new(outbound_http1),
            outbound_raw: Arc::new(outbound_raw),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn successive_forwarding_instances_keep_the_original_inspection_identity() {
        let original = TlsMitm::generate().unwrap();
        let bytes = serde_json::to_vec(&original.export_authority()).unwrap();
        let material: TlsAuthority = serde_json::from_slice(&bytes).unwrap();
        let replacement = TlsMitm::restore_authority(&material, vec![]).unwrap();
        assert_eq!(original.ca_der, replacement.ca_der);
        assert_eq!(original.ca_pem(), replacement.ca_pem());
        let mut roots = RootCertStore::empty();
        roots.add(original.ca_der.clone()).unwrap();
        let client = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        let mut connections = Vec::new();
        let mut servers = Vec::new();
        for instance in [original, replacement] {
            let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let acceptor = TlsAcceptor::from(instance.server_config("localhost").unwrap());
            servers.push(tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = acceptor.accept(stream).await.unwrap();
                let mut bytes = [0; 3];
                stream.read_exact(&mut bytes).await.unwrap();
                stream.write_all(&bytes).await.unwrap();
            }));
            connections.push(
                client
                    .connect(
                        ServerName::try_from("localhost").unwrap(),
                        tokio::net::TcpStream::connect(address).await.unwrap(),
                    )
                    .await
                    .unwrap(),
            );
        }
        // The first connection remains alive after the second instance's TLS
        // handshake, and both chain to the target's original trusted CA.
        for mut stream in connections {
            stream.write_all(b"old").await.unwrap();
            let mut response = [0; 3];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"old");
        }
        for server in servers {
            server.await.unwrap();
        }
    }
    #[test]
    fn rejects_a_different_signing_key_and_multiple_authority_certificates() {
        let first = TlsMitm::generate().unwrap();
        let second = TlsMitm::generate().unwrap();
        let mut authority = first.export_authority();
        authority.private_key = second.export_authority().private_key.clone();
        assert!(TlsMitm::restore_authority(&authority, vec![]).is_err());
        let mut authority = first.export_authority();
        authority.certificate.push_str(first.ca_pem());
        assert!(TlsMitm::restore_authority(&authority, vec![]).is_err());
    }
}
