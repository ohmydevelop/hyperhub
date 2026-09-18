use crate::policy::Protocol;
use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct Inspection {
    pub protocol: Protocol,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub http_method: Option<String>,
    pub tls_alpn: Vec<Vec<u8>>,
    pub proxy_form: bool,
    pub detail: Option<Value>,
}

impl Inspection {
    pub fn unknown() -> Self {
        Self {
            protocol: Protocol::Unknown,
            hostname: None,
            port: None,
            http_method: None,
            tls_alpn: Vec::new(),
            proxy_form: false,
            detail: None,
        }
    }
}

pub fn inspect(data: &[u8], port: u16) -> Inspection {
    inspect_ssh(data, port)
        .or_else(|| inspect_http(data, port))
        .or_else(|| inspect_tls(data, port))
        .or_else(|| inspect_git(data, port))
        .unwrap_or_else(Inspection::unknown)
}

pub(crate) fn inspect_ssh(data: &[u8], port: u16) -> Option<Inspection> {
    if !data.starts_with(b"SSH-") && !(data.is_empty() && port == 22) {
        return None;
    }
    let banner = data
        .split(|b| *b == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .map(str::trim)
        .unwrap_or("SSH");
    Some(Inspection {
        protocol: Protocol::Ssh,
        hostname: None,
        port: None,
        http_method: None,
        tls_alpn: Vec::new(),
        proxy_form: false,
        detail: Some(json!({"banner": banner})),
    })
}

pub(crate) fn inspect_http(data: &[u8], _port: u16) -> Option<Inspection> {
    let (host, port, method, path, proxy_form) = parse_http(data)?;
    if let Some((operation, repository)) = inspect_git_http(&method, &path) {
        return Some(Inspection {
            protocol: Protocol::Git,
            hostname: host.clone(),
            port,
            http_method: Some(method.clone()),
            tls_alpn: Vec::new(),
            proxy_form,
            detail: Some(json!({
                "carrier": "http",
                "operation": operation,
                "repository": repository,
                "host": host,
                "method": method,
            })),
        });
    }
    Some(Inspection {
        protocol: Protocol::Http,
        hostname: host.clone(),
        port,
        http_method: Some(method.clone()),
        tls_alpn: Vec::new(),
        proxy_form,
        detail: Some(
            json!({"method": method, "host": host, "path": crate::audit::redact_path(&path)}),
        ),
    })
}

pub(crate) fn inspect_tls(data: &[u8], _port: u16) -> Option<Inspection> {
    let hello = inspect_tls_client_hello(data)?;
    let alpn = hello
        .alpn
        .iter()
        .map(|value| String::from_utf8_lossy(value).into_owned())
        .collect::<Vec<_>>();
    Some(Inspection {
        protocol: Protocol::Tls,
        hostname: hello.sni.clone(),
        port: Some(443),
        http_method: None,
        tls_alpn: hello.alpn,
        proxy_form: false,
        detail: Some(json!({"sni": hello.sni, "alpn": alpn})),
    })
}

pub(crate) fn inspect_git(data: &[u8], _port: u16) -> Option<Inspection> {
    let (service, path, host) = parse_git(data)?;
    Some(Inspection {
        protocol: Protocol::Git,
        hostname: host.clone(),
        port: None,
        http_method: None,
        tls_alpn: Vec::new(),
        proxy_form: false,
        detail: Some(json!({"service": service, "repository": path, "host": host})),
    })
}

pub fn inspect_git_http(method: &str, path: &str) -> Option<(&'static str, String)> {
    let clean = path.split('?').next()?;
    if method == "GET" && path.contains("service=git-upload-pack") {
        return Some(("fetch", clean.trim_end_matches("/info/refs").to_string()));
    }
    if method == "GET" && path.contains("service=git-receive-pack") {
        return Some(("push", clean.trim_end_matches("/info/refs").to_string()));
    }
    if method == "POST" && clean.ends_with("/git-upload-pack") {
        return Some((
            "fetch",
            clean.trim_end_matches("/git-upload-pack").to_string(),
        ));
    }
    if method == "POST" && clean.ends_with("/git-receive-pack") {
        return Some((
            "push",
            clean.trim_end_matches("/git-receive-pack").to_string(),
        ));
    }
    None
}

fn parse_http(data: &[u8]) -> Option<(Option<String>, Option<u16>, String, String, bool)> {
    let end = data.windows(4).position(|window| window == b"\r\n\r\n")? + 4;
    let text = std::str::from_utf8(&data[..end]).ok()?;
    let mut lines = text.split("\r\n");
    let request = lines.next()?;
    let mut parts = request.split_whitespace();
    let method = parts.next()?.to_string();
    if ![
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE",
    ]
    .contains(&method.as_str())
    {
        return None;
    }
    let path = parts.next()?.to_string();
    let host_header = lines
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
                .map(|(_, value)| value.trim().to_string())
        })
        .filter(|value| !value.is_empty());
    let proxy_form = method == "CONNECT"
        || path
            .get(..7)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
        || path
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"));
    let target_uri = if method == "CONNECT" {
        format!("http://{path}").parse::<hyper::Uri>().ok()
    } else {
        path.parse::<hyper::Uri>().ok()
    };
    let header_uri = host_header
        .as_deref()
        .and_then(|value| format!("http://{value}").parse::<hyper::Uri>().ok());
    let host = target_uri
        .as_ref()
        .and_then(hyper::Uri::host)
        .or_else(|| header_uri.as_ref().and_then(hyper::Uri::host))
        .map(|value| value.to_ascii_lowercase());
    let port = target_uri
        .as_ref()
        .and_then(hyper::Uri::port_u16)
        .or_else(|| header_uri.as_ref().and_then(hyper::Uri::port_u16))
        .or_else(|| {
            if method == "CONNECT"
                || path
                    .get(..8)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
            {
                Some(443)
            } else {
                Some(80)
            }
        });
    Some((host, port, method, path, proxy_form))
}

fn parse_git(data: &[u8]) -> Option<(String, String, Option<String>)> {
    if data.len() < 5 {
        return None;
    }
    let len = usize::from_str_radix(std::str::from_utf8(&data[..4]).ok()?, 16).ok()?;
    if len < 5 || len > data.len() {
        return None;
    }
    let payload = std::str::from_utf8(&data[4..len]).ok()?;
    let (service, rest) = payload.split_once(' ')?;
    if service != "git-upload-pack" && service != "git-receive-pack" {
        return None;
    }
    let mut fields = rest.split('\0');
    let path = fields.next()?.to_string();
    let host = fields.find_map(|field| field.strip_prefix("host=").map(str::to_string));
    Some((service.to_string(), path, host))
}

struct TlsClientHello {
    sni: Option<String>,
    alpn: Vec<Vec<u8>>,
}

fn inspect_tls_client_hello(data: &[u8]) -> Option<TlsClientHello> {
    if data.len() < 5 || data[0] != 22 {
        return None;
    }
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len || record_len < 4 {
        return None;
    }
    let mut offset = 5;
    if data[offset] != 1 {
        return None;
    }
    offset += 4;
    offset += 2 + 32;
    let session_len = *data.get(offset)? as usize;
    offset += 1 + session_len;
    let cipher_len = u16::from_be_bytes([*data.get(offset)?, *data.get(offset + 1)?]) as usize;
    offset += 2 + cipher_len;
    let compression_len = *data.get(offset)? as usize;
    offset += 1 + compression_len;
    let extensions_len = u16::from_be_bytes([*data.get(offset)?, *data.get(offset + 1)?]) as usize;
    offset += 2;
    let limit = offset.checked_add(extensions_len)?.min(data.len());
    let mut sni = None;
    let mut alpn = Vec::new();
    while offset + 4 <= limit {
        let kind = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;
        if offset + len > limit {
            return None;
        }
        if kind == 0 && len >= 5 {
            let mut name_offset = offset + 2;
            while name_offset + 3 <= offset + len {
                let name_type = data[name_offset];
                let name_len =
                    u16::from_be_bytes([data[name_offset + 1], data[name_offset + 2]]) as usize;
                name_offset += 3;
                if name_offset + name_len > offset + len {
                    return None;
                }
                if name_type == 0 {
                    sni = std::str::from_utf8(&data[name_offset..name_offset + name_len])
                        .ok()
                        .map(str::to_string);
                    break;
                }
                name_offset += name_len;
            }
        } else if kind == 16 && len >= 3 {
            let list_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            let list_limit = (offset + 2).checked_add(list_len)?;
            if list_limit > offset + len {
                return None;
            }
            let mut protocol_offset = offset + 2;
            while protocol_offset < list_limit {
                let protocol_len = *data.get(protocol_offset)? as usize;
                protocol_offset += 1;
                let protocol_end = protocol_offset.checked_add(protocol_len)?;
                if protocol_len == 0 || protocol_end > list_limit {
                    return None;
                }
                alpn.push(data[protocol_offset..protocol_end].to_vec());
                protocol_offset = protocol_end;
            }
        }
        offset += len;
    }
    Some(TlsClientHello { sni, alpn })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn client_hello(host: &str, protocols: &[&[u8]]) -> Vec<u8> {
        let mut extensions = Vec::new();
        let host = host.as_bytes();
        let mut sni = Vec::new();
        sni.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host);
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni);

        let mut alpn = Vec::new();
        let protocol_len = protocols.iter().map(|value| value.len() + 1).sum::<usize>();
        alpn.extend_from_slice(&(protocol_len as u16).to_be_bytes());
        for protocol in protocols {
            alpn.push(protocol.len() as u8);
            alpn.extend_from_slice(protocol);
        }
        extensions.extend_from_slice(&16u16.to_be_bytes());
        extensions.extend_from_slice(&(alpn.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&alpn);

        let mut body = Vec::new();
        body.extend_from_slice(&[3, 3]);
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![1, 0, 0, 0];
        let body_len = body.len();
        handshake[1] = ((body_len >> 16) & 0xff) as u8;
        handshake[2] = ((body_len >> 8) & 0xff) as u8;
        handshake[3] = (body_len & 0xff) as u8;
        handshake.extend_from_slice(&body);

        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn identifies_http_and_redacts_query() {
        let value = inspect(
            b"GET /path?token=x HTTP/1.1\r\nHost: github.com\r\n\r\n",
            80,
        );
        assert_eq!(value.protocol, Protocol::Http);
        assert_eq!(value.hostname.as_deref(), Some("github.com"));
        assert_eq!(value.detail.unwrap()["path"], "/path");
    }
    #[test]
    fn identifies_http_proxy_targets() {
        let value = inspect(
            b"GET http://api.example.test:8080/path HTTP/1.1\r\nHost: api.example.test:8080\r\n\r\n",
            7890,
        );
        assert!(value.proxy_form);
        assert_eq!(value.hostname.as_deref(), Some("api.example.test"));
        assert_eq!(value.port, Some(8080));
        assert_eq!(value.http_method.as_deref(), Some("GET"));

        let value = inspect(
            b"CONNECT api.example.test:443 HTTP/1.1\r\nHost: api.example.test:443\r\n\r\n",
            7890,
        );
        assert!(value.proxy_form);
        assert_eq!(value.hostname.as_deref(), Some("api.example.test"));
        assert_eq!(value.port, Some(443));
        assert_eq!(value.http_method.as_deref(), Some("CONNECT"));
    }

    #[test]
    fn identifies_ssh() {
        assert_eq!(
            inspect(b"SSH-2.0-OpenSSH_9.0\r\n", 22).protocol,
            Protocol::Ssh
        );
    }

    #[test]
    fn identifies_tls_sni_and_alpn() {
        let hello = client_hello("service.example", &[b"h2", b"custom/1"]);
        let inspection = inspect(&hello, 443);
        assert_eq!(inspection.protocol, Protocol::Tls);
        assert_eq!(inspection.hostname.as_deref(), Some("service.example"));
        assert_eq!(
            inspection.tls_alpn,
            vec![b"h2".to_vec(), b"custom/1".to_vec()]
        );
    }
    #[test]
    fn identifies_git() {
        let payload = b"git-upload-pack /repo.git\0host=example.com\0";
        let frame = format!("{:04x}", payload.len() + 4)
            .into_bytes()
            .into_iter()
            .chain(payload.iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(
            inspect(&frame, 9418).hostname.as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn identifies_git_smart_http() {
        let value = inspect(
            b"GET /owner/repo.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: example.com\r\n\r\n",
            80,
        );
        assert_eq!(value.protocol, Protocol::Git);
        assert_eq!(value.detail.unwrap()["operation"], "fetch");
    }
}
