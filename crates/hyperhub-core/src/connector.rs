use crate::config::{SecretValue, Upstream, UpstreamKind};
use crate::policy::Destination;
use base64::Engine;
use ipnet::IpNet;
use std::collections::HashMap;
use std::env;
use std::io;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const ENV_PROXY_TIMEOUT_MS: u64 = 10_000;

#[derive(Clone, Debug, Default)]
pub struct EnvironmentProxy {
    https: Option<EnvironmentUpstream>,
    http: Option<EnvironmentUpstream>,
    all: Option<EnvironmentUpstream>,
    no_proxy: Vec<NoProxyRule>,
}

#[derive(Clone, Debug)]
struct EnvironmentUpstream {
    upstream: Upstream,
    host: String,
    port: u16,
}

#[derive(Clone, Debug)]
enum NoProxyRule {
    Any,
    Host { value: String, port: Option<u16> },
    Ip { value: IpAddr, port: Option<u16> },
    Network(IpNet),
}

impl EnvironmentProxy {
    pub fn from_env() -> io::Result<Self> {
        Self::from_values(
            read_proxy_env("https_proxy", "HTTPS_PROXY"),
            read_proxy_env("http_proxy", "HTTP_PROXY"),
            read_proxy_env("all_proxy", "ALL_PROXY"),
            read_proxy_env("no_proxy", "NO_PROXY"),
        )
    }

    fn from_values(
        https: Option<String>,
        http: Option<String>,
        all: Option<String>,
        no_proxy: Option<String>,
    ) -> io::Result<Self> {
        Ok(Self {
            https: https
                .map(|value| parse_environment_upstream("HTTPS_PROXY", &value))
                .transpose()?,
            http: http
                .map(|value| parse_environment_upstream("HTTP_PROXY", &value))
                .transpose()?,
            all: all
                .map(|value| parse_environment_upstream("ALL_PROXY", &value))
                .transpose()?,
            no_proxy: no_proxy.as_deref().map(parse_no_proxy).unwrap_or_default(),
        })
    }

    pub fn upstream_for(&self, destination: &Destination) -> Option<Upstream> {
        if self.no_proxy.iter().any(|rule| rule.matches(destination)) {
            return None;
        }
        let selected = match destination.port {
            80 => self.http.as_ref().or(self.all.as_ref()),
            443 => self.https.as_ref().or(self.all.as_ref()),
            _ => self.all.as_ref(),
        }?;
        if selected.points_to(destination) {
            return None;
        }
        Some(selected.upstream.clone())
    }
}

impl EnvironmentUpstream {
    fn points_to(&self, destination: &Destination) -> bool {
        if destination.port != self.port {
            return false;
        }
        if self
            .host
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip == destination.ip)
        {
            return true;
        }
        destination
            .hostnames
            .iter()
            .any(|host| normalize_host(host) == self.host)
    }
}

impl NoProxyRule {
    fn matches(&self, destination: &Destination) -> bool {
        match self {
            Self::Any => true,
            Self::Host { value, port } => {
                port.is_none_or(|port| port == destination.port)
                    && destination.hostnames.iter().any(|host| {
                        let host = normalize_host(host);
                        host == *value || host.ends_with(&format!(".{value}"))
                    })
            }
            Self::Ip { value, port } => {
                port.is_none_or(|port| port == destination.port) && destination.ip == *value
            }
            Self::Network(network) => network.contains(&destination.ip),
        }
    }
}

fn read_proxy_env(lower: &str, upper: &str) -> Option<String> {
    env::var(lower)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            env::var(upper)
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
}

fn parse_environment_upstream(name: &str, value: &str) -> io::Result<EnvironmentUpstream> {
    let value = value.trim();
    let (scheme, remainder) = value
        .split_once("://")
        .map(|(scheme, remainder)| (scheme.to_ascii_lowercase(), remainder))
        .unwrap_or_else(|| ("http".to_owned(), value));
    let (kind, default_port) = match scheme.as_str() {
        "http" => (UpstreamKind::HttpConnect, 80),
        "socks" | "socks5" | "socks5h" => (UpstreamKind::Socks5, 1080),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{name} uses unsupported proxy scheme '{scheme}'; supported schemes: http, socks, socks5, socks5h"
                ),
            ))
        }
    };
    let authority = remainder.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} has no proxy address"),
        ));
    }
    let (credentials, address) = authority
        .rsplit_once('@')
        .map_or((None, authority), |(credentials, address)| {
            (Some(credentials), address)
        });
    let (host, port) = parse_host_port(address, default_port).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid {name}: {error}"),
        )
    })?;
    let (username, password) = credentials
        .map(|credentials| {
            let (username, password) = credentials.split_once(':').unwrap_or((credentials, ""));
            Ok::<_, io::Error>((
                Some(SecretValue::Inline {
                    value: percent_decode(username)?,
                }),
                Some(SecretValue::Inline {
                    value: percent_decode(password)?,
                }),
            ))
        })
        .transpose()?
        .unwrap_or((None, None));
    let address = format_host_port(&host, port);
    Ok(EnvironmentUpstream {
        upstream: Upstream {
            id: format!("env:{name}"),
            kind,
            address,
            timeout_ms: ENV_PROXY_TIMEOUT_MS,
            username,
            password,
            headers: HashMap::new(),
        },
        host: normalize_host(&host),
        port,
    })
}

fn parse_host_port(value: &str, default_port: u16) -> Result<(String, u16), &'static str> {
    if let Some(rest) = value.strip_prefix('[') {
        let Some((host, suffix)) = rest.split_once(']') else {
            return Err("unterminated IPv6 address");
        };
        let port = if suffix.is_empty() {
            default_port
        } else {
            suffix
                .strip_prefix(':')
                .ok_or("unexpected characters after IPv6 address")?
                .parse()
                .map_err(|_| "invalid proxy port")?
        };
        if host.is_empty() {
            return Err("empty proxy host");
        }
        return Ok((host.to_owned(), port));
    }
    let colon_count = value.bytes().filter(|byte| *byte == b':').count();
    if colon_count > 1 {
        return Err("IPv6 proxy addresses must be enclosed in brackets");
    }
    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) => (host, port.parse().map_err(|_| "invalid proxy port")?),
        None => (value, default_port),
    };
    if host.is_empty() {
        return Err("empty proxy host");
    }
    Ok((host.to_owned(), port))
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn percent_decode(value: &str) -> io::Result<String> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            output.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "proxy credentials contain incomplete percent encoding",
            ));
        }
        let high = hex(bytes[index + 1]).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid proxy percent encoding",
            )
        })?;
        let low = hex(bytes[index + 2]).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid proxy percent encoding",
            )
        })?;
        output.push((high << 4) | low);
        index += 3;
    }
    String::from_utf8(output).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "proxy credentials are not UTF-8",
        )
    })
}

fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn parse_no_proxy(value: &str) -> Vec<NoProxyRule> {
    value
        .split(',')
        .filter_map(|entry| parse_no_proxy_rule(entry.trim()))
        .collect()
}

fn parse_no_proxy_rule(value: &str) -> Option<NoProxyRule> {
    if value.is_empty() {
        return None;
    }
    if value == "*" {
        return Some(NoProxyRule::Any);
    }
    if let Ok(network) = value.parse::<IpNet>() {
        return Some(NoProxyRule::Network(network));
    }
    let (host, port) = parse_optional_no_proxy_port(value)?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(NoProxyRule::Ip { value: ip, port });
    }
    let value = normalize_host(host.trim_start_matches("*."));
    (!value.is_empty()).then_some(NoProxyRule::Host { value, port })
}

fn parse_optional_no_proxy_port(value: &str) -> Option<(&str, Option<u16>)> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, suffix) = rest.split_once(']')?;
        let port = if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':')?.parse().ok()?)
        };
        return Some((host, port));
    }
    if value.bytes().filter(|byte| *byte == b':').count() == 1 {
        let (host, port) = value.rsplit_once(':')?;
        if let Ok(port) = port.parse() {
            return Some((host, Some(port)));
        }
    }
    Some((value.trim_start_matches('.'), None))
}

fn normalize_host(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

pub async fn connect_direct(destination: Destination) -> io::Result<TcpStream> {
    if let Some(host) = destination.hostnames.first() {
        TcpStream::connect((host.as_str(), destination.port)).await
    } else {
        TcpStream::connect(SocketAddr::new(destination.ip, destination.port)).await
    }
}

pub async fn connect_upstream(
    upstream: Upstream,
    destination: Destination,
) -> io::Result<TcpStream> {
    let result = async {
        let mut stream = TcpStream::connect(&upstream.address)
            .await
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "connect to upstream proxy '{}' failed: {error}",
                        upstream.address
                    ),
                )
            })?;
        match upstream.kind {
            UpstreamKind::Socks5 => socks5_handshake(&mut stream, &upstream, &destination).await?,
            UpstreamKind::HttpConnect => {
                http_connect_handshake(&mut stream, &upstream, &destination).await?
            }
        }
        Ok(stream)
    };
    timeout(upstream.timeout(), result)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream proxy timeout"))?
}

async fn socks5_handshake(
    stream: &mut TcpStream,
    upstream: &Upstream,
    destination: &Destination,
) -> io::Result<()> {
    let username = resolve_optional(upstream.username.as_ref())?;
    let password = resolve_optional(upstream.password.as_ref())?;
    if username.is_some() != password.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOCKS5 username and password must be configured together",
        ));
    }
    if username.is_some() {
        stream.write_all(&[5, 2, 0, 2]).await?;
    } else {
        stream.write_all(&[5, 1, 0]).await?;
    }
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    if method[0] != 5 || method[1] == 0xff {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 proxy rejected authentication methods",
        ));
    }
    if method[1] == 2 {
        let username = username.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 requested credentials",
            )
        })?;
        let password = password.unwrap_or_default();
        if username.len() > 255 || password.len() > 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS5 credential exceeds 255 bytes",
            ));
        }
        let mut auth = Vec::with_capacity(username.len() + password.len() + 3);
        auth.extend([1, username.len() as u8]);
        auth.extend(username.as_bytes());
        auth.push(password.len() as u8);
        auth.extend(password.as_bytes());
        stream.write_all(&auth).await?;
        let mut reply = [0u8; 2];
        stream.read_exact(&mut reply).await?;
        if reply != [1, 0] {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 authentication failed",
            ));
        }
    } else if method[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SOCKS5 selected unsupported authentication",
        ));
    }

    let mut request = vec![5, 1, 0];
    if let Some(host) = destination.hostnames.first() {
        if host.len() > 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "destination hostname exceeds 255 bytes",
            ));
        }
        request.extend([3, host.len() as u8]);
        request.extend(host.as_bytes());
    } else {
        match destination.ip {
            std::net::IpAddr::V4(ip) => {
                request.push(1);
                request.extend(ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                request.push(4);
                request.extend(ip.octets());
            }
        }
    }
    request.extend(destination.port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 5 || head[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 CONNECT failed with code {}", head[1]),
        ));
    }
    let tail = match head[3] {
        1 => 4,
        4 => 16,
        3 => stream.read_u8().await? as usize,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid SOCKS5 address type",
            ))
        }
    };
    let mut discard = vec![0; tail + 2];
    stream.read_exact(&mut discard).await?;
    Ok(())
}

async fn http_connect_handshake(
    stream: &mut TcpStream,
    upstream: &Upstream,
    destination: &Destination,
) -> io::Result<()> {
    let host = destination
        .hostnames
        .first()
        .cloned()
        .unwrap_or_else(|| destination.ip.to_string());
    let authority = if destination.ip.is_ipv6() && destination.hostnames.is_empty() {
        format!("[{host}]:{}", destination.port)
    } else {
        format!("{host}:{}", destination.port)
    };
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let (Some(username), Some(password)) = (
        resolve_optional(upstream.username.as_ref())?,
        resolve_optional(upstream.password.as_ref())?,
    ) {
        let value =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        request.push_str(&format!("Proxy-Authorization: Basic {value}\r\n"));
    }
    for (name, value) in &upstream.headers {
        validate_header_name(name)?;
        let value = value.resolve().map_err(io::Error::other)?;
        if value.contains(['\r', '\n']) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "proxy header contains newline",
            ));
        }
        request.push_str(name);
        request.push_str(": ");
        request.push_str(&value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    loop {
        if response.len() >= 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP CONNECT response too large",
            ));
        }
        let byte = stream.read_u8().await?;
        response.push(byte);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = std::str::from_utf8(&response).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP CONNECT response is not UTF-8",
        )
    })?;
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(0);
    if !(200..300).contains(&status) {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("HTTP CONNECT failed with status {status}"),
        ));
    }
    Ok(())
}

fn resolve_optional(value: Option<&SecretValue>) -> io::Result<Option<String>> {
    value
        .map(|v| v.resolve().map_err(io::Error::other))
        .transpose()
}

fn validate_header_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid HTTP header name",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn destination(host: &str, ip: &str, port: u16) -> Destination {
        Destination {
            ip: ip.parse().unwrap(),
            port,
            hostnames: (!host.is_empty())
                .then(|| host.to_owned())
                .into_iter()
                .collect(),
        }
    }

    #[test]
    fn selects_protocol_specific_proxy_before_all_proxy() {
        let proxies = EnvironmentProxy::from_values(
            Some("http://https-proxy.example:8443".into()),
            Some("http://http-proxy.example:8080".into()),
            Some("socks5://all-proxy.example:1080".into()),
            None,
        )
        .unwrap();

        let https = proxies
            .upstream_for(&destination("chatgpt.com", "203.0.113.10", 443))
            .unwrap();
        assert_eq!(https.kind, UpstreamKind::HttpConnect);
        assert_eq!(https.address, "https-proxy.example:8443");

        let http = proxies
            .upstream_for(&destination("example.com", "203.0.113.11", 80))
            .unwrap();
        assert_eq!(http.address, "http-proxy.example:8080");

        let ssh = proxies
            .upstream_for(&destination("git.example.com", "203.0.113.12", 22))
            .unwrap();
        assert_eq!(ssh.kind, UpstreamKind::Socks5);
        assert_eq!(ssh.address, "all-proxy.example:1080");
    }

    #[test]
    fn parses_proxy_credentials_without_leaking_them_into_address() {
        let proxies = EnvironmentProxy::from_values(
            Some("http://alice:p%40ss@proxy.example:3128".into()),
            None,
            None,
            None,
        )
        .unwrap();
        let upstream = proxies
            .upstream_for(&destination("example.com", "203.0.113.1", 443))
            .unwrap();
        assert_eq!(upstream.address, "proxy.example:3128");
        assert_eq!(upstream.username.unwrap().resolve().unwrap(), "alice");
        assert_eq!(upstream.password.unwrap().resolve().unwrap(), "p@ss");
    }

    #[test]
    fn no_proxy_supports_domain_port_ip_and_cidr() {
        let proxies = EnvironmentProxy::from_values(
            None,
            None,
            Some("socks5://proxy.example:1080".into()),
            Some(".example.com,api.test:443,127.0.0.1,10.0.0.0/8".into()),
        )
        .unwrap();

        assert!(proxies
            .upstream_for(&destination("sub.example.com", "203.0.113.1", 443),)
            .is_none());
        assert!(proxies
            .upstream_for(&destination("api.test", "203.0.113.2", 443),)
            .is_none());
        assert!(proxies
            .upstream_for(&destination("api.test", "203.0.113.2", 80),)
            .is_some());
        assert!(proxies
            .upstream_for(&destination("", "10.20.30.40", 22),)
            .is_none());
    }

    #[test]
    fn does_not_route_a_proxy_connection_back_to_itself() {
        let proxies = EnvironmentProxy::from_values(
            Some("http://proxy.example:8080".into()),
            None,
            None,
            None,
        )
        .unwrap();
        assert!(proxies
            .upstream_for(&destination("proxy.example", "192.0.2.1", 8080),)
            .is_none());
    }

    #[tokio::test]
    async fn environment_http_proxy_uses_connect_for_https() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                request.push(stream.read_u8().await.unwrap());
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request
                .starts_with("CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: chatgpt.com:443\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
        });
        let proxies = EnvironmentProxy::from_values(
            Some(format!("http://{proxy_address}")),
            None,
            None,
            None,
        )
        .unwrap();
        let destination = destination("chatgpt.com", "203.0.113.10", 443);
        let upstream = proxies.upstream_for(&destination).unwrap();
        connect_upstream(upstream, destination).await.unwrap();
        proxy.await.unwrap();
    }

    #[test]
    fn rejects_unsupported_proxy_schemes() {
        let error = EnvironmentProxy::from_values(
            Some("https://proxy.example:443".into()),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported proxy scheme 'https'"));
        assert!(error.to_string().contains("socks5"));
    }

    #[test]
    fn accepts_socks_alias_as_socks5() {
        for scheme in ["socks", "socks5", "socks5h"] {
            let proxies = EnvironmentProxy::from_values(
                None,
                None,
                Some(format!("{scheme}://127.0.0.1:1080")),
                None,
            )
            .unwrap();
            let upstream = proxies
                .upstream_for(&destination("example.com", "203.0.113.1", 22))
                .unwrap();
            assert_eq!(upstream.kind, UpstreamKind::Socks5);
            assert_eq!(upstream.address, "127.0.0.1:1080");
        }
    }
}
