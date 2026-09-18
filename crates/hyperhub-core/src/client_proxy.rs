//! Recognition and preservation of proxy protocols configured by the target
//! application. The injected agent never parses these protocols.

use crate::policy::Destination;
use crate::session::SessionRegistry;
use std::io;
use std::net::IpAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const SOCKS_VERSION: u8 = 5;
const AUTH_USERPASS: u8 = 2;

#[derive(Debug)]
pub(crate) enum Socks5Target {
    Ip(IpAddr, u16),
    Domain(String, u16),
}

pub(crate) fn is_socks5_greeting(data: &[u8]) -> bool {
    if data.len() < 3 || data[0] != SOCKS_VERSION || data[1] == 0 {
        return false;
    }
    data.len() >= 2 + data[1] as usize
}

/// Relays method negotiation (including RFC 1929) to the application's
/// original proxy, then consumes and returns its CONNECT destination.
pub(crate) async fn negotiate_socks5<C, P>(
    client: &mut C,
    proxy: &mut P,
) -> io::Result<Socks5Target>
where
    C: AsyncRead + AsyncWrite + Unpin,
    P: AsyncRead + AsyncWrite + Unpin,
{
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).await?;
    if greeting[0] != SOCKS_VERSION || greeting[1] == 0 {
        return Err(invalid("invalid client SOCKS5 greeting"));
    }
    let mut methods = vec![0u8; greeting[1] as usize];
    client.read_exact(&mut methods).await?;
    proxy.write_all(&greeting).await?;
    proxy.write_all(&methods).await?;
    proxy.flush().await?;

    let mut selected = [0u8; 2];
    proxy.read_exact(&mut selected).await?;
    client.write_all(&selected).await?;
    client.flush().await?;
    if selected[0] != SOCKS_VERSION || selected[1] == 0xff {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "original SOCKS5 proxy rejected authentication methods",
        ));
    }
    match selected[1] {
        0 => {}
        AUTH_USERPASS => relay_rfc1929(client, proxy).await?,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "original SOCKS5 proxy selected an unsupported authentication method",
            ));
        }
    }

    let mut head = [0u8; 4];
    client.read_exact(&mut head).await?;
    if head[0] != SOCKS_VERSION || head[1] != 1 || head[2] != 0 {
        write_socks5_reply(client, 7).await?;
        return Err(invalid("client proxy only supports SOCKS5 CONNECT"));
    }
    let target = match head[3] {
        1 => {
            let mut bytes = [0u8; 4];
            client.read_exact(&mut bytes).await?;
            Socks5Target::Ip(IpAddr::V4(bytes.into()), client.read_u16().await?)
        }
        4 => {
            let mut bytes = [0u8; 16];
            client.read_exact(&mut bytes).await?;
            Socks5Target::Ip(IpAddr::V6(bytes.into()), client.read_u16().await?)
        }
        3 => {
            let length = client.read_u8().await? as usize;
            if length == 0 {
                write_socks5_reply(client, 8).await?;
                return Err(invalid("empty client SOCKS5 hostname"));
            }
            let mut bytes = vec![0u8; length];
            client.read_exact(&mut bytes).await?;
            let hostname = std::str::from_utf8(&bytes)
                .map_err(|_| invalid("client SOCKS5 hostname is not UTF-8"))?
                .to_ascii_lowercase();
            Socks5Target::Domain(hostname, client.read_u16().await?)
        }
        _ => {
            write_socks5_reply(client, 8).await?;
            return Err(invalid("unsupported client SOCKS5 address type"));
        }
    };
    let port = match &target {
        Socks5Target::Ip(_, port) | Socks5Target::Domain(_, port) => *port,
    };
    if port == 0 {
        write_socks5_reply(client, 8).await?;
        return Err(invalid("client SOCKS5 destination port is zero"));
    }
    Ok(target)
}

async fn relay_rfc1929<C, P>(client: &mut C, proxy: &mut P) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    P: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    if head[0] != 1 || head[1] == 0 {
        return Err(invalid("invalid client RFC1929 request"));
    }
    let mut username = vec![0u8; head[1] as usize];
    client.read_exact(&mut username).await?;
    let password_len = client.read_u8().await?;
    if password_len == 0 {
        return Err(invalid("empty client RFC1929 password"));
    }
    let mut password = vec![0u8; password_len as usize];
    client.read_exact(&mut password).await?;

    proxy.write_all(&head).await?;
    proxy.write_all(&username).await?;
    proxy.write_u8(password_len).await?;
    proxy.write_all(&password).await?;
    proxy.flush().await?;
    username.fill(0);
    password.fill(0);

    let mut reply = [0u8; 2];
    proxy.read_exact(&mut reply).await?;
    client.write_all(&reply).await?;
    client.flush().await?;
    if reply[0] != 1 || reply[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "original SOCKS5 proxy authentication failed",
        ));
    }
    Ok(())
}

pub(crate) async fn resolve_socks5_target(
    target: Socks5Target,
    session_id: &str,
    sessions: &SessionRegistry,
) -> io::Result<Destination> {
    match target {
        Socks5Target::Domain(hostname, port) => {
            let ip = tokio::net::lookup_host((hostname.as_str(), port))
                .await?
                .next()
                .map(|address| address.ip())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "client SOCKS5 hostname resolved to no addresses",
                    )
                })?;
            Ok(Destination {
                ip,
                port,
                hostnames: vec![hostname],
            })
        }
        Socks5Target::Ip(mut ip, port) => {
            let mut hostnames = Vec::new();
            if let Some(hostname) = sessions.restore_fake(session_id, ip) {
                ip = tokio::net::lookup_host((hostname.as_str(), port))
                    .await?
                    .next()
                    .map(|address| address.ip())
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            "client SOCKS5 Fake-IP hostname resolved to no addresses",
                        )
                    })?;
                hostnames.push(hostname);
            } else if is_fake_ip(ip) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unknown or expired client SOCKS5 Fake-IP",
                ));
            }
            Ok(Destination {
                ip,
                port,
                hostnames,
            })
        }
    }
}

pub(crate) async fn complete_socks5_connect<C, P>(
    client: &mut C,
    proxy: &mut P,
    destination: &Destination,
) -> io::Result<bool>
where
    C: AsyncRead + AsyncWrite + Unpin,
    P: AsyncRead + AsyncWrite + Unpin,
{
    proxy
        .write_all(&encode_socks5_connect(destination)?)
        .await?;
    proxy.flush().await?;

    let mut head = [0u8; 4];
    proxy.read_exact(&mut head).await?;
    if head[0] != SOCKS_VERSION || head[2] != 0 {
        return Err(invalid("invalid response from original SOCKS5 proxy"));
    }
    let mut reply = head.to_vec();
    match head[3] {
        1 => {
            let mut tail = [0u8; 6];
            proxy.read_exact(&mut tail).await?;
            reply.extend_from_slice(&tail);
        }
        4 => {
            let mut tail = [0u8; 18];
            proxy.read_exact(&mut tail).await?;
            reply.extend_from_slice(&tail);
        }
        3 => {
            let length = proxy.read_u8().await?;
            reply.push(length);
            let mut tail = vec![0u8; length as usize + 2];
            proxy.read_exact(&mut tail).await?;
            reply.extend_from_slice(&tail);
        }
        _ => return Err(invalid("invalid original SOCKS5 response address type")),
    }
    client.write_all(&reply).await?;
    client.flush().await?;
    Ok(head[1] == 0)
}

fn encode_socks5_connect(destination: &Destination) -> io::Result<Vec<u8>> {
    let mut request = vec![SOCKS_VERSION, 1, 0];
    if let Some(hostname) = destination.hostnames.first() {
        let bytes = hostname.as_bytes();
        if bytes.is_empty() || bytes.len() > u8::MAX as usize {
            return Err(invalid("client SOCKS5 hostname length is invalid"));
        }
        request.push(3);
        request.push(bytes.len() as u8);
        request.extend_from_slice(bytes);
    } else {
        match destination.ip {
            IpAddr::V4(address) => {
                request.push(1);
                request.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                request.push(4);
                request.extend_from_slice(&address.octets());
            }
        }
    }
    request.extend_from_slice(&destination.port.to_be_bytes());
    Ok(request)
}

pub(crate) async fn write_socks5_reply<C>(client: &mut C, code: u8) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    client
        .write_all(&[SOCKS_VERSION, code, 0, 1, 0, 0, 0, 0, 0, 0])
        .await?;
    client.flush().await
}

fn is_fake_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            octets[0] == 198 && matches!(octets[1], 18 | 19)
        }
        IpAddr::V6(address) => address.segments()[..5] == [0xfdfe, 0x6879, 0x7065, 0x7268, 0x7562],
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio::net::TcpStream;

    #[test]
    fn recognizes_complete_socks5_greetings() {
        assert!(is_socks5_greeting(&[5, 2, 0, 2]));
        assert!(is_socks5_greeting(&[5, 1, 0]));
        assert!(!is_socks5_greeting(&[5, 2, 0]));
        assert!(!is_socks5_greeting(b"GET / HTTP/1.1\r\n"));
    }

    #[tokio::test]
    async fn relays_rfc1929_without_exposing_credentials() {
        let original_proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = original_proxy.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut stream, _) = original_proxy.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 2]);
            stream.write_all(&[5, 2]).await.unwrap();
            let mut authentication = [0u8; 11];
            stream.read_exact(&mut authentication).await.unwrap();
            assert_eq!(&authentication, b"\x01\x04user\x04pass");
            stream.write_all(&[1, 0]).await.unwrap();
            let mut request = [0u8; 19];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..17], b"\x05\x01\x00\x03\x0cexample.test");
            assert_eq!(u16::from_be_bytes([request[17], request[18]]), 8080);
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
        });

        let ingress = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ingress_address = ingress.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut client, _) = ingress.accept().await.unwrap();
            let mut proxy = TcpStream::connect(proxy_address).await.unwrap();
            let target = negotiate_socks5(&mut client, &mut proxy).await.unwrap();
            assert!(matches!(
                target,
                Socks5Target::Domain(ref host, 8080) if host == "example.test"
            ));
            assert!(complete_socks5_connect(
                &mut client,
                &mut proxy,
                &Destination {
                    ip: "192.0.2.1".parse().unwrap(),
                    port: 8080,
                    hostnames: vec!["example.test".into()],
                },
            )
            .await
            .unwrap());
        });

        let mut client = TcpStream::connect(ingress_address).await.unwrap();
        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut selected = [0u8; 2];
        client.read_exact(&mut selected).await.unwrap();
        assert_eq!(selected, [5, 2]);
        client.write_all(b"\x01\x04user\x04pass").await.unwrap();
        let mut auth_reply = [0u8; 2];
        client.read_exact(&mut auth_reply).await.unwrap();
        assert_eq!(auth_reply, [1, 0]);
        client
            .write_all(b"\x05\x01\x00\x03\x0cexample.test\x1f\x90")
            .await
            .unwrap();
        let mut connect_reply = [0u8; 10];
        client.read_exact(&mut connect_reply).await.unwrap();
        assert_eq!(connect_reply[1], 0);
        server.await.unwrap();
        proxy_task.await.unwrap();
    }
}
