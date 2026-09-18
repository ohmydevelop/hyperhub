use crate::client_proxy::is_socks5_greeting;
use crate::inspect::Inspection;
use crate::policy::Protocol;
use crate::protocol::handlers::builtin_protocols;
use serde_json::json;

/// 入站传输：客户端在截获连接上实际发送的协议帧。
///
/// 这是状态机的第一个状态：客户端说了什么协议，serve 对原对端就说什么协议。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IngressTransport {
    /// 未知、SSH、git 原生等无代理帧的原始流量。
    Raw,
    /// 明文 HTTP（origin-form 或 absolute-form，非 CONNECT）。
    PlainHttp,
    /// HTTP 代理 CONNECT host:port。
    HttpConnect,
    /// SOCKS5 greeting。
    Socks5,
    /// TLS ClientHello。
    Tls,
}

/// 复用协议栈的注册顺序做首包探测；raw 终态层保证始终返回一个 Inspection。
pub(crate) fn detect(data: &[u8], port: u16) -> Inspection {
    for layer in builtin_protocols() {
        if let Some(mut inspection) = layer.detect(data, port) {
            if let Some(detail) = inspection.detail.as_mut() {
                detail["detector"] = json!(layer.name());
            }
            return inspection;
        }
    }
    Inspection::unknown()
}

/// 从首包分类入站传输。探测有界（16 KiB 内），未命中时按 Raw 处理。
pub(crate) fn classify_ingress(data: &[u8], port: u16) -> IngressTransport {
    if is_socks5_greeting(data) {
        return IngressTransport::Socks5;
    }
    let inspection = detect(data, port);
    if inspection.proxy_form
        && inspection
            .http_method
            .as_deref()
            .is_some_and(|method| method.eq_ignore_ascii_case("CONNECT"))
    {
        IngressTransport::HttpConnect
    } else if inspection.http_method.is_some() {
        IngressTransport::PlainHttp
    } else if inspection.protocol == Protocol::Tls {
        IngressTransport::Tls
    } else {
        IngressTransport::Raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspect;

    fn tls_client_hello(host: &str) -> Vec<u8> {
        inspect::tests::client_hello(host, &[b"h2"])
    }

    #[test]
    fn classifies_plaintext_smart_http_as_plain_http() {
        let data =
            b"GET /owner/repo.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(classify_ingress(data, 443), IngressTransport::PlainHttp);
    }

    #[test]
    fn classifies_http_connect_as_http_connect() {
        let data = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        assert_eq!(classify_ingress(data, 7890), IngressTransport::HttpConnect);
    }

    #[test]
    fn classifies_tls_client_hello_as_tls() {
        let hello = tls_client_hello("example.com");
        assert_eq!(classify_ingress(&hello, 443), IngressTransport::Tls);
    }

    #[test]
    fn classifies_socks5_greeting_as_socks5() {
        assert_eq!(classify_ingress(&[5, 1, 0], 1080), IngressTransport::Socks5);
        assert_eq!(
            classify_ingress(&[5, 2, 0, 2], 1080),
            IngressTransport::Socks5
        );
    }

    #[test]
    fn classifies_ssh_banner_as_raw() {
        assert_eq!(
            classify_ingress(b"SSH-2.0-OpenSSH_9.0\r\n", 22),
            IngressTransport::Raw
        );
    }
}
