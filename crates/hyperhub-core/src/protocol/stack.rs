//! 递归协议栈（Protocol Stack v1）。
//!
//! `run_stack` 按注册顺序（`protocol::handlers::builtin_protocols()`）逐层探测
//! 入栈，深度达 `MAX_PROTOCOL_DEPTH` 或匹配终态层（raw）后出栈转发。每协议一个
//! `ProtocolHandler` 模块位于 `protocol/handlers/`：新增协议 = 新建模块实现
//! trait 并在注册表登记，无需改动 `handle_authenticated` 的分派。
//!
//! 入栈语义：`LayerContext.peek` 是已从 client 侧**消费**的前缀字节，服务层必须
//! 用 `PrefixedIo` 回放后再继续读取，避免与 socket 残留字节重复或丢失。
//!
//! 不变量：serve 对原对端说的协议 = 客户端对原对端说的协议；外层代理协议
//! （HTTP CONNECT、SOCKS5、absolute-form）端到端保留；MITM 只替换被审计的最内层。
//!
//! 逐层精化：每层命中后以"最后发现的协议"重新匹配 route（`refine_route_from_inspection`），
//! 最内层协议驱动 gate/审计/deny；是否精化/门控由层自己声明的 `LayerKind` 决定，
//! 栈机制按枚举分派，不再按层名字符串判断。

use crate::config::PluginProtocol;
use crate::inspect::Inspection;
use crate::plugin::PluginSet;
use crate::protocol::context::HandlerContext;
use crate::protocol::handlers::{builtin_protocols, RawLayer};
use std::future::Future;
use std::io;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};

/// 递归深度上限：超过即出栈透传，避免无限递归。
pub(crate) const MAX_PROTOCOL_DEPTH: usize = 8;

/// 读写流合并 trait：供 `BoxedStream` 类型对象使用。
pub(crate) trait ReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> ReadWrite for T {}

/// 栈内流：一层消费、一层封装，天然支持 TLS、代理隧道等流包装。
pub(crate) type BoxedStream = Box<dyn ReadWrite + Unpin + Send>;

/// 层上下文：入栈一层的全部输入。
pub(crate) struct LayerContext {
    pub inner: HandlerContext,
    pub client: BoxedStream,
    pub upstream: BoxedStream,
    /// 已从 client 侧消费的前缀字节，服务层必须用 `PrefixedIo` 回放。
    pub peek: Vec<u8>,
    pub depth: usize,
}

/// 层能力：加协议时在模块内声明，`run_stack` 与审计门控按枚举分派，
/// 不再按层名字符串判断。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LayerKind {
    /// 代理隧道层（HTTP CONNECT）：目标可承载任意协议，不参与逐层精化；
    /// 是否 MITM 由入口连接级决策门控（HTTPS 家族 / Git@443）。
    Tunnel,
    /// 无门控层（SOCKS5 / raw）：不参与逐层精化与栈级门控；
    /// socks5 在层内解析目标后自决策，raw 终态透传。
    Passthrough,
    /// HTTPS 可审计层（TLS）：命中后按探测协议精化 route，按 HTTPS 家族门控。
    Https,
    /// HTTP 可审计层（明文 HTTP）：命中后精化，按 HTTP 家族门控。
    Http,
    /// 原生协议层（SSH / Git 原生）：参与精化（deny/审计归属），不参与 MITM 门控。
    Native,
}

impl LayerKind {
    /// 是否参与逐层精化：命中后以"最后发现的协议"重新匹配 route。
    fn refines_route(self) -> bool {
        matches!(self, Self::Https | Self::Http | Self::Native)
    }

    /// 连接级审计门控：`Some(false)` 表示策略不在该层处理（出栈透传）；
    /// `None` 表示不参与门控，总是进入层服务。MITM/解析由插件 `protocols` 驱动：
    /// 命中 http 或 ws 插件才解密/解析，否则透传。
    fn audited(self, plugins: &PluginSet) -> Option<bool> {
        match self {
            Self::Tunnel | Self::Https | Self::Http => Some(plugins.iter().any(|plugin| {
                plugin.protocols.contains(&PluginProtocol::Http)
                    || plugin.protocols.contains(&PluginProtocol::Ws)
            })),
            Self::Native | Self::Passthrough => None,
        }
    }
}

/// 协议处理器：探测 + 服务 + 可下钻。加协议 = 在 `handlers/` 加模块并注册。
pub(crate) trait ProtocolHandler: Send + Sync {
    fn name(&self) -> &'static str;
    /// 层能力：精化与门控按 `LayerKind` 分派。
    fn kind(&self) -> LayerKind;
    fn detect(&self, data: &[u8], port: u16) -> Option<Inspection>;
    fn serve(&self, ctx: LayerContext)
        -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>>;
}

/// 递归协议栈：按注册顺序命中层 → 层 serve；深度超限或未命中终态层 → 透传。
pub(crate) async fn run_stack(
    client: BoxedStream,
    upstream: BoxedStream,
    peek: Vec<u8>,
    depth: usize,
    mut inner: HandlerContext,
) -> io::Result<()> {
    if depth >= MAX_PROTOCOL_DEPTH {
        return RawLayer
            .serve(LayerContext {
                inner,
                client,
                upstream,
                peek,
                depth,
            })
            .await;
    }
    let port = inner.context.destination.port;
    let detected = builtin_protocols().iter().copied().find_map(|layer| {
        layer
            .detect(&peek, port)
            .map(|inspection| (layer, inspection))
    });
    let Some((layer, inspection)) = detected else {
        return RawLayer
            .serve(LayerContext {
                inner,
                client,
                upstream,
                peek,
                depth,
            })
            .await;
    };
    // 逐层下钻：可审计层（Https/Http/Native）更新观测协议，供审计事件使用。
    if layer.kind().refines_route() {
        inner.context.protocol = inspection.protocol;
    }
    // 连接级决策门控：命中 MITM 能力层但该路由未绑定 http/ws 插件时出栈透传。
    if layer.kind().audited(&inner.decision.plugins) == Some(false) {
        return RawLayer
            .serve(LayerContext {
                inner,
                client,
                upstream,
                peek,
                depth,
            })
            .await;
    }
    layer
        .serve(LayerContext {
            inner,
            client,
            upstream,
            peek,
            depth,
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PluginConfig, PluginKind, PluginProtocol};
    use crate::inspect;
    use crate::plugin::PluginSet;
    use crate::policy::Destination;
    use std::net::IpAddr;

    fn credential(protocols: &[PluginProtocol]) -> PluginConfig {
        PluginConfig {
            uuid: crate::config::new_config_uuid(),
            id: "cred".into(),
            kind: PluginKind::Credential,
            protocols: protocols.to_vec(),
            ..PluginConfig::default()
        }
    }

    #[test]
    fn tunnel_http_https_gates_mitm_only_with_http_or_ws_plugins() {
        assert_eq!(
            LayerKind::Tunnel.audited(&PluginSet::default()),
            Some(false)
        );
        assert_eq!(
            LayerKind::Tunnel.audited(&PluginSet(vec![credential(&[PluginProtocol::Http])])),
            Some(true)
        );
        assert_eq!(
            LayerKind::Tunnel.audited(&PluginSet(vec![PluginConfig {
                uuid: crate::config::new_config_uuid(),
                id: "ws".into(),
                kind: PluginKind::Audit,
                protocols: vec![PluginProtocol::Ws],
                ..PluginConfig::default()
            }])),
            Some(true)
        );
        assert_eq!(
            LayerKind::Tunnel.audited(&PluginSet(vec![credential(&[PluginProtocol::Ssh])])),
            Some(false)
        );
    }

    #[test]
    fn http_gate_parses_only_with_http_or_ws_plugins() {
        assert_eq!(LayerKind::Http.audited(&PluginSet::default()), Some(false));
        assert_eq!(
            LayerKind::Http.audited(&PluginSet(vec![credential(&[PluginProtocol::Http])])),
            Some(true)
        );
    }

    #[test]
    fn https_gate_mitms_only_with_http_or_ws_plugins() {
        assert_eq!(LayerKind::Https.audited(&PluginSet::default()), Some(false));
        assert_eq!(
            LayerKind::Https.audited(&PluginSet(vec![credential(&[PluginProtocol::Ssh])])),
            Some(false)
        );
        assert_eq!(
            LayerKind::Https.audited(&PluginSet(vec![credential(&[PluginProtocol::Http])])),
            Some(true)
        );
    }

    #[test]
    fn layer_kind_declares_refinement_and_gate_capabilities() {
        for kind in [LayerKind::Https, LayerKind::Http, LayerKind::Native] {
            assert!(kind.refines_route(), "{kind:?} must refine");
        }
        for kind in [LayerKind::Tunnel, LayerKind::Passthrough] {
            assert!(!kind.refines_route(), "{kind:?} must not refine");
        }
        assert_eq!(LayerKind::Passthrough.audited(&PluginSet::default()), None);
        assert_eq!(LayerKind::Native.audited(&PluginSet::default()), None);
    }

    fn inner_context(port: u16) -> HandlerContext {
        use crate::audit::AuditWriter;
        use crate::config::Config;
        use crate::http::TlsMitm;
        use crate::policy::{ConnectionContext, PolicySnapshot, ProcessInfo};
        use crate::session::SessionRegistry;
        use std::sync::Arc;
        let config = Arc::new(Config::default());
        let policy = Arc::new(PolicySnapshot::compile(&config).unwrap());
        let context = ConnectionContext {
            session_id: "stack-test".into(),
            connection_id: 1,
            process: ProcessInfo {
                pid: 1,
                tid: 1,
                executable: "fixture".into(),
            },
            destination: Destination {
                ip: IpAddr::V4("203.0.113.1".parse().unwrap()),
                port,
                hostnames: vec!["example.com".into()],
            },
            protocol: crate::policy::Protocol::Tls,
        };
        let decision = policy.decide(&context);
        HandlerContext {
            host: "example.com".into(),
            mitm: TlsMitm::generate().unwrap(),
            ssh_mitm_key: Arc::new(crate::ssh_mitm::server_key_from_master(b"test")),
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

    #[tokio::test]
    async fn run_stack_bridges_when_depth_exceeds_limit() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut application, client) = tokio::io::duplex(128);
        let (upstream, mut target) = tokio::io::duplex(128);
        let hello = inspect::tests::client_hello("example.com", &[b"h2"]);
        // 深度已达上限：即使首包是 TLS ClientHello 也不再下钻，直接透传。
        let task = tokio::spawn(run_stack(
            Box::new(client),
            Box::new(upstream),
            hello.clone(),
            MAX_PROTOCOL_DEPTH,
            inner_context(443),
        ));
        let mut received = vec![0u8; hello.len()];
        target.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, &hello);
        application.shutdown().await.unwrap();
        target.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn run_stack_bridges_ssh_banner_without_parsing() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut application, client) = tokio::io::duplex(128);
        let (upstream, mut target) = tokio::io::duplex(128);
        let banner = b"SSH-2.0-OpenSSH_9.0\r\n";
        let task = tokio::spawn(run_stack(
            Box::new(client),
            Box::new(upstream),
            banner.to_vec(),
            0,
            inner_context(22),
        ));
        let mut received = vec![0u8; banner.len()];
        target.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, banner);
        application.shutdown().await.unwrap();
        target.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn run_stack_relays_nested_socks5_and_drills_down() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio::net::TcpStream;
        // 客户端自己的 SOCKS5 代理：收 greeting 选 NO AUTH，收 CONNECT 回成功，随后回显。
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(&greeting, &[5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();
            let mut head = [0u8; 4];
            stream.read_exact(&mut head).await.unwrap();
            assert_eq!(&head[..2], &[5, 1]);
            assert_eq!(head[2], 0);
            match head[3] {
                1 => {
                    let mut rest = [0u8; 6];
                    stream.read_exact(&mut rest).await.unwrap();
                }
                3 => {
                    let mut length = [0u8; 1];
                    stream.read_exact(&mut length).await.unwrap();
                    let mut rest = vec![0u8; length[0] as usize + 2];
                    stream.read_exact(&mut rest).await.unwrap();
                }
                4 => {
                    let mut rest = [0u8; 18];
                    stream.read_exact(&mut rest).await.unwrap();
                }
                _ => panic!("unexpected address type"),
            }
            stream
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut buffer = [0u8; 16];
            loop {
                let count = stream.read(&mut buffer).await.unwrap();
                if count == 0 {
                    break;
                }
                stream.write_all(&buffer[..count]).await.unwrap();
            }
        });

        let (mut application, client) = tokio::io::duplex(128);
        let upstream = TcpStream::connect(proxy_address).await.unwrap();
        // 首包 = 客户端自己的 SOCKS5 greeting，已消费后作为栈首包入栈。
        let task = tokio::spawn(run_stack(
            Box::new(client),
            Box::new(upstream),
            vec![5, 1, 0],
            0,
            inner_context(proxy_address.port()),
        ));

        application
            .write_all(&[
                5, 1, 0, 3, 9, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't', 1, 0xbb,
            ])
            .await
            .unwrap();
        let mut selected = [0u8; 2];
        application.read_exact(&mut selected).await.unwrap();
        assert_eq!(&selected, &[5, 0]);
        let mut reply = [0u8; 10];
        application.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply[..2], &[5, 0]);

        application.write_all(b"ping").await.unwrap();
        let mut echo = [0u8; 4];
        application.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping");

        application.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
        proxy_task.await.unwrap();
    }
}
