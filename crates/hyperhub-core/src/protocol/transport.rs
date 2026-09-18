use crate::session::ClientProxySnapshot;
use tokio::net::TcpStream;

/// 上游连接的种类：`connect_for` 建立连接时如实记录，供状态机分派与审计使用。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpstreamTransport {
    /// 到 requested 地址的裸 TCP 连接（未执行任何代理握手）。
    Direct,
    /// 经 HTTP CONNECT / SOCKS5 握手建立的隧道，端点是 requested 地址。
    Tunneled,
}

pub(crate) struct ConnectedUpstream {
    pub stream: TcpStream,
    pub transport: UpstreamTransport,
    pub associated_client_proxy: Option<ClientProxySnapshot>,
}
