use crate::audit::AuditCategory;
use crate::policy::Destination;
use crate::session::{ConnectionSnapshot, SessionRegistry};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::io;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Request {
    FakeIp {
        session_id: String,
        address: IpAddr,
    },
    Audit {
        category: AuditCategory,
        event: String,
        dimensions: Map<String, Value>,
        attributes: Value,
        debug_only: bool,
    },
    DebugEnabled,
    Connection {
        snapshot: ConnectionSnapshot,
    },
    ConnectionClosed {
        session_id: String,
        pid: u32,
        connection_id: u64,
    },
    TlsMaterial {
        host: String,
        port: u16,
    },
    TrustTls {
        host: String,
        port: u16,
        certificate: Vec<u8>,
    },
    TrustSsh {
        host: String,
        port: u16,
        key_type: String,
        key_blob: String,
    },
    RememberProxy {
        session_id: String,
        destination: Destination,
        protocol: String,
        address: String,
    },
    LookupProxy {
        session_id: String,
        destination: Destination,
    },
}
#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Response {
    Ok,
    FakeIp {
        hostname: Option<String>,
    },
    DebugEnabled {
        enabled: bool,
    },
    TlsMaterial {
        roots: Vec<TlsAnchor>,
        host_certificate: Option<Vec<u8>>,
    },
    Proxy {
        proxy: Option<crate::socks::LearnedProxy>,
    },
    Error {
        message: String,
    },
}
#[derive(Deserialize, Serialize)]
pub(crate) struct TlsAnchor {
    pub(crate) subject: Vec<u8>,
    pub(crate) subject_public_key_info: Vec<u8>,
    pub(crate) name_constraints: Option<Vec<u8>>,
}
/// The transport owns authentication and peer/offer association. Calls have no
/// implicit retry; a lost result cannot be treated as an unexecuted mutation.
pub(crate) trait Rpc: Send + Sync {
    fn call(&self, request: Request) -> io::Result<Response>;
}
#[derive(Clone)]
pub(crate) struct Client(Arc<dyn Rpc>);
impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ResidentAuthority")
    }
}
impl Client {
    pub(crate) fn new(rpc: impl Rpc + 'static) -> Self {
        Self(Arc::new(rpc))
    }
    pub(crate) fn call(&self, request: Request) -> io::Result<Response> {
        match self.0.call(request)? {
            Response::Error { message } => Err(io::Error::other(message)),
            response => Ok(response),
        }
    }
    pub(crate) fn expect_ok(&self, request: Request) -> io::Result<()> {
        match self.call(request)? {
            Response::Ok => Ok(()),
            _ => Err(invalid_response()),
        }
    }
}
pub(crate) fn invalid_response() -> io::Error {
    io::Error::other("invalid resident authority response")
}

#[derive(Clone)]
pub(crate) enum NameService {
    Local(SessionRegistry),
    Remote(Client),
}
impl From<SessionRegistry> for NameService {
    fn from(registry: SessionRegistry) -> Self {
        Self::Local(registry)
    }
}
impl NameService {
    pub(crate) fn restore_fake(
        &self,
        session_id: &str,
        address: IpAddr,
    ) -> io::Result<Option<String>> {
        match self {
            Self::Local(registry) => Ok(registry.restore_fake(session_id, address)),
            Self::Remote(client) => match client.call(Request::FakeIp {
                session_id: session_id.into(),
                address,
            })? {
                Response::FakeIp { hostname } => Ok(hostname),
                _ => Err(invalid_response()),
            },
        }
    }
}
