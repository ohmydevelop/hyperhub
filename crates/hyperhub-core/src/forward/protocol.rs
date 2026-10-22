use super::authority::{Request, Response};
use crate::config::Config;
use crate::connector::EnvironmentProxy;
use crate::http::TlsAuthority;
use crate::session::AuthenticatedSession;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::Zeroize;

pub(crate) const VERSION: u32 = 1;
pub(super) const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnginePreflight {
    pub manifest: hyperhub_runtime::Manifest,
    pub source: PathBuf,
    pub cache: PathBuf,
}

// This material contains signing and upstream credentials. Never derive Debug.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Bootstrap {
    pub config: Config,
    pub audit_log: Option<PathBuf>,
    pub transcript_dir: Option<PathBuf>,
    pub tls: TlsAuthority,
    pub roots: Vec<Vec<u8>>,
    pub ssh_private_key: String,
    pub environment: EnvironmentProxy,
    pub trust: bool,
    pub engine: Option<EnginePreflight>,
}
impl Drop for Bootstrap {
    fn drop(&mut self) {
        self.ssh_private_key.zeroize();
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identity {
    pub session_id: String,
    pub pid: u32,
    pub connection_id: u64,
    pub executable: String,
}
impl From<&AuthenticatedSession> for Identity {
    fn from(session: &AuthenticatedSession) -> Self {
        Self {
            session_id: session.session_id.clone(),
            pid: session.pid,
            connection_id: session.connection_id,
            executable: session.executable.clone(),
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Frame {
    Bootstrap {
        protocol: u32,
        parent_pid: u32,
        worker_pid: u32,
        generation: u64,
        nonce: String,
        material: Box<Bootstrap>,
    },
    Rejected {
        requires_restart: bool,
    },
    Booted {
        protocol: u32,
        parent_pid: u32,
        worker_pid: u32,
        generation: u64,
        nonce: String,
        version: String,
    },
    Offer {
        id: u64,
        identity: Identity,
        config: Box<Config>,
        audit_log: Option<PathBuf>,
        transcript_dir: Option<PathBuf>,
    },
    Ready {
        id: u64,
    },
    Grant {
        id: u64,
    },
    Cancel {
        id: u64,
    },
    Finished {
        id: u64,
        error: Option<String>,
    },
    Rpc {
        id: u64,
        offer: u64,
        request: Request,
    },
    Reply {
        id: u64,
        response: Response,
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    Drain,
    Drained,
}
