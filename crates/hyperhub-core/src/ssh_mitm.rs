//! SSH 双向代理（MITM）：对客户端充当 SSH 服务端，对真实服务器充当 SSH 客户端，
//! 校验上游主机密钥、注入配置凭证，并在通道层双向桥接数据。
//!
//! 认证候选先私钥（公钥认证）后密码；用户名取自客户端 `USERAUTH_REQUEST`。
//! 端口转发（direct-tcpip / tcpip-forward）默认拒绝。

use crate::audit::{AuditWriter, TranscriptMetadata};
use crate::duplex::{prepare_transcript, CaptureConfig};
use crate::policy::ConnectionContext;
use crate::protocol::stack::BoxedStream;
use base64::Engine;
use russh::client;
use russh::server;
use russh::Channel;
use russh::ChannelId;
use russh::ChannelMsg;
use russh::ChannelReadHalf;
use russh::ChannelWriteHalf;
use russh::Pty;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex, OnceCell};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const SSH_EVENT_BUFFER_SIZE: usize = 64;
const SSH_CHANNEL_BUFFER_SIZE: usize = 64;
const SSH_AUDIT_BUFFER_SIZE: usize = 256;
const SSH_TRANSCRIPT_BUFFER_SIZE: usize = 32;
const SSH_TRANSCRIPT_FLUSH_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_AUDITED_COMMAND_BYTES: usize = 16 * 1024;

enum UpstreamControl {
    Pty {
        want_reply: bool,
        term: String,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        terminal_modes: Vec<(Pty, u32)>,
    },
    Shell(bool),
    Exec(Vec<u8>),
    Env {
        variable_name: String,
        variable_value: String,
    },
    WindowChange {
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    },
    Subsystem(String),
    Signal(russh::Sig),
    Eof,
    Close,
}

#[derive(Default)]
struct CommandBuffer {
    bytes: Vec<u8>,
    truncated: bool,
}

impl CommandBuffer {
    fn push(&mut self, data: &[u8]) -> Vec<(Vec<u8>, bool)> {
        let mut complete = Vec::new();
        for &byte in data {
            if byte == b'\n' || byte == b'\r' {
                if !self.bytes.is_empty() || self.truncated {
                    complete.push((std::mem::take(&mut self.bytes), self.truncated));
                    self.truncated = false;
                }
            } else if self.bytes.len() < MAX_AUDITED_COMMAND_BYTES {
                self.bytes.push(byte);
            } else {
                self.truncated = true;
            }
        }
        complete
    }
}

struct SshAuditEvent {
    event: &'static str,
    outcome: &'static str,
    bytes: Option<(u64, u64)>,
    detail: serde_json::Value,
}

#[derive(Default)]
struct ChannelCounters {
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
}

#[derive(Clone)]
struct SshAuditSink {
    sender: mpsc::Sender<SshAuditEvent>,
    dropped: Arc<AtomicU64>,
    enabled: bool,
}

impl SshAuditSink {
    fn emit(&self, event: SshAuditEvent) {
        if !self.enabled {
            return;
        }
        if self.sender.try_send(event).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

struct TranscriptState {
    size: u64,
    queued: usize,
    hash: Sha256,
    stopped: bool,
}

#[derive(Clone)]
struct TranscriptRecorder {
    sender: mpsc::Sender<Vec<u8>>,
    state: Arc<StdMutex<TranscriptState>>,
    limit: usize,
}

impl TranscriptRecorder {
    fn record(&self, data: &[u8]) {
        let mut state = self.state.lock().unwrap();
        state.size = state.size.saturating_add(data.len() as u64);
        state.hash.update(data);
        if state.stopped {
            return;
        }
        let count = self.limit.saturating_sub(state.queued).min(data.len());
        if count == 0 {
            state.stopped = true;
            return;
        }
        if self.sender.try_send(data[..count].to_vec()).is_err() {
            // 转录是旁路观察面；磁盘或队列变慢时停止捕获，绝不阻塞 SSH 数据转发。
            state.stopped = true;
            return;
        }
        state.queued += count;
        if count < data.len() || state.queued == self.limit {
            state.stopped = true;
        }
    }
}

struct TranscriptDirection {
    sender: Option<mpsc::Sender<Vec<u8>>>,
    worker: JoinHandle<io::Result<u64>>,
    path: PathBuf,
    direction: &'static str,
    state: Arc<StdMutex<TranscriptState>>,
}

impl TranscriptDirection {
    fn start(path: PathBuf, direction: &'static str) -> Self {
        let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(SSH_TRANSCRIPT_BUFFER_SIZE);
        let worker_path = path.clone();
        let worker = tokio::spawn(async move {
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .open(worker_path)
                .await?;
            let mut written = 0u64;
            while let Some(bytes) = receiver.recv().await {
                file.write_all(&bytes).await?;
                written = written.saturating_add(bytes.len() as u64);
            }
            file.flush().await?;
            Ok(written)
        });
        let state = Arc::new(StdMutex::new(TranscriptState {
            size: 0,
            queued: 0,
            hash: Sha256::new(),
            stopped: false,
        }));
        Self {
            sender: Some(sender),
            worker,
            path,
            direction,
            state,
        }
    }

    fn recorder(&self, limit: usize) -> TranscriptRecorder {
        TranscriptRecorder {
            sender: self.sender.as_ref().unwrap().clone(),
            state: self.state.clone(),
            limit,
        }
    }

    async fn finish(mut self) -> (TranscriptMetadata, Option<String>) {
        self.sender.take();
        let (captured_size, error) =
            match tokio::time::timeout(SSH_TRANSCRIPT_FLUSH_TIMEOUT, &mut self.worker).await {
                Ok(Ok(Ok(written))) => (written, None),
                Ok(Ok(Err(error))) => (0, Some(error.to_string())),
                Ok(Err(error)) => (0, Some(error.to_string())),
                Err(_) => {
                    self.worker.abort();
                    (0, Some("transcript flush timed out".into()))
                }
            };
        let state = self.state.lock().unwrap();
        let size = state.size;
        let hash = state.hash.clone();
        drop(state);
        (
            TranscriptMetadata {
                direction: self.direction,
                path: self.path,
                sha256: format!("{:x}", hash.finalize()),
                size,
                captured_size,
                truncated: size > captured_size,
            },
            error,
        )
    }
}

struct SshTranscript {
    up: Option<TranscriptDirection>,
    down: Option<TranscriptDirection>,
    limit: usize,
}

impl SshTranscript {
    async fn open(mut config: CaptureConfig, channel: ChannelId) -> io::Result<Self> {
        config.stream_id = Some(channel.number().into());
        let (up_path, down_path) = config.transcript_paths("bin");
        let prepare_up = config.client_upload.then(|| up_path.clone());
        let prepare_down = config.server_response.then(|| down_path.clone());
        tokio::task::spawn_blocking(move || {
            if let Some(path) = prepare_up.as_deref() {
                prepare_transcript(path)?;
            }
            if let Some(path) = prepare_down.as_deref() {
                prepare_transcript(path)?;
            }
            Ok::<(), io::Error>(())
        })
        .await
        .map_err(io::Error::other)??;
        Ok(Self {
            up: config
                .client_upload
                .then(|| TranscriptDirection::start(up_path, "client_to_target")),
            down: config
                .server_response
                .then(|| TranscriptDirection::start(down_path, "target_to_client")),
            limit: config.limit,
        })
    }

    fn recorders(&self) -> (Option<TranscriptRecorder>, Option<TranscriptRecorder>) {
        (
            self.up.as_ref().map(|value| value.recorder(self.limit)),
            self.down.as_ref().map(|value| value.recorder(self.limit)),
        )
    }

    async fn finish(self) -> (Vec<TranscriptMetadata>, Vec<String>) {
        let Self { up, down, .. } = self;
        let (up, down) = tokio::join!(
            async move {
                match up {
                    Some(value) => Some(value.finish().await),
                    None => None,
                }
            },
            async move {
                match down {
                    Some(value) => Some(value.finish().await),
                    None => None,
                }
            }
        );
        let mut transcripts = Vec::new();
        let mut errors = Vec::new();
        if let Some((metadata, error)) = up {
            transcripts.push(metadata);
            if let Some(error) = error {
                errors.push(format!("client_to_target: {error}"));
            }
        }
        if let Some((metadata, error)) = down {
            transcripts.push(metadata);
            if let Some(error) = error {
                errors.push(format!("target_to_client: {error}"));
            }
        }
        (transcripts, errors)
    }
}

struct Shared {
    server_handle: OnceCell<server::Handle>,
    upstream_write: Mutex<HashMap<ChannelId, Arc<ChannelWriteHalf<client::Msg>>>>,
    upstream_auth_error: Mutex<Option<String>>,
    line_buffers: Mutex<HashMap<ChannelId, CommandBuffer>>,
    shutdown: CancellationToken,
}

struct ServerHandler {
    shared: Arc<Shared>,
    client_handle: client::Handle<ClientHandler>,
    candidates: Arc<SshAuthCandidates>,
    upstream_auth: Option<(String, bool)>,
    audit: SshAuditSink,
    transcript: Option<CaptureConfig>,
}

/// SSH 上游认证账号；用户名精确匹配后，按顺序先尝试私钥，再尝试密码。
pub struct SshAuthAccount {
    pub username: String,
    pub keys: Vec<String>,
    pub passwords: Vec<String>,
}

pub struct SshAuthCandidates {
    pub accounts: Vec<SshAuthAccount>,
}

impl SshAuthCandidates {
    fn account_for(&self, username: &str) -> Option<&SshAuthAccount> {
        self.accounts
            .iter()
            .find(|account| account.username == username)
    }
}

/// SSH 审计上下文：MITM 过程中把 exec/shell 等事件写入统一审计流。
pub struct SshAuditContext {
    pub audit: AuditWriter,
    pub context: ConnectionContext,
    pub rule_id: Option<String>,
    pub server_key: Arc<russh::keys::PrivateKey>,
    /// 是否记录命令、shell、subsystem 与 channel close 等结构化 SSH 事件。
    pub record_events: bool,
    /// 仅在 SSH 已由凭证 MITM 解密后，旁路保存各 channel 的双向会话内容。
    pub transcript: Option<CaptureConfig>,
}

/// 从配置主密钥（session auth key）确定性派生 SSH MITM 服务端主机密钥，保证重启后稳定。
pub fn server_key_from_master(master: &[u8]) -> russh::keys::PrivateKey {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(master).expect("hmac accepts any key length");
    mac.update(b"hyperhub/ssh-mitm-server-key/v1");
    let digest = mac.finalize().into_bytes();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    let keypair = russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&seed);
    russh::keys::ssh_key::PrivateKey::new(
        russh::keys::ssh_key::private::KeypairData::from(keypair),
        "",
    )
    .expect("build ssh mitm server key")
}

fn spawn_audit_worker(
    audit: AuditWriter,
    context: ConnectionContext,
    rule_id: Option<String>,
    enabled: bool,
) -> (SshAuditSink, tokio::task::JoinHandle<()>) {
    let (sender, mut receiver) = mpsc::channel::<SshAuditEvent>(SSH_AUDIT_BUFFER_SIZE);
    let dropped = Arc::new(AtomicU64::new(0));
    let worker_dropped = dropped.clone();
    let worker = tokio::spawn(async move {
        while let Some(event) = receiver.recv().await {
            let audit = audit.clone();
            let context = context.clone();
            let rule_id = rule_id.clone();
            let _ = tokio::task::spawn_blocking(move || {
                audit.connection(
                    event.event,
                    &context,
                    rule_id.as_deref(),
                    "proxy",
                    event.outcome,
                    event.bytes,
                    None,
                    Some(event.detail),
                );
            })
            .await;
        }
        let count = worker_dropped.load(Ordering::Relaxed);
        if count > 0 {
            let _ = tokio::task::spawn_blocking(move || {
                audit.connection(
                    "ssh_audit_dropped",
                    &context,
                    rule_id.as_deref(),
                    "proxy",
                    "degraded",
                    None,
                    None,
                    Some(json!({"count": count, "reason": "audit_queue_full"})),
                );
            })
            .await;
        }
    });
    (
        SshAuditSink {
            sender,
            dropped,
            enabled,
        },
        worker,
    )
}

/// 客户端输入（server channel 读端）→ 上游（client channel 写端）。
/// 只转发数据并持续排空读缓冲；控制消息由 `ServerHandler` 回调按序转发。
async fn forward_client_to_upstream(
    mut read: ChannelReadHalf,
    write: Arc<ChannelWriteHalf<client::Msg>>,
    counters: Arc<ChannelCounters>,
    transcript: Option<TranscriptRecorder>,
) -> Result<&'static str, russh::Error> {
    while let Some(message) = read.wait().await {
        match message {
            ChannelMsg::Data { data } => {
                let count = data.len() as u64;
                if let Some(transcript) = &transcript {
                    transcript.record(&data);
                }
                write.data_bytes(data).await?;
                counters.bytes_up.fetch_add(count, Ordering::Relaxed);
            }
            ChannelMsg::ExtendedData { ext, data } => {
                let count = data.len() as u64;
                if let Some(transcript) = &transcript {
                    transcript.record(&data);
                }
                write.extended_data_bytes(ext, data).await?;
                counters.bytes_up.fetch_add(count, Ordering::Relaxed);
            }
            ChannelMsg::Close => return Ok("client_close"),
            _ => continue,
        }
    }
    Ok("client_disconnected")
}

/// 上游输出（client channel 读端）→ 客户端（server channel 写端），
/// `Success`/`ExitStatus` 等控制消息在数据之前按序送达，不会饿死。
async fn forward_upstream_to_client(
    mut read: ChannelReadHalf,
    write: Arc<ChannelWriteHalf<server::Msg>>,
    handle: server::Handle,
    server_id: ChannelId,
    counters: Arc<ChannelCounters>,
    transcript: Option<TranscriptRecorder>,
) -> Result<&'static str, russh::Error> {
    while let Some(message) = read.wait().await {
        let result = match message {
            ChannelMsg::Data { data } => {
                let count = data.len() as u64;
                if let Some(transcript) = &transcript {
                    transcript.record(&data);
                }
                write.data_bytes(data).await?;
                counters.bytes_down.fetch_add(count, Ordering::Relaxed);
                Ok(())
            }
            ChannelMsg::ExtendedData { ext, data } => {
                let count = data.len() as u64;
                if let Some(transcript) = &transcript {
                    transcript.record(&data);
                }
                write.extended_data_bytes(ext, data).await?;
                counters.bytes_down.fetch_add(count, Ordering::Relaxed);
                Ok(())
            }
            ChannelMsg::Eof => write.eof().await,
            ChannelMsg::Close => {
                write.close().await?;
                return Ok("upstream_close");
            }
            ChannelMsg::Success => handle
                .channel_success(server_id)
                .await
                .map_err(|_| russh::Error::SendError),
            ChannelMsg::Failure => handle
                .channel_failure(server_id)
                .await
                .map_err(|_| russh::Error::SendError),
            ChannelMsg::ExitStatus { exit_status } => write.exit_status(exit_status).await,
            ChannelMsg::ExitSignal {
                signal_name,
                core_dumped,
                error_message,
                lang_tag,
            } => handle
                .exit_signal_request(server_id, signal_name, core_dumped, error_message, lang_tag)
                .await
                .map_err(|_| russh::Error::SendError),
            _ => continue,
        };
        result?;
    }
    Ok("upstream_disconnected")
}

/// 一个 channel 只有固定大小的 russh 队列和 SSH window；任一方向结束时统一关闭两端并
/// 清理通道状态。慢消费者会在 `data_bytes` 上自然背压，不会产生额外堆积。
#[allow(clippy::too_many_arguments)]
async fn run_channel_bridge(
    server_id: ChannelId,
    server_read: ChannelReadHalf,
    server_write: Arc<ChannelWriteHalf<server::Msg>>,
    client_read: ChannelReadHalf,
    client_write: Arc<ChannelWriteHalf<client::Msg>>,
    server_handle: server::Handle,
    shared: Arc<Shared>,
    audit: SshAuditSink,
    transcript_config: Option<CaptureConfig>,
) {
    let counters = Arc::new(ChannelCounters::default());
    let transcript = match transcript_config {
        Some(config) => match SshTranscript::open(config, server_id).await {
            Ok(transcript) => Some(transcript),
            Err(error) => {
                audit.emit(SshAuditEvent {
                    event: "ssh_transcript_error",
                    outcome: "degraded",
                    bytes: None,
                    detail: json!({
                        "channel": server_id.number(),
                        "message": error.to_string(),
                    }),
                });
                None
            }
        },
        None => None,
    };
    let (up_transcript, down_transcript) = transcript
        .as_ref()
        .map(SshTranscript::recorders)
        .unwrap_or((None, None));
    let (reason, error) = {
        let up = forward_client_to_upstream(
            server_read,
            client_write.clone(),
            counters.clone(),
            up_transcript,
        );
        let down = forward_upstream_to_client(
            client_read,
            server_write.clone(),
            server_handle,
            server_id,
            counters.clone(),
            down_transcript,
        );
        tokio::pin!(up, down);

        tokio::select! {
            _ = shared.shutdown.cancelled() => ("session_shutdown", None),
            result = &mut up => match result {
                Ok(reason) => (reason, None),
                Err(error) => ("client_to_upstream_error", Some(error.to_string())),
            },
            result = &mut down => match result {
                Ok(reason) => (reason, None),
                Err(error) => ("upstream_to_client_error", Some(error.to_string())),
            },
        }
    };

    // close 是幂等的；这里是通道级 finally，确保错误、断连和会话退出走同一清理路径。
    let _ = tokio::time::timeout(Duration::from_secs(1), client_write.close()).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), server_write.close()).await;
    shared.upstream_write.lock().await.remove(&server_id);
    shared.line_buffers.lock().await.remove(&server_id);

    let (transcripts, transcript_errors) = match transcript {
        Some(transcript) => transcript.finish().await,
        None => (Vec::new(), Vec::new()),
    };
    let outcome = if error.is_some() { "error" } else { "closed" };
    audit.emit(SshAuditEvent {
        event: "ssh_channel_close",
        outcome,
        bytes: Some((
            counters.bytes_up.load(Ordering::Relaxed),
            counters.bytes_down.load(Ordering::Relaxed),
        )),
        detail: json!({
            "channel": server_id.number(),
            "reason": reason,
            "message": error,
            "transcripts": transcripts,
            "transcript_errors": transcript_errors,
        }),
    });
}

pub struct SshHostKeyExpectation {
    pub key_type: String,
    pub key_blob: String,
}

struct ClientHandler {
    expected: SshHostKeyExpectation,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        let key_type = server_public_key.algorithm().to_string();
        let key_blob = base64::engine::general_purpose::STANDARD.encode(
            server_public_key
                .to_bytes()
                .map_err(|_| russh::Error::Disconnect)?,
        );
        Ok(key_type == self.expected.key_type && key_blob == self.expected.key_blob)
    }
}

impl server::Handler for ServerHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<server::Auth, Self::Error> {
        self.ensure_upstream_auth(user).await;
        Ok(server::Auth::reject())
    }

    async fn auth_password(
        &mut self,
        user: &str,
        _password: &str,
    ) -> Result<server::Auth, Self::Error> {
        Ok(if self.ensure_upstream_auth(user).await {
            server::Auth::Accept
        } else {
            server::Auth::reject()
        })
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        _key: &russh::keys::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        Ok(if self.ensure_upstream_auth(user).await {
            server::Auth::Accept
        } else {
            server::Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let client_channel = self.client_handle.channel_open_session().await?;
        let server_id = channel.id();
        let (client_read, client_write) = client_channel.split();
        let (server_read, server_write) = channel.split();
        let client_write = Arc::new(client_write);
        let server_write = Arc::new(server_write);

        reply.accept().await;

        self.shared
            .upstream_write
            .lock()
            .await
            .insert(server_id, client_write.clone());

        let server_handle = self
            .shared
            .server_handle
            .get()
            .cloned()
            .expect("server handle must be set before channel open");
        tokio::spawn(run_channel_bridge(
            server_id,
            server_read,
            server_write,
            client_read,
            client_write,
            server_handle,
            self.shared.clone(),
            self.audit.clone(),
            self.transcript.clone(),
        ));
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if self.audit.enabled {
            self.record_shell_input(channel, data).await;
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.forward_control(
            channel,
            UpstreamControl::Pty {
                want_reply: true,
                term: term.to_string(),
                col_width,
                row_height,
                pix_width,
                pix_height,
                terminal_modes: modes.to_vec(),
            },
        )
        .await;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.audit.emit(SshAuditEvent {
            event: "ssh_shell",
            outcome: "exec",
            bytes: None,
            detail: json!({"channel": channel.number(), "type": "shell"}),
        });
        self.forward_control(channel, UpstreamControl::Shell(true))
            .await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).into_owned();
        self.audit.emit(SshAuditEvent {
            event: "ssh_command",
            outcome: "exec",
            bytes: None,
            detail: json!({"channel": channel.number(), "command": command}),
        });
        self.forward_control(channel, UpstreamControl::Exec(command.into_bytes()))
            .await;
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.forward_control(
            channel,
            UpstreamControl::Env {
                variable_name: variable_name.to_string(),
                variable_value: variable_value.to_string(),
            },
        )
        .await;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.forward_control(
            channel,
            UpstreamControl::WindowChange {
                col_width,
                row_height,
                pix_width,
                pix_height,
            },
        )
        .await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.audit.emit(SshAuditEvent {
            event: "ssh_subsystem",
            outcome: "exec",
            bytes: None,
            detail: json!({"channel": channel.number(), "name": name}),
        });
        self.forward_control(channel, UpstreamControl::Subsystem(name.to_string()))
            .await;
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: russh::Sig,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.forward_control(channel, UpstreamControl::Signal(signal))
            .await;
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.forward_control(channel, UpstreamControl::Eof).await;
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.forward_control(channel, UpstreamControl::Close).await;
        Ok(())
    }
}
impl ServerHandler {
    async fn forward_control(&self, channel: ChannelId, message: UpstreamControl) {
        let Some(write) = self
            .shared
            .upstream_write
            .lock()
            .await
            .get(&channel)
            .cloned()
        else {
            return;
        };
        let result = match message {
            UpstreamControl::Pty {
                want_reply,
                term,
                col_width,
                row_height,
                pix_width,
                pix_height,
                terminal_modes,
            } => {
                write
                    .request_pty(
                        want_reply,
                        &term,
                        col_width,
                        row_height,
                        pix_width,
                        pix_height,
                        &terminal_modes,
                    )
                    .await
            }
            UpstreamControl::Shell(want_reply) => write.request_shell(want_reply).await,
            UpstreamControl::Exec(command) => write.exec(true, command).await,
            UpstreamControl::Env {
                variable_name,
                variable_value,
            } => write.set_env(true, variable_name, variable_value).await,
            UpstreamControl::WindowChange {
                col_width,
                row_height,
                pix_width,
                pix_height,
            } => {
                write
                    .window_change(col_width, row_height, pix_width, pix_height)
                    .await
            }
            UpstreamControl::Subsystem(name) => write.request_subsystem(true, name).await,
            UpstreamControl::Signal(signal) => write.signal(signal).await,
            UpstreamControl::Eof => write.eof().await,
            UpstreamControl::Close => write.close().await,
        };
        if result.is_err() {
            let _ = write.close().await;
        }
    }

    async fn ensure_upstream_auth(&mut self, user: &str) -> bool {
        if let Some((cached_user, success)) = &self.upstream_auth {
            if cached_user == user {
                return *success;
            }
        }
        let success = self.authenticate_upstream(user).await;
        self.upstream_auth = Some((user.to_string(), success));
        success
    }

    async fn record_shell_input(&self, channel: ChannelId, data: &[u8]) {
        let mut buffers = self.shared.line_buffers.lock().await;
        let buffer = buffers.entry(channel).or_default();
        let complete = buffer.push(data);
        drop(buffers);

        for (line, truncated) in complete {
            let command = String::from_utf8_lossy(&line).trim().to_string();
            if command.is_empty() && !truncated {
                continue;
            }
            self.audit.emit(SshAuditEvent {
                event: "ssh_command",
                outcome: "exec",
                bytes: None,
                detail: json!({
                    "channel": channel.number(),
                    "command": command,
                    "kind": "stdin",
                    "truncated": truncated,
                }),
            });
        }
    }

    async fn authenticate_upstream(&mut self, user: &str) -> bool {
        let Some(account) = self.candidates.account_for(user) else {
            return false;
        };
        for pem in &account.keys {
            let key = match russh::keys::PrivateKey::from_openssh(pem.as_bytes()) {
                Ok(key) => key,
                Err(_) => continue,
            };
            let hash = match self.client_handle.best_supported_rsa_hash().await {
                Ok(Some(Some(hash))) if key.algorithm().is_rsa() => Some(hash),
                _ => None,
            };
            let key = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), hash);
            if let Ok(auth) = self
                .client_handle
                .authenticate_publickey(user.to_string(), key)
                .await
            {
                if auth.success() {
                    return true;
                }
            }
        }
        for password in &account.passwords {
            if let Ok(auth) = self
                .client_handle
                .authenticate_password(user.to_string(), password.clone())
                .await
            {
                if auth.success() {
                    return true;
                }
            }
        }
        *self.shared.upstream_auth_error.lock().await =
            Some("SSH 认证失败：所有私钥与密码均被拒绝".into());
        false
    }
}

/// 建立并运行 SSH 双向代理：返回时两侧会话均已结束。
pub async fn run_ssh_mitm(
    client_stream: BoxedStream,
    upstream_stream: BoxedStream,
    candidates: SshAuthCandidates,
    expected_host_key: SshHostKeyExpectation,
    audit: SshAuditContext,
) -> io::Result<()> {
    let SshAuditContext {
        audit,
        context,
        rule_id,
        server_key,
        record_events,
        transcript,
    } = audit;
    let (audit, audit_worker) = spawn_audit_worker(audit, context, rule_id, record_events);
    let server_config = Arc::new(server::Config {
        keys: vec![(*server_key).clone()],
        auth_rejection_time: Duration::from_secs(1),
        event_buffer_size: SSH_EVENT_BUFFER_SIZE,
        channel_buffer_size: SSH_CHANNEL_BUFFER_SIZE,
        nodelay: true,
        ..Default::default()
    });
    let client_config = Arc::new(client::Config {
        // 空闲会话不是故障。连接活性由 SSH/TCP 错误决定，不能把正常停留在 shell
        // 提示符的用户误判为“卡死”。
        inactivity_timeout: None,
        channel_buffer_size: SSH_CHANNEL_BUFFER_SIZE,
        nodelay: true,
        ..Default::default()
    });

    let shared = Arc::new(Shared {
        server_handle: OnceCell::new(),
        upstream_write: Mutex::new(HashMap::new()),
        upstream_auth_error: Mutex::new(None),
        line_buffers: Mutex::new(HashMap::new()),
        shutdown: CancellationToken::new(),
    });

    let client_handle = client::connect_stream(
        client_config,
        upstream_stream,
        ClientHandler {
            expected: expected_host_key,
        },
    )
    .await
    .map_err(io::Error::other)?;

    let running = server::run_stream(
        server_config,
        client_stream,
        ServerHandler {
            shared: shared.clone(),
            client_handle,
            candidates: Arc::new(candidates),
            upstream_auth: None,
            audit,
            transcript,
        },
    )
    .await
    .map_err(io::Error::other)?;
    let _ = shared.server_handle.set(running.handle());
    let result = running.await.map_err(io::Error::other);
    shared.shutdown.cancel();
    shared.upstream_write.lock().await.clear();
    shared.line_buffers.lock().await.clear();
    if let Some(message) = shared.upstream_auth_error.lock().await.take() {
        drop(audit_worker);
        return Err(io::Error::other(message));
    }
    drop(audit_worker);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Destination, ProcessInfo, Protocol};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::AtomicBool;
    use tokio::time::timeout;

    const OUTPUT_SIZE: usize = 16 * 1024 * 1024;
    const OUTPUT_CHUNK_SIZE: usize = 32 * 1024;
    const TEST_TIMEOUT: Duration = Duration::from_secs(20);

    #[derive(Clone)]
    struct OutputServer {
        finished: Arc<AtomicBool>,
        signal_seen: Arc<AtomicBool>,
        subsystem_seen: Arc<AtomicBool>,
    }

    impl server::Handler for OutputServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            _user: &str,
            password: &str,
        ) -> Result<server::Auth, Self::Error> {
            Ok(if password == "configured-secret" {
                server::Auth::Accept
            } else {
                server::Auth::reject()
            })
        }

        async fn channel_open_session(
            &mut self,
            _channel: Channel<server::Msg>,
            reply: server::ChannelOpenHandle,
            _session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn exec_request(
            &mut self,
            channel: ChannelId,
            _data: &[u8],
            session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            let handle = session.handle();
            let finished = self.finished.clone();
            tokio::spawn(async move {
                let chunk = vec![b'x'; OUTPUT_CHUNK_SIZE];
                for _ in 0..OUTPUT_SIZE / OUTPUT_CHUNK_SIZE {
                    if handle.data(channel, chunk.clone()).await.is_err() {
                        return;
                    }
                }
                let _ = handle.exit_status_request(channel, 23).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
                finished.store(true, Ordering::Release);
            });
            Ok(())
        }

        async fn subsystem_request(
            &mut self,
            channel: ChannelId,
            name: &str,
            session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            if name == "test-subsystem" {
                self.subsystem_seen.store(true, Ordering::Release);
                session.channel_success(channel)?;
            } else {
                session.channel_failure(channel)?;
            }
            let handle = session.handle();
            tokio::spawn(async move {
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
            });
            Ok(())
        }

        async fn signal(
            &mut self,
            _channel: ChannelId,
            signal: russh::Sig,
            _session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            if matches!(signal, russh::Sig::INT) {
                self.signal_seen.store(true, Ordering::Release);
            }
            Ok(())
        }
    }

    struct TestClient;

    impl client::Handler for TestClient {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &russh::keys::PublicKey,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    #[test]
    fn auth_candidates_match_username_exactly() {
        let candidates = SshAuthCandidates {
            accounts: vec![
                SshAuthAccount {
                    username: "root".into(),
                    keys: vec!["root-key".into()],
                    passwords: vec!["root-password".into()],
                },
                SshAuthAccount {
                    username: "ubuntu".into(),
                    keys: vec!["ubuntu-key".into()],
                    passwords: vec!["ubuntu-password".into()],
                },
            ],
        };

        assert_eq!(
            candidates.account_for("ubuntu").unwrap().passwords,
            vec!["ubuntu-password"]
        );
        assert!(candidates.account_for("Ubuntu").is_none());
        assert!(candidates.account_for("deploy").is_none());
    }

    fn audit_context() -> SshAuditContext {
        SshAuditContext {
            audit: AuditWriter::open(None).unwrap(),
            context: ConnectionContext {
                session_id: "ssh-backpressure-test".into(),
                connection_id: 1,
                process: ProcessInfo::default(),
                destination: Destination {
                    ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    port: 22,
                    hostnames: vec!["localhost".into()],
                },
                protocol: Protocol::Ssh,
            },
            rule_id: Some("test".into()),
            server_key: Arc::new(server_key_from_master(b"mitm-test-key")),
            record_events: true,
            transcript: None,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn large_output_backpressures_and_preserves_exit_status() {
        timeout(TEST_TIMEOUT, async {
            let finished = Arc::new(AtomicBool::new(false));
            let signal_seen = Arc::new(AtomicBool::new(false));
            let subsystem_seen = Arc::new(AtomicBool::new(false));
            let upstream_key = server_key_from_master(b"upstream-test-key");
            let host_public = upstream_key.public_key().clone();
            let upstream_config = Arc::new(server::Config {
                keys: vec![upstream_key],
                auth_rejection_time: Duration::ZERO,
                event_buffer_size: 8,
                channel_buffer_size: 8,
                ..Default::default()
            });
            let (proxy_upstream, upstream_stream) = tokio::io::duplex(64 * 1024);
            let upstream_finished = finished.clone();
            let upstream_signal_seen = signal_seen.clone();
            let upstream_subsystem_seen = subsystem_seen.clone();
            let upstream_task = tokio::spawn(async move {
                let running = server::run_stream(
                    upstream_config,
                    upstream_stream,
                    OutputServer {
                        finished: upstream_finished,
                        signal_seen: upstream_signal_seen,
                        subsystem_seen: upstream_subsystem_seen,
                    },
                )
                .await
                .unwrap();
                let _ = running.await;
            });

            let (client_stream, proxy_client) = tokio::io::duplex(64 * 1024);
            let transcript_root = std::env::temp_dir().join(format!(
                "hyperhub-ssh-transcript-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            let transcript_date = 20260817;
            let mut audit = audit_context();
            audit.transcript = Some(CaptureConfig {
                root: transcript_root.clone(),
                date_key: transcript_date,
                limit: 4096,
                session_id: audit.context.session_id.clone(),
                connection_id: audit.context.connection_id,
                stream_id: None,
                client_upload: false,
                server_response: true,
            });
            let proxy_task = tokio::spawn(run_ssh_mitm(
                Box::new(proxy_client),
                Box::new(proxy_upstream),
                SshAuthCandidates {
                    accounts: vec![SshAuthAccount {
                        username: "test-user".into(),
                        keys: Vec::new(),
                        passwords: vec!["configured-secret".into()],
                    }],
                },
                SshHostKeyExpectation {
                    key_type: host_public.algorithm().to_string(),
                    key_blob: base64::engine::general_purpose::STANDARD
                        .encode(host_public.to_bytes().unwrap()),
                },
                audit,
            ));

            let mut session = client::connect_stream(
                Arc::new(client::Config {
                    channel_buffer_size: 8,
                    ..Default::default()
                }),
                client_stream,
                TestClient,
            )
            .await
            .unwrap();
            assert!(session
                .authenticate_password("test-user", "ignored-client-password")
                .await
                .unwrap()
                .success());

            let mut channel = session.channel_open_session().await.unwrap();
            channel.exec(true, b"large-output".to_vec()).await.unwrap();

            // 应用层暂时不读取：上游生产者必须被端到端背压，而不是在代理里无限堆积。
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(!finished.load(Ordering::Acquire));
            channel.signal(russh::Sig::INT).await.unwrap();

            let mut received = 0usize;
            let mut exit_status = None;
            while let Some(message) = channel.wait().await {
                match message {
                    ChannelMsg::Data { data } => received += data.len(),
                    ChannelMsg::ExitStatus {
                        exit_status: status,
                    } => exit_status = Some(status),
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
            assert_eq!(received, OUTPUT_SIZE);
            assert_eq!(exit_status, Some(23));
            assert!(finished.load(Ordering::Acquire));
            assert!(signal_seen.load(Ordering::Acquire));

            let mut subsystem = session.channel_open_session().await.unwrap();
            subsystem
                .request_subsystem(true, "test-subsystem")
                .await
                .unwrap();
            while let Some(message) = subsystem.wait().await {
                if matches!(message, ChannelMsg::Close) {
                    break;
                }
            }
            assert!(subsystem_seen.load(Ordering::Acquire));

            session
                .disconnect(russh::Disconnect::ByApplication, "test complete", "")
                .await
                .unwrap();
            proxy_task.await.unwrap().unwrap();
            upstream_task.abort();

            let transcript_directory =
                crate::retention::date_partition_directory(&transcript_root, transcript_date)
                    .join("ssh-backpressure-test");
            assert!(std::fs::read_dir(&transcript_directory)
                .unwrap()
                .filter_map(Result::ok)
                .all(|entry| !entry.file_name().to_string_lossy().ends_with("-up.bin")));
            let captured_output = std::fs::read_dir(&transcript_directory)
                .unwrap()
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.ends_with("-down.bin"))
                })
                .filter_map(|path| std::fs::read(path).ok())
                .find(|bytes| bytes.len() == 4096)
                .expect("decrypted SSH output transcript was not written");
            assert_eq!(captured_output, vec![b'x'; 4096]);
            std::fs::remove_dir_all(transcript_root).ok();
        })
        .await
        .expect("SSH MITM large-output regression test timed out");
    }

    #[test]
    fn command_audit_buffer_has_a_hard_limit() {
        let mut buffer = CommandBuffer::default();
        let mut input = vec![b'a'; MAX_AUDITED_COMMAND_BYTES * 2];
        input.push(b'\n');
        let complete = buffer.push(&input);
        assert_eq!(complete.len(), 1);
        assert_eq!(complete[0].0.len(), MAX_AUDITED_COMMAND_BYTES);
        assert!(complete[0].1);
        assert!(buffer.bytes.is_empty());
        assert!(!buffer.truncated);
    }

    #[tokio::test]
    async fn disabled_ssh_event_audit_does_not_write_commands() {
        let root = std::env::temp_dir().join(format!(
            "hyperhub-ssh-audit-disabled-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let writer = AuditWriter::open(Some(&root.join("audit.jsonl"))).unwrap();
        let actual_path = writer.current_log_path().unwrap();
        let context = audit_context().context;
        let (sink, worker) = spawn_audit_worker(writer, context, Some("test".into()), false);
        sink.emit(SshAuditEvent {
            event: "ssh_command",
            outcome: "exec",
            bytes: None,
            detail: json!({"command": "must-not-be-written"}),
        });
        drop(sink);
        worker.await.unwrap();
        assert!(std::fs::read_to_string(actual_path).unwrap().is_empty());
        std::fs::remove_dir_all(root).ok();
    }
}
