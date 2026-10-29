//! Controlled parent-to-child Core succession. State moves only through pipes
//! owned by the actual child handle; it is never a public control response.
pub(crate) mod bounded_json;

use crate::attachments::{self, ProcessIdentity};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CoreState {
    pub(crate) config_path: std::path::PathBuf,
    pub(crate) configuration_digest: String,
    pub(crate) attachments: Option<attachments::SuccessorAttachmentState>,
    pub(crate) sessions: crate::session::SuccessorSessions,
    pub(crate) aliases: Vec<u8>,
    pub(crate) accepted_operations: Vec<[u8; 32]>,
}

/// Opaque state can only be obtained from a verified direct-parent pipe.
pub struct ReceivedSuccessor {
    pub(crate) state: CoreState,
}

pub(crate) struct PreparedSuccessor {
    child: ChildGuard,
    input: tokio::process::ChildStdin,
    pub(crate) identity: ProcessIdentity,
    nonce: [u8; 32],
}
struct ChildGuard {
    child: tokio::process::Child,
    committed: bool,
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.child.start_kill();
        }
    }
}
impl PreparedSuccessor {
    pub(crate) async fn commit(mut self) -> Result<(), String> {
        self.input
            .write_all(&self.nonce)
            .await
            .map_err(|e| e.to_string())?;
        self.input.shutdown().await.map_err(|e| e.to_string())?;
        self.child.committed = true;
        Ok(())
    }
}

/// The caller must retain the admission freeze until it sends shutdown. A
/// failed preparation drops a kill-on-drop *child created here*, never a target.
pub(crate) async fn prepare(state: CoreState, debug: bool) -> Result<PreparedSuccessor, String> {
    // Check while serializing and before spawning a child. Source state and all
    // partially encoded key bytes are dropped if the bounded writer rejects it.
    let bytes = Zeroizing::new(bounded_json::to_vec(&state, MAX_STATE)?);
    drop(state);
    let parent = attachments::inspect_process(std::process::id())?;
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    let home = crate::config_store::hyperhub_home().map_err(|e| e.to_string())?;
    let log_path = home.join("serve.log");
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| e.to_string())?;
    let mut command = tokio::process::Command::new(&executable);
    command
        .arg("serve")
        .arg("--successor-stdin")
        .arg("--output")
        .arg(home.join("runtime/successor-output.log"));
    if debug {
        command.arg("--debug");
    }
    command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(log);
    #[cfg(unix)]
    command.process_group(0);
    #[cfg(windows)]
    command.creation_flags(0x08000000); // CREATE_NO_WINDOW, no target console.
    let mut child = ChildGuard {
        child: command.spawn().map_err(|e| e.to_string())?,
        committed: false,
    };
    let pid = child
        .child
        .id()
        .ok_or("successor child exited during creation")?;
    let identity = attachments::inspect_process(pid)?;
    let intro = Introduction {
        parent: parent.clone(),
        child: identity.clone(),
        nonce: rand::random(),
        expires_at_ms: crate::session::unix_timestamp_ms()
            .saturating_add(DEADLINE.as_millis() as u64),
    };
    intro.validate(&parent, &identity, crate::session::unix_timestamp_ms())?;
    if crate::control::process_ancestors(pid).first().copied() != Some(parent.pid) {
        return Err("created successor is no longer this Core's direct child".into());
    }
    let mut input = child
        .child
        .stdin
        .take()
        .ok_or("successor input pipe unavailable")?;
    let mut output = child
        .child
        .stdout
        .take()
        .ok_or("successor output pipe unavailable")?;
    let transfer = async {
        send_bytes(&mut input, &bounded_json::to_vec(&intro, MAX_STATE)?).await?;
        let mut nonce = [0; 32];
        output
            .read_exact(&mut nonce)
            .await
            .map_err(|e| e.to_string())?;
        attachments::verify_process(&identity)?;
        if nonce != intro.nonce {
            return Err("successor identity acknowledgement rejected".into());
        }
        // No key or authority bytes are written before both actual processes
        // have checked the exact parent/child incarnation and pipe nonce.
        send_bytes(&mut input, &bytes).await?;
        output
            .read_exact(&mut nonce)
            .await
            .map_err(|e| e.to_string())?;
        if nonce != intro.nonce {
            return Err("successor state acknowledgement rejected".into());
        }
        attachments::verify_process(&identity)?;
        Ok::<(), String>(())
    };
    tokio::time::timeout(DEADLINE, transfer)
        .await
        .map_err(|_| "successor preparation deadline expired")??;
    Ok(PreparedSuccessor {
        child,
        input,
        identity,
        nonce: intro.nonce,
    })
}

/// Internal CLI entry. The flag alone grants no authority: the actual direct
/// parent must own this instance's live Serve lease before any state is read.
pub async fn receive_from_parent(
    preflight: impl FnOnce(&std::path::Path) -> Result<crate::config_store::UnlockedConfig, String>,
) -> Result<ReceivedSuccessor, String> {
    let mut input = tokio::io::stdin();
    let mut output = tokio::io::stdout();
    let receive = async {
        let bytes = receive_bytes(&mut input).await?;
        let intro: Introduction = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        verify_parent(&intro)?;
        let config = crate::config_store::default_config_path().map_err(|e| e.to_string())?;
        let lease = crate::serve_lease::path_for_config(&config)?;
        crate::serve_lease::verify(
            &lease,
            &crate::control::discovery_control_endpoint(),
            &intro.parent,
        )?;
        output
            .write_all(&intro.nonce)
            .await
            .map_err(|e| e.to_string())?;
        output.flush().await.map_err(|e| e.to_string())?;
        let bytes = receive_bytes(&mut input).await?;
        let state: CoreState = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        let current = std::fs::read(&config).map_err(|e| e.to_string())?;
        if state.config_path != config
            || attachments::digest(&current) != state.configuration_digest
        {
            return Err("successor configuration changed before state acceptance".into());
        }
        let unlocked = preflight(&config)?;
        state.sessions.validate_successor_configuration(&unlocked)?;
        if let Some(attachments) = &state.attachments {
            crate::attachments::validate_successor_configuration(attachments, &config, &unlocked)?;
            crate::attachments::validate_successor_parent(
                attachments,
                &intro.parent,
                &intro.child,
            )?;
        }
        verify_parent(&intro)?;
        output
            .write_all(&intro.nonce)
            .await
            .map_err(|e| e.to_string())?;
        output.flush().await.map_err(|e| e.to_string())?;
        let mut commit = [0; 32];
        input
            .read_exact(&mut commit)
            .await
            .map_err(|e| e.to_string())?;
        if commit != intro.nonce {
            return Err("successor commit nonce rejected".into());
        }
        Ok::<_, String>((intro, state))
    };
    let (intro, state) = tokio::time::timeout(DEADLINE, receive)
        .await
        .map_err(|_| "successor receive deadline expired")??;
    let parent_exit = async {
        while !crate::engine_hosts::EngineHosts::process_is_gone(
            intro.parent.pid,
            intro.parent.birth,
        ) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(30), parent_exit)
        .await
        .map_err(|_| "successor parent did not exit after committing handoff")?;
    Ok(ReceivedSuccessor { state })
}

pub(crate) const DEADLINE: Duration = Duration::from_secs(10);
pub(crate) const MAX_STATE: usize = 16 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"HHCORE01";

#[derive(Default)]
struct AdmissionState {
    frozen: bool,
    active: usize,
}
#[derive(Clone, Default)]
pub(crate) struct Admission(Arc<(Mutex<AdmissionState>, tokio::sync::Notify)>);
pub(crate) struct RequestPermit(Admission);
pub(crate) struct Freeze(Admission);
impl Admission {
    pub(crate) fn enter(&self) -> Result<RequestPermit, String> {
        let mut state = self
            .0
             .0
            .lock()
            .map_err(|_| "Core succession admission unavailable")?;
        if state.frozen {
            return Err("Core succession in progress; retry the request".into());
        }
        state.active = state
            .active
            .checked_add(1)
            .ok_or("Core request count exhausted")?;
        Ok(RequestPermit(self.clone()))
    }
    pub(crate) async fn freeze(&self) -> Result<Freeze, String> {
        {
            let mut state = self
                .0
                 .0
                .lock()
                .map_err(|_| "Core succession admission unavailable")?;
            if state.frozen {
                return Err("Core succession is already in progress".into());
            }
            state.frozen = true;
        }
        let guard = Freeze(self.clone());
        let wait = async {
            loop {
                let changed = self.0 .1.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if self
                    .0
                     .0
                    .lock()
                    .map_err(|_| "Core succession admission unavailable")?
                    .active
                    == 0
                {
                    return Ok::<(), String>(());
                }
                changed.await;
            }
        };
        tokio::time::timeout(DEADLINE, wait)
            .await
            .map_err(|_| "Core succession could not drain current requests")??;
        Ok(guard)
    }
}
impl Drop for RequestPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0 .0 .0.lock() {
            state.active -= 1;
            if state.active == 0 {
                self.0 .0 .1.notify_waiters();
            }
        }
    }
}
impl Drop for Freeze {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0 .0 .0.lock() {
            state.frozen = false;
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Introduction {
    pub(crate) parent: ProcessIdentity,
    pub(crate) child: ProcessIdentity,
    pub(crate) nonce: [u8; 32],
    pub(crate) expires_at_ms: u64,
}
impl Introduction {
    pub(crate) fn validate(
        &self,
        parent: &ProcessIdentity,
        child: &ProcessIdentity,
        now: u64,
    ) -> Result<(), String> {
        if &self.parent != parent
            || &self.child != child
            || parent.pid == child.pid
            || parent.executable_sha256 != child.executable_sha256
            || parent.owner != child.owner
            || self.nonce == [0; 32]
            || now >= self.expires_at_ms
            || self.expires_at_ms.saturating_sub(now) > DEADLINE.as_millis() as u64
        {
            return Err("Core successor pipe identity, nonce or deadline rejected".into());
        }
        Ok(())
    }
}

pub(crate) async fn send_bytes<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
) -> Result<(), String> {
    if bytes.len() > MAX_STATE {
        return Err("Core succession state exceeds its bounded pipe limit".into());
    }
    writer.write_all(MAGIC).await.map_err(|e| e.to_string())?;
    writer
        .write_u32(bytes.len() as u32)
        .await
        .map_err(|e| e.to_string())?;
    writer.write_all(bytes).await.map_err(|e| e.to_string())?;
    writer.flush().await.map_err(|e| e.to_string())
}
pub(crate) async fn receive_bytes<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut magic = [0; 8];
    reader
        .read_exact(&mut magic)
        .await
        .map_err(|e| e.to_string())?;
    let count = reader.read_u32().await.map_err(|e| e.to_string())? as usize;
    if &magic != MAGIC || count > MAX_STATE {
        return Err("Core successor pipe frame rejected".into());
    }
    let mut bytes = Zeroizing::new(vec![0; count]);
    reader
        .read_exact(&mut bytes)
        .await
        .map_err(|e| e.to_string())?;
    Ok(bytes)
}

/// Validate the direct OS parent before a child accepts any authority bytes.
pub(crate) fn verify_parent(intro: &Introduction) -> Result<(), String> {
    let child = attachments::inspect_process(std::process::id())?;
    let parent = attachments::inspect_process(intro.parent.pid)?;
    let ancestors = crate::control::process_ancestors(child.pid);
    if ancestors.first().copied() != Some(parent.pid) {
        return Err("Core successor was not created by the claimed direct parent".into());
    }
    intro.validate(&parent, &child, crate::session::unix_timestamp_ms())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn succession_introduction_binds_both_incarnations_and_has_a_short_deadline() {
        let parent = ProcessIdentity {
            pid: 10,
            birth: 20,
            executable: "private-test-cli".into(),
            executable_sha256: "ab".repeat(32),
            owner: "private-test-owner".into(),
        };
        let child = ProcessIdentity {
            pid: 11,
            birth: 21,
            ..parent.clone()
        };
        let mut intro = Introduction {
            parent: parent.clone(),
            child: child.clone(),
            nonce: [1; 32],
            expires_at_ms: 2000,
        };
        intro.validate(&parent, &child, 1000).unwrap();
        let other = ProcessIdentity {
            birth: 22,
            ..child.clone()
        };
        assert!(intro.validate(&parent, &other, 1000).is_err());
        assert!(intro.validate(&child, &parent, 1000).is_err());
        assert!(intro.validate(&parent, &child, 2000).is_err());
        intro.expires_at_ms = 1000 + DEADLINE.as_millis() as u64 + 1;
        assert!(intro.validate(&parent, &child, 1000).is_err());
        intro.expires_at_ms = 2000;
        intro.nonce = [0; 32];
        assert!(intro.validate(&parent, &child, 1000).is_err());
    }
    #[tokio::test]
    async fn succession_freeze_drains_only_started_short_requests_and_rolls_back() {
        let admission = Admission::default();
        let first = admission.enter().unwrap();
        let clone = admission.clone();
        let waiting = tokio::spawn(async move { clone.freeze().await });
        tokio::task::yield_now().await;
        assert!(admission.enter().is_err());
        assert!(!waiting.is_finished());
        drop(first);
        let freeze = waiting.await.unwrap().unwrap();
        assert!(admission.enter().is_err());
        assert!(admission.freeze().await.is_err());
        drop(freeze);
        assert!(admission.enter().is_ok());
    }
    #[tokio::test]
    async fn succession_pipe_is_typed_bounded_and_rejects_truncation() {
        let (mut send, mut receive) = tokio::io::duplex(128);
        send_bytes(&mut send, b"test-only-no-secret").await.unwrap();
        assert_eq!(
            receive_bytes(&mut receive).await.unwrap().as_slice(),
            b"test-only-no-secret"
        );
        send.write_all(MAGIC).await.unwrap();
        send.write_u32((MAX_STATE + 1) as u32).await.unwrap();
        assert!(receive_bytes(&mut receive).await.is_err());
        send.write_all(MAGIC).await.unwrap();
        send.write_u32(4).await.unwrap();
        send.write_all(b"a").await.unwrap();
        drop(send);
        assert!(receive_bytes(&mut receive).await.is_err());
    }
}
