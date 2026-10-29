//! A waiting helper owns its delegated key before any administrator signature.
//! Only public identity and a one-shot commit cross the creator's anonymous
//! pipes. Until commit the child does not open Execution or inspect the target.
use super::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io::Read;
use std::process::{Child, ChildStdin};

const LIMIT: usize = 16 * 1024;
const TIMEOUT: Duration = Duration::from_secs(30);
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Begin {
    schema_version: u32,
    nonce: [u8; 32],
    creator: attachments::ProcessIdentity,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    schema_version: u32,
    nonce: [u8; 32],
    claimant: hyperhub_runtime::attachment::ManagerClaimant,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Commit {
    schema_version: u32,
    nonce: [u8; 32],
    claimant: hyperhub_runtime::attachment::ManagerClaimant,
}
fn validate_hello(
    hello: &Hello,
    nonce: &[u8; 32],
    identity: &attachments::ProcessIdentity,
) -> Result<(), String> {
    hello.claimant.validate().map_err(|e| e.to_string())?;
    if hello.schema_version != 1
        || &hello.nonce != nonce
        || hello.claimant.pid != identity.pid
        || hello.claimant.birth != identity.birth
    {
        return Err("manager public key reply differs from actual created helper".into());
    }
    Ok(())
}
fn validate_commit(
    commit: &Commit,
    nonce: &[u8; 32],
    claimant: &hyperhub_runtime::attachment::ManagerClaimant,
) -> Result<(), String> {
    if commit.schema_version != 1 || &commit.nonce != nonce || &commit.claimant != claimant {
        return Err("private manager commit differs from creator-bound key".into());
    }
    Ok(())
}
fn write_packet<T: Serialize>(writer: &mut impl Write, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if bytes.len() > LIMIT {
        return Err("private manager frame exceeds limit".into());
    }
    writer
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|_| writer.write_all(&bytes))
        .and_then(|_| writer.flush())
        .map_err(|e| e.to_string())
}
fn read_packet<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T, String> {
    let mut length = [0; 4];
    reader
        .read_exact(&mut length)
        .map_err(|_| "missing private manager bootstrap frame")?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > LIMIT {
        return Err("invalid private manager bootstrap frame length".into());
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid private manager bootstrap: {e}"))
}
pub(super) struct WaitingManager {
    child: Option<Child>,
    input: Option<ChildStdin>,
    identity: attachments::ProcessIdentity,
    pub(super) claimant: hyperhub_runtime::attachment::ManagerClaimant,
    nonce: [u8; 32],
}
impl WaitingManager {
    pub(super) fn spawn(directory: &Path) -> Result<Self, String> {
        let creator = attachments::inspect_process(std::process::id())?;
        let mut command = ProcessCommand::new(std::env::current_exe().map_err(|e| e.to_string())?);
        command
            .arg("attachment-manager")
            .arg(directory)
            .env(
                "HYPERHUB_HOME",
                config_store::hyperhub_home().map_err(|e| e.to_string())?,
            )
            .env_remove("HYPERHUB_CONFIG_PASSWORD")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            unsafe {
                command.pre_exec(|| {
                    if libc::setsid() < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                });
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000 | 0x00000200);
        }
        let mut child = command.spawn().map_err(|e| e.to_string())?;
        let identity = match attachments::inspect_process(child.id()) {
            Ok(identity) => identity,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        let nonce = rand::random();
        let mut value = Self {
            input: child.stdin.take(),
            child: Some(child),
            identity,
            claimant: hyperhub_runtime::attachment::ManagerClaimant {
                pid: 0,
                birth: 0,
                role_epoch: [0; 32],
                public_key: [0; 32],
            },
            nonce,
        };
        attachments::verify_created_manager(&creator, &value.identity)?;
        let mut output = value
            .child
            .as_mut()
            .unwrap()
            .stdout
            .take()
            .ok_or("manager reply pipe missing")?;
        write_packet(
            value.input.as_mut().ok_or("manager input pipe missing")?,
            &Begin {
                schema_version: 1,
                nonce,
                creator: creator.clone(),
            },
        )?;
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            let result: Result<Hello, String> = read_packet(&mut output);
            let _ = sender.send(result);
        });
        let hello = receiver
            .recv_timeout(TIMEOUT)
            .map_err(|_| "private manager key bootstrap timed out".to_string())?;
        let _ = reader.join();
        let hello = hello?;
        validate_hello(&hello, &nonce, &value.identity)?;
        attachments::verify_created_manager(&creator, &value.identity)?;
        value.claimant = hello.claimant;
        Ok(value)
    }
    pub(super) fn commit(mut self) -> Result<StartedManager, String> {
        attachments::verify_process(&self.identity)?;
        write_packet(
            self.input.as_mut().ok_or("manager input pipe missing")?,
            &Commit {
                schema_version: 1,
                nonce: self.nonce,
                claimant: self.claimant.clone(),
            },
        )?;
        drop(self.input.take());
        Ok(StartedManager {
            child: self.child.take(),
            identity: self.identity.clone(),
        })
    }
}
impl Drop for WaitingManager {
    fn drop(&mut self) {
        drop(self.input.take());
        if let Some(mut child) = self.child.take() {
            // This handle was created here; never signal a target or a PID
            // recovered from a mutable record.
            if attachments::process_birth(child.id()) == Some(self.identity.birth)
                || matches!(child.try_wait(), Ok(None))
            {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}
pub(super) struct StartedManager {
    child: Option<Child>,
    identity: attachments::ProcessIdentity,
}
impl StartedManager {
    pub(super) fn exited(&mut self) -> Result<Option<std::process::ExitStatus>, String> {
        self.child
            .as_mut()
            .ok_or("created manager handle missing")?
            .try_wait()
            .map_err(|e| e.to_string())
    }
    pub(super) fn identity(&self) -> &attachments::ProcessIdentity {
        &self.identity
    }
}
impl Drop for StartedManager {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // Committed managers may outlive approval. Reap while this CLI is
            // alive without killing a controller or waiting for the target.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
    }
}
pub(super) struct UncommittedRecord {
    directory: PathBuf,
    fresh: bool,
    armed: bool,
}
impl UncommittedRecord {
    pub(super) fn new(directory: &Path, fresh: bool) -> Self {
        Self {
            directory: directory.into(),
            fresh,
            armed: true,
        }
    }
    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
}
impl Drop for UncommittedRecord {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let error = "approved waiting manager was cancelled before execution commit".to_string();
        if self.fresh
            && attachments::load_record(&self.directory)
                .is_ok_and(|record| record.phase == Phase::Preparing && record.manager.is_none())
        {
            let _ = attachments::fail_record(&self.directory, error);
        } else {
            let _ = attachments::record_execution_error(&self.directory, error);
        }
    }
}
pub(super) fn await_creator() -> Result<(), String> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result: Result<Begin, String> = read_packet(&mut std::io::stdin().lock());
        let _ = sender.send(result);
    });
    let begin = receiver
        .recv_timeout(TIMEOUT)
        .map_err(|_| "private manager creator timed out")??;
    if begin.schema_version != 1 || begin.nonce == [0; 32] {
        return Err("invalid private manager creator challenge".into());
    }
    attachments::verify_manager_creator(&begin.creator)?;
    let claimant = attachments::manager_operation_claimant()?;
    write_packet(
        &mut std::io::stdout().lock(),
        &Hello {
            schema_version: 1,
            nonce: begin.nonce,
            claimant: claimant.clone(),
        },
    )?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result: Result<Commit, String> = read_packet(&mut std::io::stdin().lock());
        let _ = sender.send(result);
    });
    let commit = receiver
        .recv_timeout(TIMEOUT)
        .map_err(|_| "private manager commit timed out")??;
    validate_commit(&commit, &begin.nonce, &claimant)?;
    attachments::verify_manager_creator(&begin.creator)?;
    Ok(())
}
pub(super) fn redirect_output(directory: &Path) -> Result<(), String> {
    let path = directory.join("manager.log");
    if !path.exists() {
        attachments::create_private_file(&path, &[])?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let log = options.open(path).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        if unsafe { libc::dup2(log.as_raw_fd(), libc::STDOUT_FILENO) } < 0
            || unsafe { libc::dup2(log.as_raw_fd(), libc::STDERR_FILENO) } < 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::IntoRawHandle;
        use windows_sys::Win32::System::Console::{
            SetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
        };
        let handle = log.into_raw_handle(); // Standard handles retain ownership until process exit.
        if unsafe { SetStdHandle(STD_OUTPUT_HANDLE, handle) } == 0
            || unsafe { SetStdHandle(STD_ERROR_HANDLE, handle) } == 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bootstrap_frames_reject_truncation_oversize_and_unknown_fields() {
        assert!(read_packet::<Hello>(&mut &[][..]).is_err());
        assert!(read_packet::<Hello>(&mut &(u32::MAX.to_be_bytes())[..]).is_err());
        let mut bytes = Vec::new();
        write_packet(&mut bytes, &json!({"unexpected":true})).unwrap();
        assert!(read_packet::<Hello>(&mut &bytes[..]).is_err());
    }
    #[test]
    #[cfg(any(windows, target_os = "linux"))]
    fn creator_nonce_schema_and_committed_claimant_cannot_be_substituted() {
        let claimant = attachments::manager_operation_claimant().unwrap();
        let identity = attachments::ProcessIdentity {
            pid: claimant.pid,
            birth: claimant.birth,
            executable: "unit-manager".into(),
            executable_sha256: "ab".repeat(32),
            owner: "unit-owner".into(),
        };
        let mut hello = Hello {
            schema_version: 1,
            nonce: [3; 32],
            claimant: claimant.clone(),
        };
        validate_hello(&hello, &[3; 32], &identity).unwrap();
        assert!(validate_hello(&hello, &[4; 32], &identity).is_err());
        hello.schema_version = 2;
        assert!(validate_hello(&hello, &[3; 32], &identity).is_err());
        hello.schema_version = 1;
        hello.claimant.birth += 1;
        assert!(validate_hello(&hello, &[3; 32], &identity).is_err());
        let mut commit = Commit {
            schema_version: 1,
            nonce: [3; 32],
            claimant: claimant.clone(),
        };
        validate_commit(&commit, &[3; 32], &claimant).unwrap();
        assert!(validate_commit(&commit, &[4; 32], &claimant).is_err());
        commit.claimant.role_epoch[0] ^= 1;
        assert!(validate_commit(&commit, &[3; 32], &claimant).is_err());
    }
    fn spec() -> attachments::Spec {
        attachments::Spec {
            id: attachments::new_id(),
            target: attachments::ProcessIdentity {
                pid: 42,
                birth: 9,
                executable: "unit-target".into(),
                executable_sha256: "ab".repeat(32),
                owner: "unit-owner".into(),
            },
            current_target: None,
            exec_epoch: 0,
            scope: Scope::Tree,
            backend: Backend::Ptrace,
            policy_digest: "cd".repeat(32),
            capabilities: Default::default(),
            recovery: None,
        }
    }
    #[test]
    fn uncommitted_fresh_record_becomes_failed_but_recovery_retains_residue() {
        let root = std::env::temp_dir().join(format!(
            "hh-manager-record-cancel-{}",
            attachments::new_id()
        ));
        let target = spec();
        attachments::create_record(&root, target.clone()).unwrap();
        let directory = attachments::attachment_directory(&root, &target.id).unwrap();
        drop(UncommittedRecord::new(&directory, true));
        assert_eq!(
            attachments::load_record(&directory).unwrap().phase,
            Phase::Failed
        );
        let outcome = attachments::Outcome {
            phase: Phase::DetachedResident,
            members: vec![target.target.clone()],
            manager: Some(target.target.clone()),
            manager_endpoint: Some("retained-private-endpoint".into()),
            compatibility_reasons: vec!["resident_native_module".into()],
        };
        attachments::update_record(&directory, &outcome).unwrap();
        attachments::create_private_file(
            &directory.join("recovery.bin"),
            b"dummy-private-recovery-metadata",
        )
        .unwrap();
        drop(UncommittedRecord::new(&directory, false));
        let retained = attachments::load_record(&directory).unwrap();
        assert_eq!(retained.phase, Phase::DetachedResident);
        assert_eq!(retained.manager, outcome.manager);
        assert_eq!(retained.members, outcome.members);
        assert_eq!(
            retained.compatibility_reasons,
            outcome.compatibility_reasons
        );
        assert!(retained.error.is_some());
        assert_eq!(
            std::fs::read(directory.join("recovery.bin")).unwrap(),
            b"dummy-private-recovery-metadata"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
