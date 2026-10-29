//! The control endpoint and this role lease are part of the control-plane TCB.
//! Public keys are not enrolled from this file. It binds an IPC connection to
//! the actual controlled Serve incarnation before any password bytes are sent.
use crate::attachments::{self, ManagerGuard, ProcessIdentity};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema_version: u32,
    endpoint: String,
    process: ProcessIdentity,
}
pub(crate) struct ServeLease {
    _guard: ManagerGuard,
    path: PathBuf,
    process: ProcessIdentity,
}
pub(crate) fn path_for_config(config: &Path) -> Result<PathBuf, String> {
    Ok(config
        .parent()
        .ok_or("configuration has no instance directory")?
        .join("runtime")
        .join("core-lease")
        .join("serve.json"))
}
/// Denial-only liveness hint. A matching file never authorizes an RPC peer.
pub(crate) fn has_live_core(config: &Path) -> Result<bool, String> {
    let path = path_for_config(config)?;
    if !path.exists() {
        return Ok(false);
    }
    let record: Record = serde_json::from_slice(&attachments::read_private_file(&path, 64 * 1024)?)
        .map_err(|e| format!("cannot determine Core configuration ownership: {e}"))?;
    if record.schema_version != 1 {
        return Err("unknown Core lease schema".into());
    }
    Ok(attachments::process_birth(record.process.pid) == Some(record.process.birth))
}
impl ServeLease {
    pub(crate) fn acquire(path: PathBuf, endpoint: &str) -> Result<Self, String> {
        let directory = path.parent().ok_or("Core lease directory is missing")?;
        let guard = ManagerGuard::acquire(directory)
            .map_err(|e| format!("Core instance lease is already owned: {e}"))?;
        if path.exists() {
            let old: Record =
                serde_json::from_slice(&attachments::read_private_file(&path, 64 * 1024)?)
                    .map_err(|e| e.to_string())?;
            if old.process.pid != std::process::id()
                && attachments::process_birth(old.process.pid) == Some(old.process.birth)
            {
                return Err("another live Serve incarnation owns this control namespace".into());
            }
        }
        let _ = endpoint;
        Ok(Self {
            _guard: guard,
            path,
            process: attachments::inspect_process(std::process::id())?,
        })
    }
    pub(crate) fn publish(&self, endpoint: &str) -> Result<(), String> {
        let value = Record {
            schema_version: 1,
            endpoint: endpoint.into(),
            process: self.process.clone(),
        };
        crate::config_store::save_durable_private_bytes(
            &self.path,
            &serde_json::to_vec(&value).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())
    }
}
impl Drop for ServeLease {
    fn drop(&mut self) {
        let Ok(bytes) = attachments::read_private_file(&self.path, 64 * 1024) else {
            return;
        };
        let Ok(record) = serde_json::from_slice::<Record>(&bytes) else {
            return;
        };
        if record.process == self.process {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
/// A cheap rejection only. A matching advertisement never proves code identity;
/// the client must still inspect the actual OS peer and verify this lease.
pub(crate) fn reject_different_image(
    path: &Path,
    endpoint: &str,
    expected_digest: &str,
) -> Result<(), String> {
    let record: Record = serde_json::from_slice(&attachments::read_private_file(path, 64 * 1024)?)
        .map_err(|e| e.to_string())?;
    if record.schema_version != 1
        || record.endpoint != endpoint
        || record.process.executable_sha256 != expected_digest
    {
        return Err("Core role does not advertise the trusted HyperHub executable".into());
    }
    Ok(())
}
pub(crate) fn verify(path: &Path, endpoint: &str, peer: &ProcessIdentity) -> Result<(), String> {
    let record: Record = serde_json::from_slice(&attachments::read_private_file(path, 64 * 1024)?)
        .map_err(|e| e.to_string())?;
    if record.schema_version != 1 || record.endpoint != endpoint || &record.process != peer {
        return Err("Core IPC peer does not match the controlled Serve lease incarnation".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[cfg(any(windows, target_os = "linux"))]
    fn lease_binds_control_role_endpoint_and_birth_and_releases_ownership() {
        let root = std::env::temp_dir().join(format!("hh-serve-lease-{}", attachments::new_id()));
        let config = root.join("config.bin");
        let path = path_for_config(&config).unwrap();
        let endpoint = "private-test-control-endpoint";
        let lease = ServeLease::acquire(path.clone(), endpoint).unwrap();
        lease.publish(endpoint).unwrap();
        let own = attachments::inspect_process(std::process::id()).unwrap();
        verify(&path, endpoint, &own).unwrap();
        assert!(
            ServeLease::acquire(path.clone(), endpoint).is_err(),
            "second Core acquired the live instance lease"
        );
        assert!(verify(&path, "another-endpoint", &own).is_err());
        let mut stale = own;
        stale.birth += 1;
        assert!(verify(&path, endpoint, &stale).is_err());
        reject_different_image(&path, endpoint, &lease.process.executable_sha256).unwrap();
        assert!(reject_different_image(&path, endpoint, "not-the-current-executable").is_err());
        // Matching advertised bytes are only a prefilter. Changed real actor
        // birth still fails the full role check.
        let wrong = Record {
            schema_version: 1,
            endpoint: endpoint.into(),
            process: stale,
        };
        crate::config_store::save_durable_private_bytes(
            &path,
            &serde_json::to_vec(&wrong).unwrap(),
        )
        .unwrap();
        reject_different_image(&path, endpoint, &lease.process.executable_sha256).unwrap();
        assert!(verify(&path, endpoint, &lease.process).is_err());
        lease.publish(endpoint).unwrap();
        drop(lease);
        assert!(!path.exists());
        let replacement = ServeLease::acquire(path, endpoint).unwrap();
        drop(replacement);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(all(test, not(any(windows, target_os = "linux"))))]
mod unsupported_platform_tests {
    use super::*;
    #[tokio::test]
    async fn ordinary_serve_configures_without_dynamic_attachment_identity() {
        use crate::session::{
            ConnectionRegistry, ControlRequest, ControlResponse, SessionRegistry,
        };
        use std::sync::Arc;
        let root =
            std::env::temp_dir().join(format!("hh-ordinary-serve-{}", attachments::new_id()));
        attachments::private_directory(&root).unwrap();
        let endpoint = crate::control::instance_control_endpoint(&root);
        let service = crate::control::ControlService::new(
            SessionRegistry::default(),
            ConnectionRegistry::default(),
            "test-ca".into(),
            crate::audit::AuditWriter::open(None).unwrap(),
            crate::runtime::RuntimeState::new(Arc::new(crate::config::Config::default())).unwrap(),
            zeroize::Zeroizing::new(vec![0; 32]),
        )
        .with_attachment_directory(root.join("runtime").join("attachments"))
        .with_approval_anchor(
            &root.join("config.bin"),
            &crate::config_store::new_descriptor(),
            None,
        )
        .unwrap();
        let task = tokio::spawn(crate::control::run_control_server(
            endpoint.clone(),
            service,
        ));
        let ready = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                if let Ok(reply) =
                    crate::control::control_request(&endpoint, &ControlRequest::Ping).await
                {
                    break reply;
                }
                if task.is_finished() {
                    panic!("ordinary Serve exited before binding without attachment identity");
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert!(matches!(ready, ControlResponse::Ok));
        assert!(matches!(
            crate::control::control_request(&endpoint, &ControlRequest::BeginApprovalEnrollment)
                .await
                .unwrap(),
            ControlResponse::Error { .. }
        ));
        assert!(!path_for_config(&root.join("config.bin")).unwrap().exists());
        task.abort();
        let _ = task.await;
        std::fs::remove_dir_all(root).unwrap();
    }
}
