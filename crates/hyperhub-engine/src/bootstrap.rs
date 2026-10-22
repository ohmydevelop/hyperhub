//! Authenticated selection of the Engine for a newly created resident Host.
//! Selection is followed by synchronous enrollment before the target resumes.
use hmac::{Hmac, Mac};
use hyperhub_runtime::{Manifest, Runtime};
use serde::{Deserialize, Serialize};
use std::{io, path::PathBuf};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    pub manifest: Manifest,
    pub source: PathBuf,
    pub cache: PathBuf,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub id: String,
    pub deployment: Deployment,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub pid: u32,
    pub root_pid: u32,
    pub nonce: [u8; 32],
    pub host: Manifest,
    pub native_base_sha256: String,
    pub stable: Option<Deployment>,
    pub candidate: Option<Candidate>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    pub selection: Selection,
    pub proof: Vec<u8>,
}
fn mac(token: &str, selection: &Selection) -> io::Result<Hmac<sha2::Sha256>> {
    let mut mac =
        Hmac::<sha2::Sha256>::new_from_slice(token.as_bytes()).map_err(io::Error::other)?;
    mac.update(b"hyperhub-engine-bootstrap-v1\0");
    mac.update(&serde_json::to_vec(selection).map_err(io::Error::other)?);
    Ok(mac)
}
impl Bootstrap {
    pub fn sign(selection: Selection, token: &str) -> io::Result<Self> {
        let proof = mac(token, &selection)?.finalize().into_bytes().to_vec();
        Ok(Self { selection, proof })
    }
    pub fn verify(
        &self,
        token: &str,
        nonce: &[u8; 32],
        pid: u32,
        root_pid: u32,
        host: &Manifest,
        native_base_sha256: &str,
    ) -> bool {
        self.selection.nonce == *nonce
            && self.selection.pid == pid
            && self.selection.root_pid == root_pid
            && self.selection.host == *host
            && self.selection.native_base_sha256 == native_base_sha256
            && native_base_sha256.len() == 64
            && native_base_sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            && mac(token, &self.selection).is_ok_and(|mac| mac.verify_slice(&self.proof).is_ok())
    }
}
/// # Safety
/// The caller authenticated the selection and holds no Host or OS loader lock.
/// A trusted signed manifest permits native loading, not sandboxed code.
pub unsafe fn install(runtime: &Runtime, selection: &Selection) -> Result<(), String> {
    use crate::management::{self, Command, Reply};
    let apply = |command| match unsafe { management::execute(runtime, command) } {
        Reply::Error { message, .. } => Err(message),
        _ => Ok(()),
    };
    if let Some(stable) = &selection.stable {
        stable.manifest.validate().map_err(|e| e.to_string())?;
        let id = format!("bootstrap-{}", &stable.manifest.sha256[..32]);
        apply(Command::Prepare {
            id: id.clone(),
            manifest: stable.manifest.clone(),
            source: stable.source.clone(),
            cache: stable.cache.clone(),
        })?;
        apply(Command::CommitHeld { id: id.clone() })?;
        apply(Command::FinalizeObservation { id })?;
    }
    if let Some(candidate) = &selection.candidate {
        apply(Command::Prepare {
            id: candidate.id.clone(),
            manifest: candidate.deployment.manifest.clone(),
            source: candidate.deployment.source.clone(),
            cache: candidate.deployment.cache.clone(),
        })?;
        apply(Command::CommitHeld {
            id: candidate.id.clone(),
        })?;
    }
    Ok(())
}
