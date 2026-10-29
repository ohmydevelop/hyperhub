use super::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    directory: std::path::PathBuf,
    bootstrap: Bootstrap,
    key: SigningKey,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
impl Fixture {
    fn new() -> Self {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        let directory = std::env::temp_dir().join(format!(
            "hh-host-proof-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let authority = directory.join("authority.json");
        let key = SigningKey::from_bytes(&[41; 32]);
        let bytes=serde_json::to_vec(&json!({"schema_version":1,"config_id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"instance_id":"fixture-instance","public_key":key.verifying_key().to_bytes()})).unwrap();
        use std::io::Write;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&authority)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
        let bootstrap = Bootstrap {
            attachment_id: "fixture-attachment".into(),
            session_id: "session".into(),
            token: "t".repeat(64),
            control_endpoint: "control".into(),
            socks_address: "127.0.0.1:1".into(),
            tls_ca_pem: "-----BEGIN CERTIFICATE-----fixture".into(),
            observe: false,
            firewall: None,
            sandbox: None,
            host_endpoint: "host".into(),
            host_token: "h".repeat(64),
            scope_tree: true,
            root_pid: 123,
            approval_authority_file: authority.to_string_lossy().into_owned(),
            approval_instance_id: "fixture-instance".into(),
            initially_owned: false,
            external_attachment: true,
            native_dns_mode: crate::attachment::NativeDnsMode::PreserveAnswers,
            approval_not_before_ms: 0,
            approval_public_key: Some(key.verifying_key().to_bytes()),
            approval_inherited_public_key: None,
            approval_root_identity: None,
            alias_inherited: None,
            approval_core_public_key: None,
            approval_core_pid: 0,
            approval_core_birth: 0,
            approval_cli_sha256: "c".repeat(64),
        };
        Self {
            directory,
            bootstrap,
            key,
        }
    }
    fn payload(&self) -> Value {
        json!({"request":{"schema_version":1,"instance_id":"fixture-instance","action":{"kind":"attach","spec":{"id":"fixture-attachment","scope":"tree","target":{"pid":123}}}},"approved_at_ms":100,"expires_at_ms":500,"nonce":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"executor_sha256":"e".repeat(64),"execution_digest":"d".repeat(64),"host_binding":self.bootstrap.approval_binding().unwrap()})
    }
    fn sign(&self, value: &Value) -> ApprovalProof {
        let mut payload = DOMAIN.to_vec();
        payload.extend(serde_json::to_vec(value).unwrap());
        let signature = self.key.sign(&payload).to_bytes().to_vec();
        ApprovalProof { payload, signature }
    }
}
#[test]
fn approval_requires_signature_current_instance_scope_target_and_lifetime() {
    let fixture = Fixture::new();
    let value = fixture.payload();
    let proof = fixture.sign(&value);
    assert_eq!(
        verify_proof(&fixture.bootstrap, &proof, 200)
            .unwrap()
            .action,
        ApprovedAction::Attach
    );
    let mut forged = proof.clone();
    forged.signature[0] ^= 1;
    assert!(verify_proof(&fixture.bootstrap, &forged, 200).is_err());
    assert!(verify_proof(&fixture.bootstrap, &proof, 500).is_err());
    assert!(verify_proof(&fixture.bootstrap, &proof, 501).is_err());
    assert!(verify_proof(&fixture.bootstrap, &proof, 99).is_err());
    for changed in [json!("other-instance"), json!(123)] {
        let mut altered = value.clone();
        altered["request"]["instance_id"] = changed;
        assert!(verify_proof(&fixture.bootstrap, &fixture.sign(&altered), 200).is_err());
    }
    let mut changed = value.clone();
    changed["request"]["action"]["spec"]["scope"] = json!("process");
    assert!(verify_proof(&fixture.bootstrap, &fixture.sign(&changed), 200).is_err());
    changed = value.clone();
    changed["request"]["action"]["spec"]["target"]["pid"] = json!(124);
    assert!(verify_proof(&fixture.bootstrap, &fixture.sign(&changed), 200).is_err());
    changed = value.clone();
    changed["expires_at_ms"] = json!(600101);
    assert!(verify_proof(&fixture.bootstrap, &fixture.sign(&changed), 200).is_err());
}
#[test]
fn replacing_discovery_authority_cannot_replace_pinned_signer() {
    let mut fixture = Fixture::new();
    let old = fixture.sign(&fixture.payload());
    let new = SigningKey::from_bytes(&[42; 32]);
    let path = &fixture.bootstrap.approval_authority_file;
    let mut authority: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    authority["public_key"] = json!(new.verifying_key().to_bytes());
    std::fs::write(path, serde_json::to_vec(&authority).unwrap()).unwrap();
    assert!(verify_proof(&fixture.bootstrap, &old, 200).is_ok());
    fixture.key = new;
    assert!(verify_proof(&fixture.bootstrap, &fixture.sign(&fixture.payload()), 200).is_err());
}
#[test]
fn missing_discovery_file_does_not_remove_the_pinned_root_and_empty_root_never_trusts_it() {
    let mut fixture = Fixture::new();
    let proof = fixture.sign(&fixture.payload());
    std::fs::remove_file(&fixture.bootstrap.approval_authority_file).unwrap();
    assert!(verify_proof(&fixture.bootstrap, &proof, 200).is_ok());
    fixture.bootstrap.approval_public_key = None;
    assert!(verify_proof(&fixture.bootstrap, &proof, 200).is_err());
}

#[test]
fn bootstrap_binding_rejects_runtime_envelope_rebinding_but_allows_member_transport_derivatives() {
    let fixture = Fixture::new();
    let proof = fixture.sign(&fixture.payload());
    for changed in [
        "session",
        "session_token",
        "control",
        "scope",
        "authority",
        "root",
        "external_origin",
    ] {
        let mut boot = fixture.bootstrap.clone();
        match changed {
            "session" => boot.session_id.push('x'),
            "session_token" => boot.token.push('x'),
            "control" => boot.control_endpoint.push('x'),
            "scope" => boot.scope_tree = false,
            "authority" => boot.approval_instance_id.push('x'),
            "root" => boot.root_pid += 1,
            "external_origin" => boot.external_attachment = !boot.external_attachment,
            _ => unreachable!(),
        };
        assert!(
            verify_proof(&boot, &proof, 200).is_err(),
            "bootstrap field {changed} was not bound"
        );
    }
    let mut child = fixture.bootstrap.clone();
    child.host_endpoint.push_str("-member");
    child.host_token = "m".repeat(64);
    child.initially_owned = true;
    assert!(child.external_attachment);
    assert!(verify_proof(&child, &proof, 200).is_ok());
}
#[cfg(target_os = "linux")]
#[test]
fn host_exchange_rejects_wrong_os_peer_before_sending_credentials_or_proof() {
    use std::io::Read;
    let fixture = Fixture::new();
    let path = fixture.directory.join("host.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        let mut bytes = [0u8; 8];
        stream.read(&mut bytes).unwrap()
    });
    let command = super::super::AuthenticatedCommand {
        attachment_id: fixture.bootstrap.attachment_id.clone(),
        token: fixture.bootstrap.host_token.clone(),
        command: super::super::HostCommand::Detach,
        proof: Some(fixture.sign(&fixture.payload())),
        enrollment: None,
        aliases: None,
        root_image: None,
    };
    let error = super::super::exchange_for_process(
        path.to_str().unwrap(),
        &command,
        std::process::id().wrapping_add(1),
    )
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(
        server.join().unwrap(),
        0,
        "Host credentials or approval proof were exposed before peer authentication"
    );
}

#[test]
fn fresh_exec_host_inherits_epoch_and_rejects_both_old_attach_and_detach_proofs() {
    let fixture = Fixture::new();
    let parent = fixture.payload();
    let old_attach = fixture.sign(&parent);
    let mut old_detach = parent.clone();
    old_detach["request"]["action"] =
        json!({"kind":"detach","attachment_id":"fixture-attachment","target":{"pid":123}});
    let old_detach = fixture.sign(&old_detach);
    let mut exec = fixture.bootstrap.clone();
    exec.initially_owned = true;
    exec.host_endpoint = "fresh-exec-host".into();
    exec.approval_not_before_ms = 200;
    assert_eq!(
        exec.approval_binding().unwrap(),
        fixture.bootstrap.approval_binding().unwrap()
    );
    assert!(verify_proof(&exec, &old_attach, 300).is_err());
    assert!(verify_proof(&exec, &old_detach, 300).is_err());
    let mut fresh = parent.clone();
    fresh["approved_at_ms"] = json!(201);
    let fresh = fixture.sign(&fresh);
    assert!(verify_proof(&exec, &fresh, 300).is_ok());
    let mut equal = parent;
    equal["approved_at_ms"] = json!(200);
    assert!(verify_proof(&exec, &fixture.sign(&equal), 300).is_err());
    equal["request"]["action"] =
        json!({"kind":"detach","attachment_id":"fixture-attachment","target":{"pid":123}});
    assert!(verify_proof(&exec, &fixture.sign(&equal), 300).is_err());
}

#[test]
fn effective_image_and_exec_epoch_are_carried_by_the_signed_lifecycle_claims() {
    let fixture = Fixture::new();
    let mut payload = fixture.payload();
    payload["request"]["action"]["spec"]["target"] =
        json!({"pid":123,"birth":45,"executable_sha256":"a".repeat(64)});
    payload["request"]["action"]["spec"]["current_target"] =
        json!({"pid":123,"birth":45,"executable_sha256":"b".repeat(64)});
    payload["request"]["action"]["spec"]["exec_epoch"] = json!(2);
    let claims = verify_proof(&fixture.bootstrap, &fixture.sign(&payload), 200).unwrap();
    assert_eq!(claims.exec_epoch, 2);
    assert_eq!(claims.root_image.unwrap().executable_sha256, "b".repeat(64));
    payload["request"]["action"] = json!({"kind":"detach","attachment_id":"fixture-attachment","target":{"pid":123,"birth":45,"executable_sha256":"b".repeat(64)},"exec_epoch":2});
    let claims = verify_proof(&fixture.bootstrap, &fixture.sign(&payload), 200).unwrap();
    assert_eq!(claims.action, ApprovedAction::Detach);
    assert_eq!(claims.exec_epoch, 2);
}
