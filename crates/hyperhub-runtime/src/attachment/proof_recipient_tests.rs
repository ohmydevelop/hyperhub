use super::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

fn fixture(tree: bool) -> (Bootstrap, SigningKey, ApprovalProof) {
    let key = SigningKey::from_bytes(&[31; 32]);
    let root = if std::process::id() == 123 { 124 } else { 123 };
    let bootstrap:Bootstrap=serde_json::from_value(json!({
        "attachment_id":"recipient-fixture","session_id":"session","token":"t".repeat(64),"control_endpoint":"unused","socks_address":"127.0.0.1:1",
        "tls_ca_pem":"unused","observe":false,"firewall":null,"sandbox":null,"host_endpoint":"unused","host_token":"h".repeat(64),
        "scope_tree":tree,"root_pid":root,"approval_authority_file":"unused","approval_instance_id":"recipient-instance","initially_owned":false,
        "approval_public_key":key.verifying_key().to_bytes(),"approval_core_public_key":null,"approval_core_pid":0,"approval_core_birth":0,"approval_cli_sha256":"c".repeat(64)
    })).unwrap();
    let body = json!({"request":{"schema_version":1,"instance_id":"recipient-instance","action":{"kind":"attach","spec":{
        "id":"recipient-fixture","scope":if tree{"tree"}else{"process"},"target":{"pid":root,"birth":42,"executable_sha256":"ab".repeat(32)},"exec_epoch":0
    }}},"approved_at_ms":100,"expires_at_ms":500,"nonce":vec![3u8;32],"executor_sha256":"ef".repeat(32),"execution_digest":null,"host_binding":bootstrap.approval_binding().unwrap()});
    let mut payload = DOMAIN.to_vec();
    payload.extend(serde_json::to_vec(&body).unwrap());
    let signature = key.sign(&payload).to_bytes().to_vec();
    (bootstrap, key, ApprovalProof { payload, signature })
}
#[test]
fn process_recipient_verification_does_not_relax_host_self_pid_wrapper() {
    let (bootstrap, key, proof) = fixture(false);
    assert_ne!(bootstrap.root_pid, std::process::id());
    assert!(
        verify_proof_with_key(&bootstrap, &key.verifying_key().to_bytes(), &proof, 200).is_err()
    );
    assert!(verify_proof(&bootstrap, &proof, 200).is_err());
    verify_proof_with_key_for_recipient(
        &bootstrap,
        &key.verifying_key().to_bytes(),
        &proof,
        200,
        bootstrap.root_pid,
    )
    .unwrap();
}
#[test]
fn process_recipient_verification_rejects_other_process_and_scope_substitution() {
    let (bootstrap, key, proof) = fixture(false);
    for recipient in [0, bootstrap.root_pid + 1] {
        assert!(verify_proof_with_key_for_recipient(
            &bootstrap,
            &key.verifying_key().to_bytes(),
            &proof,
            200,
            recipient
        )
        .is_err());
    }
    let mut changed = bootstrap.clone();
    changed.scope_tree = true;
    assert!(verify_proof_with_key_for_recipient(
        &changed,
        &key.verifying_key().to_bytes(),
        &proof,
        200,
        bootstrap.root_pid
    )
    .is_err());
}
#[test]
fn tree_recipient_verification_allows_proven_child_but_never_changes_signed_root() {
    let (bootstrap, key, proof) = fixture(true);
    verify_proof_with_key_for_recipient(
        &bootstrap,
        &key.verifying_key().to_bytes(),
        &proof,
        200,
        bootstrap.root_pid + 1,
    )
    .unwrap();
    assert!(verify_proof_with_key_for_recipient(
        &bootstrap,
        &key.verifying_key().to_bytes(),
        &proof,
        200,
        0
    )
    .is_err());
    let mut changed = bootstrap.clone();
    changed.root_pid += 1;
    assert!(verify_proof_with_key_for_recipient(
        &changed,
        &key.verifying_key().to_bytes(),
        &proof,
        200,
        changed.root_pid + 1
    )
    .is_err());
}
