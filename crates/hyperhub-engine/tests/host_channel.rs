use hyperhub_engine::{
    host::{self, Delivery},
    management::Command,
};
use std::io::Cursor;

#[test]
fn a_forged_or_replayed_delivery_cannot_reach_the_native_loader() {
    let runtime = hyperhub_engine::resident();
    let mut manifest = runtime.snapshot().unwrap().host;
    manifest.state_schema += 1;
    let command = Command::Prepare {
        id: "must-not-prepare".into(),
        manifest,
        source: "missing-native-library".into(),
        cache: "must-not-create".into(),
    };
    let nonce = [4; 32];
    let proof = host::delivery_proof("session secret", &nonce, "request", &command).unwrap();
    let frame = Delivery {
        request_id: "request".into(),
        command,
        proof,
    };
    for (token, stream_nonce) in [("wrong token", nonce), ("session secret", [5; 32])] {
        let mut bytes = Vec::new();
        host::write_frame(&mut bytes, &frame).unwrap();
        let error = unsafe { host::serve(&mut Cursor::new(bytes), &runtime, token, &stream_nonce) }
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(runtime.snapshot().unwrap().transactions.is_empty());
    }
}
#[test]
fn oversized_and_truncated_frames_fail_before_allocating_or_dispatching() {
    for bytes in [
        ((host::MAX_FRAME + 1) as u32).to_be_bytes().to_vec(),
        vec![0, 0, 0, 4, b'{'],
    ] {
        assert!(host::read_frame::<Delivery>(&mut Cursor::new(bytes)).is_err());
    }
}

#[test]
fn bounded_reports_expose_omissions_and_preserve_transaction_recovery() {
    let runtime = hyperhub_engine::resident();
    let mut manifest = runtime.snapshot().unwrap().host;
    manifest.state_schema += 1;
    for n in 0..40 {
        let reply = unsafe {
            hyperhub_engine::management::execute(
                &runtime,
                Command::Prepare {
                    id: format!("transaction-{n:02}"),
                    manifest: manifest.clone(),
                    source: "must-not-open".into(),
                    cache: "must-not-create".into(),
                },
            )
        };
        assert!(
            matches!(reply, hyperhub_engine::management::Reply::Transaction { transaction }
            if transaction.stage == hyperhub_runtime::Stage::RequiresRestart)
        );
    }
    let report = host::report(&runtime).unwrap();
    assert_eq!(report.transactions.len(), 32);
    assert_eq!(report.transactions_omitted, 8);
    assert_eq!(runtime.snapshot().unwrap().transactions.len(), 40);
    assert_eq!(runtime.snapshot().unwrap().transactions_omitted, 0);
    assert_eq!(
        runtime.query("transaction-00").unwrap().stage,
        hyperhub_runtime::Stage::RequiresRestart
    );
    assert!(runtime.query("unknown").is_err());
}
