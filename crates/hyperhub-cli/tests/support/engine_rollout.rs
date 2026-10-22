use super::*;
use hyperhub_core::upgrade::{Action, Phase, RecordView, Request};
pub fn start(
    service: &ControlService,
) -> (
    hyperhub_core::upgrade::Coordinator,
    tokio::task::JoinHandle<()>,
) {
    let coordinator = service.engine_upgrade_coordinator().unwrap();
    let runner = coordinator.spawn().unwrap();
    (coordinator, runner)
}
pub async fn interrupt_and_recover(endpoint: &str, runner: tokio::task::JoinHandle<()>) {
    runner.abort();
    let _ = runner.await;
    submit(endpoint, Action::Recover).await;
}
pub async fn stop(coordinator: hyperhub_core::upgrade::Coordinator) {
    coordinator.stop_runner();
    tokio::time::timeout(Duration::from_secs(5), async {
        while coordinator.runner_running() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

pub fn api_key() -> String {
    format!(
        "hhk_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7; 32])
    )
}
pub async fn reject_configuration_key(endpoint: &str) {
    let request = Request {
        id: "forged".into(),
        issued_at_ms: hyperhub_core::session::unix_timestamp_ms(),
        action: Action::Commit,
    };
    let proof = request.proof(&[0; 32]).unwrap();
    assert!(
        matches!(exchange(endpoint, &ControlRequest::EngineUpgrade { request, proof }).await,
        ControlResponse::Error { message } if message == "invalid upgrade owner proof")
    );
}
pub async fn submit(endpoint: &str, action: Action) -> RecordView {
    let request = Request {
        id: "change".into(),
        issued_at_ms: hyperhub_core::session::unix_timestamp_ms(),
        action,
    };
    let proof = request.proof(api_key().as_bytes()).unwrap();
    match exchange(endpoint, &ControlRequest::EngineUpgrade { request, proof }).await {
        ControlResponse::EngineUpgrade { record } => record,
        response => panic!("unexpected rollout response: {response:?}"),
    }
}
pub async fn until(endpoint: &str, phase: Phase) -> RecordView {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match exchange(
                endpoint,
                &ControlRequest::GetEngineUpgrades {
                    id: Some("change".into()),
                },
            )
            .await
            {
                ControlResponse::EngineUpgrades {
                    status: Some(status),
                } => {
                    assert!(status.error.is_none(), "{status:?}");
                    let record = status
                        .records
                        .into_iter()
                        .next()
                        .expect("rollout is missing");
                    if record.phase == phase {
                        return record;
                    }
                    assert!(
                        !record.phase.terminal(),
                        "unexpected rollout terminal state: {record:?}"
                    );
                }
                response => panic!("unexpected rollout status: {response:?}"),
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("native rollout did not reach the requested phase")
}
