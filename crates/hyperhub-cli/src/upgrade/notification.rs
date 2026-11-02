use hyperhub_core::release::{Phase, RecordView};
use hyperhub_core::session::{ControlRequest, ControlResponse};
use std::time::Duration;

pub(super) fn print_success(version: &str) {
    println!("\n🎉 HyperHub {version} updated successfully! Enjoy the new version.");
}

// Installation and the irreversible runtime decision must both be confirmed.
// Old connections may keep draining indefinitely after the new version is ready.
fn completion(record: &RecordView) -> Result<bool, String> {
    match record.phase {
        Phase::Failed
        | Phase::RollingBack
        | Phase::RolledBack
        | Phase::RequiresRestart
        | Phase::InstallationPending => Err(record
            .reason
            .clone()
            .unwrap_or_else(|| format!("upgrade is {:?}", record.phase))),
        Phase::Draining | Phase::Complete => {
            Ok(record.finalize_decided && record.installation_confirmed)
        }
        _ => Ok(false),
    }
}

pub(crate) fn watch_completion(id: &str) -> Result<i32, String> {
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    runtime.block_on(async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        loop {
            let response = tokio::time::timeout(
                Duration::from_secs(2),
                hyperhub_core::control::control_request(
                    &hyperhub_core::control::discovery_control_endpoint(),
                    &ControlRequest::GetReleaseUpgrades { id: Some(id.into()) },
                ),
            )
            .await;
            let last_error = match response {
                Ok(Ok(ControlResponse::ReleaseUpgrades { status: Some(status) })) => {
                    if let Some(error) = status.error {
                        return Err(format!("cannot confirm update completion: {error}; use hyperhub upgrade status {id}"));
                    }
                    if let Some(record) = status.records.iter().find(|record| record.id == id) {
                        match completion(record) {
                            Ok(true) => {
                                print_success(&record.version);
                                return Ok(0);
                            }
                            Ok(false) => {}
                            Err(reason) => {
                                return Err(format!("update did not complete: {reason}; use hyperhub upgrade status {id}"));
                            }
                        }
                        None
                    } else {
                        Some("upgrade transaction was not found".into())
                    }
                }
                Ok(Ok(ControlResponse::Error { message })) => Some(message),
                Ok(Ok(_)) => Some("upgrade status is unavailable".into()),
                Ok(Err(error)) => Some(error.to_string()),
                Err(_) => Some("upgrade status request timed out".into()),
            };
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "update completion has not been confirmed{}; use hyperhub upgrade status {id}",
                    last_error.map(|error| format!(": {error}")).unwrap_or_default(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(phase: Phase) -> RecordView {
        RecordView {
            id: "celebration-test".into(),
            version: "1.2.3".into(),
            phase,
            reason: None,
            created_at_ms: 0,
            updated_at_ms: 0,
            finalize_decided: false,
            installation_confirmed: false,
            engine_hosts: 0,
            worker_generation: None,
            worker_pid: None,
            helper_pid: None,
            requires_restart_processes: vec![],
        }
    }

    #[test]
    fn celebration_requires_both_confirmations_but_does_not_wait_for_old_connections() {
        for phase in [Phase::Draining, Phase::Complete] {
            for decided in [false, true] {
                for installed in [false, true] {
                    let mut record = record(phase);
                    record.finalize_decided = decided;
                    record.installation_confirmed = installed;
                    assert_eq!(completion(&record), Ok(decided && installed));
                }
            }
        }
        for phase in [
            Phase::Preparing,
            Phase::Prepared,
            Phase::Switching,
            Phase::Observing,
            Phase::Finalizing,
            Phase::Installing,
        ] {
            let mut record = record(phase);
            record.finalize_decided = true;
            record.installation_confirmed = true;
            assert_eq!(completion(&record), Ok(false));
        }
    }

    #[test]
    fn unsuccessful_or_uncertain_updates_report_the_reason_without_celebrating() {
        for phase in [
            Phase::Failed,
            Phase::RollingBack,
            Phase::RolledBack,
            Phase::RequiresRestart,
            Phase::InstallationPending,
        ] {
            let mut record = record(phase);
            record.finalize_decided = true;
            record.installation_confirmed = true;
            record.reason = Some("update needs attention".into());
            assert_eq!(completion(&record), Err("update needs attention".into()));
        }
    }
}
