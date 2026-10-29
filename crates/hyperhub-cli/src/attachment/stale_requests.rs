//! Only confirmed binding changes are terminal. Transport and profile failures
//! cannot prove a request stale and must leave the proposal pending.
use super::*;
use attachments::StaleRequestReason;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Freshness {
    Current,
    Stale(StaleRequestReason),
    Unavailable(String),
}
fn binding_change(request: &Request, instance: &str, policy: &str) -> Option<StaleRequestReason> {
    if request.instance_id != instance {
        Some(StaleRequestReason::InstanceChanged)
    } else if request.action.policy_digest() != policy {
        Some(StaleRequestReason::PolicyChanged)
    } else {
        None
    }
}
fn classify(
    request: &Request,
    instance: &str,
    policy: &str,
    epoch: Result<Option<u64>, String>,
) -> Freshness {
    if let Some(reason) = binding_change(request, instance, policy) {
        return Freshness::Stale(reason);
    }
    match epoch {
        Ok(Some(current)) if current != request.action.exec_epoch() => {
            Freshness::Stale(StaleRequestReason::ExecutableEpochChanged {
                expected: request.action.exec_epoch(),
                current,
            })
        }
        Ok(_) => Freshness::Current,
        Err(error) => Freshness::Unavailable(error),
    }
}
pub(super) fn archived_error(directory: &Path, id: &str) -> Result<Option<String>, String> {
    Ok(
        attachments::stale_request_audit(directory, id)?.map(|audit| {
            format!(
                "runtime request {id} is stale and archived: {}; create a new proposal",
                audit.reason
            )
        }),
    )
}
pub(super) fn probe_epoch(directory: &Path, request: &Request) -> Result<Option<u64>, String> {
    let path = attachments::attachment_directory(directory, request.action.attachment_id())?
        .join("record.json");
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            trusted_exec_epoch(request.action.attachment_id()).map(Some)
        }
        Ok(_) => Err("attachment state is not a regular record".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("cannot inspect attachment state: {error}")),
    }
}
pub(super) fn filter_pending(
    directory: &Path,
    instance: &str,
    policy: &str,
    mut probe: impl FnMut(&Request) -> Result<Option<u64>, String>,
) -> Result<Vec<Request>, String> {
    let guard = attachments::OperationGuard::acquire(directory)?;
    let mut pending = Vec::new();
    // A failed Core connection is probed at most once per attachment slot,
    // including when several historical requests share that target process.
    let mut epochs = std::collections::HashMap::new();
    for request in attachments::requests(directory)? {
        let epoch = if binding_change(&request, instance, policy).is_some() {
            Ok(None)
        } else {
            epochs
                .entry(request.action.attachment_id().to_owned())
                .or_insert_with(|| probe(&request))
                .clone()
        };
        match classify(&request, instance, policy, epoch) {
            Freshness::Stale(reason) => {
                attachments::archive_stale_request(directory, &request, reason.clone(), &guard)?;
                eprintln!(
                    "Runtime request {} is stale and archived: {reason}.",
                    request.id
                );
            }
            Freshness::Current | Freshness::Unavailable(_) => pending.push(request),
        }
    }
    Ok(pending)
}
pub(super) fn validate_selected(
    directory: &Path,
    request: &Request,
    instance: &str,
    policy: &str,
    guard: &attachments::OperationGuard,
    probe: impl FnOnce(&Request) -> Result<Option<u64>, String>,
) -> Result<(), String> {
    if attachments::load_request(directory, &request.id)? != *request {
        return Err("runtime proposal changed while human approval was pending".into());
    }
    let epoch = if binding_change(request, instance, policy).is_some() {
        Ok(None)
    } else {
        probe(request)
    };
    match classify(request, instance, policy, epoch) {
        Freshness::Current => Ok(()),
        Freshness::Unavailable(error) => Err(format!(
            "cannot validate pending runtime request {}: {error}; request remains pending",
            request.id
        )),
        Freshness::Stale(reason) => {
            attachments::archive_stale_request(directory, request, reason.clone(), guard)?;
            Err(format!(
                "runtime request {} is stale and archived: {reason}; create a new proposal",
                request.id
            ))
        }
    }
}

#[cfg(test)]
#[path = "stale_requests_tests.rs"]
mod tests;
