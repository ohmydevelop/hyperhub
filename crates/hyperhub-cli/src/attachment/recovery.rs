//! A vanished manager requires a new scoped human decision. Existing credentials
//! only locate the old Host; they never authorize a new injection.
use super::*;
use attachments::{ProcessIdentity, Record, RecoveryBinding};

pub(super) fn binding(record: &Record) -> Result<Option<RecoveryBinding>, String> {
    let Some(manager) = record.manager.as_ref() else {
        return Ok(None);
    };
    if attachments::process_birth(manager.pid) == Some(manager.birth) {
        return Ok(None);
    }
    let directory = attachments::attachment_directory(&attachments::directory()?, &record.spec.id)?;
    let (_, digest) = attachments::load_recovery_context::<serde_json::Value>(
        &directory,
        &crate::password::load_runtime_keyring()?,
    )?;
    Ok(Some(RecoveryBinding {
        manager: manager.clone(),
        context_digest: digest,
    }))
}

pub(super) fn execute_approved(
    directory: &Path,
    record_directory: &Path,
    path: &Path,
    descriptor: &config_store::KdfDescriptor,
    password: &[u8],
    keyring: &ConfigKeyring,
    request: &Request,
) -> Result<Option<i32>, String> {
    let record = attachments::load_record(record_directory)?;
    let binding = request
        .action
        .recovery()
        .ok_or("recovery binding missing")?;
    if record.manager.as_ref() != Some(&binding.manager)
        || attachments::process_birth(binding.manager.pid) == Some(binding.manager.birth)
        || !record.spec.target.same_incarnation(request.action.target())
    {
        return Err("recovery manager or original target changed; submit a new proposal".into());
    }
    let (_, digest) =
        attachments::load_recovery_context::<serde_json::Value>(record_directory, keyring)?;
    if digest != binding.context_digest {
        return Err("recovery metadata changed after approval was proposed".into());
    }
    let mut execution = attachments::load_execution(record_directory, keyring)?;
    if execution.spec.target != record.spec.target || execution.spec.id != record.spec.id {
        return Err("sealed recovery target differs from durable record".into());
    }
    execution.spec = match &request.action {
        Action::Attach { spec } => spec.clone(),
        Action::Detach {
            policy_digest,
            target,
            ..
        } => {
            let mut spec = record.spec.clone();
            spec.current_target = (target != &spec.target).then(|| target.clone());
            spec.exec_epoch = request.action.exec_epoch();
            spec.policy_digest = policy_digest.clone();
            spec.recovery = Some(binding.clone());
            spec
        }
    };
    let waiting_manager = manager_bootstrap::WaitingManager::spawn(record_directory)?;
    execution.authorization = attachments::authorize_claimant_bound(
        directory,
        path,
        password,
        descriptor,
        request.clone(),
        unix_timestamp_ms(),
        Some(attachments::bootstrap_digest(&execution.bootstrap)?),
        attachments::executor_digest()?,
        record.host_binding.clone(),
        waiting_manager.claimant.clone(),
    )?;
    let mut uncommitted = manager_bootstrap::UncommittedRecord::new(record_directory, false);
    attachments::save_execution(record_directory, &execution, keyring)?;
    archive_request(directory, request, "approved")?;
    let mut started_manager = waiting_manager.commit()?;
    uncommitted.disarm();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = started_manager.exited()? {
            let final_record = attachments::load_record(record_directory)?;
            if final_record.manager.as_ref() == Some(started_manager.identity())
                && matches!(final_record.phase, Phase::Detached | Phase::Exited)
            {
                println!(
                    "{}",
                    json!({"status":"approved","request_id":request.id,"attachment_id":final_record.spec.id,"phase":final_record.phase,"recovery":true,"compatibility_reasons":final_record.compatibility_reasons})
                );
                return Ok(Some(0));
            }
            attachments::record_execution_error(
                record_directory,
                format!("created recovery manager exited before acknowledgement: {status}"),
            )?;
            return Err("approved recovery manager exited; existing native residue is preserved for inspection".into());
        }
        let current = attachments::load_record(record_directory)?;
        let new_manager = current
            .manager
            .as_ref()
            .is_some_and(|manager| manager == started_manager.identity() && manager_alive(manager));
        if new_manager
            && matches!(
                current.phase,
                Phase::Active | Phase::Detached | Phase::DetachedResident | Phase::Draining
            )
        {
            println!(
                "{}",
                json!({"status":"approved","request_id":request.id,"attachment_id":current.spec.id,"phase":current.phase,"recovery":true,"compatibility_reasons":current.compatibility_reasons})
            );
            return Ok(Some(0));
        }
        if new_manager
            && matches!(
                current.phase,
                Phase::Failed | Phase::CleanupPending | Phase::Degraded
            )
        {
            return Err(
                "approved recovery failed; inspect durable state and private manager log".into(),
            );
        }
        if Instant::now() >= deadline {
            println!(
                "{}",
                json!({"status":"execution_pending","request_id":request.id,"attachment_id":record.spec.id,"recovery":true})
            );
            return Ok(Some(0));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn manager_alive(manager: &ProcessIdentity) -> bool {
    attachments::process_birth(manager.pid) == Some(manager.birth)
}
