//! Enroll a legacy empty Host only through its original pinned Core. New
//! configurations carry a password public anchor from initial owned startup.
use super::*;
use hyperhub_runtime::attachment as wire;
pub(super) fn existing_hosts(
    directory: &Path,
    keyring: &ConfigKeyring,
    config: &Path,
    password: &[u8],
) -> Result<(), String> {
    if !directory.join("record.json").exists() {
        return Ok(());
    }
    let current = config_store::load_encrypted(config, password).map_err(|e| e.to_string())?;
    let current_key = current.approval_public_key;
    let record = attachments::load_record(directory)?;
    if record.spec.backend != Backend::Gum
        || matches!(
            record.phase,
            Phase::Detached | Phase::Exited | Phase::Failed
        )
    {
        return Ok(());
    }
    let execution = attachments::load_execution(directory, keyring)?;
    let (context, _) = attachments::load_recovery_context::<serde_json::Value>(directory, keyring)?;
    let members = context
        .get("members")
        .and_then(serde_json::Value::as_array)
        .ok_or("native Host recovery members are unavailable for enrollment")?;
    for member in members {
        let identity: attachments::ProcessIdentity = serde_json::from_value(
            member
                .get("identity")
                .cloned()
                .ok_or("Host identity missing")?,
        )
        .map_err(|e| e.to_string())?;
        if attachments::process_birth(identity.pid) != Some(identity.birth) {
            continue;
        }
        attachments::verify_process(&identity)?;
        if member.get("unloaded").and_then(serde_json::Value::as_bool) == Some(true) {
            continue;
        }
        let bootstrap: wire::Bootstrap = serde_json::from_value(
            member
                .get("bootstrap")
                .cloned()
                .ok_or("Host bootstrap missing")?,
        )
        .map_err(|e| e.to_string())?;
        if bootstrap.attachment_id != execution.spec.id
            || bootstrap.root_pid != execution.spec.target.pid
            || bootstrap.approval_instance_id != execution.authorization.request.instance_id
        {
            return Err("Host enrollment differs from approved attachment identity".into());
        }
        let command = |kind, enrollment| wire::AuthenticatedCommand {
            attachment_id: bootstrap.attachment_id.clone(),
            token: bootstrap.host_token.clone(),
            command: kind,
            proof: None,
            enrollment,
            aliases: None,
            root_image: None,
        };
        let status = wire::exchange_for_process(
            &bootstrap.host_endpoint,
            &command(wire::HostCommand::Status, None),
            identity.pid,
        )
        .map_err(|e| e.to_string())?;
        if status.approval_root_enrolled && status.approval_public_key == current_key {
            continue;
        }
        let rotating = status.approval_root_enrolled;
        let status = wire::exchange_for_process(
            &bootstrap.host_endpoint,
            &command(wire::HostCommand::EnrollmentChallenge, None),
            identity.pid,
        )
        .map_err(|e| e.to_string())?;
        let challenge = status
            .approval_challenge
            .ok_or("Host did not return an approval enrollment challenge")?;
        if challenge.host_pid != identity.pid || challenge.host_birth != identity.birth {
            return Err("Host enrollment challenge incarnation differs from OS process".into());
        }
        let certificate = if rotating {
            config_store::approval_rotation_certificate(
                config,
                password,
                &bootstrap,
                &challenge,
                unix_timestamp_ms(),
            )
            .map_err(|e| e.to_string())?
        } else {
            let response = runtime()?
                .block_on(hyperhub_core::control::trusted_control_request(
                    &bootstrap.control_endpoint,
                    &ControlRequest::GetApprovalRootCertificate {
                        bootstrap: bootstrap.clone(),
                        challenge,
                    },
                ))
                .map_err(|e| e.to_string())?;
            let certificate = match response {
                ControlResponse::ApprovalRootCertificate { certificate } => certificate,
                ControlResponse::Error { message } => return Err(message),
                _ => return Err("Core did not return Host root enrollment certificate".into()),
            };
            certificate
        };
        let enrolled = wire::exchange_for_process(
            &bootstrap.host_endpoint,
            &command(wire::HostCommand::EnrollApprovalRoot, Some(certificate)),
            identity.pid,
        )
        .map_err(|e| e.to_string())?;
        if !enrolled.approval_root_enrolled || enrolled.approval_public_key != current_key {
            return Err("Host did not confirm administrator root enrollment".into());
        }
    }
    Ok(())
}
