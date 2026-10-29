use super::{Authorization, Execution, ProcessIdentity};
use crate::session::{ControlRequest, ControlResponse};
/// Activate a signed external attachment before the injected agent enrolls.
pub async fn activate_session(
    execution: &Execution,
    manager: &ProcessIdentity,
    members: &[ProcessIdentity],
) -> Result<(), String> {
    super::register_manager_execution(execution)?;
    super::set_manager_policy_required(&execution.spec.id, true)?;
    let response = crate::control::control_request(
        &execution.bootstrap.control_endpoint,
        &ControlRequest::ActivateAttachment {
            authorization: execution.authorization.clone(),
            session_id: execution.bootstrap.session_id.clone(),
            token: execution.bootstrap.token.clone().into(),
            manager: manager.clone(),
            members: members.to_vec(),
            hosts: Vec::new(),
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    match response {
        ControlResponse::Ok => {
            sync_manager_root_image(execution).await?;
            Ok(())
        }
        ControlResponse::Error { message } => Err(message),
        _ => Err("unexpected attachment activation response".into()),
    }
}

/// End a session only after its manager proved physical detachment. A consumed
/// operation may finish draining after the grant's initial execution deadline.
pub async fn complete_session(
    execution: &Execution,
    authorization: &super::Authorization,
) -> Result<(), String> {
    let response = crate::control::control_request(
        &execution.bootstrap.control_endpoint,
        &ControlRequest::CompleteAttachment {
            authorization: authorization.clone(),
            session_id: execution.bootstrap.session_id.clone(),
            token: execution.bootstrap.token.clone().into(),
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    match response {
        ControlResponse::Ok => super::set_manager_policy_required(&execution.spec.id, false),
        ControlResponse::Error { message } => Err(message),
        _ => Err("unexpected attachment completion response".into()),
    }
}

/// Adopt only existing authenticated session members under a fresh human grant.
pub async fn recover_session(
    execution: &Execution,
    manager: &ProcessIdentity,
    members: &[ProcessIdentity],
) -> Result<(), String> {
    recover_session_with_unstarted(execution, manager, members, &[]).await
}

/// Cleanup-only recovery of journaled attempts whose dispatch bit was durably
/// false. The caller must supply every unstarted attempt, never an unknown bit.
pub async fn recover_session_with_unstarted(
    execution: &Execution,
    manager: &ProcessIdentity,
    members: &[ProcessIdentity],
    unstarted: &[super::HostBootstrapBinding],
) -> Result<(), String> {
    recover_session_with_startup_cleanup(execution, manager, members, &[], unstarted).await
}

/// Supply the complete real Host roster when cleanup recovers startup before
/// alias registration. Each locator is bound to this accepted manager's proof.
pub async fn recover_session_with_startup_cleanup(
    execution: &Execution,
    manager: &ProcessIdentity,
    members: &[ProcessIdentity],
    hosts: &[super::HostBootstrapBinding],
    unstarted: &[super::HostBootstrapBinding],
) -> Result<(), String> {
    super::register_manager_execution(execution)?;
    super::set_manager_policy_required(&execution.spec.id, true)?;
    let response = crate::control::control_request(
        &execution.bootstrap.control_endpoint,
        &ControlRequest::RecoverAttachment {
            authorization: execution.authorization.clone(),
            session_id: execution.bootstrap.session_id.clone(),
            token: execution.bootstrap.token.clone().into(),
            manager: manager.clone(),
            members: members.to_vec(),
            startup_hosts: hosts.to_vec(),
            unstarted: unstarted.to_vec(),
            unstarted_proof: if unstarted.is_empty() && hosts.is_empty() {
                None
            } else {
                Some(super::operation::prove_unstarted_injections(
                    execution, hosts, unstarted,
                )?)
            },
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    match response {
        ControlResponse::Ok => {
            sync_manager_root_image(execution).await?;
            Ok(())
        }
        ControlResponse::Error { message } => Err(message),
        _ => Err("unexpected attachment recovery response".into()),
    }
}

/// A new signed Attach decision reauthorizes a retained native base before it
/// refreshes policy. Old API/session tokens alone never recreate membership.
pub async fn reactivate_session(
    execution: &Execution,
    authorization: &super::Authorization,
    manager: &ProcessIdentity,
    members: &[ProcessIdentity],
    hosts: &[super::HostBootstrapBinding],
) -> Result<(), String> {
    super::register_manager_execution(execution)?;
    // Publish admission before Core accepts the operation. A lost response can
    // already mean an accepted activation, so errors retain the safe true state.
    super::set_manager_policy_required(&execution.spec.id, true)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        let response = crate::control::control_request(
            &execution.bootstrap.control_endpoint,
            &ControlRequest::ActivateAttachment {
                authorization: authorization.clone(),
                session_id: execution.bootstrap.session_id.clone(),
                token: execution.bootstrap.token.clone().into(),
                manager: manager.clone(),
                members: members.to_vec(),
                hosts: hosts.to_vec(),
            },
        )
        .await
        .map_err(|e| e.to_string())?;
        match response {
            ControlResponse::Ok => return Ok(()),
            ControlResponse::Error { message }
                if message == "alias_publication_busy" && std::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            ControlResponse::Error { message } => return Err(message),
            _ => return Err("unexpected resident session reauthorization response".into()),
        }
    }
}
/// Legacy empty Hosts enroll only through their originally pinned live Core.
/// New configurations already carry the password public anchor at startup.
pub fn ensure_host_approval_root(
    bootstrap: &hyperhub_runtime::attachment::Bootstrap,
    identity: &ProcessIdentity,
) -> Result<(), String> {
    use hyperhub_runtime::attachment as wire;
    super::verify_process(identity)?;
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
    if status.approval_root_enrolled {
        return Ok(());
    }
    if !status.approval_enrollment_available {
        return Err("legacy empty Host has no original Core attestation; administrator enrollment is unavailable".into());
    }
    let status = wire::exchange_for_process(
        &bootstrap.host_endpoint,
        &command(wire::HostCommand::EnrollmentChallenge, None),
        identity.pid,
    )
    .map_err(|e| e.to_string())?;
    let challenge = status
        .approval_challenge
        .ok_or("Host did not return an enrollment challenge")?;
    if challenge.host_pid != identity.pid || challenge.host_birth != identity.birth {
        return Err("Host enrollment incarnation mismatch".into());
    }
    let endpoint = bootstrap.control_endpoint.clone();
    let request = ControlRequest::GetApprovalRootCertificate {
        bootstrap: bootstrap.clone(),
        challenge,
    };
    let response = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        rt.block_on(crate::control::trusted_control_request(&endpoint, &request))
            .map_err(|e| e.to_string())
    })
    .join()
    .map_err(|_| "Host enrollment worker failed")??;
    let certificate = match response {
        ControlResponse::ApprovalRootCertificate { certificate } => certificate,
        ControlResponse::Error { message } => return Err(message),
        _ => return Err("Core did not return Host enrollment certificate".into()),
    };
    let status = wire::exchange_for_process(
        &bootstrap.host_endpoint,
        &command(wire::HostCommand::EnrollApprovalRoot, Some(certificate)),
        identity.pid,
    )
    .map_err(|e| e.to_string())?;
    if !status.approval_root_enrolled {
        return Err("Host did not confirm root enrollment".into());
    }
    Ok(())
}

/// Flush the issuance prefix before a manager removes any Host policy. This is
/// a continuation of an already consumed human Detach, never token-only authority.
pub async fn prepare_detach_session(
    execution: &Execution,
    authorization: &Authorization,
    manager: &ProcessIdentity,
) -> Result<(), String> {
    let result = detach_barrier_plan_loop(execution, authorization, manager, false).await;
    if let Err(error) = result {
        return match detach_barrier_plan_loop(execution, authorization, manager, true).await {
            Ok(()) => Err(error),
            Err(cancel) => Err(format!(
                "{error}; admission cancellation remains pending: {cancel}"
            )),
        };
    }
    Ok(())
}
async fn detach_barrier_plan_loop(
    execution: &Execution,
    authorization: &Authorization,
    manager: &ProcessIdentity,
    cancel: bool,
) -> Result<(), String> {
    use hyperhub_runtime::attachment::HostLifecycleCommand;
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(if cancel { 5 } else { 15 });
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(if cancel {
                "detach cancellation deadline exceeded"
            } else {
                "alias_publication_busy"
            }
            .into());
        }
        let request = if cancel {
            ControlRequest::CancelAttachmentDetach {
                authorization: authorization.clone(),
                session_id: execution.bootstrap.session_id.clone(),
                token: execution.bootstrap.token.clone().into(),
                manager: manager.clone(),
            }
        } else {
            ControlRequest::PrepareAttachmentDetach {
                authorization: authorization.clone(),
                session_id: execution.bootstrap.session_id.clone(),
                token: execution.bootstrap.token.clone().into(),
                manager: manager.clone(),
            }
        };
        let response =
            crate::control::control_request(&execution.bootstrap.control_endpoint, &request)
                .await
                .map_err(|e| e.to_string())?;
        let result = match response {
            ControlResponse::Ok => return Ok(()),
            ControlResponse::AttachmentDetachPlan { plan } => super::execute_detach_barrier_plan(
                execution,
                authorization,
                plan,
                if cancel {
                    HostLifecycleCommand::CancelDetachmentPreparation
                } else {
                    HostLifecycleCommand::PrepareDetachment
                },
            ),
            ControlResponse::Error { message } => Err(message),
            _ => return Err("unexpected alias detach barrier response".into()),
        };
        if let Err(message) = result {
            if !matches!(
                message.as_str(),
                "activation_busy" | "alias_publication_busy"
            ) {
                return Err(message);
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
}
pub async fn finish_detach_session(
    execution: &Execution,
    authorization: &Authorization,
    manager: &ProcessIdentity,
) -> Result<bool, String> {
    match crate::control::control_request(
        &execution.bootstrap.control_endpoint,
        &ControlRequest::FinishAttachmentDetach {
            authorization: authorization.clone(),
            session_id: execution.bootstrap.session_id.clone(),
            token: execution.bootstrap.token.clone().into(),
            manager: manager.clone(),
        },
    )
    .await
    .map_err(|e| e.to_string())?
    {
        ControlResponse::Ok => {
            super::set_manager_policy_required(&execution.spec.id, false)?;
            Ok(true)
        }
        ControlResponse::Error { message } if message == "alias_detach_members_pending" => {
            Ok(false)
        }
        ControlResponse::Error { message } => Err(message),
        _ => Err("unexpected alias detach completion response".into()),
    }
}
/// Catch a verified suspended child up without asking its listener to recursively
/// call itself. Caller must be the authenticated attachment manager.
pub async fn catchup_alias_host(
    bootstrap: &hyperhub_runtime::attachment::Bootstrap,
    identity: &ProcessIdentity,
) -> Result<(), String> {
    use hyperhub_runtime::attachment as wire;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if std::time::Instant::now() >= deadline {
            return Err("alias Host catchup deadline exceeded".into());
        }
        let status = wire::exchange_for_process(
            &bootstrap.host_endpoint,
            &wire::AuthenticatedCommand {
                attachment_id: bootstrap.attachment_id.clone(),
                token: bootstrap.host_token.clone(),
                command: wire::HostCommand::Status,
                proof: None,
                enrollment: None,
                aliases: None,
                root_image: None,
            },
            identity.pid,
        )
        .map_err(|e| e.to_string())?;
        let anchor = status
            .alias_inheritance
            .ok_or("Host has no trusted session alias signer")?;
        let mut bootstrap = bootstrap.clone();
        bootstrap.alias_inherited = Some(anchor.clone());
        match crate::control::control_request(
            &bootstrap.control_endpoint,
            &ControlRequest::RegisterAliasHost {
                identity: Some(identity.clone()),
                bootstrap: bootstrap.clone(),
                sequence: anchor.sequence,
                head: anchor.head,
                root_image_challenge: None,
            },
        )
        .await
        .map_err(|e| e.to_string())?
        {
            ControlResponse::AliasHostRegistration {
                ready: true,
                snapshot: None,
                ..
            } => return Ok(()),
            ControlResponse::AliasHostRegistration {
                snapshot: Some(snapshot),
                proof,
                ..
            } => {
                wire::exchange_for_process(
                    &bootstrap.host_endpoint,
                    &wire::AuthenticatedCommand {
                        attachment_id: bootstrap.attachment_id.clone(),
                        token: bootstrap.host_token.clone(),
                        command: wire::HostCommand::ApplySessionAliases,
                        proof,
                        enrollment: None,
                        aliases: Some(snapshot),
                        root_image: None,
                    },
                    identity.pid,
                )
                .map_err(|e| e.to_string())?;
            }
            ControlResponse::Error { message } => return Err(message),
            _ => return Err("unexpected alias Host catchup response".into()),
        }
    }
}

/// Report an OS-observed root exec while the backend still owns its startup gate.
pub async fn report_attachment_exec(
    execution: &Execution,
    manager: &ProcessIdentity,
    previous: &ProcessIdentity,
    current: &ProcessIdentity,
    transition_nonce: [u8; 32],
) -> Result<hyperhub_runtime::attachment::RootImageState, String> {
    match crate::control::control_request(
        &execution.bootstrap.control_endpoint,
        &ControlRequest::ReportAttachmentExec {
            attachment_id: execution.spec.id.clone(),
            session_id: execution.bootstrap.session_id.clone(),
            token: execution.bootstrap.token.clone().into(),
            manager: manager.clone(),
            previous: previous.clone(),
            current: current.clone(),
            transition_nonce,
        },
    )
    .await
    .map_err(|e| e.to_string())?
    {
        ControlResponse::AttachmentImage { state } => {
            super::remember_manager_root_image(&execution.spec.id, state.clone())?;
            Ok(state)
        }
        ControlResponse::Error { message } => Err(message),
        _ => Err("unexpected root exec reporting response".into()),
    }
}
pub async fn sync_manager_root_image(
    execution: &Execution,
) -> Result<hyperhub_runtime::attachment::RootImageState, String> {
    super::register_manager_execution(execution)?;
    match crate::control::control_request(
        &execution.bootstrap.control_endpoint,
        &ControlRequest::GetAttachmentImage {
            attachment_id: execution.spec.id.clone(),
        },
    )
    .await
    .map_err(|e| e.to_string())?
    {
        ControlResponse::AttachmentImage { state } => {
            super::remember_manager_root_image(&execution.spec.id, state.clone())?;
            Ok(state)
        }
        ControlResponse::Error { message } => Err(message),
        _ => Err("unexpected manager root image response".into()),
    }
}
pub async fn initialize_owned_image(
    execution: &Execution,
    manager: &ProcessIdentity,
) -> Result<hyperhub_runtime::attachment::RootImageState, String> {
    super::register_manager_execution(execution)?;
    match crate::control::control_request(
        &execution.bootstrap.control_endpoint,
        &ControlRequest::InitializeOwnedAttachmentImage {
            bootstrap: execution.bootstrap.clone(),
            manager: manager.clone(),
            target: execution.spec.target.clone(),
        },
    )
    .await
    .map_err(|e| e.to_string())?
    {
        ControlResponse::AttachmentImage { state } => {
            super::remember_manager_root_image(&execution.spec.id, state.clone())?;
            Ok(state)
        }
        ControlResponse::Error { message } => Err(message),
        _ => Err("unexpected owned image initialization response".into()),
    }
}
