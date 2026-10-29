//! Signed manager relay. The transport never authorizes a mutation: the owning
//! backend verifies and consumes the scoped Authorization before changing state.
use super::{Authorization, Outcome};
use serde::{Deserialize, Serialize};
use std::sync::atomic::AtomicBool;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagerCommand {
    authorization: Authorization,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    outcome: Option<Outcome>,
    error: Option<String>,
}
pub fn manager_exchange(endpoint: &str, authorization: &Authorization) -> Result<Outcome, String> {
    manager_exchange_checked(endpoint, authorization, None)
}
pub fn manager_exchange_for_process(
    endpoint: &str,
    authorization: &Authorization,
    pid: u32,
) -> Result<Outcome, String> {
    manager_exchange_checked(endpoint, authorization, Some(pid))
}
pub fn manager_claimant_for_record(
    record: &super::Record,
) -> Result<hyperhub_runtime::attachment::ManagerClaimant, String> {
    let manager = record
        .manager
        .as_ref()
        .ok_or("attachment manager identity missing")?;
    super::verify_process(manager)
        .map_err(|e| format!("attachment manager identity before claimant query: {e}"))?;
    let endpoint = record
        .manager_endpoint
        .as_deref()
        .ok_or("attachment manager endpoint missing")?;
    let value = serde_json::json!({"query":"operation_claimant","attachment_id":record.spec.id});
    let reply =
        hyperhub_runtime::attachment::exchange_raw_for_process(endpoint, &value, manager.pid)
            .map_err(|e| e.to_string())?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ClaimantReply {
        attachment_id: String,
        claimant: Option<hyperhub_runtime::attachment::ManagerClaimant>,
        error: Option<String>,
    }
    let reply: ClaimantReply = serde_json::from_value(reply).map_err(|e| e.to_string())?;
    if let Some(error) = reply.error {
        return Err(error);
    }
    let claimant = reply.claimant.ok_or("manager did not publish a claimant")?;
    claimant.validate().map_err(|e| e.to_string())?;
    if reply.attachment_id != record.spec.id
        || claimant.pid != manager.pid
        || claimant.birth != manager.birth
    {
        return Err("manager claimant differs from authenticated record incarnation".into());
    }
    super::verify_process(manager)
        .map_err(|e| format!("attachment manager identity after claimant query: {e}"))?;
    Ok(claimant)
}
pub fn manager_profile_for_record(
    record: &super::Record,
) -> Result<super::ManagerExecutionProfile, String> {
    let manager = record
        .manager
        .as_ref()
        .ok_or("attachment manager identity missing")?;
    super::verify_process(manager)
        .map_err(|e| format!("execution profile manager identity: {e}"))?;
    if manager.pid == std::process::id() {
        // A lifecycle callback can synchronously ask Core to validate policy.
        // Never call the listener that is already handling that callback.
        let profile = super::manager_execution_profile(&record.spec.id)
            .map_err(|e| format!("execution profile local RAM lookup: {e}"))?;
        profile
            .validate_record(record)
            .map_err(|e| format!("execution profile local binding: {e}"))?;
        return Ok(profile);
    }
    let endpoint = record
        .manager_endpoint
        .as_deref()
        .ok_or("execution profile remote endpoint missing")?;
    let reply = hyperhub_runtime::attachment::exchange_raw_for_process(
        endpoint,
        &serde_json::json!({"query":"execution_profile","attachment_id":record.spec.id}),
        manager.pid,
    )
    .map_err(|e| format!("execution profile remote OS-peer RPC: {e}"))?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ProfileReply {
        attachment_id: String,
        profile: Option<super::ManagerExecutionProfile>,
        error: Option<String>,
    }
    let reply: ProfileReply = serde_json::from_value(reply)
        .map_err(|e| format!("execution profile reply decoding: {e}"))?;
    if let Some(error) = reply.error {
        return Err(format!("execution profile remote RAM lookup: {error}"));
    }
    if reply.attachment_id != record.spec.id {
        return Err("manager returned another attachment profile".into());
    }
    let profile = reply
        .profile
        .ok_or("manager omitted its RAM execution profile")?;
    profile
        .validate_record(record)
        .map_err(|e| format!("execution profile remote binding: {e}"))?;
    super::verify_process(manager)
        .map_err(|e| format!("execution profile reply manager identity: {e}"))?;
    Ok(profile)
}
/// Query the actual controller. A missing or failed query is not evidence that
/// policy is off. Self-resolution never calls the controller's busy listener.
pub fn manager_policy_admission_for_record(
    record: &super::Record,
) -> Result<super::ManagerPolicyAdmission, String> {
    let manager = record
        .manager
        .as_ref()
        .ok_or("attachment manager identity missing")?;
    super::verify_process(manager)?;
    let admission = if manager.pid == std::process::id() {
        super::manager_policy_admission(&record.spec.id)?
    } else {
        let endpoint = record
            .manager_endpoint
            .as_deref()
            .ok_or("manager endpoint missing")?;
        let value = serde_json::json!({"query":"policy_admission","attachment_id":record.spec.id});
        let reply =
            hyperhub_runtime::attachment::exchange_raw_for_process(endpoint, &value, manager.pid)
                .map_err(|e| e.to_string())?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct AdmissionReply {
            attachment_id: String,
            admission: Option<super::ManagerPolicyAdmission>,
            error: Option<String>,
        }
        let reply: AdmissionReply = serde_json::from_value(reply).map_err(|e| e.to_string())?;
        if let Some(error) = reply.error {
            return Err(error);
        }
        if reply.attachment_id != record.spec.id {
            return Err("manager admission scope mismatch".into());
        }
        reply.admission.ok_or("manager omitted policy admission")?
    };
    admission.profile.validate_record(record)?;
    super::verify_process(manager)?;
    Ok(admission)
}
fn manager_exchange_checked(
    endpoint: &str,
    authorization: &Authorization,
    pid: Option<u32>,
) -> Result<Outcome, String> {
    let value = serde_json::to_value(ManagerCommand {
        authorization: authorization.clone(),
    })
    .map_err(|e| e.to_string())?;
    let reply = match pid {
        Some(pid) => hyperhub_runtime::attachment::exchange_raw_for_process(endpoint, &value, pid),
        None => hyperhub_runtime::attachment::exchange_raw(endpoint, &value),
    }
    .map_err(|e| e.to_string())?;
    let reply: Reply = serde_json::from_value(reply).map_err(|e| e.to_string())?;
    match (reply.outcome, reply.error) {
        (Some(outcome), None) => Ok(outcome),
        (_, Some(error)) => Err(error),
        _ => Err("invalid attachment manager reply".into()),
    }
}
pub struct ManagerListener(hyperhub_runtime::attachment::Listener);
impl ManagerListener {
    pub fn bind(endpoint: &str) -> Result<Self, String> {
        hyperhub_runtime::attachment::Listener::bind(endpoint)
            .map(Self)
            .map_err(|e| e.to_string())
    }
    pub fn run(
        self,
        stop: &AtomicBool,
        callback: impl Fn(Authorization) -> Result<Outcome, String>,
    ) -> Result<(), String> {
        self.0
            .run_raw(stop, |value| {
                if value.get("query").and_then(serde_json::Value::as_str) == Some("policy_admission") {
                    let id = value.get("attachment_id").and_then(serde_json::Value::as_str).unwrap_or("");
                    return match super::manager_policy_admission(id) {
                        Ok(admission) => serde_json::json!({"attachment_id":id,"admission":admission,"error":null}),
                        Err(error) => serde_json::json!({"attachment_id":id,"admission":null,"error":error}),
                    };
                }
                if value.get("query").and_then(serde_json::Value::as_str)
                    == Some("execution_profile")
                {
                    let id = value
                        .get("attachment_id")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");
                    return match super::manager_execution_profile(id) {
                        Ok(profile) => {
                            serde_json::json!({"attachment_id":id,"profile":profile,"error":null})
                        }
                        Err(error) => {
                            serde_json::json!({"attachment_id":id,"profile":null,"error":error})
                        }
                    };
                }
                if value.get("query").and_then(serde_json::Value::as_str)
                    == Some("operation_claimant")
                {
                    let id = value
                        .get("attachment_id")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");
                    let result = super::manager_root_image(id)
                        .and_then(|_| super::manager_operation_claimant());
                    return match result {
                        Ok(claimant) => {
                            serde_json::json!({"attachment_id":id,"claimant":claimant,"error":null})
                        }
                        Err(error) => {
                            serde_json::json!({"attachment_id":id,"claimant":null,"error":error})
                        }
                    };
                }
                if value.get("query").and_then(serde_json::Value::as_str) == Some("root_image") {
                    let id = value
                        .get("attachment_id")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");
                    return match super::manager_root_image(id) {
                        Ok(state) => {
                            serde_json::json!({"attachment_id":id,"root_image":state,"error":null})
                        }
                        Err(error) => {
                            serde_json::json!({"attachment_id":id,"root_image":null,"error":error})
                        }
                    };
                }
                let result = serde_json::from_value::<ManagerCommand>(value)
                    .map_err(|_| "invalid attachment manager command".to_string())
                    .and_then(|command| callback(command.authorization));
                let reply = match result {
                    Ok(outcome) => Reply {
                        outcome: Some(outcome),
                        error: None,
                    },
                    Err(error) => Reply {
                        outcome: None,
                        error: Some(error),
                    },
                };
                serde_json::to_value(reply).unwrap_or_else(
                    |_| serde_json::json!({"outcome":null,"error":"cannot encode manager reply"}),
                )
            })
            .map_err(|e| e.to_string())
    }
}
