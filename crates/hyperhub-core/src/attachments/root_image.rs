//! Root executable epochs are trusted process memory, never record.json state.
use super::{ProcessIdentity, Spec};
use hyperhub_runtime::attachment as wire;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Scope {
    instance_id: String,
    attachment_id: String,
    session_id: String,
    host_binding: String,
    initial: wire::RootImageIdentity,
    current: wire::RootImageState,
    last: Option<wire::RootImagePayload>,
    profile: Option<super::ManagerExecutionProfile>,
}
pub(crate) fn verify_root_image_bootstrap(
    directory: &Path,
    bootstrap: &wire::Bootstrap,
) -> Result<(), String> {
    let shared = scopes(directory);
    let mut values = shared.lock().map_err(|_| "root image state unavailable")?;
    let scope = values
        .get_mut(&bootstrap.attachment_id)
        .ok_or("root image profile is unproven")?;
    if scope.instance_id != bootstrap.approval_instance_id
        || scope.session_id != bootstrap.session_id
        || scope.initial.pid != bootstrap.root_pid
        || bootstrap.approval_root_identity.as_ref() != Some(&scope.initial)
        || scope.host_binding != bootstrap.approval_binding().map_err(|e| e.to_string())?
    {
        return Err("Bootstrap differs from trusted RootImage binding".into());
    }
    let origin = match bootstrap.native_dns_mode {
        wire::NativeDnsMode::PreserveAnswers => super::Origin::Attach,
        wire::NativeDnsMode::SyntheticPool => super::Origin::Run,
    };
    let profile = super::ManagerExecutionProfile::from_bootstrap(bootstrap, origin)?;
    if scope.profile.as_ref().is_some_and(|old| old != &profile) {
        return Err("trusted execution profile changed".into());
    }
    scope.profile = Some(profile);
    Ok(())
}
pub(crate) fn root_image_profile(
    directory: &Path,
    id: &str,
) -> Result<super::ManagerExecutionProfile, String> {
    scopes(directory)
        .lock()
        .map_err(|_| "root image state unavailable")?
        .get(id)
        .and_then(|scope| scope.profile.clone())
        .ok_or_else(|| "trusted execution profile is unproven".into())
}
fn scopes(directory: &Path) -> Arc<Mutex<HashMap<String, Scope>>> {
    static STATES: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<HashMap<String, Scope>>>>>> =
        OnceLock::new();
    STATES
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .entry(
            directory
                .canonicalize()
                .unwrap_or_else(|_| directory.to_path_buf()),
        )
        .or_default()
        .clone()
}
pub(crate) fn initialize_root_image(
    directory: &Path,
    spec: &Spec,
    session: &str,
    instance: &str,
    binding: &str,
) -> Result<(), String> {
    let shared = scopes(directory);
    let mut values = shared.lock().map_err(|_| "root image state unavailable")?;
    if let Some(old) = values.get(&spec.id) {
        if old.initial != spec.target.root_image_identity()
            || old.session_id != session
            || old.host_binding != binding
        {
            return Err("root image scope cannot be rebound".into());
        }
        return Ok(());
    }
    if spec.exec_epoch != 0 || spec.current_target.is_some() {
        return Err("root image epoch has no trusted retained source".into());
    }
    let initial = spec.target.root_image_identity();
    values.insert(
        spec.id.clone(),
        Scope {
            instance_id: instance.into(),
            attachment_id: spec.id.clone(),
            session_id: session.into(),
            host_binding: binding.into(),
            current: wire::RootImageState {
                identity: initial.clone(),
                exec_epoch: 0,
                observed_at_ms: 0,
                head: [0; 32],
            },
            initial,
            last: None,
            profile: None,
        },
    );
    Ok(())
}
pub(crate) fn root_image_state(directory: &Path, id: &str) -> Result<wire::RootImageState, String> {
    scopes(directory).lock().map_err(|_|"root image state unavailable")?.get(id).map(|scope|scope.current.clone()).ok_or_else(||"root image epoch is unproven; an authenticated live Host or controlled Core handoff is required".into())
}
pub(crate) fn under_root_image_scope<T>(
    directory: &Path,
    action: &super::Action,
    call: impl FnOnce(&wire::RootImageState) -> Result<T, String>,
) -> Result<T, String> {
    let shared = scopes(directory);
    let values = shared.lock().map_err(|_| "root image state unavailable")?;
    let state = &values
        .get(action.attachment_id())
        .ok_or("root image epoch is unproven")?
        .current;
    if state.exec_epoch != action.exec_epoch()
        || state.identity != action.target().root_image_identity()
    {
        return Err("approval predates the current root executable epoch".into());
    }
    call(state)
}
pub(crate) fn verify_root_image_scope(
    directory: &Path,
    action: &super::Action,
) -> Result<wire::RootImageState, String> {
    let state = root_image_state(directory, action.attachment_id())?;
    if state.exec_epoch != action.exec_epoch()
        || state.identity != action.target().root_image_identity()
    {
        return Err("approval predates the current root executable epoch".into());
    }
    Ok(state)
}
pub(crate) fn restore_root_image(
    directory: &Path,
    bootstrap: &wire::Bootstrap,
    sources: &[wire::RootImageState],
) -> Result<(), String> {
    let initial = bootstrap
        .approval_root_identity
        .clone()
        .ok_or("Bootstrap has no initial root image binding")?;
    let first = sources
        .first()
        .ok_or("no authenticated retained root image source")?;
    if !initial.same_incarnation(&first.identity)
        || sources.iter().any(|state| state != first)
        || (first.exec_epoch == 0
            && (first.identity != initial || first.head != [0; 32] || first.observed_at_ms != 0))
        || (first.exec_epoch > 0 && first.head == [0; 32])
    {
        return Err("authenticated root image sources disagree or lack a valid epoch".into());
    }
    let shared = scopes(directory);
    let mut values = shared.lock().map_err(|_| "root image state unavailable")?;
    if let Some(old) = values.get(&bootstrap.attachment_id) {
        if old.initial != initial
            || old.session_id != bootstrap.session_id
            || old.host_binding != bootstrap.approval_binding().map_err(|e| e.to_string())?
            || old.current != *first
        {
            return Err("retained root image would replace a different trusted live epoch".into());
        }
        return Ok(());
    }
    values.insert(
        bootstrap.attachment_id.clone(),
        Scope {
            instance_id: bootstrap.approval_instance_id.clone(),
            attachment_id: bootstrap.attachment_id.clone(),
            session_id: bootstrap.session_id.clone(),
            host_binding: bootstrap.approval_binding().map_err(|e| e.to_string())?,
            initial,
            current: first.clone(),
            last: None,
            profile: None,
        },
    );
    Ok(())
}
pub(crate) fn observe_root_exec(
    directory: &Path,
    id: &str,
    previous: &ProcessIdentity,
    current: &ProcessIdentity,
    nonce: [u8; 32],
) -> Result<(wire::RootImageState, wire::SignedRootImage), String> {
    observe_root_exec_at(
        directory,
        id,
        previous,
        current,
        nonce,
        crate::session::unix_timestamp_ms(),
    )
}
fn observe_root_exec_at(
    directory: &Path,
    id: &str,
    previous: &ProcessIdentity,
    current: &ProcessIdentity,
    nonce: [u8; 32],
    now: u64,
) -> Result<(wire::RootImageState, wire::SignedRootImage), String> {
    let shared = scopes(directory);
    let mut values = shared.lock().map_err(|_| "root image state unavailable")?;
    let scope = values
        .get_mut(id)
        .ok_or("root exec has no trusted initial image epoch")?;
    if let Some(last) = &scope.last {
        if last.transition_nonce == nonce {
            if last.previous.identity != previous.root_image_identity()
                || last.current.identity != current.root_image_identity()
            {
                return Err("exec retry nonce has different image identities".into());
            }
            return Ok((
                scope.current.clone(),
                super::sign_root_image_payload(directory, last)?,
            ));
        }
    }
    if scope.current.identity != previous.root_image_identity()
        || !previous.same_incarnation(current)
        || !scope
            .initial
            .same_incarnation(&current.root_image_identity())
    {
        return Err("root exec does not extend the current trusted image".into());
    }
    let epoch = scope
        .current
        .exec_epoch
        .checked_add(1)
        .ok_or("root exec epoch exhausted")?;
    let observed = now.max(scope.current.observed_at_ms);
    let next = wire::RootImageState {
        identity: current.root_image_identity(),
        exec_epoch: epoch,
        observed_at_ms: observed,
        head: wire::root_image_head(
            &scope.current,
            &current.root_image_identity(),
            epoch,
            observed,
            &nonce,
        )
        .map_err(|e| e.to_string())?,
    };
    let payload = wire::RootImagePayload {
        schema_version: 1,
        instance_id: scope.instance_id.clone(),
        attachment_id: scope.attachment_id.clone(),
        session_id: scope.session_id.clone(),
        host_binding: scope.host_binding.clone(),
        initial_identity: scope.initial.clone(),
        previous: scope.current.clone(),
        current: next.clone(),
        transition_nonce: nonce,
        challenge: None,
        host_pid: None,
        host_birth: None,
    };
    let signed = super::sign_root_image_payload(directory, &payload)?;
    scope.current = next.clone();
    scope.last = Some(payload);
    Ok((next, signed))
}
pub(crate) fn challenged_root_image(
    directory: &Path,
    bootstrap: &wire::Bootstrap,
    host: &ProcessIdentity,
    challenge: [u8; 32],
) -> Result<wire::SignedRootImage, String> {
    let shared = scopes(directory);
    let values = shared.lock().map_err(|_| "root image state unavailable")?;
    let scope = values
        .get(&bootstrap.attachment_id)
        .ok_or("current root image epoch is unproven")?;
    if scope.session_id != bootstrap.session_id
        || scope.host_binding != bootstrap.approval_binding().map_err(|e| e.to_string())?
        || bootstrap.approval_root_identity.as_ref() != Some(&scope.initial)
    {
        return Err("root image challenge has a different immutable scope".into());
    }
    super::sign_root_image_payload(
        directory,
        &wire::RootImagePayload {
            schema_version: 1,
            instance_id: scope.instance_id.clone(),
            attachment_id: scope.attachment_id.clone(),
            session_id: scope.session_id.clone(),
            host_binding: scope.host_binding.clone(),
            initial_identity: scope.initial.clone(),
            previous: scope.current.clone(),
            current: scope.current.clone(),
            transition_nonce: [0; 32],
            challenge: Some(challenge),
            host_pid: Some(host.pid),
            host_birth: Some(host.birth),
        },
    )
}

fn manager_images() -> &'static Mutex<HashMap<String, wire::RootImageState>> {
    static IMAGES: OnceLock<Mutex<HashMap<String, wire::RootImageState>>> = OnceLock::new();
    IMAGES.get_or_init(Default::default)
}
/// Read-only state retained by the actual controller, not a persisted verifier.
pub fn manager_root_image(id: &str) -> Result<wire::RootImageState, String> {
    manager_images()
        .lock()
        .map_err(|_| "manager image memory unavailable")?
        .get(id)
        .cloned()
        .ok_or_else(|| "manager has no authenticated root image epoch".into())
}
pub(crate) fn remember_manager_root_image(
    id: &str,
    value: wire::RootImageState,
) -> Result<(), String> {
    let mut images = manager_images()
        .lock()
        .map_err(|_| "manager image memory unavailable")?;
    if images.get(id).is_some_and(|old| {
        value.exec_epoch < old.exec_epoch || (value.exec_epoch == old.exec_epoch && value != *old)
    }) {
        return Err("manager image update would roll back or replace an accepted epoch".into());
    }
    images.insert(id.into(), value);
    Ok(())
}
pub(crate) fn adopt_manager_root_image(
    directory: &Path,
    record: &super::Record,
    instance: &str,
    current: wire::RootImageState,
    profile: &super::ManagerExecutionProfile,
) -> Result<(), String> {
    profile.validate_record(record)?;
    let initial = record.spec.target.root_image_identity();
    if !initial.same_incarnation(&current.identity)
        || (current.exec_epoch == 0
            && (current.identity != initial
                || current.head != [0; 32]
                || current.observed_at_ms != 0))
        || (current.exec_epoch > 0 && current.head == [0; 32])
    {
        return Err("actual manager retained an invalid root image epoch".into());
    }
    if super::process_birth(current.identity.pid) == Some(current.identity.birth)
        && super::inspect_process(current.identity.pid)?.executable_sha256
            != current.identity.executable_sha256
    {
        return Err("manager root image epoch is older than actual executable".into());
    }
    let shared = scopes(directory);
    let mut values = shared.lock().map_err(|_| "root image state unavailable")?;
    if let Some(scope) = values.get(&record.spec.id) {
        if scope.current != current {
            return Err("manager image does not match trusted Core epoch".into());
        }
        return Ok(());
    }
    values.insert(
        record.spec.id.clone(),
        Scope {
            instance_id: instance.into(),
            attachment_id: record.spec.id.clone(),
            session_id: record.session_id.clone(),
            host_binding: record
                .host_binding
                .clone()
                .ok_or("attachment has no original Host binding")?,
            initial,
            current,
            last: None,
            profile: Some(profile.clone()),
        },
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (PathBuf, Spec) {
        let directory =
            std::env::temp_dir().join(format!("hh-root-image-{}", super::super::new_id()));
        super::super::private_directory(&directory).unwrap();
        (
            directory,
            Spec {
                id: super::super::new_id(),
                recovery: None,
                capabilities: Default::default(),
                target: ProcessIdentity {
                    pid: 42,
                    birth: 9,
                    owner: "fixture".into(),
                    executable: "fixture".into(),
                    executable_sha256: "ab".repeat(32),
                },
                current_target: None,
                exec_epoch: 0,
                scope: super::super::Scope::Tree,
                backend: super::super::Backend::Gum,
                policy_digest: "cd".repeat(32),
            },
        )
    }
    #[test]
    fn same_image_execs_advance_epoch_and_head_once_even_with_backward_clock() {
        let (directory, spec) = fixture();
        initialize_root_image(&directory, &spec, "session", "instance", "binding").unwrap();
        let first = observe_root_exec_at(
            &directory,
            &spec.id,
            &spec.target,
            &spec.target,
            [1; 32],
            100,
        )
        .unwrap();
        assert_eq!(first.0.exec_epoch, 1);
        let second = observe_root_exec_at(
            &directory,
            &spec.id,
            &spec.target,
            &spec.target,
            [2; 32],
            50,
        )
        .unwrap();
        assert_eq!(second.0.exec_epoch, 2);
        assert_eq!(second.0.observed_at_ms, 100);
        assert_ne!(first.0.head, second.0.head);
        let retry =
            observe_root_exec_at(&directory, &spec.id, &spec.target, &spec.target, [2; 32], 1)
                .unwrap();
        assert_eq!(retry, second);
        let mut changed = spec.target.clone();
        changed.executable_sha256 = "ef".repeat(32);
        let third =
            observe_root_exec_at(&directory, &spec.id, &spec.target, &changed, [3; 32], 100)
                .unwrap();
        assert_eq!(third.0.exec_epoch, 3);
        assert_eq!(third.0.identity, changed.root_image_identity());
        assert!(observe_root_exec_at(
            &directory,
            &spec.id,
            &spec.target,
            &spec.target,
            [4; 32],
            100
        )
        .is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn public_record_epochs_do_not_replace_or_initialize_trusted_memory() {
        let (directory, spec) = fixture();
        let record = super::super::create_record(&directory, spec.clone()).unwrap();
        initialize_root_image(&directory, &spec, &record.session_id, "instance", "binding")
            .unwrap();
        observe_root_exec_at(
            &directory,
            &spec.id,
            &spec.target,
            &spec.target,
            [1; 32],
            10,
        )
        .unwrap();
        let mut edited = record.clone();
        edited.exec_epoch = 999;
        crate::config_store::save_durable_private_bytes(
            &directory.join(&spec.id).join("record.json"),
            &serde_json::to_vec(&edited).unwrap(),
        )
        .unwrap();
        assert_eq!(
            root_image_state(&directory, &spec.id).unwrap().exec_epoch,
            1
        );
        let other = directory.join("cold");
        super::super::private_directory(&other).unwrap();
        super::super::create_record(&other, spec.clone()).unwrap();
        assert!(root_image_state(&other, &spec.id).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn retained_root_scope_rejects_stale_execs_without_requiring_kernel_root_liveness() {
        let (directory, mut spec) = fixture();
        initialize_root_image(&directory, &spec, "session", "instance", "binding").unwrap();
        let old = super::super::Action::Detach {
            exec_epoch: 0,
            attachment_id: spec.id.clone(),
            target: spec.target.clone(),
            policy_digest: spec.policy_digest.clone(),
            recovery: None,
        };
        assert!(verify_root_image_scope(&directory, &old).is_ok());
        observe_root_exec_at(
            &directory,
            &spec.id,
            &spec.target,
            &spec.target,
            [1; 32],
            10,
        )
        .unwrap();
        assert!(verify_root_image_scope(&directory, &old).is_err());
        spec.exec_epoch = 1;
        let fresh = super::super::Action::Attach { spec: spec.clone() };
        assert!(verify_root_image_scope(&directory, &fresh).is_ok());
        observe_root_exec_at(&directory, &spec.id, &spec.target, &spec.target, [2; 32], 9).unwrap();
        assert!(verify_root_image_scope(&directory, &fresh).is_err());
        let detach = super::super::Action::Detach {
            exec_epoch: 2,
            attachment_id: spec.id,
            target: spec.target,
            policy_digest: spec.policy_digest,
            recovery: None,
        };
        assert!(verify_root_image_scope(&directory, &detach).is_ok());
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn acceptance_and_exec_epoch_commit_have_one_order() {
        use std::sync::mpsc;
        let (directory, spec) = fixture();
        initialize_root_image(&directory, &spec, "session", "instance", "binding").unwrap();
        let action = super::super::Action::Attach { spec: spec.clone() };
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let accepting_directory = directory.clone();
        let accepting = std::thread::spawn(move || {
            under_root_image_scope(&accepting_directory, &action, |state| {
                entered_tx.send(()).map_err(|e| e.to_string())?;
                release_rx
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .map_err(|e| e.to_string())?;
                Ok(state.exec_epoch)
            })
        });
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let (attempt_tx, attempt_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let observing_directory = directory.clone();
        let observing = std::thread::spawn(move || {
            let shared = scopes(&observing_directory);
            let blocked = matches!(shared.try_lock(), Err(std::sync::TryLockError::WouldBlock));
            attempt_tx.send(blocked).unwrap();
            done_tx
                .send(observe_root_exec_at(
                    &observing_directory,
                    &spec.id,
                    &spec.target,
                    &spec.target,
                    [1; 32],
                    10,
                ))
                .unwrap();
        });
        let blocked = attempt_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        release_tx.send(()).unwrap();
        let accepted = accepting.join().unwrap().unwrap();
        let observed = done_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap()
            .unwrap();
        observing.join().unwrap();
        assert!(
            blocked,
            "exec changed the epoch before the prior acceptance committed"
        );
        assert_eq!(accepted, 0);
        assert_eq!(observed.0.exec_epoch, 1);
        std::fs::remove_dir_all(directory).unwrap();
    }
}

// Called only while the owning Core has closed and drained control admission.
pub(super) fn export_successor(directory: &Path) -> Result<Vec<u8>, String> {
    let shared = scopes(directory);
    let values = shared.lock().map_err(|_| "root image state unavailable")?;
    crate::successor::bounded_json::to_vec(&*values, crate::successor::MAX_STATE)
}
pub(super) fn import_successor(directory: &Path, bytes: &[u8]) -> Result<(), String> {
    let incoming: HashMap<String, Scope> =
        serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    for (id, scope) in &incoming {
        if id != &scope.attachment_id
            || !super::valid_id(id)
            || scope.instance_id.is_empty()
            || !scope.initial.same_incarnation(&scope.current.identity)
            || (scope.current.exec_epoch == 0 && scope.current.identity != scope.initial)
        {
            return Err("invalid successor root image scope".into());
        }
    }
    let shared = scopes(directory);
    let mut values = shared.lock().map_err(|_| "root image state unavailable")?;
    if !values.is_empty() {
        return Err("successor root image memory is already initialized".into());
    }
    *values = incoming;
    Ok(())
}
