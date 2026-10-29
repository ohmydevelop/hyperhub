//! Reversible lifecycle for an injected live target. Credentials never enter
//! process environment variables or diagnostic/status values.
use crate::{HH_ERR_INVALID, HH_ERR_NOT_INITIALIZED, HH_ERR_PROTOCOL};
use hyperhub_runtime::attachment::{
    AuthenticatedCommand, Bootstrap, HostCommand, HostPhase, HostStatus, Listener, PROTOCOL,
};
use std::sync::{
    atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering},
    Mutex,
};
#[path = "attachment_host_command.rs"]
mod host_command;
#[path = "attachment_startup.rs"]
pub(crate) mod startup;
pub(crate) use host_command::{advance_state_epoch, state_gate, with_state_mutation};

static BOOTSTRAP: AtomicPtr<Mutex<Option<Bootstrap>>> = AtomicPtr::new(std::ptr::null_mut());
static SNAPSHOT: AtomicPtr<Bootstrap> = AtomicPtr::new(std::ptr::null_mut());
static OWNER_PID: AtomicU32 = AtomicU32::new(0);
static ROOT_PID: AtomicU32 = AtomicU32::new(0);
static SCOPE_TREE: AtomicBool = AtomicBool::new(false);
static EXTERNAL_ATTACHMENT: AtomicBool = AtomicBool::new(false);
pub(crate) fn externally_attached() -> bool {
    EXTERNAL_ATTACHMENT.load(Ordering::Acquire)
}
fn bootstrap_slot() -> &'static Mutex<Option<Bootstrap>> {
    let mut pointer = BOOTSTRAP.load(Ordering::Acquire);
    if pointer.is_null() {
        let fresh = Box::into_raw(Box::new(Mutex::new(None)));
        match BOOTSTRAP.compare_exchange(
            std::ptr::null_mut(),
            fresh,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => pointer = fresh,
            Err(existing) => {
                unsafe {
                    drop(Box::from_raw(fresh));
                }
                pointer = existing;
            }
        }
    }
    // Published state remains pinned; a fork child abandons the copied mutex.
    unsafe { &*pointer }
}
/// Compatibility launcher diagnostics never consume an attached app's env.
pub(crate) fn legacy_debug() -> bool {
    !managed() && std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some()
}
pub(crate) fn is_explicit() -> bool {
    managed()
}
pub(crate) fn local_owner() -> bool {
    OWNER_PID.load(Ordering::Acquire) == std::process::id()
}
pub(crate) fn after_fork_unmanaged_child() {
    after_fork_child();
    PHASE.store(4, Ordering::Release);
    SCOPE_TREE.store(false, Ordering::Release);
}
pub(crate) fn bootstrap() -> Option<Bootstrap> {
    let pointer = SNAPSHOT.load(Ordering::Acquire);
    if pointer.is_null() {
        None
    } else {
        Some(unsafe { &*pointer }.clone())
    }
}
pub(crate) fn native_dns_mode() -> hyperhub_runtime::attachment::NativeDnsMode {
    let pointer = SNAPSHOT.load(Ordering::Acquire);
    if pointer.is_null() {
        hyperhub_runtime::attachment::NativeDnsMode::SyntheticPool
    } else {
        unsafe { &*pointer }.native_dns_mode
    }
}
/// Called only in the atfork child. No allocation, locks, IO or destructors.
pub(crate) fn after_fork_child() {
    crate::runtime::after_fork_child();
    host_command::after_fork_child();
    startup::after_fork_child();
    NATIVE_READY.store(false, Ordering::Release);
    crate::alias_namespace::reset_after_fork();
    crate::root_image::clear_challenge();
    BOOTSTRAP.store(std::ptr::null_mut(), Ordering::Release);
    HISTORY.store(std::ptr::null_mut(), Ordering::Release);
    ENROLLMENT.store(std::ptr::null_mut(), Ordering::Release);
    if !SNAPSHOT.load(Ordering::Acquire).is_null() {
        PHASE.store(1, Ordering::Release);
    }
    // The accepted cutoff is a lock-free inherited value. Abandoning copied
    // mutexes must not reopen older approvals in a new child history.
    LIFE_EPOCH.fetch_add(1, Ordering::AcqRel);
    CALLS.store(0, Ordering::Release);
    SPAWNS.store(0, Ordering::Release);
    BACKGROUND.store(0, Ordering::Release);
    CONTROL_BACKGROUND.store(0, Ordering::Release);
    ALIAS_PUBLICATIONS.store(0, Ordering::Release);
    ALIAS_ADMISSION_PAUSED.store(false, Ordering::SeqCst);
    SERVER_STARTED.store(false, Ordering::Release);
    STOP_SERVER.store(false, Ordering::Release);
    STOP_BACKGROUND.store(false, Ordering::Release);
}
static APPROVAL_ROOT: AtomicPtr<[u8; 32]> = AtomicPtr::new(std::ptr::null_mut());
static APPROVAL_GENERATION: AtomicU64 = AtomicU64::new(0);
static ENROLLMENT: AtomicPtr<
    Mutex<Option<hyperhub_runtime::attachment::ApprovalEnrollmentChallenge>>,
> = AtomicPtr::new(std::ptr::null_mut());
pub(crate) fn approval_public_key() -> Option<[u8; 32]> {
    let pointer = APPROVAL_ROOT.load(Ordering::Acquire);
    if pointer.is_null() {
        None
    } else {
        Some(unsafe { *pointer })
    }
}
fn pin_approval_key(key: [u8; 32]) -> Result<(), String> {
    let fresh = Box::into_raw(Box::new(key));
    match APPROVAL_ROOT.compare_exchange(
        std::ptr::null_mut(),
        fresh,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => Ok(()),
        Err(old) => {
            unsafe {
                drop(Box::from_raw(fresh));
            }
            if unsafe { *old } == key {
                Ok(())
            } else {
                Err("approval root is already pinned".into())
            }
        }
    }
}
fn enrollment_slot(
) -> &'static Mutex<Option<hyperhub_runtime::attachment::ApprovalEnrollmentChallenge>> {
    let mut pointer = ENROLLMENT.load(Ordering::Acquire);
    if pointer.is_null() {
        let fresh = Box::into_raw(Box::new(Mutex::new(None)));
        match ENROLLMENT.compare_exchange(
            std::ptr::null_mut(),
            fresh,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => pointer = fresh,
            Err(old) => {
                unsafe {
                    drop(Box::from_raw(fresh));
                }
                pointer = old;
            }
        }
    }
    unsafe { &*pointer }
}
fn enrollment_challenge() -> Result<(), String> {
    let mut slot = enrollment_slot()
        .lock()
        .map_err(|_| "enrollment challenge state unavailable")?;
    let now = now_ms();
    if slot.as_ref().is_some_and(|value| value.expires_at_ms > now) {
        return Ok(());
    }
    use rand::TryRng;
    let mut challenge = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut challenge)
        .map_err(|_| "cannot create approval enrollment challenge")?;
    let identity = hyperhub_runtime::attachment::process_incarnation(std::process::id())
        .map_err(|e| e.to_string())?;
    *slot = Some(hyperhub_runtime::attachment::ApprovalEnrollmentChallenge {
        challenge,
        host_pid: identity.pid,
        host_birth: identity.birth,
        expires_at_ms: now.saturating_add(60_000),
    });
    Ok(())
}
static DETACH_CUTOFF_MS: AtomicU64 = AtomicU64::new(0);
pub(crate) fn approval_not_before_ms() -> u64 {
    DETACH_CUTOFF_MS.load(Ordering::Acquire)
}
static PHASE: AtomicU8 = AtomicU8::new(0);
static NATIVE_READY: AtomicBool = AtomicBool::new(false);
pub(crate) fn status_phase() -> HostPhase {
    match PHASE.load(Ordering::Acquire) {
        1 => HostPhase::Preparing,
        2 => HostPhase::Active,
        3 => HostPhase::Detaching,
        4 => HostPhase::DetachedResident,
        5 => HostPhase::Detached,
        _ => HostPhase::Preparing,
    }
}
pub(crate) fn native_ready() -> bool {
    #[cfg(all(windows, feature = "gum-agent"))]
    if crate::windows_gum::external_posix_runtime_unsupported() {
        return false;
    }
    NATIVE_READY.load(Ordering::Acquire)
}
pub(crate) fn clear_native_ready() {
    if !local_owner() {
        NATIVE_READY.store(false, Ordering::Release);
        return;
    }
    let _ = with_state_mutation(|| {
        NATIVE_READY.store(false, Ordering::Release);
        Ok(())
    });
}
pub(crate) fn mark_native_ready() -> Result<(), i32> {
    if !managed() || !local_owner() {
        return Err(HH_ERR_PROTOCOL);
    }
    with_state_mutation(|| {
        startup::check().map_err(|_| "attachment initialization was cancelled")?;
        NATIVE_READY.store(true, Ordering::Release);
        Ok(())
    })
    .map_err(|_| HH_ERR_PROTOCOL)
}
static LIFE_EPOCH: AtomicU64 = AtomicU64::new(1);
static SPAWNS: AtomicU64 = AtomicU64::new(0);
static CALLS: AtomicU64 = AtomicU64::new(0);
static BACKGROUND: AtomicUsize = AtomicUsize::new(0);
static CONTROL_BACKGROUND: AtomicUsize = AtomicUsize::new(0);
static ALIAS_PUBLICATIONS: AtomicU64 = AtomicU64::new(0);
static ALIAS_ADMISSION_PAUSED: AtomicBool = AtomicBool::new(false);
static STOP_BACKGROUND: AtomicBool = AtomicBool::new(false);
static STOP_SERVER: AtomicBool = AtomicBool::new(false);
static SERVER_STARTED: AtomicBool = AtomicBool::new(false);
static CALLBACKS_RETIRED: AtomicBool = AtomicBool::new(false);
static STATE_RETIRED: AtomicBool = AtomicBool::new(false);
static RETIRE_ERROR: Mutex<Option<String>> = Mutex::new(None);
static HISTORY: AtomicPtr<Mutex<History>> = AtomicPtr::new(std::ptr::null_mut());
#[derive(Default)]
struct History {
    seen: std::collections::BTreeMap<[u8; 32], u64>,
    last: Option<Accepted>,
    last_detach_at: u64,
}
struct Accepted {
    claims: hyperhub_runtime::attachment::ApprovalClaims,
    proof: hyperhub_runtime::attachment::ApprovalProof,
    action: hyperhub_runtime::attachment::ApprovedAction,
    nonce: [u8; 32],
    approved_at_ms: u64,
    committed: bool,
}
fn history() -> &'static Mutex<History> {
    let mut pointer = HISTORY.load(Ordering::Acquire);
    if pointer.is_null() {
        let fresh = Box::into_raw(Box::new(Mutex::new(History::default())));
        match HISTORY.compare_exchange(
            std::ptr::null_mut(),
            fresh,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => pointer = fresh,
            Err(old) => {
                unsafe {
                    drop(Box::from_raw(fresh));
                }
                pointer = old;
            }
        }
    }
    unsafe { &*pointer }
}
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}
fn attachment_epoch_allows(
    _action: hyperhub_runtime::attachment::ApprovedAction,
    approved: u64,
    detached: u64,
) -> bool {
    approved > detached
}

fn authorize_mutation(request: &AuthenticatedCommand) -> Result<bool, String> {
    use hyperhub_runtime::attachment::ApprovedAction;
    if matches!(
        request.command,
        HostCommand::Status
            | HostCommand::EnrollmentChallenge
            | HostCommand::EnrollApprovalRoot
            | HostCommand::SnapshotAliases
            | HostCommand::ApplySessionAliases
            | HostCommand::ApplyRootImage
    ) {
        return Ok(false);
    }
    let boot = bootstrap().ok_or("attachment is not initialized")?;
    if request.command == HostCommand::Activate
        && request.proof.is_none()
        && boot.initially_owned
        && PHASE.load(Ordering::Acquire) == 2
    {
        // A status-equivalent duplicate from the owning launcher; this cannot
        // reactivate a detached target or perform a state transition.
        return Ok(true);
    }
    let proof = request
        .proof
        .as_ref()
        .ok_or("human approval proof is required for Host mutation")?;
    let mut history = history()
        .lock()
        .map_err(|_| "approval history unavailable")?;
    if let Some(last) = history.last.as_ref() {
        if last.action == ApprovedAction::Detach
            && last.claims.action == ApprovedAction::Attach
            && !initial_attach_rollback()
        {
            return Err(
                "initial Attach rollback requires a fresh never-active initialization".into(),
            );
        }
        if last.action == ApprovedAction::Detach
            && !last.committed
            && last.proof == *proof
            && request.command == HostCommand::CancelDetachmentPreparation
            && PHASE.load(Ordering::Acquire) == 2
        {
            return Ok(false);
        }
        if last.action == ApprovedAction::Detach
            && last.committed
            && last.proof == *proof
            && matches!(request.command, HostCommand::Detach | HostCommand::Retire)
            && matches!(PHASE.load(Ordering::Acquire), 3 | 4)
        {
            // This only completes the already accepted detach epoch, even if
            // its ten-minute execution window or verifier generation changed.
            return Ok(false);
        }
    }
    let now = now_ms();
    let claims = hyperhub_runtime::attachment::verify_proof_with_key(
        &boot,
        &approval_public_key().ok_or("approval root is not enrolled")?,
        proof,
        now,
    )
    .map_err(|e| e.to_string())?;
    let expected = match request.command {
        HostCommand::Activate => ApprovedAction::Attach,
        HostCommand::Detach
            if claims.action == ApprovedAction::Attach && PHASE.load(Ordering::Acquire) == 1 =>
        {
            ApprovedAction::Detach
        }
        HostCommand::Detach
        | HostCommand::Retire
        | HostCommand::PrepareDetachment
        | HostCommand::CancelDetachmentPreparation => ApprovedAction::Detach,
        HostCommand::Status
        | HostCommand::EnrollmentChallenge
        | HostCommand::EnrollApprovalRoot
        | HostCommand::SnapshotAliases
        | HostCommand::ApplySessionAliases
        | HostCommand::ApplyRootImage => unreachable!(),
    };
    let rollback = claims.action == ApprovedAction::Attach
        && request.command == HostCommand::Detach
        && PHASE.load(Ordering::Acquire) == 1
        && initial_attach_rollback();
    let preparation_detach = preparation_cleanup()
        && claims.action == ApprovedAction::Detach
        && matches!(
            request.command,
            HostCommand::Detach
                | HostCommand::Retire
                | HostCommand::PrepareDetachment
                | HostCommand::CancelDetachmentPreparation
        )
        && crate::root_image::current().is_none();
    if !rollback && !preparation_detach {
        crate::root_image::verify_operation(&claims)?;
    }
    if claims.action != expected && !rollback {
        return Err("approval action does not authorize this Host mutation".into());
    }
    if !attachment_epoch_allows(
        claims.action,
        claims.approved_at_ms,
        history.last_detach_at.max(approval_not_before_ms()),
    ) {
        return Err("approval predates the current detach epoch".into());
    }
    history.seen.retain(|_, expires| *expires >= now);
    if history.seen.contains_key(&claims.nonce) {
        if let Some(last) = history.last.as_ref() {
            if last.nonce == claims.nonce && last.proof == *proof {
                if last.action == ApprovedAction::Detach
                    && !last.committed
                    && (PHASE.load(Ordering::Acquire) == 2
                        || (PHASE.load(Ordering::Acquire) == 1 && preparation_cleanup()))
                    && matches!(
                        request.command,
                        HostCommand::PrepareDetachment
                            | HostCommand::Detach
                            | HostCommand::CancelDetachmentPreparation
                    )
                {
                    return Ok(false);
                }
                if last.action == ApprovedAction::Attach && request.command == HostCommand::Activate
                {
                    return if PHASE.load(Ordering::Acquire) == 2 {
                        Ok(true)
                    } else if !last.committed && matches!(PHASE.load(Ordering::Acquire), 1 | 4) {
                        Ok(false)
                    } else {
                        Err("approval belongs to an older attachment epoch".into())
                    };
                }
                if rollback && !last.committed {
                    history.last = Some(Accepted {
                        claims: claims.clone(),
                        proof: proof.clone(),
                        action: ApprovedAction::Detach,
                        nonce: claims.nonce,
                        approved_at_ms: claims.approved_at_ms,
                        committed: false,
                    });
                    return Ok(false);
                }
            }
        }
        return Err("attachment approval nonce was already consumed".into());
    }
    if request.command == HostCommand::Retire {
        return Err("retire requires the current accepted detach epoch".into());
    }
    if history.seen.len() >= 4096 {
        return Err("attachment approval history capacity reached".into());
    }
    history.seen.insert(claims.nonce, claims.expires_at_ms);
    history.last = Some(Accepted {
        claims: claims.clone(),
        proof: proof.clone(),
        action: if rollback {
            ApprovedAction::Detach
        } else {
            claims.action
        },
        nonce: claims.nonce,
        approved_at_ms: claims.approved_at_ms,
        committed: false,
    });
    Ok(false)
}
fn commit_operation() {
    if let Ok(mut history) = history().lock() {
        let detach = if let Some(last) = history.last.as_mut() {
            last.committed = true;
            if last.action == hyperhub_runtime::attachment::ApprovedAction::Detach {
                Some(last.approved_at_ms)
            } else {
                None
            }
        } else {
            None
        };
        if let Some(approved) = detach {
            history.last_detach_at = history.last_detach_at.max(approved);
            DETACH_CUTOFF_MS.fetch_max(approved, Ordering::AcqRel);
        }
    }
}

#[cfg(all(windows, feature = "gum-agent"))]
pub(crate) fn server_running() -> bool {
    SERVER_STARTED.load(Ordering::Acquire)
}
pub(crate) fn unload_ready() -> bool {
    STATE_RETIRED.load(Ordering::Acquire)
}
pub(crate) fn active_calls() -> u64 {
    CALLS
        .load(Ordering::Acquire)
        .saturating_add(startup::running() as u64)
}

pub(crate) fn managed() -> bool {
    PHASE.load(Ordering::Acquire) != 0
}
/// Original Attach authority can undo only its own fresh, never-Active base.
/// A future managed fork has inherited policy admission and needs new Detach
/// authority even though its new SDK has not yet become locally Active.
pub(super) fn initial_attach_rollback() -> bool {
    startup::origin() == hyperhub_runtime::attachment::InitializationOrigin::Fresh
        && !host_command::ever_active()
        && local_owner()
        && bootstrap().is_some_and(|boot| !boot.initially_owned)
}
pub(super) fn preparation_cleanup() -> bool {
    startup::tracked()
        && !host_command::ever_active()
        && local_owner()
        && matches!(PHASE.load(Ordering::Acquire), 1 | 3 | 4)
}
pub(crate) fn logically_detached() -> bool {
    matches!(PHASE.load(Ordering::Acquire), 3 | 4 | 5)
}
pub(crate) fn enforcing() -> bool {
    matches!(PHASE.load(Ordering::Acquire), 0 | 2)
}
pub(crate) fn propagating() -> bool {
    if !managed() {
        return true;
    }
    enforcing() && SCOPE_TREE.load(Ordering::Acquire)
}
pub(crate) fn root_pid() -> u32 {
    {
        let pid = ROOT_PID.load(Ordering::Acquire);
        if pid == 0 {
            std::process::id()
        } else {
            pid
        }
    }
}
pub(crate) fn stopping_background() -> bool {
    managed() && STOP_BACKGROUND.load(Ordering::Acquire)
}
pub(crate) struct CallGuard {
    pid: u32,
    epoch: u64,
    counted: bool,
}
/// Allocator VM callbacks cannot initialize even a destructor-free dynamic TLS
/// slot. Count the entire native wrapper using process/epoch atomics only.
pub(crate) fn enter_allocator() -> CallGuard {
    let pid = std::process::id();
    let epoch = LIFE_EPOCH.load(Ordering::Acquire);
    CALLS.fetch_add(1, Ordering::AcqRel);
    CallGuard {
        pid,
        epoch,
        counted: true,
    }
}
pub(crate) fn enter() -> CallGuard {
    let pid = std::process::id();
    let epoch = LIFE_EPOCH.load(Ordering::Acquire);
    #[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
    let counted = !crate::engine_call::host_background();
    #[cfg(not(all(any(windows, target_os = "linux"), feature = "gum-agent")))]
    let counted = true;
    if counted {
        CALLS.fetch_add(1, Ordering::AcqRel);
    }
    CallGuard {
        pid,
        epoch,
        counted,
    }
}
impl Drop for CallGuard {
    fn drop(&mut self) {
        if self.counted
            && self.pid == std::process::id()
            && self.epoch == LIFE_EPOCH.load(Ordering::Acquire)
        {
            CALLS.fetch_sub(1, Ordering::AcqRel);
        }
    }
}
/// The preparation gate stops only new process-creation entries, without
/// suspending application threads while the loader or allocator may need them.
#[cfg(all(windows, feature = "gum-agent"))]
pub(crate) struct SpawnGuard {
    pid: u32,
    epoch: u64,
    counted: bool,
}
#[cfg(all(windows, feature = "gum-agent"))]
pub(crate) fn enter_spawn() -> SpawnGuard {
    let _error = crate::engine_call::WindowsLastErrorGuard::capture();
    let counted = managed() && local_owner() && !crate::engine_call::host_background();
    if counted {
        while PHASE.load(Ordering::Acquire) == 1 && SCOPE_TREE.load(Ordering::Acquire) {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        SPAWNS.fetch_add(1, Ordering::AcqRel);
    }
    SpawnGuard {
        pid: std::process::id(),
        epoch: LIFE_EPOCH.load(Ordering::Acquire),
        counted,
    }
}
#[cfg(all(windows, feature = "gum-agent"))]
impl Drop for SpawnGuard {
    fn drop(&mut self) {
        if self.counted
            && self.pid == std::process::id()
            && self.epoch == LIFE_EPOCH.load(Ordering::Acquire)
        {
            SPAWNS.fetch_sub(1, Ordering::AcqRel);
        }
    }
}
/// Native DNS publication is narrower than an arbitrary application call:
/// snapshot recovery must drain pending alias outputs, never blocked user I/O.
pub(crate) struct AliasPublicationGuard {
    pid: u32,
    epoch: u64,
    admitted: bool,
}
fn try_alias_publication() -> Option<AliasPublicationGuard> {
    ALIAS_PUBLICATIONS.fetch_add(1, Ordering::SeqCst);
    if !ALIAS_ADMISSION_PAUSED.load(Ordering::SeqCst) || !enforcing() {
        Some(AliasPublicationGuard {
            pid: std::process::id(),
            epoch: LIFE_EPOCH.load(Ordering::Acquire),
            admitted: true,
        })
    } else {
        ALIAS_PUBLICATIONS.fetch_sub(1, Ordering::SeqCst);
        None
    }
}
pub(crate) fn begin_alias_publication() -> AliasPublicationGuard {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        // Counter-before-closed-check and closed-before-counter-snapshot share
        // one total order. A newly blocked call never keeps the drain busy.
        if let Some(guard) = try_alias_publication() {
            return guard;
        }
        if std::time::Instant::now() >= deadline {
            return AliasPublicationGuard {
                pid: std::process::id(),
                epoch: LIFE_EPOCH.load(Ordering::Acquire),
                admitted: false,
            };
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}
pub(crate) fn alias_publications() -> u64 {
    ALIAS_PUBLICATIONS.load(Ordering::SeqCst)
}
impl AliasPublicationGuard {
    pub(crate) fn admitted(&self) -> bool {
        self.admitted
    }
    pub(crate) fn may_publish(&self) -> bool {
        self.admitted
            && self.pid == std::process::id()
            && self.epoch == LIFE_EPOCH.load(Ordering::Acquire)
    }
}
impl Drop for AliasPublicationGuard {
    fn drop(&mut self) {
        if self.admitted
            && self.pid == std::process::id()
            && self.epoch == LIFE_EPOCH.load(Ordering::Acquire)
        {
            ALIAS_PUBLICATIONS.fetch_sub(1, Ordering::SeqCst);
        }
    }
}
pub(crate) struct BackgroundGuard {
    pid: u32,
    epoch: u64,
    control: bool,
}
fn background_guard(control: bool) -> BackgroundGuard {
    let pid = std::process::id();
    let epoch = LIFE_EPOCH.load(Ordering::Acquire);
    BACKGROUND.fetch_add(1, Ordering::AcqRel);
    if control {
        CONTROL_BACKGROUND.fetch_add(1, Ordering::AcqRel);
    }
    BackgroundGuard {
        pid,
        epoch,
        control,
    }
}
pub(crate) fn background_enter() -> BackgroundGuard {
    background_guard(true)
}
#[cfg(all(windows, feature = "gum-agent"))]
pub(crate) fn resident_background_enter() -> BackgroundGuard {
    background_guard(false)
}
impl Drop for BackgroundGuard {
    fn drop(&mut self) {
        if self.pid == std::process::id() && self.epoch == LIFE_EPOCH.load(Ordering::Acquire) {
            if self.control {
                CONTROL_BACKGROUND.fetch_sub(1, Ordering::AcqRel);
            }
            BACKGROUND.fetch_sub(1, Ordering::AcqRel);
        }
    }
}
fn equal(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes()
        .iter()
        .zip(b.as_bytes())
        .fold(0u8, |v, (a, b)| v | (a ^ b))
        == 0
}
pub(crate) fn bind_metadata(bootstrap: &Bootstrap) -> Result<bool, i32> {
    bind_metadata_inner(bootstrap, None).map(|(bound, _)| bound)
}
/// A recoverable binding is never published before its initializer is owned.
/// Only a fresh binding creates this guard; duplicate dispatch cannot reset an
/// existing initializer's cancellation, phase or readiness.
pub(crate) fn bind_metadata_for_startup(
    bootstrap: &Bootstrap,
    child: bool,
) -> Result<Option<startup::Startup>, i32> {
    bind_metadata_inner(bootstrap, Some(child)).map(|(_, worker)| worker)
}
fn bind_metadata_inner(
    bootstrap: &Bootstrap,
    child: Option<bool>,
) -> Result<(bool, Option<startup::Startup>), i32> {
    let _access = crate::runtime::host_access().ok_or(HH_ERR_NOT_INITIALIZED)?;
    if crate::runtime::sdk_access_closed() {
        return Err(HH_ERR_NOT_INITIALIZED);
    }
    bootstrap.validate().map_err(|_| HH_ERR_INVALID)?;
    let mut current = bootstrap_slot().lock().map_err(|_| HH_ERR_PROTOCOL)?;
    if let Some(existing) = current.as_ref() {
        if existing.attachment_id != bootstrap.attachment_id
            || !equal(&existing.host_token, &bootstrap.host_token)
        {
            return Err(HH_ERR_PROTOCOL);
        }
        return Ok((false, None));
    }
    if let Some(key) = bootstrap
        .approval_public_key
        .or(bootstrap.approval_inherited_public_key)
    {
        pin_approval_key(key).map_err(|_| HH_ERR_PROTOCOL)?;
    }
    // Register the worker while this new binding is still unpublished. A
    // recovery caller may open the Host as soon as OWNER/PHASE become visible,
    // including before the entrypoint's next instruction executes.
    let worker = child.map(startup::begin);
    // No Host exists yet. Do not acquire state_gate while holding this slot:
    // lifecycle readers acquire those locks in the opposite order.
    NATIVE_READY.store(false, Ordering::Release);
    *current = Some(bootstrap.clone());
    EXTERNAL_ATTACHMENT.store(bootstrap.external_attachment, Ordering::Release);
    SNAPSHOT.store(
        Box::into_raw(Box::new(bootstrap.clone())),
        Ordering::Release,
    );
    OWNER_PID.store(std::process::id(), Ordering::Release);
    ROOT_PID.store(bootstrap.root_pid, Ordering::Release);
    SCOPE_TREE.store(bootstrap.scope_tree, Ordering::Release);
    DETACH_CUTOFF_MS.fetch_max(bootstrap.approval_not_before_ms, Ordering::AcqRel);
    PHASE.store(1, Ordering::Release);
    drop(current);
    Ok((true, worker))
}
pub(crate) fn initialize(bootstrap: &Bootstrap) -> Result<(), i32> {
    if !bind_metadata(bootstrap)? {
        return Ok(());
    }
    initialize_bound(bootstrap)
}
pub(crate) fn initialize_bound(bootstrap: &Bootstrap) -> Result<(), i32> {
    startup::check()?;
    let result: Result<(), i32> = (|| {
        startup::check()?;
        startup::mutate_runtime(|| {
            crate::state()
                .lock()
                .map_err(|_| HH_ERR_PROTOCOL)?
                .initialize_from_bootstrap(bootstrap)
        })?;
        #[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
        {
            startup::check()?;
            crate::engine_call::initialize_thread_slots()?;
            crate::control::initialize_engine_control(crate::control::StartupDeadline::new())?;
            startup::check()?;
            crate::subscribe_sandbox();
        }
        Ok(())
    })();
    // A failed initializer remains non-active until authenticated cleanup.
    // A protected fork child must keep waiting for its approved cancellation.
    result?;
    startup::check()
}
/// Bind the child's fresh lifecycle channel after fork recovery has rebuilt
/// the inherited runtime. Existing sockets, DNS aliases and Engine leases stay.
pub(crate) fn initialize_rebuilt(bootstrap: &Bootstrap) -> Result<(), i32> {
    let _access = crate::runtime::host_access().ok_or(HH_ERR_NOT_INITIALIZED)?;
    if crate::runtime::sdk_access_closed() {
        return Err(HH_ERR_NOT_INITIALIZED);
    }
    crate::root_image::clear_challenge();
    bootstrap.validate().map_err(|_| HH_ERR_INVALID)?;
    clear_native_ready();
    if let Some(key) = bootstrap
        .approval_public_key
        .or(bootstrap.approval_inherited_public_key)
    {
        pin_approval_key(key).map_err(|_| HH_ERR_PROTOCOL)?;
    }
    let mut current = bootstrap_slot().lock().map_err(|_| HH_ERR_PROTOCOL)?;
    if current.is_some() {
        return Err(HH_ERR_PROTOCOL);
    }
    *current = Some(bootstrap.clone());
    EXTERNAL_ATTACHMENT.store(bootstrap.external_attachment, Ordering::Release);
    SNAPSHOT.store(
        Box::into_raw(Box::new(bootstrap.clone())),
        Ordering::Release,
    );
    OWNER_PID.store(std::process::id(), Ordering::Release);
    ROOT_PID.store(bootstrap.root_pid, Ordering::Release);
    SCOPE_TREE.store(bootstrap.scope_tree, Ordering::Release);
    DETACH_CUTOFF_MS.fetch_max(bootstrap.approval_not_before_ms, Ordering::AcqRel);
    PHASE.store(1, Ordering::Release);
    drop(current);
    startup::runtime_rebuilt()?;
    Ok(())
}
pub(crate) fn start_server() -> Result<(), i32> {
    let _access = crate::runtime::host_access().ok_or(HH_ERR_NOT_INITIALIZED)?;
    if crate::runtime::sdk_access_closed() {
        return Err(HH_ERR_NOT_INITIALIZED);
    }
    if SERVER_STARTED.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    let endpoint = bootstrap_slot()
        .lock()
        .map_err(|_| HH_ERR_PROTOCOL)?
        .as_ref()
        .ok_or(HH_ERR_PROTOCOL)?
        .host_endpoint
        .clone();
    let listener = match Listener::bind(&endpoint) {
        Ok(listener) => listener,
        Err(_) => {
            SERVER_STARTED.store(false, Ordering::Release);
            return Err(HH_ERR_PROTOCOL);
        }
    };
    if std::thread::Builder::new()
        .name("hyperhub-attachment".into())
        .spawn(move || {
            #[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
            crate::engine_call::background(|| {
                let _ = listener.run_raw_with_peer(&STOP_SERVER, host_command::receive);
            });
            #[cfg(not(all(any(windows, target_os = "linux"), feature = "gum-agent")))]
            {
                let _ = listener.run_raw_with_peer(&STOP_SERVER, host_command::receive);
            }
            SERVER_STARTED.store(false, Ordering::Release);
        })
        .is_err()
    {
        SERVER_STARTED.store(false, Ordering::Release);
        return Err(HH_ERR_PROTOCOL);
    }
    Ok(())
}
/// Reopen only the already-bound recovery channel. This does not initialize an
/// Engine, install Hook callbacks, change policy or accept a lifecycle command.
#[no_mangle]
pub extern "C" fn hyperhub_attachment_recover_transport() -> i32 {
    if !managed()
        || !local_owner()
        || status_phase() == HostPhase::Active
        || STATE_RETIRED.load(Ordering::Acquire)
        || crate::runtime::sdk_access_closed()
    {
        return HH_ERR_NOT_INITIALIZED;
    }
    #[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
    {
        crate::engine_call::background(|| {
            start_server()
                .map(|_| crate::HH_OK)
                .unwrap_or_else(|code| code)
        })
    }
    #[cfg(not(all(any(windows, target_os = "linux"), feature = "gum-agent")))]
    {
        start_server()
            .map(|_| crate::HH_OK)
            .unwrap_or_else(|code| code)
    }
}
fn finalized_status() -> HostStatus {
    // The listener is already stopped. A direct diagnostic call must remain
    // safe if another module owner keeps this DLL mapped after final release.
    HostStatus {
        initialization: startup::status(),
        protocol: PROTOCOL,
        pid: std::process::id(),
        attachment_id: String::new(),
        phase: HostPhase::DetachedResident,
        native_ready: false,
        active_calls: 0,
        control_workers: 0,
        background_workers: 0,
        pending_alias_publications: 0,
        alias_publication_paused: false,
        spawn_calls: 0,
        approval_not_before_ms: 0,
        approval_root_enrolled: false,
        approval_enrollment_available: false,
        approval_public_key: None,
        approval_challenge: None,
        unload_ready: true,
        tracked_sockets: 0,
        fake_addresses: 0,
        compatibility_reasons: vec!["native_storage_finalized".into()],
        alias_snapshot: None,
        alias_inheritance: None,
        alias_history_ready: false,
        root_image: None,
    }
}
pub(crate) fn status() -> HostStatus {
    let Some(_access) = crate::runtime::host_access() else {
        return finalized_status();
    };
    let (attachment_id, configured) = bootstrap_slot()
        .lock()
        .ok()
        .and_then(|b| b.as_ref().map(|b| (b.attachment_id.clone(), true)))
        .unwrap_or_default();
    let runtime_available = startup::runtime_available();
    let (sockets, dns) = if !runtime_available {
        (usize::MAX, usize::MAX)
    } else if STATE_RETIRED.load(Ordering::Acquire) {
        (0, 0)
    } else {
        crate::state()
            .try_lock()
            .map(|s| (s.gateway.sockets.len(), s.gateway.issued_aliases.len()))
            .unwrap_or((usize::MAX, usize::MAX))
    };
    let active = active_calls();
    let phase = match PHASE.load(Ordering::Acquire) {
        1 => HostPhase::Preparing,
        2 => HostPhase::Active,
        3 => HostPhase::Detaching,
        4 => HostPhase::DetachedResident,
        5 => HostPhase::Detached,
        _ => HostPhase::Preparing,
    };
    let mut reasons = Vec::new();
    if !runtime_available {
        reasons.push("initialization_runtime_unavailable".into());
    }
    if startup::running() != 0 {
        reasons.push("initialization_worker_running".into());
    }
    #[cfg(all(windows, feature = "gum-agent"))]
    if crate::windows_gum::external_posix_runtime_unsupported() {
        reasons.push("external_posix_runtime_fork_unsupported".into());
    }
    if matches!(phase, HostPhase::Detaching | HostPhase::DetachedResident) {
        if sockets > 0 {
            reasons.push("existing_socket_state".into());
        }
        if dns > 0 {
            reasons.push("application_may_cache_fake_addresses".into());
        }
        if runtime_available && !STATE_RETIRED.load(Ordering::Acquire) {
            if let Ok(core) = crate::state().try_lock() {
                if core
                    .gateway
                    .issued_aliases
                    .values()
                    .any(|alias| alias.native_fallback.addresses.is_empty())
                {
                    reasons.push("issued_alias_native_cache_unavailable".into());
                }
                if !core.gateway.ambiguous_aliases.is_empty() {
                    reasons.push("ambiguous_cached_alias_identity".into());
                }
            }
        }
        if alias_publications() > 0 {
            reasons.push("pending_issued_dns_publications".into());
        }
        if active > 0 {
            reasons.push("active_hook_calls".into());
        }
        if CONTROL_BACKGROUND.load(Ordering::Acquire) > 0 {
            reasons.push("control_threads_still_retiring".into());
        }
        if configured && !CALLBACKS_RETIRED.load(Ordering::Acquire) {
            reasons.push("native_callbacks_not_yet_retired".into());
        }
        if let Ok(error) = RETIRE_ERROR.lock() {
            if let Some(error) = error.as_ref() {
                reasons.push(error.clone());
            }
        }
        if STATE_RETIRED.load(Ordering::Acquire) {
            reasons.push("native_module_waiting_for_verified_unload".into());
        }
    }
    HostStatus {
        initialization: startup::status(),
        protocol: PROTOCOL,
        pid: std::process::id(),
        attachment_id,
        phase,
        native_ready: native_ready(),
        active_calls: active,
        control_workers: CONTROL_BACKGROUND.load(Ordering::Acquire) as u64,
        background_workers: BACKGROUND.load(Ordering::Acquire) as u64,
        pending_alias_publications: alias_publications(),
        alias_publication_paused: ALIAS_ADMISSION_PAUSED.load(Ordering::SeqCst),
        spawn_calls: SPAWNS.load(Ordering::Acquire),
        approval_not_before_ms: approval_not_before_ms(),
        approval_root_enrolled: approval_public_key().is_some(),
        approval_enrollment_available: bootstrap()
            .is_some_and(|boot| boot.approval_core_public_key.is_some()),
        approval_public_key: approval_public_key(),
        approval_challenge: enrollment_slot().lock().ok().and_then(|slot| slot.clone()),
        unload_ready: STATE_RETIRED.load(Ordering::Acquire),
        tracked_sockets: sockets,
        fake_addresses: dns,
        compatibility_reasons: reasons,
        alias_snapshot: None,
        root_image: crate::root_image::current_for_status(),
        alias_inheritance: (runtime_available && startup::running() == 0)
            .then(crate::alias_namespace::inheritance)
            .flatten(),
        alias_history_ready: runtime_available
            && startup::running() == 0
            && crate::alias_namespace::history_ready(),
    }
}
pub(crate) fn snapshot_issued_aliases(
    gateway: &crate::GatewayState,
) -> Result<hyperhub_runtime::attachment::AliasSnapshot, i32> {
    let mut snapshot = gateway.issued_snapshot()?;
    snapshot.complete = alias_publications() == 0
        && (gateway.namespace.anchor.is_none() || gateway.namespace.history_ready);
    if serde_json::to_vec(&snapshot)
        .map_err(|_| HH_ERR_PROTOCOL)?
        .len()
        > hyperhub_runtime::attachment::MAX_FRAME / 2
    {
        return Err(crate::HH_ERR_BUFFER_TOO_SMALL);
    }
    Ok(snapshot)
}
pub(crate) fn command(request: AuthenticatedCommand) -> Result<HostStatus, String> {
    command_with_peer(request, 0)
}
fn command_with_peer(request: AuthenticatedCommand, peer: u32) -> Result<HostStatus, String> {
    if hyperhub_runtime::attachment::host_command_authority(request.command)
        == hyperhub_runtime::attachment::HostCommandAuthority::ManagerLifecycle
        && !(request.command == HostCommand::Activate
            && request.proof.is_none()
            && bootstrap().is_some_and(|boot| boot.initially_owned)
            && PHASE.load(Ordering::Acquire) == 2)
    {
        return Err("Host lifecycle challenge and manager possession are required".into());
    }
    command_semantic(request, peer, None)
}
fn command_semantic(
    request: AuthenticatedCommand,
    peer: u32,
    mut lifecycle: Option<&mut host_command::Execution<'_>>,
) -> Result<HostStatus, String> {
    let _access = crate::runtime::host_access().ok_or("attachment runtime storage is finalized")?;
    if STATE_RETIRED.load(Ordering::Acquire)
        && matches!(
            request.command,
            HostCommand::Activate
                | HostCommand::EnrollApprovalRoot
                | HostCommand::ApplySessionAliases
                | HostCommand::ApplyRootImage
        )
    {
        return Err(
            "native base is retired; only scoped cleanup and reads remain available".into(),
        );
    }
    {
        let current = bootstrap_slot()
            .lock()
            .map_err(|_| "attachment state unavailable")?;
        let current = current.as_ref().ok_or("attachment is not initialized")?;
        if current.attachment_id != request.attachment_id
            || !equal(&current.host_token, &request.token)
        {
            return Err("attachment authorization rejected".into());
        }
    }
    if !startup::runtime_available()
        && !matches!(
            request.command,
            HostCommand::Status
                | HostCommand::EnrollmentChallenge
                | HostCommand::EnrollApprovalRoot
                | HostCommand::Detach
                | HostCommand::Retire
                | HostCommand::PrepareDetachment
                | HostCommand::CancelDetachmentPreparation
        )
    {
        return Err(
            "attachment Runtime is not rebuilt; only authenticated cleanup is available".into(),
        );
    }
    if request.command == HostCommand::PrepareDetachment
        && PHASE.load(Ordering::Acquire) == 1
        && !preparation_cleanup()
    {
        return Err("activation_busy".into());
    }
    if request.command == HostCommand::Activate && ALIAS_ADMISSION_PAUSED.load(Ordering::SeqCst) {
        return Err("detachment_preparation_pending".into());
    }
    if request.command == HostCommand::CancelDetachmentPreparation
        && ALIAS_ADMISSION_PAUSED.load(Ordering::SeqCst)
    {
        let history = history()
            .lock()
            .map_err(|_| "approval history unavailable")?;
        if !history.last.as_ref().is_some_and(|last| {
            last.action == hyperhub_runtime::attachment::ApprovedAction::Detach
                && !last.committed
                && request.proof.as_ref() == Some(&last.proof)
        }) {
            return Err("cancel requires the same uncommitted Detach approval".into());
        }
    }
    if request.command == HostCommand::PrepareDetachment
        && ALIAS_ADMISSION_PAUSED.load(Ordering::SeqCst)
    {
        let history = history()
            .lock()
            .map_err(|_| "approval history unavailable")?;
        if !history
            .last
            .as_ref()
            .is_some_and(|last| !last.committed && request.proof.as_ref() == Some(&last.proof))
        {
            return Err("another detachment preparation is pending".into());
        }
    }
    // Already policy-off Hosts need no new admission stage. Verify the exact
    // scope without overwriting the old accepted detach/retirement continuation.
    if (request.command == HostCommand::PrepareDetachment
        && matches!(PHASE.load(Ordering::Acquire), 3 | 4 | 5))
        || (request.command == HostCommand::CancelDetachmentPreparation
            && !ALIAS_ADMISSION_PAUSED.load(Ordering::SeqCst))
    {
        verify_detachment_gate_noop(&request)?;
        host_command::finish_noop(&mut lifecycle)?;
        return Ok(status());
    }
    if request.command == HostCommand::Activate && !native_ready() {
        return Err("native hook base is not ready".into());
    }
    if request.command == HostCommand::ApplyRootImage {
        if !local_owner() {
            return Err("native Host ownership is not rebuilt".into());
        }
        let boot = bootstrap().ok_or("attachment bootstrap unavailable")?;
        crate::root_image::apply_transition(
            &boot,
            request
                .root_image
                .as_ref()
                .ok_or("signed root image metadata is missing")?,
            request.proof.as_ref(),
        )?;
        return Ok(status());
    }
    if request.command == HostCommand::ApplySessionAliases {
        if !local_owner() {
            return Err("native Host ownership is not rebuilt".into());
        }
        let boot = bootstrap().ok_or("attachment bootstrap unavailable")?;
        crate::alias_namespace::apply(
            &boot,
            request
                .aliases
                .as_ref()
                .ok_or("signed session aliases are missing")?,
            request.proof.as_ref(),
        )?;
        return Ok(status());
    }
    if request.command == HostCommand::SnapshotAliases {
        if !local_owner() {
            return Err("native Host ownership is not rebuilt".into());
        }
        let boot = bootstrap().ok_or("attachment bootstrap unavailable")?;
        let key = approval_public_key().ok_or("approval root is not enrolled")?;
        let proof = request
            .proof
            .as_ref()
            .ok_or("fresh scoped approval is required for alias snapshot")?;
        let claims =
            hyperhub_runtime::attachment::verify_proof_with_key(&boot, &key, proof, now_ms())
                .map_err(|e| e.to_string())?;
        if !attachment_epoch_allows(
            claims.action,
            claims.approved_at_ms,
            approval_not_before_ms(),
        ) {
            return Err("alias snapshot requires current Attach approval epoch".into());
        }
        crate::root_image::verify_operation(&claims)?;
        let mut reply = status();
        let core = crate::state()
            .lock()
            .map_err(|_| "issued alias state unavailable")?;
        reply.alias_snapshot = Some(
            snapshot_issued_aliases(&core.gateway)
                .map_err(|_| "issued alias snapshot exceeds bounded protocol frame")?,
        );
        return Ok(reply);
    }
    if authorize_mutation(&request)? {
        host_command::finish_noop(&mut lifecycle)?;
        return Ok(status());
    }
    match request.command {
        HostCommand::SnapshotAliases
        | HostCommand::ApplySessionAliases
        | HostCommand::ApplyRootImage => unreachable!(),
        HostCommand::EnrollmentChallenge => {
            enrollment_challenge()?;
        }
        HostCommand::EnrollApprovalRoot => {
            with_state_mutation(|| {
                let mut slot = enrollment_slot()
                    .lock()
                    .map_err(|_| "enrollment challenge state unavailable")?;
                // Every attempt consumes the challenge, including invalid chains.
                let challenge = slot
                    .take()
                    .ok_or("approval enrollment challenge is missing")?;
                let certificate = request
                    .enrollment
                    .as_ref()
                    .ok_or("approval root certificate is missing")?;
                let boot = bootstrap().ok_or("attachment bootstrap unavailable")?;
                if let Some(previous) = approval_public_key() {
                    let (key, generation) =
                        hyperhub_runtime::attachment::verify_approval_rotation_enrollment(
                            &boot,
                            &previous,
                            APPROVAL_GENERATION.load(Ordering::Acquire),
                            &challenge,
                            certificate,
                            now_ms(),
                        )
                        .map_err(|e| e.to_string())?;
                    // Readers may retain an old pointer. Public-key allocations
                    // remain valid for the Host lifetime, bounded by chain size.
                    let fresh = Box::into_raw(Box::new(key));
                    APPROVAL_ROOT.store(fresh, Ordering::Release);
                    APPROVAL_GENERATION.store(generation, Ordering::Release);
                } else {
                    let key = hyperhub_runtime::attachment::verify_enrollment(
                        &boot,
                        &challenge,
                        certificate,
                        peer,
                        now_ms(),
                    )
                    .map_err(|e| e.to_string())?;
                    pin_approval_key(key)?;
                }
                Ok(())
            })?;
        }
        HostCommand::PrepareDetachment => {
            if PHASE.load(Ordering::Acquire) != 2 && !preparation_cleanup() {
                return Err(
                    "detachment preparation requires an Active or never-active startup Host".into(),
                );
            }
            host_command::commit_mutation(&mut lifecycle, || {
                ALIAS_ADMISSION_PAUSED.store(true, Ordering::SeqCst);
                Ok(())
            })?;
        }
        HostCommand::CancelDetachmentPreparation => {
            host_command::commit_mutation(&mut lifecycle, || {
                ALIAS_ADMISSION_PAUSED.store(false, Ordering::SeqCst);
                Ok(())
            })?;
        }
        HostCommand::Activate => {
            if CALLBACKS_RETIRED.load(Ordering::Acquire) {
                return Err("native base is retiring for physical unload".into());
            }
            if !host_command::activation_prepared(&lifecycle)? {
                let values = bootstrap().ok_or("attachment is not initialized")?;
                let deadline = crate::control::StartupDeadline::host_command();
                let trust = crate::control::fetch_trust_control(
                    &values.control_endpoint,
                    &values.session_id,
                    &values.token,
                    &deadline,
                )
                .map_err(|code| format!("cannot refresh attachment policy: {code}"))?;
                {
                    let mut core = crate::state()
                        .lock()
                        .map_err(|_| "attachment state unavailable")?;
                    core.sandbox.firewall = trust.firewall.map(std::sync::Arc::new);
                }
                #[cfg(all(any(windows, unix), feature = "gum-agent"))]
                if let Some(snapshot) = trust.sandbox {
                    crate::apply_sandbox_snapshot(snapshot);
                }
                if STOP_BACKGROUND.swap(false, Ordering::AcqRel) {
                    if CONTROL_BACKGROUND.load(Ordering::Acquire) != 0 {
                        STOP_BACKGROUND.store(true, Ordering::Release);
                        return Err("attachment workers are still retiring".into());
                    }
                    #[cfg(all(any(windows, target_os = "linux"), feature = "gum-agent"))]
                    {
                        if let Err(code) = crate::control::initialize_engine_control(deadline) {
                            STOP_BACKGROUND.store(true, Ordering::Release);
                            return Err(format!("cannot reenroll attachment: {code}"));
                        }
                        crate::subscribe_sandbox();
                    }
                }
                crate::alias_namespace::initialize_host_detailed_until(deadline)
                    .map_err(|error| format!("cannot catch up session aliases: {error}"))?;
                host_command::remember_activation_prepared(&lifecycle)?;
            }
            let claims = history()
                .lock()
                .map_err(|_| "approval history unavailable")?
                .last
                .as_ref()
                .ok_or("accepted activation approval is missing")?
                .claims
                .clone();
            host_command::commit_mutation(&mut lifecycle, || {
                crate::root_image::with_verified_operation(&claims, |core| {
                    if let Some(anchor) = core.gateway.namespace.anchor.as_mut() {
                        anchor.metadata_only = false;
                    }
                    PHASE.store(2, Ordering::Release);
                    host_command::mark_active();
                })?;
                commit_operation();
                Ok(())
            })?;
        }
        HostCommand::Detach => {
            host_command::commit_mutation(&mut lifecycle, || {
                startup::cancel();
                PHASE.store(3, Ordering::Release);
                ALIAS_ADMISSION_PAUSED.store(false, Ordering::SeqCst);
                let current = status();
                if current.tracked_sockets == 0 {
                    STOP_BACKGROUND.store(true, Ordering::Release);
                }
                PHASE.store(4, Ordering::Release);
                commit_operation();
                Ok(())
            })?;
            try_retire();
        }
        HostCommand::Status => {
            try_retire();
        }
        HostCommand::Retire => {
            if !status().unload_ready {
                return Err("attachment is not safe to unload".into());
            }
            host_command::commit_mutation(&mut lifecycle, || {
                STOP_SERVER.store(true, Ordering::Release);
                Ok(())
            })?;
        }
    }
    Ok(status())
}

fn verify_detachment_gate_noop(request: &AuthenticatedCommand) -> Result<(), String> {
    let proof = request
        .proof
        .as_ref()
        .ok_or("Detach approval is required")?;
    {
        let history = history()
            .lock()
            .map_err(|_| "approval history unavailable")?;
        if history.last.as_ref().is_some_and(|last| {
            last.action == hyperhub_runtime::attachment::ApprovedAction::Detach
                && (last.committed || request.command == HostCommand::CancelDetachmentPreparation)
                && last.proof == *proof
        }) {
            return Ok(());
        }
    }
    let boot = bootstrap().ok_or("attachment bootstrap unavailable")?;
    let key = approval_public_key().ok_or("approval root is not enrolled")?;
    let claims = hyperhub_runtime::attachment::verify_proof_with_key(&boot, &key, proof, now_ms())
        .map_err(|e| e.to_string())?;
    if claims.action != hyperhub_runtime::attachment::ApprovedAction::Detach
        || claims.approved_at_ms <= approval_not_before_ms()
    {
        return Err("current scoped Detach approval is required".into());
    }
    Ok(())
}

pub(crate) fn initialize_alias_host() -> Result<(), i32> {
    crate::alias_namespace::initialize_host()
}
/// Metadata authority changes require the current real administrator and the
/// same immutable Host scope. They never enable enforcement on their own.
pub(crate) fn verify_root_endorsement(
    proof: &hyperhub_runtime::attachment::ApprovalProof,
) -> Result<hyperhub_runtime::attachment::ApprovalClaims, String> {
    let boot = bootstrap().ok_or("attachment bootstrap unavailable")?;
    let key = approval_public_key().ok_or("approval root is not enrolled")?;
    let claims = hyperhub_runtime::attachment::verify_proof_with_key(&boot, &key, proof, now_ms())
        .map_err(|e| e.to_string())?;
    if claims.approved_at_ms <= approval_not_before_ms() {
        return Err("metadata endorsement predates the accepted detach epoch".into());
    }
    let history = history()
        .lock()
        .map_err(|_| "approval history unavailable")?;
    if history.last.as_ref().is_some_and(|last| {
        claims.approved_at_ms < last.approved_at_ms
            || (claims.approved_at_ms == last.approved_at_ms && claims.nonce != last.nonce)
    }) {
        return Err("metadata endorsement predates the accepted operation".into());
    }
    Ok(claims)
}
pub(crate) fn verify_alias_endorsement(
    proof: &hyperhub_runtime::attachment::ApprovalProof,
) -> Result<hyperhub_runtime::attachment::ApprovalClaims, String> {
    let claims = verify_root_endorsement(proof)?;
    crate::root_image::verify_operation(&claims)?;
    if claims.action == hyperhub_runtime::attachment::ApprovedAction::Detach
        && !ALIAS_ADMISSION_PAUSED.load(Ordering::SeqCst)
        && !logically_detached()
    {
        return Err("Detach metadata endorsement requires closed synthetic admission".into());
    }
    Ok(claims)
}

fn try_retire() {
    if !matches!(PHASE.load(Ordering::Acquire), 3 | 4)
        || STATE_RETIRED.load(Ordering::Acquire)
        || startup::running() != 0
        || !startup::runtime_available()
    {
        return;
    }
    let (sockets, dns) = crate::state()
        .lock()
        .map(|s| (s.gateway.sockets.len(), s.gateway.issued_aliases.len()))
        .unwrap_or((usize::MAX, usize::MAX));
    // Subscription retirement is independent of native-code retirement. An
    // ordinary blocked application call still owns its return path, but no
    // longer needs policy workers after all managed network work has drained.
    if sockets == 0 && dns == 0 && alias_publications() == 0 {
        STOP_BACKGROUND.store(true, Ordering::Release);
    }
    if sockets != 0 || dns != 0 || active_calls() != 0 || alias_publications() != 0 {
        return;
    }
    let result = (|| -> Result<(), String> {
        if !CALLBACKS_RETIRED.load(Ordering::Acquire) {
            #[cfg(all(windows, feature = "gum-agent"))]
            crate::windows_gum::retire_attachment_callbacks()?;
            #[cfg(all(target_os = "linux", feature = "gum-agent"))]
            crate::unix_gum::retire_attachment_callbacks()?;
            #[cfg(not(all(any(windows, target_os = "linux"), feature = "gum-agent")))]
            return Err("native callback retirement not provided by this backend".into());
            clear_native_ready();
            CALLBACKS_RETIRED.store(true, Ordering::Release);
        }
        if !crate::runtime::close_sdk_access() {
            return Err("SDK runtime calls are still returning".into());
        }
        if active_calls() != 0 || BACKGROUND.load(Ordering::Acquire) != 0 {
            return Err("module workers are still retiring".into());
        }
        crate::engine_call::retire_thread_slots().map_err(|_| "thread slots are still in use")?;
        if active_calls() != 0 {
            return Err("TLS cleanup callback is still returning".into());
        }
        #[cfg(all(windows, feature = "gum-agent"))]
        crate::windows_gum::finish_attachment_retirement()?;
        // Keep verification/status state alive through the final Retire reply.
        // The stopped-channel external release owns its eventual destruction.
        with_state_mutation(|| {
            STATE_RETIRED.store(true, Ordering::Release);
            Ok(())
        })?;
        Ok(())
    })();
    if let Ok(mut error) = RETIRE_ERROR.lock() {
        *error = result.err();
    }
}

pub(crate) fn activate_initial_owned() -> Result<(), i32> {
    if !native_ready() || !crate::alias_namespace::admission_ready() {
        return Err(HH_ERR_PROTOCOL);
    }
    let boot = bootstrap().ok_or(HH_ERR_PROTOCOL)?;
    if !boot.initially_owned || PHASE.load(Ordering::Acquire) != 1 {
        return Err(HH_ERR_PROTOCOL);
    }
    let trust = crate::control::fetch_trust_control(
        &boot.control_endpoint,
        &boot.session_id,
        &boot.token,
        &crate::control::StartupDeadline::new(),
    )?;
    if let Ok(mut core) = crate::state().lock() {
        core.sandbox.firewall = trust.firewall.map(std::sync::Arc::new);
    } else {
        return Err(HH_ERR_PROTOCOL);
    }
    #[cfg(all(any(windows, unix), feature = "gum-agent"))]
    if let Some(snapshot) = trust.sandbox {
        crate::apply_sandbox_snapshot(snapshot);
    }
    commit_initial_owned_activation()
}
fn commit_initial_owned_activation() -> Result<(), i32> {
    with_state_mutation(|| {
        startup::check().map_err(|_| "initial owned activation was cancelled")?;
        if PHASE.load(Ordering::Acquire) != 1 {
            return Err("initial owned Host is no longer Preparing".into());
        }
        PHASE.store(2, Ordering::Release);
        host_command::mark_active();
        Ok(())
    })
    .map_err(|_| HH_ERR_PROTOCOL)
}

#[cfg(test)]
#[path = "attachment_tests.rs"]
mod tests;

/// Called only by the final Windows loader release after the external thread
/// barrier. No application callback or Host server can observe this storage.
#[cfg(all(windows, feature = "gum-agent"))]
pub(crate) unsafe fn release_retired_storage() -> Result<(), i32> {
    if !unload_ready()
        || SERVER_STARTED.load(Ordering::Acquire)
        || active_calls() != 0
        || BACKGROUND.load(Ordering::Acquire) != 0
    {
        return Err(HH_ERR_PROTOCOL);
    }
    crate::runtime::retire_attachment_state()?;
    let pointer = BOOTSTRAP.swap(std::ptr::null_mut(), Ordering::AcqRel);
    if !pointer.is_null() {
        drop(Box::from_raw(pointer));
    }
    let pointer = SNAPSHOT.swap(std::ptr::null_mut(), Ordering::AcqRel);
    if !pointer.is_null() {
        drop(Box::from_raw(pointer));
    }
    let pointer = HISTORY.swap(std::ptr::null_mut(), Ordering::AcqRel);
    if !pointer.is_null() {
        drop(Box::from_raw(pointer));
    }
    if let Ok(mut error) = RETIRE_ERROR.lock() {
        error.take();
    }
    let pointer = ENROLLMENT.swap(std::ptr::null_mut(), Ordering::AcqRel);
    if !pointer.is_null() {
        drop(Box::from_raw(pointer));
    }
    let pointer = APPROVAL_ROOT.swap(std::ptr::null_mut(), Ordering::AcqRel);
    if !pointer.is_null() {
        drop(Box::from_raw(pointer));
    }
    crate::native_alias_snapshot::release_retired();
    crate::engine_call::release_retired_slot_registry();
    host_command::release_retired();
    Ok(())
}
