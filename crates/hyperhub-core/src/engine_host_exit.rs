use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessExit {
    pub session_id: String,
    pub pid: u32,
    pub start_time: u64,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub source: String,
    pub issued_at_ms: u64,
}
impl ProcessExit {
    fn mac(&self, key: &[u8]) -> io::Result<Hmac<Sha256>> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(io::Error::other)?;
        mac.update(b"hyperhub-engine-process-exit-owner-v1\0");
        mac.update(&serde_json::to_vec(self).map_err(io::Error::other)?);
        Ok(mac)
    }
    pub fn proof(&self, key: &[u8]) -> io::Result<Vec<u8>> {
        Ok(self.mac(key)?.finalize().into_bytes().to_vec())
    }
    pub fn authenticate(&self, key: &[u8], proof: &[u8]) -> bool {
        self.pid != 0
            && self.start_time != 0
            && !self.session_id.is_empty()
            && self.session_id.len() <= 128
            && self.issued_at_ms.abs_diff(unix_timestamp_ms()) <= 30_000
            && matches!(
                self.source.as_str(),
                "ptrace_process" | "ptrace_tree" | "gum_launcher" | "gum_tree"
            )
            && self
                .mac(key)
                .is_ok_and(|mac| mac.verify_slice(proof).is_ok())
    }
}

// Business exit codes describe the target's result, not Engine health. Unix
// wait statuses distinguish exit() from a fatal signal. Windows reports both
// application codes and exception statuses in the same field; preserve all
// high-bit statuses as failures, including warning-severity exceptions.
fn completed_normally(backend: Backend, code: Option<i32>, signal: Option<i32>) -> bool {
    signal.is_none()
        && code.is_some_and(|code| match backend {
            Backend::LinuxPtrace | Backend::LinuxGum => (0..=255).contains(&code),
            Backend::WindowsGum => code >= 0,
        })
}

#[derive(Default)]
pub(super) struct ExitState {
    normal_completed: bool,
    failure: Option<(u64, String)>,
    last_seen: Option<std::time::Instant>,
}
fn key(host: &HostStatus) -> Option<(String, u32, u64)> {
    Some((
        host.session_id.clone(),
        host.host_pid,
        host.host_start_time?,
    ))
}
impl EngineHosts {
    pub(crate) fn note_member_birth(&self, session: &str, pid: u32, start: u64) -> io::Result<()> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("engine registry poisoned"))?;
        Self::record_birth(&mut state, session, pid, start)
    }
    pub(super) fn record_birth(
        state: &mut State,
        session: &str,
        pid: u32,
        start: u64,
    ) -> io::Result<()> {
        let now = std::time::Instant::now();
        if state.births.len() >= 8192
            || state
                .last_birth_scan
                .is_none_or(|last| now.duration_since(last).as_secs() >= 1)
        {
            Self::prune_births(state, now);
        }
        let key = (session.into(), pid, start);
        if state.births.len() >= 8192 && !state.births.contains_key(&key) {
            return Err(io::Error::other(
                "Engine member birth evidence limit reached",
            ));
        }
        state.births.entry(key).or_insert(None);
        Ok(())
    }
    fn prune_births(state: &mut State, now: std::time::Instant) {
        state.last_birth_scan = Some(now);
        state.births.retain(|(_, pid, start), gone_since| {
            if !Self::process_is_gone(*pid, *start) {
                *gone_since = None;
                return true;
            }
            let first = gone_since.get_or_insert(now);
            now.duration_since(*first).as_secs() < 30
        });
    }
    pub(crate) fn authorize_exit_reporter(&self, id: &str, pid: u32, start: u64) -> io::Result<()> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("engine registry poisoned"))?;
        let host = state
            .hosts
            .get_mut(id)
            .ok_or_else(|| io::Error::other("unknown Engine Host"))?;
        if host.reporters.len() >= 128 {
            return Err(io::Error::other("Engine reporter ancestor limit exceeded"));
        }
        host.reporters.insert(pid, start);
        Ok(())
    }
    pub(crate) fn owns_gum_parent(
        &self,
        session: &str,
        parent: u32,
        reporter: u32,
        start: u64,
    ) -> bool {
        self.0.lock().is_ok_and(|state| {
            state.hosts.values().any(|host| {
                host.session_id == session
                    && host.status.backend != Backend::LinuxPtrace
                    && host.status.root_pid == parent
                    && host.reporters.get(&reporter) == Some(&start)
                    && crate::session::process_start_time(parent)
                        .is_none_or(|actual| host.status.root_start_time == Some(actual))
            })
        })
    }
    pub(crate) fn report_exit(&self, event: ProcessExit, peer: u32) -> io::Result<()> {
        let peer_start = crate::session::process_start_time(peer)
            .ok_or_else(|| io::Error::other("exit reporter process is unavailable"))?;
        if !Self::process_is_gone(event.pid, event.start_time) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "reported process incarnation is still alive or unknown",
            ));
        }
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("engine registry poisoned"))?;
        let host = state
            .hosts
            .values()
            .find(|host| {
                if host.session_id != event.session_id {
                    return false;
                }
                match event.source.as_str() {
                    "ptrace_process" | "ptrace_tree" => {
                        host.status.backend == Backend::LinuxPtrace
                            && host.status.host_pid == peer
                            && host.status.host_start_time == Some(peer_start)
                    }
                    "gum_launcher" | "gum_tree" => {
                        host.status.backend != Backend::LinuxPtrace
                            && host.status.root_pid == event.pid
                            && host.status.host_start_time == Some(event.start_time)
                            && host.reporters.get(&peer) == Some(&peer_start)
                    }
                    _ => false,
                }
            })
            .map(|h| h.status.clone())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "exit reporter does not own this Host incarnation",
                )
            })?;
        let birth = (event.session_id.clone(), event.pid, event.start_time);
        let tree_anchor = matches!(event.source.as_str(), "ptrace_tree" | "gum_tree")
            && host.root_pid == event.pid
            && host.root_start_time == Some(event.start_time);
        if !state.births.contains_key(&birth)
            && state.hosts.get(&host.host_id).and_then(|h| h.last_exit)
                != Some((event.pid, event.start_time))
            && !tree_anchor
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "exit process birth was not registered",
            ));
        }
        let complete = event.source != "ptrace_process";
        Self::record_exit(
            &mut state,
            &host,
            event.pid,
            event.exit_code,
            event.signal,
            complete,
        )?;
        state.births.remove(&birth);
        if let Some(owner) = state.hosts.get_mut(&host.host_id) {
            owner.last_exit = Some((event.pid, event.start_time));
        }
        Ok(())
    }
    fn record_exit(
        state: &mut State,
        host: &HostStatus,
        pid: u32,
        code: Option<i32>,
        signal: Option<i32>,
        complete: bool,
    ) -> io::Result<()> {
        let key = key(host).ok_or_else(|| io::Error::other("Host process birth is unavailable"))?;
        if state.exits.len() >= 4096 && !state.exits.contains_key(&key) {
            return Err(io::Error::other("Engine exit evidence limit reached"));
        }
        let exit = state.exits.entry(key).or_default();
        exit.last_seen = Some(std::time::Instant::now());
        if completed_normally(host.backend, code, signal) {
            if complete && exit.failure.is_none() {
                exit.normal_completed = true;
            }
        } else {
            exit.failure = Some((
                unix_timestamp_ms(),
                format!("managed process {pid} failed: exit_code={code:?} signal={signal:?}"),
            ));
            exit.normal_completed = false;
        }
        Ok(())
    }
    pub(crate) fn retire_exit_evidence(
        &self,
        referenced: &std::collections::BTreeSet<(String, u32, u64)>,
    ) {
        if let Ok(mut state) = self.0.lock() {
            Self::prune_exits(&mut state, referenced, std::time::Instant::now());
        }
    }
    fn prune_exits(
        state: &mut State,
        referenced: &std::collections::BTreeSet<(String, u32, u64)>,
        now: std::time::Instant,
    ) {
        if state.exits.is_empty() {
            return;
        }
        let online = state
            .hosts
            .values()
            .filter(|h| h.status.online)
            .filter_map(|h| key(&h.status))
            .collect::<std::collections::BTreeSet<_>>();
        state.exits.retain(|identity, evidence| {
            referenced.contains(identity)
                || online.contains(identity)
                || evidence
                    .last_seen
                    .is_none_or(|last| now.duration_since(last).as_secs() < 30)
        });
    }
    #[cfg(windows)]
    pub(crate) fn windows_process_exit(&self, session: &str, pid: u32, start: u64, code: u32) {
        if let Ok(mut state) = self.0.lock() {
            let host = state
                .hosts
                .values()
                .find(|h| {
                    h.session_id == session
                        && h.status.backend == Backend::WindowsGum
                        && h.status.host_pid == pid
                        && h.status.host_start_time == Some(start)
                })
                .map(|h| h.status.clone());
            if let Some(host) = host {
                let _ = Self::record_exit(&mut state, &host, pid, Some(code as i32), None, true);
                state.births.remove(&(session.into(), pid, start));
            }
        }
    }
    pub(crate) fn normal_exit(&self, identity: &crate::upgrade::Identity) -> bool {
        self.0
            .lock()
            .ok()
            .and_then(|s| {
                s.exits
                    .get(&(
                        identity.session_id.clone(),
                        identity.host_pid,
                        identity.host_start_time,
                    ))
                    .map(|exit| exit.normal_completed && exit.failure.is_none())
            })
            .unwrap_or(false)
    }
    pub(crate) fn process_failure(
        &self,
        identity: &crate::upgrade::Identity,
        since: u64,
    ) -> Option<String> {
        let state = self.0.lock().ok()?;
        state
            .exits
            .get(&(
                identity.session_id.clone(),
                identity.host_pid,
                identity.host_start_time,
            ))?
            .failure
            .as_ref()
            .filter(|(at, _)| *at >= since)
            .map(|(_, reason)| reason.clone())
    }
    pub(crate) fn process_is_gone(pid: u32, start: u64) -> bool {
        if let Some(actual) = crate::session::process_start_time(pid) {
            if actual != start {
                return true;
            }
        }
        #[cfg(target_os = "linux")]
        {
            match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                Ok(stat) => stat
                    .rsplit_once(") ")
                    .is_some_and(|(_, tail)| tail.starts_with("Z ")),
                Err(error) => error.kind() == io::ErrorKind::NotFound,
            }
        }
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::{
                Foundation::{CloseHandle, GetLastError, ERROR_INVALID_PARAMETER, STILL_ACTIVE},
                System::Threading::{
                    GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
                },
            };
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                return GetLastError() == ERROR_INVALID_PARAMETER;
            }
            let mut code = STILL_ACTIVE as u32;
            let gone = GetExitCodeProcess(handle, &mut code) != 0 && code != STILL_ACTIVE as u32;
            CloseHandle(handle);
            gone
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(source: &str) -> ProcessExit {
        ProcessExit {
            session_id: "exit-unit".into(),
            pid: std::process::id(),
            start_time: crate::session::process_start_time(std::process::id()).unwrap(),
            exit_code: Some(0),
            signal: None,
            source: source.into(),
            issued_at_ms: unix_timestamp_ms(),
        }
    }

    #[test]
    fn application_exit_codes_are_distinct_from_signals_unknown_and_windows_exceptions() {
        for backend in [Backend::LinuxPtrace, Backend::LinuxGum, Backend::WindowsGum] {
            for code in [0, 1, 4, 42, 127, 139, 255] {
                assert!(completed_normally(backend, Some(code), None));
                assert!(!completed_normally(backend, Some(code), Some(11)));
            }
            assert!(!completed_normally(backend, None, None));
            for status in [0x8000_0003u32, 0xC000_0005, 0xC000_0409, u32::MAX] {
                assert!(!completed_normally(backend, Some(status as i32), None));
            }
        }
        assert!(!completed_normally(Backend::LinuxGum, Some(256), None));
        assert!(completed_normally(Backend::WindowsGum, Some(256), None));
    }

    #[test]
    fn exit_proof_binds_incarnation_status_source_and_purpose() {
        let event = event("gum_launcher");
        let proof = event.proof(b"owner").unwrap();
        assert!(event.authenticate(b"owner", &proof));
        assert!(!event.authenticate(b"different owner", &proof));
        let mut changed = event.clone();
        changed.start_time += 1;
        assert!(!changed.authenticate(b"owner", &proof));
        changed = event.clone();
        changed.exit_code = Some(1);
        assert!(!changed.authenticate(b"owner", &proof));
        changed = event.clone();
        changed.source = "ptrace_tree".into();
        assert!(!changed.authenticate(b"owner", &proof));
        changed = event.clone();
        changed.session_id = "other-session".into();
        assert!(!changed.authenticate(b"owner", &proof));
        let other_purpose =
            crate::session::config_update_proof(b"owner", &serde_json::to_string(&event).unwrap())
                .unwrap();
        assert!(!event.authenticate(b"owner", &other_purpose));
    }

    #[test]
    fn ptrace_process_exit_does_not_finish_tree_and_failure_cannot_be_erased() {
        let registry = EngineHosts::default();
        let mut event = event("ptrace_process");
        let peer = event.pid;
        let birth = event.start_time;
        // A reused target PID represents a conclusively terminated old target.
        // The authenticated manager remains the live current incarnation.
        event.start_time += 1;
        let registration = registry
            .register(
                event.session_id.clone(),
                String::new(),
                Backend::LinuxPtrace,
                peer,
                event.pid,
                1,
                Some(event.start_time),
                Some(birth),
                host::report(&hyperhub_engine::resident()).unwrap(),
            )
            .unwrap();
        let host = registry.host(Some(&registration.id)).pop().unwrap();
        let identity = crate::upgrade::Identity {
            session_id: host.session_id.clone(),
            backend: host.backend,
            host_pid: peer,
            host_start_time: birth,
            member_instance: 1,
            root_pid: event.pid,
            root_start_time: event.start_time,
        };
        assert!(registry.report_exit(event.clone(), peer).is_ok());
        assert!(!registry.normal_exit(&identity));
        let mut invalid = event.clone();
        invalid.session_id = "other".into();
        assert!(registry.report_exit(invalid, peer).is_err());
        invalid = event.clone();
        invalid.start_time += 1;
        assert!(registry.report_exit(invalid, peer).is_err());
        invalid = event.clone();
        invalid.source = "gum_launcher".into();
        assert!(registry.report_exit(invalid, peer).is_err());
        invalid = event.clone();
        invalid.start_time = birth;
        assert_eq!(
            registry.report_exit(invalid, peer).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        event.source = "ptrace_tree".into();
        registry.report_exit(event.clone(), peer).unwrap();
        assert!(registry.normal_exit(&identity));
        event.exit_code = Some(139);
        registry.report_exit(event.clone(), peer).unwrap();
        assert!(registry.normal_exit(&identity));
        assert!(registry.process_failure(&identity, 0).is_none());
        event.signal = Some(11);
        registry.report_exit(event.clone(), peer).unwrap();
        assert!(!registry.normal_exit(&identity));
        assert!(registry
            .process_failure(&identity, 0)
            .unwrap()
            .contains("139"));
        event.exit_code = Some(0);
        event.signal = None;
        registry.report_exit(event, peer).unwrap();
        assert!(!registry.normal_exit(&identity));
        assert!(registry
            .process_failure(&identity, unix_timestamp_ms() + 1)
            .is_none());
    }

    #[test]
    fn a_gum_launcher_must_match_its_session_and_historical_parent_incarnation() {
        let registry = EngineHosts::default();
        let pid = std::process::id();
        let birth = crate::session::process_start_time(pid).unwrap();
        let registration = registry
            .register(
                "tree-session".into(),
                String::new(),
                Backend::LinuxGum,
                u32::MAX,
                u32::MAX,
                1,
                Some(42),
                Some(42),
                host::report(&hyperhub_engine::resident()).unwrap(),
            )
            .unwrap();
        registry
            .authorize_exit_reporter(&registration.id, pid, birth)
            .unwrap();
        assert!(registry.owns_gum_parent("tree-session", u32::MAX, pid, birth));
        assert!(!registry.owns_gum_parent("other-session", u32::MAX, pid, birth));
        assert!(!registry.owns_gum_parent("tree-session", u32::MAX, pid, birth + 1));
        assert!(!registry.owns_gum_parent("tree-session", pid, pid, birth));
        let reused = registry
            .register(
                "tree-session".into(),
                String::new(),
                Backend::LinuxGum,
                pid,
                pid,
                2,
                Some(birth + 1),
                Some(birth + 1),
                host::report(&hyperhub_engine::resident()).unwrap(),
            )
            .unwrap();
        registry
            .authorize_exit_reporter(&reused.id, pid, birth)
            .unwrap();
        assert!(!registry.owns_gum_parent("tree-session", pid, pid, birth));
    }

    #[test]
    fn a_ptrace_tree_can_finish_at_its_original_anchor_after_later_child_exits() {
        let registry = EngineHosts::default();
        let mut root = event("ptrace_process");
        let peer = root.pid;
        let peer_birth = root.start_time;
        root.start_time += 1;
        let registration = registry
            .register(
                root.session_id.clone(),
                String::new(),
                Backend::LinuxPtrace,
                peer,
                root.pid,
                1,
                Some(root.start_time),
                Some(peer_birth),
                host::report(&hyperhub_engine::resident()).unwrap(),
            )
            .unwrap();
        registry.report_exit(root.clone(), peer).unwrap();
        for child_birth in 1..=4 {
            registry
                .note_member_birth(&root.session_id, u32::MAX, child_birth)
                .unwrap();
            let mut child = root.clone();
            child.pid = u32::MAX;
            child.start_time = child_birth;
            registry.report_exit(child, peer).unwrap();
        }
        assert!(registry.0.lock().unwrap().births.is_empty());
        root.source = "ptrace_tree".into();
        registry.report_exit(root, peer).unwrap();
        let state = registry.0.lock().unwrap();
        assert!(
            state
                .exits
                .get(&key(&state.hosts[&registration.id].status).unwrap())
                .unwrap()
                .normal_completed
        );
    }

    #[test]
    fn birth_capacity_reclaims_only_after_a_full_gone_evidence_window() {
        let mut state = State::default();
        for start in 1..=8192 {
            state
                .births
                .insert(("expired-tree".into(), u32::MAX, start), None);
        }
        let now = std::time::Instant::now();
        EngineHosts::prune_births(&mut state, now);
        assert_eq!(state.births.len(), 8192);
        assert!(EngineHosts::record_birth(&mut state, "new-tree", u32::MAX, 8193).is_err());
        EngineHosts::prune_births(&mut state, now + std::time::Duration::from_secs(29));
        assert_eq!(state.births.len(), 8192);
        EngineHosts::prune_births(&mut state, now + std::time::Duration::from_secs(30));
        assert!(state.births.is_empty());
        EngineHosts::record_birth(&mut state, "new-tree", u32::MAX, 8193).unwrap();
        assert_eq!(state.births.len(), 1);
        assert!(!state
            .births
            .contains_key(&("expired-tree".into(), u32::MAX, 1)));
        let mut expired = event("gum_tree");
        expired.issued_at_ms = unix_timestamp_ms().saturating_sub(30_001);
        let proof = expired.proof(b"owner").unwrap();
        assert!(!expired.authenticate(b"owner", &proof));
    }

    #[test]
    fn exit_capacity_preserves_referenced_failures_and_unconsumed_recent_reports() {
        let now = std::time::Instant::now();
        let mut state = State::default();
        for birth in 1..=4096 {
            state.exits.insert(
                ("tree".into(), u32::MAX, birth),
                ExitState {
                    normal_completed: false,
                    failure: Some((1, "unconsumed failure".into())),
                    last_seen: Some(now),
                },
            );
        }
        let referenced = std::collections::BTreeSet::from([("tree".into(), u32::MAX, 1)]);
        EngineHosts::prune_exits(
            &mut state,
            &referenced,
            now + std::time::Duration::from_secs(29),
        );
        assert_eq!(state.exits.len(), 4096);
        EngineHosts::prune_exits(
            &mut state,
            &referenced,
            now + std::time::Duration::from_secs(30),
        );
        assert_eq!(state.exits.len(), 1);
        assert!(state.exits.values().next().unwrap().failure.is_some());
        EngineHosts::prune_exits(
            &mut state,
            &Default::default(),
            now + std::time::Duration::from_secs(31),
        );
        assert!(state.exits.is_empty());
        let registry = EngineHosts::default();
        let pid = std::process::id();
        let birth = crate::session::process_start_time(pid).unwrap();
        let registration = registry
            .register(
                "live-tree".into(),
                String::new(),
                Backend::LinuxPtrace,
                pid,
                pid,
                1,
                Some(birth),
                Some(birth),
                host::report(&hyperhub_engine::resident()).unwrap(),
            )
            .unwrap();
        let host = registry.host(Some(&registration.id)).pop().unwrap();
        {
            let mut state = registry.0.lock().unwrap();
            EngineHosts::record_exit(&mut state, &host, pid, Some(1), None, true).unwrap();
            EngineHosts::prune_exits(
                &mut state,
                &Default::default(),
                now + std::time::Duration::from_secs(60),
            );
            assert_eq!(
                state.exits.len(),
                1,
                "an online Host can still consume its failure"
            );
        }
        drop(registration);
        let mut state = registry.0.lock().unwrap();
        EngineHosts::prune_exits(
            &mut state,
            &Default::default(),
            now + std::time::Duration::from_secs(60),
        );
        assert!(state.exits.is_empty());
    }
}
