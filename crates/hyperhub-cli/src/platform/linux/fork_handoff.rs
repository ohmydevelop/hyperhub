//! Private manager-owned fork reservations. An accepted Begin keeps the manager
//! alive until explicit cancellation or complete child enrollment. Timeouts are
//! failures, never evidence that the process tree has drained.
use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const MAX_LEASES: usize = 256;
const LEASE_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const WORKERS: usize = 4;
const REQUEST_SIZE: usize = 70;
const REPLY_SIZE: usize = 33;
type LeaseId = [u8; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    pid: u32,
    birth: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ForkCandidate {
    pub lease_id: LeaseId,
    pub parent_pid: u32,
    pub child_pid: u32,
    pub child_birth: u64,
    pub ready: bool,
}

pub(super) struct ForkSnapshot {
    pub pending_count: usize,
    pub candidates: Vec<ForkCandidate>,
}

struct Reservation {
    parent: Identity,
    child: Option<Identity>,
    ready: bool,
    attached: bool,
    deadline: Instant,
}

#[derive(Default)]
struct State {
    parents: HashMap<u32, u64>,
    leases: HashMap<LeaseId, Reservation>,
    failure: Option<String>,
}

impl State {
    fn check(&mut self) -> io::Result<()> {
        if self.failure.is_none()
            && self
                .leases
                .values()
                .any(|lease| Instant::now() >= lease.deadline)
        {
            self.failure = Some("fork handoff expired before child enrollment".into());
        }
        match &self.failure {
            Some(message) => Err(io::Error::other(message.clone())),
            None => Ok(()),
        }
    }

    fn request(&mut self, op: u8, peer: Identity, lease_id: LeaseId) -> Result<LeaseId, u8> {
        self.check().map_err(|_| 4)?;
        match op {
            1 => {
                if lease_id != [0; 32] {
                    return Err(2);
                }
                if self.parents.get(&peer.pid) != Some(&peer.birth) {
                    return Err(1);
                }
                if self.leases.len() >= MAX_LEASES {
                    return Err(3);
                }
                let id = loop {
                    let id = rand::random();
                    if id != [0; 32] && !self.leases.contains_key(&id) {
                        break id;
                    }
                };
                self.leases.insert(
                    id,
                    Reservation {
                        parent: peer,
                        child: None,
                        ready: false,
                        attached: false,
                        deadline: Instant::now() + LEASE_TIMEOUT,
                    },
                );
                Ok(id)
            }
            2 | 3 | 4 | 5 => {
                if lease_id == [0; 32] {
                    return Err(2);
                }
                let lease = self.leases.get_mut(&lease_id).ok_or(5)?;
                if op == 2 {
                    if peer.pid == lease.parent.pid
                        || lease.child.is_some_and(|child| child != peer)
                    {
                        return Err(6);
                    }
                    lease.child = Some(peer);
                } else if op == 4 {
                    if lease.child != Some(peer) {
                        return Err(1);
                    }
                    lease.ready = true;
                } else if op == 5 {
                    if peer != lease.parent {
                        return Err(1);
                    }
                    if !lease.attached {
                        return Err(8);
                    }
                } else {
                    if peer != lease.parent {
                        return Err(1);
                    }
                    if lease.child.is_some() {
                        return Err(6);
                    }
                    self.leases.remove(&lease_id);
                }
                Ok(lease_id)
            }
            _ => Err(2),
        }
    }
}

pub(super) struct ForkHandoffBroker {
    directory: PathBuf,
    socket: PathBuf,
    secret: [u8; 32],
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
}

impl ForkHandoffBroker {
    pub fn new() -> io::Result<Self> {
        let directory = std::env::temp_dir().join(format!(
            "hfg-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
        let socket = directory.join("s");
        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(error) => {
                let _ = std::fs::remove_dir(&directory);
                return Err(error);
            }
        };
        let mut broker = Self {
            directory,
            socket,
            secret: rand::random(),
            state: Arc::new(Mutex::new(State::default())),
            stop: Arc::new(AtomicBool::new(false)),
            workers: Vec::new(),
        };
        std::fs::set_permissions(&broker.socket, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        for _ in 0..WORKERS {
            let listener = listener.try_clone()?;
            let state = broker.state.clone();
            let stop = broker.stop.clone();
            let secret = broker.secret;
            broker.workers.push(
                std::thread::Builder::new()
                    .name("hyperhub-fork-handoff".into())
                    .spawn(move || {
                        while !stop.load(Ordering::Acquire) {
                            match listener.accept() {
                                Ok((stream, _)) => serve(stream, &secret, &state),
                                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                    std::thread::sleep(Duration::from_millis(5));
                                }
                                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                                Err(error) => {
                                    if let Ok(mut state) = state.lock() {
                                        state.failure =
                                            Some(format!("fork broker accept failed: {error}"));
                                    }
                                    break;
                                }
                            }
                        }
                    })?,
            );
        }
        Ok(broker)
    }

    pub fn environment(&self) -> [(OsString, OsString); 2] {
        let secret: String = self
            .secret
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        [
            (
                "HYPERHUB_FORK_HANDOFF_SOCKET".into(),
                self.socket.clone().into_os_string(),
            ),
            ("HYPERHUB_FORK_HANDOFF_SECRET".into(), secret.into()),
        ]
    }

    pub fn allow_parent(&self, pid: u32, birth: u64) -> io::Result<()> {
        if identity(pid)? != (Identity { pid, birth }) {
            return Err(io::Error::other("fork parent process identity changed"));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("fork broker poisoned"))?;
        state.check()?;
        state.parents.insert(pid, birth);
        Ok(())
    }

    pub fn snapshot(&self) -> io::Result<ForkSnapshot> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("fork broker poisoned"))?;
        state.check()?;
        // Admission history is not a process-lifetime registry. Remove only
        // identities proven dead or reused; accepted leases keep their own
        // parent identity and remain pending even after that parent's exit.
        state
            .parents
            .retain(|pid, birth| match live_identity(*pid) {
                Ok(Some(current)) => current.birth == *birth,
                Ok(None) => false,
                Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                Err(_) => true,
            });
        Ok(ForkSnapshot {
            pending_count: state.leases.len(),
            candidates: state
                .leases
                .iter()
                .filter_map(|(id, lease)| {
                    let child = lease.child?;
                    Some(ForkCandidate {
                        lease_id: *id,
                        parent_pid: lease.parent.pid,
                        child_pid: child.pid,
                        child_birth: child.birth,
                        ready: lease.ready,
                    })
                })
                .collect(),
        })
    }

    /// Keep the fork caller alive until Frida has a retained child session.
    /// An automatic resume cannot unload an entry with that session attached.
    pub fn mark_attached(&self, lease_id: LeaseId) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("fork broker poisoned"))?;
        state.check()?;
        let lease = state
            .leases
            .get_mut(&lease_id)
            .ok_or_else(|| io::Error::other("unknown fork handoff"))?;
        let child = lease
            .child
            .ok_or_else(|| io::Error::other("fork handoff has no candidate"))?;
        if identity(child.pid)? != child {
            return Err(io::Error::other("fork child process identity changed"));
        }
        lease.attached = true;
        Ok(())
    }

    /// The manager calls this only after the exact candidate completed enrollment.
    pub fn complete(&self, lease_id: LeaseId) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("fork broker poisoned"))?;
        state.check()?;
        let lease = state
            .leases
            .get(&lease_id)
            .ok_or_else(|| io::Error::other("unknown fork handoff"))?;
        if !lease.attached {
            return Err(io::Error::other("fork child session is not attached"));
        }
        let child = lease
            .child
            .ok_or_else(|| io::Error::other("fork handoff has no candidate"))?;
        if identity(child.pid)? != child {
            return Err(io::Error::other("fork child process identity changed"));
        }
        state.parents.insert(child.pid, child.birth);
        state.leases.remove(&lease_id);
        Ok(())
    }
}

impl Drop for ForkHandoffBroker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_dir(&self.directory);
    }
}

fn identity(pid: u32) -> io::Result<Identity> {
    live_identity(pid)?.ok_or_else(|| io::Error::other("fork peer has exited"))
}

fn live_identity(pid: u32) -> io::Result<Option<Identity>> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let tail = stat
        .rsplit_once(") ")
        .ok_or_else(|| io::Error::other("invalid process stat"))?
        .1;
    let mut fields = tail.split_whitespace();
    if fields.next() == Some("Z") {
        return Ok(None);
    }
    let birth = fields
        .nth(18)
        .and_then(|field| field.parse().ok())
        .ok_or_else(|| io::Error::other("missing process birth"))?;
    Ok(Some(Identity { pid, birth }))
}

fn peer_identity(stream: &UnixStream) -> io::Result<Identity> {
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut peer as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of::<libc::ucred>() || peer.pid <= 0 {
        return Err(io::Error::other("invalid fork peer credentials"));
    }
    identity(peer.pid as u32)
}

// Wire: HHFH | version=1 | opcode (Begin=1, Candidate=2, Cancel=3, Ready=4,
// ParentAttachedStatus=5)
// | secret[32] | lease[32]. Ready proves the claimed child passed Frida recovery.
// Reply: status (0 ok, 1 auth, 2 format, 3 capacity, 4 expired,
// 5 unknown, 6 conflict, 7 internal, 8 still pending) | lease[32] (zero on failure).
fn serve(mut stream: UnixStream, secret: &[u8; 32], state: &Mutex<State>) {
    let result = (|| -> Result<LeaseId, u8> {
        stream
            .set_read_timeout(Some(REQUEST_TIMEOUT))
            .map_err(|_| 7)?;
        stream
            .set_write_timeout(Some(REQUEST_TIMEOUT))
            .map_err(|_| 7)?;
        let peer = peer_identity(&stream).map_err(|_| 1)?;
        let mut request = [0; REQUEST_SIZE];
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        let mut remaining = request.as_mut_slice();
        while !remaining.is_empty() {
            let timeout = deadline.checked_duration_since(Instant::now()).ok_or(2)?;
            stream.set_read_timeout(Some(timeout)).map_err(|_| 7)?;
            match stream.read(remaining) {
                Ok(0) => return Err(2),
                Ok(count) => remaining = &mut remaining[count..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(2),
            }
        }
        if &request[..4] != b"HHFH" || request[4] != 1 {
            return Err(2);
        }
        // Constant work for the capability comparison, including mismatches.
        if request[6..38]
            .iter()
            .zip(secret)
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            != 0
        {
            return Err(1);
        }
        let lease_id = request[38..70].try_into().map_err(|_| 2)?;
        state
            .lock()
            .map_err(|_| 7)?
            .request(request[5], peer, lease_id)
    })();
    let mut reply = [0; REPLY_SIZE];
    match result {
        Ok(id) => reply[1..].copy_from_slice(&id),
        Err(status) => reply[0] = status,
    }
    let _ = stream.write_all(&reply);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    struct TestChild(std::process::Child);
    impl Drop for TestChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn me() -> Identity {
        identity(std::process::id()).unwrap()
    }

    fn exchange(broker: &ForkHandoffBroker, op: u8, lease: LeaseId) -> (u8, LeaseId) {
        let mut stream = UnixStream::connect(&broker.socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut request = [0u8; REQUEST_SIZE];
        request[..4].copy_from_slice(b"HHFH");
        request[4] = 1;
        request[5] = op;
        request[6..38].copy_from_slice(&broker.secret);
        request[38..].copy_from_slice(&lease);
        stream.write_all(&request).unwrap();
        let mut reply = [0u8; REPLY_SIZE];
        stream.read_exact(&mut reply).unwrap();
        (reply[0], reply[1..].try_into().unwrap())
    }

    #[test]
    fn begin_reserves_until_explicit_parent_cancel_and_cleans_private_socket() {
        let broker = ForkHandoffBroker::new().unwrap();
        let socket = broker.socket.clone();
        let directory = broker.directory.clone();
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(exchange(&broker, 1, [0; 32]).0, 1);
        assert!(broker.allow_parent(me().pid, me().birth + 1).is_err());
        broker.allow_parent(me().pid, me().birth).unwrap();
        let (status, lease) = exchange(&broker, 1, [0; 32]);
        assert_eq!(status, 0);
        assert_ne!(lease, [0; 32]);
        let snapshot = broker.snapshot().unwrap();
        assert_eq!(snapshot.pending_count, 1);
        assert!(snapshot.candidates.is_empty());
        assert!(
            broker.mark_attached(lease).is_err(),
            "an unclaimed lease has no attached child"
        );
        assert!(broker.mark_attached([0x24; 32]).is_err());
        assert!(broker.complete(lease).is_err());
        assert_eq!(
            exchange(&broker, 2, lease).0,
            6,
            "parent cannot claim its own child"
        );
        assert_eq!(exchange(&broker, 3, lease), (0, lease));
        assert_eq!(broker.snapshot().unwrap().pending_count, 0);
        assert_eq!(exchange(&broker, 3, lease).0, 5);
        drop(broker);
        assert!(!socket.exists());
        assert!(!directory.exists());
    }

    #[test]
    fn dead_parent_reservation_is_not_pruned_and_expiration_is_sticky_failure() {
        let mut state = State::default();
        let parent = Identity {
            pid: 100,
            birth: 42,
        };
        let child = Identity {
            pid: 101,
            birth: 43,
        };
        state.parents.insert(parent.pid, parent.birth);
        let lease = state.request(1, parent, [0; 32]).unwrap();
        state.parents.remove(&parent.pid);
        assert_eq!(state.request(2, child, lease), Ok(lease));
        assert_eq!(state.request(2, child, lease), Ok(lease));
        assert_eq!(
            state.request(2, Identity { birth: 44, ..child }, lease),
            Err(6)
        );
        assert_eq!(state.request(3, child, lease), Err(1));
        assert_eq!(state.request(3, parent, lease), Err(6));
        assert_eq!(state.leases.len(), 1);
        state.leases.get_mut(&lease).unwrap().deadline = Instant::now() - Duration::from_secs(1);
        assert!(state.check().is_err());
        state.leases.clear();
        assert!(
            state.check().is_err(),
            "expiration cannot become a normal drained tree"
        );
    }

    #[test]
    fn ready_requires_the_exact_claimed_child_and_preserves_pending_reservation() {
        let mut state = State::default();
        let parent = me();
        let child = Identity {
            pid: parent.pid + 1,
            birth: parent.birth + 1,
        };
        state.parents.insert(parent.pid, parent.birth);
        let lease = state.request(1, parent, [0; 32]).unwrap();
        assert_eq!(state.request(4, child, lease), Err(1));
        assert_eq!(state.request(2, child, lease), Ok(lease));
        assert!(!state.leases[&lease].ready);
        assert_eq!(state.request(4, parent, lease), Err(1));
        assert_eq!(
            state.request(
                4,
                Identity {
                    birth: child.birth + 1,
                    ..child
                },
                lease
            ),
            Err(1)
        );
        assert_eq!(state.request(4, child, lease), Ok(lease));
        assert_eq!(state.request(4, child, lease), Ok(lease));
        assert!(state.leases[&lease].ready);
        assert_eq!(state.leases.len(), 1, "Ready does not complete enrollment");
    }

    #[test]
    fn attached_status_requires_original_parent_and_does_not_consume_the_handoff() {
        let mut state = State::default();
        let parent = me();
        let child = Identity {
            pid: parent.pid + 1,
            birth: parent.birth + 1,
        };
        state.parents.insert(parent.pid, parent.birth);
        let lease = state.request(1, parent, [0; 32]).unwrap();
        assert_eq!(state.request(5, parent, [0; 32]), Err(2));
        assert_eq!(state.request(5, parent, [0x24; 32]), Err(5));
        assert_eq!(state.request(5, child, lease), Err(1));
        assert_eq!(
            state.request(
                5,
                Identity {
                    birth: parent.birth + 1,
                    ..parent
                },
                lease
            ),
            Err(1)
        );
        assert_eq!(state.request(5, parent, lease), Err(8));
        assert_eq!(state.request(2, child, lease), Ok(lease));
        assert_eq!(state.request(5, parent, lease), Err(8));
        state.leases.get_mut(&lease).unwrap().attached = true;
        assert_eq!(state.request(5, parent, lease), Ok(lease));
        assert_eq!(state.request(5, parent, lease), Ok(lease));
        assert_eq!(
            state.leases.len(),
            1,
            "parent acknowledgement does not complete enrollment"
        );
    }

    #[test]
    fn reservations_are_bounded_and_wrong_birth_is_unauthorized() {
        let mut state = State::default();
        let parent = me();
        state.parents.insert(parent.pid, parent.birth);
        assert_eq!(
            state.request(
                1,
                Identity {
                    birth: parent.birth + 1,
                    ..parent
                },
                [0; 32]
            ),
            Err(1)
        );
        for _ in 0..MAX_LEASES {
            assert!(state.request(1, parent, [0; 32]).is_ok());
        }
        assert_eq!(state.request(1, parent, [0; 32]), Err(3));
        assert_eq!(state.leases.len(), MAX_LEASES);
    }

    #[test]
    fn wire_rejects_bad_secret_version_and_unknown_operations() {
        let broker = ForkHandoffBroker::new().unwrap();
        for (version, op, secret, expected) in [
            (1, 1, [0; 32], 1),
            (2, 1, broker.secret, 2),
            (1, 9, broker.secret, 2),
        ] {
            let mut stream = UnixStream::connect(&broker.socket).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = [0; REQUEST_SIZE];
            request[..4].copy_from_slice(b"HHFH");
            request[4] = version;
            request[5] = op;
            request[6..38].copy_from_slice(&secret);
            stream.write_all(&request).unwrap();
            let mut reply = [0; REPLY_SIZE];
            stream.read_exact(&mut reply).unwrap();
            assert_eq!(reply[0], expected);
            assert_eq!(reply[1..], [0; 32]);
        }
        assert_eq!(broker.snapshot().unwrap().pending_count, 0);
    }

    #[test]
    fn stalled_request_cannot_hold_broker_shutdown_indefinitely() {
        let broker = ForkHandoffBroker::new().unwrap();
        let mut stream = UnixStream::connect(&broker.socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        stream.write_all(b"H").unwrap();
        let mut reply = [0; REPLY_SIZE];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(reply[0], 2);
        assert_eq!(broker.snapshot().unwrap().pending_count, 0);
        drop(broker);
    }

    #[test]
    fn snapshot_retires_exited_and_reused_parent_authorizations_but_keeps_leases() {
        let broker = ForkHandoffBroker::new().unwrap();
        let mut child = TestChild(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "platform::linux::fork_handoff::tests::peer_client",
                ])
                .env("HH_TEST_FORK_IDLE", "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let parent = identity(child.0.id()).unwrap();
        broker.allow_parent(parent.pid, parent.birth).unwrap();
        let lease = broker
            .state
            .lock()
            .unwrap()
            .request(1, parent, [0; 32])
            .unwrap();
        assert_eq!(broker.snapshot().unwrap().pending_count, 1);
        assert_eq!(
            broker.state.lock().unwrap().parents.get(&parent.pid),
            Some(&parent.birth)
        );
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let snapshot = broker.snapshot().unwrap();
        assert_eq!(snapshot.pending_count, 1);
        assert!(snapshot.candidates.is_empty());
        {
            let mut state = broker.state.lock().unwrap();
            assert!(!state.parents.contains_key(&parent.pid));
            assert_eq!(state.leases[&lease].parent, parent);
            // A current process with a different birth cannot inherit an old
            // authorization when the OS reuses its PID.
            state.parents.insert(me().pid, me().birth + 1);
        }
        assert_eq!(broker.snapshot().unwrap().pending_count, 1);
        assert!(broker.state.lock().unwrap().parents.is_empty());
    }

    #[test]
    fn real_child_peer_claim_is_bound_to_kernel_pid_and_completed_before_reuse() {
        let broker = ForkHandoffBroker::new().unwrap();
        broker.allow_parent(me().pid, me().birth).unwrap();
        let (status, lease) = exchange(&broker, 1, [0; 32]);
        assert_eq!(status, 0);
        let mut child = TestChild(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "platform::linux::fork_handoff::tests::peer_client",
                    "--nocapture",
                ])
                .envs(broker.environment())
                .env(
                    "HH_TEST_FORK_LEASE",
                    lease
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>(),
                )
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut stdout = std::io::BufReader::new(child.0.stdout.take().unwrap());
        let (send, recv) = std::sync::mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            use std::io::BufRead;
            let mut line = String::new();
            while stdout.read_line(&mut line).unwrap_or(0) != 0 {
                if line.trim() == "CLAIMED" {
                    let _ = send.send(());
                }
                line.clear();
            }
        });
        recv.recv_timeout(Duration::from_secs(5))
            .expect("child claim did not complete");
        let snapshot = broker.snapshot().unwrap();
        assert_eq!(snapshot.pending_count, 1);
        assert_eq!(
            snapshot.candidates,
            vec![ForkCandidate {
                lease_id: lease,
                parent_pid: me().pid,
                child_pid: child.0.id(),
                child_birth: identity(child.0.id()).unwrap().birth,
                ready: false,
            }]
        );
        assert!(
            broker.complete(lease).is_err(),
            "completion requires a retained child session"
        );
        assert_eq!(exchange(&broker, 5, lease).0, 8);
        let original_child = {
            let mut state = broker.state.lock().unwrap();
            let candidate = &mut state.leases.get_mut(&lease).unwrap().child;
            let original = candidate.unwrap();
            *candidate = Some(Identity {
                birth: original.birth + 1,
                ..original
            });
            original
        };
        assert!(
            broker.mark_attached(lease).is_err(),
            "a reused child PID cannot be admitted"
        );
        broker
            .state
            .lock()
            .unwrap()
            .leases
            .get_mut(&lease)
            .unwrap()
            .child = Some(original_child);
        broker.mark_attached(lease).unwrap();
        broker.mark_attached(lease).unwrap();
        assert_eq!(exchange(&broker, 5, lease), (0, lease));
        assert_eq!(broker.snapshot().unwrap().pending_count, 1);
        broker.complete(lease).unwrap();
        assert_eq!(exchange(&broker, 5, lease).0, 5);
        assert_eq!(broker.snapshot().unwrap().pending_count, 0);
        assert_eq!(
            broker
                .state
                .lock()
                .unwrap()
                .parents
                .get(&child.0.id())
                .copied(),
            Some(identity(child.0.id()).unwrap().birth)
        );
        child.0.stdin.take().unwrap().write_all(b"\n").unwrap();
        assert!(child.0.wait().unwrap().success());
        reader.join().unwrap();
    }

    // Run only in the fresh test child, so SO_PEERCRED observes a distinct PID.
    #[test]
    fn peer_client() {
        if std::env::var_os("HH_TEST_FORK_IDLE").is_some() {
            let mut release = [0];
            std::io::stdin().read_exact(&mut release).unwrap();
            return;
        }
        let Ok(lease) = std::env::var("HH_TEST_FORK_LEASE") else {
            return;
        };
        fn decode(value: &str) -> LeaseId {
            let mut bytes = [0; 32];
            for (i, byte) in bytes.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&value[2 * i..2 * i + 2], 16).unwrap();
            }
            bytes
        }
        let mut stream =
            UnixStream::connect(std::env::var_os("HYPERHUB_FORK_HANDOFF_SOCKET").unwrap()).unwrap();
        let mut request = [0; REQUEST_SIZE];
        request[..4].copy_from_slice(b"HHFH");
        request[4] = 1;
        request[5] = 2;
        request[6..38].copy_from_slice(&decode(
            &std::env::var("HYPERHUB_FORK_HANDOFF_SECRET").unwrap(),
        ));
        request[38..].copy_from_slice(&decode(&lease));
        stream.write_all(&request).unwrap();
        let mut reply = [0; REPLY_SIZE];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(reply[0], 0);
        println!("CLAIMED");
        std::io::stdout().flush().unwrap();
        let mut release = [0];
        std::io::stdin().read_exact(&mut release).unwrap();
    }
}
