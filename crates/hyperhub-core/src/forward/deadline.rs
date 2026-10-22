use super::wire::Wire;
use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// One independent timer thread per worker. It never waits on the channel's
/// send lock, so it can cancel a phase whose native send has stopped making IO.
pub(super) struct Scheduler(Arc<Shared>);
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}
struct State {
    stopped: bool,
    next: u64,
    deadlines: BTreeMap<(Instant, u64), ()>,
}
pub(super) struct Deadline {
    shared: Arc<Shared>,
    key: (Instant, u64),
}
impl Scheduler {
    pub(super) fn new(wire: Wire) -> io::Result<Self> {
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                stopped: false,
                next: 1,
                deadlines: BTreeMap::new(),
            }),
            changed: Condvar::new(),
        });
        let timer = shared.clone();
        std::thread::Builder::new()
            .name("hh-worker-deadline".into())
            .spawn(move || {
                let mut state = timer
                    .state
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                loop {
                    if state.stopped {
                        break;
                    }
                    if let Some((&(deadline, _), _)) = state.deadlines.first_key_value() {
                        let now = Instant::now();
                        if deadline <= now {
                            state.stopped = true;
                            state.deadlines.clear();
                            drop(state);
                            wire.shutdown();
                            return;
                        }
                        state = timer
                            .changed
                            .wait_timeout(state, deadline - now)
                            .unwrap_or_else(|error| error.into_inner())
                            .0;
                    } else {
                        state = timer
                            .changed
                            .wait(state)
                            .unwrap_or_else(|error| error.into_inner());
                    }
                }
            })?;
        Ok(Self(shared))
    }
    pub(super) fn start(&self, duration: Duration) -> io::Result<Deadline> {
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if state.stopped {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "worker deadline scheduler stopped",
            ));
        }
        if state.deadlines.len() >= 4097 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "worker deadline capacity reached",
            ));
        }
        let id = state.next;
        state.next = id
            .checked_add(1)
            .ok_or_else(|| io::Error::other("worker deadline sequence exhausted"))?;
        let key = (Instant::now() + duration, id);
        state.deadlines.insert(key, ());
        self.0.changed.notify_one();
        Ok(Deadline {
            shared: self.0.clone(),
            key,
        })
    }
}
impl Drop for Scheduler {
    fn drop(&mut self) {
        self.0
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .stopped = true;
        self.0.changed.notify_one();
    }
}
impl Drop for Deadline {
    fn drop(&mut self) {
        self.shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .deadlines
            .remove(&self.key);
        self.shared.changed.notify_one();
    }
}
