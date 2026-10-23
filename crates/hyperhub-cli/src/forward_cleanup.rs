use hyperhub_core::socks::WorkerManager;
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Keep setup failures on the same bounded retirement path as normal stop.
pub(crate) struct Retirement {
    manager: WorkerManager,
    executable: PathBuf,
    key: Zeroizing<Vec<u8>>,
    finished: bool,
}
impl Retirement {
    pub(crate) fn new(manager: WorkerManager, executable: PathBuf, key: &[u8]) -> Self {
        Self {
            manager,
            executable,
            key: Zeroizing::new(key.to_vec()),
            finished: false,
        }
    }
    pub(crate) fn finish(&mut self) -> Result<(), String> {
        self.finished = true;
        self.manager
            .shutdown_cleanup(&self.executable, &self.key)
            .map_err(|error| format!("cannot retire forwarding worker cache: {error}"))
    }
}
impl Drop for Retirement {
    fn drop(&mut self) {
        if !self.finished {
            if let Err(error) = self.finish() {
                eprintln!("hyperhub: {error}");
            }
        }
    }
}
