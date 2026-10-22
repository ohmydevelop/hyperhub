//! Deliberately never reads its inherited IPC endpoint. Its bounded lifetime
//! makes a missing parent send deadline fail without leaving an orphan process.
fn main() {
    assert_eq!(std::env::args().nth(1).as_deref(), Some("forward-worker"));
    std::fs::write(
        env!("HH_SILENT_WORKER_MARKER"),
        b"entered without reading stdin",
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_secs(36));
}
