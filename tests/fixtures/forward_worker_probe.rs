//! Standalone source fixture for the same private worker entry used by the CLI.
fn main() {
    let threads = std::thread::available_parallelism().map_or(1, |count| count.get().min(4));
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .max_blocking_threads(32)
        .enable_all()
        .build()
        .unwrap()
        .block_on(run());
}
async fn run() {
    if std::env::args().nth(1).as_deref() != Some("forward-worker") {
        eprintln!("expected private forward-worker invocation");
        std::process::exit(2);
    }
    if let Err(error) = hyperhub_core::socks::SocksService::run_forward_worker().await {
        eprintln!("forwarding worker: {error}");
        std::process::exit(1);
    }
}
