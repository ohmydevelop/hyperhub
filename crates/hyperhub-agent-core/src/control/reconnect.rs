use std::time::Duration;

/// Consecutive connection failures back off. A successfully authenticated
/// subscription starts a new outage, even if its read loop later disconnects.
#[derive(Default)]
pub(super) struct Backoff {
    failures: usize,
}

impl Backoff {
    pub(super) fn connected(&mut self) {
        self.failures = 0;
    }

    pub(super) fn disconnected(&mut self) -> Duration {
        const DELAYS_MS: [u64; 6] = [250, 1000, 2000, 5000, 10000, 30000];
        let delay = DELAYS_MS[self.failures.min(DELAYS_MS.len() - 1)];
        self.failures = self.failures.saturating_add(1);
        Duration::from_millis(delay)
    }
}

/// A backoff retains its normal schedule while the Host is live, but SDK
/// retirement must not wait through a thirty-second outage sleep.
pub(super) fn pause(delay: Duration) {
    pause_until(delay, crate::attachment::stopping_background)
}
fn pause_until(delay: Duration, stop: impl Fn() -> bool) {
    let deadline = std::time::Instant::now() + delay;
    while !stop() {
        let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) else {
            return;
        };
        if remaining.is_zero() {
            return;
        }
        std::thread::sleep(remaining.min(Duration::from_millis(25)));
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_recovered_subscription_starts_a_new_outage() {
        let mut backoff = Backoff::default();
        for _outage in 0..3 {
            for expected in [250, 1000, 2000, 5000, 10000, 30000, 30000, 30000] {
                assert_eq!(backoff.disconnected(), Duration::from_millis(expected));
            }
            backoff.connected();
        }
        assert_eq!(backoff.disconnected(), Duration::from_millis(250));
    }

    #[test]
    fn successful_updates_do_not_accumulate_failure_history() {
        let mut backoff = Backoff::default();
        for _update in 0..100 {
            backoff.connected();
        }
        assert_eq!(backoff.disconnected(), Duration::from_millis(250));
        assert_eq!(backoff.disconnected(), Duration::from_millis(1000));
    }
    #[test]
    fn retirement_interrupts_the_longest_outage_backoff() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        let started = std::time::Instant::now();
        let worker = std::thread::spawn(move || {
            pause_until(Duration::from_secs(30), || signal.load(Ordering::Acquire))
        });
        std::thread::sleep(Duration::from_millis(40));
        stop.store(true, Ordering::Release);
        worker.join().unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "retirement waited for outage backoff"
        );
    }
}
