# Forward worker component benchmark

This benchmark evaluates the forwarding-worker component of the smooth-upgrade
project. The project also requires Engine, resident release coordination, native
hook, installer and platform validation. This component report does not replace
those checks or establish production capacity.

The maintainer accepted two engineering budgets for this component: a successful
`WorkerManager::prepare` returns within 30 seconds, and the synchronous
`WorkerManager::commit` pointer switch returns within 100 milliseconds. These
are local soft budgets, not a guarantee under arbitrary storage stalls, scheduler
starvation, suspend, or production load. Report every observation and maximum;
do not infer switch latency from total unit-test duration.

Each measured process group uses the same built executable and configuration.
The final CLI worker runtime has up to four Tokio worker threads and a maximum
of 32 blocking threads. The source probe uses the same settings. The benchmark
controller has four Tokio worker threads. Build profile, executable hash and size,
OS, CPU, quotas, memory, background load and runtime toolchain are evidence.

States are `baseline` (one active worker without an upgrade), `upgrade-0`,
`upgrade-1`, and `upgrade-4`. The suffix is the number of live old generations
after the measured switch. Existing streams keep old generations alive. Every
old stream must still echo a distinct token after the switch and after business
measurement. At four retained generations the manager's accepted capacity is
full; this workload does not attempt an additional prepare.

Prepare uses the executable already installed in the same manager cache. It
includes source hash verification, immutable cache verification, child creation,
private bootstrap, worker version handshake and health. It excludes computing the
caller's expected hash, fixture construction and pre-existing generation setup.
This is a warm-artifact measurement; cold download, archive extraction, installer
publication, Engine preflight and power-loss recovery are excluded. Commit timing
starts immediately before its synchronous call and ends immediately after return;
status assertions and finalize are outside that interval.

The local origin echoes bytes. The independent client oracle uses a 256-byte
payload containing client ID, sequence and deterministic remaining bytes, and
compares every received byte with its original request. There are eight closed
loop clients, 32 untimed warmup exchanges each, and 128 timed exchanges each.
A trial therefore offers and succeeds at exactly 1024 logical echoes, with zero
retries. Failures, refusals, cancellations or unfinished echoes invalidate that
trial rather than increasing throughput. A 10-second per-read limit prevents
unbounded hangs. This workload measures local forwarding overhead at a fixed
supply; it does not establish saturation throughput or open-arrival tail latency.

A separate 32-client admission burst times authentication, CONNECT and first
validated echo. It includes socket-offer and watchdog creation costs. A sampler
observes controller and worker RSS and thread counts about every millisecond
through preparation, admission and traffic. Sampled maxima are lower bounds on
instantaneous peaks: short-lived threads can start and stop between samples.
The controller includes test harness and local origin work. It is not a pure
resident Serve process measurement. Worker resources are reported separately.

There are five independent process-group trials per state. State order reverses
on alternate trials. Save every per-request latency and each resource sample.
Report medians and ranges across trial throughput; pooled request P95 is an
observed percentile, not an independent-trial confidence bound. Five prepare and
commit samples characterize this host only and do not support reliable P99.
This sample budget is an explicit local development budget, not a production
statistical power claim. No throughput, memory or thread acceptance threshold is
specified; comparisons are descriptive. A failed budget remains valid evidence
when the measurement and oracle are valid.

Before timing, run forwarding unit regressions and the native functional suite
in the same batch. A Unix subprocess exercises actual descriptor exhaustion:
failure to create the granted socket's cancellation probe must mark its original
shared socket complete. Control-loss state tests require immediate release of
ungranted claims while granted cancellation watchers remain available.
Native boolean decoding accepts exactly the one-byte BOOLEAN and four-byte
DWORD representations returned by Winsock providers, uses only the reported
bytes, and rejects all unsupported lengths. Its decoder regression runs on
every platform; Linux execution is not a claim of native Windows socket IO.
It covers actual TCP, stable Fake-IP lookup, centralized cancellation, retained
capacity, failed candidate preparation, control disconnection, TLS authority,
WebSocket and SSH flows. Each timed scenario also performs its own untimed byte
oracle and verifies the retained generation count. A preflight failure stops
formal measurement. The runner saves partial raw output and returns nonzero on
native assertions, missing samples or checker failures.

The model reviews the complete F01-F16 fault catalog for this narrow measurement
scope. Exclusions refer to this benchmark only. They do not remove functional,
security or platform obligations from the project. Native Linux and Windows
resource collectors exist. A run on one platform is not evidence of a run on the
other. macOS managed forwarding is outside this component workload.
The descriptor-exhaustion subprocess is Unix-only. A Windows run must report
that fault verification as not observed until an equivalent native fault test
exists; other Windows tests passing cannot fill that measurement-model gap.
