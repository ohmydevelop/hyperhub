# Local final CLI measurement r2, 2026-10-22

The final 0.2.13 r2 Linux CLI passed the declared forwarding-worker component
budgets on this host. This result supersedes the earlier local candidate report.
Project release and native Windows acceptance remain separate.

- CLI SHA-256: `419800bd707330167f7486f3d4d2c945e423a984c084568e4efe1a03f19f64a4` (153045216 bytes).
- Model digest: `6ec4c18b1e24d970e0d92e61c788a834d5d2e4a79205f630c2c210ad7df4dfe9`.
- Plan digest: `51e1a8ae5261a9fe2fb92557df70450084d5f8b88195f1faeac1f6ef0c9b1eda`.
- Forwarding unit preflight: 23/23 passed, 0.27 seconds.
- Functional preflight: 12/12 actual subprocess cases passed, 36.08 seconds.
- Native performance: 20 fresh worker groups, 62.52 seconds; 20480 validated
  echoes, 640 validated admissions, 15 upgrades, zero failed or retried work.
- Runner exit codes: unit preflight 0, native preflight 0, measurement 0,
  checker 0; budget failure false.
- Fixed checker report: [BENCHMARK.valid.md](BENCHMARK.valid.md).

The reviewed model binds five obligations, eleven explicit flow/fault boundaries
and four measured states. It retains all nine original boundaries and adds real
descriptor-exhaustion completion marking and ungranted control-loss cleanup.
The transfer regression also rejects a duplicate live identity across generations
before receiving CONNECT, while keeping both original streams usable.

The controller and candidate workers use release builds. Each state has five
fresh worker groups; the controller process and Tokio blocking pool are reused.
There are eight established echo clients and a separate 32-client admission
burst. Host background jobs were active; a supplementary host-pressure snapshot
is retained with the raw results. This is a local fixed-work comparison, not a
production capacity or tail-latency guarantee.

| State | Prepare median / max (ms) | Commit median / max (ms) | Echo median / observed P95 (us) | Echo/s median [min, max] | Admission median / max (ms) |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline | — | — | 79.051 / 160.687 | 48726 [24753, 74096] | 22.824 / 50.434 |
| upgrade-0 | 279.65908 / 600.37249 | 0.00312 / 0.00332 | 80.511 / 1370.719 | 36205 [8744, 67933] | 24.094 / 142.496 |
| upgrade-1 | 299.18230 / 444.46584 | 0.00160 / 0.00324 | 76.157 / 128.689 | 41407 [34372, 77376] | 23.754 / 49.821 |
| upgrade-4 | 227.76944 / 416.84552 | 0.00182 / 0.00342 | 78.258 / 304.504 | 37257 [27306, 73779] | 34.372 / 54.138 |

Every measured prepare was below 30000 ms (largest 600.37249 ms) and
every measured commit was below 100 ms (largest 0.00342 ms). All samples
are retained. Prepare means the warm-artifact `WorkerManager::prepare` API,
including supplied/cached executable verification and child bootstrap. Optional
native Engine preflight is covered by functional tests, not this timed operation.
Commit timestamps surround the synchronous pointer-switch API only.

Observed P95 uses nearest rank over the 5120 request samples in each state.
Requests within each group are correlated. Five group trials and overlapping
rate ranges do not establish a causal ordering between these states.

| State | Controller peak threads | Controller peak RSS (MiB) | Summed worker peak threads | Summed worker peak RSS (MiB) |
| --- | ---: | ---: | ---: | ---: |
| baseline | 46 | 122.20 | 7 | 21.61 |
| upgrade-0 | 53 | 269.31 | 14 | 37.12 |
| upgrade-1 | 53 | 275.84 | 14 | 41.04 |
| upgrade-4 | 74 | 272.58 | 35 | 98.22 |

Resource sampling spans generation setup, prepare, admission and echo work.
Thus even upgrade-0 can include both workers during preparation. Nominal 1 ms
sampling gives observed lower bounds for transient peaks. Controller totals
include the test origin, reused Tokio blocking pool and allocator high water;
they are not the production Serve RSS. Business/resource metrics have no
acceptance thresholds in this model.

The same r2 CLI passed isolated sensitivity checks with a development controller
build. Three normal medians were 186.522, 190.1325, 154.7025 us.
A wrong origin byte failed the untimed independent payload oracle (exit 101),
before any timed raw file existed. A 3 ms origin delay produced medians
4935.4445, 4520.978, 4334.3525 us; each exceeds the largest normal median
by the predetermined 2500 us limit. Production source hashes stayed unchanged.
These mutations validate the byte oracle and fixed-supply cost detection only.

Raw files are generated under `target/` and are not committed. Reproduce with
the commands in [README.md](README.md), using the exact frozen source bytes.
This local run used:

- `target/benchmarks/forward-workers/formal-013-r2-final/` for environment,
  raw samples, run records, logs and exit codes.
- `target/benchmarks/forward-workers/sensitivity-013-r2/` for isolated mutation
  source, logs and sensitivity summary.

The previous `formal-013/` and `sensitivity-013/` results remain historical
evidence for their earlier binary/source snapshot. The initial r2 attempt under
`formal-013-r2/` was rejected before native execution for missing entrypoint
artifact paths; the plan metadata was corrected before this fresh run. No older
measurement samples or successful records were substituted.

Final evidence SHA-256 values:

- `target/benchmarks/forward-workers/formal-013-r2-final/raw.json`: `5babbb5eefb94fd9c5057bb62fd7bd2d9f0d5933a86ee0673bd7c8b6ceba8c58`.
- `target/benchmarks/forward-workers/formal-013-r2-final/run.json`: `2c6d8182094ca5dc05bd33c79c8534ac112d2ae0f700ec412d093996153d75f8`.
- `target/benchmarks/forward-workers/formal-013-r2-final/environment.json`: `c28f777932a49a168e6db914ad86f7b836e6ddb733cbb6780a18dbca1720026d`.
- `target/benchmarks/forward-workers/formal-013-r2-final/unit-preflight.log`: `df27f03e180b7c1a66dce2b393b58fe5b8b7cafe3f8068e512b1981324e70144`.
- `target/benchmarks/forward-workers/formal-013-r2-final/preflight.log`: `b495d5ea86be74f0b55d6d7855747721064f61f95885965a366c8d381aed4263`.
- `target/benchmarks/forward-workers/formal-013-r2-final/measurement.log`: `d75481a2a127298b0d084d043cd948b82949beb12f3129e021d34b16f89a4f65`.
- `target/benchmarks/forward-workers/formal-013-r2-final/exit-codes.json`: `a6ebb8fe59bee645b7a265cba5d132298ef25d2046379909a0027ce7d60f8164`.
- `target/benchmarks/forward-workers/formal-013-r2-final/host-pressure-supplement.json`: `932a8c96ee7b0c50a3eadb2468564434ae7b56c8937afad1ba0391d200dd514c`.
- `target/benchmarks/forward-workers/sensitivity-013-r2/summary.json`: `bf68c8c3dd8bfb5173ea9abebed2732498d4bab49c93d410b35885531f90e1d4`.

Linux is the executed platform for this measurement. Windows GNU source checks
passed separately; native Windows shared-socket cancellation and pipe behavior
must pass the registered Windows Suite before project release. The real resource
exhaustion subprocess uses Unix RLIMIT_NOFILE; its trigger is not observed on
Windows and the benchmark runner preserves that coverage gap there. macOS native
execution is not represented by these results. The fixed checker validates the
declared coverage, record structure and hashes; it does not authenticate execution
or prove that the model captures all possible failures.
