# Local final CLI measurement r3, 2026-10-22

The final 0.2.13 r3 Linux CLI passed the declared forwarding-worker component
budgets on this host. This result supersedes the earlier local candidate report.
Project release and native Windows acceptance remain separate.

- CLI SHA-256: `649121688cfc7eff6b79103667bccd10eec578f57fa70bf9186295b4999a532d` (153045104 bytes).
- Model digest: `dc63d466b15e31f0f000d8ce4b5cde3948cd94c954aad3ddf52fce177a3ea7f8`.
- Plan digest: `cbbfe45742194359b107d1652da65e7231aa25c52111f5b7fcb35e11bd004c64`.
- Forwarding unit preflight: 24/24 passed, 0.28 seconds.
- Functional preflight: 12/12 actual subprocess cases passed, 35.62 seconds.
- Native performance: 20 fresh worker groups, 25.69 seconds; 20480 validated
  echoes, 640 validated admissions, 15 upgrades, zero failed or retried work.
- Runner exit codes: unit preflight 0, native preflight 0, measurement 0,
  checker 0; budget failure false.
- Fixed checker report: [BENCHMARK.valid.md](BENCHMARK.valid.md).

The reviewed model binds five obligations, twelve explicit flow/fault boundaries
and four measured states. It retains all eleven previous boundaries and adds
exact Winsock BOOLEAN/DWORD decoding with strict invalid-size rejection.
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
| baseline | — | — | 41.221 / 65.100 | 139675 [95090, 153625] | 12.105 / 18.484 |
| upgrade-0 | 98.33982 / 101.48668 | 0.00206 / 0.00219 | 46.041 / 63.072 | 165495 [164016, 172891] | 12.802 / 16.604 |
| upgrade-1 | 97.74703 / 104.87086 | 0.00200 / 0.00236 | 45.378 / 71.828 | 151518 [100608, 161938] | 12.015 / 16.700 |
| upgrade-4 | 97.96270 / 98.89019 | 0.00201 / 0.00205 | 43.915 / 64.479 | 161122 [121453, 171088] | 10.400 / 19.619 |

Every measured prepare was below 30000 ms (largest 104.87086 ms) and
every measured commit was below 100 ms (largest 0.00236 ms). All samples
are retained. Prepare means the warm-artifact `WorkerManager::prepare` API,
including supplied/cached executable verification and child bootstrap. Optional
native Engine preflight is covered by functional tests, not this timed operation.
Commit timestamps surround the synchronous pointer-switch API only.

Observed P95 uses nearest rank over the 5120 request samples in each state.
Requests within each group are correlated. Five group trials and overlapping
rate ranges do not establish a causal ordering between these states.

| State | Controller peak threads | Controller peak RSS (MiB) | Summed worker peak threads | Summed worker peak RSS (MiB) |
| --- | ---: | ---: | ---: | ---: |
| baseline | 47 | 70.14 | 7 | 21.69 |
| upgrade-0 | 54 | 216.36 | 14 | 37.18 |
| upgrade-1 | 54 | 213.54 | 14 | 41.25 |
| upgrade-4 | 75 | 216.44 | 35 | 99.73 |

Resource sampling spans generation setup, prepare, admission and echo work.
Thus even upgrade-0 can include both workers during preparation. Nominal 1 ms
sampling gives observed lower bounds for transient peaks. Controller totals
include the test origin, reused Tokio blocking pool and allocator high water;
they are not the production Serve RSS. Business/resource metrics have no
acceptance thresholds in this model.

The same r3 CLI passed isolated sensitivity checks with a development controller
build. Three normal medians were 154.4735, 188.582, 156.5975 us.
A wrong origin byte failed the untimed independent payload oracle (exit 101),
before any timed raw file existed. A 3 ms origin delay produced medians
4399.4529999999995, 4420.032499999999, 4414.098 us; each exceeds the largest normal median
by the predetermined 2500 us limit. Production source hashes stayed unchanged.
These mutations validate the byte oracle and fixed-supply cost detection only.

Raw files are generated under `target/` and are not committed. Reproduce with
the commands in [README.md](README.md), using the exact frozen source bytes.
This local run used:

- `target/benchmarks/forward-workers/formal-013-r3/` for environment,
  raw samples, run records, logs and exit codes.
- `target/benchmarks/forward-workers/sensitivity-013-r3/` for isolated mutation
  source, logs and sensitivity summary.

The previous `formal-013/`, `formal-013-r2-final/`, and their sensitivity results
remain historical evidence for their own snapshots. The initial r2 attempt under
`formal-013-r2/` was rejected before native execution for missing entrypoint
artifact paths; the plan metadata was corrected before this fresh run. No older
measurement samples or successful records were substituted.

Final evidence SHA-256 values:

- `target/benchmarks/forward-workers/formal-013-r3/raw.json`: `c2938569567f7455d09e4c8f96dce5d54bf20d45fc6401b1ec93f26c6847291e`.
- `target/benchmarks/forward-workers/formal-013-r3/run.json`: `4173bfcb1364204a04a5fc762409c5898b39638a2b1620b1a53c5763f3059d8f`.
- `target/benchmarks/forward-workers/formal-013-r3/environment.json`: `cfaf0c281636362f27a771b2bcdf151060fdec45e41c0830e424b0d85c3d419e`.
- `target/benchmarks/forward-workers/formal-013-r3/unit-preflight.log`: `224325bd0496a036a88c1188ae90b3dc591b20925a152e5a37f12b657f53e2df`.
- `target/benchmarks/forward-workers/formal-013-r3/preflight.log`: `37a3626778370986667ff912c8d8ac454d2a78eed2a7b382dc4229b9706439d3`.
- `target/benchmarks/forward-workers/formal-013-r3/measurement.log`: `6a738d482d3f131c35eb9716adacde9d1271683485e81704d210092401cae9f2`.
- `target/benchmarks/forward-workers/formal-013-r3/exit-codes.json`: `3e9a50b7731554f37c0b0001cb3941d25dc5cc3d85ddb20d68257eb28826be23`.
- `target/benchmarks/forward-workers/formal-013-r3/host-pressure-supplement.json`: `cbc05cc810f54104ef92bc226f8061855859d2613d1635793723dadc01f9d2ce`.
- `target/benchmarks/forward-workers/sensitivity-013-r3/summary.json`: `429de46750e5d8f18d108bad4872ce2515522e999617ca423e76c5bc6d3c71b7`.

Linux is the executed platform for this measurement. Windows GNU source checks
passed separately; native Windows shared-socket cancellation and pipe behavior
must pass the registered Windows Suite before project release. The real resource
exhaustion subprocess uses Unix RLIMIT_NOFILE; its trigger is not observed on
Windows and the benchmark runner preserves that coverage gap there. macOS native
execution is not represented by these results. The fixed checker validates the
declared coverage, record structure and hashes; it does not authenticate execution
or prove that the model captures all possible failures.
