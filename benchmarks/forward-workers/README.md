# Forwarding worker performance

Read [CONTRACT.md](CONTRACT.md) before interpreting results. The native workload
measures versioned forwarding workers with zero, one and four retained old
generations, alongside a group without an upgrade. It records API prepare/commit
latencies separately, validated TCP echo throughput/latency, a 32-client admission
burst and controller/worker RSS and sampled thread peaks.

Build the candidate CLI with the repository release build entry. Pass that exact
binary to the runner. On POSIX:

```bash
python3 scripts/benchmark-forward-workers.py \
  --worker target/release/hyperhub --profile release \
  --output target/benchmarks/forward-workers/final-cli
```

On Windows PowerShell:

```powershell
python scripts/benchmark-forward-workers.py `
  --worker target/release/hyperhub.exe --profile release `
  --output target/benchmarks/forward-workers/final-cli
```

The runner needs the benchmark skill's v1.1 contract checker. Its default location
is `~/.agents/skills/benchmark/scripts/benchmark_contract.py`; use
`--contract-tool <path>` when installed elsewhere. The Python checker requires
`jsonschema`. The native test dependencies and standalone `rustc` fixtures must
already be available locally; execution uses Cargo offline mode. Output must be a
new directory within the repository. There are no external service dependencies
or real credentials.

The runner validates the frozen source/plan hashes, executes the native functional
preflight, and starts timing only after that preflight passes. It saves raw trial
samples, environment and checker fingerprints, failure logs, `run.json`, native
and checker exit codes, and the generated `BENCHMARK.valid.md`. It returns nonzero
for native failures, missing/invalid measurements, checker failures or an exceeded
prepare/commit budget. Performance validity and budget acceptance are separate
fields in the report.

For development without the final CLI, build the source worker probe and use
`--profile dev`. Such results are explicitly probe/dev results:

```bash
cargo build -p hyperhub-core --example forward_worker_probe --offline
python3 scripts/benchmark-forward-workers.py \
  --worker target/debug/examples/forward_worker_probe --profile dev \
  --output target/benchmarks/forward-workers/dev-probe
```

The private worker process uses up to four Tokio worker threads and at most 32
blocking threads in both the source probe and final CLI. The controller's four
Tokio threads and local origin belong to the test harness, so its absolute RSS and
thread count are not a production resident Serve resource claim.

The source fingerprints require the same file bytes as the frozen checkout.
Use LF source files when reproducing a Linux freeze on Windows; automatic line
ending conversion changes the checked source snapshot.
The frozen model now includes a Unix descriptor-exhaustion subprocess. The
runner preserves this verification as not observed on Windows, so its valid
coverage gate cannot pass there without an equivalent native fault regression.
This limitation applies to this benchmark report; the project Windows Suite
still executes its registered native worker and shared-socket tests.

The frozen model, plan and implementation report describe a component scope.
`FROZEN.md` pins the reviewed model digest. Changes to bound production sources
require a documented review and a new freeze; the runner never updates the model
or baseline to make a failed measurement pass. Existing evidence remains evidence
only for its original bound snapshot.

Run isolated oracle/performance sensitivity checks with the same candidate:

```bash
python3 benchmarks/forward-workers/sensitivity.py \
  --worker target/release/hyperhub --profile release \
  --output target/benchmarks/forward-workers/sensitivity
```

The sensitivity runner copies only the test workload into standalone temporary
Cargo packages under its output directory. It does not edit production sources.
It uses a private build directory to avoid cache collisions with concurrent root
workspace builds. Three normal process-group trials must pass. A wrong origin
reply byte must fail the untimed independent payload oracle. Adding 3ms to each
origin reply must raise every mutated trial's median echo latency by at least
2500 us above the largest normal trial median. Compilation errors and unrelated
timeouts do not count as mutation detection. These checks cover the byte oracle
and the fixed supplied-work measurement; they do not establish mutation coverage
for every protocol, race or project obligation.

The Windows overlapped stdio read/write boundaries are mandatory. A Linux run
keeps `C-windows-stdio` blocked and returns a nonzero final checker status even
when all Linux correctness and timed samples pass. After the exact-source native
Windows CI succeeds, save the REST run/job metadata and complete job log, then
bind that actual evidence without repeating or replacing the timed samples:

```bash
python3 scripts/verify-forward-workers-windows.py \
  --run target/benchmarks/forward-workers/final-cli \
  --ci-run target/diagnostics/windows-run.json \
  --job target/diagnostics/windows-job.json \
  --log target/diagnostics/windows-job.log \
  --expected-commit <full-source-commit-sha>
```

Use `gh api repos/ohmydevelop/hyperhub/actions/runs/ID` and
`gh api repos/ohmydevelop/hyperhub/actions/jobs/ID` for metadata. The binder checks
successful native steps, explicit passing test results and committed source
hashes. It preserves `run-linux-only.json` and the previous checker report;
external evidence completes correctness coverage, not Linux timing.
