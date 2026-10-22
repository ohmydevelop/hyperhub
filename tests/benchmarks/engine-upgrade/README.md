# Native Engine component performance

This experiment measures native Engine preparation and commit separately while four threads execute real file/process decisions and retain old native leases. The same initial native version runs without an upgrade for the baseline. The candidate is an independently compiled native module; a sentinel decision changes from `pass` to `deny` after commit, while the old lease still returns `pass`.

Each useful work unit contains three successful native decisions: current file, current process and pinned old file. Each decision checks its action, last matching rule and protection. The workload uses 32 ordered rules, five paired baseline/upgrade trials and 250 ms per worker trial. File operations and process patterns use their respective production schemas. The harness asserts that all four workers remain active immediately before and after commit.

Run from the repository root with a supported Rust toolchain:

```text
cargo run --release -p hyperhub-engine --example native_upgrade_bench --locked -- target/diagnostics/native-engine-performance
```

The command works in POSIX shells and PowerShell. Source-built fixture libraries and private caches stay under the requested output directory. It uses local data and does not start Serve or use credentials. The raw result is `raw.json` in that directory. Use `python3 tests/benchmarks/engine-upgrade/record.py <raw.json>` on POSIX to regenerate the execution record, or `python` on PowerShell. For another platform, pass its own `--evidence-dir` and `--run` paths; do not replace the checked Linux evidence. The frozen model, plan and checked Linux execution are adjacent to this README. `BENCHMARK.md` is rendered by the benchmark contract validator; do not edit it manually.

The recorded Linux run observed preparation between 58.191 and 76.269 ms. Direct commit took 0.988–1.296 µs; all five samples met the requested 100 ms soft commit budget. Preparation includes artifact installation, hashing, fsync, module loading and health checking. Commit measures the direct management call and generation publication. Neither interval includes fixture compilation or control subscription polling.

Median useful throughput was 18,144.72 units/s for the baseline and 15,724.59 units/s with an upgrade, about 13.34% lower in this final run. This includes concurrent preparation and candidate cold-cache work. Median per-trial sampled unit p50 was 166.403 versus 171.627 µs; sampled p99 was 226.111 versus 424.166 µs. Latency samples cover every 64th completed work unit. These are finite samples on a shared runner; they do not establish production tail latency or a statistically significant regression. No throughput acceptance threshold was specified. Earlier valid workload runs observed both lower and higher throughput during upgrade. They used prior source freezes and are not pooled into this final report. The direction changed under shared-runner conditions, so these observations establish the measured local cost and do not establish a statistically significant improvement or regression.

Before the valid run, an initial preflight rejected an incorrect benchmark input that omitted the file operation list and reused file patterns for process rules. That run produced no valid metrics. The input was corrected and the source/model were refrozen before collecting the retained run. The final refreeze also binds the ownership regression, dependency manifests and evidence recorder, plus a Clippy-equivalent sampling expression. This final revision also includes the static call/serialization wrapper and the bounded policy-output capacity fix. The final v7 freeze additionally binds the Engine build/native Base generation sources and immutable r2 release context after the verified lifecycle fixes. Prior v5 and v6 raw evidence remains in `evidence/linux-x64/previous-v5-raw.json` and `previous-v6-raw.json`; it is not pooled into this run. The final model digest is `f408c8d3cff99a1b177285b51a2647a1df16ee71364f053b33a91d0d93dd7166`.

The baseline measures the upgrade increment within the new native Base. It does not compare total cost with the earlier Host architecture.

This scope covers healthy native component calls. The unified native Host regression separately exercises real ptrace/Gum hooks, fork, child enrollment, rollback, old TCP streams and actual compiled-cache reclamation. Worker, full-product recovery and native Windows release checks remain separate requirements. The source benchmark is portable; this snapshot contains Linux x86_64 performance evidence only.
