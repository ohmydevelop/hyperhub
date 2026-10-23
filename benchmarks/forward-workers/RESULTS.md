# Final forwarding-worker component measurement

This fresh Linux batch passed the frozen forwarding-worker budgets and payload checks. Native Windows correctness is bound separately to successful CI 39810903916, job 119936546176.

- CLI SHA-256: `535729536f8b00b993f58b04ef401458da9dcf9256f11da07933584e0037af94` (153121016 bytes).
- NativeBase: `a23dc05b4ddf025d13f5d429fb0326dba4d5414f7b7991c74993f8cc1819bef2`.
- Model digest: `df0e0ab65eb5288b2bc0c9f1699367f5eaa9646df5f19fa8e9fc0499c73cfbea` (195 source bindings).
- Plan digest: `8a3df43d00db4cab8f29dfe1b542b08e912f69900ee19577b7d37e8fb45ab9ab`.
- Product source commit: `0df20519b2a6af4d16d29da7b2e872e624a5f785`; native CI matched 192 product/build/fixture files.
- Linux preflight: 24 unit regressions in 0.26s and twelve actual subprocess cases in 31.66s.
- Twenty fresh worker groups produced 20480 byte-validated echoes, 640 admissions and fifteen upgrades; accounting contains no failed, retried or unfinished requests.
- All preflight, measurement and completed valid-check exit codes are zero.

The model retains five obligations, fourteen flow/fault boundaries and four measured states. The controller and workers use release builds. Each state has five independent groups, eight established echo clients, and a separate 32-client admission burst. This is fixed local work; request samples within a group are correlated.

| State | Prepare median / max (ms) | Commit median / max (ms) | Echo median / observed P95 (us) | Echo/s median [min, max] | Admission median / max (ms) |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline | — | — | 41.273 / 62.222 | 143741 [131093, 191513] | 10.636 / 18.334 |
| upgrade-0 | 88.15587 / 89.41708 | 0.00199 / 0.00220 | 43.892 / 63.737 | 162485 [108922, 175513] | 11.416 / 14.028 |
| upgrade-1 | 88.39373 / 90.54804 | 0.00192 / 0.00239 | 42.329 / 62.939 | 156804 [117833, 176348] | 10.932 / 15.073 |
| upgrade-4 | 87.82367 / 88.85123 | 0.00191 / 0.00209 | 44.901 / 63.687 | 160620 [126135, 174500] | 12.671 / 19.863 |

Largest measured prepare was 90.54804ms, below 30000ms. Largest commit was 0.00239ms, below 100ms. Prepare times cover the warm-artifact WorkerManager prepare API, verification and child bootstrap. Commit times cover the synchronous switch API. Optional native Engine preflight is exercised by functional tests and is outside this timed operation.

Observed P95 uses nearest rank over 5120 requests per state; it is not a population tail guarantee. Overlapping rates from five groups do not establish causal ordering. Throughput, admission and resource observations have no acceptance thresholds in this model.

| State | Controller peak threads | Controller peak RSS (MiB) | Summed worker peak threads | Summed worker peak RSS (MiB) |
| --- | ---: | ---: | ---: | ---: |
| baseline | 46 | 49.40 | 7 | 21.63 |
| upgrade-0 | 53 | 209.32 | 14 | 36.86 |
| upgrade-1 | 53 | 211.76 | 14 | 40.88 |
| upgrade-4 | 74 | 213.70 | 35 | 98.14 |

Nominal 1ms resource sampling spans setup, preparation, admission and echo work. Peaks are observed lower bounds; upgrade-0 can include both generations during prepare. Controller totals include the local origin, reused Tokio blocking pool and allocator high water, rather than production Serve memory.

The same CLI passed a new sensitivity batch. Normal trial echo medians were 47.696, 45.648, 50.708us; 3ms-cost medians were 4139.776, 4201.149, 4139.533us. Every cost median exceeded the largest normal median by the predefined 2500us threshold. Wrong-byte mutation failed the independent untimed oracle with exit101 before a raw timing file existed. All bound source hashes remained unchanged. These mutations cover the byte oracle and fixed-supply cost detection, not every flow boundary.

Formal evidence: `target/benchmarks/forward-workers/formal-013-r6/`. Sensitivity evidence: `target/benchmarks/forward-workers/sensitivity-013-r6/`. The original Linux-only run, exit codes and incomplete coverage report remain beside the exact-source Windows completion record. Earlier directories retain their own source/binary histories; no old samples or successful Windows records were substituted.

Five evidence-binding negative controls rejected a wrong commit, an incomplete CI run, a failed job, a partial log and stale committed sources. Every control left the pending formal record unchanged. The real Windows binding was then applied once from the successful exact-source run. Negative-control record: `target/diagnostics/forward-windows-binder-negative-final6/results.json`, SHA-256 `834be2becfcef8482cf767f0466fa36fe84bbdd7eb07488ba399e13504182f89`.

Linux supplies these performance observations. Native Windows supplies the bound cancellation and twelve-case correctness evidence. macOS execution is not represented, and no ARM native Hook performance claim follows from package/QEMU export checks. Shared-host conditions and warm artifacts limit extrapolation to cold startup, saturation and production capacity. The checker validates declared coverage and hashes; it does not authenticate executions or prove semantic completeness.

Evidence SHA-256 values:

- `target/benchmarks/forward-workers/formal-013-r6/raw.json`: `59e1009b0461b00a4c97c7ab57af05ec5e5952b12e841dab02a610c847e205b6`.
- `target/benchmarks/forward-workers/formal-013-r6/run.json`: `284bf6904aefcaf69e06b9e94730b826cfde6f7526cb150f3a24f8ce6a50573f`.
- `target/benchmarks/forward-workers/formal-013-r6/environment.json`: `030e177066efe6e0cfd14b5a0c898e11f7d4f9d68f1304b0fe8d5e99bc6a9fd9`.
- `target/benchmarks/forward-workers/formal-013-r6/unit-preflight.log`: `e8c634e0671c41b727f7b39f1de8fcbc0c4cd5250e133c60e319b19ebe28ab35`.
- `target/benchmarks/forward-workers/formal-013-r6/preflight.log`: `b2812a23d880bd8b411a77d2359b8deaedb0003ebbcf7546eb8f277277eeac9d`.
- `target/benchmarks/forward-workers/formal-013-r6/measurement.log`: `c575691f11c29299dcf91ce70620e169fda6a80bb6a2652e8ae5f2bb9fc12b8d`.
- `target/benchmarks/forward-workers/formal-013-r6/exit-codes.json`: `cdc352ad8da7f57c6cf546effdc0d4f169aefd691d2f5249d009cc9521363107`.
- `target/benchmarks/forward-workers/formal-013-r6/host-pressure-supplement.json`: `f240431537a15edec27ee5002dded6ee648bc1187296eb1605d6bb813b641253`.
- `target/benchmarks/forward-workers/formal-013-r6/run-linux-only.json`: `6d01bc35a93b9ffd5728ed6568fe6f7d4813bc5ba1d3795bbad2f1e8cb65df81`.
- `target/benchmarks/forward-workers/formal-013-r6/exit-codes-linux-only.json`: `93baf01a9e31e558f269a2a9e74b2e9a9e50c68f716e818d266c20bfb43847b4`.
- `target/benchmarks/forward-workers/formal-013-r6/windows-ci/binding.json`: `7f0f505ce51e942bc5bccebb15ed525aaad9ff045462a16168410957ad50a177`.
- `target/benchmarks/forward-workers/formal-013-r6/windows-ci/run-metadata.json`: `197907513d525058a5772caa1901d80b5cff8f0af0a8013dce52bc0d544c86df`.
- `target/benchmarks/forward-workers/formal-013-r6/windows-ci/job-metadata.json`: `1c10016201bcfdbbff2fa8b8d6699f75f2ba6d742bf693527ee2224f02ccd534`.
- `target/benchmarks/forward-workers/formal-013-r6/windows-ci/job.log`: `c0353d9636c4f49296a28258d5b3daebb51842a0a5731ec5e11be5dde0d16e70`.
- `target/benchmarks/forward-workers/sensitivity-013-r6/summary.json`: `30cb2f9377fefe284abce6944c93ee6c69a4ea3f7071c003a23cd8a1e1db35cd`.
