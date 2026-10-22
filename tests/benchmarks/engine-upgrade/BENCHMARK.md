# HyperHub native Engine component benchmark 测试报告

**报告状态：所选阶段门槛满足。** 所选阶段：reported\_valid。

阶段、条件假设和缺口分别列出；本报告不认证真实执行或模型完备性。

- schema_version: 1\.1
- target: HyperHub native Engine component
- version_or_revision: native\-component\-v1 \(v0\.2\.13 final\-lifecycle\-v7 worktree snapshot\)
- model_digest: f408c8d3cff99a1b177285b51a2647a1df16ee71364f053b33a91d0d93dd7166
- plan_digest: db70268e46a5bc5df081911e9e8e8a48c84ddade9a57f8b51c9705f9f96d2ddc

导航：[准备](#准备) · [可靠性场景](#可靠性场景) · [性能场景](#性能场景) · [覆盖映射](#覆盖映射) · [未覆盖与后续](#未覆盖与后续)

## 不变量

- 正确性 preflight 与性能计时分开；性能 case 必须关联 preflight。
- 覆盖分母来自冻结模型；条件假设、未决项与排除项保持可见。
- 未运行阶段不写通过结论；测量有效和性能验收分别报告。

## 准备

### 环境

Actual optimized native component run; fixed four\-worker/32\-rule workload, shared local runner\.

### 配置

```json
{
  "constraints": [],
  "factors": [
    {
      "id": "mode",
      "values": [
        "baseline",
        "upgrade"
      ]
    }
  ]
}
```

### 共用前提与清理

```json
{
  "cleanup": [
    "Drop Runtime/leases after each trial and preserve raw.json before removing private artifact caches."
  ],
  "generation_notes": [
    "Initial model was refrozen before any performance execution to add an explicit all-four-worker overlap oracle; the denominator and requested scope were unchanged. A failed preflight was retained, operation-specific inputs were corrected, and a final refreeze binds the added ownership unit regression, dependency manifests and evidence recorder before the repeated run. The v6 refreeze adds the statically linked Engine lib.rs dependency and its bounded pure-policy capacity retry. The final v7 refreeze binds Engine build/native Base source generation and the immutable r2 release context after the verified exec enrollment, ordinary-exit, process-birth and connection-claim lifecycle fixes. v5 and v6 raw evidence remain archived separately; no prior performance observations are pooled into this run.",
    "Self-reviewed complete category catalog; exclusions are local to this healthy-path timing experiment."
  ],
  "preconditions": [
    "Use source/model hashes exactly as frozen; build with the lockfile and a Rust release toolchain.",
    "Use isolated private diagnostic output; no real Serve or credentials participate."
  ]
}
```

### 目标范围与工作负载

```json
{
  "scope": {
    "delivered_level": "component",
    "goal": "Native prepare/commit latency and concurrent useful decision cost with old leases",
    "rationale": "This report covers the native Engine component only; worker and product release acceptance remain separate.",
    "requested_level": "component"
  },
  "workloads": [
    {
      "applicability": "required",
      "goal": "Four workers execute current file/current process/pinned old-file decisions with a 32-rule snapshot",
      "id": "W-decisions",
      "obligation_ids": [
        "O-oracle",
        "O-decisions"
      ],
      "rationale": "Deterministic worst ordered-rule position, synthetic paths and no external service dependency",
      "role": "primary",
      "source_refs": [
        {
          "first": 1,
          "last": 231,
          "path": "crates/hyperhub-engine/examples/native_upgrade_bench.rs"
        }
      ]
    },
    {
      "applicability": "required",
      "goal": "One actual native prepare and commit while the four workers remain active",
      "id": "W-switch",
      "obligation_ids": [
        "O-oracle",
        "O-switch"
      ],
      "rationale": "Direct management boundary excludes fixture compilation and all control polling",
      "role": "primary",
      "source_refs": [
        {
          "first": 1,
          "last": 231,
          "path": "crates/hyperhub-engine/examples/native_upgrade_bench.rs"
        }
      ]
    }
  ]
}
```

### 故障类别审查

目录版本：1\.0；目录摘要：6213ed21d151dabcd89b020d2e38a9388f7de8c832099fe78446c563dc3b1f4f。

类别审查完成与适用类别覆盖分别统计；审查全部类别不代表穷尽真实故障。

| 类别 | 适用性 | 关联义务 | 理由 | 源码依据 |
|---|---|---|---|---|
| F01 | required | O\-oracle | Native policy output and real post\-commit sentinel semantics are checked against fixed explicit expectations\. | crates/hyperhub\-engine/examples/native\_upgrade\_bench\.rs:1\-231 |
| F02 | required | O\-oracle | The controlled workload matches the last of 32 ordered rules; release and retained generations are independently checked\. | crates/hyperhub\-engine/examples/native\_upgrade\_bench\.rs:1\-231 |
| F03 | not\_applicable | 无 | This performance model accepts bounded valid JSON and manifests only\. Invalid\-input capability regressions run separately and no hostile\-input performance claim is made\. | crates/hyperhub\-engine/examples/native\_upgrade\_bench\.rs:1\-231 |
| F04 | required | O\-oracle | Current and pinned old generation identities must differ after commit, while old semantics remain callable\. | crates/hyperhub\-engine/examples/native\_upgrade\_bench\.rs:1\-231 |
| F05 | required | O\-decisions, O\-oracle, O\-switch | Four active decision workers overlap actual native preparation and commit; no worker may fail or lose completed work\. | crates/hyperhub\-engine/examples/native\_upgrade\_bench\.rs:1\-231 |
| F06 | required | O\-oracle, O\-switch | Prepare and commit clocks are distinct from construction and RPC polling; the requested 100 ms soft commit budget is checked without a hard cancellation claim\. | crates/hyperhub\-engine/examples/native\_upgrade\_bench\.rs:1\-231 |
| F07 | required | O\-decisions, O\-oracle, O\-switch | Each worker retains an old lease for the entire trial; real native old code remains callable across replacement\. | crates/hyperhub\-engine/examples/native\_upgrade\_bench\.rs:1\-231 |
| F08 | required | O\-decisions, O\-oracle | Successful decision throughput and sampled unit latency are measured under the fixed four\-thread/32\-rule load\. | crates/hyperhub\-engine/examples/native\_upgrade\_bench\.rs:1\-231 |
| F09 | required | O\-oracle | Any native error, bad result or worker panic invalidates the run\. Failure recovery is outside this healthy\-path performance model\. | crates/hyperhub\-engine/examples/native\_upgrade\_bench\.rs:1\-231 |
| F10 | not\_applicable | 无 | The direct management component experiment performs no retries or fallback; control retry reliability is tested in the separate product Suite\. | crates/hyperhub\-engine/examples/native\_upgrade\_bench\.rs:1\-231 |
| F11 | not\_applicable | 无 | Preparation includes real immutable artifact installation and fsync, but no power\-loss or process\-interruption recovery claim is made by this timing experiment\. | crates/hyperhub\-engine/examples/native\_upgrade\_bench\.rs:1\-231 |
| F12 | not\_applicable | 无 | No coordinator RPC, participant fanout or subscription polling occurs inside the measured component boundary; those product boundaries require their separate tests\. | crates/hyperhub\-engine/examples/native\_upgrade\_bench\.rs:1\-231 |
| F13 | required | O\-decisions, O\-oracle | Every measured decision calls the native C ABI through NativeEngine and verifies decoded result fields\. | crates/hyperhub\-engine/examples/native\_upgrade\_bench\.rs:1\-231 |
| F14 | required | O\-oracle | Both modes use the same valid 32\-rule snapshot, four threads and retained baseline version; only actual upgrade differs\. | crates/hyperhub\-engine/examples/native\_upgrade\_bench\.rs:1\-231 |
| F15 | not\_applicable | 无 | Locally compiled trusted DSOs and deterministic fake paths contain no external credentials\. Release authentication and hostile module security are separate acceptance gates\. | crates/hyperhub\-engine/examples/native\_upgrade\_bench\.rs:1\-231 |
| F16 | required | O\-decisions, O\-oracle, O\-switch | Raw completed work, elapsed time, sampled unit latencies and distinct preparation/commit durations are preserved; no failed work is counted as success\. | crates/hyperhub\-engine/examples/native\_upgrade\_bench\.rs:1\-231 |

### 基线

各性能场景分别列出比较基线与验收依据；未声明的值不补写。

### 审查记录

```json
{
  "kind": "self",
  "notes": "Reviewed all sixteen categories against this controlled healthy-path native component scope; excludes whole-product delivery, hostile inputs and crash recovery. Existing separate functional regressions are not substituted for timing evidence. Final release context: immutable CLI SHA256 419800bd707330167f7486f3d4d2c945e423a984c084568e4efe1a03f19f64a4, Agent SHA256 f09a19ce5da463322ba9f14cc546f7ed5bd1f5c0d094b474053a550a7ad7416a, native Base 219dac7345afe39fb7d7f6f60fd351ecf7f26346a093b7e7fdbb6531183e4b8f. This timing harness still measures the native Engine component, not CLI or Core RPC latency.",
  "reviewer": "Codex remaining_engines"
}
```

### 证据

冻结源码：

```json
[
  {
    "path": "Cargo.lock",
    "sha256": "b07289572b4637a0b02e161163cec09376a0a7fc76c431049f8d1ffb4a200922"
  },
  {
    "path": "Cargo.toml",
    "sha256": "ae520aa3ad69b534592df54e0f54c8c6e66ea54331b78b7f61f677db7b6f4404"
  },
  {
    "path": "build_support/native_base.rs",
    "sha256": "34391c5e8857e2e4a4806f3d39aaf7440624cd75c2fb452871691035694d7460"
  },
  {
    "path": "crates/hyperhub-engine/Cargo.toml",
    "sha256": "6cd2f5e78f8c9e505498108a5216138f06f5a24a35ac34119a06cd223e0b2e63"
  },
  {
    "path": "crates/hyperhub-engine/build.rs",
    "sha256": "b33c3c6a66c6e890990855e494caa8b77db48d6867bf23da3bd3a80378655852"
  },
  {
    "path": "crates/hyperhub-engine/examples/native_upgrade_bench.rs",
    "sha256": "64fae1816f2ca8bc080f997a8dfdaf76a3a20bd1c69694ec9dde78da6d414804"
  },
  {
    "path": "crates/hyperhub-engine/src/contract.rs",
    "sha256": "6cc99eb607f0307195079158782c7ea2f04001d8365c1c8694ff065bf4810724"
  },
  {
    "path": "crates/hyperhub-engine/src/lib.rs",
    "sha256": "c195335972a56640fc4cd82c29f420bb749bfc20ea2a84c8518d9db2179ace36"
  },
  {
    "path": "crates/hyperhub-engine/src/operations.rs",
    "sha256": "100514cc0c7c277ff0f1b9ff957828c367c529fe5a6dee049b1cd711cc139ca9"
  },
  {
    "path": "crates/hyperhub-engine/src/policy.rs",
    "sha256": "294dc09e25c3565ce0f3f698f888f5340a0d13cfa37a82700ac9f5dff9652c7b"
  },
  {
    "path": "crates/hyperhub-runtime/Cargo.toml",
    "sha256": "dc2aa4549c6c6fa82a9bcaa2a78ed19c82035371fc25378fcc7489a9d5912f96"
  },
  {
    "path": "crates/hyperhub-runtime/src/artifact.rs",
    "sha256": "f33f68ccac6839730bb09745bd61c113a559d6518d170b8595f840696d594e13"
  },
  {
    "path": "crates/hyperhub-runtime/src/generation.rs",
    "sha256": "0c5237ca00c516d0570dd5639e7337faa5ec4cff38179baff7fb9a70f8897b8e"
  },
  {
    "path": "crates/hyperhub-runtime/src/native.rs",
    "sha256": "5fcc307a162c1c9d6c06fdfbd2971c49e0c5f7b7e9e22094c5c0f2f585ad9238"
  },
  {
    "path": "tests/benchmarks/engine-upgrade/record.py",
    "sha256": "e90fb6032a41321a18a4fad7a821c4ec48c0be54732022402f82c2c4d76048cf"
  },
  {
    "path": "tests/fixtures/engine_fixture_build.rs",
    "sha256": "312ae35ffb2db399024beeeb07f63f063a497bce3f220ea37a49ac7c296752e2"
  },
  {
    "path": "tests/fixtures/network_upgrade_engine.rs",
    "sha256": "b32eb29e3cfda1345b038fdd7fee77740771b2df996f5557fcdcc25311635573"
  }
]
```

## 可靠性场景

| 场景 | 标题 | 来源 | 实现状态 | 运行状态 |
|---|---|---|---|---|
| [C\-native](#case-C-native) | Real native semantic and old\-lease preflight | generated | implemented | completed |

<a id="case-C-native"></a>

### C\-native Real native semantic and old\-lease preflight

- id: C\-native
- title: Real native semantic and old\-lease preflight
- kind: correctness
- implementation_status: implemented
- origin: generated
- goal: Native FILE/PROCESS decisions match the last rule and protection; candidate code changes a sentinel from pass to deny while pinned old code stays pass\.
- obligation_ids: O\-oracle
- boundary_ids: 未声明
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Two independently compiled native DSOs; 32 ordered anchored\-regex rules; matching last target and protection; four workers; fixed pinned old lease; deterministic local data without credentials\.
- steps:
  1. Construct the initial real native Runtime and warm both operation caches outside timing\.
  2. Validate the initial sentinel pass result\. Start four workers through a barrier\.
  3. In upgrade mode measure Prepare installation/hash/fsync/health and CommitHeld separately, with all four workers asserted active\.
  4. Verify candidate sentinel deny and pinned old sentinel pass, plus changed generation\. Join workers and account only units that passed all three native decision assertions\.
- oracle.method: Fixed explicit semantic outputs and rule/protection expectations independent of matcher implementation
- oracle.assertion: Every current file/current process/old\-file result is pass with rule\-31 and review\. Actual candidate code changes sentinel pass to deny while old code remains pass\. No panic or error is accepted\.
- oracle.independence: Expected values are fixed from the controlled input and fixture change; the oracle does not rerun or mirror the rule matcher\.
- workload_ids: W\-decisions, W\-switch
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Candidate sentinel changes to deny, old sentinel stays pass, generation changes; every completed work unit matches rule-31 and review.",
    "assertion_refs": [
      {
        "first": 1,
        "last": 231,
        "path": "crates/hyperhub-engine/examples/native_upgrade_bench.rs"
      }
    ],
    "id": "V-native",
    "obligation_id": "O-oracle",
    "trigger": "Two independently compiled baseline/candidate DSOs execute before and after native generation switch with a pinned old lease.",
    "trigger_refs": [
      {
        "first": 1,
        "last": 231,
        "path": "crates/hyperhub-engine/examples/native_upgrade_bench.rs"
      }
    ]
  }
]
```

- code_references:

```json
[
  {
    "first": 1,
    "last": 231,
    "path": "crates/hyperhub-engine/examples/native_upgrade_bench.rs"
  }
]
```

- matrix:

```json
{}
```

- automation / reproduction:

```json
{
  "argv": [
    "cargo",
    "run",
    "--release",
    "-p",
    "hyperhub-engine",
    "--example",
    "native_upgrade_bench",
    "--locked",
    "--",
    "target/diagnostics/native-engine-performance"
  ],
  "artifact_paths": [
    "crates/hyperhub-engine/examples/native_upgrade_bench.rs",
    "tests/fixtures/network_upgrade_engine.rs",
    "tests/fixtures/engine_fixture_build.rs",
    "tests/benchmarks/engine-upgrade/record.py"
  ],
  "cwd": "."
}
```

- reported_result:

```json
{
  "acceptance": "not_evaluated",
  "case_id": "C-native",
  "checks": [],
  "correctness": "passed",
  "details": "Actual release native DSOs and five paired trials; component evidence, without product-wide or cross-platform performance claims.",
  "evidence": [
    {
      "path": "tests/benchmarks/engine-upgrade/evidence/linux-x64/raw.json",
      "sha256": "e6b3b733adb2620d0d57fd70d120849932a0f5a8844d2576f33a4fa168cd6987"
    }
  ],
  "measurement": "not_applicable",
  "parameters": {},
  "samples": {},
  "status": "completed",
  "verifications": [
    {
      "details": "Compiled native baseline/candidate code and pinned old leases passed the fixed source semantic assertions.",
      "evidence_paths": [
        "tests/benchmarks/engine-upgrade/evidence/linux-x64/raw.json"
      ],
      "id": "V-native",
      "status": "passed",
      "trigger": "observed"
    }
  ]
}
```

## 性能场景

| 场景 | 标题 | 来源 | 实现状态 | 运行状态 |
|---|---|---|---|---|
| [P\-decisions\-baseline](#case-P-decisions-baseline) | Useful native decision cost baseline | generated | implemented | completed |
| [P\-decisions\-upgrade](#case-P-decisions-upgrade) | Useful native decision cost upgrade | generated | implemented | completed |
| [P\-switch](#case-P-switch) | Direct native prepare and commit under active calls | generated | implemented | completed |

<a id="case-P-decisions-baseline"></a>

### P\-decisions\-baseline Useful native decision cost baseline

- id: P\-decisions\-baseline
- title: Useful native decision cost baseline
- kind: performance
- implementation_status: implemented
- origin: generated
- goal: Measure successful three\-call file/process/old\-file units under matched baseline and upgrade loads\.
- obligation_ids: O\-decisions
- boundary_ids: 未声明
- preconditions: 见共用前提与场景输入；性能 preflight: C\-native
- inputs: Two independently compiled native DSOs; 32 ordered anchored\-regex rules; matching last target and protection; four workers; fixed pinned old lease; deterministic local data without credentials\.
- steps:
  1. Construct the initial real native Runtime and warm both operation caches outside timing\.
  2. Validate the initial sentinel pass result\. Start four workers through a barrier\.
  3. In upgrade mode measure Prepare installation/hash/fsync/health and CommitHeld separately, with all four workers asserted active\.
  4. Verify candidate sentinel deny and pinned old sentinel pass, plus changed generation\. Join workers and account only units that passed all three native decision assertions\.
- oracle.method: Fixed explicit semantic outputs and rule/protection expectations independent of matcher implementation
- oracle.assertion: Every current file/current process/old\-file result is pass with rule\-31 and review\. Actual candidate code changes sentinel pass to deny while old code remains pass\. No panic or error is accepted\.
- oracle.independence: Expected values are fixed from the controlled input and fixture change; the oracle does not rerun or mirror the rule matcher\.
- workload_ids: W\-decisions
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "All measured units contain exactly three successfully checked native decisions; positive work, elapsed intervals and sampled latencies are preserved.",
    "assertion_refs": [
      {
        "first": 1,
        "last": 231,
        "path": "crates/hyperhub-engine/examples/native_upgrade_bench.rs"
      }
    ],
    "id": "V-decisions-baseline",
    "obligation_id": "O-decisions",
    "trigger": "Four workers run the matched 250 ms workload with 32 rules and a retained old lease.",
    "trigger_refs": [
      {
        "first": 1,
        "last": 231,
        "path": "crates/hyperhub-engine/examples/native_upgrade_bench.rs"
      }
    ]
  }
]
```

- code_references:

```json
[
  {
    "first": 1,
    "last": 231,
    "path": "crates/hyperhub-engine/examples/native_upgrade_bench.rs"
  }
]
```

- matrix:

```json
{
  "mode": "baseline"
}
```

- automation / reproduction:

```json
{
  "argv": [
    "cargo",
    "run",
    "--release",
    "-p",
    "hyperhub-engine",
    "--example",
    "native_upgrade_bench",
    "--locked",
    "--",
    "target/diagnostics/native-engine-performance"
  ],
  "artifact_paths": [
    "crates/hyperhub-engine/examples/native_upgrade_bench.rs",
    "tests/fixtures/network_upgrade_engine.rs",
    "tests/fixtures/engine_fixture_build.rs",
    "tests/benchmarks/engine-upgrade/record.py"
  ],
  "cwd": "."
}
```

- measurement_protocol:

```json
{
  "accounting": "Count unique three-call decision units only after all results pass their independent assertions. A worker error invalidates the execution; no retry is used.",
  "budget": {
    "rationale": "Fixed ten 250ms trials and bounded local source compilation. The external runner imposes process timeout; native deadlock is a failure.",
    "timeout_seconds": 120
  },
  "comparison": {
    "acceptance": null,
    "baseline": null,
    "basis": "Matched same-initial-version no-upgrade baseline; user provided no numeric throughput regression threshold.",
    "factor_ids": [
      "mode"
    ]
  },
  "execution_model": "closed_loop",
  "measurement_context": {
    "end_event": "Instant after all four workers join with successful counts",
    "factor_ids": [
      "mode"
    ],
    "id": "M-decisions-baseline",
    "level": "component",
    "resources": [],
    "start_event": "Instant immediately before releasing the four-worker barrier",
    "work_units": [
      {
        "description": "One current file decision, one current process decision and one pinned old-file decision, all verified.",
        "id": "decision_unit",
        "unit": "units"
      }
    ]
  },
  "metrics": [
    {
      "kind": "throughput",
      "minimum": 0,
      "name": "units_per_second",
      "subject_id": "decision_unit",
      "subject_kind": "work_unit",
      "summary": "Successful three-native-call units divided by joined wall time.",
      "unit": "units/s"
    },
    {
      "kind": "latency",
      "minimum": 0,
      "name": "unit_latency_ns_p50",
      "subject_id": "decision_unit",
      "subject_kind": "work_unit",
      "summary": "Median of systematically sampled every-64th successful unit latencies within a trial.",
      "unit": "ns"
    },
    {
      "kind": "latency",
      "minimum": 0,
      "name": "unit_latency_ns_p99",
      "subject_id": "decision_unit",
      "subject_kind": "work_unit",
      "summary": "99th percentile of sampled every-64th successful unit latencies; not the full population or service tail.",
      "unit": "ns"
    }
  ],
  "reset": "Fresh Runtime and private artifact cache for each trial; pinned lease remains until the completed trial is dropped.",
  "sampling": {
    "basis": "Five paired alternating-mode trials expose local variation; not a statistical significance or whole-product tail claim.",
    "min_samples": 5,
    "unit": "trial"
  },
  "timing_boundary": "Wall clock from immediately before barrier release until all four workers join; unit sample from before current acquire through three native calls, assertions and successful counter update. Excludes compilation, initial native load/cache warmup and sentinel preflight. Upgrade mode includes concurrent preparation/commit activity in wall time.",
  "uncertainty": "Uncontrolled shared Linux runner, five correlated paired trials, fixed four-thread synthetic load. Sampled unit percentiles omit most calls; report no production SLO or statistically significant regression.",
  "validity_checks": [
    {
      "condition": "All worker assertions pass; every offered unit succeeds exactly once, with three native calls; no retries.",
      "id": "V-work"
    },
    {
      "condition": "Elapsed times, sampled latencies and completed units are positive.",
      "id": "V-clock"
    },
    {
      "condition": "Five actual trials per mode contain raw work counts and samples.",
      "id": "V-samples"
    },
    {
      "condition": "In upgrade mode all four decision workers remain active immediately before and after direct commit.",
      "id": "V-overlap"
    }
  ],
  "warmup": "128 successful file and process decisions per trial before workers start.",
  "work_unit": "One verified file/process/pinned-file decision unit"
}
```

- reported_result:

```json
{
  "acceptance": "not_evaluated",
  "accounting": {
    "accepted": 21648,
    "cancelled": 0,
    "failed": 0,
    "offered": 21648,
    "rejected": 0,
    "retries": 0,
    "succeeded": 21648,
    "unfinished": 0,
    "work_unit_id": "decision_unit"
  },
  "case_id": "P-decisions-baseline",
  "checks": [
    {
      "details": "Native source assertions and recorded counts, clocks and worker-overlap observations passed.",
      "id": "V-work",
      "status": "passed"
    },
    {
      "details": "Native source assertions and recorded counts, clocks and worker-overlap observations passed.",
      "id": "V-clock",
      "status": "passed"
    },
    {
      "details": "Native source assertions and recorded counts, clocks and worker-overlap observations passed.",
      "id": "V-samples",
      "status": "passed"
    },
    {
      "details": "Native source assertions and recorded counts, clocks and worker-overlap observations passed.",
      "id": "V-overlap",
      "status": "passed"
    }
  ],
  "correctness": "passed",
  "details": "Actual release native DSOs and five paired trials; component evidence, without product-wide or cross-platform performance claims.",
  "evidence": [
    {
      "path": "tests/benchmarks/engine-upgrade/evidence/linux-x64/raw.json",
      "sha256": "e6b3b733adb2620d0d57fd70d120849932a0f5a8844d2576f33a4fa168cd6987"
    }
  ],
  "measurement": "valid",
  "measurement_context_digest": "3971a8c229c8bbf14be9ab5efc096aeb2672b4919a565a5fbe5c896b1cc28061",
  "parameters": {
    "mode": "baseline"
  },
  "samples": {
    "unit_latency_ns_p50": [
      169343,
      166848,
      166047,
      166403,
      165938
    ],
    "unit_latency_ns_p99": [
      938472,
      226111,
      184138,
      181484,
      1197957
    ],
    "units_per_second": [
      18144.721423724444,
      20567.28310630514,
      18567.460386742823,
      12094.071454845052,
      15513.147374695473
    ]
  },
  "status": "completed",
  "verifications": [
    {
      "details": "Compiled native baseline/candidate code and pinned old leases passed the fixed source semantic assertions.",
      "evidence_paths": [
        "tests/benchmarks/engine-upgrade/evidence/linux-x64/raw.json"
      ],
      "id": "V-decisions-baseline",
      "status": "passed",
      "trigger": "observed"
    }
  ]
}
```

<a id="case-P-decisions-upgrade"></a>

### P\-decisions\-upgrade Useful native decision cost upgrade

- id: P\-decisions\-upgrade
- title: Useful native decision cost upgrade
- kind: performance
- implementation_status: implemented
- origin: generated
- goal: Measure successful three\-call file/process/old\-file units under matched baseline and upgrade loads\.
- obligation_ids: O\-decisions
- boundary_ids: 未声明
- preconditions: 见共用前提与场景输入；性能 preflight: C\-native
- inputs: Two independently compiled native DSOs; 32 ordered anchored\-regex rules; matching last target and protection; four workers; fixed pinned old lease; deterministic local data without credentials\.
- steps:
  1. Construct the initial real native Runtime and warm both operation caches outside timing\.
  2. Validate the initial sentinel pass result\. Start four workers through a barrier\.
  3. In upgrade mode measure Prepare installation/hash/fsync/health and CommitHeld separately, with all four workers asserted active\.
  4. Verify candidate sentinel deny and pinned old sentinel pass, plus changed generation\. Join workers and account only units that passed all three native decision assertions\.
- oracle.method: Fixed explicit semantic outputs and rule/protection expectations independent of matcher implementation
- oracle.assertion: Every current file/current process/old\-file result is pass with rule\-31 and review\. Actual candidate code changes sentinel pass to deny while old code remains pass\. No panic or error is accepted\.
- oracle.independence: Expected values are fixed from the controlled input and fixture change; the oracle does not rerun or mirror the rule matcher\.
- workload_ids: W\-decisions
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "All measured units contain exactly three successfully checked native decisions; positive work, elapsed intervals and sampled latencies are preserved.",
    "assertion_refs": [
      {
        "first": 1,
        "last": 231,
        "path": "crates/hyperhub-engine/examples/native_upgrade_bench.rs"
      }
    ],
    "id": "V-decisions-upgrade",
    "obligation_id": "O-decisions",
    "trigger": "Four workers run the matched 250 ms workload with 32 rules and a retained old lease.",
    "trigger_refs": [
      {
        "first": 1,
        "last": 231,
        "path": "crates/hyperhub-engine/examples/native_upgrade_bench.rs"
      }
    ]
  }
]
```

- code_references:

```json
[
  {
    "first": 1,
    "last": 231,
    "path": "crates/hyperhub-engine/examples/native_upgrade_bench.rs"
  }
]
```

- matrix:

```json
{
  "mode": "upgrade"
}
```

- automation / reproduction:

```json
{
  "argv": [
    "cargo",
    "run",
    "--release",
    "-p",
    "hyperhub-engine",
    "--example",
    "native_upgrade_bench",
    "--locked",
    "--",
    "target/diagnostics/native-engine-performance"
  ],
  "artifact_paths": [
    "crates/hyperhub-engine/examples/native_upgrade_bench.rs",
    "tests/fixtures/network_upgrade_engine.rs",
    "tests/fixtures/engine_fixture_build.rs",
    "tests/benchmarks/engine-upgrade/record.py"
  ],
  "cwd": "."
}
```

- measurement_protocol:

```json
{
  "accounting": "Count unique three-call decision units only after all results pass their independent assertions. A worker error invalidates the execution; no retry is used.",
  "budget": {
    "rationale": "Fixed ten 250ms trials and bounded local source compilation. The external runner imposes process timeout; native deadlock is a failure.",
    "timeout_seconds": 120
  },
  "comparison": {
    "acceptance": null,
    "baseline": "P-decisions-baseline",
    "basis": "Matched same-initial-version no-upgrade baseline; user provided no numeric throughput regression threshold.",
    "factor_ids": [
      "mode"
    ]
  },
  "execution_model": "closed_loop",
  "measurement_context": {
    "end_event": "Instant after all four workers join with successful counts",
    "factor_ids": [
      "mode"
    ],
    "id": "M-decisions-upgrade",
    "level": "component",
    "resources": [],
    "start_event": "Instant immediately before releasing the four-worker barrier",
    "work_units": [
      {
        "description": "One current file decision, one current process decision and one pinned old-file decision, all verified.",
        "id": "decision_unit",
        "unit": "units"
      }
    ]
  },
  "metrics": [
    {
      "kind": "throughput",
      "minimum": 0,
      "name": "units_per_second",
      "subject_id": "decision_unit",
      "subject_kind": "work_unit",
      "summary": "Successful three-native-call units divided by joined wall time.",
      "unit": "units/s"
    },
    {
      "kind": "latency",
      "minimum": 0,
      "name": "unit_latency_ns_p50",
      "subject_id": "decision_unit",
      "subject_kind": "work_unit",
      "summary": "Median of systematically sampled every-64th successful unit latencies within a trial.",
      "unit": "ns"
    },
    {
      "kind": "latency",
      "minimum": 0,
      "name": "unit_latency_ns_p99",
      "subject_id": "decision_unit",
      "subject_kind": "work_unit",
      "summary": "99th percentile of sampled every-64th successful unit latencies; not the full population or service tail.",
      "unit": "ns"
    }
  ],
  "reset": "Fresh Runtime and private artifact cache for each trial; pinned lease remains until the completed trial is dropped.",
  "sampling": {
    "basis": "Five paired alternating-mode trials expose local variation; not a statistical significance or whole-product tail claim.",
    "min_samples": 5,
    "unit": "trial"
  },
  "timing_boundary": "Wall clock from immediately before barrier release until all four workers join; unit sample from before current acquire through three native calls, assertions and successful counter update. Excludes compilation, initial native load/cache warmup and sentinel preflight. Upgrade mode includes concurrent preparation/commit activity in wall time.",
  "uncertainty": "Uncontrolled shared Linux runner, five correlated paired trials, fixed four-thread synthetic load. Sampled unit percentiles omit most calls; report no production SLO or statistically significant regression.",
  "validity_checks": [
    {
      "condition": "All worker assertions pass; every offered unit succeeds exactly once, with three native calls; no retries.",
      "id": "V-work"
    },
    {
      "condition": "Elapsed times, sampled latencies and completed units are positive.",
      "id": "V-clock"
    },
    {
      "condition": "Five actual trials per mode contain raw work counts and samples.",
      "id": "V-samples"
    },
    {
      "condition": "In upgrade mode all four decision workers remain active immediately before and after direct commit.",
      "id": "V-overlap"
    }
  ],
  "warmup": "128 successful file and process decisions per trial before workers start.",
  "work_unit": "One verified file/process/pinned-file decision unit"
}
```

- reported_result:

```json
{
  "acceptance": "not_evaluated",
  "accounting": {
    "accepted": 21808,
    "cancelled": 0,
    "failed": 0,
    "offered": 21808,
    "rejected": 0,
    "retries": 0,
    "succeeded": 21808,
    "unfinished": 0,
    "work_unit_id": "decision_unit"
  },
  "case_id": "P-decisions-upgrade",
  "checks": [
    {
      "details": "Native source assertions and recorded counts, clocks and worker-overlap observations passed.",
      "id": "V-work",
      "status": "passed"
    },
    {
      "details": "Native source assertions and recorded counts, clocks and worker-overlap observations passed.",
      "id": "V-clock",
      "status": "passed"
    },
    {
      "details": "Native source assertions and recorded counts, clocks and worker-overlap observations passed.",
      "id": "V-samples",
      "status": "passed"
    },
    {
      "details": "Native source assertions and recorded counts, clocks and worker-overlap observations passed.",
      "id": "V-overlap",
      "status": "passed"
    }
  ],
  "correctness": "passed",
  "details": "Actual release native DSOs and five paired trials; component evidence, without product-wide or cross-platform performance claims.",
  "evidence": [
    {
      "path": "tests/benchmarks/engine-upgrade/evidence/linux-x64/raw.json",
      "sha256": "e6b3b733adb2620d0d57fd70d120849932a0f5a8844d2576f33a4fa168cd6987"
    }
  ],
  "measurement": "valid",
  "measurement_context_digest": "bddaa85267a694c2a041846e4055cb02a42aa7d1b3b674b7bcc5bba52d5c6d6a",
  "parameters": {
    "mode": "upgrade"
  },
  "samples": {
    "unit_latency_ns_p50": [
      173026,
      169972,
      172128,
      170165,
      171627
    ],
    "unit_latency_ns_p99": [
      3019729,
      223100,
      2188026,
      225283,
      424166
    ],
    "units_per_second": [
      14344.214381448199,
      20905.80462736558,
      12896.634388933733,
      15724.585405056663,
      22448.72245805892
    ]
  },
  "status": "completed",
  "verifications": [
    {
      "details": "Compiled native baseline/candidate code and pinned old leases passed the fixed source semantic assertions.",
      "evidence_paths": [
        "tests/benchmarks/engine-upgrade/evidence/linux-x64/raw.json"
      ],
      "id": "V-decisions-upgrade",
      "status": "passed",
      "trigger": "observed"
    }
  ]
}
```

<a id="case-P-switch"></a>

### P\-switch Direct native prepare and commit under active calls

- id: P\-switch
- title: Direct native prepare and commit under active calls
- kind: performance
- implementation_status: implemented
- origin: generated
- goal: Measure real native preparation separately from direct commit under concurrent decisions, retaining old leases; compare commit with the 100 ms soft budget\.
- obligation_ids: O\-switch
- boundary_ids: 未声明
- preconditions: 见共用前提与场景输入；性能 preflight: C\-native
- inputs: Two independently compiled native DSOs; 32 ordered anchored\-regex rules; matching last target and protection; four workers; fixed pinned old lease; deterministic local data without credentials\.
- steps:
  1. Construct the initial real native Runtime and warm both operation caches outside timing\.
  2. Validate the initial sentinel pass result\. Start four workers through a barrier\.
  3. In upgrade mode measure Prepare installation/hash/fsync/health and CommitHeld separately, with all four workers asserted active\.
  4. Verify candidate sentinel deny and pinned old sentinel pass, plus changed generation\. Join workers and account only units that passed all three native decision assertions\.
- oracle.method: Fixed explicit semantic outputs and rule/protection expectations independent of matcher implementation
- oracle.assertion: Every current file/current process/old\-file result is pass with rule\-31 and review\. Actual candidate code changes sentinel pass to deny while old code remains pass\. No panic or error is accepted\.
- oracle.independence: Expected values are fixed from the controlled input and fixture change; the oracle does not rerun or mirror the rule matcher\.
- workload_ids: W\-switch
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Native preparation and commit have separate positive durations; candidate semantics change while the old lease retains old semantics.",
    "assertion_refs": [
      {
        "first": 1,
        "last": 231,
        "path": "crates/hyperhub-engine/examples/native_upgrade_bench.rs"
      }
    ],
    "id": "V-switch",
    "obligation_id": "O-switch",
    "trigger": "Actual candidate native module is installed and committed while all four workers remain active.",
    "trigger_refs": [
      {
        "first": 1,
        "last": 231,
        "path": "crates/hyperhub-engine/examples/native_upgrade_bench.rs"
      }
    ]
  }
]
```

- code_references:

```json
[
  {
    "first": 1,
    "last": 231,
    "path": "crates/hyperhub-engine/examples/native_upgrade_bench.rs"
  }
]
```

- matrix:

```json
{}
```

- automation / reproduction:

```json
{
  "argv": [
    "cargo",
    "run",
    "--release",
    "-p",
    "hyperhub-engine",
    "--example",
    "native_upgrade_bench",
    "--locked",
    "--",
    "target/diagnostics/native-engine-performance"
  ],
  "artifact_paths": [
    "crates/hyperhub-engine/examples/native_upgrade_bench.rs",
    "tests/fixtures/network_upgrade_engine.rs",
    "tests/fixtures/engine_fixture_build.rs",
    "tests/benchmarks/engine-upgrade/record.py"
  ],
  "cwd": "."
}
```

- measurement_protocol:

```json
{
  "accounting": "One unique native candidate prepare+commit constitutes one upgrade. Five upgrades are offered, accepted and complete; retries and failures are zero for a valid run.",
  "budget": {
    "rationale": "Same bounded component harness and external deadline.",
    "timeout_seconds": 120
  },
  "comparison": {
    "acceptance": "Each of five observed direct commit_ns samples must be <= 100000000 ns (100 ms soft budget). This is no universal latency bound.",
    "baseline": null,
    "basis": "Explicitly requested 100ms soft native switch budget; prepare reported separately with no invented acceptance bound.",
    "factor_ids": []
  },
  "execution_model": "closed_loop",
  "measurement_context": {
    "end_event": "Immediate successful response of each direct management call",
    "factor_ids": [],
    "id": "M-switch",
    "level": "component",
    "resources": [],
    "start_event": "Separate Instant boundaries before direct Prepare and CommitHeld calls",
    "work_units": [
      {
        "description": "One real candidate preparation followed by direct commit under active native decision workers.",
        "id": "native_upgrade",
        "unit": "upgrades"
      }
    ]
  },
  "metrics": [
    {
      "kind": "latency",
      "minimum": 0,
      "name": "prepare_ns",
      "subject_id": "native_upgrade",
      "subject_kind": "work_unit",
      "summary": "Actual direct preparation duration; no 100ms preparation budget is asserted.",
      "unit": "ns"
    },
    {
      "kind": "latency",
      "minimum": 0,
      "name": "commit_ns",
      "subject_id": "native_upgrade",
      "subject_kind": "work_unit",
      "summary": "Actual direct commit duration compared with the requested 100ms soft switch budget.",
      "unit": "ns"
    }
  ],
  "reset": "Fresh initial Runtime/cache per trial; candidate is a separate compiled DSO; rollback occurs after measurements.",
  "sampling": {
    "basis": "Five independent Runtime/candidate installations under the same four-worker offered load; finite local soft-budget check.",
    "min_samples": 5,
    "unit": "trial"
  },
  "timing_boundary": "Prepare clock starts immediately before management::execute(Command::Prepare) and ends after response; includes content-addressed artifact installation, digest checking, fsync, module loading and native health. Commit clock starts immediately before management::execute(Command::CommitHeld) and ends on response; includes actual generation publication, excludes source compilation, source pre-read and control subscription/RPC polling.",
  "uncertainty": "Includes local filesystem/cache behavior and a shared runner. Five samples support only observed soft-budget acceptance, not an upper bound for all hardware/workloads.",
  "validity_checks": [
    {
      "condition": "Actual separate DSOs change sentinel behavior and preserve the pinned old lease.",
      "id": "V-native"
    },
    {
      "condition": "All four workers are still active directly before and after commit.",
      "id": "V-overlap"
    },
    {
      "condition": "Both direct-operation intervals are positive.",
      "id": "V-clock"
    },
    {
      "condition": "Five actual prepare/commit pairs are present.",
      "id": "V-samples"
    }
  ],
  "warmup": "Initial native file/process caches warmed before workers, candidate cache intentionally cold.",
  "work_unit": "One real native candidate prepare and commit"
}
```

- reported_result:

```json
{
  "acceptance": "passed",
  "accounting": {
    "accepted": 5,
    "cancelled": 0,
    "failed": 0,
    "offered": 5,
    "rejected": 0,
    "retries": 0,
    "succeeded": 5,
    "unfinished": 0,
    "work_unit_id": "native_upgrade"
  },
  "case_id": "P-switch",
  "checks": [
    {
      "details": "Native source assertions and recorded counts, clocks and worker-overlap observations passed.",
      "id": "V-native",
      "status": "passed"
    },
    {
      "details": "Native source assertions and recorded counts, clocks and worker-overlap observations passed.",
      "id": "V-overlap",
      "status": "passed"
    },
    {
      "details": "Native source assertions and recorded counts, clocks and worker-overlap observations passed.",
      "id": "V-clock",
      "status": "passed"
    },
    {
      "details": "Native source assertions and recorded counts, clocks and worker-overlap observations passed.",
      "id": "V-samples",
      "status": "passed"
    }
  ],
  "correctness": "passed",
  "details": "Actual release native DSOs and five paired trials; component evidence, without product-wide or cross-platform performance claims.",
  "evidence": [
    {
      "path": "tests/benchmarks/engine-upgrade/evidence/linux-x64/raw.json",
      "sha256": "e6b3b733adb2620d0d57fd70d120849932a0f5a8844d2576f33a4fa168cd6987"
    }
  ],
  "measurement": "valid",
  "measurement_context_digest": "096ff3299ed09378b9fb9acffbda2e16fd0a65474e65be5cfa1500ce1637f969",
  "parameters": {},
  "samples": {
    "commit_ns": [
      1296,
      988,
      1073,
      1019,
      1139
    ],
    "prepare_ns": [
      67752261,
      61057987,
      76268923,
      68985266,
      58191492
    ]
  },
  "status": "completed",
  "verifications": [
    {
      "details": "Compiled native baseline/candidate code and pinned old leases passed the fixed source semantic assertions.",
      "evidence_paths": [
        "tests/benchmarks/engine-upgrade/evidence/linux-x64/raw.json"
      ],
      "id": "V-switch",
      "status": "passed",
      "trigger": "observed"
    }
  ]
}
```

## 覆盖映射

| 阶段 | 义务覆盖 | 子边界覆盖 | 关键缺口 | 完整模型门槛 |
|---|---|---|---|---|
| 设计 | 3/3 | 不适用（分母为零） | 无 | 满足 |
| 实现 | 3/3 | 不适用（分母为零） | 无 | 满足 |
| 申报执行 | 3/3 | 不适用（分母为零） | 无 | 满足 |
| 申报有效测量 | 3/3 | 不适用（分母为零） | 无 | 满足 |

### 义务与子边界

| ID | 类别 / 风险 / 适用性 | 属性与依据 | 所选阶段 |
|---|---|---|---|
| O\-decisions | performance / normal / required | Measure successful three\-call file/process/old\-file units under matched baseline and upgrade loads\. / contract / Authorized native component performance acceptance; 100 ms commit soft budget; no throughput regression threshold specified\. | 已覆盖 |
| O\-oracle | correctness / critical / required | Native FILE/PROCESS decisions match the last rule and protection; candidate code changes a sentinel from pass to deny while pinned old code stays pass\. / contract / Authorized native component performance acceptance; 100 ms commit soft budget; no throughput regression threshold specified\. | 已覆盖 |
| O\-switch | performance / normal / required | Measure real native preparation separately from direct commit under concurrent decisions, retaining old leases; compare commit with the 100 ms soft budget\. / contract / Authorized native component performance acceptance; 100 ms commit soft budget; no throughput regression threshold specified\. | 已覆盖 |

### 组合覆盖

```json
[
  {
    "covered": 2,
    "fraction": 1.0,
    "id": "I-mode",
    "missing": [],
    "obligation_ids": [
      "O-decisions"
    ],
    "required": 2
  }
]
```

### 属性依据与允许结果

#### O\-decisions

```json
{
  "allowed_outcomes": [
    "Measure successful three-call file/process/old-file units under matched baseline and upgrade loads.",
    "Any failed native operation, bad decision, worker panic, or missing timing invalidates the measurement."
  ],
  "basis_evidence": [
    {
      "adoption_reference": null,
      "locator": "crates/hyperhub-engine/examples/native_upgrade_bench.rs:1-209",
      "reference": "Direct native benchmark semantics and controlled workload",
      "role": "acceptance",
      "source_type": "project_contract",
      "verified_scope": "Valid native policy workload, old lease preservation, direct prepare/commit only",
      "version": "native-component-v1"
    }
  ],
  "fault_ids": [
    "F05",
    "F07",
    "F08",
    "F13",
    "F16"
  ],
  "trigger_dimensions": [
    "input",
    "state",
    "concurrency",
    "time",
    "version"
  ]
}
```

#### O\-oracle

```json
{
  "allowed_outcomes": [
    "Native FILE/PROCESS decisions match the last rule and protection; candidate code changes a sentinel from pass to deny while pinned old code stays pass.",
    "Any failed native operation, bad decision, worker panic, or missing timing invalidates the measurement."
  ],
  "basis_evidence": [
    {
      "adoption_reference": null,
      "locator": "crates/hyperhub-engine/examples/native_upgrade_bench.rs:1-209",
      "reference": "Direct native benchmark semantics and controlled workload",
      "role": "acceptance",
      "source_type": "project_contract",
      "verified_scope": "Valid native policy workload, old lease preservation, direct prepare/commit only",
      "version": "native-component-v1"
    }
  ],
  "fault_ids": [
    "F01",
    "F02",
    "F04",
    "F05",
    "F06",
    "F07",
    "F08",
    "F09",
    "F13",
    "F14",
    "F16"
  ],
  "trigger_dimensions": [
    "input",
    "state",
    "concurrency",
    "time",
    "version"
  ]
}
```

#### O\-switch

```json
{
  "allowed_outcomes": [
    "Measure real native preparation separately from direct commit under concurrent decisions, retaining old leases; compare commit with the 100 ms soft budget.",
    "Any failed native operation, bad decision, worker panic, or missing timing invalidates the measurement."
  ],
  "basis_evidence": [
    {
      "adoption_reference": null,
      "locator": "crates/hyperhub-engine/examples/native_upgrade_bench.rs:1-209",
      "reference": "Direct native benchmark semantics and controlled workload",
      "role": "acceptance",
      "source_type": "project_contract",
      "verified_scope": "Valid native policy workload, old lease preservation, direct prepare/commit only",
      "version": "native-component-v1"
    }
  ],
  "fault_ids": [
    "F05",
    "F06",
    "F07",
    "F16"
  ],
  "trigger_dimensions": [
    "input",
    "state",
    "concurrency",
    "time",
    "version"
  ]
}
```

### 类别审查与类别覆盖

各阶段类别覆盖要求该类别关联的义务均达到对应阶段；目录审查完成率不能替代义务或子边界覆盖。

| 阶段 | 类别审查完成 | 适用类别覆盖 |
|---|---|---|
| 设计 | 完成 | 11/11 |
| 实现 | 完成 | 11/11 |
| 申报执行 | 完成 | 11/11 |
| 申报有效测量 | 完成 | 11/11 |

### 工作负载覆盖与范围一致性

#### 设计

```json
{
  "covered": 2,
  "items": [
    {
      "case_ids": [
        "C-native",
        "P-decisions-baseline",
        "P-decisions-upgrade"
      ],
      "covered": true,
      "goal": "Four workers execute current file/current process/pinned old-file decisions with a 32-rule snapshot",
      "id": "W-decisions",
      "missing_atoms": [],
      "role": "primary",
      "unresolved_obligations": []
    },
    {
      "case_ids": [
        "C-native",
        "P-switch"
      ],
      "covered": true,
      "goal": "One actual native prepare and commit while the four workers remain active",
      "id": "W-switch",
      "missing_atoms": [],
      "role": "primary",
      "unresolved_obligations": []
    }
  ],
  "missing": [],
  "mode": "structured",
  "required": 2,
  "scope_aligned": true
}
```

#### 实现

```json
{
  "covered": 2,
  "items": [
    {
      "case_ids": [
        "C-native",
        "P-decisions-baseline",
        "P-decisions-upgrade"
      ],
      "covered": true,
      "goal": "Four workers execute current file/current process/pinned old-file decisions with a 32-rule snapshot",
      "id": "W-decisions",
      "missing_atoms": [],
      "role": "primary",
      "unresolved_obligations": []
    },
    {
      "case_ids": [
        "C-native",
        "P-switch"
      ],
      "covered": true,
      "goal": "One actual native prepare and commit while the four workers remain active",
      "id": "W-switch",
      "missing_atoms": [],
      "role": "primary",
      "unresolved_obligations": []
    }
  ],
  "missing": [],
  "mode": "structured",
  "required": 2,
  "scope_aligned": true
}
```

#### 申报执行

```json
{
  "covered": 2,
  "items": [
    {
      "case_ids": [
        "C-native",
        "P-decisions-baseline",
        "P-decisions-upgrade"
      ],
      "covered": true,
      "goal": "Four workers execute current file/current process/pinned old-file decisions with a 32-rule snapshot",
      "id": "W-decisions",
      "missing_atoms": [],
      "role": "primary",
      "unresolved_obligations": []
    },
    {
      "case_ids": [
        "C-native",
        "P-switch"
      ],
      "covered": true,
      "goal": "One actual native prepare and commit while the four workers remain active",
      "id": "W-switch",
      "missing_atoms": [],
      "role": "primary",
      "unresolved_obligations": []
    }
  ],
  "missing": [],
  "mode": "structured",
  "required": 2,
  "scope_aligned": true
}
```

#### 申报有效测量

```json
{
  "covered": 2,
  "items": [
    {
      "case_ids": [
        "C-native",
        "P-decisions-baseline",
        "P-decisions-upgrade"
      ],
      "covered": true,
      "goal": "Four workers execute current file/current process/pinned old-file decisions with a 32-rule snapshot",
      "id": "W-decisions",
      "missing_atoms": [],
      "role": "primary",
      "unresolved_obligations": []
    },
    {
      "case_ids": [
        "C-native",
        "P-switch"
      ],
      "covered": true,
      "goal": "One actual native prepare and commit while the four workers remain active",
      "id": "W-switch",
      "missing_atoms": [],
      "role": "primary",
      "unresolved_obligations": []
    }
  ],
  "missing": [],
  "mode": "structured",
  "required": 2,
  "scope_aligned": true
}
```

### 性能验收申报

```json
{
  "failed": [],
  "not_evaluated": [
    "C-native",
    "P-decisions-baseline",
    "P-decisions-upgrade"
  ],
  "passed": [
    "P-switch"
  ]
}
```

## 未覆盖与后续

### 设计缺口

```json
{
  "boundaries": [],
  "interactions": [],
  "obligations": [],
  "scope_aligned": true,
  "workloads": []
}
```

### 实现缺口

```json
{
  "boundaries": [],
  "interactions": [],
  "obligations": [],
  "scope_aligned": true,
  "workloads": []
}
```

### 申报执行缺口

```json
{
  "boundaries": [],
  "interactions": [],
  "obligations": [],
  "scope_aligned": true,
  "workloads": []
}
```

### 申报有效测量缺口

```json
{
  "boundaries": [],
  "interactions": [],
  "obligations": [],
  "scope_aligned": true,
  "workloads": []
}
```

### 假设、排除与粒度限制

```json
{
  "coarse_obligations": [
    "O-decisions",
    "O-oracle",
    "O-switch"
  ],
  "conditional_obligations": [],
  "excluded_obligations": [],
  "unresolved_obligations": []
}
```

未声明子边界的义务只有父项粒度；这些比例不能证明其内部边界全部覆盖。触发与断言引用仍需语义审查。

- This is native Engine component performance only; real Hook backend behavior, Windows native execution, workers and whole\-product recovery have separate release tests\.
- Linux release\-profile execution is measured here; no Windows/macOS performance numbers are inferred\.
- Four threads, 32 ordered regex rules, 250ms trials and every\-64th latency samples are controlled assumptions, not a production workload distribution\.
- Only the 100ms commit soft budget has numeric acceptance; no throughput regression threshold or statistical significance is claimed\.
- Coverage is relative to the declared model, source snapshot, and finite factor partitions\.
- Hashes and declarations do not prove semantic completeness, oracle truth, execution authenticity, or statistical validity\.
