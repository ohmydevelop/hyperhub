# HyperHub native Engine component benchmark 测试报告

**报告状态：所选阶段门槛满足。** 所选阶段：reported\_valid。

阶段、条件假设和缺口分别列出；本报告不认证真实执行或模型完备性。

- schema_version: 1\.1
- target: HyperHub native Engine component
- version_or_revision: native\-component\-v1 \(v0\.2\.13 final\-lifecycle\-v12 worktree snapshot\)
- model_digest: 6b192e2ce87b5f818fda9f35ec27787c1afeae5bdc7a0e6def4abbedc87b9bea
- plan_digest: 4c0dc7fd3d4b4c34de57998724aa8ae388a9a4047d6b842328fd10c426e300c9

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
    "Initial model was refrozen before any performance execution to add an explicit all-four-worker overlap oracle; the denominator and requested scope were unchanged. A failed preflight was retained, operation-specific inputs were corrected, and a final refreeze binds the added ownership unit regression, dependency manifests and evidence recorder before the repeated run. The v6 refreeze adds the statically linked Engine lib.rs dependency and its bounded pure-policy capacity retry. The v7 refreeze binds Engine build/native Base source generation and the immutable r2 release context after the verified exec enrollment, ordinary-exit, process-birth and connection-claim lifecycle fixes. The final v8 refreeze binds the r3 immutable CLI after the Windows-only Winsock startup fix; Linux Agent, Engine and native Base remain byte-identical with r2. v5, v6 and v7 raw evidence remain archived separately; no prior performance observations are pooled into this run.",
    "Self-reviewed complete category catalog; exclusions are local to this healthy-path timing experiment.",
    "The v9 provenance refreeze follows the Windows overlapped Stdio::piped cancellation correction. CancelSynchronousIo alone could not cancel the real parent's asynchronous child-pipe operations. The final r4 CLI and Serve Base are bound in model review notes. The native useful-work denominator, fixed trial order/count, source timing boundaries, correctness oracle, sampling and 100ms soft commit acceptance are unchanged. All v8 raw data remains archived separately; no older observation is pooled into the new measurement.",
    "The v10 provenance refreeze follows the actual Windows joint LastError defect. Stable native slot and guard bookkeeping now preserves error state on entry/exit and final destruction. The r5 immutable artifacts and source hashes bind this context; Windows functional error semantics remain a separate real native probe/Suite gate. The native useful-work denominator, fixed trial order/count, source timing boundaries, oracle, sampling and 100ms soft commit acceptance are unchanged. All v9 raw data and reports remain archived separately and are not pooled.",
    "The v11 provenance refreeze follows the minimal test-cfg layout correction that restores the documented tests-do-not-change-NativeBase invariant. Only source hash/current artifact context and review notes change; workload, full fault-category review, cases, oracle, timers, sampling and 100ms soft commit acceptance are preserved. All prior v10 raw observations and reports stay separate, with no pooled measurement or best-run selection.",
    "The v12 source/artifact refreeze follows actual Unix fork handoff and application callback/signal safety corrections. All new lifecycle sources are bound as release context, while the native timed healthy workload and its complete category review, correctness oracle, trial protocol and acceptance threshold stay fixed. The unmeasured v11 freeze is preserved as such; earlier measured v10 evidence is separate and not pooled."
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
  "notes": "Re-reviewed the same sixteen fault categories for this controlled healthy-path native component timing scope. The authenticated Unix fork broker, pre-recovery policy rejection, original-thread signal-mask restoration and same-Core persistent native listener change the actual NativeBase and embedded artifacts. The process-lifetime Frida device owner avoids blocking SDK teardown on an unused failed-fork clone after the managed tree is drained. The model now binds their authoritative production sources and the separate actual source-fixture regressions. These sources are release context; the timed component workload does not claim to execute fork recovery, application signal handlers or product delivery. Functional before/after and full product gates remain separately required. Immutable build context: release-013-acceptance-r13; artifact SHA256 {\"hyperhub\": \"535729536f8b00b993f58b04ef401458da9dcf9256f11da07933584e0037af94\", \"libhyperhub_engine.so\": \"8954ddcced32a22ab22e5c8c8adb9618152fe7dffa1446e0280405f2b26f6fb3\", \"libhyperhub_gum_agent.so\": \"a5ad8fcd54b90e6a0bca0b3a8193855c8c4a6bee7587f87d7b0157ff9376633c\"}; Base context {\"abi\": 65536, \"frida_version\": \"17.17.0\", \"hooks\": 8191, \"installer_protocol\": 1, \"native_base_sha256\": \"a23dc05b4ddf025d13f5d429fb0326dba4d5414f7b7991c74993f8cc1819bef2\", \"serve_base_sha256\": \"1ab0a09259195121185e553e7a0248775dbf2301fc6b5eaa500b4fe5f268651f\", \"state_schema\": 2, \"worker_protocol\": 1}. Reviewed later test-only source deltas are explicitly recorded: the helper Host-registration oracle and the unified Linux Suite private0700 XDG_RUNTIME_DIR isolate actual CA artifacts from the full user runtime. Neither changes native timing workload or acceptance. The useful-work denominator, fixed baseline/upgrade trial order/count, overlap oracle, native timer boundaries, sampling, and 100ms soft-commit acceptance remain unchanged. The v11 source freeze was not measured. All actual v10 raw evidence and reports remain archived separately; observations are never pooled or selected.",
  "reviewer": "Codex release_audit"
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
    "path": "crates/hyperhub-agent-core/src/engine_call.rs",
    "sha256": "4a12bc5dba2e02de8d6fc897704f65c9557f6cf3976ba00f35e4ab2ff6450c7e"
  },
  {
    "path": "crates/hyperhub-agent-core/src/engine_call/slots.rs",
    "sha256": "27ac1918a08f59892d93e2d63d6ccf27fe5bc54eab12d942690fabea8145ba05"
  },
  {
    "path": "crates/hyperhub-agent-core/src/unix_gum/adapters/native.rs",
    "sha256": "7773e2b84aec9564264ab8cad530c334cda0079ed025c41cbfb0a9c8dde90276"
  },
  {
    "path": "crates/hyperhub-agent-core/src/unix_gum/fork.rs",
    "sha256": "90d48a66b88bc2cebdf5eef4f9a74988d63567f209b658ef0b03c03da3fecddc"
  },
  {
    "path": "crates/hyperhub-agent-core/src/unix_gum/fork_handoff.rs",
    "sha256": "fcc344df772dc4dcbf10cfec7d7aad1aa771162eb9f0088acea4757b89a5ca7e"
  },
  {
    "path": "crates/hyperhub-agent-core/src/unix_gum/gum.rs",
    "sha256": "f982244b1ade21b8ab3060660e8b1e48905dfa3d0e7120465dc367c424f8f323"
  },
  {
    "path": "crates/hyperhub-agent-core/src/unix_gum/mod.rs",
    "sha256": "12d83a39b753cf826cc72f719d861e1412f3757f80513643738c7b40eb94cf51"
  },
  {
    "path": "crates/hyperhub-agent-core/src/windows_gum/gum.rs",
    "sha256": "c42423a2d45f0c556aeecbae9be0721eb32cbdba81b9fa2db0ef389bb1366e99"
  },
  {
    "path": "crates/hyperhub-cli/src/platform/linux/fork_handoff.rs",
    "sha256": "4ec85b2ef49d2439b947b91f3ec09951023c3a03e3f397b36d5b46665d70d013"
  },
  {
    "path": "crates/hyperhub-cli/src/platform/linux/frida_core/child_gating.rs",
    "sha256": "a251bb64afb86b95b006f61c914c829bdab19df046015c06b80b52e07dcbe0a0"
  },
  {
    "path": "crates/hyperhub-cli/src/platform/linux/frida_core/context.rs",
    "sha256": "747e7a5cfc6570d1dd39d96ef655e32914fbe553b04ec76eda30ac1122be4d9b"
  },
  {
    "path": "crates/hyperhub-cli/src/platform/linux/frida_core/fork_listener.rs",
    "sha256": "6f03c7d2c088ac0ef3c6d4d842f4c432661ad5d049ab8302c156c9a13f620e87"
  },
  {
    "path": "crates/hyperhub-cli/src/platform/linux/frida_core/mod.rs",
    "sha256": "759ea620add421aae68eb0d2247c0fc5383f56f6ddb650999d0258f98a1fadf8"
  },
  {
    "path": "crates/hyperhub-cli/src/platform/linux/launcher.rs",
    "sha256": "73d408a10750fba6ecfabad2251cc0e8d14f5123add8a08063971929caaa9d9a"
  },
  {
    "path": "crates/hyperhub-cli/src/platform/linux/mod.rs",
    "sha256": "65ab5e181e7a4d1a4080c96ad96fc29d71b911acfc9b6779ec53732be098a800"
  },
  {
    "path": "crates/hyperhub-cli/tests/engine_host_live.rs",
    "sha256": "7fe5db95d3cc7c4e8841e8466b03ca6df16aface9461a82941b52398d0b2d268"
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
    "sha256": "d16ccaa65fb4b33239118b93bd9a3870ce9fb3583486373e389499d8186d3100"
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
    "path": "scripts/benchmark-linux-backends.sh",
    "sha256": "98c2b3b1e159ffe402d314a2f5b1cc2ae682ab3688073436d52daa1a6462257b"
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
    "path": "tests/fixtures/engine_host_target.rs",
    "sha256": "6fa7462f395a6b2e26e6354e1e1f5b7872eef174b6ae7634279902a79fbf0516"
  },
  {
    "path": "tests/fixtures/failed_fork_target.rs",
    "sha256": "5239af1749dca5f053357ba84b33af6837e2b17e1673de53e83e6ebc9e23ca2a"
  },
  {
    "path": "tests/fixtures/linux_fork_signal_target.rs",
    "sha256": "58a175f4de6a3bf30957378d37702053dce38ead0dfd5f8da81a0cce6ca32c62"
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
      "sha256": "ec5c77b10328714778b07813f312d38fea3515bbc0e0bc144c3e5d9663347382"
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
    "accepted": 26175,
    "cancelled": 0,
    "failed": 0,
    "offered": 26175,
    "rejected": 0,
    "retries": 0,
    "succeeded": 26175,
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
      "sha256": "ec5c77b10328714778b07813f312d38fea3515bbc0e0bc144c3e5d9663347382"
    }
  ],
  "measurement": "valid",
  "measurement_context_digest": "3971a8c229c8bbf14be9ab5efc096aeb2672b4919a565a5fbe5c896b1cc28061",
  "parameters": {
    "mode": "baseline"
  },
  "samples": {
    "unit_latency_ns_p50": [
      168315,
      165420,
      166289,
      165850,
      165802
    ],
    "unit_latency_ns_p99": [
      465933,
      217108,
      429444,
      186579,
      204032
    ],
    "units_per_second": [
      18914.89211529286,
      21360.34913764924,
      21660.4090314671,
      21618.345852759398,
      20866.616142176892
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
    "accepted": 26302,
    "cancelled": 0,
    "failed": 0,
    "offered": 26302,
    "rejected": 0,
    "retries": 0,
    "succeeded": 26302,
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
      "sha256": "ec5c77b10328714778b07813f312d38fea3515bbc0e0bc144c3e5d9663347382"
    }
  ],
  "measurement": "valid",
  "measurement_context_digest": "bddaa85267a694c2a041846e4055cb02a42aa7d1b3b674b7bcc5bba52d5c6d6a",
  "parameters": {
    "mode": "upgrade"
  },
  "samples": {
    "unit_latency_ns_p50": [
      172810,
      170997,
      170753,
      169915,
      171671
    ],
    "unit_latency_ns_p99": [
      188998,
      217954,
      287055,
      182727,
      3180548
    ],
    "units_per_second": [
      18182.37815266687,
      21201.440802608602,
      22791.226064780116,
      22852.271725228697,
      19651.677817918728
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
      "sha256": "ec5c77b10328714778b07813f312d38fea3515bbc0e0bc144c3e5d9663347382"
    }
  ],
  "measurement": "valid",
  "measurement_context_digest": "096ff3299ed09378b9fb9acffbda2e16fd0a65474e65be5cfa1500ce1637f969",
  "parameters": {},
  "samples": {
    "commit_ns": [
      1165,
      1130,
      1121,
      988,
      1509
    ],
    "prepare_ns": [
      81000545,
      46633534,
      45414031,
      38074398,
      45747315
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
