# HyperHub dynamic attachment lifecycle benchmark 测试报告

**报告状态：未达标草案。** 所选阶段：implemented。

阶段、条件假设和缺口分别列出；本报告不认证真实执行或模型完备性。

- schema_version: 1\.1
- target: HyperHub dynamic attachment lifecycle
- version_or_revision: 0\.3\.0\-alpha\.1 development draft before final source freeze
- model_digest: 5f44b700169fa4f3238bf264aa259f6bab94fcc850d97a655890190d8eff929e
- plan_digest: 73edcf2302fc805765b5d4dbce1a485a9041c2ab574dac1b13d2a158055510ed

导航：[准备](#准备) · [可靠性场景](#可靠性场景) · [性能场景](#性能场景) · [覆盖映射](#覆盖映射) · [未覆盖与后续](#未覆盖与后续)

## 不变量

- 正确性 preflight 与性能计时分开；性能 case 必须关联 preflight。
- 覆盖分母来自冻结模型；条件假设、未决项与排除项保持可见。
- 未运行阶段不写通过结论；测量有效和性能验收分别报告。

## 准备

### 环境

待记录；本次未提交执行环境或运行证据。

### 配置

```json
{
  "constraints": [],
  "factors": [
    {
      "id": "backend",
      "values": [
        "linux-ptrace",
        "linux-gum",
        "windows-gum"
      ]
    },
    {
      "id": "origin",
      "values": [
        "attach",
        "run"
      ]
    }
  ]
}
```

### 共用前提与清理

```json
{
  "cleanup": [
    "Terminate only owned fixture processes and remove only owned temporary state.",
    "Retain sanitized pass/failure evidence separately from encrypted configuration and approval secrets."
  ],
  "generation_notes": [
    "Primary-agent draft began as self review; this revision adds an independent attach_core source/assertion audit. It is still a mutable development draft, not an executed or frozen release report.",
    "Independent attach_core review preserves primary-agent draft denominator; implemented status means actual source trigger/assertion/entrypoint binding only. It does not claim build, native execution, a two-hour soak, mutation sensitivity or performance acceptance. No final freeze while production sources change."
  ],
  "preconditions": [
    "Use disposable targets, private Home and local deterministic services.",
    "Do not weaken host attach restrictions or operate real application processes."
  ]
}
```

### 目标范围与工作负载

```json
{
  "scope": {
    "delivered_level": "component",
    "goal": "Validate dynamic attachment and observable local-fixture overhead.",
    "rationale": "Feature scope; not all HyperHub protocols or production workload distributions.",
    "requested_level": "component"
  },
  "workloads": [
    {
      "applicability": "required",
      "goal": "Approved attach, detach, reattach and fault recovery for local process trees.",
      "id": "W-attachment",
      "obligation_ids": [
        "O-approval",
        "O-tree",
        "O-continuity",
        "O-drain",
        "O-fake",
        "O-recovery",
        "O-resources",
        "O-release",
        "O-measure"
      ],
      "rationale": "Directly requested feature.",
      "role": "primary",
      "source_refs": [
        {
          "first": 1,
          "last": 84,
          "path": "docs/dynamic-attach.md"
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
| F01 | required | O\-approval, O\-continuity, O\-tree | Only fresh human approval bound to exact process incarnation, instance, scope, backend, policy and bootstrap may mutate an external target\. Proposal alone has no effect\.; Tree scope covers current threads, existing descendants and future descendants; process scope leaves other processes unmanaged\. Living descendants remain managed after root exit\.; Preserve allowed payloads, existing TCP, blocking original calls, socket flags, explicit child environments, PID, cwd, stdio, terminal state and original root exit status\. | docs/dynamic\-attach\.md:1\-84 |
| F02 | required | O\-drain, O\-measure | Approved detach stops new enforcement\. Keep compatibility code while calls, async operations, trust contexts, callbacks or cached addresses need it\. Detached requires independent physical\-unload proof\.; Compare identical validated snapshot/socket work in unmanaged, same\-backend run, Active and Detached windows\. Separate raw command latency and valid throughput from approval duration\. No universal performance threshold\. | docs/dynamic\-attach\.md:1\-84 |
| F03 | required | O\-approval, O\-release | Only fresh human approval bound to exact process incarnation, instance, scope, backend, policy and bootstrap may mutate an external target\. Proposal alone has no effect\.; Isolate development binaries, Home, Skill and updates\. Explicit prerelease tags do not replace stable defaults\. Publish only after exact\-commit platform CI and soak success\. | docs/dynamic\-attach\.md:1\-84 |
| F04 | required | O\-approval, O\-continuity, O\-drain, O\-fake, O\-tree | Only fresh human approval bound to exact process incarnation, instance, scope, backend, policy and bootstrap may mutate an external target\. Proposal alone has no effect\.; Tree scope covers current threads, existing descendants and future descendants; process scope leaves other processes unmanaged\. Living descendants remain managed after root exit\.; Preserve allowed payloads, existing TCP, blocking original calls, socket flags, explicit child environments, PID, cwd, stdio, terminal state and original root exit status\.; Approved detach stops new enforcement\. Keep compatibility code while calls, async operations, trust contexts, callbacks or cached addresses need it\. Detached requires independent physical\-unload proof\.; Previously cached FAKE\-IP aliases remain usable across detach and reattach\. Do not reassign an address to another destination while application caches may retain it\. | docs/dynamic\-attach\.md:1\-84 |
| F05 | required | O\-continuity, O\-drain, O\-tree | Tree scope covers current threads, existing descendants and future descendants; process scope leaves other processes unmanaged\. Living descendants remain managed after root exit\.; Preserve allowed payloads, existing TCP, blocking original calls, socket flags, explicit child environments, PID, cwd, stdio, terminal state and original root exit status\.; Approved detach stops new enforcement\. Keep compatibility code while calls, async operations, trust contexts, callbacks or cached addresses need it\. Detached requires independent physical\-unload proof\. | docs/dynamic\-attach\.md:1\-84 |
| F06 | required | O\-approval, O\-continuity, O\-recovery | Only fresh human approval bound to exact process incarnation, instance, scope, backend, policy and bootstrap may mutate an external target\. Proposal alone has no effect\.; Preserve allowed payloads, existing TCP, blocking original calls, socket flags, explicit child environments, PID, cwd, stdio, terminal state and original root exit status\.; Serve and manager loss preserve allowed business activity and report enforcement loss\. Fresh approved recovery reconnects compatible residue or safely seizes an untraced target; never stack injection\. | docs/dynamic\-attach\.md:1\-84 |
| F07 | required | O\-drain, O\-fake, O\-resources | Approved detach stops new enforcement\. Keep compatibility code while calls, async operations, trust contexts, callbacks or cached addresses need it\. Detached requires independent physical\-unload proof\.; Previously cached FAKE\-IP aliases remain usable across detach and reattach\. Do not reassign an address to another destination while application caches may retain it\.; At least 100 cycles and two hours of mixed activity per backend preserve semantics without continued native module, thread, FD or handle count growth after warmup\. | docs/dynamic\-attach\.md:1\-84 |
| F08 | required | O\-measure, O\-resources | At least 100 cycles and two hours of mixed activity per backend preserve semantics without continued native module, thread, FD or handle count growth after warmup\.; Compare identical validated snapshot/socket work in unmanaged, same\-backend run, Active and Detached windows\. Separate raw command latency and valid throughput from approval duration\. No universal performance threshold\. | docs/dynamic\-attach\.md:1\-84 |
| F09 | required | O\-continuity, O\-drain, O\-recovery | Preserve allowed payloads, existing TCP, blocking original calls, socket flags, explicit child environments, PID, cwd, stdio, terminal state and original root exit status\.; Approved detach stops new enforcement\. Keep compatibility code while calls, async operations, trust contexts, callbacks or cached addresses need it\. Detached requires independent physical\-unload proof\.; Serve and manager loss preserve allowed business activity and report enforcement loss\. Fresh approved recovery reconnects compatible residue or safely seizes an untraced target; never stack injection\. | docs/dynamic\-attach\.md:1\-84 |
| F10 | required | O\-recovery | Serve and manager loss preserve allowed business activity and report enforcement loss\. Fresh approved recovery reconnects compatible residue or safely seizes an untraced target; never stack injection\. | docs/dynamic\-attach\.md:1\-84 |
| F11 | required | O\-approval, O\-recovery | Only fresh human approval bound to exact process incarnation, instance, scope, backend, policy and bootstrap may mutate an external target\. Proposal alone has no effect\.; Serve and manager loss preserve allowed business activity and report enforcement loss\. Fresh approved recovery reconnects compatible residue or safely seizes an untraced target; never stack injection\. | docs/dynamic\-attach\.md:1\-84 |
| F12 | required | O\-recovery | Serve and manager loss preserve allowed business activity and report enforcement loss\. Fresh approved recovery reconnects compatible residue or safely seizes an untraced target; never stack injection\. | docs/dynamic\-attach\.md:1\-84 |
| F13 | required | O\-approval, O\-drain, O\-fake, O\-release, O\-tree | Only fresh human approval bound to exact process incarnation, instance, scope, backend, policy and bootstrap may mutate an external target\. Proposal alone has no effect\.; Tree scope covers current threads, existing descendants and future descendants; process scope leaves other processes unmanaged\. Living descendants remain managed after root exit\.; Approved detach stops new enforcement\. Keep compatibility code while calls, async operations, trust contexts, callbacks or cached addresses need it\. Detached requires independent physical\-unload proof\.; Previously cached FAKE\-IP aliases remain usable across detach and reattach\. Do not reassign an address to another destination while application caches may retain it\.; Isolate development binaries, Home, Skill and updates\. Explicit prerelease tags do not replace stable defaults\. Publish only after exact\-commit platform CI and soak success\. | docs/dynamic\-attach\.md:1\-84 |
| F14 | required | O\-continuity, O\-release | Preserve allowed payloads, existing TCP, blocking original calls, socket flags, explicit child environments, PID, cwd, stdio, terminal state and original root exit status\.; Isolate development binaries, Home, Skill and updates\. Explicit prerelease tags do not replace stable defaults\. Publish only after exact\-commit platform CI and soak success\. | docs/dynamic\-attach\.md:1\-84 |
| F15 | required | O\-approval, O\-release | Only fresh human approval bound to exact process incarnation, instance, scope, backend, policy and bootstrap may mutate an external target\. Proposal alone has no effect\.; Isolate development binaries, Home, Skill and updates\. Explicit prerelease tags do not replace stable defaults\. Publish only after exact\-commit platform CI and soak success\. | docs/dynamic\-attach\.md:1\-84 |
| F16 | required | O\-measure, O\-recovery, O\-release, O\-resources | Serve and manager loss preserve allowed business activity and report enforcement loss\. Fresh approved recovery reconnects compatible residue or safely seizes an untraced target; never stack injection\.; At least 100 cycles and two hours of mixed activity per backend preserve semantics without continued native module, thread, FD or handle count growth after warmup\.; Isolate development binaries, Home, Skill and updates\. Explicit prerelease tags do not replace stable defaults\. Publish only after exact\-commit platform CI and soak success\.; Compare identical validated snapshot/socket work in unmanaged, same\-backend run, Active and Detached windows\. Separate raw command latency and valid throughput from approval duration\. No universal performance threshold\. | docs/dynamic\-attach\.md:1\-84 |

### 基线

各性能场景分别列出比较基线与验收依据；未声明的值不补写。

### 审查记录

```json
{
  "kind": "independent",
  "notes": "Independent review against native drivers, actual fixture assertions and accepted PLAN.md. All original nine obligations and six backend/origin combinations remain required. Explicit sub-boundaries expose missing FAKE-IP, fault, resource, terminal, unload and throughput coverage. Mutable source snapshot is a draft, not the release freeze; no execution or valid measurements are inferred. Required trust-root/cold-start/history-integrity and Windows MSYS/Cygwin fork boundaries are explicitly planned; no native exec equivalence is assumed.",
  "reviewer": "Codex attach_core subagent reviewing primary-agent draft"
}
```

### 证据

冻结源码：

```json
[
  {
    "path": ".github/workflows/release.yml",
    "sha256": "389664b86207d5cbd3d98bdd7f2ef828045061fa37e2c7d7d4a210eeffdc226b"
  },
  {
    "path": "Cargo.lock",
    "sha256": "718685ca937deb7e964290569a388dfc07576a41b8cba0576bbbbbe238b623c5"
  },
  {
    "path": "Cargo.toml",
    "sha256": "9a88ae7fa40d858654f67da1347cb85edfec4ba33444d9217a502acfb1dbc472"
  },
  {
    "path": "crates/hyperhub-agent-core/src/attachment.rs",
    "sha256": "61d16a998ae443c47ce934fa7a0088951463518eca94dd6fc6e05ab67c4ecd94"
  },
  {
    "path": "crates/hyperhub-agent-core/src/sandbox/network.rs",
    "sha256": "f608ca36f3277f5003e15d49ebbcb2a6a76797872308a8d143e434951f43a0d8"
  },
  {
    "path": "crates/hyperhub-cli/src/attachment/owned_keeper.rs",
    "sha256": "95cec04a6a47170052ed1480af08122c24da34d8cc02fb7f7d40be100104fc43"
  },
  {
    "path": "crates/hyperhub-cli/src/attachment/terminal_replan.rs",
    "sha256": "0e0a09250c24531a98496236b8168c8592854083556da0074d94f0a051626e0e"
  },
  {
    "path": "crates/hyperhub-core/src/attachments/authority.rs",
    "sha256": "8d23a18b0bdbb00db5f5841b3a4ba9aa026f22a55b85e091f678a6ce3532161c"
  },
  {
    "path": "crates/hyperhub-core/src/attachments/capabilities.rs",
    "sha256": "a3a58c0eb7213e76322c53345ac3e71fdeca39fcd2d9927f5eb8eeb58c2ff744"
  },
  {
    "path": "crates/hyperhub-core/src/attachments/control.rs",
    "sha256": "28eb206395043a1696c1a4c3ca49ea3f9767a11302a223a92353f40d0f6a02b2"
  },
  {
    "path": "crates/hyperhub-core/src/attachments/manager.rs",
    "sha256": "281845ff0e392c24f4b33c6a1caa22e51a311c22e61fe7c98e91b4914f01c96d"
  },
  {
    "path": "crates/hyperhub-core/src/attachments/tests.rs",
    "sha256": "8b540d0f2e8faba5a4ddae8bd9bce5da7c0b61727be0920df2b276ac78f959d1"
  },
  {
    "path": "crates/hyperhub-runtime/src/attachment/proof_tests.rs",
    "sha256": "9dc55bac261095bf81d64ef3f5512d44cc634a7d456fc901c59b350bc7ec0061"
  },
  {
    "path": "docs/benchmarks/dynamic-attach/AUTHORITY-ANCHOR-DESIGN.draft.md",
    "sha256": "d3236fb646cca0a281c397d82a0dff3e58ed7e5ef3e05cd8588fb5a6b5e6be31"
  },
  {
    "path": "docs/benchmarks/dynamic-attach/DETACHED-ALIAS-DNS-DESIGN.draft.md",
    "sha256": "7a84c028ce7d9ac859745f9332a9b3805ec17553a741bf2cc5e9e3aa9cfc835c"
  },
  {
    "path": "docs/dynamic-attach.md",
    "sha256": "34360634b6e231ab2c72c5517f9d0751833b43d740c731ba2e0799cb272ecc0a"
  },
  {
    "path": "scripts/benchmark-linux-backends.sh",
    "sha256": "8f32c183ed7550660621733798b90a26a6e86a2d0f4d0e4bbb76f109f4c01f16"
  },
  {
    "path": "scripts/install.ps1",
    "sha256": "c8c07adde5d6656eba673892280c070ce2221f8fae091ea1f1490b18923ff1ff"
  },
  {
    "path": "scripts/install.sh",
    "sha256": "81b88b2ab890e33372dcb2b6d87a92f0688d286290711a26d0db9ad265a35f62"
  },
  {
    "path": "scripts/test-development-install.ps1",
    "sha256": "e27d292c8846ff2a2dfea25f2bd1bffb2d5822d3f10702dcf3a4e8655b8f3c04"
  },
  {
    "path": "scripts/test-development-release.py",
    "sha256": "9fe5b56b9da0eb960347fc1205ea97254b27b0af60725cd09c55e5f757606730"
  },
  {
    "path": "scripts/test-dynamic-attach-windows.py",
    "sha256": "61e5381b020eea734736027809125545758a403ee0ab4c0322245b18d292a634"
  },
  {
    "path": "scripts/test-dynamic-attach.py",
    "sha256": "e5863b560950f6f9a9084d58cf83dfef4ff4a815bcde84811cf892630e2c43eb"
  },
  {
    "path": "scripts/test-windows-hooks.ps1",
    "sha256": "2527193afa883def9bfbbdb18646d66164f85c17359a54d9574d6b111e928798"
  },
  {
    "path": "scripts/windows_conpty.py",
    "sha256": "d3031c44fdcac839bb07466e726e64c9703126809739aad975bef923eeda89f1"
  },
  {
    "path": "tests/fixtures/dynamic_attach_legacy_marker.rs",
    "sha256": "a47614ab8859bbe05f39dc7115febb2378e74ff9ed830b61f9e32d19d48feee6"
  },
  {
    "path": "tests/fixtures/dynamic_attach_target.c",
    "sha256": "3b3dca010046d905e84ed4c37546c50cb5dcf9b273e0bd0b9c2a56453a883024"
  },
  {
    "path": "tests/fixtures/dynamic_attach_windows.rs",
    "sha256": "15fb63c2337e54df0f8ecb5da0e7c35b5e8df2433a74aa8b9f1aff9b36326273"
  }
]
```

## 可靠性场景

| 场景 | 标题 | 来源 | 实现状态 | 运行状态 |
|---|---|---|---|---|
| [C\-approval](#case-C-approval) | Only fresh human approval bound to exact process incarnation, instance, scope, backend, policy and bootstrap may mutate an external target\. Proposal alone has no effect\. | generated | planned | 未提交执行记录 |
| [C\-cached\-alias\-linux\-gum](#case-C-cached-alias-linux-gum) | Active cached\-alias new TCP is denied while independent native loopback echo succeeds; after detach that same cached alias echoes and getpeername proves the native loopback target, not old gateway\. | existing | planned | 未提交执行记录 |
| [C\-cached\-alias\-linux\-ptrace](#case-C-cached-alias-linux-ptrace) | Active cached\-alias new TCP is denied while independent native loopback echo succeeds; after detach that same cached alias echoes and getpeername proves the native loopback target, not old gateway\. | existing | planned | 未提交执行记录 |
| [C\-capability\-preflight](#case-C-capability-preflight) | Existing\-context TLS and SSH requirement rejection | existing | implemented | 未提交执行记录 |
| [C\-committed\-cleanup\-recovery](#case-C-committed-cleanup-recovery) | Fresh cleanup after lost completion ACK and old\-manager death | existing | implemented | 未提交执行记录 |
| [C\-completion\-protocol](#case-C-completion-protocol) | Consumed historical approval and exact physical\-completion marker | existing | implemented | 未提交执行记录 |
| [C\-continuity](#case-C-continuity) | Preserve allowed payloads, existing TCP, blocking original calls, socket flags, explicit child environments, PID, cwd, stdio, terminal state and original root exit status\. | generated | planned | 未提交执行记录 |
| [C\-core\-approval\-boundaries](#case-C-core-approval-boundaries) | Shared signatures, single consumption, API isolation and password generation | existing | implemented | 未提交执行记录 |
| [C\-development\-isolation](#case-C-development-isolation) | Linux explicit\-tag installer and real prerelease CLI isolation | existing | implemented | 未提交执行记录 |
| [C\-dirty\-ptrace\-recovery\-refusal](#case-C-dirty-ptrace-recovery-refusal) | Ptrace dirty virtual descriptor recovery refuses safely | existing | implemented | 未提交执行记录 |
| [C\-drain](#case-C-drain) | Approved detach stops new enforcement\. Keep compatibility code while calls, async operations, trust contexts, callbacks or cached addresses need it\. Detached requires independent physical\-unload proof\. | generated | planned | 未提交执行记录 |
| [C\-fake](#case-C-fake) | Previously cached FAKE\-IP aliases remain usable across detach and reattach\. Do not reassign an address to another destination while application caches may retain it\. | generated | planned | 未提交执行记录 |
| [C\-linux\-gum\-process](#case-C-linux-gum-process) | Linux gum process scope excludes other processes | existing | implemented | 未提交执行记录 |
| [C\-linux\-host\-peer](#case-C-linux-host-peer) | Linux IPC authenticates server before proof exposure | existing | implemented | 未提交执行记录 |
| [C\-linux\-ptrace\-process](#case-C-linux-ptrace-process) | Linux ptrace process scope excludes other processes | existing | implemented | 未提交执行记录 |
| [C\-manager\-recovery\-linux\-gum](#case-C-manager-recovery-linux-gum) | Target survives; ptrace reports lost enforcement and Gum retains cached deny; fresh approved same\-id recovery restores deny, same session scope and correct child results\. | existing | implemented | 未提交执行记录 |
| [C\-manager\-recovery\-linux\-ptrace](#case-C-manager-recovery-linux-ptrace) | Target survives; ptrace reports lost enforcement and Gum retains cached deny; fresh approved same\-id recovery restores deny, same session scope and correct child results\. | existing | implemented | 未提交执行记录 |
| [C\-native\-linux\-gum\-attach](#case-C-native-linux-gum-attach) | Linux gum attach native correctness and controlling PTY | existing | implemented | 未提交执行记录 |
| [C\-native\-linux\-gum\-run](#case-C-native-linux-gum-run) | Linux gum run native correctness and controlling PTY | existing | implemented | 未提交执行记录 |
| [C\-native\-linux\-ptrace\-attach](#case-C-native-linux-ptrace-attach) | Linux ptrace attach native correctness and controlling PTY | existing | implemented | 未提交执行记录 |
| [C\-native\-linux\-ptrace\-run](#case-C-native-linux-ptrace-run) | Linux ptrace run native correctness and controlling PTY | existing | implemented | 未提交执行记录 |
| [C\-native\-windows\-gum](#case-C-native-windows-gum) | Windows native tree, reconnect, original\-call drain and module absence | existing | implemented | 未提交执行记录 |
| [C\-recovery](#case-C-recovery) | Serve and manager loss preserve allowed business activity and report enforcement loss\. Fresh approved recovery reconnects compatible residue or safely seizes an untraced target; never stack injection\. | generated | planned | 未提交执行记录 |
| [C\-release](#case-C-release) | Isolate development binaries, Home, Skill and updates\. Explicit prerelease tags do not replace stable defaults\. Publish only after exact\-commit platform CI and soak success\. | generated | planned | 未提交执行记录 |
| [C\-resources](#case-C-resources) | At least 100 cycles and two hours of mixed activity per backend preserve semantics without continued native module, thread, FD or handle count growth after warmup\. | generated | planned | 未提交执行记录 |
| [C\-rootexit\-linux\-gum](#case-C-rootexit-linux-gum) | Owned Linux gum root exits while survivor stays managed | existing | implemented | 未提交执行记录 |
| [C\-rootexit\-linux\-ptrace](#case-C-rootexit-linux-ptrace) | Owned Linux ptrace root exits while survivor stays managed | existing | implemented | 未提交执行记录 |
| [C\-serve\-restart\-linux\-gum](#case-C-serve-restart-linux-gum) | Direct old stream survives; deny remains and original attachment session id is preserved\. | existing | implemented | 未提交执行记录 |
| [C\-serve\-restart\-linux\-ptrace](#case-C-serve-restart-linux-ptrace) | Direct old stream survives; deny remains and original attachment session id is preserved\. | existing | implemented | 未提交执行记录 |
| [C\-soak\-linux\-gum](#case-C-soak-linux-gum) | At least100 successful cycles and7200 post\-setup seconds; every checked payload is valid and FD/thread/executable\-map counts do not exceed the cycle\-two warmup baseline\. | existing | implemented | 未提交执行记录 |
| [C\-soak\-linux\-ptrace](#case-C-soak-linux-ptrace) | At least100 successful cycles and7200 post\-setup seconds; every checked payload is valid and FD/thread/executable\-map counts do not exceed the cycle\-two warmup baseline\. | existing | implemented | 未提交执行记录 |
| [C\-soak\-windows\-gum](#case-C-soak-windows-gum) | At least100 successful cycles and7200 post\-setup seconds; no native load/TCP or resource\-sampling error; every post\-warmup logical detach remains within documented handle\+8/thread\+1 bounded slack and eligible modules are absent\. | existing | implemented | 未提交执行记录 |
| [C\-terminal\-slot\-race](#case-C-terminal-slot-race) | A Draining/resident slot that becomes terminal during human review receives fresh request/attachment/session/token epochs without changing target/scope/backend/policy or repeating approval; clients follow the actual returned id\. | existing | implemented | 未提交执行记录 |
| [C\-tree](#case-C-tree) | Tree scope covers current threads, existing descendants and future descendants; process scope leaves other processes unmanaged\. Living descendants remain managed after root exit\. | generated | planned | 未提交执行记录 |
| [C\-windows\-installer\-isolation](#case-C-windows-installer-isolation) | Windows explicit\-tag installer preserves stable paths | existing | implemented | 未提交执行记录 |

<a id="case-C-approval"></a>

### C\-approval Only fresh human approval bound to exact process incarnation, instance, scope, backend, policy and bootstrap may mutate an external target\. Proposal alone has no effect\.

- id: C\-approval
- title: Only fresh human approval bound to exact process incarnation, instance, scope, backend, policy and bootstrap may mutate an external target\. Proposal alone has no effect\.
- kind: correctness
- implementation_status: planned
- origin: generated
- goal: Only fresh human approval bound to exact process incarnation, instance, scope, backend, policy and bootstrap may mutate an external target\. Proposal alone has no effect\.
- obligation_ids: O\-approval
- boundary_ids: B\-approval\-accepted\-history\-integrity, B\-approval\-api\-only, B\-approval\-capability\-preflight, B\-approval\-cold\-unenrolled, B\-approval\-core\-pinned\-root, B\-approval\-fresh\-single\-use, B\-approval\-host\-peer\-linux, B\-approval\-host\-peer\-windows, B\-approval\-host\-pinned\-root, B\-approval\-proposal\-linux\-gum, B\-approval\-proposal\-linux\-ptrace, B\-approval\-proposal\-windows\-gum, B\-approval\-rotation\-chain, B\-approval\-rotation\-envelopes, B\-approval\-signed\-bindings, B\-approval\-terminal\-slot\-renewal, B\-approval\-trusted\-enrollment
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Private local fixtures with fictional credentials; execute every named backend\-specific boundary separately\. This aggregate remains planned while any sub\-boundary lacks an implemented oracle\.
- steps:
  1. Trigger the stated lifecycle boundary under a private instance\.
  2. Check external target semantics and authenticated durable state independently\.
  3. Retain failure evidence and return a nonzero exit status on assertion failure\.
- oracle.method: External target payload, OS process/module identity, terminal state and signed operation status\.
- oracle.assertion: Only fresh human approval bound to exact process incarnation, instance, scope, backend, policy and bootstrap may mutate an external target\. Proposal alone has no effect\.
- oracle.independence: Target assertions use observable results and OS state rather than accepting the manager ACK as proof\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Consumed/completion history must be rooted in trusted accepted-operation state; an ordinary writable ledger key snapshot cannot alone authorize continuation.",
    "assertion_refs": [],
    "boundary_id": "B-approval-accepted-history-integrity",
    "id": "V-approval-accepted-history-integrity",
    "obligation_id": "O-approval",
    "trigger": "Consumed/completion history must be rooted in trusted accepted-operation state; an ordinary writable ledger key snapshot cannot alone authorize continuation.",
    "trigger_refs": []
  },
  {
    "assertion": "Runtime envelope/API authority cannot derive the administrator signing key or claim implicit external run ownership.",
    "assertion_refs": [],
    "boundary_id": "B-approval-api-only",
    "id": "V-approval-api-only",
    "obligation_id": "O-approval",
    "trigger": "Runtime envelope/API authority cannot derive the administrator signing key or claim implicit external run ownership.",
    "trigger_refs": []
  },
  {
    "assertion": "Refuse configured TLS/SSH interception unsupported by existing contexts without weakening configuration.",
    "assertion_refs": [],
    "boundary_id": "B-approval-capability-preflight",
    "id": "V-approval-capability-preflight",
    "obligation_id": "O-approval",
    "trigger": "Refuse configured TLS/SSH interception unsupported by existing contexts without weakening configuration.",
    "trigger_refs": []
  },
  {
    "assertion": "API-only cold startup stays Unenrolled for external lifecycle mutation while ordinary Serve/policy/run startup remains usable.",
    "assertion_refs": [],
    "boundary_id": "B-approval-cold-unenrolled",
    "id": "V-approval-cold-unenrolled",
    "obligation_id": "O-approval",
    "trigger": "API-only cold startup stays Unenrolled for external lifecycle mutation while ordinary Serve/policy/run startup remains usable.",
    "trigger_refs": []
  },
  {
    "assertion": "Core verification uses an enrolled in-memory approval key; ordinary verifier-file replacement cannot register or change the root.",
    "assertion_refs": [],
    "boundary_id": "B-approval-core-pinned-root",
    "id": "V-approval-core-pinned-root",
    "obligation_id": "O-approval",
    "trigger": "Core verification uses an enrolled in-memory approval key; ordinary verifier-file replacement cannot register or change the root.",
    "trigger_refs": []
  },
  {
    "assertion": "Reject future, exactly expired and expired grants; consume each nonce once for its OS claimant.",
    "assertion_refs": [],
    "boundary_id": "B-approval-fresh-single-use",
    "id": "V-approval-fresh-single-use",
    "obligation_id": "O-approval",
    "trigger": "Reject future, exactly expired and expired grants; consume each nonce once for its OS claimant.",
    "trigger_refs": []
  },
  {
    "assertion": "Linux Host OS peer authentication rejects wrong server PID before credentials/proofs are sent.",
    "assertion_refs": [],
    "boundary_id": "B-approval-host-peer-linux",
    "id": "V-approval-host-peer-linux",
    "obligation_id": "O-approval",
    "trigger": "Linux Host OS peer authentication rejects wrong server PID before credentials/proofs are sent.",
    "trigger_refs": []
  },
  {
    "assertion": "Windows named-pipe OS peer authentication rejects wrong server PID before credentials/proofs are sent.",
    "assertion_refs": [],
    "boundary_id": "B-approval-host-peer-windows",
    "id": "V-approval-host-peer-windows",
    "obligation_id": "O-approval",
    "trigger": "Windows named-pipe OS peer authentication rejects wrong server PID before credentials/proofs are sent.",
    "trigger_refs": []
  },
  {
    "assertion": "Every Host pins its initial approval root; no command or ordinary file may lazily choose a different first root.",
    "assertion_refs": [],
    "boundary_id": "B-approval-host-pinned-root",
    "id": "V-approval-host-pinned-root",
    "obligation_id": "O-approval",
    "trigger": "Every Host pins its initial approval root; no command or ordinary file may lazily choose a different first root.",
    "trigger_refs": []
  },
  {
    "assertion": "Linux Gum attach and detach proposals have no policy side effects before approval.",
    "assertion_refs": [],
    "boundary_id": "B-approval-proposal-linux-gum",
    "id": "V-approval-proposal-linux-gum",
    "obligation_id": "O-approval",
    "trigger": "Linux Gum attach and detach proposals have no policy side effects before approval.",
    "trigger_refs": []
  },
  {
    "assertion": "Linux ptrace attach and detach proposals have no policy side effects before approval.",
    "assertion_refs": [],
    "boundary_id": "B-approval-proposal-linux-ptrace",
    "id": "V-approval-proposal-linux-ptrace",
    "obligation_id": "O-approval",
    "trigger": "Linux ptrace attach and detach proposals have no policy side effects before approval.",
    "trigger_refs": []
  },
  {
    "assertion": "Windows Gum attach and detach proposals have no policy side effects before approval.",
    "assertion_refs": [],
    "boundary_id": "B-approval-proposal-windows-gum",
    "id": "V-approval-proposal-windows-gum",
    "obligation_id": "O-approval",
    "trigger": "Windows Gum attach and detach proposals have no policy side effects before approval.",
    "trigger_refs": []
  },
  {
    "assertion": "Password changes require contiguous instance/generation-bound old-key-signed rotation records; missing/reordered/backward or untrusted chains never replace a pinned root.",
    "assertion_refs": [],
    "boundary_id": "B-approval-rotation-chain",
    "id": "V-approval-rotation-chain",
    "obligation_id": "O-approval",
    "trigger": "Password changes require contiguous instance/generation-bound old-key-signed rotation records; missing/reordered/backward or untrusted chains never replace a pinned root.",
    "trigger_refs": []
  },
  {
    "assertion": "Password/config-generation changes immediately invalidate old signers, preserve consumed audit and retain encrypted recovery readability.",
    "assertion_refs": [],
    "boundary_id": "B-approval-rotation-envelopes",
    "id": "V-approval-rotation-envelopes",
    "obligation_id": "O-approval",
    "trigger": "Password/config-generation changes immediately invalidate old signers, preserve consumed audit and retain encrypted recovery readability.",
    "trigger_refs": []
  },
  {
    "assertion": "Reject altered process identity, scope, policy, capabilities, executor, Bootstrap, Host identity and recovery bindings.",
    "assertion_refs": [],
    "boundary_id": "B-approval-signed-bindings",
    "id": "V-approval-signed-bindings",
    "obligation_id": "O-approval",
    "trigger": "Reject altered process identity, scope, policy, capabilities, executor, Bootstrap, Host identity and recovery bindings.",
    "trigger_refs": []
  },
  {
    "assertion": "A Draining/resident slot that becomes terminal during human review receives fresh request/attachment/session/token epochs without changing target/scope/backend/policy or repeating approval; clients follow the actual returned id.",
    "assertion_refs": [],
    "boundary_id": "B-approval-terminal-slot-renewal",
    "id": "V-approval-terminal-slot-renewal",
    "obligation_id": "O-approval",
    "trigger": "A Draining/resident slot that becomes terminal during human review receives fresh request/attachment/session/token epochs without changing target/scope/backend/policy or repeating approval; clients follow the actual returned id.",
    "trigger_refs": []
  },
  {
    "assertion": "First real administrator approve completes challenge-bound registration via authenticated trusted CLI code, then the exact original request without another password prompt.",
    "assertion_refs": [],
    "boundary_id": "B-approval-trusted-enrollment",
    "id": "V-approval-trusted-enrollment",
    "obligation_id": "O-approval",
    "trigger": "First real administrator approve completes challenge-bound registration via authenticated trusted CLI code, then the exact original request without another password prompt.",
    "trigger_refs": []
  }
]
```

- code_references:

```json
[
  {
    "first": 1,
    "last": 80,
    "path": "crates/hyperhub-core/src/attachments/authority.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  }
]
```

- matrix:

```json
{}
```

- automation / reproduction:

尚无已实现入口；设计可审查，执行就绪另行判定。

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-cached-alias-linux-gum"></a>

### C\-cached\-alias\-linux\-gum Active cached\-alias new TCP is denied while independent native loopback echo succeeds; after detach that same cached alias echoes and getpeername proves the native loopback target, not old gateway\.

- id: C\-cached\-alias\-linux\-gum
- title: Active cached\-alias new TCP is denied while independent native loopback echo succeeds; after detach that same cached alias echoes and getpeername proves the native loopback target, not old gateway\.
- kind: correctness
- implementation_status: planned
- origin: existing
- goal: Previously cached FAKE\-IP aliases remain usable across detach and reattach\. Do not reassign an address to another destination while application caches may retain it\.
- obligation_ids: O\-fake
- boundary_ids: B\-fake\-linux\-gum
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Replace invalid no\-native\-route external\-FAKE oracle with a genuine unmanaged native baseline, and separately exercise actual SDK/Core\-issued aliases\.
- steps:
  1. First establish provenance: ObservedExternal versus HyperHub\-issued\.
  2. For external addresses compare the exact native sockaddr outcome against an unmanaged baseline; do not require an unreachable native address to succeed\.
  3. For issued addresses validate SDK local original\-resolver/connect compatibility, policy exit and unchanged old streams\.
- oracle.method: Native fixture replies, pidfd/process incarnation, OS tracer state, native TCP echo and actual post\-fault lifecycle\.
- oracle.assertion: Active cached\-alias new TCP is denied while independent native loopback echo succeeds; after detach that same cached alias echoes and getpeername proves the native loopback target, not old gateway\.
- oracle.independence: Policy results, byte echoes and OS state are observed outside manager ACKs; no formal run is synthesized\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Source-separated native-equivalence assertions must be implemented and reviewed before this case counts.",
    "assertion_refs": [],
    "boundary_id": "B-fake-linux-gum",
    "id": "V-fake-linux-gum",
    "obligation_id": "O-fake",
    "trigger": "Observe localhost FAKE-IP through the fixture resolver/DNS packet, keep that exact sockaddr, tighten gateway default to deny, then human-approve detach.",
    "trigger_refs": []
  }
]
```

- code_references:

```json
[
  {
    "first": 1,
    "last": 80,
    "path": "crates/hyperhub-agent-core/src/sandbox/network.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 467,
    "last": 469,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 493,
    "last": 501,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 569,
    "last": 572,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 54,
    "last": 74,
    "path": "tests/fixtures/dynamic_attach_target.c"
  }
]
```

- matrix:

```json
{
  "backend": "linux-gum",
  "origin": "attach"
}
```

- automation / reproduction:

尚无已实现入口；设计可审查，执行就绪另行判定。

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-cached-alias-linux-ptrace"></a>

### C\-cached\-alias\-linux\-ptrace Active cached\-alias new TCP is denied while independent native loopback echo succeeds; after detach that same cached alias echoes and getpeername proves the native loopback target, not old gateway\.

- id: C\-cached\-alias\-linux\-ptrace
- title: Active cached\-alias new TCP is denied while independent native loopback echo succeeds; after detach that same cached alias echoes and getpeername proves the native loopback target, not old gateway\.
- kind: correctness
- implementation_status: planned
- origin: existing
- goal: Previously cached FAKE\-IP aliases remain usable across detach and reattach\. Do not reassign an address to another destination while application caches may retain it\.
- obligation_ids: O\-fake
- boundary_ids: B\-fake\-linux\-ptrace
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Replace invalid no\-native\-route external\-FAKE oracle with a genuine unmanaged native baseline, and separately exercise actual SDK/Core\-issued aliases\.
- steps:
  1. First establish provenance: ObservedExternal versus HyperHub\-issued\.
  2. For external addresses compare the exact native sockaddr outcome against an unmanaged baseline; do not require an unreachable native address to succeed\.
  3. For issued addresses validate SDK local original\-resolver/connect compatibility, policy exit and unchanged old streams\.
- oracle.method: Native fixture replies, pidfd/process incarnation, OS tracer state, native TCP echo and actual post\-fault lifecycle\.
- oracle.assertion: Active cached\-alias new TCP is denied while independent native loopback echo succeeds; after detach that same cached alias echoes and getpeername proves the native loopback target, not old gateway\.
- oracle.independence: Policy results, byte echoes and OS state are observed outside manager ACKs; no formal run is synthesized\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Source-separated native-equivalence assertions must be implemented and reviewed before this case counts.",
    "assertion_refs": [],
    "boundary_id": "B-fake-linux-ptrace",
    "id": "V-fake-linux-ptrace",
    "obligation_id": "O-fake",
    "trigger": "Observe localhost FAKE-IP through the fixture resolver/DNS packet, keep that exact sockaddr, tighten gateway default to deny, then human-approve detach.",
    "trigger_refs": []
  }
]
```

- code_references:

```json
[
  {
    "first": 1,
    "last": 80,
    "path": "crates/hyperhub-agent-core/src/sandbox/network.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 467,
    "last": 469,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 493,
    "last": 501,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 569,
    "last": 572,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 54,
    "last": 74,
    "path": "tests/fixtures/dynamic_attach_target.c"
  }
]
```

- matrix:

```json
{
  "backend": "linux-ptrace",
  "origin": "attach"
}
```

- automation / reproduction:

尚无已实现入口；设计可审查，执行就绪另行判定。

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-capability-preflight"></a>

### C\-capability\-preflight Existing\-context TLS and SSH requirement rejection

- id: C\-capability\-preflight
- title: Existing\-context TLS and SSH requirement rejection
- kind: correctness
- implementation_status: implemented
- origin: existing
- goal: Only fresh human approval bound to exact process incarnation, instance, scope, backend, policy and bootstrap may mutate an external target\. Proposal alone has no effect\.
- obligation_ids: O\-approval
- boundary_ids: B\-approval\-capability\-preflight
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Pure configuration capability test; no production trust material\.
- steps:
  1. Run referenced configuration preflight tests\.
- oracle.method: Review and execute the cited native fixture or Rust test assertions; inspect matching raw outputs and actual OS identities\.
- oracle.assertion: Every cited per\-boundary assertion must run and pass; a top\-level success or manager ACK does not substitute for a missing assertion\.
- oracle.independence: Native results and OS enumeration are independent of lifecycle ACKs; cryptographic mutation units test explicit rejected inputs but do not replace end\-to\-end authorization tests\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Required TLS/SSH interception returns error, while disabled/unreferenced route does not block opaque configuration.",
    "assertion_refs": [
      {
        "first": 107,
        "last": 129,
        "path": "crates/hyperhub-core/src/attachments/capabilities.rs"
      }
    ],
    "boundary_id": "B-approval-capability-preflight",
    "id": "V-1",
    "obligation_id": "O-approval",
    "trigger": "Configure default-route HTTP credential then SSH credential; disable unused route.",
    "trigger_refs": [
      {
        "first": 107,
        "last": 129,
        "path": "crates/hyperhub-core/src/attachments/capabilities.rs"
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
    "last": 80,
    "path": "crates/hyperhub-core/src/attachments/authority.rs"
  },
  {
    "first": 107,
    "last": 129,
    "path": "crates/hyperhub-core/src/attachments/capabilities.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
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
    "test",
    "-p",
    "hyperhub-core",
    "--lib",
    "attachments::capabilities::tests",
    "--locked"
  ],
  "artifact_paths": [
    "crates/hyperhub-core/src/attachments/capabilities.rs"
  ],
  "cwd": "."
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-committed-cleanup-recovery"></a>

### C\-committed\-cleanup\-recovery Fresh cleanup after lost completion ACK and old\-manager death

- id: C\-committed\-cleanup\-recovery
- title: Fresh cleanup after lost completion ACK and old\-manager death
- kind: correctness
- implementation_status: implemented
- origin: existing
- goal: Serve and manager loss preserve allowed business activity and report enforcement loss\. Fresh approved recovery reconnects compatible residue or safely seizes an untraced target; never stack injection\.
- obligation_ids: O\-recovery
- boundary_ids: B\-recovery\-committed\-cleanup\-protocol
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: A real short\-lived child test executable consumes the old grant/writes receipt then exits\. A different manager submits new signed cleanup; wrong token/target/claimant and Attach remain denied, membership stays empty\.
- steps:
  1. Run the exact native crate test filter\.
  2. Require the cited input mutation and each explicit negative/positive assertion; do not promote its result to a broader native lifecycle claim\.
- oracle.method: Explicit independent expected rejection/acceptance, private ledger bytes and session membership, or OS peer observation\.
- oracle.assertion: After completed revocation plus ACK loss and manager death, fresh approved Detach may perform exact historical\-receipt cleanup without creating members; wrong identity/token/target and Attach are denied\.
- oracle.independence: Unit seam validates only this named boundary; backend module absence and real fault timing remain separate planned native cases\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "After completed revocation plus ACK loss and manager death, fresh approved Detach may perform exact historical-receipt cleanup without creating members; wrong identity/token/target and Attach are denied.",
    "assertion_refs": [
      {
        "first": 1152,
        "last": 1183,
        "path": "crates/hyperhub-core/src/attachments/control.rs"
      },
      {
        "first": 1185,
        "last": 1417,
        "path": "crates/hyperhub-core/src/attachments/control.rs"
      }
    ],
    "boundary_id": "B-recovery-committed-cleanup-protocol",
    "id": "V-recovery-committed-cleanup-protocol",
    "obligation_id": "O-recovery",
    "trigger": "A real short-lived child test executable consumes the old grant/writes receipt then exits. A different manager submits new signed cleanup; wrong token/target/claimant and Attach remain denied, membership stays empty.",
    "trigger_refs": [
      {
        "first": 1152,
        "last": 1183,
        "path": "crates/hyperhub-core/src/attachments/control.rs"
      },
      {
        "first": 1185,
        "last": 1417,
        "path": "crates/hyperhub-core/src/attachments/control.rs"
      }
    ]
  }
]
```

- code_references:

```json
[
  {
    "first": 1051,
    "last": 1082,
    "path": "crates/hyperhub-core/src/attachments/control.rs"
  },
  {
    "first": 1084,
    "last": 1316,
    "path": "crates/hyperhub-core/src/attachments/control.rs"
  },
  {
    "first": 1152,
    "last": 1183,
    "path": "crates/hyperhub-core/src/attachments/control.rs"
  },
  {
    "first": 1185,
    "last": 1417,
    "path": "crates/hyperhub-core/src/attachments/control.rs"
  },
  {
    "first": 1,
    "last": 31,
    "path": "crates/hyperhub-core/src/attachments/manager.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
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
    "test",
    "-p",
    "hyperhub-core",
    "--lib",
    "cleanup_recovery_tests",
    "--locked"
  ],
  "artifact_paths": [
    "crates/hyperhub-core/src/attachments/control.rs"
  ],
  "cwd": "."
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-completion-protocol"></a>

### C\-completion\-protocol Consumed historical approval and exact physical\-completion marker

- id: C\-completion\-protocol
- title: Consumed historical approval and exact physical\-completion marker
- kind: correctness
- implementation_status: implemented
- origin: existing
- goal: Approved detach stops new enforcement\. Keep compatibility code while calls, async operations, trust contexts, callbacks or cached addresses need it\. Detached requires independent physical\-unload proof\.
- obligation_ids: O\-drain
- boundary_ids: B\-drain\-completion\-protocol
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Consume a signed grant, rotate verifier, try unconsumed/forged/wrong claimant, then accepted marker and repeated completion after revocation\.
- steps:
  1. Run the exact native crate test filter\.
  2. Require the cited input mutation and each explicit negative/positive assertion; do not promote its result to a broader native lifecycle claim\.
- oracle.method: Explicit independent expected rejection/acceptance, private ledger bytes and session membership, or OS peer observation\.
- oracle.assertion: Only exact physical\-absence marker/pending phases and an accepted signed consumed operation can revoke session; rotation and lost ACK preserve idempotent completion\.
- oracle.independence: Unit seam validates only this named boundary; backend module absence and real fault timing remain separate planned native cases\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Only exact physical-absence marker/pending phases and an accepted signed consumed operation can revoke session; rotation and lost ACK preserve idempotent completion.",
    "assertion_refs": [
      {
        "first": 543,
        "last": 577,
        "path": "crates/hyperhub-core/src/attachments/tests.rs"
      },
      {
        "first": 948,
        "last": 1145,
        "path": "crates/hyperhub-core/src/attachments/control.rs"
      }
    ],
    "boundary_id": "B-drain-completion-protocol",
    "id": "V-drain-completion-protocol",
    "obligation_id": "O-drain",
    "trigger": "Consume a signed grant, rotate verifier, try unconsumed/forged/wrong claimant, then accepted marker and repeated completion after revocation.",
    "trigger_refs": [
      {
        "first": 543,
        "last": 577,
        "path": "crates/hyperhub-core/src/attachments/tests.rs"
      },
      {
        "first": 948,
        "last": 1145,
        "path": "crates/hyperhub-core/src/attachments/control.rs"
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
    "last": 80,
    "path": "crates/hyperhub-agent-core/src/attachment.rs"
  },
  {
    "first": 847,
    "last": 1044,
    "path": "crates/hyperhub-core/src/attachments/control.rs"
  },
  {
    "first": 948,
    "last": 1145,
    "path": "crates/hyperhub-core/src/attachments/control.rs"
  },
  {
    "first": 542,
    "last": 576,
    "path": "crates/hyperhub-core/src/attachments/tests.rs"
  },
  {
    "first": 543,
    "last": 577,
    "path": "crates/hyperhub-core/src/attachments/tests.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
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
    "test",
    "-p",
    "hyperhub-core",
    "--lib",
    "--locked"
  ],
  "artifact_paths": [
    "crates/hyperhub-core/src/attachments/control.rs",
    "crates/hyperhub-core/src/attachments/tests.rs"
  ],
  "cwd": "."
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-continuity"></a>

### C\-continuity Preserve allowed payloads, existing TCP, blocking original calls, socket flags, explicit child environments, PID, cwd, stdio, terminal state and original root exit status\.

- id: C\-continuity
- title: Preserve allowed payloads, existing TCP, blocking original calls, socket flags, explicit child environments, PID, cwd, stdio, terminal state and original root exit status\.
- kind: correctness
- implementation_status: planned
- origin: generated
- goal: Preserve allowed payloads, existing TCP, blocking original calls, socket flags, explicit child environments, PID, cwd, stdio, terminal state and original root exit status\.
- obligation_ids: O\-continuity
- boundary_ids: B\-continuity\-linux\-gum\-identity, B\-continuity\-linux\-gum\-io, B\-continuity\-linux\-gum\-terminal, B\-continuity\-linux\-ptrace\-identity, B\-continuity\-linux\-ptrace\-io, B\-continuity\-linux\-ptrace\-terminal, B\-continuity\-owned\-ready\-failure, B\-continuity\-owned\-wait, B\-continuity\-windows\-identity, B\-continuity\-windows\-io, B\-continuity\-windows\-terminal
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Private local fixtures with fictional credentials; execute every named backend\-specific boundary separately\. This aggregate remains planned while any sub\-boundary lacks an implemented oracle\.
- steps:
  1. Trigger the stated lifecycle boundary under a private instance\.
  2. Check external target semantics and authenticated durable state independently\.
  3. Retain failure evidence and return a nonzero exit status on assertion failure\.
- oracle.method: External target payload, OS process/module identity, terminal state and signed operation status\.
- oracle.assertion: Preserve allowed payloads, existing TCP, blocking original calls, socket flags, explicit child environments, PID, cwd, stdio, terminal state and original root exit status\.
- oracle.independence: Target assertions use observable results and OS state rather than accepting the manager ACK as proof\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Linux Gum preserves PID/cwd/stdio/env, explicit exec/spawn environment and original exit status.",
    "assertion_refs": [],
    "boundary_id": "B-continuity-linux-gum-identity",
    "id": "V-continuity-linux-gum-identity",
    "obligation_id": "O-continuity",
    "trigger": "Linux Gum preserves PID/cwd/stdio/env, explicit exec/spawn environment and original exit status.",
    "trigger_refs": []
  },
  {
    "assertion": "Linux Gum preserves existing/new TCP payload, blocked read result and preopened/nonblocking socket flags.",
    "assertion_refs": [],
    "boundary_id": "B-continuity-linux-gum-io",
    "id": "V-continuity-linux-gum-io",
    "obligation_id": "O-continuity",
    "trigger": "Linux Gum preserves existing/new TCP payload, blocked read result and preopened/nonblocking socket flags.",
    "trigger_refs": []
  },
  {
    "assertion": "Linux Gum target with controlling PTY preserves termios and foreground terminal identity.",
    "assertion_refs": [],
    "boundary_id": "B-continuity-linux-gum-terminal",
    "id": "V-continuity-linux-gum-terminal",
    "obligation_id": "O-continuity",
    "trigger": "Linux Gum target with controlling PTY preserves termios and foreground terminal identity.",
    "trigger_refs": []
  },
  {
    "assertion": "Linux ptrace preserves PID/cwd/stdio/env, explicit exec/spawn environment and original exit status.",
    "assertion_refs": [],
    "boundary_id": "B-continuity-linux-ptrace-identity",
    "id": "V-continuity-linux-ptrace-identity",
    "obligation_id": "O-continuity",
    "trigger": "Linux ptrace preserves PID/cwd/stdio/env, explicit exec/spawn environment and original exit status.",
    "trigger_refs": []
  },
  {
    "assertion": "Linux ptrace preserves existing/new TCP payload, blocked read result and preopened/nonblocking socket flags.",
    "assertion_refs": [],
    "boundary_id": "B-continuity-linux-ptrace-io",
    "id": "V-continuity-linux-ptrace-io",
    "obligation_id": "O-continuity",
    "trigger": "Linux ptrace preserves existing/new TCP payload, blocked read result and preopened/nonblocking socket flags.",
    "trigger_refs": []
  },
  {
    "assertion": "Linux ptrace target with controlling PTY preserves termios and foreground terminal identity.",
    "assertion_refs": [],
    "boundary_id": "B-continuity-linux-ptrace-terminal",
    "id": "V-continuity-linux-ptrace-terminal",
    "obligation_id": "O-continuity",
    "trigger": "Linux ptrace target with controlling PTY preserves termios and foreground terminal identity.",
    "trigger_refs": []
  },
  {
    "assertion": "After authenticated Host READY, failed keeper creation/claim/control I/O never kills the target; retire only the exact created helper, preserve native recovery context and truthful owner.",
    "assertion_refs": [],
    "boundary_id": "B-continuity-owned-ready-failure",
    "id": "V-continuity-owned-ready-failure",
    "obligation_id": "O-continuity",
    "trigger": "After authenticated Host READY, failed keeper creation/claim/control I/O never kills the target; retire only the exact created helper, preserve native recovery context and truthful owner.",
    "trigger_refs": []
  },
  {
    "assertion": "Each backend run launcher keeps waiting after detach and returns original root status independently of persistent manager lifetime.",
    "assertion_refs": [],
    "boundary_id": "B-continuity-owned-wait",
    "id": "V-continuity-owned-wait",
    "obligation_id": "O-continuity",
    "trigger": "Each backend run launcher keeps waiting after detach and returns original root status independently of persistent manager lifetime.",
    "trigger_refs": []
  },
  {
    "assertion": "Windows Gum preserves PID/cwd/stdio/env and original exit status.",
    "assertion_refs": [],
    "boundary_id": "B-continuity-windows-identity",
    "id": "V-continuity-windows-identity",
    "obligation_id": "O-continuity",
    "trigger": "Windows Gum preserves PID/cwd/stdio/env and original exit status.",
    "trigger_refs": []
  },
  {
    "assertion": "Windows Gum preserves existing/new TCP payload and blocked original ReadFile result.",
    "assertion_refs": [],
    "boundary_id": "B-continuity-windows-io",
    "id": "V-continuity-windows-io",
    "obligation_id": "O-continuity",
    "trigger": "Windows Gum preserves existing/new TCP payload and blocked original ReadFile result.",
    "trigger_refs": []
  },
  {
    "assertion": "Native Windows target terminal modes, foreground console and keyboard semantics survive lifecycle changes; an approval ConPTY alone is insufficient.",
    "assertion_refs": [],
    "boundary_id": "B-continuity-windows-terminal",
    "id": "V-continuity-windows-terminal",
    "obligation_id": "O-continuity",
    "trigger": "Native Windows target terminal modes, foreground console and keyboard semantics survive lifecycle changes; an approval ConPTY alone is insufficient.",
    "trigger_refs": []
  }
]
```

- code_references:

```json
[
  {
    "first": 277,
    "last": 301,
    "path": "crates/hyperhub-cli/src/attachment/owned_keeper.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 1,
    "last": 80,
    "path": "tests/fixtures/dynamic_attach_target.c"
  }
]
```

- matrix:

```json
{}
```

- automation / reproduction:

尚无已实现入口；设计可审查，执行就绪另行判定。

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-core-approval-boundaries"></a>

### C\-core\-approval\-boundaries Shared signatures, single consumption, API isolation and password generation

- id: C\-core\-approval\-boundaries
- title: Shared signatures, single consumption, API isolation and password generation
- kind: correctness
- implementation_status: implemented
- origin: existing
- goal: Only fresh human approval bound to exact process incarnation, instance, scope, backend, policy and bootstrap may mutate an external target\. Proposal alone has no effect\.
- obligation_ids: O\-approval
- boundary_ids: B\-approval\-api\-only, B\-approval\-fresh\-single\-use, B\-approval\-rotation\-envelopes, B\-approval\-signed\-bindings
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: No real process mutation; supported minimum Argon2 parameters and fictional secrets in private temp state\.
- steps:
  1. Execute all shared approval unit regressions\.
  2. Inspect individual test names/results; this does not prove every native OS authorization path\.
- oracle.method: Review and execute the cited native fixture or Rust test assertions; inspect matching raw outputs and actual OS identities\.
- oracle.assertion: Every cited per\-boundary assertion must run and pass; a top\-level success or manager ACK does not substitute for a missing assertion\.
- oracle.independence: Native results and OS enumeration are independent of lifecycle ACKs; cryptographic mutation units test explicit rejected inputs but do not replace end\-to\-end authorization tests\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Every forged grant/execution is rejected; original grant succeeds.",
    "assertion_refs": [
      {
        "first": 80,
        "last": 103,
        "path": "crates/hyperhub-core/src/attachments/tests.rs"
      },
      {
        "first": 295,
        "last": 357,
        "path": "crates/hyperhub-core/src/attachments/tests.rs"
      },
      {
        "first": 489,
        "last": 540,
        "path": "crates/hyperhub-core/src/attachments/tests.rs"
      }
    ],
    "boundary_id": "B-approval-signed-bindings",
    "id": "V-1",
    "obligation_id": "O-approval",
    "trigger": "Mutate signed target, scope, policy, capabilities, bootstrap endpoint/token, executor, recovery manager/context and Host binding.",
    "trigger_refs": [
      {
        "first": 80,
        "last": 103,
        "path": "crates/hyperhub-core/src/attachments/tests.rs"
      },
      {
        "first": 295,
        "last": 357,
        "path": "crates/hyperhub-core/src/attachments/tests.rs"
      },
      {
        "first": 489,
        "last": 540,
        "path": "crates/hyperhub-core/src/attachments/tests.rs"
      }
    ]
  },
  {
    "assertion": "Future and exactly expired grants fail; second consume fails and only current OS claimant matches.",
    "assertion_refs": [
      {
        "first": 80,
        "last": 103,
        "path": "crates/hyperhub-core/src/attachments/tests.rs"
      },
      {
        "first": 131,
        "last": 142,
        "path": "crates/hyperhub-core/src/attachments/tests.rs"
      }
    ],
    "boundary_id": "B-approval-fresh-single-use",
    "id": "V-2",
    "obligation_id": "O-approval",
    "trigger": "Use valid grant before deadline, at expiry, before issuance and consume twice.",
    "trigger_refs": [
      {
        "first": 80,
        "last": 103,
        "path": "crates/hyperhub-core/src/attachments/tests.rs"
      },
      {
        "first": 131,
        "last": 142,
        "path": "crates/hyperhub-core/src/attachments/tests.rs"
      }
    ]
  },
  {
    "assertion": "Runtime master cannot sign/replace verifier; implicit-run external execution rejected.",
    "assertion_refs": [
      {
        "first": 105,
        "last": 129,
        "path": "crates/hyperhub-core/src/attachments/tests.rs"
      },
      {
        "first": 295,
        "last": 357,
        "path": "crates/hyperhub-core/src/attachments/tests.rs"
      }
    ],
    "boundary_id": "B-approval-api-only",
    "id": "V-3",
    "obligation_id": "O-approval",
    "trigger": "Attempt administrator authorization with runtime master or wrong password; change external Execution origin to implicit run.",
    "trigger_refs": [
      {
        "first": 105,
        "last": 129,
        "path": "crates/hyperhub-core/src/attachments/tests.rs"
      },
      {
        "first": 295,
        "last": 357,
        "path": "crates/hyperhub-core/src/attachments/tests.rs"
      }
    ]
  },
  {
    "assertion": "Old verifier immediately removed, old grants invalid, ledger retained and encrypted backend data remains readable with current generation.",
    "assertion_refs": [
      {
        "first": 360,
        "last": 403,
        "path": "crates/hyperhub-core/src/attachments/tests.rs"
      },
      {
        "first": 405,
        "last": 417,
        "path": "crates/hyperhub-core/src/attachments/tests.rs"
      },
      {
        "first": 420,
        "last": 486,
        "path": "crates/hyperhub-core/src/attachments/tests.rs"
      }
    ],
    "boundary_id": "B-approval-rotation-envelopes",
    "id": "V-4",
    "obligation_id": "O-approval",
    "trigger": "Change encryption descriptor/password, rotate again and preserve old recovery payload.",
    "trigger_refs": [
      {
        "first": 360,
        "last": 403,
        "path": "crates/hyperhub-core/src/attachments/tests.rs"
      },
      {
        "first": 405,
        "last": 417,
        "path": "crates/hyperhub-core/src/attachments/tests.rs"
      },
      {
        "first": 420,
        "last": 486,
        "path": "crates/hyperhub-core/src/attachments/tests.rs"
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
    "last": 80,
    "path": "crates/hyperhub-core/src/attachments/authority.rs"
  },
  {
    "first": 80,
    "last": 103,
    "path": "crates/hyperhub-core/src/attachments/tests.rs"
  },
  {
    "first": 105,
    "last": 129,
    "path": "crates/hyperhub-core/src/attachments/tests.rs"
  },
  {
    "first": 131,
    "last": 142,
    "path": "crates/hyperhub-core/src/attachments/tests.rs"
  },
  {
    "first": 295,
    "last": 356,
    "path": "crates/hyperhub-core/src/attachments/tests.rs"
  },
  {
    "first": 295,
    "last": 357,
    "path": "crates/hyperhub-core/src/attachments/tests.rs"
  },
  {
    "first": 359,
    "last": 402,
    "path": "crates/hyperhub-core/src/attachments/tests.rs"
  },
  {
    "first": 360,
    "last": 403,
    "path": "crates/hyperhub-core/src/attachments/tests.rs"
  },
  {
    "first": 404,
    "last": 416,
    "path": "crates/hyperhub-core/src/attachments/tests.rs"
  },
  {
    "first": 405,
    "last": 417,
    "path": "crates/hyperhub-core/src/attachments/tests.rs"
  },
  {
    "first": 419,
    "last": 466,
    "path": "crates/hyperhub-core/src/attachments/tests.rs"
  },
  {
    "first": 419,
    "last": 485,
    "path": "crates/hyperhub-core/src/attachments/tests.rs"
  },
  {
    "first": 420,
    "last": 486,
    "path": "crates/hyperhub-core/src/attachments/tests.rs"
  },
  {
    "first": 469,
    "last": 514,
    "path": "crates/hyperhub-core/src/attachments/tests.rs"
  },
  {
    "first": 488,
    "last": 539,
    "path": "crates/hyperhub-core/src/attachments/tests.rs"
  },
  {
    "first": 489,
    "last": 540,
    "path": "crates/hyperhub-core/src/attachments/tests.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
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
    "test",
    "-p",
    "hyperhub-core",
    "--lib",
    "attachments::tests",
    "--locked"
  ],
  "artifact_paths": [
    "crates/hyperhub-core/src/attachments/tests.rs"
  ],
  "cwd": "."
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-development-isolation"></a>

### C\-development\-isolation Linux explicit\-tag installer and real prerelease CLI isolation

- id: C\-development\-isolation
- title: Linux explicit\-tag installer and real prerelease CLI isolation
- kind: correctness
- implementation_status: implemented
- origin: existing
- goal: Isolate development binaries, Home, Skill and updates\. Explicit prerelease tags do not replace stable defaults\. Publish only after exact\-commit platform CI and soak success\.
- obligation_ids: O\-release
- boundary_ids: B\-release\-linux\-install, B\-release\-private\-cli
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Private temporary user home and fictional local release archive; no download/publish claim\.
- steps:
  1. Execute installer mock matrix and built CLI behavior tests\.
  2. Keep public release/download verification planned\.
- oracle.method: Review and execute the cited native fixture or Rust test assertions; inspect matching raw outputs and actual OS identities\.
- oracle.assertion: Every cited per\-boundary assertion must run and pass; a top\-level success or manager ACK does not substitute for a missing assertion\.
- oracle.independence: Native results and OS enumeration are independent of lifecycle ACKs; cryptographic mutation units test explicit rejected inputs but do not replace end\-to\-end authorization tests\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Explicit prerelease lands in isolated version directory and stable executable/shortcut stay unchanged.",
    "assertion_refs": [
      {
        "first": 88,
        "last": 132,
        "path": "scripts/test-development-release.py"
      }
    ],
    "boundary_id": "B-release-linux-install",
    "id": "V-1",
    "obligation_id": "O-release",
    "trigger": "Use a mock tagged archive and existing stable executable sentinel.",
    "trigger_refs": [
      {
        "first": 88,
        "last": 132,
        "path": "scripts/test-development-release.py"
      }
    ]
  },
  {
    "assertion": "Default instance is .hyperhub-dev, updates require explicit tag, stable and global agent paths absent, Skill documents runtime approval.",
    "assertion_refs": [
      {
        "first": 61,
        "last": 94,
        "path": "scripts/test-development-release.py"
      }
    ],
    "boundary_id": "B-release-private-cli",
    "id": "V-2",
    "obligation_id": "O-release",
    "trigger": "Run built prerelease CLI status, upgrade and embedded Skill in fresh HOME.",
    "trigger_refs": [
      {
        "first": 61,
        "last": 94,
        "path": "scripts/test-development-release.py"
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
    "last": 80,
    "path": ".github/workflows/release.yml"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 5,
    "last": 10,
    "path": "scripts/install.sh"
  },
  {
    "first": 18,
    "last": 63,
    "path": "scripts/test-development-release.py"
  },
  {
    "first": 61,
    "last": 94,
    "path": "scripts/test-development-release.py"
  },
  {
    "first": 88,
    "last": 132,
    "path": "scripts/test-development-release.py"
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
    "python3",
    "scripts/test-development-release.py",
    "--hyperhub",
    "target/release/hyperhub"
  ],
  "artifact_paths": [
    "scripts/install.sh",
    "scripts/test-development-release.py"
  ],
  "cwd": "."
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-dirty-ptrace-recovery-refusal"></a>

### C\-dirty\-ptrace\-recovery\-refusal Ptrace dirty virtual descriptor recovery refuses safely

- id: C\-dirty\-ptrace\-recovery\-refusal
- title: Ptrace dirty virtual descriptor recovery refuses safely
- kind: correctness
- implementation_status: implemented
- origin: existing
- goal: Serve and manager loss preserve allowed business activity and report enforcement loss\. Fresh approved recovery reconnects compatible residue or safely seizes an untraced target; never stack injection\.
- obligation_ids: O\-recovery
- boundary_ids: B\-recovery\-dirty\-ptrace\-refusal
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Create virtualized nonblocking socket state, kill only validated manager, submit fresh recovery and require explicit unproven\-state refusal\.
- steps:
  1. Execute the isolated native driver command using a built embedded candidate\.
  2. Require the cited fault/continuity/native\-policy oracle and preserve any nonzero failure\.
  3. Product failures remain failures; implemented status only records the real fixture/assertion path\.
- oracle.method: Native fixture replies, pidfd/process incarnation, OS tracer state, native TCP echo and actual post\-fault lifecycle\.
- oracle.assertion: Fresh approved recovery refuses dirty virtual\-descriptor state explicitly as unproven, keeps target alive with native read result 0 and TracerPid 0, observes the intended lost virtual O\_NONBLOCK state, and preserves exit status 37\.
- oracle.independence: Policy results, byte echoes and OS state are observed outside manager ACKs; no formal run is synthesized\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Status is degraded/cleanup_pending with unproven detail, TracerPid stays0, target remains native-readable with the intentionally reached lost virtual-flag state and exits37.",
    "assertion_refs": [
      {
        "first": 530,
        "last": 547,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 548,
        "last": 561,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-recovery-dirty-ptrace-refusal",
    "id": "V-dirty-refusal",
    "obligation_id": "O-recovery",
    "trigger": "Create virtualized nonblocking socket state, kill only validated manager, submit fresh recovery and require explicit unproven-state refusal.",
    "trigger_refs": [
      {
        "first": 530,
        "last": 547,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 548,
        "last": 561,
        "path": "scripts/test-dynamic-attach.py"
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
    "last": 31,
    "path": "crates/hyperhub-core/src/attachments/manager.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 530,
    "last": 547,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 548,
    "last": 561,
    "path": "scripts/test-dynamic-attach.py"
  }
]
```

- matrix:

```json
{
  "backend": "linux-ptrace",
  "origin": "attach"
}
```

- automation / reproduction:

```json
{
  "argv": [
    "python3",
    "scripts/test-dynamic-attach.py",
    "--hyperhub",
    "target/release/hyperhub",
    "--backend",
    "ptrace",
    "--manager-loss",
    "dirty",
    "--cycles",
    "1",
    "--output",
    "target/benchmarks/dirty-ptrace-recovery"
  ],
  "artifact_paths": [
    "scripts/test-dynamic-attach.py",
    "tests/fixtures/dynamic_attach_legacy_marker.rs",
    "tests/fixtures/dynamic_attach_target.c"
  ],
  "cwd": "."
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-drain"></a>

### C\-drain Approved detach stops new enforcement\. Keep compatibility code while calls, async operations, trust contexts, callbacks or cached addresses need it\. Detached requires independent physical\-unload proof\.

- id: C\-drain
- title: Approved detach stops new enforcement\. Keep compatibility code while calls, async operations, trust contexts, callbacks or cached addresses need it\. Detached requires independent physical\-unload proof\.
- kind: correctness
- implementation_status: planned
- origin: generated
- goal: Approved detach stops new enforcement\. Keep compatibility code while calls, async operations, trust contexts, callbacks or cached addresses need it\. Detached requires independent physical\-unload proof\.
- obligation_ids: O\-drain
- boundary_ids: B\-drain\-completion\-protocol, B\-drain\-linux\-gum\-blocked, B\-drain\-linux\-gum\-physical, B\-drain\-linux\-ptrace\-blocked, B\-drain\-linux\-ptrace\-physical, B\-drain\-windows\-blocked\-trust, B\-drain\-windows\-physical
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Private local fixtures with fictional credentials; execute every named backend\-specific boundary separately\. This aggregate remains planned while any sub\-boundary lacks an implemented oracle\.
- steps:
  1. Trigger the stated lifecycle boundary under a private instance\.
  2. Check external target semantics and authenticated durable state independently\.
  3. Retain failure evidence and return a nonzero exit status on assertion failure\.
- oracle.method: External target payload, OS process/module identity, terminal state and signed operation status\.
- oracle.assertion: Approved detach stops new enforcement\. Keep compatibility code while calls, async operations, trust contexts, callbacks or cached addresses need it\. Detached requires independent physical\-unload proof\.
- oracle.independence: Target assertions use observable results and OS state rather than accepting the manager ACK as proof\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Only exact physical-absence marker/pending phases and an accepted signed consumed operation can revoke session; rotation and lost ACK preserve idempotent completion.",
    "assertion_refs": [],
    "boundary_id": "B-drain-completion-protocol",
    "id": "V-drain-completion-protocol",
    "obligation_id": "O-drain",
    "trigger": "Only exact physical-absence marker/pending phases and an accepted signed consumed operation can revoke session; rotation and lost ACK preserve idempotent completion.",
    "trigger_refs": []
  },
  {
    "assertion": "Linux Gum detach preserves an outstanding original blocked read and nonblocking flags.",
    "assertion_refs": [],
    "boundary_id": "B-drain-linux-gum-blocked",
    "id": "V-drain-linux-gum-blocked",
    "obligation_id": "O-drain",
    "trigger": "Linux Gum detach preserves an outstanding original blocked read and nonblocking flags.",
    "trigger_refs": []
  },
  {
    "assertion": "Independent module/callback/cache evidence distinguishes Linux Gum resident compatibility from proven unload.",
    "assertion_refs": [],
    "boundary_id": "B-drain-linux-gum-physical",
    "id": "V-drain-linux-gum-physical",
    "obligation_id": "O-drain",
    "trigger": "Independent module/callback/cache evidence distinguishes Linux Gum resident compatibility from proven unload.",
    "trigger_refs": []
  },
  {
    "assertion": "Linux ptrace detach preserves an outstanding original blocked read and nonblocking flags.",
    "assertion_refs": [],
    "boundary_id": "B-drain-linux-ptrace-blocked",
    "id": "V-drain-linux-ptrace-blocked",
    "obligation_id": "O-drain",
    "trigger": "Linux ptrace detach preserves an outstanding original blocked read and nonblocking flags.",
    "trigger_refs": []
  },
  {
    "assertion": "Independent OS TracerPid checks prove every covered live member is untraced before public Detached.",
    "assertion_refs": [],
    "boundary_id": "B-drain-linux-ptrace-physical",
    "id": "V-drain-linux-ptrace-physical",
    "obligation_id": "O-drain",
    "trigger": "Independent OS TracerPid checks prove every covered live member is untraced before public Detached.",
    "trigger_refs": []
  },
  {
    "assertion": "Windows Gum remains loaded during blocked ReadFile and retained modified Schannel credential; unload only after explicit release.",
    "assertion_refs": [],
    "boundary_id": "B-drain-windows-blocked-trust",
    "id": "V-drain-windows-blocked-trust",
    "obligation_id": "O-drain",
    "trigger": "Windows Gum remains loaded during blocked ReadFile and retained modified Schannel credential; unload only after explicit release.",
    "trigger_refs": []
  },
  {
    "assertion": "Independent native module enumeration proves all eligible live members are unloaded before public Detached; token/session revocation completes.",
    "assertion_refs": [],
    "boundary_id": "B-drain-windows-physical",
    "id": "V-drain-windows-physical",
    "obligation_id": "O-drain",
    "trigger": "Independent native module enumeration proves all eligible live members are unloaded before public Detached; token/session revocation completes.",
    "trigger_refs": []
  }
]
```

- code_references:

```json
[
  {
    "first": 1,
    "last": 80,
    "path": "crates/hyperhub-agent-core/src/attachment.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  }
]
```

- matrix:

```json
{}
```

- automation / reproduction:

尚无已实现入口；设计可审查，执行就绪另行判定。

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-fake"></a>

### C\-fake Previously cached FAKE\-IP aliases remain usable across detach and reattach\. Do not reassign an address to another destination while application caches may retain it\.

- id: C\-fake
- title: Previously cached FAKE\-IP aliases remain usable across detach and reattach\. Do not reassign an address to another destination while application caches may retain it\.
- kind: correctness
- implementation_status: planned
- origin: generated
- goal: Previously cached FAKE\-IP aliases remain usable across detach and reattach\. Do not reassign an address to another destination while application caches may retain it\.
- obligation_ids: O\-fake
- boundary_ids: B\-fake\-linux\-gum, B\-fake\-linux\-gum\-issued, B\-fake\-linux\-gum\-nonreuse, B\-fake\-linux\-ptrace, B\-fake\-linux\-ptrace\-issued, B\-fake\-linux\-ptrace\-nonreuse, B\-fake\-windows\-gum
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Private local fixtures with fictional credentials; execute every named backend\-specific boundary separately\. This aggregate remains planned while any sub\-boundary lacks an implemented oracle\.
- steps:
  1. Trigger the stated lifecycle boundary under a private instance\.
  2. Check external target semantics and authenticated durable state independently\.
  3. Retain failure evidence and return a nonzero exit status on assertion failure\.
- oracle.method: External target payload, OS process/module identity, terminal state and signed operation status\.
- oracle.assertion: Previously cached FAKE\-IP aliases remain usable across detach and reattach\. Do not reassign an address to another destination while application caches may retain it\.
- oracle.independence: Target assertions use observable results and OS state rather than accepting the manager ACK as proof\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "ObservedExternal cached addresses on linux-gum use the unchanged original native connect after Detach and match a genuine unmanaged same-sockaddr baseline, with no old gateway policy.",
    "assertion_refs": [],
    "boundary_id": "B-fake-linux-gum",
    "id": "V-fake-linux-gum",
    "obligation_id": "O-fake",
    "trigger": "ObservedExternal cached addresses on linux-gum use the unchanged original native connect after Detach and match a genuine unmanaged same-sockaddr baseline, with no old gateway policy.",
    "trigger_refs": []
  },
  {
    "assertion": "Actual HyperHub-issued aliases on linux-gum preserve their hostname and use the target SDK original resolver/connect after Detach, without Core/Socks dependency.",
    "assertion_refs": [],
    "boundary_id": "B-fake-linux-gum-issued",
    "id": "V-fake-linux-gum-issued",
    "obligation_id": "O-fake",
    "trigger": "Actual HyperHub-issued aliases on linux-gum preserve their hostname and use the target SDK original resolver/connect after Detach, without Core/Socks dependency.",
    "trigger_refs": []
  },
  {
    "assertion": "Allocate/observe another destination on linux-gum and prove an application-cached old alias is never reassigned across detach epochs or DNS TTL expiry.",
    "assertion_refs": [],
    "boundary_id": "B-fake-linux-gum-nonreuse",
    "id": "V-fake-linux-gum-nonreuse",
    "obligation_id": "O-fake",
    "trigger": "Allocate/observe another destination on linux-gum and prove an application-cached old alias is never reassigned across detach epochs or DNS TTL expiry.",
    "trigger_refs": []
  },
  {
    "assertion": "ObservedExternal cached addresses on linux-ptrace use the unchanged original native connect after Detach and match a genuine unmanaged same-sockaddr baseline, with no old gateway policy.",
    "assertion_refs": [],
    "boundary_id": "B-fake-linux-ptrace",
    "id": "V-fake-linux-ptrace",
    "obligation_id": "O-fake",
    "trigger": "ObservedExternal cached addresses on linux-ptrace use the unchanged original native connect after Detach and match a genuine unmanaged same-sockaddr baseline, with no old gateway policy.",
    "trigger_refs": []
  },
  {
    "assertion": "Actual HyperHub-issued aliases on linux-ptrace preserve their hostname and use the target SDK original resolver/connect after Detach, without Core/Socks dependency.",
    "assertion_refs": [],
    "boundary_id": "B-fake-linux-ptrace-issued",
    "id": "V-fake-linux-ptrace-issued",
    "obligation_id": "O-fake",
    "trigger": "Actual HyperHub-issued aliases on linux-ptrace preserve their hostname and use the target SDK original resolver/connect after Detach, without Core/Socks dependency.",
    "trigger_refs": []
  },
  {
    "assertion": "Allocate/observe another destination on linux-ptrace and prove an application-cached old alias is never reassigned across detach epochs or DNS TTL expiry.",
    "assertion_refs": [],
    "boundary_id": "B-fake-linux-ptrace-nonreuse",
    "id": "V-fake-linux-ptrace-nonreuse",
    "obligation_id": "O-fake",
    "trigger": "Allocate/observe another destination on linux-ptrace and prove an application-cached old alias is never reassigned across detach epochs or DNS TTL expiry.",
    "trigger_refs": []
  },
  {
    "assertion": "Cache a real HyperHub FAKE-IP before detach, connect through that exact cached alias after detach/reattach, and prove an additional destination never reuses it.",
    "assertion_refs": [],
    "boundary_id": "B-fake-windows-gum",
    "id": "V-fake-windows-gum",
    "obligation_id": "O-fake",
    "trigger": "Cache a real HyperHub FAKE-IP before detach, connect through that exact cached alias after detach/reattach, and prove an additional destination never reuses it.",
    "trigger_refs": []
  }
]
```

- code_references:

```json
[
  {
    "first": 1,
    "last": 80,
    "path": "crates/hyperhub-agent-core/src/sandbox/network.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  }
]
```

- matrix:

```json
{}
```

- automation / reproduction:

尚无已实现入口；设计可审查，执行就绪另行判定。

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-linux-gum-process"></a>

### C\-linux\-gum\-process Linux gum process scope excludes other processes

- id: C\-linux\-gum\-process
- title: Linux gum process scope excludes other processes
- kind: correctness
- implementation_status: implemented
- origin: existing
- goal: Tree scope covers current threads, existing descendants and future descendants; process scope leaves other processes unmanaged\. Living descendants remain managed after root exit\.
- obligation_ids: O\-tree
- boundary_ids: B\-tree\-linux\-gum\-process
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Same native C fixture and private local policy, process scope\.
- steps:
  1. Create and human\-approve a process\-scoped attach\.
  2. Observe root deny and child allow results, then approve detach\.
- oracle.method: Review and execute the cited native fixture or Rust test assertions; inspect matching raw outputs and actual OS identities\.
- oracle.assertion: Every cited per\-boundary assertion must run and pass; a top\-level success or manager ACK does not substitute for a missing assertion\.
- oracle.independence: Native results and OS enumeration are independent of lifecycle ACKs; cryptographic mutation units test explicit rejected inputs but do not replace end\-to\-end authorization tests\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Covered parent is denied, all separate descendants return allowed 0.",
    "assertion_refs": [
      {
        "first": 485,
        "last": 501,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-tree-linux-gum-process",
    "id": "V-1",
    "obligation_id": "O-tree",
    "trigger": "Attach --scope process; then command preexisting/fork/exec descendants to read.",
    "trigger_refs": [
      {
        "first": 485,
        "last": 501,
        "path": "scripts/test-dynamic-attach.py"
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
    "last": 80,
    "path": "crates/hyperhub-agent-core/src/attachment.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 485,
    "last": 501,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 79,
    "last": 84,
    "path": "tests/fixtures/dynamic_attach_target.c"
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
    "python3",
    "scripts/test-dynamic-attach.py",
    "--hyperhub",
    "target/release/hyperhub",
    "--backend",
    "gum",
    "--scope",
    "process",
    "--cycles",
    "1",
    "--output",
    "target/benchmarks/process-gum"
  ],
  "artifact_paths": [
    "scripts/test-dynamic-attach.py",
    "tests/fixtures/dynamic_attach_target.c"
  ],
  "cwd": "."
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-linux-host-peer"></a>

### C\-linux\-host\-peer Linux IPC authenticates server before proof exposure

- id: C\-linux\-host\-peer
- title: Linux IPC authenticates server before proof exposure
- kind: correctness
- implementation_status: implemented
- origin: existing
- goal: Only fresh human approval bound to exact process incarnation, instance, scope, backend, policy and bootstrap may mutate an external target\. Proposal alone has no effect\.
- obligation_ids: O\-approval
- boundary_ids: B\-approval\-host\-peer\-linux
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Unix listener reports wrong expected OS PID; server reads zero credential/proof bytes\.
- steps:
  1. Run the exact native crate test filter\.
  2. Require the cited input mutation and each explicit negative/positive assertion; do not promote its result to a broader native lifecycle claim\.
- oracle.method: Explicit independent expected rejection/acceptance, private ledger bytes and session membership, or OS peer observation\.
- oracle.assertion: Linux Host OS peer authentication rejects wrong server PID before credentials/proofs are sent\.
- oracle.independence: Unit seam validates only this named boundary; backend module absence and real fault timing remain separate planned native cases\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Linux Host OS peer authentication rejects wrong server PID before credentials/proofs are sent.",
    "assertion_refs": [
      {
        "first": 169,
        "last": 200,
        "path": "crates/hyperhub-runtime/src/attachment/proof_tests.rs"
      }
    ],
    "boundary_id": "B-approval-host-peer-linux",
    "id": "V-approval-host-peer-linux",
    "obligation_id": "O-approval",
    "trigger": "Unix listener reports wrong expected OS PID; server reads zero credential/proof bytes.",
    "trigger_refs": [
      {
        "first": 169,
        "last": 200,
        "path": "crates/hyperhub-runtime/src/attachment/proof_tests.rs"
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
    "last": 80,
    "path": "crates/hyperhub-core/src/attachments/authority.rs"
  },
  {
    "first": 169,
    "last": 200,
    "path": "crates/hyperhub-runtime/src/attachment/proof_tests.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
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
    "test",
    "-p",
    "hyperhub-runtime",
    "--lib",
    "attachment::proof::proof_tests",
    "--locked"
  ],
  "artifact_paths": [
    "crates/hyperhub-runtime/src/attachment/proof_tests.rs"
  ],
  "cwd": "."
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-linux-ptrace-process"></a>

### C\-linux\-ptrace\-process Linux ptrace process scope excludes other processes

- id: C\-linux\-ptrace\-process
- title: Linux ptrace process scope excludes other processes
- kind: correctness
- implementation_status: implemented
- origin: existing
- goal: Tree scope covers current threads, existing descendants and future descendants; process scope leaves other processes unmanaged\. Living descendants remain managed after root exit\.
- obligation_ids: O\-tree
- boundary_ids: B\-tree\-linux\-ptrace\-process
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Same native C fixture and private local policy, process scope\.
- steps:
  1. Create and human\-approve a process\-scoped attach\.
  2. Observe root deny and child allow results, then approve detach\.
- oracle.method: Review and execute the cited native fixture or Rust test assertions; inspect matching raw outputs and actual OS identities\.
- oracle.assertion: Every cited per\-boundary assertion must run and pass; a top\-level success or manager ACK does not substitute for a missing assertion\.
- oracle.independence: Native results and OS enumeration are independent of lifecycle ACKs; cryptographic mutation units test explicit rejected inputs but do not replace end\-to\-end authorization tests\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Covered parent is denied, all separate descendants return allowed 0.",
    "assertion_refs": [
      {
        "first": 485,
        "last": 501,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-tree-linux-ptrace-process",
    "id": "V-1",
    "obligation_id": "O-tree",
    "trigger": "Attach --scope process; then command preexisting/fork/exec descendants to read.",
    "trigger_refs": [
      {
        "first": 485,
        "last": 501,
        "path": "scripts/test-dynamic-attach.py"
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
    "last": 80,
    "path": "crates/hyperhub-agent-core/src/attachment.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 485,
    "last": 501,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 79,
    "last": 84,
    "path": "tests/fixtures/dynamic_attach_target.c"
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
    "python3",
    "scripts/test-dynamic-attach.py",
    "--hyperhub",
    "target/release/hyperhub",
    "--backend",
    "ptrace",
    "--scope",
    "process",
    "--cycles",
    "1",
    "--output",
    "target/benchmarks/process-ptrace"
  ],
  "artifact_paths": [
    "scripts/test-dynamic-attach.py",
    "tests/fixtures/dynamic_attach_target.c"
  ],
  "cwd": "."
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-manager-recovery-linux-gum"></a>

### C\-manager\-recovery\-linux\-gum Target survives; ptrace reports lost enforcement and Gum retains cached deny; fresh approved same\-id recovery restores deny, same session scope and correct child results\.

- id: C\-manager\-recovery\-linux\-gum
- title: Target survives; ptrace reports lost enforcement and Gum retains cached deny; fresh approved same\-id recovery restores deny, same session scope and correct child results\.
- kind: correctness
- implementation_status: implemented
- origin: existing
- goal: Serve and manager loss preserve allowed business activity and report enforcement loss\. Fresh approved recovery reconnects compatible residue or safely seizes an untraced target; never stack injection\.
- obligation_ids: O\-recovery
- boundary_ids: B\-recovery\-manager\-linux\-gum
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Terminate only the validated disposable manager PID/birth with pidfd; keep target and direct connection alive; fresh approve recovery\.
- steps:
  1. Execute the isolated native driver command using a built embedded candidate\.
  2. Require the cited fault/continuity/native\-policy oracle and preserve any nonzero failure\.
  3. Product failures remain failures; implemented status only records the real fixture/assertion path\.
- oracle.method: Native fixture replies, pidfd/process incarnation, OS tracer state, native TCP echo and actual post\-fault lifecycle\.
- oracle.assertion: Target survives; ptrace reports lost enforcement and Gum retains cached deny; fresh approved same\-id recovery restores deny, same session scope and correct child results\.
- oracle.independence: Policy results, byte echoes and OS state are observed outside manager ACKs; no formal run is synthesized\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Target survives; ptrace reports lost enforcement and Gum retains cached deny; fresh approved same-id recovery restores deny, same session scope and correct child results.",
    "assertion_refs": [
      {
        "first": 530,
        "last": 547,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 562,
        "last": 567,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-recovery-manager-linux-gum",
    "id": "V-recovery-manager-linux-gum",
    "obligation_id": "O-recovery",
    "trigger": "Terminate only the validated disposable manager PID/birth with pidfd; keep target and direct connection alive; fresh approve recovery.",
    "trigger_refs": [
      {
        "first": 530,
        "last": 547,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 562,
        "last": 567,
        "path": "scripts/test-dynamic-attach.py"
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
    "last": 31,
    "path": "crates/hyperhub-core/src/attachments/manager.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 530,
    "last": 547,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 562,
    "last": 567,
    "path": "scripts/test-dynamic-attach.py"
  }
]
```

- matrix:

```json
{
  "backend": "linux-gum",
  "origin": "attach"
}
```

- automation / reproduction:

```json
{
  "argv": [
    "python3",
    "scripts/test-dynamic-attach.py",
    "--hyperhub",
    "target/release/hyperhub",
    "--backend",
    "gum",
    "--manager-loss",
    "clean",
    "--cycles",
    "1",
    "--output",
    "target/benchmarks/C-manager-recovery-linux-gum"
  ],
  "artifact_paths": [
    "scripts/test-dynamic-attach.py",
    "tests/fixtures/dynamic_attach_legacy_marker.rs",
    "tests/fixtures/dynamic_attach_target.c"
  ],
  "cwd": "."
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-manager-recovery-linux-ptrace"></a>

### C\-manager\-recovery\-linux\-ptrace Target survives; ptrace reports lost enforcement and Gum retains cached deny; fresh approved same\-id recovery restores deny, same session scope and correct child results\.

- id: C\-manager\-recovery\-linux\-ptrace
- title: Target survives; ptrace reports lost enforcement and Gum retains cached deny; fresh approved same\-id recovery restores deny, same session scope and correct child results\.
- kind: correctness
- implementation_status: implemented
- origin: existing
- goal: Serve and manager loss preserve allowed business activity and report enforcement loss\. Fresh approved recovery reconnects compatible residue or safely seizes an untraced target; never stack injection\.
- obligation_ids: O\-recovery
- boundary_ids: B\-recovery\-manager\-linux\-ptrace
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Terminate only the validated disposable manager PID/birth with pidfd; keep target and direct connection alive; fresh approve recovery\.
- steps:
  1. Execute the isolated native driver command using a built embedded candidate\.
  2. Require the cited fault/continuity/native\-policy oracle and preserve any nonzero failure\.
  3. Product failures remain failures; implemented status only records the real fixture/assertion path\.
- oracle.method: Native fixture replies, pidfd/process incarnation, OS tracer state, native TCP echo and actual post\-fault lifecycle\.
- oracle.assertion: Target survives; ptrace reports lost enforcement and Gum retains cached deny; fresh approved same\-id recovery restores deny, same session scope and correct child results\.
- oracle.independence: Policy results, byte echoes and OS state are observed outside manager ACKs; no formal run is synthesized\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Target survives; ptrace reports lost enforcement and Gum retains cached deny; fresh approved same-id recovery restores deny, same session scope and correct child results.",
    "assertion_refs": [
      {
        "first": 530,
        "last": 547,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 562,
        "last": 567,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-recovery-manager-linux-ptrace",
    "id": "V-recovery-manager-linux-ptrace",
    "obligation_id": "O-recovery",
    "trigger": "Terminate only the validated disposable manager PID/birth with pidfd; keep target and direct connection alive; fresh approve recovery.",
    "trigger_refs": [
      {
        "first": 530,
        "last": 547,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 562,
        "last": 567,
        "path": "scripts/test-dynamic-attach.py"
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
    "last": 31,
    "path": "crates/hyperhub-core/src/attachments/manager.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 530,
    "last": 547,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 562,
    "last": 567,
    "path": "scripts/test-dynamic-attach.py"
  }
]
```

- matrix:

```json
{
  "backend": "linux-ptrace",
  "origin": "attach"
}
```

- automation / reproduction:

```json
{
  "argv": [
    "python3",
    "scripts/test-dynamic-attach.py",
    "--hyperhub",
    "target/release/hyperhub",
    "--backend",
    "ptrace",
    "--manager-loss",
    "clean",
    "--cycles",
    "1",
    "--output",
    "target/benchmarks/C-manager-recovery-linux-ptrace"
  ],
  "artifact_paths": [
    "scripts/test-dynamic-attach.py",
    "tests/fixtures/dynamic_attach_legacy_marker.rs",
    "tests/fixtures/dynamic_attach_target.c"
  ],
  "cwd": "."
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-native-linux-gum-attach"></a>

### C\-native\-linux\-gum\-attach Linux gum attach native correctness and controlling PTY

- id: C\-native\-linux\-gum\-attach
- title: Linux gum attach native correctness and controlling PTY
- kind: correctness
- implementation_status: implemented
- origin: existing
- goal: Only fresh human approval bound to exact process incarnation, instance, scope, backend, policy and bootstrap may mutate an external target\. Proposal alone has no effect\.; Preserve allowed payloads, existing TCP, blocking original calls, socket flags, explicit child environments, PID, cwd, stdio, terminal state and original root exit status\.; Approved detach stops new enforcement\. Keep compatibility code while calls, async operations, trust contexts, callbacks or cached addresses need it\. Detached requires independent physical\-unload proof\.; Tree scope covers current threads, existing descendants and future descendants; process scope leaves other processes unmanaged\. Living descendants remain managed after root exit\.
- obligation_ids: O\-approval, O\-continuity, O\-drain, O\-tree
- boundary_ids: B\-approval\-proposal\-linux\-gum, B\-continuity\-linux\-gum\-identity, B\-continuity\-linux\-gum\-io, B\-continuity\-linux\-gum\-terminal, B\-drain\-linux\-gum\-blocked, B\-tree\-linux\-gum\-tree
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Local echo server, S newline protected file, preexisting descendant, explicit\-environment children, two managed native threads and real target PTY\.
- steps:
  1. Build embedded optimized CLI and C fixture through the existing driver\.
  2. Run three complete approved lifecycle cycles under the specified backend/origin\.
  3. Use the cited command responses and identity/terminal assertions; preserve any failure\.json and nonzero exit\.
- oracle.method: Review and execute the cited native fixture or Rust test assertions; inspect matching raw outputs and actual OS identities\.
- oracle.assertion: Every cited per\-boundary assertion must run and pass; a top\-level success or manager ACK does not substitute for a missing assertion\.
- oracle.independence: Native results and OS enumeration are independent of lifecycle ACKs; cryptographic mutation units test explicit rejected inputs but do not replace end\-to\-end authorization tests\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Root, existing child, fork child and exec child each report EACCES 13.",
    "assertion_refs": [
      {
        "first": 485,
        "last": 501,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-tree-linux-gum-tree",
    "id": "V-1",
    "obligation_id": "O-tree",
    "trigger": "Run tree scope; fixture has a preexisting child and creates fork/exec children during Active.",
    "trigger_refs": [
      {
        "first": 485,
        "last": 501,
        "path": "scripts/test-dynamic-attach.py"
      }
    ]
  },
  {
    "assertion": "Byte echoes, blocked-read byte/result and O_NONBLOCK flags survive; read policy stops after approved detach.",
    "assertion_refs": [
      {
        "first": 473,
        "last": 487,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 577,
        "last": 592,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-continuity-linux-gum-io",
    "id": "V-2",
    "obligation_id": "O-continuity",
    "trigger": "Use existing TCP, open new TCP, connect a preopened socket, and block an original read before approved detach.",
    "trigger_refs": [
      {
        "first": 473,
        "last": 487,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 577,
        "last": 592,
        "path": "scripts/test-dynamic-attach.py"
      }
    ]
  },
  {
    "assertion": "PID/cwd/stdio/environment snapshots stay stable, explicit child environments return success, target exits 37.",
    "assertion_refs": [
      {
        "first": 499,
        "last": 502,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 599,
        "last": 604,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 629,
        "last": 641,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-continuity-linux-gum-identity",
    "id": "V-3",
    "obligation_id": "O-continuity",
    "trigger": "Keep the same target across lifecycle and pass explicit exec/spawn child environment.",
    "trigger_refs": [
      {
        "first": 499,
        "last": 502,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 599,
        "last": 604,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 629,
        "last": 641,
        "path": "scripts/test-dynamic-attach.py"
      }
    ]
  },
  {
    "assertion": "has_terminal matches requested PTY and stable_terminal remains true after lifecycle; fixture compares termios and foreground group.",
    "assertion_refs": [
      {
        "first": 416,
        "last": 425,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 599,
        "last": 604,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-continuity-linux-gum-terminal",
    "id": "V-4",
    "obligation_id": "O-continuity",
    "trigger": "Start the target under --target-pty with a real controlling terminal.",
    "trigger_refs": [
      {
        "first": 416,
        "last": 425,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 599,
        "last": 604,
        "path": "scripts/test-dynamic-attach.py"
      }
    ]
  },
  {
    "assertion": "Unblock returns original B byte successfully; idle socket remains nonblocking after detach.",
    "assertion_refs": [
      {
        "first": 577,
        "last": 585,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-drain-linux-gum-blocked",
    "id": "V-5",
    "obligation_id": "O-drain",
    "trigger": "Start blocked original read and create nonblocking socket before detach.",
    "trigger_refs": [
      {
        "first": 577,
        "last": 585,
        "path": "scripts/test-dynamic-attach.py"
      }
    ]
  },
  {
    "assertion": "Attach proposal leaves read allowed; detach proposal leaves read denied until human approval.",
    "assertion_refs": [
      {
        "first": 467,
        "last": 473,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 579,
        "last": 586,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-approval-proposal-linux-gum",
    "id": "V-6",
    "obligation_id": "O-approval",
    "trigger": "Read file before attach approval and before detach approval.",
    "trigger_refs": [
      {
        "first": 467,
        "last": 473,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 579,
        "last": 586,
        "path": "scripts/test-dynamic-attach.py"
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
    "last": 80,
    "path": "crates/hyperhub-agent-core/src/attachment.rs"
  },
  {
    "first": 1,
    "last": 80,
    "path": "crates/hyperhub-core/src/attachments/authority.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 416,
    "last": 425,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 467,
    "last": 473,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 473,
    "last": 487,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 485,
    "last": 501,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 499,
    "last": 502,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 577,
    "last": 585,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 577,
    "last": 592,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 579,
    "last": 586,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 599,
    "last": 604,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 629,
    "last": 641,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 1,
    "last": 80,
    "path": "tests/fixtures/dynamic_attach_target.c"
  },
  {
    "first": 79,
    "last": 84,
    "path": "tests/fixtures/dynamic_attach_target.c"
  },
  {
    "first": 89,
    "last": 99,
    "path": "tests/fixtures/dynamic_attach_target.c"
  },
  {
    "first": 147,
    "last": 151,
    "path": "tests/fixtures/dynamic_attach_target.c"
  }
]
```

- matrix:

```json
{
  "backend": "linux-gum",
  "origin": "attach"
}
```

- automation / reproduction:

```json
{
  "argv": [
    "python3",
    "scripts/test-dynamic-attach.py",
    "--hyperhub",
    "target/release/hyperhub",
    "--backend",
    "gum",
    "--origin",
    "attach",
    "--scope",
    "tree",
    "--target-pty",
    "--cycles",
    "3",
    "--output",
    "target/benchmarks/C-native-linux-gum-attach"
  ],
  "artifact_paths": [
    "scripts/test-dynamic-attach.py",
    "tests/fixtures/dynamic_attach_target.c"
  ],
  "cwd": "."
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-native-linux-gum-run"></a>

### C\-native\-linux\-gum\-run Linux gum run native correctness and controlling PTY

- id: C\-native\-linux\-gum\-run
- title: Linux gum run native correctness and controlling PTY
- kind: correctness
- implementation_status: implemented
- origin: existing
- goal: Preserve allowed payloads, existing TCP, blocking original calls, socket flags, explicit child environments, PID, cwd, stdio, terminal state and original root exit status\.; Approved detach stops new enforcement\. Keep compatibility code while calls, async operations, trust contexts, callbacks or cached addresses need it\. Detached requires independent physical\-unload proof\.; Tree scope covers current threads, existing descendants and future descendants; process scope leaves other processes unmanaged\. Living descendants remain managed after root exit\.
- obligation_ids: O\-continuity, O\-drain, O\-tree
- boundary_ids: B\-continuity\-linux\-gum\-identity, B\-continuity\-linux\-gum\-io, B\-continuity\-linux\-gum\-terminal, B\-drain\-linux\-gum\-blocked, B\-tree\-linux\-gum\-tree
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Local echo server, S newline protected file, preexisting descendant, explicit\-environment children, two managed native threads and real target PTY\.
- steps:
  1. Build embedded optimized CLI and C fixture through the existing driver\.
  2. Run three complete approved lifecycle cycles under the specified backend/origin\.
  3. Use the cited command responses and identity/terminal assertions; preserve any failure\.json and nonzero exit\.
- oracle.method: Review and execute the cited native fixture or Rust test assertions; inspect matching raw outputs and actual OS identities\.
- oracle.assertion: Every cited per\-boundary assertion must run and pass; a top\-level success or manager ACK does not substitute for a missing assertion\.
- oracle.independence: Native results and OS enumeration are independent of lifecycle ACKs; cryptographic mutation units test explicit rejected inputs but do not replace end\-to\-end authorization tests\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Root, existing child, fork child and exec child each report EACCES 13.",
    "assertion_refs": [
      {
        "first": 485,
        "last": 501,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-tree-linux-gum-tree",
    "id": "V-1",
    "obligation_id": "O-tree",
    "trigger": "Run tree scope; fixture has a preexisting child and creates fork/exec children during Active.",
    "trigger_refs": [
      {
        "first": 485,
        "last": 501,
        "path": "scripts/test-dynamic-attach.py"
      }
    ]
  },
  {
    "assertion": "Byte echoes, blocked-read byte/result and O_NONBLOCK flags survive; read policy stops after approved detach.",
    "assertion_refs": [
      {
        "first": 473,
        "last": 487,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 577,
        "last": 592,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-continuity-linux-gum-io",
    "id": "V-2",
    "obligation_id": "O-continuity",
    "trigger": "Use existing TCP, open new TCP, connect a preopened socket, and block an original read before approved detach.",
    "trigger_refs": [
      {
        "first": 473,
        "last": 487,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 577,
        "last": 592,
        "path": "scripts/test-dynamic-attach.py"
      }
    ]
  },
  {
    "assertion": "PID/cwd/stdio/environment snapshots stay stable, explicit child environments return success, target exits 37.",
    "assertion_refs": [
      {
        "first": 499,
        "last": 502,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 599,
        "last": 604,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 629,
        "last": 641,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-continuity-linux-gum-identity",
    "id": "V-3",
    "obligation_id": "O-continuity",
    "trigger": "Keep the same target across lifecycle and pass explicit exec/spawn child environment.",
    "trigger_refs": [
      {
        "first": 499,
        "last": 502,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 599,
        "last": 604,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 629,
        "last": 641,
        "path": "scripts/test-dynamic-attach.py"
      }
    ]
  },
  {
    "assertion": "has_terminal matches requested PTY and stable_terminal remains true after lifecycle; fixture compares termios and foreground group.",
    "assertion_refs": [
      {
        "first": 416,
        "last": 425,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 599,
        "last": 604,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-continuity-linux-gum-terminal",
    "id": "V-4",
    "obligation_id": "O-continuity",
    "trigger": "Start the target under --target-pty with a real controlling terminal.",
    "trigger_refs": [
      {
        "first": 416,
        "last": 425,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 599,
        "last": 604,
        "path": "scripts/test-dynamic-attach.py"
      }
    ]
  },
  {
    "assertion": "Unblock returns original B byte successfully; idle socket remains nonblocking after detach.",
    "assertion_refs": [
      {
        "first": 577,
        "last": 585,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-drain-linux-gum-blocked",
    "id": "V-5",
    "obligation_id": "O-drain",
    "trigger": "Start blocked original read and create nonblocking socket before detach.",
    "trigger_refs": [
      {
        "first": 577,
        "last": 585,
        "path": "scripts/test-dynamic-attach.py"
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
    "last": 80,
    "path": "crates/hyperhub-agent-core/src/attachment.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 416,
    "last": 425,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 473,
    "last": 487,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 485,
    "last": 501,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 499,
    "last": 502,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 577,
    "last": 585,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 577,
    "last": 592,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 599,
    "last": 604,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 629,
    "last": 641,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 1,
    "last": 80,
    "path": "tests/fixtures/dynamic_attach_target.c"
  },
  {
    "first": 79,
    "last": 84,
    "path": "tests/fixtures/dynamic_attach_target.c"
  },
  {
    "first": 89,
    "last": 99,
    "path": "tests/fixtures/dynamic_attach_target.c"
  },
  {
    "first": 147,
    "last": 151,
    "path": "tests/fixtures/dynamic_attach_target.c"
  }
]
```

- matrix:

```json
{
  "backend": "linux-gum",
  "origin": "run"
}
```

- automation / reproduction:

```json
{
  "argv": [
    "python3",
    "scripts/test-dynamic-attach.py",
    "--hyperhub",
    "target/release/hyperhub",
    "--backend",
    "gum",
    "--origin",
    "run",
    "--scope",
    "tree",
    "--target-pty",
    "--cycles",
    "3",
    "--output",
    "target/benchmarks/C-native-linux-gum-run"
  ],
  "artifact_paths": [
    "scripts/test-dynamic-attach.py",
    "tests/fixtures/dynamic_attach_target.c"
  ],
  "cwd": "."
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-native-linux-ptrace-attach"></a>

### C\-native\-linux\-ptrace\-attach Linux ptrace attach native correctness and controlling PTY

- id: C\-native\-linux\-ptrace\-attach
- title: Linux ptrace attach native correctness and controlling PTY
- kind: correctness
- implementation_status: implemented
- origin: existing
- goal: Only fresh human approval bound to exact process incarnation, instance, scope, backend, policy and bootstrap may mutate an external target\. Proposal alone has no effect\.; Preserve allowed payloads, existing TCP, blocking original calls, socket flags, explicit child environments, PID, cwd, stdio, terminal state and original root exit status\.; Approved detach stops new enforcement\. Keep compatibility code while calls, async operations, trust contexts, callbacks or cached addresses need it\. Detached requires independent physical\-unload proof\.; Tree scope covers current threads, existing descendants and future descendants; process scope leaves other processes unmanaged\. Living descendants remain managed after root exit\.
- obligation_ids: O\-approval, O\-continuity, O\-drain, O\-tree
- boundary_ids: B\-approval\-proposal\-linux\-ptrace, B\-continuity\-linux\-ptrace\-identity, B\-continuity\-linux\-ptrace\-io, B\-continuity\-linux\-ptrace\-terminal, B\-drain\-linux\-ptrace\-blocked, B\-tree\-linux\-ptrace\-tree
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Local echo server, S newline protected file, preexisting descendant, explicit\-environment children, two managed native threads and real target PTY\.
- steps:
  1. Build embedded optimized CLI and C fixture through the existing driver\.
  2. Run three complete approved lifecycle cycles under the specified backend/origin\.
  3. Use the cited command responses and identity/terminal assertions; preserve any failure\.json and nonzero exit\.
- oracle.method: Review and execute the cited native fixture or Rust test assertions; inspect matching raw outputs and actual OS identities\.
- oracle.assertion: Every cited per\-boundary assertion must run and pass; a top\-level success or manager ACK does not substitute for a missing assertion\.
- oracle.independence: Native results and OS enumeration are independent of lifecycle ACKs; cryptographic mutation units test explicit rejected inputs but do not replace end\-to\-end authorization tests\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Root, existing child, fork child and exec child each report EACCES 13.",
    "assertion_refs": [
      {
        "first": 485,
        "last": 501,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-tree-linux-ptrace-tree",
    "id": "V-1",
    "obligation_id": "O-tree",
    "trigger": "Run tree scope; fixture has a preexisting child and creates fork/exec children during Active.",
    "trigger_refs": [
      {
        "first": 485,
        "last": 501,
        "path": "scripts/test-dynamic-attach.py"
      }
    ]
  },
  {
    "assertion": "Byte echoes, blocked-read byte/result and O_NONBLOCK flags survive; read policy stops after approved detach.",
    "assertion_refs": [
      {
        "first": 473,
        "last": 487,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 577,
        "last": 592,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-continuity-linux-ptrace-io",
    "id": "V-2",
    "obligation_id": "O-continuity",
    "trigger": "Use existing TCP, open new TCP, connect a preopened socket, and block an original read before approved detach.",
    "trigger_refs": [
      {
        "first": 473,
        "last": 487,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 577,
        "last": 592,
        "path": "scripts/test-dynamic-attach.py"
      }
    ]
  },
  {
    "assertion": "PID/cwd/stdio/environment snapshots stay stable, explicit child environments return success, target exits 37.",
    "assertion_refs": [
      {
        "first": 499,
        "last": 502,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 599,
        "last": 604,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 629,
        "last": 641,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-continuity-linux-ptrace-identity",
    "id": "V-3",
    "obligation_id": "O-continuity",
    "trigger": "Keep the same target across lifecycle and pass explicit exec/spawn child environment.",
    "trigger_refs": [
      {
        "first": 499,
        "last": 502,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 599,
        "last": 604,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 629,
        "last": 641,
        "path": "scripts/test-dynamic-attach.py"
      }
    ]
  },
  {
    "assertion": "has_terminal matches requested PTY and stable_terminal remains true after lifecycle; fixture compares termios and foreground group.",
    "assertion_refs": [
      {
        "first": 416,
        "last": 425,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 599,
        "last": 604,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-continuity-linux-ptrace-terminal",
    "id": "V-4",
    "obligation_id": "O-continuity",
    "trigger": "Start the target under --target-pty with a real controlling terminal.",
    "trigger_refs": [
      {
        "first": 416,
        "last": 425,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 599,
        "last": 604,
        "path": "scripts/test-dynamic-attach.py"
      }
    ]
  },
  {
    "assertion": "Unblock returns original B byte successfully; idle socket remains nonblocking after detach.",
    "assertion_refs": [
      {
        "first": 577,
        "last": 585,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-drain-linux-ptrace-blocked",
    "id": "V-5",
    "obligation_id": "O-drain",
    "trigger": "Start blocked original read and create nonblocking socket before detach.",
    "trigger_refs": [
      {
        "first": 577,
        "last": 585,
        "path": "scripts/test-dynamic-attach.py"
      }
    ]
  },
  {
    "assertion": "Attach proposal leaves read allowed; detach proposal leaves read denied until human approval.",
    "assertion_refs": [
      {
        "first": 467,
        "last": 473,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 579,
        "last": 586,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-approval-proposal-linux-ptrace",
    "id": "V-6",
    "obligation_id": "O-approval",
    "trigger": "Read file before attach approval and before detach approval.",
    "trigger_refs": [
      {
        "first": 467,
        "last": 473,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 579,
        "last": 586,
        "path": "scripts/test-dynamic-attach.py"
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
    "last": 80,
    "path": "crates/hyperhub-agent-core/src/attachment.rs"
  },
  {
    "first": 1,
    "last": 80,
    "path": "crates/hyperhub-core/src/attachments/authority.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 416,
    "last": 425,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 467,
    "last": 473,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 473,
    "last": 487,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 485,
    "last": 501,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 499,
    "last": 502,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 577,
    "last": 585,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 577,
    "last": 592,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 579,
    "last": 586,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 599,
    "last": 604,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 629,
    "last": 641,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 1,
    "last": 80,
    "path": "tests/fixtures/dynamic_attach_target.c"
  },
  {
    "first": 79,
    "last": 84,
    "path": "tests/fixtures/dynamic_attach_target.c"
  },
  {
    "first": 89,
    "last": 99,
    "path": "tests/fixtures/dynamic_attach_target.c"
  },
  {
    "first": 147,
    "last": 151,
    "path": "tests/fixtures/dynamic_attach_target.c"
  }
]
```

- matrix:

```json
{
  "backend": "linux-ptrace",
  "origin": "attach"
}
```

- automation / reproduction:

```json
{
  "argv": [
    "python3",
    "scripts/test-dynamic-attach.py",
    "--hyperhub",
    "target/release/hyperhub",
    "--backend",
    "ptrace",
    "--origin",
    "attach",
    "--scope",
    "tree",
    "--target-pty",
    "--cycles",
    "3",
    "--output",
    "target/benchmarks/C-native-linux-ptrace-attach"
  ],
  "artifact_paths": [
    "scripts/test-dynamic-attach.py",
    "tests/fixtures/dynamic_attach_target.c"
  ],
  "cwd": "."
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-native-linux-ptrace-run"></a>

### C\-native\-linux\-ptrace\-run Linux ptrace run native correctness and controlling PTY

- id: C\-native\-linux\-ptrace\-run
- title: Linux ptrace run native correctness and controlling PTY
- kind: correctness
- implementation_status: implemented
- origin: existing
- goal: Preserve allowed payloads, existing TCP, blocking original calls, socket flags, explicit child environments, PID, cwd, stdio, terminal state and original root exit status\.; Approved detach stops new enforcement\. Keep compatibility code while calls, async operations, trust contexts, callbacks or cached addresses need it\. Detached requires independent physical\-unload proof\.; Tree scope covers current threads, existing descendants and future descendants; process scope leaves other processes unmanaged\. Living descendants remain managed after root exit\.
- obligation_ids: O\-continuity, O\-drain, O\-tree
- boundary_ids: B\-continuity\-linux\-ptrace\-identity, B\-continuity\-linux\-ptrace\-io, B\-continuity\-linux\-ptrace\-terminal, B\-drain\-linux\-ptrace\-blocked, B\-tree\-linux\-ptrace\-tree
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Local echo server, S newline protected file, preexisting descendant, explicit\-environment children, two managed native threads and real target PTY\.
- steps:
  1. Build embedded optimized CLI and C fixture through the existing driver\.
  2. Run three complete approved lifecycle cycles under the specified backend/origin\.
  3. Use the cited command responses and identity/terminal assertions; preserve any failure\.json and nonzero exit\.
- oracle.method: Review and execute the cited native fixture or Rust test assertions; inspect matching raw outputs and actual OS identities\.
- oracle.assertion: Every cited per\-boundary assertion must run and pass; a top\-level success or manager ACK does not substitute for a missing assertion\.
- oracle.independence: Native results and OS enumeration are independent of lifecycle ACKs; cryptographic mutation units test explicit rejected inputs but do not replace end\-to\-end authorization tests\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Root, existing child, fork child and exec child each report EACCES 13.",
    "assertion_refs": [
      {
        "first": 485,
        "last": 501,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-tree-linux-ptrace-tree",
    "id": "V-1",
    "obligation_id": "O-tree",
    "trigger": "Run tree scope; fixture has a preexisting child and creates fork/exec children during Active.",
    "trigger_refs": [
      {
        "first": 485,
        "last": 501,
        "path": "scripts/test-dynamic-attach.py"
      }
    ]
  },
  {
    "assertion": "Byte echoes, blocked-read byte/result and O_NONBLOCK flags survive; read policy stops after approved detach.",
    "assertion_refs": [
      {
        "first": 473,
        "last": 487,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 577,
        "last": 592,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-continuity-linux-ptrace-io",
    "id": "V-2",
    "obligation_id": "O-continuity",
    "trigger": "Use existing TCP, open new TCP, connect a preopened socket, and block an original read before approved detach.",
    "trigger_refs": [
      {
        "first": 473,
        "last": 487,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 577,
        "last": 592,
        "path": "scripts/test-dynamic-attach.py"
      }
    ]
  },
  {
    "assertion": "PID/cwd/stdio/environment snapshots stay stable, explicit child environments return success, target exits 37.",
    "assertion_refs": [
      {
        "first": 499,
        "last": 502,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 599,
        "last": 604,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 629,
        "last": 641,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-continuity-linux-ptrace-identity",
    "id": "V-3",
    "obligation_id": "O-continuity",
    "trigger": "Keep the same target across lifecycle and pass explicit exec/spawn child environment.",
    "trigger_refs": [
      {
        "first": 499,
        "last": 502,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 599,
        "last": 604,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 629,
        "last": 641,
        "path": "scripts/test-dynamic-attach.py"
      }
    ]
  },
  {
    "assertion": "has_terminal matches requested PTY and stable_terminal remains true after lifecycle; fixture compares termios and foreground group.",
    "assertion_refs": [
      {
        "first": 416,
        "last": 425,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 599,
        "last": 604,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-continuity-linux-ptrace-terminal",
    "id": "V-4",
    "obligation_id": "O-continuity",
    "trigger": "Start the target under --target-pty with a real controlling terminal.",
    "trigger_refs": [
      {
        "first": 416,
        "last": 425,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 599,
        "last": 604,
        "path": "scripts/test-dynamic-attach.py"
      }
    ]
  },
  {
    "assertion": "Unblock returns original B byte successfully; idle socket remains nonblocking after detach.",
    "assertion_refs": [
      {
        "first": 577,
        "last": 585,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-drain-linux-ptrace-blocked",
    "id": "V-5",
    "obligation_id": "O-drain",
    "trigger": "Start blocked original read and create nonblocking socket before detach.",
    "trigger_refs": [
      {
        "first": 577,
        "last": 585,
        "path": "scripts/test-dynamic-attach.py"
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
    "last": 80,
    "path": "crates/hyperhub-agent-core/src/attachment.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 416,
    "last": 425,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 473,
    "last": 487,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 485,
    "last": 501,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 499,
    "last": 502,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 577,
    "last": 585,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 577,
    "last": 592,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 599,
    "last": 604,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 629,
    "last": 641,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 1,
    "last": 80,
    "path": "tests/fixtures/dynamic_attach_target.c"
  },
  {
    "first": 79,
    "last": 84,
    "path": "tests/fixtures/dynamic_attach_target.c"
  },
  {
    "first": 89,
    "last": 99,
    "path": "tests/fixtures/dynamic_attach_target.c"
  },
  {
    "first": 147,
    "last": 151,
    "path": "tests/fixtures/dynamic_attach_target.c"
  }
]
```

- matrix:

```json
{
  "backend": "linux-ptrace",
  "origin": "run"
}
```

- automation / reproduction:

```json
{
  "argv": [
    "python3",
    "scripts/test-dynamic-attach.py",
    "--hyperhub",
    "target/release/hyperhub",
    "--backend",
    "ptrace",
    "--origin",
    "run",
    "--scope",
    "tree",
    "--target-pty",
    "--cycles",
    "3",
    "--output",
    "target/benchmarks/C-native-linux-ptrace-run"
  ],
  "artifact_paths": [
    "scripts/test-dynamic-attach.py",
    "tests/fixtures/dynamic_attach_target.c"
  ],
  "cwd": "."
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-native-windows-gum"></a>

### C\-native\-windows\-gum Windows native tree, reconnect, original\-call drain and module absence

- id: C\-native\-windows\-gum
- title: Windows native tree, reconnect, original\-call drain and module absence
- kind: correctness
- implementation_status: implemented
- origin: existing
- goal: Only fresh human approval bound to exact process incarnation, instance, scope, backend, policy and bootstrap may mutate an external target\. Proposal alone has no effect\.; Preserve allowed payloads, existing TCP, blocking original calls, socket flags, explicit child environments, PID, cwd, stdio, terminal state and original root exit status\.; Approved detach stops new enforcement\. Keep compatibility code while calls, async operations, trust contexts, callbacks or cached addresses need it\. Detached requires independent physical\-unload proof\.; Serve and manager loss preserve allowed business activity and report enforcement loss\. Fresh approved recovery reconnects compatible residue or safely seizes an untraced target; never stack injection\.; Tree scope covers current threads, existing descendants and future descendants; process scope leaves other processes unmanaged\. Living descendants remain managed after root exit\.
- obligation_ids: O\-approval, O\-continuity, O\-drain, O\-recovery, O\-tree
- boundary_ids: B\-approval\-proposal\-windows\-gum, B\-continuity\-windows\-identity, B\-continuity\-windows\-io, B\-drain\-windows\-blocked\-trust, B\-recovery\-manager\-windows, B\-tree\-rootexit\-windows, B\-tree\-windows\-existing, B\-tree\-windows\-future
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Native Windows Rust fixture, local TCP echo, disposable credentials, busy process creation, blocked ReadFile and retained Schannel credential\.
- steps:
  1. Build fixture with rustc and use real human ConPTY approvals\.
  2. Execute three complete cycles including actual authenticated manager termination and recovery\.
  3. Treat module enumeration as physical evidence; terminal target\-mode and session\-revocation oracles remain separate planned gaps\.
- oracle.method: Review and execute the cited native fixture or Rust test assertions; inspect matching raw outputs and actual OS identities\.
- oracle.assertion: Every cited per\-boundary assertion must run and pass; a top\-level success or manager ACK does not substitute for a missing assertion\.
- oracle.independence: Native results and OS enumeration are independent of lifecycle ACKs; cryptographic mutation units test explicit rejected inputs but do not replace end\-to\-end authorization tests\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Read remains allowed before attach approval and denied before detach approval.",
    "assertion_refs": [
      {
        "first": 354,
        "last": 361,
        "path": "scripts/test-dynamic-attach-windows.py"
      },
      {
        "first": 421,
        "last": 425,
        "path": "scripts/test-dynamic-attach-windows.py"
      }
    ],
    "boundary_id": "B-approval-proposal-windows-gum",
    "id": "V-1",
    "obligation_id": "O-approval",
    "trigger": "Submit attach/detach proposals through real ConPTY approvals.",
    "trigger_refs": [
      {
        "first": 354,
        "last": 361,
        "path": "scripts/test-dynamic-attach-windows.py"
      },
      {
        "first": 421,
        "last": 425,
        "path": "scripts/test-dynamic-attach-windows.py"
      }
    ]
  },
  {
    "assertion": "At least10 strict-post-cutoff events are present, every one denied; stop/join then recheck final in-flight events. Ambiguous/sub-guard commit timing remains a separate planned boundary.",
    "assertion_refs": [
      {
        "first": 418,
        "last": 419,
        "path": "scripts/test-dynamic-attach-windows.py"
      }
    ],
    "boundary_id": "B-tree-windows-future",
    "id": "V-2",
    "obligation_id": "O-tree",
    "trigger": "Keep all pre/boundary/post child events without counter reset; use the published Active record timestamp with explicit1ms clock guard.",
    "trigger_refs": [
      {
        "first": 418,
        "last": 419,
        "path": "scripts/test-dynamic-attach-windows.py"
      }
    ]
  },
  {
    "assertion": "Both echoes remain correct and unblock reports preserved original result.",
    "assertion_refs": [
      {
        "first": 418,
        "last": 427,
        "path": "scripts/test-dynamic-attach-windows.py"
      },
      {
        "first": 470,
        "last": 476,
        "path": "scripts/test-dynamic-attach-windows.py"
      }
    ],
    "boundary_id": "B-continuity-windows-io",
    "id": "V-3",
    "obligation_id": "O-continuity",
    "trigger": "Maintain old/new TCP and original blocked ReadFile across detach.",
    "trigger_refs": [
      {
        "first": 418,
        "last": 427,
        "path": "scripts/test-dynamic-attach-windows.py"
      },
      {
        "first": 470,
        "last": 476,
        "path": "scripts/test-dynamic-attach-windows.py"
      }
    ]
  },
  {
    "assertion": "Snapshot identity/cwd/stdio/environment stay stable, progress increases, real root exits37.",
    "assertion_refs": [
      {
        "first": 473,
        "last": 485,
        "path": "scripts/test-dynamic-attach-windows.py"
      }
    ],
    "boundary_id": "B-continuity-windows-identity",
    "id": "V-4",
    "obligation_id": "O-continuity",
    "trigger": "Use the same root with unchanged environment, cwd and stdio across lifecycle.",
    "trigger_refs": [
      {
        "first": 473,
        "last": 485,
        "path": "scripts/test-dynamic-attach-windows.py"
      }
    ]
  },
  {
    "assertion": "OS module remains present before unblock and while retained credential exists, then credential release allows cleanup.",
    "assertion_refs": [
      {
        "first": 420,
        "last": 458,
        "path": "scripts/test-dynamic-attach-windows.py"
      },
      {
        "first": 466,
        "last": 469,
        "path": "scripts/test-dynamic-attach-windows.py"
      }
    ],
    "boundary_id": "B-drain-windows-blocked-trust",
    "id": "V-5",
    "obligation_id": "O-drain",
    "trigger": "Keep an original ReadFile outstanding and a modified Schannel credential alive during detach.",
    "trigger_refs": [
      {
        "first": 420,
        "last": 458,
        "path": "scripts/test-dynamic-attach-windows.py"
      },
      {
        "first": 466,
        "last": 469,
        "path": "scripts/test-dynamic-attach-windows.py"
      }
    ]
  },
  {
    "assertion": "Same attachment id, new manager PID, exactly one native module and protected read remains denied.",
    "assertion_refs": [
      {
        "first": 376,
        "last": 387,
        "path": "scripts/test-dynamic-attach-windows.py"
      },
      {
        "first": 429,
        "last": 439,
        "path": "scripts/test-dynamic-attach-windows.py"
      }
    ],
    "boundary_id": "B-recovery-manager-windows",
    "id": "V-6",
    "obligation_id": "O-recovery",
    "trigger": "Kill only manager after validating its image/birth; propose fresh attach recovery.",
    "trigger_refs": [
      {
        "first": 376,
        "last": 387,
        "path": "scripts/test-dynamic-attach-windows.py"
      },
      {
        "first": 429,
        "last": 439,
        "path": "scripts/test-dynamic-attach-windows.py"
      }
    ]
  },
  {
    "assertion": "Foreground root exits37, survivor remains in membership and denied until approved detach; module absent after cleanup.",
    "assertion_refs": [
      {
        "first": 486,
        "last": 510,
        "path": "scripts/test-dynamic-attach-windows.py"
      }
    ],
    "boundary_id": "B-tree-rootexit-windows",
    "id": "V-7",
    "obligation_id": "O-tree",
    "trigger": "Owned run creates survivor, root exits, keeper remains.",
    "trigger_refs": [
      {
        "first": 486,
        "last": 510,
        "path": "scripts/test-dynamic-attach-windows.py"
      }
    ]
  },
  {
    "assertion": "The exact preexisting child is listed in committed members and its read becomes13.",
    "assertion_refs": [
      {
        "first": 337,
        "last": 346,
        "path": "scripts/test-dynamic-attach-windows.py"
      },
      {
        "first": 388,
        "last": 416,
        "path": "scripts/test-dynamic-attach-windows.py"
      }
    ],
    "boundary_id": "B-tree-windows-existing",
    "id": "V-held-existing-child",
    "obligation_id": "O-tree",
    "trigger": "Keep a known child alive before attach with baseline read0, then publish Active and query that same PID.",
    "trigger_refs": [
      {
        "first": 337,
        "last": 346,
        "path": "scripts/test-dynamic-attach-windows.py"
      },
      {
        "first": 388,
        "last": 416,
        "path": "scripts/test-dynamic-attach-windows.py"
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
    "last": 80,
    "path": "crates/hyperhub-agent-core/src/attachment.rs"
  },
  {
    "first": 1,
    "last": 80,
    "path": "crates/hyperhub-core/src/attachments/authority.rs"
  },
  {
    "first": 1,
    "last": 31,
    "path": "crates/hyperhub-core/src/attachments/manager.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 337,
    "last": 346,
    "path": "scripts/test-dynamic-attach-windows.py"
  },
  {
    "first": 354,
    "last": 361,
    "path": "scripts/test-dynamic-attach-windows.py"
  },
  {
    "first": 376,
    "last": 387,
    "path": "scripts/test-dynamic-attach-windows.py"
  },
  {
    "first": 388,
    "last": 416,
    "path": "scripts/test-dynamic-attach-windows.py"
  },
  {
    "first": 418,
    "last": 419,
    "path": "scripts/test-dynamic-attach-windows.py"
  },
  {
    "first": 418,
    "last": 427,
    "path": "scripts/test-dynamic-attach-windows.py"
  },
  {
    "first": 420,
    "last": 458,
    "path": "scripts/test-dynamic-attach-windows.py"
  },
  {
    "first": 421,
    "last": 425,
    "path": "scripts/test-dynamic-attach-windows.py"
  },
  {
    "first": 429,
    "last": 439,
    "path": "scripts/test-dynamic-attach-windows.py"
  },
  {
    "first": 466,
    "last": 469,
    "path": "scripts/test-dynamic-attach-windows.py"
  },
  {
    "first": 470,
    "last": 476,
    "path": "scripts/test-dynamic-attach-windows.py"
  },
  {
    "first": 473,
    "last": 485,
    "path": "scripts/test-dynamic-attach-windows.py"
  },
  {
    "first": 486,
    "last": 510,
    "path": "scripts/test-dynamic-attach-windows.py"
  },
  {
    "first": 1,
    "last": 80,
    "path": "tests/fixtures/dynamic_attach_target.c"
  },
  {
    "first": 32,
    "last": 40,
    "path": "tests/fixtures/dynamic_attach_windows.rs"
  }
]
```

- matrix:

```json
{
  "backend": "windows-gum",
  "origin": "attach"
}
```

- automation / reproduction:

```json
{
  "argv": [
    "python",
    "scripts/test-dynamic-attach-windows.py",
    "--hyperhub",
    "target/release/hyperhub.exe",
    "--origin",
    "attach",
    "--cycles",
    "3",
    "--output",
    "target/benchmarks/windows-native"
  ],
  "artifact_paths": [
    "scripts/test-dynamic-attach-windows.py",
    "scripts/windows_conpty.py",
    "tests/fixtures/dynamic_attach_legacy_marker.rs",
    "tests/fixtures/dynamic_attach_windows.rs"
  ],
  "cwd": "."
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-recovery"></a>

### C\-recovery Serve and manager loss preserve allowed business activity and report enforcement loss\. Fresh approved recovery reconnects compatible residue or safely seizes an untraced target; never stack injection\.

- id: C\-recovery
- title: Serve and manager loss preserve allowed business activity and report enforcement loss\. Fresh approved recovery reconnects compatible residue or safely seizes an untraced target; never stack injection\.
- kind: correctness
- implementation_status: planned
- origin: generated
- goal: Serve and manager loss preserve allowed business activity and report enforcement loss\. Fresh approved recovery reconnects compatible residue or safely seizes an untraced target; never stack injection\.
- obligation_ids: O\-recovery
- boundary_ids: B\-recovery\-committed\-cleanup\-protocol, B\-recovery\-deadroot\-cleanup\-linux\-gum, B\-recovery\-deadroot\-cleanup\-linux\-ptrace, B\-recovery\-deadroot\-cleanup\-windows, B\-recovery\-dirty\-ptrace\-refusal, B\-recovery\-manager\-linux\-gum, B\-recovery\-manager\-linux\-ptrace, B\-recovery\-manager\-windows, B\-recovery\-serve\-linux\-gum, B\-recovery\-serve\-linux\-ptrace, B\-recovery\-serve\-windows, B\-recovery\-tighten\-before\-reactivate
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Private local fixtures with fictional credentials; execute every named backend\-specific boundary separately\. This aggregate remains planned while any sub\-boundary lacks an implemented oracle\.
- steps:
  1. Trigger the stated lifecycle boundary under a private instance\.
  2. Check external target semantics and authenticated durable state independently\.
  3. Retain failure evidence and return a nonzero exit status on assertion failure\.
- oracle.method: External target payload, OS process/module identity, terminal state and signed operation status\.
- oracle.assertion: Serve and manager loss preserve allowed business activity and report enforcement loss\. Fresh approved recovery reconnects compatible residue or safely seizes an untraced target; never stack injection\.
- oracle.independence: Target assertions use observable results and OS state rather than accepting the manager ACK as proof\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "After completed revocation plus ACK loss and manager death, fresh approved Detach may perform exact historical-receipt cleanup without creating members; wrong identity/token/target and Attach are denied.",
    "assertion_refs": [],
    "boundary_id": "B-recovery-committed-cleanup-protocol",
    "id": "V-recovery-committed-cleanup-protocol",
    "obligation_id": "O-recovery",
    "trigger": "After completed revocation plus ACK loss and manager death, fresh approved Detach may perform exact historical-receipt cleanup without creating members; wrong identity/token/target and Attach are denied.",
    "trigger_refs": []
  },
  {
    "assertion": "After original root and manager exit, approve cleanup by id and reconnect/detach exact live Gum descendants without injection.",
    "assertion_refs": [],
    "boundary_id": "B-recovery-deadroot-cleanup-linux-gum",
    "id": "V-recovery-deadroot-cleanup-linux-gum",
    "obligation_id": "O-recovery",
    "trigger": "After original root and manager exit, approve cleanup by id and reconnect/detach exact live Gum descendants without injection.",
    "trigger_refs": []
  },
  {
    "assertion": "After original root and manager exit, approve cleanup by id and detach live ptrace descendants without requiring dead-root inspection.",
    "assertion_refs": [],
    "boundary_id": "B-recovery-deadroot-cleanup-linux-ptrace",
    "id": "V-recovery-deadroot-cleanup-linux-ptrace",
    "obligation_id": "O-recovery",
    "trigger": "After original root and manager exit, approve cleanup by id and detach live ptrace descendants without requiring dead-root inspection.",
    "trigger_refs": []
  },
  {
    "assertion": "After original root and manager exit, approve cleanup by id and detach exact live Windows descendants.",
    "assertion_refs": [],
    "boundary_id": "B-recovery-deadroot-cleanup-windows",
    "id": "V-recovery-deadroot-cleanup-windows",
    "obligation_id": "O-recovery",
    "trigger": "After original root and manager exit, approve cleanup by id and detach exact live Windows descendants.",
    "trigger_refs": []
  },
  {
    "assertion": "After ptrace manager loss with unproven virtual descriptor state, refuse unsafe recovery explicitly, keep target alive and do not silently seize or claim protection.",
    "assertion_refs": [],
    "boundary_id": "B-recovery-dirty-ptrace-refusal",
    "id": "V-recovery-dirty-ptrace-refusal",
    "obligation_id": "O-recovery",
    "trigger": "After ptrace manager loss with unproven virtual descriptor state, refuse unsafe recovery explicitly, keep target alive and do not silently seize or claim protection.",
    "trigger_refs": []
  },
  {
    "assertion": "Kill only the disposable Gum manager, prove target/allowed traffic survives; fresh approval reconnects exact compatible Host with no new injection.",
    "assertion_refs": [],
    "boundary_id": "B-recovery-manager-linux-gum",
    "id": "V-recovery-manager-linux-gum",
    "obligation_id": "O-recovery",
    "trigger": "Kill only the disposable Gum manager, prove target/allowed traffic survives; fresh approval reconnects exact compatible Host with no new injection.",
    "trigger_refs": []
  },
  {
    "assertion": "Kill only the disposable authenticated ptrace manager, prove target survives and enforcement loss is truthful; fresh approval safely reseizes with no duplicate tracer.",
    "assertion_refs": [],
    "boundary_id": "B-recovery-manager-linux-ptrace",
    "id": "V-recovery-manager-linux-ptrace",
    "obligation_id": "O-recovery",
    "trigger": "Kill only the disposable authenticated ptrace manager, prove target survives and enforcement loss is truthful; fresh approval safely reseizes with no duplicate tracer.",
    "trigger_refs": []
  },
  {
    "assertion": "Kill only the authenticated disposable Windows manager; fresh approval reconnects exact resident Host and one native module.",
    "assertion_refs": [],
    "boundary_id": "B-recovery-manager-windows",
    "id": "V-recovery-manager-windows",
    "obligation_id": "O-recovery",
    "trigger": "Kill only the authenticated disposable Windows manager; fresh approval reconnects exact resident Host and one native module.",
    "trigger_refs": []
  },
  {
    "assertion": "Restart/lose Serve during active Gum tree; cached policy, allowed streams and subsequent approved lifecycle remain valid.",
    "assertion_refs": [],
    "boundary_id": "B-recovery-serve-linux-gum",
    "id": "V-recovery-serve-linux-gum",
    "obligation_id": "O-recovery",
    "trigger": "Restart/lose Serve during active Gum tree; cached policy, allowed streams and subsequent approved lifecycle remain valid.",
    "trigger_refs": []
  },
  {
    "assertion": "Restart/lose Serve during active ptrace tree; cached policy, allowed streams and subsequent approved lifecycle remain valid.",
    "assertion_refs": [],
    "boundary_id": "B-recovery-serve-linux-ptrace",
    "id": "V-recovery-serve-linux-ptrace",
    "obligation_id": "O-recovery",
    "trigger": "Restart/lose Serve during active ptrace tree; cached policy, allowed streams and subsequent approved lifecycle remain valid.",
    "trigger_refs": []
  },
  {
    "assertion": "Restart/lose Serve during active Windows tree; cached policy, allowed streams and subsequent approved lifecycle remain valid.",
    "assertion_refs": [],
    "boundary_id": "B-recovery-serve-windows",
    "id": "V-recovery-serve-windows",
    "obligation_id": "O-recovery",
    "trigger": "Restart/lose Serve during active Windows tree; cached policy, allowed streams and subsequent approved lifecycle remain valid.",
    "trigger_refs": []
  },
  {
    "assertion": "Tighten a real deny policy while detached; the first covered operation after fresh approved reactivation must use the new policy synchronously.",
    "assertion_refs": [],
    "boundary_id": "B-recovery-tighten-before-reactivate",
    "id": "V-recovery-tighten-before-reactivate",
    "obligation_id": "O-recovery",
    "trigger": "Tighten a real deny policy while detached; the first covered operation after fresh approved reactivation must use the new policy synchronously.",
    "trigger_refs": []
  }
]
```

- code_references:

```json
[
  {
    "first": 1,
    "last": 31,
    "path": "crates/hyperhub-core/src/attachments/manager.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  }
]
```

- matrix:

```json
{}
```

- automation / reproduction:

尚无已实现入口；设计可审查，执行就绪另行判定。

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-release"></a>

### C\-release Isolate development binaries, Home, Skill and updates\. Explicit prerelease tags do not replace stable defaults\. Publish only after exact\-commit platform CI and soak success\.

- id: C\-release
- title: Isolate development binaries, Home, Skill and updates\. Explicit prerelease tags do not replace stable defaults\. Publish only after exact\-commit platform CI and soak success\.
- kind: correctness
- implementation_status: planned
- origin: generated
- goal: Isolate development binaries, Home, Skill and updates\. Explicit prerelease tags do not replace stable defaults\. Publish only after exact\-commit platform CI and soak success\.
- obligation_ids: O\-release
- boundary_ids: B\-release\-linux\-install, B\-release\-private\-cli, B\-release\-public\-artifacts, B\-release\-windows\-install
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Private local fixtures with fictional credentials; execute every named backend\-specific boundary separately\. This aggregate remains planned while any sub\-boundary lacks an implemented oracle\.
- steps:
  1. Trigger the stated lifecycle boundary under a private instance\.
  2. Check external target semantics and authenticated durable state independently\.
  3. Retain failure evidence and return a nonzero exit status on assertion failure\.
- oracle.method: External target payload, OS process/module identity, terminal state and signed operation status\.
- oracle.assertion: Isolate development binaries, Home, Skill and updates\. Explicit prerelease tags do not replace stable defaults\. Publish only after exact\-commit platform CI and soak success\.
- oracle.independence: Target assertions use observable results and OS state rather than accepting the manager ACK as proof\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Linux explicit-tag installer preserves stable sentinel and shortcut and uses development version directory.",
    "assertion_refs": [],
    "boundary_id": "B-release-linux-install",
    "id": "V-release-linux-install",
    "obligation_id": "O-release",
    "trigger": "Linux explicit-tag installer preserves stable sentinel and shortcut and uses development version directory.",
    "trigger_refs": []
  },
  {
    "assertion": "Built prerelease CLI selects private default HOME/Skill and manual updates without touching stable paths.",
    "assertion_refs": [],
    "boundary_id": "B-release-private-cli",
    "id": "V-release-private-cli",
    "obligation_id": "O-release",
    "trigger": "Built prerelease CLI selects private default HOME/Skill and manual updates without touching stable paths.",
    "trigger_refs": []
  },
  {
    "assertion": "Exact commit native platform CI and full soak pass; published prerelease is not latest; download all six artifacts and verify manifest/version/architecture/SHA and real operations.",
    "assertion_refs": [],
    "boundary_id": "B-release-public-artifacts",
    "id": "V-release-public-artifacts",
    "obligation_id": "O-release",
    "trigger": "Exact commit native platform CI and full soak pass; published prerelease is not latest; download all six artifacts and verify manifest/version/architecture/SHA and real operations.",
    "trigger_refs": []
  },
  {
    "assertion": "Windows explicit-tag installer preserves stable executable, shortcut and user PATH.",
    "assertion_refs": [],
    "boundary_id": "B-release-windows-install",
    "id": "V-release-windows-install",
    "obligation_id": "O-release",
    "trigger": "Windows explicit-tag installer preserves stable executable, shortcut and user PATH.",
    "trigger_refs": []
  }
]
```

- code_references:

```json
[
  {
    "first": 1,
    "last": 80,
    "path": ".github/workflows/release.yml"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  }
]
```

- matrix:

```json
{}
```

- automation / reproduction:

尚无已实现入口；设计可审查，执行就绪另行判定。

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-resources"></a>

### C\-resources At least 100 cycles and two hours of mixed activity per backend preserve semantics without continued native module, thread, FD or handle count growth after warmup\.

- id: C\-resources
- title: At least 100 cycles and two hours of mixed activity per backend preserve semantics without continued native module, thread, FD or handle count growth after warmup\.
- kind: correctness
- implementation_status: planned
- origin: generated
- goal: At least 100 cycles and two hours of mixed activity per backend preserve semantics without continued native module, thread, FD or handle count growth after warmup\.
- obligation_ids: O\-resources
- boundary_ids: B\-resources\-linux\-gum, B\-resources\-linux\-ptrace, B\-resources\-windows\-gum
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Private local fixtures with fictional credentials; execute every named backend\-specific boundary separately\. This aggregate remains planned while any sub\-boundary lacks an implemented oracle\.
- steps:
  1. Trigger the stated lifecycle boundary under a private instance\.
  2. Check external target semantics and authenticated durable state independently\.
  3. Retain failure evidence and return a nonzero exit status on assertion failure\.
- oracle.method: External target payload, OS process/module identity, terminal state and signed operation status\.
- oracle.assertion: At least 100 cycles and two hours of mixed activity per backend preserve semantics without continued native module, thread, FD or handle count growth after warmup\.
- oracle.independence: Target assertions use observable results and OS state rather than accepting the manager ACK as proof\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Complete >=100 successful cycles AND >=7200 seconds of target mixed activity after readiness on linux-gum; after warmup track native modules, threads and FDs/handles without continued growth.",
    "assertion_refs": [],
    "boundary_id": "B-resources-linux-gum",
    "id": "V-resources-linux-gum",
    "obligation_id": "O-resources",
    "trigger": "Complete >=100 successful cycles AND >=7200 seconds of target mixed activity after readiness on linux-gum; after warmup track native modules, threads and FDs/handles without continued growth.",
    "trigger_refs": []
  },
  {
    "assertion": "Complete >=100 successful cycles AND >=7200 seconds of target mixed activity after readiness on linux-ptrace; after warmup track native modules, threads and FDs/handles without continued growth.",
    "assertion_refs": [],
    "boundary_id": "B-resources-linux-ptrace",
    "id": "V-resources-linux-ptrace",
    "obligation_id": "O-resources",
    "trigger": "Complete >=100 successful cycles AND >=7200 seconds of target mixed activity after readiness on linux-ptrace; after warmup track native modules, threads and FDs/handles without continued growth.",
    "trigger_refs": []
  },
  {
    "assertion": "Complete >=100 successful cycles AND >=7200 seconds of target mixed activity after readiness on windows-gum; after warmup track native modules, threads and FDs/handles without continued growth.",
    "assertion_refs": [],
    "boundary_id": "B-resources-windows-gum",
    "id": "V-resources-windows-gum",
    "obligation_id": "O-resources",
    "trigger": "Complete >=100 successful cycles AND >=7200 seconds of target mixed activity after readiness on windows-gum; after warmup track native modules, threads and FDs/handles without continued growth.",
    "trigger_refs": []
  }
]
```

- code_references:

```json
[
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 1,
    "last": 80,
    "path": "scripts/test-dynamic-attach.py"
  }
]
```

- matrix:

```json
{}
```

- automation / reproduction:

尚无已实现入口；设计可审查，执行就绪另行判定。

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-rootexit-linux-gum"></a>

### C\-rootexit\-linux\-gum Owned Linux gum root exits while survivor stays managed

- id: C\-rootexit\-linux\-gum
- title: Owned Linux gum root exits while survivor stays managed
- kind: correctness
- implementation_status: implemented
- origin: existing
- goal: Tree scope covers current threads, existing descendants and future descendants; process scope leaves other processes unmanaged\. Living descendants remain managed after root exit\.
- obligation_ids: O\-tree
- boundary_ids: B\-tree\-rootexit\-linux\-gum
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Tree owned\-run; survivor retains fixture protocol and private policy\.
- steps:
  1. Run root\-exit fixture with an already active tree\.
  2. Wait original foreground status then read and detach surviving child by original attachment id\.
- oracle.method: Review and execute the cited native fixture or Rust test assertions; inspect matching raw outputs and actual OS identities\.
- oracle.assertion: Every cited per\-boundary assertion must run and pass; a top\-level success or manager ACK does not substitute for a missing assertion\.
- oracle.independence: Native results and OS enumeration are independent of lifecycle ACKs; cryptographic mutation units test explicit rejected inputs but do not replace end\-to\-end authorization tests\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Foreground returns 37 within ten seconds, survivor file read still denied, survivor accepts approved detach and explicit exit.",
    "assertion_refs": [
      {
        "first": 568,
        "last": 576,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 629,
        "last": 639,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-tree-rootexit-linux-gum",
    "id": "V-1",
    "obligation_id": "O-tree",
    "trigger": "Owned run forks the command-serving survivor and original root exits.",
    "trigger_refs": [
      {
        "first": 568,
        "last": 576,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 629,
        "last": 639,
        "path": "scripts/test-dynamic-attach.py"
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
    "last": 80,
    "path": "crates/hyperhub-agent-core/src/attachment.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 568,
    "last": 576,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 629,
    "last": 639,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 173,
    "last": 186,
    "path": "tests/fixtures/dynamic_attach_target.c"
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
    "python3",
    "scripts/test-dynamic-attach.py",
    "--hyperhub",
    "target/release/hyperhub",
    "--backend",
    "gum",
    "--origin",
    "run",
    "--root-exit",
    "--target-pty",
    "--cycles",
    "1",
    "--output",
    "target/benchmarks/rootexit-gum"
  ],
  "artifact_paths": [
    "scripts/test-dynamic-attach.py",
    "tests/fixtures/dynamic_attach_target.c"
  ],
  "cwd": "."
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-rootexit-linux-ptrace"></a>

### C\-rootexit\-linux\-ptrace Owned Linux ptrace root exits while survivor stays managed

- id: C\-rootexit\-linux\-ptrace
- title: Owned Linux ptrace root exits while survivor stays managed
- kind: correctness
- implementation_status: implemented
- origin: existing
- goal: Tree scope covers current threads, existing descendants and future descendants; process scope leaves other processes unmanaged\. Living descendants remain managed after root exit\.
- obligation_ids: O\-tree
- boundary_ids: B\-tree\-rootexit\-linux\-ptrace
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Tree owned\-run; survivor retains fixture protocol and private policy\.
- steps:
  1. Run root\-exit fixture with an already active tree\.
  2. Wait original foreground status then read and detach surviving child by original attachment id\.
- oracle.method: Review and execute the cited native fixture or Rust test assertions; inspect matching raw outputs and actual OS identities\.
- oracle.assertion: Every cited per\-boundary assertion must run and pass; a top\-level success or manager ACK does not substitute for a missing assertion\.
- oracle.independence: Native results and OS enumeration are independent of lifecycle ACKs; cryptographic mutation units test explicit rejected inputs but do not replace end\-to\-end authorization tests\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Foreground returns 37 within ten seconds, survivor file read still denied, survivor accepts approved detach and explicit exit.",
    "assertion_refs": [
      {
        "first": 568,
        "last": 576,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 629,
        "last": 639,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-tree-rootexit-linux-ptrace",
    "id": "V-1",
    "obligation_id": "O-tree",
    "trigger": "Owned run forks the command-serving survivor and original root exits.",
    "trigger_refs": [
      {
        "first": 568,
        "last": 576,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 629,
        "last": 639,
        "path": "scripts/test-dynamic-attach.py"
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
    "last": 80,
    "path": "crates/hyperhub-agent-core/src/attachment.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 568,
    "last": 576,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 629,
    "last": 639,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 173,
    "last": 186,
    "path": "tests/fixtures/dynamic_attach_target.c"
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
    "python3",
    "scripts/test-dynamic-attach.py",
    "--hyperhub",
    "target/release/hyperhub",
    "--backend",
    "ptrace",
    "--origin",
    "run",
    "--root-exit",
    "--target-pty",
    "--cycles",
    "1",
    "--output",
    "target/benchmarks/rootexit-ptrace"
  ],
  "artifact_paths": [
    "scripts/test-dynamic-attach.py",
    "tests/fixtures/dynamic_attach_target.c"
  ],
  "cwd": "."
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-serve-restart-linux-gum"></a>

### C\-serve\-restart\-linux\-gum Direct old stream survives; deny remains and original attachment session id is preserved\.

- id: C\-serve\-restart\-linux\-gum
- title: Direct old stream survives; deny remains and original attachment session id is preserved\.
- kind: correctness
- implementation_status: implemented
- origin: existing
- goal: Serve and manager loss preserve allowed business activity and report enforcement loss\. Fresh approved recovery reconnects compatible residue or safely seizes an untraced target; never stack injection\.
- obligation_ids: O\-recovery
- boundary_ids: B\-recovery\-serve\-linux\-gum
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: While Active retain pre\-attach direct TCP, restart the private Serve, then continue lifecycle\.
- steps:
  1. Execute the isolated native driver command using a built embedded candidate\.
  2. Require the cited fault/continuity/native\-policy oracle and preserve any nonzero failure\.
  3. Product failures remain failures; implemented status only records the real fixture/assertion path\.
- oracle.method: Native fixture replies, pidfd/process incarnation, OS tracer state, native TCP echo and actual post\-fault lifecycle\.
- oracle.assertion: Direct old stream survives; deny remains and original attachment session id is preserved\.
- oracle.independence: Policy results, byte echoes and OS state are observed outside manager ACKs; no formal run is synthesized\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Direct old stream survives; deny remains and original attachment session id is preserved.",
    "assertion_refs": [
      {
        "first": 519,
        "last": 528,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-recovery-serve-linux-gum",
    "id": "V-recovery-serve-linux-gum",
    "obligation_id": "O-recovery",
    "trigger": "While Active retain pre-attach direct TCP, restart the private Serve, then continue lifecycle.",
    "trigger_refs": [
      {
        "first": 519,
        "last": 528,
        "path": "scripts/test-dynamic-attach.py"
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
    "last": 31,
    "path": "crates/hyperhub-core/src/attachments/manager.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 519,
    "last": 528,
    "path": "scripts/test-dynamic-attach.py"
  }
]
```

- matrix:

```json
{
  "backend": "linux-gum",
  "origin": "attach"
}
```

- automation / reproduction:

```json
{
  "argv": [
    "python3",
    "scripts/test-dynamic-attach.py",
    "--hyperhub",
    "target/release/hyperhub",
    "--backend",
    "gum",
    "--serve-restart",
    "--cycles",
    "1",
    "--output",
    "target/benchmarks/C-serve-restart-linux-gum"
  ],
  "artifact_paths": [
    "scripts/test-dynamic-attach.py",
    "tests/fixtures/dynamic_attach_legacy_marker.rs",
    "tests/fixtures/dynamic_attach_target.c"
  ],
  "cwd": "."
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-serve-restart-linux-ptrace"></a>

### C\-serve\-restart\-linux\-ptrace Direct old stream survives; deny remains and original attachment session id is preserved\.

- id: C\-serve\-restart\-linux\-ptrace
- title: Direct old stream survives; deny remains and original attachment session id is preserved\.
- kind: correctness
- implementation_status: implemented
- origin: existing
- goal: Serve and manager loss preserve allowed business activity and report enforcement loss\. Fresh approved recovery reconnects compatible residue or safely seizes an untraced target; never stack injection\.
- obligation_ids: O\-recovery
- boundary_ids: B\-recovery\-serve\-linux\-ptrace
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: While Active retain pre\-attach direct TCP, restart the private Serve, then continue lifecycle\.
- steps:
  1. Execute the isolated native driver command using a built embedded candidate\.
  2. Require the cited fault/continuity/native\-policy oracle and preserve any nonzero failure\.
  3. Product failures remain failures; implemented status only records the real fixture/assertion path\.
- oracle.method: Native fixture replies, pidfd/process incarnation, OS tracer state, native TCP echo and actual post\-fault lifecycle\.
- oracle.assertion: Direct old stream survives; deny remains and original attachment session id is preserved\.
- oracle.independence: Policy results, byte echoes and OS state are observed outside manager ACKs; no formal run is synthesized\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Direct old stream survives; deny remains and original attachment session id is preserved.",
    "assertion_refs": [
      {
        "first": 519,
        "last": 528,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-recovery-serve-linux-ptrace",
    "id": "V-recovery-serve-linux-ptrace",
    "obligation_id": "O-recovery",
    "trigger": "While Active retain pre-attach direct TCP, restart the private Serve, then continue lifecycle.",
    "trigger_refs": [
      {
        "first": 519,
        "last": 528,
        "path": "scripts/test-dynamic-attach.py"
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
    "last": 31,
    "path": "crates/hyperhub-core/src/attachments/manager.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 519,
    "last": 528,
    "path": "scripts/test-dynamic-attach.py"
  }
]
```

- matrix:

```json
{
  "backend": "linux-ptrace",
  "origin": "attach"
}
```

- automation / reproduction:

```json
{
  "argv": [
    "python3",
    "scripts/test-dynamic-attach.py",
    "--hyperhub",
    "target/release/hyperhub",
    "--backend",
    "ptrace",
    "--serve-restart",
    "--cycles",
    "1",
    "--output",
    "target/benchmarks/C-serve-restart-linux-ptrace"
  ],
  "artifact_paths": [
    "scripts/test-dynamic-attach.py",
    "tests/fixtures/dynamic_attach_legacy_marker.rs",
    "tests/fixtures/dynamic_attach_target.c"
  ],
  "cwd": "."
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-soak-linux-gum"></a>

### C\-soak\-linux\-gum At least100 successful cycles and7200 post\-setup seconds; every checked payload is valid and FD/thread/executable\-map counts do not exceed the cycle\-two warmup baseline\.

- id: C\-soak\-linux\-gum
- title: At least100 successful cycles and7200 post\-setup seconds; every checked payload is valid and FD/thread/executable\-map counts do not exceed the cycle\-two warmup baseline\.
- kind: correctness
- implementation_status: implemented
- origin: existing
- goal: At least 100 cycles and two hours of mixed activity per backend preserve semantics without continued native module, thread, FD or handle count growth after warmup\.
- obligation_ids: O\-resources
- boundary_ids: B\-resources\-linux\-gum
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Disposable native target under &gt;=100 complete lifecycle cycles and &gt;=7200 seconds measured from post\-setup target readiness\. No completed run is declared here\.
- steps:
  1. Execute the exact native driver command with cycles100/duration7200\.
  2. Require the loop to complete both requested minima, valid mixed I/O checks and post\-warmup resource assertions\.
  3. Keep every native failure, resource sample and actual elapsed timestamp; do not count an incomplete or failed attempt as a completed soak\.
- oracle.method: Review and execute the cited native fixture or Rust test assertions; inspect matching raw outputs and actual OS identities\.
- oracle.assertion: Every cited per\-boundary assertion must run and pass; a top\-level success or manager ACK does not substitute for a missing assertion\.
- oracle.independence: Native results and OS enumeration are independent of lifecycle ACKs; cryptographic mutation units test explicit rejected inputs but do not replace end\-to\-end authorization tests\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "At least100 successful cycles and7200 post-setup seconds; every checked payload is valid and FD/thread/executable-map counts do not exceed the cycle-two warmup baseline.",
    "assertion_refs": [
      {
        "first": 448,
        "last": 460,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 482,
        "last": 484,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 617,
        "last": 641,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 309,
        "last": 327,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-resources-linux-gum",
    "id": "V-resources-linux-gum",
    "obligation_id": "O-resources",
    "trigger": "After setup/readiness, complete both the cycle counter and elapsed target-activity loop while issuing snapshot/socket/read/new-socket operations.",
    "trigger_refs": [
      {
        "first": 448,
        "last": 460,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 482,
        "last": 484,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 617,
        "last": 641,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 309,
        "last": 327,
        "path": "scripts/test-dynamic-attach.py"
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
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 1,
    "last": 80,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 309,
    "last": 327,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 448,
    "last": 460,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 482,
    "last": 484,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 617,
    "last": 641,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 124,
    "last": 146,
    "path": "tests/fixtures/dynamic_attach_target.c"
  }
]
```

- matrix:

```json
{
  "backend": "linux-gum",
  "origin": "attach"
}
```

- automation / reproduction:

```json
{
  "argv": [
    "python3",
    "scripts/test-dynamic-attach.py",
    "--hyperhub",
    "target/release/hyperhub",
    "--backend",
    "gum",
    "--origin",
    "attach",
    "--target-pty",
    "--cycles",
    "100",
    "--duration",
    "7200",
    "--output",
    "target/benchmarks/soak-linux-gum"
  ],
  "artifact_paths": [
    "scripts/test-dynamic-attach.py",
    "tests/fixtures/dynamic_attach_target.c"
  ],
  "cwd": "."
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-soak-linux-ptrace"></a>

### C\-soak\-linux\-ptrace At least100 successful cycles and7200 post\-setup seconds; every checked payload is valid and FD/thread/executable\-map counts do not exceed the cycle\-two warmup baseline\.

- id: C\-soak\-linux\-ptrace
- title: At least100 successful cycles and7200 post\-setup seconds; every checked payload is valid and FD/thread/executable\-map counts do not exceed the cycle\-two warmup baseline\.
- kind: correctness
- implementation_status: implemented
- origin: existing
- goal: At least 100 cycles and two hours of mixed activity per backend preserve semantics without continued native module, thread, FD or handle count growth after warmup\.
- obligation_ids: O\-resources
- boundary_ids: B\-resources\-linux\-ptrace
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Disposable native target under &gt;=100 complete lifecycle cycles and &gt;=7200 seconds measured from post\-setup target readiness\. No completed run is declared here\.
- steps:
  1. Execute the exact native driver command with cycles100/duration7200\.
  2. Require the loop to complete both requested minima, valid mixed I/O checks and post\-warmup resource assertions\.
  3. Keep every native failure, resource sample and actual elapsed timestamp; do not count an incomplete or failed attempt as a completed soak\.
- oracle.method: Review and execute the cited native fixture or Rust test assertions; inspect matching raw outputs and actual OS identities\.
- oracle.assertion: Every cited per\-boundary assertion must run and pass; a top\-level success or manager ACK does not substitute for a missing assertion\.
- oracle.independence: Native results and OS enumeration are independent of lifecycle ACKs; cryptographic mutation units test explicit rejected inputs but do not replace end\-to\-end authorization tests\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "At least100 successful cycles and7200 post-setup seconds; every checked payload is valid and FD/thread/executable-map counts do not exceed the cycle-two warmup baseline.",
    "assertion_refs": [
      {
        "first": 448,
        "last": 460,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 482,
        "last": 484,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 617,
        "last": 641,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 309,
        "last": 327,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-resources-linux-ptrace",
    "id": "V-resources-linux-ptrace",
    "obligation_id": "O-resources",
    "trigger": "After setup/readiness, complete both the cycle counter and elapsed target-activity loop while issuing snapshot/socket/read/new-socket operations.",
    "trigger_refs": [
      {
        "first": 448,
        "last": 460,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 482,
        "last": 484,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 617,
        "last": 641,
        "path": "scripts/test-dynamic-attach.py"
      },
      {
        "first": 309,
        "last": 327,
        "path": "scripts/test-dynamic-attach.py"
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
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 1,
    "last": 80,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 309,
    "last": 327,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 448,
    "last": 460,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 482,
    "last": 484,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 617,
    "last": 641,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 124,
    "last": 146,
    "path": "tests/fixtures/dynamic_attach_target.c"
  }
]
```

- matrix:

```json
{
  "backend": "linux-ptrace",
  "origin": "attach"
}
```

- automation / reproduction:

```json
{
  "argv": [
    "python3",
    "scripts/test-dynamic-attach.py",
    "--hyperhub",
    "target/release/hyperhub",
    "--backend",
    "ptrace",
    "--origin",
    "attach",
    "--target-pty",
    "--cycles",
    "100",
    "--duration",
    "7200",
    "--output",
    "target/benchmarks/soak-linux-ptrace"
  ],
  "artifact_paths": [
    "scripts/test-dynamic-attach.py",
    "tests/fixtures/dynamic_attach_target.c"
  ],
  "cwd": "."
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-soak-windows-gum"></a>

### C\-soak\-windows\-gum At least100 successful cycles and7200 post\-setup seconds; no native load/TCP or resource\-sampling error; every post\-warmup logical detach remains within documented handle\+8/thread\+1 bounded slack and eligible modules are absent\.

- id: C\-soak\-windows\-gum
- title: At least100 successful cycles and7200 post\-setup seconds; no native load/TCP or resource\-sampling error; every post\-warmup logical detach remains within documented handle\+8/thread\+1 bounded slack and eligible modules are absent\.
- kind: correctness
- implementation_status: implemented
- origin: existing
- goal: At least 100 cycles and two hours of mixed activity per backend preserve semantics without continued native module, thread, FD or handle count growth after warmup\.
- obligation_ids: O\-resources
- boundary_ids: B\-resources\-windows\-gum
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Disposable native target under &gt;=100 complete lifecycle cycles and &gt;=7200 seconds measured from post\-setup target readiness\. No completed run is declared here\.
- steps:
  1. Execute the exact native driver command with cycles100/duration7200\.
  2. Require the loop to complete both requested minima, valid mixed I/O checks and post\-warmup resource assertions\.
  3. Keep every native failure, resource sample and actual elapsed timestamp; do not count an incomplete or failed attempt as a completed soak\.
- oracle.method: Review and execute the cited native fixture or Rust test assertions; inspect matching raw outputs and actual OS identities\.
- oracle.assertion: Every cited per\-boundary assertion must run and pass; a top\-level success or manager ACK does not substitute for a missing assertion\.
- oracle.independence: Native results and OS enumeration are independent of lifecycle ACKs; cryptographic mutation units test explicit rejected inputs but do not replace end\-to\-end authorization tests\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "At least100 successful cycles and7200 post-setup seconds; no native load/TCP or resource-sampling error; every post-warmup logical detach remains within documented handle+8/thread+1 bounded slack and eligible modules are absent.",
    "assertion_refs": [
      {
        "first": 347,
        "last": 348,
        "path": "scripts/test-dynamic-attach-windows.py"
      },
      {
        "first": 459,
        "last": 479,
        "path": "scripts/test-dynamic-attach-windows.py"
      },
      {
        "first": 63,
        "last": 106,
        "path": "scripts/test-dynamic-attach-windows.py"
      }
    ],
    "boundary_id": "B-resources-windows-gum",
    "id": "V-resources-windows-gum",
    "obligation_id": "O-resources",
    "trigger": "After native target readiness, sample OS handle/thread/memory counts each0.5s while fixture mixed file/TCP load continues; iterate both requested cycle/time minima.",
    "trigger_refs": [
      {
        "first": 347,
        "last": 348,
        "path": "scripts/test-dynamic-attach-windows.py"
      },
      {
        "first": 459,
        "last": 479,
        "path": "scripts/test-dynamic-attach-windows.py"
      },
      {
        "first": 63,
        "last": 106,
        "path": "scripts/test-dynamic-attach-windows.py"
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
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 63,
    "last": 106,
    "path": "scripts/test-dynamic-attach-windows.py"
  },
  {
    "first": 347,
    "last": 348,
    "path": "scripts/test-dynamic-attach-windows.py"
  },
  {
    "first": 459,
    "last": 479,
    "path": "scripts/test-dynamic-attach-windows.py"
  },
  {
    "first": 1,
    "last": 80,
    "path": "scripts/test-dynamic-attach.py"
  }
]
```

- matrix:

```json
{
  "backend": "windows-gum",
  "origin": "attach"
}
```

- automation / reproduction:

```json
{
  "argv": [
    "python",
    "scripts/test-dynamic-attach-windows.py",
    "--hyperhub",
    "target/release/hyperhub.exe",
    "--origin",
    "attach",
    "--cycles",
    "100",
    "--duration",
    "7200",
    "--output",
    "target/benchmarks/soak-windows-gum"
  ],
  "artifact_paths": [
    "scripts/test-dynamic-attach-windows.py",
    "scripts/windows_conpty.py",
    "tests/fixtures/dynamic_attach_legacy_marker.rs",
    "tests/fixtures/dynamic_attach_windows.rs"
  ],
  "cwd": "."
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-terminal-slot-race"></a>

### C\-terminal\-slot\-race A Draining/resident slot that becomes terminal during human review receives fresh request/attachment/session/token epochs without changing target/scope/backend/policy or repeating approval; clients follow the actual returned id\.

- id: C\-terminal\-slot\-race
- title: A Draining/resident slot that becomes terminal during human review receives fresh request/attachment/session/token epochs without changing target/scope/backend/policy or repeating approval; clients follow the actual returned id\.
- kind: correctness
- implementation_status: implemented
- origin: existing
- goal: Only fresh human approval bound to exact process incarnation, instance, scope, backend, policy and bootstrap may mutate an external target\. Proposal alone has no effect\.
- obligation_ids: O\-approval
- boundary_ids: B\-approval\-terminal\-slot\-renewal
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Advance the old durable record from Draining to Detached between review steps; retain an old receipt sentinel; request fresh ids and create a distinct session\.
- steps:
  1. Execute the exact native crate test entry\.
  2. Require named triggers and assertions; do not turn this seam test into a broader native lifecycle claim\.
- oracle.method: Explicit identity/epoch, disk sentinel, session and timing assertions\.
- oracle.assertion: A Draining/resident slot that becomes terminal during human review receives fresh request/attachment/session/token epochs without changing target/scope/backend/policy or repeating approval; clients follow the actual returned id\.
- oracle.independence: Old state/sentinel and OS IPC behavior are checked independently of the newly chosen request id or a manager ACK\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "A Draining/resident slot that becomes terminal during human review receives fresh request/attachment/session/token epochs without changing target/scope/backend/policy or repeating approval; clients follow the actual returned id.",
    "assertion_refs": [
      {
        "first": 82,
        "last": 140,
        "path": "crates/hyperhub-cli/src/attachment/terminal_replan.rs"
      },
      {
        "first": 142,
        "last": 157,
        "path": "crates/hyperhub-cli/src/attachment/terminal_replan.rs"
      }
    ],
    "boundary_id": "B-approval-terminal-slot-renewal",
    "id": "V-approval-terminal-slot-renewal",
    "obligation_id": "O-approval",
    "trigger": "Advance the old durable record from Draining to Detached between review steps; retain an old receipt sentinel; request fresh ids and create a distinct session.",
    "trigger_refs": [
      {
        "first": 82,
        "last": 140,
        "path": "crates/hyperhub-cli/src/attachment/terminal_replan.rs"
      },
      {
        "first": 142,
        "last": 157,
        "path": "crates/hyperhub-cli/src/attachment/terminal_replan.rs"
      }
    ]
  }
]
```

- code_references:

```json
[
  {
    "first": 82,
    "last": 140,
    "path": "crates/hyperhub-cli/src/attachment/terminal_replan.rs"
  },
  {
    "first": 142,
    "last": 157,
    "path": "crates/hyperhub-cli/src/attachment/terminal_replan.rs"
  },
  {
    "first": 1,
    "last": 80,
    "path": "crates/hyperhub-core/src/attachments/authority.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
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
    "test",
    "-p",
    "hyperhub",
    "terminal_replan::tests",
    "--locked"
  ],
  "artifact_paths": [
    "crates/hyperhub-cli/src/attachment/terminal_replan.rs"
  ],
  "cwd": "."
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-tree"></a>

### C\-tree Tree scope covers current threads, existing descendants and future descendants; process scope leaves other processes unmanaged\. Living descendants remain managed after root exit\.

- id: C\-tree
- title: Tree scope covers current threads, existing descendants and future descendants; process scope leaves other processes unmanaged\. Living descendants remain managed after root exit\.
- kind: correctness
- implementation_status: planned
- origin: generated
- goal: Tree scope covers current threads, existing descendants and future descendants; process scope leaves other processes unmanaged\. Living descendants remain managed after root exit\.
- obligation_ids: O\-tree
- boundary_ids: B\-tree\-detach\-epoch\-inheritance, B\-tree\-linux\-gum\-process, B\-tree\-linux\-gum\-tree, B\-tree\-linux\-ptrace\-process, B\-tree\-linux\-ptrace\-tree, B\-tree\-rootexit\-linux\-gum, B\-tree\-rootexit\-linux\-ptrace, B\-tree\-rootexit\-windows, B\-tree\-threads\-boundary, B\-tree\-windows\-creation\-boundary, B\-tree\-windows\-existing, B\-tree\-windows\-future, B\-tree\-windows\-msys\-fork
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Private local fixtures with fictional credentials; execute every named backend\-specific boundary separately\. This aggregate remains planned while any sub\-boundary lacks an implemented oracle\.
- steps:
  1. Trigger the stated lifecycle boundary under a private instance\.
  2. Check external target semantics and authenticated durable state independently\.
  3. Retain failure evidence and return a nonzero exit status on assertion failure\.
- oracle.method: External target payload, OS process/module identity, terminal state and signed operation status\.
- oracle.assertion: Tree scope covers current threads, existing descendants and future descendants; process scope leaves other processes unmanaged\. Living descendants remain managed after root exit\.
- oracle.independence: Target assertions use observable results and OS state rather than accepting the manager ACK as proof\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "fork/clone/rebuild descendants preserve the accepted detach cutoff and cannot replay an older/equal-time Attach to reactivate policy.",
    "assertion_refs": [],
    "boundary_id": "B-tree-detach-epoch-inheritance",
    "id": "V-tree-detach-epoch-inheritance",
    "obligation_id": "O-tree",
    "trigger": "fork/clone/rebuild descendants preserve the accepted detach cutoff and cannot replay an older/equal-time Attach to reactivate policy.",
    "trigger_refs": []
  },
  {
    "assertion": "Linux Gum process: deny target, permit separate existing/future descendants.",
    "assertion_refs": [],
    "boundary_id": "B-tree-linux-gum-process",
    "id": "V-tree-linux-gum-process",
    "obligation_id": "O-tree",
    "trigger": "Linux Gum process: deny target, permit separate existing/future descendants.",
    "trigger_refs": []
  },
  {
    "assertion": "Linux Gum tree: deny root and preexisting/fork/exec descendants.",
    "assertion_refs": [],
    "boundary_id": "B-tree-linux-gum-tree",
    "id": "V-tree-linux-gum-tree",
    "obligation_id": "O-tree",
    "trigger": "Linux Gum tree: deny root and preexisting/fork/exec descendants.",
    "trigger_refs": []
  },
  {
    "assertion": "Linux ptrace process: deny target, permit separate existing/future descendants.",
    "assertion_refs": [],
    "boundary_id": "B-tree-linux-ptrace-process",
    "id": "V-tree-linux-ptrace-process",
    "obligation_id": "O-tree",
    "trigger": "Linux ptrace process: deny target, permit separate existing/future descendants.",
    "trigger_refs": []
  },
  {
    "assertion": "Linux ptrace tree: deny root and preexisting/fork/exec descendants.",
    "assertion_refs": [],
    "boundary_id": "B-tree-linux-ptrace-tree",
    "id": "V-tree-linux-ptrace-tree",
    "obligation_id": "O-tree",
    "trigger": "Linux ptrace tree: deny root and preexisting/fork/exec descendants.",
    "trigger_refs": []
  },
  {
    "assertion": "Owned Linux Gum run returns root exit 37 promptly while its survivor remains managed and can be detached.",
    "assertion_refs": [],
    "boundary_id": "B-tree-rootexit-linux-gum",
    "id": "V-tree-rootexit-linux-gum",
    "obligation_id": "O-tree",
    "trigger": "Owned Linux Gum run returns root exit 37 promptly while its survivor remains managed and can be detached.",
    "trigger_refs": []
  },
  {
    "assertion": "Owned Linux ptrace run returns root exit 37 promptly while its survivor remains managed and can be detached.",
    "assertion_refs": [],
    "boundary_id": "B-tree-rootexit-linux-ptrace",
    "id": "V-tree-rootexit-linux-ptrace",
    "obligation_id": "O-tree",
    "trigger": "Owned Linux ptrace run returns root exit 37 promptly while its survivor remains managed and can be detached.",
    "trigger_refs": []
  },
  {
    "assertion": "Windows keeper preserves descendant enforcement and detach after original root exit.",
    "assertion_refs": [],
    "boundary_id": "B-tree-rootexit-windows",
    "id": "V-tree-rootexit-windows",
    "obligation_id": "O-tree",
    "trigger": "Windows keeper preserves descendant enforcement and detach after original root exit.",
    "trigger_refs": []
  },
  {
    "assertion": "Already running target threads and concurrent thread creation cannot escape at attach/detach boundaries on every backend.",
    "assertion_refs": [],
    "boundary_id": "B-tree-threads-boundary",
    "id": "V-tree-threads-boundary",
    "obligation_id": "O-tree",
    "trigger": "Already running target threads and concurrent thread creation cannot escape at attach/detach boundaries on every backend.",
    "trigger_refs": []
  },
  {
    "assertion": "Measure children alive or in-flight across the actual Windows commit boundary; no reset may hide post-commit allowed work.",
    "assertion_refs": [],
    "boundary_id": "B-tree-windows-creation-boundary",
    "id": "V-tree-windows-creation-boundary",
    "obligation_id": "O-tree",
    "trigger": "Measure children alive or in-flight across the actual Windows commit boundary; no reset may hide post-commit allowed work.",
    "trigger_refs": []
  },
  {
    "assertion": "Hold a deterministic existing child alive before Windows attach; it must be denied after tree commit.",
    "assertion_refs": [],
    "boundary_id": "B-tree-windows-existing",
    "id": "V-tree-windows-existing",
    "obligation_id": "O-tree",
    "trigger": "Hold a deterministic existing child alive before Windows attach; it must be denied after tree commit.",
    "trigger_refs": []
  },
  {
    "assertion": "Windows approved tree denies post-commit child exec and at least ten fresh native child reads.",
    "assertion_refs": [],
    "boundary_id": "B-tree-windows-future",
    "id": "V-tree-windows-future",
    "obligation_id": "O-tree",
    "trigger": "Windows approved tree denies post-commit child exec and at least ten fresh native child reads.",
    "trigger_refs": []
  },
  {
    "assertion": "Native Windows lifecycle and approved tree cover MSYS/Cygwin fork/clone shared-memory rebuild and metadata/Host identity rebinding; native Rust exec fixtures do not cover this ABI boundary.",
    "assertion_refs": [],
    "boundary_id": "B-tree-windows-msys-fork",
    "id": "V-tree-windows-msys-fork",
    "obligation_id": "O-tree",
    "trigger": "Native Windows lifecycle and approved tree cover MSYS/Cygwin fork/clone shared-memory rebuild and metadata/Host identity rebinding; native Rust exec fixtures do not cover this ABI boundary.",
    "trigger_refs": []
  }
]
```

- code_references:

```json
[
  {
    "first": 1,
    "last": 80,
    "path": "crates/hyperhub-agent-core/src/attachment.rs"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  }
]
```

- matrix:

```json
{}
```

- automation / reproduction:

尚无已实现入口；设计可审查，执行就绪另行判定。

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-C-windows-installer-isolation"></a>

### C\-windows\-installer\-isolation Windows explicit\-tag installer preserves stable paths

- id: C\-windows\-installer\-isolation
- title: Windows explicit\-tag installer preserves stable paths
- kind: correctness
- implementation_status: implemented
- origin: existing
- goal: Isolate development binaries, Home, Skill and updates\. Explicit prerelease tags do not replace stable defaults\. Publish only after exact\-commit platform CI and soak success\.
- obligation_ids: O\-release
- boundary_ids: B\-release\-windows\-install
- preconditions: 见共用前提与场景输入；性能 preflight: 不适用
- inputs: Disposable Windows CI user; script restores process environment and user PATH in finally\.
- steps:
  1. Run native PowerShell installer regression with built prerelease CLI\.
- oracle.method: Review and execute the cited native fixture or Rust test assertions; inspect matching raw outputs and actual OS identities\.
- oracle.assertion: Every cited per\-boundary assertion must run and pass; a top\-level success or manager ACK does not substitute for a missing assertion\.
- oracle.independence: Native results and OS enumeration are independent of lifecycle ACKs; cryptographic mutation units test explicit rejected inputs but do not replace end\-to\-end authorization tests\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Installed bytes match fixture; stable hash, stable shortcut and user PATH remain unchanged.",
    "assertion_refs": [
      {
        "first": 33,
        "last": 50,
        "path": "scripts/test-development-install.ps1"
      }
    ],
    "boundary_id": "B-release-windows-install",
    "id": "V-1",
    "obligation_id": "O-release",
    "trigger": "Prepare stable sentinel, mock archive download, execute install.ps1 with explicit alpha tag.",
    "trigger_refs": [
      {
        "first": 33,
        "last": 50,
        "path": "scripts/test-development-install.ps1"
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
    "last": 80,
    "path": ".github/workflows/release.yml"
  },
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 4,
    "last": 8,
    "path": "scripts/install.ps1"
  },
  {
    "first": 33,
    "last": 50,
    "path": "scripts/test-development-install.ps1"
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
    "pwsh",
    "-NoProfile",
    "-File",
    "scripts/test-development-install.ps1",
    "-HyperHub",
    "target/release/hyperhub.exe"
  ],
  "artifact_paths": [
    "scripts/install.ps1",
    "scripts/test-development-install.ps1"
  ],
  "cwd": "."
}
```

- reported_result:

未提交执行记录；未运行／未验证。

## 性能场景

| 场景 | 标题 | 来源 | 实现状态 | 运行状态 |
|---|---|---|---|---|
| [P\-linux\-gum\-attach](#case-P-linux-gum-attach) | Validated snapshot/socket work: linux\-gum\-attach | existing | implemented | 未提交执行记录 |
| [P\-linux\-gum\-run](#case-P-linux-gum-run) | Validated snapshot/socket work: linux\-gum\-run | existing | implemented | 未提交执行记录 |
| [P\-linux\-ptrace\-attach](#case-P-linux-ptrace-attach) | Validated snapshot/socket work: linux\-ptrace\-attach | existing | implemented | 未提交执行记录 |
| [P\-linux\-ptrace\-run](#case-P-linux-ptrace-run) | Validated snapshot/socket work: linux\-ptrace\-run | existing | implemented | 未提交执行记录 |
| [P\-windows\-gum\-attach](#case-P-windows-gum-attach) | Validated snapshot/socket work: windows\-gum\-attach | generated | planned | 未提交执行记录 |
| [P\-windows\-gum\-attach\-snapshot\-latency](#case-P-windows-gum-attach-snapshot-latency) | Windows attach 50\-snapshot latency observations | existing | implemented | 未提交执行记录 |
| [P\-windows\-gum\-run](#case-P-windows-gum-run) | Validated snapshot/socket work: windows\-gum\-run | generated | planned | 未提交执行记录 |
| [P\-windows\-gum\-run\-snapshot\-latency](#case-P-windows-gum-run-snapshot-latency) | Windows run 50\-snapshot latency observations | existing | implemented | 未提交执行记录 |

<a id="case-P-linux-gum-attach"></a>

### P\-linux\-gum\-attach Validated snapshot/socket work: linux\-gum\-attach

- id: P\-linux\-gum\-attach
- title: Validated snapshot/socket work: linux\-gum\-attach
- kind: performance
- implementation_status: implemented
- origin: existing
- goal: Compare each platform declared workload within unmanaged, same\-backend run, Active and Detached phases; Linux uses 32 snapshot/socket pairs and Windows uses 50 snapshot commands\. Keep raw latency and valid\-throughput timing separate from approval duration and do not compare different workload units as one cross\-platform result\.
- obligation_ids: O\-measure
- boundary_ids: B\-measure\-linux\-gum\-attach
- preconditions: 见共用前提与场景输入；性能 preflight: C\-native\-linux\-gum\-attach
- inputs: Exactly 32 alternating snapshot/socket pairs per Linux unmanaged or run baseline, Active and Detached fixed window; same fixture and target PID except separate unmanaged run comparison target\.
- steps:
  1. Execute matching native correctness preflight before accepting timing\.
  2. Use measure\_window raw 64\-command samples and elapsed\_ns; exclude approval/setup waits\.
  3. Do not use approval\-inclusive cycle duration or paced\-soak prefix samples as fixed\-window throughput or whole\-run P99\.
- oracle.method: Exact PID and stable target state plus byte\-identical TCP echo\.
- oracle.assertion: Every measured command completes its declared work and passes payload and identity assertions\.
- oracle.independence: Expected payload and identity are set by the fixture caller; backend responses do not define expected results\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Within linux-gum-attach compare validated local fixed-window work with native and same-backend run baselines; save raw samples and exact valid counts/window elapsed for latency and throughput.",
    "assertion_refs": [
      {
        "first": 296,
        "last": 307,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-measure-linux-gum-attach",
    "id": "VP-linux-gum-attach",
    "obligation_id": "O-measure",
    "trigger": "Enter the backend/origin fixed measurement phase only after its native correctness preflight passed.",
    "trigger_refs": [
      {
        "first": 296,
        "last": 307,
        "path": "scripts/test-dynamic-attach.py"
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
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 1,
    "last": 80,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 296,
    "last": 307,
    "path": "scripts/test-dynamic-attach.py"
  }
]
```

- matrix:

```json
{
  "backend": "linux-gum",
  "origin": "attach"
}
```

- automation / reproduction:

```json
{
  "argv": [
    "python3",
    "scripts/test-dynamic-attach.py",
    "--hyperhub",
    "target/release/hyperhub",
    "--backend",
    "gum",
    "--origin",
    "attach",
    "--scope",
    "tree",
    "--target-pty",
    "--cycles",
    "3",
    "--output",
    "target/benchmarks/C-native-linux-gum-attach"
  ],
  "artifact_paths": [
    "scripts/test-dynamic-attach.py",
    "tests/fixtures/dynamic_attach_target.c"
  ],
  "cwd": "."
}
```

- measurement_protocol:

```json
{
  "accounting": "Retain failed and unknown work separately. Correctness failure invalidates the associated performance case.",
  "budget": {
    "rationale": "Build and two-hour mixed soak plus bounded correctness and sampling setup.",
    "timeout_seconds": 14400
  },
  "comparison": {
    "acceptance": null,
    "baseline": "Unmanaged and same-backend run with identical command semantics.",
    "basis": "User requires semantic continuity and measured overhead, without a universal performance threshold.",
    "factor_ids": [
      "backend",
      "origin"
    ]
  },
  "execution_model": "closed_loop",
  "measurement_context": {
    "end_event": "Caller validates the complete matching response.",
    "factor_ids": [
      "backend",
      "origin"
    ],
    "id": "M-linux-gum-attach",
    "level": "component",
    "resources": [],
    "start_event": "Caller sends one command.",
    "work_units": [
      {
        "description": "One validated snapshot or TCP echo command.",
        "id": "fixture-command",
        "unit": "commands"
      }
    ]
  },
  "metrics": [
    {
      "kind": "latency",
      "name": "command_latency",
      "subject_id": "fixture-command",
      "subject_kind": "work_unit",
      "summary": "Raw samples with descriptive p50/p95/p99/max per command and phase.",
      "unit": "ns"
    },
    {
      "kind": "throughput",
      "name": "valid_throughput",
      "subject_id": "fixture-command",
      "subject_kind": "work_unit",
      "summary": "Validated complete commands divided by each fixed window elapsed time.",
      "unit": "commands/s"
    }
  ],
  "reset": "A fresh target and private instance for each backend/origin trial. Preserve state between lifecycle phases by design.",
  "sampling": {
    "basis": "32 pairs provide descriptive local observations; correlated samples do not establish a production tail-latency SLO.",
    "min_samples": 64,
    "unit": "operation"
  },
  "timing_boundary": "Before sending a fixture command until the validated complete response is received.",
  "uncertainty": "Report concurrent load, machine/build identity and correlation; no statistical confidence or capacity claim from this short window.",
  "validity_checks": [
    {
      "condition": "All timed payload, identity and terminal assertions pass.",
      "id": "payload"
    },
    {
      "condition": "Each fixed window reports exactly 64 complete valid commands and no failed command counted.",
      "id": "accounting"
    },
    {
      "condition": "Setup, approval waits and pacing sleeps are excluded from fixed measurement windows.",
      "id": "boundaries"
    }
  ],
  "warmup": "Fixture setup and first correct response precede each fixed window; no claim of steady-state convergence.",
  "work_unit": "one validated snapshot or socket command"
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-P-linux-gum-run"></a>

### P\-linux\-gum\-run Validated snapshot/socket work: linux\-gum\-run

- id: P\-linux\-gum\-run
- title: Validated snapshot/socket work: linux\-gum\-run
- kind: performance
- implementation_status: implemented
- origin: existing
- goal: Compare each platform declared workload within unmanaged, same\-backend run, Active and Detached phases; Linux uses 32 snapshot/socket pairs and Windows uses 50 snapshot commands\. Keep raw latency and valid\-throughput timing separate from approval duration and do not compare different workload units as one cross\-platform result\.
- obligation_ids: O\-measure
- boundary_ids: B\-measure\-linux\-gum\-run
- preconditions: 见共用前提与场景输入；性能 preflight: C\-native\-linux\-gum\-run
- inputs: Exactly 32 alternating snapshot/socket pairs per Linux unmanaged or run baseline, Active and Detached fixed window; same fixture and target PID except separate unmanaged run comparison target\.
- steps:
  1. Execute matching native correctness preflight before accepting timing\.
  2. Use measure\_window raw 64\-command samples and elapsed\_ns; exclude approval/setup waits\.
  3. Do not use approval\-inclusive cycle duration or paced\-soak prefix samples as fixed\-window throughput or whole\-run P99\.
- oracle.method: Exact PID and stable target state plus byte\-identical TCP echo\.
- oracle.assertion: Every measured command completes its declared work and passes payload and identity assertions\.
- oracle.independence: Expected payload and identity are set by the fixture caller; backend responses do not define expected results\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Within linux-gum-run compare validated local fixed-window work with native and same-backend run baselines; save raw samples and exact valid counts/window elapsed for latency and throughput.",
    "assertion_refs": [
      {
        "first": 296,
        "last": 307,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-measure-linux-gum-run",
    "id": "VP-linux-gum-run",
    "obligation_id": "O-measure",
    "trigger": "Enter the backend/origin fixed measurement phase only after its native correctness preflight passed.",
    "trigger_refs": [
      {
        "first": 296,
        "last": 307,
        "path": "scripts/test-dynamic-attach.py"
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
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 1,
    "last": 80,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 296,
    "last": 307,
    "path": "scripts/test-dynamic-attach.py"
  }
]
```

- matrix:

```json
{
  "backend": "linux-gum",
  "origin": "run"
}
```

- automation / reproduction:

```json
{
  "argv": [
    "python3",
    "scripts/test-dynamic-attach.py",
    "--hyperhub",
    "target/release/hyperhub",
    "--backend",
    "gum",
    "--origin",
    "run",
    "--scope",
    "tree",
    "--target-pty",
    "--cycles",
    "3",
    "--output",
    "target/benchmarks/C-native-linux-gum-run"
  ],
  "artifact_paths": [
    "scripts/test-dynamic-attach.py",
    "tests/fixtures/dynamic_attach_target.c"
  ],
  "cwd": "."
}
```

- measurement_protocol:

```json
{
  "accounting": "Retain failed and unknown work separately. Correctness failure invalidates the associated performance case.",
  "budget": {
    "rationale": "Build and two-hour mixed soak plus bounded correctness and sampling setup.",
    "timeout_seconds": 14400
  },
  "comparison": {
    "acceptance": null,
    "baseline": "Unmanaged and same-backend run with identical command semantics.",
    "basis": "User requires semantic continuity and measured overhead, without a universal performance threshold.",
    "factor_ids": [
      "backend",
      "origin"
    ]
  },
  "execution_model": "closed_loop",
  "measurement_context": {
    "end_event": "Caller validates the complete matching response.",
    "factor_ids": [
      "backend",
      "origin"
    ],
    "id": "M-linux-gum-run",
    "level": "component",
    "resources": [],
    "start_event": "Caller sends one command.",
    "work_units": [
      {
        "description": "One validated snapshot or TCP echo command.",
        "id": "fixture-command",
        "unit": "commands"
      }
    ]
  },
  "metrics": [
    {
      "kind": "latency",
      "name": "command_latency",
      "subject_id": "fixture-command",
      "subject_kind": "work_unit",
      "summary": "Raw samples with descriptive p50/p95/p99/max per command and phase.",
      "unit": "ns"
    },
    {
      "kind": "throughput",
      "name": "valid_throughput",
      "subject_id": "fixture-command",
      "subject_kind": "work_unit",
      "summary": "Validated complete commands divided by each fixed window elapsed time.",
      "unit": "commands/s"
    }
  ],
  "reset": "A fresh target and private instance for each backend/origin trial. Preserve state between lifecycle phases by design.",
  "sampling": {
    "basis": "32 pairs provide descriptive local observations; correlated samples do not establish a production tail-latency SLO.",
    "min_samples": 64,
    "unit": "operation"
  },
  "timing_boundary": "Before sending a fixture command until the validated complete response is received.",
  "uncertainty": "Report concurrent load, machine/build identity and correlation; no statistical confidence or capacity claim from this short window.",
  "validity_checks": [
    {
      "condition": "All timed payload, identity and terminal assertions pass.",
      "id": "payload"
    },
    {
      "condition": "Each fixed window reports exactly 64 complete valid commands and no failed command counted.",
      "id": "accounting"
    },
    {
      "condition": "Setup, approval waits and pacing sleeps are excluded from fixed measurement windows.",
      "id": "boundaries"
    }
  ],
  "warmup": "Fixture setup and first correct response precede each fixed window; no claim of steady-state convergence.",
  "work_unit": "one validated snapshot or socket command"
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-P-linux-ptrace-attach"></a>

### P\-linux\-ptrace\-attach Validated snapshot/socket work: linux\-ptrace\-attach

- id: P\-linux\-ptrace\-attach
- title: Validated snapshot/socket work: linux\-ptrace\-attach
- kind: performance
- implementation_status: implemented
- origin: existing
- goal: Compare each platform declared workload within unmanaged, same\-backend run, Active and Detached phases; Linux uses 32 snapshot/socket pairs and Windows uses 50 snapshot commands\. Keep raw latency and valid\-throughput timing separate from approval duration and do not compare different workload units as one cross\-platform result\.
- obligation_ids: O\-measure
- boundary_ids: B\-measure\-linux\-ptrace\-attach
- preconditions: 见共用前提与场景输入；性能 preflight: C\-native\-linux\-ptrace\-attach
- inputs: Exactly 32 alternating snapshot/socket pairs per Linux unmanaged or run baseline, Active and Detached fixed window; same fixture and target PID except separate unmanaged run comparison target\.
- steps:
  1. Execute matching native correctness preflight before accepting timing\.
  2. Use measure\_window raw 64\-command samples and elapsed\_ns; exclude approval/setup waits\.
  3. Do not use approval\-inclusive cycle duration or paced\-soak prefix samples as fixed\-window throughput or whole\-run P99\.
- oracle.method: Exact PID and stable target state plus byte\-identical TCP echo\.
- oracle.assertion: Every measured command completes its declared work and passes payload and identity assertions\.
- oracle.independence: Expected payload and identity are set by the fixture caller; backend responses do not define expected results\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Within linux-ptrace-attach compare validated local fixed-window work with native and same-backend run baselines; save raw samples and exact valid counts/window elapsed for latency and throughput.",
    "assertion_refs": [
      {
        "first": 296,
        "last": 307,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-measure-linux-ptrace-attach",
    "id": "VP-linux-ptrace-attach",
    "obligation_id": "O-measure",
    "trigger": "Enter the backend/origin fixed measurement phase only after its native correctness preflight passed.",
    "trigger_refs": [
      {
        "first": 296,
        "last": 307,
        "path": "scripts/test-dynamic-attach.py"
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
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 1,
    "last": 80,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 296,
    "last": 307,
    "path": "scripts/test-dynamic-attach.py"
  }
]
```

- matrix:

```json
{
  "backend": "linux-ptrace",
  "origin": "attach"
}
```

- automation / reproduction:

```json
{
  "argv": [
    "python3",
    "scripts/test-dynamic-attach.py",
    "--hyperhub",
    "target/release/hyperhub",
    "--backend",
    "ptrace",
    "--origin",
    "attach",
    "--scope",
    "tree",
    "--target-pty",
    "--cycles",
    "3",
    "--output",
    "target/benchmarks/C-native-linux-ptrace-attach"
  ],
  "artifact_paths": [
    "scripts/test-dynamic-attach.py",
    "tests/fixtures/dynamic_attach_target.c"
  ],
  "cwd": "."
}
```

- measurement_protocol:

```json
{
  "accounting": "Retain failed and unknown work separately. Correctness failure invalidates the associated performance case.",
  "budget": {
    "rationale": "Build and two-hour mixed soak plus bounded correctness and sampling setup.",
    "timeout_seconds": 14400
  },
  "comparison": {
    "acceptance": null,
    "baseline": "Unmanaged and same-backend run with identical command semantics.",
    "basis": "User requires semantic continuity and measured overhead, without a universal performance threshold.",
    "factor_ids": [
      "backend",
      "origin"
    ]
  },
  "execution_model": "closed_loop",
  "measurement_context": {
    "end_event": "Caller validates the complete matching response.",
    "factor_ids": [
      "backend",
      "origin"
    ],
    "id": "M-linux-ptrace-attach",
    "level": "component",
    "resources": [],
    "start_event": "Caller sends one command.",
    "work_units": [
      {
        "description": "One validated snapshot or TCP echo command.",
        "id": "fixture-command",
        "unit": "commands"
      }
    ]
  },
  "metrics": [
    {
      "kind": "latency",
      "name": "command_latency",
      "subject_id": "fixture-command",
      "subject_kind": "work_unit",
      "summary": "Raw samples with descriptive p50/p95/p99/max per command and phase.",
      "unit": "ns"
    },
    {
      "kind": "throughput",
      "name": "valid_throughput",
      "subject_id": "fixture-command",
      "subject_kind": "work_unit",
      "summary": "Validated complete commands divided by each fixed window elapsed time.",
      "unit": "commands/s"
    }
  ],
  "reset": "A fresh target and private instance for each backend/origin trial. Preserve state between lifecycle phases by design.",
  "sampling": {
    "basis": "32 pairs provide descriptive local observations; correlated samples do not establish a production tail-latency SLO.",
    "min_samples": 64,
    "unit": "operation"
  },
  "timing_boundary": "Before sending a fixture command until the validated complete response is received.",
  "uncertainty": "Report concurrent load, machine/build identity and correlation; no statistical confidence or capacity claim from this short window.",
  "validity_checks": [
    {
      "condition": "All timed payload, identity and terminal assertions pass.",
      "id": "payload"
    },
    {
      "condition": "Each fixed window reports exactly 64 complete valid commands and no failed command counted.",
      "id": "accounting"
    },
    {
      "condition": "Setup, approval waits and pacing sleeps are excluded from fixed measurement windows.",
      "id": "boundaries"
    }
  ],
  "warmup": "Fixture setup and first correct response precede each fixed window; no claim of steady-state convergence.",
  "work_unit": "one validated snapshot or socket command"
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-P-linux-ptrace-run"></a>

### P\-linux\-ptrace\-run Validated snapshot/socket work: linux\-ptrace\-run

- id: P\-linux\-ptrace\-run
- title: Validated snapshot/socket work: linux\-ptrace\-run
- kind: performance
- implementation_status: implemented
- origin: existing
- goal: Compare each platform declared workload within unmanaged, same\-backend run, Active and Detached phases; Linux uses 32 snapshot/socket pairs and Windows uses 50 snapshot commands\. Keep raw latency and valid\-throughput timing separate from approval duration and do not compare different workload units as one cross\-platform result\.
- obligation_ids: O\-measure
- boundary_ids: B\-measure\-linux\-ptrace\-run
- preconditions: 见共用前提与场景输入；性能 preflight: C\-native\-linux\-ptrace\-run
- inputs: Exactly 32 alternating snapshot/socket pairs per Linux unmanaged or run baseline, Active and Detached fixed window; same fixture and target PID except separate unmanaged run comparison target\.
- steps:
  1. Execute matching native correctness preflight before accepting timing\.
  2. Use measure\_window raw 64\-command samples and elapsed\_ns; exclude approval/setup waits\.
  3. Do not use approval\-inclusive cycle duration or paced\-soak prefix samples as fixed\-window throughput or whole\-run P99\.
- oracle.method: Exact PID and stable target state plus byte\-identical TCP echo\.
- oracle.assertion: Every measured command completes its declared work and passes payload and identity assertions\.
- oracle.independence: Expected payload and identity are set by the fixture caller; backend responses do not define expected results\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Within linux-ptrace-run compare validated local fixed-window work with native and same-backend run baselines; save raw samples and exact valid counts/window elapsed for latency and throughput.",
    "assertion_refs": [
      {
        "first": 296,
        "last": 307,
        "path": "scripts/test-dynamic-attach.py"
      }
    ],
    "boundary_id": "B-measure-linux-ptrace-run",
    "id": "VP-linux-ptrace-run",
    "obligation_id": "O-measure",
    "trigger": "Enter the backend/origin fixed measurement phase only after its native correctness preflight passed.",
    "trigger_refs": [
      {
        "first": 296,
        "last": 307,
        "path": "scripts/test-dynamic-attach.py"
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
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 1,
    "last": 80,
    "path": "scripts/test-dynamic-attach.py"
  },
  {
    "first": 296,
    "last": 307,
    "path": "scripts/test-dynamic-attach.py"
  }
]
```

- matrix:

```json
{
  "backend": "linux-ptrace",
  "origin": "run"
}
```

- automation / reproduction:

```json
{
  "argv": [
    "python3",
    "scripts/test-dynamic-attach.py",
    "--hyperhub",
    "target/release/hyperhub",
    "--backend",
    "ptrace",
    "--origin",
    "run",
    "--scope",
    "tree",
    "--target-pty",
    "--cycles",
    "3",
    "--output",
    "target/benchmarks/C-native-linux-ptrace-run"
  ],
  "artifact_paths": [
    "scripts/test-dynamic-attach.py",
    "tests/fixtures/dynamic_attach_target.c"
  ],
  "cwd": "."
}
```

- measurement_protocol:

```json
{
  "accounting": "Retain failed and unknown work separately. Correctness failure invalidates the associated performance case.",
  "budget": {
    "rationale": "Build and two-hour mixed soak plus bounded correctness and sampling setup.",
    "timeout_seconds": 14400
  },
  "comparison": {
    "acceptance": null,
    "baseline": "Unmanaged and same-backend run with identical command semantics.",
    "basis": "User requires semantic continuity and measured overhead, without a universal performance threshold.",
    "factor_ids": [
      "backend",
      "origin"
    ]
  },
  "execution_model": "closed_loop",
  "measurement_context": {
    "end_event": "Caller validates the complete matching response.",
    "factor_ids": [
      "backend",
      "origin"
    ],
    "id": "M-linux-ptrace-run",
    "level": "component",
    "resources": [],
    "start_event": "Caller sends one command.",
    "work_units": [
      {
        "description": "One validated snapshot or TCP echo command.",
        "id": "fixture-command",
        "unit": "commands"
      }
    ]
  },
  "metrics": [
    {
      "kind": "latency",
      "name": "command_latency",
      "subject_id": "fixture-command",
      "subject_kind": "work_unit",
      "summary": "Raw samples with descriptive p50/p95/p99/max per command and phase.",
      "unit": "ns"
    },
    {
      "kind": "throughput",
      "name": "valid_throughput",
      "subject_id": "fixture-command",
      "subject_kind": "work_unit",
      "summary": "Validated complete commands divided by each fixed window elapsed time.",
      "unit": "commands/s"
    }
  ],
  "reset": "A fresh target and private instance for each backend/origin trial. Preserve state between lifecycle phases by design.",
  "sampling": {
    "basis": "32 pairs provide descriptive local observations; correlated samples do not establish a production tail-latency SLO.",
    "min_samples": 64,
    "unit": "operation"
  },
  "timing_boundary": "Before sending a fixture command until the validated complete response is received.",
  "uncertainty": "Report concurrent load, machine/build identity and correlation; no statistical confidence or capacity claim from this short window.",
  "validity_checks": [
    {
      "condition": "All timed payload, identity and terminal assertions pass.",
      "id": "payload"
    },
    {
      "condition": "Each fixed window reports exactly 64 complete valid commands and no failed command counted.",
      "id": "accounting"
    },
    {
      "condition": "Setup, approval waits and pacing sleeps are excluded from fixed measurement windows.",
      "id": "boundaries"
    }
  ],
  "warmup": "Fixture setup and first correct response precede each fixed window; no claim of steady-state convergence.",
  "work_unit": "one validated snapshot or socket command"
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-P-windows-gum-attach"></a>

### P\-windows\-gum\-attach Validated snapshot/socket work: windows\-gum\-attach

- id: P\-windows\-gum\-attach
- title: Validated snapshot/socket work: windows\-gum\-attach
- kind: performance
- implementation_status: planned
- origin: generated
- goal: Compare each platform declared workload within unmanaged, same\-backend run, Active and Detached phases; Linux uses 32 snapshot/socket pairs and Windows uses 50 snapshot commands\. Keep raw latency and valid\-throughput timing separate from approval duration and do not compare different workload units as one cross\-platform result\.
- obligation_ids: O\-measure
- boundary_ids: B\-measure\-windows\-gum\-attach\-throughput
- preconditions: 见共用前提与场景输入；性能 preflight: C\-continuity, C\-drain, C\-tree
- inputs: Same local fixture and loopback echo server; unmanaged, Active, Detached and same\-backend run windows\.
- steps:
  1. Pass the matching correctness preflight\.
  2. Measure fixed 32 snapshot/socket pairs with identical assertions in each window\.
  3. Report raw command samples and valid\-work accounting; keep approval durations separate\.
- oracle.method: Exact PID and stable target state plus byte\-identical TCP echo\.
- oracle.assertion: Every measured command completes its declared work and passes payload and identity assertions\.
- oracle.independence: Expected payload and identity are set by the fixture caller; backend responses do not define expected results\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Within windows-gum-attach-throughput measure actual complete fixed-window elapsed and validated snapshot counts to report commands/s; current driver has no such throughput timer.",
    "assertion_refs": [],
    "boundary_id": "B-measure-windows-gum-attach-throughput",
    "id": "VP-windows-gum-attach",
    "obligation_id": "O-measure",
    "trigger": "Enter the backend/origin fixed measurement phase only after its native correctness preflight passed.",
    "trigger_refs": []
  }
]
```

- code_references:

```json
[
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 1,
    "last": 80,
    "path": "scripts/test-dynamic-attach.py"
  }
]
```

- matrix:

```json
{
  "backend": "windows-gum",
  "origin": "attach"
}
```

- automation / reproduction:

尚无已实现入口；设计可审查，执行就绪另行判定。

- measurement_protocol:

```json
{
  "accounting": "Retain failed and unknown work separately. Correctness failure invalidates the associated performance case.",
  "budget": {
    "rationale": "Build and two-hour mixed soak plus bounded correctness and sampling setup.",
    "timeout_seconds": 14400
  },
  "comparison": {
    "acceptance": null,
    "baseline": "Unmanaged and same-backend run with identical command semantics.",
    "basis": "User requires semantic continuity and measured overhead, without a universal performance threshold.",
    "factor_ids": [
      "backend",
      "origin"
    ]
  },
  "execution_model": "closed_loop",
  "measurement_context": {
    "end_event": "After validating the fiftieth snapshot; collector now records total window elapsed_ns.",
    "factor_ids": [
      "backend",
      "origin"
    ],
    "id": "M-windows-gum-attach",
    "level": "component",
    "resources": [],
    "start_event": "Before sending the first snapshot in a 50-snapshot Windows phase.",
    "work_units": [
      {
        "description": "One validated native Windows snapshot response.",
        "id": "fixture-command",
        "unit": "commands"
      }
    ]
  },
  "metrics": [
    {
      "kind": "latency",
      "name": "command_latency",
      "subject_id": "fixture-command",
      "subject_kind": "work_unit",
      "summary": "50 raw snapshot samples per Windows phase, descriptive p50/p95/max; no TCP command latency and no production tail claim.",
      "unit": "ns"
    },
    {
      "kind": "throughput",
      "name": "valid_throughput",
      "subject_id": "fixture-command",
      "subject_kind": "work_unit",
      "summary": "Validated complete commands divided by each fixed window elapsed time.",
      "unit": "commands/s"
    }
  ],
  "reset": "A fresh target and private instance for each backend/origin trial. Preserve state between lifecycle phases by design.",
  "sampling": {
    "basis": "Exactly50 snapshot samples per phase; declared comparison pairing still needs final protocol review, so this aggregate remains planned.",
    "min_samples": 50,
    "unit": "operation"
  },
  "timing_boundary": "Before sending a fixture command until the validated complete response is received.",
  "uncertainty": "Report concurrent load, machine/build identity and correlation; no statistical confidence or capacity claim from this short window.",
  "validity_checks": [
    {
      "condition": "All timed payload, identity and terminal assertions pass.",
      "id": "payload"
    },
    {
      "condition": "Each Windows phase has exactly50 validated snapshot samples and complete-window elapsed_ns; cross-invocation same-backend run comparison and correctness preflight must match this snapshot-only workload.",
      "id": "accounting"
    },
    {
      "condition": "Setup, approval waits and pacing sleeps are excluded from fixed measurement windows.",
      "id": "boundaries"
    }
  ],
  "warmup": "Fixture setup and first correct response precede each fixed window; no claim of steady-state convergence.",
  "work_unit": "one validated Windows snapshot command"
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-P-windows-gum-attach-snapshot-latency"></a>

### P\-windows\-gum\-attach\-snapshot\-latency Windows attach 50\-snapshot latency observations

- id: P\-windows\-gum\-attach\-snapshot\-latency
- title: Windows attach 50\-snapshot latency observations
- kind: performance
- implementation_status: implemented
- origin: existing
- goal: Compare each platform declared workload within unmanaged, same\-backend run, Active and Detached phases; Linux uses 32 snapshot/socket pairs and Windows uses 50 snapshot commands\. Keep raw latency and valid\-throughput timing separate from approval duration and do not compare different workload units as one cross\-platform result\.
- obligation_ids: O\-measure
- boundary_ids: B\-measure\-windows\-gum\-attach\-latency, B\-measure\-windows\-gum\-attach\-throughput
- preconditions: 见共用前提与场景输入；性能 preflight: C\-native\-windows\-gum
- inputs: Same local fixture and loopback echo server; unmanaged, Active, Detached and same\-backend run windows\.
- steps:
  1. Execute native Windows driver with the specified origin; preserve all actual failures\.
  2. Read performance entries with workload=same\_fixture\_snapshot\_command; count50 samples per phase\.
  3. Report descriptive snapshot latency only; whole\-window commands/s remains planned\.
- oracle.method: Exact PID and stable target state plus byte\-identical TCP echo\.
- oracle.assertion: Every measured command completes its declared work and passes payload and identity assertions\.
- oracle.independence: Expected payload and identity are set by the fixture caller; backend responses do not define expected results\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Retain actual window elapsed, validated count, raw samples and effective_operations_per_second = count * 1e9 / elapsed_ns.",
    "assertion_refs": [
      {
        "first": 177,
        "last": 184,
        "path": "scripts/test-dynamic-attach-windows.py"
      }
    ],
    "boundary_id": "B-measure-windows-gum-attach-throughput",
    "id": "V-measure-windows-gum-attach-throughput",
    "obligation_id": "O-measure",
    "trigger": "Run exactly 50 successful same-fixture snapshot exchanges within the measured window.",
    "trigger_refs": [
      {
        "first": 177,
        "last": 184,
        "path": "scripts/test-dynamic-attach-windows.py"
      }
    ]
  },
  {
    "assertion": "Every reported Windows phase stores exactly50 validated snapshot latency samples with correct identity/environment/cwd/stdio.",
    "assertion_refs": [
      {
        "first": 177,
        "last": 184,
        "path": "scripts/test-dynamic-attach-windows.py"
      }
    ],
    "boundary_id": "B-measure-windows-gum-attach-latency",
    "id": "V-windows-attach-snapshot-latency",
    "obligation_id": "O-measure",
    "trigger": "Enter the backend/origin fixed measurement phase only after its native correctness preflight passed.",
    "trigger_refs": [
      {
        "first": 177,
        "last": 184,
        "path": "scripts/test-dynamic-attach-windows.py"
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
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 177,
    "last": 184,
    "path": "scripts/test-dynamic-attach-windows.py"
  },
  {
    "first": 1,
    "last": 80,
    "path": "scripts/test-dynamic-attach.py"
  }
]
```

- matrix:

```json
{
  "backend": "windows-gum",
  "origin": "attach"
}
```

- automation / reproduction:

```json
{
  "argv": [
    "python",
    "scripts/test-dynamic-attach-windows.py",
    "--hyperhub",
    "target/release/hyperhub.exe",
    "--origin",
    "attach",
    "--cycles",
    "3",
    "--output",
    "target/benchmarks/windows-attach-latency"
  ],
  "artifact_paths": [
    "scripts/test-dynamic-attach-windows.py",
    "scripts/windows_conpty.py",
    "tests/fixtures/dynamic_attach_legacy_marker.rs",
    "tests/fixtures/dynamic_attach_windows.rs"
  ],
  "cwd": "."
}
```

- measurement_protocol:

```json
{
  "accounting": "Retain failed and unknown work separately. Correctness failure invalidates the associated performance case.",
  "budget": {
    "rationale": "Build and two-hour mixed soak plus bounded correctness and sampling setup.",
    "timeout_seconds": 14400
  },
  "comparison": {
    "acceptance": null,
    "baseline": "Native Windows unmanaged and same-backend run snapshot windows, with matching50-command semantics; no mixed Linux TCP comparison.",
    "basis": "User requires semantic continuity and measured overhead, without a universal performance threshold.",
    "factor_ids": [
      "backend",
      "origin"
    ]
  },
  "execution_model": "closed_loop",
  "measurement_context": {
    "end_event": "After receiving its complete validated response.",
    "factor_ids": [
      "backend",
      "origin"
    ],
    "id": "M-windows-gum-attach",
    "level": "component",
    "resources": [],
    "start_event": "Before sending each native Windows snapshot command.",
    "work_units": [
      {
        "description": "One validated native Windows snapshot response.",
        "id": "fixture-command",
        "unit": "commands"
      }
    ]
  },
  "metrics": [
    {
      "kind": "latency",
      "name": "command_latency",
      "subject_id": "fixture-command",
      "subject_kind": "work_unit",
      "summary": "50 raw snapshot samples per Windows phase, descriptive p50/p95/max; no TCP command latency and no production tail claim.",
      "unit": "ns"
    }
  ],
  "reset": "A fresh target and private instance for each backend/origin trial. Preserve state between lifecycle phases by design.",
  "sampling": {
    "basis": "Native collector emits50 validated snapshot latencies per phase; the current driver also records total elapsed_ns and throughput separately.",
    "min_samples": 50,
    "unit": "operation"
  },
  "timing_boundary": "Before sending a fixture command until the validated complete response is received.",
  "uncertainty": "Report concurrent load, machine/build identity and correlation; no statistical confidence or capacity claim from this short window.",
  "validity_checks": [
    {
      "condition": "All timed payload, identity and terminal assertions pass.",
      "id": "payload"
    },
    {
      "condition": "Each phase has exactly50 validated snapshot latency samples. This case reports latency only; use the separately reviewed throughput comparison case for operations/s.",
      "id": "accounting"
    },
    {
      "condition": "Setup, approval waits and pacing sleeps are excluded from fixed measurement windows.",
      "id": "boundaries"
    }
  ],
  "warmup": "Fixture setup and first correct response precede each fixed window; no claim of steady-state convergence.",
  "work_unit": "one validated native Windows snapshot command"
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-P-windows-gum-run"></a>

### P\-windows\-gum\-run Validated snapshot/socket work: windows\-gum\-run

- id: P\-windows\-gum\-run
- title: Validated snapshot/socket work: windows\-gum\-run
- kind: performance
- implementation_status: planned
- origin: generated
- goal: Compare each platform declared workload within unmanaged, same\-backend run, Active and Detached phases; Linux uses 32 snapshot/socket pairs and Windows uses 50 snapshot commands\. Keep raw latency and valid\-throughput timing separate from approval duration and do not compare different workload units as one cross\-platform result\.
- obligation_ids: O\-measure
- boundary_ids: B\-measure\-windows\-gum\-run\-throughput
- preconditions: 见共用前提与场景输入；性能 preflight: C\-continuity, C\-drain, C\-tree
- inputs: Same local fixture and loopback echo server; unmanaged, Active, Detached and same\-backend run windows\.
- steps:
  1. Pass the matching correctness preflight\.
  2. Measure fixed 32 snapshot/socket pairs with identical assertions in each window\.
  3. Report raw command samples and valid\-work accounting; keep approval durations separate\.
- oracle.method: Exact PID and stable target state plus byte\-identical TCP echo\.
- oracle.assertion: Every measured command completes its declared work and passes payload and identity assertions\.
- oracle.independence: Expected payload and identity are set by the fixture caller; backend responses do not define expected results\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Within windows-gum-run-throughput measure actual complete fixed-window elapsed and validated snapshot counts to report commands/s; current driver has no such throughput timer.",
    "assertion_refs": [],
    "boundary_id": "B-measure-windows-gum-run-throughput",
    "id": "VP-windows-gum-run",
    "obligation_id": "O-measure",
    "trigger": "Enter the backend/origin fixed measurement phase only after its native correctness preflight passed.",
    "trigger_refs": []
  }
]
```

- code_references:

```json
[
  {
    "first": 1,
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 1,
    "last": 80,
    "path": "scripts/test-dynamic-attach.py"
  }
]
```

- matrix:

```json
{
  "backend": "windows-gum",
  "origin": "run"
}
```

- automation / reproduction:

尚无已实现入口；设计可审查，执行就绪另行判定。

- measurement_protocol:

```json
{
  "accounting": "Retain failed and unknown work separately. Correctness failure invalidates the associated performance case.",
  "budget": {
    "rationale": "Build and two-hour mixed soak plus bounded correctness and sampling setup.",
    "timeout_seconds": 14400
  },
  "comparison": {
    "acceptance": null,
    "baseline": "Unmanaged and same-backend run with identical command semantics.",
    "basis": "User requires semantic continuity and measured overhead, without a universal performance threshold.",
    "factor_ids": [
      "backend",
      "origin"
    ]
  },
  "execution_model": "closed_loop",
  "measurement_context": {
    "end_event": "After validating the fiftieth snapshot; collector now records total window elapsed_ns.",
    "factor_ids": [
      "backend",
      "origin"
    ],
    "id": "M-windows-gum-run",
    "level": "component",
    "resources": [],
    "start_event": "Before sending the first snapshot in a 50-snapshot Windows phase.",
    "work_units": [
      {
        "description": "One validated native Windows snapshot response.",
        "id": "fixture-command",
        "unit": "commands"
      }
    ]
  },
  "metrics": [
    {
      "kind": "latency",
      "name": "command_latency",
      "subject_id": "fixture-command",
      "subject_kind": "work_unit",
      "summary": "50 raw snapshot samples per Windows phase, descriptive p50/p95/max; no TCP command latency and no production tail claim.",
      "unit": "ns"
    },
    {
      "kind": "throughput",
      "name": "valid_throughput",
      "subject_id": "fixture-command",
      "subject_kind": "work_unit",
      "summary": "Validated complete commands divided by each fixed window elapsed time.",
      "unit": "commands/s"
    }
  ],
  "reset": "A fresh target and private instance for each backend/origin trial. Preserve state between lifecycle phases by design.",
  "sampling": {
    "basis": "Exactly50 snapshot samples per phase; declared comparison pairing still needs final protocol review, so this aggregate remains planned.",
    "min_samples": 50,
    "unit": "operation"
  },
  "timing_boundary": "Before sending a fixture command until the validated complete response is received.",
  "uncertainty": "Report concurrent load, machine/build identity and correlation; no statistical confidence or capacity claim from this short window.",
  "validity_checks": [
    {
      "condition": "All timed payload, identity and terminal assertions pass.",
      "id": "payload"
    },
    {
      "condition": "Each Windows phase has exactly50 validated snapshot samples and complete-window elapsed_ns; cross-invocation same-backend run comparison and correctness preflight must match this snapshot-only workload.",
      "id": "accounting"
    },
    {
      "condition": "Setup, approval waits and pacing sleeps are excluded from fixed measurement windows.",
      "id": "boundaries"
    }
  ],
  "warmup": "Fixture setup and first correct response precede each fixed window; no claim of steady-state convergence.",
  "work_unit": "one validated Windows snapshot command"
}
```

- reported_result:

未提交执行记录；未运行／未验证。

<a id="case-P-windows-gum-run-snapshot-latency"></a>

### P\-windows\-gum\-run\-snapshot\-latency Windows run 50\-snapshot latency observations

- id: P\-windows\-gum\-run\-snapshot\-latency
- title: Windows run 50\-snapshot latency observations
- kind: performance
- implementation_status: implemented
- origin: existing
- goal: Compare each platform declared workload within unmanaged, same\-backend run, Active and Detached phases; Linux uses 32 snapshot/socket pairs and Windows uses 50 snapshot commands\. Keep raw latency and valid\-throughput timing separate from approval duration and do not compare different workload units as one cross\-platform result\.
- obligation_ids: O\-measure
- boundary_ids: B\-measure\-windows\-gum\-run\-latency, B\-measure\-windows\-gum\-run\-throughput
- preconditions: 见共用前提与场景输入；性能 preflight: C\-native\-windows\-gum
- inputs: Same local fixture and loopback echo server; unmanaged, Active, Detached and same\-backend run windows\.
- steps:
  1. Execute native Windows driver with the specified origin; preserve all actual failures\.
  2. Read performance entries with workload=same\_fixture\_snapshot\_command; count50 samples per phase\.
  3. Report descriptive snapshot latency only; whole\-window commands/s remains planned\.
- oracle.method: Exact PID and stable target state plus byte\-identical TCP echo\.
- oracle.assertion: Every measured command completes its declared work and passes payload and identity assertions\.
- oracle.independence: Expected payload and identity are set by the fixture caller; backend responses do not define expected results\.
- workload_ids: W\-attachment
- trigger_and_assertion_links:

```json
[
  {
    "assertion": "Retain actual window elapsed, validated count, raw samples and effective_operations_per_second = count * 1e9 / elapsed_ns.",
    "assertion_refs": [
      {
        "first": 177,
        "last": 184,
        "path": "scripts/test-dynamic-attach-windows.py"
      }
    ],
    "boundary_id": "B-measure-windows-gum-run-throughput",
    "id": "V-measure-windows-gum-run-throughput",
    "obligation_id": "O-measure",
    "trigger": "Run exactly 50 successful same-fixture snapshot exchanges within the measured window.",
    "trigger_refs": [
      {
        "first": 177,
        "last": 184,
        "path": "scripts/test-dynamic-attach-windows.py"
      }
    ]
  },
  {
    "assertion": "Every reported Windows phase stores exactly50 validated snapshot latency samples with correct identity/environment/cwd/stdio.",
    "assertion_refs": [
      {
        "first": 177,
        "last": 184,
        "path": "scripts/test-dynamic-attach-windows.py"
      }
    ],
    "boundary_id": "B-measure-windows-gum-run-latency",
    "id": "V-windows-run-snapshot-latency",
    "obligation_id": "O-measure",
    "trigger": "Enter the backend/origin fixed measurement phase only after its native correctness preflight passed.",
    "trigger_refs": [
      {
        "first": 177,
        "last": 184,
        "path": "scripts/test-dynamic-attach-windows.py"
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
    "last": 84,
    "path": "docs/dynamic-attach.md"
  },
  {
    "first": 177,
    "last": 184,
    "path": "scripts/test-dynamic-attach-windows.py"
  },
  {
    "first": 1,
    "last": 80,
    "path": "scripts/test-dynamic-attach.py"
  }
]
```

- matrix:

```json
{
  "backend": "windows-gum",
  "origin": "run"
}
```

- automation / reproduction:

```json
{
  "argv": [
    "python",
    "scripts/test-dynamic-attach-windows.py",
    "--hyperhub",
    "target/release/hyperhub.exe",
    "--origin",
    "run",
    "--cycles",
    "3",
    "--output",
    "target/benchmarks/windows-run-latency"
  ],
  "artifact_paths": [
    "scripts/test-dynamic-attach-windows.py",
    "scripts/windows_conpty.py",
    "tests/fixtures/dynamic_attach_legacy_marker.rs",
    "tests/fixtures/dynamic_attach_windows.rs"
  ],
  "cwd": "."
}
```

- measurement_protocol:

```json
{
  "accounting": "Retain failed and unknown work separately. Correctness failure invalidates the associated performance case.",
  "budget": {
    "rationale": "Build and two-hour mixed soak plus bounded correctness and sampling setup.",
    "timeout_seconds": 14400
  },
  "comparison": {
    "acceptance": null,
    "baseline": "Native Windows unmanaged and same-backend run snapshot windows, with matching50-command semantics; no mixed Linux TCP comparison.",
    "basis": "User requires semantic continuity and measured overhead, without a universal performance threshold.",
    "factor_ids": [
      "backend",
      "origin"
    ]
  },
  "execution_model": "closed_loop",
  "measurement_context": {
    "end_event": "After receiving its complete validated response.",
    "factor_ids": [
      "backend",
      "origin"
    ],
    "id": "M-windows-gum-run",
    "level": "component",
    "resources": [],
    "start_event": "Before sending each native Windows snapshot command.",
    "work_units": [
      {
        "description": "One validated native Windows snapshot response.",
        "id": "fixture-command",
        "unit": "commands"
      }
    ]
  },
  "metrics": [
    {
      "kind": "latency",
      "name": "command_latency",
      "subject_id": "fixture-command",
      "subject_kind": "work_unit",
      "summary": "50 raw snapshot samples per Windows phase, descriptive p50/p95/max; no TCP command latency and no production tail claim.",
      "unit": "ns"
    }
  ],
  "reset": "A fresh target and private instance for each backend/origin trial. Preserve state between lifecycle phases by design.",
  "sampling": {
    "basis": "Native collector emits50 validated snapshot latencies per phase; the current driver also records total elapsed_ns and throughput separately.",
    "min_samples": 50,
    "unit": "operation"
  },
  "timing_boundary": "Before sending a fixture command until the validated complete response is received.",
  "uncertainty": "Report concurrent load, machine/build identity and correlation; no statistical confidence or capacity claim from this short window.",
  "validity_checks": [
    {
      "condition": "All timed payload, identity and terminal assertions pass.",
      "id": "payload"
    },
    {
      "condition": "Each phase has exactly50 validated snapshot latency samples. This case reports latency only; use the separately reviewed throughput comparison case for operations/s.",
      "id": "accounting"
    },
    {
      "condition": "Setup, approval waits and pacing sleeps are excluded from fixed measurement windows.",
      "id": "boundaries"
    }
  ],
  "warmup": "Fixture setup and first correct response precede each fixed window; no claim of steady-state convergence.",
  "work_unit": "one validated native Windows snapshot command"
}
```

- reported_result:

未提交执行记录；未运行／未验证。

## 覆盖映射

| 阶段 | 义务覆盖 | 子边界覆盖 | 关键缺口 | 完整模型门槛 |
|---|---|---|---|---|
| 设计 | 9/9 | 82/82 | 无 | 满足 |
| 实现 | 2/9 | 52/82 | O\-approval, O\-continuity, O\-drain, O\-fake, O\-recovery, O\-release, O\-tree | 未满足 |
| 申报执行 | 0/9 | 0/82 | O\-approval, O\-continuity, O\-drain, O\-fake, O\-recovery, O\-release, O\-resources, O\-tree | 未满足 |
| 申报有效测量 | 0/9 | 0/82 | O\-approval, O\-continuity, O\-drain, O\-fake, O\-recovery, O\-release, O\-resources, O\-tree | 未满足 |

### 义务与子边界

| ID | 类别 / 风险 / 适用性 | 属性与依据 | 所选阶段 |
|---|---|---|---|
| O\-approval | correctness / critical / required | Only fresh human approval bound to exact process incarnation, instance, scope, backend, policy and bootstrap may mutate an external target\. Proposal alone has no effect\. / contract / docs/dynamic\-attach\.md and accepted PLAN\.md contract | 未覆盖 |
| B\-approval\-accepted\-history\-integrity | 子边界 | Consumed/completion history must be rooted in trusted accepted\-operation state; an ordinary writable ledger key snapshot cannot alone authorize continuation\. | 未覆盖 |
| B\-approval\-api\-only | 子边界 | Runtime envelope/API authority cannot derive the administrator signing key or claim implicit external run ownership\. | 已覆盖 |
| B\-approval\-capability\-preflight | 子边界 | Refuse configured TLS/SSH interception unsupported by existing contexts without weakening configuration\. | 已覆盖 |
| B\-approval\-cold\-unenrolled | 子边界 | API\-only cold startup stays Unenrolled for external lifecycle mutation while ordinary Serve/policy/run startup remains usable\. | 未覆盖 |
| B\-approval\-core\-pinned\-root | 子边界 | Core verification uses an enrolled in\-memory approval key; ordinary verifier\-file replacement cannot register or change the root\. | 未覆盖 |
| B\-approval\-fresh\-single\-use | 子边界 | Reject future, exactly expired and expired grants; consume each nonce once for its OS claimant\. | 已覆盖 |
| B\-approval\-host\-peer\-linux | 子边界 | Linux Host OS peer authentication rejects wrong server PID before credentials/proofs are sent\. | 已覆盖 |
| B\-approval\-host\-peer\-windows | 子边界 | Windows named\-pipe OS peer authentication rejects wrong server PID before credentials/proofs are sent\. | 未覆盖 |
| B\-approval\-host\-pinned\-root | 子边界 | Every Host pins its initial approval root; no command or ordinary file may lazily choose a different first root\. | 未覆盖 |
| B\-approval\-proposal\-linux\-gum | 子边界 | Linux Gum attach and detach proposals have no policy side effects before approval\. | 已覆盖 |
| B\-approval\-proposal\-linux\-ptrace | 子边界 | Linux ptrace attach and detach proposals have no policy side effects before approval\. | 已覆盖 |
| B\-approval\-proposal\-windows\-gum | 子边界 | Windows Gum attach and detach proposals have no policy side effects before approval\. | 已覆盖 |
| B\-approval\-rotation\-chain | 子边界 | Password changes require contiguous instance/generation\-bound old\-key\-signed rotation records; missing/reordered/backward or untrusted chains never replace a pinned root\. | 未覆盖 |
| B\-approval\-rotation\-envelopes | 子边界 | Password/config\-generation changes immediately invalidate old signers, preserve consumed audit and retain encrypted recovery readability\. | 已覆盖 |
| B\-approval\-signed\-bindings | 子边界 | Reject altered process identity, scope, policy, capabilities, executor, Bootstrap, Host identity and recovery bindings\. | 已覆盖 |
| B\-approval\-terminal\-slot\-renewal | 子边界 | A Draining/resident slot that becomes terminal during human review receives fresh request/attachment/session/token epochs without changing target/scope/backend/policy or repeating approval; clients follow the actual returned id\. | 已覆盖 |
| B\-approval\-trusted\-enrollment | 子边界 | First real administrator approve completes challenge\-bound registration via authenticated trusted CLI code, then the exact original request without another password prompt\. | 未覆盖 |
| O\-continuity | correctness / critical / required | Preserve allowed payloads, existing TCP, blocking original calls, socket flags, explicit child environments, PID, cwd, stdio, terminal state and original root exit status\. / contract / docs/dynamic\-attach\.md and accepted PLAN\.md contract | 未覆盖 |
| B\-continuity\-linux\-gum\-identity | 子边界 | Linux Gum preserves PID/cwd/stdio/env, explicit exec/spawn environment and original exit status\. | 已覆盖 |
| B\-continuity\-linux\-gum\-io | 子边界 | Linux Gum preserves existing/new TCP payload, blocked read result and preopened/nonblocking socket flags\. | 已覆盖 |
| B\-continuity\-linux\-gum\-terminal | 子边界 | Linux Gum target with controlling PTY preserves termios and foreground terminal identity\. | 已覆盖 |
| B\-continuity\-linux\-ptrace\-identity | 子边界 | Linux ptrace preserves PID/cwd/stdio/env, explicit exec/spawn environment and original exit status\. | 已覆盖 |
| B\-continuity\-linux\-ptrace\-io | 子边界 | Linux ptrace preserves existing/new TCP payload, blocked read result and preopened/nonblocking socket flags\. | 已覆盖 |
| B\-continuity\-linux\-ptrace\-terminal | 子边界 | Linux ptrace target with controlling PTY preserves termios and foreground terminal identity\. | 已覆盖 |
| B\-continuity\-owned\-ready\-failure | 子边界 | After authenticated Host READY, failed keeper creation/claim/control I/O never kills the target; retire only the exact created helper, preserve native recovery context and truthful owner\. | 未覆盖 |
| B\-continuity\-owned\-wait | 子边界 | Each backend run launcher keeps waiting after detach and returns original root status independently of persistent manager lifetime\. | 未覆盖 |
| B\-continuity\-windows\-identity | 子边界 | Windows Gum preserves PID/cwd/stdio/env and original exit status\. | 已覆盖 |
| B\-continuity\-windows\-io | 子边界 | Windows Gum preserves existing/new TCP payload and blocked original ReadFile result\. | 已覆盖 |
| B\-continuity\-windows\-terminal | 子边界 | Native Windows target terminal modes, foreground console and keyboard semantics survive lifecycle changes; an approval ConPTY alone is insufficient\. | 未覆盖 |
| O\-drain | correctness / critical / required | Approved detach stops new enforcement\. Keep compatibility code while calls, async operations, trust contexts, callbacks or cached addresses need it\. Detached requires independent physical\-unload proof\. / contract / docs/dynamic\-attach\.md and accepted PLAN\.md contract | 未覆盖 |
| B\-drain\-completion\-protocol | 子边界 | Only exact physical\-absence marker/pending phases and an accepted signed consumed operation can revoke session; rotation and lost ACK preserve idempotent completion\. | 已覆盖 |
| B\-drain\-linux\-gum\-blocked | 子边界 | Linux Gum detach preserves an outstanding original blocked read and nonblocking flags\. | 已覆盖 |
| B\-drain\-linux\-gum\-physical | 子边界 | Independent module/callback/cache evidence distinguishes Linux Gum resident compatibility from proven unload\. | 未覆盖 |
| B\-drain\-linux\-ptrace\-blocked | 子边界 | Linux ptrace detach preserves an outstanding original blocked read and nonblocking flags\. | 已覆盖 |
| B\-drain\-linux\-ptrace\-physical | 子边界 | Independent OS TracerPid checks prove every covered live member is untraced before public Detached\. | 未覆盖 |
| B\-drain\-windows\-blocked\-trust | 子边界 | Windows Gum remains loaded during blocked ReadFile and retained modified Schannel credential; unload only after explicit release\. | 已覆盖 |
| B\-drain\-windows\-physical | 子边界 | Independent native module enumeration proves all eligible live members are unloaded before public Detached; token/session revocation completes\. | 未覆盖 |
| O\-fake | correctness / critical / required | Previously cached FAKE\-IP aliases remain usable across detach and reattach\. Do not reassign an address to another destination while application caches may retain it\. / contract / docs/dynamic\-attach\.md and accepted PLAN\.md contract | 未覆盖 |
| B\-fake\-linux\-gum | 子边界 | ObservedExternal cached addresses on linux\-gum use the unchanged original native connect after Detach and match a genuine unmanaged same\-sockaddr baseline, with no old gateway policy\. | 未覆盖 |
| B\-fake\-linux\-gum\-issued | 子边界 | Actual HyperHub\-issued aliases on linux\-gum preserve their hostname and use the target SDK original resolver/connect after Detach, without Core/Socks dependency\. | 未覆盖 |
| B\-fake\-linux\-gum\-nonreuse | 子边界 | Allocate/observe another destination on linux\-gum and prove an application\-cached old alias is never reassigned across detach epochs or DNS TTL expiry\. | 未覆盖 |
| B\-fake\-linux\-ptrace | 子边界 | ObservedExternal cached addresses on linux\-ptrace use the unchanged original native connect after Detach and match a genuine unmanaged same\-sockaddr baseline, with no old gateway policy\. | 未覆盖 |
| B\-fake\-linux\-ptrace\-issued | 子边界 | Actual HyperHub\-issued aliases on linux\-ptrace preserve their hostname and use the target SDK original resolver/connect after Detach, without Core/Socks dependency\. | 未覆盖 |
| B\-fake\-linux\-ptrace\-nonreuse | 子边界 | Allocate/observe another destination on linux\-ptrace and prove an application\-cached old alias is never reassigned across detach epochs or DNS TTL expiry\. | 未覆盖 |
| B\-fake\-windows\-gum | 子边界 | Cache a real HyperHub FAKE\-IP before detach, connect through that exact cached alias after detach/reattach, and prove an additional destination never reuses it\. | 未覆盖 |
| O\-measure | performance / normal / required | Compare each platform declared workload within unmanaged, same\-backend run, Active and Detached phases; Linux uses 32 snapshot/socket pairs and Windows uses 50 snapshot commands\. Keep raw latency and valid\-throughput timing separate from approval duration and do not compare different workload units as one cross\-platform result\. / contract / docs/dynamic\-attach\.md and accepted PLAN\.md contract | 已覆盖 |
| B\-measure\-linux\-gum\-attach | 子边界 | Within linux\-gum\-attach compare validated local fixed\-window work with native and same\-backend run baselines; save raw samples and exact valid counts/window elapsed for latency and throughput\. | 已覆盖 |
| B\-measure\-linux\-gum\-run | 子边界 | Within linux\-gum\-run compare validated local fixed\-window work with native and same\-backend run baselines; save raw samples and exact valid counts/window elapsed for latency and throughput\. | 已覆盖 |
| B\-measure\-linux\-ptrace\-attach | 子边界 | Within linux\-ptrace\-attach compare validated local fixed\-window work with native and same\-backend run baselines; save raw samples and exact valid counts/window elapsed for latency and throughput\. | 已覆盖 |
| B\-measure\-linux\-ptrace\-run | 子边界 | Within linux\-ptrace\-run compare validated local fixed\-window work with native and same\-backend run baselines; save raw samples and exact valid counts/window elapsed for latency and throughput\. | 已覆盖 |
| B\-measure\-windows\-gum\-attach\-latency | 子边界 | Within windows\-gum\-attach\-latency preserve 50 validated snapshot command latency samples and phase labels; this is not the Linux mixed 64\-command workload\. | 已覆盖 |
| B\-measure\-windows\-gum\-attach\-throughput | 子边界 | Measure actual fixed\-window elapsed and 50 validated same\-fixture snapshot commands on windows\-gum\-attach; report commands/s separately from Linux mixed\-command throughput\. | 已覆盖 |
| B\-measure\-windows\-gum\-run\-latency | 子边界 | Within windows\-gum\-run\-latency preserve 50 validated snapshot command latency samples and phase labels; this is not the Linux mixed 64\-command workload\. | 已覆盖 |
| B\-measure\-windows\-gum\-run\-throughput | 子边界 | Measure actual fixed\-window elapsed and 50 validated same\-fixture snapshot commands on windows\-gum\-run; report commands/s separately from Linux mixed\-command throughput\. | 已覆盖 |
| O\-recovery | correctness / critical / required | Serve and manager loss preserve allowed business activity and report enforcement loss\. Fresh approved recovery reconnects compatible residue or safely seizes an untraced target; never stack injection\. / contract / docs/dynamic\-attach\.md and accepted PLAN\.md contract | 未覆盖 |
| B\-recovery\-committed\-cleanup\-protocol | 子边界 | After completed revocation plus ACK loss and manager death, fresh approved Detach may perform exact historical\-receipt cleanup without creating members; wrong identity/token/target and Attach are denied\. | 已覆盖 |
| B\-recovery\-deadroot\-cleanup\-linux\-gum | 子边界 | After original root and manager exit, approve cleanup by id and reconnect/detach exact live Gum descendants without injection\. | 未覆盖 |
| B\-recovery\-deadroot\-cleanup\-linux\-ptrace | 子边界 | After original root and manager exit, approve cleanup by id and detach live ptrace descendants without requiring dead\-root inspection\. | 未覆盖 |
| B\-recovery\-deadroot\-cleanup\-windows | 子边界 | After original root and manager exit, approve cleanup by id and detach exact live Windows descendants\. | 未覆盖 |
| B\-recovery\-dirty\-ptrace\-refusal | 子边界 | After ptrace manager loss with unproven virtual descriptor state, refuse unsafe recovery explicitly, keep target alive and do not silently seize or claim protection\. | 已覆盖 |
| B\-recovery\-manager\-linux\-gum | 子边界 | Kill only the disposable Gum manager, prove target/allowed traffic survives; fresh approval reconnects exact compatible Host with no new injection\. | 已覆盖 |
| B\-recovery\-manager\-linux\-ptrace | 子边界 | Kill only the disposable authenticated ptrace manager, prove target survives and enforcement loss is truthful; fresh approval safely reseizes with no duplicate tracer\. | 已覆盖 |
| B\-recovery\-manager\-windows | 子边界 | Kill only the authenticated disposable Windows manager; fresh approval reconnects exact resident Host and one native module\. | 已覆盖 |
| B\-recovery\-serve\-linux\-gum | 子边界 | Restart/lose Serve during active Gum tree; cached policy, allowed streams and subsequent approved lifecycle remain valid\. | 已覆盖 |
| B\-recovery\-serve\-linux\-ptrace | 子边界 | Restart/lose Serve during active ptrace tree; cached policy, allowed streams and subsequent approved lifecycle remain valid\. | 已覆盖 |
| B\-recovery\-serve\-windows | 子边界 | Restart/lose Serve during active Windows tree; cached policy, allowed streams and subsequent approved lifecycle remain valid\. | 未覆盖 |
| B\-recovery\-tighten\-before\-reactivate | 子边界 | Tighten a real deny policy while detached; the first covered operation after fresh approved reactivation must use the new policy synchronously\. | 未覆盖 |
| O\-release | correctness / critical / required | Isolate development binaries, Home, Skill and updates\. Explicit prerelease tags do not replace stable defaults\. Publish only after exact\-commit platform CI and soak success\. / contract / docs/dynamic\-attach\.md and accepted PLAN\.md contract | 未覆盖 |
| B\-release\-linux\-install | 子边界 | Linux explicit\-tag installer preserves stable sentinel and shortcut and uses development version directory\. | 已覆盖 |
| B\-release\-private\-cli | 子边界 | Built prerelease CLI selects private default HOME/Skill and manual updates without touching stable paths\. | 已覆盖 |
| B\-release\-public\-artifacts | 子边界 | Exact commit native platform CI and full soak pass; published prerelease is not latest; download all six artifacts and verify manifest/version/architecture/SHA and real operations\. | 未覆盖 |
| B\-release\-windows\-install | 子边界 | Windows explicit\-tag installer preserves stable executable, shortcut and user PATH\. | 已覆盖 |
| O\-resources | correctness / critical / required | At least 100 cycles and two hours of mixed activity per backend preserve semantics without continued native module, thread, FD or handle count growth after warmup\. / contract / docs/dynamic\-attach\.md and accepted PLAN\.md contract | 已覆盖 |
| B\-resources\-linux\-gum | 子边界 | Complete &gt;=100 successful cycles AND &gt;=7200 seconds of target mixed activity after readiness on linux\-gum; after warmup track native modules, threads and FDs/handles without continued growth\. | 已覆盖 |
| B\-resources\-linux\-ptrace | 子边界 | Complete &gt;=100 successful cycles AND &gt;=7200 seconds of target mixed activity after readiness on linux\-ptrace; after warmup track native modules, threads and FDs/handles without continued growth\. | 已覆盖 |
| B\-resources\-windows\-gum | 子边界 | Complete &gt;=100 successful cycles AND &gt;=7200 seconds of target mixed activity after readiness on windows\-gum; after warmup track native modules, threads and FDs/handles without continued growth\. | 已覆盖 |
| O\-tree | correctness / critical / required | Tree scope covers current threads, existing descendants and future descendants; process scope leaves other processes unmanaged\. Living descendants remain managed after root exit\. / contract / docs/dynamic\-attach\.md and accepted PLAN\.md contract | 未覆盖 |
| B\-tree\-detach\-epoch\-inheritance | 子边界 | fork/clone/rebuild descendants preserve the accepted detach cutoff and cannot replay an older/equal\-time Attach to reactivate policy\. | 未覆盖 |
| B\-tree\-linux\-gum\-process | 子边界 | Linux Gum process: deny target, permit separate existing/future descendants\. | 已覆盖 |
| B\-tree\-linux\-gum\-tree | 子边界 | Linux Gum tree: deny root and preexisting/fork/exec descendants\. | 已覆盖 |
| B\-tree\-linux\-ptrace\-process | 子边界 | Linux ptrace process: deny target, permit separate existing/future descendants\. | 已覆盖 |
| B\-tree\-linux\-ptrace\-tree | 子边界 | Linux ptrace tree: deny root and preexisting/fork/exec descendants\. | 已覆盖 |
| B\-tree\-rootexit\-linux\-gum | 子边界 | Owned Linux Gum run returns root exit 37 promptly while its survivor remains managed and can be detached\. | 已覆盖 |
| B\-tree\-rootexit\-linux\-ptrace | 子边界 | Owned Linux ptrace run returns root exit 37 promptly while its survivor remains managed and can be detached\. | 已覆盖 |
| B\-tree\-rootexit\-windows | 子边界 | Windows keeper preserves descendant enforcement and detach after original root exit\. | 已覆盖 |
| B\-tree\-threads\-boundary | 子边界 | Already running target threads and concurrent thread creation cannot escape at attach/detach boundaries on every backend\. | 未覆盖 |
| B\-tree\-windows\-creation\-boundary | 子边界 | Measure children alive or in\-flight across the actual Windows commit boundary; no reset may hide post\-commit allowed work\. | 未覆盖 |
| B\-tree\-windows\-existing | 子边界 | Hold a deterministic existing child alive before Windows attach; it must be denied after tree commit\. | 已覆盖 |
| B\-tree\-windows\-future | 子边界 | Windows approved tree denies post\-commit child exec and at least ten fresh native child reads\. | 已覆盖 |
| B\-tree\-windows\-msys\-fork | 子边界 | Native Windows lifecycle and approved tree cover MSYS/Cygwin fork/clone shared\-memory rebuild and metadata/Host identity rebinding; native Rust exec fixtures do not cover this ABI boundary\. | 未覆盖 |

### 组合覆盖

```json
[
  {
    "covered": 6,
    "fraction": 1.0,
    "id": "I-backend-origin",
    "missing": [],
    "obligation_ids": [
      "O-measure"
    ],
    "required": 6
  }
]
```

### 属性依据与允许结果

#### O\-approval

```json
{
  "allowed_outcomes": [
    "Only fresh human approval bound to exact process incarnation, instance, scope, backend, policy and bootstrap may mutate an external target. Proposal alone has no effect."
  ],
  "basis_evidence": [
    {
      "adoption_reference": null,
      "locator": "docs/dynamic-attach.md",
      "reference": "Accepted dynamic attachment plan",
      "role": "acceptance",
      "source_type": "project_contract",
      "verified_scope": "Only fresh human approval bound to exact process incarnation, instance, scope, backend, policy and bootstrap may mutate an external target. Proposal alone has no effect.",
      "version": "0.3.0-alpha.1 development contract"
    }
  ],
  "fault_ids": [
    "F01",
    "F03",
    "F04",
    "F06",
    "F11",
    "F13",
    "F15"
  ],
  "trigger_dimensions": [
    "identity",
    "state",
    "time",
    "version",
    "commit"
  ]
}
```

#### O\-continuity

```json
{
  "allowed_outcomes": [
    "Preserve allowed payloads, existing TCP, blocking original calls, socket flags, explicit child environments, PID, cwd, stdio, terminal state and original root exit status."
  ],
  "basis_evidence": [
    {
      "adoption_reference": null,
      "locator": "docs/dynamic-attach.md",
      "reference": "Accepted dynamic attachment plan",
      "role": "acceptance",
      "source_type": "project_contract",
      "verified_scope": "Preserve allowed payloads, existing TCP, blocking original calls, socket flags, explicit child environments, PID, cwd, stdio, terminal state and original root exit status.",
      "version": "0.3.0-alpha.1 development contract"
    }
  ],
  "fault_ids": [
    "F01",
    "F04",
    "F05",
    "F06",
    "F09",
    "F14"
  ],
  "trigger_dimensions": [
    "state",
    "concurrency",
    "environment",
    "dependency"
  ]
}
```

#### O\-drain

```json
{
  "allowed_outcomes": [
    "Approved detach stops new enforcement. Keep compatibility code while calls, async operations, trust contexts, callbacks or cached addresses need it. Detached requires independent physical-unload proof."
  ],
  "basis_evidence": [
    {
      "adoption_reference": null,
      "locator": "docs/dynamic-attach.md",
      "reference": "Accepted dynamic attachment plan",
      "role": "acceptance",
      "source_type": "project_contract",
      "verified_scope": "Approved detach stops new enforcement. Keep compatibility code while calls, async operations, trust contexts, callbacks or cached addresses need it. Detached requires independent physical-unload proof.",
      "version": "0.3.0-alpha.1 development contract"
    }
  ],
  "fault_ids": [
    "F02",
    "F04",
    "F05",
    "F07",
    "F09",
    "F13"
  ],
  "trigger_dimensions": [
    "state",
    "concurrency",
    "resource",
    "recovery"
  ]
}
```

#### O\-fake

```json
{
  "allowed_outcomes": [
    "Previously cached FAKE-IP aliases remain usable across detach and reattach. Do not reassign an address to another destination while application caches may retain it."
  ],
  "basis_evidence": [
    {
      "adoption_reference": null,
      "locator": "docs/dynamic-attach.md",
      "reference": "Accepted dynamic attachment plan",
      "role": "acceptance",
      "source_type": "project_contract",
      "verified_scope": "Previously cached FAKE-IP aliases remain usable across detach and reattach. Do not reassign an address to another destination while application caches may retain it.",
      "version": "0.3.0-alpha.1 development contract"
    }
  ],
  "fault_ids": [
    "F04",
    "F07",
    "F13"
  ],
  "trigger_dimensions": [
    "state",
    "identity",
    "recovery"
  ]
}
```

#### O\-measure

```json
{
  "allowed_outcomes": [
    "Compare each platform declared workload within unmanaged, same-backend run, Active and Detached phases; Linux uses 32 snapshot/socket pairs and Windows uses 50 snapshot commands. Keep raw latency and valid-throughput timing separate from approval duration and do not compare different workload units as one cross-platform result."
  ],
  "basis_evidence": [
    {
      "adoption_reference": null,
      "locator": "docs/dynamic-attach.md",
      "reference": "Accepted dynamic attachment plan",
      "role": "acceptance",
      "source_type": "project_contract",
      "verified_scope": "Compare identical validated snapshot/socket work in unmanaged, same-backend run, Active and Detached windows. Separate raw command latency and valid throughput from approval duration. No universal performance threshold.",
      "version": "0.3.0-alpha.1 development contract"
    }
  ],
  "fault_ids": [
    "F02",
    "F08",
    "F16"
  ],
  "trigger_dimensions": [
    "time",
    "resource",
    "environment"
  ]
}
```

#### O\-recovery

```json
{
  "allowed_outcomes": [
    "Serve and manager loss preserve allowed business activity and report enforcement loss. Fresh approved recovery reconnects compatible residue or safely seizes an untraced target; never stack injection."
  ],
  "basis_evidence": [
    {
      "adoption_reference": null,
      "locator": "docs/dynamic-attach.md",
      "reference": "Accepted dynamic attachment plan",
      "role": "acceptance",
      "source_type": "project_contract",
      "verified_scope": "Serve and manager loss preserve allowed business activity and report enforcement loss. Fresh approved recovery reconnects compatible residue or safely seizes an untraced target; never stack injection.",
      "version": "0.3.0-alpha.1 development contract"
    }
  ],
  "fault_ids": [
    "F06",
    "F09",
    "F10",
    "F11",
    "F12",
    "F16"
  ],
  "trigger_dimensions": [
    "dependency",
    "commit",
    "recovery",
    "state"
  ]
}
```

#### O\-release

```json
{
  "allowed_outcomes": [
    "Isolate development binaries, Home, Skill and updates. Explicit prerelease tags do not replace stable defaults. Publish only after exact-commit platform CI and soak success."
  ],
  "basis_evidence": [
    {
      "adoption_reference": null,
      "locator": "docs/dynamic-attach.md",
      "reference": "Accepted dynamic attachment plan",
      "role": "acceptance",
      "source_type": "project_contract",
      "verified_scope": "Isolate development binaries, Home, Skill and updates. Explicit prerelease tags do not replace stable defaults. Publish only after exact-commit platform CI and soak success.",
      "version": "0.3.0-alpha.1 development contract"
    }
  ],
  "fault_ids": [
    "F03",
    "F13",
    "F14",
    "F15",
    "F16"
  ],
  "trigger_dimensions": [
    "environment",
    "version",
    "commit"
  ]
}
```

#### O\-resources

```json
{
  "allowed_outcomes": [
    "At least 100 cycles and two hours of mixed activity per backend preserve semantics without continued native module, thread, FD or handle count growth after warmup."
  ],
  "basis_evidence": [
    {
      "adoption_reference": null,
      "locator": "docs/dynamic-attach.md",
      "reference": "Accepted dynamic attachment plan",
      "role": "acceptance",
      "source_type": "project_contract",
      "verified_scope": "At least 100 cycles and two hours of mixed activity per backend preserve semantics without continued native module, thread, FD or handle count growth after warmup.",
      "version": "0.3.0-alpha.1 development contract"
    }
  ],
  "fault_ids": [
    "F07",
    "F08",
    "F16"
  ],
  "trigger_dimensions": [
    "resource",
    "capacity",
    "state",
    "time"
  ]
}
```

#### O\-tree

```json
{
  "allowed_outcomes": [
    "Tree scope covers current threads, existing descendants and future descendants; process scope leaves other processes unmanaged. Living descendants remain managed after root exit."
  ],
  "basis_evidence": [
    {
      "adoption_reference": null,
      "locator": "docs/dynamic-attach.md",
      "reference": "Accepted dynamic attachment plan",
      "role": "acceptance",
      "source_type": "project_contract",
      "verified_scope": "Tree scope covers current threads, existing descendants and future descendants; process scope leaves other processes unmanaged. Living descendants remain managed after root exit.",
      "version": "0.3.0-alpha.1 development contract"
    }
  ],
  "fault_ids": [
    "F01",
    "F04",
    "F05",
    "F13"
  ],
  "trigger_dimensions": [
    "identity",
    "concurrency",
    "state"
  ]
}
```

### 类别审查与类别覆盖

各阶段类别覆盖要求该类别关联的义务均达到对应阶段；目录审查完成率不能替代义务或子边界覆盖。

| 阶段 | 类别审查完成 | 适用类别覆盖 |
|---|---|---|
| 设计 | 完成 | 16/16 |
| 实现 | 完成 | 1/16 |
| 申报执行 | 完成 | 0/16 |
| 申报有效测量 | 完成 | 0/16 |

### 工作负载覆盖与范围一致性

#### 设计

```json
{
  "covered": 1,
  "items": [
    {
      "case_ids": [
        "C-approval",
        "C-cached-alias-linux-gum",
        "C-cached-alias-linux-ptrace",
        "C-capability-preflight",
        "C-committed-cleanup-recovery",
        "C-completion-protocol",
        "C-continuity",
        "C-core-approval-boundaries",
        "C-development-isolation",
        "C-dirty-ptrace-recovery-refusal",
        "C-drain",
        "C-fake",
        "C-linux-gum-process",
        "C-linux-host-peer",
        "C-linux-ptrace-process",
        "C-manager-recovery-linux-gum",
        "C-manager-recovery-linux-ptrace",
        "C-native-linux-gum-attach",
        "C-native-linux-gum-run",
        "C-native-linux-ptrace-attach",
        "C-native-linux-ptrace-run",
        "C-native-windows-gum",
        "C-recovery",
        "C-release",
        "C-resources",
        "C-rootexit-linux-gum",
        "C-rootexit-linux-ptrace",
        "C-serve-restart-linux-gum",
        "C-serve-restart-linux-ptrace",
        "C-soak-linux-gum",
        "C-soak-linux-ptrace",
        "C-soak-windows-gum",
        "C-terminal-slot-race",
        "C-tree",
        "C-windows-installer-isolation",
        "P-linux-gum-attach",
        "P-linux-gum-run",
        "P-linux-ptrace-attach",
        "P-linux-ptrace-run",
        "P-windows-gum-attach",
        "P-windows-gum-attach-snapshot-latency",
        "P-windows-gum-run",
        "P-windows-gum-run-snapshot-latency"
      ],
      "covered": true,
      "goal": "Approved attach, detach, reattach and fault recovery for local process trees.",
      "id": "W-attachment",
      "missing_atoms": [],
      "role": "primary",
      "unresolved_obligations": []
    }
  ],
  "missing": [],
  "mode": "structured",
  "required": 1,
  "scope_aligned": true
}
```

#### 实现

```json
{
  "covered": 0,
  "items": [
    {
      "case_ids": [
        "C-capability-preflight",
        "C-committed-cleanup-recovery",
        "C-completion-protocol",
        "C-core-approval-boundaries",
        "C-development-isolation",
        "C-dirty-ptrace-recovery-refusal",
        "C-linux-gum-process",
        "C-linux-host-peer",
        "C-linux-ptrace-process",
        "C-manager-recovery-linux-gum",
        "C-manager-recovery-linux-ptrace",
        "C-native-linux-gum-attach",
        "C-native-linux-gum-run",
        "C-native-linux-ptrace-attach",
        "C-native-linux-ptrace-run",
        "C-native-windows-gum",
        "C-rootexit-linux-gum",
        "C-rootexit-linux-ptrace",
        "C-serve-restart-linux-gum",
        "C-serve-restart-linux-ptrace",
        "C-soak-linux-gum",
        "C-soak-linux-ptrace",
        "C-soak-windows-gum",
        "C-terminal-slot-race",
        "C-windows-installer-isolation",
        "P-linux-gum-attach",
        "P-linux-gum-run",
        "P-linux-ptrace-attach",
        "P-linux-ptrace-run",
        "P-windows-gum-attach-snapshot-latency",
        "P-windows-gum-run-snapshot-latency"
      ],
      "covered": false,
      "goal": "Approved attach, detach, reattach and fault recovery for local process trees.",
      "id": "W-attachment",
      "missing_atoms": [
        {
          "boundary_id": "B-approval-accepted-history-integrity",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-cold-unenrolled",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-core-pinned-root",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-host-peer-windows",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-host-pinned-root",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-rotation-chain",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-trusted-enrollment",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-continuity-owned-ready-failure",
          "obligation_id": "O-continuity"
        },
        {
          "boundary_id": "B-continuity-owned-wait",
          "obligation_id": "O-continuity"
        },
        {
          "boundary_id": "B-continuity-windows-terminal",
          "obligation_id": "O-continuity"
        },
        {
          "boundary_id": "B-drain-linux-gum-physical",
          "obligation_id": "O-drain"
        },
        {
          "boundary_id": "B-drain-linux-ptrace-physical",
          "obligation_id": "O-drain"
        },
        {
          "boundary_id": "B-drain-windows-physical",
          "obligation_id": "O-drain"
        },
        {
          "boundary_id": "B-fake-linux-gum",
          "obligation_id": "O-fake"
        },
        {
          "boundary_id": "B-fake-linux-gum-issued",
          "obligation_id": "O-fake"
        },
        {
          "boundary_id": "B-fake-linux-gum-nonreuse",
          "obligation_id": "O-fake"
        },
        {
          "boundary_id": "B-fake-linux-ptrace",
          "obligation_id": "O-fake"
        },
        {
          "boundary_id": "B-fake-linux-ptrace-issued",
          "obligation_id": "O-fake"
        },
        {
          "boundary_id": "B-fake-linux-ptrace-nonreuse",
          "obligation_id": "O-fake"
        },
        {
          "boundary_id": "B-fake-windows-gum",
          "obligation_id": "O-fake"
        },
        {
          "boundary_id": "B-recovery-deadroot-cleanup-linux-gum",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-deadroot-cleanup-linux-ptrace",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-deadroot-cleanup-windows",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-serve-windows",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-tighten-before-reactivate",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-release-public-artifacts",
          "obligation_id": "O-release"
        },
        {
          "boundary_id": "B-tree-detach-epoch-inheritance",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-threads-boundary",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-windows-creation-boundary",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-windows-msys-fork",
          "obligation_id": "O-tree"
        }
      ],
      "role": "primary",
      "unresolved_obligations": []
    }
  ],
  "missing": [
    "W-attachment"
  ],
  "mode": "structured",
  "required": 1,
  "scope_aligned": true
}
```

#### 申报执行

```json
{
  "covered": 0,
  "items": [
    {
      "case_ids": [],
      "covered": false,
      "goal": "Approved attach, detach, reattach and fault recovery for local process trees.",
      "id": "W-attachment",
      "missing_atoms": [
        {
          "boundary_id": "B-approval-accepted-history-integrity",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-api-only",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-capability-preflight",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-cold-unenrolled",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-core-pinned-root",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-fresh-single-use",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-host-peer-linux",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-host-peer-windows",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-host-pinned-root",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-proposal-linux-gum",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-proposal-linux-ptrace",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-proposal-windows-gum",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-rotation-chain",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-rotation-envelopes",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-signed-bindings",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-terminal-slot-renewal",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-trusted-enrollment",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-continuity-linux-gum-identity",
          "obligation_id": "O-continuity"
        },
        {
          "boundary_id": "B-continuity-linux-gum-io",
          "obligation_id": "O-continuity"
        },
        {
          "boundary_id": "B-continuity-linux-gum-terminal",
          "obligation_id": "O-continuity"
        },
        {
          "boundary_id": "B-continuity-linux-ptrace-identity",
          "obligation_id": "O-continuity"
        },
        {
          "boundary_id": "B-continuity-linux-ptrace-io",
          "obligation_id": "O-continuity"
        },
        {
          "boundary_id": "B-continuity-linux-ptrace-terminal",
          "obligation_id": "O-continuity"
        },
        {
          "boundary_id": "B-continuity-owned-ready-failure",
          "obligation_id": "O-continuity"
        },
        {
          "boundary_id": "B-continuity-owned-wait",
          "obligation_id": "O-continuity"
        },
        {
          "boundary_id": "B-continuity-windows-identity",
          "obligation_id": "O-continuity"
        },
        {
          "boundary_id": "B-continuity-windows-io",
          "obligation_id": "O-continuity"
        },
        {
          "boundary_id": "B-continuity-windows-terminal",
          "obligation_id": "O-continuity"
        },
        {
          "boundary_id": "B-drain-completion-protocol",
          "obligation_id": "O-drain"
        },
        {
          "boundary_id": "B-drain-linux-gum-blocked",
          "obligation_id": "O-drain"
        },
        {
          "boundary_id": "B-drain-linux-gum-physical",
          "obligation_id": "O-drain"
        },
        {
          "boundary_id": "B-drain-linux-ptrace-blocked",
          "obligation_id": "O-drain"
        },
        {
          "boundary_id": "B-drain-linux-ptrace-physical",
          "obligation_id": "O-drain"
        },
        {
          "boundary_id": "B-drain-windows-blocked-trust",
          "obligation_id": "O-drain"
        },
        {
          "boundary_id": "B-drain-windows-physical",
          "obligation_id": "O-drain"
        },
        {
          "boundary_id": "B-fake-linux-gum",
          "obligation_id": "O-fake"
        },
        {
          "boundary_id": "B-fake-linux-gum-issued",
          "obligation_id": "O-fake"
        },
        {
          "boundary_id": "B-fake-linux-gum-nonreuse",
          "obligation_id": "O-fake"
        },
        {
          "boundary_id": "B-fake-linux-ptrace",
          "obligation_id": "O-fake"
        },
        {
          "boundary_id": "B-fake-linux-ptrace-issued",
          "obligation_id": "O-fake"
        },
        {
          "boundary_id": "B-fake-linux-ptrace-nonreuse",
          "obligation_id": "O-fake"
        },
        {
          "boundary_id": "B-fake-windows-gum",
          "obligation_id": "O-fake"
        },
        {
          "boundary_id": "B-measure-linux-gum-attach",
          "obligation_id": "O-measure"
        },
        {
          "boundary_id": "B-measure-linux-gum-run",
          "obligation_id": "O-measure"
        },
        {
          "boundary_id": "B-measure-linux-ptrace-attach",
          "obligation_id": "O-measure"
        },
        {
          "boundary_id": "B-measure-linux-ptrace-run",
          "obligation_id": "O-measure"
        },
        {
          "boundary_id": "B-measure-windows-gum-attach-latency",
          "obligation_id": "O-measure"
        },
        {
          "boundary_id": "B-measure-windows-gum-attach-throughput",
          "obligation_id": "O-measure"
        },
        {
          "boundary_id": "B-measure-windows-gum-run-latency",
          "obligation_id": "O-measure"
        },
        {
          "boundary_id": "B-measure-windows-gum-run-throughput",
          "obligation_id": "O-measure"
        },
        {
          "boundary_id": "B-recovery-committed-cleanup-protocol",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-deadroot-cleanup-linux-gum",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-deadroot-cleanup-linux-ptrace",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-deadroot-cleanup-windows",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-dirty-ptrace-refusal",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-manager-linux-gum",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-manager-linux-ptrace",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-manager-windows",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-serve-linux-gum",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-serve-linux-ptrace",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-serve-windows",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-tighten-before-reactivate",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-release-linux-install",
          "obligation_id": "O-release"
        },
        {
          "boundary_id": "B-release-private-cli",
          "obligation_id": "O-release"
        },
        {
          "boundary_id": "B-release-public-artifacts",
          "obligation_id": "O-release"
        },
        {
          "boundary_id": "B-release-windows-install",
          "obligation_id": "O-release"
        },
        {
          "boundary_id": "B-resources-linux-gum",
          "obligation_id": "O-resources"
        },
        {
          "boundary_id": "B-resources-linux-ptrace",
          "obligation_id": "O-resources"
        },
        {
          "boundary_id": "B-resources-windows-gum",
          "obligation_id": "O-resources"
        },
        {
          "boundary_id": "B-tree-detach-epoch-inheritance",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-linux-gum-process",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-linux-gum-tree",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-linux-ptrace-process",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-linux-ptrace-tree",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-rootexit-linux-gum",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-rootexit-linux-ptrace",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-rootexit-windows",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-threads-boundary",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-windows-creation-boundary",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-windows-existing",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-windows-future",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-windows-msys-fork",
          "obligation_id": "O-tree"
        }
      ],
      "role": "primary",
      "unresolved_obligations": []
    }
  ],
  "missing": [
    "W-attachment"
  ],
  "mode": "structured",
  "required": 1,
  "scope_aligned": true
}
```

#### 申报有效测量

```json
{
  "covered": 0,
  "items": [
    {
      "case_ids": [],
      "covered": false,
      "goal": "Approved attach, detach, reattach and fault recovery for local process trees.",
      "id": "W-attachment",
      "missing_atoms": [
        {
          "boundary_id": "B-approval-accepted-history-integrity",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-api-only",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-capability-preflight",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-cold-unenrolled",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-core-pinned-root",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-fresh-single-use",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-host-peer-linux",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-host-peer-windows",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-host-pinned-root",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-proposal-linux-gum",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-proposal-linux-ptrace",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-proposal-windows-gum",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-rotation-chain",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-rotation-envelopes",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-signed-bindings",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-terminal-slot-renewal",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-approval-trusted-enrollment",
          "obligation_id": "O-approval"
        },
        {
          "boundary_id": "B-continuity-linux-gum-identity",
          "obligation_id": "O-continuity"
        },
        {
          "boundary_id": "B-continuity-linux-gum-io",
          "obligation_id": "O-continuity"
        },
        {
          "boundary_id": "B-continuity-linux-gum-terminal",
          "obligation_id": "O-continuity"
        },
        {
          "boundary_id": "B-continuity-linux-ptrace-identity",
          "obligation_id": "O-continuity"
        },
        {
          "boundary_id": "B-continuity-linux-ptrace-io",
          "obligation_id": "O-continuity"
        },
        {
          "boundary_id": "B-continuity-linux-ptrace-terminal",
          "obligation_id": "O-continuity"
        },
        {
          "boundary_id": "B-continuity-owned-ready-failure",
          "obligation_id": "O-continuity"
        },
        {
          "boundary_id": "B-continuity-owned-wait",
          "obligation_id": "O-continuity"
        },
        {
          "boundary_id": "B-continuity-windows-identity",
          "obligation_id": "O-continuity"
        },
        {
          "boundary_id": "B-continuity-windows-io",
          "obligation_id": "O-continuity"
        },
        {
          "boundary_id": "B-continuity-windows-terminal",
          "obligation_id": "O-continuity"
        },
        {
          "boundary_id": "B-drain-completion-protocol",
          "obligation_id": "O-drain"
        },
        {
          "boundary_id": "B-drain-linux-gum-blocked",
          "obligation_id": "O-drain"
        },
        {
          "boundary_id": "B-drain-linux-gum-physical",
          "obligation_id": "O-drain"
        },
        {
          "boundary_id": "B-drain-linux-ptrace-blocked",
          "obligation_id": "O-drain"
        },
        {
          "boundary_id": "B-drain-linux-ptrace-physical",
          "obligation_id": "O-drain"
        },
        {
          "boundary_id": "B-drain-windows-blocked-trust",
          "obligation_id": "O-drain"
        },
        {
          "boundary_id": "B-drain-windows-physical",
          "obligation_id": "O-drain"
        },
        {
          "boundary_id": "B-fake-linux-gum",
          "obligation_id": "O-fake"
        },
        {
          "boundary_id": "B-fake-linux-gum-issued",
          "obligation_id": "O-fake"
        },
        {
          "boundary_id": "B-fake-linux-gum-nonreuse",
          "obligation_id": "O-fake"
        },
        {
          "boundary_id": "B-fake-linux-ptrace",
          "obligation_id": "O-fake"
        },
        {
          "boundary_id": "B-fake-linux-ptrace-issued",
          "obligation_id": "O-fake"
        },
        {
          "boundary_id": "B-fake-linux-ptrace-nonreuse",
          "obligation_id": "O-fake"
        },
        {
          "boundary_id": "B-fake-windows-gum",
          "obligation_id": "O-fake"
        },
        {
          "boundary_id": "B-measure-linux-gum-attach",
          "obligation_id": "O-measure"
        },
        {
          "boundary_id": "B-measure-linux-gum-run",
          "obligation_id": "O-measure"
        },
        {
          "boundary_id": "B-measure-linux-ptrace-attach",
          "obligation_id": "O-measure"
        },
        {
          "boundary_id": "B-measure-linux-ptrace-run",
          "obligation_id": "O-measure"
        },
        {
          "boundary_id": "B-measure-windows-gum-attach-latency",
          "obligation_id": "O-measure"
        },
        {
          "boundary_id": "B-measure-windows-gum-attach-throughput",
          "obligation_id": "O-measure"
        },
        {
          "boundary_id": "B-measure-windows-gum-run-latency",
          "obligation_id": "O-measure"
        },
        {
          "boundary_id": "B-measure-windows-gum-run-throughput",
          "obligation_id": "O-measure"
        },
        {
          "boundary_id": "B-recovery-committed-cleanup-protocol",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-deadroot-cleanup-linux-gum",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-deadroot-cleanup-linux-ptrace",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-deadroot-cleanup-windows",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-dirty-ptrace-refusal",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-manager-linux-gum",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-manager-linux-ptrace",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-manager-windows",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-serve-linux-gum",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-serve-linux-ptrace",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-serve-windows",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-recovery-tighten-before-reactivate",
          "obligation_id": "O-recovery"
        },
        {
          "boundary_id": "B-release-linux-install",
          "obligation_id": "O-release"
        },
        {
          "boundary_id": "B-release-private-cli",
          "obligation_id": "O-release"
        },
        {
          "boundary_id": "B-release-public-artifacts",
          "obligation_id": "O-release"
        },
        {
          "boundary_id": "B-release-windows-install",
          "obligation_id": "O-release"
        },
        {
          "boundary_id": "B-resources-linux-gum",
          "obligation_id": "O-resources"
        },
        {
          "boundary_id": "B-resources-linux-ptrace",
          "obligation_id": "O-resources"
        },
        {
          "boundary_id": "B-resources-windows-gum",
          "obligation_id": "O-resources"
        },
        {
          "boundary_id": "B-tree-detach-epoch-inheritance",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-linux-gum-process",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-linux-gum-tree",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-linux-ptrace-process",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-linux-ptrace-tree",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-rootexit-linux-gum",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-rootexit-linux-ptrace",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-rootexit-windows",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-threads-boundary",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-windows-creation-boundary",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-windows-existing",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-windows-future",
          "obligation_id": "O-tree"
        },
        {
          "boundary_id": "B-tree-windows-msys-fork",
          "obligation_id": "O-tree"
        }
      ],
      "role": "primary",
      "unresolved_obligations": []
    }
  ],
  "missing": [
    "W-attachment"
  ],
  "mode": "structured",
  "required": 1,
  "scope_aligned": true
}
```

### 性能验收申报

```json
{}
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
  "boundaries": [
    "B-approval-accepted-history-integrity",
    "B-approval-cold-unenrolled",
    "B-approval-core-pinned-root",
    "B-approval-host-peer-windows",
    "B-approval-host-pinned-root",
    "B-approval-rotation-chain",
    "B-approval-trusted-enrollment",
    "B-continuity-owned-ready-failure",
    "B-continuity-owned-wait",
    "B-continuity-windows-terminal",
    "B-drain-linux-gum-physical",
    "B-drain-linux-ptrace-physical",
    "B-drain-windows-physical",
    "B-fake-linux-gum",
    "B-fake-linux-gum-issued",
    "B-fake-linux-gum-nonreuse",
    "B-fake-linux-ptrace",
    "B-fake-linux-ptrace-issued",
    "B-fake-linux-ptrace-nonreuse",
    "B-fake-windows-gum",
    "B-recovery-deadroot-cleanup-linux-gum",
    "B-recovery-deadroot-cleanup-linux-ptrace",
    "B-recovery-deadroot-cleanup-windows",
    "B-recovery-serve-windows",
    "B-recovery-tighten-before-reactivate",
    "B-release-public-artifacts",
    "B-tree-detach-epoch-inheritance",
    "B-tree-threads-boundary",
    "B-tree-windows-creation-boundary",
    "B-tree-windows-msys-fork"
  ],
  "interactions": [],
  "obligations": [
    "O-approval",
    "O-continuity",
    "O-drain",
    "O-fake",
    "O-recovery",
    "O-release",
    "O-tree"
  ],
  "scope_aligned": true,
  "workloads": [
    "W-attachment"
  ]
}
```

### 申报执行缺口

```json
{
  "boundaries": [
    "B-approval-accepted-history-integrity",
    "B-approval-api-only",
    "B-approval-capability-preflight",
    "B-approval-cold-unenrolled",
    "B-approval-core-pinned-root",
    "B-approval-fresh-single-use",
    "B-approval-host-peer-linux",
    "B-approval-host-peer-windows",
    "B-approval-host-pinned-root",
    "B-approval-proposal-linux-gum",
    "B-approval-proposal-linux-ptrace",
    "B-approval-proposal-windows-gum",
    "B-approval-rotation-chain",
    "B-approval-rotation-envelopes",
    "B-approval-signed-bindings",
    "B-approval-terminal-slot-renewal",
    "B-approval-trusted-enrollment",
    "B-continuity-linux-gum-identity",
    "B-continuity-linux-gum-io",
    "B-continuity-linux-gum-terminal",
    "B-continuity-linux-ptrace-identity",
    "B-continuity-linux-ptrace-io",
    "B-continuity-linux-ptrace-terminal",
    "B-continuity-owned-ready-failure",
    "B-continuity-owned-wait",
    "B-continuity-windows-identity",
    "B-continuity-windows-io",
    "B-continuity-windows-terminal",
    "B-drain-completion-protocol",
    "B-drain-linux-gum-blocked",
    "B-drain-linux-gum-physical",
    "B-drain-linux-ptrace-blocked",
    "B-drain-linux-ptrace-physical",
    "B-drain-windows-blocked-trust",
    "B-drain-windows-physical",
    "B-fake-linux-gum",
    "B-fake-linux-gum-issued",
    "B-fake-linux-gum-nonreuse",
    "B-fake-linux-ptrace",
    "B-fake-linux-ptrace-issued",
    "B-fake-linux-ptrace-nonreuse",
    "B-fake-windows-gum",
    "B-measure-linux-gum-attach",
    "B-measure-linux-gum-run",
    "B-measure-linux-ptrace-attach",
    "B-measure-linux-ptrace-run",
    "B-measure-windows-gum-attach-latency",
    "B-measure-windows-gum-attach-throughput",
    "B-measure-windows-gum-run-latency",
    "B-measure-windows-gum-run-throughput",
    "B-recovery-committed-cleanup-protocol",
    "B-recovery-deadroot-cleanup-linux-gum",
    "B-recovery-deadroot-cleanup-linux-ptrace",
    "B-recovery-deadroot-cleanup-windows",
    "B-recovery-dirty-ptrace-refusal",
    "B-recovery-manager-linux-gum",
    "B-recovery-manager-linux-ptrace",
    "B-recovery-manager-windows",
    "B-recovery-serve-linux-gum",
    "B-recovery-serve-linux-ptrace",
    "B-recovery-serve-windows",
    "B-recovery-tighten-before-reactivate",
    "B-release-linux-install",
    "B-release-private-cli",
    "B-release-public-artifacts",
    "B-release-windows-install",
    "B-resources-linux-gum",
    "B-resources-linux-ptrace",
    "B-resources-windows-gum",
    "B-tree-detach-epoch-inheritance",
    "B-tree-linux-gum-process",
    "B-tree-linux-gum-tree",
    "B-tree-linux-ptrace-process",
    "B-tree-linux-ptrace-tree",
    "B-tree-rootexit-linux-gum",
    "B-tree-rootexit-linux-ptrace",
    "B-tree-rootexit-windows",
    "B-tree-threads-boundary",
    "B-tree-windows-creation-boundary",
    "B-tree-windows-existing",
    "B-tree-windows-future",
    "B-tree-windows-msys-fork"
  ],
  "interactions": [
    {
      "id": "I-backend-origin",
      "missing": [
        {
          "backend": "linux-gum",
          "origin": "attach"
        },
        {
          "backend": "linux-gum",
          "origin": "run"
        },
        {
          "backend": "linux-ptrace",
          "origin": "attach"
        },
        {
          "backend": "linux-ptrace",
          "origin": "run"
        },
        {
          "backend": "windows-gum",
          "origin": "attach"
        },
        {
          "backend": "windows-gum",
          "origin": "run"
        }
      ]
    }
  ],
  "obligations": [
    "O-approval",
    "O-continuity",
    "O-drain",
    "O-fake",
    "O-measure",
    "O-recovery",
    "O-release",
    "O-resources",
    "O-tree"
  ],
  "scope_aligned": true,
  "workloads": [
    "W-attachment"
  ]
}
```

### 申报有效测量缺口

```json
{
  "boundaries": [
    "B-approval-accepted-history-integrity",
    "B-approval-api-only",
    "B-approval-capability-preflight",
    "B-approval-cold-unenrolled",
    "B-approval-core-pinned-root",
    "B-approval-fresh-single-use",
    "B-approval-host-peer-linux",
    "B-approval-host-peer-windows",
    "B-approval-host-pinned-root",
    "B-approval-proposal-linux-gum",
    "B-approval-proposal-linux-ptrace",
    "B-approval-proposal-windows-gum",
    "B-approval-rotation-chain",
    "B-approval-rotation-envelopes",
    "B-approval-signed-bindings",
    "B-approval-terminal-slot-renewal",
    "B-approval-trusted-enrollment",
    "B-continuity-linux-gum-identity",
    "B-continuity-linux-gum-io",
    "B-continuity-linux-gum-terminal",
    "B-continuity-linux-ptrace-identity",
    "B-continuity-linux-ptrace-io",
    "B-continuity-linux-ptrace-terminal",
    "B-continuity-owned-ready-failure",
    "B-continuity-owned-wait",
    "B-continuity-windows-identity",
    "B-continuity-windows-io",
    "B-continuity-windows-terminal",
    "B-drain-completion-protocol",
    "B-drain-linux-gum-blocked",
    "B-drain-linux-gum-physical",
    "B-drain-linux-ptrace-blocked",
    "B-drain-linux-ptrace-physical",
    "B-drain-windows-blocked-trust",
    "B-drain-windows-physical",
    "B-fake-linux-gum",
    "B-fake-linux-gum-issued",
    "B-fake-linux-gum-nonreuse",
    "B-fake-linux-ptrace",
    "B-fake-linux-ptrace-issued",
    "B-fake-linux-ptrace-nonreuse",
    "B-fake-windows-gum",
    "B-measure-linux-gum-attach",
    "B-measure-linux-gum-run",
    "B-measure-linux-ptrace-attach",
    "B-measure-linux-ptrace-run",
    "B-measure-windows-gum-attach-latency",
    "B-measure-windows-gum-attach-throughput",
    "B-measure-windows-gum-run-latency",
    "B-measure-windows-gum-run-throughput",
    "B-recovery-committed-cleanup-protocol",
    "B-recovery-deadroot-cleanup-linux-gum",
    "B-recovery-deadroot-cleanup-linux-ptrace",
    "B-recovery-deadroot-cleanup-windows",
    "B-recovery-dirty-ptrace-refusal",
    "B-recovery-manager-linux-gum",
    "B-recovery-manager-linux-ptrace",
    "B-recovery-manager-windows",
    "B-recovery-serve-linux-gum",
    "B-recovery-serve-linux-ptrace",
    "B-recovery-serve-windows",
    "B-recovery-tighten-before-reactivate",
    "B-release-linux-install",
    "B-release-private-cli",
    "B-release-public-artifacts",
    "B-release-windows-install",
    "B-resources-linux-gum",
    "B-resources-linux-ptrace",
    "B-resources-windows-gum",
    "B-tree-detach-epoch-inheritance",
    "B-tree-linux-gum-process",
    "B-tree-linux-gum-tree",
    "B-tree-linux-ptrace-process",
    "B-tree-linux-ptrace-tree",
    "B-tree-rootexit-linux-gum",
    "B-tree-rootexit-linux-ptrace",
    "B-tree-rootexit-windows",
    "B-tree-threads-boundary",
    "B-tree-windows-creation-boundary",
    "B-tree-windows-existing",
    "B-tree-windows-future",
    "B-tree-windows-msys-fork"
  ],
  "interactions": [
    {
      "id": "I-backend-origin",
      "missing": [
        {
          "backend": "linux-gum",
          "origin": "attach"
        },
        {
          "backend": "linux-gum",
          "origin": "run"
        },
        {
          "backend": "linux-ptrace",
          "origin": "attach"
        },
        {
          "backend": "linux-ptrace",
          "origin": "run"
        },
        {
          "backend": "windows-gum",
          "origin": "attach"
        },
        {
          "backend": "windows-gum",
          "origin": "run"
        }
      ]
    }
  ],
  "obligations": [
    "O-approval",
    "O-continuity",
    "O-drain",
    "O-fake",
    "O-measure",
    "O-recovery",
    "O-release",
    "O-resources",
    "O-tree"
  ],
  "scope_aligned": true,
  "workloads": [
    "W-attachment"
  ]
}
```

### 假设、排除与粒度限制

```json
{
  "coarse_obligations": [],
  "conditional_obligations": [],
  "excluded_obligations": [],
  "unresolved_obligations": []
}
```

未声明子边界的义务只有父项粒度；这些比例不能证明其内部边界全部覆盖。触发与断言引用仍需语义审查。

- DRAFT REVIEW SNAPSHOT ONLY: source is still changing\. The digest binds this manifest snapshot, not a final release/source freeze; refresh and independently review changed references before actual benchmark execution\.
- No run\.json is synthesized\. Existing r1/r2/r3 diagnostic evidence predates this model and remains diagnostic, including known failures; no record is promoted to frozen execution or valid measurement\.
- All nine original obligations and all six backend/origin combinations remain required\. Added explicit sub\-boundaries prevent one implemented path from completing unrelated platform or safety boundaries\.
- Native Windows, aarch64 hardware attachment, 100cycle/two\-hour backend soaks and exact\-commit release CI/publication remain separate execution gates; structural checker success is not native execution\.
- Windows future\-child stress resets counters after Active and does not independently prove a deterministic preexisting child or allowed/denied outcomes exactly across commit\. Those two native boundaries remain planned\.
- Linux fixed window is32 snapshot/socket pairs=64 commands; Windows fixed window is50 snapshots\. Both collectors now have elapsed timing, but cross\-invocation same\-backend run comparison protocol remains planned on Windows; latency\-only implemented mappings do not complete throughput comparison obligations\.
- Current resource drivers now have post\-readiness clocks, concrete loop minima, mixed\-work assertions and native resource plateaus\. Their source implementation is bound in C\-soak cases; no100cycle/7200second execution or valid measurement is declared\. Windows bounded slack is the explicit code contract \(\+8 handles/\+1 thread\), distinct from Linux exact post\-warmup FD/thread/map counts\.
- Windows MSYS/Cygwin fork/clone lifecycle is an explicit planned boundary\. Native Rust CreateProcess/exec and native console fixtures cannot satisfy it\.
- Approval root anchoring is still a read\-only interface design\. Core/Host pinned roots, API\-only cold Unenrolled state, trusted first enrollment, signed rotation chain and accepted\-history integrity remain planned release gates\. Existing crypto tests against a mutable verifier are not proof of those properties\.
- ObservedExternal and HyperHub\-issued addresses require separate native\-equivalence oracles\. Earlier no\-native\-route external FAKE fixture assertions were invalid; they remain raw diagnostics, not confirmed product defects or fixed coverage\. Revised source\-provenance cases are planned until reviewed\.
- Windows now holds a deterministic preexisting child and retains all timed busy\-child events\. Strict post\-published\-Active events after a1ms clock guard are asserted; exact commit/ambiguous time\-window scheduling still has a distinct planned boundary\.
- r4 ptrace100\-cycle attempt completed2 cycles then failed a terminal\-slot approval race; r4 ptrace manager recovery failed Engine bootstrap and Gum post\-Active fork crashed\. Keep these failures and require post\-fix native reruns; do not promote them into formal current\-model passes\.
- Completion and helper seam tests do not satisfy whole native READY\-failure, double\-death, module absence or privilege\-root acceptance\. Root enrollment remains a read\-only design pending the user deployment/threat\-boundary decision\.
- Coverage is relative to the declared model, source snapshot, and finite factor partitions\.
- Hashes and declarations do not prove semantic completeness, oracle truth, execution authenticity, or statistical validity\.
