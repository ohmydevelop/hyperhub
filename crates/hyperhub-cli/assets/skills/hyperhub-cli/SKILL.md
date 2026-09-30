---
name: hyperhub-cli
description: Use for HyperHub CLI configuration and runtime operations, including show, Schema v2 RFC 6902 proposals, human approval handoff, Serve lifecycle, target-program and SSH tests, status, logs, and diagnostics. The bundled reference covers configuration fields and examples; implementation debugging is a separate workflow when the task actually requires it.
---

# HyperHub CLI 操作手册

本 Skill 旨在把常见 HyperHub 配置与运行任务所需的操作语义、Schema、审批边界、验证方法和已知失败模式集中说明完整。普通任务优先按本手册和随附参考推进，通常无需另外研究实现；如果用户要求根因分析、修复实现，或公开操作语义确实不足以继续，再切换到实现调试流程。

## 推荐信息来源与升级路径

### 普通配置与运行任务

以下信息组合通常足以完成任务：

1. 本 `SKILL.md`：任务分类、推荐流程、安全边界、验证和错误处理；
2. [配置数据参考](references/configuration.md)：Schema v2 字段、引用关系、JSON Patch 示例和功能域语义；
3. 用户明确提供的目标、路径、主机、账号、安全效果和授权范围；
4. 当前 PATH 中 `hyperhub` 的 `--help`、`skill`、`show`、`status --json`、`doctor`、`logs`、`config patch` 等实际输出。

`hyperhub show` 的脱敏 JSON 用于确认当前实例的数组索引、UUID、ID、引用和默认值；运行态以 `status --json`、`doctor`、`logs` 和目标程序结果为准；命令是否接受某个操作以当前 CLI 返回为准。源码说明实现机制，但不能代替当前实例与当前二进制的实际状态。

### 何时升级到实现调试

- 用户明确要求调试、修复或审查 HyperHub 实现时，按代码仓库开发流程检查源码、测试和构建产物。
- 手册、配置参考、`--help` 与诊断输出仍不足以定义关键行为时，先明确尚不确定的语义及其对操作的影响；根据用户目标选择询问、保留现状，或进入实现调查。
- CLI 出现未知错误时，先收集原始错误、`status --json`、`doctor` 和相关脱敏日志；若任务要求定位根因，再进入实现调试，而不是把未经证实的配置变通当作答案。
- CLI 的明确输出与源码推断不一致时，操作报告同时记录版本和实际输出；实现调试可解释差异，但不把推断描述为已经生效的运行事实。

### 不明确时的处理

- Skill、参考或 CLI 已明确：直接执行，不重复询问。
- 用户未明确会改变安全效果、身份、匹配范围或对象生命周期的选择：只问一个聚焦问题。
- 仍有未定义语义：说明不确定点、可能影响和下一种可靠确认方式，不静默猜测。
- CLI 拒绝：概括实际限制；任何删除重建、改名、扩大范围、重启或其他替代方案都作为新的选择单独说明，不默认执行。

## 任务导航

| 用户目标 | 主要依据与动作 | 结果落点 |
| --- | --- | --- |
| 查看配置 | `hyperhub show`，按 ID、UUID、引用和脱敏值做语义摘要 | `read_only_report` |
| 查看运行态 | `status --json`；异常时补 `doctor` 和相关 `logs` | `read_only_report` 或诊断结论 |
| 新增/修改/删除配置 | `show` + 配置参考相关章节，生成最小 RFC 6902 Patch，提交 `config patch` | `proposal_submitted` |
| 修改 Secret | 使用 `${APPROVE:name}`；先读“Secret、脱敏值与 UUID”和参考中的同名章节 | Proposal，或明确 Secret-only CLI 限制 |
| 配置智能防护 | 参考“智能防护 Profile”“路由与智能防护绑定”“沙盒与智能防护”，确认 observe/enforce 与失败动作 | Proposal + 审批后 Provider/引用验证 |
| 配置 SSH 审计 | 同时核对 SSH 凭证、SSH 审计 Profile、路由绑定与 transcript 语义 | Proposal + 审批后结构化事件验证 |
| 启停 Serve | `start`、`stop`、`restart`、`status --json`，只执行用户要求的生命周期动作 | 实际运行态 |
| 测试目标程序 | Serve 运行后使用 `hyperhub run -- program args...` | `runtime_tested` |
| 排查操作失败 | 保留原错，按错误表收集 `status`、`doctor`、`logs` 与版本 | 可操作诊断或实现调试入口 |
| 调试实现 | 按仓库开发流程检查源码、测试与构建；仍以 CLI 实测验证用户可见结果 | 根因、修复与回归 |

## 结果状态

建议用以下状态标记交付结果，核心要求是不能把计划或 Proposal 描述为已生效：

- `read_only_report`：只读取并报告，没有提交变更。
- `needs_user_decision`：缺少必须由用户选择的语义，尚未提交变更。
- `proposal_submitted`：已提交 Proposal，**配置尚未生效**，等待用户执行 `hyperhub approve`。
- `approved_verified`：用户已确认审批完成，且已执行配置与运行态验证。
- `cli_limitation`：CLI 明确拒绝或不支持请求；没有采取替代修改。
- `runtime_tested`：已通过 `hyperhub run -- ...` 完成用户明确要求的目标程序测试，并报告实际结果。

## 意图到结果的推荐流程

按任务需要沿以下顺序推进；已有可靠信息可以复用，状态发生变化后再重读相关数据。

### 1. 分类用户意图

先判断属于哪一类：

- 只读检查：配置摘要、状态、日志、诊断；
- 配置变更：路由、凭证、审计、信任、沙盒、智能防护、环境变量；
- Serve 生命周期：start/stop/restart/status；
- 目标程序测试：必须通过 `hyperhub run -- target args...`；
- 实现调试：用户要求根因、代码修复或实现审查，或公开操作语义不足以完成任务。

不要把“测试登录”误当成配置授权，也不要把“修改凭证”扩展成删除重建凭证。

### 2. 锁定实例

```sh
type -a hyperhub
printf 'HYPERHUB_HOME=%s\n' "${HYPERHUB_HOME-}"
```

- 使用 PATH 中的 `hyperhub`。
- 用户指定 `HYPERHUB_HOME` 后，后续所有命令必须使用同一个值。
- 不同 Home 是完全独立的配置、Proposal、Serve 和审计实例。
- Home、远端或目标不明确时，不猜测。

### 3. 读取一次现状

配置任务先执行一次：

```sh
hyperhub show
```

需要运行态时按需执行一次：

```sh
hyperhub status --json
hyperhub doctor
hyperhub logs --lines 100
```

解析脱敏 JSON，不猜测数组索引、UUID、ID、引用或未显示的 Secret。除非状态在本轮中已被用户或命令改变，不重复执行 `show`。

### 4. 取得用户必须决定的语义

以下选择不得代替用户决定：

- 只记录（`observe`/`pass`）还是实际阻断（`enforce`/`deny`）；
- 路由或规则使用 `allow`、`deny` 还是 `smart`；
- Provider 异常时 `error_action: pass|deny`；
- Provider 低置信度时 `low_confidence_action: pass|deny`；
- 是否扩大匹配范围、删除对象、重命名被引用 ID、覆盖配置；
- 是否删除并重建已有对象，从而改变 UUID；
- 是否连接用户指定的真实 SSH/网络目标做行为测试。

用户已经明确表达时直接沿用，不再次询问。安全效果不明确时，返回 `needs_user_decision`，只问一个问题。

### 5. 读取相关 Schema 参考

配置变更任务读取 [配置数据参考](references/configuration.md) 中对应章节。该参考包含凭证、代理、智能防护、路由、审计、沙盒、信任、环境变量和审批占位符的可操作 Schema；优先据此生成 Patch。若用户任务是实现调试，再结合源码核对实现。

### 6. 设计最小原子 Patch

- 只使用 RFC 6902 `add`、`replace`、`remove`、`test`。
- 第一个参数是 Patch 文件路径；标准输入使用 `-`。
- 修改或删除现有集合对象前，用 `show` 中同一索引的 `uuid` 添加 `test`。
- 新增集合对象使用 `/-` 并省略 `uuid`，由 CLI 生成。
- 整体替换现有对象必须保留其 UUID。
- 修改被引用 ID 时，同一 Patch 更新全部引用并保护所有被修改对象。
- 优先复用现有对象；不顺带创建、删除或重命名无关对象。
- 不把真实 Secret 放入 Patch。

示例：

```json
[
  {"op":"add","path":"/gateway/credentials/-","value":{"id":"example-bearer","type":"http_bearer","secret":{"value":"${APPROVE:example-token}"}}},
  {"op":"add","path":"/gateway/routing/routes/-","value":{"id":"example-api","enabled":true,"priority":300,"endpoints":[{"target":"https://api.example.test/v1","port":443}],"decision":{"action":"allow","credentials":["example-bearer"]}}}
]
```

### 7. 提交 Proposal

```sh
hyperhub config patch <patch-file>
```

- `config patch` 不需要密码，只提交待审批 Proposal。
- 解析并报告 CLI 返回的实际 `status`、request 数、变更摘要和审批 token（若输出包含）。
- 若已有未完成 Proposal，不用不同 Patch 覆盖；报告冲突并让用户先处理现有 Proposal。
- CLI 拒绝时返回 `cli_limitation` 或实际错误状态，不自动改用替代方案。

### 8. 停在人工审批边界

提交成功后返回 `proposal_submitted`，并提示用户在真实终端运行：

```sh
hyperhub approve
```

Agent **不得代替用户运行** `hyperhub approve`、输入主密码、填写真实敏感值、批准、编辑或拒绝请求。用户未明确确认审批完成前，不运行审批后验证，不声称配置已生效。

### 9. 审批后验证

用户明确表示已完成审批后，才执行：

```sh
hyperhub validate --password-file /path/to/password
hyperhub show
hyperhub status --json
```

按需补充：

```sh
hyperhub logs --lines 100
hyperhub doctor
```

配置热更新成功时继续使用现有 Serve；不要无故重启。验证完成返回 `approved_verified`。

## Secret、脱敏值与 UUID

### 基本规则

- 不向用户索取真实 Token、API Key、密码或私钥。
- 非交互命令需要密码时，只能使用用户明确提供、权限受限的 `--password-file`。
- 不把 Secret 写入回复、命令参数、日志或普通临时文件。
- 新 Secret 使用 `{"value":"${APPROVE:meaningful-name}"}`，由人工在 `approve` 中填写。
- 不使用 `export --plain` 获取真实值。

### `<redacted>` 不是可修改的真实值

`hyperhub show` 把已有 inline Secret 显示为 `<redacted>`。Agent不知道原值，也不能用 `<redacted>` 做相等性、复制或恢复判断。

仅把现有 `<redacted>` Secret 替换为 `${APPROVE:name}` 时，`config patch` 可能返回：

```text
JSON patch does not change the configuration
```

这是 Agent Patch 流程的明确限制：脱敏前后没有可展示的配置差异。遇到该错误时：

1. 返回 `cli_limitation` 并报告 CLI 原因；
2. 不删除并重建凭证；
3. 不添加无关可见字段来强行制造差异；
4. 不改变 UUID；
5. 建议用户在真实终端运行 `hyperhub config` 修改现有 Secret；若用户明确要求删除重建，先说明引用与 UUID 会变化，再取得明确授权。

如果同一原子 Patch 中本来就包含用户要求的可见字段变化，可以同时携带 Secret 审批占位符，但不得为了绕过限制制造无关变化。

## SSH 审计的精确语义

同一路由绑定 SSH 凭证，并绑定 `protocols` 包含 `ssh` 的审计 Profile 时，HyperHub 才能解密 SSH 并执行以下审计：

- `ssh_transcript: false`：不保存解密后的 SSH 通道上下行内容文件；
- 结构化 SSH 事件仍会记录，包括 `ssh_command`、`ssh_shell`、`ssh_subsystem` 和通道结束事件；
- `ssh_transcript: true`：在结构化事件之外，按方向与大小限制保存解密后的通道内容；
- 未绑定 SSH 审计 Profile：不记录上述结构化命令事件；
- 未绑定 SSH 凭证：连接按加密流透传，无法记录结构化命令或解密内容；若请求了内容转录，则不保存密文，并记录跳过原因。

因此“关闭 SSH 内容转录”不等于“关闭 SSH 事件审计”。用户要求完全不记录 SSH 命令时，应移除路由对 SSH 审计 Profile 的绑定或让 Profile 不再声明 SSH 协议；这是扩大/缩小审计范围的变更，必须按用户明确意图处理。

## SSH 登录测试必须经过 HyperHub

只有在以下条件都满足时测试：配置已 `approved_verified`、Serve 正在运行、用户提供目标主机/端口/用户名并明确要求连接测试。

POSIX Shell：

```sh
hyperhub run --password-file /path/to/password -- \
  ssh -o BatchMode=yes -o ConnectTimeout=10 -p 22 deploy@example.test true
```

PowerShell：

```powershell
hyperhub run --password-file C:\path\password.txt -- ssh -o BatchMode=yes -o ConnectTimeout=10 -p 22 deploy@example.test true
```

规则：

- 必须使用 `hyperhub run ... -- ssh ...`；直接运行 `ssh` 不经过 HyperHub，不能作为验证。
- 沿用同一 `HYPERHUB_HOME`。
- 不添加 `StrictHostKeyChecking=no`、真实密码、私钥内容或用户未要求的危险选项。
- 测试失败后先报告 SSH 退出码，再查看 `status --json`、`logs --lines 100` 和 `doctor --target ssh`；不要立即改配置或重启。
- 审计验证只检查本次连接产生的脱敏事件，不输出认证材料或转录正文。
- 成功时返回 `runtime_tested`，说明目标、命令类型、退出码和对应审计结果。

## 智能防护

智能防护位于 `/gateway/protections`：

- 明确“只记录”使用 `mode: observe`；明确“阻断”使用 `mode: enforce`；
- Profile 只有被路由或沙盒规则以 `action: smart` 引用后才影响行为；
- `allow`/`deny` 不绑定 `protection`；
- Provider 使用 System One（`protocol: system_one`）、HTTPS Endpoint、Model 和 `${APPROVE:name}` API Key；
- `error_action`、`low_confidence_action` 未明确时必须询问；
- 远程 Provider 只接收脱敏动作和检测摘要，不发送真实正文、Header、Query、凭证或私钥；
- Provider 异常时依据 CLI 日志和 `doctor` 报告，不重复提交相同 Patch。

## Serve 与目标程序

```sh
hyperhub start --password-file /path/to/password
hyperhub stop
hyperhub restart --password-file /path/to/password
hyperhub status --json
hyperhub run --password-file /path/to/password -- program args...
```

- 只有用户明确要求 start/stop/restart 时执行；配置热更新不自动重启。
- Linux 默认使用 ptrace；只有用户明确要求 Gum 时才加 `--backend gum`。
- 目标测试使用 `--` 分隔 HyperHub 参数和目标程序参数。

## 错误处理与升级判断

| CLI 结果 | Agent 行为 |
| --- | --- |
| `approval_pending` | 报告已有 Proposal，停止提交不同 Patch |
| `JSON patch does not change the configuration` | 返回 `cli_limitation`；不删除重建、不改变 UUID |
| Schema/validation error | 报告具体字段；根据 Skill 参考修正一次确定性错误，语义不明确则询问 |
| Provider/网络错误 | 查看脱敏日志与 doctor；不猜 Secret、不重复盲试 |
| SSH 测试失败 | 报告退出码与本次日志；不自动关闭主机校验或改凭证 |
| 未知错误 | 保留原始错误并收集 `status --json`、`doctor`、相关脱敏日志与版本；若用户需要根因或操作无法继续，转入实现调试 |

Agent 创建的无敏感临时 Patch 在操作结束后删除；用户文件和与任务无关的工作区内容保持不变。

## 最终回复建议清单

为便于用户接手，回复包含：

1. 结果状态；
2. 使用的 HyperHub Home；
3. 只读摘要、Proposal 摘要或运行测试结果；
4. CLI 的实际成功/限制/错误；
5. 唯一下一步（例如用户运行 `hyperhub approve`）；
6. 明确说明配置是否已生效；
7. 若未执行测试，不能声称行为已验证。
