---
name: hyperhub-cli
description: Use for HyperHub CLI configuration and runtime operations. Follow the Skill-only workflow for show, proposal, approval handoff, Serve lifecycle, SSH tests, status, logs, and diagnostics; do not inspect HyperHub source unless the user explicitly asks to debug its implementation.
---

# HyperHub CLI 操作手册

目标是只依靠本 Skill、随附配置参考、用户提供的信息和 HyperHub CLI 的实际输出，把用户意图推进到可审批或已验证的结果。不要为了“避免猜测”越界读取实现；语义不明确时，停止在不确定点并询问用户。

## 绝对操作边界

### 普通 HyperHub 操作允许使用的依据

按优先级只使用：

1. 本 `SKILL.md`；
2. 当前 Skill 目录中的 [配置数据参考](references/configuration.md)；
3. 用户明确提供的目标、路径、主机、账号和安全选择；
4. PATH 中 `hyperhub` 的 `--help`、`skill`、`show`、`status --json`、`doctor`、`logs`、`config patch` 等输出。

`hyperhub show` 的脱敏 JSON 是当前配置索引、UUID、ID、引用和默认值的唯一事实来源。CLI 的成功、拒绝和错误文本是操作能力的最终事实来源。

### 普通操作禁止事项

除非用户明确要求“调试、修复或审查 HyperHub 实现”，不得：

- 读取 HyperHub 源码、测试代码、Git 元数据、构建产物或仓库内未随 Skill 提供的文档；
- 搜索网络来推断 HyperHub 行为；
- 用源码推理覆盖 CLI 的明确输出；
- 因 CLI 拒绝某个操作而静默改用删除重建、改名、扩大范围、重启服务或其他替代方案；
- 把一次操作权限解释为允许额外修改。

用户明确要求调试实现时，应先说明将离开“仅 Skill/CLI”操作边界，再按代码仓库开发流程处理；不要把调试手段混入普通配置操作。

### 不明确时的处理

- Skill 和 CLI 已明确：直接执行，不重复询问。
- 用户未明确会改变安全效果、身份、匹配范围或对象生命周期的选择：只问一个聚焦问题。
- Skill 未定义且 CLI 输出无法证明：说明“当前 Skill/CLI 未定义该语义”，询问用户，不读取源码补答案。
- CLI 拒绝：原样概括限制并停止；不要自行设计绕过方案。

## 结果状态

每次交付必须使用以下状态之一，不能把计划或 Proposal 描述为已生效：

- `read_only_report`：只读取并报告，没有提交变更。
- `needs_user_decision`：缺少必须由用户选择的语义，尚未提交变更。
- `proposal_submitted`：已提交 Proposal，**配置尚未生效**，等待用户执行 `hyperhub approve`。
- `approved_verified`：用户已确认审批完成，且已执行配置与运行态验证。
- `cli_limitation`：CLI 明确拒绝或不支持请求；没有采取替代修改。
- `runtime_tested`：已通过 `hyperhub run -- ...` 完成用户明确要求的目标程序测试，并报告实际结果。

## 意图到结果的固定流程

按顺序执行；不要跳步，不重复读取相同状态。

### 1. 分类用户意图

先判断属于哪一类：

- 只读检查：配置摘要、状态、日志、诊断；
- 配置变更：路由、凭证、审计、信任、沙盒、智能防护、环境变量；
- Serve 生命周期：start/stop/restart/status；
- 目标程序测试：必须通过 `hyperhub run -- target args...`；
- 实现调试：只有用户明确要求时才离开本手册的普通操作边界。

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

只有配置变更任务才读取 [配置数据参考](references/configuration.md) 中相关章节。不要读取仓库源码来补充 Schema。

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

## 错误处理与禁止变通

| CLI 结果 | Agent 行为 |
| --- | --- |
| `approval_pending` | 报告已有 Proposal，停止提交不同 Patch |
| `JSON patch does not change the configuration` | 返回 `cli_limitation`；不删除重建、不改变 UUID |
| Schema/validation error | 报告具体字段；根据 Skill 参考修正一次确定性错误，语义不明确则询问 |
| Provider/网络错误 | 查看脱敏日志与 doctor；不猜 Secret、不重复盲试 |
| SSH 测试失败 | 报告退出码与本次日志；不自动关闭主机校验或改凭证 |
| 未知错误 | 原样概括并停止；不得读取源码寻找绕过方案 |

Agent 创建的无敏感临时 Patch 在操作结束后删除；不得删除用户文件或使用破坏性清理命令。

## 最终回复最小清单

每次回复包含：

1. 结果状态；
2. 使用的 HyperHub Home；
3. 只读摘要、Proposal 摘要或运行测试结果；
4. CLI 的实际成功/限制/错误；
5. 唯一下一步（例如用户运行 `hyperhub approve`）；
6. 明确说明配置是否已生效；
7. 若未执行测试，不能声称行为已验证。
