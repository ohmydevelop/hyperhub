---
name: hyperhub-cli
description: Use when an Agent needs to inspect, plan, submit, or verify HyperHub configuration through the installed CLI, including routes, credentials, audit profiles, trust, sandbox, smart protection, environment variables, Serve lifecycle, status, logs, and backend diagnostics. Configuration changes require HyperHub's encrypted human-approval queue.
---

# HyperHub CLI 操作

目标是把用户意图尽快推进到**可审批的结果**：先读取现状，自动完成所有确定的工作；只有安全语义确实不明确时才询问用户。配置变更最终停在加密 Proposal，必须由用户在真实终端 `approve`；Agent 不代替用户审批、输入密码或填写敏感值。

## 意图到结果的快速流程

按以下顺序执行，不重复询问或重复读取：

1. **定位实例**：确认 PATH 中的 `hyperhub` 和 `HYPERHUB_HOME`。用户指定 Home 后，所有命令都使用同一 Home。
2. **读取现状**：执行一次 `hyperhub show`；需要运行态时按需执行 `status --json`、`doctor` 或 `logs --lines 100`。解析脱敏 JSON，不猜测数组索引、UUID、ID 或引用关系。
3. **判断意图**：
   - 用户明确说“只记录/观察”：使用 `observe`、允许动作或 `pass`，不要再次询问。
   - 用户明确说“阻断/拒绝/失败关闭”：使用 `enforce`、拒绝动作或 `deny`，不要再次询问。
   - 用户没有明确安全效果（安全效果不明确）：只提出一个聚焦问题，让用户在“只记录”和“阻断”之间选择；在回答前不要提交会改变安全效果的 Patch。
4. **复用并设计**：优先复用已有 Profile、Provider、规则和引用；只生成完成意图所需的最小 RFC 6902 Patch。互不依赖的只读检查可以并行。
5. **提交结果**：使用 `hyperhub config patch <patch-file>` 提交 Proposal；确认 CLI 返回状态后停止自动修改，并引导用户运行 `hyperhub approve`。
6. **审批后验证**：只有用户明确表示已完成审批后，才执行 `validate`、`show`、`status --json`，必要时查看日志或做针对性行为验证。

### 必须询问用户的安全决策

以下选择不能自行猜测；若用户没有明确表达，先询问，再继续：

- 只记录（observe）还是实际阻断（enforce）；
- `allow`、`deny` 还是 `smart`；
- Provider 服务异常时 `pass` 还是 `deny`；
- Provider 低置信度时 `pass` 还是 `deny`；
- 是否扩大匹配范围、删除已有规则、覆盖已有配置或重命名被引用的 ID。

普通技术细节如果可以从 `show`、配置参考或 CLI 输出推导，不要把问题转给用户。存在未完成 Proposal 且新变更可能冲突时，先报告冲突并询问是否处理现有 Proposal。

## 实例、认证与敏感值

1. 使用 PATH 中的 `hyperhub`；找不到时才请用户提供路径。
2. 用户指定 `HYPERHUB_HOME` 时，后续 `show`、`config patch`、`approve`、`start`、`status`、`run` 和 `stop` 必须使用同一个环境变量；不同值代表完全独立的实例。
3. 需要密码的非交互命令只能使用用户明确提供的权限受限密码文件：

   ```sh
   hyperhub <command> --password-file /path/to/password
   ```

4. 不向用户索取真实 Token、API Key 或密码，也不把敏感值写入回复、日志、命令参数或普通临时文件。

## 读取配置与运行态

```sh
hyperhub show
hyperhub status --json
hyperhub doctor
hyperhub logs --lines 100
```

`show` 不需要密码，输出完整 Schema v2 脱敏 JSON；inline secret 的真实值统一显示为 `<redacted>`。向用户报告语义化摘要，只有用户明确要求原始 JSON 时才原样展示。不得使用 `export --plain` 获取真实值。

## 生成并提交 JSON Patch

新增或修改配置前，读取 [配置数据参考](references/configuration.md)，并先运行 `hyperhub show`。

1. 只使用 RFC 6902 的 `add`、`replace`、`remove`、`test`。
2. `config patch` 的第一个参数是 **Patch 文件路径**，不是内联 JSON；标准输入使用 `-`：

   ```sh
   cat patch.json | hyperhub config patch -
   ```

3. 新增集合对象使用 `/-` 并省略 `uuid`，由 CLI 生成；修改或删除现有对象前，用 `show` 得到的 UUID 添加 `test`，再修改同一索引。不得修改、复制或复用现有 UUID。
4. 修改被规则引用的 ID 时，必须在同一个 Patch 中同步修改所有引用，并为每个被修改对象添加 UUID `test`。
5. 新增凭证后再新增引用它的路由；不要在同一路由绑定同协议的多个同类凭证。
6. 真实敏感值只能使用审批占位符：

   ```json
   {"value":{"value":"${APPROVE:meaningful-name}"}}
   ```

7. `config patch` 不需要密码，只提交禁止包含真实 Secret 的待审批 Proposal，不直接应用配置。已有未完成 Proposal 时不要用不同 Patch 覆盖它。
8. 尽量提交一个原子、最小 Patch，不为同一意图拆分多个无必要 Proposal。

典型 Patch：

```json
[
  {"op":"add","path":"/gateway/credentials/-","value":{"id":"example-bearer","type":"http_bearer","secret":{"value":"${APPROVE:example-token}"}}},
  {"op":"add","path":"/gateway/routing/routes/-","value":{"id":"example-api","enabled":true,"priority":300,"endpoints":[{"target":"https://api.example.test/v1","port":443}],"decision":{"action":"allow","credentials":["example-bearer"]}}}
]
```

提交后必须报告 Proposal 的实际状态、变更摘要和下一步。不要只给审批命令而省略提交结果。

## 智能防护

智能防护位于 `/gateway/protections`，默认不改变任何未绑定规则。安全效果按用户意图处理：明确“只记录”使用 `mode: observe`；明确“阻断”使用 `mode: enforce`；未明确时先询问。

- `data`：本地检测托管 Secret、常见 Token、私钥、提示注入和来源复用。
- `intelligence`：可选的 System One Provider；启用时必须配置 Provider、Endpoint、Model 和审批占位的 API Key。
- 路由和默认路由使用 `decision.action: smart` 与 `decision.protection` 绑定 Profile。
- 网络、文件、进程沙盒规则使用 `action: smart` 与 `protection` 绑定 Profile。
- 只有 `smart` 动作允许绑定 `protection`；普通 `allow`/`deny` 规则不要添加该字段。
- `observe` 记录将要拒绝的结果但允许动作；`enforce` 才实际阻断。
- Provider 的 `error_action` 和 `low_confidence_action` 会改变故障时的放行/阻断语义。用户未指定时必须询问，不能静默选择；`error_action: deny` 明确表示 Provider 异常时失败关闭。
- Provider 异常时先检查 Endpoint、Model、凭证占位符、`doctor` 和日志，不要盲目重复提交相同 Patch；不得输出真实 API Key。
- 不把原始正文、真实凭证、Header、Query 值、命令行 Secret 或私钥发送给远程 Provider；只允许发送脱敏动作和检测结果摘要。
- 智能防护 API Key 使用 `${APPROVE:name}`，只能由人工在 `approve` 中填写，禁止写入 Agent 回复、Patch、命令参数或日志。

## 人工审批边界与结果状态

提交 Proposal 后立即停止自动修改，并提示用户在真实终端执行：

```sh
hyperhub approve
```

Agent 不得代替用户运行 `approve`、输入主密码、填写敏感值或选择批准/拒绝。人工流程支持逐条语义化审阅、二次编辑、拒绝、暂退和中断续审；批准后立即加密保存，并在 Serve 运行时尝试热更新。

交付状态必须区分：

- `proposal_submitted`：Patch 已提交，配置尚未生效；引导用户 `hyperhub approve`。
- `approved_verified`：用户确认审批完成，且 Agent 已完成 `validate`、`show`、`status --json` 和必要的运行态验证。

不得把 `proposal_submitted` 描述为“配置已生效”。`hyperhub chat` 是用户输入主密码后使用本地模型直接修改配置的人工入口，外部 Agent 不得调用它绕过审批队列。

## 审批后验证

用户明确确认审批完成后再执行：

```sh
hyperhub validate --password-file /path/to/password
hyperhub show
hyperhub status --json
```

配置热更新成功时优先继续使用现有 Serve，不要无故重启导致已有 Session 失效。若验证失败，先查看 `hyperhub logs --lines 100` 和 `hyperhub doctor`，不要盲目重复提交相同 Patch。

## Serve 与目标程序

```sh
hyperhub start --password-file /path/to/password
hyperhub stop
hyperhub restart --password-file /path/to/password
hyperhub status --json
hyperhub run --password-file /path/to/password -- program args...
```

Linux 默认使用 ptrace 保底后端；只有用户明确要求时才指定 `--backend gum`。操作结束后删除 Agent 创建的无敏感临时 Patch；任何可能含真实敏感值的文件都不得提交。
