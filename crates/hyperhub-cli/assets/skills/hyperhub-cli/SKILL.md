---
name: hyperhub-cli
description: Use when an Agent needs to inspect, plan, submit, or verify HyperHub configuration through the installed CLI, including routes, credentials, audit profiles, trust, sandbox, smart protection, environment variables, Serve lifecycle, status, logs, and backend diagnostics. Configuration changes require HyperHub's encrypted human-approval queue.
---

# HyperHub CLI 操作

通过已安装的 `hyperhub` CLI 管理本机 HyperHub。先读取现状，再生成脱敏变更请求；不要猜测配置数组索引、UUID、凭证 ID 或智能防护引用。

## 定位 CLI、实例与认证材料

1. 使用 PATH 中的 `hyperhub`；找不到时请用户提供可执行文件路径。
2. 用户指定 `HYPERHUB_HOME` 时，后续 `show`、`config patch`、`approve`、`start`、`status`、`run` 和 `stop` 必须在同一个环境变量下执行；不同值代表完全独立的 HyperHub 实例。
3. 需要密码的非交互命令使用用户明确提供的权限受限密码文件：

   ```sh
   hyperhub <command> --password-file /path/to/password
   ```

4. 不向用户索取真实 token、key 或密码，也不把敏感值写入回复、日志或普通临时文件。

## 读取配置

```sh
hyperhub show
```

`show` 不需要密码，输出完整 Schema v2 脱敏 JSON；数据结构与导出配置一致，inline secret 的真实值统一显示为 `<redacted>`。Agent 应解析 JSON 后向用户输出语义化摘要，只有用户明确要求原始 JSON 时才原样展示。不得使用 `export --plain` 获取真实值。

运行状态和能力：

```sh
hyperhub status --json
hyperhub doctor
hyperhub logs --lines 100
```

## 提交配置变更

新增或修改配置前，读取 [配置数据参考](references/configuration.md)，并先运行 `hyperhub show`。

1. 根据当前 JSON 的数组索引、UUID、ID 和默认值生成 RFC 6902 JSON Patch；只使用 `add`、`replace`、`remove`、`test`。
2. `config patch` 的第一个参数是 **Patch 文件路径**，不是内联 JSON；标准输入使用 `-`：

   ```sh
   cat patch.json | hyperhub config patch -
   ```

3. 新增集合对象使用 `/-` 并省略 `uuid`，由 CLI 生成；修改或删除现有对象前，先用从 `show` 读取的 UUID 添加 `test`，再修改同一索引。不得修改、复制或复用现有 UUID。
4. 新增凭证后，再新增引用该凭证 ID 的路由；不要在同一路由绑定同协议的多个同类凭证。
5. 需要人工填写的敏感值只能使用占位符：

   ```json
   {"value":{"value":"${APPROVE:meaningful-name}"}}
   ```

6. 典型的凭证与路由新增 Patch：

   ```json
   [
     {"op":"add","path":"/gateway/credentials/-","value":{"id":"example-bearer","type":"http_bearer","secret":{"value":"${APPROVE:example-token}"}}},
     {"op":"add","path":"/gateway/routing/routes/-","value":{"id":"example-api","enabled":true,"priority":300,"endpoints":[{"target":"https://api.example.test/v1","port":443}],"decision":{"action":"allow","credentials":["example-bearer"]}}}
   ]
   ```

7. `config patch` 不需要密码，只写入权限受限且禁止包含真实 Secret 的待审批 Proposal，不直接应用配置。已有未完成 Proposal 时不要用不同 Patch 覆盖它。

提交后必须明确告知用户：Agent 已提交 Patch，用户需要在真实终端运行 `hyperhub approve`。不要只给审批命令而省略 Patch 提交结果。

## 智能防护

智能防护位于 `/gateway/protections`，默认不改变任何未绑定规则。推荐先使用 `mode: observe` 验证命中和审计，再由用户明确要求切换为 `enforce`。

- `data`：本地检测托管 Secret、常见 Token、私钥、提示注入和来源复用。
- `intelligence`：可选的 System One Provider；启用时必须配置 Provider、Endpoint、Model 和审批占位的 API Key。
- 路由和默认路由使用 `decision.action: smart` 与 `decision.protection` 绑定 Profile。
- 网络、文件、进程沙盒规则使用 `action: smart` 与 `protection` 绑定 Profile。
- 只有 `smart` 动作允许绑定 `protection`；普通 `allow`/`deny` 规则不要添加该字段。
- `observe` 记录将要拒绝的结果但允许动作；`enforce` 才实际阻断。
- Provider 的 `error_action` 和 `low_confidence_action` 默认建议 `pass`；除非用户明确要求，不要因 Provider 故障或低置信度阻断全部流量。
- 不把原始正文、真实凭证、Header、Query 值、命令行 Secret 或私钥发送给远程 Provider；只允许发送脱敏动作和检测结果摘要。
- 智能防护 API Key 使用 `${APPROVE:name}`，只能由人工在 `approve` 中填写，禁止写入 Agent 回复、Patch、命令参数或日志。

智能防护变更示例流程：

1. `show` 确认目标规则、数组索引和 UUID；
2. 新增或修改 Profile，默认 `observe`；
3. 用 `smart` 动作将 Profile 绑定到精确路由或沙盒规则；
4. `config patch <patch-file>` 提交 Proposal；
5. 用户运行 `approve`，审核语义化变更并填写 API Key；
6. 用户批准后运行 `validate`、`show`、`status --json`，必要时查看 `logs` 和审计事件；
7. 只有用户确认观测结果后，才提交把 Profile 切换为 `enforce` 的第二次变更。

## 人工审批边界

提交后停止自动修改，并提示用户在真实终端执行：

```sh
hyperhub approve
```

Agent 不得代替用户运行 `approve`、输入主密码、填写敏感值或选择批准/拒绝。人工流程支持逐条语义化审阅、二次编辑、拒绝、批准、暂退和中断续审；批准后立即加密保存，并在 Serve 运行时尝试热更新。

`hyperhub chat` 是用户输入主密码后使用本地模型直接修改配置的人工入口。外部 Agent 不得调用它绕过审批队列。

## 审批后验证

用户确认审批完成后再执行：

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
