# CLI + Skill 的 LLM 驱动工作流

## 0. 本地 Chat 直接配置

交互式本地配置可运行：

```sh
hyperhub chat
```

用户先输入 HyperHub 主密码，随后进入内嵌 Needle 3 驱动的 Chat。因为本地用户已经用主密码解锁活动配置，Chat 的语义化工具调用在全量校验后直接加密保存并热更新 Serve，不创建审批队列，也不需要 `approve`。该通道适合由用户亲自输入敏感数据。

Needle 3 权重与平台 runner 都嵌入 HyperHub 二进制；运行时关闭 telemetry，只在随机本机回环端口进行父子进程通信。聊天记录不持久化，配置摘要不显示 Secret。非交互式外部 LLM 和 Skill 仍必须使用下述 JSON Patch + 人工审批流程，两条信任边界不能混用。

LLM 通过 HyperHub CLI 内嵌并安装的 Agent Skill 调用普通 CLI；Shell 负责组合能力，HyperHub CLI 负责配置语义、加密存储、运行时热更新和可恢复的人工审批队列。

如需操作非默认实例，先设置绝对路径 `HYPERHUB_HOME`，并确保同一任务中的 `show`、`config patch`、`approve`、`start`、`run` 与 `stop` 均继承相同值。控制端点和所有可变状态会由该目录自动隔离。

`hyperhub start` 和 `hyperhub restart` 会把 Skill 安装到用户级通用目录：

```text
~/.agents/skills/hyperhub-cli
```

Skill 源码属于 CLI 构建资源，不依赖仓库工作目录。CLI 版本或内容摘要变化时全量原子替换，版本一致时跳过；安装失败会阻止 Serve 启动。

## 1. 读取脱敏配置

```sh
hyperhub show
```

输出直接是完整的 Schema v2 JSON，不增加额外包装字段；它与导出配置 1:1 对应，唯一变化是所有 inline secret 的真实值被替换为 `<redacted>`。根结构按 `gateway`、`sandbox` 和 `environment_variables` 分类，读取不需要密码。

加密配置每次保存时都会原子写入权限为当前用户独占的 `config.redacted.json`。v0.2 不读取或迁移旧 Schema；检测到旧配置或旧脱敏视图时会明确拒绝，用户需要重新创建配置。

## 2. 提交配置请求

LLM 使用 JSON Patch 描述意图。支持 `add`、`replace`、`remove`、`test`，数组追加使用 `/-`。每个修改操作对应一条人工审批请求，应当包含完整对象并可独立通过配置校验。

可独立增删改的配置对象持久化 `uuid`，包括代理、凭证、审计 Profile、路由、环境变量、TLS 证书、SSH 主机密钥、网络规则、文件规则和子进程规则。现有对象的 UUID 必须保持不变且不能复用；新增对象省略 UUID 时由 CLI 生成 RFC 4122 UUID。Patch 路径必须来自当前 `show` 输出，不得使用旧 `/plugins`、`/routes` 或 `/firewall` 路径。

需要真实凭证的位置使用审批占位符：

```json
[
  {
    "op": "add",
    "path": "/environment_variables/-",
    "value": {
      "name": "GH_TOKEN",
      "value": { "value": "${APPROVE:github-token}" }
    }
  }
]
```

LLM 只运行提交命令：

```sh
hyperhub config patch patch.json
```

该命令会完成全量配置校验并返回：

- `status = approval_required`；
- 审计用 `approval_token`；
- 请求数量 `request_count`；
- 已脱敏的整体 `changes`；
- Serve 是否正在运行。

活动配置不会在此阶段改变。请求首先写入权限为当前用户独占的 `config.approval.json` Proposal。CLI 拒绝其中出现真实 inline Secret，只允许 `${APPROVE:name}`、环境变量引用或受保护文件引用。人工首次运行 `approve` 并通过主密码解锁配置后，Proposal 会立即迁移到使用独立密钥域的 `config.approval.bin` 加密队列并删除明文 Proposal。相同 Patch 可以安全重试，不同 Patch 不会覆盖未完成队列。

## 3. 人工逐条审批

人工在真实终端运行：

```sh
hyperhub approve
```

也可从权限受限的文件读取密码，并指定编辑器：

```sh
hyperhub approve --password-file ./password --editor /path/to/editor
```

执行后首先输入 HyperHub 密码，然后逐条显示：

```text
[2/5] 配置审批项
```

每条请求都有独立的审批请求 UUID，并显示被操作配置对象的 `config_item_uuid`。界面同时展示当前 `n/m` 进度、“新增 / 修改 / 删除”动作、与 Config TUI 相同的分类路径和字段名称、语义详情及脱敏变更。原始 JSON Patch 的 `op/path` 仅放在 `technical` 区域，避免成为主要认知界面。可选择：

- `a / approve`：批准该请求；
- `e / edit`：只编辑当前请求，保存后重新展示脱敏结果；
- `r / reject`：拒绝该请求并继续下一条；
- `q / quit`：保留进度并退出。

批准含 `${APPROVE:name}` 的请求时，CLI 会逐项使用星号掩码输入读取真实值。真实值不会写回 LLM patch、终端输出或脱敏视图。

每次批准或拒绝后都会原子保存队列进度。Ctrl+C、终端关闭或进程异常退出后，再次运行 `hyperhub approve` 会从第一条未处理请求继续，已处理请求不会重复出现。队列还记录加密的 in-flight 状态，可区分配置保存前后发生的中断并完成恢复。

批准请求会立即写入加密配置；拒绝请求不会修改配置。Serve 正在运行时，每条批准请求都会尝试热更新。全部请求处理后删除审批队列并输出汇总。

`test` 操作不单独显示，它与后续修改请求绑定为前置条件；拒绝该修改时一并跳过。

## 4. 初始化与密码

配置不存在时，`config patch` 以默认配置为基线并创建不含真实 Secret 的权限受限 Proposal，首次 `approve` 时才创建活动配置。密码只在人工审批阶段通过权限受限的文件或 `HYPERHUB_CONFIG_PASSWORD` 提供。例如：

```sh
printf 'replace-with-a-long-password
' > password
chmod 0600 password
```

密码文件只用于 CLI，不得提交。`show`、计划结果、逐条审批显示和应用结果均不得泄漏 inline secret。

## 5. 自动测试

```sh
./scripts/test-cli-config-approval.sh ./target/release/hyperhub
```

测试使用临时 HOME 和任意测试密码，覆盖：

1. 提交请求不会提前创建活动配置；
2. 审批队列加密保存且不同 patch 不能覆盖；
3. 配置对象 UUID 在规划、审批、保存和 `show` 中保持一致；
4. 逐条展示请求 UUID、`n/m` 进度和新增/修改/删除语义；
5. 审批分类路径与 Config TUI 使用同一语义定义；
6. 单条请求可以拒绝、编辑或批准；
7. `${APPROVE:name}` 通过星号掩码输入填写且不会泄漏；
8. 中断后只继续未处理请求，请求 UUID 保持不变；
9. 已批准请求立即持久化，完成后删除队列；
10. 保存后的配置可通过 `validate`；
11. Serve 运行时批准请求可以热更新。
