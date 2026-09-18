# CLI + Skill 的 LLM 驱动工作流

LLM 通过仓库 Skill 调用普通 CLI；Shell 负责组合能力，HyperHub CLI 负责配置语义、加密存储、运行时热更新和可恢复的人工审批队列。

Skill 位于：

```text
.agents/skills/hyperhub-cli/SKILL.md
```

## 1. 读取脱敏配置

```sh
hyperhub show
```

输出直接是完整配置 JSON，不增加包装字段；它与导出配置使用同一份 `Config` 数据，唯一变化是所有 inline secret 的真实值被替换为 `<redacted>`。读取不需要密码。

加密配置每次保存时都会原子写入权限为当前用户独占的 `config.redacted.json`。从旧版本升级且该文件尚不存在时，先执行一次 `hyperhub validate --password-file ./password` 生成脱敏视图。

## 2. 提交配置请求

LLM 使用 JSON Patch 描述意图。支持 `add`、`replace`、`remove`、`test`，数组追加使用 `/-`。每个修改操作对应一条人工审批请求，应当包含完整对象并可独立通过配置校验。

可独立增删改的配置对象持久化 `uuid`，包括代理、插件、路由、环境变量、根证书、SSH 主机密钥、网络规则、文件规则和子进程规则。现有对象的 UUID 必须保持不变且不能复用；新增对象省略 UUID 时由 CLI 生成 RFC 4122 UUID。旧配置缺少 UUID 时按对象类型和业务 ID 生成稳定的迁移 UUID，因此重复读取不会改变身份。

需要真实凭证的位置使用审批占位符：

```json
[
  {
    "op": "add",
    "path": "/environment/-",
    "value": {
      "name": "GH_TOKEN",
      "value": { "value": "${APPROVE:github-token}" }
    }
  }
]
```

LLM 只运行提交命令：

```sh
hyperhub config patch patch.json --password-file ./password
```

该命令会完成全量配置校验并返回：

- `status = approval_required`；
- 审计用 `approval_token`；
- 请求数量 `request_count`；
- 已脱敏的整体 `changes`；
- Serve 是否正在运行。

活动配置不会在此阶段改变。请求会写入 `config.approval.bin` 加密队列；文件使用与配置分离的加密密钥域和当前用户独占权限。相同 patch 可以安全重试并返回当前进度，不同 patch 不会覆盖未完成队列。

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

配置不存在时，`config patch` 以默认配置为基线并创建加密审批队列，首次批准请求时才创建活动配置。密码通过权限受限的文件或 `HYPERHUB_CONFIG_PASSWORD` 提供。例如：

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
