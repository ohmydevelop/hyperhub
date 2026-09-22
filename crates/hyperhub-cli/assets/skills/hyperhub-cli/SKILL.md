---
name: hyperhub-cli
description: Use when an Agent needs to inspect, plan, submit, or verify HyperHub configuration through the installed CLI, including routes, credentials, audit profiles, trust, sandbox, environment variables, Serve lifecycle, status, logs, and backend diagnostics. Configuration changes require HyperHub's encrypted human-approval queue.
---

# HyperHub CLI 操作

通过已安装的 `hyperhub` CLI 管理本机 HyperHub。

## 定位 CLI 与认证材料

1. 使用 PATH 中的 `hyperhub`；找不到时请用户提供可执行文件路径。
2. 需要认证的非交互命令使用用户明确提供的权限受限密码文件：

   ```sh
   hyperhub <command> --password-file /path/to/password
   ```

3. 不向用户索取真实 token、key 或密码，也不把敏感值写入回复、日志或普通临时文件。
4. 用户指定 `HYPERHUB_HOME` 时，后续 `show`、`config patch`、`approve`、`start`、`status`、`run` 和 `stop` 必须在同一个环境变量下执行；不同值代表完全独立的 HyperHub 实例。

## 读取配置

```sh
hyperhub show
```

`show` 不需要密码，输出完整配置 JSON；数据结构与导出配置一致，inline secret 的真实值统一显示为 `<redacted>`。不得使用 `export --plain` 获取真实值。

## 提交配置变更

新增或修改配置前，读取 [配置数据参考](references/configuration.md)，根据其中的对象结构和约束生成数据。

1. 根据 `show` 输出和 [配置数据参考](references/configuration.md) 生成 RFC 6902 风格 JSON Patch，只使用 `add`、`replace`、`remove`、`test`，数组追加使用 `/-`。
2. `config patch` 的第一个参数是 **Patch 文件路径**，不是内联 JSON；需要通过标准输入提交时使用 `-`：

   ```sh
   cat patch.json | hyperhub config patch - --password-file /path/to/password
   ```

3. 每个修改操作必须是可独立校验的完整配置请求。新增凭证后，再新增引用该凭证 ID 的路由；不要在同一个路由中绑定同协议的多个同类凭证。
4. 现有配置对象的 `uuid` 是稳定身份，不得修改、复制或复用；新增对象必须省略 `uuid`，由 CLI 生成。修改或删除数组对象时，先用从 `show` 读取的 UUID 添加 `test` 操作，再对同一索引执行变更：

   ```json
   [
     {"op":"test","path":"/gateway/routing/routes/2/uuid","value":"show 中的现有 UUID"},
     {"op":"replace","path":"/gateway/routing/routes/2/priority","value":400}
   ]
   ```

5. 需要人工填写的敏感值使用占位符：

   ```json
   {"value":{"value":"${APPROVE:github-api-key}"}}
   ```

6. 提交审批队列：

   ```sh
   hyperhub config patch <patch-file> --password-file /path/to/password
   ```

   例如，新增 Bearer 凭证和路由时，Patch 的核心对象应类似：

   ```json
   [
     {"op":"add","path":"/gateway/credentials/-","value":{"id":"devboard-bearer","type":"http_bearer","secret":{"value":"${APPROVE:devboard-token}"}}},
     {"op":"add","path":"/gateway/routing/routes/-","value":{"id":"devboard-api","enabled":true,"priority":300,"endpoints":[{"target":"https://devboard.example/api","port":443}],"decision":{"action":"allow","credentials":["devboard-bearer"]}}}
   ]
   ```

   真实 token 只在人工 `approve` 时由用户输入；不得放入 Patch、命令行参数、日志或 Agent 回复。

该命令只写入加密审批队列，不直接应用配置。已有未完成队列时，不得用不同 patch 覆盖；不要把 `config patch` 当作直接生效命令。向用户汇报时必须同时说明“Agent 已提交 Patch，用户需要在真实终端运行 `hyperhub approve`”，不得只给出审批命令而省略 Patch 提交步骤。

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

按任务需要补充：

```sh
hyperhub logs --lines 100
hyperhub doctor --target /path/to/program
```

## Serve 与目标程序

```sh
hyperhub start --password-file /path/to/password
hyperhub stop
hyperhub restart --password-file /path/to/password
hyperhub status --json
hyperhub run --password-file /path/to/password -- program args...
```

- 配置优先通过审批热更新，避免不必要的 Serve 重启使现有 Session 失效。
- Linux 默认使用 ptrace 保底后端；只有用户明确要求时才指定 `--backend gum`。
- 不手工编辑加密的 `config.bin`，不使用未知字段，不绕过 CLI 校验。
- 操作结束后删除 Agent 创建的无敏感临时 patch；任何可能含真实敏感值的文件都不得提交。
