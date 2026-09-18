---
name: hyperhub-cli
description: Use when an LLM needs to inspect, plan, apply, or verify HyperHub configuration through the local CLI, including routes, firewall, sandbox, credentials, environment, Serve lifecycle, status, logs, and backend diagnostics. Changes require the CLI approval-token workflow.
---

# HyperHub CLI 操作

HyperHub 的 LLM 驱动入口是本地 CLI 与 Shell。

## 配置工作流

1. 确定 `hyperhub` 路径和权限为 `0600` 的密码文件。
2. 读取当前配置：

   ```sh
   hyperhub config show --password-file /path/to/password
   ```

   输出中的 inline secret 会显示为 `<redacted>`。
3. 生成 RFC 6902 风格 JSON Patch。仅使用 `add`、`replace`、`remove`、`test`；数组追加使用 `/-`。包含 secret 的临时 patch 文件必须设为 `0600`。
4. 只生成计划，不修改配置：

   ```sh
   hyperhub config patch patch.json --password-file /path/to/password
   ```

   向用户展示返回的 `changes`，并请求明确批准。不得把普通任务授权、历史批准或模型判断当作本次批准。
5. 用户批准后，原样使用计划返回的 token：

   ```sh
   hyperhub config patch patch.json \
     --password-file /path/to/password \
     --approve <approval_token>
   ```

   Token 绑定当前配置、patch 和结果。配置变化或 token 不匹配时重新生成计划并再次请求批准，不要绕过。
6. 验证：

   ```sh
   hyperhub validate --password-file /path/to/password
   hyperhub config show --password-file /path/to/password
   hyperhub status --json
   ```

运行中的 Serve 会自动热更新；CLI 返回的 `live_update` 必须为 `true`。未运行时为 `false`，配置在下次启动生效。

## 常用操作

```sh
hyperhub start --password-file /path/to/password
hyperhub stop
hyperhub restart --password-file /path/to/password
hyperhub status --json
hyperhub logs --lines 100
hyperhub doctor --target /path/to/program
hyperhub run --password-file /path/to/password -- program args...
```

## 安全约束

- 不使用 `export --plain` 获取配置，也不在回复、日志或 Commit 中输出 secret。
- 计划阶段不得修改配置；只有用户明确批准后才能传递 `--approve`。
- 不手工编辑加密的 `config.bin`。
- 不使用未知字段或跳过 CLI 语义校验；若 patch 被拒绝，修正 patch 后重新计划。
- 操作结束后删除含 secret 的临时文件；不得提交密码文件、patch secret 或生成的配置。
