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
   hyperhub show
   ```

   输出与配置导出的数据结构 1:1 对应，仅将所有 inline secret 的真实值替换为 `<redacted>`。读取脱敏视图不需要密码；`hyperhub config show` 是兼容别名。
3. 生成 RFC 6902 风格 JSON Patch。仅使用 `add`、`replace`、`remove`、`test`；数组追加使用 `/-`。需要人工输入的 key、token 或密码必须使用占位符，例如：

   ```json
   {"value":{"value":"${APPROVE:github-api-key}"}}
   ```

   不要向用户索取真实 key，也不要把真实 key 写入 patch。
4. 只生成计划，不修改配置：

   ```sh
   hyperhub config patch patch.json --password-file /path/to/password
   ```

   向用户展示返回的脱敏 `changes` 和 `approval_token`。然后停止自动操作，提示用户在本地终端执行人工审计：

   ```sh
   hyperhub approve patch.json \
     --password-file /path/to/password \
     --token <approval_token>
   ```

5. `approve` 会执行以下人工步骤：
   - 在权限受限的临时副本中打开 patch，允许二次编辑；
   - 对 `${APPROVE:name}` 占位符进行隐藏输入，真实值不会写回 patch；
   - 显示最终脱敏 diff；
   - 要求输入动态的 `APPLY <code>` 后才保存；
   - Serve 运行时自动热更新。
6. 用户完成 approve 后再验证：

   ```sh
   hyperhub validate --password-file /path/to/password
   hyperhub show
   hyperhub status --json
   ```

`approval_token` 绑定计划时的当前配置与原始 patch。配置或原始 patch 变化后必须重新规划。人工二次编辑后的最终结果由 `APPLY <code>` 再次绑定确认。

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
- 计划阶段不得修改配置；LLM 不得代替用户运行交互式 `approve` 或输入 `APPLY <code>`。
- 不手工编辑加密的 `config.bin`。
- 不使用未知字段或跳过 CLI 语义校验；若 patch 被拒绝，修正 patch 后重新计划。
- 操作结束后删除含 secret 的临时文件；不得提交密码文件、patch secret 或生成的配置。
