---
name: hyperhub-cli
description: Use when an LLM needs to inspect, plan, apply, or verify HyperHub configuration through the local CLI, including routes, firewall, sandbox, credentials, environment, Serve lifecycle, status, logs, and backend diagnostics. Changes require the encrypted CLI approval-queue workflow.
---

# HyperHub CLI 操作

HyperHub 的 LLM 驱动入口是本地 CLI 与 Shell。

## 配置工作流

1. 确定 `hyperhub` 路径和权限为 `0600` 的密码文件。
2. 读取当前配置：

   ```sh
   hyperhub show
   ```

   输出与配置导出的数据结构 1:1 对应，仅将所有 inline secret 的真实值替换为 `<redacted>`。读取脱敏视图不需要密码。
3. 生成 RFC 6902 风格 JSON Patch。仅使用 `add`、`replace`、`remove`、`test`；数组追加使用 `/-`。每个修改操作应当构成可以独立校验的完整配置请求。现有配置对象的 `uuid` 是稳定身份，不得修改或复用；新增对象可省略 `uuid`，CLI 会生成。需要人工输入的 key、token 或密码必须使用占位符，例如：

   ```json
   {"value":{"value":"${APPROVE:github-api-key}"}}
   ```

   不要向用户索取真实 key，也不要把真实 key 写入 patch。
4. 提交请求，不直接修改活动配置：

   ```sh
   hyperhub config patch patch.json --password-file /path/to/password
   ```

   CLI 返回脱敏 `changes`、审计用 `approval_token` 和请求数量，并把请求写入加密审批队列。已有未完成队列时不得提交不同 patch。
5. 停止自动操作，提示用户在真实终端执行：

   ```sh
   hyperhub approve
   ```

   LLM 不得代替用户运行此命令、输入密码或作出审批决定。人工流程会：
   - 输入 HyperHub 密码；
   - 同时显示审批请求 UUID 与配置对象 UUID、`n/m` 进度以及“新增 / 修改 / 删除”；
   - 使用与 Config TUI 一致的“网关 / 凭证”“网关 / 路由”“沙盒 / 网络”等分类路径和字段名称；
   - 允许批准、编辑、拒绝或暂退；
   - 在批准需要凭证的请求时以星号掩码输入 `${APPROVE:name}` 的真实值；
   - 每处理一条就持久化进度，意外中断后从第一条未处理请求继续；
   - 立即加密保存已批准请求，并在 Serve 运行时热更新。
6. 用户完成审批后再验证：

   ```sh
   hyperhub validate --password-file /path/to/password
   hyperhub show
   hyperhub status --json
   ```

`approval_token` 仍绑定提交时的配置、原始 patch 和计划结果，用作审计标识；人工审批不需要复制或输入 token。`test` 操作会与其后的修改请求绑定，拒绝请求时一并跳过。

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
- 计划阶段不得修改活动配置；LLM 不得代替用户运行交互式 `approve`、输入密码、敏感值或审批决定。
- 不手工编辑加密的 `config.bin`。
- 不使用未知字段或跳过 CLI 语义校验；若 patch 被拒绝，修正 patch 后重新计划。
- 操作结束后删除含 secret 的临时文件；不得提交密码文件、patch secret 或生成的配置。
