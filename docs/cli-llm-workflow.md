# CLI + Skill 的 LLM 驱动工作流

LLM 通过仓库 Skill 调用普通 CLI；Shell 负责组合能力，HyperHub CLI 负责配置语义、加密存储、运行时热更新和审批 token 校验。

Skill 位于：

```text
.agents/skills/hyperhub-cli/SKILL.md
```

## 非交互配置接口

读取脱敏配置：

```sh
hyperhub config show --password-file ./password
```

规划 JSON Patch：

```sh
hyperhub config patch patch.json --password-file ./password
```

规划命令不会写入配置，返回：

- `status = approval_required`；
- 与当前配置、patch 和计算结果绑定的 `approval_token`；
- 已脱敏的 `changes`；
- Serve 是否正在运行。

人工确认后应用同一个 patch：

```sh
hyperhub config patch patch.json \
  --password-file ./password \
  --approve <approval_token>
```

若当前配置、patch 内容或结果发生变化，旧 token 会失效，必须重新规划和确认。该机制避免 LLM 在没有本次人工批准时直接修改配置。

支持的 patch 操作：

- `add`；
- `replace`；
- `remove`；
- `test`。

路径使用 JSON Pointer；向数组末尾追加使用 `/-`。CLI 在计划阶段反序列化并校验完整配置，因此无效 route、重复 ID、无效正则、错误引用或非 loopback listener 不会进入审批阶段。

## 初始化与密码

配置不存在时，`config patch` 以默认配置为基线。第一次应用时创建加密配置；密码通过权限受限的文件或 `HYPERHUB_CONFIG_PASSWORD` 提供。例如：

```sh
printf 'replace-with-a-long-password\n' > password
chmod 0600 password
```

密码文件只用于 CLI，不得提交。`config show` 永不输出 inline secret；计划和应用结果中的变更也会脱敏。

## 热更新

Serve 正在运行时，CLI 保存配置后用当前加密配置派生的证明调用现有控制面执行热更新。应用结果：

```json
{
  "status": "applied",
  "live_update": true
}
```

Serve 未运行时 `live_update` 为 `false`，下次启动读取新配置。

## 自动测试

```sh
./scripts/test-cli-config-approval.sh ./target/release/hyperhub
```

测试使用临时 HOME 和任意测试密码，覆盖：

1. 未批准的计划不创建配置；
2. 错误 token 不能修改配置；
3. 正确 token 可以初始化并添加 route/environment；
4. `config show` 不泄漏 inline secret；
5. 保存后的配置可以通过 `validate`；
6. Serve 运行时 patch 能完成热更新。
