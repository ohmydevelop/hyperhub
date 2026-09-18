# CLI + Skill 的 LLM 驱动工作流

LLM 通过仓库 Skill 调用普通 CLI；Shell 负责组合能力，HyperHub CLI 负责配置语义、加密存储、运行时热更新和审批 token 校验。

Skill 位于：

```text
.agents/skills/hyperhub-cli/SKILL.md
```

## CLI 配置与人工审计接口

读取完整、脱敏的 JSON 配置：

```sh
hyperhub show --password-file ./password
```

`hyperhub config show` 是兼容别名。输出中的 `sensitive_values_redacted` 固定为 `true`，`redacted_paths` 会列出所有被替换为 `<redacted>` 的 inline secret 路径。

LLM 使用 JSON Patch 描述意图。需要真实凭证的位置使用审批占位符：

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

LLM 只运行规划命令：

```sh
hyperhub config patch patch.json --password-file ./password
```

规划命令不会写入配置，返回：

- `status = approval_required`；
- 与当前配置、原始 patch 和计划结果绑定的 `approval_token`；
- 已脱敏的 `changes`；
- Serve 是否正在运行。

之后由人工在真实终端运行：

```sh
hyperhub approve patch.json \
  --password-file ./password \
  --token <approval_token>
```

`approve` 会把 patch 复制到权限受限的临时文件，并使用 `$HYPERHUB_EDITOR` 指定的编辑器打开；未设置时 POSIX 默认使用 `vi`，Windows 默认使用 `notepad.exe`。也可以显式指定单个编辑器程序：

```sh
hyperhub approve patch.json --token <token> \
  --password-file ./password --editor /path/to/editor-wrapper
```

人工可以在编辑器里调整目标、端口、优先级或删除不接受的操作。保存并退出后，CLI 对每个 `${APPROVE:name}` 使用隐藏输入读取真实值；真实值只存在于内存，不写回 LLM 生成的 patch 或 review 临时文件。

最后 CLI 显示二次编辑后的脱敏 diff，并要求输入动态的：

```text
APPLY <12位确认码>
```

只有完全匹配才保存配置。原始配置或原始 patch 发生变化会使 proposal token 失效；二次编辑、人工填写的 key 和最终配置则由新的确认码绑定。

支持的 patch 操作：

- `add`；
- `replace`；
- `remove`；
- `test`。

路径使用 JSON Pointer；向数组末尾追加使用 `/-`。CLI 在规划和审批后都会反序列化并校验完整配置，因此无效 route、重复 ID、无效正则、错误引用或非 loopback listener 不会被保存。

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
3. `approve` 会打开二次编辑器，并保留人工修改后的配置；
4. `${APPROVE:name}` 由人工隐藏输入真实 key；
5. review、应用结果和 `config show` 均不泄漏 inline secret；
6. 正确 proposal token 和最终 `APPLY <code>` 可以初始化配置；
7. 保存后的配置可以通过 `validate`；
8. Serve 运行时 approve 能完成热更新。
