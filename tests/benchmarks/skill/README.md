# HyperHub Skill 黑盒 Benchmark

这个 Benchmark 验证面向用户和 Agent 的 `hyperhub-cli` Skill 是否仍然能够独立指导配置数据生成。
它把 Skill 和脱敏配置 fixture 提供给一个黑盒 subagent；subagent 不得读取 HyperHub 源码、Git
信息、仓库其他文档或网络。测试重点不是模型是否知道仓库实现，而是 Skill 是否公开了足够的
配置 Schema、UUID 语义、JSON Patch 写法、敏感占位符和人工审批边界。

## 快速运行

先运行不依赖模型的契约检查：

```sh
./scripts/benchmark-skill-subagent.sh --contract-only
```

使用已安装的 Skill：

```sh
./scripts/benchmark-skill-subagent.sh \
  --skill "$HOME/.agents/skills/hyperhub-cli" \
  --agent-command 'your-black-box-agent-command'
```

`--agent-command` 通过环境变量取得输入和输出路径：

- `HYPERHUB_SKILL_PROMPT_FILE`：测试任务；
- `HYPERHUB_SKILL_DIR`：仅包含待测 Skill 的临时目录；
- `HYPERHUB_SKILL_FIXTURE`：脱敏配置 fixture；
- `HYPERHUB_SKILL_OUTPUT_FILE`：Agent 必须写入最终 JSON 的文件；
- `HYPERHUB_SKILL_WORKDIR`：空的临时工作目录。

命令也可以从 stdin 读取 prompt，并将 JSON 写到 stdout。为了避免模型把答案写入日志，优先使用
`HYPERHUB_SKILL_OUTPUT_FILE`。例如适配器可以是：

```sh
HYPERHUB_SKILL_AGENT_CMD='my-agent-adapter'
./scripts/benchmark-skill-subagent.sh \
  --skill "$HOME/.agents/skills/hyperhub-cli" \
  --agent-command "$HYPERHUB_SKILL_AGENT_CMD" \
  --require-agent
```

没有 Agent 运行器时，默认只执行契约检查并返回成功；`--require-agent` 可用于本地验收或 CI，确保
确实执行了黑盒 subagent。结果默认写入 `target/benchmarks/skill/report.json`，临时 prompt、fixture、
答案和 Skill 副本都会在退出时删除。

## 覆盖场景

- 新增 Bearer 凭证和 HTTP 路由，并使用 `${APPROVE:name}` 占位符；
- 通过 UUID + `test` 安全修改现有配置；
- 通过 UUID + `test` 安全删除现有对象；
- 生成 RFC 6902 patch，而不是猜测内联 CLI 参数；
- 区分 Agent 提交审批队列与人工 `approve`，禁止 Agent 代填真实 secret；
- 检查回答中不存在真实凭证或测试用假 secret。

新增或修改 Skill 后，至少运行契约检查；如果有可用 subagent，再运行带 `--require-agent` 的黑盒
检查。这个 Benchmark 不会写入用户的 HyperHub 配置，也不会执行 `approve`。
