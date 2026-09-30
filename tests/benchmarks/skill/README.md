# HyperHub Skill 黑盒 Benchmark

这个 Benchmark 验证面向用户和 Agent 的 `hyperhub-cli` Skill 是否足够完备，能够独立指导普通配置数据生成和关键运行决策。
它把 Skill 和脱敏配置 fixture 作为黑盒 subagent 的隔离输入，以检验 Skill 自身是否公开了足够的配置 Schema、UUID 语义、JSON Patch 写法、敏感占位符、人工审批边界、诊断依据和升级条件。输入隔离是 Benchmark 的测试方法，不是要求 Skill 对 Agent 设置普遍的源码访问禁令。

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

- 新增 Schema v2 Bearer 凭证和 HTTP 路由，并使用 `${APPROVE:name}` 占位符；
- 通过 UUID + `test` 安全修改现有配置；
- 通过 UUID + `test` 安全删除现有对象；
- 生成 RFC 6902 patch，而不是猜测内联 CLI 参数；
- 区分 Agent 提交审批队列与人工 `approve`，禁止 Agent 代填真实 secret；
- 检查回答中不存在真实凭证或测试用假 secret。
- 验证普通操作可优先由 Skill、配置参考、脱敏 `show` 和 CLI 诊断完整指导，并能说明何时需要升级到实现调查，而不是设置绝对源码禁令；
- 验证 `ssh_transcript=false` 只关闭内容文件，同一路由绑定 SSH 凭证与审计 Profile 时结构化命令事件仍保留；
- 验证仅替换 `<redacted>` Secret 被 CLI 判为无变化时，Agent 报告限制且不删除重建凭证或改变 UUID；
- 验证 SSH 行为测试必须在审批完成、Serve 运行后通过 `hyperhub run -- ssh ...` 执行。

新增或修改 Skill 后，至少运行契约检查；如果有可用 subagent，再运行带 `--require-agent` 的黑盒
检查。这个 Benchmark 不会写入用户的 HyperHub 配置，也不会执行 `approve`。
