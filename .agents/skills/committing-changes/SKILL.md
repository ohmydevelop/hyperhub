---
name: committing-changes
description: Use when preparing, splitting, writing, or reviewing Git commits and commit messages for the HyperHub repository.
---

# HyperHub 提交规范

## 核心原则

每个 Commit 只表达一个逻辑变更。提交摘要和正文使用中文，保持可检索、可回滚、可审查。仓库采用无人值守全流程自动提交：当前任务变更自检通过后自动执行 `git commit`；若用户仅要求生成消息，则不改变 Git 历史。

## 提交流程

1. 查看 `git status` 和相关 diff，确认只包含当前任务的文件；保留用户已有修改。
2. 按逻辑拆分变更。功能、Bug 修复、文档、测试和纯格式化通常分别提交；不要为了省时间合并无关变更。
3. 检查待提交文件，禁止提交密钥、Token、密码、真实凭证、本地构建产物、临时文件或无关审计数据。
4. 按下列格式生成 Commit message，并让摘要准确描述实际变更：

   ```text
   <type>(<scope>): <中文摘要>
   ```

5. 在提交前运行与改动风险匹配的验证；未运行的测试标记为“未验证”，不得声称通过。

## 类型与正文

| type | 用途 |
| --- | --- |
| `feat` | 新增用户可见能力 |
| `fix` | 修复错误或回归 |
| `refactor` | 不改变外部行为的重构 |
| `perf` | 性能改进 |
| `docs` | 文档变更 |
| `test` | 测试变更 |
| `build` / `ci` | 构建或持续集成变更 |
| `chore` | 其他维护性变更 |
| `revert` | 回滚已有提交 |

`scope` 可选，使用模块或平台名，例如 `core`、`broker`、`gateway`、`agent`、`linux`、`windows`。摘要使用简洁的动宾结构，末尾不加句号。需要背景时，摘要后空一行，正文说明原因、实现、影响和验证结果。

破坏性变更在类型后添加 `!`，并在正文中加入：

```text
BREAKING CHANGE: <中文说明>
```

## 示例

```text
feat(broker): 增加 HTTP CONNECT 认证支持

使用配置中的凭证引用完成 Basic/Header 认证。
验证：cargo test --workspace
```

```text
fix!(config): 重命名代理认证配置字段

BREAKING CHANGE: 旧字段不再兼容，请迁移到新配置字段。
```

## 提交前检查

- [ ] 变更已按逻辑拆分，未混入无关格式化。
- [ ] 摘要为中文，类型和范围准确。
- [ ] 破坏性变更已声明兼容性影响。
- [ ] 未包含敏感信息或构建产物。
- [ ] 验证结果真实且可复现。
