# 运行中进程的附加与卸载审批

用户要求保护、附加、解除接管或卸载一个运行中程序时，创建审批是 Agent 的工作。用户不需要再额外要求“创建审批”。这些是运行时操作，不是配置 JSON Patch。

## 确认目标与实例

1. 确认使用的 CLI 绝对路径、版本来源及 `HYPERHUB_HOME`，读取该二进制的 `--help`、`status --json`。旧版不提供 attach/detach 时报告实际限制，不尝试叠加注入。
2. 确认实际执行文件访问和网络操作的进程。客户端把任务委托给独立常驻执行器时，附加客户端不代表已经保护执行器。
3. 核对 PID、创建身份、可执行文件和所属用户。同名进程不唯一时，列出脱敏候选并确认目标，不能仅凭名称附加全部实例。
4. 默认 tree 包含该目标的全部线程、既有后代和未来后代；process 仅包含目标全部线程。审批预览中的范围必须符合用户意图，树外进程不会自动纳入。

## 主动提交审批

```text
hyperhub attach <pid> --scope tree --backend auto
hyperhub detach <attachment-id>
```

attach/detach 只创建待审请求。卸载使用 `status --json` 中实际记录的 attachment ID，不猜测 ID，不使用配置 UUID 代替。

`approval_trust.state: unenrolled` 表示运行时审批验证根尚未登记，不表示当前配置或已有文件策略失效。照常主动提交请求；人类执行 `approve` 时，同一次密码输入完成登记和原请求审批。不要要求用户另行初始化公钥、编辑运行文件或自己创建提案。`approval_trust_source: unavailable` 表示当前无法读取实时审批状态，不能把离线记录解释成已登记或未登记。

提交成功后报告 `proposal_submitted`，说明请求 ID、目标和范围。人工审批的语法是 `hyperhub approve <request-id>`；交付给用户的实际命令必须保留本轮已核实的 CLI 绝对路径和 `HYPERHUB_HOME`，不能仅给裸 `hyperhub approve` 后让另一个终端猜测 PATH 或实例。配置审批与运行时审批都遵守此规则。

例如 POSIX Shell（替换为本轮实际路径）：

```sh
HYPERHUB_HOME='/absolute/instance-home' '/absolute/path/to/hyperhub' approve <request-id>
```

例如 Windows PowerShell（替换为本轮实际路径）：

```powershell
$env:HYPERHUB_HOME = 'C:/absolute/instance-home'
& 'C:/absolute/path/to/hyperhub.exe' approve <request-id>
```

只输出当前平台所需的实际命令，并按该 Shell 正确引用路径；不要把示例占位路径原样交给用户。无法确定实际二进制或实例时，先完成只读确认。

Agent 不得运行 approve，不读取或代填管理员密码，不自行批准。API Key 不足以代替人工授权。提交成功不等于批准，批准成功不等于操作执行完成。

## 审批后验证

用户确认审批完成后，查询同一实例的 `status --json`，根据 attachments 的实际执行阶段报告结果：

- active：目标已经接管；仍须检查实际执行器和成员范围，不能把一个根 PID 解释成任意外部进程均受保护。
- draining：已经开始解除接管，兼容资源尚未排空。
- detached_resident：已解除策略接管，但兼容组件仍驻留；不能报告“已完全卸载”。
- detached：后端确认安全卸载完成。
- degraded、failed、cleanup_pending：分别报告防护降级、执行失败或清理未完成，保留实际原因。
- exited：目标已经退出，不代表执行过完整卸载流程。

FAKE-IP 可能仍在应用缓存中；即使连接数归零，也不能据此要求强制卸载。既有长连接、活动回调和线程退出回调也可能需要保留兼容组件。

重复提交、审批时身份变化、权限不足、跟踪器冲突、过期授权或旧基座不兼容时，按实际错误处理。不得杀进程、重启目标、停用系统附加限制或用 run 新建进程来伪装附加成功。

Serve/CLI 断连时，存活后端继续缓存策略与配置的失败动作。动态 ptrace 跟踪器本身致命退出属于失去拦截的降级边界；目标仍存活不能证明防护仍在。

## 开发版操作

开发版通过明确的预发行标签安装在独立目录，默认运行目录为 `.hyperhub-dev`。使用其绝对路径和同一 Home 完成全部操作；不修改目标的 HOME、不覆盖稳定版二进制、用户 PATH 或稳定版 Skill。开发版不自动切换版本。
