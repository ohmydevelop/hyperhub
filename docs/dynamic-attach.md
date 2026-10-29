# 动态附加开发版

动态附加功能在 `dev/dynamic-attach` 分支开发，首个目标预发行版本为 `v0.3.0-alpha.1`。这份文档描述开发契约；版本是否已经发布、各平台是否通过验收，以该标签的 GitHub Pre-release、CI 和测试报告为准。稳定分支需经过实际试用反馈后才合并。

## 安装与运行实例

开发版使用明确标签安装，默认配置和运行目录为用户目录下的 `.hyperhub-dev`。安装器将二进制放入独立版本目录，不覆盖稳定版快捷方式，不自动把开发版加入全局 PATH。开发版不自动替换自身版本。后续版本同样使用明确标签安装。

Linux：

```bash
curl -fsSL https://github.com/ohmydevelop/hyperhub/releases/download/v0.3.0-alpha.1/install.sh -o install-hyperhub-dev.sh
HYPERHUB_VERSION=v0.3.0-alpha.1 sh install-hyperhub-dev.sh
"$HOME/.local/opt/hyperhub-dev/0.3.0-alpha.1/hyperhub" start
```

Windows PowerShell：

```powershell
Invoke-WebRequest https://github.com/ohmydevelop/hyperhub/releases/download/v0.3.0-alpha.1/install.ps1 -OutFile install-hyperhub-dev.ps1
$env:HYPERHUB_VERSION = 'v0.3.0-alpha.1'
& ./install-hyperhub-dev.ps1
& "$env:USERPROFILE/.hyperhub-dev/bin/0.3.0-alpha.1/hyperhub.exe" start
```

以下示例中的 `hyperhub` 指上述开发版的绝对路径。自定义实例时，所有命令使用同一 `HYPERHUB_HOME`。内置 Skill 安装到该实例的 `skills/hyperhub-cli`，可以通过开发版 `hyperhub skill` 读取。

稳定版和开发版并行运行时，还需为两个实例分别配置监听地址或端口；独立 Home 不隔离操作系统的网络端口。端口占用应明确报错，不能停掉另一个实例来完成启动。

## 为运行中的程序创建审批

```text
hyperhub attach <pid> --scope tree --backend auto
hyperhub approve <request-id>
hyperhub status --json
```

`attach` 创建待审批请求；人类在真实终端审核进程身份、范围、后端和策略，并输入管理员密码。Agent 负责创建请求、说明审批入口和检查最终状态，不代填密码或执行批准。API Key 不能单独授权附加或卸载。

`tree` 是默认范围，包含目标全部线程、既有后代和未来后代。`process` 仅接管目标的全部线程。实际执行文件访问或网络操作的独立服务，需要作为目标或被覆盖的后代纳入。附加一个客户端不会自动覆盖树外执行器。

Linux 提供 `ptrace` 和 `gum` 后端；Windows 提供 `gum`。macOS 不在首版范围内。进程权限、已有跟踪器、二进制兼容性和当前策略要求都会影响是否可以附加。无法证明安全时，操作应拒绝或保留明确的清理状态，不通过重启目标或叠加旧基座实现表面成功。

Linux 的 `auto` 选择 ptrace。Gum 要求环境已经允许其辅助进程跟踪进程执行转换和未来子进程；首版只在 Yama `ptrace_scope=0` 的环境中开放 Gum，包括 `process` 范围和可撤销 `run`。其他值或无法确认该值时拒绝 Gum。即使只接管单个进程，也必须覆盖该进程的自我 exec；一次注入成功不能证明执行转换后仍受保护。HyperHub 在审批和执行前检查，不会为附加修改系统限制。Gum 底层的线程调试辅助机制还可能改写目标的调试器许可，首版不承诺恢复无法读取的旧许可声明；有此要求时选择 ptrace。

部署保持无特权，仅保护受管范围；控制面程序和配置属于可信基础。审批公钥从已验证的初始化或人工批准建立信任，普通运行文件不能替换验证根。同用户程序如果能够修改全部可信基础或控制其内存，超出该部署的隔离边界。Gum 也不保证覆盖绕过原生 API Hook 的直接系统调用。

## 配置保存与平台边界

运行中的配置保存由 Core 验证实际接管范围和后端能力后执行。新配置在校验、编译或密文保存失败时，不能先改变磁盘内容、公开新的监听地址或切换 debug 状态。已解除的 Resident 是否还存在已接受激活，由实际 manager 的内存状态确认，不能仅根据显示阶段判断。持久化请求使用独立的密码派生签名，并绑定当前 Core 启动代次；API Key 不能签署这类请求。

首版开发契约中，Linux 和 Windows 的在线保存还要求认证实际 Core IPC peer。macOS 的普通 Serve、run 和离线配置保持可用，但本 alpha 不提供在线配置保存：应先停止 Serve，再保存配置。CLI 在连接或发送含 Secret 的配置内容前明确拒绝该在线操作，不自动退回普通未认证连接或离线写盘。macOS 原生行为尚未执行验证；动态附加也不在 macOS 首版范围内。

Windows 原生 `CreateProcess` 和 MSYS/Cygwin `fork` 是不同的进程模型。当前开发版会在提案、执行和注入前检查目标的实际运行时导出；发现 MSYS/Cygwin fork ABI 时，拒绝外部进程的 process/tree 附加。已附加的程序后来加载该运行时，会报告 `degraded`；仍接管时，其 fork/vfork 在创建子进程前被拒绝，不进入不完整的子进程重建路径。解除后的分支直接调用原生 fork，不执行 HyperHub 子进程重建；这不表示 copied heap、地址缓存和 Winsock 状态的透明兼容已经实现或验收。

MSYS/Cygwin 的完整透明附加和跨 fork 连接目前不在支持范围，普通托管启动的既有实现也不能代替这项验收。统一 Windows Suite 的 `-PosixRuntimeCompiler` 参数接收真实 MSYS/Cygwin 编译器，运行原生对照及当前能力拒绝回归；完整 managed-continuity oracle 另行保留，不能用拒绝回归、Windows GNU 交叉编译或 `not_executed` 报告冒充通过。原生 Windows 场景尚未在本机执行。

## 解除接管和安全卸载

```text
hyperhub detach <attachment-id>
hyperhub approve <request-id>
hyperhub status --json
```

attachment ID 来自 `status --json` 中的 `attachments`。提交和批准不是操作完成的证明，应检查实际阶段与原因：

| 阶段 | 含义 |
| --- | --- |
| `active` | 后端已接管目标及报告的成员范围 |
| `draining` | 新的策略接管已停止，正在等待兼容资源排空 |
| `detached_resident` | 策略接管已解除，兼容组件仍驻留 |
| `detached` | 后端已确认安全卸载完成 |
| `degraded` | 防护能力出现降级，应读取原因 |
| `cleanup_pending` | 操作未完整收尾，仍存在需要清理的状态 |
| `failed` | 操作失败，应读取实际错误 |
| `exited` | 目标已退出 |

允许的长连接、正在执行的回调、线程退出回调和应用缓存的 FAKE-IP 可能阻止物理卸载。连接数归零不能证明应用已丢弃地址缓存。后端可以保留最低兼容组件，不能因此把状态写成完全卸载，也不能强制断开业务连接。

附加前已有的 DNS 缓存不可观测，单凭一个地址无法证明它是 HyperHub 发放的别名。外部解析结果与 HyperHub 的签名发行历史必须区分，跨进程传递地址也不能丢失原始解析来源。显式使用合成地址的能力需要独立地址池；原生解析已经返回该池内地址时，应拒绝继续合成，不能猜测地址含义。依赖无法证明的域名或信任能力的策略应明确拒绝接管。

接管目标时应保持 PID、环境、工作目录、stdio、TTY 和允许的业务连接。已经创建的 TLS 或 SSH 信任上下文无法保证透明改写；策略需要后端尚未证明支持的能力时，应在执行前拒绝。Serve 断连时，存活后端继续使用缓存策略及其失败动作。Linux ptrace 跟踪器致命退出会失去系统调用拦截，必须报告降级；目标存活不等于仍受保护。

## 复现和验收

Linux 与 Windows 的源码 fixture、审批驱动和统一 Suite 保存在仓库。全部运行使用独立 Home、虚构凭证和本地服务。不要对真实业务进程运行破坏性故障测试。

Linux 示例：

```bash
python3 scripts/test-dynamic-attach.py --hyperhub /absolute/path/to/hyperhub --backend ptrace --origin attach --target-pty --cycles 100 --duration 7200 --output target/benchmarks/attach-ptrace
python3 scripts/test-dynamic-attach.py --hyperhub /absolute/path/to/hyperhub --backend gum --origin run --target-pty --cycles 3 --output target/benchmarks/run-gum
```

Windows PowerShell 示例：

```powershell
python scripts/test-dynamic-attach-windows.py --hyperhub C:/absolute/path/to/hyperhub.exe --origin attach --cycles 100 --duration 7200 --output target/benchmarks/attach-windows
```

输出目录须是新的目录，保留失败记录。普通 CI 运行短回归；开发分支最终提交包含 `[attach soak]` 时，CI 运行三个后端的至少 100 次循环与两小时混合压力，并单独测试可撤销 `run`。预发行发布门禁要求同一提交的常规 CI 与这三个压力任务全部成功。Windows 原生执行和 Linux aarch64 原生运行分别报告，交叉编译不代替原生验证。性能比较需要同一构建、同一工作负载和有效工作计数；未通过正确性测试的运行不计为有效性能结果。

Linux Gum 正例 CI 使用 GitHub 专用的一次性测试虚拟机，显式准备 `ptrace_scope=0` 并在结束时恢复原值。这只证明该前提下的后端行为，不证明系统默认限制下可以接管进程树。环境脚本拒绝在普通本机或自托管 runner 上执行；本地受限环境验证的是执行前拒绝且目标保持原生行为。
