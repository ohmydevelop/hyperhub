# Hook 意图与点位矩阵

HyperHub 先按安全意图定义语义，再为不同运行后端绑定点位。点位不是按某个应用名称选择；Codex、BusyBox、Go、Rust 或 C 都经过相同的 ELF 与 syscall 路径。

## 网络请求

一次域名网络请求至少跨越 DNS、socket 状态、TCP connect、数据收发和描述符生命周期：

| 子意图 | 动态 ELF 点位 | 静态 ELF syscall 点位 | 验证 |
| --- | --- | --- | --- |
| DNS 请求 | `getaddrinfo/freeaddrinfo` | `write/read`、`writev/readv`、`sendto/recvfrom`、`sendmsg/recvmsg`、`sendmmsg/recvmmsg`，以及 UDP `connect` 状态 | 标量/vectored/batch、部分成功、多事务源码回归；连接审计核对目的域名 |
| socket 建立 | `connect` 前的 libc socket 状态 | `socket` | C/Go/Rust TCP；C UDP DNS |
| 非阻塞状态 | `fcntl`、`ioctl` | `SOCK_NONBLOCK`、`fcntl(F_GETFL/F_SETFL)`、`ioctl(FIONBIO)` | C 同时验证设置与读取语义；Go、Rust 覆盖常见路径 |
| TCP 重定向 | `connect` | `connect` entry/exit | 根进程和 exec 后代都必须经 SOCKS5 |
| 描述符复制 | 运行时 socket 状态 | `dup/dup2/dup3`、`fcntl(F_DUPFD*)` | C fixture hook report |
| 数据路径 | `send/recv/sendto/recvfrom/sendmsg/recvmsg` | `read/write/readv/writev/pread/pwrite`、`sendto/recvfrom`、`sendmsg/recvmsg` | C echo 的多种 I/O；Go/Rust 标准库 I/O |
| 连接结果 | libc 返回值 | `getsockopt(SO_ERROR)` | C fixture hook report |
| 关闭 | `close` | `close/close_range`，exec 时清理 `CLOEXEC` 状态 | 每种 fixture、close-range 源码路径与大型程序 |

静态 DNS 响应解析 A/AAAA 记录，并把 IP 关联回域名。后续 SOCKS5 CONNECT 优先发送域名，使 domain firewall、route 与审计不退化成纯 IP。UDP socket 本身不会被错误重定向到 TCP SOCKS listener。

DNS 查询按 socket 身份、resolver、transaction ID 和 question 关联，不能用同一 fd 的最后一个查询替代响应身份。Linux 当前明确拒绝 `MSG_FASTOPEN` 组合建连并返回 `EOPNOTSUPP`；目标可改用普通 connect 后发送数据，不能直接绕过网关。

`poll/ppoll/select/epoll` 不是策略边界：supervisor 在握手期间临时同步化 connect，并在握手前向目标虚拟化 `F_GETFL` 的非阻塞可见性，完成后恢复内核非阻塞状态，所以这些等待 API 不需要改写。它们仍由目标原样执行。descriptor 复制和 fork 继承的是同一个 open file description 语义，握手与非阻塞状态必须在所有别名间一致。

## 文件意图

| 意图 | 动态 ELF 点位 | 静态 ELF syscall 点位 | 验证 |
| --- | --- | --- | --- |
| 打开/创建 | `open/open64/openat/openat64/creat` | `open/openat/openat2/creat` | hook report；create deny 场景 |
| 读取 | `read` | `read/pread64/readv/preadv/preadv2` | hook report；read deny 场景 |
| 写入 | `write` | `write/pwrite64/writev/pwritev/pwritev2` | hook report；write deny 场景 |
| 删除 | `unlink/unlinkat` | `unlink/unlinkat` | hook report；delete deny 场景 |
| 重命名 | `rename/renameat` | `rename/renameat/renameat2`，同时检查源和目标 | hook report；仅目标路径命中 deny 的场景 |
| 映射 | `mmap/mprotect/munmap` | `mmap/mprotect/munmap` | hook report；初始可写映射及只读映射升级为可写权限均按 write 意图判定 |

相对路径按目标进程 cwd 或 dirfd 解析。文件规则使用与 Agent 相同的正则、优先级、默认动作和 error action。

文件映射的可读、可写或可执行访问均检查 Read 意图，可写访问另外检查 Write。仅设置 `PROT_WRITE` 也不能用于绕过 Read：部分体系结构的可写页同时可读。匿名映射不按传入但被内核忽略的 fd 判定文件权限。

## Windows 异步解析与组合建连

`GetAddrInfoExW` 保留调用者的 OVERLAPPED、事件/回调和取消句柄。异步解析在原生回调或 `GetAddrInfoExOverlappedResult` 交付结果时登记域名；立即完成遵循原生同步返回约定。`ConnectEx` 无首包的路径继续支持，非空首包当前明确返回 `WSAEOPNOTSUPP`，避免首包先于 SOCKS 握手发送。Windows 源码回归通过 `scripts/test-windows-hooks.ps1` 集中运行，并接入 CI。

## 进程意图

| 意图 | 动态 ELF 点位 | 静态 ELF syscall/事件点位 | 验证 |
| --- | --- | --- | --- |
| 创建线程/进程 | `posix_spawn/posix_spawnp` 与平台创建 API | `clone/clone3/fork/vfork` + ptrace events | C fixture hook report，Go/Rust 多线程 |
| 替换映像 | `execve` | `execve/execveat` | exec 后代联网；process sandbox deny |
| 生命周期 | child gating | `wait4`、exit event、`PTRACE_O_EXITKILL` | 根进程退出码和后代审计 |

process sandbox 在 clone/fork/vfork 和 exec 副作用发生前判定；exec 读取目标 executable 与 argv。命中 deny 时用无副作用 syscall 替换原 syscall，再返回 `EACCES`。

## 自动验证

`scripts/test-linux-static-coverage.sh` 执行四层检查：

1. 动态 C fixture 默认使用 ptrace 覆盖后代进程，并显式使用 Gum Agent 执行 当前 manifest 对应的全部必测语义分组，输出 `dynamic-hooks.json`；open/open64 与 openat/openat64 按同址 alias 组统计；
2. 静态 C/Go/Rust 不提供 Agent runtime，根进程和 exec 后代仍产生至少 6 条连接审计；
3. 静态 C 对抗 fixture 输出 `hooks.json`，manifest 中所有当前架构必测点位都必须出现；
4. file read/write/create/delete/rename、process fork、根进程 exec 与 fork 后代 exec 分别配置 deny，必须全部失败并产生统一的 `security_alert`。

大型兼容性 benchmark 继续覆盖 BusyBox、GitHub CLI、yq 和 ripgrep。Codex 使用同一个静态 syscall supervisor 做真实模型对话测试，产品代码中没有 Codex 名称、路径、特征码或专用分支。
