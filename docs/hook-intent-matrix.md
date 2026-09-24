# Hook 意图与点位矩阵

HyperHub 先按安全意图定义语义，再为不同运行后端绑定点位。点位不是按某个应用名称选择；Codex、BusyBox、Go、Rust 或 C 都经过相同的 ELF 与 syscall 路径。

## 网络请求

一次域名网络请求至少跨越 DNS、socket 状态、TCP connect、数据收发和描述符生命周期：

| 子意图 | 动态 ELF 点位 | 静态 ELF syscall 点位 | 验证 |
| --- | --- | --- | --- |
| DNS 请求 | `getaddrinfo/freeaddrinfo` | `write/read`、`sendto/recvfrom`、`sendmsg/recvmsg`，以及 UDP `connect` 状态 | C fixture 分别执行三种 DNS I/O；连接审计必须恢复 `localhost` |
| socket 建立 | `connect` 前的 libc socket 状态 | `socket` | C/Go/Rust TCP；C UDP DNS |
| 非阻塞状态 | `fcntl`、`ioctl` | `SOCK_NONBLOCK`、`fcntl(F_SETFL)`、`ioctl(FIONBIO)` | C、Go、Rust 各覆盖一种常见路径 |
| TCP 重定向 | `connect` | `connect` entry/exit | 根进程和 exec 后代都必须经 SOCKS5 |
| 描述符复制 | 运行时 socket 状态 | `dup/dup2/dup3`、`fcntl(F_DUPFD*)` | C fixture hook report |
| 数据路径 | `send/recv` | `read/write`、`sendto/recvfrom`、`sendmsg/recvmsg` | C echo 的三种 I/O；Go/Rust 标准库 I/O |
| 连接结果 | libc 返回值 | `getsockopt(SO_ERROR)` | C fixture hook report |
| 关闭 | `close` | `close` | 每种 fixture 与大型程序 |

静态 DNS 响应解析 A/AAAA 记录，并把 IP 关联回域名。后续 SOCKS5 CONNECT 优先发送域名，使 domain firewall、route 与审计不退化成纯 IP。UDP socket 本身不会被错误重定向到 TCP SOCKS listener。

`poll/ppoll/select/epoll` 不是策略边界：supervisor 在握手期间临时同步化 connect，完成后恢复原始非阻塞状态，所以这些等待 API 不需要改写。它们仍由目标原样执行。

## 文件意图

| 意图 | 动态 ELF 点位 | 静态 ELF syscall 点位 | 验证 |
| --- | --- | --- | --- |
| 打开/创建 | `open/open64/openat/openat64/creat` | `open/openat/openat2/creat` | hook report；create deny 场景 |
| 读取 | `read` | `read/pread64/readv/preadv/preadv2` | hook report；read deny 场景 |
| 写入 | `write` | `write/pwrite64/writev/pwritev/pwritev2` | hook report；write deny 场景 |
| 删除 | `unlink/unlinkat` | `unlink/unlinkat` | hook report；delete deny 场景 |
| 重命名 | `rename/renameat` | `rename/renameat/renameat2`，同时检查源和目标 | hook report；仅目标路径命中 deny 的场景 |
| 映射 | `mmap/mprotect/munmap` | `mmap/mprotect/munmap` | hook report；可写文件映射按 write 意图判定 |

相对路径按目标进程 cwd 或 dirfd 解析。文件规则使用与 Agent 相同的正则、优先级、默认动作和 error action。

## 进程意图

| 意图 | 动态 ELF 点位 | 静态 ELF syscall/事件点位 | 验证 |
| --- | --- | --- | --- |
| 创建线程/进程 | `posix_spawn/posix_spawnp` 与平台创建 API | `clone/clone3/fork/vfork` + ptrace events | C fixture hook report，Go/Rust 多线程 |
| 替换映像 | `execve` | `execve/execveat` | exec 后代联网；process sandbox deny |
| 生命周期 | child gating | `wait4`、exit event、`PTRACE_O_EXITKILL` | 根进程退出码和后代审计 |

process sandbox 在 clone/fork/vfork 和 exec 副作用发生前判定；exec 读取目标 executable 与 argv。命中 deny 时用无副作用 syscall 替换原 syscall，再返回 `EACCES`。

## 自动验证

`scripts/test-linux-static-coverage.sh` 执行四层检查：

1. 动态 C fixture 默认使用 ptrace 覆盖后代进程，并显式使用 Gum Agent 执行 25 个 descriptor 对应的全部语义分组，输出 `dynamic-hooks.json`；open/open64 与 openat/openat64 按同址 alias 组统计；
2. 静态 C/Go/Rust 不提供 Agent runtime，根进程和 exec 后代仍产生至少 6 条连接审计；
3. 静态 C 对抗 fixture 输出 `hooks.json`，manifest 中所有当前架构必测点位都必须出现；
4. file read/write/create/delete/rename、process fork、根进程 exec 与 fork 后代 exec 分别配置 deny，必须全部失败并产生统一的 `security_alert`。

大型兼容性 benchmark 继续覆盖 BusyBox、GitHub CLI、yq 和 ripgrep。Codex 使用同一个静态 syscall supervisor 做真实模型对话测试，产品代码中没有 Codex 名称、路径、特征码或专用分支。
