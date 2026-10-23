# Linux 运行时夹具

`file_alias_target.rs` 用 dummy 文件验证受管进程不能通过硬链接、重命名或符号链接读取受路径规则拒绝的内容，并保留普通文件硬链接和重命名的成功对照。仅拒绝写入的规则另有直接读成功、直接写拒绝、硬链接/重命名后写入不能成功及原内容保持的断言。Linux 路径还覆盖 `linkat` 目录 fd、跟随/不跟随末端符号链接、继承的 O_PATH fd、`AT_EMPTY_PATH`（先验证本机无保护时可用）、目录符号链接与 `..`、精确路径规则，以及 `RENAME_EXCHANGE` 的双向交换。`file_alias_live` 运行真实隔离 CLI/Serve，分别验证 ptrace 和 Gum，已注册到 Linux/Windows Suite；它不声称 Gum 能拦截绕过 libc 的任意内联系统调用。创建于托管树之外、在首次路径拒绝之前读取的已有硬链接被记录为文件名正则策略的独立诊断；可读时明确输出保护缺口，拒绝时输出受保护，测试不要求该漏洞一直存在。该诊断不声称提供 inode 级全系统保护。

`restart_target.rs` 是跨平台常驻执行器，用本地 dummy 文件验证 Serve 重启后的文件拒绝、允许读取和 shell 子命令进度。`serve_restart_live` 驱动真实隔离 CLI，覆盖原根存活、根退出后子进程存活、Linux 根进程合法 exec、控制 socket 暂时不可用、两次重启及重启后的策略更新；同时检查会话身份、成员和 Engine Host 重新上线。Gum 负例保持私有 Serve 不可用至初始化超时，核对原 spawn 成功语义、被拒绝子进程的信号、marker 未写入及父执行器恢复；相同 shell 在断线前必须实际成功写入该 marker。

`executor_scope_target.rs` 用本地 TCP IPC 模拟预先启动的外部执行器。`executor_scope_live` 验证托管客户端直接读取 dummy 文件被拒绝，但委托树外服务读取仍发生在外部进程中，并核对完整成员列表和实际 PID 创建身份。它记录保护边界，不把 HyperHub 声称为全系统防御。这两组源码回归已注册到 `scripts/benchmark-linux-backends.sh` 和 `scripts/test-windows-hooks.ps1`，不需要真实凭证或外部服务。

`linux_probe.c` 用于验证动态 ELF 的默认 ptrace 后代覆盖和显式 Gum 完整 manifest：DNS、阻塞与非阻塞 connect、延迟 SOCKS 握手、send/recv/sendto/recvfrom/sendmsg/recvmsg、fcntl/ioctl、dup/dup2/dup3/F_DUPFD、Unix socket 的 `SOCK_NONBLOCK`/`F_SETFL`/`FIONBIO` 语义、open/open64/openat/openat64/creat、read/write/readv/writev/pread/pwrite、rename/unlink 变体、只读文件映射升级为可写权限的 mprotect、mmap/munmap、execve 失败路径，以及 fork+exec、posix_spawn/posix_spawnp 后代递归注入。

`linux_static_probe.c` 是无符号静态 C 对抗探针。它按意图覆盖 DNS 三种 I/O、TCP 三种 I/O、descriptor 状态与复制、open/read/write 的 positioned/vectored 变体、rename/unlink 变体、mmap 生命周期，以及 clone/clone3/fork/vfork/execve/execveat/wait4。根进程和 exec 后代都会联网。

```sh
gcc -O2 -Wall -Wextra linux_probe.c -o linux_probe
../../target/release/hyperhub run --runtime ../../target/release/libhyperhub_gum_agent.so -- \
  ./linux_probe 127.0.0.1 <echo-port>
```

构建无符号静态探针：

```sh
cc -O2 -static -s -fno-ident -Wl,--build-id=none linux_static_probe.c -o linux_static_probe
file linux_static_probe
nm -an linux_static_probe
```

`nm` 不应输出可用符号。启动本地 TCP echo server 后，可分别直接运行和通过 `hyperhub run` 运行探针；HyperHub 模式下两次 TCP 连接都应出现在连接审计中。

夹具不依赖 Ubuntu 路径或特定内核版本。

`linux_http_credential_probe.py` 是动态 ptrace 的 HTTP 路由回归夹具：客户端以 `localhost` 建连并发送占位 Authorization，服务端只接受经协议探测重新匹配 URL 路由后注入的 Bearer 值。它覆盖系统 DNS 无可观测报文时，IP-form SOCKS 连接依据 HTTP Host/path 精化策略的路径。
