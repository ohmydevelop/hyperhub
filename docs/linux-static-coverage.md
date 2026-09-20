# Linux 静态无符号程序覆盖

## 目标与约束

HyperHub 覆盖静态链接、已移除 ELF 符号的 Go、C 和 Rust 程序，包括直接 syscall。基础实现不要求 seccomp user notification、pidfd、eBPF、LSM、动态加载器或目标 libc；这些能力只作为优化。

最低前提是目标由 HyperHub 启动，并且系统允许父进程 ptrace 自己创建的同用户子进程。系统完全禁止 ptrace 时，enforce 模式明确失败，不静默放行。静态分支在要求 Agent runtime 和初始化 Frida Core 之前分流，因此不依赖 Frida 注入成功。

## 后端边界

- 动态、静态和 stripped ELF：默认使用 ptrace syscall supervisor，不依赖 Agent runtime、动态符号或目标 libc。
- 有 `PT_INTERP` 的动态 ELF：可显式使用 `--backend gum`，由 Frida Core 注入 Gum Agent 并用 Gum Interceptor 执行动态符号 Hook；此模式下 Agent runtime 缺失或校验失败时不启动目标。
- 无 `PT_INTERP` 的静态 ELF：标准 Frida Gum 注入不受支持，不解析或校验 Agent runtime，直接进入 ptrace syscall supervisor。

`--runtime` 只对动态 ELF 的显式 Gum 模式有意义。默认 ptrace 或静态 ELF 收到该参数时会明确警告并忽略，避免让调用方误以为 Gum 已注入。

## 保底后端

动态与静态 ELF 默认使用 CLI 内置 ptrace syscall supervisor；动态 ELF 的 Gum 是显式优化模式：

1. 子进程 `PTRACE_TRACEME` 后 exec 原始目标；
2. 父进程在 exec trap 激活 Session；
3. `PTRACE_SYSCALL` 捕获 syscall entry/exit，不依赖符号；
4. `PTRACE_O_TRACECLONE/FORK/VFORK/EXEC` 接管线程和后代；
5. 后代第一次产生受控意图前登记真实 PID；
6. `PTRACE_O_EXITKILL` 防止 supervisor 异常退出后留下失控进程。

## 当前阶段：最坏条件基线

当前默认且唯一的静态执行路径是全量 `PTRACE_SYSCALL`。它不根据程序名称、编译器、libc、符号、syscall 频率或内核可选能力裁剪跟踪点；每个 syscall 都经过 entry/exit 状态机，再由意图层决定是否读取参数、改写结果或更新状态。

阶段顺序固定为：

1. **保底正确性**：全量 ptrace 覆盖静态无符号程序和直接 syscall；
2. **保底路径优化**：在不跳过 syscall、不改变语义的前提下减少分配、重复解析和跨进程内存访问；
3. **环境能力加速**：最后才考虑 seccomp-BPF、pidfd、eBPF 等可选能力，并保留自动回退和等价性测试。

在第一阶段完成前，不以 Codex、Go runtime、musl/glibc 或特定二进制特征做适配。

## 意图覆盖

完整点位矩阵见 `docs/hook-intent-matrix.md`。静态后端当前覆盖：

- DNS：UDP connect 状态，以及 `write/read`、`sendto/recvfrom`、`sendmsg/recvmsg`；
- 网络：`socket/connect/getsockopt`、非阻塞 `fcntl/ioctl`、descriptor dup/close；
- 文件：open/openat/openat2/creat、read/write 及 vectored/positioned 变体、unlink、rename、mmap/mprotect/munmap；
- 进程：clone/clone3/fork/vfork、execve/execveat、wait4；
- 后代：fork/exec 后继续共享 Session、sandbox 与审计。

DNS 响应中的 A/AAAA 会建立 IP→域名关联，SOCKS5 CONNECT 优先发送域名。这样 domain firewall、route 和审计不会因为目标是静态程序而退化成纯 IP。UDP DNS socket 只观察，不会被重定向到 TCP SOCKS listener。

## Sandbox

Session bootstrap 向 launcher 提供已编译来源的 sandbox snapshot。supervisor 使用 HyperHub Core 的统一语义编译规则：

- file sandbox 在 syscall 副作用前判定 read/write/create/delete/rename；
- rename 同时检查源和目标；
- 可写文件 mmap 按 write 判定；
- process sandbox 在 clone/fork/vfork 及 execve/execveat 前判定；exec 路径读取 executable 和 argv；
- deny 通过把原 syscall 替换成无副作用 syscall，再覆盖返回值为 `-EACCES`；
- observe 模式只审计，不阻断；
- 静态 supervisor 使用专用认证请求上报 `sandbox_denied`，但不赋予目标额外控制能力。

TCP 最终仍进入 Serve，服务端会再次执行 firewall、route、代理和连接审计。

## 可复用 Benchmark

完整测试矩阵、缓存规则、单命令入口和产物说明见 `docs/benchmarks/linux-backend-suite.md`。日常开发执行：

```sh
./scripts/benchmark-linux-backends.sh
```

旧 `test-linux-static-coverage.sh` 仅保留为兼容包装，实际执行同一套 benchmark。

## 测试

- C 对抗 fixture 触发当前架构 manifest 中所有必测 hook 点；缺失点会让集成测试失败；
- C/Go/Rust 根进程和 exec 后代在不提供 Agent runtime 的情况下执行真实 TCP echo；测试还把 CLI 复制到没有任何 runtime discovery 候选的位置，验证静态启动不解析 Gum runtime；
- C 分别使用三种 UDP DNS I/O，连接审计必须恢复 `localhost`；
- file 五种操作、process fork、根进程 exec 和 fork 后代 exec 分别配置 deny 并验证审计；
- BusyBox、GitHub CLI、yq、ripgrep 用于大型静态程序兼容性和性能；
- Codex 251 MiB static PIE 使用通用后端完成真实模型对话，不存在 Codex 专用适配。

## 当前边界

- TCP connect 和传统 UDP/TCP DNS已覆盖；通用 UDP、QUIC/HTTP3 仍不支持；
- DNS parser 处理常见 A/AAAA 响应和压缩名称，不替代完整递归解析器；
- file mprotect/munmap 作为生命周期点位观测，规则判定发生在 open/read/write/mmap 等有文件身份的点位；
- secure-exec、setuid/setgid 和禁止 ptrace 的策略不绕过。

## 后续优化

第二阶段先优化全量 ptrace 路径本身；第三阶段才允许使用 seccomp-BPF、`process_vm_readv/writev`、pidfd 或 eBPF/cgroup。任何环境相关优化都必须默认可关闭、失败后回退，并通过与全量 ptrace 相同的 Hook、sandbox、DNS 和后代测试。
