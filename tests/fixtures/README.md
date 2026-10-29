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

`dynamic_attach_target.c` 是动态接管和可撤销 `run` 共用的无凭证目标。`scripts/test-dynamic-attach.py` 建立私有 HOME、Serve、管理员密码和本地 TCP echo 服务，通过真实 PTY 完成审批；目标自身可以运行于控制终端，核对 termios、前台进程组、PID、环境、stdio、cwd、已建立 TCP、后续 TCP、文件拒绝、fork/exec/spawn 后代、阻塞中的原始 read 和原始退出码 37。显式子进程环境使用仅含测试 marker 的 envp，检查 Hook 不补入父环境或信任变量。首次 detach 前还进行已批准的配置热更新。每循环记录 FD、线程和原生映射，预热后不能持续增长。

统一 Linux Suite 自动注册并执行 ptrace/Gum 的 attach/run 三循环及真实 PTY 路径。独立长测使用同一入口，例如：

```sh
python3 scripts/test-dynamic-attach.py --hyperhub target/release/hyperhub \
  --backend ptrace --origin attach --target-pty --cycles 100 --duration 7200 \
  --output target/benchmarks/attach-ptrace-stress
```

达到最小循环次数后，驱动保持混合策略生效/解除工作负载，最多每分钟增加一次审批循环，避免生成无界审批转录。结果包含原始循环数据、有限数量的延迟样本、分位数和有效完成命令计数；失败保留 `failure.json` 及退出码。审批耗时单独命名，不能当作纯系统暂停耗时。`--origin run` 同时断言解除后前台启动器仍等待目标并传递退出码。`dynamic_attach_legacy_marker.rs` 只导出通用原生 ABI 标记，不安装 Hook；`--legacy-negative` 预加载它并要求拒绝叠加接管，原进程和 TCP 保持正常。

`successful_cycles` 记录通过完整行为断言的循环数。`bounded_phase_valid_commands` 只统计各固定测量窗口中实际完成的命令；`paced_soak_valid_commands` 单独统计长测期间有节奏的混合业务命令。没有指定长测时，后者为零且对应速率为空，不表示循环没有执行业务。各阶段使用自己的真实计时，不把审批或整个测试耗时作为总容量分母。

`--fake-ip` 使用 `dynamic_attach_native_route.c` 模拟外部解析器及其已存在的原生连接路径，先在未管理的目标内验证该路径。`--issued-fake-ip` 单独调用实际已加载 SDK 的解析 ABI，缓存由 HyperHub 发布的地址。两者都先验证策略生效时的连接，然后批准收紧网关策略；解除后，缓存地址的阻塞与非阻塞连接必须到达原生本地 echo 目的地址，不得继续通过旧网关执行策略。统一 Suite 分别注册这两类来源，不能将没有原生路由的任意保留地址当作解除后的成功 oracle。

`--manager-loss clean` 仅对一次性 manager 发送 SIGKILL，要求新审批恢复同一会话及后代策略；`--manager-loss dirty` 先创建被虚拟化的非阻塞描述符，要求明确拒绝无法证明语义的恢复。`--serve-restart` 验证服务重启。驱动只继承 PATH、locale、终端及时区变量，并创建私有 HOME、运行目录和测试密码。可选 `--diagnostic-crash` 为一次性目标安装崩溃记录器，在真实错误时用私有 gdb 记录地址与无参数回溯，不打印环境、参数或局部变量，不更改宿主 core_pattern 或 ptrace_scope。

`--inherited-issued` 检查 process scope 的未管理子进程，以及解除后的子进程、孙进程：文件读取必须恢复原生允许，已缓存 Issued 地址的阻塞和非阻塞连接必须到达原生目的地址。原生解析器若把另一个名称返回为旧 Issued 地址，子进程必须在暴露 addrinfo 前拒绝，且不能污染父进程缓存。`--alias-serve-offline` 在解除后停止私有 Serve，验证连接仅依赖原生兼容快照；重启并重新审批附加后，SDK 为第二个本地名称分配的地址必须不同于旧缓存，两个地址都必须可用。

统一 Linux Suite 读取实际 Yama 状态，不修改系统设置。Yama 非 0 时仍执行 ptrace 正例和三个 Gum 拒绝负例，并为未执行的 Gum 正例记录 `skip` 及原因；JSON/Markdown 报告使用 `partial`、`coverage_complete: false`，不能将该子集视作完整通过。`--restricted-yama-only` 同样只报告部分覆盖。合法环境中执行的测试失败仍返回非零，不能转换为跳过。入口还运行 `python3 tests/test_linux_suite_reporting.py` 的确定性报告与调度测试，它们只使用临时文件和本地命令桩，不运行目标程序或更改 Yama。

完整 Gum process/tree/run 正例要求测试环境处于 Yama 0。受限 Yama 的拒绝回归注册在同一 Suite 入口：`scripts/benchmark-linux-backends.sh --restricted-yama-only --hyperhub <CLI> --output <新目录>`。它验证 explicit Gum 在变更目标前拒绝、原生 fork/exec/vfork 继续成功。在实际允许追踪的环境，自动后端必须使用可撤销的 ptrace；Yama 2/3 若由内核拒绝追踪，则必须明确报告权限失败并保留原生目标行为，不能报告自动后端支持通过。`--fixture-child-debugger` 只用于定位第三方运行时权限错误的独立对照，不能作为一般环境支持 Gum tree 的通过证据。

`--root-self-exec --root-exec-methods path path fexecve execveat` 在同一原始进程内按顺序执行两次路径 exec、一次 `fexecve` 和一次 `execveat(AT_EMPTY_PATH)`。驱动先运行相同的未管理原生序列；托管序列的每次事件均要求首次策略探测立即被拒绝、可信 `exec_epoch` 恰好加一、原始 Spec 不变、PID/birth/当前映像保持一致。每次 exec 前生成的待审批 Detach 必须在 exec 后明确拒绝，不能重新规划或影响 Active 策略；最终使用当前 epoch/映像重新创建 Detach。样例自行关闭旧映像资源，解除后主动关闭新映像的业务长连接，再要求实际退订。不同映像与非主线程 exec 是单独待补边界，不能用此同映像序列代替。

`--busy-preparation` 在初次附加和重新附加审批期间持续运行真实 fork/read/waitpid，默认使用两个独立的 fork 线程；`--busy-fork-workers 1` 保留单线程最小路径。先验证每个线程的原生允许 oracle，再要求每个线程在生效后都继续创建后代，且这些后代读取全部被拒绝。停止并 join 后核对每线程完成数、marked 数与汇总相等，避免一个线程的进展掩盖另一个线程停住。若准备阶段无法完整接管，则只接受明确的准备失败、后续管理员审批清理和原生文件、连接、终端与子进程继续正常；任何崩溃、被杀死的子进程或遗留启动门都使测试失败。该独立场景在统一 Suite 中以 Yama 0 为前提运行，结果区分实际生效和明确拒绝，不能把拒绝算作并发接管正例。

`dynamic_attach_target.c` 的 `--map-cursor-oracle` 模式独立比较同一 proc maps 描述符的并发字节偏移读取与串行顺序游标：后台只做匿名 mmap/mprotect/munmap，顺序游标必须零解析错误；旧方式的错误计数按实际观测报告，不要求每种调度都复现。`test-dynamic-attach.py --backend gum --scope process --thread-creation-regression` 在原生、接管、解除三个阶段分别执行 4、32、4 轮普通 pthread 分配与内容校验，并在接管时保持两个匿名 VMA 变更线程。它断言线程创建返回码、malloc 结果和匿名 mprotect 错误数；该独立模式不执行文件探测。统一 Linux Suite 注册这两项，Gum 正例仍要求 Yama0。

`dynamic-attach-terminal` 是独立的跨平台真实终端应用，包含固定依赖和自己的 Cargo.lock。它进入 raw mode、绘制 VT 输出，并从目标自己的 PTY/ConPTY 接收 ASCII、方向键、DEL 和原始 Ctrl-C；测试控制命令通过另一个本地 socket 传输。每个阶段以唯一的 VT 输出标记确认实际显示，完整可见输出只允许夹具自己的消息；supervisor 等待应用退出后检查终端模式恢复并传递退出码。该样例验证目标终端，不能用审批 CLI 的伪终端代替。

`dynamic_attach_posix_runtime.c` 是 Windows 上真实 MSYS/Cygwin `fork` 的源码目标；原生 MinGW 的 CreateProcess 不能替代它。`scripts/test-dynamic-attach-posix-runtime.py` 提供原生父/子读取、同一 TCP 复用、环境/cwd 与退出码对照，以及当前 `--expect-unsupported` 模式：process/tree 附加在注入前被拒绝，目标继续原生 fork/读取/通信。完整 managed-continuity 模式保留在驱动中，要求实际子策略及附加后新建代理 TCP 跨 fork；当前能力门会拒绝，因此不能将其记成通过。统一 Windows Suite 接受 `-PosixRuntimeCompiler C:/msys64/usr/bin/gcc.exe` 并执行 native/能力拒绝两项，缺编译器输出 `posix-runtime-not-executed.json`。Windows 原生尚未执行；Linux POSIX 对照或交叉编译不算 MSYS 实测。

```sh
cargo build --locked --manifest-path tests/fixtures/dynamic-attach-terminal/Cargo.toml --target-dir target/terminal-fixture
python3 scripts/test-dynamic-attach-terminal.py --fixture target/terminal-fixture/debug/dynamic-attach-terminal --native-only --output target/benchmarks/terminal-native
python3 scripts/test-dynamic-attach-terminal.py --fixture target/terminal-fixture/debug/dynamic-attach-terminal --hyperhub target/release/hyperhub --backend ptrace --origin attach --cycles 2 --output target/benchmarks/terminal-ptrace
```

Windows PowerShell 使用同一 Cargo 构建命令，运行：

```powershell
python scripts/test-dynamic-attach-terminal.py --fixture target/terminal-fixture/debug/dynamic-attach-terminal.exe --native-only --output target/benchmarks/terminal-native
python scripts/test-dynamic-attach-terminal.py --fixture target/terminal-fixture/debug/dynamic-attach-terminal.exe --hyperhub target/release/hyperhub.exe --backend gum --origin attach --cycles 2 --output target/benchmarks/terminal-gum
```

`--origin run` 另测前台启动器。驱动在审批、服务重启和解除期间持续发送真实键盘字节，断言 PID、原始终端模式、前台进程组、工作目录、HOME、允许/拒绝文件读取及退出码37，并核对全部输入不丢失、不改写、不重复。服务重启不再输入管理员密码。失败保留阶段和终端转录；输出包含实际 CLI、fixture、声明的源码和锁文件摘要。它是业务连续性回归，不输出统一延迟 SLA。全部进程、密码和文件为一次性夹具，清理只针对已验证且由句柄固定的目标。

`attachment_init_failure.rs` 是跨Linux/Windows的真实原生入口失败回归，由 `hyperhub-runtime` 的同名 example 构建。Windows使用DLL入口与无效Engine快照；Linux同一源码提供 `engine`、`missing-pin`、`host-bind` 三模式，并令ready私有staging写失败，证明无ACK仍可经同一认证Host取得真实Failed/worker终态/pin证据。host-bind冲突移除后仅重开原绑定通道，不能改Bootstrap或重新初始化。fixture使用本地固定dummy签名key与完整Admin/Core/manager possession，断言未ready不能Activate或执行新Core工作，以及新Detach的Prepare→Detach可以取消失败startup。运行产物留在target/或临时目录，无真实凭据。

`attachment_bind_fault.c` 是仅供 Linux Suite 使用的受控 `bind` 故障夹具，同一源码构建 LD_PRELOAD shim 和原生对照程序。默认未加载/未启用时不制造故障。驱动提供私有 MAP_SHARED 文件，仅允许非原根 PID 在指定私有 Host IPC pathname 前缀内的 AF_UNIX bind 返回 EADDRINUSE；Frida abstract socket、独立 fork broker 目录、业务 socket 和原根 bind 均有成功对照。控制程序以共享原子字段启用/解除故障，既不增加产品调试接口，也不调整系统 ptrace 配置。

统一动态附加驱动的独立场景先执行该原生对照（包括 FIFO 原生 S 字节读），再以 Active Gum tree 启动现有目标的单个 busy fork worker：

```sh
python3 scripts/test-dynamic-attach.py --hyperhub target/release/hyperhub \
  --backend gum --scope tree --origin attach --child-startup-failure \
  --output target/benchmarks/child-startup-failure
```

故障必须实际命中原生 Host bind；若 SDK 没有走 shim，场景明确失败。新 child 在故障下必须保持超过 12 秒未返回，原父线程进度和 stdio 仍工作；单纯解除 bind 故障再等待 2 秒仍不得放行。新的真实 Detach 审批后，子进程才可进入现有 `read_secret`，测试临时 FIFO 的唯一 reader/原生 S 字节与 busy worker 的 waitpid 完成共同验证 native read 成功。FIFO 在这一个场景中保留 child 存活，以检查未知继承 Runtime 只能 Resident/Pending，不能签发全量 completion proof；随后恢复同内容 dummy regular 文件并结束目标。该场景不要求整个附件完成 Detach，也不要求新 fork 在 Core cleanup fence 后获得注册；不放宽普通场景的断言。编译产物及独立 checks/状态证据写入指定 target 输出目录，无真实凭据或外部服务。
