# Linux 后端可复用 Benchmark 套件

## 目的

该套件把 Linux 动态 ELF、静态无符号 ELF、Hook 点位、sandbox 和性能检查收敛为一个可重复命令。开发后不再临时编写探针或手工组合命令；仓库中的固定 fixture、输入语料、版本和断言即为测试规格。

默认执行快速套件：

```sh
./scripts/benchmark-linux-backends.sh
```

该命令会：

1. 构建 release HyperHub CLI 与 Gum Agent；
2. 根据源码、架构和工具链指纹生成或复用 fixture；
3. 启动隔离的 HyperHub Serve 与临时配置；
4. 执行动态/静态 ptrace 基线、显式动态 Gum、DNS、后代、凭证路由和 sandbox 功能检查；
5. 交替测量 native/HyperHub 性能；
6. 生成机器可读结果和 Markdown 报告。

日常开发只需要运行上述命令一次。已经构建好 CLI/Agent 时可跳过 Rust build：

```sh
./scripts/benchmark-linux-backends.sh \
  --skip-build \
  --hyperhub ./target/release/hyperhub \
  --runtime ./target/release/libhyperhub_gum_agent.so
```

## Fixture 缓存

默认缓存目录：

```text
target/benchmarks/linux-fixtures/<architecture>/
```

探针指纹包含：

- C、Go、Rust fixture 源码 SHA-256；
- CPU 架构和 Rust musl target；
- C、Go、Rust 工具链版本。

指纹未变化时直接复用二进制。需要主动重建时使用：

```sh
./scripts/benchmark-linux-backends.sh --rebuild-fixtures
```

`manifest.json` 记录每个 fixture 的路径、类型、大小和 SHA-256，便于确认两次开发运行使用的是同一测试对象。

## 固定测试矩阵

| 分组 | Fixture/对象 | 必须验证的行为 |
| --- | --- | --- |
| 动态 ptrace 基线 | `linux-dynamic-probe`、`linux_http_credential_probe.py` | 动态 ELF 默认不依赖 Agent；覆盖 fork/exec、spawn，以及 IP-form SOCKS 经 HTTP Host/path 精化路由并注入凭证 |
| 动态 Gum 优化 | `linux-dynamic-probe` | 显式 `--backend gum` 时 25 个动态 Hook descriptor 全部安装并命中 |
| 静态后端边界 | 复制到无 Agent 目录的 CLI | 动态 ELF 必须拒绝启动；静态 ELF 必须在无 Agent runtime 时正常进入 ptrace |
| 静态 C | raw-syscall stripped static ELF | DNS 三种 I/O、TCP、descriptor、文件变体、clone/fork/exec/wait 和完整 manifest |
| 静态 Go | `CGO_ENABLED=0` stripped binary | runtime 线程、raw syscall、根进程和 exec 后代 TCP |
| 静态 Rust | musl stripped binary | 内联汇编 syscall、根进程和 exec 后代 TCP |
| DNS | 本地 UDP DNS fixture | A/AAAA 响应恢复 `localhost`，连接审计保留域名 |
| Sandbox | C intent modes | read/write/create/delete/rename、fork、根 exec、后代 exec 全部 deny 并审计 |
| 性能 | C/Go/Rust | native 与 HyperHub 中位数、增加时间和倍率 |

所有网络服务仅绑定临时 loopback 端口；配置、密码、HOME 和审计目录都在临时目录中，退出时自动清理。

## 完整性能套件

发布前或性能专项使用：

```sh
./scripts/benchmark-linux-backends.sh --full --iterations 5
```

`--full` 在固定语言探针之外加入：

- BusyBox SHA-256；
- GitHub CLI；
- yq；
- x86_64 上的 musl ripgrep。

远端 release 资产固定版本并校验 SHA-256，下载和 strip 后的二进制也进入 fixture 缓存。

## 输出

默认结果目录：

```text
target/benchmarks/linux-backends/
```

| 文件 | 内容 |
| --- | --- |
| `checks.tsv` | 每个功能断言的通过状态和细节 |
| `results.csv` | 每次 native/HyperHub 计时样本 |
| `summary.csv` | 各 workload 中位数、增加时间和倍率 |
| `report.md` | 独立性能表格 |
| `dynamic-hooks.json` | 显式 Gum Interceptor 动态 Hook 覆盖 |
| `hooks.json` | ptrace 静态 syscall Hook 覆盖 |
| `suite.json` | 功能、性能和 fixture identity 的统一机器报告 |
| `suite-report.md` | 一页式人工验收报告 |

命令 exit code 为 0 且 `suite.json` 的 `status` 为 `pass` 才算通过。任一点位缺失、目标错误放行、runtime 边界失效、sandbox 未拒绝或程序异常退出都会立即失败。

## 兼容入口

旧命令仍可使用：

```sh
./scripts/test-linux-static-coverage.sh [hyperhub] [runtime] [output]
```

该脚本只是新 benchmark 的兼容包装，不再维护独立测试逻辑。低层纯性能脚本 `benchmark-linux-static.sh` 仍可单独使用，并共享同一 fixture 缓存。
