# Linux 静态无符号程序性能基线（2026-09-17）

## 环境

- Linux 7.0.0-31-generic，x86_64；
- Intel Core Ultra 7 270K Plus，测试环境可用 5 个 CPU；
- Rust 1.98.1、Go 1.26.0、GCC 15.2.0；
- release 构建；
- 每个 workload 预热 1 次，随后测量 5 次并取中位数；
- HyperHub Serve 已启动，认证缓存已建立；
- HyperHub 时间包含 CLI Session 建立、ptrace supervisor 和目标运行时间。

执行命令：

```sh
./scripts/benchmark-linux-static.sh \
  --iterations 5 \
  --hyperhub ./target/release/hyperhub \
  --password-file /path/to/password
```

## 结果

| Workload | 二进制大小 | Native 中位数 | HyperHub 中位数 | 增加时间 | 倍率 |
| --- | ---: | ---: | ---: | ---: | ---: |
| C raw-syscall probe | 0.71 MiB | 4.243 ms | 105.483 ms | 101.240 ms | 24.86x |
| Go static probe | 2.32 MiB | 4.753 ms | 105.462 ms | 100.709 ms | 22.19x |
| Rust musl probe | 0.54 MiB | 3.657 ms | 105.244 ms | 101.587 ms | 28.78x |
| BusyBox SHA-256 | 2.09 MiB | 7.813 ms | 105.411 ms | 97.598 ms | 13.49x |
| GitHub CLI 2.78.0 | 52.05 MiB | 26.097 ms | 105.477 ms | 79.380 ms | 4.04x |
| yq 4.47.2 | 10.94 MiB | 39.370 ms | 105.319 ms | 65.949 ms | 2.68x |
| ripgrep 14.1.1 | 6.29 MiB | 27.504 ms | 105.429 ms | 77.925 ms | 3.83x |

## 分析

1. **当前主要成本是约 100 ms 的固定启动成本。** 七组 HyperHub 中位数都集中在 105 ms 左右，而 native workload 从 3.6 ms 到 40.8 ms 不等。这表明当前短任务主要受 Session 建立、进程跟踪建立和生命周期收尾影响，而不是二进制大小。
2. **倍率不适合单独评价极短命令。** 对 3–8 ms 的 probe/BusyBox，约 100 ms 的固定成本会显示为 13–29 倍；对 yq 这类 40 ms workload，倍率下降到 2.58 倍。
3. **大型静态二进制可以稳定运行。** 52 MiB 的官方静态 GitHub CLI、Go 构建的 yq、Rust musl ripgrep 和 BusyBox 均通过无 `PT_INTERP`、无 `DT_NEEDED`、无可见符号检查，并能在 supervisor 下正常退出。
4. **网络覆盖不是只验证根进程。** C、Go、Rust probe 的根进程和 exec 后代分别连接 echo server；C 还覆盖 DNS、descriptor 和所有 manifest 必测 syscall 点位。
5. **扩展点位后固定成本没有明显上升。** C fixture 增加 DNS、vectored I/O、openat2/renameat2/execveat 后，HyperHub 中位数仍约 105 ms。
6. **后续优化目标应首先降低固定成本。** 优先分析 Session/进程监控启动与结束路径；之后再使用 seccomp-BPF 过滤无关 syscall、`process_vm_readv/writev` 加速内存访问。优化必须保留 ptrace 后端作为兼容性回退。

该结果是当前机器上的开发基线，不应直接视为其他内核、CPU、虚拟化环境或安全策略下的绝对性能数据。CI 会上传 `results.csv`、`summary.csv` 和 `report.md`，用于持续比较回归。
