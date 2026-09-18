# Linux 静态无符号基准

> 完整、可复用的一键功能与性能入口见
> `docs/benchmarks/linux-backend-suite.md`，日常开发运行
> `./scripts/benchmark-linux-backends.sh`。本目录保存其固定 fixture 源码、
> 本地 echo/DNS 服务和报告生成器。

该基准构建并运行三种不依赖动态解释器、已移除 ELF 符号表和调试段的程序：

- C：直接发出 x86_64/aarch64 syscall；
- Go：`CGO_ENABLED=0`，显式执行 raw syscall；
- Rust：使用 musl target 和内联汇编 syscall。

三种探针都覆盖文件、TCP、fork/exec 后代及后代 TCP。C 对抗探针还覆盖三种 DNS I/O、descriptor 复制、positioned/vectored 文件 I/O、openat2/renameat2/execveat 等静态 syscall 点位。Go 和 Rust 仍保留运行时执行所必需的内部元数据；这里的“无符号”特指没有 ELF `.symtab`、`.debug_*` 和 `nm` 可见符号。

默认还包含几个常见的大型静态无符号程序：

| 程序 | 固定版本/来源 | 工作负载 |
| --- | --- | --- |
| BusyBox | 系统 `busybox-static` | 对约 10 MiB 语料执行 SHA-256 |
| GitHub CLI | 2.78.0 官方 Linux release | `gh --version` 启动负载 |
| yq | 4.47.2 官方 Linux release | 解析并筛选大型 YAML |
| ripgrep | 14.1.1 musl release，仅 x86_64 | 单线程扫描大型文本 |

下载的 release 资产使用固定 SHA-256 校验，并在运行前再次 strip 和验证。二进制缓存在 `target/benchmarks/linux-fixtures/<architecture>/`，结果 CSV 和 Markdown 默认位于 `target/benchmarks/linux-static/`。源码、架构或工具链指纹未变化时不会重新构建 fixture。

## 依赖

- C、Go 和 Rust 工具链；
- 当前架构对应的 Rust musl target；
- `busybox-static`；
- `readelf`、`nm`、`strip`、`curl`、Python 3 和常见 POSIX 工具。

Ubuntu/Debian 示例：

```sh
sudo apt-get install build-essential musl-tools busybox-static golang-go python3 binutils curl
case "$(uname -m)" in
  x86_64) rust_target=x86_64-unknown-linux-musl ;;
  aarch64|arm64) rust_target=aarch64-unknown-linux-musl ;;
  *) echo "unsupported architecture" >&2; exit 1 ;;
esac
rustup target add "$rust_target"
```

## 原生基准

```sh
./scripts/benchmark-linux-static.sh --iterations 5
```

仅运行语言探针、跳过大型 release 下载：

```sh
./scripts/benchmark-linux-static.sh --iterations 5 --skip-large
```

## HyperHub 前后对比

先启动 Serve，再指定 HyperHub CLI。脚本会依次运行 native 和 HyperHub 两种模式：

```sh
hyperhub start --password-file ~/.hyperhub/password

./scripts/benchmark-linux-static.sh \
  --iterations 5 \
  --hyperhub ./target/release/hyperhub \
  --password-file ~/.hyperhub/password
```

所有 workload 都是静态 ELF，因此不会加载 Gum Agent；`--runtime` 仅作为旧调用兼容参数保留并会被忽略。

输出包括：

- `results.csv`：每一次测量；
- `summary.csv`：native/HyperHub 中位数、增加时间和倍率；
- `report.md`：便于 CI artifact 和人工阅读的表格；
- 统一后端套件额外生成 `checks.tsv`、`suite.json`、`suite-report.md`、`dynamic-hooks.json` 与 `hooks.json`。

脚本验证每个产物：

1. ELF program header 不包含 `PT_INTERP`；
2. dynamic section 不包含 `DT_NEEDED`；
3. section table 不包含 `.symtab` 或 `.debug_*`；
4. `nm -an` 不输出可用符号。
