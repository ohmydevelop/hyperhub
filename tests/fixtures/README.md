# Linux 运行时夹具

`linux_probe.c` 用于验证动态 ELF 的完整 Gum manifest：DNS、阻塞与非阻塞 connect、延迟 SOCKS 握手、send/recv、fcntl/ioctl、open/open64/openat/openat64/creat、read/write、rename/unlink 变体、mmap/mprotect/munmap、execve 失败路径，以及 posix_spawn/posix_spawnp 后代递归注入。

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
