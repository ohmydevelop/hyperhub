# 进程内 TLS 信任

TOML 不配置 CA 私钥。`serve` 启动时在内存中生成根 CA，并按目标域名动态签发叶子证书。Agent 使用会话令牌取得公开根证书，私钥不会离开 `serve`。

Windows Gum Agent 将 Schannel 客户端凭证切换为手工证书校验。TLS 握手完成后，它使用“系统 ROOT + 当前 HyperHub ROOT”构建证书链，并验证服务端用途、有效期、签名和 SAN/主机名。

Agent 还会在目标主逻辑启动前设置通用 `SSL_CERT_FILE`，指向临时生成的 PEM bundle。该 bundle 合并系统 CA、目标进程原有文件型 CA 配置和当前 HyperHub ROOT，适用于主动读取此标准变量的 Rustls、OpenSSL 等 TLS 客户端；`SSL_CERT_DIR` 同时指向当前 Agent 的私有 CA 目录，而不是 PEM 文件。配置不包含程序名、二进制特征或专属环境变量。

该机制：

- 不修改系统 ROOT Store。
- 不把 CA 私钥注入目标。
- 不把所有验证无条件改为成功。
- 不绕过 certificate pinning。

完全内置根集合、忽略 `SSL_CERT_FILE` 的自定义 TLS 实现、macOS SecTrust 和 certificate pinning 不在当前覆盖范围内。
