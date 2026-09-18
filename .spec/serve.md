# HyperHub Serve 开发目标

`serve` 是 HyperHub 的本地代理核心。Agent 将目标程序的 TCP 连接转换为带会话认证的 SOCKS5 CONNECT，`serve` 负责恢复目标、匹配规则、选择上游、注入凭证和记录审计。

状态：`[x]` 已支持，`[ ]` 待开发。

```text
目标程序 → Agent → SOCKS5 → serve → 目标服务器或上游代理
```

## 协议能力

### 基础代理

- [x] 标准 SOCKS5 CONNECT 入口，支持域名、IPv4、IPv6。
- [x] RFC 1929 会话认证，拒绝未注册、过期或已撤销的进程。
- [x] 任意 TCP 和未知协议透明转发。
- [x] direct、SOCKS5 upstream、HTTP CONNECT upstream。
- [x] 继承 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY` 和 `NO_PROXY`。
- [x] 识别并兼容目标程序原本使用的 HTTP Proxy 或 SOCKS5 Proxy。
- [ ] UDP、QUIC 和 HTTP/3。

### HTTP 与 HTTPS

- [x] HTTP/1.1 请求代理和 keep-alive。
- [x] HTTP/2 多路请求代理。
- [x] HTTPS TLS MITM，动态签发目标域名证书。
- [x] HTTP Basic、Bearer、X-API-Key 和自定义 Header 凭证注入。
- [x] 协议感知令牌由路由限定 URL 范围：普通 HTTP 注入 Bearer，Git Smart HTTP/LFS 自动注入 Basic；Challenge 不触发重放。
- [x] Cookie 合并注入和 Query 参数替换注入。
- [ ] OAuth2 Client Credentials 自动换取和刷新 Token。
- [ ] mTLS 客户端证书注入。
- [x] 按域名、IP、端口、进程、HTTP 方法和 URL 路径匹配规则。
- [x] 地址/端口重写、deny、passthrough 和 proxy 动作。
- [x] 严格验证真实上游 TLS 证书。

### WebSocket

- [x] HTTP/1.1 WebSocket Upgrade 透明转发。
- [x] HTTP/2 Extended CONNECT 透明转发。
- [x] 保存 TLS 解密后的原始 WebSocket 帧。
- [x] 去除 mask、重组分片并解压 `permessage-deflate`。
- [x] 文本消息写入 JSONL，二进制消息使用 Base64。

### Git

- [x] 识别 Git smart HTTP 与 Git LFS 操作并按作用域注入 HTTP 凭证。
- [x] 识别原生 `git://` 的仓库和操作并保持透明转发。
- [ ] 终止 SSH 后识别 `git-upload-pack`、`git-receive-pack` 及仓库。
- [ ] 为 SSH Git 注入目标凭证。

### SSH

- [x] 识别 SSH 流量并透明代理。
- [ ] 终止客户端 SSH 会话并使用配置凭证连接真实服务器。
- [ ] 严格校验上游 SSH host key。
- [ ] 支持 shell、exec、PTY 和 subsystem。
- [ ] SSH 输入输出限长转录。
- [ ] 默认拒绝端口转发。

## 通用能力

- [x] 主密码 challenge-response、根进程生命周期 Session、子进程继承、Fake-IP 域名恢复和公开 CA 获取。
- [x] 规则按 priority 和文件顺序匹配。
- [x] enforce 失败关闭与 observe 失败透传。
- [x] JSONL 连接审计、敏感信息脱敏和限长内容转录。
- [x] 查询当前会话、连接、目标、规则和处理阶段。
- [ ] 配置热加载。
- [ ] 1000 并发连接资源泄漏验收。

## 安全边界

- [x] 数据面只监听 loopback，管理面使用 Named Pipe 或 Unix Domain Socket。
- [x] CA 私钥和目标凭证只保存在 `serve`，不发送给 Agent。
- [x] Authorization、Cookie、密码、私钥和 SOCKS token 不写日志。
- [x] 不修改系统信任库，不绕过 certificate pinning。
- [x] 未识别协议始终回退为原始 TCP，不因缺少专用处理器而中断流量。


## 配置与 Session

- [x] `hyperhub config` Ratatui 配置界面，支持完整对象表单增删改。
- [x] Session 双鉴权：有效父进程 Session 自动授权，否则回退主密码 challenge-response。
- [x] Windows x64 后代递归注入：覆盖 CreateProcess、CreateProcessInternal 和 NtCreateUserProcess，Ready/登记完成前保持挂起，enforce 失败关闭。
- [x] Argon2id + XChaCha20-Poly1305 加密存储 `~/.hyperhub/config.bin`。
- [x] `import`/`export` 支持加密 BIN、明文 BIN、TOML 和明文导出确认。
- [x] 首次密码确认、主密码修改、密码文件和环境变量自动化。
- [x] 根进程存活期间 Session 永不过期，退出后立即撤销并关闭连接。
- [x] Windows `CreateProcessA/W` 子进程挂起、登记和 Agent 继承注入。
- [ ] 配置热加载和 Serve 重启后的 Session 恢复。


## 协议状态机

SOCKS5 -> [TLS, SSH, HTTP1, Raw]
TLS    -> [HTTP1, HTTP2, Raw]
HTTP1  -> [CONNECT(Tunnel), WebSocket, GitHTTP, Response, Message, RawBody]
HTTP2  -> [gRPC, WebSocket, RawBody]
SSH    -> [GitSSH, RawChannel]
WS     -> [Response]

之后没增加一个协议只需要创建协议处理器，然后注册到协议数组中，注意需要设置深度，避免无限递归

通过协议栈逐层解析，直到达到最大深度或者匹配到合适的协议处理器，然后出栈恢复数据转发给upstream
serve收到数据后

凭证和审计可以当作MITM插件来设计, 每种插件通过插件配置绑定协议类型，现有插件包括：
1. 协议审计：http，ws，git，ssh, response, messages；选择协议后，渐进式披露对应的其它配置参数，比如是否 dump 数据，针对ws可以选择fram之类的
2. 凭证注入：http，ssh；选择协议后，渐进式披露对应的其它配置参数
3. 协议转换（先不实现）：reponse协议与messages协议互转

route 中的插件生效过程会将相关配置的插件注册到对应的协议
route1
    -- http
        凭证注入
        协议审计
route1
    -- http
        凭证注入
    -- message
        协议审计

使用栈结构进行协议识别和插件回调：
入栈：一层一层下钻，直到匹配一条 route 匹配（进程、目标、端口）或达到最大深度，在不超过最大深度的情况下尽可能的继续下探找到所有注册的协议并调用该协议下注册的插件进行处理
出栈：一层一层出栈构造发往 upstream 的数据


新增模型转换插件


# 支持 ssh 协议
tui 设计：
root 根证书改成证书
环境变量因为长度过长放在最后面

证书除了保持原有的root ca外，还需支持信任某个具体ssl目标的ca证书，具体流程如下
1. 直接给定ca路径
2. 给定一个https或者ssh主机的地址（地址:端口）
    可能但不仅限于这些例子
    https://www.baidu.com
    https://xxxx.com:3333
    ssh://10.0.0.1
    ssh://aaa:1234
