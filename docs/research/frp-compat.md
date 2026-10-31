# FRP 兼容性调研（原版 fatedier/frp 与 ChmlFrp）

- 调研日期：2026-10-31（结论以截至今日为准）
- 调研方法：上游源码逐行阅读（fatedier/frp dev 分支 HEAD `93b5279`，2026-10-23，`pkg/util/version/version.go` 标识 0.71.1；以及 v0.46.0–v0.71.1 各 tag 抽查）、ChmlFrp 魔改仓库源码 diff（TechCat-Team/ChmlFrp-Frp @ `9899607`）、gofrp.org 官方文档、chmlfrp.net 官网/文档、ChmlFrp 公开 API 实测、本机 frp 隧道透传实证实验。
- 约定：标注【已证实】的论断均有一级来源（源码行号 / 实验命令与输出 / 官方文档 URL）；标注【推断】的论断给出推断依据；查不到的写入文末「未决问题」。
- 来源缩写：`frp-src/` = 本地克隆的上游仓库（`.tmp/frp-src`，dev @ 93b5279）；`chml/` = 本地克隆的 ChmlFrp-Frp 仓库（`.tmp/chmlfrp-frp`）；`golib` = fatedier/golib v0.8.2（上游 go.mod 锁定版本）。

---

## 0. 执行摘要

1. **数据面纯透传成立**【已证实】：tcp 代理在 `useEncryption=false、useCompression=false` 时，frps/frpc 对用户字节流零改动、零框定，仅按 16 KiB 块双向 `io.Copy`；本机 v0.71.1 实验中含全部 256 字节值、`0x17` 首字节、1 MiB 随机数据往返 sha256 完全一致。ChmlVPN 的应用层端到端加密协议可无感穿越 frp 中转。
2. **但有两个必须绕开的坑**【已证实】：① TCP 半关闭（`SHUT_WR`）不保留——任一方向关闭即整链拆除，实测回程 0/65536 字节；② frps 对 **frpc 入口连接**（bindPort）有首字节 TLS 探测（0x16/0x17），对 **proxy 用户口** 无探测——应用层协议不得出现在 frpc 入口方向（那是 frp 自己的），只出现在 proxy 用户口方向，实测无约束。
3. **原版与 ChmlFrp 是两代不互通的控制面协议**【已证实】：ChmlFrp 客户端/节点基于原版 **v0.51.2**（2023-07）魔改，无控制面 token 加密；原版 v0.53.0（2023-12）起控制连接登录后**强制** AES-128-CFB（token 派生 key），因此 ChmlFrp frpc ↔ 原版 frps ≥v0.53.0 双向均不兼容；v0.69.0（2026-05）又引入可选 wire protocol v2（帧 + 协商 AEAD），默认仍 v1，官方计划 v0.78.0 移除 v1。**兼容两家的唯一稳妥路径是子进程托管两套 frpc 二进制**。
4. **推荐方案 A（子进程托管）**：风险最低、协议漂移零成本、实证充分；ChmlFrp frpc 有「三次重连失败即退出进程」的魔改，托管层必须做进程守护 + 拉起。方案 B（Rust 原生实现）需同时维护 v0.51.2 无加密控制面与 v0.53+ 加密控制面两代，且撞上 v1→v2 过渡期，漂移风险高，不建议现在做。方案 C（visitor/xtcp）在 ChmlFrp 上不可用（面板无法创建 stcp/xtcp + 服务端 CheckProxy 校验）。

---

## 1. 原版 frp（v0.71.1，2026-10-14 发布）协议要点

版本事实：GitHub Releases API 实测 `v0.71.1 / 2026-10-14`；dev HEAD `93b5279`（2026-10-23）`pkg/util/version/version.go` 为 `"0.71.1"`。许可证 Apache-2.0（`frp-src/LICENSE`）。

### 1.1 架构与连接模型【已证实，frp-src 源码】

- frps 监听 `bindPort`（默认 7000，`frp-src/pkg/config/v1/server.go:113`）；frpc 主动外连，无需 frpc 侧开洞。
- **一条控制连接**：TCP（或 kcp/quic/websocket/wss，`frp-src/pkg/config/v1/client.go:152` 默认 tcp）→ TLS（默认开）→ **yamux 多路复用**（`transport.tcpMux` 默认 true，`client.go:159`；`frp-src/client/connector.go:142-162` 用 `fatedier/yamux` 建会话，`MaxStreamWindowSize=6MiB`，KeepAlive 默认 30s）。控制连接、work conn 都是这条 TCP 上的 yamux 流。
- 登录：`Login{version,user,privilege_key,timestamp,run_id,pool_count,metas}`（`frp-src/pkg/msg/msg.go:76-93`）→ `LoginResp{version,run_id,error}`。`PrivilegeKey = GetAuthKey(token, timestamp)`（HMAC，`frp-src/pkg/auth/token.go:40`）。
- **proxy 模型**：frpc 发 `NewProxy`（类型/远程端口/带宽限制等，`msg.go:102-134`）→ frps 监听用户口 → 用户连接到来时 frps 经控制连接发 `ReqWorkConn` → frpc 开新 yamux 流发 `NewWorkConn{run_id,privilege_key}` → frps 回 `StartWorkConn{proxy_name,src/dst addr/port}` → 双方 `Join`（`frp-src/client/control.go:124-162`、`frp-src/server/proxy/proxy.go:270-342`）。
- **visitor 模型**（stcp/sudp/xtcp）：两端都跑 frpc。visitor 侧连接 frps 发 `NewVisitorConn{run_id,proxy_name,sign_key,timestamp,use_encryption,use_compression}`（`msg.go:163-170`），`sign_key = GetAuthKey(secret_key, ts)`（`frp-src/client/visitor/visitor.go:165-201`）；frps 校验后把 visitor 连接与 proxy 侧 work conn 桥接。**visitor 不是通用「连到任意 frps 端口」机制，只能连到对端 frpc 注册的 stcp/sudp/xtcp proxy**。
- 心跳：tcpMux 开启时应用层心跳默认禁用（interval=-1），靠 yamux keepalive 30s；关闭 tcpMux 时 30s 发/90s 超时（`frp-src/pkg/config/v1/client.go:158-164`）。
- 重连：frpc 侧 FastBackoff（1s 起指数 ×2，上限=heartbeatInterval，`frp-src/client/control.go:256-265`）；服务端心跳超时 90s 断开。重连时携带旧 `run_id`（`client/control_session.go:117`），frps 顶换旧会话（v0.70.1 修了半开 TCP mux 下会话替换泄漏，见 v0.70.1 release notes）。

### 1.2 消息线上格式【已证实】

| 代际 | 帧格式 | 状态 |
|---|---|---|
| v1（v0.46.0 起） | `1 字节类型('o','1','p',…) + 8 字节大端 int64 长度 + JSON 载荷`；单消息上限 10240 字节（frp 未覆盖 golib 默认值） | **默认**，计划 v0.78.0 移除 |
| v2（v0.69.0 起，可选） | 魔数 `FRP\x00\x02\r\n` + 8 字节帧头（2B type / 2B flags=0 / 4B len，payload ≤ 64 KiB）+ ClientHello/ServerHello 能力协商帧 + 消息帧（2B 类型 ID + JSON） | frpc 显式设 `transport.wireProtocol="v2"` 才启用 |

来源：v1 编解码 `frp-src/pkg/msg/ctl.go:17-44` 委托 golib `msg/json`（pack.go/process.go：Write 一个 typeByte + `binary.Write(BigEndian, int64)` + JSON；`defaultMaxMsgLength=10240`）；v2 `frp-src/pkg/msg/wire_v2.go:27-47`、`frp-src/pkg/proto/wire/wire.go:28-167`；v1/v2 选择 `frp-src/pkg/msg/handler.go:79-90`；服务端按首 7 字节魔数识别 v2、否则回退 v1（`frp-src/server/service.go:645-674`）。v1 默认与弃用时间表来自 v0.69.0 官方 release notes。

### 1.3 控制面安全演进（本项目最关键的版本分界）【已证实】

| 版本 | 日期 | 变化 | 来源 |
|---|---|---|---|
| ≤ v0.52.x | ≤2023-10 | 控制连接明文（仅 TLS 可选保护） | v0.52.3 源码无 ConnEncrypted（git grep 本地 tag） |
| **v0.53.0** | 2023-12-14 | **登录后双方无条件用 auth.token 派生 key 做 AES-128-CFB 加密控制连接**（ssh-tunnel VirtualClient 除外）；key = PBKDF2-SHA1(token, salt="frp", 64 iters)，IV 前置 | v0.53.0 `server/control.go:161-193`（`NewControl(..., !internal, ...)`）、`client/control.go:90-97`；当前版 `frp-src/server/service.go:548-553,688-702`、`frp-src/client/control_session.go:211-225`；算法 golib `crypto/encode.go`/`decode.go`、salt 见 `client/service.go` init `crypto.DefaultSalt="frp"` |
| v0.61.0 | 2024-10-17 | （兼容窗口下界锚点） | v0.69.0 release notes |
| **v0.69.0** | 2026-05-21 | 可选 wire v2：帧化 + 协商 AEAD（`xchacha20-poly1305`/`aes-256-gcm`，HKDF(token, 双向 Hello transcript) 派生）；v1 保持默认；**官方兼容政策：每个 minor 支持到其后第 9 个 minor（frpc v0.69.0 ↔ frps v0.61.0–v0.77.0），升级顺序先 frps 后 frpc** | v0.69.0 release notes；`frp-src/pkg/proto/wire/wire.go:169-251`、`frp-src/pkg/util/net/conn.go:260-303` |

推论（对 ChmlVPN 硬约束）：**ChmlFrp frpc（v0.51.2 基线，无控制面加密）与原版 frps ≥v0.53.0 互不兼容；原版 frpc ≥v0.53.0 与 ChmlFrp 节点（不解密）也不兼容**。混用两代必挂——这是「双 FRP 兼容」必须用两套客户端二进制（或原生实现双代协议）的根本原因。

### 1.4 useEncryption / useCompression / TLS 的确切行为【已证实】

**均为 per-proxy、只在 frpc↔frps 的 work conn 上生效，与用户连接内容无关：**

- `useEncryption`：work conn 双端各自包裹 AES-128-CFB 流（同 §1.3 算法，key=token）。客户端 `frp-src/client/proxy/proxy.go:144-151`（`libio.WithEncryption`），服务端 `frp-src/server/proxy/proxy.go:297-304`。**默认 false**。
- `useCompression`：snappy 流式压缩（`golang/snappy`，golib `io.go:21,78-95` `WithCompressionFromPool`）。**是 snappy，不是 gzip**——frp 从未提供 gzip 选项（全仓库 grep 仅 `pkg/util/net/http.go` 的 HTTP 场景出现 gzip）。**默认 false**。
- 两者都为 false 时（ChmlVPN 的用法），work conn 就是裸 TCP/yamux 流，`wrapWorkConn` 原样返回（`frp-src/client/proxy/proxy.go:137-157`），服务端 `local` 即 workConn（`server/proxy/proxy.go:294-312`）。
- TLS（frpc↔frps 之间）：v0.50.0 起默认 `tls.enable=true` 且默认**不**发自定义首字节（`DisableCustomTLSFirstByte` 默认 true，即标准 TLS ClientHello 0x16），`frp-src/pkg/config/v1/client.go:186-200`。frps 端对 bindPort 入口读首字节：0x17→自定义前缀 TLS、0x16→标准 TLS、其他→非 TLS 直通（`tls.force=true` 时拒绝非 TLS）（`frp-src/pkg/util/net/tls.go:22-54`）。**TLS 只覆盖 frpc↔frps 段，proxy 用户口与本地服务之间从不加 TLS**。
- 带宽限制 `bandwidthLimit`（客户端模式默认 client 侧生效）、服务端 maxPoolCount=5 等不改变字节语义（`frp-src/pkg/config/v1/server.go` transport 段；gofrp.org server-configures 参考）。

### 1.5 数据面：缓冲、超时、粘包、半关闭【已证实（源码 + 本机实验）】

数据通路：`userConn ⇄ frps(Join) ⇄ workConn(yamux 流) ⇄ frpc(Join) ⇄ localConn`。Join 实现（golib `io.go:28-52`）：两个 goroutine 各持 **16 KiB** 缓冲 `io.CopyBuffer`，**任一方向读到 EOF/错误即关闭双向**。proxy 用户口由 `net.Listen` 直接 accept（`frp-src/server/proxy/tcp.go:49-81`），**无任何首字节探测、无协议解析**（对比 frpc 入口 `server/service.go:766-797` 有 TLS 探测）。

本机实证（2026-10-31，Windows，dev 源码自建 frps/frpc——官方下载的 exe 被本机安全策略拦截执行，自建 `--version` 输出 `0.71.1` 与 release 一致；拓扑 `python echo(127.0.0.1:18099) ← frpc → frps(7000) → 用户口 18100`，无加密无压缩，token=`chmlvpn-research-test`）：

| # | 实验 | 结果 | 结论 |
|---|---|---|---|
| T1 | 传输 `bytes(range(256))×64 + 1 MiB 随机`（首字节 0x00）echo 回来比对 sha256 | **PASS**（1,064,960 字节哈希一致） | 二进制全字符集透传，零篡改 |
| T2 | 10 个以 `0x17` 开头的 13 字节 chunk 逐个 send，读回应答 | **PASS**（60 字节逐位一致） | 用户口无首字节干扰；无框定，TCP 粘包/合流透明 |
| T3 | 发 64 KiB 后 `shutdown(SHUT_WR)`，读 echo | **FAIL：回程 0/65536 字节** | **半关闭不保留**：一方向 EOF 即整链关闭，在途回程数据全丢 |
| T4 | 10 MiB 往返计时 | 0.06 s ≈ **166.7 MiB/s**（环回量级参考） | 单流无应用层瓶颈 |

超时与保活事实：登录读超时 10 s（`frp-src/server/service.go:65 connReadTimeout`）；`userConnTimeout` 默认 10 s（等 frpc 响应 StartWorkConn）；**数据面无空闲超时**（Join 无 read deadline）；底层 TCP keepalive 默认 7200 s（`frp-src/pkg/config/v1/client.go:153 DialServerKeepAlive`）。

**对 ChmlVPN 协议层的直接约束**：
1. 禁止依赖 TCP 半关闭表达「本方向发送完毕」——必须用应用层长度前缀或显式 EOF 帧；
2. 长空闲连接在 frp 侧不会被主动断，但**节点重启/frpc 退出/NAT 超时都会硬断 TCP**，协议层必须自带心跳 + 会话可恢复（重连后重新握手）；
3. 单流吞吐受 yamux 窗口（6 MiB）与 RTT 影响，跨节点高延迟场景避免依赖「大量小消息串行往返」的握手设计；
4. 应用层加密流的首字节任意（含 0x16/0x17 均安全，仅 frpc 入口方向有探测语义，用户口无约束，T2 已证）。

### 1.6 yamux / tcpmux 是两个不同的东西【已证实】

- `transport.tcpMux`（默认 true）＝ frpc↔frps 单 TCP 连接上的 **yamux 多路复用**（`fatedier/yamux` fork），控制连接与所有 work conn 都是流；关掉则每条连接一个独立 TCP。
- `tcpmux` **代理类型**＝ frps 单监听端口按 HTTP `CONNECT` 的 host 路由到不同 proxy（唯一 multiplexer：`httpconnect`；`tcpmuxPassthrough` 选项透传 CONNECT 头）（gofrp.org/docs/features/tcpmux；`frp-src/pkg/config/types`、`frp-src/server/proxy/tcpmux.go`）。与 yamux 无关；ChmlVPN 中通常用不上。

### 1.7 visitor / xtcp（P2P）能力【已证实】

- xtcp：两端 frpc + frps 协调（NatHoleVisitor/Client/Resp/Sid/Report 消息走控制连接，`msg.go:192-247`），客户端经 STUN 发现公网映射（默认服务器 `stun.easyvoip.com:3478`，`frp-src/pkg/config/v1/client.go:90`），打洞成功后直连（默认 QUIC，可选 kcp，`frp-src/client/visitor/xtcp.go:55-60` + `pkg/config/v1/visitor.go:160`），失败可 `fallbackTo` stcp visitor（超时可配，gofrp.org/docs/features/xtcp）。**官方明言可用性/稳定性不保证**。
- stcp：秘密 tcp，两端 frpc + frps 中继，`secretKey` 鉴权；适合两端可控的场景（gofrp.org/docs/examples/stcp）。

### 1.8 frpc CLI（原版 v0.71.1）【已证实，`frp-src/pkg/config/flags.go:150-172`】

`-c/--config`（配置文件，默认 `./frpc.ini`）、`-u/--user`（**用户名前缀**，非鉴权 token）、`-p/--protocol`（tcp/kcp/quic/websocket/wss）、`-P`（server_port）、`-t/--token`（鉴权 token）。**原版不存在「`-u <token> -p <隧道ID>`」语义**——那是 ChmlFrp 魔改（见 §2.2）。

---

## 2. ChmlFrp（chmlfrp.cn → chmlfrp.net）

### 2.1 身份与现状（2026-10-31 实测）【已证实】

| 项 | 事实 | 来源 |
|---|---|---|
| 官网 | `www.chmlfrp.cn` 301 → `www.chmlfrp.net`（"ChmlFrp Panel Version 3.x.x"） | curl 实测 + 站点页脚 |
| 面板 / 文档 / API | `panel.chmlfrp.net`（下载页 HTTP 200）/ `docs.chmlfrp.net` / `cf-v1/v2.uapis.cn` | curl 实测 |
| 源码 | GitHub 组织 `TechCat-Team`：`ChmlFrp-Frp`（客户端/服务端，Go）、`ChmlFrp-Panel-v3`、`ChmlFrp-Docs`、`ChmlFrpLauncher`（图形启动器）等 | GitHub API 实测 |
| 客户端本质 | **基于 fatedier/frp v0.51.2 魔改**：`pkg/util/version/version.go` = `"ChmlFrp-0.51.2_251023"`；README 自述"基于 github 开源项目 frp"；Apache-2.0 保留 | `chml/pkg/util/version/version.go:22` |
| 下载源 | 官方直链 `https://cf-v1.uapis.cn/download/ChmlFrp-0.51.2_251023_<os>_<arch>.tar.gz`（实测下载成功，12 MB，内含 frpc+frps+ini 样例+LICENSE）；面板 `panel.chmlfrp.net/tunnel/download`；支持 amd64/386/arm/arm64/mips 系列/riscv64 | 实测下载 + 官方文档 download 页 |
| 套餐 | 免费 8 Mbps 限速 / 4 隧道 / 不限流量；会员 8–12–18 元/月至 32 Mbps / 16 隧道 | 官网定价区 |
| 节点实测 | `GET https://cf-v2.uapis.cn/node`（无需登录）：**32 节点全部 online**；16 user 组 + 16 vip 组；31 个允许 UDP；**仅 1 个支持 quic**；字段含 area/china(限速归属)/fangyu/ipv6/web/notes | 2026-10-31 curl 实测（node.json 存档于 `.tmp/chmlfrpc/`） |

### 2.2 usertoken / 隧道ID 模型（showroom 自举方式）【已证实，魔改源码】

`frpc -u <usertoken> -p <隧道ID>` 的真实语义（`chml/cmd/frpc/sub/root.go:92-93,133-174`）：

- `-u` = `--token`（"The Token of ChmlFrp"，面板用户的 **usertoken**，非 frp token）；
- `-p` = `--id`（"The ProxyID of ChmlFrp"，**隧道数字 ID**，逗号分隔可多个）；
- 启动流程：`GET https://cf-v2.uapis.cn/cfg?action=getcfg&token=<usertoken>&id=<ids>`（**InsecureSkipVerify 的 HTTPS**，`chml/pkg/api/api.go:30-46`）→ 面板返回该用户这些隧道的 **frpc.ini 全文**（`{success,message,cfg}`）→ 覆写本地 `frpc.ini` → 走原版 v0.51.2 流程启动。API 实测：错误 token 返回 HTTP 400 `{"success":false,"message":"错误的用户token…","status":400}`。
- 不带 `-u/-p` 时直接读本地 `frpc.ini`（官方文档主推路径：面板「隧道管理→配置文件」选节点生成，粘贴进 frpc.ini）。
- 面板 v2 API 另有正式的 `/tunnel_config`（token+node+tunnel_names → ini 文本）与 `/node` 节点列表（docs.chmlfrp.net/API/v2）。

### 2.3 与原版的差异（fork 对 v0.51.2 的 diff，`git diff v0.51.2 HEAD`）【已证实】

| 差异点 | 内容 | 影响 |
|---|---|---|
| CLI 自举 | 上述 `-u/-p` → API 拉配置（root.go + 新增 `pkg/api` 331 行） | ChmlVPN 托管层可直接复用该 API 或走 `-c` 配置文件模式 |
| **重连行为** | 登录失败**直接 `os.Exit(1)`**；控制连接断开后按 **5s/10s/20s 重连 3 次，仍失败即退出进程**（原版为无限指数退避，上限 20s） | **托管层必须监控进程退出并拉起**；「多主多活」的故障切换要靠 ChmlVPN 自己 |
| 服务端鉴权 | frps 登录改调面板 API `CheckToken(user, privilege_key, ts)`；用户名须 `^[A-Za-z0-9]{1,64}$`（server/service.go diff） | usertoken 不直接进 frp 协议；面板签发短时 key |
| **proxy 白名单** | `NewProxy` 须经面板 `CheckProxy` 与记录比对，不一致即拒（"客户端代理参数错误，配置文件与记录不匹配"，官方 FAQ 亦印证；日志样例 user=`token-6e447a2e28fdb4d0`，proxy 名 `<user>.<name>`） | **ChmlVPN 不能在 ChmlFrp 节点上自创 proxy 参数**（类型/端口/名称由面板生成）；E2E 协议只能装在隧道载荷里 |
| **服务端限速** | 面板 `GetProxyLimit` 下发 in/out KB/s，frps 用 `limit.NewLimitConn` 包 work conn（server/control.go diff） | 套餐限速 8–32 Mbps 在节点侧强制执行 |
| 其它 | 日志中文化、`cs.json` 节点状态导出（CPU/内存/带宽）、UDP 代理仅日志改动 | 无协议影响 |

**协议层未被改动**：`pkg/msg`（JSON v1 编码）与原版 v0.51.2 完全一致【已证实，diff 无涉】。v0.51.2 特征：JSON v1 消息（v0.46.0 起即是）、**无控制面 token 加密**（v0.53.0 才引入）、INI 配置、无 ClientID 字段（v0.67.0 引入）。

### 2.4 STUN/P2P 能力【推断（基于实证材料的负面证据）】

- 官方文档（docs.chmlfrp.net 全站抓取）**无任何 xtcp/stcp/visitor/P2P 内容**；面板创建隧道仅 TCP/UDP/HTTP/HTTPS 四类（官方教程页）；节点 API 无 xtcp 相关字段。
- fork 源码保留了原版 xtcp 代码，但服务端 `CheckProxy` 只认面板记录 → **面板建不出的 stcp/xtcp 隧道实际不可用**。cs.json 样例含 `bind_udp_port=7001`（fork 仓库文件），主要服务 kcp 端口复用。
- 结论：**ChmlFrp 只提供 TCP/UDP/HTTP/HTTPS 中转，无 P2P**。ChmlVPN 的 P2P 演进只能依赖自建节点（原版 xtcp）或自研打洞。

### 2.5 文档与下载源现状【已证实】

- 文档站活跃（docs.chmlfrp.net，VitePress，仓库 ChmlFrp-Docs 最后推送 2026-08-26；Panel-v3 2026-10-30 仍在更新）；v1 API 文档标注「即将弃用，尽快迁移 v2」。
- 下载直链（cf-v1.uapis.cn）与面板下载页均可用；图形客户端 ChmlFrpLauncher（Win/macOS/Linux）为主推方式。
- 客户端版本**停在 frp v0.51.2 基线**（fork 仓库最后提交 2025-10-25，包名 `_251023`）——**三年未跟随上游**，v0.53+ 的控制面加密、v0.69+ 的 wire v2 均不存在。

---

## 3. 集成方式对比与推荐

| 维度 | A：子进程托管 frpc（showroom 现状） | B：Rust 原生实现 frp 客户端协议 | C：frp visitor / xtcp 模式 |
|---|---|---|---|
| 双 FRP 兼容 | ✅ 捆绑两套二进制即可（ChmlFrp frpc 连 ChmlFrp 节点；原版 frpc ≥v0.61 连自建节点），版本各自锁定 | ⚠️ 需同时实现两代控制面（v0.51.2 无加密 + v0.53+ AES-CFB；未来 v2 AEAD），且 ChmlFrp 服务端 CheckProxy 语义（proxy 名 `<user>.<name>`、参数与面板记录一致）必须逆向对齐 | ❌ ChmlFrp 节点不可用（面板无 stcp/xtcp + CheckProxy 拒绝）；自建节点可用但要求两端都跑 frpc |
| 协议漂移风险 | 无（上游升级换二进制即可） | **高**：v1→v2 过渡期（v1 将于 v0.78.0 移除）；历史前例 v0.49 xtcp 重构即不兼容；ChmlFrp 魔改不跟随上游 | 中（xtcp 行为随版本变，v0.49 即破坏过一次） |
| 工作量 | 低：进程守护 + 配置生成 + 日志观测 | 高：yamux(或关 tcpMux 走多 TCP)+TLS+JSON v1 编解码+AES-CFB+登录/心跳/work conn 状态机+错误矩阵；双版本分支 | 中（两端 frpc 编排 + fallback 逻辑） |
| 许可 | Apache-2.0 分发二进制合规（保留 LICENSE/NOTICE） | 干净室重实现协议无版权问题；移植 Go 代码则成衍生作品需 Apache-2.0 合规 | 同 A |
| 性能 | 每实例多一个进程（实测 frps+frpc 环回 166 MiB/s，非瓶颈）；数据面与 B 等价（都是用户态 copy） | 单二进制、零额外跳数感、可零拷贝/细粒度流控 | 打洞成功后真正 P2P（最优），失败回退中继 |
| 可控性 | 日志/状态靠子进程 stdout 与探测；ChmlFrp frpc 3 次重连即退出需守护 | 完全可控（重连/多活/流量调度可编程） | frp 自动管理，黑盒 |
| 对 ChmlVPN「多主多活」 | 每台服务端一条 frpc 实例挂各自中转节点，客户端任意接入——与应用层多活天然正交 | 同左，且可在协议内做节点测速切换 | visitor 只能连注册过的对端 proxy，与「任意服务端一致」目标错位 |

**推荐：A（子进程托管）为主，双 frpc 变体（ChmlFrp frpc v0.51.2 定版 + 原版 frpc 定版），B 列为远期演进，C 不采用。**

理由：
1. §1.3 已证两代控制面互不兼容，A 是唯一「同时兼容两家且零协议维护成本」的路径；B 在 v1→v2 过渡期承担双向漂移风险，且 ChmlFrp 侧还要额外对齐其魔改鉴权/命名规则——投入产出比最差的时间点就是现在。
2. A 的所有已知短板都有工程解：进程守护（ChmlFrp frpc 退出即拉起 + 指数退避）、健康探测（本地隧道端口 + frpc admin API）、配置生成（ChmlFrp：面板 `/tunnel_config` 或 `-u/-p` 自举；原版：TOML 模板）。
3. C 的核心价值（P2P 免中转带宽）与 ChmlVPN「节点限速 8–32 Mbps」的痛点直接相关，但 ChmlFrp 上不可用；可作为**自建节点上的可选加速层**（原版 xtcp + fallback stcp）写进远期路线图，主链路不走它。

---

## 4. 「兼容原版 FRP 与 ChmlFrp」协议层要求清单（可测试）

以下每条均可写成自动化验收用例。已在原版 v0.71.1 上跑通的标 ✅（实验复现命令见 §1.5 与 `.tmp/frp-test/`）：

| # | 要求 | 验证方法 | 状态 |
|---|---|---|---|
| R1 | **字节透传**：任意二进制（含 0x00/0xFF/0x16/0x17 首字节、全 256 字节值）过任一中转 sha256 不变 | 经隧道 echo 回 1 MiB 随机 + `bytes(range(256))×64` 比对哈希 | ✅ 原版 v0.71.1（T1/T2）；ChmlFrp 真实节点待测（见未决问题） |
| R2 | **无框定/粘包透明**：任意分段写与合并读字节流一致，中转不注入任何分隔/心跳字节 | 10×13 B 分段写 → 单次读 130 B 比对；再反向（单写大块、分小段读） | ✅ 原版（T2） |
| R3 | **禁用半关闭语义**：协议不依赖 `SHUT_WR`；单向结束用显式 EOF 帧或长度前缀表达 | 单元测试断言协议状态机不触发 shutdown(write)；集成测试模拟「发完即等应答」不依赖 FIN | ✅ 风险已实证（T3：回程 0/65536），设计约束生效 |
| R4 | **首字节自由**：E2E 加密流首帧首字节可为任意值（不避开 0x16/0x17） | 首字节分别取 0x00/0x16/0x17 的握手包过隧道，握手成功率 100% | ✅ 原版用户口实证（T2 用 0x17 首块）；注意 frpc↔frps 入口方向是 frp 自有协议，应用层不出现 |
| R5 | **空闲韧性**：≥10 分钟零流量连接不被中转主动断（数据面无空闲超时），但仍需应用层心跳防 NAT/节点重启 | 空闲连接定时器 + 应用心跳开关两态测试；断言空闲存活、拔掉心跳后在 heartbeatTimeout 内检测断链 | ⏳ 设计项（源码证实无空闲超时：Join 无 deadline） |
| R6 | **断链重连一致**：中转/frpc/节点任一重启后，TCP 对 ChmlVPN 呈现硬断——会话层必须在重连（新 TCP）后恢复且握手结果与断前等价；ChmlFrp 节点上还需覆盖「frpc 3 次重连退出被守护拉起」场景 | kill frpc / 重启 frps / 断网 60s 三场景，断言：恢复时间、会话密钥重协商、无粘死流 | ⏳（ChmlFrp 重连退出行为已证：§2.3） |
| R7 | **吞吐一致性**：同一对端经「原版节点 vs ChmlFrp 节点」吞吐应只差节点限速（ChmlFrp 8–32 Mbps 服务端强制）与 RTT，协议层自身开销 <10% | 10 MiB 传输计时，归一化对比；ChmlFrp 免费节点应收敛到 ~8 Mbps | ⏳（原版环回 166.7 MiB/s 基线已测） |
| R8 | **双栈自举**：同一 ChmlVPN 二进制既能以「usertoken+隧道ID → cfg API → INI → ChmlFrp frpc」拉起，也能以「TOML → 原版 frpc」拉起；两者配置生成器有独立单测 | 对两个生成器做 golden-file 测试；对 cfg API 用录制的响应样本（错误 token 400 行为已实测） | ⏳ |
| R9 | **版本矩阵锁定**：ChmlFrp 节点 ⇔ ChmlFrp frpc（v0.51.2）；自建原版节点 ⇔ 原版 frpc（与 frps 同 minor 代，按官方 9-minor 窗口）；禁止交叉。CI 中固化版本对 | 矩阵冒烟：4 种组合各跑一次 R1，断言只有对角线成功 | ⏳（交叉失败的机理已从源码证实：§1.3） |
| R10 | **UDP 语义**：如走 UDP 隧道，frp 将 UDP 封装在 TCP/yamux 上的 UDPPacket 消息里（`udpPacketSize` 默认 1500，两端需一致，gofrp.org server 参考）；VPN 的 UDP 承载需按「尽力而为、可能乱序/丢失」设计并在 ChmlFrp 节点确认 UDP 开关（31/32 节点允许） | UDP 隧道丢包/乱序注入测试 + 节点字段断言 | ⏳ |
| R11 | **多实例隔离**：每条隧道一个 frpc 实例（或 config_dir 多实例），ChmlFrp 免费套餐 4 隧道上限 → ChmlVPN 服务端暴露模型按「每节点 1 条 tcp 隧道承载全部 VPN 流量（协议层自带多路复用）」设计，不依赖多隧道 | 单隧道上多会话并发压测（≥100 并发流） | ⏳ 设计项 |
| R12 | **合规红线**：不得篡改 ChmlFrp 面板生成的 proxy 参数（CheckProxy 会拒）；境内节点 HTTP 映射需备案域名——ChmlVPN 全走 tcp 类型隧道规避 | 配置生成器断言输出与面板样本逐字段一致（golden 对比） | ⏳ |

---

## 5. 未决问题（gaps）

1. **ChmlFrp 真实节点端到端实测未做**：需要实名注册的 usertoken + 隧道 ID（本调研不注册账号）。§2 全部结论基于魔改仓库源码逐行 diff + 公开 API 实测 + 官方文档，置信度高，但 R1/R6/R7 在 ChmlFrp 节点上的最终验收仍待有账号后补测。
2. **ChmlFrp 节点端运行的 frps 版本**：推断为 ChmlFrp-Frp 仓库的 frps（依据：仓库描述、frps 侧魔改与面板行为一一对应、cs.json 状态导出与面板节点字段吻合、发行包同时含 frps），无官方架构文档直接确认。
3. **面板生成的 frpc.ini 具体字段默认值**（user/token/tls_enable 等）未取得样本（需登录面板）；从 FAQ 日志推断 `user = token-<hash>`、proxy 名 `<user>.<name>`。
4. **官方 frp Windows 二进制在本机被安全策略拦截执行**（「文件所在的卷已被外部更改」错误，重下载/换路径均复现）；实验改用同版本源码自建二进制完成（`--version` 均输出 0.71.1）。在用户机器上分发 frpc.exe 需评估杀软误报与加白名单/签名问题。
5. **wire v2 无正式协议规范文档**：现行依据为 v0.69.0/v0.70.x release notes 与源码；v1 移除时点（v0.78.0）是官方现行计划，可能变动。若未来 ChmlFrp 升级基线或上游切 v2 默认，本报告 §1.3 版本矩阵需复核。
6. **xtcp 在 ChmlFrp 的不可用性**为推断（负面证据：文档/面板/API 均无此能力 + CheckProxy 机制），未实测（无处创建 xtcp 隧道即无法测）。

---

## 附：本调研产出物

- 上游源码克隆：`.tmp/frp-src`（dev @ 93b5279，含 v0.46.0–v0.71.1 tags 供考古）
- ChmlFrp 魔改仓库克隆：`.tmp/chmlfrp-frp`（main @ 9899607，已 fetch v0.51.2 tag 并 diff）
- ChmlFrp 官方发行包：`.tmp/chmlfrpc/ChmlFrp-0.51.2_251023_linux_amd64/`
- 透传实验：`.tmp/frp-test/`（frps.toml/frpc.toml/echo_server2.py/passthrough_test.py/halfclose_detail.py，源码自建 frps.exe/frpc.exe）
- 节点列表快照：`.tmp/chmlfrpc/node.json`（2026-10-31，32 节点）
