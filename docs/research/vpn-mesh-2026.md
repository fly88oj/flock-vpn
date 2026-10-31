# ChmlVPN 调研报告：跨平台 Rust VPN 架构参考与多主多活同步

- 调研日期：2026-10-31（所有结论以截至今日核实到的来源为准）
- 调研对象：本报告服务于 ChmlVPN（本仓库当前为空，已用 `ls -la E:\Works\ChmlVPN` 核实，仅有 `.tmp/`、`.zcode/`、`docs/`）：跨平台高性能 Rust VPN，多台机器经 ChmlFrp（frp 中转服务）组成 VPN 网络；frp 只做纯 TCP 中转，加密/协议层自研端到端；服务端经 FRP 暴露、负责登录认证与设备管理、多主多活互相同步。
- 方法与纪律：只认一级来源（官方文档、RFC、上游源码/README、crates.io 官方注册表 API、微软官方内核配置），逐条标注来源编号（文末「来源清单」）；已证实与推测/建议严格区分。凡本报告写「已验证」的命令类结论，均给出本次实际执行的命令与输出。

---

## 1. TUN 虚拟网卡跨平台

### 1.1 各平台机制（已证实）

| 平台 | 机制 | 关键事实 | 来源 |
| --- | --- | --- | --- |
| Windows | Wintun 驱动（Layer 3 TUN） | 官方自述「与 Linux `/dev/net/tun` 等价的极简 TUN 驱动」；集成只需随程序分发单个 `wintun.dll`（官方预编译签名版 0.14.1，覆盖 AMD64/X86/ARM64/ARM32）；驱动源码 GPL 2.0，官方唯一支持的分发方式是预编译签名 DLL（其授权更宽松） | [S1] |
| macOS | `utun`（内核控制 socket） | 无标准 `/dev/tun`；`utun` 行为与其它平台的 tun 基本一致；TAP 场景用较不公开的 `feth` 接口对（10.13 起可用）；创建接口名必须是 `utun[0-9]+`（boringtun 文档） | [S6][S9] |
| Linux | `/dev/net/tun` + `TUNSETIFF` ioctl | 打开 `/dev/net/tun` 并 ioctl 注册网络设备；`IFF_TUN`（IP 包）/`IFF_TAP`（以太网帧）；创建网络设备需 `CAP_NET_ADMIN`；关闭 fd 即设备消失；3.8 起支持 multiqueue（多 fd 并行收发）；新内核新增 `IFF_BACKPRESSURE`（qdisc 背压） | [S2] |
| Android | `VpnService`（Java API，非 root 唯一路径） | `Builder.establish()` 创建虚拟网卡并返回 fd：「每次 read 取走一个被路由到该接口的出向包，每次 write 注入一个入向包」；同一时刻只允许一个 VPN；首次需用户授权（`prepare()`）；系统强制常驻通知；底层 socket 必须 `protect()` 排除出 VPN 路由（防回环）；`/dev/net/tun` 仅 root 可用，且 VpnService 无 native 等价 API | [S3][S6] |
| iOS/tvOS | NetworkExtension `NEPacketTunnelProvider` | iOS 不允许任意 TUN、不支持 TAP；Rust 侧通过 Swift 层传入的 fd 收发 IP 包；iOS 16+ 旧的 KVO 取 fd 方法失效，业界（WireGuard）通行做法是遍历 fd 找 `com.apple.net.utun_control` 的 `sockaddr_ctl` 对端 | [S4][S5][S6] |

注：Apple 官方 developer.apple.com 文档页为纯 JS 渲染，本次所有抓取工具均无法取到正文（见「未决/限制」）；上表 iOS 事实以三个独立上游工程（tun、tun-rs、tappers/boringtun）的官方仓库文档为据。

### 1.2 Rust 生态现状（crates.io 官方 API 核实，2026-10-31）

| crate | 版本 | 最近更新 | 状态要点 | 来源 |
| --- | --- | --- | --- | --- |
| **tun-rs** | 2.8.16 | 2026-10-29（昨天级活跃） | TUN+TAP；宣称支持 Linux/Windows/macOS/BSD/Android/iOS/tvOS/OpenHarmony 等 11+ 平台；Windows 走 wintun.dll；Linux 支持 TSO/GSO offload 与 multi-queue（自报基准 70.6 Gbps、offload 提速 3–4x）；内置 iOS fd 搜索示例与 Android `VpnService.Builder().establish().getFd()` 示例；同步+tokio/async-io 双 API；Apache-2.0；68 万+ 下载 | [S5][S7] |
| tun (meh/rust-tun) | 0.8.14 | 2026-07-21 | 经典跨平台库（Win/Linux/macOS/FreeBSD/Android/iOS/tvOS/OpenHarmony）；现由 ssrlive 维护发布，Windows 依赖 `wintun-bindings`；README 含 iOS `NEPacketTunnelProvider` 传 fd 完整示例；WTFPL 许可 | [S4][S7] |
| tun2 | 4.0.0 | 2024-10-27（约两年未更新） | tun 的分叉（ssrlive/rust-tun）；已趋停滞，不建议新项目采用 | [S7] |
| tappers (pkts-rs) | 0.x（WIP） | — | 定位测试/抓包友好（pkts.org 生态）；无移动端支持（明确说明 Android/iOS 平台 API 无 native 等价物，不封装）；Windows TAP 依赖 tap-windows6；跨平台包格式一致；依赖极简 | [S6] |
| wintun (nulldotblack) | 0.5.1 | 2025-01-29 | Wintun C 库的安全 Rust 绑定：`load` DLL → `Adapter::create/open` → `start_session(MAX_RING_CAPACITY)` 环形缓冲收发；MIT；README 明言 async 支持仍是 TODO | [S8] |
| rtnetlink | 0.23.0 | 2026-08-18 | Linux 路由/地址/链路配置的 netlink 高层库，tokio 集成；2880 万下载。注意：原 rust-netlink 组织仓库已归档（2022-10-07），但 rtnetlink crate 本身仍由新维护者（Gris Ge）持续发版 | [S10][S11] |
| boringtun | — | — | Cloudflare 的 Rust 用户态 WireGuard 实现（库+CLI）；官方自述已部署于数以百万计 iOS/Android 设备与数千台 Cloudflare Linux 服务器；提供 C ABI 与 JNI 绑定；macOS 即用 utun | [S9] |

**结论（建议）**：数据面网卡层直接采用 **tun-rs**（活跃度、平台覆盖、offload/多队列、移动端 fd 接入路径最完整）；Linux 路由/地址编程配 **rtnetlink**；Windows 不必直接依赖 wintun crate（其无 async），tun-rs 已内置 wintun 集成。若未来需要用户态 WireGuard 兼容协议，boringtun 是 Rust 生态最成熟参考。

### 1.3 容器内 `/dev/net/tun` + `NET_ADMIN`（重点核实 Docker Desktop on Windows）

- **Linux 原生容器（已证实）**：Docker 官方 run 参考写明「默认容器是 unprivileged 的、不允许访问任何设备」；可用 `--cap-add`/`--cap-drop` 细粒度增减 Linux capabilities，其中 `NET_ADMIN` 定义为「执行各类网络相关操作」；`--device=[]` 允许不经 `--privileged` 把宿主机设备开放给容器（官方示例即 `--cap-add SYS_ADMIN --device /dev/fuse`）[S12]。内核文档亦确认：`/dev/net/tun` 的 open 需要 `CAP_NET_ADMIN`（对非自有设备）[S2]。
- **Docker Desktop on Windows（本次重点，已证实到内核级）**：
  1. Docker 官方文档：Docker Desktop for Windows 支持 WSL 2、Hyper-V、Docker VMM 三种后端，**「WSL 2 is the default」**（每用户安装模式仅 WSL2/Docker VMM）[S13]。
  2. 我方本次实际执行验证（一级来源：微软官方 WSL2 内核配置文件）：
     `curl -s https://raw.githubusercontent.com/microsoft/WSL2-Linux-Kernel/master/Microsoft/config-wsl | grep -E "^CONFIG_TUN"`
     输出：`CONFIG_TUN=y` —— WSL2 官方内核把 TUN **编译进内核**（非模块），因此 WSL2 VM 内无需 `modprobe tun`。
  3. 旁证（上游维护者，非官方文档）：gluetun（容器化 VPN 客户端）维护者在 Docker Desktop (WSL2) 讨论中确认无需安装 tun 内核模块即可用；用户日志同时显示 VM 内 `modprobe tun` 报「module not found in 5.4.72-microsoft-standard-WSL2」但容器自行 mknod 出 `/dev/net/tun` 后 OpenVPN 正常工作——即「模块缺失报错无害，设备节点需在容器内创建」[S14]。
- **结论（已证实）**：在 Docker Desktop on Windows（默认 WSL2 后端）里跑需要 TUN 的 Linux 容器可行：容器加 `--cap-add NET_ADMIN`，并 `--device /dev/net/tun`（或容器内 `mknod /dev/net/tun c 10 200`）。
- **限制（未验证）**：Hyper-V / Docker VMM 后端使用 Docker 自带内核，其 `CONFIG_TUN` 本次未核实；若目标用户可能切到这些后端，需另行验证。

---

## 2. 开源对标：数据面 / 控制面 / 密钥分发 / 中继架构

| 项目 | 数据面 | 控制面 | 密钥分发 | 中继/穿透 | 来源 |
| --- | --- | --- | --- | --- | --- |
| **boringtun** | 用户态 WireGuard（Rust 库，协议层无网络/隧道栈，平台自理） | 无（只是协议引擎，CLI 模拟 wg 接口） | 沿用 WireGuard 静态公钥模型 | 无 | [S9] |
| **innernet** | 内核/wireguard-go WireGuard | 单一 coordination server（`innernet-server`）：管理 peer、CIDR、关联（association）即 ACL；peer 主动拉取配置 | 邀请文件（一次性）兑换时客户端**生成新密钥对**并向服务器注册公钥；服务器向 peer 分发其它 peer 的公钥/端点 | 无内置中继；依赖服务器看到的公网端点做直连（可手工 override-endpoint） | [S15] |
| **netbird** | WireGuard（内核优先）p2p mesh | Management 服务（gRPC+UI）：注册认证（IdP/一次性 setup key）、网络图、**IP 分配**、访问策略下发、控制通道推送变更 | 客户端本地生成 WireGuard 密钥对，公钥交 Management，分发给被授权 peer；信号消息用 NaCl box（Curve25519+XSalsa20+Poly1305）端到端加密 | ICE（pion）+STUN 打洞；Signal 服务只做加密信令不存数据；打洞失败回落 Relay（原为 Coturn TURN，v0.29.0 起转为自研 WebSocket relay）；支持 Rosenpass 抗量子 | [S16][S17] |
| **tailscale** | WireGuard（wireguard-go）全互通 mesh；ACL 在**每个节点入向解密时**执行 | 「coordination server」＝公钥收发信箱：节点上传公钥+当前端点，下载域内其它节点公钥/地址；认证外包给 OIDC/SAML IdP；策略集中存储、分布执行 | 私钥永不离开节点；E2E 加密，协调服务器不可解密 | STUN/ICE 高级打洞；打不透时回落 **DERP**（Designated Encrypted Relay for Packets）：全球分布的「加密 TCP 中继」，用 HTTPS 流+WireGuard 密钥，角色类似 TURN 但盲转已加密流量、无法解密 | [S18] |
| **zerotier** | 自研 VL2（类 VXLAN 以太网仿真）+ VL1（加密 p2p 传输）；VL1 加密 Salsa20/Poly1305（NaCl 组合），**明确不实现前向保密** | 网络控制器（controller，即 SDN CA）：签发成员证书（CoM，滑动时间窗防时钟依赖）、能力（capability）、标签（tag）、**地址所有权证书（防 IP 伪冒）**；撤销（revocation）用 rumor-mill 算法 p2p 快速传播 | 身份=公私钥对，40 位地址由公钥带算力代价地推导（碰撞需约 1 万 CPU 年）；先到先得，60 天不活跃过期 | 「行星」根服务器（4 台，ZeroTier Inc. 运营，类 DNS 根）+用户自建「月球」根；先经根转发触发 transport-triggered link provisioning，双方拿到 rendezvous 提示后打洞（含对称 NAT 端口预测、uPnP/NAT-PMP）；打不透就一直走根中继（慢） | [S19] |

### 可借鉴点（针对 ChmlVPN）

1. **「控制面集中、数据面分布」**（Tailscale 模型 [S18]）：ChmlVPN 的服务端本来就承担登录/设备管理，天然是 coordination server；FRP 中转链路则相当于自建的「DERP/Coturn 角色」——两者业界均已验证：中继只盲转密文即可工作，端到端安全不依赖中继可信。
2. **中继不可解密**：DERP「never a way for a DERP server to decrypt your traffic」、NetBird relay 同理 [S17][S18]。ChmlVPN「frp 只做纯 TCP 中转 + 协议层自加密」与该原则一致，且 frp 的 `transport.useEncryption/useCompression` **默认就是关闭的**（frp 官方 README：「The features are off by default」）[S20]，不与自研加密层冲突。
3. **每节点入向过滤执行策略**（Tailscale [S18]、innernet 的 CIDR 关联 [S15]）：设备 ACL 下发到端执行，而不是只在服务端网关过滤。
4. **在线/撤销的传播机制**（ZeroTier 撤销的 rumor-mill、证书滑动窗 [S19]）：多主多活下「踢设备/吊销」需要在无中央单点时仍能全网生效，可借鉴。
5. **IP 防伪冒**（ZeroTier Certificates of Ownership [S19]）：对「设备注册表 + 虚拟 IP」绑定关系可做签名凭证，端侧可独立验证。
6. **抗量子**（NetBird 集成 Rosenpass [S16]）：可选演进方向。
7. **HA 的现实参照**：NetBird 自托管官方文档明言 Management/Signal 的高可用是**商业版功能**，自托管扩展路径是「拆 Relay + SQLite→PostgreSQL」[S21]——说明「多主多活控制面」在同类项目里也不是默认能力，ChmlVPN 自研是合理差异化点。

---

## 3. 虚拟 IP 分配、MTU、路由与 NAT

### 3.1 IP 地址段选择与分配/冲突避免（对标事实）

| 项目 | 地址池 | 分配与冲突策略 | 来源 |
| --- | --- | --- | --- |
| Tailscale | IPv4 `100.64.0.0/10`（CGNAT，RFC 6598 保留段）；IPv6 ULA `fd7a:115c:a1e0::/48` | 「节点只要仍注册，IP 就不变（除非管理员改）」；范围不与 10/8、192.168/16 等常用私网冲突；对内保留 `100.100.0.0/24`、`100.100.100.0/24`、`100.115.92.0/23` 不可分配；官方明示风险：若 ISP 也用 CGNAT 段会冲突；备份/克隆系统盘会出现两设备同 IP | [S22][S23][S27] |
| NetBird | 同为 `100.64.0.0/10` | 每账号随机一个 /16，新 peer 从中**随机选空闲地址**；删除 peer 立即释放地址、无保留期，可再分配 | [S17] |
| innernet | 自选（示例 `10.60.0.0/16` 树状 CIDR） | 「出于安全考虑 IP 不可复用，peer 不可删除只能 disable」；服务端 CLI 自动建议下一个可用 IP；邀请兑换后地址固定 | [S15] |
| ZeroTier | 控制器配置的地址池；另有 rfc4193/6plane 两种 NDP 仿真 IPv6 模式（节点本地无状态推导，免中心分配） | 40 位加密身份与 IP 绑定由「地址所有权证书」防伪冒 | [S19] |

**对 ChmlVPN 的建议（推测/设计建议，非来源结论）**：
- 采用 `100.64.0.0/10`（RFC 6598 IANA 保留给 CGN 的共享地址段 [S27]，Tailscale/NetBird 双先例 [S22][S17]），自留若干 /24 内部用途（对标 Tailscale 的保留子网 [S23]）；IPv6 用 ULA 前缀（对标 Tailscale `fd7a::/48` [S22]）。
- 冲突避免三原则（均有先例）：分配由**强一致存储**裁决（见 §5）；地址与设备公钥/设备 ID 绑定；「释放策略」二选一并写死语义——学 NetBird 立即释放（省地址、随机重取避免撞车 [S17]）或学 innernet 永不复用（安全但耗地址 [S15]）。考虑到本项目设备数规模有限而安全优先，建议「禁用不删除、IP 保留」，提供显式回收命令。
- 防备份/克隆导致的同 IP：借鉴 Tailscale 的教训条目 [S23]，接入时检测重复并强制后连者重新分配。

### 3.2 MTU 与分片

已证实事实：
- RFC 8200（IPv6）：可配置 MTU 的链路「must be configured to have an MTU of at least 1280 octets」（原文见 [S26]，本次 grep 验证第 1385 行附近）。
- Tailscale 官方文档：「Tailscale uses a maximum transmission unit (MTU) of 1280」，且指出其它接口发出更大包时可能被静默丢弃，解法是调低链路 MTU 或 MSS 钳制（本次自官方页面 RSC 数据核验原文 [S24]）。
- ZeroTier 官方文档：默认 MTU `2800`，可升到 9000（巨型帧），但「every member and the physical path between them must support the larger value or traffic may be silently dropped」[S25]。

对 ChmlVPN 的分析与建议（推测）：
- 经 FRP 的**单条 TCP 中转**上，外层是字节流：内层 IP 包不会因路径 MTU 触发 IP 分片（由外层 TCP 分段承载），所以 MTU 的意义主要是（a）内层 TCP 会按内层 MTU 协商 MSS，（b）接收端重组缓冲与内存控制。
- 建议 TUN MTU 取 **1280**（与 Tailscale 一致 [S24]、满足 IPv6 最小值 [S26]）或 1380 左右折中；关键是**避免过大**导致对端内核对超 TUN MTU 的包静默丢弃（ZeroTier 文档描述了该现象 [S25]）。
- **必须重视 TCP-over-TCP**：在「FRP 纯 TCP 中转」上跑 VPN，内层 TCP 流嵌套外层 TCP，两层拥塞控制/重传互相干扰，弱网下性能坍缩是经典问题（经典文献 O. Titz《Why TCP over TCP is a bad idea》2001，本次原站不可达，经 arXiv OpenVPN 性能论文的参考文献核得其存在与被引情况 [S28]）。缓解：预留日后 P2P 直连（UDP）升级路径；短期可对内层流量做单流限速/队列管理，避免多流放大争抢。

### 3.3 路由表与 NAT

已证实事实：
- WireGuard 系（innernet/NetBird/Tailscale）均以「peer 公钥 ↔ 目标网段（allowed-IP 风格）」的映射做密码学路由，配置由控制面下发 [S15][S17][S18]。
- tun/tun-rs 在 macOS/BSD 创建设备时自动按地址配置加路由（README：`route -n add -net 10.0.0.0/24 10.0.0.1`）；tun-rs 把「跨平台一致的自动路由」列为核心特性 [S4][S5]。
- Android：路由由 `VpnService.Builder` 的参数决定（官方：「creates a virtual network interface, configures addresses and routing rules」），且底层 socket 必须 `protect()` 以免隧道自环 [S3]。
- Linux 安全配套（innernet 官方建议）：严格反向路径过滤（`rp_filter=1`，RFC 3704 语境）防跨接口源地址伪冒，以及 `SO_BINDTODEVICE`/`IP_BOUND_IF` 保证控制流量走物理口 [S15]。

对 ChmlVPN 的建议（推测/设计）：全互通小网可用「/16 池整体指向 TUN」单路由；按组隔离时下发明细路由 + 端侧入向过滤（借鉴 §2.3）；服务端如做出口转发（exit node）需 NAT，Windows 用内置 NAT/转发、Linux 用 nftables masquerade——具体策略属实现决策，本次未找到需要引用的额外事实。

---

## 4. 单条 FRP 中转 TCP 连接上的数据面多路复用

前提（已证实）：frp 的 `type = "tcp"` 代理即端口级原始 TCP 转发（官方示例：`ssh -oPort=6000 user@frps公网IP` 直达内网 22 端口）[S20]；frp 自身的加密/压缩默认关闭 [S20]；故 ChmlVPN 拥有这条 TCP 流的完整协议栈自由度。

### 4.1 候选方案对比

| 方案 | 原理与生态 | 优点 | 缺点/风险 | 来源 |
| --- | --- | --- | --- | --- |
| **yamux** | hashicorp 规范（spec.md），显式设计为「依赖底层可靠有序连接（TCP/Unix socket）的流式多路复用」：双向流、流控/背压、**原生 KeepAlive**、低开销支撑数千流；Rust 实现 libp2p/rust-yamux（0.14.1，2026-09-21 更新，实现官方 spec） | 与「可靠字节流」前提完全匹配；协议小、易审计；keepalive 内建；Rust 实现被 libp2p/substrate 大规模使用 | TCP 之上流级 HOL 仍存在（见 4.2）；Go/Rust 双实现需对齐版本语义 | [S29][S30] |
| HTTP/2 (h2) | RFC 9113；Rust 生态 h2 crate（0.4.20，9.3 亿下载）非常成熟 | 生态最厚；h2 crate 直接可用；浏览器/代理兼容 | 语义面向请求-响应（一端发起、头部语义）；RFC 9113 明文：「Note, however, that TCP head-of-line blocking is not addressed by this protocol」——同样无法解决传输层 HOL，却背上不必要的 HTTP 语义复杂度 | [S31][S32] |
| QUIC (quinn) | RFC 9000：「A UDP-Based Multiplexed and Secure Transport」——设计前提是 UDP 承载；自带流复用、流控、连接迁移；quinn（5.3k stars）为纯 Rust 实现，`quinn-proto` 无 I/O、可接自定义事件循环 | 若底层是 UDP，这是最优解：流间无 HOL、0/1-RTT、内置 TLS1.3 | **在「单条 TCP 流」里跑 QUIC 属于双层可靠传输**（QUIC 自己的 ACK/重传叠在 TCP 之上），且 quinn 生态以 UDP socket 为中心（endpoint=单个 UDP socket），改造为流式传输属非支撑用法；收益为零、复杂度翻倍 | [S33][S34] |
| 自定义帧 | 长度前缀帧 + 流 ID + 控制帧 | 最简单、可控、与 showroom 思路延续 | 要自己补：流控、keepalive、背压、粘包边界、版本协商——等于重写半个 yamux | （工程判断） |

### 4.2 队头阻塞（已证实 vs 分析）

- 传输层 HOL：只要底层是单条 TCP，任何复用器都无法消除——RFC 9113 对 HTTP/2 的这句说明同样适用于 yamux [S32]。QUIC 的流间 HOL 消除依赖 UDP 承载 [S33]，在 TCP 里得不到。
- 分析（推测）：对 ChmlVPN 的实际影响取决于内层流量构成。内层 UDP/ICMP（游戏、DNS）对 HOL 敏感；内层 TCP 本身有序，损失主要是「多内层流共享一条外层 TCP 的公平性」。缓解手段：yamux 流级 backpressure + 适度增大窗口 + 对控制流（心跳/信令）用独立小流并高优先级调度。

### 4.3 心跳、断线重连（已证实 + 建议）

- yamux 原生 KeepAlive（README 明列），无需自造 ping 帧 [S29]。
- frp 侧：frps↔frpc 控制连接有自己的 heartbeat（可选把认证扩展到心跳包），但那是 frp 内部连接；ChmlVPN 客户端↔服务端的会话心跳属于我们自己的协议层职责 [S20]。
- 建议（推测）：外层 TCP 断线后（1）会话句柄保留期 + 指数退避重连（ChmlFrp 节点列表轮询）；（2）重连后用会话 ID + 单调递增序号恢复流上下文，或简单粗暴全量重建（设备上线即重新拉网络配置，借鉴 Tailscale「控制通道重连后重拉」模型 [S18]）；（3）心跳间隔可配，默认 30s、3 次未响应判定断线（工程惯例，非来源结论）。

### 4.4 本课题推荐（推测/设计建议）

**推荐：E2E 加密层（沿用 showroom 协议层；清单未随任务提供，见未决）承载于 yamux 之上**：`TcpStream(FRP) → 握手/加密层（E2E，服务端身份由注册时预置凭证认证）→ yamux → 逻辑流{设备数据流(承载 TUN 包的帧化)、控制流(网络配置/心跳/事件)}`。yamux 的 Rust 实现（libp2p/rust-yamux）活跃维护、协议规范公开可审计、原生 keepalive，与「一条可靠字节流」的前提严丝合缝；不建议 HTTP/2（语义错配）与 QUIC-over-TCP（双重可靠层）。若 showroom 现有协议已有帧格式与流概念，则「自定义帧」是低迁移成本备选，但应补齐流控与 keepalive 语义后再定。

---

## 5. 多主多活服务端同步

### 5.1 候选机制对比（事实部分依来源，评价部分为分析）

| 机制 | 一致性与冲突处理 | 适配本项目三类数据的评价 | 来源 |
| --- | --- | --- | --- |
| **Raft（openraft）** | 强一致：日志复制 + 单一 leader 提交；openraft（Rust，0.9.25 稳定 / 0.10.0-alpha.37，2026-10 仍在发版）：`ensure_linearizable()` 线性一致读、快照/日志压缩、joint 动态成员变更、learner 节点、混沌测试（分区/暂停/时钟偏移等 8 类 nemesis）进 CI；为 Databend meta-service 的共识引擎 | **设备注册表 + 认证凭证**：写少读多、要求「吊销立刻全局生效」「任意节点读写一致」——正是 Raft 的甜区。读走 follower 的线性一致读，正好满足「客户端接任意服务端效果一致」 | [S35] |
| **CRDT** | 最终一致；并发写自动合流（无冲突，但「合流」不等于「正确」） | 适合**在线状态**这类「最后一次看见 wins / 集合增删」的数据；不适合凭证吊销（必须全序且及时） | （机制通识；本报告未对 CRDT 原始论文逐条核实，见未决） |
| **Gossip/SWIM（memberlist）** | memberlist：SWIM + Lifeguard 扩展，「eventually consistent but converges quickly」，管理成员关系与故障检测，可调收敛速度/带宽 | 适合**在线状态 + 服务端成员发现**：低频小状态、容忍秒级陈旧；不承载强一致数据 | [S36] |
| **共享数据库**（如 PostgreSQL） | 一致性依赖数据库（单写者 + 复制）；应用层多主需自行处理并发写语义 | 最省事的基线（NetBird 自托管路径：SQLite→PostgreSQL [S21]）；但引入外部有状态组件与运维面，且「多主」实为「库前负载均衡」，故障切换语义不属于应用层 | [S21] |

### 5.2 分数据类别结论

| 数据 | 一致性要求 | 推荐机制 | 冲突处理 |
| --- | --- | --- | --- |
| 设备注册表（设备 ID、虚拟 IP、元数据） | 强一致；IP 分配不能撞 | **openraft 复制状态机**（建议 redb/rocksdb 作为状态机存储） | 所有分配/回收 = Raft 日志里的串行操作，天然无冲突；快照供新节点加入 |
| 认证凭证（设备密钥/吊销列表） | 强一致 + 及时吊销 | 同上（同一状态机） | 吊销提交即全序生效；配合短 TTL 的会话票据控制传播延迟面 |
| 在线状态（谁连着哪个服务端） | 弱一致可接受（秒级陈旧） | **本地所有权 + gossip 传播**（memberlist 思路：每台服务端只权威报告「连在我这的设备」，带租约 TTL） | 「同一设备连到两个服务端」冲突：以租约时间新者胜，旧服务端收到通知后踢会话（借鉴 ZeroTier 撤销的快速传播思路 [S19]）；这是策略决策不是数据合并问题 |
| 网络配置快照（下发客户端的 peer/路由/ACL） | 派生数据 | 由 Raft 状态机版本化生成，gossip/推送到客户端 | 幂等按版本号应用 |

### 5.3 结合本项目约束的推荐架构（推测/设计建议）

约束回顾：每个服务端各挂一个 FRP 中转节点；客户端接入任意服务端效果一致；服务端之间亦经公网（各自 FRP 链路或直连）互通。

推荐分两阶段：

1. **第一阶段（快速可用）——「单写多读」的 Raft 多主多活**：
   - 3 台（容 1 故障；5 台容 2）服务端组成 openraft 集群；注册/凭证/配置全部进状态机；
   - 客户端可连任意服务端：读（登录校验、拉配置）走该节点线性一致读（`ensure_linearizable`），写（注册、改配置）由该节点转发给 leader，多一跳 FRP 延迟对写少场景可忽略；
   - 在线状态用独立 gossip 通道（自实现 UDP/TCP gossip 或移植 memberlist 思路；Rust 无官方 memberlist，需自实现或用其它 crate——见未决）传播租约；
   - 某台服务端或其 FRP 节点整体失联：Raft 自动选主，客户端按「服务端列表 + 探活」切换，效果等价（对标 NetBird「客户端容忍 Management 短暂离线、连接已建立则不受影响」的设计取向 [S21]）。
2. **第二阶段（规模/自治需要时）**：把「会话票据签发」下放为各服务端本地能力（凭证根在 Raft，短时效票据本地签），进一步消除登录路径对 leader 的依赖。

明确不推荐：CRDT 管凭证（吊销语义无法保证）；纯 gossip 管注册表（IP 分配可能脑裂撞车）；只上共享 DB（把多主多活问题转嫁给数据库，且与「每服务端一个 FRP 节点、无共享内网」的部署形态不契合——NetBird 的 PG 方案仍要求数据库单独可达 [S21]）。

---

## 6. 推荐总体架构（综合以上，全部为设计建议）

```
┌────────────── 客户端（Win/macOS/Linux/Android/iOS）──────────────┐
│ TUN(tun-rs) ←帧化→ 会话层(E2E 加密, 沿用 showroom) ←yamux→ 单条TCP │
│ 路由/protect/分片控制（§3）                                        │
└───────────────┬───────────────────────────────────────────────┘
                │ 经 ChmlFrp（frp 纯 TCP 代理，不加密不压缩）
        ┌───────┴────────┐
        ▼                ▼
   服务端 A (FRP节点A)  服务端 B (FRP节点B) ...（3/5 台）
        │  openraft 强一致状态机：设备注册表 + 凭证 + 配置版本        │
        │  本地会话表 + gossip 租约（在线状态、成员发现）             │
        └────────────── 服务器间互联（公网直连或经各自 FRP）──────────┘
```

要点：数据面在客户端—服务端之间仍是「会话型隧道」（首发版本不做 peer 直连，规避 NAT 穿透复杂度）；服务端之间只同步控制面；FRP 全程只见密文。

---

## 7. 未决与限制（如实声明）

1. **showroom 现有协议层清单未随任务提供**（任务写「见下方清单」但清单缺失），本报告无法评估「直接沿用」的具体兼容性；§4.4 的推荐以「加密层与复用层解耦」为前提给出。
2. **Apple 官方文档未能抓取**（developer.apple.com 为 JS 渲染，WebFetch/抓取器均只得空壳/404）；iOS 事实以 tun/tun-rs/tappers/boringtun 四个上游仓库官方文档为据，未直接引用 Apple 原文。
3. **ChmlFrp 平台本身未核实**（免费额度、是否放行长连接、是否支持 xtcp/tcpmux、带宽与稳定性）；frp 能力均引自 frp 上游 [S20]。
4. **NetBird Signal 的集群化协议**（是否内部使用 memberlist gossip）未在其官方文档中找到说明，本报告未作此断言。
5. **Rust 侧 gossip/SWIM 库选型未完成核实**（memberlist 为 Go 库 [S36]；Rust 对应物如 `chitchat`/`swim` 等未逐一考证活跃度）。
6. **Docker Desktop 的 Hyper-V / Docker VMM 后端内核 `CONFIG_TUN` 未验证**（仅 WSL2 默认后端已验证）。
7. **TCP-over-TCP 经典文献原站不可达**（Titz 2001；经 arXiv 论文参考文献佐证其存在与表述 [S28]），其机理描述在本报告中标注为工程分析。
8. WireGuard 常见的 1420 MTU 说法本次未核实来源，报告未采用该数字。

---

## 来源清单（全部于 2026-10-31 访问核实）

| # | 来源 | URL |
| --- | --- | --- |
| S1 | Wintun 官网（Layer 3 TUN 驱动，0.14.1 签名 DLL） | https://www.wintun.net/ |
| S2 | Linux 内核官方文档：Universal TUN/TAP device driver | https://docs.kernel.org/networking/tuntap.html |
| S3 | Android 官方 API 参考：VpnService | https://developer.android.com/reference/android/net/VpnService |
| S4 | tun crate 上游仓库（meh/rust-tun，README 平台说明与 iOS 示例） | https://github.com/meh/rust-tun |
| S5 | tun-rs 上游仓库（平台矩阵、offload/多队列基准、iOS/Android 接入示例） | https://github.com/tun-rs/tun-rs |
| S6 | tappers 上游仓库（utun/feth/Windows 驱动/移动端限制说明、对比表） | https://github.com/pkts-rs/tappers |
| S7 | crates.io 官方 API（tun-rs 2.8.16@2026-10-29、tun 0.8.14@2026-07-21、tun2 4.0.0@2024-10-27 等元数据） | https://crates.io/api/v1/crates/tun-rs 等 |
| S8 | wintun crate 上游仓库（Rust 绑定、ring buffer 会话、无 async 说明） | https://github.com/nulldotblack/wintun |
| S9 | boringtun 上游仓库（Cloudflare 用户态 WireGuard，平台表、utun 说明） | https://github.com/cloudflare/boringtun |
| S10 | rust-netlink 组织仓库（已归档说明） | https://github.com/rust-netlink/netlink |
| S11 | crates.io API：rtnetlink（0.23.0@2026-08-18，2880 万下载） | https://crates.io/api/v1/crates/rtnetlink |
| S12 | Docker 官方 run 参考（docker/docs 所 vendor 的 docker/cli 源文件；--cap-add/--device/NET_ADMIN 定义） | https://docs.docker.com/reference/cli/docker/container/run/ （源：_vendor/github.com/docker/cli/docs/reference/run.md） |
| S13 | Docker 官方文档：Install Docker Desktop on Windows（三后端，WSL 2 默认） | https://docs.docker.com/desktop/setup/install/windows-install/ |
| S14 | gluetun 上游讨论 #534（Docker Desktop WSL2 下 tun 可用性，维护者确认） | https://github.com/passteque/gluetun/discussions/534 |
| S15 | innernet 上游仓库（coordination server、邀请兑换新密钥对、IP 不复用只禁用、RPF 建议） | https://github.com/tonarino/innernet |
| S16 | NetBird 上游仓库（特性矩阵、内部机制：ICE/STUN/Signal/Relay 回落、Rosenpass） | https://github.com/netbirdio/netbird |
| S17 | NetBird 官方文档：How NetBird Works（Management 职责、100.64.0.0/10 随机 /16、地址立即释放、Signal/Relay 细节） | https://docs.netbird.io/about-netbird/how-netbird-works |
| S18 | Tailscale 官方博客：How Tailscale works（WireGuard 数据面、coordination server、DERP 无法解密、节点级 ACL、审计日志） | https://tailscale.com/blog/how-tailscale-works |
| S19 | ZeroTier 官方协议文档（VL1/VL2、行星/月球根、rendezvous、Salsa20/Poly1305 无前向保密、控制器 CA、CoM/撤销/所有权证书） | https://docs.zerotier.com/protocol/ |
| S20 | frp 上游仓库（TCP 代理用法、加密/压缩默认关闭、TLS 默认开、心跳认证扩展、tcpmux/xtcp） | https://github.com/fatedier/frp |
| S21 | NetBird 官方文档：Splitting Your Self-Hosted Deployment（SQLite→PostgreSQL、Management/Signal HA 为商业版、Relay 拆分、客户端容忍 Management 宕机） | https://docs.netbird.io/selfhosted/maintenance/scaling/scaling-your-self-hosted-deployment |
| S22 | Tailscale 官方文档：How Tailscale assigns IP addresses（100.x.y.z 稳定 IP、fd7a:115c:a1e0::/48） | https://tailscale.com/docs/concepts/ip-and-dns-addresses |
| S23 | Tailscale 官方文档：Reserved IP addresses（CGNAT RFC 6598、保留子网、CGNAT 冲突、克隆盘同 IP） | https://tailscale.com/docs/reference/reserved-ip-addresses |
| S24 | Tailscale 官方文档：Troubleshoot TCP connection issues（MTU 1280、静默丢弃、MSS 钳制） | https://tailscale.com/docs/reference/troubleshooting/network-configuration/tcp-connection-two-devices |
| S25 | ZeroTier 官方文档：Central API Examples（默认 MTU 2800、可调 9000 及静默丢弃风险） | https://docs.zerotier.com/api-central-examples/ |
| S26 | RFC 8200（IPv6；可配置 MTU 链路 ≥1280 octets） | https://www.rfc-editor.org/rfc/rfc8200.txt |
| S27 | RFC 6598（IANA 保留 IPv4 共享地址空间 /10，供 CGN 使用） | https://www.rfc-editor.org/rfc/rfc6598.txt |
| S28 | arXiv 2504.19069（OpenVPN 性能分析；其参考文献[12]即 O. Titz《Why TCP over TCP is a bad idea》2001） | https://arxiv.org/html/2504.19069v1 |
| S29 | hashicorp/yamux 上游仓库（依赖可靠有序连接、双向流/流控/keepalive、spec.md） | https://github.com/hashicorp/yamux |
| S30 | libp2p/rust-yamux 上游仓库 + crates.io（0.14.1@2026-09-21，实现官方 spec） | https://github.com/libp2p/rust-yamux |
| S31 | crates.io API：h2（0.4.20@2026-10-06） | https://crates.io/api/v1/crates/h2 |
| S32 | RFC 9113（HTTP/2；「TCP head-of-line blocking is not addressed by this protocol」） | https://www.rfc-editor.org/rfc/rfc9113.txt |
| S33 | RFC 9000（QUIC：A UDP-Based Multiplexed and Secure Transport） | https://www.rfc-editor.org/rfc/rfc9000.txt |
| S34 | quinn 上游仓库（纯 Rust QUIC；endpoint=单 UDP socket；quinn-proto 无 I/O 可接自定义事件循环） | https://github.com/quinn-rs/quinn |
| S35 | openraft 上游仓库 + crates.io（0.9.25 稳定/0.10.0-alpha.37；线性一致读、快照、动态成员、混沌测试；Databend 生产使用） | https://github.com/databendlabs/openraft |
| S36 | hashicorp/memberlist 上游仓库（SWIM+Lifeguard、最终一致成员与故障检测） | https://github.com/hashicorp/memberlist |

### 本次实际执行的验证命令（供复核）

- `curl -s https://raw.githubusercontent.com/microsoft/WSL2-Linux-Kernel/master/Microsoft/config-wsl | grep -E "^CONFIG_TUN"` → 输出 `CONFIG_TUN=y`（WSL2 官方内核 TUN 内建）。
- `curl -s https://www.rfc-editor.org/rfc/rfc8200.txt | grep …"1280 octets"` → 命中第 1385 行「must be configured to have an MTU of at least 1280 octets」。
- `curl -s https://www.rfc-editor.org/rfc/rfc9113.txt | grep …head-of-line` → 命中「TCP head-of-line blocking is not addressed by this protocol」。
- `curl -sL https://tailscale.com/docs/reference/troubleshooting/network-configuration/tcp-connection-two-devices | …` → 页面数据中命中「uses a maximum transmission unit (MTU) of 1280…might get dropped silently…use MSS clamping」。
- `curl -s https://raw.githubusercontent.com/docker/docs/main/_vendor/github.com/docker/cli/docs/reference/run.md`（经 GitHub tree API 定位路径）→ 提取「Runtime privilege and Linux capabilities」一节与 `--cap-add`/`--device`/`NET_ADMIN` 定义。
- crates.io 官方 API 抓取（tun-rs/tun/tun2/rtnetlink/wintun/openraft/yamux/h2）核实版本与更新日期（正文引用处标注）。
