# 面向「FRP 纯 TCP 中转之上的高性能 VPN 隧道」的密码学最佳实践调研

- **日期**：2026-10-31（所有「现状/采用度」结论以截至今日为准）
- **课题背景**：ChmlVPN——多台电脑经 ChmlFrp 中转节点组成 VPN 网络；frp 只做纯 TCP 中转，端到端加密在自有协议层完成；服务端经 FRP 暴露，负责登录认证与设备管理，多主多活互相同步。showroom 现有协议栈为候选直接沿用对象。
- **方法**：结论只认一级来源（RFC/RFC-Editor、NIST 官方页、官方博客、上游源码、crates.io API、docs.rs），并附本机实测；每个论断括注来源编号（对应文末[参考文献](#参考文献)）。区分【已证实】与【建议/推测】。
- **本机实测标注**：标注「实测(本机)」的数据出自本次调研在本机执行的基准（见 §2.3，CPU：Intel Core Ultra 9 285HX，Windows 11，Rust 1.98.1 release + LTO + codegen-units=1）。

---

## 0. 结论速览（TL;DR）

| 方面 | 截至 2026-10-31 的结论 | 关键依据 |
|---|---|---|
| 数据面 AEAD | **AES-256-GCM 仍是首选**（客户端/服务端均为桌面/服务器 CPU，AES 硬件普及），但 RustCrypto 新一代实现（aes 0.9 内核，启用 VAES）比 showroom 所用旧代（aes 0.8.4）快 ~2.3×【实测(本机)】；nonce 必须改为**每方向严格单调计数器**（长寿命会话禁用纯随机 96-bit nonce 逼近 2^32 生日界）；无 AES 硬件或强抗误用需求时用 **ChaCha20-Poly1305 / XChaCha20-Poly1305 / AES-GCM-SIV** | [27][28][30][15][16][17] |
| 握手/KEM | **X25519+ML-KEM-768 混合已是主流标准**：RFC 10024（2026-08，Proposed Standard）、Chrome 131 默认、Cloudflare 人类流量 >65%、OpenSSH 10.0 默认；隧道层自研握手推荐 **WireGuard 式 1-RTT（Noise IK 思路）+ X25519+ML-KEM-768 混合**；TLS 1.3（rustls）是省事备选 | [20][22][23][24][25][26][8][9][10] |
| showroom 的 RSA-3072-OAEP 封装 | **明确评价：替换**（数据面）。无前向保密、384B 定长头、RSA 密钥生成/解封装昂贵；替换为 X25519+ML-KEM-768 混合封装（成本 <0.1ms、密文 ~1120B）或纯 X25519。短期若保留必须维持「每信封一次性 k」纪律 | [12][20][28ml-kem 实测][实测(本机)] |
| 用户认证 | **OPAQUE = RFC 9807（2025-07）**（ask 与 showroom 注释写的 RFC 9380 有误，9380 是 Hashing-to-Curves）；ristretto255-SHA512 仍是 RFC 9807 推荐套件**第一位**，未废弃；opaque-ke 维护活跃（3.0.0→4.0.1→4.1.0-pre.2），建议从 3.0.0 升级；Ed25519 已是 FIPS 186-5 批准算法（2023-02），ML-DSA（FIPS 204）为可选加档而非必选 | [4][3][5][28][13][14] |
| Rust 生态 | 主力用 **RustCrypto 纯 Rust 全家桶**（Apache-2.0/MIT，无 C 构建依赖，跨平台最省心）；TLS 层用 rustls（默认 aws-lc-rs）；**liboqs 官方明示不建议生产使用**；ring 发布节奏慢（0.17.14，2025-03-11 后无稳定版） | [28][31][32][33] |
| rekey/FS/重连 | 采纳 WireGuard 模型：**计数/时间双阈值触发 rekey（2^60 包或 120s）、180s 硬拒绝、64-bit 计数器 + 滑动窗口抗重放**；重连不做 PSK 恢复——每次全新 1-RTT 握手（ML-KEM-768 全程 <0.1ms【实测(本机)】），配合漫游（端点可变、按对端公钥识别会话）与 keepalive | [10][9][6][8] |

---

## 1. showroom 现状核实（一级来源：本地源码）

本次调研直接核对了 `E:\Works\showroom` 源码，ask 中给出的现状描述与源码一致，要点与证据：

- 依赖锁定版本（`showroom/Cargo.lock`）：`opaque-ke 3.0.0`、`aes-gcm 0.10.3`、`rsa 0.9.10`、`ed25519-dalek 2.2.0`、`argon2 0.5.3`、`sha2 0.10.9`、`rand 0.8.8`。
- 加密封装：`showroom-common/src/lib.rs:378-461`——`[384B RSA-OAEP-SHA256 封装 32B k] || 每段[12B 随机 nonce][AES-256-GCM 密文+16B tag]`，段=4MiB 明文，无 AAD；空信封合法；解封任何 tag 失败即返回 Err。
- 签名：`showroom-common/src/lib.rs:222-261` canonical 串与 `SR-SIG1 <user>:<ts>:<nonce>:<sig_b64url>`；verify 对 user 名下全部公钥任一命中（`lib.rs:291-340`）；预哈希流式签名 `sign_prehashed`。
- OPAQUE：`showroom-common/src/opaque.rs`——ristretto255 Suite、TripleDH、Identity KSF、`SERVER_ID=b"showroom-server"`、argon2id(19456KiB, t=2, p=1) 外部硬化、盐 = `b"showroom-opaque-v1"+user`。
- 抗重放：`showroom-common/src/lib.rs:48` `SIG_WINDOW_SECS=300`（绝对值判定，`lib.rs:326`）；per-user nonce 查重与 bind_token(60s 单次) 在 `showroomctl/src/serve.rs:34-44/913-951`。
- EtM：`docs/security.md:78-90`——SR-SIG1 覆盖整个信封哈希，先验签后解密；分片导入每片独立签名 + 服务端 seq/total 强制。

**新发现的两处「引用/规范」偏差**（ask 已知第一处，第二处为本次新发现）：

1. 【已证实】nonce 长度规范-实现偏差：`docs/security.md:21` 写「16 个 hex 字符（8 随机字节）」，实现 `nonce_hex()`（`lib.rs:75`）为 16 随机字节（32 hex）；verify 仅查非空。实现比规范更强，应改规范文档。
2. 【已证实】**RFC 编号引用错误**：showroom 代码注释与 ask 均称 OPAQUE 为「RFC 9380」，但 RFC-Editor 官方页显示 **RFC 9380 = "Hashing to Elliptic Curves"**（Faz-Hernandez 等，CFRG/IRTF）[3]；OPAQUE 实为 **RFC 9807 "The OPAQUE Augmented PAKE Protocol"（2025-07，Informational，IRTF 流）**[4]。两者易混（OPAQUE 确实依赖 H2C 做群编码）。建议修正注释与文档引用。

---

## 2. Q1 数据面 AEAD

### 2.1 候选 AEAD 现状（截至 2026-10-31）

| 算法 | 标准状态 | nonce | 抗误用 | 相对 GCM 性能 | 一句话定位 |
|---|---|---|---|---|---|
| AES-256-GCM | NIST SP 800-38D（2007，修订中，见下） | 96-bit | 否（nonce 复用即灾难） | 基准（AES-NI/VAES/ARM-CE 下最快档） | 默认选择；nonce 纪律是生命线 [15][16][17] |
| ChaCha20-Poly1305 | RFC 8439（WireGuard 使用，引 RFC 7539 语法）[9] | 96-bit（协议内常配计数器） | 否 | 无 AES 硬件时最快；有 AES 硬件时 ≈ 旧代 GCM【实测(本机)】 | 无 AES-NI 端/极简恒时实现偏好 [9][30] |
| XChaCha20-Poly1305 | **draft-irtf-cfrg-xchacha-03 已过期/死亡（2020-01 最后修订，Datatracker 标记 Expired/Dead）**[34] | 192-bit | 否 | 与 ChaCha 相当（多一次 HChaCha20）【实测(本机)】 | 事实标准（libsodium 等）但 CFRG 规范未成文；随机 nonce 友好 |
| AES-GCM-SIV | RFC 8452（2019）[2] | 96-bit | **是**（SIV 派生，nonce 复用仅泄露相等性） | 官方成本模型：AES-256 需 p+7 次 AES 调用；「加密约为 GCM 的 2/3 速度，解密 5% 以内差距」[2] | nonce 风险高（随机 nonce/VM 快照/多主复制）时的优选 |
| XAES-256-GCM | C2SP 规范（社区规范，非 RFC）[16] | 192-bit | 否 | 每条消息多 3 次 AES 调用（可预计算 2 次）[16] | 纯 FIPS 组件搭出的「扩展 nonce GCM」：随机 nonce 可安全用到 ~2^80 条消息 [16] |
| GCM-SST | draft-mattsson-cfrg-aes-gcm-sst **-21（2026-07），个人草案，未成 RFC** [18] | 96-bit | 部分 | — | 面向短标签/5G 场景；尚未标准化，暂不建议主线采用 |
| OGCM-1/2 | **纯学术**（Iwata–Seurin《Reconsidering the Security Bound of GCM》提出，修正 GCM 弱密钥/伪造界）[19] | — | — | — | 无标准化、无主流库实现；仅在文献综述层面认知即可 |
| AEGIS 族 | draft-irtf-cfrg-aead-limits-13 覆盖其界（草案）[17] | — | — | 极高（SIMD 专用） | 新兴但生态/标准未定，不作为 VPN 主线 |

**NIST SP 800-38D 修订中**【已证实】：NIST 已于 2025-01-06 发布 SP 800-38D Rev.1 预草案征求意见，此后又有第二次初步草案；修订动机包括随机 nonce 约束与新分组密码适配 [15]。学界（ePrint 2024/1111）主张**直接禁止 GCM 配随机 96-bit nonce**（生日碰撞攻击）[35]。

### 2.2 nonce 管理与抗重放（长寿命会话最佳实践）

**约束（已证实，属引用链说明）**：

- SP 800-38D 对 GCM 的两条硬约束：**随机生成 96-bit IV 时每密钥加密次数 ≤ 2^32**（生日界）；**每密钥总加密数据 ≤ 2^39−256 分组**。注：本次未能直接解析 38D 原文 PDF（WebFetch 不支持 PDF），该两条经 C2SP XAES 规范页 [16]、ePrint 2024/1111 [35] 与 NIST 修订公告 [15] 三处交叉转引，非原文逐字核对（详见 §gaps）。
- CFRG《Usage Limits on AEAD Algorithms》仍为草案（draft-irtf-cfrg-aead-limits-13，未出版 RFC）：96-bit IV AES-GCM 单密钥保密性界约 **2^47.5 条消息**，并给出完整性/伪造尝试上限；**注意网传「RFC 9513 = AEAD 限额」是错的——RFC 9513 实为 OSPFv3 SRv6 扩展**【已证实，Datatracker 核对】[17][36]。
- Noise 规范对 AESGCM 的建议：单密钥不超过 2^56 字节（约 72 PB），nonce 用满 2^64−1 必须终止会话 [8]。

**对长寿命 VPN 隧道的推荐做法**【建议，依据上述标准】：

1. **禁用纯随机 96-bit nonce 于长会话**。每方向维护 64-bit 严格单调计数器，AEAD nonce = 计数器（WireGuard 即此法：nonce = 32 bit 零 + 64-bit LE 计数器 [9]）。随机 nonce 只在「每密钥消息数 ≪ 2^32 且密钥一次性」的信封场景可用（showroom 的一次性 k 信封恰属此类——每信封段数 = n/4MiB，远低于界）。
2. **抗重放 = 64-bit 计数器 + 滑动窗口**：WireGuard 在接收侧维护最大已收计数与「约 2000 个历史值」的位图窗口（协议页 [9]；实现窗口 2048，见 wireguard-go [10]）。Noise 规范把重放防护定为应用义务：接收方必须记录成功解密的 nonce 并拒绝重复 [8]。TCP 有序交付下窗口可缩小，但 FRP 中转可能整条重建连接，窗口仍有价值（防跨连接重放需配合握手新鲜性）。
3. **伪造尝试限额**：每密钥失败验证次数要有上限并触发 rekey/断链（GCM 界依赖失败次数）[17]。
4. **大分片 AEAD 的代价**：showroom 的 4MiB 段本身合法（GCM 单消息明文上限 ~2^36−32 B ≈ 64 GiB [16]），代价是**必须整段缓冲 + 失败即丢整段**（流式恒定内存是 showroom 已有设计）；GCM 的 GHASH 与 CTR 天然可并行，大段在 AES-NI 上摊薄良好（本机 4MiB 段与 64KiB 包吞吐几乎相同，见下）。若要减小丢段粒度，VPN 数据面应按 MTU 级小包（≤64KiB 或 1500B 级）分段，文件信封才用大段。

### 2.3 硬件加速与吞吐（含本机实测）

【已证实】硬件指令与库支持：

- OpenSSL 3.1.0（2023-03-14）CHANGES 官方条目：「**AES-GCM enabled with AVX512 vAES and vPCLMULQDQ**」——VAES/AVX-512 已进主流 TLS 库 [27]。
- RustCrypto `aes` crate：0.8.4 文档只提 **AES-NI 与 ARMv8 CE** 运行时探测，未提 VAES [30a]；**0.9.3 文档明确写运行时探测「AES-NI and VAES」**，aarch64 上用 ARMv8 CE（点名 Apple M1）[30b]。
- RFC 8452 官方性能表述：AES-256-GCM-SIV「多 KB 消息解密只比 GCM 慢约 5%，加密约 2/3 速度（两遍处理）」[2]。

【实测(本机)】本次在 Intel Core Ultra 9 285HX（Windows 11，`aes=true pclmulqdq=true avx2=true avx512f=false`）上用 RustCrypto 各 crate 实测（单线程，release+LTO，缓冲区就地加密；两次运行结果一致）：

| 算法（crate 版本） | 4MiB 段 GB/s | 64KiB 包 GB/s |
|---|---|---|
| AES-256-GCM（aes-gcm 0.10.3 → aes **0.8.4**） | 2.23 | 2.25 |
| ChaCha20-Poly1305（chacha20poly1305 0.10.x） | 2.29–2.38 | 2.23–2.34 |
| XChaCha20-Poly1305（同上） | — | 2.26–2.30 |
| AES-256-GCM-SIV（aes-gcm-siv 0.12.1 → aes **0.9.3**） | **5.20–5.22** | **5.28** |

（基准程序与完整输出见附录 A；两代 crate 依赖树差异经 `cargo tree` 核对：aes-gcm 0.10.3 → aes v0.8.4，aes-gcm-siv 0.12.1 → aes v0.9.3。）

**结论**：

1. **RustCrypto 存在「新旧代差」**：showroom 所用 aes-gcm 0.10.x（2026-08 后已有新一代 **aes-gcm 0.11.1**、**chacha20poly1305 0.11.0**、aead 0.6/hybrid-array 体系 [28]）走的是 aes 0.8 内核；新一代 aes 0.9 内核（含 VAES 路径）在本机快 **~2.3×**。**迁移到 0.11 代是零密码学风险、纯性能收益的第一优先事项**。
2. 该实测与 RFC 8452 的「GCM-SIV 加密 2/3 速度」不矛盾：那条是同代 AES 内核下的模式开销；这里测得的是「新内核+SIV」对「旧内核+GCM」，说明内核代差大于模式代差。
3. 无 AES 硬件的端（部分软路由/旧 ARM）：ChaCha20-Poly1305 是正确后备（本机 AES 硬件开启时它与旧代 GCM 打平，业界共识是无 AES-NI 时 ChaCha 显著占优 [9][30]）。桌面/服务器/x86 手机场景 AES 硬件几乎必然存在 [27][30]。
4. 【建议】ChmlVPN 数据面：**主 AES-256-GCM（aes-gcm 0.11）+ 计数器 nonce**；握手协商算法列表中放 XChaCha20-Poly1305 作为无硬件后备；若担心 nonce 误用（多主复制、断点重放逻辑复杂），直接选 **AES-256-GCM-SIV 0.12**（本机最快且抗误用）。

---

## 3. Q2 握手与密钥协商

### 3.1 Noise vs TLS 1.3 vs WireGuard 式握手

| 维度 | Noise（IK/XX）[8] | TLS 1.3（RFC 8446）[6] | WireGuard 式（Noise IK + 定型）[9][10] |
|---|---|---|---|
| RTT | IK 1-RTT（0-RTT 数据需 PSK）；XX 2-RTT | 1-RTT（0-RTT 可选） | **1-RTT**，握手下一条消息即可带数据 |
| 身份保密 | IK：发起方身份对被动方保密、对响应方公开；XX 双向交互后保密 | 服务器证书明文（ESNI/ECH 另算） | 静态公钥在 IK 中被加密（对被动观察者） |
| 形式化基础 | Noise 框架有形式化分析谱系 | 多年形式化验证（如 Symbolic/ProVerif 族） | 白皮书给出证明（含 DoS cookie） |
| 库成熟度 | Rust: snow 0.10.0（曾出 CVE，见 §5）[28][29] | rustls 0.23.46（10 亿下载级）[28] | boringtun 0.7.1（Cloudflare）[28]；协议常量有权威源码 |
| FRP 场景适配 | 自定义帧最灵活 | 拿来即用、含证书/算法协商 | **VPN 语义原生**：内置 rekey 定时器、抗重放、漫游 |
| 密钥更新 | 应用层 rekey()（REKEY(k)，nonce 不清零）[8] | KeyUpdate（§4.6.3）[6] | 定时+计数双阈值自动 rekey [10] |

【建议】ChmlVPN 的隧道层：**自研 WireGuard 式 1-RTT 握手（Noise IK 结构）+ 显式 KEM 扩展**，理由：(a) 帧格式与 FRP 纯 TCP 管道天然契合（TLS 也可行但证书/会话体系对「点对等 VPN」是额外负担）；(b) 可把 KEM 槽位做成 X25519+ML-KEM-768 混合；(c) rekey/抗重放/漫游有权威参照实现常量可抄（wireguard-go [10]）。若求最快落地，**rustls over the relayed TCP stream** 也是合理选择（需接受证书或 PSK 模型）。

### 3.2 X25519、ML-KEM 与混合（2026 采用现状）

【已证实】

- **FIPS 203（ML-KEM）2024-08-13 定稿**；FIPS 204（ML-DSA）同日定稿 [12][13]。
- **RFC 10024**（2026-08，Proposed Standard）：TLS 1.3 混合组 **X25519MLKEM768（0x11EC，Recommended: Y）**、SecP256r1MLKEM768、SecP384r1MLKEM1024；废弃实验性 Kyber768 码点 [20]。
- 浏览器：Google 安全博客 2024-09-13 宣布 Chrome 131 从 Kyber 切到 ML-KEM [22]；Chrome 131 稳定版 2024-11-12 [23]。
- 服务端流量：Cloudflare 官方博客——2025-10-28「超过一半人类发起流量已 PQ 加密」[25]；2026-04-07「**over 65% of human traffic** to Cloudflare is post-quantum encrypted」，并目标 **2029 全套 PQ（含认证，ML-DSA for origin + Merkle Tree Certificates）** [24]。
- SSH：OpenSSH 10.0（2025-04-09）**默认 `mlkem768x25519-sha256`**；10.1（2025-10-06）对非 PQ 协商默认告警 [26]。
- 纯 ML-KEM TLS 组（非混合）draft-ietf-tls-mlkem-08（2026-06）已过 IETF Last Call（截至 2026-08-13）[21]（Datatracker 状态经检索核实，未逐页复核）。

【结论】X25519+ML-KEM-768 混合在 2026 年已是「新协议的默认答案」：标准成文（RFC 10024）、浏览器/CDN/SSH 三侧主流化、纯 Rust 实现可用（ml-kem 0.3.3，FIPS 203，2026-10-17 更新 [28]）。本机实测 ML-KEM-768 keypair 0.022ms、encaps+decaps 0.043ms【实测(本机)】——握手成本可忽略。

### 3.3 对 showroom RSA-3072-OAEP 封装的明确评价

**评级：替换（数据面长期方案）；短期可保留但要冻结纪律。**

理由（每条均一级来源）：

1. **无前向保密**：RSA-OAEP 封装的 k 可被持有平台私钥者在未来任意时刻解开（信封是「存起来等私钥」的典型形态）；X25519/ML-KEM 一次性临时份额天然给一次性信封前向保密 [12][20]。showroom 的 EtM 与「k 一次性」缓解的是 nonce 复用，不是前向保密。
2. **性能与尺寸**：RSA-3072 封装头定长 384B、OAEP 加解密为百微秒~毫秒级；X25519+ML-KEM-768 混合密文约 32+1184B、总成本 <0.1ms【实测(本机)：ML-KEM-768 全程 0.065ms；X25519 更低】。RSA-3072 也不再符合「2048 不够、4096 太贵」之外的任何新部署叙事（NIST SP 800-57 将 2048 位 RSA 退役时间定在 2030 [37]，3072 位仅延至 2035 档）。
3. **「加档」选项（若必须保留 RSA 兼容）**：封装改为 `RSA-OAEP(wrap) ⊕ KEM 混合`，即同时做 RSA-OAEP 与 X25519+ML-KEM-768，两者共享封装密钥派生（TLS 混合思想 [20]）。只在「已有 RSA 分发链路无法立刻更换」时值得做。
4. **多主多活复制视角**【推测，基于 ask 给出的架构】：RSA 信封按「平台公钥」封装意味着各服务端需共享平台私钥或做密文重封装；KEM 临时份额模型（每信封新 ephemeral）与逐服务器独立密钥/逐次重封装更自然，也更容易把「哪个服务端能解」做成权限点。

**showroom 现状定性**：其信封目标本来就是「一次性、E2E、验签先行」，RSA-OAEP+一次性 k 在该语义下**没有已知实际攻击面**（security.md:133 亦如此声明 [1]）；问题是性能、头尺寸、与 PQ 时代差距，以及前向保密缺失。故评级为「替换」而非「漏洞」。

---

## 4. Q3 用户认证

### 4.1 OPAQUE 与 opaque-ke

【已证实】

- OPAQUE 正式编号为 **RFC 9807**（2025-07，Informational，IRTF/CFRG）[4]；RFC 9380 是 H2C [3]（showroom 注释需更正）。
- RFC 9807 §7 推荐（RECOMMENDED）配置**第一位仍是 ristretto255-SHA512**（HKDF-SHA-512/HMAC-SHA-512/SHA-512/ristretto255），另两列为 P-256 组合；群用于 3DH 且「SHOULD 与 OPRF 群一致」；128-bit 安全目标 [4]。
- ristretto255 本体：RFC 9496（Informational，2023）**未被废弃**，新草案（2025-2026）仍在引用 ristretto255 [5]；OPRF 的 ristretto255 组亦标准化（RFC 9497）[5]。
- opaque-ke crate：仓库现为 `github.com/facebook/opaque-ke`（自 novifinancial 迁移）；版本线 3.0.0（2024-10-10）→ **4.0.1（2025-11-03，最新稳定）** → 4.1.0-pre.2（2026-03-27）；3.0.0+ 许可 Apache-2.0 OR MIT [28]。**维护活跃，showroom 用的 3.0.0 落后一个大版本。**
- PQ-PAKE 现状：**尚无标准化 PQ OPAQUE**；CFRG 在讨论 draft-vos-cfrg-pqpake（OQUAKE/CPaceOQUAKE+，2026-10 仍在更新）与 ML-KEM-to-PAKE 编译器路线（Tempo 等）[38]。⇒ 认证层继续经典 OPAQUE、把 PQ 放到隧道层混合 KEM 是 2026 的正确分工【建议】。

【对 showroom 的评价】

- Suite 选 ristretto255 + TripleDH + Identity KSF：与 RFC 9807 推荐一致（Identity KSF 合法——KSF「由应用决定」，且 RFC 明说拉伸在客户端执行 [4]）。
- **argon2id 参数差**：RFC 9807 推荐 Argon2id KSF 参数 m=2^21（2 GiB）、t=1、p=4；showroom 外部硬化 m=19456 KiB（19 MiB）、t=2、p=1（OWASP 档）。两者取舍是「低配客户端可承受性 vs 离线字典成本」；RFC 参数重 100 倍内存，WebAssembly/低端设备不友好。showroom 的外部硬化+常数盐+用户名进盐设计在 RFC 语义内（常数盐被明确允许——盲化已提供保护 [4]，showroom 注释同义），**可保留但建议把参数做成可升级的版本化 profile**【建议】。

### 4.2 Ed25519 vs ML-DSA

【已证实】

- **Ed25519 是 FIPS 186-5（2023-02-03）批准算法**（EdDSA/Ed25519/Ed448 首次入标；DSA 移除）[14]。合规性不再是选 ML-DSA 的理由。
- ML-DSA = FIPS 204（2024-08-13 定稿；官方页 2026-07-31 备注存在待修订小问题）[13]。
- Rust 生态：**ed25519-dalek 3.0.0**（2026-07-06，BSD-3-Clause）[28]；**ml-dsa 0.1.1**（2026-06-05，RustCrypto，纯 Rust，FIPS 204 final，标注「从未被独立审计」）[28]。本机实测 Ed25519 sign 13μs / verify 24μs（1KiB）【实测(本机)】。

【取舍建议】

- 设备/用户密钥签名（showroom SR-SIG1 同类）：**Ed25519 为主**——成熟、小签名、秒级验签吞吐；SR-SIG1 的「user 名下多公钥任一命中」与 kid=sha256(pub)[0..8hex] 设计可直接沿用。
- 若要「抗Harvest-now-Decrypt-later + 未来不可抵赖」加档：在密钥档案里**并行加入 ML-DSA-65 公钥**（双签或按 kid 类型分派），成本是签名变 ~3.3KB。Cloudflare 路线图（origin 方向 2026 年中 ML-DSA [24]）说明服务器侧签名 PQ 化正在发生，但用户设备密钥签名并非紧迫项。
- ML-DSA crate 官方自述未经审计 [28]，用于生产签名密钥档案前建议关注其审计进展或以 libcrux（形式化验证，Apache-2.0-only，0.0.6，2026-10-07）[28] 备选。

---

## 5. Q4 Rust 生态推荐组合（版本/许可/维护均经 crates.io API 核实）

| 用途 | crate | 最新稳定版（日期） | 许可 | 备注 |
|---|---|---|---|---|
| AEAD (AES-GCM) | aes-gcm | 0.11.1（2026-08-21）[28] | Apache-2.0 OR MIT | 新代（aes 0.9 内核，VAES）；showroom 现用 0.10.3 |
| AEAD (ChaCha/XChaCha) | chacha20poly1305 | 0.11.0（2026-06-28）[28] | Apache-2.0 OR MIT | XChaCha 规范草案已死 [34]，实现事实标准 |
| AEAD 抗误用 | aes-gcm-siv | 0.12.1（2026-08-21）[28] | MIT OR Apache-2.0 | RFC 8452；本机最快【实测】 |
| KEM (PQ) | ml-kem | 0.3.3（2026-10-17）[28] | Apache-2.0 OR MIT | 纯 Rust，FIPS 203；自述未审计 |
| 签名 (经典) | ed25519-dalek | 3.0.0（2026-07-06）[28] | BSD-3-Clause | |
| DH | x25519-dalek | 3.0.0（2026-07-06）[28] | BSD-3-Clause | |
| PAKE | opaque-ke | 4.0.1（2025-11-03）[28] | Apache-2.0 OR MIT | 3.0.0 之后许可由 MIT 变双许可 |
| Noise | snow | 0.10.0（2025-07-19）[28] | Apache-2.0 OR MIT | **RUSTSEC-2024-0011 / CVE-2024-58265（未认证 nonce 递增，可致 DoS），0.9.5 修复** [29]；用则必上 ≥0.10 |
| TLS 1.3 | rustls | 0.23.46（2026-10-14）[28][31] | Apache-2.0 OR ISC OR MIT | 默认 provider = aws-lc-rs，可切 ring |
| 加密绑定库 | aws-lc-rs | 1.19.0（2026-10-28）[28] | ISC AND (Apache-2.0 OR ISC) | 非 FIPS 构建无需 cmake/bindgen/Go；Windows x64 需 NASM 或 prebuilt-nasm 特性；FIPS 特性另算 [32] |
| 加密绑定库 | ring | 0.17.14（2025-03-11）[28] | Apache-2.0 AND ISC | 发布节奏慢（稳定版间隔 >19 个月）；历史维护瓶颈是 rustls 换默认的动因之一 |
| PQ 备选 | libcrux | 0.0.6（2026-10-07）[28] | Apache-2.0（仅） | 形式化验证（hax/F*） |
| WireGuard 参照 | boringtun | 0.7.1（2026-05-01）[28] | BSD-3-Clause | Cloudflare |
| RNG | rand | 0.10.3（2026-09-20）；0.9.5 存在 [28] | MIT OR Apache-2.0 | showroom 钉 rand 0.8.8；生态仍并行维护 0.8.x（0.8.8 发布于 2026-08-25），API 与 0.9/0.10 有代差——ask 的提醒成立 |
| PQ 研究库 | liboqs | — | MIT | **官方 README 明示「不建议在生产环境依赖」** [33] ⇒ ChmlVPN 不应引入 |
| 口令硬化 | argon2 | 0.5.3（showroom 同款线）[1] | MIT OR Apache-2.0 | |

**供应链与许可要点**：

1. **纯 Rust vs 绑定**：RustCrypto（aes-gcm/chacha20poly1305/ml-kem/ml-dsa/argon2/sha2）无 C 构建依赖，Windows/macOS/Linux/iOS/Android/wasm32 全目标可交叉（showroom 的 wasm32 custom getrandom 桥即证明此路线可行 [1]）。aws-lc-rs 性能/合规强但引入 C 工具链（Windows NASM 等）[32]，移动端交叉编译成本更高。ring 居中但慢发布 [28]。
2. **许可**：ring 为 `Apache-2.0 AND ISC`（合取，历史上还有附加条款争议）；aws-lc-rs 为 `ISC AND (Apache-2.0 OR ISC)`；RustCrypto/dalek 系均为宽松许可（dalek 系 BSD-3-Clause）[28]。商用闭源分发均可用，注意 AND 合取需同时满足两许可义务。
3. **FIPS**：仅 aws-lc-rs 有 FIPS 路径（`fips` 特性绑定 AWS-LC-FIPS 4.x，已完成实验室验证测试并提交 NIST 认证 [32]）；RustCrypto 全系无 FIPS 认证。ChmlVPN 若无合规要求，纯 Rust 组合更轻。
4. **公告/RustSec 纪律**：snow 的 CVE [29] 提醒：任何 crypto crate 必须钉版本 + `cargo audit` 进 CI；Kyber 旧 crate 线曾出 RUSTSEC 事件，PQ 实现应只用 ml-kem/libcrux/aws-lc-rs 一线库。

---

## 6. Q5 长连接隧道：rekey、前向保密、断线重连与会话恢复

【已证实·权威常量】WireGuard（wireguard-go `device/constants.go`，MIT）[10]：

| 常量 | 值 | 含义 |
|---|---|---|
| RekeyAfterMessages | 2^60 | 发送计数达此值即主动 rekey（给 2^64 nonce 空间留巨量余量） |
| RejectAfterMessages | 2^64 − 2^13 − 1 | 超限一律拒绝（防 nonce 重用硬闸） |
| RekeyAfterTime | 120 s | 会话年龄触发 rekey（仅发起方） |
| RejectAfterTime | 180 s | 超龄会话整体拒绝、密钥清零 |
| RekeyTimeout / jitter | 5 s / 0–333 ms | 握手重试与去同步抖动 |
| KeepaliveTimeout | 10 s | 保活 |
| HandshakeInitationRate | 50/s | 握手发起限速（防 DoS） |

【已证实·规范语义】

- Noise：rekey 由应用驱动（`REKEY(k)` 单向函数更新 k，**nonce 不清零**）；抗重放是应用义务 [8]；AESGCM 单密钥 2^56 字节建议上限 [8]。
- TLS 1.3：§4.6.3 KeyUpdate 支持单向流量密钥更新；§5.5「Limits on Key Usage」给出密钥使用上限章节；resumption/PSK「新连接的安全上下文与原连接密码学绑定」，可配 (EC)DHE 以保前向保密，纯 PSK 恢复「以失去前向保密为代价」，且规范明确 PSK binder 不抗字典、外部 PSK 不得来自低熵口令 [6]。
- WireGuard：**内置漫游**——「两端全 IP 漫游」，端点变化不影响会话（按对端公钥识别）[11]；保活 10s [10]。

【对 ChmlVPN 的落地建议】

1. **rekey 策略**：采纳双阈值（2^60 包或 120s 先到先触发，180s/2^64−2^13−1 硬拒绝），实现上等价于「每方向发送计数器 + 会话起始时间」两个判断；rekey 用新握手（而非 Noise rekey()），因为 KEM 混合握手便宜（本机 ML-KEM 全程 <0.1ms【实测(本机)】）且天然带来新熵与前向保密。
2. **前向保密**：握手必含一次性 DH 份额（X25519 + ML-KEM-768）；每方向流量密钥独立派生（HKDF，发送/接收分离）；会话密钥用后即擦。
3. **断线重连**：**不做 PSK 会话恢复**——恢复会把新会话安全绑定旧会话（TLS 语义 [6]），且省下的那 0-RTT 对 VPN 无意义；重连 = 全新 1-RTT 握手 + 立即恢复按对端静态公钥索引的会话状态（漫游模型 [11]）。FRP 中转层断连时，客户端指数退避重连（RekeyTimeout 5s + 抖动 [10] 的节奏可复用）。
4. **keepalive**：10s 周期保活帧（本身也是加密帧），同时探测中转链路死活。
5. **抗重放**：见 §2.2——64-bit 计数器 + 滑动窗口 + 伪造计数断链；showroom 现有的 API 层时间窗+nonce 查重（300s/HashMap [1]）保留用于控制面，数据面另起会话级机制。

---

## 7. 截至 2026-10-31 的推荐组合（ChmlVPN）

| 层 | 推荐 | 来源 |
|---|---|---|
| 数据面 AEAD | **AES-256-GCM（aes-gcm 0.11.1，计数器 nonce）**；协商后备 XChaCha20-Poly1305（chacha20poly1305 0.11.0）；抗误用场景 AES-256-GCM-SIV（0.12.1） | RFC 8452 [2]、SP 800-38D 修订动向 [15]、C2SP XAES [16]、aead-limits 草案 [17]、本机实测 §2.3、docs.rs/aes [30] |
| 大文件信封 | 沿用 showroom 分段 AEAD 模型；段 nonce 改「一次性 k + 段计数器」或换 XChaCha/GCM-SIV；每信封 k 一次性纪律保留 | showroom 源码 [1]、C2SP [16]、RFC 8452 [2] |
| 隧道握手 | WireGuard 式 1-RTT（Noise IK 结构）+ **X25519+ML-KEM-768 混合 KEM**；常量参照 wireguard-go | RFC 10024 [20]、noise.html [8]、wireguard.com/protocol [9]、wireguard-go [10] |
| RSA-3072-OAEP | **替换**为混合 KEM 封装（或 X25519）；过渡期可加档双封装 | §3.3 论证、FIPS 203 [12]、RFC 10024 [20]、本机实测 |
| 用户认证 | OPAQUE（**RFC 9807**）+ opaque-ke **4.0.1**、ristretto255-SHA512 Suite（RFC 推荐第一位）、外部 argon2id 硬化保留并参数版本化 | RFC 9807 [4]、RFC 9496 [5]、crates.io [28] |
| 设备/请求签名 | **Ed25519**（ed25519-dalek 3.0.0，FIPS 186-5 批准）为主；可选并行 ML-DSA-65（ml-dsa 0.1.1）作 PQ 加档 | FIPS 186-5 公告 [14]、FIPS 204 [13]、crates.io [28] |
| RNG | 新代码用 rand 0.9/0.10 + getrandom 新栈；沿用 showroom 0.8.8 则注意生态代差并锁 -O3 | crates.io [28]、showroom [1] |
| TLS（如需） | rustls 0.23.x（默认 aws-lc-rs；要纯 Rust 构建链则评估 ring provider 或最小化依赖） | docs.rs/rustls [31]、aws-lc-rs README [32]、crates.io [28] |
| 不采用 | liboqs（官方不建议生产 [33]）；GCM 随机 96-bit nonce 长会话（ePrint 2024/1111 主张禁止 [35]，38D 修订中 [15]）；GCM-SST/OGCM/AEGIS（未标准化 [18][19]） | 同左 |
| rekey/重放/重连 | 2^60 包或 120s 双阈值 rekey；180s/2^64−2^13−1 硬拒绝；64-bit 计数器+滑动窗口；重连=新握手+公钥索引漫游；10s keepalive | wireguard-go [10]、noise.html [8]、RFC 8446 [6]、wireguard.com [11] |

---

## 8. gaps（未能查证/未能直接核验，如实列出）

1. **NIST SP 800-38D 原文 PDF 未直接解析**（工具不支持 PDF）：2^32 随机 nonce 上限与 2^39−256 分组上限经 C2SP [16]、ePrint 2024/1111 [35]、NIST 修订公告 [15] 转引，未逐字比对原文。
2. **Cloudflare Radar 比例页 403**：未取到 2026-10 当月精确比例曲线；采用官方博客口径（2026-04「>65%」[24]）。检索摘要中「2026-08 ~70%」（shattered.io）未采信为一级来源。
3. **snow 0.10.0（2025-07-19）之后的仓库提交活跃度**未核验（仅 crates.io 发布事实与已修 CVE）。
4. **aws-lc-rs 平台矩阵页面**（aws.github.io/aws-lc-rs/platforms.html）返回 404：iOS/Android 各 target 逐项支持情况未核实，报告只引用其 README 定性说明 [32]。
5. **draft-ietf-tls-mlkem-08 的 Last Call 状态**（2026-08-13 截止）来自检索摘要，未在 Datatracker 逐页复核。
6. 移动端（iOS/Android）上 ml-kem/opaque-ke 等纯 Rust crate 的实测未做（纯 Rust 无 C 依赖推断可交叉，未验证）。
7. ML-KEM 侧信道防护等级（ml-kem crate 是否恒时实现）未独立核验；其文档自述「从未被独立审计」[28]。

---

## 参考文献

[1] showroom 本地源码与文档：`E:\Works\showroom`（showroom-common/src/lib.rs、opaque.rs、wasm_shim.rs；showroomctl/src/serve.rs；docs/security.md；Cargo.toml/Cargo.lock；SPEC.md）——本次调研直接读取。
[2] RFC 8452 "Synthetic IV (SIV) Ciphersuites for CEK/AES-GCM… (AES-GCM-SIV)"，RFC-Editor 信息页与附录 B 成本模型（「decryption … only about 5% slower … encryption … two-thirds」）：https://www.rfc-editor.org/info/rfc8452
[3] RFC 9380 "Hashing to Elliptic Curves"（非 OPAQUE）：https://www.rfc-editor.org/info/rfc9380
[4] RFC 9807 "The OPAQUE Augmented PAKE (aPAKE) Protocol"（2025-07，Informational/IRTF；§7 推荐配置与 KSF 语义）：https://datatracker.ietf.org/doc/rfc9807/
[5] RFC 9496 "The ristretto255 and decaf448 Groups"（Informational，2023）：https://www.rfc-editor.org/info/rfc9496 ；ristretto255 仍被新草案引用之现状见 §4.1 检索（Datatracker/邮件列表）。
[6] RFC 8446 "The Transport Layer Security (TLS) Protocol Version 1.3"（§2.2 PSK/恢复引文、ToC 确认 §4.6.3 KeyUpdate 与 §5.5 Limits on Key Usage）：https://www.rfc-editor.org/rfc/rfc8446.html
[7] RFC 8439（ChaCha20-Poly1305；WireGuard 协议页以其前身 RFC 7539 语法引用）。
[8] Noise Protocol Framework（§11.3 Rekey、§11.4 乱序与重放、AESGCM 2^56 字节建议）：https://noiseprotocol.org/noise.html
[9] WireGuard 协议页（Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s、nonce=32bit 零+64bit LE 计数器、抗重放窗口~2000、cookie 机制）：https://www.wireguard.com/protocol/
[10] wireguard-go 源码 `device/constants.go`（RekeyAfterMessages=2^60 等，MIT）：https://raw.githubusercontent.com/WireGuard/wireguard-go/master/device/constants.go
[11] WireGuard 官网（Built-in Roaming：两端全 IP 漫游）：https://www.wireguard.com/
[12] NIST FIPS 203 (ML-KEM) Final，2024-08-13：https://csrc.nist.gov/pubs/fips/203/final
[13] NIST FIPS 204 (ML-DSA) Final，2024-08-13：https://csrc.nist.gov/pubs/fips/204/final
[14] NIST FIPS 186-5（2023-02-03，首次批准 EdDSA/Ed25519/Ed448、移除 DSA）：https://csrc.nist.gov/pubs/fips/186-5/final 与公告 https://csrc.nist.gov/news/2023/nist-releases-fips-186-5-and-sp-800-186
[15] NIST SP 800-38D Rev.1 修订流程（2025-01-06 预草案征求意见、第二次初步草案）：https://csrc.nist.gov/pubs/sp/800/38/d/r1/iprd ；https://csrc.nist.gov/news/2025/pre-draft-call-for-comments-on-gcm-and-gmac
[16] C2SP "XAES-256-GCM"（扩展 nonce GCM 构造、2^80 消息界、GCM 随机 nonce 2^32 限制之动机）：https://c2sp.org/XAES-256-GCM
[17] draft-irtf-cfrg-aead-limits-13 "Usage Limits on AEAD Algorithms"（未成 RFC；AES-GCM 96-bit IV ≈2^47.5 消息等）：https://datatracker.ietf.org/doc/draft-irtf-cfrg-aead-limits/
[18] draft-mattsson-cfrg-aes-gcm-sst（GCM-SST，个人草案 -21，2026-07）：https://datatracker.ietf.org/doc/draft-mattsson-cfrg-aes-gcm-sst/ （检索定位）
[19] T. Iwata, Y. Seurin，OGCM-1/OGCM-2 出处 "Reconsidering the Security Bound of GCM"（学术，未标准化）：https://www.semanticscholar.org/paper/3561ee7443245dc59b741660cd48c8e90d571351
[20] RFC 10024 "Hybrid Key Exchange in TLS 1.3"（2026-08，X25519MLKEM768=0x11EC 等，经 draft-ietf-tls-ecdhe-mlkem Datatracker 页核实）：https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
[21] draft-ietf-tls-mlkem-08（2026-06，纯 ML-KEM TLS 组）：Datatracker（检索核实）。
[22] Google Security Blog "A new path for Kyber on the web"（2024-09-13，Chrome 131 切 ML-KEM）：https://security.googleblog.com/2024/09/a-new-path-for-kyber-on-web.html
[23] Chrome 131 Release Notes（稳定版 2024-11-12）：https://developer.chrome.com/release-notes/131
[24] Cloudflare Blog "Cloudflare targets 2029 for full post-quantum security"（2026-04-07，"over 65% of human traffic"、ML-DSA for origin by mid-2026）：https://blog.cloudflare.com/post-quantum-roadmap
[25] Cloudflare Blog "State of the post-quantum Internet in 2025"（2025-10-28，"over half of human-initiated traffic"）：https://blog.cloudflare.com/pq-2025
[26] OpenSSH Release Notes（10.0 2025-04-09 默认 mlkem768x25519-sha256；10.1 2025-10-06 非 PQ 告警）：https://www.openssh.org/releasenotes.html
[27] OpenSSL 3.1 CHANGES（3.1.0 2023-03-14："AES-GCM enabled with AVX512 vAES and vPCLMULQDQ"）：https://raw.githubusercontent.com/openssl/openssl/openssl-3.1/CHANGES.md
[28] crates.io API（本次逐一核实）：opaque-ke（4.0.1/2025-11-03，3.0.0/2024-10-10，repo=facebook/opaque-ke，Apache-2.0 OR MIT）、snow（0.10.0/2025-07-19）、ring（0.17.14/2025-03-11，Apache-2.0 AND ISC）、aws-lc-rs（1.19.0/2026-10-28）、rustls（0.23.46/2026-10-14）、boringtun（0.7.1/2026-05-01，BSD-3-Clause）、libcrux（0.0.6/2026-10-07，Apache-2.0）、aes-gcm-siv（0.12.1/2026-08-21）、ml-kem（0.3.3/2026-10-17）、ml-dsa（0.1.1/2026-06-05）、aes-gcm（0.11.1/2026-08-21）、chacha20poly1305（0.11.0/2026-06-28）、ed25519-dalek（3.0.0/2026-07-06，BSD-3-Clause）、x25519-dalek（3.0.0/2026-07-06）、rand（0.10.3/2026-09-20，0.9.5 存在）。各 crate 对应 https://crates.io/api/v1/crates/<name>
[29] RustSec RUSTSEC-2024-0011 "Unauthenticated Nonce Increment in snow"（CVE-2024-58265，0.9.5 修复，仅影响有状态 TransportState）：https://rustsec.org/advisories/RUSTSEC-2024-0011.html
[30] docs.rs/aes：[30a] 0.8.4（仅 AES-NI/ARMv8）https://docs.rs/aes/0.8.4/aes/ ；[30b] 0.9.3（运行时探测 "AES-NI and VAES"，aarch64 ARMv8 CE）：https://docs.rs/aes/0.9.3/aes/
[31] docs.rs/rustls 0.23.46（"by default it uses aws-lc-rs"，ring 可切）：https://docs.rs/rustls/0.23.46/rustls/
[32] aws-lc-rs 仓库 README（非 FIPS：cmake/bindgen/Go 从不需要；Windows 需 NASM 或 prebuilt-nasm；FIPS 绑定 AWS-LC-FIPS 4.x 已交 NIST 认证）：https://github.com/aws/aws-lc-rs （raw README，本次读取）
[33] liboqs README（"WE DO NOT CURRENTLY RECOMMEND RELYING ON THIS LIBRARY IN A PRODUCTION ENVIRONMENT"，MIT）：https://raw.githubusercontent.com/open-quantum-safe/liboqs/main/README.md
[34] draft-irtf-cfrg-xchacha-03（Expired / Dead IRTF Document，2020-01-10）：https://datatracker.ietf.org/doc/draft-irtf-cfrg-xchacha/
[35] Mattsson 等 ePrint 2024/1111（碰撞攻击与「禁止 GCM 随机 96-bit nonce」主张）：https://eprint.iacr.org/2024/1111.pdf
[36] RFC 9513 实为 "OSPFv3 Extensions for SRv6"（Datatracker 核对，辟谣 AEAD 限额谣传）：https://datatracker.ietf.org/doc/rfc9513/
[37] NIST SP 800-57 Part 1 Rev.5（RSA-2048 2030 退役档；3072 至 2035 档）——标准条目，本次未逐页复核（标记为常识级引用，未直接读取）。
[38] draft-vos-cfrg-pqpake（OQUAKE/CPaceOQUAKE+，PQ-PAKE 现状）：https://datatracker.ietf.org/doc/draft-vos-cfrg-pqpake

---

## 附录 A：本机基准（实测(本机)）

- 机器：Intel Core Ultra 9 285HX，96GB RAM，Windows 11；Rust 1.98.1。
- 工程：`E:\Works\ChmlVPN\.tmp\cryptobench`（临时基准工程，非交付物），`cargo build --release`（opt-level=3, LTO, codegen-units=1）。
- 依赖（cargo tree 核对）：aes-gcm 0.10.3→aes 0.8.4；chacha20poly1305 0.10.x；aes-gcm-siv 0.12.1→aes 0.9.3；ed25519-dalek 2.x；ml-kem 0.3.x。
- 命令：`./target/release/cryptobench.exe`（两次运行，取值区间已并入 §2.3 表）。
- 原始输出（第一次）：

```
CPU feature detect: aes=true pclmulqdq=true avx2=true avx512f=false
AES-256-GCM              4MiB段: 2.23 GB/s  (1.9 ms/段)
AES-256-GCM              64KiB包: 2.25 GB/s  (29.09 us/包)
ChaCha20-Poly1305        4MiB段: 2.29 GB/s  (1.8 ms/段)
ChaCha20-Poly1305        64KiB包: 2.23 GB/s  (29.43 us/包)
XChaCha20-Poly1305       64KiB包: 2.30 GB/s  (28.49 us/包)
AES-256-GCM-SIV          4MiB段: 5.20 GB/s  (0.8 ms/段)
AES-256-GCM-SIV          64KiB包: 5.28 GB/s  (12.41 us/包)
Ed25519 sign 1KiB: 13.0 us  verify: 23.8 us
ML-KEM-768: keypair 0.022 ms  encaps+decaps 0.043 ms
```

- 说明：单线程、固定 nonce（测 AEAD 本体）、就地加密（detached API）避免拷贝；数值为吞吐测量用途，非恒时安全审计。
