# Showroom 协议层裁定（Verdict）：截至 2026-10-31 是否行业最佳

- 评估人：架构评审官（动态工作流子代理）
- 裁定日期：2026-10-31
- 输入材料（本次全部通读）：
  `docs/research/showroom-analysis.md`、`docs/research/crypto-2026.md`、
  `docs/research/compression-2026.md`、`docs/research/vpn-mesh-2026.md`、`docs/research/frp-compat.md`
- 评估对象：`E:\Works\showroom` 的 `showroom-common`（SR-SIG1 + 加密信封 v1 + OPAQUE）
  及其调用方约定，作为 ChmlVPN 协议库候选底子。
- 场景区分（裁定前提）：showroom = 文件/请求传输（短生命周期信封、一次性密钥、
  HTTP 请求响应语义）；ChmlVPN = 长寿命隧道（大量小包 + 高吞吐混合、单条 FRP TCP、
  多主多活）。VPN 侧新增面（tun、多主多活）不参与 adopt/upgrade/hedge 判定，
  但必须进升级清单（协议库要为它们提供接口）。

---

## 0. 本次亲自执行的源码抽查（裁定证据基线）

以下各项在本次评估中直接读取 `E:\Works\showroom` 源码核实，与 showroom-analysis.md
的描述**全部一致**：

| 论断 | 核实位置（本次读取） |
|---|---|
| `SIG_WINDOW_SECS=300`；`KEY_LEN=32`/`NONCE_LEN=12`/`TAG_LEN=16`/`SEG=4MiB`/`WRAP_LEN=384` | showroom-common/src/lib.rs:48-55 |
| `nonce_hex()` = 16 随机字节 → 32 hex 字符（实现强于文档的"8 随机字节"） | lib.rs:75-79 |
| SR-SIG1 canonical 串七字段 + Ed25519 签名 + base64url 无 pad | lib.rs:221-261 |
| 验签：格式 → ±300s 窗口 → user 名下公钥逐一试签 | lib.rs:289-340 |
| 信封：一次性随机 32B k → RSA-3072-OAEP-SHA256 封装、强制 384B 头 | lib.rs:383-394 |
| 每段：新随机 12B nonce + AES-256-GCM，**无 AAD、无段序号** | lib.rs:396-411（encrypt 调用仅 nonce+明文） |
| 解封流式、错误不 panic、段边界干净 EOF | lib.rs:416-461 |
| OPAQUE Suite = Ristretto255(OPRF+KE) + TripleDH + Identity KSF | showroom-common/src/opaque.rs:32-39 |
| argon2id m=19456KiB/t=2/p=1，盐 = `b"showroom-opaque-v1"+user` | opaque.rs:53-70 |
| **opaque.rs:1 注释误写「RFC 9380」**（OPAQUE 实为 RFC 9807；9380 是 H2C）——crypto-2026.md §1 的发现属实 | opaque.rs:1（本次目视确认） |
| nonce 查重：`HashMap<"user:nonce", 过期时刻>` + 惰性 retain 清理 + 重启清零；bind_token 60s 单次 | showroomctl/src/serve.rs:34-44（AppState）、serve.rs:913-922（nonce_fresh）、serve.rs:924-951（auth） |
| zstd 固定 level 19（上行 docker save / 下行 pg_dump） | showroom/src/main.rs:318、showroomctl/src/dbmaint.rs:158 |
| 魔数自适应解包（zstd `28 B5 2F FD`） | showroomctl/src/unpack.rs:15 |
| ndjson 30s 心跳 `{"hb":true}` | showroomctl/src/streams.rs:28、68-69 |
| dump 分片 ≤4MiB（`DUMP_CHUNK_MAX = 4<<20`） | dbmaint.rs:155 |
| import 8MB 分片（wasm 控制台契约） | showroom-web/smoke-wizard.mjs:808-811（CHUNK8=8*1024*1024 测试佐证） |
| 依赖锁定：opaque-ke 3.0.0 / aes-gcm 0.10.3 / rsa 0.9.10 / ed25519-dalek 2.2.0 / argon2 0.5.3 / sha2 0.10.9 / rand 0.8.8 / zstd 0.13.3 / curve25519-dalek 4.1.3 | Cargo.lock（本次 grep 逐项核对） |
| **首登无信任锚边界**（复核轮新增核实）：『明文 HTTP 首登无信任锚——PAKE 只保证密码不泄露，主动 MITM 可中继 login-finish 并在 key-bind 登记自己的公钥接管账号（缓解：公网站点 B 经 Caddy TLS；LAN 不可信时用 CLI 钥匙路径）』 | E:\Works\showroom\SPEC.md:285-287（§16.2 风险边界，本次 sed 读取原文） |
| ML-KEM-768 尺寸口径（复核轮实跑）：`ML-KEM-768 sizes: ek=1184B ct=1088B dk=64B \| hybrid X25519+ML-KEM-768: key-share=32+1184=1216B, ciphertext=32+1088=1120B`。**口径注记（三轮复核补）**：`dk=64B` 是 ml-kem 0.3.x `KeyExport::to_bytes()` 返回的**种子序列化形态**（Seed=d‖z，恒 64B），非 FIPS 203 完整解封装密钥长度（ML-KEM-768 dkLen=**2400B**）；本报告无任何结论引用 dk 尺寸，ek/ct 两值即 FIPS 203 参数组 | 本次执行 `cd .tmp/cryptobench && cargo run --release`（ml-kem 0.3.3，新增 size-check 代码）；种子语义经本地 registry 源码核实：ml-kem-0.3.3/src/decapsulation_key.rs:231-233（`fn to_bytes(&self) -> Seed`）与 :243-245（种子恒 64B、展开形态 ML-KEM-768=2400B）；同轮复跑的性能输出见 §3.3/§3.7 |

本次**未复跑**的检查（如实声明）：compression-2026.md §2 的压缩实测为前期调研在同一台
机器上执行，本次仅引用其数据未复现。crypto-2026.md 附录 A 的密码学基准在**复核轮已复跑**
（cryptobench，输出与原报告一致：旧内核 AES-GCM 2.21–2.29 GB/s、GCM-SIV 5.09–5.27 GB/s、
Ed25519 13.3/22.7μs、ML-KEM-768 keypair 0.022ms / encap+decap 0.044ms）。
streams.rs 的逐行实现、serve.rs 的 kid 派生细节未逐行复核，按报告采信（关键常量已抽查）。

---

## 1. 总判断

**整体不可视为截至 2026-10-31 的行业最佳（overallKeep = false）。**

showroom 协议层是 2024 年前后水准的**优秀经典密码学工程**：认证（OPAQUE）与请求签名
（Ed25519）两维的算法选型即使放到今天也是行业第一梯队，可直接沿用；工程纪律
（流式恒定内存、EtM、防枚举、0600 落盘、wasm 同栈向量测试）扎实。但整体落后在五点：

1. **密钥封装是上个时代的答案**：RSA-3072-OAEP 无前向保密、无后量子路径、运算贵；
   2026 年新协议的默认答案是 X25519+ML-KEM-768 混合（RFC 10024）。
2. **后量子就绪为零**：全栈无任何 PQ 元素。对 showroom 自己的「存起来等私钥」型备份
   信封，harvest-now-decrypt-later 威胁尤其成立。
3. **控制面信任引导缺失（复核轮补入）**：明文链路首登无信任锚，主动 MITM 可中继
   login-finish 并经 bind_token 登记自己的公钥接管账号（SPEC.md:285-287 本次核实）；
   现有缓解仅为部署层（前置 TLS / 换 CI 钥匙路径），无协议层机制。对 VPN——账号
   接管 ≈ 网络接入接管——这是必须协议层解决的维度。
4. **依赖代际落后且性能白丢**：aes-gcm 0.10.3 走 aes 0.8.4 旧内核（新代 0.11/VAES
   实测 ~2.3×，复核轮复跑确认）；opaque-ke 3.0.0 落后一个大版本（4.0.1）；
   ed25519-dalek 2.2.0（3.0.0 已发布）；rand 0.8.8（生态已并行 0.9/0.10）。
5. **缺传输帧/多路复用层与压缩策略档位**：showroom 依托 HTTP 语义，没有自己的帧与流；
   压缩只有单一 zstd-19 批量档——这两项对 VPN 长寿命隧道是必须新建的面，且压缩直接
   搬用会有 VORACLE 一族侧信道风险。

---

## 2. 逐维度裁定表

| # | 维度 | showroom 现状 | 截至 2026-10-31 行业最佳 | 判定 |
|---|---|---|---|---|
| 1 | 用户认证（OPAQUE） | OPAQUE ristretto255-SHA512 + TripleDH + Identity KSF + 外部 argon2id(19MiB/t2/p1)；opaque-ke 3.0.0 | 同协议同套件；实现升 opaque-ke 4.0.1；PQ-PAKE 尚无标准 | **adopt** |
| 2 | 请求签名（SR-SIG1/Ed25519） | Ed25519 canonical 签名 + 预哈希流式；ed25519-dalek 2.2.0 | Ed25519（FIPS 186-5 批准）仍为主流；dalek 3.0.0；ML-DSA 仅可选加档 | **adopt** |
| 3 | 信封密钥封装（RSA-3072-OAEP） | RSA-3072-OAEP-SHA256 封一次性 32B k，384B 定长头 | X25519+ML-KEM-768 混合（RFC 10024；Chrome/OpenSSH/Cloudflare 已主流化） | **upgrade** |
| 4 | 对称加密与流式分段（AES-256-GCM/4MiB 段） | AES-256-GCM，每段随机 96-bit nonce、无 AAD、一次性 k；aes-gcm 0.10.3（aes 0.8 旧内核） | 算法不变；计数器 nonce 纪律（长会话）+ 段序号 AAD + aes-gcm 0.11 新内核 + XChaCha/GCM-SIV 后备档 | **hedge** |
| 5 | 压缩（zstd） | zstd 固定 level 19，先压后密，魔数路由解包 | zstd 分档（直通/字典/分块流）+ 非膨胀回退 + 默认关按策略开（VORACLE） | **hedge** |
| 6 | 抗重放与会话管理 | ±300s 窗 + per-user nonce 内存查重 + bind_token 60s + EtM；无会话/rekey/keepalive | 控制面沿用；数据面 64-bit 计数器 + 滑动窗口 + 双阈值 rekey + keepalive（WireGuard 常量） | **hedge** |
| 7 | 后量子就绪 | 零（RSA/Ed25519/OPAQUE 全经典） | 传输层 X25519+ML-KEM-768 混合为默认；签名 ML-DSA-65 可选加档 | **upgrade** |
| 8 | 传输帧与多路复用 | 无自有帧/复用层（HTTP + ndjson + 分片端点；30s JSON 心跳） | 单条 TCP 上：长度前缀帧 + yamux（rust-yamux 0.14.1）承载于 E2E 会话之上；显式 EOF 帧 | **upgrade** |
| 9 | 首登信任锚/控制面 MITM（复核轮补入） | 明文 HTTP 首登无信任锚：MITM 可中继 login-finish 抢用 bind_token 登记自己公钥接管账号（SPEC.md:285-287） | 协议层信任引导：TOFU+公钥指纹钉扎、带外预置凭证/邀请制、或服务端长期身份密钥进 OPAQUE/握手并由客户端钉扎（RFC 9807 的 aPAKE 模型要求客户端持有已认证服务端身份） | **upgrade** |

---

## 3. 逐维度详述（证据 + 理由 + 动作）

### 3.1 用户认证（OPAQUE）——adopt

**现状**（本次核实：opaque.rs:32-39、42、53-70）：OPAQUE，Suite =
Ristretto255（OPRF 群 + KE 群）+ TripleDH + Identity KSF；口令硬化外置 argon2id
m=19456KiB/t=2/p=1（OWASP 档），盐 = 常数前缀 + 用户名；未知用户走 dummy 假记录防枚举。
依赖 opaque-ke 3.0.0（Cargo.lock 本次核对）。注释误引 RFC 9380（opaque.rs:1，本次目视确认）。

**行业最佳**（crypto-2026.md §4.1，来源 [4][5][28]）：OPAQUE 正式编号 **RFC 9807**
（2025-07）；其 §7 推荐配置**第一位仍是 ristretto255-SHA512**——showroom 的套件选择与
RFC 推荐一致，ristretto255 未废弃（RFC 9496 仍被新草案引用）。PQ-PAKE 尚无标准化实现
（draft-vos-cfrg-pqpake 仍在讨论），因此「认证层经典 OPAQUE + 隧道层混合 KEM」就是
2026 年的正确分工——不存在比 OPAQUE 更先进的可落地替代。实现侧最新稳定为
opaque-ke **4.0.1**（2025-11-03），showroom 落后一个大版本。

**理由**：算法/套件/防枚举设计=行业最佳，无更优选项可换；差距只在 crate 版本、
RFC 引用笔误与 argon2 参数档位，均属升级清单项而非改选算法。
**动作**：升 opaque-ke 4.0.1（注意 API 代际回归测试，固定向量测试是守门员）；
修正 RFC 引用；argon2 参数做成可升级的版本化 profile（RFC 9807 档 m=2GiB/t=1/p=4
作为高配档，WebAssembly/低端设备保留 OWASP 档）。

### 3.2 请求签名（SR-SIG1/Ed25519）——adopt

**现状**（本次核实：lib.rs:221-261、289-340）：canonical 七字段
`SR-SIG1\nuser\nts\nnonce\nMETHOD\npath_with_query\nsha256(body)`，Ed25519 签名，
base64url 无 pad；大文件流式预哈希签名（sign_prehashed）；多公钥任一命中 + kid 定位。
ed25519-dalek 2.2.0（Cargo.lock 本次核对）。

**行业最佳**（crypto-2026.md §4.2，来源 [13][14][28]）：Ed25519 是 **FIPS 186-5 批准
算法**（2023-02），合规性不再构成换 ML-DSA 的理由；请求级非对称签名（对比 AWS SigV4
的 HMAC 对称方案）配多设备公钥档案 + kid 吊销，就是设备/用户请求认证的主流最佳形态。
新代码用 ed25519-dalek 3.0.0（2026-07-06）。ML-DSA-65（FIPS 204）只是「未来不可抵赖 +
抗收割」的可选并行档，不是必选——签名密钥档案的 PQ 化在业界尚不紧迫（Cloudflare
origin 侧 ML-DSA 也才 2026 年中路线图）。

**理由**：算法与协议设计达行业水准且无短板；升级项（dalek 3.0.0、可选 ML-DSA 并行
公钥）不改变「已是最佳」的定性。
**动作**：升 ed25519-dalek 3.0.0；密钥档案预留 kid→算法类型分派，为 ML-DSA-65 并行
公钥留位（PQ 维度统一处理）。

### 3.3 信封密钥封装（RSA-3072-OAEP）——upgrade

**现状**（本次核实：lib.rs:383-394、347-349）：每信封一次性随机 32B AES 密钥，用平台
RSA-3072 公钥以 OAEP-SHA256 封装，强制 384B 定长头；平台 RSA 常驻不轮换（泄露才换）。

**行业最佳**（crypto-2026.md §3.2/§3.3，来源 [12][20][22]-[26][37]）：
**X25519 + ML-KEM-768 混合 KEM** 已是 2026 年新协议的默认答案——RFC 10024
（2026-08，Proposed Standard）定型 TLS 混合组 X25519MLKEM768；Chrome 131 起默认；
OpenSSH 10.0 起默认 `mlkem768x25519-sha256`；Cloudflare 人类流量 PQ 占比 >65%
（2026-04）。成本可忽略——**复核轮实跑**（`.tmp/cryptobench`，ml-kem 0.3.3，release）：
keypair 0.022ms、encap+decaps 0.044ms。尺寸口径（同轮实跑输出，FIPS 203 参数组）：
ML-KEM-768 **ek=1184B、ct=1088B** ⇒ 混合封装**密文 = 32(X25519 临时公钥)+1088 =
1120B**，接收方混合**公钥（key share）= 32+1184 = 1216B**。勘误：crypto-2026.md
§3.3 原文「混合密文约 32+1184B」把 ek（封装公钥）混进了密文口径，本报告按实跑修正。

**理由**：RSA-3072-OAEP 三重落后——①无前向保密（持平台私钥者未来任意时刻可解历史
信封，对 dump 备份这类「存起来等私钥」形态是实质弱点，EtM 与一次性 k 均不缓解此点）；
②无 PQ 路径（RSA 落在 SHC 攻击面内）；③运算贵：OAEP 加解密百微秒~毫秒级、RSA-3072
keygen 昂贵（多主多活逐服务器密钥场景更痛）。尺寸上 RSA 的 384B 头反而**小于**混合
密文 1120B——这是 RSA 唯一的尺寸优势，不构成保留理由。NIST SP 800-57 也只把
RSA-3072 排到 2035 档。这不是漏洞（一次性 k 纪律下无已知实际攻击），但作为 2026 年
的长期方案必须替换。
**动作**：封装头改为 X25519+ML-KEM-768 混合（可保留 RSA-OAEP 兼容档做过渡双封装）；
信封语义从「平台公钥收件」自然升级为「临时份额收件」，顺带获得一次性信封的前向保密。

### 3.4 对称加密与流式分段（AES-256-GCM / 4MiB 段）——hedge

**现状**（本次核实：lib.rs:396-411、51-55）：AES-256-GCM，96-bit nonce，每段独立
**随机** nonce，**无 AAD、无段序号**；密钥为每信封一次性随机 32B；段 = 4MiB 明文，
流式恒定内存（seal 一块 / open 两块 4MiB 级缓冲）。aes-gcm 0.10.3（→ aes 0.8.4 旧内核，
Cargo.lock 本次核对）。

**行业最佳**（crypto-2026.md §2，来源 [2][15]-[17][27][30] 及附录 A 实测）：
- 算法：AES-256-GCM 仍是桌面/服务器 CPU 上的首选（AES 硬件普及）——算法选择本身最佳；
  无 AES 硬件端后备 ChaCha20/XChaCha20-Poly1305，抗误用场景 AES-256-GCM-SIV（RFC 8452）。
- **nonce 纪律是分水岭**：随机 96-bit nonce 仅在「每密钥消息数 ≪ 2^32 且密钥一次性」
  时可用（SP 800-38D 随机 IV 上限，经 C2SP/ePrint 2024/1111 转引；38D Rev.1 修订中）。
  showroom 的「一次性 k + 每信封段数 = n/4MiB」恰好落在安全区内——**文件信封场景合法**；
  但长寿命 VPN 会话必须改为每方向 64-bit 严格单调计数器 nonce（WireGuard 模型）。
- **段 AAD**：标准做法是把段序号（及总长/信封 ID）绑进 AAD——showroom 缺失，意味着
  信封层本身不防段重排/段拼接（同一信封内各段独立可解）；现靠外层 SR-SIG1 全信封哈希
  （EtM，先验签后解密，security.md:84）兜底。作为通用协议库，AAD 应补。
- **实现代际**：RustCrypto 新代 aes-gcm 0.11.1（aes 0.9 内核，运行时探测 VAES）比
  showroom 所用旧代实测快 **~2.3×**（2.23 → 5.20-5.22 GB/s @4MiB 段，crypto-2026.md
  附录 A；复核轮复跑复现：2.21-2.29 → 5.09-5.27 GB/s）——零密码学风险、纯性能收益的
  第一优先升级。
- 4MiB 段本身合法（GCM 单消息上限 ~64GiB；恒定内存设计是对的）；VPN 数据面则应按
  MTU 级小包分段，文件信封才用大段。

**理由**：算法与流式架构正确且经测试（长度不变量断言），但三项改造（段 AAD、0.11 代
内核、为 VPN 另立计数器 nonce + rekey 档位）必须做——保留主体、加新档位，故 hedge。
**动作**：升 aes-gcm 0.11.1；信封 v2 加段序号 AAD（v1 兼容读）；协议库提供
「一次性 k + 随机 nonce（信封档）」与「会话密钥 + 计数器 nonce（隧道档）」两个明确
档位并文档化各自安全前提；协商后备 XChaCha20-Poly1305 与 AES-256-GCM-SIV。

### 3.5 压缩（zstd）——hedge

**现状**（本次核实：main.rs:318、dbmaint.rs:158、unpack.rs:15）：zstd 固定 level 19，
先压后密（顺序正确）；解包按魔数自适应（zstd/gzip/裸流）；common 刻意不含 zstd
（压缩管道在调用方）。仅此一档，无字典、无分块流、无非膨胀回退开关。

**行业最佳**（compression-2026.md §0/§2/§3/§6，来源 S1-S13）：
- **算法族选对了**：zstd 是大流与小包（配字典）的双料最优；brotli/snappy 出局。
  这部分 adopt。
- **但档位必须重做**（依据本机实测 + 一级来源）：①<128B 直通（实测 40B 膨胀至
  122.5%、120B 零收益；zstd #3722 固定成本主导）；②128B–1.5KB 结构化小包
  zstd level 1 + 训练字典 4–16KB（实测 120B→28–30%、1400B→9.4% 且比无字典更快）；
  ③大流 zstd -1 分块 16–64KB + 5–10ms 定时 flush（实测 64KB 块仅损 0.2pp）；
  ④非膨胀回退（RFC 3173 §2.2 MUST）+ 自适应跳过；⑤上下文复用（实测 3×）。
- **安全前提变了**：showroom 压的是自家批量载荷（docker 层、DB dump），注入面小；
  ChmlVPN 隧道承载成员全部上网流量 + FRP 中转即密文长度观察点——CRIME/BREACH/VORACLE
  三前提全部成立（compression-2026.md §3.2）。行业结论：WireGuard 完全不压缩（宁可
  16B 填充）、OpenVPN 2.5→2.6 默认禁用并计划移除。因此 VPN 数据面压缩必须
  **默认关、按策略开 + 输出填充**。

**理由**：zstd-19 单一档对 showroom 的批量场景够用且比率优先合理，但作为协议库的
压缩层既缺性能档（小包/延迟敏感）又缺安全档（策略门控/回退/填充），照搬进 VPN 会
同时输掉性能与安全。
**动作**：压缩层按上述四档重构；level 19 保留为「批量/归档」档；帧格式加压缩标志位
+ 原始长度字段（解压端预分配）；默认安全态=关闭；字典用合成模板训练并版本化分发。

### 3.6 抗重放与会话管理——hedge

**现状**（本次核实：lib.rs:48、326-328；serve.rs:34-44、913-951）：时间窗
|now−ts|≤300s + per-user nonce 查重（`HashMap<"user:nonce", 过期时刻>`，插入时惰性
清理，条目寿命=窗口期，**重启清零**——SPEC 明示可接受）；bind_token 60s 单次消费；
EtM 先验签后解密；分片导入 seq/total 服务端强制。**没有会话概念**：无 rekey、
无 keepalive（ndjson 流有 30s JSON 心跳，属 HTTP 层）、无数据面计数器。

**行业最佳**（crypto-2026.md §2.2/§6，来源 [6][8][9][10]；vpn-mesh-2026.md §5）：
- 控制面/API 面：时间窗 + nonce 查重是标准做法（与 AWS SigV4 同型且 nonce 存储更强），
  showroom 现设计可保留。
- 数据面/长寿命会话（WireGuard 常量，wireguard-go `device/constants.go`）：nonce =
  32-bit 零 + 64-bit LE 计数器；接收侧 64-bit 计数 + 滑动窗口（实现 2048）；
  rekey 双阈值 2^60 包或 120s；180s / 2^64−2^13−1 硬拒绝；10s keepalive；
  重连 = 全新握手（不做 PSK 恢复）；伪造尝试限额触发断链。
- 多主多活新增约束：nonce/会话/吊销状态跨服务端的语义需要设计（内存态重启清零在
  多活集群里等于「重启窗口全网重放面」，需共享状态或会话级机制接管）。

**理由**：showroom 单服务器场景内该设计成立且边界已被 SPEC 知悉接受；但协议库面向
长寿命隧道完全没有会话级抗重放/rekey/保活档位，VPN 场景必须新增——保留并加档，hedge。
**动作**：API 面机制原样保留；新增会话档（计数器+滑动窗口+双阈值 rekey+keepalive，
常量参照 wireguard-go）；明确多主多活下的重放状态归属（Raft 状态机或会话票据）。

### 3.7 后量子就绪——upgrade

**现状**（本次核实：Cargo.lock 无 ml-kem/ml-dsa/liboqs 等条目；封装=RSA、签名=Ed25519、
认证=OPAQUE，全经典）：**零 PQ 元素**。

**行业最佳**（crypto-2026.md §3.2/§7，来源 [12][13][20]-[26]）：X25519+ML-KEM-768
混合是 2026 年新协议默认（RFC 10024 / FIPS 203；Chrome 131 默认、OpenSSH 10.0 默认、
Cloudflare >65% 并目标 2029 全 PQ）；纯 Rust ml-kem 0.3.3（FIPS 203）可用（复核轮
实跑其延迟与 crypto-2026.md 附录 A 一致：keypair 0.022ms / encap+decaps 0.044ms）；
签名侧 ML-DSA-65（FIPS 204）为可选加档（crate 自述未审计，或用形式化验证的 libcrux
备选）；**不要用 liboqs**（官方明示不建议生产）。认证层 PQ-PAKE 尚无标准 → PQ 放
传输层即可。

**理由**：这是唯一「完全空白」的维度。RSA 信封对 harvest-now-decrypt-later 尤其脆弱
（备份 dump 天生长存）；2026 年评估「行业最佳」，无 PQ 路径即不合格。
**动作**：与 3.3 合并执行——封装/握手换混合 KEM；密钥档案可选并行 ML-DSA-65；
版本协商字段预留算法档位以便未来升级。

### 3.8 传输帧与多路复用——upgrade

**现状**（本次核实：streams.rs:28/68-69 心跳、dbmaint.rs:155 dump 分片、
smoke-wizard.mjs:808-811 import 8MB 分片佐证；showroom-analysis.md §4.2）：showroom
**没有自己的传输帧/复用层**——控制面是 HTTP/1.1 请求响应（axum），下行是 ndjson 流
（30s `{"hb":true}` 心跳防代理断连），大载荷靠端点级分片（import 8MB/片、dump ≤4MB/片）。
对 FRP 明文中转的适配靠 HTTP 自身的可代理性。

**行业最佳**（vpn-mesh-2026.md §4；frp-compat.md §1.5）：单条 FRP TCP 中转上的
VPN 隧道应采用：**长度前缀帧 + 流 ID 的多路复用，承载于 E2E 加密会话之上**——具体
推荐 yamux（hashicorp 规范；Rust 实现 rust-yamux 0.14.1，2026-09-21 仍活跃，被
libp2p 大规模使用）：依赖可靠有序字节流的前提与单条 TCP 严丝合缝、原生 keepalive、
流控/背压内建。明确不选：HTTP/2（语义错配且同样有 TCP 队头阻塞）、QUIC-over-TCP
（双层可靠传输，收益为零复杂度翻倍）。**硬约束**（frp 实证）：禁依赖 TCP 半关闭表达
单向结束（T3 实验：SHUT_WR 后回程 0/65536 字节，整链即拆）——必须用显式 EOF 帧或
长度前缀；首字节任意值安全（用户口无探测，T2 已证）；数据面空闲不超时但节点重启/
NAT 会硬断，需应用层心跳 + 重连。

**理由**：这不是「showroom 做得不够好」，而是该层在 showroom 中根本不存在（HTTP
代行了帧与多路复用）。VPN 隧道必须新建此层，故 upgrade。
**动作**：协议库新增帧层（长度前缀 + 流 ID + 帧类型含显式 EOF/keepalive）与
复用层（yamux 或等价语义：流控、背压、keepalive、多流优先级——控制流高优先级）；
会话/重连语义按 3.6 的 WireGuard 模型配套。

### 3.9 首登信任锚/控制面 MITM（复核轮补入维度）——upgrade

**现状**（本次核实：SPEC.md:285-287 原文读取；showroom-analysis.md §6 第 5 条同载）：
明文 HTTP 首登无信任锚——SPEC §16.2 风险边界如实声明：「PAKE 只保证密码不泄露，
主动 MITM 可中继 login-finish 并在 key-bind 登记自己的公钥接管账号」，现行缓解
仅为**部署层**（公网站点前置 Caddy TLS；LAN 不可信时改走 CI 钥匙路径），协议层
无任何信任引导机制。攻击路径（由已核实的机制推演）：OPAQUE 全程可被中继（PAKE
不向首登客户端认证服务端身份——showroom 的 `SERVER_ID=b"showroom-server"` 是
字面量常量，opaque.rs:42 本次核实，不是已认证的密钥材料）；login-finish 后服务端
下发 60s 单次 bind_token（serve.rs:43-44 本次核实）是 bearer 凭据，中继者可抢在
客户端之前用它 key-bind 登记自己持有的公钥（key-bind 的签名由候选新钥匙本体作出，
只证明持有新钥匙、不证明持有账号口令），账号即被接管。次要同类边界：UnknownUser
假记录存在响应长度/时序统计残差（SPEC.md:287-288）。

**行业最佳**：身份引导（trust bootstrap）是authenticated key exchange 的标准议题——
RFC 9807 的 aPAQUE 安全模型**要求客户端持有已认证的服务端身份**，否则 PAKE 不提供
服务端认证；工程上的成熟做法：①TOFU + 公钥指纹钉扎（SSH known_hosts 模型，指纹
变更告警）；②带外预置凭证/邀请制（innernet 一次性邀请文件、Tailscale IdP 外包、
ZeroTier 控制器证书）；③服务端长期签名身份密钥进 OPAQUE 信封/握手 transcript，
客户端首登钉扎、后续登录强制校验（与混合 KEM 的服务端静态份额天然可合并）。

**理由**：showroom 自己已如实声明该边界且以部署层缓解——在其「管理员可控部署」
场景属已知取舍；但 ChmlVPN 的账号即网络接入权，接管账号=接管网格 membership，
且 FRP 明文中转是该攻击的结构性放大器（中转方天然位于中继位置）。作为 VPN 协议库
的必备维度，此为结构性缺口。
**动作**：升级清单 P0-5：协议层信任引导（TOFU 钉扎 + 带外预置凭证双路径，服务端
长期身份密钥进握手/OPAQUE 并覆盖 bind_token 等引导凭据的完整性）；首登指纹展示
与钉扎变更告警进管理面。

---

## 4. 升级清单（协议库设计硬输入）

按优先级排列；标 ★ 的为 VPN 新增面（不参与上文判定，但协议库必须提供接口）。

**P0（安全结构项，不做则不配称 2026 最佳）**
1. 密钥封装替换为 **X25519 + ML-KEM-768 混合 KEM**（RFC 10024 / FIPS 203；ml-kem
   0.3.3 纯 Rust；不用 liboqs）；一次性信封获得前向保密 + PQ；可保留 RSA-OAEP 兼容
   档做过渡双封装。（尺寸参考，复核轮实跑：混合密文 32+1088=1120B、混合公钥
   32+1184=1216B、延迟 <0.1ms）
2. **会话/隧道档 AEAD 纪律**：每方向 64-bit 严格单调计数器 nonce；2^60 包或 120s
   双阈值 rekey；180s / 2^64−2^13−1 硬拒绝；伪造尝试限额断链；禁用长会话随机
   96-bit nonce（信封档保留「一次性 k + 随机 nonce」并文档化前提）。
3. **信封 v2 段 AAD**：段序号（+ 信封 ID/总段数）进 AAD，防段重排与拼接；v1 只读兼容。
4. **压缩层安全化**：压缩默认关闭、按策略/按流开启（VORACLE/CRIME 前提在 ChmlVPN
   成立——FRP 中转即长度观察点）；开启会话配输出填充；非膨胀回退（RFC 3173 §2.2 MUST）
   + 自适应跳过。
5. **首登信任锚/控制面 MITM（复核轮补入）**：协议层信任引导——①服务端长期签名
   身份密钥进 OPAQUE 信封/握手 transcript，客户端首登 TOFU 钉扎（指纹展示 + 变更
   告警），后续登录强制校验；②带外预置凭证/邀请制作为强路径（对标 innernet 邀请
   文件 / SSH known_hosts）；bind_token 等引导凭据的完整性须被服务端身份密钥覆盖。
   依据：SPEC.md:285-287 已声明的接管攻击；RFC 9807 aPAKE 模型要求客户端持有已
   认证服务端身份。

**P1（性能与档位项）**
6. **crate 代际升级**：aes-gcm 0.10.3 → 0.11.1（aes 0.9/VAES 内核，实测 ~2.3×）；
   opaque-ke 3.0.0 → 4.0.1；ed25519-dalek 2.2.0 → 3.0.0；评估 rand 0.8.8 → 0.9/0.10
   （API 代差；0.8.x 仍被维护，可延后但要有计划）。
7. **压缩档位重构**：<128B 直通；128B–1.5KB zstd-1 + 字典 4–16KB（合成模板训练、
   dictID 协商、版本强制一致）；>1.5KB zstd -1 分块 16–64KB + 5–10ms flush；上下文
   复用；level 19 仅留批量/归档档；帧头加压缩标志 + 原始长度；lz4_flex 作 CPU 受限
   备选档。
8. **AEAD 协商后备档**：XChaCha20-Poly1305（无 AES 硬件端）、AES-256-GCM-SIV
   （抗误用/多主复制场景，本机实测最快）。
9. **传输帧与多路复用层**：长度前缀帧 + 流 ID + 显式 EOF 帧（禁依赖 TCP 半关闭，
   frp T3 实证）+ keepalive；复用采用 yamux（rust-yamux 0.14.1）或等价语义（流控/
   背压/keepalive/控制流高优先级）；首字节任意值合规（frp 用户口无探测）。
10. **握手**：WireGuard 式 1-RTT（Noise IK 结构）+ 混合 KEM 槽位；按对端静态公钥
    索引会话支持漫游；重连 = 全新握手（不做 PSK 恢复）；10s keepalive 兼作中转探活。

**P2（认证/签名维护项）**
11. OPAQUE：升 opaque-ke 4.0.1（固定向量测试守门）；argon2id 参数版本化 profile
    （RFC 9807 高配档 vs OWASP 档）；修正 RFC 引用 9380 → **9807**（opaque.rs:1，
    本次已核实笔误存在）。
12. 签名：ed25519-dalek 3.0.0；密钥档案预留 ML-DSA-65 并行公钥/kid 类型分派（可选
    PQ 加档）。
13. 文档回改：nonce 长度规范-实现偏差以实现为准（16 随机字节/32 hex，lib.rs:75-79）。

**★ VPN 新增面（必须提供接口，不参与判定）**
14. **tun 数据面接口**：帧化 TUN IP 包进逻辑流；适配 tun-rs 2.8.16（Win/macOS/Linux/
    Android/iOS 平台矩阵最全）；Linux 路由配 rtnetlink；MTU 1280（Tailscale 同款、
    IPv6 下限）；Android `protect()` / iOS fd 传入的接入缝。
15. **多主多活同步接口**：设备注册表/凭证/配置版本走强一致状态机（openraft）；
    在线状态走 gossip 租约；会话票据本地签发下放；吊销全网生效语义 + nonce/重放状态
    的跨服务端归属；协议库需暴露「按服务器独立密钥/逐次重封装」的权限点。
16. **frp 中转适配接口**：应用层心跳 + 断链重连（全新握手）；不依赖半关闭；单隧道
    多会话复用（不依赖多隧道）；frpc 子进程托管（ChmlFrp v0.51.2 定版 + 原版定版
    双栈，ChmlFrp 三次重连退出需进程守护）。

---

## 5. 方法与限度声明

- 本报告的「行业最佳」结论转引自五份调研报告的一级来源链（RFC/NIST/官方博客/
  上游源码/crates.io API + 报告内本机实测），评估人对报告结论做了源码侧交叉抽查
  （§0 表）；网络检索未复跑。密码学基准在复核轮已实跑复现（cryptobench，§0 表），
  压缩实测未复跑。
- 本次未做的：ChmlVPN 侧任何实现验证（仓库尚无代码）；移动端（iOS/Android）纯 Rust
  crate 交叉实测（crypto-2026.md gaps #6）；ChmlFrp 真实节点端到端实测
  （frp-compat.md gaps #1）。
- 9 个维度中 adopt 2 项、hedge 3 项、upgrade 4 项；总判断 overallKeep = false，
  主要由 #3（封装）、#7（PQ）、#8（帧/复用）、#9（信任锚）四项 upgrade 与
  #4/#5/#6 的档位缺口驱动。

---

## 6. 复核修订记录（2026-10-31 第二轮）

复核员提出两条异议，逐条核实结果如下：

1. **遗漏「首登信任锚/控制面 MITM」维度——成立，已修订。** 核实：SPEC.md:285-287
   原文本次读取，确载「明文 HTTP 首登无信任锚——PAKE 只保证密码不泄露，主动 MITM
   可中继 login-finish 并在 key-bind 登记自己的公钥接管账号」；showroom-analysis.md
   §6 第 5 条（229-231 行）同载。原 verdict 的 8 维度与 15 项升级清单均未覆盖，属
   完备性缺口。修订：新增维度 9（§2 表、§3.9 详述，判定 upgrade）、升级清单新增
   P0-5（TOFU 钉扎 / 带外预置凭证 / 服务端身份密钥进 OPAQUE 与握手）；总判断
   overallKeep=false 不变且论据增强。
2. **§3.3 混合密文数字口径错误——成立，已修订。** 核实：本次实跑 cryptobench
   （ml-kem 0.3.3）输出 `ek=1184B ct=1088B`，即混合密文 = 32+1088 = **1120B**、
   混合公钥 key share = 32+1184 = **1216B**。crypto-2026.md §3.3 原文「混合密文约
   32+1184B」把 ek 混入密文口径（1184 是封装公钥长度，密文是 1088）；原 verdict
   「混合密文 ~1120B + 32B」为重复加总。修订：§3.3 数字按实跑改正并注明勘误；
   同时纠正理由段——RSA 384B 头其实**小于**混合密文 1120B（RSA 唯一的尺寸优势，
   不构成保留理由），替换论据是前向保密 + PQ + 速度。维度 upgrade 结论不变。

## 7. 复核修订记录（2026-10-31 第三轮）

复核员提出两条（均文书级，不影响任何判定），逐条核实结果如下：

1. **§4 升级清单编号冲突——成立，已重编。** 核实：grep 本文件确认第二轮在 P0 块
   末尾插入第 5 项（首登信任锚）后，P1 块仍从「5. crate 代际升级」起号，出现两个
   5 号；P2 仍为 10–12、★ 仍为 13–15，未顺延。无条目丢失，§3.9 的「P0-5」指称
   在 P0 块内无歧义。修订：P1 重编为 6–10、P2 重编为 11–13、★ 重编为 14–16，
   共 16 项连续编号；条目内容零变化。
2. **§0 表『dk=64B』口径无限定语——成立，已加注。** 核实：本地 cargo registry
   源码 ml-kem-0.3.3/src/decapsulation_key.rs:231-233 证实 `KeyExport::to_bytes()`
   返回 `Seed`（d‖z，恒 64B），:243-245 证实展开形态（FIPS 203 dkLen）ML-KEM-768
   为 2400B。§0 表原样照录了程序输出 `dk=64B` 而未注明是种子序列化形态，易被误读
   为 FIPS dk 尺寸。修订：§0 表该行加「口径注记」；报告无任何结论引用 dk 尺寸，
   各判定不受影响。
