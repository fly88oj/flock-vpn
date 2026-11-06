# Flock VPN 总体设计

- 设计人：总设计师（动态工作流子代理）；日期：2026-10-31
- 输入材料（全部通读）：
  `docs/research/verdict.md`（评估结论 + upgradeList 16 项，本设计的硬输入）、
  `docs/research/showroom-analysis.md`、`crypto-2026.md`、`compression-2026.md`、
  `vpn-mesh-2026.md`、`frp-compat.md`；showroom 源码（`E:\Works\showroom`，只读抽查）。
- 设计语言：深模块 / 接口 / 接缝 / 适配器 / 深度（leverage·locality），按
  `C:\Users\FLYING\.zcode\skills\codebase-design\SKILL.md` 的词汇表使用。
- 证据纪律：文中每个关键论断括注来源（报告§节 / 源码 `文件:行` / 本会话执行的命令与输出）。
  本会话亲自执行的核实见附录 B；未执行的一律写明「未验证」。
- 硬性约束追踪：verdict §4 upgradeList 共 16 项（P0-1..P2-13、★VPN-14..16）一项不漏，
  落位对照表见附录 A。

---

## 0. 设计总览

一句话：**Flock VPN = showroom 协议层的「升级档位化抽库」+ 长寿命隧道会话层 + 接入端点（Direct 缺省 / FRP 中转可选）+ openraft 多主多活控制面**。协议层抽成独立库 `flock-protocol`（深模块：文件信封/签名/认证/会话/复用/压缩/信任锚七个小接口藏大实现），Flock VPN 与 showroom 两项目共用；VPN 特有的 tun 适配、frpc 托管、多主同步以「接缝 + 适配器」形式落在协议库外圈的 Flock VPN workspace crate 里。

**硬约束（用户令，最高优先级，覆盖任何相反表述）**：Flock VPN **不得与 frp/chmlfrp 强绑定**。frp 只服务于「服务端无公网 IP 或客户端无法直连服务端 IP」的场景；服务端可直连时**不执行任何 frp 相关逻辑**（无 frpc 子进程、无配置生成）——listener mode 缺省 = `Direct`，`Frp` 是可选适配器而非前提（§2.1/§2.2/§3.11/§5）。

分层（自下而上）：

```
┌─ 客户端 app（flock-client）────────────────────────────────────┐
│ tun(tun-rs) → PacketChannel → yamux 流 ─┐                        │
│ 路由（rtnetlink/wintun/VpnService）      │                        │
└──────────────────────────────────────────┼────────────────────────┘
                                            │ 单条 TCP（密文；路径=接入端点：
                                            │  Direct 直连 或 经 FRP 中转）
┌─ flock-protocol（会话层）──────────────────┼───────────────────────┐
│ SecureStream(记录层: 计数器nonce AEAD+抗重放+rekey) ← yamux 跑在加密内 │
│ 握手: 已钉扎 1-RTT Noise-IK / TOFU 首连 2-RTT；X25519+ML-KEM-768 混合 │
│       KEM + 服务端身份签名（邀请文件携带静态混合公钥）                  │
└──────────────────────────────────────────┼───────────────────────┘
                                            │ TCP 字节流（直连或中转，均透明）
┌─ 服务端 app（flock-server）─────────────┼────────────────────────┐
│ 监听器 ListenerMode: Direct(缺省,零 frp) │ tun + 路由 + peer 转发   │
│   或 Frp(flock-frpc Supervisor 托管中转)  │ flock-sync: openraft+租约│
│ 控制流: OPAQUE 登录 + 设备注册表 + 配置下发 │                        │
└───────────────────────────────────────────────────────────────────┘
```

走 FRP 中转时全程只见密文（frp useEncryption/useCompression 默认关，frp-compat §0.1/S20；字节透传经 T1/T2 实证，含 0x00–0xFF 全字符集与 0x16/0x17 首字节）；直连时链路上只有本协议密文。

---

## 1. 共享协议库：`flock-protocol`

### 1.1 名字与落位

- **crate 名**：`flock-protocol`（lib 名 `flock_protocol`）。
- **落位**：本仓库 workspace member，`E:\Works\FlockVPN\crates\flock-protocol`。
  workspace 布局：

  ```
  E:\Works\FlockVPN\
  ├── Cargo.toml            # workspace root（成员见下）
  ├── crates/
  │   ├── flock-protocol/    # ★ 共享协议库（Flock VPN 与 showroom 两边引用）
  │   ├── flock-frpc/        # frpc 子进程托管双栈（Flock VPN 专用）
  │   └── flock-sync/        # openraft 状态机 + gossip 租约（Flock VPN 专用）
  ├── app/
  │   ├── flock-server/
  │   └── flock-client/
  ├── deploy/               # Docker compose 拓扑 + 断言脚本（§6）
  └── docs/
  ```

- 理由：协议库必须能被 showroom 独立引用（showroom 是另一个仓库 `E:\Works\showroom`，
  其 workspace members = showroom-common/showroomctl/showroom，showroom/Cargo.toml:3 本次核实），
  所以它不能是 Flock VPN app 的内部模块；同时它是本仓库的交付主体（M1 里程碑），放本仓库
  `crates/` 是唯一同时满足「本仓库内目录」与「跨仓库可引用」的落位。

### 1.2 被两项目引用的方式（路径/发布策略）

双轨引用，开发期零摩擦、生产期可钉版：

1. **Flock VPN（本仓库）**：workspace path 成员依赖 `flock-protocol = { path = "crates/flock-protocol" }`。
2. **showroom（外部仓库）**：git 依赖钉 tag：
   `flock-protocol = { git = "<Flock VPN 仓库 URL>", tag = "flock-protocol-v0.1.0", default-features = false, features = ["legacy", "wasm"] }`；
   开发期在 showroom 仓库 `.cargo/config.toml` 用 `[patch."<git-url>"]` 覆盖为本地路径
   `path = "../FlockVPN/crates/flock-protocol"`（标准 patch 工作流，showroom 不改 Cargo.toml 即可本地联调）。
3. **发布策略**：阶段一 git+tag（够用、无发布仪式）；若 showroom CI 或第三方需要，阶段二
   发 crates.io（许可 Apache-2.0 OR MIT，与 RustCrypto 生态一致，crypto-2026 §5）。
   版本纪律：showroom-common 的 `pub use {ed25519_dalek, rsa}`「版本收口」语义保留
   （showroom-analysis §2 再导出注意点）——flock-protocol 继续再导出其锁定的 dalek/x25519-dalek 等，
   两项目不得另引版本。

showroom 的迁移面（兼容保留，见 §1.3）：`showroom-common` 改为对 `flock-protocol` 的薄再导出
（保留全部既有 pub 项签名），showroomctl/showroom 源码零改动。此迁移本身属 showroom 侧工作，
本仓库只保证接口可替换；不在本设计交付范围（本仓库不写 showroom 代码）。

### 1.3 API 设计：兼容面 + 升级档位

设计原则（SKILL.md）：**小接口、大实现**。每个子模块的接口是「调用方需要知道的一切」——
包括安全前提（如信封档的一次性 k）显式写进类型名或文档契约。

#### 1.3.1 feature 划分

| feature | 内容 | 默认 | 服务对象 |
|---|---|---|---|
| （默认） | sig / pake / kem-hybrid / envelope-v2 / session / mux / compress / trust | 开 | Flock VPN 全量 |
| `legacy` | 信封 v1（RSA-OAEP）seal/open、SR-SIG1 旧常量 | 关 | showroom 过渡 |
| `anchor` | OPAQUE 服务端身份签名层（P0-5 的登录锚） | 关（Flock VPN 构建里开） | Flock VPN；showroom 后续跟进 |
| `pq-sign` | ML-DSA-65 并行公钥档（ml-dsa 0.1.1，crate 自述未审计，crypto-2026 §5） | 关 | 可选 |
| `wasm` | getrandom custom 后端桥等 showroom wasm 约束（showroom-analysis §6.3） | 关 | showroom |

#### 1.3.2 兼容面（保留给 showroom 的接口，签名不变）

以下全部来自 showroom-analysis §2 的 pub 面清单（本次抽查源码一致），原样保留：

- `sig`：`build_canonical / sign / sign_prehashed / verify / verify_with_hash`，
  canonical 七字段与 `SR-SIG1 <user>:<ts>:<nonce>:<sig_b64url>` 线上格式逐字节不变
  （showroom-common/src/lib.rs:222-261 本次核实）；`SIG_WINDOW_SECS=300`（lib.rs:48）。
- `envelope` v1（`legacy`）：`seal/open` 与 `[384B RSA-OAEP 头]||段{[12B nonce][ct+tag]}`
  布局不变（lib.rs:376-412 本次核实），长度不变量测试保留。
- `pake`：OPAQUE Suite（ristretto255+TripleDH+Identity KSF，opaque.rs:32-39 本次核实）、
  全部 login/reg/server_* 函数、`SERVER_ID` 导出、rwd 外部 argon2id
  （opaque.rs:53-70 本次核实：m=19456KiB/t=2/p=1，盐前缀 `showroom-opaque-v1`）。
- 工具：`sha256_hex(_stream)`、`nonce_hex`（16 随机字节→32 hex，lib.rs:75-79——P2-13 文档回改按实现为准）、
  `write_private`（0600）、`names::*`、常量 `KEY_LEN/NONCE_LEN/TAG_LEN/SEG/WRAP_LEN`。
- 依赖代际（P1-6）：aes-gcm 0.11.1 / opaque-ke 4.0.1 / ed25519-dalek 3.0.0 /
  rand 0.9（新代码；理由：非 wasm 的 VPN 无 0.8 兼容包袱，0.8.x 虽仍维护但 API 代差迟早要还，
  crypto-2026 §5 rand 行）。**兼容性守门**：opaque-ke 3→4 必须过「showroom 固定向量样本互通」
  测试（M1 硬门槛，见 §7）；OPAQUE 报文格式由 RFC 9807 固定，升级属实现代际而非协议变化
  （crypto-2026 §4.1）。
- 勘误落实（P2-11）：库内注释引用 RFC **9807**（opaque.rs:1 误写 9380，本次核实存在）。

#### 1.3.3 升级档位（按评估结论新增/替换）

**(a) `kem` —— 混合 KEM 模块（P0-1、P0-7 PQ）**

```rust
pub struct HybridKeypair { … }          // X25519 静态 + ML-KEM-768 密钥对
pub struct HybridPubkey { … }           // 线上 1216B = 32(X25519) + 1184(ML-KEM ek)
pub struct SealedShared([u8; 32]);
pub fn encapsulate(pk: &HybridPubkey, rng) -> (SealedShared, HybridCt); // ct 1120B = 32+1088
pub fn decapsulate(sk: &HybridKeypair, ct: &HybridCt) -> Option<SealedShared>;
pub fn fingerprint(pk: &HybridPubkey) -> Fingerprint;                  // 钉扎/展示用
```

- 组合规则：`shared = HKDF-SHA256(x25519_ss || ml_kem_ss)`（TLS 混合思想，RFC 10024；frp-compat 无涉）。
- 尺寸与延迟依据（verdict §3.3 复核轮实跑）：ek=1184B/ct=1088B、混合密文 1120B、混合公钥
  1216B、encap+decap <0.1ms。实现用 ml-kem 0.3.3（纯 Rust FIPS 203）+ x25519-dalek 3.0.0；
  **不用 liboqs**（官方明示不建议生产，crypto-2026 §5）。
- RSA 兼容档：`legacy` feature 保留 v1 read/open；「过渡双封装」评估结论为**不提供**——
  v1 读者按定长 384B 解析头部，任何含混合密文的新布局它都无法解析，双封装不能带来
  「新老同解」，真正的过渡=迁移窗口内 showroom 继续写 v1、永远可读 v1（P0-1 的「可保留」
  以此形式满足；理由与 showroom-analysis §4.1 头部布局一致）。

**(b) `envelope` v2 —— 段序号 AAD（P0-3）+ 混合封装**

```
头: [1B ver=2][16B envelope_id][32B eph_x25519][1088B ml_kem_ct]   = 1137B
段: [12B nonce][AES-256-GCM ct‖tag]，AAD = ver‖envelope_id‖seg_idx‖is_final
```

- 一次性 k 由混合 KEM 派生（每信封新临时份额 ⇒ **一次性信封获得前向保密**，verdict §3.3）。
- 信封档保留「一次性 k + 每段随机 96-bit nonce」的**文档化前提**（每密钥消息数 = n/4MiB ≪ 2^32，
  SP 800-38D 随机 IV 界内，verdict §3.4）；AAD 把段序号+信封 ID+结束位绑进认证，防段重排/拼接
  （v1 缺失，本次核实 lib.rs:396-411 encrypt 调用仅 nonce+明文）。
- `open_v1` 只读兼容（`legacy`）。zstd-19 批量档（P1-7）继续由调用方管道组合，库只加
  `seal_v2_compress(policy)` 便捷档位。

**(c) `session` —— 隧道会话（P0-2、P1-8、P1-10 的核心承载）**

深模块：调用方只见到 `Tunnel`，内部藏握手/记录层/抗重放/rekey/keepalive/伪造限额全套纪律。

```rust
pub struct TunnelConfig {
    pub aead: AeadPreference,        // 主 AES-256-GCM(aes-gcm 0.11.1)；后备 XChaCha20-Poly1305 /
                                     // AES-256-GCM-SIV（P1-8，协商取交集）
    pub keepalive: Duration,         // 默认 10s（WireGuard KeepaliveTimeout，crypto-2026 §6）
    pub rekey_after: (u64, Duration),// 默认 (2^60, 120s) 双阈值
    pub reject_after: (u64, Duration),// 默认 (2^64−2^13−1, 180s) 硬拒绝
    pub forge_limit: u32,            // 伪造尝试限额断链（默认 100，P0-2）
}
pub enum LookupVerdict { NotFound, Revoked { since_epoch: u64 }, Active(DeviceRecord) }
pub trait DeviceDirectory: Send + Sync + 'static {
    fn lookup(&self, id: &DeviceId) -> BoxFuture<'static, LookupVerdict>;  // 必须异步：
        // 线性一致读经 Raft leader 是网络往返（§4）；NotFound 与 Revoked 都必须拒握手且
        // 时序对齐（防在线探测设备枚举）。
}
pub async fn initiate(io: TcpStream, device: &DeviceStaticKeys,
                      expect_server: &ServerPin, cfg: TunnelConfig) -> Result<Tunnel>;
pub async fn respond(io: TcpStream, server: &ServerIdentity,
                     dir: impl DeviceDirectory, cfg: TunnelConfig) -> Result<Tunnel>;
impl Tunnel {
    pub async fn open_stream(&self, prio: Prio) -> io::Result<Stream>;     // 逻辑流（yamux 内跑）
    pub async fn open_packet_channel(&self) -> io::Result<PacketChannel>;  // TUN 帧化（VPN-14 接口）
    pub fn stats(&self) -> SessionStats;                                    // epoch/计数/重放拒绝
}
```

- **lookup 接缝的实现契约**（防重连风暴放大到 Raft leader，详见 §4「读与缓存」）：握手侧
  `DeviceDirectory` 的服务端实现用「记录缓存 + 吊销纪元（revocation_epoch，随 Raft 日志
  apply 自动推进）」两级——epoch 未变且缓存命中 ⇒ 本地答；epoch 变化或 miss ⇒ 线性一致读。
  中转断链后的 N 客户端重连风暴在无吊销时全部命中本地缓存，不触碰 leader。
- **握手（P1-10）双形态**——首连是否有服务器静态材料决定往返数（钉扎模型 = 集群根公钥锚定
  全套服务器材料，§1.3.3f）：
  - **已钉扎形态（邀请文件或既有 pin，常态 1-RTT，Noise IK 结构）**：
    I1 = 版本+算法集+X25519 临时 + ML-KEM-768 ct(1088B，对**目标服务器**——即该端点在
    ClusterDirectory 中对应 ServerEntry 的——**静态 ML-KEM 公钥**封装) + 以
    HKDF(x25519(e,s_srv)‖mlkem_ss) 派生密钥加密的「设备静态 X25519 公钥+设备 Ed25519
    公钥+**设备签名**」；R1 = 服务器临时 + **服务器身份密钥对 transcript 的签名（P0-5 隧道侧）**
    + 双向密钥确认。握手后首帧即可承数据。`initiate` 的 `expect_server: &ServerPin` =
    （cluster_root_pub + 目标端点的 ServerEntry）——切端点 = 换 ServerEntry，材料来自
    邀请文件或 dir_pull 刷新的根签目录，**任意端点均 1-RTT**（A5/A15 的实现基础）。
    - **签名覆盖契约（防 UKS/未知密钥共享）**：设备 Ed25519 签名的覆盖范围 = I1 **全部已发
      字段**（含两个临时份额与算法集）+ 协议上下文（cluster_id、期望的服务器身份公钥、
      会话用途标签）；服务器身份签名覆盖 = I1‖R1 全 transcript。M1 向量必须含「篡改上下文/
      换服务器身份 → 验签失败」用例。
  - **TOFU 首连引导形态（无任何集群材料，仅一次，2-RTT）**：
    I0 = 版本+算法集+客户端 X25519 临时（此时无服务器静态公钥，无法封装/加密，明文发起）；
    R0 = 该服务器的**入群凭证公开部分**（server_id + identity_pub + static_hybrid_pub 全量
    + access_endpoint）+ **集群根公钥** + 服务器身份对 I0‖R0 的签名。客户端验证：入群凭证
    = 根公钥对 ServerEntry 的签名 ⇒ 材料链可信；随后展示**集群根指纹**、用户确认后
    **只钉扎根公钥**（cluster_id → root_pub），并即以该 ServerEntry 按 1-RTT 形态发 I1/R1。
    其他端点/新服务器材料经控制流 `dir_pull`（根签 ClusterDirectory，dir_version 递增）
    获取——**此后任何端点均 1-RTT，I0 不再出现**。
    - **残余风险明示**：TOFU 不防首登在线 MITM——首连时攻击者可自签一套「根公钥+凭证链」、
      客户端把攻击者的根钉住（SSH known_hosts 同类限制）；组织场景必须走邀请文件强路径
      （§1.3.3f）。
  - 按对端静态公钥索引会话 ⇒ 端点（中转入口）可换而会话语义连续（漫游模型，vpn-mesh §2 /
    crypto-2026 §6）。重连 = **全新握手**，不做 PSK 恢复（TLS 恢复会绑定旧会话安全上下文且
    binder 不抗字典，crypto-2026 §6）。
- **记录层（P0-2）**：`[u32 len ≤1MiB][type][AEAD(payload)]`，nonce = 32-bit 零 ‖ 64-bit LE
  计数器（WireGuard 形态）；每方向独立计数与密钥；**长会话禁随机 96-bit nonce**（信封档前提
  不适用于隧道档——两档分立并各自文档化，verdict §3.4）。
- **抗重放**：TCP 有序交付下接收侧检查计数严格递增，重复/回退即拒并计伪造；2048 滑动窗口
  数据结构保留给未来 UDP 直连路径（crypto-2026 §2.2 明示 TCP 下窗口可缩、跨连接重放靠握手
  新鲜性兜底——如实记录，不夸大）。
- **rekey**：控制流上跑 REKEY_INIT/RESP（新混合 KEM，成本 <0.1ms），epoch 切换后计数器随新密钥
  重置；`reject_after` 触发即清零密钥断链。
- **AEAD 后备协商（P1-8）**：无 AES 硬件端 XChaCha20-Poly1305；抗误用/复制敏感场景
  AES-256-GCM-SIV（本机最快 5.09-5.27 GB/s，verdict §0 复跑）。

**(d) `mux` —— 复用与 EOF 语义（P1-9、VPN-16 协议侧）**

- 复用器：**rust-yamux 0.14.1**（hashicorp 规范实现，2026-09-21 活跃，vpn-mesh §4.1 表）。
  yamux 本身 = 长度前缀帧 + 流 ID + 显式 FIN/EOF + ping keepalive + 流控背压——正是 P1-9
  列出的全部语义，**不重造**。链路次序：TCP → SecureStream（记录层加密）→ yamux → 逻辑流。
  yamux 在加密内 ⇒ 流数/流元数据对中转不可见。
- **禁依赖 TCP 半关闭**（frp T3 实证：SHUT_WR 后回程 0/65536，整链即拆，frp-compat §1.5）——
  单向结束一律 yamux FIN；keepalive 用 yamux ping（默认 10s，P1-10/VPN-16 应用层心跳，
  兼作中转探活）。首字节任意值合规（用户口无 TLS 探测，T2 已证）。
- 控制流（stream 0）高优先级调度；`PacketChannel` = TUN 包专用帧化
  （`[u16 len][ip packet]`，保边界），是 VPN-14 要求的库侧接口。

**(e) `compress` —— 压缩档位与安全化（P0-4、P1-7）**

```rust
pub struct CompressPolicy { pub mode: Mode /* Off(默认) | Interactive | Bulk | Archive */,
                            pub padding: PadPolicy, pub dict: DictRef }
pub fn compress_frame(p: &Policy, bytes) -> Frame;   // 帧头: 压缩标志 + 原始长度
```

- **默认关闭**；按策略/按流开启（VORACLE/CRIME/BREACH 前提在 Flock VPN 成立——FRP 中转即
  长度观察点，compression-2026 §3.2）；开启时配输出填充（16B 倍数起步，可调桶化）。
- 档位（compression-2026 §0/§2 实测）：`<128B` 直通（40B 反膨胀 122.5%、120B 零收益）；
  `128B–1.5KB` zstd-1 + 字典 4–16KB（合成模板训练、dictID 握手协商、版本强制一致；
  120B→28–30% 且更快）；`>1.5KB` zstd-1 分块 16–64KB + 5–10ms flush（64KB 块仅损 0.2pp）；
  level 19 仅留 Archive/归档档；lz4_flex 0.14 作 CPU 受限备选；上下文复用（实测 3×）。
- **非膨胀回退 MUST**（RFC 3173 §2.2）：试压不缩小即发明文 + 连续失败自适应停试。
- 先压后密顺序不变（RFC 3173 §1）；压缩发生在记录层 payload 内。

**(f) `trust` —— 首登信任锚（P0-5）**

钉扎模型定型（第三轮评审 blocking 的裁决，先说结论再给结构）：**客户端锚定「集群根公钥」，
持全套服务器的根签接入材料（方案②）**。三种可选调和方式中——①集群共享一套服务器静态密钥：
**否决**，与 §4「每台服务器各自 identity/static_hybrid 密钥」的准入模型冲突，且使 VPN-15
「逐服务器独立封装/rewrap 权限点」变成假的（共享 HybridKeypair 下任一台泄露即可解全部 OPRF
封装）；③切换端点回落 2-RTT 引导：**否决**，重连/切换是常态路径，每次 2-RTT + 重新人工确认
不可接受；②客户端持全套材料、由单一根签名背书：**采纳**——「端点→服务器材料」映射本身被
集群根密钥签名（防 MITM 的来源就是这份签名），单台服务器换静态密钥只需根签新条目、客户端
控制流刷新目录即可，不触及其他端点的钉扎。

```rust
pub struct ServerIdentity { ed: VerifyingKey /* + 可选 ml_dsa */, … } // 长期签名身份（每台各自）
pub struct ServerEntry {                // = §4 入群凭证的「公开部分」，同一凭证两用：
                                        //   服务器互认（§4）/ 客户端接入材料（此处）
    pub server_id: ServerId,
    pub access_endpoint: SocketAddr,    // 该服务器的**接入端点**：Direct 形态=直连地址（公网/
                                        // 内网 host:port，零 frp），Frp 形态=中转用户口（frps
                                        // host:port）——两种形态对客户端无感知差异，都是拨号
                                        // 目标（第四轮更名自 relay_endpoint，语义扩大）
    pub endpoint_form: Direct | Frp,    // 标注形态（客户端仅作展示/诊断，选路逻辑不变）
    pub identity_pub: VerifyingKey,     // 该服务器身份 Ed25519 公钥
    pub static_hybrid_pub: HybridPubkey,// 该服务器静态混合公钥（1216B；I1 的 ML-KEM ct 必须封装给它）
}
pub struct ClusterDirectory {           // 端点列表与凭证同签一份，防「列表真、条目假」的拼接
    pub cluster_id: ClusterId,
    pub servers: Vec<ServerEntry>,
    pub dir_version: u64,               // 递增；单台换钥 ⇒ 根签新目录 ⇒ 客户端 dir_pull 刷新
}
pub struct InviteFile {                 // v3：集群目录 + 一次性消费凭据，一次根签名
    pub directory: ClusterDirectory,
    pub cluster_root_pub: VerifyingKey, // 集群根公钥（§4 根密钥之公钥，信任锚本体）
    pub expiry: DateTime,               // 默认 7 天（可配）
    pub invite_id: Uuid,                // 进 Raft 状态机做单次消费（见下）
    pub root_sig: Signature,            // 集群根密钥签名，覆盖上述全部字段
}
pub struct PinStore { … }               // 钉扎粒度 = (cluster_id → cluster_root_pub)
pub fn first_pin(cluster_id, root_pub) / verify_pinned(cluster_id, root_pub) -> Verdict;
                                        // 变更→显式告警；服务器级材料不单独 TOFU（由根签名背书）
pub fn load_invite(path) -> Result<InviteFile>;
```

- **落地双路径**：①**邀请文件强路径**（对标 innernet 一次性邀请，vpn-mesh §2/S15）：v3 内含
  **全套服务器接入材料（ClusterDirectory）+ 集群根公钥**，一次根签名同签——持邀请客户端对
  任意端点（含 A5 切换到 server-b、A15 迁移到 server-a）都直接 1-RTT，完全避开 TOFU；
  ②TOFU 路径（个人自建）：首连 2-RTT 引导（§1.3.3c），客户端**只钉扎集群根公钥**（展示根
  指纹、确认一次），服务器材料经入群凭证链由根验签；此后任何端点（含新服务器，经 dir_pull
  取根签目录）均 1-RTT。服务端身份密钥另进 OPAQUE login-finish（`anchor` feature：签名覆盖
  SERVER_ID‖user‖ke2 transcript‖bind_token）。
- **邀请文件的一生（一次性语义，对标 innernet「邀请文件（一次性）」 vpn-mesh §2 表）**：
  生成（管理操作，根密钥语境）→ 分发（0600 文件，按凭据对待）→ **兑换 = Raft 管理操作
  `redeem_invite(invite_id)`：查重（used? 拒）+ 吊销检查 + expiry 检查 → 标记 used → 创建
  用户/设备并分配 VIP**；同一 invite_id 二次兑换必拒；`revoke_invite(invite_id)`（根密钥签名
  的管理操作）可吊销未兑换邀请。已兑换文件泄露 = 无效（used）；未兑换文件泄露 = expiry 内
  可被抢先兑换一次（接受边界：邀请按一次性凭据管理，默认 7 天过期，写入部署文档）。
- **开户流程（用户账号从哪来，补齐 showroom 语义的对齐）**：用户账号 = 管理员 `user-add`
  或邀请兑换时创建；之后走 OPAQUE 注册（pw-begin/pw-commit）设置口令；设备密钥（X25519+
  Ed25519）客户端本地生成、公钥经登录态登记（key-bind 类似物，受服务端身份签名覆盖）；
  设备进注册表 = `(DeviceId, owner, VIP, 静态公钥集, status)`。即：**邀请文件决定「谁能
  入网」（根签）、OPAQUE 决定「谁是谁」（账号口令）、设备密钥决定「哪台机器」**，三者分离。
- **残余风险明示（不可静默）**：TOFU 不防首登在线 MITM（首连可被整体替身+钉扎攻击者密钥，
  随后 bind_token 抢用接管依旧成立——SSH known_hosts 同类限制，verdict §3.9 攻击只被
  部分关闭）；面向组织的部署文档必须把邀请文件标为推荐路径。
- 依据：verdict §3.9（SPEC.md:285-287 已声明的 bind_token 抢用接管攻击；`SERVER_ID` 是
  字面量非密钥，opaque.rs:42 本次核实）；RFC 9807 aPAKE 模型要求客户端持有已认证服务端身份。

**(g) `sig` 档位（P2-12）**：SR-SIG1 线上格式不变；新增 `KeyProfile`（kid→算法分派：
Ed25519 主档 + `pq-sign` 下 ML-DSA-65 并行公钥位）。

**(h) `pake` 档位（P2-11）**：argon2id 参数版本化 profile
  （`Profile::Owasp19MiB`（showroom 兼容默认）/`Profile::Rfc9807High`（m=2GiB,t=1,p=4 高配档）），
  profile id 进注册记录，防跨档漂移；OPAQUE 本体不变（adopt，verdict §3.1）。

### 1.4 原版 FRP 与 ChmlFrp 下行为一致（论证）

协议库只假设底层是「可靠有序、字节透明、可能整条硬断的 TCP 流」：

1. **字节透明已证**：原版 v0.71.1 上全 256 字节值 + 1MiB 随机往返 sha256 一致、首字节 0x16/0x17
   无干扰、无框定注入（frp-compat §1.5 T1/T2）；ChmlFrp 数据面与原版 v0.51.2 逐行一致
   （fork diff 未涉 `pkg/msg` 与数据通路，frp-compat §2.3）⇒ 两家中转承载同一密文字节流。
2. **不依赖中转特有行为**：禁半关闭（用 yamux FIN，R3）；不依赖多隧道（单 frp 隧道承载全部
   会话，yamux 复用，R11——ChmlFrp 免费档 4 隧道上限下的硬要求）；应用层 10s 心跳探活
   （数据面无空闲超时但节点重启/NAT 硬断，R5）；断链 = 全新握手重连（R6）。
3. **两家中转的差异被隔离在 `flock-frpc`**（§5）：协议库本体不感知 frp 存在——它的接缝是
   `TcpStream`，直连/原版中转/ChmlFrp 中转是同一接缝上的三个适配器，行为差异只剩 RTT 与
   节点限速（ChmlFrp 8–32Mbps 服务端强制，frp-compat §2.3）。

---

## 2. Flock VPN 总体架构

### 2.1 部署形态（对标 Tailscale「控制面集中、数据面分布」模型，vpn-mesh §2）

- **接入端点模型（硬约束落地，最高优先级）**：每台服务器暴露**一个接入端点**，形态二选一，
  由 `server.toml` 的 `listener.mode` 配置，**`Direct` 为缺省**：
  - `Direct`（缺省）：服务器直接监听公网/内网地址，客户端 TCP 直连——**零 frp 逻辑**
    （无 frpc 子进程、无配置生成、不装配 flock-frpc）；
  - `Frp(RelaySpec)`：仅当「服务端无公网 IP 或客户端无法直连服务端 IP」时选用——
    `flock-frpc` 托管 frpc（§3.9/§5）把监听口经中转节点暴露成用户口。
  两种形态对协议层完全同构（都是「一条 TCP 字节流」，§1.4），同一集群可按机器混布
  （server-a 直连、server-b 经中转、server-c 直连）。服务端互连（Raft + gossip +
  跨服转发）同理走直连或经各自接入路径，跑**服务器-服务器 profile** 的同一 E2E 会话协议
  （双向入群凭证认证，§4 准入）。
- **服务端 ×3 起**（Raft 奇数 voter，容 1 故障）：每台按上文二选一暴露接入端点；只有无公网
  IP/不可直连的机器才挂 FRP 中转节点（ChmlFrp 节点或自建原版 frps）并运行 `flock-frpc`。
- **客户端 ×N**（Windows/macOS/Linux 首发，Android/iOS 接缝预留）：`flock-client` 按
  ClusterDirectory 中的接入端点拨号——**直连地址或中转用户口客户端无感知差异**（都是 TCP
  拨号目标；tcp 代理形态下客户端本来就不需要 frpc，frp-compat §1.1 proxy 模型），持有
  「接入端点列表 + 探活切换」，任意服务端接入效果一致。
- 数据面：客户端 ↔ 服务端会话型隧道（首版 hub-and-spoke，peer 间经服务端路由；不做 P2P
  直连，vpn-mesh §6 明示首发策略）；任何链路形态下第三方只见本协议密文。
- 虚拟网：`100.64.0.0/10`（RFC 6598 CGNAT 段，Tailscale/NetBird 双先例，vpn-mesh §3.1），
  内部保留 /24 若干；分配由 Raft 状态机裁决（强一致防撞）；MTU 1280（Tailscale 同款、
  IPv6 下限，vpn-mesh §3.2）。
  **IP 复用策略（M7 修订，取代此前「禁用不删除、IP 不复用」的一刀切表述）**：
  - **吊销（Revoked）→ IP 永不复用**（不变；innernet 先例，安全优先，vpn-mesh §3.1）；
    禁用（Disabled）同理：行保留、VIP 不回收。
  - **离线超过保留期 → Expired + VIP 归还分配池**（新，M7）：回收器把「离线 > 保留期」
    的设备经 Raft 管理操作置 Expired 并释放其 VIP 回分配池——新设备可分到该 VIP；
    **过期记录本身保留在册**（审计可查），名册查询排除 Expired。窗口内重连同设备保持
    同 IP（未过期不动行）。保留期 = server.toml `peer_retention_days`（缺省 30 天；
    **0 = 永不过期**，兼容旧行为）。Expired ≠ Revoked：两者都阻断握手，但状态可区分
    （审计/名册语义不同——Expired 是时间性淘汰，Revoked 是安全处置）。

### 2.2 服务端（`app/flock-server`）

职责链：**接入 → 认证 → 注册表 → 会话 → 转发 → 同步**。

- 监听器（TCP :9443）：每条入连一个 E2E 会话（`session::respond`）。暴露形态 =
  `server.toml` 的 `listener.mode`（§3.11 ListenerMode 接缝）——**`Direct` 缺省**（直接
  监听，零 frp 逻辑）/`Frp(RelaySpec)`（flock-frpc Supervisor 路径）；**Direct 模式的代码
  路径不触碰 flock-frpc**（不实例化 Supervisor、不生成配置、不启动任何子进程）。
- 控制流（yamux stream 0，postcard 编码消息）：OPAQUE 登录（`anchor` 开：身份签名 + TOFU/
  邀请钉扎校验）→ 会话票据签发（本地短 TTL 票据，密钥根来自 Raft，VPN-15 下放）；
  设备注册/配置拉取（网络视图：peer VIP/公钥/路由）。
  - **票据强制契约（SR-SIG1 跨服重放面的闭合前提，必须写成接口契约）**：所有受 SR-SIG1
    保护的**状态变更**请求必须携带有效会话票据（绑定 device + revocation_epoch），且校验
    顺序 = 票据有效性（签名+TTL+epoch+吊销）**先于** nonce 记账；等效重放窗 =
    min(±300s, 票据 TTL)。没有这个前提，同一签名请求发给未见过 nonce 的另一台服务器即可
    重放（票据密钥根 Raft 共享、任何服务器都验得了，挡得住的只有「票据 TTL + epoch 失效」）。
- 设备管理：设备 = `(DeviceId=Ed25519 指纹, owner, VIP, 静态公钥集, status, hostname,
  expired_at)`（hostname/expired_at 为 M7 增补，§7-M7），全部进 `flock-sync` 强一致
  状态机。
  - **吊销传播界（数字定死，A6 据此可验证）**：吊销 = Raft 提交；每台服务器在**自己的
    日志 apply 回调**里 (a) 推进 revocation_epoch、失效记录缓存，(b) 杀死本地该设备会话，
    (c) 清拒其票据（票据 epoch < 当前 epoch 即拒）。即「踢会话」不需要额外广播——Raft
    复制本身就把吊销送到每台服务器的状态机。时序预算：健康集群（中转 RTT ~100ms、心跳
    500ms）commit→apply ≤2s + 事件余量 ≤1s + slack 2s ⇒ **A6 ≤5s 成立**；票据 TTL 60s
    硬顶兜住跨服重放。在线租约另有事件推送（≤1s）+ 5s 反熵（§4）。
- **数据面（含跨服务端转发——「任意服务端接入效果一致」的必要组成）**：服务端自身也是
  peer（有 tun + VIP 100.64.0.1…）。转发判定序：
  0. **源 VIP 绑定校验（第 0 步，先于一切转发逻辑）**：从 PacketChannel 读出的每个 IP 包，
     其**源地址必须等于该会话设备的注册 VIP**（会话 DeviceId ↔ src VIP 绑定）；失配 ⇒
     丢包 + 计数 + 超限告警/断会话。注意：§2.3 的 `rp_filter=1` 只作用于内核网络接口的
     入向，对经 yamux 流上来的用户态 IP 包**不生效**——此校验是应用层的「每节点入向过滤
     执行策略」（Tailscale/innernet 先例，vpn-mesh §2 借鉴点 3）。没有它，持有有效会话的
     恶意设备可用任意 peer 的 VIP 作源发包（身份嫁祸/反射/未来 ACL 全绕过）。ForwardEnvelope
     的 `src_dev` 字段同样与内层包源地址交叉校验（收端与发端各查一次）。
  1. 目标 VIP → 设备归属：查**本地租约表**（gossip）。**设备当前位置的唯一真相源 = 租约域**
     （每台服务器权威发布「连在我这的设备」+ 租约 TTL 30s + 事件推送 ≤1s + 5s 反熵）；
     **NetState（Raft）只存静态注册信息**（设备/VIP/公钥/状态/邀请消费记录），**不存
     「设备当前在哪台服务器」**——接入/切换是高频事件，实时写 Raft 会把重连风暴变成写
     风暴（R18 只防了读风暴），不实时写则映射陈旧、回退必然再错：双源真相不可取，定死
     单源。
  2. 归属本机 ⇒ 直接投该会话的 PacketChannel（同服路径）。
  3. 归属他机 ⇒ **跨服转发**：`ForwardEnvelope{ver, src_dev, dst_dev, origin_server,
     hop=1, payload=IP 包}` 经服务器互连 E2E 会话的专用 FRWD 流发出（外层有服务器间
     加密；内层 IP 包此时为明文——威胁模型见 §2.5）。收端：dst 在本地会话 ⇒ 投递；
     否则回 `NOT_HERE` 给 origin（**禁止二次转发**，hop=1 防环）。
  4. **租约未命中/陈旧的容错策略**（vpn-mesh §5.2 明示这是策略决策，此处定死）：
     设备刚迁移到另一台服务器时，旧租约窗口内的包发往旧服务器 → 旧服务器回 NOT_HERE →
     origin 发**一次性位置查询**（LocationQuery：问租约表里有该设备租约的服务器，或
     fan-out ≤3 台互连服务器「谁在托管 dst？」）重定向一次；仍失败 ⇒ **丢包 + 尽力发
     ICMP unreachable**（不广播、不缓存重试——VPN 流量丢包可由上层恢复，避免转发面状态
     膨胀）。设备上线/迁移的事件推送（≤1s）使该窗口通常短于租约 TTL。
  - Linux 路由配 rtnetlink（VPN-14）。
- `flock-frpc` 托管（§5）：配置生成 + 进程守护 + 健康探测。

### 2.3 客户端（`app/flock-client`）

- 接入器：接入端点列表（来自根签 ClusterDirectory 的 `access_endpoint`——直连地址或中转
  用户口，无感知差异）→ TCP 拨号 → `session::initiate`（带 ServerPin）；断线指数退避
  （5s 起步 + 抖动，wireguard-go RekeyTimeout 节奏，crypto-2026 §6）+ 端点轮询切换。
- tun 数据面：`tun-rs 2.8.16`（平台矩阵最全、活跃度最高、内置 wintun/iOS fd/Android
  establish 示例，vpn-mesh §1.2）创建 TUN（MTU 1280）；IP 包 ↔ `PacketChannel`。
  **接缝**：`TunDevice` trait（open/read/write/close），平台适配器 = tun-rs 原生、
  Android `VpnService` fd 传入 + `protect()`、iOS `NEPacketTunnelProvider` fd 传入
  （vpn-mesh §1.1：两平台无 native 等价 API，fd 必须由上层框架注入——这是库必须留的缝）。
- 路由：Linux rtnetlink 0.23.0（/16 池指向 TUN + rp_filter=1 反向路径过滤，innernet 建议，
  vpn-mesh §3.3）；Windows 用 wintun 路由 API；Android 走 `VpnService.Builder` 路由参数。
- TCP-over-TCP 缓解：内层单流限速与队列管理（避免多内层流放大争抢；弱网坍缩机理见
  vpn-mesh §3.2）；P2P 直连列远期路线（自建节点 xtcp），首版不做。

### 2.4 密钥与会话生命周期

| 阶段 | 密钥/凭据 | 生命周期 |
|---|---|---|
| 引导 | 邀请文件 v3（集群根公钥+根签 ClusterDirectory 全套服务器材料+一次性 invite_id）或 TOFU 首连 2-RTT 引导后**钉扎集群根公钥** | 根公钥变更 = 显式告警 + 人工确认；单台服务器换钥 = 根签新目录条目 + dir_pull 刷新（合法变更不告警） |
| 登录 | OPAQUE（密码不上线）+ 服务端身份签名 | 每次登录重新执行；成功 → 会话票据（短 TTL，本地签发） |
| 设备注册 | 设备静态密钥（X25519 会话用 + Ed25519 身份用，客户端生成永不出机） | 注册进 Raft；吊销即全网失效 |
| 隧道会话 | 1-RTT 握手派生双向密钥（混合 KEM ⇒ 前向保密 + PQ） | rekey 双阈值 2^60 包/120s；180s/2^64−2^13−1 硬拒绝；断链重连=全新握手 |
| 服务端身份密钥 | Ed25519（可选 ML-DSA 并行） | 长期；轮换=新密钥+老密钥并行期+客户端重钉扎流程 |
| OPRF key | OPAQUE 服务端密钥（Raft 状态机内，加密封装到各服务器混合公钥） | 常驻（轮换使全部 pass.opaque 失效——showroom 同语义，showroom-analysis §5） |
| 共享秘密封装 | 状态机内秘密逐服务器封装（envelope v2 到各自 HybridPubkey） | 「按服务器独立密钥/逐次重封装」权限点：新增服务器 = re-wrap（VPN-15） |

前向保密链：握手一次性 DH/KEM 份额 → 每 120s（或 2^60 包）rekey 换新份额 → 旧密钥擦除。
重放状态分级归属（verdict §3.6 多主多活约束）：**隧道数据面** = 会话级计数器（随会话归属
单一服务端，无需共享）；**控制面关键一次性操作**（bind_token/票据换发）= Raft 线性一致查重
（低频，写放大可接受）；**SR-SIG1 请求 nonce** = 本地 ±300s 窗 + **票据强制契约**（§2.2：
状态变更请求必带有效票据、票据校验先于 nonce 记账、等效重放窗 = min(±300s, 票据 TTL 60s)）
收窄跨服重放面（如实记录：高频请求级 nonce 非强一致，靠票据 TTL 闭合，这是工程取舍）。

### 2.5 威胁模型边界（明确声明，防止安全主张被误读为 peer 级 E2E）

1. **跨 peer 流量在接入服务器明文**：首版 hub-and-spoke（§2.1/§2.2）意味着客户端↔客户端
   流量在接入服务器**解密后转发**（跨服路径在外层有服务器间加密，但每台服务器内部仍是
   明文）。这与 Tailscale「协调服务器无法解密」（vpn-mesh §2/S18）的属性**根本不同**：
   任一台在册服务器可观察/篡改全部经其转发的跨 peer 流量。缓解：服务器主机加固 + 准入
   控制（§4）；**远期**：peer 间端到端 overlay 加密层（客户端-客户端内层会话，服务器退化为
   盲转），列入路线图但不在本设计范围。
2. **任一服务器可离线字典全部口令**：OPRF key 逐服务器封装（§2.4 表）⇒ 攻破任一台在册
   服务器即得 OPRF key，可对全部用户口令做离线字典（OPAQUE aPAKE 模型内 OPRF key 持有者
   即有此能力——showroom 同语义，showroom-analysis §5；argon2id 档位是唯一减速带）。
   缓解：服务器密钥 0600/内存驻留 + 准入红线（§4：伪节点拿不到 key）；**远期**：OPRF key
   门限化（quorum 解封）。此为接受边界，写进部署文档。
3. **TOFU 不防首登在线 MITM**（§1.3.3f 残余风险）：个人自建可接受；组织场景强制邀请文件。
4. **中转与链路**：FRP 中转/链路观察者只见密文与长度（长度侧信道对策见压缩档 P0-4）；
   ChmlFrp 面板凭据通道风险见 §5/R 表（R20）。

---

## 3. 模块划分（ModuleSpec）

每个 spec：**接口**（调用方需知的一切）· **接缝**（接口落点、谁可替换）· **实现要点**。
深模块检验：接口方法数 ≤5、安全前提进类型/契约、删除测试（删掉则复杂度回到 N 个调用方）。

### 3.1 `flock-protocol::kem`（混合 KEM 原语）
- **接口**：`HybridKeypair/HybridPubkey/HybridCt` 三类型 + `encapsulate/decapsulate/fingerprint`
  三函数（§1.3.3a）。
- **接缝**：KEM 算法槽位——`trait KemGroup` 内部缝（X25519、ML-KEM-768 各一实现），未来
  换 ML-KEM-1024/纯 PQ 不动调用方。
- **实现要点**：ml-kem 0.3.3 + x25519-dalek 3.0.0；HKDF 合流；`legacy` 下 RSA-OAEP 只读。

### 3.2 `flock-protocol::envelope`（文件信封 v1/v2）
- **接口**：`seal_v2(recipient, plain_reader, out) -> SealInfo`、`open_v2(sk, in, out)`、
  `open_v1_legacy(rsa_sk, in, out)`；SealInfo 含 envelope_id/段数/总长。
- **接缝**：封装算法（头的 ver 字节分派 v1/v2）；段 AAD 构造为内部实现细节。
- **实现要点**：v2 头 1137B（§1.3.3b）；流式恒定内存（沿用 showroom seal/open 缓冲模型，
  showroom-analysis §4.1）；AAD=ver‖id‖seg_idx‖is_final；长度不变量测试（v1 的测试思想平移）。

### 3.3 `flock-protocol::sig`（SR-SIG1 + 密钥档案）
- **接口**：v1 兼容五函数（§1.3.2）+ `KeyProfile::verify_dispatch(kid)`（kid→Ed25519/ML-DSA）。
- **接缝**：kid 算法分派表——`ProfileKey` enum 扩展新算法零调用方改动。
- **实现要点**：ed25519-dalek 3.0.0；预哈希流式签名保留；`pq-sign` off by default
  （ml-dsa 0.1.1 未审计，crypto-2026 §5——如实标注）。

### 3.4 `flock-protocol::pake`（OPAQUE + 身份锚）
- **接口**：showroom 兼容函数族 + `login_finish_anchored(...) -> (SessionSeed, ServerIdentity)`
  （`anchor` feature）；`rwd(pw, user, profile)`。
- **接缝**：argon2 profile 参数化（版本化升级不破老记录）；锚签名层可开关（showroom 先关）。
- **实现要点**：opaque-ke 4.0.1；固定向量互通测试（3.0.0 记录样本 → 4.0.1 可解，M1 守门）；
  RFC 引用 9807；dummy 假记录防枚举保留。

### 3.5 `flock-protocol::session`（会话/记录层/握手）
- **接口**：`initiate/respond(async)/Tunnel{async open_stream, async open_packet_channel, stats}`
  （§1.3.3c）；握手双形态：已钉扎 1-RTT / TOFU 首连 2-RTT 引导。
- **接缝**：`trait DeviceDirectory: fn lookup(&self, &DeviceId) -> BoxFuture<LookupVerdict>`
  （异步 + 三态 NotFound/Revoked/Active——服务端把注册表/吊销查询注入协议库，多主多活的
  权限点之一；线性一致读是网络往返，同步签名不可实现）；`AeadPreference`（算法协商档）；
  `DeviceStaticKeys`（设备密钥注入，Android/iOS 由上层钥匙库供）。
- **实现要点**：P0-2 全部纪律内建（计数器 nonce/双阈值 rekey/硬拒绝/伪造断链）；Noise IK
  结构自研（不用 snow——其 CVE 史与无法插 KEM 槽位，crypto-2026 §5/§3.1）；**设备签名覆盖
  I1 全字段 + 协议上下文（cluster_id/期望身份指纹）——防 UKS，M1 有对应失败向量**；
  transcript 哈希链 + 测试向量（M1）；严格递增计数校验 + 窗口结构留 UDP 路径。

### 3.6 `flock-protocol::mux`（yamux 承载与包通道）
- **接口**：`Stream`（AsyncRead/Write + 显式 `finish()`）、`PacketChannel::send(pkt)/recv_stream()`、
  `Prio` 调度档。
- **接缝**：复用器实现——`trait Multiplexer` 内部缝（yamux 适配器为唯一首发实现；第二个
  适配器出现前不外露该 trait——「一个适配器=假想缝」纪律，SKILL.md 原则）。
- **实现要点**：rust-yamux 0.14.1 跑在 SecureStream 内；控制流 stream 0 高优先级；
  keepalive = yamux ping 10s；FIN 表达单向结束（禁半关闭）。

### 3.7 `flock-protocol::compress`（压缩档位）
- **接口**：`CompressPolicy` + `compress_frame/decompress_frame`（§1.3.3e）。
- **接缝**：策略档位（Off/Interactive/Bulk/Archive）+ 字典版本协商（dictID 进握手扩展）。
- **实现要点**：zstd 0.14.3（Windows/MSVC 已证可编译，compression-2026 §5）+ lz4_flex 0.14；
  非膨胀回退 MUST；默认 Off + 填充联动。

### 3.8 `flock-protocol::trust`（TOFU/邀请）
- **接口**：`PinStore`（钉扎粒度 = cluster_id → 集群根公钥）、`InviteFile`（v3：根签
  ClusterDirectory 全套服务器接入材料 + 一次性 invite_id + expiry 默认 7 天，§1.3.3f）、
  `ClusterDirectory/ServerEntry`（= §4 入群凭证公开部分；`access_endpoint` = 接入端点——
  Direct 直连地址或 Frp 中转用户口，**客户端无感知差异**，选路/探活逻辑不分形态）、
  `fingerprint`、集群根密钥/入群凭证类型（§4 准入用）。
- **接缝**：钉扎存储（文件适配器首发；钥匙库适配器给移动端）；邀请文件版本（v2 单服务器
  材料与 v1 指纹-only 均不再接受——多服务器集群下无法支撑任意端点 1-RTT）；目录刷新
  （dir_pull，根验签 + dir_version 递增）。
- **实现要点**：known_hosts 语义（集群根级）；指纹展示格式（8 组 hex）；根公钥变更告警
  不可静默跳过；invite_id 单次消费语义由 flock-sync 的 Raft 状态机保证（库只做结构校验）；
  **文档必须内嵌 TOFU 残余风险声明**（不防首登在线 MITM，组织走邀请强路径）。

### 3.9 `crates/flock-frpc`（frpc 子进程托管，VPN-16）
- **接口**：`Supervisor::start(spec: RelaySpec) -> ManagedRelay`；
  `RelaySpec::ChmlFrp{mode: ChmlFrpMode} | Original{toml}`，其中
  `ChmlFrpMode::ConfigFile(ini_path)`（**默认**：面板「隧道管理→配置文件」粘贴导出的
  frpc.ini，走 `-c` 模式）| `ChmlFrpMode::UserTokenAuto{usertoken, tunnel_id}`（legacy
  可选：`-u/-p` cfg API 自举）；`health() -> RelayStatus`。
- **接缝**：frpc 变体（ChmlFrp v0.51.2 定版二进制 / 原版 v0.71.1 定版二进制）+ 配置生成器
  （golden-file 测试，R8/R12：**不改面板生成的 proxy 参数**——CheckProxy 会拒，frp-compat §2.3）。
- **实现要点**：进程守护（ChmlFrp frpc 三次重连失败即退出——魔改行为，frp-compat §2.3——
  退出即拉起 + 指数退避）；健康探测（本地隧道口 + frpc admin）；版本矩阵锁（R9：ChmlFrp 节点
  ⇔ ChmlFrp frpc、自建节点 ⇔ 同代原版 frpc，禁交叉——两代控制面互不兼容，frp-compat §1.3）；
  **usertoken 安全档**：`-u/-p` 自举的 cfg API 是 InsecureSkipVerify 的 HTTPS
  （frp-compat §2.2，chml/pkg/api/api.go:30-46），面板全权凭据可被中间人截获 ⇒ 默认走
  `-c` 配置文件模式，UserTokenAuto 保留但文档标注风险（R20）。仅服务端
  `listener.mode = Frp` 时装配（Direct 模式零 frp 逻辑，§3.11）；tcp 代理形态下客户端
  直连用户口、自身从不需要 frpc。

### 3.10 `crates/flock-sync`（多主多活，VPN-15）
- **接口**：`NetState::{register_device, revoke, allocate_ip, redeem_invite,
  revoke_invite, config_version, server_keys, rewrap, admin_op}`（写，经 Raft 提交；
  admin_op = add_voter/rewrap/revoke_invite，须集群根密钥签名；**NetState 不存设备当前位置
  ——静态注册信息与邀请消费记录而已**）+ `read_linearizable(...)` + `LeaseTable::{publish,
  observe, location_query}`（gossip：事件推送 ≤1s + 5s 反熵；租约 TTL 30s；**设备当前位置
  的唯一真相源**；location_query = 一次性跨服位置询问，fan-out ≤3）+ `TicketIssuer::
  issue/verify`（本地签发，TTL 60s，带 revocation_epoch）+ `Enrollment`（入群凭证验证/
  轮换，§4）+ `Directory::serve(dir_pull)`（向客户端下发根签 ClusterDirectory，§1.3.3f）
  + 跨服转发承载（互连会话 FRWD 流上的 ForwardEnvelope，§2.2）。
- **接缝**：状态机存储（redb 适配器首发）；Raft 网络传输（直接 TCP / 经中转 TCP——都跑
  **服务器-服务器 profile** 的 E2E 会话：双向入群凭证 + transcript 签名，无凭证即拒）；
  gossip 传输（复用服务端互连会话）。
- **实现要点**：openraft 0.9.25 稳定线（0.10 仍是 alpha，vpn-mesh §5.1）；redb 单文件嵌入
  （纯 Rust，契合「无共享数据库」部署形态）；apply 回调推进 revocation_epoch + 杀本地会话
  （§2.2 吊销传播界）+ **apply-lag >2s 熔断本地缓存、降级线性一致读**（§4 读与缓存）；
  learner→快照→add_voter→rewrap 准入流水（§4）；租约冲突 = 新者胜 + 旧端踢会话
  （vpn-mesh §5.2）；invite_id 单次消费在 Raft 内查重（§1.3.3f 邀请一生）。
  M7 增补（§7-M7）：租约条目携带 per-device EWMA 流量与 last_seen（动态面搭租约
  便车，不进 Raft）；注册表支持 Expired 状态与 VIP 归还分配池（§2.1 IP 复用策略
  修订）。

### 3.11 `app/flock-server`（服务端装配）
- **接口**：`flock-server --config server.toml` / `init-cluster` / `enroll`（进程入口）
  + 控制流消息协议（版本化，票据强制契约见 §2.2；含 dir_pull/开户兑换流程 §1.3.3f）。
- **接缝**：`ListenerMode`（接入端点形态，server.toml `listener.mode`，**Direct 缺省**）：
  ```rust
  enum ListenerMode {
      Direct { bind: SocketAddr },                 // 直接监听公网/内网地址——零 frp 逻辑，
                                                   // 代码路径不触碰 flock-frpc（不实例化
                                                   // Supervisor/不生成配置/不启动子进程）
      Frp { bind: SocketAddr, relay: RelaySpec },  // 无公网 IP/不可直连时：本地监听 +
                                                   // flock-frpc Supervisor 托管中转（§3.9/§5）
  }
  ```
  对下注入 session::respond 的 `DeviceDirectory`（= 「NetState 缓存 + epoch 两级读 + lag
  熔断」，§4 读与缓存）；对上挂 tun 适配器、flock-sync（含 FRWD 转发面）与
  **仅 Frp 模式下的** flock-frpc（装配期按 mode 分派，Direct 分支无 flock-frpc 类型引用）。
- **实现要点**：tokio 运行时；每入连一会话任务；转发面 = **第 0 步源 VIP 绑定校验** →
  租约表定位 → 本机投递或 ForwardEnvelope 跨服转发（NOT_HERE → 一次性 location_query
  重定向 + hop=1 防环 + 失败丢包/ICMP，§2.2）；吊销在 apply 回调内本地执行（无额外广播依赖）。

### 3.12 `app/flock-client`（客户端装配）
- **接口**：`flock-client --config client.toml` / `flock-client invite <file>`。
- **接缝**：`TunDevice` trait（tun-rs 适配器首发；Android/iOS fd 注入适配器接缝预留）；
  接入端点列表（来源 = 邀请文件/钉扎目录中的根签 ClusterDirectory，可 dir_pull 刷新、
  可探活切换——任意端点均 1-RTT，§1.3.3c/§1.3.3f）。
- **实现要点**：路由配置（rtnetlink/wintun/VpnService 参数）；接入器退避重连；数据面
  IP 包 ↔ PacketChannel；MTU 1280。

---

## 4. 多主多活同步方案（择型：openraft 强一致状态机 + gossip 租约）

**选择**：调研推荐的第一阶段形态——「openraft 复制状态机（设备注册表/凭证/配置版本）+
gossip 租约（在线状态）+ 会话票据本地签发」（vpn-mesh §5.3）。

**理由**（逐条对调研证据）：
1. 数据分三类定机制（vpn-mesh §5.2）：注册表/IP 分配/吊销要**强一致**（IP 撞车=脑裂事故、
   吊销必须全序及时）——Raft 甜区，openraft `ensure_linearizable` 恰好满足「任意服务端接入
   效果一致」；在线状态秒级陈旧可接受——gossip 租约；网络配置是派生数据——状态机版本化。
2. 明确不选 CRDT（吊销无全序保证）、纯 gossip（IP 分配可脑裂）、共享 DB（把多主问题转嫁给
   数据库且要求库独立可达，与「每服务端一个中转节点、无共享内网」形态不契合；NetBird 自托管
   HA 本就是商业版功能，同类项目里多主多活不是默认能力，vpn-mesh §2/§5.3）。
3. openraft 是 Rust 生态最成熟的 Raft（Databend 生产使用、混沌测试进 CI、0.9.25 稳定线，
   vpn-mesh §5.1/S35）；服务端互连跑我们自己的 E2E 会话协议 ⇒ 同步链路也有加密/认证/重连
   语义，不另造协议。

**要点**：3 voter 起（容 1 故障）；写转发 leader（多一跳中转延迟，写少场景可忽略）；
票据密钥根在 Raft、短 TTL 票据本地签发（登录路径不依赖 leader，vpn-mesh §5.3 第二阶段
能力直接吸收进首版）；选举/心跳超时按中转 RTT 调参（默认心跳 500ms/选举超时 1.5s，
M4 注入 100ms RTT 校准）；重放状态分级归属见 §2.4。

**读与缓存（防重连风暴打穿 leader）**：`DeviceDirectory`（§1.3.3c）的服务端实现 =
「设备记录缓存 + revocation_epoch（随 Raft 日志 apply 自动推进，**无需额外广播即全网
收敛**）」两级——epoch 未变且缓存命中 ⇒ 本地答；epoch 前进 ⇒ 失效缓存、下次查线性一致读。
中转断链后的 N 客户端重连风暴在无吊销时全部命中本地缓存，leader 只承接真正的全局序变化。
`ensure_linearizable` 保留给「必须读到最新」的少数路径（如管理员侧查询）。
**陈旧读边界的披露与熔断（诚实声明健康前提）**：follower 落后时（分区恢复/追赶中）其本地
epoch 是旧值且「未变」，缓存中的 Active 记录照常命中放行——**leader 已 commit 的吊销在本地
apply 之前挡不住新握手**，窗口 = follower 日志落后时长（正常 < 心跳 500ms；分区恢复后可达
秒级以上）。对策（熔断）：心跳/AppendEntries 携带 leader commit index，follower 自监听
apply lag，**lag > 2s（= A6 时序预算）即停用本地缓存路径、降级线性一致读**，追平后恢复；
叠加兜底 = 会话票据 epoch 校验（票据 TTL 60s 内必然经过一次本地 apply 点）。M4 测试含
「follower 人为落后 5s 时吊销仍被拦截」用例。A6 的 ≤5s 因此带显式健康前提：健康集群或
熔断生效时成立，失联且 lag>2s 的节点已被熔断降级。

**服务器间信任引导与集群准入（M4 开工前提，安全关键）**：

1. **集群引导**：运维运行 `flock-server init-cluster --voters 3` 生成**集群根密钥**
   （Ed25519，离线保管，只签名不组网）与每台初始 voter 的**入群凭证（enrollment cert）**
   = `{cluster_id, server_id, role, identity_pub, static_hybrid_pub, raft_addr, access_endpoint,
   expiry}` 的根密钥签名。每台服务器持有：自己的身份/静态混合私钥 + 自己的入群凭证 + 集群
   根公钥。**同一信任根两用**：入群凭证的公开部分（ServerEntry，§1.3.3f）就是客户端接入
   材料——根密钥既做服务器互认（本节）也签客户端邀请文件/集群目录（§1.3.3f），不引入第二
   个信任根。
2. **互连认证**：服务器互连（Raft/gossip/跨服转发）跑 E2E 会话协议的**服务器-服务器
   profile**——双向要求对方出示入群凭证并以凭证内身份密钥对 transcript 签名；无有效凭证
   的对端在握手层即被拒。openraft 网络适配器只挂在该认证会话之上 ⇒ **攻击者拉起伪节点
   既拿不到快照也进不了 Raft**（若只靠 Raft 层弱认证，伪节点可索要快照与 re-wrap——
   rewrap 即解封 OPRF key，全网口令离线字典面被打开，此为本设计的红线）。
3. **新节点准入（授权路径定死）**：运维用集群根密钥签发新节点入群凭证 → 新节点以
   **learner** 加入（openraft 动态成员，joint 共识）→ 快照同步 → 运维发起 Raft 管理操作
   `add_voter`（请求体带集群根密钥签名，状态机验签后生效）→ 提升为 voter；**secrets
   rewrap（把 OPRF key 等逐服务器封装扩到新服务器）是另一个独立的管理操作**
   `rewrap(server_id)`，同样要求集群根密钥签名——被入侵的单台在册服务器没有根密钥，
   无法自授准入、无法触发 rewrap。
4. **凭证轮换**：入群凭证带 expiry；轮换 = 根密钥签新凭证 + Raft 提交生效窗口
   （新旧并行的最小窗口），集群根密钥泄露 = 全网重引导（文档明示为灾难恢复路径）。

---

## 5. FRP 兼容策略（择型：方案 A 子进程托管，双栈定版）——**可选适配器，非前提**

> **硬约束（§0）**：frp 只服务于「服务端无公网 IP 或客户端无法直连服务端 IP」的场景；
> `listener.mode = Direct`（缺省）时**不执行任何 frp 相关逻辑**。本章全部内容仅适用于
> 显式选择 `Frp` 形态的服务器。

**选择**：frp-compat §3 的**方案 A**——子进程托管两套定版 frpc：ChmlFrp 节点用
`ChmlFrp-0.51.2_251023`（已有 Linux 包：`.tmp/chmlfrpc/ChmlFrp-0.51.2_251023_linux_amd64/`，
本次核实存在），自建/原版节点用原版 frp v0.71.1（Linux 官方包本次下载并容器内执行验证：
`frps --version` → `0.71.1`，FRPS_LINUX_OK）。

**理由**（frp-compat §0.4/§3）：
1. ChmlFrp 基于 v0.51.2（无控制面加密）与原版 ≥v0.53.0（强制 AES-128-CFB）**两代互不兼容**
   （§1.3 源码级证实）⇒ A 是唯一「同时兼容两家且零协议维护成本」路径。
2. B（Rust 原生实现）撞上 v1→v2 wire protocol 过渡期（v1 计划 v0.78.0 移除）+ 需对齐 ChmlFrp
   魔改鉴权/CheckProxy 命名——投入产出比最差的时间点；列远期演进。
3. C（visitor/xtcp）在 ChmlFrp 不可用（面板建不出 stcp/xtcp + CheckProxy 拒绝，§2.4）；
   仅自建节点可作远期 P2P 加速层，主链路不走。
4. 已知短板全有工程解：ChmlFrp frpc 三次重连退出 → 守护拉起（§3.9）；proxy 参数不可自创
   （CheckProxy）→ golden-file 配置生成（R12）；单隧道多会话 → yamux 复用（R11）。
5. 协议层一致性断言集：R1–R12（frp-compat §4）作为 §6 Docker 断言与 M2/M5 验收用例来源。

---

## 6. Docker 多机互连实测拓扑（Windows 主机 + Docker Desktop Linux 容器）

### 6.1 可行性核实（本会话全部实际执行，命令与输出见附录 B）

| 项 | 结果 | 命令（摘要） |
|---|---|---|
| Docker 后端 | Docker Desktop 29.8.2 / Engine 29.8.2，**WSL2**（内核 6.18.54.1-microsoft-standard-WSL2） | `docker version` / `docker info` |
| `/dev/net/tun` 直通 | **可行**：`--cap-add NET_ADMIN --device /dev/net/tun` 下 `ip tuntap add` + `ip addr add 100.64.0.1/32` 成功（TUN_CREATE_OK） | 见附录 B-2 |
| `mknod` 回退 | **可行**：无 `--device` 时容器内 `mknod /dev/net/tun c 10 200` + 建设备成功（MKNOD_PATH_OK） | 附录 B-3 |
| 原版 frps Linux 二进制 | **可行**：官方 v0.71.1 linux_amd64 下载（14,140,587B）+ 容器内 `frps --version`→`0.71.1` | 附录 B-4 |
| ChmlFrp Linux 包 | 已在 `.tmp/chmlfrpc/ChmlFrp-0.51.2_251023_linux_amd64/`（frpc+frps+ini，本次 ls 核实） | 附录 B-5 |
| Windows 主机工具链 | Rust 1.98.1（msvc + linux-gnu + wasm32 目标已装） | 附录 B-6 |
| 未验证（如实声明） | 容器内 Rust 镜像构建未跑（仓库尚无代码，无事可建）；Hyper-V/Docker VMM 后端 CONFIG_TUN 未核（vpn-mesh §1.3 限制——**部署约束写死 WSL2 后端**） | — |

### 6.2 拓扑（deploy/e2e.yml，三网隔离——单网段会让「模拟不可信公网」名不副实）

```
网络划分（关键：Frp 形态的 server-a/b 对 flockpub 不可直连，杜绝实现走直连回退骗过断言；
server-c 故意以 Direct 形态直挂 flockpub——两种 listener mode 同拓扑共存，验证硬约束）：
  flockpub  172.28.0.0/24  bridge，模拟不可信公网——挂 frps、frpc 边车、client、
                          以及 Direct 形态的 server-c；密文流经它
  srvmesh  172.29.0.0/24  internal——只挂三台 server（Raft/gossip/FRWD 互连，不出公网）
  link-a/b 各 /30 内联网——frpc 边车 ↔ 对应 server（边车把 server:9443 经中转暴露出去）

frps-a   [flockpub]  原版 frps 0.71.1  :7000(frpc 控制) :23000(用户口A)
frps-b   [flockpub]  原版 frps 0.71.1  :7000           :23001(用户口B)
frpc-a   [flockpub+link-a] frpc 0.71.1 → 注册到 frps-a，转发至 server-a:9443
frpc-b   [flockpub+link-b] frpc 0.71.1 → 注册到 frps-b，转发至 server-b:9443
server-a [link-a+srvmesh]  flock-server listener.mode=Frp   tun0 VIP 100.64.0.1
server-b [link-b+srvmesh]  flock-server listener.mode=Frp   tun0 VIP 100.64.0.2
server-c [flockpub+srvmesh] flock-server listener.mode=Direct（缺省）:9443 直挂公网
                                                                  tun0 VIP 100.64.0.3
         （C 为 Raft 仲裁 voter：2 节点 Raft 容错为 0，故障切换断言需 3 voter——
           对题目「服务端×2 各挂中转」的必要扩展，理由见 §4；第四轮起 C 兼任
           Direct 形态样板：无 frpc 边车、无 frp 进程，接入端点=172.28.0.22:9443）
client-1 [flockpub] flock-client  tun0 VIP 100.64.0.11  ——配置钉死经 frps-a:23000 接入
client-2 [flockpub] flock-client  tun0 VIP 100.64.0.12  ——配置钉死经 frps-b:23001 接入
client-3 [flockpub] flock-client  tun0 VIP 100.64.0.13  ——配置钉死直连 172.28.0.22:9443
         （钉死映射是断言语义要求：A2 的 client-1↔client-2 互 ping 必然跨服（server-a↔server-b
           的 ForwardEnvelope 路径），不能让两 client 连同一服务器绕过跨服转发面）
（client-N 可复制；全部 flock 容器 --cap-add NET_ADMIN --device /dev/net/tun，MTU 1280）
```

服务端容器内：`flock-server` 监听 :9443——server-a/b 仅 link 网可达（经 frpc 边车暴露成
frps 用户口 23000/23001）；server-c 以 Direct 形态直接监听 flockpub 地址（**容器内无 frpc
边车、无任何 frp 进程**）。客户端拨接入端点（直连地址或中转用户口，逻辑同构，§2.1）。
Frp 形态生产部署中 frpc 是 server 进程内子进程（§3.9），测试拓扑用独立边车容器只是组网
需要——同一 Supervisor 代码两种部署。
构建：Windows 主机写码与跑主机单测；Linux 二进制在容器内构建——构建镜像的 C 工具链问题
**本会话已实测闭环**（修订轮，附录 B-9）：`rust:1-slim-bookworm` 实测自带 `/usr/bin/cc`、
`/usr/bin/gcc`（Debian gcc 12.2.0），且在该镜像内 `cargo add zstd@0.14 && cargo build
--release` 编译 zstd-sys 2.1.2（vendored C 源）**成功**（7.67s，ZSTD_BUILD_CHECK_DONE）
——默认 feature 含压缩模块的构建不会在 zstd-sys 处挂掉。镜像 tag 钉 digest（或 `rust:1` +
CI 校验 `rustc --version` ≥1.98）；若追求更稳可用完整版 `rust:1-bookworm`。
自动化基线用原版 frp ×2（ChmlFrp 真实节点需实名账号，frp-compat gaps#1——留手工清单项，
协议字节流一致性由 §1.4 论证 + R8/R12 golden-file 覆盖配置侧）。

### 6.3 断言清单（deploy/e2e_assert.sh，M5 验收 = 全 PASS）

| # | 断言 | 通过标准 |
|---|---|---|
| A1 | 字节透传 | 复用 frp-compat T1/T2 harness：经两条中转各 echo 回 1MiB 随机 + 全 256 字节值，sha256 一致（R1/R2） |
| A2 | 隧道连通（含跨服） | client-1 `ping -c 3 100.64.0.1` 0 丢包（同服路径）；client-1↔client-2 互 ping 通——接入映射钉死 client-1→frps-a、client-2→frps-b，此互 ping **必然走跨服转发**（§2.2 ForwardEnvelope 路径） |
| A3 | MTU | `ip link show tun0` 含 `mtu 1280`；`ping -c 2 -s 1252 -M do 100.64.0.1` 通（1252+28=1280） |
| A4 | 吞吐基线 | iperf3 over 隧道 ≥ 100 Mbps（本地中转无 8Mbps 限速；记录数值供回归对比，R7） |
| A5 | 中转故障切换 | `docker stop frps-a` → client-1 在 ≤30s 内切换 `frps-b:23001`（= server-b 的端点，用 ClusterDirectory 中 server-b 的 ServerEntry）完成全新握手——**1-RTT 已钉扎形态，I0 不得出现**（钉扎模型 §1.3.3f 的直接验证），VIP 不变，ping 恢复；断言依据：客户端配置只含根签目录内端点列表（R6） |
| A6 | 多主吊销生效（参数化） | 经 server-b 吊销 client-2 → 各 server 在 Raft apply 回调内杀本地会话 + revocation_epoch 前进 → server-a 上会话被踢 + 新握手被拒 + 票据 epoch 检验失效；≤5s（预算：commit→apply ≤2s + 事件余量 ≤1s + slack 2s，§2.2；票据 TTL 60s 兜底） |
| A7 | Raft 容错 | `docker stop server-a`（含其 frpc）→ B/C 仍有 quorum，A2/A6 全量重跑通过；重选举 ≤15s |
| A8 | 单隧道多会话 | 100 并发 yamux 流持续 60s 无错（R11） |
| A9 | keepalive 断链检测 | `docker network disconnect` 模拟静默死链 → 双侧 ≤3×10s 内检测并进入重连（R5） |
| A10 | rekey 无感 | iperf3 持续负载 ≥5min，epoch 递增 ≥2 次，吞吐无 >1s 平台（P0-2） |
| A11 | 压缩默认关 | 默认配置抓记录长度=原始+常数开销；开压缩档后非膨胀回退生效（P0-4） |
| A12 | 抗重放（单元级注入） | 会话层注入重复/回退计数记录被拒且计入伪造限额（M1 单测在 M5 复跑入口） |
| A13 | 无直连回退（拓扑有效性，Frp 形态服务器） | 从 client-1 容器 `timeout 2 bash -c '</dev/tcp/172.28.0.20/9443'`、`…/172.28.0.21/9443` 对 server-a/b 的 flockpub 直连失败（两台不挂 flockpub ⇒ 必须失败，否则 A1/A5 的「经中转」语义已被绕过；server-c 除外——它是 Direct 形态，本就该直达，由 A16 正面断言） |
| A16 | Direct 形态（硬约束守门） | client-3 直连 `172.28.0.22:9443` 完成 1-RTT 握手（同一 ServerEntry 材料体系）且 ping 100.64.0.3 通；client-1/2 ↔ client-3 互 ping 通（Direct↔Frp 跨服转发同构）；server-c 容器内 `pgrep -f frp` 无任何进程、无 frpc 边车容器（Direct 模式零 frp 逻辑的运行时证明） |
| A14 | 跨服转发面 + 源 VIP 校验 | client-1（挂 server-a）↔client-2（挂 server-b）互 ping 的抓包计数：server-a 的 FRWD 流出现 ForwardEnvelope（非零计数），且 kill srvmesh 连接后互 ping 断、本服 ping server-a 仍通（隔离跨服面故障）；另以 client-1 内 `hping3/scapy` 伪造 src=100.64.0.12（client-2 的 VIP）发包 ⇒ server-a 丢包计数递增、client-2 收不到（§2.2 第 0 步源 VIP 绑定校验） |
| A15 | 租约陈旧容错 | 迁移 client-2 配置从 frps-b 切到 frps-a 并重启（新端点握手同样 1-RTT），旧租约窗口内 client-1→client-2 丢包 ≤ 租约 TTL(30s)+反熵(5s) 后恢复（§2.2 容错策略：NOT_HERE→location_query 重定向路径被走到，FRWD 计数可见重定向帧） |

---

## 7. 里程碑拆分（每个有可验证完成标准）

### M1 协议库（crates/flock-protocol）
范围：§1.3 全部档位 + 兼容面 + feature 矩阵；upgradeList 落位 P0-1/2/3/4/5、P1-6/7/8/9/10、
P2-11/12/13（协议库部分）。
完成标准（全部可跑）：
- `cargo test -p flock-protocol --all-features` 全绿，其中必须包含：
  - OPAQUE 向量：showroom 3.0.0 生成的注册记录/登录样本在 4.0.1 下互通（P2-11 守门）；
  - 信封 v1 只读兼容：showroom `seal` 产物被 `open_v1_legacy` 解开且长度不变量断言通过（P0-1 兼容档）；
  - 信封 v2 AAD：段重排/拼接/删尾用例必须失败（P0-3）；
  - 会话纪律：重复计数拒、120s 注入时钟触发 rekey、180s 硬拒绝、伪造 N 次断链（P0-2）；
  - **握手双形态**：已钉扎 1-RTT 全向量；TOFU 首连 2-RTT（I0→R0→I1→R1）状态机向量；
    邀请文件 v3（含集群根公钥+全套服务器材料）→ 任意端点首连即 1-RTT；
  - **UKS/绑定失败向量（防未知密钥共享）**：篡改协议上下文（cluster_id/期望身份指纹）或
    替换服务器身份 → 设备签名/服务器签名验签必须失败（§1.3.3c 签名覆盖契约）；
  - **DeviceDirectory 假实现三态**：NotFound/Revoked/Active 各自的握手行为（前两者拒、
    时序对齐）+ 异步接口（BoxFuture）编译期断言；
  - 混合 KEM 往返 + ml-kem 官方 KAT 复跑（P0-1）；
  - 压缩：<128B 直通、试压不缩回退明文、dictID 协商（P0-4/P1-7）；
  - trust：钉扎变更触发告警路径；邀请文件 v3 结构向量——根签名不匹配/目录条目被篡改/
    dir_version 回退 → 拒载入；同一根公钥下**多端点 ServerEntry 各自可完成 1-RTT 封装**
    （多服务器钉扎模型 §1.3.3f 的守门用例）（P0-5）。
- `cargo bench -p flock-protocol --bench aead`：aes-gcm 0.11.1 @4MiB ≥ 4 GB/s
  （本机旧内核基线 2.2，P1-6 的 2.3× 预期下限）。
- `cargo clippy -p flock-protocol --all-features -- -D warnings` 通过。

### M2 服务端（app/flock-server + flock-frpc，单服形态）
范围：监听器（ListenerMode：Direct 缺省 / Frp）/控制流/OPAQUE 登录+锚/设备注册（本地
NetState 适配器：redb 单机版，接口与 flock-sync 相同）/frpc 托管双栈（仅 Frp 模式装配）/
配置生成 golden-file。
完成标准：
- `docker compose -f deploy/m2.yml up -d --build`（1 frps + 1 server(Frp 模式) + 1 client
  骨架）起稳；
- **直连冒烟变体（硬约束守门，第四轮新增）**：`docker compose -f deploy/m2-direct.yml up
  -d --build` 起稳——**无 frps 容器**，server 以 `listener.mode = Direct` 监听并映射到
  宿主端口，client 直连该端口跑完与 m2.yml 完全相同的 smoke 断言集（`cargo test -p
  flock-server --test smoke -- --ignored --direct` 或等效 env 切换端点）；并断言
  Direct 形态 server 容器内 `pgrep -f frp` 无进程、Supervisor 未实例化（Direct 代码路径
  零 frp 逻辑的运行时证明）；
- `cargo test -p flock-server --test smoke -- --ignored`（对容器实跑）断言：
  邀请文件（含静态混合公钥）→1-RTT 首连→OPAQUE 登录→key-bind（签名校验路径）→设备出现
  在注册表→SR-SIG1 请求验签通过→吊销后握手被拒；
  **票据强制契约测试**：无票据/过期票据/低 epoch 票据（吊销后）的状态变更请求必须被拒，
  且票据校验先于 nonce 记账（顺序断言：错误票据 + 全新 nonce → 拒，错误票据 + 已用 nonce
  → 拒且 nonce 不入账）；等效重放窗 = min(±300s, 60s) 验证；
  **TOFU 首连路径测试**：无邀请时 I0→R0 引导（R0 携入群凭证链）+ 根指纹确认回调 →
  钉扎集群根公钥落盘 → 二连为 1-RTT 且**换端点（另一台服务器）仍 1-RTT**（目录拉取生效）；
  **开户/邀请一次性测试**：兑换 invite_id → 用户/设备创建+VIP 分配；同 invite_id 二次兑换
  拒；revoke_invite 后拒；过期拒。
- frpc 生成配置 golden-file 测试（ChmlFrp INI 样本 + 原版 TOML 样本逐字段一致，R8/R12）；
  ChmlFrp frpc「退出被拉起」守护单测（假进程 3 退→3 拉）；ChmlFrp 默认 `-c` 模式断言
  （UserTokenAuto 显式 opt-in 才启用）。

### M3 客户端（app/flock-client，数据面打通）
范围：tun 适配（tun-rs）/路由（rtnetlink/wintun）/接入器退避/PacketChannel 数据面。
完成标准：
- `docker compose -f deploy/m3.yml up -d --build`；
- `deploy/m3_assert.sh` 全 PASS：断言 A2/A3/A4/A9（单服版）；Windows 主机上
  `cargo test -p flock-client`（tun 单测用 mock TunDevice——主机无容器 NET_ADMIN 环境）；
- **Windows 真机手工清单（首发平台必须有真机记录）**：开发机上以本地测试中转跑通
  wintun 创建+路由注入+`--smoke`（wintun.dll 权限/驱动首次安装行为记录）；macOS 无设备
  ⇒ 标注未验证（utun 依 tun-rs 平台矩阵设计）。

### M4 多主同步（crates/flock-sync）
范围：openraft 状态机（注册表/凭证/配置版本/票据密钥根）+ gossip 租约 + rewrap 权限点 +
**集群准入（入群凭证/服务器-服务器 profile，§4）** + 跨服转发承载（ForwardEnvelope）。
完成标准：
- `cargo test -p flock-sync --test cluster`（3 节点内存集群）断言：
  任意节点写入 → 任意节点线性一致读 ≤2s 可见（含吊销记录）；
  kill leader → 重选举 ≤15s 且无丢提交（注入中转 RTT 100ms 模拟）；
  同设备双服务端租约冲突 → 新者胜、旧端踢出回调触发；
  `register→revoke→register`（IP 不复用语义）与 `server_keys→rewrap` 往返；
  **吊销传播界**：revoke 提交后各节点 apply 回调推进 revocation_epoch + 杀本地会话
  钩子触发 ≤2s（注入 RTT 100ms）。
- `cargo test -p flock-sync --test admission` 断言：
  **无入群凭证/伪造凭证的节点在服务器-服务器握手层被拒**（拿不到快照也进不了 Raft）；
  learner 加入→快照同步→`add_voter`（根密钥签名）→提升；`rewrap` 无根密钥签名 → 状态机
  拒绝；有根密钥签名 → 新服务器混合公钥进入封装集（OPRF key 副本数 +1 可观测）。
- `cargo test -p flock-sync --test forward` 断言：**源 VIP 绑定校验**（会话设备发包
  src=他人 VIP ⇒ 丢+计数；ForwardEnvelope src_dev 与内层源地址失配 ⇒ 收端拒）；本机投递/
  NOT_HERE → 一次性 location_query 重定向/hop=1 防环（构造二次转发 → 丢弃计数）；仍失败发
  ICMP unreachable。
- `cargo test -p flock-sync --test cluster` 追加：**apply-lag 熔断**——人为让 follower 落后
  5s，期间注入吊销 ⇒ 该 follower 拒用缓存（降级线性一致读）且新握手被拒（§4 陈旧读边界）。

### M5 Docker 多机实测（deploy/e2e.yml + e2e_assert.sh）
范围：§6.2 全拓扑（三网隔离 + 接入映射钉死 + Direct/Frp 混布）+ §6.3 断言 A1–A16。
完成标准：`docker compose -f deploy/e2e.yml up -d --build && deploy/e2e_assert.sh` 全 PASS，
脚本输出逐项 PASS/FAIL 汇总（A5/A6/A7/A15 允许显式重试窗口内通过）。
**桌面真机手工清单（M5 验收必填项，主机执行非容器）**：
- Windows（开发机即真机）：`cargo run -p flock-client -- --smoke`——wintun 设备创建、
  `route print` 断言 100.64.0.0/10 路由存在、tun0 MTU 1280、经本地测试中转 ping 通 server VIP；
  wintun.dll 首次装驱动的管理员权限行为记录进清单。
- macOS：无设备，列**未验证**（utun 路径按 tun-rs 平台矩阵设计，留待有设备后补；vpn-mesh
  §1.1 的 utun 事实为设计依据）。
- Linux 容器路径已被 A2–A15 覆盖，无需手工。
未含项如实声明：ChmlFrp 真实节点端到端（需账号，手工清单：M5 后有账号时补 R1/R6/R7 于
ChmlFrp 节点）；移动端（Android/iOS）真机（M3 后独立排期，接缝已在 §3.12 预留）。

### M6 系统服务化 + 客户端控制面（第一阶段：daemon 侧；托盘第二阶段并行）

需求（用户原话）：Windows/Linux/macOS 作为系统服务开机启动；主机有 GUI 则显示系统托盘
图标（暂不弹 GUI 窗口），托盘右键菜单三项：连接状态、VPN IP、退出。第一阶段交付 daemon
侧（服务化/IPC/安装器），托盘 UI 第二阶段开发——**IPC 契约本阶段固化为可独立编译消费的
模块**（`flock_client::ipc`，托盘工程直接依赖）。

#### M6.1 双进程模型（架构定型）

- `flock-client service`：**系统服务进程**——无任何 GUI 依赖，开机自启（Windows SCM /
  systemd / launchd），持有全部既有 supervise/数据面逻辑（§3.12 不变），另起本地控制
  IPC 服务端。
- `flock-client tray`：**用户会话进程**——仅托盘 UI（第二阶段实现），经控制 IPC 查询
  状态/触发退出，不接触密钥/tun/数据面。
- **理由**：Windows 服务运行在 session 0，无法创建托盘（Shell 屏蔽，事实约束）；单进程
  无法同时满足「无会话开机自启」与「会话内托盘」。Linux/macOS 服务同样跑在系统上下文
  （systemd system unit / LaunchDaemon），与用户会话 GUI 分离——三平台同构，避免平台
  分叉（Linux 的 user-service 形态不采用：与 Windows 服务形态不可对齐、登录前不启动）。
- **退出语义**（「退出」托盘菜单）：停 VPN + 托盘进程退出；**服务保持已安装**（下次开机
  自启）。daemon 侧的 Shutdown = 优雅停服：断会话（隧道 GoAway/FIN）→ 停数据面 → 拆
  tun → 进程退出；服务管理器**不复活**（systemd 单元 `Restart=on-failure`——正常退出
  非失败；launchd plist 不设 KeepAlive；Windows 服务恢复策略只对失败退出动作）。

#### M6.2 控制 IPC（v1 契约）

**传输**（postcard over 本地传输，帧格式与 §3.11 admin 面同构：`[u32 LE len][postcard]`，
单连接单请求-响应）：

| 平台 | 端点 | 权限 |
|---|---|---|
| Windows | 命名管道 `\\.\pipe\flock-client-control` | 显式 DACL（SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)`）：SYSTEM + Administrators + 交互用户组（IU）读写 |
| Linux/macOS | Unix socket `/run/flock/client.sock` | 0660，目录 `/run/flock` 0755 root |

**认证**：daemon 每次启动生成 32B 随机 token（`rand::random`），落 token 文件——Windows
`%ProgramData%\flock\control-token`（显式 ACL：Users 读）；Linux/macOS
`/var/lib/flock/client/control-token`（0640 root；`client.toml` 的 `control_group` 字段
指定组则 daemon 写盘时 chgrp token 与 socket 到该组——组名单一真相源在配置而非
install 参数，安装动作不改写用户配置；仅解析本地 /etc/group 或数字 gid，失败告警
不阻断，缺省 root:root 即「仅 root 可控」，即装即用文档说明）。**每请求都带
token**（Status 与 Shutdown 同一信封字段），校验先于分发，错即 `Denied`——比「仅
Shutdown 带 token」收紧：Status 泄露端点/VIP，不放开给传输层全体可连者。

**消息**（`flock_client::ipc`，postcard/serde，`#[derive(Clone, PartialEq)]`）：

```rust
pub enum CtrlReq {
    Status   { token: [u8; 32] },
    Shutdown { token: [u8; 32] },
}
pub enum CtrlResp {
    Status {
        state: ConnState,              // Connected | Connecting | Disconnected
        vip: Option<String>,           // 本端 VIP（启动即解析 ⇒ Some；文案容错位）
        endpoint: Option<String>,      // 当前/最近拨号端点
        epoch: u64,                    // 当前会话密钥纪元（rekey 推进；断开 ⇒ 0）
        uptime_secs: u64,              // daemon 启动至今秒数
    },
    Ok,        // Shutdown 受理
    Denied,    // token 错
}
```

**语义**：`Status` 无副作用幂等；`Shutdown` = §M6.1 优雅停服，回 `Ok` 后 daemon 完成拆除
即退出（进程退出与响应写出竞速以响应先写为承诺，极端情形客户端见连接重置亦视为已受理）。
v1 无版本协商字段——枚举加变体向后兼容（postcard varint 变体序号），跨版本策略留给 v2。

#### M6.3 服务安装（`flock-client install` / `uninstall`）

`--user` 只装托盘自启、`--service` 只装服务、缺省两者。安装动作记录**安装时**的 `--config`
路径进服务定义（unit/plist/服务命令行携带），卸载反向清理。

- **Windows**（windows-service crate）：`SERVICE_AUTO_START` + 失败恢复策略（重启，延迟
  5s/次封顶 3 次）；服务名 `flock-client`，二进制路径 = 当前 exe，命令行 `service --config
  <path>`；事件日志源 `flock-client`（报告 Start/Stop/失败）。**服务安装需管理员**：非提升
  会话给出清晰错误提示（docs/manual/windows-smoke.md 先例——真机安装列入手工清单项
  `docs/manual/service-install.md`）。
- **Linux**：渲染 `/etc/systemd/flock-client.service`（`WantedBy=multi-user.target`，
  `Restart=on-failure`，`After=network-online.target` + `Wants=network-online.target`，
  `ExecStart=<exe> service --config <path>`）→ `systemctl daemon-reload` → `systemctl
  enable --now flock-client`。**需 root**（sudo 提示）。uninstall：`disable --now` → 删单元
  → `daemon-reload`。容器内安装需 systemd 运行（测试阶段只验证单元渲染与命令序列，
  enable 执行面留给真机清单）。
- **macOS**：写 `/Library/LaunchDaemons/com.flockvpn.client.plist`（`RunAtLoad=true`、
  **无 KeepAlive**——Shutdown 后不复活）→ `launchctl load -w`。需 root。**本机无设备 ⇒
  标注未验证**（文件与命令照常写出，M6 手工清单留位）。
- **托盘自启**：Windows `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 值
  `flock-client-tray` = `<exe> tray`（HKCU 无需提权）；Linux
  `~/.config/autostart/flock-client-tray.desktop`；macOS
  `~/Library/LaunchAgents/com.flockvpn.client-tray.plist`（`RunAtLoad`，无 KeepAlive）。

#### M6.4 CLI 面

现有默认运行（`--config` 裸跑）保留为**前台调试模式**（不起 IPC，日志直连 stderr）；新增
子命令：`service`（daemon 装配：supervise + IPC 服务端 + 优雅停服，前台运行于服务管理器
之下）、`tray`（第二阶段；本阶段为 feature 门控的占位入口）、`install`/`uninstall`
（§M6.3）、`status`（直接发一次 `Status` 请求并打印——无托盘环境与测试的探针；token 从
token 文件读，读不到即报「daemon 未运行/无权限」）。

#### M6.5 feature 门控

`tray` feature：Windows/macOS 开发默认包含；Linux 无头服务器镜像默认不拖累托盘 GUI 依赖。
**Cargo 限制如实声明**：cargo 无法表达按 target 差异的 default features——本阶段 `default =
["tray"]` 对三平台一致，但 tray 门控面仅是子命令注册（零依赖差异）；第二阶段托盘 GUI 依赖
全部按 `[target.'cfg(windows/macos)'.dependencies]` + `optional = true` 挂进 `tray`
feature，Linux 默认构建（含 default features）不引入 GUI 依赖面，发布档以
`--no-default-features` 显式去托盘（CI 门禁含该档）。

#### M6.6 完成标准（第一阶段）

1. `cargo test -p flock-client --all-features` 全绿（IPC 契约往返/token 拒绝/Denied/守护
   装配与服务语义单测；传输层 mock + 平台真实回环各一组）。
2. `cargo check -p flock-client --no-default-features`（无 tray 档）与
   `cargo check --target x86_64-unknown-linux-gnu -p flock-client`（Linux 编译面）通过。
3. `cargo clippy -p flock-client -- -D warnings` 通过。
4. Windows 服务安装/启动/真机托盘自启、macOS 全链路：需管理员/真机，列
   `docs/manual/service-install.md` 手工清单（Windows 真机项标注「待管理员会话执行」；
   macOS 标注未验证）。
5. 托盘工程可直接 `use flock_client::ipc::{CtrlReq, CtrlResp, ...}` 消费契约（lib 面
   导出 + 契约单测即消费样例）。

### M7 成员名册与可观测性（服务端侧）

需求（用户原话浓缩）：CLI 要能列出各 VPN IP 的主机名、账户、在线状态、平均流量；
主机离线不马上消失，默认保留 1 个月；窗口内重连同设备保持同 IP（到期后设备过期、
IP 归还池子）；响应速度由客户端实测（不在本里程碑范围）。

#### M7.1 注册表扩展（Raft 静态面）

`DeviceRow` 增两字段（`crates/flock-sync/src/proto.rs`，注册表行 = Raft 状态机快照
线格式）：

```rust
pub struct DeviceRow {
    pub owner: String,
    pub device_x25519: [u8; 32],
    pub device_ed25519: [u8; 32],
    pub vip: [u8; 4],
    pub status: DeviceStatus,      // Active | Disabled | Revoked | Expired(新)
    pub since_epoch: u64,
    pub hostname: String,          // 新（M7）：客户端入网上报；空 ⇒ "(unknown)"；
                                   //   re-register（同设备 key-bind 再入网）可更新
    pub expired_at: Option<u64>,   // 新（M7）：置 Expired 的 unix 秒（审计）；非 Expired
                                   //   恒 None
}
```

- `hostname` 来源：enroll/key-bind 路径（`DevicePubs` 增 `hostname: String` 字段，进
  key-bind 设备签名覆盖面）；服务端先把字段与默认值打通——客户端上报为 M8 客户端
  阶段补齐，空串落 `"(unknown)"`（长度上限 64 字节，超长截断）。
- **快照/线格式兼容（如实声明）**：postcard 无字段标签，`DeviceRow`/`SyncRequest`
  加字段后**旧快照与旧日志条目不可解码**——未发布窗口允许（与 proto.rs 既有
  `L_SERVER_KEYS` 更名的同一纪律）；升级残留旧库需重建（init-cluster 重跑），不提供
  迁移。

#### M7.2 IP 复用策略修订（§2.1 已同步修订）

- **吊销 → IP 永不复用**（不变）；**离线超过保留期 → Expired + VIP 归还分配池**
  （新设备可分到）；**过期记录保留在册**（审计），名册查询排除。
- 实现：`SyncRequest::Expire { device, now_unix }`（Raft 写操作；`now_unix` 由提交方
  注入，状态机确定性落 `expired_at`）。apply 语义：仅 Active/Disabled → Expired
  （幂等：已 Expired 重放放行、不动 epoch）；推进 revocation_epoch 并触发吊销传播钩子
  （杀残留会话/废票据——与 Revoked 同路径，仅状态语义不同）；释放 VIP 进分配池
  （`NetStateData.vip_pool: BTreeSet<[u8; 4]>`，**优先于水位线分配**——池取最小，
  池空回退水位线 `vip_next` 单调递增）；VIP 反查索引删除旧条目（Expired 行不进索引
  ——释放后的 VIP 单射性由「池内 VIP 不在索引」维持）。
- **Expired 为终态**（同 Revoked）：不可 Enable（旧 VIP 可能已属他设备，复活会破
  单射）；同设备身份复活 = 新 key-bind 注册新行新 VIP。单服形态（netstate.rs
  StateStore）同语义：`expire()` + VIP 池表。
- 保留期 = server.toml `peer_retention_days`（缺省 30；**0 = 永不过期**，兼容旧行为；
  u64 天然 ≥0，解析即校验）。

#### M7.3 动态面搭租约便车（EWMA 流量 + last_seen，不进 Raft）

- 租约条目（`flock-sync/src/lease.rs`）增：`tx_ewma/rx_ewma: u64`（bytes/s，**设备
  视角**——tx = 设备发出、rx = 设备收到；服务器自身条目同理）与
  `last_seen_unix: u64`。gossip `Publish`/`Anti` 消息同步携带（持有者权威值）。
- EWMA：α = 0.2（`EWMA_ALPHA_NUM/DEN = 1/5`），**1s 更新窗口**——`LeaseTable` 内
  per-device 字节累加器（`note_tx/note_rx`），`tick_ewma(now_ms)` 每 1s 折一次：
  `ewma = ewma·(1−α) + (Δbytes/Δt)·α`（只折本机持有的行——远端行的值以持有者
  publish/反熵为准，不本地覆写）。
- **计数点（单点原则，杜绝双计）**：按「投递成功点计数」——
  - **src 设备 tx**：由**接入服务器**（src 租约持有者）在其 ingest 通过第 0 步源
    VIP 绑定校验后计 1 次（收进 mesh 即成功；dst 侧绝不计 src）；
  - **dst 设备 rx**：由**投递成功的服务器**（本机 sink 投递成功 / ForwardEnvelope
    收端本机投递成功——即 dst 的真实持有者）计 1 次；跨服 FRWD 的 origin 不计 dst，
    Not_HERE/丢弃不计；
  - **服务器自身条目**：dst = 本机 VIP 注内核成功 ⇒ 本机 rx；内核回程
    `route_outbound` ⇒ 本机 tx。
  - TTL 过期的租约行**保留**（不再删除）：`observe` 语义不变（过期 ⇒ None），但
    行内 `last_seen_unix`/ewma 留存供名册离线设备展示（内存权衡：每行 ~60B）。
- `last_seen_unix` 更新点：publish/续期（持有者）、本机计到该设备流量（持有者）、
  收到对端 publish/反熵事件（远端条目以消息携带值为准）。
- 同步通道：随**现有**租约 publish/事件（≤1s 语义；续期循环 10s 重发布携带最新
  ewma）与反熵（5s）——不新增 gossip 消息类型。名册装配从**本地租约视图**取。
- 单服形态：无租约表——`flock-sync` 提供同数学的 `TrafficMeter`（任意键 + EWMA +
  last_seen，无 gossip），`PeerRouter::serve_stream` 双向计数（入站 = 该设备 tx、
  出站 = 该设备 rx；dst = 服务器 VIP 的入站包计服务器 rx，内核回程计服务器 tx）。

#### M7.4 名册契约（控制流新增；客户端阶段消费，逐字固化）

`CtrlRequest` 新增变体 + 响应 + 行类型（postcard，`flock-server/src/control.rs`）：

```rust
CtrlRequest::PeerListPull { ticket: Option<TicketWire> }
CtrlResponse::PeerList { peers: Vec<PeerInfo> }

pub struct PeerInfo {
    vip: [u8; 4],
    hostname: String,
    owner: String,
    kind: PeerKind,            // pub enum PeerKind { Device, Server }
    online: bool,
    last_seen_unix: u64,
    tx_bps: u64,               // 设备视角 EWMA（bytes/s）
    rx_bps: u64,
}
```

- **票据保护**：登录票据必带（`ticket: None` ⇒ `TicketMissing`）；**票据校验
  （签名+TTL+epoch+设备态）先于名册数据装配**——沿 §2.2 票据强制契约纪律（本操作
  为只读，无 nonce 记账面；顺序有测试断言：坏票据 ⇒ `TicketBad` 且装配计数不动）。
- **装配** = 注册表快照（**本地已 apply 视图**——两级读缓存档即可，不强制线性一致
  读：名册是展示面，允许follower 视图的秒级陈旧）⋈ 本地租约视图（含 ewma）：
  - 设备条目：`status == Active` 的行（Disabled/Revoked/Expired 排除——名册 = 现任
    成员；审计走 DeviceList）；`online` = 本地租约视图 TTL 有效；`last_seen_unix`/
    `tx_bps`/`rx_bps` 取租约行（无租约历史 ⇒ 0）。
  - **服务器自身也进名册**（kind=Server）：多主形态取 Raft `server_keys` 本地视图
    （`ServerKeyEntry` 增 `vip: [u8; 4]`——根签登记时随身份/混合公钥同签，canonical
    字节随之扩展）；`owner` = 该服务器的 node_id 十进制串（server_id 的承载形态），
    `hostname` = 根签 ClusterDirectory 内该服务器 `relay_endpoint`（客户端可见端点，
    熟悉且唯一）；流量 = 本地租约视图内该服务器的自发布条目（`server_self_device_id
    (node_id)` 合成设备键——node_id 大端居前 8B + 固定标记后缀，与真实设备 id
    （sha256(ed25519)）碰撞概率可忽略；各服务器在租约续期循环里自发布 + 内核路径
    计数）。单服形态：本机一条 Server 条目（vip = `cfg.vip`，hostname =
    `advertise_endpoint`，流量 = 本机 TrafficMeter）。
  - **按 VIP 升序**排序输出。

#### M7.5 回收器（低频任务）

server 内低频任务（周期 60s）：扫本地已 apply 注册表快照，把「Active 且
`last_seen_unix` 距今 > `peer_retention_days`」的设备经 Raft 写操作置 Expired + 释放
VIP（M7.2 路径）。`peer_retention_days = 0` ⇒ 不装配回收器。多台并发回收幂等
（Expire 重放放行）；`last_seen_unix` = 本地租约视图（多主）/TrafficMeter（单服）；
从未在线的设备 `last_seen_unix = 0` ⇒ 按纪元 0 起算保留期（确定性：注册即起算）。
窗口判定函数以注入时钟取值（`reap_once(.., now_unix)` 可测）。

#### M7.6 完成标准

1. `cargo test -p flock-sync --all-features`：含 DeviceRow 往返（新字段）、Expired
   释放后新设备拿到该 VIP、EWMA 收敛、lease gossip 带宽字段往返、快照兼容性声明
   （旧格式不可解码 ⇒ 干净失败）。
2. `cargo test -p flock-server --all-features`：roster 装配（在线/离线/过期三态 +
   Server 条目）、票据先行顺序断言、回收器窗口逻辑（注入时钟）、hostname 默认值/
   re-register 更新。
3. `tests/multi_primary.rs` 追加：双客户端跨服时 roster 在任一服务器装配一致
   （结构字段严格相等；ewma/last_seen 容差比较——两服务器的本地视图来自不同时刻的
   反熵快照，逐字节相等不可实现也不必要），假流量泵使 ewma 非零。
4. 门禁：两 crate clippy `-D warnings`、workspace check、fmt；容器 linux 档 check
   （涉及 cfg 的仅数据面计数路径，不新增平台分支）。

---

## 8. 风险与对策

| # | 风险 | 依据 | 对策 | 残余 |
|---|---|---|---|---|
| R1 | Windows Docker Desktop 下 tun 不可用 | vpn-mesh §1.3 | **已实测消除**：WSL2 后端 `--cap-add NET_ADMIN` + `--device /dev/net/tun` 与 mknod 两路径均建设备成功（附录 B-2/3） | Hyper-V/VMM 后端未核 → 部署约束钉 WSL2 并写进 deploy/README |
| R2 | ChmlFrp 真实节点未实测（需实名账号） | frp-compat gaps#1 | 自动化用原版 frp×2；协议一致性靠字节透传论证（§1.4）+ golden-file（配置侧）+ ChmlFrp 源码 diff 证据；有账号后按 R1/R6/R7 补测 | 中转侧残差（节点限速/长连接策略）只能在真实节点验证 |
| R3 | TCP-over-TCP 弱网性能坍缩 | vpn-mesh §3.2（Titz 2001） | 单流限速/队列管理；MTU 1280 控制内层 MSS；远期 UDP 直连（自建节点 xtcp/自研） | 首版接受（形态如此），文档明示 |
| R4 | 自研握手无形式化验证 | 本设计 §3.5（不用 snow 的理由） | 结构复刻 Noise IK/WireGuard 常量；transcript 测试向量 M1 守门；外部审计前列「实验档」标注；libcrux 备选关注 | 实现缺陷风险在 M1 向量覆盖前存在 |
| R5 | opaque-ke 3→4 / dalek 2→3 API 代际迁移破坏兼容 | P1-6 | 固定向量互通测试 = M1 硬门槛；不通过则钉老版本并开迁移分支 | — |
| R6 | ChmlFrp 免费档 8Mbps + 4 隧道上限 | frp-compat §2.1 | 单隧道多会话复用（yamux）设计定型；生产吞吐预期管理写入文档 | 带宽硬限不可解（付费档或自建节点） |
| R7 | frp 官方 Windows exe 被本机安全策略拦截 | frp-compat gaps#4（本次研究实证） | 服务端 frpc 全部跑 Linux 容器（已验 FRPS_LINUX_OK）；Windows 客户端无需 frpc（直连用户口） | 分发给第三方 Windows 用户的 frpc 需签名/加白评估 |
| R8 | zstd C 工具链跨平台/交叉编译 | compression-2026 §5 | Windows/MSVC 已证可编译；**容器路径已实测**：rust:1-slim-bookworm 自带 cc/gcc 且 zstd-sys vendored 编译成功（附录 B-9，7.67s）——slim 镜像即够用；lz4_flex 纯 Rust 后备档 | musl 静态链接路径 M1 内验证 |
| R9 | 多主 Raft 经中转高 RTT → 选举抖动 | vpn-mesh §5.3 约束回顾 | 心跳/选举超时按中转 RTT 调参（M4 注入 100ms RTT 校准）；3 voter 起 | 跨国中转 RTT>500ms 时需实测调参 |
| R10 | VORACLE/CRIME 长度侧信道 | compression-2026 §3.2（前提全成立） | 压缩默认关 + 策略开 + 填充 + 非膨胀回退（P0-4 全落） | 开启压缩的会话仍有残余信道——文档明示给管理员 |
| R11 | yamux/TCP 队头阻塞 | vpn-mesh §4.2（RFC 9113 明示 TCP HOL 不可消） | 控制流高优先级 + 流控背压；接受为形态属性 | UDP 路径是唯一根治，远期 |
| R12 | ML-DSA crate 未审计 | crypto-2026 §5 | `pq-sign` 默认关；启用需显式 opt-in 并读风险说明 | — |
| R13 | wintun.dll 分发（Windows 客户端） | vpn-mesh §1.1（驱动 GPL、官方签名 DLL 分发例外） | tun-rs 内置 wintun 集成；随程序分发官方 0.14.1 签名 DLL | 杀软误报同 R7 策略 |
| R14 | 内存态 SR-SIG1 nonce 表多主重启重放面 | verdict §3.6 | 重放状态分级归属（§2.4）：票据短 TTL + 关键操作 Raft 查重 + 会话计数器 | 高频请求级 nonce 非强一致——工程取舍，文档明示 |
| R15 | 会话票据/共享秘密的多主封装面扩大 | VPN-15 | 逐服务器独立混合公钥 + rewrap 权限点（§3.10）；票据密钥根轮换经 Raft | — |
| R16 | TOFU 首登在线 MITM 接管（SSH known_hosts 同类限制） | 本设计 §1.3.3f/§2.5-3（verdict §3.9 只被部分关闭） | 组织场景强制邀请文件强路径（含静态混合公钥+签名绑定）；TOFU 首连指纹确认 UI 不得静默 | 个人自建场景残余接受，文档明示 |
| R17 | 跨 peer 流量在接入服务器明文 + 任一服务器可离线字典全部口令 | §2.5-1/2（与 Tailscale peer-E2E 属性根本不同） | 边界显式写进部署文档；服务器主机加固+准入红线（§4）；远期：peer 内层 E2E overlay、OPRF key 门限化 | 首版接受，防「误读为 peer 级 E2E」 |
| R18 | 重连风暴把线性一致读全部打到 Raft leader | §1.3.3c lookup 接缝 | DeviceDirectory 两级读：epoch 缓存命中本地答，仅 epoch 变化/miss 才线性一致读（§4 读与缓存） | 吊销恰好与风暴同发时 leader 短时压力（写少场景可承受） |
| R19 | 集群准入被伪造节点渗透（快照/rewrap 即 OPRF key 泄露面） | §4 准入红线 | 集群根密钥离线保管；服务器-服务器 profile 双向入群凭证；add_voter/rewrap 均需根密钥签名的 Raft 管理操作 | 根密钥泄露=全网重引导（灾难恢复路径文档化） |
| R20 | ChmlFrp `-u/-p` 自举的 usertoken 经 InsecureSkipVerify HTTPS 传输 | frp-compat §2.2（api.go:30-46） | 默认 `-c` 配置文件模式（面板粘贴导出）；UserTokenAuto 显式 opt-in + 风险标注 | 用户坚持 -u/-p 模式时面板账号接管面存在 |
| R21 | 租约陈旧窗口内跨服路由黑洞（设备迁移期） | §2.2 容错策略（vpn-mesh §5.2 明示为策略决策） | NOT_HERE → 一次性 location_query 重定向 + 失败丢包/ICMP（不缓存重试）；断言 A15 给 ≤35s 恢复界 | 迁移窗口丢包由上层恢复 |
| R22 | 持有效会话的恶意设备伪造他人源 VIP（身份嫁祸/反射/未来 ACL 绕过；rp_filter 不覆盖用户态流） | §2.2 第 0 步（vpn-mesh §2 借鉴点 3「每节点入向过滤」） | 会话 DeviceId ↔ src VIP 绑定校验（失配丢+计数+超限断），ForwardEnvelope src_dev 交叉校验；A14 伪造源断言 | — |
| R23 | 未兑换邀请文件泄露 = expiry 内被抢先兑换一次入网 | §1.3.3f 邀请一生 | invite_id 进 Raft 单次消费（二次拒）+ revoke_invite 吊销 + expiry 默认 7 天 + 文件按一次性凭据管理（0600） | 抢先兑换窗口存在（与 innernet 同边界），部署文档明示 |
| R24 | follower 落后（分区恢复/追赶）时本地缓存放行已吊销设备 | §4 读与缓存的陈旧读边界披露 | apply-lag >2s 熔断本地缓存、降级线性一致读 + 票据 epoch/TTL 60s 兜底；M4 落后 5s 用例 | 熔断阈值内的 ≤2s 放行窗口与 A6 预算一致（健康前提显式化） |
| R25 | 多服务器钉扎模型三选一的坑（共享密钥毁逐服务器封装/逐台 TOFU 不可扩展/切换降 2-RTT） | §1.3.3f 定型理由（第三轮评审 blocking） | 方案②：客户端锚定集群根公钥 + 根签 ClusterDirectory 全套材料（端点↔材料映射同签防拼接）；换钥=根签新条目+dir_pull，任意端点 1-RTT | 根密钥泄露=全网重引导（与 R19 同灾难路径） |
| R26 | 架构强绑 frp 致直连场景多余进程/故障面（可直连的服务器被迫跑 frpc：多余子进程、配置生成、ChmlFrp 三退守护、中转带宽瓶颈与故障点） | 用户硬约束（第四轮，§0）——**已消除**：ListenerMode `Direct` 缺省、Direct 代码路径不触碰 flock-frpc；frp 降级为「无公网 IP/不可直连」场景的可选适配器（§2.1/§2.2/§3.11/§5） | 守门断言：M2 `m2-direct.yml` 直连冒烟（无 frps、容器内无 frp 进程）+ M5 A16（Direct/Frp 同拓扑混布） | — |

---

## 附录 A：upgradeList 16 项 → 设计落位对照（一项不漏）

| # | 升级项（verdict §4） | 落位 | 里程碑 |
|---|---|---|---|
| P0-1 | 封装替换 X25519+ML-KEM-768 混合 KEM（RSA 兼容档） | §1.3.3a `kem`、§1.3.3b `envelope` v2（兼容策略=迁移窗口而非双封装，理由见 §1.3.3a） | M1 |
| P0-2 | 会话/隧道档 AEAD 纪律（计数器 nonce/rekey/硬拒/伪造断链） | §1.3.3c `session` 记录层；信封档前提文档化 | M1 |
| P0-3 | 信封 v2 段 AAD（v1 只读） | §1.3.3b | M1 |
| P0-4 | 压缩安全化（默认关/策略开/填充/非膨胀回退） | §1.3.3e `compress` | M1 |
| P0-5 | 首登信任锚/TOFU/邀请制/bind_token 覆盖 | §1.3.3f `trust`（邀请 v2 含静态混合公钥+签名绑定）+ §1.3.3c 握手 R0/R1 签名与 TOFU 2-RTT 首连 + §1.3.3d `anchor` + 残余风险 §2.5-3 | M1/M2 |
| P1-6 | crate 代际升级（aes-gcm 0.11.1/opaque-ke 4.0.1/dalek 3.0.0/rand 0.9） | §1.3.2 依赖代际；bench 门槛 | M1 |
| P1-7 | 压缩档位重构（直通/字典/分块/lz4/上下文复用/level19 归档档） | §1.3.3e | M1 |
| P1-8 | AEAD 后备档（XChaCha20-Poly1305/AES-256-GCM-SIV） | §1.3.3c `AeadPreference` | M1 |
| P1-9 | 传输帧与多路复用（yamux/EOF/keepalive/首字节自由） | §1.3.3d `mux`（yamux 0.14.1 内跑加密内） | M1 |
| P1-10 | 握手 1-RTT Noise-IK + 混合 KEM/漫游/重连=新握手/10s keepalive | §1.3.3c（双形态：已钉扎 1-RTT / TOFU 首连 2-RTT；UKS 签名覆盖契约） | M1 |
| P2-11 | OPAQUE 维护（4.0.1/argon2 profile/RFC 9807 勘误） | §1.3.2/§1.3.3h | M1 |
| P2-12 | 签名维护（dalek 3.0/ML-DSA-65 kid 分派预留） | §1.3.3g | M1 |
| P2-13 | nonce 长度文档回改（以实现为准 16B/32hex） | §1.3.2（库文档+showroom 侧迁移说明） | M1 |
| ★VPN-14 | tun 数据面接口（帧化/tun-rs/rtnetlink/MTU 1280/移动 fd 缝） | §3.6 `PacketChannel` + §3.12 `TunDevice` 接缝 + §2.3 | M3 |
| ★VPN-15 | 多主多活同步接口（强一致状态机/gossip 租约/票据下放/重封装权限点） | §3.10 `flock-sync` + §4（含集群准入/rewrap 授权）+ §2.4 + §2.2（票据契约/吊销传播界/跨服转发面） | M4 |
| ★VPN-16 | frp 中转适配接口（心跳/断链重连/不依赖半关闭/单隧道多会话/frpc 双栈托管）——**可选适配器非前提：Direct 缺省零 frp 逻辑（§0 硬约束/§3.11）** | §1.4（协议侧约束，直连/中转同构）+ §3.9 `flock-frpc`（仅 Frp 模式装配）+ §5 + §2.1 接入端点模型；守门=M2 m2-direct + M5 A16 | M2/M5 |

## 附录 B：本会话执行的核实（命令与关键输出）

1. `docker version` / `docker info` → Client 29.8.2 (windows/amd64, context desktop-linux)；
   Server "Docker Desktop 4.95.0" Engine 29.8.2 linux/amd64，
   Kernel `6.18.54.1-microsoft-standard-WSL2` ⇒ WSL2 后端。
2. `docker run --rm --cap-add NET_ADMIN --device /dev/net/tun debian:bookworm-slim sh -c '… ip tuntap add mode tun dev flocktest0 && ip link set … up && ip addr add 100.64.0.1/32 …'`
   → `3: flocktest0: <…,UP> …` + `TUN_CREATE_OK`（Git Bash 下需 `MSYS_NO_PATHCONV=1` 防
   `/dev/net/tun` 被改写为 Windows 路径——首次未加时报 `adding custom device "C"`，已定位并绕过）。
3. `docker run --rm --cap-add NET_ADMIN debian:bookworm-slim sh -c 'mknod /dev/net/tun c 10 200 … && ip tuntap add …'`
   → `MKNOD_PATH_OK`（无 --device 参数的回退路径亦可行）。
4. `curl -sL -o frp_linux_test.tar.gz …/frp_0.71.1_linux_amd64.tar.gz`（14,140,587B）+
   `docker run … -v …/frp_0.71.1_linux_amd64:/frp:ro debian … /frp/frps --version` →
   `0.71.1` + `FRPS_LINUX_OK`。
5. `ls .tmp/chmlfrpc/ChmlFrp-0.51.2_251023_linux_amd64/` → `frpc frps frpc.ini frps.ini …`
   （ChmlFrp 定版 Linux 二进制在位）；`ls .tmp/frp-src .tmp/frp-test .tmp/cryptobench` →
   上游源码/透传实验/基准工程均在位（frp-compat 附录所述资产属实）。
6. `cargo --version` → 1.98.1；`rustup target list --installed` →
   `x86_64-pc-windows-msvc`、`x86_64-unknown-linux-gnu`、`wasm32-unknown-unknown`。
7. showroom 源码抽查（只读）：`opaque.rs:1`（RFC 9380 误引）、`opaque.rs:32-39`（Suite）、
   `opaque.rs:42`（SERVER_ID 字面量）、`opaque.rs:53-70`（argon2id 参数与盐）、
   `lib.rs:48-55`（常量）、`lib.rs:376-412`（seal 布局/随机 nonce/无 AAD）、
   Cargo.lock 版本（aes-gcm 0.10.3/argon2 0.5.3/ed25519-dalek 2.2.0/opaque-ke 3.0.0/
   rand 0.8.8/rsa 0.9.10/zstd 0.13.3）、`Cargo.toml:3`（workspace members）——
   与 verdict §0 抽查表一致。
8. 未执行：容器内 Rust 工程 cargo build（仓库尚无代码）；cryptobench 复跑（verdict 复核轮
   已复跑，本会话直接采信其输出）；ChmlFrp 真实节点连通（需账号）。
9. rust slim 镜像 cc 核查 + zstd vendored 容器内编译（修订轮，评审非阻塞项触发，**已实测**）：
   `docker pull rust:1-slim-bookworm` 成功；`docker run --rm rust:1-slim-bookworm sh -c
   'which cc gcc clang; cc --version'` → `/usr/bin/cc`、`/usr/bin/gcc`（clang 无）、
   `cc (Debian 12.2.0-14+deb12u1) 12.2.0`——**slim 镜像自带 cc/gcc**（rust 镜像的 rustc
   需要链接器，官方 slim 变体亦装 gcc；评审「按官方镜像惯例不带 gcc」的假设与实测不符，
   以实测为准）。进一步 `cargo new + cargo add zstd@0.14 + cargo build --release`
   → `Compiling zstd-sys v2.1.2+zstd.1.5.7 … Finished release in 7.67s`，
   `ZSTD_BUILD_CHECK_DONE`——zstd vendored C 编译路径在容器内端到端打通。
   注：完整 workspace 的容器构建仍待 M1（仓库尚无代码可建）。

---

## 附录 C：修订记录

- 2026-10-31 第二轮（评审 4 blocking + 9 非阻塞全量吸收）：
  1. **B1**：握手双形态定型——邀请文件 v2 必含服务器静态混合公钥（1216B）并与身份签名绑定
     （指纹是哈希不能 encapsulate）；TOFU 首连 2-RTT（I0→R0 出示静态公钥→I1/R1），
     常态 1-RTT（§1.3.3c/§1.3.3f）；新增 UKS 签名覆盖契约 + M1 失败向量。
  2. **B2**：`lookup` 接缝改为 `trait DeviceDirectory` 异步（BoxFuture）+
     `LookupVerdict{NotFound,Revoked,Active}` 三态；`Tunnel::open_stream/open_packet_channel`
     补 async；新增「读与缓存」两级策略防重连风暴打穿 leader（§1.3.3c/§3.5/§4）。
  3. **B3**：补全跨服数据面——ForwardEnvelope/hop=1 防环/NOT_HERE 回退/租约未命中容错
     （丢包+ICMP，不缓存重试）（§2.2）；A2 钉死跨服接入映射、新增 A14 跨服面断言。
  4. **B4**：集群准入设计——集群根密钥（离线）+ 入群凭证 + 服务器-服务器 profile 双向认证；
     learner→快照→add_voter→rewrap 全部要求根密钥签名的管理操作（§4/§3.10）；M4 新增
     admission 测试组。
  5. 非阻塞：§2.5 威胁模型边界四条（跨 peer 明文/OPRF 离线字典面/TOFU 残余/中转）；
     票据强制契约（状态变更必带票据、校验先于 nonce 记账、重放窗=min(300s,TTL)）；
     吊销传播界参数化（apply ≤2s+事件 ≤1s+slack，票据 TTL 60s，租约 TTL 30s/反熵 5s）；
     ChmlFrp 托管默认 `-c` 模式（usertoken InsecureSkipVerify 风险入 R20）；Windows 真机
     手工清单入 M3/M5、macOS 标注未验证；构建镜像与 R8 的「slim 无 cc」矛盾以**实测**解决：
     rust:1-slim-bookworm 自带 cc/gcc 且 zstd-sys vendored 容器内编译成功（附录 B-9）；
     §6.2 拆 chmlpub/srvmesh/link 三网 + frpc 边车 + A13 直连不可达断言 + A15 租约容错断言。

- 2026-10-31 第三轮（评审 1 blocking + 4 非阻塞全量吸收）：
  1. **blocking·多服务器钉扎模型定型（方案②）**：客户端锚定**集群根公钥**，持根签
     **ClusterDirectory**（全套 ServerEntry = 入群凭证公开部分，端点列表与凭证同签一份防
     拼接）；任意端点 1-RTT（I1 封装给目标服务器自己的静态 KEM 公钥）；TOFU 首连只钉根
     （R0 携入群凭证链）；换钥=根签新目录条目+dir_pull；明确否决共享服务器密钥（毁逐服务器
     封装/rewrap 权限点）与切换降 2-RTT（§1.3.3c/§1.3.3f/§3.8/R25）。A5/A15 措辞按
     「任意端点 1-RTT、I0 不得出现」改齐。
  2. 非阻塞：§4 读与缓存补**陈旧读边界披露 + apply-lag>2s 熔断**（R24，M4 落后 5s 用例）；
     §2.2 转发判定序补**第 0 步源 VIP 绑定校验**（R22，A14 伪造源断言——rp_filter 不覆盖
     用户态流）；**设备位置单一真相源 = 租约域**（NetState 不存当前位置，NOT_HERE 回退改
     一次性 location_query，杜绝 Raft 写风暴与双源不一致）；**邀请一生 + 开户流程**定死
     （invite_id 进 Raft 单次消费、revoke_invite、expiry 默认 7 天、用户/设备/口令三分离，
     R23；M2 开户测试）。

- 2026-11-01 第四轮（**用户硬约束：ChmlVPN 不得与 frp/chmlfrp 强绑定**，最高优先级）：
  1. §0 增硬约束声明并改分层图（接入端点 = Direct 缺省 / Frp 可选，frp 只服务「服务端无
     公网 IP 或客户端不可直连」场景，可直连时不执行任何 frp 逻辑）。
  2. §2.1/§2.2 接入端点模型：每台服务器一个接入端点，`server.toml` `listener.mode`
     二选一、**Direct 缺省**；同一集群可混布；两种形态对协议层同构。
  3. §3.11 `ListenerMode` 接缝（Direct 直接监听零 frp 逻辑 / Frp(RelaySpec) 走 Supervisor），
     Direct 分支不实例化 Supervisor、不生成配置、无 chml-frpc 类型引用；§3.9/§5 标注
     「仅 Frp 模式装配、可选适配器非前提」。
  4. §1.3.3f/§3.8：`ServerEntry.relay_endpoint` 更名 `access_endpoint`（+endpoint_form
     标注），语义=接入端点（直连地址或中转用户口，客户端无感知差异）；客户端选路/探活不变。
  5. §6/§7：M2 新增直连冒烟变体 `deploy/m2-direct.yml`（无 frps、宿主映射直连、容器内
     pgrep frp 为空）；§6.2 server-c 改 Direct 形态直挂 chmlpub（去 frpc-c 边车）+ 新增
     client-3 直连；A13 收窄为仅 Frp 形态 server-a/b；新增 A16（Direct 会话连通 + 容器内
     无 frp 进程 + Direct↔Frp 跨服转发同构）；M5 断言范围 A1–A16；R 表新增 R26（本约束
     消除的风险）。A2/A5/A15 语义核对不受影响（client-1/2 的接入映射与跨服路径未变）。

- 2026-11-01 命名调整：chml-protocol → flock-protocol（协议层独立于 chml/frp 品牌；flock=雁群，小型分布式网络意象；行为零变化）。
- 2026-11-02 项目更名：ChmlVPN → Flock VPN（chmlvpn-server/client→flock-server/client、chml-sync/frpc→flock-sync/frpc、网络 chmlpub→flockpub、占位 git URL 换 flock 域；flock-protocol 线上行为零变化）。仓库目录同步更名为 FlockVPN——会话占用期间经 junction 过渡（宿主机两路径等价、Docker 挂载内仅真实路径可见，容器命令暂用 ChmlVPN 路径），收尾步骤见 docs/manual/dir-rename-final.md。
- 2026-11-06 M6 第一阶段（系统服务化 + 控制面 daemon 侧）：新增 §7-M6——双进程模型（`flock-client service` 系统服务持全部 supervise/数据面 + `flock-client tray` 用户会话托盘经本地 IPC，Windows session 0 托盘约束定案）；控制 IPC v1 契约（postcard over 命名管道/Unix socket + 32B token 信封认证，**每请求带 token**——较「仅 Shutdown 带 token」收紧，Status 不裸奔）；三平台服务安装（Windows AUTO_START+恢复策略 / systemd Restart=on-failure / launchd 无 KeepAlive）+ 托盘自启 + `install/uninstall/status` 子命令 + `tray` feature 门控（cargo 无按平台 default features 的限制如实声明，GUI 依赖留 target 门控给第二阶段）；退出语义定型（Shutdown=优雅停服不复活、服务保持已安装）。IPC 契约固化为 `flock_client::ipc` 模块供托盘工程独立消费。
- 2026-11-06 M7（成员名册与可观测性·服务端侧）：新增 §7-M7；**§2.1 IP 复用策略修订**（吊销→永不复用不变；离线超保留期→Expired+VIP 归还分配池、记录留册审计、名册排除；`peer_retention_days` 缺省 30、0=永不过期兼容旧行为）；注册表 DeviceRow 增 `hostname/expired_at` + `DeviceStatus::Expired`（终态）+ VIP 释放池（快照/线格式兼容性如实声明：postcard 无字段标签，旧快照不可解码——未发布窗口允许）；动态面搭租约便车（lease 条目 + gossip 携带 per-device EWMA 流量与 last_seen，α=0.2/1s 窗，「投递成功点计数」单点原则防双计）；名册契约 `CtrlRequest::PeerListPull`（票据先行）→ `Vec<PeerInfo>`（VIP 升序，含 Server 条目）；60s 回收器置 Expired。
