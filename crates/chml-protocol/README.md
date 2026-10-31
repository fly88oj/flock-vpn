# chml-protocol

ChmlVPN 与 showroom 共享的协议契约层（`docs/design.md` §1）：混合 KEM、文件信封 v2、
SR-SIG1、OPAQUE、压缩档位、隧道会话（session）、复用（mux）、首登信任锚（trust）。
设计全文见 `docs/design.md`；本 README 只摘调用方必须知道的契约。

## 模块与档位

| 模块 | 内容 | 设计节 |
|---|---|---|
| `kem` | X25519 + ML-KEM-768 混合 KEM（ek 1184B / ct 1088B / 混合公钥 1216B） | §1.3.3a |
| `envelope` | 文件信封 v2（混合封装 + 段序号 AAD）；`legacy` 下 v1 只读兼容 | §1.3.3b |
| `sig` | SR-SIG1 五函数兼容 + `KeyProfile` kid 分派 | §1.3.2/§1.3.3g |
| `pake` | OPAQUE（RFC 9807 / opaque-ke 4.0.1）+ argon2id profile | §1.3.3h |
| `compress` | 压缩档位（默认关；<128B 直通；zstd-1 字典 / zstd-1 分块 / level-19 归档；非膨胀回退 MUST） | §1.3.3e |
| `session` | 隧道会话：握手双形态 + 记录层 + 抗重放 + rekey + 伪造断链 | §1.3.3c |
| `mux` | yamux 0.14.1（加密记录层内）+ 显式 FIN + PacketChannel | §1.3.3d |
| `trust` | PinStore（集群根级钉扎）/ ClusterDirectory（根签目录）/ InviteFile v3 | §1.3.3f |

feature 矩阵（§1.3.1）：默认＝全 VPN 档；`legacy`（信封 v1 只读）/ `anchor` / `pq-sign` /
`wasm`（getrandom custom 后端桥，见 `src/wasm_bridge.rs`）默认关。

## 两份文档化 nonce 契约（档位分立，不可混用）

**信封档（`envelope` v2）——一次性 k + 每段随机 96-bit nonce**：

- 前提：k 为**一次性**混合 KEM 派生（每信封新临时 X25519 + ML-KEM-768 份额），且单信封
  段数 = n/4MiB ≪ 2^32——随机 nonce 落在 SP 800-38D 随机 IV 界内（verdict §3.4）。
- 适用：**离线文件/一次性载荷**。把同一 k 复用于大量消息或长寿命流都**违反本前提**。

**隧道档（`session` 记录层）——计数器 nonce，禁随机**：

- 记录层 `[u32 len ≤1MiB][type][AEAD(payload)]`，nonce = 32-bit 零 ‖ 64-bit LE 计数器
  （WireGuard 形态；XChaCha 后备档为 16B 零 ‖ 计数器）；每方向独立密钥与计数。
- 计数器不上线：TCP 有序 ⇒ 接收侧以「上一条 +1」隐式重建；重复/回退表现为认证失败，
  拒收并计入伪造（forge_limit 默认 100，达限断链）。
- 密钥寿命双阈值：rekey (2^60 包, 120s) 先到先换（REKEY_INIT/RESP，新混合 KEM，计数器
  随新密钥重置）；(2^64−2^13−1, 180s) 硬拒绝——清零密钥断链。
- 长会话**禁用随机 96-bit nonce**：随机 IV 的安全界依赖消息数约束，长寿命隧道必然越界
  ——这正是两档分立的原因（§1.3.3b/§1.3.3c，verdict §3.4）。

## 握手双形态（session）

- **已钉扎 1-RTT**（Noise-IK 结构）：`initiate(io, device, &ServerPin, cfg)`——I1 =
  版本+算法集+X25519 临时+ML-KEM-768 ct（封给目标服务器静态混合公钥）+加密的设备静态
  公钥与设备签名；R1 = 服务器临时 + 身份签名 + 密钥确认。任意端点均 1-RTT（I0 不出现）。
- **TOFU 首连 2-RTT**（仅一次）：`initiate_tofu(...)` → 展示根指纹（`root_fingerprint`）
  → `confirm()`；钉扎落地走 `trust::confirm_tofu_and_pin`。TOFU 不防首登在线 MITM
  （SSH known_hosts 同类限制）——组织场景必须走邀请文件强路径（trust::InviteFile v3）。
- 设备签名覆盖 I1 全部已发字段 + 协议上下文（cluster_id/期望服务器身份）——UKS 篡改
  向量必失败（§1.3.3c 签名覆盖契约）。

## 版本收口（§1.2）

本 crate 再导出锁定的 `ed25519_dalek` / `x25519_dalek` / `ml_kem` / `opaque_ke` / `rand`
（`legacy` 下另含 `rsa`），下游不得另引版本。

## 构建/门禁（§7-M1）

```sh
cargo test -p chml-protocol --all-features          # 全量测试
cargo clippy -p chml-protocol --all-features -- -D warnings
cargo bench -p chml-protocol --bench aead           # 末行机读：BENCH_AESGCM_4M <数值> GB/s（门槛 ≥4）
cargo check -p chml-protocol --no-default-features --features legacy,wasm --target wasm32-unknown-unknown
```

wasm32 构建前置：需一个**带 WebAssembly 后端的 clang**（zstd-sys C 源交叉编译）。
注意：LLVM 官方 Windows 发行版（installer 与 `clang+llvm-*-windows-msvc` tar.xz）**不含
wasm 后端**（`clang --print-targets` 无 wasm32，本次实测）；可用
[wasi-sdk](https://github.com/WebAssembly/wasi-sdk) 的 clang（其 `bin` 加入 PATH 即可，
cc crate 自动探测）。getrandom custom 后端 cfg 由仓库 `.cargo/config.toml` 配置，熵桥见
`src/wasm_bridge.rs`。
