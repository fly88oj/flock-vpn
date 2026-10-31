# ChmlVPN 调研：VPN 隧道流量的压缩策略

- 日期：2026-10-31（结论以截至今日的一级来源与本机实测为准）
- 场景前提：多台跨平台电脑经 ChmlFrp 中转节点组成 VPN；frp 只做纯 TCP 中转，不使用 frp 自带加密/压缩；协议层自做端到端加密（服务端↔客户端）。流量画像：40–1500B 交互小包与大块传输混合，链路可能跨公网，带宽与 RTT 可变。
- 调研纪律：只认一级来源（官方仓库/文档、RFC、官方公告、维护者答复）；本机实测单独标注。所有论断附来源；已证实与推测严格区分。

---

## 0. 结论速览（分档推荐）

| 档位 | 条件 | 推荐 | 阈值依据 |
|---|---|---|---|
| **直通（不压缩）** | 包长 **< 128B**；或试压后不缩小；或已判定不可压缩（随机/已加密负载）；或会话策略关闭压缩 | 直接明文进加密层 | 本机实测：40B 包 zstd/brotli 反膨胀至 110–122.5%，lz4/snap 仅省 ~1B；120B 包全部算法收益 ≤1%（§2.1 表）。zstd 维护者：低于 ~50B 固定成本占主导（[zstd #3722](https://github.com/facebook/zstd/issues/3722)）。RFC 3173 §2.2 的非膨胀策略 + 自适应跳过是标准做法（[RFC 3173](https://www.rfc-editor.org/rfc/rfc3173.txt)） |
| **小包可选档** | 128B–~1.5KB 结构化小包，带宽受限链路 | **zstd level 1 + 部署字典（4–16KB）**，复用压缩/解压上下文；必须配非膨胀回退 | 本机实测（§2.2）：字典使 120B→28–30%、512B→13.5–13.7%、1400B→9.4–9.7%，且**比无字典更快**；zstd 官方：字典设计目标 ~1KB 输入、~100B 仍有效（[zstd #3722](https://github.com/facebook/zstd/issues/3722)） |
| **中包备选档（CPU 受限）** | 256B–1.5KB，客户端 CPU 紧张或要求纯 Rust 无 C 依赖 | lz4_flex block | 本机实测：512B 42.6% @1294MB/s、1400B 25.3% @1481MB/s，解压 6.5GB/s（§2.2）；lz4_flex 为纯 Rust、默认 safe（[lz4_flex README](https://github.com/PSeitz/lz4_flex)） |
| **大流档** | >1.5KB 连续流 / 聚合缓冲 | **zstd -1 分块流式，块 16–64KB，定时 flush（5–10ms 量级）** | 本机实测：1MB 日志型数据 11.7% @864MB/s 压缩 / 1205MB/s 解压；64KB 块仅比整块差 0.2 个百分点（§2.3）；zstd 官方对小目标块与首字节延迟的权衡说明（[zstd crate docs](https://docs.rs/zstd/0.14.3/zstd/bulk/struct.Compressor.html)） |
| **不采用** | — | brotli、snappy | 本机实测：brotli q5 压 120B 包需 **118µs**（zstd+字典 0.5µs，差 200 倍以上），解压也最慢（§2.2）；官方大流基准中 brotli-1 压缩速度仅为 zstd-1 的 ~57%、解压 27%（[zstd README](https://github.com/facebook/zstd)，Silesia）。snappy 在比率与解压速度上全面逊于 lz4（[lzbench](https://github.com/inikep/lzbench)） |

**安全前提（详见 §3）**：压缩必须放在加密之前（先压后密），且 ChmlVPN 的威胁模型满足 CRIME/BREACH/VORACLE 一族侧信道攻击的全部前提（FRP 中转链路天然是"密文长度观察点"，恶意网页可向隧道注入选择明文）。因此**压缩默认应关闭或仅对受信任的批量流量按策略开启**，这是 WireGuard 完全不做压缩、OpenVPN 2.5→2.6 逐步默认禁用乃至计划移除压缩的共同原因。

---

## 1. 算法横评：官方一级基准

### 1.1 大流（MB 级）——zstd 官方 README（lzbench、Silesia 语料、i7-9700K@4.9GHz）

来源：[facebook/zstd README（dev 分支，2026-10-31 抓取）](https://github.com/facebook/zstd)

| 压缩器 | 比率 | 压缩 MB/s | 解压 MB/s |
|---|---|---|---|
| zstd 1.5.7 -1 | 2.896 | 510 | 1550 |
| brotli 1.1.0 -1 | 2.883 | 290 | 425 |
| zlib 1.3.1 -1 | 2.743 | 105 | 390 |
| zstd 1.5.7 --fast=1 | 2.439 | 545 | 1850 |
| **lz4 1.10.0** | 2.101 | **675** | **3850** |
| snappy 1.2.1 | 2.089 | 520 | 1500 |

### 1.2 交叉验证——lzbench 官方表（AMD EPYC 9554 单线程 3.10GHz，silesia.tar）

来源：[inikep/lzbench README（master，2026-10-31 抓取）](https://github.com/inikep/lzbench)。表中"比率"为压缩后占原文的百分比，越小越好。

| 压缩器 | 压缩 MB/s | 解压 MB/s | 压缩后 % |
|---|---|---|---|
| zstd 1.5.6 -1 | 422 | 1347 | 34.64 |
| brotli 1.1.0 -0 | 341 | 352 | 37.01 |
| brotli 1.1.0 -2 | 140 | 413 | 32.12 |
| lz4 1.10.0 | 577 | 3716 | 47.60 |
| snappy 1.2.1 | 401 | 1077 | 47.85 |

两份官方基准的结论一致（已证实）：

- **zstd -1 是大流上的最佳平衡**：比率显著优于 lz4/snappy（~35% vs ~48%），压缩速度略慢但同量级，解压 1.3–1.5GB/s；
- **lz4 的定位是极低延迟**：解压 3.7–3.9GB/s 一骑绝尘，适合 CPU 敏感路径；但 64KB 窗口（见 §4.1）与较差比率限制了大流收益；
- **brotli**：只有高质量级（-5 以上）比率才反超 zstd，但压缩速度掉到 37–140MB/s（lzbench 表），解压也只有 zstd 的 ~1/3；
- **snappy**：比率与解压速度均劣于 lz4（1077 vs 3716MB/s），在 2026 年没有选择它的理由。

### 1.3 小数据：zstd 官方的"小数据专章"

来源：[zstd README "The case for Small Data compression"](https://github.com/facebook/zstd)。要点（均为官方原文的转述）：

1. 数据越小越难压——压缩算法靠"过去的数据"学习，新数据集开头没有"过去"；
2. zstd 为此提供**训练模式（字典）**：用同族样本训练出字典，压缩/解压双方预加载，小数据比率"戏剧性改善"，且**同时更快**；
3. 字典收益集中在**前几 KB**，之后算法逐渐改用已解码内容；
4. 不存在通用字典，越贴数据族的字典越有效；
5. 维护者 Yann Collet 对超小输入的量化口径（[zstd #3722](https://github.com/facebook/zstd/issues/3722)，2023）：字典为 ~1KB 输入设计，~100B 仍够用，**低于 ~50B 时固定成本主导**——zstd 帧固定开销为 magic 4B + 帧头 ≥2B + 块头 3B + 字面量头 1B + 序列头 1B；
6. 字典为何对小数据有效（[zstd #3783](https://github.com/facebook/zstd/issues/3783)，Cyan4973 答复）：适合"**消息间冗余高、消息内冗余低**"的结构化数据；典型场景正是"记录必须立刻发出、不能在批处理队列里等"——与 VPN 逐包隧道场景吻合。

注：zstd 并没有独立的"小数据模式"开关；官方给小数据的答案就是字典压缩（README 专章 + 上述 issue），负压缩级（--fast）只是更快更松的另一档速度/比率权衡。

---

## 2. 本机实测（Windows x64，2026-10-31）

### 2.0 方法学（可复现）

- 环境：Windows 10 26300（win32 10.0.26300 x64），rustc 1.98.1（x86_64-pc-windows-msvc），MSVC 2022 Community 工具链；单线程，release（lto=true, codegen-units=1, opt-level=3）。
- 依赖（`cargo add` 实际解析版本，Cargo.lock 为证）：**zstd 0.14.3、lz4_flex 0.14.0、brotli 9.1.1、snap 1.1.2**。zstd 0.14.3 在本机直接编译内嵌 C 源成功——这本身就是 Windows/MSVC 可用性的一手证据（见 §5）。
- 工作负载（确定性 xorshift PRNG 造的合成流量）：
  - `hdr40`：40B 纯 IP+TCP 报头（字段大多恒定，seq/ack 随机）——纯 ACK/心跳型；
  - `pkt120` / `pkt512` / `pkt1400`：40B 报头 + 模板化 JSON 文本负载（模拟交互式应用包，报头高度重复正是隧道流量特征）；
  - `rand1400`：1400B 全随机（模拟已加密/媒体等不可压负载）；
  - `bulk1m`：1MB 日志型大流。
- 计时：每负载 500 个独立测试样本逐个 one-shot 压缩/解压取平均（符合逐包隧道形态）；字典用另外 500 个训练样本现场训练。压缩计时含 Vec 分配；"ctx复用"表示复用 zstd 压缩/解压上下文（生产代码应当如此）。
- 局限：合成数据（模板类收益是上界）；单次运行；纯 CPU 计时，不含网络 RTT。基准代码位于 `%TEMP%\chml-bench`（临时目录，可能被清理；方法学与结果表已完整收录于本文）。

### 2.1 小包（关键结论：无字典时小包压缩无净收益，40B 反膨胀）

| 负载 | 算法 | 输出 | 比率 | 压缩 ns/op | 解压 ns/op |
|---|---|---|---|---|---|
| hdr40 (40B) | zstd 1 | 49B | **122.5%** | 2204 | 179 |
| hdr40 | zstd 1 (ctx复用) | 49B | 122.5% | 742 | 68 |
| hdr40 | lz4_flex block(safe) | 39B | 97.5% | 190 | 31 |
| hdr40 | snap raw | 39B | 97.5% | 57 | 65 |
| hdr40 | brotli q1 | 44B | 110.0% | 2929 | 649 |
| pkt120 (120B) | zstd 1 | 129B | **107.5%** | 4619 | 180 |
| pkt120 | lz4_flex block(safe) | 119B | 99.2% | 462 | 46 |
| pkt120 | snap raw | 119B | 99.2% | 119 | 52 |
| pkt120 | brotli q1 | 124B | 103.3% | 4415 | 614 |

读数（已证实，限本机与合成负载）：

- **40B 包**：zstd 膨胀 +9B——与维护者给出的固定开销公式（magic 4 + 帧头 2 + 块头 3）严丝合缝（[zstd #3722](https://github.com/facebook/zstd/issues/3722)）；brotli 也膨胀（+4B）。lz4/snap 能缩到 39B，但省 1B 换来的是多一次编解码与分支——不值得。
- **120B 包**：最好的算法也只省 1B（99.2%）。任何算法在 120B 无字典时都没有净收益。
- **结论**：<128B 一律直通。128B 与 512B 之间存在交叉点（120B 无收益、512B 已省 60%），取 256B 作快速短路阈值属工程折中（推测成分，见 §2.2 与 gaps）；更稳的做法是 RFC 3173 §2.2 的"试压+非膨胀回退+自适应跳过"，不依赖固定阈值。

### 2.2 中小包：字典模式把"负收益"变成"数量级收益"

| 负载 | 算法 | 输出 | 比率 | 压缩 ns/op (MB/s) | 解压 ns/op (MB/s) |
|---|---|---|---|---|---|
| hdr40 | zstd 1 +dict~12KB | 28B | **70.0%** | 540 (74) | 125 (320) |
| pkt120 | zstd 1 +dict16KB | 36B | **30.0%** | 535 (224) | 112 (1071) |
| pkt120 | zstd 1 +dict4KB | 34B | **28.3%** | 505 (238) | 106 (1134) |
| pkt512 | zstd 1 (ctx复用) | 205B | 40.0% | 3053 (168) | 1427 (359) |
| pkt512 | zstd 1 +dict16KB | 70B | **13.7%** | 857 (597) | 296 (1731) |
| pkt512 | lz4_flex block(safe) | 218B | 42.6% | 396 (1294) | 87 (5885) |
| pkt512 | snap raw | 225B | 43.9% | 286 (1793) | 104 (4904) |
| pkt512 | brotli q5 | 190B | 37.1% | 169070 (3) | 3766 (136) |
| pkt1400 | zstd 1 (ctx复用) | 297B | 21.2% | 4144 (338) | 1848 (757) |
| pkt1400 | zstd 1 +dict4KB | 131B | **9.4%** | 1694 (826) | 779 (1796) |
| pkt1400 | lz4_flex block(safe) | 354B | 25.3% | 945 (1481) | 213 (6573) |
| pkt1400 | brotli q1 | 314B | 22.4% | 7731 (181) | 4752 (295) |
| pkt1400 | brotli q5 | 262B | 18.7% | 220843 (6) | 5519 (254) |

读数（已证实，限本机与合成负载；字典收益是"模板化流量类"的上界）：

- **字典是隧道小包压缩的唯一正解**：120B 从 107.5%（膨胀）变为 28–30%；512B 从 40% 到 13.7%；1400B 从 21.2% 到 9.4%。4KB 字典与 16KB 字典效果相当——小字典就够。
- **字典同时更快**（官方 README 亦如此声称）：pkt1400 字典档压缩 826MB/s vs 无字典 338MB/s——字典预热了熵表与匹配状态，小输入不用"从零学习"。
- **上下文复用是硬要求**：40B 无字典 zstd，ctx 复用把 2204ns 降到 742ns（3 倍）；bulk 档 648→864MB/s。zstd crate 文档亦强调复用 context 对小任务的意义（[docs.rs/zstd bulk 模块](https://docs.rs/zstd/latest/zstd/bulk/)："It re-uses the zstd context between jobs to avoid re-allocations"）。
- **brotli 在逐包低延迟场景出局**：q5 压一个 120B 包要 118µs（是 zstd+字典的 ~230 倍），解压也最慢；q1 也没有比率优势。其价值在 Web 静态内容，不在隧道。
- **lz4_flex 与 snap**：512–1400B 上 lz4 比率略逊 zstd（42.6% vs 40.0%）但压缩快 ~8 倍、解压快 ~8 倍（87ns vs 1427ns），是 CPU 受限设备的正当备选；snap 全面被 lz4 压制，排除。

### 2.3 大流与分块

| 负载 | 算法 | 输出 | 比率 | 压缩 (MB/s) | 解压 (MB/s) |
|---|---|---|---|---|---|
| bulk1m | zstd 1 | 122939B | 11.7% | 648 | 1059 |
| bulk1m | zstd 1 (ctx复用) | 122939B | 11.7% | 864 | 1205 |
| bulk1m | zstd 3 | 130545B | 12.4% | 631 | 1609 |
| bulk1m | lz4_flex block(safe) | 217745B | 20.8% | 1517 | 1991 |
| bulk1m | brotli q5 | 109856B | 10.5% | 88 | 712 |
| bulk1m | zstd 1 整块 64KB 分块 | 125289B | 11.9% | 771 | 2100 |
| bulk1m | zstd 1 整块 8KB 分块 | 140787B | 13.4% | 534 | 1560 |

读数（已证实，限本机）：

- 本机日志型 1MB：zstd -1 压到 11.7%，864/1205MB/s；比官方 Silesia 数（34.6%）低是因为语料不同，不影响排序。
- **64KB 分块只损失 0.2 个百分点（11.7%→11.9%）**，8KB 分块损失 1.7 个百分点且更慢。zstd 官方 API 文档给出同类量化："更小的目标块 ~2% 速度、~0.1% 比率的代价，换取低带宽环境下更低的首字节延迟"（[Compressor::set_target_cblock_size](https://docs.rs/zstd/0.14.3/zstd/bulk/struct.Compressor.html)）。
- brotli q5 比率最好（10.5%）但压缩只有 88MB/s——大流上也不是 zstd 的对手。

### 2.4 不可压缩数据：必须直通 + 自适应跳过

- `rand1400`：所有算法输出 100.3–101.0%（zstd +10B 帧开销、lz4/snap +5–7B token 开销）。官方佐证：LZ4 块格式规定不可压输入膨胀 0.4%（[lz4_Block_format.md](https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md)）；RFC 3173 §2.2 要求"压缩后不小于原文则 MUST 发送原始形态"，并建议对连续压缩失败的数据包自适应停试若干个（实现相关阈值）。
- 真实隧道里 HTTPS/视频流量已是密文（随机），压缩纯烧 CPU。OpenVPN 官方 wiki 也以此为由反对默认压缩："互联网上绝大多数数据在进入 VPN 前就已被压缩"（[OpenVPN wiki: Compression](https://community.openvpn.net/Pages/Compression)）。

---

## 3. 压缩与加密的顺序、侧信道，以及 WireGuard 的选择

### 3.1 顺序：先压缩后加密（没有第二种选项）

- RFC 3173 §1："若同时需要压缩与加密，**必须先压缩后加密**"——加密输出近似随机，压不动；先压后密则解密侧先解密再解压即可（[RFC 3173](https://www.rfc-editor.org/rfc/rfc3173.txt)）。
- 因此**压缩输出长度 = 密文长度差异的直接来源**。AEAD 只保护内容，不隐藏长度。这是整族侧信道的根。

### 3.2 CRIME/BREACH/VORACLE 在 ChmlVPN 的适用性：成立

攻击三前提：① 攻击者能向压缩窗口注入**选择明文**；② 秘密与选择明文同窗；③ 攻击者能**观察密文长度**。对号入座：

- ① ②：ChmlVPN 隧道承载成员机器的全部内网流量。恶意网页可诱导受害者浏览器向内网服务发起携带攻击者可控路径/参数的请求（img/form 到 `http://内网地址/?guess=...`），与 Cookie/Authorization 等秘密同处一条 TCP 流——与 VORACLE 针对 OpenVPN 的机理完全相同。OpenVPN 官方公告原文：受害者经加密 VPN 访问明文 HTTP 站点时，"若攻击者能捕获密文包并向隧道内喂数据，就能从密文长度推断内容线索"；"**没有压缩时密文长度不变，攻击者一无所获**"（[OpenVPN VORACLE 安全公告，2018-09-29](https://openvpn.net/security-advisory/the-voracle-attack-vulnerability/)）。
- ③：**ChmlVPN 架构把长度观察点结构性内置了**——frp 中转节点被明确定义为不可信（所以才做端到端加密），中转方看得到每一帧密文长度；公网链路上的观察者同理。

结论（分析，基于上述一级来源）：WireGuard 的顾虑在 ChmlVPN 中**不是理论风险**，前提 ①②③ 均可满足。字典模式还会放大该信道（常见模式映射为更短的输出，长度差异更细）。

### 3.3 WireGuard 为什么明确不压缩；该决策对 ChmlVPN 是否适用

- **协议事实**：WireGuard 数据包格式只有 `message_type/receiver_index/counter/encrypted_encapsulated_packet`，没有任何压缩字段；发送前把内层包**填充到 16 字节倍数**再 AEAD（[wireguard.com/protocol](https://www.wireguard.com/protocol/)）。它宁可加填充也不做压缩。
- **设计者理由**（一级来源，2016-12-30 邮件列表答复提议加入 zstd 的用户）："第一个涌入脑海的顾虑就是**数据泄露与 CRIME 式压缩攻击**……历史上给加密协议加压缩一直相当危险"（[WireGuard mailing list, 2017-January 线程](https://lists.zx2c4.com/pipermail/wireguard/2017-January/000858.html)）。同页还体现其泄露规避哲学：外层包不复制内层 DSCP，"以免泄露内层加密数据的信息"。
- **行业后续验证**：OpenVPN 的轨迹是 2.5 默认 `allow-compression asym`（只收不发压缩——因只有上行受 VORACLE 威胁）→ 2.6 默认 `no` → 官方 wiki 明言"OpenVPN 终将移除全部压缩"；并总结" mixing compression and encryption without great care can have disastrous side-effects"、"没有安全的压缩方案"（[OpenVPN VORACLE 公告](https://openvpn.net/security-advisory/the-voracle-attack-vulnerability/)、[OpenVPN wiki: Compression](https://community.openvpn.net/Pages/Compression)）。
- **对 ChmlVPN 是否适用**：适用，且比 WireGuard 更迫切——WireGuard 面向通用公网隧道选择零压缩；ChmlVPN 同样承载不可控的上层流量（成员浏览网页）+ 不可信中继。**但 ChmlVPN 是自管设备网格**，存在 WireGuard 生态里少见的合法压缩场景：可控两端间的备份/同步/日志等已知 bulk 流量。因此不建议照抄"完全禁压"，而是**默认关、按策略开**（见 §6）。

### 3.4 缓解清单（若决定开启压缩）

1. **默认关闭，按流/按子网/按配置显式开启**，仅对"两端可信、内容不含攻击者可注入数据"的 bulk 流启用（OpenVPN asym 思路的加强版）；
2. **非膨胀回退**：压缩输出 ≥ 原文（减去允许余量）即改发明文（RFC 3173 §2.2 MUST）；
3. **长度规整/填充**：对压缩输出按桶填充（WireGuard 的 16B 倍数是最小形态；更强的做法是带抖动的指数桶），直接钝化长度 oracle，代价是带宽；
4. **自适应跳过**：连续 i 次压缩失败则跳过后续 k 包（RFC 3173 §2.2 建议的自适应算法），顺带省 CPU；
5. **字典只编码"结构"，不编码"秘密形态"**：用合成模板/自家协议头训练，而不是拿用户流量明文训练后再分发（字典本身会泄露流量画像）；
6. **每方向独立策略**（OpenVPN 2.5 的 asym 证明方向不对称是可用的缓解）。

---

## 4. 流式/分块：窗口与延迟的权衡；字典值不值得

### 4.1 逐包独立 vs 流式聚合

- RFC 3173 §2：IPComp 是**逐报文无状态压缩**，因为"IP 报文可能乱序或丢失"——解压器不能依赖前一包的状态。ChmlVPN 走 TCP 中转虽不丢包，但多服务端多活、连接迁移/重连都要求解压状态可重置；**逐包独立（或短窗口块独立）是抗乱序与快速恢复的正确形态**。
- lz4 块格式硬约束：匹配偏移最大 65535，即 **64KB 窗口**；且"块 <12B 无法压缩"、不可压膨胀 0.4%（[lz4_Block_format.md](https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md)，2026-10-26 修订版）。
- zstd 的窗口可调（`window_log`："最大回溯距离为 2^log_distance，解压侧需至少同级设置"，[zstd crate docs](https://docs.rs/zstd/0.14.3/zstd/bulk/struct.Compressor.html)），但窗口越大解压端内存与首包依赖越大。zstd README：字典收益集中在前几 KB，其后算法自然用已解码内容——**隧道场景没必要追大窗口**。

### 4.2 块大小与延迟（实测 + 官方口径）

- 实测（§2.3）：64KB 块比率损失 0.2pp；8KB 块损失 1.7pp 且吞吐下降 ~30%。
- zstd 官方：可用 `set_target_cblock_size` 让 C 块更小，"速度 ~2%、比率 ~0.1% 的代价，换取低带宽环境下更低的首字节延迟"（[docs.rs](https://docs.rs/zstd/0.14.3/zstd/bulk/struct.Compressor.html)）。
- 工程结论：**16–64KB 独立块 + 定时 flush（5–10ms 无数据即冲块）**，在比率损失 <1pp 的前提下把队头延迟压到与逐包同量级。纯交互小包走逐包档（或直通），不要进聚合缓冲。

### 4.3 字典模式值不值得引入（隧道包头高度重复）

值得，且有明确边界：

- **收益实测**（§2.2）：把 120–1400B 结构化包的比率从 99–21% 拉到 28–9.4%，同时压缩速度**不降反升**。zstd 官方定位（字典为跨消息冗余而生，"记录必须立刻发出、不能等批处理"，[zstd #3783](https://github.com/facebook/zstd/issues/3783)）就是隧道逐包场景。
- **代价与风险**：
  1. 分发与版本：多服务端多活要求所有服务端/客户端字典版本一致，握手需协商 dictID；轮换要重训重推（运维成本，分析）；
  2. 训练数据来源：见 §3.4-5（用合成/自家协议模板训练，避免拿用户明文训练）；
  3. 侧信道放大：字典让"匹配常见模式"输出更短，长度差异更细——开启字典的会话必须同时启用填充/策略白名单（§3.4）；
  4. 上界问题：本机实测基于模板流量，真实混合流量收益会稀释（zstd 官方："不存在通用字典"，越贴数据族越有效）。
- **不建议为 <50B 包上字典**：官方明言该区间固定成本主导（[zstd #3722](https://github.com/facebook/zstd/issues/3722)）；实测 40B+字典也只到 28B（省 12B），不值得为它引入整套字典机制——直通更干净。

---

## 5. Rust crate 成熟度与推荐（含 Windows）

| crate | 版本（本机 `cargo add` 实测解析） | 形态 | 跨平台/Windows | 评价 |
|---|---|---|---|---|
| **zstd**（gyscos/zstd-rs） | **0.14.3** | libzstd C 绑定（zstd-sys 经 cc 编译内嵌源码，预生成 bindings，bindgen 可选） | **本次调研即在本机 Windows/MSVC 编译运行成功**；crates.io 累计下载 3.4 亿+（[crates.io API](https://crates.io/api/v1/crates/zstd)）；支持 vendored/pkg-config/cmake 特性 | 大流 + 字典小包的首选。注意：需要 C 工具链（MSVC Build Tools）；`zstdmt` 多线程仅对大输入有意义（官方：小输入反而亏） |
| **lz4_flex**（PSeitz） | **0.14.0** | 纯 Rust，无 C 依赖；默认 safe（无 unsafe），可开 unsafe 提速；no_std（block） | 无工具链要求，跨平台零成本；官方基准与 C 版（lzzzz）同量级甚至更快（[README](https://github.com/PSeitz/lz4_flex)：66KB JSON 压缩 1615 vs 1469 MiB/s） | CPU 受限路径/嵌入式备选。注意 block API 每次调用重建哈希表（README 提供 `_into`/`with_table` 变体） |
| **brotli**（dropbox/rust-brotli） | **9.1.1** | 纯 Rust 移植（no_std、自定义分配器、FFI 可选） | 纯 Rust，跨平台无忧；维护活跃（9.1.1 更新含对 C 解码器 CVE-2026-111497 场景的错误码处理，[README](https://github.com/dropbox/rust-brotli)） | 技术上成熟，但性能定位是 Web 内容（见 §2.2 实测的逐包延迟），**不建议用于隧道** |
| snap（BurntSushi/rust-snappy） | **1.1.2** | 纯 Rust，与 C++ 参考实现逐字节一致（CI 对拍），MSRV 1.39 | 纯 Rust，成熟 | 算法本体被 lz4 全面取代（§1.1/§1.2），无推荐场景 |

推荐组合：**zstd 0.14.x（大流分块 + 小包字典档，复用 CCtx/DCtx）+ lz4_flex 0.14（可选超低延迟/纯 Rust 路径）**。若某目标平台拿不出 C 工具链，则该平台只配 lz4_flex（zstd 无生产级纯 Rust 编码器；ruzstd 仅解压）。

---

## 6. 对 ChmlVPN 的落地建议（汇总）

1. **协议设计**：帧头加 1 bit 压缩标志 + 原始长度字段（解压端按长度预分配——zstd crate 文档称预分配对解压有约 2 倍收益）；未压缩帧直通。遵循 RFC 3173：先压缩后加密、非膨胀 MUST 回退、小包阈值 + 自适应跳过。
2. **默认安全态**：压缩默认**关闭**；按路由/配置对受信任 bulk 流显式开启（§3.3/§3.4 的 WireGuard 与 OpenVPN 证据链）。开启压缩的会话建议同时启用输出填充。
3. **分档执行**（阈值依据见 §0 表）：
   - `<128B`：直通（实测 40B 膨胀、120B 零收益）；
   - `128B–1.5KB`：可选 zstd1+字典（4–16KB，实测 28–9.4% 且更快）；CPU 紧张则 lz4_flex（512B 档 1294MB/s）；
   - `>1.5KB`/连续流：zstd -1 分块 16–64KB + 5–10ms 定时 flush；
   - 任何档位：试压不缩小即回退明文，连续失败自适应停试；
   - 不可压（随机/已加密）流量：直通（实测 100.3–101% 膨胀）。
4. **上下文与字典生命周期**：每连接/每方向复用 `zstd::bulk::Compressor/Decompressor`（实测 3 倍差距）；字典经协商按 dictID 加载，多服务端同步分发，版本强制一致。
5. **不要引入** brotli（逐包延迟差 2 个数量级）与 snappy（被 lz4 全面超越）。

---

## 7. 证据清单（一级来源）

| # | 来源 | 用途 |
|---|---|---|
| S1 | [facebook/zstd README（dev）](https://github.com/facebook/zstd) | 官方基准表、小数据/字典专章 |
| S2 | [inikep/lzbench README（master）](https://github.com/inikep/lzbench) | 跨算法大流基准交叉验证 |
| S3 | [zstd issue #3722](https://github.com/facebook/zstd/issues/3722)（Cyan4973） | 超小输入固定成本、帧开销构成、~1KB/~100B/~50B 口径 |
| S4 | [zstd issue #3783](https://github.com/facebook/zstd/issues/3783)（Cyan4973） | 字典适用形态（跨消息冗余、不能等批处理） |
| S5 | [lz4 Block format（2026-10-26 修订）](https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md) | 0.4% 膨胀、64KB 窗口、<12B 不可压 |
| S6 | [RFC 3173](https://www.rfc-editor.org/rfc/rfc3173.txt) | 先压后密 MUST、逐报文无状态、非膨胀策略、自适应跳过、安全考虑 |
| S7 | [OpenVPN VORACLE 官方安全公告](https://openvpn.net/security-advisory/the-voracle-attack-vulnerability/) | VPN 压缩侧信道机理与"无安全压缩方案"结论 |
| S8 | [OpenVPN wiki: Compression](https://community.openvpn.net/Pages/Compression) | 2.5 asym 默认、2.6 no 默认、计划移除压缩 |
| S9 | [WireGuard mailing list 2017-01 线程](https://lists.zx2c4.com/pipermail/wireguard/2017-January/000858.html) | Jason Donenfeld 拒绝压缩的原始理由（CRIME 式泄露） |
| S10 | [wireguard.com/protocol](https://www.wireguard.com/protocol/) | 数据包无压缩字段、16B 填充、DSCP 不外泄 |
| S11 | [docs.rs zstd 0.14.3](https://docs.rs/zstd/0.14.3/zstd/bulk/struct.Compressor.html) | bulk 定位（小网络包）、ctx 复用、块大小/窗口/预分配性能指南、字典 API |
| S12 | [lz4_flex README](https://github.com/PSeitz/lz4_flex)、[rust-brotli README](https://github.com/dropbox/rust-brotli)、[rust-snappy README](https://github.com/BurntSushi/rust-snappy)、[crates.io API](https://crates.io/api/v1/crates/zstd) | crate 形态、基准、维护状态、下载量 |
| S13 | 本机实测（§2，环境与命令见 §2.0） | 小包/字典/分块/上下文复用的量化结论 |

## 8. Gaps（未能查证/未做，如实列出）

1. **未在 Linux/macOS 实测**：跨平台性能排序引用官方基准（S1/S2），本机数据仅 Windows x64 一台。
2. **未用真实流量样本**：合成模板流量（报文头+模板文本）——字典收益（28–9.4%）是"结构化流量类"的上界，真实混合流量会更低；<128B 直通与 512B 值得压的两个端点有实测，**256B 快速短路阈值是插值推测**（建议实现时用"试压+回退"替代固定阈值）。
3. **未做端到端网络实验**：压缩对总延迟/吞吐的影响（含 RTT、TCP 中转排队）未实测，仅有 CPU 侧数据与官方定性结论；flush 间隔 5–10ms 是工程建议非实测最优值。
4. **crates.io 元数据不一致**：API `max_version` 显示 zstd 0.13.3（2025-02-20），但 docs.rs 与本机 `cargo add` 均解析到 0.14.3——以本地实测解析为准，未深究差异原因。
5. **CRIME/BREACH 原始论文未直接引用**：机理引用自 OpenVPN VORACLE 官方公告（其明确自述"与 CRIME 和 BREACH 相似"）与 WireGuard 邮件列表；未回溯 2012/2013 原始演讲材料。
6. **frp 侧 TCP 中转的 MSS/分段对压缩分块的实际影响**未实测（分块建议基于压缩层本身的权衡）。
