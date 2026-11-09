# Flock VPN

[![CI](https://github.com/fly88oj/flock-vpn/actions/workflows/ci.yml/badge.svg)](https://github.com/fly88oj/flock-vpn/actions/workflows/ci.yml)

自建、可多主多活的开源 VPN：直连优先（Direct 缺省、零 frp 依赖），FRP 中转作为可选双栈；
密码学契约层由独立协议仓
[`flock-protocol`](https://github.com/fly88oj/flock-protocol)（tag
[`v0.1.0`](https://github.com/fly88oj/flock-protocol/releases/tag/v0.1.0)）以 git
依赖提供——混合 KEM（X25519 + ML-KEM-768）、Noise-IK 式 1-RTT 隧道会话、OPAQUE
登录、TOFU/邀请信任锚。

- 总体设计（权威文档）：[docs/design.md](docs/design.md)
- 协议库独立仓：[fly88oj/flock-protocol](https://github.com/fly88oj/flock-protocol)
- 参与贡献：[CONTRIBUTING.md](CONTRIBUTING.md) · 安全：[SECURITY.md](SECURITY.md)

## 核心特性

| 特性 | 说明 |
|---|---|
| 直连优先 + frp 双栈 | 每台服务器一个接入端点：`Direct`（缺省，直接监听，零 frp 逻辑）/ `Frp`（[flock-frpc](crates/flock-frpc) 托管 frpc 中转，服务端无公网 IP 时选）；两种形态对协议层完全同构，同一集群可按机器混布 |
| 多主多活控制面 | [flock-sync](crates/flock-sync)：openraft 强一致状态机 + redb 存储 + 服务器间 E2E profile 传输 + gossip 在线租约；任一服务器接入效果一致，吊销经 Raft 复制 ≤5s 全网生效 |
| flock-protocol 三层嵌入 | 协议层独立成仓：传输层嵌入（tunnel 档泛型于任意可靠有序字节流——直连/frp/QUIC 适配器零改动）、应用层嵌入（envelope/sig/pake 按 feature 裁剪）、运行时嵌入（wasm32 + C-ABI 垫片）——详见[协议仓 README](https://github.com/fly88oj/flock-protocol#readme) |
| 后量子混合 KEM | X25519 + ML-KEM-768（FIPS 203）双栈封装，量子迁移期同时保住经典与后量子安全边界 |
| 1-RTT 隧道会话 | 已钉扎服务器一次往返建立加密隧道：计数器 nonce AEAD、抗重放、双阈值 rekey、伪造断链检测 |
| OPAQUE 登录 + 信任锚 | RFC 9807 aPAKE（口令不出客户端、离线字典需攻破服务器）；TOFU 首连 / 邀请文件强路径两种钉扎 |
| 名册与可观测 | `flock-client peers`（VIP/主机名/账户/在线/延迟/流量，`--json` 机读档）；服务端 `stats` 快照 + Web UI（M8） |
| 跨平台客户端 | Windows / macOS / Linux 首发（tun-rs 原生路径），Android/iOS 走 fd 注入接缝预留；系统服务化 + 托盘 |

## 架构

分层总览（摘自 [docs/design.md §0](docs/design.md#0-设计总览)）：

```
┌─ 客户端 app（flock-client）────────────────────────────────────┐
│ tun(tun-rs) → PacketChannel → yamux 流 ─┐                        │
│ 路由（rtnetlink/wintun/VpnService）      │                        │
└──────────────────────────────────────────┼────────────────────────┘
                                            │ 单条 TCP（密文；路径=接入端点：
                                            │  Direct 直连 或 经 FRP 中转）
┌─ flock-protocol（会话层，独立仓）──────────┼───────────────────────┐
│ SecureStream(记录层: 计数器nonce AEAD+抗重放+rekey) ← yamux 跑在加密内 │
│ 握手: 已钉扎 1-RTT Noise-IK / TOFU 首连 2-RTT；X25519+ML-KEM-768 混合 │
│       KEM + 服务端身份签名（邀请文件携带静态混合公钥）                  │
└──────────────────────────────────────────┼───────────────────────┘
                                            │ TCP 字节流（直连或中转，均透明）
┌─ 服务端 app（flock-server）─────────────┼────────────────────────┐
│ 监听器 ListenerMode: Direct(缺省,零 frp) │ tun + 路由 + peer 转发   │
│   或 Frp(flock-frpc Supervisor 托管中转)  │ flock-sync: openraft+租约│
│ 控制流: OPAQUE 登录 + 设备注册表 + 配置下发 │                        │
└──────────────────────────────────────────┴───────────────────────┘
```

数据面首版为 hub-and-spoke（客户端互访经服务端路由，威胁边界见下文
[安全模型](#安全模型)）；虚拟网段 `100.64.0.0/10`（RFC 6598 CGNAT），MTU 1280。

## 快速开始

### 一键体验（容器直连冒烟，免 prepare）

```bash
git clone https://github.com/fly88oj/flock-vpn.git
cd flock-vpn
docker compose -f deploy/m2-direct.yml up -d --build   # 镜像内构建走 git 依赖，零 frp 资产
cargo test -p flock-server --test smoke -- --ignored direct
docker compose -f deploy/m2-direct.yml down -v
```

三条 smoke 断言：Direct 起服后容器内无 frp 进程、TOFU 全链登录 + 根签目录拉取、
双端点切换模拟（9443/9444 同容器端口）。

### 三步（服务端起服 → 客户端登录 → 查看名册）

1. **服务端 install**：编 `server.toml`（`listener.mode` 缺省即 `direct`）后引导并起服，

   ```bash
   flock-server --config /etc/flock/server.toml init-cluster   # 引导状态库
   flock-server --config /etc/flock/server.toml                # = run，TCP :9443
   ```

   开户（客户端先 `flock-client gen-keys` 打印 `device-x=`/`device-ed=` 公钥）：

   ```bash
   flock-server invite > invite.b64
   flock-server redeem --user alice --invite-b64 "$(cat invite.b64)" \
       --device-x <b64> --device-ed <b64>
   ```

2. **客户端登录**：载入邀请（钉扎根公钥）后登录并保活，

   ```bash
   flock-client invite invite.b64
   flock-client login        # 口令 → 0600 凭据 + 登录验证 + hostname 入册
   flock-client service      # daemon：tun + 路由 + 接入守护 + 控制面 IPC
   ```

3. **查看名册**：

   ```bash
   flock-client peers        # VIP/主机名/账户/状态/延迟/流量（--json 机读档）
   ```

多主集群（×3 起，Raft 奇数 voter）：`flock-server init-cluster --voters N` 生成根密钥与
各节点入群捆绑，`enroll` / `cluster-bootstrap` / `cluster-invite` 完成组网——完整真机
拓扑实录见 [docs/manual/multinode-test.md](docs/manual/multinode-test.md)。

## CLI 速查

`flock-server [--config <server.toml>] [<子命令>]`

| 子命令 | 作用 |
|---|---|
| `(run)` | 起服（缺省；listener.mode：`direct` 缺省 / `frp`；`[sync] mode=raft` 走多主装配） |
| `init-cluster [--voters N --out DIR --endpoints e1,e2,…]` | 引导状态库；`--voters` 生成多主集群材料（根密钥 + 入群捆绑） |
| `enroll --bundle FILE` | 装载并验证节点捆绑（根签目录 + 入群凭证） |
| `cluster-bootstrap --root-seed FILE` | 根密钥签 Bootstrap（票据根）+ SetOprf（共享 OPRF），幂等可重跑 |
| `cluster-invite --root-seed FILE --bundle FILE [--ttl-secs N]` | 根密钥签 v3 邀请 → stdout b64 |
| `stats` | 运行状态快照（epoch/leader/转发计数/在线会话） |
| `invite [--ttl-secs N]` | 签发邀请 → stdout 单行 b64（单服形态） |
| `redeem --user U --invite-b64 B --device-x B64 --device-ed B64` | 兑换邀请开户（建用户/设备 + 分 VIP） |
| `device-add --user U --device-x B64 --device-ed B64` | 直接注册设备（TOFU 预置） |
| `revoke --device HEX64` | 吊销设备（推进 revocation_epoch + 杀会话） |
| `web-admin-add <用户名>` | Web UI 首 admin 引导（stdin 两遍口令，原生 OPAQUE 注册） |

`flock-client [--config <client.toml>] [<子命令>]`

| 子命令 | 作用 |
|---|---|
| `(run)` | 前台调试模式（缺省）：tun + 路由 + 接入器守护 |
| `service` | daemon：supervise + 控制面 IPC + 优雅停服 + 登录保持 |
| `status` | 向 daemon 发一次 Status 请求并打印 |
| `login` | 首次配置：读口令 → 0600 凭据 → 登录验证 + hostname 入册 |
| `peers [--json]` | 成员名册（VIP/主机名/账户/状态/延迟/流量） |
| `install / uninstall [--user\|--service]` | 安装/卸载服务 + 托盘自启（缺省两者） |
| `tray` | 托盘进程（连接状态/VPN IP/退出） |
| `invite <path>` | 载入邀请（b64 文本/原始字节）→ 钉扎根公钥 + 存根签目录 |
| `gen-keys` | 生成/复用设备密钥并打印公钥 |

## 目录结构

```
.
├── app/
│   ├── flock-server/        # 服务端装配：监听器(Direct/Frp) + 控制流 + Web UI
│   └── flock-client/        # 客户端装配：tun 适配 + 接入器 + 名册/托盘/服务化
├── crates/
│   ├── flock-frpc/          # frpc 子进程双栈托管（ChmlFrp 0.51.2 / 原版 frp 0.71.1）
│   └── flock-sync/          # 多主多活同步：openraft + redb + 服务器间 E2E 传输
├── deploy/                  # Docker Compose 拓扑（m2/m3/m7/e2e/webui/multinode）+ 断言脚本
├── docs/
│   ├── design.md            # 总体设计（权威文档，§编号被代码注释引用）
│   ├── manual/              # 实测/部署手册（multinode/service-install/windows-smoke…）
│   └── research/            # 选型研究报告（crypto/compression/vpn-mesh/frp-compat…）
├── .github/workflows/ci.yml # CI：三平台矩阵 test + check，ubuntu clippy/fmt
└── Cargo.lock               # 含 flock-protocol 的 git 源钉扎（rev 级）
```

密码学协议本体（kem/envelope/sig/pake/session/mux/compress/trust/roster）不在本仓——
见独立仓 [flock-protocol](https://github.com/fly88oj/flock-protocol)。

## 开发

环境：Rust **1.98.1**（`rust-toolchain.toml` 钉死）+ Docker Desktop（容器 e2e 用）。

```bash
cargo test --workspace --all-features                     # 测试门禁
cargo clippy --workspace --all-features -- -D warnings    # lint 门禁
cargo fmt --all -- --check                                # 格式门禁
cargo check -p flock-client --no-default-features         # 无头档编译面
```

协议联调（改 [flock-protocol](https://github.com/fly88oj/flock-protocol) 本地检出而主仓
依赖不动）走临时 `[patch]`——示例与注意事项见
[CONTRIBUTING.md](CONTRIBUTING.md#协议联调patch-工作流)；容器 e2e 指引与 PR 前
checklist 亦见该文档。

## 安全模型

链路上任何第三方（含 FRP 中转节点）只见本协议密文与长度。**边界声明**（全文见
[docs/design.md §2.5](docs/design.md#25-威胁模型边界明确声明防止安全主张被误读为-peer-级-e2e)）：

1. **跨 peer 流量在接入服务器明文**：首版 hub-and-spoke，客户端互访流量在接入服务器
   解密后转发——与 Tailscale「协调服务器无法解密」根本不同，任一台在册服务器可观察/
   篡改经其转发的跨 peer 流量。缓解：服务器主机加固 + 准入控制；远期：peer 间端到端
   overlay 加密（列入路线图）。
2. **任一服务器可离线字典全部口令**：攻破任一台在册服务器即得 OPRF key（OPAQUE 模型
   内固有；argon2id 是唯一减速带）。缓解：密钥 0600/内存驻留 + 准入红线；远期：OPRF
   key 门限化。
3. **TOFU 不防首登在线 MITM**：个人自建可接受；组织场景强制邀请文件。
4. **中转与链路**：FRP 中转/链路观察者只见密文与长度（长度侧信道对策见压缩档位）；
   ChmlFrp 面板凭据通道风险见设计 §5。

漏洞报告：[SECURITY.md](SECURITY.md)（GitHub 私有漏洞报告）。

## 路线图

- [ ] peer 间端到端 overlay 加密（客户端-客户端内层会话，服务器退化为盲转）
- [ ] OPRF key 门限化（quorum 解封，消除单服务器口令字典面）
- [ ] Android / iOS 客户端（tun fd 注入接缝已预留）
- [ ] `pq-sign`（ML-DSA-65 并行签名档）待独立审计后转默认开
- [x] 协议库独立发布（flock-protocol v0.1.0）

## 许可

双许可（Apache-2.0 OR MIT），任选其一：

- [LICENSE-APACHE-2.0](LICENSE-APACHE-2.0)
- [LICENSE-MIT](LICENSE-MIT)

© 2026 Flock VPN contributors
