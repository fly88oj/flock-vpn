# 贡献指南（CONTRIBUTING）

欢迎为 Flock VPN 贡献。动手前请先读 [README.md](README.md) 与总体设计
[docs/design.md](docs/design.md)（代码注释大量按 `§编号` 回链设计文档——改动行为前
先找到对应 §节，保持设计与实现同步演进）。

## 环境要求

| 项 | 要求 |
|---|---|
| Rust | **1.98.1**（仓库根 `rust-toolchain.toml` 钉死；进入仓库 rustup 自动切换） |
| Docker Desktop | 容器 e2e / 冒烟（deploy/ 下 compose 拓扑；Linux 容器，Windows/macOS 宿主均可） |
| 网络 | 首次构建需访问 GitHub：`flock-protocol` 以 git 依赖引入（tag `v0.1.0`）；镜像内构建同理 |
| 平台 | 开发任选 Windows/macOS/Linux；CI 三平台矩阵把关 |

## 克隆

```bash
git clone https://github.com/fly88oj/flock-vpn.git
cd flock-vpn
cargo test --workspace --all-features    # 首跑即门禁自证
```

协议库是**独立仓库**（不再 vendored 在本仓）：

```bash
git clone https://github.com/fly88oj/flock-protocol.git   # 仅联调/改协议时需要
```

日常改主仓无需克隆协议仓——依赖经 Cargo.lock 钉到 git rev（`?tag=v0.1.0#<rev>`）。

## 常用门禁命令清单

```bash
cargo fmt --all -- --check                                # 格式
cargo clippy --workspace --all-features -- -D warnings    # lint（警告即错）
cargo test --workspace --all-features                     # 全量测试
cargo check -p flock-client --no-default-features         # 无头档编译面（CI 同款）
```

CI（[.github/workflows/ci.yml](.github/workflows/ci.yml)）跑的就是这四条：三平台
（ubuntu-24.04 / windows-2025 / macos-14）test + check，ubuntu 追加 clippy 与 fmt。
本地全绿再提 PR。

## 协议联调：[patch] 工作流

场景：改了本地 [flock-protocol](https://github.com/fly88oj/flock-protocol) 检出，想在
主仓立即验证效果，**不等协议仓发新 tag**。

做法：在主仓根的 `.cargo/config.toml` 里**临时**加一段 `[patch]`。注意：该文件本身是
入库文件（现有内容 = wasm32 的 getrandom rustflags，须保留）——**patch 段勿提交**，
验证完即撤除（也可放到仓库外的父目录 `.cargo/config.toml`，见下「多仓联调」）：

```toml
# .cargo/config.toml —— 在既有 [target.wasm32-unknown-unknown] 段之外临时追加
# （联调用完即删，勿提交！路径按你的 protocol clone 位置调整）：
[patch."https://github.com/fly88oj/flock-protocol.git"]
flock-protocol = { path = "../flock-protocol" }
```

多仓联调（主仓 + protocol + 其他消费方同机开发）可把同一 patch 放在共同父目录的
`.cargo/config.toml`——cargo 按 cwd 向上发现配置，任意仓库内跑门禁均命中。

要点：

- patch 生效后 `cargo tree -p flock-server | head` 应显示 flock-protocol 指向本地路径；
  验证完**删除该 patch 段并确认 `git diff .cargo/` 干净**，确保提交的代码在干净克隆
  （纯 git 依赖）下也绿。
- 协议改动合入协议仓并打新 tag 后，主仓升级依赖：改三处 manifest 的 `tag =`（
  `crates/flock-sync`、`app/flock-server`、`app/flock-client`）并重新生成
  `Cargo.lock`，核对除 `flock-protocol` 源条目外**版本零漂移**。
- CI 不带 patch：PR 若只在本地 patch 下绿而在 CI 红，多半是协议 API 变更未同步主仓调用点。

## 容器 e2e 指引

前置：Docker Desktop 运行中。两档（relay / direct）端口不冲突（27500/27501 vs
9443/9444），**可并行起栈、一条命令跑全部六个冒烟**：

```bash
# relay 档需 frp 二进制资产（命名构建上下文）：
mkdir -p .tmp && cd .tmp
# 下载 frp v0.71.1 linux_amd64（github.com/fatedier/frp/releases）解压为
#   .tmp/frp_0.71.1_linux_amd64/（内含 frps/frpc）
cd ..

docker compose -f deploy/m2.yml        up -d --build   # frp 中转变体
docker compose -f deploy/m2-direct.yml up -d --build   # 直连变体（免 prepare）

cargo test -p flock-server --test smoke -- --ignored            # 全部 6 个
cargo test -p flock-server --test smoke -- --ignored direct     # 只跑 direct 3 个

docker compose -f deploy/m2.yml        down -v
docker compose -f deploy/m2-direct.yml down -v
```

更重的多机/多主拓扑（e2e.yml、multinode/）见 [deploy/](deploy/) 与
[docs/manual/](docs/manual/) 各手册；`#[ignore]` 测试均属「对容器实跑」档，不进 CI
（理由见 ci.yml 头注）。

## Commit 风格

**中文祈使句 + 作用域前缀**，一行说清「做了什么、为什么」；评审/修复类注明出处。例：

```
build(deps): flock-protocol 切换为独立仓 git 依赖（tag v0.1.0）——……
deploy: 六个 Dockerfile 与 build-wasm.sh 适配 git 依赖——……
test(sync): 流量计数跨服用例前置显式化——等 C 租约 gossip 扩散到 n0 再 ingest（修并行负载下 flaky：……）
webui(ui): round2 评审项 8 桌面 dashboard 布局——集群卡与服务器区两列并排
```

常用作用域：`build` / `deploy` / `ci` / `docs` / `test` / 模块名（`sync`、`frpc`、
`webui`、`client`、`server`、`protocol`…）。每个逻辑项一个独立 commit——依赖切换、
构建面适配、文档各自成 commit，不混装。

## PR 前 checklist

- [ ] `cargo fmt --all -- --check` 绿
- [ ] `cargo clippy --workspace --all-features -- -D warnings` 绿
- [ ] `cargo test --workspace --all-features` 绿（新增行为有对应测试）
- [ ] `cargo check -p flock-client --no-default-features` 绿（无头档未破）
- [ ] 涉及协议接口 → 先在 [flock-protocol](https://github.com/fly88oj/flock-protocol) 仓提交/发 tag，主仓锁文件同步且版本零漂移
- [ ] 涉及部署/拓扑 → 容器 e2e（上节）跑过对应档
- [ ] 涉及行为变更 → docs/design.md 对应 §节同步修订（编号被注释引用，勿裸删）
- [ ] 临时 [patch] 已撤除——干净克隆（纯 git 依赖）下可构建
- [ ] commit 按上节风格拆分

安全相关（新密码学路径、认证/信任锚改动）请先读 [SECURITY.md](SECURITY.md) 与
docs/research/crypto-2026.md，并在 PR 描述中明确威胁模型影响。
