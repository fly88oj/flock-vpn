# flock-frpc

frpc 子进程双栈托管（docs/design.md §3.9 / §5 / §7-M2，★VPN-16）。Flock VPN 服务端经
FRP 中转暴露监听口，但不把 frp 协议编进自身——两套定版 frpc 二进制作为子进程托管：

- **ChmlFrp 节点** ⇔ `ChmlFrp-0.51.2_251023` 定版 frpc（面板托管）；
- **自建节点** ⇔ 原版 frp `v0.71.1` 定版 frpc。

双栈的根因：两代控制面互不兼容（ChmlFrp 基于 v0.51.2 无控制面加密；原版 ≥v0.53.0
登录后强制 AES-128-CFB——双向均挂，`docs/research/frp-compat.md` §1.3），子进程托管是
唯一「同时兼容两家且零协议维护成本」路径（frp-compat §3 方案 A）。

## 面积

| 模块 | 内容 |
|---|---|
| `spec` | `RelaySpec::ChmlFrp{mode} / Original{toml}`；`ChmlFrpMode::ConfigFile`（默认 `-c`）/ `UserTokenAuto`（显式 opt-in，R20 风险见类型文档）；R9 版本矩阵锁（禁交叉 + 定版校验 + `--version` 实测核对） |
| `config` | 配置生成器接缝：ChmlFrp INI（v0.51.2 方言）生成/解析/`[common]`-only admin 注入（proxy 节字节透传，R12）；原版 TOML（v0.71.1 方言）生成/只读解析 |
| `probe` | 健康探测：本地隧道口 TCP + frpc admin（`/healthz`，两代同有） |
| `supervisor` | `Supervisor::start(spec) -> ManagedRelay`、`health() -> RelayStatus`、`stop()`；ChmlFrp 三次重连退出（魔改）→ 守护拉起 + 指数退避 |

## 测试

`cargo test -p flock-frpc --all-features`——含 golden-file（R8/R12：生成物与官方发行包
样本逐字节/逐字段一致）、矩阵（R9：4 组合只有对角线过）、守护（假进程桩 3 退→3 拉 +
退避下界 + 停止语义 + 探测面）。真实 frpc 二进制不进测试（假桩承担），golden 样本逐
字节复制自 `.tmp/chmlfrpc/.../frpc.ini` 与 `.tmp/frp_0.71.1_linux_amd64/frpc.toml`。

## 安全档（R20）

ChmlFrp `-u/-p` 自举的 cfg API 是 InsecureSkipVerify 的 HTTPS（面板全权 usertoken 可被
中间人截获）⇒ 默认走 `-c` 配置文件模式（面板「隧道管理→配置文件」粘贴导出）；
`UserTokenAuto` 保留但需显式 opt-in，组织/多用户机器不要启用。
