//! # flock-frpc
//!
//! frpc 子进程双栈托管（docs/design.md §3.9 / §5 / §7-M2，★VPN-16）。
//!
//! Flock VPN 服务端经 FRP 中转暴露监听口，但**不把 frp 协议编进自身**：两套定版 frpc 二进制
//! （ChmlFrp 节点用 `ChmlFrp-0.51.2_251023`、自建节点用原版 `frp v0.71.1`）作为子进程托管，
//! 行为差异全部隔离在本 crate（§1.4-3）。选择子进程托管（方案 A）的根因：ChmlFrp 基于
//! v0.51.2（无控制面加密）与原版 ≥v0.53.0（登录后强制 AES-128-CFB）**两代控制面互不兼容**
//! （frp-compat §1.3），子进程双栈是唯一「同时兼容两家且零协议维护成本」路径（frp-compat §3）。
//!
//! 模块：
//!
//! - [`spec`]：`RelaySpec`（`ChmlFrp{mode}` | `Original{toml}`）与 `ChmlFrpMode`
//!   （`ConfigFile` 默认 `-c` 模式 / `UserTokenAuto` 显式 opt-in，R20 风险标注）+ **R9 版本
//!   矩阵锁**（ChmlFrp 节点 ⇔ ChmlFrp frpc、自建节点 ⇔ 同代原版 frpc，禁交叉）；
//! - [`config`]：配置生成器接缝（golden-file 测试守门，R8/R12——**不改面板生成的 proxy
//!   参数**，CheckProxy 会拒，frp-compat §2.3）：ChmlFrp INI（v0.51.2 方言）生成/解析/
//!   admin 注入 + 原版 TOML（v0.71.1 方言）生成/解析；
//! - [`probe`]：健康探测——本地隧道口 TCP + frpc admin（`/healthz` 免认证端点，两代同有）；
//! - [`supervisor`]：`Supervisor::start(spec) -> ManagedRelay`——进程守护（ChmlFrp frpc 三次
//!   重连失败即退出进程的魔改行为 → 退出即拉起 + 指数退避，frp-compat §2.3）与
//!   `ManagedRelay::health() -> RelayStatus`。
//!
//! 安全档（R20）：ChmlFrp `-u/-p` 自举的 cfg API 是 InsecureSkipVerify 的 HTTPS
//! （frp-compat §2.2，`chml/pkg/api/api.go:41-46`），面板全权 usertoken 可被中间人截获 ⇒
//! **默认走 `-c` 配置文件模式**（面板「隧道管理→配置文件」粘贴导出），`UserTokenAuto` 保留
//! 但需显式 opt-in（见 [`spec::ChmlFrpMode::UserTokenAuto`] 文档）。
//!
//! 本 crate 仅服务端使用（tcp 代理下客户端直连 frps 用户口，无需 frpc，frp-compat §1.1）。

#![forbid(unsafe_code)]

pub mod config;
pub mod probe;
pub mod spec;
pub mod supervisor;

pub use config::AdminCommon;
pub use probe::{AdminEndpoint, ProbeReport, ProbeResult, ProbeTargets};
pub use spec::{
    check_version_matrix, ChmlFrpMode, FrpcBinaries, FrpcBinary, FrpcError, RelayFlavor, RelaySpec,
    CHMLFRP_PINNED_VERSION, ORIGINAL_PINNED_VERSION,
};
pub use supervisor::{
    ManagedRelay, RelayPhase, RelayStatus, RestartPolicy, StopReason, Supervisor,
};
