//! `RelaySpec` 与 R9 版本矩阵锁（docs/design.md §3.9 / §5-4；frp-compat §1.3/§4-R9）。

use std::fmt;
use std::path::{Path, PathBuf};

/// ChmlFrp 定版 frpc 版本串（`frpc --version` 输出形态；frp-compat §2.1：
/// `pkg/util/version/version.go` = `"ChmlFrp-0.51.2_251023"`）。
pub const CHMLFRP_PINNED_VERSION: &str = "ChmlFrp-0.51.2_251023";

/// 原版定版 frpc 版本串（设计 §5 定版 v0.71.1；frp-compat §1：
/// GitHub Releases `v0.71.1 / 2026-10-14`，`frps --version` 容器实测 `0.71.1`）。
pub const ORIGINAL_PINNED_VERSION: &str = "0.71.1";

/// 中转栈代（节点风格 = frpc 变体，二者一一绑定）。
///
/// R9 矩阵锁的「行/列」：两代控制面互不兼容（ChmlFrp 基线 v0.51.2 无控制面加密；
/// 原版 ≥v0.53.0 登录后强制 AES-128-CFB token 派生加密——双向均不兼容，frp-compat §1.3），
/// 因此栈代是节点与 frpc 二进制的**共同**标识，禁交叉配对。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RelayFlavor {
    /// ChmlFrp 节点（面板托管，CheckProxy 白名单、套餐限速 8–32Mbps，frp-compat §2.3）。
    ChmlFrp,
    /// 自建原版节点（frps 由运维部署，frpc 与 frps 同代原版，frp-compat §1）。
    Original,
}

impl RelayFlavor {
    /// 该栈代允许的 frpc 定版版本串（§5 双栈定版；换版 = 改此表 + 过 golden/矩阵测试）。
    pub fn pinned_version(self) -> &'static str {
        match self {
            RelayFlavor::ChmlFrp => CHMLFRP_PINNED_VERSION,
            RelayFlavor::Original => ORIGINAL_PINNED_VERSION,
        }
    }
}

impl fmt::Display for RelayFlavor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RelayFlavor::ChmlFrp => "chmlfrp",
            RelayFlavor::Original => "original",
        })
    }
}

/// 中继接入规格：`Supervisor::start` 的输入（§3.9 接口）。
#[derive(Clone, Debug)]
pub enum RelaySpec {
    /// ChmlFrp 节点 ⇔ ChmlFrp frpc（`ChmlFrp-0.51.2_251023` 定版）。
    ChmlFrp {
        /// 接入模式：默认 [`ChmlFrpMode::ConfigFile`]（`-c`），`UserTokenAuto` 显式 opt-in。
        mode: ChmlFrpMode,
    },
    /// 自建原版节点 ⇔ 原版 frpc（v0.71.1 定版）。
    ///
    /// `toml` = 原版 frpc TOML 配置文件路径（v0.71.1 方言：`serverAddr`/`serverPort`/
    /// `[[proxies]]` camelCase，样本见 `.tmp/frp_0.71.1_linux_amd64/frpc.toml`）。
    /// 托管层**只读**该文件（推导探活目标），绝不改写。
    Original { toml: PathBuf },
}

impl RelaySpec {
    /// 栈代（R9 矩阵的 spec 侧标识）。
    pub fn flavor(&self) -> RelayFlavor {
        match self {
            RelaySpec::ChmlFrp { .. } => RelayFlavor::ChmlFrp,
            RelaySpec::Original { .. } => RelayFlavor::Original,
        }
    }
}

/// ChmlFrp 接入模式（§3.9；frp-compat §2.2/§2.3）。
#[derive(Clone, Debug)]
pub enum ChmlFrpMode {
    /// **默认模式**：面板「隧道管理→配置文件」粘贴导出的 frpc.ini，frpc 以 `-c <ini>` 启动。
    ///
    /// 面板生成的 proxy 参数（类型/端口/名称等）由服务端 CheckProxy 与面板记录逐项比对，
    /// 不一致即拒（"客户端代理参数错误"，frp-compat §2.3）⇒ 托管层对这些字段**字节级透传**
    /// （见 [`crate::config`] 的 golden 守门），仅允许向 `[common]` 注入 admin 探测字段。
    ConfigFile(
        /// 面板导出的 frpc.ini 路径。
        PathBuf,
    ),
    /// **显式 opt-in**：`frpc -u <usertoken> -p <tunnel_id>` 自举（魔改 CLI，root.go:92-93）。
    ///
    /// 启动流程：frpc 自行 `GET https://cf-v2.uapis.cn/cfg?action=getcfg&token=<usertoken>
    /// &id=<tunnel_id>` 拉取面板生成的 frpc.ini 全文 → 覆写本地 `./frpc.ini`（cwd 相对，
    /// root.go:133-174）→ 按原版流程启动。
    ///
    /// # 风险（R20，opt-in 前必读）
    ///
    /// - cfg API 走 **InsecureSkipVerify** 的 HTTPS（`chml/pkg/api/api.go:41-46`）：中间人
    ///   可截获面板全权 usertoken（可建/删/改隧道的凭据）；
    /// - usertoken 进入子进程命令行（`ps`/`/proc/<pid>/cmdline` 对同机其他用户可读）；
    /// - 拉取的配置对托管层不透明（探活目标无法预推导，[`crate::probe`] 只剩进程状态面）。
    ///
    /// 组织/多用户机器不要启用；默认 [`ChmlFrpMode::ConfigFile`]（§8-R20 对策）。
    UserTokenAuto {
        /// 面板 usertoken（**凭据**：面板全权；勿入日志）。
        usertoken: String,
        /// 隧道数字 ID（面板「隧道管理」可见；`-p/--id`）。
        tunnel_id: u64,
    },
}

/// 定版 frpc 二进制声明（R9 矩阵的二进制侧标识）。
///
/// `decl_version` 是**运维声明**的版本（应与 `<bin> --version` 输出一致）。声明≠定版
/// 即被 [`check_version_matrix`] 拒绝；「实测 `--version` ↔ 声明」的进程级核对是
/// 测试面纪律（tests/matrix.rs 的测试内 helper 承担，不占生产启动路径——多一次
/// 子进程往返，生产恒不开）。
#[derive(Clone, Debug)]
pub struct FrpcBinary {
    /// 二进制路径。
    pub path: PathBuf,
    /// 栈代。
    pub flavor: RelayFlavor,
    /// 声明版本串（`--version` 输出形态）。
    pub decl_version: String,
}

/// R9 版本矩阵锁：spec 栈代 ⇔ frpc 二进制栈代 ⇔ 定版版本，禁交叉。
///
/// 合法配对只有对角线：
///
/// | spec \ bin | ChmlFrp          | Original           |
/// |------------|------------------|--------------------|
/// | ChmlFrp    | ✅ `ChmlFrp-0.51.2_251023` | ❌ 两代控制面互不兼容 |
/// | Original   | ❌ 同上            | ✅ `0.71.1`          |
///
/// 机理（frp-compat §1.3 源码级证实）：ChmlFrp frpc（v0.51.2 基线，无控制面加密）连原版
/// frps ≥v0.53.0 会在对端开启 AES-128-CFB 后握手失败；原版 frpc ≥v0.53.0 连 ChmlFrp 节点
/// 则对不加密控制面同样失败——**双向均挂**。CI 矩阵冒烟（4 组合断言只有对角线成功）在
/// 本函数的单测中固化（`tests/matrix.rs`）。
pub fn check_version_matrix(
    spec_flavor: RelayFlavor,
    decl_version: &str,
    bin: &FrpcBinary,
) -> Result<(), FrpcError> {
    if spec_flavor != bin.flavor {
        return Err(FrpcError::Matrix(format!(
            "R9 版本矩阵禁止交叉：{} 规格 × {} frpc（{}）——两代控制面互不兼容（frp-compat §1.3）",
            spec_flavor,
            bin.flavor,
            bin.path.display()
        )));
    }
    let pinned = spec_flavor.pinned_version();
    if decl_version != pinned {
        return Err(FrpcError::Matrix(format!(
            "R9 定版校验失败：{} 栈代要求 frpc 版本 {pinned:?}，声明为 {decl_version:?}（{}）",
            spec_flavor,
            bin.path.display()
        )));
    }
    Ok(())
}

/// RelaySpec 结构校验（含 R9 矩阵）。文件级检查（存在性/可解析）在此层，
/// 进程级失败留给 [`crate::supervisor::Supervisor::start`]。
pub(crate) fn validate_spec(
    spec: &RelaySpec,
    bins: &FrpcBinaries,
) -> Result<ValidatedSpec, FrpcError> {
    let flavor = spec.flavor();
    match spec {
        RelaySpec::ChmlFrp { mode } => {
            let bin = bins.chmlfrp.clone();
            check_version_matrix(flavor, &bin.decl_version, &bin)?;
            match mode {
                ChmlFrpMode::ConfigFile(ini) => {
                    ensure_readable_file(ini, "ChmlFrp 面板 frpc.ini")?;
                }
                ChmlFrpMode::UserTokenAuto {
                    usertoken,
                    tunnel_id,
                } => {
                    if usertoken.trim().is_empty() {
                        return Err(FrpcError::Spec("UserTokenAuto: usertoken 为空".into()));
                    }
                    if *tunnel_id == 0 {
                        return Err(FrpcError::Spec("UserTokenAuto: tunnel_id 为 0".into()));
                    }
                }
            }
            Ok(ValidatedSpec {
                spec: spec.clone(),
                bin,
            })
        }
        RelaySpec::Original { toml } => {
            let bin = bins.original.clone();
            check_version_matrix(flavor, &bin.decl_version, &bin)?;
            ensure_readable_file(toml, "原版 frpc.toml")?;
            // 早失败：TOML 解析不了就别等子进程退出码了（文件是调用方资产，只读）。
            let _ = crate::config::parse_original_toml(toml)?;
            Ok(ValidatedSpec {
                spec: spec.clone(),
                bin,
            })
        }
    }
}

/// 双栈定版二进制表（`Supervisor` 持有；两栈都常驻，按 spec 分派）。
#[derive(Clone, Debug)]
pub struct FrpcBinaries {
    /// ChmlFrp 节点栈（`ChmlFrp-0.51.2_251023` 定版）。
    pub chmlfrp: FrpcBinary,
    /// 自建原版节点栈（`0.71.1` 定版）。
    pub original: FrpcBinary,
}

#[derive(Debug)]
pub(crate) struct ValidatedSpec {
    /// 已校验的 spec（后续以校验后的形态参与启动计划组装）。
    pub spec: RelaySpec,
    pub bin: FrpcBinary,
}

fn ensure_readable_file(p: &Path, what: &str) -> Result<(), FrpcError> {
    if !p.is_file() {
        return Err(FrpcError::Spec(format!(
            "{what} 不存在或不是文件：{}",
            p.display()
        )));
    }
    Ok(())
}

/// 托管错误。
#[derive(Debug)]
pub enum FrpcError {
    /// RelaySpec 结构/文件校验失败。
    Spec(String),
    /// R9 版本矩阵违例（交叉/非定版）。
    Matrix(String),
    /// 子进程 spawn 失败（二进制缺失/不可执行等）。
    Spawn(String),
    /// 配置生成/解析失败（golden 守门对象，frp-compat §4-R8/R12）。
    Config(String),
    /// IO 错误。
    Io(std::io::Error),
}

impl fmt::Display for FrpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrpcError::Spec(m) => write!(f, "frpc spec 校验失败: {m}"),
            FrpcError::Matrix(m) => write!(f, "frpc 版本矩阵: {m}"),
            FrpcError::Spawn(m) => write!(f, "frpc 子进程: {m}"),
            FrpcError::Config(m) => write!(f, "frpc 配置: {m}"),
            FrpcError::Io(e) => write!(f, "frpc IO: {e}"),
        }
    }
}

impl std::error::Error for FrpcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FrpcError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for FrpcError {
    fn from(e: std::io::Error) -> Self {
        FrpcError::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bins(chmlfrp_ver: &str, original_ver: &str) -> FrpcBinaries {
        FrpcBinaries {
            chmlfrp: FrpcBinary {
                path: PathBuf::from("bin/chmlfrpc"),
                flavor: RelayFlavor::ChmlFrp,
                decl_version: chmlfrp_ver.into(),
            },
            original: FrpcBinary {
                path: PathBuf::from("bin/frpc"),
                flavor: RelayFlavor::Original,
                decl_version: original_ver.into(),
            },
        }
    }

    #[test]
    fn flavor_pinned_versions() {
        assert_eq!(
            RelayFlavor::ChmlFrp.pinned_version(),
            "ChmlFrp-0.51.2_251023"
        );
        assert_eq!(RelayFlavor::Original.pinned_version(), "0.71.1");
    }

    #[test]
    fn user_token_auto_rejects_empty_token_and_zero_id() {
        let b = bins(CHMLFRP_PINNED_VERSION, ORIGINAL_PINNED_VERSION);
        let err = validate_spec(
            &RelaySpec::ChmlFrp {
                mode: ChmlFrpMode::UserTokenAuto {
                    usertoken: "  ".into(),
                    tunnel_id: 42,
                },
            },
            &b,
        )
        .unwrap_err();
        assert!(matches!(err, FrpcError::Spec(ref m) if m.contains("usertoken")));
        let err = validate_spec(
            &RelaySpec::ChmlFrp {
                mode: ChmlFrpMode::UserTokenAuto {
                    usertoken: "tok".into(),
                    tunnel_id: 0,
                },
            },
            &b,
        )
        .unwrap_err();
        assert!(matches!(err, FrpcError::Spec(ref m) if m.contains("tunnel_id")));
    }

    #[test]
    fn config_file_mode_requires_existing_ini() {
        let b = bins(CHMLFRP_PINNED_VERSION, ORIGINAL_PINNED_VERSION);
        let err = validate_spec(
            &RelaySpec::ChmlFrp {
                mode: ChmlFrpMode::ConfigFile(PathBuf::from("no/such.ini")),
            },
            &b,
        )
        .unwrap_err();
        assert!(matches!(err, FrpcError::Spec(_)));
    }
}
