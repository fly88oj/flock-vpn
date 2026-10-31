//! 集成测试共享工具。

use std::process::{Command, Stdio};
use std::sync::OnceLock;

/// 桩二进制预热（每测试进程一次）。
///
/// 本开发机（沙箱/AV 环境）对 frpc_stub.exe 的**首次** CreateProcess 在「argv 引用刚
/// 写入的文件 + cwd 指向其目录」的组合下会被实时扫描同步阻塞（曾无限期挂起；诊断
/// 实验：同参数 std 与 tokio spawn 同挂 ⇒ 环境层而非库层；预热一次后同组合 10ms 内
/// 完成）。先用朴素参数 spawn 一发立即退出的 `version` 模式把扫描吸收掉，后续守护
/// spawn 全部走热路径。生产托管不受影响（无本测试桩）。
pub fn prewarm_stub() {
    static WARM: OnceLock<()> = OnceLock::new();
    WARM.get_or_init(|| {
        let ok = Command::new(env!("CARGO_BIN_EXE_frpc_stub"))
            .args(["version", "--print", "warm"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(ok, "frpc_stub 预热失败（version 模式应立即成功退出）");
    });
}
