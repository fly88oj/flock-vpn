//! frpc 假进程桩（测试专用二进制；§7-M2「用假进程（脚本桩）单测」的跨平台形态——
//! Windows 主机上无 shell 脚本执行面，桩用 Rust 二进制承担同一角色）。
//!
//! 两种调用形态：
//!
//! **1. 测试直调**（首参 = 模式）：
//! ```text
//! frpc_stub crash  --marker <file> [--lifetime-ms N] [--exit-code C]
//!     记录 start → 睡 N ms → 以码 C 退出（默认 50ms/1）——模拟 ChmlFrp frpc
//!     「三次重连失败即退出进程」的魔改行为（frp-compat §2.3）供守护循环拉起。
//! frpc_stub run   --marker <file>
//!     记录 start → 长眠（被 kill 即死）——模拟健康长驻进程。
//! frpc_stub serve --marker <file> [--addr A]
//!     记录 serve（含实际监听地址）→ 对任意 HTTP 请求回 200——模拟「本地隧道口 +
//!     frpc admin」探测面。`--addr` 缺省 127.0.0.1:0（marker 里回报实际端口）。
//! frpc_stub version --print <string> | --version | -v
//!     打印版本串退出——模拟 `frpc --version`（`FrpcBinary::probe_version` 用）；
//!     `--version` 形态打印环境变量 FRPC_STUB_VERSION（缺省 stub-0.0.0）。
//! ```
//!
//! **2. frpc 形态**（首参 = `-c`/`-u` 等旗标——托管层 spawn 的真实形态）：
//! 守护层只会以 `<bin> -c <file>`（ConfigFile/Original）或 `<bin> -u <tok> -p <id>`
//! （UserTokenAuto）调起，桩无旗标可传 ⇒ 行为与 marker 落点按以下规则：
//! - marker 默认 `./stub-marker.log`（cwd = 托管 run_dir，每路中继唯一，测试间零串扰）；
//! - 有 `-c <file>` 时扫描其 `[stub]` 节取行为：`mode = crash|run`（TOML 引号容忍）、
//!   `lifetime_ms = N`；缺省 mode=run（长驻）。
//!
//! marker 每事件一行 `<kind> <unix_millis> [extra]`；start/serve 事件另起一行
//! `argv <unix_millis> <全部参数空格连接>`（测试据此刻画托管层传给子进程的 CLI 形态）。

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::exit;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_MARKER: &str = "./stub-marker.log";
const DEFAULT_LIFETIME_MS: u64 = 50;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(first) = args.first().cloned() else {
        eprintln!("usage: frpc_stub <crash|run|serve|version|--version | -c/-u/-p …>");
        exit(2);
    };

    // 形态 2：frpc 式旗标调用（托管层 spawn 形态）
    if first.starts_with('-') && first != "--version" && first != "-v" {
        let marker = args
            .iter()
            .position(|a| a == "--marker")
            .and_then(|i| args.get(i + 1).cloned())
            .unwrap_or_else(|| DEFAULT_MARKER.to_string());
        let cfg_path = args
            .iter()
            .position(|a| a == "-c")
            .and_then(|i| args.get(i + 1).cloned());
        let stub_cfg = cfg_path
            .as_deref()
            .map(read_stub_section)
            .unwrap_or_default();
        let find = |k: &str| {
            stub_cfg
                .iter()
                .find(|(ek, _)| ek == k)
                .map(|(_, v)| v.clone())
        };
        let mode = find("mode").unwrap_or_else(|| "run".to_string());
        let lifetime = find("lifetime_ms")
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_LIFETIME_MS);
        let marker = PathBuf::from(marker);
        mark(&marker, "start", "");
        mark(&marker, "argv", &args.join(" "));
        match mode.as_str() {
            "crash" => {
                std::thread::sleep(Duration::from_millis(lifetime));
                exit(1);
            }
            // 缺省/`run`：长驻直到被托管层 kill
            _ => {
                std::thread::sleep(Duration::from_secs(600));
                exit(0);
            }
        }
    }

    // 形态 1：测试直调
    let flags = Flags::parse(&args[1..]);
    match first.as_str() {
        "crash" => {
            let lifetime = flags.get_usize("lifetime-ms").unwrap_or(50) as u64;
            let code = flags.get_usize("exit-code").unwrap_or(1) as i32;
            mark(&flags.marker(), "start", "");
            mark(&flags.marker(), "argv", &args.join(" "));
            std::thread::sleep(Duration::from_millis(lifetime));
            exit(code);
        }
        "run" => {
            mark(&flags.marker(), "start", "");
            mark(&flags.marker(), "argv", &args.join(" "));
            std::thread::sleep(Duration::from_secs(600));
            exit(0);
        }
        "serve" => {
            let addr = flags
                .get("addr")
                .unwrap_or_else(|| "127.0.0.1:0".to_string());
            let ln = TcpListener::bind(&addr).unwrap_or_else(|e| {
                eprintln!("frpc_stub serve bind {addr} 失败: {e}");
                exit(3);
            });
            let bound = ln.local_addr().expect("local_addr");
            mark(&flags.marker(), "serve", &bound.to_string());
            mark(&flags.marker(), "argv", &args.join(" "));
            for stream in ln.incoming() {
                let Ok(mut s) = stream else { continue };
                std::thread::spawn(move || {
                    // 读掉请求头（最多 4KiB / 1s），回最小 HTTP 200
                    let mut buf = [0u8; 4096];
                    let _ = s.set_read_timeout(Some(Duration::from_secs(1)));
                    let _ = s.read(&mut buf);
                    let _ = s.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n");
                });
            }
        }
        "version" => {
            println!(
                "{}",
                flags
                    .get("print")
                    .unwrap_or_else(|| "stub-0.0.0".to_string())
            );
            exit(0);
        }
        "--version" | "-v" => {
            println!(
                "{}",
                std::env::var("FRPC_STUB_VERSION").unwrap_or_else(|_| "stub-0.0.0".to_string())
            );
            exit(0);
        }
        _ => {
            eprintln!("frpc_stub: 未知模式 {first:?}");
            exit(2);
        }
    }
}

/// 从配置文件（INI 或 TOML 均可）扫描 `[stub]` 节的键值（TOML 值引号容忍）。
fn read_stub_section(path: &str) -> Vec<(String, String)> {
    let Ok(mut f) = File::open(path) else {
        return Vec::new();
    };
    let mut text = String::new();
    if f.read_to_string(&mut text).is_err() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut in_stub = false;
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            in_stub = name.trim() == "stub";
            continue;
        }
        if !in_stub {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim().trim_matches('"').trim_matches('\'');
            out.push((k.trim().to_string(), v.to_string()));
        }
    }
    out
}

struct Flags(Vec<(String, String)>);

impl Flags {
    fn parse(args: &[String]) -> Self {
        let mut out = Vec::new();
        let mut i = 0;
        while i < args.len() {
            if let Some(name) = args[i].strip_prefix("--") {
                let value = args.get(i + 1).cloned().unwrap_or_default();
                out.push((name.to_string(), value));
                i += 2;
            } else {
                i += 1;
            }
        }
        Flags(out)
    }

    fn get(&self, name: &str) -> Option<String> {
        self.0
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    }

    fn get_usize(&self, name: &str) -> Option<usize> {
        self.get(name).and_then(|v| v.parse().ok())
    }

    /// marker 路径（缺省丢弃事件——桩不因测试布线问题而失真）。
    fn marker(&self) -> PathBuf {
        self.get("marker")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/dev/null"))
    }
}

fn mark(path: &PathBuf, kind: &str, extra: &str) {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let line = if extra.is_empty() {
            format!("{kind} {now_ms}\n")
        } else {
            format!("{kind} {now_ms} {extra}\n")
        };
        let _ = f.write_all(line.as_bytes());
    }
}
