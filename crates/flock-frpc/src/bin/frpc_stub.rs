//! Fake frpc process stub (a test-only binary; the cross-platform shape of
//! §7-M2's "unit-test with a fake process (script stub)" — a Windows host
//! has no shell-script execution surface, so a Rust binary fills the same
//! role).
//!
//! Two invocation shapes:
//!
//! **1. Direct test invocation** (first arg = mode):
//! ```text
//! frpc_stub crash  --marker <file> [--lifetime-ms N] [--exit-code C]
//!     Records start → sleeps N ms → exits with code C (default 50ms/1) —
//!     simulates ChmlFrp frpc's modded "exit the process after three failed
//!     reconnects" behavior (frp-compat §2.3) for the supervision loop to
//!     pull back up.
//! frpc_stub run   --marker <file>
//!     Records start → sleeps forever (dies when killed) — simulates a
//!     healthy long-lived process.
//! frpc_stub serve --marker <file> [--addr A]
//!     Records serve (including the actually bound address) → answers 200
//!     to any HTTP request — simulates the "local tunnel port + frpc admin"
//!     probe surface. `--addr` defaults to 127.0.0.1:0 (the actual port is
//!     reported in the marker).
//! frpc_stub version --print <string> | --version | -v
//!     Prints a version string and exits — simulates `frpc --version` (used
//!     by `FrpcBinary::probe_version`); the `--version` form prints the
//!     FRPC_STUB_VERSION environment variable (default stub-0.0.0).
//! ```
//!
//! **2. frpc shape** (first arg = a flag like `-c`/`-u` — the real shape the
//! supervision layer spawns): the supervisor only ever invokes `<bin> -c
//! <file>` (ConfigFile/Original) or `<bin> -u <tok> -p <id>`
//! (UserTokenAuto); the stub receives no mode flag, so behavior and marker
//! placement follow these rules:
//! - the marker defaults to `./stub-marker.log` (cwd = the supervised
//!   run_dir, unique per relay, zero cross-test interference);
//! - when `-c <file>` is present, its `[stub]` section is scanned for
//!   behavior: `mode = crash|run` (TOML quote tolerant), `lifetime_ms = N`;
//!   default mode=run (long-lived).
//!
//! The marker writes one line per event, `<kind> <unix_millis> [extra]`;
//! start/serve events add a second line `argv <unix_millis> <all args joined
//! by spaces>` (tests use it to characterize the CLI shape the supervision
//! layer passes to the subprocess).

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

    // Shape 2: frpc-style flag invocation (the shape the supervision layer
    // spawns).
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
            // Default/`run`: long-lived until the supervision layer kills it.
            _ => {
                std::thread::sleep(Duration::from_secs(600));
                exit(0);
            }
        }
    }

    // Shape 1: direct test invocation.
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
                eprintln!("frpc_stub serve bind {addr} failed: {e}");
                exit(3);
            });
            let bound = ln.local_addr().expect("local_addr");
            mark(&flags.marker(), "serve", &bound.to_string());
            mark(&flags.marker(), "argv", &args.join(" "));
            for stream in ln.incoming() {
                let Ok(mut s) = stream else { continue };
                std::thread::spawn(move || {
                    // Read off the request head (at most 4KiB / 1s), answer
                    // with a minimal HTTP 200.
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
            eprintln!("frpc_stub: unknown mode {first:?}");
            exit(2);
        }
    }
}

/// Scan the `[stub]` section's key-values from a config file (INI or TOML
/// both fine; TOML value quotes tolerated).
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

    /// Marker path (default discards events — the stub must not distort
    /// because of test-wiring problems).
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
