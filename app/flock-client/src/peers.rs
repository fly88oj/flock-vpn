//! 名册组装与渲染（M7 §7-M7.7）：`PeerRow = PeerInfo + latency + self` → 表格/--json。
//!
//! 状态列三态：`在线`（roster `online`）/ `离线`（Device 型）/ `服务未运行`
//!（Server 型离线——中继/服务器本体不在，与设备「离线」可区分）。离线行延迟列
//! `—`（不探测——离线无探测语义；online 非自身行探测失败也是 `—`）。

use std::net::Ipv4Addr;

use flock_protocol::roster::{PeerInfo, PeerKind};

use crate::ping::{probe_latency, Pinger};

/// 增强名册行（IPC `Peers` 响应载荷）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerRow {
    pub info: PeerInfo,
    /// 中位 RTT（ms）；离线/探测失败 ⇒ None。
    pub latency_ms: Option<u32>,
    /// 本机行（名册含自身——CLI 以 `(self)` 标注、不探测）。
    pub self_flag: bool,
}

/// 组装增强名册：self 标注（VIP 比对）+ 对 online 非自身行**并发**探测。
///
/// `self_vip: None` 降级档（评审项 8 说明）：服务装配恒 `Some`（daemon 启动即
/// resolve_vip），None 仅测试/异常注入面可达——无 VIP 可比对 ⇒ **无行可标
/// `(self)`，本机行按普通 online 行被探测**：本机 VIP 是本机本地地址，ICMP echo
/// 由本机协议栈本地应答（不经 tun），延迟列显示 ~0ms——显示语义降级（自身行不
/// 标注、延迟列失真为 ~0）而非功能错误，CLI 仍可用。
pub async fn assemble_rows(
    peers: Vec<PeerInfo>,
    self_vip: Option<Ipv4Addr>,
    pinger: Option<&dyn Pinger>,
) -> Vec<PeerRow> {
    // 行标注先行（探测目标收集）。
    let mut rows: Vec<PeerRow> = peers
        .into_iter()
        .map(|info| {
            let self_flag = Some(Ipv4Addr::from(info.vip)) == self_vip;
            PeerRow {
                info,
                latency_ms: None,
                self_flag,
            }
        })
        .collect();
    let Some(pinger) = pinger else {
        return rows; // 无探测权限/未装配——延迟列全 None（CLI 照常渲染）
    };
    // 并发探测（每目标内部 3 探针顺序——§7-M7.7「对 online 且非自身的 VIP 并发」）。
    let mut probes = Vec::with_capacity(rows.len());
    for r in &rows {
        if r.info.online && !r.self_flag {
            let target = Ipv4Addr::from(r.info.vip);
            probes.push(async move { (target, probe_latency(pinger, target).await) });
        }
    }
    let results = futures::future::join_all(probes).await;
    for r in rows.iter_mut() {
        if r.info.online && !r.self_flag {
            let target = Ipv4Addr::from(r.info.vip);
            if let Some((_, Some(ms))) = results.iter().find(|(t, _)| *t == target) {
                r.latency_ms = Some(*ms);
            }
        }
    }
    rows
}

// ============================================================================
// 表格渲染（对齐列；char 计宽——CJK 主机名列不严格对齐，OS 主机名常态 ASCII）
// ============================================================================

/// 状态列文本（三态）。
fn status_text(info: &PeerInfo) -> &'static str {
    match (info.kind, info.online) {
        (_, true) => "在线",
        (PeerKind::Device, false) => "离线",
        (PeerKind::Server, false) => "服务未运行",
    }
}

fn type_text(kind: PeerKind) -> &'static str {
    match kind {
        PeerKind::Device => "device",
        PeerKind::Server => "server",
    }
}

/// 表格渲染：`VIP｜主机名｜账户｜类型｜状态｜延迟(ms)｜↓流量(B/s)｜↑流量(B/s)`；
/// 离线延迟 `—`；自身行主机名后缀 `(self)`。
pub fn render_table(rows: &[PeerRow]) -> String {
    let headers = [
        "VIP",
        "主机名",
        "账户",
        "类型",
        "状态",
        "延迟(ms)",
        "↓流量(B/s)",
        "↑流量(B/s)",
    ];
    // 每行单元格（char 计宽）。
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                Ipv4Addr::from(r.info.vip).to_string(),
                if r.self_flag {
                    format!("{}(self)", r.info.hostname)
                } else {
                    r.info.hostname.clone()
                },
                r.info.owner.clone(),
                type_text(r.info.kind).to_string(),
                status_text(&r.info).to_string(),
                match r.latency_ms {
                    Some(ms) => ms.to_string(),
                    None => "—".into(),
                },
                r.info.rx_bps.to_string(),
                r.info.tx_bps.to_string(),
            ]
        })
        .collect();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in &cells {
        for (i, c) in row.iter().enumerate() {
            widths[i] = widths[i].max(c.chars().count());
        }
    }
    let mut out = String::new();
    let header: Vec<&str> = headers.to_vec();
    push_padded(&mut out, &header, &widths);
    out.push('\n');
    out.push_str(&"-".repeat(widths.iter().sum::<usize>() + widths.len().saturating_sub(1) * 3));
    out.push('\n');
    for row in &cells {
        let refs: Vec<&str> = row.iter().map(|s| s.as_str()).collect();
        push_padded(&mut out, &refs, &widths);
        out.push('\n');
    }
    out
}

fn push_padded(out: &mut String, cells: &[&str], widths: &[usize]) {
    for (i, c) in cells.iter().enumerate() {
        if i > 0 {
            out.push_str(" | ");
        }
        out.push_str(c);
        let pad = widths[i].saturating_sub(c.chars().count());
        for _ in 0..pad {
            out.push(' ');
        }
    }
    // 去行尾填充空格。
    while out.ends_with(' ') {
        out.pop();
    }
}

// ============================================================================
// --json 机读档（字段全集 + 原始值；消费方：编排/面板）
// ============================================================================

/// JSON 行形状（snake_case；延迟 null = 离线/未探测）。
#[derive(serde::Serialize)]
pub struct PeerJson<'a> {
    pub vip: String,
    pub hostname: &'a str,
    pub owner: &'a str,
    pub kind: &'a str,
    pub online: bool,
    pub last_seen_unix: u64,
    pub tx_bps: u64,
    pub rx_bps: u64,
    pub latency_ms: Option<u32>,
    pub is_self: bool,
}

/// `--json` 输出（数组；解析失败即 CLI 错误）。
pub fn render_json(rows: &[PeerRow]) -> Result<String, String> {
    let arr: Vec<PeerJson> = rows
        .iter()
        .map(|r| PeerJson {
            vip: Ipv4Addr::from(r.info.vip).to_string(),
            hostname: &r.info.hostname,
            owner: &r.info.owner,
            kind: type_text(r.info.kind),
            online: r.info.online,
            last_seen_unix: r.info.last_seen_unix,
            tx_bps: r.info.tx_bps,
            rx_bps: r.info.rx_bps,
            latency_ms: r.latency_ms,
            is_self: r.self_flag,
        })
        .collect();
    serde_json::to_string_pretty(&arr).map_err(|e| e.to_string())
}

// ============================================================================
// 单元测试：表格渲染全分支 + 组装（mock pinger）+ JSON 可解析
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn row(vip: [u8; 4], hostname: &str, owner: &str, kind: PeerKind, online: bool) -> PeerInfo {
        PeerInfo {
            vip,
            hostname: hostname.into(),
            owner: owner.into(),
            kind,
            online,
            last_seen_unix: 1,
            tx_bps: 111,
            rx_bps: 222,
        }
    }

    /// 三态 + 延迟/自身全分支：在线有延迟、离线 `—`、Server 离线 = 服务未运行、
    /// 自身标注、列对齐（各列宽 ≥ 表头）。
    #[test]
    fn render_table_all_status_branches() {
        let rows = vec![
            PeerRow {
                info: row([100, 64, 0, 1], "frps:27500", "1", PeerKind::Server, true),
                latency_ms: Some(3),
                self_flag: false,
            },
            PeerRow {
                info: row([100, 64, 0, 11], "box-a", "alice", PeerKind::Device, true),
                latency_ms: None, // 在线但探测失败（容错档）
                self_flag: true,
            },
            PeerRow {
                info: row([100, 64, 0, 12], "box-b", "bob", PeerKind::Device, false),
                latency_ms: None,
                self_flag: false,
            },
            PeerRow {
                info: row([100, 64, 0, 2], "frps-b", "2", PeerKind::Server, false),
                latency_ms: None,
                self_flag: false,
            },
        ];
        let table = render_table(&rows);
        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(lines.len(), 6, "表头 + 分隔线 + 4 行");
        assert!(
            lines[0].contains("VIP")
                && lines[0].contains("主机名")
                && lines[0].contains("↓流量(B/s)")
        );
        // 分支断言。
        assert!(
            lines[2].contains("在线") && lines[2].contains("3"),
            "在线 server + 延迟 3"
        );
        assert!(lines[3].contains("box-a(self)"), "自身标注");
        assert!(
            lines[3].contains("在线") && lines[3].contains("—"),
            "在线但未探测 ⇒ 延迟 —"
        );
        assert!(
            lines[4].contains("离线") && lines[4].contains("—"),
            "离线设备 ⇒ 离线 + —"
        );
        assert!(lines[5].contains("服务未运行"), "Server 离线 ⇒ 服务未运行");
        // 对齐：数据行同列起止一致（char 计宽下的定长列）。
        let vip_starts: Vec<usize> = lines[2..]
            .iter()
            .map(|l| l.find("100.64").unwrap())
            .collect();
        assert!(vip_starts.windows(2).all(|w| w[0] == w[1]), "VIP 列对齐");
    }

    /// 组装：并发探测仅作用于 online 非自身行（mock 全 42ms）；离线行不探测。
    struct FixedPinger(Option<u32>);
    impl Pinger for FixedPinger {
        fn rtt(
            &self,
            _t: Ipv4Addr,
            _s: u16,
            _d: std::time::Duration,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Option<std::time::Duration>> + Send + '_>,
        > {
            let v = self.0;
            Box::pin(std::future::ready(
                v.map(|ms| std::time::Duration::from_millis(ms as u64)),
            ))
        }
    }

    #[tokio::test]
    async fn assemble_marks_self_and_probes_online_non_self() {
        let peers = vec![
            row([100, 64, 0, 1], "srv", "1", PeerKind::Server, true),
            row([100, 64, 0, 11], "me", "alice", PeerKind::Device, true),
            row([100, 64, 0, 12], "off", "bob", PeerKind::Device, false),
        ];
        let pinger = FixedPinger(Some(42));
        let rows = assemble_rows(peers, Some("100.64.0.11".parse().unwrap()), Some(&pinger)).await;
        assert_eq!(rows[0].latency_ms, Some(42), "online 非自身 ⇒ 探测值");
        assert!(rows[1].self_flag, "VIP 比对 ⇒ self");
        assert_eq!(rows[1].latency_ms, None, "自身不探测");
        assert_eq!(rows[2].latency_ms, None, "离线不探测");
        // 无 pinger（无特权档）⇒ 全 None 但行完整。
        let rows2 = assemble_rows(
            vec![row([100, 64, 0, 1], "srv", "1", PeerKind::Server, true)],
            None,
            None,
        )
        .await;
        assert_eq!(rows2[0].latency_ms, None);
    }

    /// JSON 可解析 + 字段语义（离线延迟 null）。
    #[test]
    fn render_json_parses_with_null_latency() {
        let rows = vec![
            PeerRow {
                info: row([100, 64, 0, 12], "box-b", "bob", PeerKind::Device, false),
                latency_ms: None,
                self_flag: false,
            },
            PeerRow {
                info: row([100, 64, 0, 11], "box-a", "alice", PeerKind::Device, true),
                latency_ms: Some(9),
                self_flag: true,
            },
        ];
        let text = render_json(&rows).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["vip"], "100.64.0.12");
        assert_eq!(arr[0]["latency_ms"], serde_json::Value::Null);
        assert_eq!(arr[0]["online"], false);
        assert_eq!(arr[1]["latency_ms"], 9);
        assert_eq!(arr[1]["is_self"], true);
        assert_eq!(arr[1]["kind"], "device");
    }
}
