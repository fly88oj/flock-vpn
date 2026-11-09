//! Roster assembly and rendering (M7 §7-M7.7): `PeerRow = PeerInfo +
//! latency + self` → table/--json.
//!
//! Status column has three states: `online` (roster `online`) / `offline`
//! (Device kind) / `service not running` (Server kind offline — the
//! relay/server itself is absent, distinguishable from a device being
//! "offline"). Offline rows show `—` in the latency column (not probed — no
//! probing semantics while offline; online non-self rows that fail probing
//! also show `—`).
//!
//! The table renders through the [`crate::lang`] pack (interactive CLI
//! copy); the `--json` output is a fixed English machine format.

use std::net::Ipv4Addr;

use flock_protocol::roster::{PeerInfo, PeerKind};

use crate::lang::{Key, Lang};
use crate::ping::{probe_latency, Pinger};

/// Enhanced roster row (IPC `Peers` response payload).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerRow {
    pub info: PeerInfo,
    /// Median RTT (ms); offline/probe failure ⇒ None.
    pub latency_ms: Option<u32>,
    /// This-machine row (the roster includes self — the CLI marks it with
    /// `(self)` and does not probe it).
    pub self_flag: bool,
}

/// Assemble the enhanced roster: self marking (VIP comparison) + concurrent
/// probing of online non-self rows.
///
/// `self_vip: None` degraded mode (review item 8 note): the service assembly
/// is always `Some` (the daemon resolves the VIP at startup); None is
/// reachable only via test/abnormal injection — with no VIP to compare, **no
/// row can be marked `(self)` and the local row gets probed as an ordinary
/// online row**: the local VIP is a local address of this machine, so the
/// ICMP echo is answered locally by the machine's own stack (not through
/// tun), and the latency column shows ~0ms — a display-semantics degradation
/// (self row unmarked, latency column distorted to ~0) rather than a
/// functional error; the CLI remains usable.
pub async fn assemble_rows(
    peers: Vec<PeerInfo>,
    self_vip: Option<Ipv4Addr>,
    pinger: Option<&dyn Pinger>,
) -> Vec<PeerRow> {
    // Row marking first (probe-target collection).
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
        return rows; // no probe privilege / not assembled — latency column all None (CLI renders as usual)
    };
    // Concurrent probing (3 sequential probes per target internally —
    // §7-M7.7 "concurrent against online, non-self VIPs").
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
// Table rendering (aligned columns; char-counted widths — a CJK hostname
// column will not be strictly aligned, but OS hostnames are usually ASCII)
// ============================================================================

/// Status-column text (three states), localized.
fn status_text(info: &PeerInfo, lang: Lang) -> &'static str {
    match (info.kind, info.online) {
        (_, true) => lang.tr(Key::PeersStatusOnline),
        (PeerKind::Device, false) => lang.tr(Key::PeersStatusOffline),
        (PeerKind::Server, false) => lang.tr(Key::PeersStatusServerDown),
    }
}

fn type_text(kind: PeerKind) -> &'static str {
    match kind {
        PeerKind::Device => "device",
        PeerKind::Server => "server",
    }
}

/// Table rendering: `VIP | Hostname | Account | Type | Status | Latency(ms)
/// | Down(B/s) | Up(B/s)`; offline latency `—`; self rows get a `(self)`
/// hostname suffix. Interactive copy goes through the language pack.
pub fn render_table(rows: &[PeerRow], lang: Lang) -> String {
    let headers = [
        "VIP",
        lang.tr(Key::PeersHdrHostname),
        lang.tr(Key::PeersHdrAccount),
        lang.tr(Key::PeersHdrType),
        lang.tr(Key::PeersHdrStatus),
        lang.tr(Key::PeersHdrLatency),
        lang.tr(Key::PeersHdrDown),
        lang.tr(Key::PeersHdrUp),
    ];
    // Per-row cells (char-counted widths).
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
                status_text(&r.info, lang).to_string(),
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
    // Trim trailing padding spaces on the line.
    while out.ends_with(' ') {
        out.pop();
    }
}

// ============================================================================
// --json machine-readable form (full field set + raw values; consumers:
// orchestration/panels)
// ============================================================================

/// JSON row shape (snake_case; latency null = offline/not probed).
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

/// `--json` output (array; a parse failure becomes a CLI error). Fixed
/// English machine format — deliberately not localized.
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
// Unit tests: all table-rendering branches + assembly (mock pinger) + JSON
// parseability
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

    /// Three states + all latency/self branches: online with latency,
    /// offline `—`, Server offline = service not running, self marking,
    /// column alignment (each column width ≥ header). Default (en) copy.
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
                latency_ms: None, // online but probing failed (tolerant mode)
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
        let table = render_table(&rows, Lang::En);
        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(lines.len(), 6, "header + separator + 4 rows");
        assert!(
            lines[0].contains("VIP")
                && lines[0].contains("Hostname")
                && lines[0].contains("Down(B/s)")
        );
        // Branch assertions.
        assert!(
            lines[2].contains("online") && lines[2].contains("3"),
            "online server + latency 3"
        );
        assert!(lines[3].contains("box-a(self)"), "self marking");
        assert!(
            lines[3].contains("online") && lines[3].contains("—"),
            "online but not probed ⇒ latency —"
        );
        assert!(
            lines[4].contains("offline") && lines[4].contains("—"),
            "offline device ⇒ offline + —"
        );
        assert!(
            lines[5].contains("service not running"),
            "offline Server ⇒ service not running"
        );
        // Alignment: data rows share the same column start (fixed-width
        // columns under char counting).
        let vip_starts: Vec<usize> = lines[2..]
            .iter()
            .map(|l| l.find("100.64").unwrap())
            .collect();
        assert!(
            vip_starts.windows(2).all(|w| w[0] == w[1]),
            "VIP column aligned"
        );
    }

    /// zh pack renders the same table shape with Chinese headers/status
    /// (interactive copy follows `[general] language`). Asserted against the
    /// pack entries themselves — the pack's own content lives (and is
    /// literal-checked) in `lang::tests`; no Chinese literals here.
    #[test]
    fn render_table_zh_pack_headers_and_status() {
        let zh = Lang::Zh;
        let rows = vec![
            PeerRow {
                info: row([100, 64, 0, 1], "frps:27500", "1", PeerKind::Server, true),
                latency_ms: Some(3),
                self_flag: false,
            },
            PeerRow {
                info: row([100, 64, 0, 2], "frps-b", "2", PeerKind::Server, false),
                latency_ms: None,
                self_flag: false,
            },
        ];
        let table = render_table(&rows, zh);
        let lines: Vec<&str> = table.lines().collect();
        assert!(
            lines[0].contains(zh.tr(Key::PeersHdrHostname))
                && lines[0].contains(zh.tr(Key::PeersHdrDown))
        );
        assert!(
            lines[2].contains(zh.tr(Key::PeersStatusOnline)),
            "online server"
        );
        assert!(
            lines[3].contains(zh.tr(Key::PeersStatusServerDown)),
            "offline Server ⇒ service-not-running status text"
        );
        // Localization actually switched (en and zh tables differ).
        assert_ne!(table, render_table(&rows, Lang::En));
    }

    /// Assembly: concurrent probing applies only to online non-self rows
    /// (mock returns 42ms for all); offline rows are not probed.
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
        assert_eq!(
            rows[0].latency_ms,
            Some(42),
            "online non-self ⇒ probed value"
        );
        assert!(rows[1].self_flag, "VIP comparison ⇒ self");
        assert_eq!(rows[1].latency_ms, None, "self not probed");
        assert_eq!(rows[2].latency_ms, None, "offline not probed");
        // No pinger (unprivileged mode) ⇒ all None but rows complete.
        let rows2 = assemble_rows(
            vec![row([100, 64, 0, 1], "srv", "1", PeerKind::Server, true)],
            None,
            None,
        )
        .await;
        assert_eq!(rows2[0].latency_ms, None);
    }

    /// JSON parseable + field semantics (offline latency null).
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
