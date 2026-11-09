//! flock-client library surface (docs/design.md §2.3 / §3.12 / §7-M3).
//!
//! Modules:
//! - [`tun`]: the `TunDevice` seam (open/read/write/close) + the tun-rs
//!   adapter (cfg-gated) + `MockTunDevice` (host unit tests) +
//!   `TunIo/TunSession` (sync device → tokio bridge);
//! - [`route`]: route configuration adapter (Linux rtnetlink /16 pool +
//!   rp_filter=1; Windows noted as pending M5 real-machine manual
//!   verification);
//! - [`connector`]: the connector (invite/pinned-directory loading →
//!   endpoint dialing → `session::initiate`; exponential backoff + endpoint
//!   rotation);
//! - [`ctrl`]: the client half of the control stream (M7 §7-M7.7: the client
//!   implementation of OPAQUE login/key-bind/ticket keepalive — wire types
//!   reuse `flock_protocol::roster`, same types on both ends);
//! - [`ping`]: peers latency probing (M7 §7-M7.7: raw ICMP echo via tun,
//!   median of 3 probes with a 2s timeout; a thin socket2 layer — rationale
//!   in the module docs);
//! - [`peers`]: roster assembly and rendering (M7 §7-M7.7: the PeerRow
//!   enhanced roster + table/--json);
//! - [`dataplane`]: IP packet ↔ `PacketChannel` bridge;
//! - [`ipc`]: control IPC v1 contract + daemon server + client one-shot
//!   request (§7-M6.2 — the tray project consumes this module directly; the
//!   `service` subcommand assembles the server side);
//! - [`service`]: daemon assembly (§7-M6.1: supervise reuse + IPC server +
//!   status snapshot source + graceful shutdown + Windows SCM integration);
//! - [`install`]: service install/uninstall + tray autostart registration
//!   (§7-M6.3: Windows SCM/event log source/HKCU Run, systemd unit, launchd
//!   plist);
//! - [`tray`]: the tray process (§7-M6 phase two; `tray` feature-gated —
//!   platform-independent core + platform backends: Windows/macOS tray-icon,
//!   Linux ksni);
//! - [`lang`]: UI language pack for tray/CLI interactive copy (en default,
//!   zh pack; operational logs stay English).
//!
//! The server (`flock-server`) reuses [`tun`]/[`route`]/the dataplane bridge
//! as a library (§2.2 "the server is itself a peer", §3.11 "hang a tun
//! adapter on top") — the `TunDevice` seam lives in this crate per §3.12, and
//! the cross-app reuse is the seam's second consumer.

pub mod config;
pub mod connector;
pub mod ctrl;
pub mod dataplane;
pub mod install;
pub mod ipc;
pub mod lang;
pub mod peers;
pub mod ping;
// Control-plane platform transport (private: contract/server/client entry
// points all go through [`ipc`]).
#[cfg(unix)]
mod ipc_unix;
#[cfg(windows)]
mod ipc_windows;
pub mod route;
pub mod service;
#[cfg(feature = "tray")]
pub mod tray;
pub mod tun;
