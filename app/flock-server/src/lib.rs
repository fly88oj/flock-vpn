//! # flock-server (library surface)
//!
//! Flock VPN server assembly (single-server form, docs/design.md
//! §2.2/§3.11/§7-M2). Library/binary split: integration tests
//! (`tests/control_flow.rs` full-chain in-process, `tests/smoke.rs` real
//! container runs) reuse the assembly and client drivers through this lib;
//! `src/main.rs` is only the process entry (CLI subcommands).
//!
//! Modules (the §3.11 seam map):
//! - [`config`]: server.toml + `ListenerMode` (**Direct by default**, the §2.1
//!   hard constraint);
//! - [`netstate`]: the redb single-machine state machine (one-time invites /
//!   monotonic non-reused VIPs / epoch propagation; row types share
//!   provenance with flock-sync proto.rs —— review item 12 dedup);
//! - [`ticket`]: session tickets (TTL/epoch) + nonce accounting (the ticket
//!   side of the §2.2 contract order);
//! - [`control`]: control-flow messages (postcard) +
//!   [`control::CtrlGuard`] (the ticket enforcement contract: ticket →
//!   SR-SIG1 → nonce accounting; the ordering has test assertions);
//! - [`server`]: ServerCore (respond assembly/directory/invites/kill
//!   sessions) + the accept loop;
//! - [`frp`]: **the only module touching flock-frpc** (Frp-mode assembly
//!   only; the Direct code path never passes through);
//! - [`admin`]: the admin loopback endpoint (the in-process single-writer
//!   entry for CLI write operations);
//! - [`dataplane`]: the M3 server data plane (tun VIP 100.64.0.1 + source
//!   VIP validation + the session packet channel, reusing `flock-client`'s
//!   TunDevice/route seams, §2.2/§3.12);
//! - [`backend`]: NetBackend —— the unified async read/write facade over
//!   single-server (redb) and multi-primary (flock-sync Raft) (feature
//!   `multi-primary`; the §2.2/§3.11 M4 assembly batch);
//! - [`bundle`]: the node bundle files of init-cluster/enroll (root public
//!   key + enrollment credential + root-signed directory);
//! - [`sync`]: multi-primary runtime assembly (TCP fabric + SyncNode + the
//!   server's own peer surface; feature `multi-primary`, the §6.2 M5
//!   batch).

#![forbid(unsafe_code)]

use std::path::Path;

/// Persist a secret file with 0600 (review item 1: root.seed / node-*.bundle
/// / bundle.bin / frpc.toml).
///
/// Same posture as flock-protocol's `trust::write_private_file`: on unix,
/// **created** with `OpenOptions::mode(0o600)` —— the file is born 0600,
/// with no "write then tighten" permission window; overwriting an existing
/// file with looser old permissions tightens them afterwards. Windows has
/// no POSIX permission bits natively; degrades to a regular write.
pub fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        f.flush()?;
        // An overwritten existing file may carry looser old permissions (the
        // creation path itself has no window).
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        std::fs::write(path, bytes)
    }
}

pub mod admin;
pub mod backend;
pub mod bundle;
pub mod config;
pub mod control;
pub mod dataplane;
pub mod frp;
pub mod netstate;
pub mod server;
#[cfg(feature = "multi-primary")]
pub mod sync;
pub mod ticket;
pub mod webui;

#[cfg(test)]
mod tests {
    #[cfg(unix)] // the only case is the unix arm (avoids unused import on Windows builds)
    use super::*;

    // Review item 1: secret files are 0600 at creation (unix arm —— Windows
    // has no POSIX permission bits).
    #[cfg(unix)]
    #[test]
    fn private_file_created_with_0600_and_tightened_on_overwrite() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("root.seed");
        write_private_file(&p, b"secret-hex").expect("write");
        assert_eq!(
            std::fs::metadata(&p).expect("meta").permissions().mode() & 0o777,
            0o600,
            "0600 at creation"
        );
        // Overwriting an existing file with looser old permissions ⇒
        // tightened back to 0600 afterwards.
        let p2 = dir.path().join("bundle.bin");
        std::fs::write(&p2, b"x").expect("seed write");
        std::fs::set_permissions(&p2, std::fs::Permissions::from_mode(0o644)).expect("widen");
        write_private_file(&p2, b"secret").expect("overwrite");
        assert_eq!(
            std::fs::metadata(&p2).expect("meta").permissions().mode() & 0o777,
            0o600,
            "tightened back to 0600 after overwrite"
        );
        assert_eq!(std::fs::read(&p2).unwrap(), b"secret");
    }
}
