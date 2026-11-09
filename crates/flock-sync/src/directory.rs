//! `Directory::serve(dir_pull)` (§3.10/§1.3.3f): distribute the root-signed
//! ClusterDirectory to clients.
//!
//! - Holds the root public key (pinning/invite material) at assembly time +
//!   the current directory (received after root-signature verification);
//! - `install`: root verification → reject version rollback of dir_version
//!   (same-version idempotent replay allowed) — server re-key / new server
//!   admission = root-sign a new directory + install fleet-wide;
//! - `dir_pull_response`: `since >= current version` ⇒ no new content (304
//!   semantics), otherwise distribute the `ClusterDirectory::to_bytes` wire
//!   format (landed client-side by PinStore::record_directory).

use std::collections::BTreeMap;
use std::sync::RwLock;

use ed25519_dalek::VerifyingKey;
use flock_protocol::trust::ClusterDirectory;
use serde::{Deserialize, Serialize};

/// Directory service error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirError {
    /// Root signature verification failed.
    BadSignature,
    /// dir_version rollback (stored ≥ got).
    VersionRollback { stored: u64, got: u64 },
}

impl std::fmt::Display for DirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DirError::BadSignature => write!(f, "directory: root signature mismatch"),
            DirError::VersionRollback { stored, got } => {
                write!(
                    f,
                    "directory: version rollback (stored={stored}, got={got})"
                )
            }
        }
    }
}
impl std::error::Error for DirError {}

/// dir_pull response (wire format via WireResp::DirPull).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirPullResp {
    /// The server's current directory version.
    pub version: u64,
    /// New content (None = since is already up to date).
    pub bytes: Option<Vec<u8>>,
}

/// Root-signed cluster directory service (one per server; serve = the
/// dir_pull response).
pub struct Directory {
    root_pub: VerifyingKey,
    cur: RwLock<Option<ClusterDirectory>>,
}

impl Directory {
    /// Assembly (initial must pass root verification, otherwise refuse to
    /// assemble).
    pub fn new(root_pub: VerifyingKey, initial: &ClusterDirectory) -> Result<Self, DirError> {
        if !initial.verify(&root_pub) {
            return Err(DirError::BadSignature);
        }
        Ok(Directory {
            root_pub,
            cur: RwLock::new(Some(initial.clone())),
        })
    }

    /// Root public key (same source as client invites/pinning).
    pub fn root_pub(&self) -> &VerifyingKey {
        &self.root_pub
    }

    /// Current version (no directory = 0).
    pub fn version(&self) -> u64 {
        self.cur
            .read()
            .expect("dir")
            .as_ref()
            .map(|d| d.dir_version)
            .unwrap_or(0)
    }

    /// Current directory snapshot.
    pub fn current(&self) -> Option<ClusterDirectory> {
        self.cur.read().expect("dir").clone()
    }

    /// Install a new directory: root verification → reject version rollback →
    /// allow same-version idempotent replay (the server-side landing of §1.3.3f
    /// dir_pull semantics; admitting a new server = root-sign a
    /// dir_version+1 directory and install it fleet-wide).
    pub fn install(&self, dir: &ClusterDirectory) -> Result<(), DirError> {
        if !dir.verify(&self.root_pub) {
            return Err(DirError::BadSignature);
        }
        let mut cur = self.cur.write().expect("dir");
        if let Some(existing) = cur.as_ref() {
            if dir.dir_version < existing.dir_version {
                return Err(DirError::VersionRollback {
                    stored: existing.dir_version,
                    got: dir.dir_version,
                });
            }
        }
        *cur = Some(dir.clone());
        Ok(())
    }

    /// dir_pull response (serve): `since >= current` ⇒ None (client already up
    /// to date).
    pub fn dir_pull_response(&self, since: u64) -> DirPullResp {
        let cur = self.cur.read().expect("dir").clone();
        match cur {
            Some(d) if d.dir_version > since => DirPullResp {
                version: d.dir_version,
                bytes: Some(d.to_bytes()),
            },
            Some(d) => DirPullResp {
                version: d.dir_version,
                bytes: None,
            },
            None => DirPullResp {
                version: 0,
                bytes: None,
            },
        }
    }

    /// All entries in the directory (node_id → ServerEntry; for interconnect
    /// hot updates).
    pub fn node_entries(&self) -> BTreeMap<u64, flock_protocol::session::ServerEntry> {
        let cur = self.cur.read().expect("dir").clone();
        let mut out = BTreeMap::new();
        if let Some(d) = cur {
            for e in &d.servers {
                let nid = u64::from_be_bytes(e.server_id.0[..8].try_into().expect("8B"));
                out.insert(nid, e.clone());
            }
        }
        out
    }
}

impl std::fmt::Debug for Directory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Directory")
            .field("version", &self.version())
            .finish()
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use flock_protocol::session::{ClusterId, ServerEntry, ServerId};

    fn entry(n: u8) -> ServerEntry {
        ServerEntry {
            server_id: ServerId([n; 16]),
            relay_endpoint: format!("n{n}.test:9443"),
            identity_pub: ed25519_dalek::SigningKey::from_bytes(&[n; 32]).verifying_key(),
            static_hybrid_pub: flock_protocol::kem::HybridKeypair::generate(
                &mut flock_protocol::rand::rngs::OsRng,
            )
            .public(),
        }
    }

    #[test]
    fn serve_install_and_pull() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let cid = ClusterId([7; 16]);
        let v1 = ClusterDirectory::issue(&root, cid, 1, vec![entry(1)]);
        let d = Directory::new(root.verifying_key(), &v1).expect("v1");
        // Initial pull: since=0 ⇒ full content.
        let r = d.dir_pull_response(0);
        assert_eq!(r.version, 1);
        let bytes = r.bytes.expect("full");
        let back = ClusterDirectory::from_bytes(&bytes).expect("roundtrip");
        assert!(
            back.verify(&root.verifying_key()),
            "what was distributed is root-signed"
        );
        assert_eq!(back.dir_version, 1);
        // since=1 ⇒ no new content.
        assert!(d.dir_pull_response(1).bytes.is_none(), "304 semantics");
        // A directory signed by a different root ⇒ rejected.
        let other = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let forged = ClusterDirectory::issue(&other, cid, 2, vec![entry(1)]);
        assert!(matches!(d.install(&forged), Err(DirError::BadSignature)));
        // Root-signed v2 ⇒ accepted; same version idempotent; rollback rejected.
        let v2 = ClusterDirectory::issue(&root, cid, 2, vec![entry(1), entry(2)]);
        d.install(&v2).expect("v2");
        d.install(&v2).expect("same-version idempotent");
        assert!(matches!(
            d.install(&v1),
            Err(DirError::VersionRollback { stored: 2, got: 1 })
        ));
        assert_eq!(d.version(), 2);
        assert!(
            d.dir_pull_response(1).bytes.is_some(),
            "a v1 client can refresh to v2"
        );
        assert_eq!(d.node_entries().len(), 2);
    }
}
