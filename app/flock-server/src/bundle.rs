//! Node bundle files for init-cluster / enroll (docs/design.md §4 cluster
//! bootstrap / §3.11 process entry).
//!
//! §4-1: operations runs `init-cluster --voters N` to generate the
//! **cluster root key** (kept offline) and each initial voter's **enrollment
//! credential** —— this crate's on-disk form = [`NodeBundle`]: the cluster
//! root public key + this node's identity material (identity/static hybrid
//! seeds) + the root-signed [`ServerEntry`] (`entry_sig`, the signature over
//! the public part of the enrollment credential) + the root-signed full
//! ClusterDirectory. **The root signing key never leaves the operations
//! side** (bundles contain only root_pub —— the §4-3 red line: a single
//! compromised on-record server holds no root key).
//!
//! `enroll --bundle <file>`: load and **verify** (directory root-signature
//! check + enrollment credential check + consistency comparison), then write
//! into the state directory for the raft form's startup (the in-process
//! assembly is in tests/multi_primary.rs; the TCP/relay fabric connects to
//! `flock_sync::wire::Fabric` with the §6/§7-M5 deployment batches).

use flock_protocol::ed25519_dalek::Signature;
use flock_protocol::kem::HybridKeypair;
use flock_protocol::rand;
use flock_protocol::session::{verify_server_entry, ServerEntry, ServerId, ServerIdentity};
use flock_protocol::trust::ClusterDirectory;
use serde::{Deserialize, Serialize};

/// Node bundle file (postcard wire/disk format).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeBundle {
    pub cluster_id: [u8; 16],
    /// Cluster root public key (the pinning subject; the signing key stays
    /// on the operations side).
    pub root_pub: [u8; 32],
    pub server_id: [u8; 16],
    /// This node's identity Ed25519 seed (32B).
    pub identity_seed: [u8; 32],
    /// This node's static hybrid key (96B, `HybridKeypair::to_bytes`; serde
    /// arrays are capped at 32B ⇒ carried as Vec).
    pub hybrid_sk: Vec<u8>,
    /// Access endpoint (ServerEntry.relay_endpoint).
    pub endpoint: String,
    /// Root signature over this ServerEntry (the enrollment credential; 64B
    /// ⇒ carried as Vec).
    pub entry_sig: Vec<u8>,
    /// Root-signed full ClusterDirectory (`ClusterDirectory::to_bytes`).
    pub directory: Vec<u8>,
}

impl NodeBundle {
    /// Serialize (the on-disk format).
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("bundle serialize")
    }

    /// Deserialize.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        postcard::from_bytes(b).ok()
    }

    /// Restore the [`ServerIdentity`] (the entry_sig re-signature comparison
    /// is in [`NodeBundle::verify`]).
    pub fn identity(&self) -> Result<ServerIdentity, String> {
        let identity = flock_protocol::ed25519_dalek::SigningKey::from_bytes(&self.identity_seed);
        let hybrid_sk: [u8; 96] = self
            .hybrid_sk
            .clone()
            .try_into()
            .map_err(|_| "invalid hybrid_sk length (expected 96B)".to_string())?;
        let static_hybrid = HybridKeypair::from_bytes(&hybrid_sk).map_err(|e| e.to_string())?;
        let entry = ServerEntry {
            server_id: ServerId(self.server_id),
            relay_endpoint: self.endpoint.clone(),
            identity_pub: identity.verifying_key(),
            static_hybrid_pub: static_hybrid.public(),
        };
        Ok(ServerIdentity {
            cluster_id: flock_protocol::session::ClusterId(self.cluster_id),
            server_id: ServerId(self.server_id),
            identity,
            static_hybrid,
            entry,
            root_pub: root_vk(&self.root_pub)?,
            entry_sig: Signature::from_bytes(
                &self
                    .entry_sig
                    .clone()
                    .try_into()
                    .map_err(|_| "invalid entry_sig length (expected 64B)".to_string())?,
            ),
        })
    }

    /// Full verification: the root public key constructs + root-signed
    /// directory signature check + enrollment credential (entry_sig) check +
    /// consistency comparison (the directory contains this endpoint's entry,
    /// cluster identity matches —— defends against splicing "another
    /// cluster's directory + this credential").
    pub fn verify(&self) -> Result<flock_protocol::session::ClusterId, String> {
        let root = root_vk(&self.root_pub)?;
        let dir = ClusterDirectory::from_bytes(&self.directory)
            .map_err(|e| format!("directory decode: {e}"))?;
        if !dir.verify(&root) {
            return Err("root-signed directory signature check failed".into());
        }
        if dir.cluster_id.0 != self.cluster_id {
            return Err("directory cluster identity does not match the bundle".into());
        }
        let ident = self.identity()?;
        if !verify_server_entry(&root, &ident.cluster_id, &ident.entry, &ident.entry_sig) {
            return Err(
                "enrollment credential (root-signed ServerEntry) signature check failed".into(),
            );
        }
        if !dir.servers.iter().any(|e| {
            e.server_id == ident.server_id && e.relay_endpoint == ident.entry.relay_endpoint
        }) {
            return Err("root-signed directory has no entry for this node's endpoint".into());
        }
        Ok(ident.cluster_id)
    }

    /// Root-signed directory (the verified precondition is the caller's
    /// responsibility; [`NodeBundle::verify`]).
    pub fn directory(&self) -> Result<ClusterDirectory, String> {
        ClusterDirectory::from_bytes(&self.directory).map_err(|e| format!("directory decode: {e}"))
    }
}

fn root_vk(pub32: &[u8; 32]) -> Result<flock_protocol::ed25519_dalek::VerifyingKey, String> {
    flock_protocol::ed25519_dalek::VerifyingKey::from_bytes(pub32)
        .map_err(|_| "invalid root public key encoding".to_string())
}

/// init-cluster cluster material (in-memory form; `bundle()` takes each
/// voter's copy away).
pub struct ClusterMaterial {
    /// Cluster root key (**held by the operations side only**; 0600 disk
    /// semantics at write time are the caller's responsibility; bundles
    /// contain no signing key).
    pub root: flock_protocol::ed25519_dalek::SigningKey,
    pub cluster_id: flock_protocol::session::ClusterId,
    idents: Vec<ServerIdentity>,
    directory: ClusterDirectory,
}

impl ClusterMaterial {
    /// Generate the cluster material for N voters (root key + per-voter
    /// identities + root-signed directory, §4-1).
    pub fn generate(
        voters: usize,
        cluster_id: Option<flock_protocol::session::ClusterId>,
        endpoint_of: impl Fn(usize) -> String,
    ) -> Self {
        let root =
            flock_protocol::ed25519_dalek::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let cluster_id =
            cluster_id.unwrap_or_else(|| flock_protocol::session::ClusterId(rand::random()));
        let idents: Vec<ServerIdentity> = (0..voters)
            .map(|i| {
                ServerIdentity::enroll(
                    &root,
                    cluster_id,
                    ServerId(voter_server_id(i)),
                    &endpoint_of(i),
                )
            })
            .collect();
        let entries: Vec<ServerEntry> = idents.iter().map(|i| i.entry.clone()).collect();
        let directory = ClusterDirectory::issue(&root, cluster_id, 1, entries);
        ClusterMaterial {
            root,
            cluster_id,
            idents,
            directory,
        }
    }

    /// Take voter i's bundle file.
    pub fn bundle(&self, i: usize) -> NodeBundle {
        let ident = &self.idents[i];
        NodeBundle {
            cluster_id: self.cluster_id.0,
            root_pub: *ident.root_pub.as_bytes(),
            server_id: ident.server_id.0,
            identity_seed: ident.identity.to_bytes(),
            hybrid_sk: ident.static_hybrid.to_bytes().to_vec(),
            endpoint: ident.entry.relay_endpoint.clone(),
            entry_sig: ident.entry_sig.to_bytes().to_vec(),
            directory: self.directory.to_bytes(),
        }
    }

    /// The root-signed directory.
    pub fn directory(&self) -> &ClusterDirectory {
        &self.directory
    }
}

/// The deterministic ServerId of voter i (first 8B = big-endian i+1 —— the
/// same mapping as flock_sync::node_id_of; openraft NodeId = i+1).
pub fn voter_server_id(i: usize) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&((i + 1) as u64).to_be_bytes());
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_roundtrip_verify_and_tamper() {
        let m = ClusterMaterial::generate(3, None, |i| format!("node-{i}.test:9443"));
        let bundle = m.bundle(1);
        let bytes = bundle.to_bytes();
        let back = NodeBundle::from_bytes(&bytes).expect("roundtrip");
        assert_eq!(back, bundle);
        // Verification passes + the restored identity matches.
        assert_eq!(back.verify().unwrap(), m.cluster_id);
        let ident = back.identity().unwrap();
        assert_eq!(ident.server_id.0, voter_server_id(1));
        // Tampered endpoint ⇒ enrollment credential check fails.
        let mut tampered = back.clone();
        tampered.endpoint = "evil.test:9".into();
        assert!(
            tampered.verify().is_err(),
            "endpoint changed ⇒ entry_sig check fails"
        );
        // Swapped directory (another cluster) ⇒ rejected.
        let other = ClusterMaterial::generate(2, None, |i| format!("x-{i}:1"));
        let mut mixed = back.clone();
        mixed.directory = other.directory().to_bytes();
        assert!(mixed.verify().is_err());
    }
}
