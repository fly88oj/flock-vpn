//! `flock-sync`: multi-primary multi-active synchronization (docs/design.md
//! §3.10/§4 part one, VPN-15).
//!
//! This crate implements the core artifacts of the §4 selection — the
//! **openraft 0.9.25 replicated state machine** (device registry / invites /
//! VIP allocation / revocation / server keys / ticket key root, all strongly
//! consistent), plus the minimal components serving the eight assertions of
//! `tests/cluster`:
//!
//! - [`proto`]: the NetState write-operation set [`proto::SyncRequest`]
//!   (committed through Raft; admin_op = add_voter/rewrap/revoke_invite must
//!   carry a **cluster root key signature**, effective after the state machine
//!   verifies it).
//! - [`state`]: the pure state machine [`state::NetStateData`] (monotonic
//!   allocation in 100.64.0.0/10, disable-not-delete, no IP reuse, single-use
//!   invite_id dedup, revocation_epoch advancement).
//! - [`store`]: the **redb adapter** for openraft log/vote storage (single
//!   embedded file, pure Rust).
//! - [`sm`]: state machine adapter + **apply callback hooks** (revocation →
//!   kill local session / reject outstanding tickets) + test-side apply-lag
//!   injection.
//! - [`wire`]: Raft network transport — **E2E sessions on the
//!   server-server profile** (reusing flock-protocol session/trust: mutual
//!   enrollment-credential authentication, reject when no credential) + RPC
//!   frame dispatch + **apply-lag circuit breaker** (§4 reads and caching).
//! - [`dir`]: the two-tier read implementation of `session::DeviceDirectory`
//!   (record cache + epoch + lag-breaker degradation to linearizable reads).
//! - [`lease`]: the gossip lease table (single source of truth for device
//!   current location; conflict = newest wins + old-side eviction callback).
//! - [`forward`]: cross-server forwarding plane (ForwardEnvelope + source VIP
//!   binding check + hop=1 loop prevention + NOT_HERE → one-shot
//!   location_query + best-effort ICMP, §2.2).
//! - [`directory`]: `Directory::serve(dir_pull)` — root-signed
//!   ClusterDirectory distribution/installation.
//! - [`ticket`]: local short-TTL ticket issuing/verification — **the ticket
//!   key root lives inside Raft** (§4 phase-two capability absorbed into the
//!   first release).
//! - [`node`]: [`node::SyncNode`] assembly (write forwarding to the leader,
//!   linearizable reads on any node, learner admission / add_voter / rewrap
//!   management plane).
//!
//! - [`tcp`]: production fabric (direct TCP listen/dial; §6.2 M5 batch
//!   onboarding — previously in-memory fabric only).
//!
//! Not included (later batches): relayed Fabric (server interconnect when
//! srvmesh is unreachable), the client-side message protocol of the control
//! dir_pull flow.
#![forbid(unsafe_code)]

pub mod dir;
pub mod directory;
pub mod forward;
pub mod hooks;
pub mod lease;
pub mod network;
pub mod node;
pub mod proto;
pub mod sm;
pub mod state;
pub mod store;
pub mod tcp;
pub mod ticket;
pub mod wire;

/// Test support (in-memory Fabric + RTT injection; enabled via
/// `--features test-util`, not part of the default build).
#[cfg(feature = "test-util")]
pub mod testutil;

pub use directory::{DirError, DirPullResp, Directory};
pub use forward::{
    ForwardEnvelope, ForwardOutcome, ForwardPlane, ForwardStats, ForwardTransport, IngestResult,
    PacketSink, FORWARD_VER,
};
pub use lease::LocateFanout;
pub use network::{SyncNetFactory, SyncNetwork};
pub use node::{SyncNode, SyncNodeBuilder, SyncSettings};
pub use proto::{
    normalize_hostname, AdminOp, NodeId, ReadQuery, ReadView, RootSigned, ServerKeyEntry,
    StateError, SyncRequest, SyncResponse, VerdictW, HOSTNAME_MAX, HOSTNAME_UNKNOWN, VIP_FIRST,
    VIP_LAST,
};
pub use sm::{LagInjector, RedbStateMachine, SmCore};
pub use store::RedbLogStore;
pub use tcp::TcpFabric;
pub use wire::{Fabric, Interconnect, LagMonitor, PeerIo};

/// openraft type configuration (NodeId=u64 / BasicNode / standard Entry /
/// Cursor snapshot).
pub mod raft_types {
    use std::io::Cursor;

    use openraft::impls::BasicNode;

    use crate::proto::{SyncRequest, SyncResponse};

    openraft::declare_raft_types!(
        /// The openraft type set for flock-sync.
        pub SyncConfig:
            D = SyncRequest,
            R = SyncResponse,
            NodeId = u64,
            Node = BasicNode,
            Entry = openraft::impls::Entry<Self>,
            SnapshotData = Cursor<Vec<u8>>
    );
}

pub use raft_types::SyncConfig;
