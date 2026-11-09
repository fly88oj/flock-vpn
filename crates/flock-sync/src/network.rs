//! openraft network adapter: rides on top of the server-server E2E session
//! (§3.10 seam: Raft network transport over direct TCP / via relay — both run
//! interconnect sessions with the server-server profile; this file depends
//! only on [`Interconnect`], decoupled from any specific fabric).

use openraft::error::{RPCError, RaftError};
use openraft::network::{RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::BasicNode;

use crate::raft_types::SyncConfig;
use crate::wire::{remote_error, rpc_error_of, Interconnect, WireCallError, WireResp, WireRpc};

/// Network factory (Raft builds one client per replication/vote task —
/// implemented as a light handle on the interconnect manager).
#[derive(Clone)]
pub struct SyncNetFactory {
    pub ic: std::sync::Arc<Interconnect>,
}

impl RaftNetworkFactory<SyncConfig> for SyncNetFactory {
    type Network = SyncNetwork;

    async fn new_client(&mut self, target: u64, _node: &BasicNode) -> Self::Network {
        SyncNetwork {
            ic: self.ic.clone(),
            target,
        }
    }
}

/// Network client toward a single peer (opens streams over interconnect
/// sessions to send/receive).
#[derive(Clone)]
pub struct SyncNetwork {
    ic: std::sync::Arc<Interconnect>,
    target: u64,
}

impl SyncNetwork {
    async fn call(
        &self,
        rpc: WireRpc,
        ttl: std::time::Duration,
    ) -> Result<WireResp, WireCallError> {
        self.ic.call(self.target, rpc, ttl).await
    }

    fn mismatch(&self) -> RPCError<u64, BasicNode, RaftError<u64>> {
        rpc_error_of(self.target, WireCallError::Mismatch)
    }
}

impl RaftNetwork<SyncConfig> for SyncNetwork {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<SyncConfig>,
        option: openraft::network::RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        match self.call(WireRpc::Append(rpc), option.hard_ttl()).await {
            Ok(WireResp::Append(Ok(r))) => Ok(r),
            Ok(WireResp::Append(Err(e))) => Err(remote_error(self.target, e)),
            Ok(_) => Err(self.mismatch()),
            Err(e) => Err(rpc_error_of(self.target, e)),
        }
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<SyncConfig>,
        option: openraft::network::RPCOption,
    ) -> Result<
        InstallSnapshotResponse<u64>,
        RPCError<u64, BasicNode, RaftError<u64, openraft::error::InstallSnapshotError>>,
    > {
        match self.call(WireRpc::Snapshot(rpc), option.hard_ttl()).await {
            Ok(WireResp::Snapshot(Ok(r))) => Ok(r),
            Ok(WireResp::Snapshot(Err(m))) => {
                Err(RPCError::Unreachable(openraft::error::Unreachable::new(
                    &std::io::Error::other(format!("remote snapshot error: {m}")),
                )))
            }
            Ok(_) => Err(RPCError::Unreachable(openraft::error::Unreachable::new(
                &std::io::Error::other("rpc response mismatch"),
            ))),
            Err(e) => Err(RPCError::Unreachable(openraft::error::Unreachable::new(
                &std::io::Error::from(e),
            ))),
        }
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<u64>,
        option: openraft::network::RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        match self.call(WireRpc::Vote(rpc), option.hard_ttl()).await {
            Ok(WireResp::Vote(Ok(r))) => Ok(r),
            Ok(WireResp::Vote(Err(e))) => Err(remote_error(self.target, e)),
            Ok(_) => Err(self.mismatch()),
            Err(e) => Err(rpc_error_of(self.target, e)),
        }
    }
}
