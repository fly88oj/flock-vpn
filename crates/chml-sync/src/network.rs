//! openraft 网络适配器：挂在服务器-服务器 E2E 会话之上（§3.10 接缝：Raft 网络传输
//! 直接 TCP / 经中继——都跑 server-server profile 的互连会话；此处只依赖
//! [`Interconnect`]，与具体织物解耦）。

use openraft::error::{RPCError, RaftError};
use openraft::network::{RaftNetwork, RaftNetworkFactory};
use openraft::raft::{AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse, VoteRequest, VoteResponse};
use openraft::BasicNode;

use crate::raft_types::SyncConfig;
use crate::wire::{rpc_error_of, remote_error, Interconnect, WireCallError, WireResp, WireRpc};

/// 网络工厂（Raft 每个复制/投票任务各建一个客户端——实现为互连管理器的轻柄）。
#[derive(Clone)]
pub struct SyncNetFactory {
    pub ic: std::sync::Arc<Interconnect>,
}

impl RaftNetworkFactory<SyncConfig> for SyncNetFactory {
    type Network = SyncNetwork;

    async fn new_client(&mut self, target: u64, _node: &BasicNode) -> Self::Network {
        SyncNetwork { ic: self.ic.clone(), target }
    }
}

/// 到单个对端的网络客户端（经互连会话开流收发）。
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
            Ok(WireResp::Snapshot(Err(m))) => Err(RPCError::Unreachable(openraft::error::Unreachable::new(
                &std::io::Error::other(format!("remote snapshot error: {m}")),
            ))),
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
