//! `flock-sync`：多主多活同步（docs/design.md §3.10/§4 第一部分，VPN-15）。
//!
//! 本 crate 落地 §4 择型的核心件——**openraft 0.9.25 复制状态机**（设备注册表/邀请/VIP
//! 分配/吊销/服务器密钥/票据密钥根，全部强一致），外加为 `tests/cluster` 八项断言服务的
//! 最小组件：
//!
//! - [`proto`]：NetState 写操作集 [`proto::SyncRequest`]（经 Raft 提交；admin_op
//!   = add_voter/rewrap/revoke_invite 必须带**集群根密钥签名**，状态机验签后生效）。
//! - [`state`]：纯状态机 [`state::NetStateData`]（100.64.0.0/10 单调分配、禁用不删除、
//!   IP 不复用、invite_id 单次消费查重、revocation_epoch 推进）。
//! - [`store`]：openraft 日志/投票存储的 **redb 适配器**（单文件嵌入，纯 Rust）。
//! - [`sm`]：状态机适配器 + **apply 回调钩子**（吊销 → 杀本地会话/清拒票据）+
//!   测试用 apply 滞后注入。
//! - [`wire`]：Raft 网络传输——**服务器-服务器 profile 的 E2E 会话**（复用
//!   flock-protocol session/trust：双向入群凭证认证，无凭证即拒）+ RPC 帧分发 +
//!   **apply-lag 熔断**（§4 读与缓存）。
//! - [`dir`]：`session::DeviceDirectory` 两级读实现（记录缓存 + epoch + lag 熔断降级
//!   线性一致读）。
//! - [`lease`]：gossip 租约表（设备当前位置唯一真相源；冲突 = 新者胜 + 旧端踢出回调）。
//! - [`forward`]：跨服转发承载（ForwardEnvelope + 源 VIP 绑定校验 + hop=1 防环 +
//!   NOT_HERE→一次性 location_query + 尽力 ICMP，§2.2）。
//! - [`directory`]：`Directory::serve(dir_pull)`——根签 ClusterDirectory 下发/安装。
//! - [`ticket`]：本地短 TTL 票据签发/校验——**票据密钥根在 Raft 内**（§4 第二阶段能力
//!   直接吸收进首版）。
//! - [`node`]：[`node::SyncNode`] 装配（写转发 leader、任意节点线性一致读、learner
//!   准入/add_voter/rewrap 管理面）。
//!
//! - [`tcp`]：生产织物（直接 TCP 监听/拨号；§6.2 M5 批次接入——此前仅内存织物）。
//!
//! 未含（后续批次）：经中转 Fabric（srvmesh 不可直达时的服务器互连）、控制流
//! dir_pull 客户端侧消息协议。
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

/// 测试支撑（内存 Fabric + RTT 注入；`--features test-util` 启用，不入默认构建）。
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
    AdminOp, NodeId, ReadQuery, ReadView, RootSigned, ServerKeyEntry, StateError, SyncRequest,
    SyncResponse, VerdictW, VIP_FIRST, VIP_LAST,
};
pub use sm::{LagInjector, RedbStateMachine, SmCore};
pub use store::RedbLogStore;
pub use tcp::TcpFabric;
pub use wire::{Fabric, Interconnect, LagMonitor, PeerIo};

/// openraft 类型配置（NodeId=u64 / BasicNode / 标准 Entry / Cursor 快照）。
pub mod raft_types {
    use std::io::Cursor;

    use openraft::impls::BasicNode;

    use crate::proto::{SyncRequest, SyncResponse};

    openraft::declare_raft_types!(
        /// flock-sync 的 openraft 类型集。
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
