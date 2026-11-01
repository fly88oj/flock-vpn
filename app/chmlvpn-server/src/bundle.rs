//! init-cluster / enroll 的节点捆绑文件（docs/design.md §4 集群引导 / §3.11 进程入口）。
//!
//! §4-1：运维运行 `init-cluster --voters N` 生成**集群根密钥**（离线保管）与每台初始
//! voter 的**入群凭证**——本 crate 的落盘形态 = [`NodeBundle`]：集群根公钥 + 本机身份
//! 材料（identity/static hybrid 种子）+ 根签 [`ServerEntry`]（`entry_sig`，即入群凭证
//! 公开部分的签名）+ 根签 ClusterDirectory 全文。**根密钥签名钥不出运维侧**（bundle 只
//! 含 root_pub——§4-3 红线：被入侵的单台在册服务器没有根密钥）。
//!
//! `enroll --bundle <file>`：装载并**验证**（目录根验签 + 入群凭证验签 + 一致性比对），
//! 通过后写入状态目录供 raft 形态起服使用（进程内装配见 tests/multi_primary.rs；
//! TCP/中转织物随 §6/§7-M5 部署批次接 `chml_sync::wire::Fabric`）。

use chml_protocol::ed25519_dalek::Signature;
use chml_protocol::kem::HybridKeypair;
use chml_protocol::rand;
use chml_protocol::session::{verify_server_entry, ServerEntry, ServerId, ServerIdentity};
use chml_protocol::trust::ClusterDirectory;
use serde::{Deserialize, Serialize};

/// 节点捆绑文件（postcard 线/盘格式）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeBundle {
    pub cluster_id: [u8; 16],
    /// 集群根公钥（钉扎本体；签名钥在运维侧）。
    pub root_pub: [u8; 32],
    pub server_id: [u8; 16],
    /// 本机身份 Ed25519 种子（32B）。
    pub identity_seed: [u8; 32],
    /// 本机静态混合密钥（96B，`HybridKeypair::to_bytes`；serde 数组限 32B ⇒ Vec 承载）。
    pub hybrid_sk: Vec<u8>,
    /// 接入端点（ServerEntry.relay_endpoint）。
    pub endpoint: String,
    /// 根对本 ServerEntry 的签名（入群凭证；64B ⇒ Vec 承载）。
    pub entry_sig: Vec<u8>,
    /// 根签 ClusterDirectory 全文（`ClusterDirectory::to_bytes`）。
    pub directory: Vec<u8>,
}

impl NodeBundle {
    /// 序列化（落盘格式）。
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("bundle serialize")
    }

    /// 反序列化。
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        postcard::from_bytes(b).ok()
    }

    /// 还原 [`ServerIdentity`]（entry_sig 重签比对在 [`NodeBundle::verify`]）。
    pub fn identity(&self) -> Result<ServerIdentity, String> {
        let identity = chml_protocol::ed25519_dalek::SigningKey::from_bytes(&self.identity_seed);
        let hybrid_sk: [u8; 96] = self
            .hybrid_sk
            .clone()
            .try_into()
            .map_err(|_| "hybrid_sk 长度非法（期望 96B）".to_string())?;
        let static_hybrid = HybridKeypair::from_bytes(&hybrid_sk).map_err(|e| e.to_string())?;
        let entry = ServerEntry {
            server_id: ServerId(self.server_id),
            relay_endpoint: self.endpoint.clone(),
            identity_pub: identity.verifying_key(),
            static_hybrid_pub: static_hybrid.public(),
        };
        Ok(ServerIdentity {
            cluster_id: chml_protocol::session::ClusterId(self.cluster_id),
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
                    .map_err(|_| "entry_sig 长度非法（期望 64B）".to_string())?,
            ),
        })
    }

    /// 完整验证：根公钥可构 + 根签目录验签 + 入群凭证（entry_sig）验签 + 一致性比对
    /// （目录含本端点条目、集群标识一致——防拼接「他集群目录 + 本凭证」）。
    pub fn verify(&self) -> Result<chml_protocol::session::ClusterId, String> {
        let root = root_vk(&self.root_pub)?;
        let dir =
            ClusterDirectory::from_bytes(&self.directory).map_err(|e| format!("目录解码: {e}"))?;
        if !dir.verify(&root) {
            return Err("根签目录验签失败".into());
        }
        if dir.cluster_id.0 != self.cluster_id {
            return Err("目录集群标识与捆绑不一致".into());
        }
        let ident = self.identity()?;
        if !verify_server_entry(&root, &ident.cluster_id, &ident.entry, &ident.entry_sig) {
            return Err("入群凭证（根签 ServerEntry）验签失败".into());
        }
        if !dir.servers.iter().any(|e| {
            e.server_id == ident.server_id && e.relay_endpoint == ident.entry.relay_endpoint
        }) {
            return Err("根签目录不含本节点端点条目".into());
        }
        Ok(ident.cluster_id)
    }

    /// 根签目录（已验签前提由调用方保证；[`NodeBundle::verify`]）。
    pub fn directory(&self) -> Result<ClusterDirectory, String> {
        ClusterDirectory::from_bytes(&self.directory).map_err(|e| format!("目录解码: {e}"))
    }
}

fn root_vk(pub32: &[u8; 32]) -> Result<chml_protocol::ed25519_dalek::VerifyingKey, String> {
    chml_protocol::ed25519_dalek::VerifyingKey::from_bytes(pub32)
        .map_err(|_| "根公钥编码非法".to_string())
}

/// init-cluster 集群材料（内存形态；`bundle()` 逐 voter 取走）。
pub struct ClusterMaterial {
    /// 集群根密钥（**仅运维侧持有**；写盘时 0600 语义由调用方负责，bundle 不含签名钥）。
    pub root: chml_protocol::ed25519_dalek::SigningKey,
    pub cluster_id: chml_protocol::session::ClusterId,
    idents: Vec<ServerIdentity>,
    directory: ClusterDirectory,
}

impl ClusterMaterial {
    /// 生成 N voter 的集群材料（根密钥 + 各 voter 身份 + 根签目录，§4-1）。
    pub fn generate(
        voters: usize,
        cluster_id: Option<chml_protocol::session::ClusterId>,
        endpoint_of: impl Fn(usize) -> String,
    ) -> Self {
        let root =
            chml_protocol::ed25519_dalek::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let cluster_id =
            cluster_id.unwrap_or_else(|| chml_protocol::session::ClusterId(rand::random()));
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

    /// 取第 i 个 voter 的捆绑文件。
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

    /// 根签目录。
    pub fn directory(&self) -> &ClusterDirectory {
        &self.directory
    }
}

/// voter i 的确定性 ServerId（前 8B = 大端 i+1——与 chml_sync::node_id_of 同映射，
/// openraft NodeId = i+1）。
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
        // 验证通过 + 身份还原一致。
        assert_eq!(back.verify().unwrap(), m.cluster_id);
        let ident = back.identity().unwrap();
        assert_eq!(ident.server_id.0, voter_server_id(1));
        // 篡改端点 ⇒ 入群凭证验签失败。
        let mut tampered = back.clone();
        tampered.endpoint = "evil.test:9".into();
        assert!(tampered.verify().is_err(), "端点被改 ⇒ entry_sig 验签失败");
        // 换目录（他集群）⇒ 拒。
        let other = ClusterMaterial::generate(2, None, |i| format!("x-{i}:1"));
        let mut mixed = back.clone();
        mixed.directory = other.directory().to_bytes();
        assert!(mixed.verify().is_err());
    }
}
