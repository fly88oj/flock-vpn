//! `Directory::serve(dir_pull)`（§3.10/§1.3.3f）：向客户端下发根签 ClusterDirectory。
//!
//! - 装配期持根公钥（钉扎/邀请材料）+ 当前目录（根验签后收）；
//! - `install`：根验签 → dir_version 回退拒收（同版本幂等重放放行）——服务器换钥/
//!   新服务器准入 = 根签新目录 + 全网 install；
//! - `dir_pull_response`：`since >= 当前版本` ⇒ 无新内容（304 语义），否则下发
//!   `ClusterDirectory::to_bytes` 线格式（客户端 PinStore::record_directory 落地）。

use std::collections::BTreeMap;
use std::sync::RwLock;

use chml_protocol::trust::ClusterDirectory;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// 目录服务错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirError {
    /// 根签名校验失败。
    BadSignature,
    /// dir_version 回退（stored ≥ got）。
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

/// dir_pull 应答（线格式经 WireResp::DirPull）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirPullResp {
    /// 服务器当前目录版本。
    pub version: u64,
    /// 新内容（None = since 已最新）。
    pub bytes: Option<Vec<u8>>,
}

/// 根签集群目录服务（每服务器一个；serve = dir_pull 应答）。
pub struct Directory {
    root_pub: VerifyingKey,
    cur: RwLock<Option<ClusterDirectory>>,
}

impl Directory {
    /// 装配（initial 须过根验签，否则拒装配）。
    pub fn new(root_pub: VerifyingKey, initial: &ClusterDirectory) -> Result<Self, DirError> {
        if !initial.verify(&root_pub) {
            return Err(DirError::BadSignature);
        }
        Ok(Directory {
            root_pub,
            cur: RwLock::new(Some(initial.clone())),
        })
    }

    /// 根公钥（客户端邀请/钉扎同源）。
    pub fn root_pub(&self) -> &VerifyingKey {
        &self.root_pub
    }

    /// 当前版本（无目录 = 0）。
    pub fn version(&self) -> u64 {
        self.cur
            .read()
            .expect("dir")
            .as_ref()
            .map(|d| d.dir_version)
            .unwrap_or(0)
    }

    /// 当前目录快照。
    pub fn current(&self) -> Option<ClusterDirectory> {
        self.cur.read().expect("dir").clone()
    }

    /// 安装新目录：根验签 → 版本回退拒收 → 同版本幂等放行（§1.3.3f dir_pull 语义的
    /// 服务器侧落地；准入新服务器 = 根签 dir_version+1 目录全网 install）。
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

    /// dir_pull 应答（serve）：`since >= 当前` ⇒ None（客户端已最新）。
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

    /// 目录内全部条目（node_id → ServerEntry；供互连热更新）。
    pub fn node_entries(&self) -> BTreeMap<u64, chml_protocol::session::ServerEntry> {
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
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chml_protocol::session::{ClusterId, ServerEntry, ServerId};

    fn entry(n: u8) -> ServerEntry {
        ServerEntry {
            server_id: ServerId([n; 16]),
            relay_endpoint: format!("n{n}.test:9443"),
            identity_pub: ed25519_dalek::SigningKey::from_bytes(&[n; 32]).verifying_key(),
            static_hybrid_pub: chml_protocol::kem::HybridKeypair::generate(
                &mut chml_protocol::rand::rngs::OsRng,
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
        // 初始 pull：since=0 ⇒ 全量。
        let r = d.dir_pull_response(0);
        assert_eq!(r.version, 1);
        let bytes = r.bytes.expect("full");
        let back = ClusterDirectory::from_bytes(&bytes).expect("roundtrip");
        assert!(back.verify(&root.verifying_key()), "下发的是根签目录");
        assert_eq!(back.dir_version, 1);
        // since=1 ⇒ 无新内容。
        assert!(d.dir_pull_response(1).bytes.is_none(), "304 语义");
        // 换根签的目录 ⇒ 拒。
        let other = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let forged = ClusterDirectory::issue(&other, cid, 2, vec![entry(1)]);
        assert!(matches!(d.install(&forged), Err(DirError::BadSignature)));
        // 根签 v2 ⇒ 收；同版本幂等；回退拒。
        let v2 = ClusterDirectory::issue(&root, cid, 2, vec![entry(1), entry(2)]);
        d.install(&v2).expect("v2");
        d.install(&v2).expect("同版本幂等");
        assert!(matches!(
            d.install(&v1),
            Err(DirError::VersionRollback { stored: 2, got: 1 })
        ));
        assert_eq!(d.version(), 2);
        assert!(
            d.dir_pull_response(1).bytes.is_some(),
            "v1 客户端可刷新到 v2"
        );
        assert_eq!(d.node_entries().len(), 2);
    }
}
