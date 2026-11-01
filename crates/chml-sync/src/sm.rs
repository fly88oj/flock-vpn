//! openraft 状态机适配器（RaftStateMachine v2）+ apply 回调钩子 + 滞后注入。
//!
//! 职责（§2.2 吊销传播界）：
//! - apply 每条 Normal 日志 → [`NetStateData::apply`] 确定性执行；
//! - 阻断性转移（Revoke/Disable）⇒ 触发 [`crate::hooks`] 杀本地会话钩子 +
//!   广播 epoch watch（记录缓存据此失效）；
//! - Membership 日志 ⇒ 维护 `last_membership`（applied_state 契约）；
//! - 快照 = postcard(NetStateData)（redb 独立表持久化；表名与日志存储分离，避开
//!   redb 写事务表级冲突）。
//!
//! 共享面：`SmCore` 被 [`crate::node`]/[`crate::dir`] 以 `Arc` 持有做本地读（缓存路径）；
//! Raft 持有 `RedbStateMachine` 做串行 apply——状态本体在 `RwLock` 后面，apply 路径
//! 无 await 持锁（钩子/计时发送不阻塞）。

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use openraft::storage::RaftSnapshotBuilder;
use openraft::{BasicNode, Entry, EntryPayload, ErrorSubject, ErrorVerb, LogId, Snapshot, SnapshotMeta, StorageError, StoredMembership, ToStorageResult};
use redb::{Database, ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::hooks::HookRegistry;
use crate::proto::SyncResponse;
use crate::raft_types::SyncConfig;
use crate::state::NetStateData;

/// SM 侧快照持久化表（与日志存储表分离：redb 并发写事务按表粒度避冲突）。
pub const SMKV_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("chml_sync_sm");

/// 快照束（wire + 持久化格式）。
#[derive(Serialize, Deserialize)]
struct SnapBundle {
    meta: SnapshotMeta<u64, BasicNode>,
    data: NetStateData,
}

/// 测试用 apply 滞后注入（M4 §7：人为让 follower 落后 5s ⇒ apply-lag 熔断用例）。
/// 武装后每个 apply 批次先 sleep 指定时长——日志照常收（storage append 不延迟）、
/// 心跳照常进（网络不延迟），仅状态机 apply 停摆。
#[derive(Debug)]
pub struct LagInjector {
    armed: AtomicBool,
    delay: RwLock<Duration>,
}

impl LagInjector {
    pub fn new() -> Arc<Self> {
        Arc::new(LagInjector { armed: AtomicBool::new(false), delay: RwLock::new(Duration::ZERO) })
    }

    /// 武装（delay = 每批次 apply 停摆时长）。
    pub fn arm(&self, delay: Duration) {
        *self.delay.write().expect("lag delay") = delay;
        self.armed.store(true, Ordering::SeqCst);
    }

    /// 解除。
    pub fn disarm(&self) {
        self.armed.store(false, Ordering::SeqCst);
    }

    pub fn armed(&self) -> bool {
        self.armed.load(Ordering::SeqCst)
    }

    async fn maybe_delay(&self) {
        if self.armed() {
            let d = *self.delay.read().expect("lag delay");
            if d > Duration::ZERO {
                tokio::time::sleep(d).await;
            }
        }
    }
}

/// 状态机共享核（读路径 + 钩子 + watch）。
pub struct SmCore {
    db: Arc<Database>,
    data: RwLock<NetStateData>,
    /// 本机配置钉住的集群根公钥（admin 验签双保险；Bootstrap 之后以状态内为准）。
    pinned_root: Option<ed25519_dalek::VerifyingKey>,
    hooks: std::sync::Mutex<HookRegistry>,
    /// 已 apply 的最高日志 index（LagMonitor 共享消费）。
    applied_index: Arc<AtomicU64>,
    /// 当前全局 revocation_epoch 广播（记录缓存失效 + 票据校验消费）。
    epoch_tx: watch::Sender<u64>,
    /// 测试滞后注入。
    pub lag: Arc<LagInjector>,
}

impl SmCore {
    /// 以既有 redb 库与初始状态构造（`pinned_root` = 本机钉扎根，可 None）。
    pub fn new(
        db: Arc<Database>,
        data: NetStateData,
        pinned_root: Option<ed25519_dalek::VerifyingKey>,
    ) -> Arc<Self> {
        let epoch = data.epoch;
        let applied = data.last_applied.map(|l| l.index).unwrap_or(0);
        let (epoch_tx, _) = watch::channel(epoch);
        Arc::new(SmCore {
            db,
            data: RwLock::new(data),
            pinned_root,
            hooks: std::sync::Mutex::new(HookRegistry::new()),
            applied_index: Arc::new(AtomicU64::new(applied)),
            epoch_tx,
            lag: LagInjector::new(),
        })
    }

    /// 空库启动（无快照；由 Raft 重放/追赶补齐）。
    pub fn empty(db: Arc<Database>, pinned_root: Option<ed25519_dalek::VerifyingKey>) -> Arc<Self> {
        Self::new(db, NetStateData::new(), pinned_root)
    }

    /// 从库内快照恢复（存在时），否则空状态。
    pub fn restore_or_empty(
        db: Arc<Database>,
        pinned_root: Option<ed25519_dalek::VerifyingKey>,
    ) -> Arc<Self> {
        match read_snapshot(&db) {
            Some(bundle) => Self::new(db, bundle.data, pinned_root),
            None => Self::empty(db, pinned_root),
        }
    }

    /// 注册 apply 钩子（装配期注入；杀本地会话/清拒票据）。
    pub fn register_hook(&self, h: Arc<dyn crate::hooks::SyncHooks>) {
        self.hooks.lock().expect("sm hooks").add(h);
    }

    /// 钩子注册表共享柄（LeaseTable 等共用）。
    pub fn shared_hooks(&self) -> HookRegistry {
        self.hooks.lock().expect("sm hooks").clone()
    }

    /// 本地（非线性一致）读视图快照——仅缓存/展示路径使用。
    pub fn with_data<R>(&self, f: impl FnOnce(&NetStateData) -> R) -> R {
        f(&self.data.read().expect("sm data"))
    }

    /// 当前本地 epoch。
    pub fn epoch(&self) -> u64 {
        *self.epoch_tx.borrow()
    }

    /// epoch watch 订阅。
    pub fn epoch_watch(&self) -> watch::Receiver<u64> {
        self.epoch_tx.subscribe()
    }

    /// 已 apply 最高 index。
    pub fn applied_index(&self) -> u64 {
        self.applied_index.load(Ordering::SeqCst)
    }

    /// applied 计数器共享柄（LagMonitor 消费）。
    pub fn applied_counter(&self) -> Arc<AtomicU64> {
        self.applied_index.clone()
    }

    /// 票据密钥根（Raft 内；Bootstrap 后存在）。
    pub fn ticket_root(&self) -> Option<[u8; 32]> {
        self.with_data(|d| d.ticket_root)
    }

    /// 设备注册 VIP（转发面第 0 步源绑定校验/路由解析用）。
    pub fn vip_of(&self, device: &[u8; 32]) -> Option<[u8; 4]> {
        self.with_data(|d| d.devices.get(device).map(|r| r.vip))
    }

    /// 按 VIP 反查设备（目标归属解析；NetState 只存静态注册信息——不含当前位置）。
    pub fn device_by_vip(&self, vip: &[u8; 4]) -> Option<[u8; 32]> {
        self.with_data(|d| d.devices.iter().find(|(_, r)| &r.vip == vip).map(|(id, _)| *id))
    }

    /// 执行一批日志的 apply（核心转移 + 钩子触发 + watch 推进）。
    async fn apply_entries(&self, entries: &[Entry<SyncConfig>]) -> Vec<SyncResponse> {
        self.lag.maybe_delay().await;
        let mut out = Vec::with_capacity(entries.len());
        let mut new_epoch: Option<u64> = None;
        for e in entries {
            let idx = e.log_id.index;
            match &e.payload {
                // openraft 契约：apply 每条日志恰一个响应（Blank/成员日志给占位响应）。
                EntryPayload::Blank => out.push(SyncResponse::Ok),
                EntryPayload::Normal(req) => {
                    let outcome = {
                        let mut d = self.data.write().expect("sm data");
                        d.last_applied = Some(e.log_id);
                        let pinned = self.pinned_root.as_ref();
                        d.apply(req, pinned)
                    };
                    if let Some(ev) = outcome.revoked {
                        self.hooks.lock().expect("sm hooks").fire_revocation(ev, idx);
                        new_epoch = Some(ev.new_epoch);
                    }
                    out.push(outcome.resp);
                }
                EntryPayload::Membership(m) => {
                    let mut d = self.data.write().expect("sm data");
                    d.last_applied = Some(e.log_id);
                    d.last_membership = StoredMembership::new(Some(e.log_id), m.clone());
                    out.push(SyncResponse::Ok);
                }
            }
            self.applied_index.store(idx, Ordering::SeqCst);
        }
        if let Some(ep) = new_epoch {
            let _ = self.epoch_tx.send_if_modified(|cur| {
                if *cur < ep {
                    *cur = ep;
                    true
                } else {
                    false
                }
            });
        }
        out
    }

    /// 构建快照并持久化（重试避开偶发写冲突）。
    fn build_and_persist_snapshot(&self) -> Snapshot<SyncConfig> {
        let (bundle, meta) = {
            let d = self.data.read().expect("sm data");
            let meta = SnapshotMeta {
                last_log_id: d.last_applied,
                last_membership: d.last_membership.clone(),
                snapshot_id: format!("chml-sync-{:016x}", rng_u64()),
            };
            (SnapBundle { meta: meta.clone(), data: d.clone() }, meta)
        };
        let bytes = postcard::to_allocvec(&bundle).expect("sm snapshot serialize");
        persist_snapshot(&self.db, &bytes);
        Snapshot::<SyncConfig> {
            meta,
            snapshot: Box::new(std::io::Cursor::new(bytes)),
        }
    }
}

fn rng_u64() -> u64 {
    use rand::TryRngCore;
    let mut rng = rand::rng();
    rng.try_next_u64().expect("entropy")
}

fn persist_snapshot(db: &Arc<Database>, bytes: &[u8]) {
    for _ in 0..3 {
        let Ok(txn) = db.begin_write() else { continue };
        {
            let mut t = match txn.open_table(SMKV_TABLE) {
                Ok(t) => t,
                Err(_) => continue,
            };
            if t.insert("snapshot", bytes).is_err() {
                continue;
            }
        }
        if txn.commit().is_ok() {
            return;
        }
    }
    // 快照持久化失败不致命：日志在，重启可重放（openraft 启动重放语义）。
}

fn read_snapshot(db: &Arc<Database>) -> Option<SnapBundle> {
    let txn = db.begin_read().ok()?;
    let t = txn.open_table(SMKV_TABLE).ok()?;
    let v = t.get("snapshot").ok()??;
    postcard::from_bytes(v.value()).ok()
}

/// openraft 状态机句柄（Raft 持有；核以 Arc 共享给读路径）。
#[derive(Clone)]
pub struct RedbStateMachine {
    pub core: Arc<SmCore>,
}

impl RedbStateMachine {
    pub fn new(core: Arc<SmCore>) -> Self {
        RedbStateMachine { core }
    }
}

impl openraft::storage::RaftStateMachine<SyncConfig> for RedbStateMachine {
    type SnapshotBuilder = SmSnapshotBuilder;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<u64>>, StoredMembership<u64, BasicNode>), StorageError<u64>>
    {
        let d = self.core.data.read().expect("sm data");
        Ok((d.last_applied, d.last_membership.clone()))
    }

    async fn apply<I>(
        &mut self,
        entries: I,
    ) -> Result<Vec<SyncResponse>, StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<SyncConfig>> + Send,
        I::IntoIter: Send,
    {
        let entries: Vec<Entry<SyncConfig>> = entries.into_iter().collect();
        Ok(self.core.apply_entries(&entries).await)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        SmSnapshotBuilder { core: self.core.clone() }
    }

    async fn begin_receiving_snapshot(&mut self) -> Result<Box<std::io::Cursor<Vec<u8>>>, StorageError<u64>> {
        Ok(Box::new(std::io::Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<u64, BasicNode>,
        snapshot: Box<std::io::Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<u64>> {
        let bytes = snapshot.into_inner();
        let bundle: SnapBundle = postcard::from_bytes(&bytes).map_err(|e| {
            let io_err = std::io::Error::other(format!("snapshot decode: {e}"));
            Err::<(), std::io::Error>(io_err)
                .sto_res(|| (ErrorSubject::Store, ErrorVerb::Read))
                .expect_err("Err")
        })?;
        // 快照数据自身携带 meta；以传入 meta 为准对齐（openraft 契约）。
        let mut data = bundle.data;
        data.last_applied = meta.last_log_id;
        data.last_membership = meta.last_membership.clone();
        let epoch = data.epoch;
        let applied = meta.last_log_id.map(|l| l.index).unwrap_or(0);
        {
            let mut d = self.core.data.write().expect("sm data");
            *d = data;
        }
        self.core.applied_index.store(applied, Ordering::SeqCst);
        let _ = self.core.epoch_tx.send(epoch);
        // 安装即持久（下次重启直接从快照恢复）。
        let re_bundle = SnapBundle {
            meta: meta.clone(),
            data: self.core.data.read().expect("sm data").clone(),
        };
        let bytes = postcard::to_allocvec(&re_bundle).expect("sm snapshot serialize");
        persist_snapshot(&self.core.db, &bytes);
        Ok(())
    }

    async fn get_current_snapshot(&mut self) -> Result<Option<Snapshot<SyncConfig>>, StorageError<u64>> {
        Ok(read_snapshot(&self.core.db).map(|b| {
            let bytes = postcard::to_allocvec(&b).expect("sm snapshot serialize");
            Snapshot::<SyncConfig> { meta: b.meta, snapshot: Box::new(std::io::Cursor::new(bytes)) }
        }))
    }
}

/// 快照构建器（Raft 触发压缩时调用）。
pub struct SmSnapshotBuilder {
    core: Arc<SmCore>,
}

impl RaftSnapshotBuilder<SyncConfig> for SmSnapshotBuilder {
    async fn build_snapshot(&mut self) -> Result<Snapshot<SyncConfig>, StorageError<u64>> {
        Ok(self.core.build_and_persist_snapshot())
    }
}

// ============================================================================
// 单元测试：apply 钩子触发 + epoch watch + 快照恢复
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::HookRecorder;
    use crate::proto::SyncRequest;

    fn core() -> Arc<SmCore> {
        let dir = tempfile::tempdir().expect("tmp");
        let db = Database::create(dir.path().join("sm.redb")).expect("db");
        SmCore::empty(Arc::new(db), None)
    }

    #[tokio::test]
    async fn revocation_fires_hook_and_advances_epoch_watch() {
        let c = core();
        let rec = HookRecorder::new();
        c.register_hook(rec.clone());
        let root = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let entries = vec![
            entry(1, SyncRequest::bootstrap_signed(&root, [7; 16], [9; 32])),
            entry(2, SyncRequest::RegisterDevice { owner: "u".into(), x25519: [1; 32], ed25519: [1; 32] }),
            entry(3, SyncRequest::Revoke { device: sha(&[1; 32]) }),
        ];
        let res = c.apply_entries(&entries).await;
        assert_eq!(res.len(), 3);
        assert_eq!(c.epoch(), 1, "epoch watch 推进");
        assert_eq!(c.applied_index(), 3);
        let revs = rec.revocations();
        assert_eq!(revs.len(), 1, "杀会话钩子恰好一次");
        assert_eq!(revs[0].device, sha(&[1; 32]));
        assert_eq!(revs[0].new_epoch, 1);
        assert_eq!(revs[0].log_index, 3);
    }

    #[tokio::test]
    async fn lag_injector_stalls_apply() {
        let c = core();
        c.lag.arm(Duration::from_millis(300));
        let root = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
        let t0 = std::time::Instant::now();
        let _ = c.apply_entries(&[entry(1, SyncRequest::bootstrap_signed(&root, [7; 16], [9; 32]))]).await;
        assert!(t0.elapsed() >= Duration::from_millis(300), "武装后 apply 停摆");
        c.lag.disarm();
        let t1 = std::time::Instant::now();
        let _ = c.apply_entries(&[entry(2, SyncRequest::AllocateIp)]).await;
        assert!(t1.elapsed() < Duration::from_millis(200), "解除后不停摆");
    }

    #[tokio::test]
    async fn snapshot_build_and_restore() {
        let dir = tempfile::tempdir().expect("tmp");
        let db = Arc::new(Database::create(dir.path().join("sm.redb")).expect("db"));
        let c = SmCore::empty(db.clone(), None);
        let root = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let _ = c
            .apply_entries(&[
                entry(1, SyncRequest::bootstrap_signed(&root, [7; 16], [9; 32])),
                entry(2, SyncRequest::RegisterDevice { owner: "u".into(), x25519: [1; 32], ed25519: [1; 32] }),
            ])
            .await;
        let snap = c.build_and_persist_snapshot();
        assert_eq!(snap.meta.last_log_id.map(|l| l.index), Some(2));
        // 新核从库内快照恢复。
        let c2 = SmCore::restore_or_empty(db, None);
        assert_eq!(c2.epoch(), c.epoch());
        assert_eq!(c2.applied_index(), 2);
        assert!(c2.with_data(|d| d.devices.len() == 1));
        assert_eq!(c2.ticket_root(), Some([9; 32]), "票据密钥根随快照恢复");
    }

    fn entry(idx: u64, req: SyncRequest) -> Entry<SyncConfig> {
        Entry {
            log_id: LogId::new(openraft::CommittedLeaderId::new(1, 1), idx),
            payload: EntryPayload::Normal(req),
        }
    }

    fn sha(b: &[u8; 32]) -> [u8; 32] {
        use sha2::Digest as _;
        sha2::Sha256::digest(b).into()
    }
}
