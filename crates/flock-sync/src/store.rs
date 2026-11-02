//! openraft 日志/投票存储的 redb 适配器（§3.10 接缝：redb 单文件嵌入、纯 Rust，
//! 契合「无共享数据库」部署形态）。
//!
//! 表布局：
//! - `log`：u64 index → postcard(Entry\<SyncConfig\>)；
//! - `kv`：`vote`（postcard(Vote\<u64\>)）/ `last_purged`（postcard(LogId)）。
//!
//! 正确性：所有写在一个 redb 写事务内完成且 commit 即持久（`append` 返回前可读、
//! [`LogFlushed`] 回调在 commit 后触发）；无洞纪律由 openraft 调用序 + 范围删除保证。

use std::fmt;
use std::ops::RangeBounds;
use std::path::Path;
use std::sync::Arc;

use openraft::storage::{LogFlushed, RaftLogStorage};
use openraft::{ErrorSubject, ErrorVerb, LogId, LogState, ToStorageResult, Vote};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::raft_types::SyncConfig;

/// 日志表：index → entry 字节。
const LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("flock_sync_log");
/// KV 表：vote / last_purged。
const KV: TableDefinition<&str, &[u8]> = TableDefinition::new("flock_sync_kv");

/// redb 打开/读写失败 → openraft StorageError。
fn storage_err(e: impl fmt::Display) -> openraft::StorageError<u64> {
    let io_err = std::io::Error::other(format!("redb: {e}"));
    Err::<(), std::io::Error>(io_err)
        .sto_res(|| (ErrorSubject::Store, ErrorVerb::Write))
        .expect_err("Err")
}

/// redb 日志存储（RaftLogStorage + RaftLogReader；`Clone` 供 LogReader 派发）。
#[derive(Clone)]
pub struct RedbLogStore {
    db: Arc<Database>,
}

impl fmt::Debug for RedbLogStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedbLogStore").finish_non_exhaustive()
    }
}

impl RedbLogStore {
    /// 打开/创建（文件不存在则建库；目录自动创建）。
    /// （Err 载荷 = openraft StorageError（224B）——trait 签名约束，盒装不可行，显式豁免。）
    #[allow(clippy::result_large_err)]
    pub fn open(path: &Path) -> Result<Self, openraft::StorageError<u64>> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(storage_err)?;
        }
        let db = Database::create(path).map_err(storage_err)?;
        let db = Arc::new(db);
        Self::init_tables(&db)?;
        Ok(RedbLogStore { db })
    }

    /// 建表（幂等；装配方自持 Database 时调用——状态机快照表同库创建）。
    #[allow(clippy::result_large_err)]
    pub fn init_tables(db: &Arc<Database>) -> Result<(), openraft::StorageError<u64>> {
        let txn = db.begin_write().map_err(storage_err)?;
        {
            let _ = txn.open_table(LOG).map_err(storage_err)?;
            let _ = txn.open_table(KV).map_err(storage_err)?;
            let _ = txn.open_table(crate::sm::SMKV_TABLE).map_err(storage_err)?;
        }
        txn.commit().map_err(storage_err)
    }

    /// 由既有库构造（表须已建——[`RedbLogStore::init_tables`]）。
    pub fn from_db(db: Arc<Database>) -> Self {
        RedbLogStore { db }
    }

    #[allow(clippy::result_large_err)]
    fn write_txn(&self) -> Result<redb::WriteTransaction, openraft::StorageError<u64>> {
        self.db.begin_write().map_err(storage_err)
    }
}

impl openraft::storage::RaftLogReader<SyncConfig> for RedbLogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Send + fmt::Debug>(
        &mut self,
        range: RB,
    ) -> Result<Vec<openraft::Entry<SyncConfig>>, openraft::StorageError<u64>> {
        let txn = self.db.begin_read().map_err(storage_err)?;
        let table = txn.open_table(LOG).map_err(storage_err)?;
        let mut out = Vec::new();
        for row in table.range(range).map_err(storage_err)?.flatten() {
            let entry: openraft::Entry<SyncConfig> =
                postcard::from_bytes(row.1.value()).map_err(storage_err)?;
            out.push(entry);
        }
        Ok(out)
    }
}

impl RaftLogStorage<SyncConfig> for RedbLogStore {
    type LogReader = RedbLogStore;

    async fn get_log_state(&mut self) -> Result<LogState<SyncConfig>, openraft::StorageError<u64>> {
        let txn = self.db.begin_read().map_err(storage_err)?;
        let table = txn.open_table(LOG).map_err(storage_err)?;
        let last = match table.iter().map_err(storage_err)?.next_back() {
            Some(Ok((_idx, v))) => {
                let entry: openraft::Entry<SyncConfig> =
                    postcard::from_bytes(v.value()).map_err(storage_err)?;
                Some(entry.log_id)
            }
            Some(Err(e)) => return Err(storage_err(e)),
            None => None,
        };
        let kv = txn.open_table(KV).map_err(storage_err)?;
        let last_purged: Option<LogId<u64>> = match kv.get("last_purged").map_err(storage_err)? {
            Some(v) => postcard::from_bytes(v.value()).map_err(storage_err)?,
            None => None,
        };
        Ok(LogState {
            last_purged_log_id: last_purged,
            last_log_id: last,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<u64>) -> Result<(), openraft::StorageError<u64>> {
        let txn = self.write_txn()?;
        {
            let mut kv = txn.open_table(KV).map_err(storage_err)?;
            kv.insert(
                "vote",
                postcard::to_allocvec(vote).map_err(storage_err)?.as_slice(),
            )
            .map_err(storage_err)?;
        }
        txn.commit().map_err(storage_err)
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<u64>>, openraft::StorageError<u64>> {
        let txn = self.db.begin_read().map_err(storage_err)?;
        let kv = txn.open_table(KV).map_err(storage_err)?;
        match kv.get("vote").map_err(storage_err)? {
            // 写侧（save_vote）序列化的是裸 Vote——读侧必须同型解码。此前读侧按
            // 返回位置的 Option<Vote> 推断，首字节被当作 Option 判别式 ⇒ 选举后
            // 任意重启必炸（M5 A7 的 stop/start 实测暴露；tests/store_reopen 回归）。
            Some(v) => Ok(Some(
                postcard::from_bytes::<Vote<u64>>(v.value()).map_err(storage_err)?,
            )),
            None => Ok(None),
        }
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<SyncConfig>,
    ) -> Result<(), openraft::StorageError<u64>>
    where
        I: IntoIterator<Item = openraft::Entry<SyncConfig>> + Send,
        I::IntoIter: Send,
    {
        let mut serialized = Vec::new();
        for e in entries {
            serialized.push((
                e.log_id.index,
                postcard::to_allocvec(&e).map_err(storage_err)?,
            ));
        }
        let txn = self.write_txn()?;
        {
            let mut table = txn.open_table(LOG).map_err(storage_err)?;
            for (idx, bytes) in &serialized {
                table.insert(idx, bytes.as_slice()).map_err(storage_err)?;
            }
        }
        txn.commit().map_err(storage_err)?;
        // commit 即持久（redb WAL）；回调在持久后触发（契约：可先于/后于本方法返回）。
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<u64>) -> Result<(), openraft::StorageError<u64>> {
        remove_range(&self.db, log_id.index.., None)
    }

    async fn purge(&mut self, log_id: LogId<u64>) -> Result<(), openraft::StorageError<u64>> {
        remove_range(&self.db, ..=log_id.index, Some(log_id))
    }
}

/// 每批删除的 key 上限（分批收集-删除：旧实现的 collect-then-remove 把整段日志 index
/// 一次性物化进内存 + 单事务内逐 key 删——大日志下内存尖峰与长事务；每批独立事务，
/// 批间崩溃留下残余 key 幂等安全（下次重删同区间））。
const REMOVE_BATCH: usize = 10_000;

/// 分批删除日志区间。`purged` 非空 = purge 语义：`last_purged` 水位只在**末批**（不足
/// 一整批 = 区间已删净）同事务落盘——先推水位后删净的反向形态不出现（那会让
/// get_log_state 声称已压实而 key 仍在）。前批已删的 key 不再命中 range，循环自然推进。
#[allow(clippy::result_large_err)] // Err 载荷 = openraft StorageError（224B）——与文件内既有豁免同因
fn remove_range<R: RangeBounds<u64> + Clone>(
    db: &Arc<Database>,
    range: R,
    purged: Option<LogId<u64>>,
) -> Result<(), openraft::StorageError<u64>> {
    loop {
        let txn = db.begin_write().map_err(storage_err)?;
        let batch: Vec<u64> = {
            let table = txn.open_table(LOG).map_err(storage_err)?;
            table
                .range(range.clone())
                .map_err(storage_err)?
                .flatten()
                .map(|(k, _)| k.value())
                .take(REMOVE_BATCH)
                .collect()
        };
        let last = batch.len() < REMOVE_BATCH;
        {
            let mut table = txn.open_table(LOG).map_err(storage_err)?;
            for k in &batch {
                table.remove(k).map_err(storage_err)?;
            }
            if last {
                if let Some(p) = purged {
                    let mut kv = txn.open_table(KV).map_err(storage_err)?;
                    kv.insert(
                        "last_purged",
                        postcard::to_allocvec(&Some(p))
                            .map_err(storage_err)?
                            .as_slice(),
                    )
                    .map_err(storage_err)?;
                }
            }
        }
        txn.commit().map_err(storage_err)?;
        if last {
            return Ok(());
        }
    }
}
