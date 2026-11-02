//! 回归：redb 日志存储跨进程重开（M5 A7 的 stop/start 路径）。
//!
//! 曾经的缺陷（容器实测暴露）：`save_vote` 序列化裸 `Vote`，而 `read_vote` 的
//! `postcard::from_bytes` 按返回位置推断成 `Option<Vote>`——首字节被当作 Option
//! 判别式 ⇒「Found an Option discriminant that wasn't 0 or 1」。首次建库时 vote
//! 键不存在（不触发解码）所以起服正常；**选举写入 vote 后的任意一次重启必炸**。
//! M4 内存/单进程测试从未重启节点，故未暴露。
//!
//! 本测试钉住重开语义：写（vote + Blank/Normal 各类日志条目）→ 关库 → 重开 →
//! `read_vote`/`get_log_state` 原样恢复 + `save_vote` 真入口闭环。

use std::sync::Arc;

use flock_sync::store::RedbLogStore;
use flock_sync::SyncConfig;
use openraft::storage::{RaftLogReader as _, RaftLogStorage as _};

const KV: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("flock_sync_kv");
const LOG: redb::TableDefinition<u64, &[u8]> = redb::TableDefinition::new("flock_sync_log");

fn lid(idx: u64) -> openraft::LogId<u64> {
    openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), idx)
}

#[tokio::test]
async fn store_reopen_recovers_vote_and_log() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.redb");

    // Vote 的裸字节形态（[term, node, committed]——无 Option 外壳）。
    let vote = openraft::Vote::<u64>::new(3, 2);
    let vote_bytes = postcard::to_allocvec(&vote).unwrap();
    assert_eq!(vote_bytes, vec![3, 2, 0], "裸 Vote 编码（无 Option 判别字节）");

    // —— 第一段：与 save_vote/append 相同的字节写入库 → 关库 ——
    {
        let db = Arc::new(redb::Database::create(&path).unwrap());
        RedbLogStore::init_tables(&db).unwrap();
        let txn = db.begin_write().unwrap();
        {
            let mut kv = txn.open_table(KV).unwrap();
            kv.insert("vote", vote_bytes.as_slice()).unwrap();
            let mut log = txn.open_table(LOG).unwrap();
            let items: Vec<(u64, openraft::EntryPayload<SyncConfig>)> = vec![
                (1, openraft::EntryPayload::<SyncConfig>::Blank),
                (
                    2,
                    openraft::EntryPayload::Normal(flock_sync::SyncRequest::Revoke {
                        device: [7; 32],
                    }),
                ),
            ];
            for (idx, payload) in items {
                let e = openraft::Entry::<SyncConfig> {
                    log_id: lid(idx),
                    payload,
                };
                log.insert(idx, postcard::to_allocvec(&e).unwrap().as_slice())
                    .unwrap();
            }
        }
        txn.commit().unwrap();
        drop(db); // 干净关闭
    }

    // —— 第二段：重开（新 Database 实例 = 模拟进程重启）——
    {
        let db = Arc::new(redb::Database::create(&path).unwrap());
        let mut store = RedbLogStore::from_db(db.clone());
        // 修复点：vote 存在 ⇒ 必须成功解码（旧代码在此抛 Option discriminant）。
        let v = store.read_vote().await.unwrap().expect("vote 恢复");
        assert_eq!(v, vote);
        let st = store.get_log_state().await.unwrap();
        assert_eq!(st.last_log_id, Some(lid(2)));
        assert_eq!(st.last_purged_log_id, None);
        drop(store);

        // 再来一轮 store 真入口（save_vote）+ 重开闭环。
        let mut store2 = RedbLogStore::from_db(db);
        store2
            .save_vote(&openraft::Vote::new(4, 1))
            .await
            .unwrap();
        drop(store2);
        let db3 = Arc::new(redb::Database::create(&path).unwrap());
        let mut store3 = RedbLogStore::from_db(db3);
        assert_eq!(
            store3.read_vote().await.unwrap(),
            Some(openraft::Vote::new(4, 1)),
            "save_vote → 重启 → read_vote 闭环"
        );
    }
}

/// 分批删除（truncate/purge 每批 ≤10000 key）：跨批边界的大区间删净 + purge 只在
/// 末批落 `last_purged` 水位（get_log_state 可观测）。
#[tokio::test]
async fn store_purge_truncate_across_batch_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(redb::Database::create(dir.path().join("batch.redb")).unwrap());
    RedbLogStore::init_tables(&db).unwrap();

    // 10005 条 Blank 日志（> 一批 10000 ⇒ 至少两批）；`LogFlushed` 回调是 openraft
    // 内部类型（pub(crate) 构造），此处与上文同法直写 LOG 表。
    let n: u64 = 10_005;
    {
        let txn = db.begin_write().unwrap();
        {
            let mut log = txn.open_table(LOG).unwrap();
            for i in 1..=n {
                let e = openraft::Entry::<SyncConfig> {
                    log_id: lid(i),
                    payload: openraft::EntryPayload::Blank,
                };
                log.insert(i, postcard::to_allocvec(&e).unwrap().as_slice())
                    .unwrap();
            }
        }
        txn.commit().unwrap();
    }

    let mut store = RedbLogStore::from_db(db);
    assert_eq!(
        store.get_log_state().await.unwrap().last_log_id,
        Some(lid(n))
    );

    // purge 1..=10003（两整批 + 3 条）：全段删净后水位 = 10003（末批同事务落盘）。
    store.purge(lid(n - 2)).await.unwrap();
    let st = store.get_log_state().await.unwrap();
    assert_eq!(
        st.last_purged_log_id,
        Some(lid(n - 2)),
        "分批删净后 last_purged 落末批事务"
    );
    assert_eq!(st.last_log_id, Some(lid(n)), "剩余尾部日志完好");
    let left: Vec<_> = store
        .try_get_log_entries((n - 2)..=n)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.log_id.index)
        .collect();
    assert_eq!(left, vec![n - 1, n], "区间内残余仅未 purge 部分");

    // truncate 尾部（同构复核：小段一批内删净）——自 10005 起截，剩 10004 一条。
    store.truncate(lid(n)).await.unwrap();
    let st = store.get_log_state().await.unwrap();
    assert_eq!(st.last_log_id, Some(lid(n - 1)), "truncate 后末条 = 10004");
    assert_eq!(
        st.last_purged_log_id,
        Some(lid(n - 2)),
        "truncate 不动 purge 水位"
    );
}
