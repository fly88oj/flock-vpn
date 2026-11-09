//! Regression: redb log store reopened across processes (the M5 A7
//! stop/start path).
//!
//! The former defect (exposed by container runs): `save_vote` serialized a
//! bare `Vote`, while `read_vote`'s `postcard::from_bytes` inferred an
//! `Option<Vote>` from the return position — the first byte was consumed as
//! an Option discriminant ⇒ "Found an Option discriminant that wasn't 0 or
//! 1". On first database creation the vote key does not exist (decoding not
//! triggered), so startup was fine; **any restart after an election wrote a
//! vote blew up**. The M4 in-memory/single-process tests never restarted a
//! node, so it went unseen.
//!
//! This test pins the reopen semantics: write (vote + Blank/Normal log
//! entries of each kind) → close → reopen → `read_vote`/`get_log_state`
//! restored verbatim + a `save_vote` real-entry round trip.

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

    // The bare byte shape of a Vote ([term, node, committed] — no Option
    // shell).
    let vote = openraft::Vote::<u64>::new(3, 2);
    let vote_bytes = postcard::to_allocvec(&vote).unwrap();
    assert_eq!(
        vote_bytes,
        vec![3, 2, 0],
        "bare Vote encoding (no Option discriminant byte)"
    );

    // —— Stage one: write bytes identical to save_vote/append into the
    //    database → close ——
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
        drop(db); // clean close
    }

    // —— Stage two: reopen (a new Database instance = simulating a process
    //    restart) ——
    {
        let db = Arc::new(redb::Database::create(&path).unwrap());
        let mut store = RedbLogStore::from_db(db.clone());
        // The fix point: the vote exists ⇒ decoding must succeed (the old
        // code threw the Option discriminant here).
        let v = store.read_vote().await.unwrap().expect("vote restored");
        assert_eq!(v, vote);
        let st = store.get_log_state().await.unwrap();
        assert_eq!(st.last_log_id, Some(lid(2)));
        assert_eq!(st.last_purged_log_id, None);
        drop(store);

        // Another round through the store's real entry point (save_vote) +
        // reopen, closing the loop.
        let mut store2 = RedbLogStore::from_db(db);
        store2.save_vote(&openraft::Vote::new(4, 1)).await.unwrap();
        drop(store2);
        let db3 = Arc::new(redb::Database::create(&path).unwrap());
        let mut store3 = RedbLogStore::from_db(db3);
        assert_eq!(
            store3.read_vote().await.unwrap(),
            Some(openraft::Vote::new(4, 1)),
            "save_vote → restart → read_vote closed loop"
        );
    }
}

/// Batched deletion (truncate/purge, ≤10000 keys per batch): a large range
/// spanning batch boundaries fully deleted + purge persists the
/// `last_purged` watermark only in the final batch (observable via
/// get_log_state).
#[tokio::test]
async fn store_purge_truncate_across_batch_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(redb::Database::create(dir.path().join("batch.redb")).unwrap());
    RedbLogStore::init_tables(&db).unwrap();

    // 10005 Blank entries (> one 10000-key batch ⇒ at least two batches); the
    // `LogFlushed` callback is an openraft-internal type (pub(crate)
    // constructor), so we write the LOG table directly, same as above.
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

    // purge 1..=10003 (two full batches + 3 entries): after the whole range
    // is deleted the watermark = 10003 (the final batch persists it in the
    // same transaction).
    store.purge(lid(n - 2)).await.unwrap();
    let st = store.get_log_state().await.unwrap();
    assert_eq!(
        st.last_purged_log_id,
        Some(lid(n - 2)),
        "after batched deletion last_purged lands in the final batch's transaction"
    );
    assert_eq!(
        st.last_log_id,
        Some(lid(n)),
        "the remaining tail log intact"
    );
    let left: Vec<_> = store
        .try_get_log_entries((n - 2)..=n)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.log_id.index)
        .collect();
    assert_eq!(
        left,
        vec![n - 1, n],
        "residue inside the range is only the un-purged part"
    );

    // Truncate the tail (isomorphic recheck: a small range deleted within one
    // batch) — cut from 10005, leaving a single entry 10004.
    store.truncate(lid(n)).await.unwrap();
    let st = store.get_log_state().await.unwrap();
    assert_eq!(
        st.last_log_id,
        Some(lid(n - 1)),
        "after truncate the last entry = 10004"
    );
    assert_eq!(
        st.last_purged_log_id,
        Some(lid(n - 2)),
        "truncate does not move the purge watermark"
    );
}
