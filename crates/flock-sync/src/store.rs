//! redb adapter for openraft log/vote storage (§3.10 seam: redb is a
//! single-file embedded, pure-Rust store, fitting the "no shared database"
//! deployment shape).
//!
//! Table layout:
//! - `log`: u64 index → postcard(Entry\<SyncConfig\>);
//! - `kv`: `vote` (postcard(Vote\<u64\>)) / `last_purged` (postcard(LogId)).
//!
//! Correctness: all writes complete inside one redb write transaction and a
//! commit is durable (readable before `append` returns; the [`LogFlushed`]
//! callback fires after commit); the no-gaps discipline is guaranteed by the
//! openraft call order + range deletion.

use std::fmt;
use std::ops::RangeBounds;
use std::path::Path;
use std::sync::Arc;

use openraft::storage::{LogFlushed, RaftLogStorage};
use openraft::{ErrorSubject, ErrorVerb, LogId, LogState, ToStorageResult, Vote};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::raft_types::SyncConfig;

/// Log table: index → entry bytes.
const LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("flock_sync_log");
/// KV table: vote / last_purged.
const KV: TableDefinition<&str, &[u8]> = TableDefinition::new("flock_sync_kv");

/// redb open/read/write failure → openraft StorageError.
fn storage_err(e: impl fmt::Display) -> openraft::StorageError<u64> {
    let io_err = std::io::Error::other(format!("redb: {e}"));
    Err::<(), std::io::Error>(io_err)
        .sto_res(|| (ErrorSubject::Store, ErrorVerb::Write))
        .expect_err("Err")
}

/// redb log storage (RaftLogStorage + RaftLogReader; `Clone` for LogReader
/// dispatch).
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
    /// Open/create (creates the database if the file does not exist;
    /// directories created automatically). (The Err payload = openraft
    /// StorageError (224B) — a trait-signature constraint; boxing is not
    /// viable, exemption explicit.)
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

    /// Create tables (idempotent; called when the assembler holds its own
    /// Database — the state machine snapshot table is created in the same
    /// database).
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

    /// Construct from an existing database (tables must already exist —
    /// [`RedbLogStore::init_tables`]).
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
            // The write side (save_vote) serializes a bare Vote — the read
            // side must decode the same shape. Previously the read side
            // inferred from the return position's Option<Vote>, so the first
            // byte was consumed as an Option discriminant ⇒ any restart after
            // an election blew up (exposed by M5 A7's stop/start run;
            // tests/store_reopen regression).
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
        // Commit is durable (redb WAL); the callback fires after durability
        // (contract: may run before or after this method returns).
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

/// Upper bound of keys deleted per batch (batched collect-then-delete: the
/// old implementation's collect-then-remove materialized an entire log index
/// range into memory at once + deleted key by key inside a single
/// transaction — memory spikes and long transactions on large logs; each
/// batch is its own transaction, and leftover keys from a crash between
/// batches are idempotently safe to re-delete (the same range is removed
/// next time)).
const REMOVE_BATCH: usize = 10_000;

/// Batched deletion of a log range. Non-empty `purged` = purge semantics: the
/// `last_purged` watermark is persisted only in the **final batch** (shorter
/// than a full batch = the range has been fully deleted) within the same
/// transaction — the reverse shape (advancing the watermark before deleting
/// everything) never occurs (that would let get_log_state claim compaction
/// while the keys are still there). Keys already deleted by earlier batches
/// no longer match the range, so the loop naturally advances.
#[allow(clippy::result_large_err)] // Err payload = openraft StorageError (224B) — same reason as the existing exemption in this file
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
