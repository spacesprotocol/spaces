use std::{
    collections::BTreeMap,
    io, mem,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use crate::store::{EncodableOutpoint, Sha256, open_db};
use anyhow::{Context, Result, anyhow};
use borsh::{BorshDeserialize, BorshSerialize};
use spacedb::{
    Hash, Sha256Hasher,
    db::{Database, SnapshotIterator},
    tx::{ReadTransaction, WriteTransaction},
};
use spaces_nums::num_id::NumId;
use spaces_nums::snumeric::SNumeric;
use spaces_nums::{Commitment, CommitmentKey, CommitmentTipKey, DelegatorKey, FullNumOut, NumOut, NumOutpointKey, NumSource, RebindData, RebindKey};
use spaces_protocol::slabel::SLabel;
use spaces_protocol::{
    bitcoin::{BlockHash, OutPoint},
    constants::ChainAnchor,
    hasher::KeyHash,
};

type SpaceDb = Database<Sha256Hasher>;
type ReadTx = ReadTransaction<Sha256Hasher>;
pub type WriteTx<'db> = WriteTransaction<'db, Sha256Hasher>;
type WriteMemory = BTreeMap<Hash, Option<Vec<u8>>>;

#[derive(Clone)]
pub struct NumStore(SpaceDb);

#[derive(Clone)]
pub struct NumLiveStore {
    pub store: NumStore,
    pub state: NumLiveSnapshot,
}

#[derive(Clone)]
pub struct NumLiveSnapshot {
    db: SpaceDb,
    pub tip: Arc<RwLock<ChainAnchor>>,
    staged: Arc<RwLock<Staged>>,
    snapshot: (BlockHash, ReadTx),
}

pub struct Staged {
    /// Block height of latest snapshot
    snapshot_version: BlockHash,
    /// Stores changes until committed
    memory: WriteMemory,
}

impl NumStore {
    pub fn open(path: PathBuf, auto_hash_index: bool, cache_size: Option<usize>) -> Result<Self> {
        let db = open_db(path, auto_hash_index, cache_size)?;
        Ok(Self(db))
    }

    pub fn memory() -> Result<Self> {
        let db = Database::memory()?;
        Ok(Self(db))
    }

    pub fn iter(&self) -> SnapshotIterator<'_, Sha256Hasher> {
        self.0.iter()
    }

    pub fn write(&self) -> Result<WriteTx<'_>> {
        Ok(self.0.begin_write()?)
    }

    pub fn begin(&self, genesis_block: &ChainAnchor) -> Result<NumLiveSnapshot> {
        let snapshot = self.0.begin_read()?;
        let anchor: ChainAnchor = if snapshot.metadata().is_empty() {
            *genesis_block
        } else {
            snapshot.metadata().try_into()?
        };

        let version = anchor.hash;
        let live = NumLiveSnapshot {
            db: self.0.clone(),
            tip: Arc::new(RwLock::new(anchor)),
            staged: Arc::new(RwLock::new(Staged {
                snapshot_version: version,
                memory: BTreeMap::new(),
            })),
            snapshot: (version, snapshot),
        };

        Ok(live)
    }
}

pub trait NumChainState {
    fn insert_numout(&self, key: NumOutpointKey, ptrout: NumOut);
    fn insert_commitment(&self, key: CommitmentKey, commitment: Commitment);
    fn insert_commitment_tip(&self, key: CommitmentTipKey, state_root: Hash);
    fn remove_commitment_tip(&self, key: CommitmentTipKey);
    fn insert_delegator(&self, key: DelegatorKey, space: SLabel);
    fn insert_num_outpoint(&self, key: NumId, outpoint: EncodableOutpoint);
    fn insert_rebind(&self, key: RebindKey, rebind: RebindData);
    fn remove_rebind(&self, key: RebindKey);

    #[allow(dead_code)]
    fn get_num_info(&mut self, id: &NumId) -> Result<Option<FullNumOut>>;
}

impl NumChainState for NumLiveSnapshot {
    fn insert_numout(&self, key: NumOutpointKey, ptrout: NumOut) {
        self.insert(key, ptrout)
    }

    fn insert_commitment(&self, key: CommitmentKey, commitment: Commitment) {
        self.insert(key, commitment)
    }

    fn insert_commitment_tip(&self, key: CommitmentTipKey, state_root: Hash) {
        self.insert(key, state_root)
    }

    fn remove_commitment_tip(&self, key: CommitmentTipKey) {
        self.remove(key)
    }

    fn insert_delegator(&self, key: DelegatorKey, space: SLabel) {
        self.insert(key, space)
    }

    fn insert_num_outpoint(&self, key: NumId, outpoint: EncodableOutpoint) {
        self.insert(key, outpoint)
    }

    fn insert_rebind(&self, key: RebindKey, rebind: RebindData) {
        self.insert(key, rebind)
    }

    fn remove_rebind(&self, key: RebindKey) {
        self.remove(key)
    }

    fn get_num_info(&mut self, hash: &NumId) -> Result<Option<FullNumOut>> {
        let outpoint = self.get_num_outpoint_by_id(hash)?;

        if let Some(outpoint) = outpoint {
            let spaceout = self.get_numout(&outpoint)?;

            return Ok(Some(FullNumOut {
                txid: outpoint.txid,
                numout: spaceout.expect("should exist if outpoint exists"),
            }));
        }
        Ok(None)
    }
}

impl NumLiveSnapshot {
    #[inline]
    pub fn is_dirty(&self) -> bool {
        !self.staged.read().expect("read").memory.is_empty()
    }

    pub fn restore(&self, checkpoint: ChainAnchor) {
        let snapshot_version = checkpoint.hash;
        let mut meta_lock = self.tip.write().expect("write lock");
        *meta_lock = checkpoint;

        // clear all staged changes
        let mut staged_lock = self.staged.write().expect("write lock");
        *staged_lock = Staged {
            snapshot_version,
            memory: BTreeMap::new(),
        };
    }

    pub fn read_at(&self, block_height: u32) -> anyhow::Result<ReadTx> {
        self.db
            .iter()
            .filter_map(|s| s.ok())
            .find(|s| {
                s.metadata()
                    .try_into()
                    .is_ok_and(|a: ChainAnchor| a.height == block_height)
            })
            .ok_or_else(|| anyhow!("Snapshot at block {} not found", block_height))
    }

    pub fn inner(&mut self) -> anyhow::Result<&mut ReadTx> {
        {
            let rlock = self.staged.read().expect("acquire lock");
            let version = rlock.snapshot_version;
            drop(rlock);

            self.update_snapshot(version)?;
        }
        Ok(&mut self.snapshot.1)
    }

    pub fn insert<K: KeyHash + Into<Hash>, T: BorshSerialize>(&self, key: K, value: T) {
        let value = borsh::to_vec(&value).expect("encodes value");
        self.insert_raw(key.into(), value);
    }

    pub fn get<K: KeyHash + Into<Hash>, T: BorshDeserialize>(
        &mut self,
        key: K,
    ) -> spacedb::Result<Option<T>> {
        match self.get_raw(&key.into())? {
            Some(value) => {
                let decoded: T = borsh::from_slice(&value)
                    .map_err(|e| spacedb::Error::IO(io::Error::other(e.to_string())))?;
                Ok(Some(decoded))
            }
            None => Ok(None),
        }
    }

    pub fn remove<K: KeyHash + Into<Hash>>(&self, key: K) {
        self.remove_raw(&key.into())
    }

    #[inline]
    fn remove_raw(&self, key: &Hash) {
        self.staged
            .write()
            .expect("write lock")
            .memory
            .insert(*key, None);
    }

    #[inline]
    fn insert_raw(&self, key: Hash, value: Vec<u8>) {
        self.staged
            .write()
            .expect("write lock")
            .memory
            .insert(key, Some(value));
    }

    fn update_snapshot(&mut self, version: BlockHash) -> Result<()> {
        if self.snapshot.0 != version {
            self.snapshot.1 = self.db.begin_read().context("could not read snapshot")?;
            let anchor: ChainAnchor = self
                .snapshot
                .1
                .metadata()
                .try_into()
                .map_err(|_| std::io::Error::other("could not parse metdata"))?;

            assert_eq!(version, anchor.hash, "inconsistent db state");
            self.snapshot.0 = version;
        }
        Ok(())
    }

    pub fn get_raw(&mut self, key: &Hash) -> spacedb::Result<Option<Vec<u8>>> {
        let rlock = self.staged.read().expect("acquire lock");

        if let Some(value) = rlock.memory.get(key) {
            return match value {
                None => Ok(None),
                Some(value) => Ok(Some(value.clone())),
            };
        }

        let version = rlock.snapshot_version;
        drop(rlock);

        self.update_snapshot(version)
            .map_err(|error| spacedb::Error::IO(std::io::Error::other(error)))?;
        self.snapshot.1.get(key)
    }

    pub fn commit(&self, metadata: ChainAnchor, mut tx: WriteTx) -> Result<()> {
        let mut staged = self.staged.write().expect("write");
        let changes = mem::replace(
            &mut *staged,
            Staged {
                snapshot_version: metadata.hash,
                memory: BTreeMap::new(),
            },
        );

        for (key, value) in changes.memory {
            match value {
                None => tx = tx.delete(key)?,
                Some(value) => tx = tx.insert(key, value)?,
            }
        }

        tx.metadata(metadata.to_vec())?;
        tx.commit()?;
        drop(staged);
        Ok(())
    }
}

impl NumSource for NumLiveSnapshot {
    fn get_num_outpoint_by_id(
        &mut self,
        id: &NumId,
    ) -> spaces_protocol::errors::Result<Option<OutPoint>> {
        let result: Option<EncodableOutpoint> = self
            .get(*id)
            .map_err(|err| spaces_protocol::errors::Error::IO(format!("getnumoutpoint: {}", err)))?;
        Ok(result.map(|o| o.into()))
    }

    fn get_commitment(
        &mut self,
        key: &CommitmentKey,
    ) -> spaces_protocol::errors::Result<Option<Commitment>> {
        let result = self
            .get(*key)
            .map_err(|err| spaces_protocol::errors::Error::IO(format!("getcommitment: {}", err)))?;
        Ok(result)
    }

    fn get_delegator(
        &mut self,
        key: &DelegatorKey,
    ) -> spaces_protocol::errors::Result<Option<SLabel>> {
        let result = self
            .get(*key)
            .map_err(|err| spaces_protocol::errors::Error::IO(format!("getdelegate: {}", err)))?;
        Ok(result)
    }

    fn get_commitments_tip(
        &mut self,
        key: &CommitmentTipKey,
    ) -> spaces_protocol::errors::Result<Option<Hash>> {
        let result = self
            .get(*key)
            .map_err(|err| spaces_protocol::errors::Error::IO(format!("getregistry: {}", err)))?;
        Ok(result)
    }

    fn get_numout(
        &mut self,
        outpoint: &OutPoint,
    ) -> spaces_protocol::errors::Result<Option<NumOut>> {
        let h = NumOutpointKey::from_outpoint::<Sha256>(*outpoint);
        let result = self
            .get(h)
            .map_err(|err| spaces_protocol::errors::Error::IO(format!("getptrout: {}", err)))?;
        Ok(result)
    }

    fn get_num_id(&mut self, _snum: &SNumeric) -> spaces_protocol::errors::Result<Option<NumId>> {
        panic!("not supported call chain.get_num_id")
    }

    fn get_num_rebind(
        &mut self,
        key: &RebindKey,
    ) -> spaces_protocol::errors::Result<Option<RebindData>> {
        let result = self
            .get(*key)
            .map_err(|err| spaces_protocol::errors::Error::IO(format!("getrebind: {}", err)))?;
        Ok(result)
    }
}
