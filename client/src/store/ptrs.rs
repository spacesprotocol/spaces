use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io,
    io::ErrorKind,
    mem,
    path::{PathBuf},
    sync::{Arc, RwLock},
};

use anyhow::{anyhow, Context, Result};
use bincode::{config, Decode, Encode};
use spacedb::{
    db::{Database, SnapshotIterator},
    fs::FileBackend,
    subtree::SubTree,
    tx::{ProofType, ReadTransaction, WriteTransaction},
    Configuration, Hash, Sha256Hasher,
};
use spaces_protocol::{
    bitcoin::{BlockHash, OutPoint},
    constants::{ChainAnchor},
    hasher::{KeyHash},
};
use spaces_protocol::slabel::SLabel;
use spaces_ptr::{Commitment, CommitmentKey, FullPtrOut, PtrOut, PtrSource, RegistryKey, RegistrySptrKey, PtrOutpointKey};
use spaces_ptr::sptr::Sptr;
use crate::store::{EncodableOutpoint, Sha256};

type SpaceDb = Database<Sha256Hasher>;
type ReadTx = ReadTransaction<Sha256Hasher>;
pub type WriteTx<'db> = WriteTransaction<'db, Sha256Hasher>;
type WriteMemory = BTreeMap<Hash, Option<Vec<u8>>>;

#[derive(Clone)]
pub struct PtrStore(SpaceDb);

#[derive(Clone)]
pub struct PtrLiveStore {
    pub store: PtrStore,
    pub state: PtrLiveSnapshot,
}

#[derive(Clone)]
pub struct PtrLiveSnapshot {
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

impl PtrStore {
    pub fn open(path: PathBuf) -> Result<Self> {
        let db = Self::open_db(path)?;
        Ok(Self(db))
    }

    pub fn memory() -> Result<Self> {
        let db = Database::memory()?;
        Ok(Self(db))
    }

    fn open_db(path_buf: PathBuf) -> anyhow::Result<Database<Sha256Hasher>> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path_buf)?;

        let config = Configuration::new().with_cache_size(1000000 /* 1MB */);
        Ok(Database::new(Box::new(FileBackend::new(file)?), config)?)
    }

    pub fn iter(&self) -> SnapshotIterator<Sha256Hasher> {
        return self.0.iter();
    }

    pub fn write(&self) -> Result<WriteTx> {
        Ok(self.0.begin_write()?)
    }

    pub fn begin(&self, genesis_block: &ChainAnchor) -> Result<PtrLiveSnapshot> {
        let snapshot = self.0.begin_read()?;
        let anchor: ChainAnchor = if snapshot.metadata().len() == 0 {
            genesis_block.clone()
        } else {
            snapshot.metadata().try_into()?
        };

        let version = anchor.hash;
        let live = PtrLiveSnapshot {
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

pub trait PtrChainState {
    fn insert_ptrout(&self, key: PtrOutpointKey, ptrout: PtrOut);
    fn insert_commitment(&self, key: CommitmentKey, commitment: Commitment);
    fn insert_registry(&self, key: RegistryKey, state_root: Hash);
    fn insert_registry_delegation(&self, key: RegistrySptrKey, space: SLabel);
    fn insert_ptr(&self, key: Sptr, outpoint: EncodableOutpoint);

    #[allow(dead_code)]
    fn get_ptr_info(
        &mut self,
        space_hash: &Sptr,
    ) -> Result<Option<FullPtrOut>>;

    fn get_all_ptrs(&mut self, with_data: bool) -> Result<Vec<FullPtrOut>>;
}

impl PtrChainState for PtrLiveSnapshot {
    fn insert_ptrout(&self, key: PtrOutpointKey, ptrout: PtrOut) {
        self.insert(key, ptrout)
    }

    fn insert_commitment(&self, key: CommitmentKey, commitment: Commitment) {
        self.insert(key, commitment)
    }

    fn insert_registry(&self, key: RegistryKey, state_root: Hash) {
        self.insert(key, state_root)
    }

    fn insert_registry_delegation(&self, key: RegistrySptrKey, space: SLabel) {
        self.insert(key, space)
    }

    fn insert_ptr(&self, key: Sptr, outpoint: EncodableOutpoint) {
        self.insert(key, outpoint)
    }

    fn get_ptr_info(&mut self, hash: &Sptr) -> Result<Option<FullPtrOut>> {
        let outpoint = self.get_ptr_outpoint(hash)?;

        if let Some(outpoint) = outpoint {
            let spaceout = self.get_ptrout(&outpoint)?;

            return Ok(Some(FullPtrOut {
                txid: outpoint.txid,
                ptrout: spaceout.expect("should exist if outpoint exists"),
            }));
        }
        Ok(None)
    }

    fn get_all_ptrs(&mut self, with_data: bool) -> Result<Vec<FullPtrOut>> {
        let mut ptrs = Vec::new();
        let mut seen_keys = BTreeSet::new();
        
        // First, collect staged changes (memory) - collect Sptr keys first, then process
        let mut staged_sptrs = Vec::new();
        {
            let rlock = self.staged.read().expect("acquire lock");
            for (key, value) in rlock.memory.iter() {
                // Skip deleted entries
                if value.is_none() {
                    continue;
                }
                
                // Try to decode key as Sptr (32 bytes) - Hash is already [u8; 32]
                // Use unsafe transmute since Hash and Sptr are both [u8; 32]
                let sptr = unsafe { std::mem::transmute::<Hash, Sptr>(*key) };
                
                // Check if value decodes as EncodableOutpoint (indicates it's a PTR entry)
                if let Some(value) = value {
                    let decode_result: Result<(EncodableOutpoint, usize), _> = bincode::decode_from_slice(&value, config::standard());
                    if decode_result.is_ok() {
                        seen_keys.insert(*key);
                        staged_sptrs.push(sptr);
                    }
                }
            }
        }
        
        // Now process staged SPTRs (lock is dropped)
        for sptr in staged_sptrs {
            if let Ok(Some(ptr_out)) = self.get_ptr_info(&sptr) {
                // Filter by with_data flag if set
                if !with_data || (ptr_out.ptrout.sptr.is_some() && ptr_out.ptrout.sptr.as_ref().unwrap().data.is_some()) {
                    ptrs.push(ptr_out);
                }
            }
        }
        
        // Then iterate through snapshot
        let snapshot = self.inner()?;
        for item in snapshot.iter() {
            let (key, value) = item?;
            
            // Skip if already processed from staged changes
            if seen_keys.contains(&key) {
                continue;
            }
            
            // Try to decode key as Sptr (32 bytes) - Hash is already [u8; 32]
            // Use unsafe transmute since Hash and Sptr are both [u8; 32]
            let sptr = unsafe { std::mem::transmute::<Hash, Sptr>(key) };
            
            // Check if value decodes as EncodableOutpoint (indicates it's a PTR entry)
            let decode_result: Result<(EncodableOutpoint, usize), _> = bincode::decode_from_slice(&value, config::standard());
            if decode_result.is_ok() {
                // Try to get ptr info - if successful, it's a valid PTR
                if let Ok(Some(ptr_out)) = self.get_ptr_info(&sptr) {
                    // Filter by with_data flag if set
                    if !with_data || (ptr_out.ptrout.sptr.is_some() && ptr_out.ptrout.sptr.as_ref().unwrap().data.is_some()) {
                        ptrs.push(ptr_out);
                    }
                }
            }
        }
        
        Ok(ptrs)
    }
}

impl PtrLiveSnapshot {
    #[inline]
    pub fn is_dirty(&self) -> bool {
        self.staged.read().expect("read").memory.len() > 0
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

    pub fn prove_with_snapshot(
        &self,
        keys: &[Hash],
        snapshot_block_height: u32,
    ) -> Result<SubTree<Sha256Hasher>> {
        let snapshot = self.db.iter().filter_map(|s| s.ok()).find(|s| {
            let anchor: ChainAnchor = match s.metadata().try_into() {
                Ok(a) => a,
                _ => return false,
            };
            anchor.height == snapshot_block_height
        });
        if let Some(mut snapshot) = snapshot {
            return snapshot
                .prove(keys, ProofType::Standard)
                .or_else(|err| Err(anyhow!("Could not prove: {}", err)));
        }
        Err(anyhow!(
            "Older snapshot targeting block {} could not be found",
            snapshot_block_height
        ))
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

    pub fn insert<K: KeyHash + Into<Hash>, T: Encode>(&self, key: K, value: T) {
        let value = bincode::encode_to_vec(value, config::standard()).expect("encodes value");
        self.insert_raw(key.into(), value);
    }

    pub fn get<K: KeyHash + Into<Hash>, T: Decode<()>>(
        &mut self,
        key: K,
    ) -> spacedb::Result<Option<T>> {
        match self.get_raw(&key.into())? {
            Some(value) => {
                let (decoded, _): (T, _) = bincode::decode_from_slice(&value, config::standard())
                    .map_err(|e| {
                        spacedb::Error::IO(io::Error::new(ErrorKind::Other, e.to_string()))
                    })?;
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
            let anchor: ChainAnchor = self.snapshot.1.metadata().try_into().map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::Other, "could not parse metdata")
            })?;

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

        self.update_snapshot(version).map_err(|error| {
            spacedb::Error::IO(std::io::Error::new(std::io::ErrorKind::Other, error))
        })?;
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
                None => {
                    _ = {
                        tx = tx.delete(key)?;
                    }
                }
                Some(value) => tx = tx.insert(key, value)?,
            }
        }

        tx.metadata(metadata.to_vec())?;
        tx.commit()?;
        drop(staged);
        Ok(())
    }
}

impl PtrSource for PtrLiveSnapshot {
    fn get_ptr_outpoint(
        &mut self,
        sptr: &Sptr,
    ) -> spaces_protocol::errors::Result<Option<OutPoint>> {
        let result: Option<EncodableOutpoint> = self.get(*sptr).map_err(|err| {
            spaces_protocol::errors::Error::IO(format!("getptroutpoint: {}", err.to_string()))
        })?;
        Ok(result.map(|out| out.into()))
    }

    fn get_commitment(&mut self, key: &CommitmentKey) -> spaces_protocol::errors::Result<Option<Commitment>> {
        let result = self.get(*key).map_err(|err| {
            spaces_protocol::errors::Error::IO(format!("getcommitment: {}", err.to_string()))
        })?;
        Ok(result)
    }

    fn get_delegator(&mut self, key: &RegistrySptrKey) -> spaces_protocol::errors::Result<Option<SLabel>> {
        let result = self.get(*key).map_err(|err| {
            spaces_protocol::errors::Error::IO(format!("getdelegate: {}", err.to_string()))
        })?;
        Ok(result)
    }

    fn get_commitments_tip(&mut self, key: &RegistryKey) -> spaces_protocol::errors::Result<Option<Hash>> {
        let result = self.get(*key).map_err(|err| {
            spaces_protocol::errors::Error::IO(format!("getregistry: {}", err.to_string()))
        })?;
        Ok(result)
    }

    fn get_ptrout(
        &mut self,
        outpoint: &OutPoint,
    ) -> spaces_protocol::errors::Result<Option<PtrOut>> {
        let h = PtrOutpointKey::from_outpoint::<Sha256>(*outpoint);
        let result = self.get(h).map_err(|err| {
            spaces_protocol::errors::Error::IO(format!("getptrout: {}", err.to_string()))
        })?;
        Ok(result)
    }
}
