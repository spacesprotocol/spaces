use std::path::Path;
use anyhow::{anyhow, Context};
use log::info;
use spacedb::{Hash, Sha256Hasher};
use spacedb::subtree::SubTree;
use spaces_protocol::bitcoin::{BlockHash, OutPoint};
use spaces_protocol::bitcoin::hashes::Hash as HashUtil;
use spaces_protocol::constants::ChainAnchor;
use spaces_protocol::hasher::{BaseHash, BidKey, OutpointKey, SpaceKey};
use spaces_protocol::prepare::SpacesSource;
use spaces_protocol::{FullSpaceOut, SpaceOut};
use spaces_protocol::slabel::SLabel;
use spaces_ptr::{Commitment, CommitmentKey, FullPtrOut, PtrOut, PtrSource, RegistryKey, RegistrySptrKey, PtrOutpointKey};
use spaces_ptr::sptr::Sptr;
use spaces_wallet::bitcoin::Network;
use crate::client::{BlockMeta, PtrBlockMeta};
use crate::rpc::{BlockMetaWithHash, PtrBlockMetaWithHash};
use crate::store::{EncodableOutpoint, ReadTx, Sha256};
use crate::store::ptrs::{PtrChainState, PtrLiveStore, PtrStore};
use crate::store::spaces::{RolloutEntry, RolloutIterator, SpLiveStore, SpStore, SpStoreUtils, SpacesState};

pub const ROOT_ANCHORS_COUNT: u32 = 120;
pub const COMMIT_BLOCK_INTERVAL: u32 = 36;

// https://internals.rust-lang.org/t/nicer-static-assertions/15986
macro_rules! const_assert {
    ($($tt:tt)*) => {
        const _: () = assert!($($tt)*);
    }
}

const_assert!(
    spaces_protocol::constants::ROLLOUT_BLOCK_INTERVAL % COMMIT_BLOCK_INTERVAL == 0,
    "commit and rollout intervals must be aligned"
);


#[derive(Clone)]
pub struct Chain {
    db: LiveStore,
    idx: LiveIndex,
    ptrs_genesis: ChainAnchor,
}

#[derive(Clone)]
pub struct LiveStore {
    sp: SpLiveStore,
    pt: PtrLiveStore,
}

#[derive(Clone)]
pub struct LiveIndex {
    sp: Option<SpLiveStore>,
    pt: Option<PtrLiveStore>,
}

impl SpacesSource for Chain {
    fn get_space_outpoint(&mut self, space_hash: &SpaceKey) -> spaces_protocol::errors::Result<Option<OutPoint>> {
        self.db.sp.state.get_space_outpoint(space_hash)
    }

    fn get_spaceout(&mut self, outpoint: &OutPoint) -> spaces_protocol::errors::Result<Option<SpaceOut>> {
        self.db.sp.state.get_spaceout(outpoint)
    }
}

impl PtrSource for Chain {
    fn get_ptr_outpoint(&mut self, space_hash: &Sptr) -> spaces_protocol::errors::Result<Option<OutPoint>> {
        self.db.pt.state.get_ptr_outpoint(space_hash)
    }

    fn get_commitment(&mut self, key: &CommitmentKey) -> spaces_protocol::errors::Result<Option<Commitment>> {
        self.db.pt.state.get_commitment(key)
    }

    fn get_delegator(&mut self, sptr: &RegistrySptrKey) -> spaces_protocol::errors::Result<Option<SLabel>> {
        self.db.pt.state.get_delegator(sptr)
    }

    fn get_commitments_tip(&mut self, key: &RegistryKey) -> spaces_protocol::errors::Result<Option<Hash>> {
        self.db.pt.state.get_commitments_tip(key)
    }

    fn get_ptrout(&mut self, outpoint: &OutPoint) -> spaces_protocol::errors::Result<Option<PtrOut>> {
        self.db.pt.state.get_ptrout(outpoint)
    }
}

impl Chain {
    pub fn get_space_info(&mut self, space_hash: &SpaceKey) -> anyhow::Result<Option<FullSpaceOut>> {
        self.db.sp.state.get_space_info(space_hash)
    }

    pub fn get_ptr_info(&mut self, key: &Sptr) -> anyhow::Result<Option<FullPtrOut>> {
        self.db.pt.state.get_ptr_info(key)
    }

    pub fn load(_network: Network, genesis: ChainAnchor, ptrs_genesis: ChainAnchor, dir: &Path, index_spaces: bool, index_ptrs: bool) -> anyhow::Result<Self> {
        let proto_db_path = dir.join("spaces.sdb");
        let ptrs_db_path = dir.join("refs.sdb");
        let initial_sp_sync = !proto_db_path.exists();
        let initial_pt_sync = !ptrs_db_path.exists();

        let sp_store = SpStore::open(proto_db_path)?;
        let sp = SpLiveStore {
            state: sp_store.begin(&genesis)?,
            store: sp_store,
        };

        let pt_store = PtrStore::open(ptrs_db_path)?;
        let pt = PtrLiveStore {
            state: pt_store.begin(&ptrs_genesis)?,
            store: pt_store,
        };


        let mut sp_idx = None;

        if index_spaces {
            let current_tip = sp.state.tip.read().expect("tip");
            sp_idx = Some(load_sp_index(dir, genesis, *current_tip, initial_sp_sync)?)
        }

        let mut pt_idx = None;
        if index_ptrs {
            let current_tip = pt.state.tip.read().expect("tip");
            pt_idx = Some(load_pt_index(dir, ptrs_genesis, *current_tip, initial_pt_sync)?)
        }

        let chain = Chain {
            db: LiveStore { sp, pt },
            idx: LiveIndex { sp: sp_idx, pt: pt_idx },
            ptrs_genesis
        };

        // If spaces synced past the ptrs point, reset the tip
        if initial_pt_sync {
            let sp_tip = chain.db.sp.state.tip.read().expect("tip").clone();
            if sp_tip.height > ptrs_genesis.height {
                info!("spaces tip = {} > ptrs genesis = {} - rescanning to index ptrs",
                    sp_tip.height, ptrs_genesis.height
                );
                assert_eq!(
                    ptrs_genesis.height % COMMIT_BLOCK_INTERVAL, 0,
                    "ptrs genesis must align with commit interval"
                );
                chain.restore_spaces(|_| {
                    return Ok(BlockHash::from_slice(&[0u8; 32]).expect("hash"));
                }, Some(ptrs_genesis.height))?;
            }
        }

        Ok(chain)
    }

    pub fn tip(&self) -> ChainAnchor {
        self.db.sp.state.tip.read().expect("read").clone()
    }

    pub fn apply_block_to_spaces_index(
        &self,
        block_hash: BlockHash,
        block: BlockMeta,
    ) -> anyhow::Result<()> {
        if let Some(idx) = &self.idx.sp {
            idx.state.insert(BaseHash::from_slice(block_hash.as_ref()), block);
        }
        Ok(())
    }

    pub fn apply_block_to_ptrs_index(
        &self,
        block_hash: BlockHash,
        block: PtrBlockMeta,
    ) -> anyhow::Result<()> {
        if let Some(idx) = &self.idx.pt {
            idx.state.insert(BaseHash::from_slice(block_hash.as_ref()), block);
        }
        Ok(())
    }

    pub fn maybe_commit(&self, checkpoint: ChainAnchor) -> anyhow::Result<bool> {
        if checkpoint.height % COMMIT_BLOCK_INTERVAL != 0 {
            return Ok(false);
        }

        let spaces_batch = self.db.sp.store.write().expect("write handle");
        let ptrs_batch = self.db.pt.store.write().expect("write handle");

        self.db.sp.state.commit(checkpoint.clone(), spaces_batch)?;
        self.db.pt.state.commit(checkpoint.clone(), ptrs_batch)?;

        let sp_index_writer = self.idx.sp.clone();
        if let Some(index) = sp_index_writer {
            let tx = index.store.write().expect("write handle");
            index.state.commit(checkpoint, tx)?;
        }

        let pt_index_writer = self.idx.pt.clone();
        if let Some(index) = pt_index_writer {
            let tx = index.store.write().expect("write handle");
            index.state.commit(checkpoint, tx)?;
        }
        Ok(true)
    }

    pub fn spaces_mut(&mut self) -> &mut SpLiveStore {
        &mut self.db.sp
    }

    pub fn ptrs_mut(&mut self) -> &mut PtrLiveStore {
        &mut self.db.pt
    }

    pub fn has_spaces_index(&self) -> bool {
        self.idx.sp.is_some()
    }

    pub fn has_ptrs_index(&self) -> bool {
        self.idx.pt.is_some()
    }

    pub fn rollout_iter(&self) -> anyhow::Result<(RolloutIterator, ReadTx)> {
        self.db.sp.store.rollout_iter()
    }

    pub fn is_dirty(&self) -> bool {
        self.db.sp.state.is_dirty() || self.db.pt.state.is_dirty()
    }

    pub fn spaces_tip_meatadata(&mut self) -> anyhow::Result<&[u8]> {
        Ok(self.db.sp.state.inner()?.metadata())
    }

    pub(crate) fn insert_spaceout(&self, key: OutpointKey, spaceout: SpaceOut) {
        self.db.sp.state.insert(key, spaceout)
    }

    pub(crate) fn insert_space(&self, key: SpaceKey, outpoint: EncodableOutpoint) {
        self.db.sp.state.insert(key, outpoint)
    }

    pub(crate) fn update_bid(&self, previous: Option<BidKey>, bid: BidKey, space: SpaceKey) {
        if let Some(previous) = previous {
            self.db.sp.state.remove(previous);
        }
        self.db.sp.state.insert(bid, space)
    }

    pub fn remove_bid(&self, bid_key: BidKey) {
        self.db.sp.state.remove(bid_key);
    }

    pub fn spaces_inner(&mut self) -> anyhow::Result<&mut ReadTx> {
        self.db.sp.state.inner()
    }

    pub fn ptrs_tip(&self) -> ChainAnchor {
        *self.db.pt.state.tip.read().expect("ptrs tip")
    }

    pub fn can_scan_ptrs(&self, height: u32) -> bool {
        height > self.ptrs_genesis.height
    }

    pub fn update_ptrs_tip(&self, height: u32, block_hash: BlockHash) {
        let mut tip = self.db.pt.state.tip.write().expect("write tip");
        tip.height = height;
        tip.hash = block_hash;
    }

    pub fn update_spaces_tip(&self, height: u32, block_hash: BlockHash) {
        let mut tip = self.db.sp.state.tip.write().
            expect("write tip");
        tip.height = height;
        tip.hash = block_hash;
    }

    pub(crate) fn insert_ptrout(&self, key: PtrOutpointKey, ptrout: PtrOut) {
        self.db.pt.state.insert(key, ptrout)
    }

    pub(crate) fn insert_ptr(&self, key: Sptr, outpoint: EncodableOutpoint) {
        self.db.pt.state.insert(key, outpoint)
    }

    pub(crate) fn insert_delegation(&self, key: RegistrySptrKey, space: SLabel) {
        self.db.pt.state.insert_registry_delegation(key, space)
    }

    pub fn remove_delegation(&mut self, delegation: RegistrySptrKey) {
        self.db.pt.state.remove(delegation)
    }

    pub(crate) fn insert_commitment(&self, key: CommitmentKey, commitment: Commitment) {
        self.db.pt.state.insert_commitment(key, commitment)
    }

    pub(crate) fn insert_registry(&self, key: RegistryKey, state_root: Hash) {
        self.db.pt.state.insert_registry(key, state_root)
    }

    pub fn remove_ptr_utxo(&mut self, outpoint: OutPoint) {
        let key = OutpointKey::from_outpoint::<Sha256>(outpoint);
        self.db.pt.state.remove(key)
    }



    pub fn remove_commitment(&mut self, commitment: CommitmentKey) {
        self.db.pt.state.remove(commitment)
    }

    pub fn remove_space_utxo(&mut self, outpoint: OutPoint) {
        let key = OutpointKey::from_outpoint::<Sha256>(outpoint);
        self.db.sp.state.remove(key)
    }

    pub fn estimate_bid(&mut self, target: usize) -> anyhow::Result<u64> {
        self.db.sp.state.estimate_bid(target)
    }

    pub fn get_rollout(&mut self, target: usize) -> anyhow::Result<Vec<RolloutEntry>> {
        self.db.sp.state.get_rollout(target)
    }

    pub fn remove_space(&self, key: SpaceKey) {
        self.db.sp.state.remove(key)
    }

    pub fn prove_spaces_with_snapshot(
        &self,
        keys: &[Hash],
        snapshot_block_height: u32,
    ) -> anyhow::Result<SubTree<Sha256Hasher>> {
        self.db.sp.state.prove_with_snapshot(keys, snapshot_block_height)
    }

    pub fn prove_ptrs_with_snapshot(
        &self,
        keys: &[Hash],
        snapshot_block_height: u32,
    ) -> anyhow::Result<SubTree<Sha256Hasher>> {
        self.db.pt.state.prove_with_snapshot(keys, snapshot_block_height)
    }

    pub fn get_spaces_block(&mut self, hash: BlockHash) -> anyhow::Result<Option<BlockMetaWithHash>> {
        let idx = match &mut self.idx.sp  {
            None => return Err(anyhow!("spaces index must be enabled")),
            Some(idx) => idx
        };
        let key = BaseHash::from_slice(hash.as_ref());
        let block = idx.state.get(key).context("could not retrieve block meta")?;
        Ok(block.map(|b| {
           BlockMetaWithHash {
               hash,
               block_meta: b,
           }
        }))
    }

    pub fn get_ptrs_block(&mut self, hash: BlockHash) -> anyhow::Result<Option<PtrBlockMetaWithHash>> {
        let idx = match &mut self.idx.pt  {
            None => return Err(anyhow!("ptrs index must be enabled")),
            Some(idx) => idx
        };
        let key = BaseHash::from_slice(hash.as_ref());
        let block = idx.state.get(key).context("could not retrieve ptr block meta")?;
        Ok(block.map(|b| {
           PtrBlockMetaWithHash {
               hash,
               block_meta: b,
           }
        }))
    }

    pub fn restore<F>(&self, get_block_hash: F) -> anyhow::Result<()>
    where
        F: Fn(u32) -> anyhow::Result<BlockHash>,
    {
        let point = self.restore_spaces(get_block_hash, None)?;
        self.restore_ptrs(point)
    }

    pub fn restore_ptrs(&self, required_checkpoint: ChainAnchor) -> anyhow::Result<()> {
        let iter = self.db.pt.store.iter();

        let mut restore_point = None;
        for (idx, snapshot) in iter.enumerate() {
            let snapshot = snapshot?;
            let anchor: ChainAnchor = snapshot.metadata().try_into()?;
            if anchor == required_checkpoint {
                restore_point = Some((idx, snapshot, anchor));
                break;
            }
        }

        let (snapshot_idx, snapshot, checkpoint) =
            match restore_point {
                None => return Err(anyhow!("Could not restore ptrs to height = {}", required_checkpoint.height)),
                Some(rp) => rp,
            };

        info!("Restoring ptrs block={} height={}", checkpoint.hash, checkpoint.height);

        if let Some(ptr_idx) = self.idx.pt.as_ref() {
            let idx = ptr_idx.store
                .iter().skip(snapshot_idx).next();
            if idx.is_none() {
                return Err(anyhow!(
                        "Could not restore ptr block index due to missing snapshot"
                    ));
            }
            let idx = idx.unwrap()?;
            let idx_checkpoint: ChainAnchor = idx.metadata().try_into()?;
            if idx_checkpoint != checkpoint {
                return Err(anyhow!(
                        "ptr block index checkpoint does not match the ptr's checkpoint"
                    ));
            }
            idx.rollback()
                .context("could not rollback ptr block index snapshot")?;
        }

        snapshot
            .rollback()
            .context("could not rollback ptr snapshot")?;

        self.db.pt.state.restore(checkpoint.clone());
        if let Some(idx) = self.idx.pt.as_ref() {
            idx.state.restore(checkpoint);
        }

        Ok(())
    }

    pub fn restore_spaces<F>(&self, get_block_hash: F, restore_to_height: Option<u32>) -> anyhow::Result<ChainAnchor>
    where
        F: Fn(u32) -> anyhow::Result<BlockHash>,
    {
        let chain_iter = self.db.sp.store.iter();
        for (snapshot_index, snapshot) in chain_iter.enumerate() {
            let chain_snapshot = snapshot?;
            let chain_checkpoint: ChainAnchor = chain_snapshot.metadata().try_into()?;
            if let Some(restore_to_height) = restore_to_height {
                if restore_to_height != chain_checkpoint.height {
                    continue;
                }
            } else {
                let required_hash = get_block_hash(chain_checkpoint.height)?;
                if required_hash != chain_checkpoint.hash {
                    info!(
                        "Could not restore to block={} height={}",
                        chain_checkpoint.hash, chain_checkpoint.height
                    );
                    continue;
                }
            }

            info!(
                "Restoring block={} height={}",
                chain_checkpoint.hash, chain_checkpoint.height
            );

            if let Some(block_index) = self.idx.sp.as_ref() {
                let index_snapshot = block_index.store.iter().skip(snapshot_index).next();
                if index_snapshot.is_none() {
                    return Err(anyhow!(
                        "Could not restore block index due to missing snapshot"
                    ));
                }
                let index_snapshot = index_snapshot.unwrap()?;
                let index_checkpoint: ChainAnchor = index_snapshot.metadata().try_into()?;
                if index_checkpoint != chain_checkpoint {
                    return Err(anyhow!(
                        "block index checkpoint does not match the chain's checkpoint"
                    ));
                }
                index_snapshot
                    .rollback()
                    .context("could not rollback block index snapshot")?;
            }

            chain_snapshot
                .rollback()
                .context("could not rollback chain snapshot")?;

            self.db.sp.state.restore(chain_checkpoint.clone());
            if let Some(block_index) = self.idx.sp.as_ref() {
                block_index.state.restore(chain_checkpoint)
            }
            return Ok(chain_checkpoint);
        }

        Err(anyhow!("Unable to restore to a valid state"))
    }

    pub fn update_anchors(&self, anchors_path: &Path) -> anyhow::Result<()> {
        use std::collections::HashMap;
        use std::fs;
        use std::io;
        use crate::rpc::RootAnchor;

        info!("Updating root anchors ...");

        // Load previous anchors from file
        let previous: Vec<RootAnchor> = match fs::read(anchors_path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };

        let prev_map: HashMap<(BlockHash, u32), RootAnchor> = previous
            .into_iter()
            .map(|anchor| ((anchor.block.hash, anchor.block.height), anchor))
            .collect();

        let mut anchors = Vec::new();
        let sp_iter = self.db.sp.store.iter().take(ROOT_ANCHORS_COUNT as _);
        let mut pt_iter = self.db.pt.store.iter();

        for sp_snap in sp_iter {
            let mut sp_snap = sp_snap?;
            let anchor: ChainAnchor = sp_snap.metadata().try_into()?;

            // Check if we can get PTR snapshot at the same height
            let mut ptrs_root = None;
            if let Some(pt_snap) = pt_iter.next() {
                if let Ok(mut pt_snap) = pt_snap {
                    let pt_anchor: ChainAnchor = pt_snap.metadata().try_into()?;
                    // Only include PTR root if it matches the same block
                    if pt_anchor.height == anchor.height && pt_anchor.hash == anchor.hash {
                        ptrs_root = Some(pt_snap.compute_root()?);
                    }
                }
            }

            if let Some(existing) = prev_map.get(&(anchor.hash, anchor.height)) {
                // Preserve existing anchor but update ptrs_root if we have a new one
                let updated_anchor = RootAnchor {
                    spaces_root: existing.spaces_root,
                    ptrs_root: ptrs_root.or(existing.ptrs_root),
                    block: existing.block.clone(),
                };
                anchors.push(updated_anchor);
            } else {
                let spaces_root = sp_snap.compute_root()?;
                anchors.push(RootAnchor {
                    spaces_root,
                    ptrs_root,
                    block: anchor,
                });
            }
        }

        let updated = serde_json::to_vec_pretty(&anchors)?;
        fs::write(anchors_path, updated)?;

        if let Some(result) = anchors.first() {
            info!(
                "Latest root anchor spaces={} ptrs={} (height: {})",
                hex::encode(result.spaces_root),
                result.ptrs_root.as_ref().map(hex::encode).unwrap_or_else(|| "none".to_string()),
                result.block.height
            );
        }

        Ok(())
    }
}


fn load_sp_index(dir: &Path, genesis: ChainAnchor, tip: ChainAnchor, initial_sync: bool) -> anyhow::Result<SpLiveStore> {
    let block_db_path = dir.join("block_index.sdb");
    if !initial_sync && !block_db_path.exists() {
        return Err(anyhow::anyhow!(
                    "Block index must be enabled from the initial sync."
                ));
    }
    let block_store = SpStore::open(block_db_path)?;
    let index = SpLiveStore {
        state: block_store.begin(&genesis).expect("begin block index"),
        store: block_store,
    };
    {
        let idx_tip = index.state.tip.read().expect("index");
        if idx_tip.height != tip.height || idx_tip.hash != tip.hash {
            return Err(anyhow::anyhow!(
                        "Protocol and block index states don't match."
                    ));
        }
    }
    Ok(index)
}

fn load_pt_index(dir: &Path, genesis: ChainAnchor, tip: ChainAnchor, initial_sync: bool) -> anyhow::Result<PtrLiveStore> {
    let block_db_path = dir.join("ptrs_block_index.sdb");
    if !initial_sync && !block_db_path.exists() {
        return Err(anyhow::anyhow!(
                    "Ptr Block index must be enabled from the initial sync."
                ));
    }
    let block_store = PtrStore::open(block_db_path)?;
    let index = PtrLiveStore {
        state: block_store.begin(&genesis).expect("begin block index"),
        store: block_store,
    };
    {
        let idx_tip = index.state.tip.read().expect("index");
        if idx_tip.height != tip.height || idx_tip.hash != tip.hash {
            return Err(anyhow::anyhow!(
                        "Ptrs tip and block index states don't match."
                    ));
        }
    }
    Ok(index)
}
