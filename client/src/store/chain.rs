use crate::client::{BlockMeta, NumBlockMeta};
use crate::rpc::{BlockMetaWithHash, NumBlockMetaWithHash};
use crate::store::index::SqliteIndex;
use crate::store::ptrs::{NumChainState, NumLiveStore, NumStore};
use crate::store::spaces::{
    RolloutEntry, RolloutIterator, SpLiveStore, SpStore, SpStoreUtils, SpacesState,
};
use crate::store::{EncodableOutpoint, ReadTx, Sha256};
use anyhow::{Context, anyhow};
use log::info;
use spacedb::Hash;
use spaces_nums::num_id::NumId;
use spaces_nums::snumeric::SNumeric;
use spaces_nums::{Commitment, CommitmentKey, CommitmentTipKey, DelegatorKey, FullNumOut, NumOut, NumOutpointKey, NumSource, RebindData, RebindKey, RootAnchor};
use spaces_protocol::bitcoin::hashes::Hash as HashUtil;
use spaces_protocol::bitcoin::{BlockHash, OutPoint};
use spaces_protocol::constants::ChainAnchor;
use spaces_protocol::hasher::{BidKey, OutpointKey, SpaceKey};
use spaces_protocol::prepare::SpacesSource;
use spaces_protocol::slabel::SLabel;
use spaces_protocol::{FullSpaceOut, SpaceOut};
use spaces_wallet::bitcoin::Network;
use std::path::Path;
use std::sync::Arc;

pub const ROOT_ANCHORS_COUNT: u32 = 120;
pub const COMMIT_BLOCK_INTERVAL: u32 = 36;
/// ~1 week lookback for cached snapshot (7 * 144 = 1008 blocks)
pub const CACHED_SNAPSHOT_LOOKBACK: u32 = 1008;

// https://internals.rust-lang.org/t/nicer-static-assertions/15986
macro_rules! const_assert {
    ($($tt:tt)*) => {
        const _: () = assert!($($tt)*);
    }
}

const_assert!(
    spaces_protocol::constants::ROLLOUT_BLOCK_INTERVAL.is_multiple_of(COMMIT_BLOCK_INTERVAL),
    "commit and rollout intervals must be aligned"
);

pub struct CachedSnapshot {
    pub height: u32,
    pub spaces: ReadTx,
    pub nums: ReadTx,
}

pub struct Chain {
    db: LiveStore,
    idx: LiveIndex,
    nums_genesis: ChainAnchor,
    cached_snapshot: Option<CachedSnapshot>,
}

impl Clone for Chain {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            idx: self.idx.clone(),
            nums_genesis: self.nums_genesis,
            cached_snapshot: None,
        }
    }
}

#[derive(Clone)]
pub struct LiveStore {
    sp: SpLiveStore,
    num: NumLiveStore,
}

#[derive(Clone)]
pub struct LiveIndex {
    block_index: bool,
    db: Arc<SqliteIndex>,
}

impl SpacesSource for Chain {
    fn get_space_outpoint(
        &mut self,
        space_hash: &SpaceKey,
    ) -> spaces_protocol::errors::Result<Option<OutPoint>> {
        self.db.sp.state.get_space_outpoint(space_hash)
    }

    fn get_spaceout(
        &mut self,
        outpoint: &OutPoint,
    ) -> spaces_protocol::errors::Result<Option<SpaceOut>> {
        self.db.sp.state.get_spaceout(outpoint)
    }
}

impl NumSource for Chain {
    fn get_num_outpoint_by_id(
        &mut self,
        space_hash: &NumId,
    ) -> spaces_protocol::errors::Result<Option<OutPoint>> {
        self.db.num.state.get_num_outpoint_by_id(space_hash)
    }

    fn get_commitment(
        &mut self,
        key: &CommitmentKey,
    ) -> spaces_protocol::errors::Result<Option<Commitment>> {
        self.db.num.state.get_commitment(key)
    }

    fn get_delegator(
        &mut self,
        key: &DelegatorKey,
    ) -> spaces_protocol::errors::Result<Option<SLabel>> {
        self.db.num.state.get_delegator(key)
    }

    fn get_commitments_tip(
        &mut self,
        key: &CommitmentTipKey,
    ) -> spaces_protocol::errors::Result<Option<Hash>> {
        self.db.num.state.get_commitments_tip(key)
    }

    fn get_numout(
        &mut self,
        outpoint: &OutPoint,
    ) -> spaces_protocol::errors::Result<Option<NumOut>> {
        self.db.num.state.get_numout(outpoint)
    }

    fn get_num_id(&mut self, snum: &SNumeric) -> spaces_protocol::errors::Result<Option<NumId>> {
        self.idx
            .db
            .get_snumeric(snum)
            .map_err(|e| spaces_protocol::errors::Error::IO(format!("get_num_id: {}", e)))
    }

    fn get_num_rebind(
        &mut self,
        key: &RebindKey,
    ) -> spaces_protocol::errors::Result<Option<RebindData>> {
        self.db.num.state.get_num_rebind(key)
    }
}

impl Chain {
    pub fn get_space_info(
        &mut self,
        space_hash: &SpaceKey,
    ) -> anyhow::Result<Option<FullSpaceOut>> {
        self.db.sp.state.get_space_info(space_hash)
    }

    pub fn get_num_info(&mut self, key: &NumId) -> anyhow::Result<Option<FullNumOut>> {
        self.db.num.state.get_num_info(key)
    }

    pub fn snapshot_at(&mut self, target_height: u32) -> anyhow::Result<&mut CachedSnapshot> {
        if self
            .cached_snapshot
            .as_ref()
            .is_some_and(|c| c.height > self.tip().height)
        {
            self.cached_snapshot = None;
        }

        if self
            .cached_snapshot
            .as_ref()
            .is_none_or(|c| c.height != target_height)
        {
            let spaces = self.db.sp.state.read_at(target_height)?;
            let ptrs = self.db.num.state.read_at(target_height)?;
            self.cached_snapshot = Some(CachedSnapshot {
                height: target_height,
                spaces,
                nums: ptrs,
            });
        }

        Ok(self.cached_snapshot.as_mut().unwrap())
    }

    pub fn load(
        _network: Network,
        genesis: ChainAnchor,
        nums_genesis: ChainAnchor,
        dir: &Path,
        block_index: bool,
        index_hashes: bool,
        cache_size: Option<usize>,
    ) -> anyhow::Result<Self> {
        let proto_db_path = dir.join("root.sdb");
        let nums_db_path = dir.join("nums.sdb");
        let initial_num_sync = !nums_db_path.exists();

        let sp_store = SpStore::open(proto_db_path, index_hashes, cache_size)?;
        let sp = SpLiveStore {
            state: sp_store.begin(&genesis)?,
            store: sp_store,
        };

        let num_store = NumStore::open(nums_db_path, index_hashes, cache_size)?;
        let num = NumLiveStore {
            state: num_store.begin(&nums_genesis)?,
            store: num_store,
        };

        let sqlite_index = SqliteIndex::open(dir)?;

        let chain = Chain {
            db: LiveStore { sp, num },
            idx: LiveIndex {
                block_index,
                db: Arc::new(sqlite_index),
            },
            nums_genesis,
            cached_snapshot: None,
        };

        // If spaces synced past the ptrs point, reset the tip
        if initial_num_sync {
            let sp_tip = *chain.db.sp.state.tip.read().expect("tip");
            if sp_tip.height > nums_genesis.height {
                info!(
                    "spaces tip = {} > nums genesis = {} - rescanning to index nums",
                    sp_tip.height, nums_genesis.height
                );
                chain.restore_spaces(
                    |_| Ok(BlockHash::from_slice(&[0u8; 32]).expect("hash")),
                    Some(nums_genesis.height),
                )?;
            }
        }

        Ok(chain)
    }

    pub fn tip(&self) -> ChainAnchor {
        *self.db.sp.state.tip.read().expect("read")
    }

    pub fn apply_block_to_spaces_index(
        &self,
        block_hash: BlockHash,
        block: BlockMeta,
    ) -> anyhow::Result<()> {
        if self.idx.block_index {
            self.idx
                .db
                .insert_spaces_block(block_hash, block.height, block);
        }
        Ok(())
    }

    pub fn apply_block_to_ptrs_index(
        &self,
        block_hash: BlockHash,
        block: NumBlockMeta,
    ) -> anyhow::Result<()> {
        if self.idx.block_index {
            self.idx
                .db
                .insert_nums_block(block_hash, block.height, block);
        }
        Ok(())
    }

    pub fn maybe_commit(&self, checkpoint: ChainAnchor) -> anyhow::Result<bool> {
        if !checkpoint.height.is_multiple_of(COMMIT_BLOCK_INTERVAL) {
            return Ok(false);
        }

        let spaces_batch = self.db.sp.store.write().expect("write handle");
        let ptrs_batch = self.db.num.store.write().expect("write handle");

        self.db.sp.state.commit(checkpoint, spaces_batch)?;
        self.db.num.state.commit(checkpoint, ptrs_batch)?;

        self.idx.db.commit()?;

        Ok(true)
    }

    pub fn spaces_mut(&mut self) -> &mut SpLiveStore {
        &mut self.db.sp
    }

    pub fn nums_mut(&mut self) -> &mut NumLiveStore {
        &mut self.db.num
    }

    pub fn has_spaces_index(&self) -> bool {
        self.idx.block_index
    }

    pub fn has_nums_index(&self) -> bool {
        self.idx.block_index
    }

    pub fn rollout_iter(&self) -> anyhow::Result<(RolloutIterator, ReadTx)> {
        self.db.sp.store.rollout_iter()
    }

    pub fn is_dirty(&self) -> bool {
        self.db.sp.state.is_dirty() || self.db.num.state.is_dirty()
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

    pub fn nums_tip(&self) -> ChainAnchor {
        *self.db.num.state.tip.read().expect("ptrs tip")
    }

    pub fn can_scan_nums(&self, height: u32) -> bool {
        height > self.nums_genesis.height
    }

    pub fn update_nums_tip(&self, height: u32, block_hash: BlockHash) {
        let mut tip = self.db.num.state.tip.write().expect("write tip");
        tip.height = height;
        tip.hash = block_hash;
    }

    pub fn update_spaces_tip(&self, height: u32, block_hash: BlockHash) {
        let mut tip = self.db.sp.state.tip.write().expect("write tip");
        tip.height = height;
        tip.hash = block_hash;
    }

    pub(crate) fn insert_numout(&self, key: NumOutpointKey, ptrout: NumOut) {
        self.db.num.state.insert(key, ptrout)
    }

    pub(crate) fn insert_num_outpoint(&self, key: NumId, outpoint: OutPoint) {
        self.db.num.state.insert_num_outpoint(key, outpoint.into())
    }

    pub(crate) fn insert_rebind(&self, key: RebindKey, rebind: RebindData) {
        self.db.num.state.insert_rebind(key, rebind)
    }

    pub(crate) fn remove_rebind(&self, key: RebindKey) {
        self.db.num.state.remove_rebind(key)
    }

    pub(crate) fn insert_num(&self, snum: &SNumeric, id: NumId) {
        self.idx.db.insert_snumeric(snum, id)
    }

    pub(crate) fn insert_delegator(&self, key: DelegatorKey, space: SLabel) {
        self.db.num.state.insert_delegator(key, space)
    }

    pub fn remove_delegator(&mut self, key: DelegatorKey) {
        self.db.num.state.remove(key)
    }

    pub(crate) fn insert_commitment(&self, key: CommitmentKey, commitment: Commitment) {
        self.db.num.state.insert_commitment(key, commitment)
    }

    pub(crate) fn insert_commitment_tip(&self, key: CommitmentTipKey, state_root: Hash) {
        self.db.num.state.insert_commitment_tip(key, state_root)
    }

    pub(crate) fn remove_commitment_tip(&self, key: CommitmentTipKey) {
        self.db.num.state.remove_commitment_tip(key)
    }

    pub fn remove_num_utxo(&mut self, outpoint: OutPoint) {
        let key = NumOutpointKey::from_outpoint::<Sha256>(outpoint);
        self.db.num.state.remove(key)
    }

    pub fn remove_commitment(&mut self, commitment: CommitmentKey) {
        self.db.num.state.remove(commitment)
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

    pub fn get_spaces_block(&self, hash: BlockHash) -> anyhow::Result<Option<BlockMetaWithHash>> {
        if !self.idx.block_index {
            return Err(anyhow!("spaces index must be enabled"));
        }
        let block = self
            .idx
            .db
            .get_spaces_block(&hash)
            .context("could not retrieve block meta")?;
        Ok(block.map(|b| BlockMetaWithHash {
            hash,
            block_meta: b,
        }))
    }

    pub fn get_nums_block(&self, hash: BlockHash) -> anyhow::Result<Option<NumBlockMetaWithHash>> {
        if !self.idx.block_index {
            return Err(anyhow!("ptrs index must be enabled"));
        }
        let block = self
            .idx
            .db
            .get_nums_block(&hash)
            .context("could not retrieve num block meta")?;
        Ok(block.map(|b| NumBlockMetaWithHash {
            hash,
            block_meta: b,
        }))
    }

    pub fn restore<F>(&self, get_block_hash: F) -> anyhow::Result<()>
    where
        F: Fn(u32) -> anyhow::Result<BlockHash>,
    {
        let point = self.restore_spaces(get_block_hash, None)?;
        self.restore_nums(point)
    }

    pub fn restore_nums(&self, required_checkpoint: ChainAnchor) -> anyhow::Result<()> {
        let iter = self.db.num.store.iter();

        let mut restore_point = None;
        for snapshot in iter {
            let snapshot = snapshot?;
            let anchor: ChainAnchor = snapshot.metadata().try_into()?;
            if anchor == required_checkpoint {
                restore_point = Some(snapshot);
                break;
            }
        }

        let snapshot = match restore_point {
            None => {
                return Err(anyhow!(
                    "Could not restore nums to height = {}",
                    required_checkpoint.height
                ));
            }
            Some(s) => s,
        };

        info!(
            "Restoring nums block={} height={}",
            required_checkpoint.hash, required_checkpoint.height
        );

        snapshot
            .rollback()
            .context("could not rollback num snapshot")?;

        self.db.num.state.restore(required_checkpoint);

        Ok(())
    }

    pub fn restore_spaces<F>(
        &self,
        get_block_hash: F,
        nums_genesis_height: Option<u32>,
    ) -> anyhow::Result<ChainAnchor>
    where
        F: Fn(u32) -> anyhow::Result<BlockHash>,
    {
        let chain_iter = self.db.sp.store.iter();
        for snapshot in chain_iter {
            let chain_snapshot = snapshot?;
            let chain_checkpoint: ChainAnchor = chain_snapshot.metadata().try_into()?;
            if let Some(max_height) = nums_genesis_height {
                if chain_checkpoint.height > max_height {
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

            chain_snapshot
                .rollback()
                .context("could not rollback chain snapshot")?;

            self.db.sp.state.restore(chain_checkpoint);
            self.idx.db.restore(chain_checkpoint.height)?;
            return Ok(chain_checkpoint);
        }

        Err(anyhow!("Unable to restore to a valid state"))
    }

    pub fn update_anchors(&self, anchors_path: &Path, num_anchors: u32) -> anyhow::Result<()> {
        use std::collections::HashMap;
        use std::fs;
        use std::io;

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
        let sp_iter = self.db.sp.store.iter().take(num_anchors as _);
        let mut pt_iter = self.db.num.store.iter();

        for sp_snap in sp_iter {
            let mut sp_snap = sp_snap?;
            let anchor: ChainAnchor = sp_snap.metadata().try_into()?;

            // Check if we can get PTR snapshot at the same height
            let mut ptrs_root = None;
            if let Some(Ok(mut pt_snap)) = pt_iter.next() {
                let pt_anchor: ChainAnchor = pt_snap.metadata().try_into()?;
                // Only include PTR root if it matches the same block
                if pt_anchor.height == anchor.height && pt_anchor.hash == anchor.hash {
                    ptrs_root = Some(pt_snap.compute_root()?);
                }
            }

            if let Some(existing) = prev_map.get(&(anchor.hash, anchor.height)) {
                // Preserve existing anchor but update ptrs_root if we have a new one
                let updated_anchor = RootAnchor {
                    spaces_root: existing.spaces_root,
                    nums_root: ptrs_root.or(existing.nums_root),
                    block: existing.block,
                };
                anchors.push(updated_anchor);
            } else {
                let spaces_root = sp_snap.compute_root()?;
                anchors.push(RootAnchor {
                    spaces_root,
                    nums_root: ptrs_root,
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
                result
                    .nums_root
                    .as_ref()
                    .map(hex::encode)
                    .unwrap_or_else(|| "none".to_string()),
                result.block.height
            );
        }

        Ok(())
    }
}
