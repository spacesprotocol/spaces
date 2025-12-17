pub extern crate spacedb;
pub extern crate spaces_protocol;

use std::{error::Error, fmt};

use anyhow::{anyhow, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::Error as SerdeError;
use spaces_protocol::{
    bitcoin::{Amount, Block, BlockHash, OutPoint, Txid},
    constants::{ChainAnchor, ROLLOUT_BATCH_SIZE, ROLLOUT_BLOCK_INTERVAL},
    hasher::{BidKey, KeyHasher, OutpointKey, SpaceKey},
    prepare::TxContext,
    validate::{TxChangeSet, UpdateKind, Validator},
    Bytes, Covenant, FullSpaceOut, RevokeReason, SpaceOut,
};
use spaces_ptr::{CommitmentKey, RegistryKey, RegistrySptrKey, PtrOutpointKey};
use spaces_wallet::bitcoin::{Network, Transaction};

use crate::{
    source::BitcoinRpcError,
};
use crate::source::BlockQueueResult;
use crate::store::chain::{Chain};
use crate::store::Sha256;

pub trait BlockSource {
    fn get_block_hash(&self, height: u32) -> Result<BlockHash, BitcoinRpcError>;
    fn get_block(&self, hash: &BlockHash) -> Result<Option<Block>, BitcoinRpcError>;
    fn get_median_time(&self) -> Result<u64, BitcoinRpcError>;
    fn in_mempool(&self, txid: &Txid, height: u32) -> Result<bool, BitcoinRpcError>;
    fn get_block_count(&self) -> Result<u64, BitcoinRpcError>;
    fn get_best_chain(&self, tip: Option<u32>, expected_chain: Network) -> Result<Option<ChainAnchor>, BitcoinRpcError>;
    fn get_blockchain_info(&self) -> Result<BlockchainInfo, BitcoinRpcError>;
    fn get_block_filter_by_height(&self, height: u32) -> Result<Option<BlockFilterRpc>, BitcoinRpcError>;
    fn queue_blocks(&self, heights: Vec<u32>) -> Result<(), BitcoinRpcError>;
    fn queue_filters(&self) -> Result<(), BitcoinRpcError>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockFilterRpc {
    pub hash: BlockHash,
    pub height: u32,
    #[serde(
        serialize_with = "serialize_hex",
        deserialize_with = "deserialize_hex"
    )]
    pub content: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct BlockchainInfo {
    pub chain: String,
    pub blocks: u32,
    pub headers: u32,
    #[serde(rename = "bestblockhash")]
    pub best_block_hash: BlockHash,
    #[serde(rename = "pruneheight", skip_serializing_if = "Option::is_none")]
    pub prune_height: Option<u32>,
    pub pruned: bool,
    // Light sync specific info
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filters: Option<u32>,
    #[serde(rename = "filterheaders", skip_serializing_if = "Option::is_none")]
    pub filter_headers: Option<u32>,
    #[serde(rename = "blockqueue", skip_serializing_if = "Option::is_none")]
    pub block_queue: Option<BlockQueueResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<ChainAnchor>,
    #[serde(rename = "filtersprogress", skip_serializing_if = "Option::is_none")]
    pub filters_progress: Option<f32>,
    #[serde(rename = "headerssynced", skip_serializing_if = "Option::is_none")]
    pub headers_synced: Option<bool>,
}


#[derive(Debug, Clone)]
pub struct Client {
    validator: Validator,
    ptr_validator: spaces_ptr::Validator,
    tx_data: bool,
}

/// A block structure containing validated transaction metadata
/// relevant to the Spaces protocol
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BlockMeta {
    pub height: u32,
    pub tx_meta: Vec<TxEntry>,
}

/// A block structure containing validated transaction metadata for ptrs
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct PtrBlockMeta {
    pub height: u32,
    pub tx_meta: Vec<PtrTxEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct PtrTxEntry {
    #[serde(flatten)]
    pub changeset: spaces_ptr::TxChangeSet,
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    pub tx: Option<TxData>,
}


#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct TxEntry {
    #[serde(flatten)]
    pub changeset: TxChangeSet,
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    pub tx: Option<TxData>,
}

#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct TxData {
    pub position: u32,
    pub raw: Bytes,
}

#[derive(Debug)]
pub struct SyncError {
    checkpoint: ChainAnchor,
    connect_to: (u32, BlockHash),
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Could not connect block={}, height={} to checkpoint [block={}, height={}]",
            self.connect_to.1, self.connect_to.0, self.checkpoint.hash, self.checkpoint.height
        )
    }
}

impl Error for SyncError {}

impl Client {
    pub fn new(tx_data: bool) -> Self {
        Self {
            validator: Validator::new(),
            ptr_validator: spaces_ptr::Validator::new(),
            tx_data,
        }
    }

    fn verify_block_connected(chain: &mut Chain, height: u32, block_hash: BlockHash, block: &Block) -> anyhow::Result<()> {
        // Spaces tip must connect to block
        {
            let tip = chain.tip();
            if tip.hash != block.header.prev_blockhash || tip.height + 1 != height {
                return Err(SyncError {
                    checkpoint: tip.clone(),
                    connect_to: (height, block_hash),
                }
                    .into());
            }
        }
        // Ptrs tip must connect to block
        if chain.can_scan_ptrs(height) {
            let tip = chain.ptrs_tip();
            if tip.hash != block.header.prev_blockhash || tip.height + 1 != height {
                return Err(SyncError {
                    checkpoint: tip.clone(),
                    connect_to: (height, block_hash),
                }
                    .into());
            }
        }

        Ok(())
    }

    pub(crate) fn scan_block(
        &mut self,
        chain: &mut Chain,
        height: u32,
        block_hash: BlockHash,
        block: &Block,
        index_spaces: bool,
        index_ptrs: bool,
    ) -> anyhow::Result<(Option<BlockMeta>, Option<PtrBlockMeta>)> {
        Self::verify_block_connected(chain, height, block_hash, block)?;

        let mut spaces_meta = None;
        if index_spaces {
            spaces_meta = Some(BlockMeta {
                height,
                tx_meta: vec![],
            });
        }

        let mut ptr_meta = None;
        if index_ptrs {
            ptr_meta = Some(PtrBlockMeta {
                height,
                tx_meta: vec![],
            });
        }

        // Rollouts:
        if (height - 1) % ROLLOUT_BLOCK_INTERVAL == 0 {
            let batch = Self::get_rollout_batch(ROLLOUT_BATCH_SIZE, chain)?;
            let coinbase = block
                .coinbase()
                .expect("expected a coinbase tx to be present in the block")
                .clone();
            let validated = self.validator.rollout(height, &coinbase, batch);
            if let Some(idx) = spaces_meta.as_mut() {
                idx.tx_meta.push(TxEntry {
                    changeset: validated.clone(),
                    tx: if self.tx_data {
                        Some(TxData {
                            position: 0,
                            raw: Bytes::new(
                                spaces_protocol::bitcoin::consensus::encode::serialize(&coinbase),
                            ),
                        })
                    } else {
                        None
                    },
                });
            }
            self.apply_space_tx(chain, &coinbase, validated);
        }

        for (position, tx) in block.txdata.iter().enumerate() {
            let mut spaceouts = None;
            let mut spaceouts_input_ctx = None;
            if let Some(prepared) = TxContext::from_tx::<Chain, Sha256>(chain, tx)? {
                spaceouts_input_ctx = Some(prepared.inputs.clone());
                let validated_tx = self.validator.process(height, &tx, prepared);
                spaceouts = Some(validated_tx.creates.clone());

                if let Some(idx) = spaces_meta.as_mut() {
                    idx.tx_meta.push(TxEntry {
                        changeset: validated_tx.clone(),
                        tx: if self.tx_data {
                            Some(TxData {
                                position: position as u32,
                                raw: Bytes::new(
                                    spaces_protocol::bitcoin::consensus::encode::serialize(&tx),
                                ),
                            })
                        } else {
                            None
                        },
                    });
                }
                self.apply_space_tx(chain, &tx, validated_tx);
            }

            let ptrs_ctx = if chain.can_scan_ptrs(height) {
                spaces_ptr::TxContext::from_tx::<Chain, Sha256>(
                    chain,
                    tx,
                    spaceouts_input_ctx.is_some(),
                    spaceouts.clone().unwrap_or(vec![]) , height)?
            } else {
                None
            };

            if let Some(ptrs_ctx) = ptrs_ctx {
                let spent_spaceouts = spaceouts_input_ctx.unwrap_or_default().into_iter()
                    .map(|input| input.sstxo.previous_output).collect::<Vec<_>>();
                let created_spaceouts = spaceouts.unwrap_or_default();
                let ptrs_validated = self.ptr_validator
                    .process::<Sha256>(height, &tx, ptrs_ctx, spent_spaceouts, created_spaceouts);

                if let Some(idx) = ptr_meta.as_mut() {
                    {
                        idx.tx_meta.push(PtrTxEntry {
                            changeset: ptrs_validated.clone(),
                            tx: if self.tx_data {
                                Some(TxData {
                                    position: position as u32,
                                    raw: Bytes::new(
                                        spaces_protocol::bitcoin::consensus::encode::serialize(&tx),
                                    ),
                                })
                            } else {
                                None
                            },
                        });
                    }
                }
                self.apply_ptrs_tx(chain, tx, ptrs_validated);
            }
        }

        chain.update_spaces_tip(height, block_hash);
        if chain.can_scan_ptrs(height) {
            chain.update_ptrs_tip(height, block_hash);
        }

        Ok((spaces_meta, ptr_meta))
    }

    fn apply_ptrs_tx(&self, state: &mut Chain, tx: &Transaction, changeset: spaces_ptr::TxChangeSet) {
        // Remove spends
        for n in changeset.spends.into_iter() {
            let previous = tx.input[n].previous_output;
            state.remove_ptr_utxo(previous);
        }

        // Remove revoked delegations
        for revoked in changeset.revoked_delegations {
            let sptr_key = RegistrySptrKey::from_sptr::<Sha256>(revoked.sptr);
            state.remove_delegation(sptr_key);
        }
        // Remove revoked commitments
        for revoked in changeset.revoked_commitments {
            let commitment_key = CommitmentKey::new::<Sha256>(&revoked.space, revoked.commitment.state_root);
            state.remove_commitment(commitment_key);
        }

        // Create new delegations
        for delegation in changeset.new_delegations {
            let sptr_key = RegistrySptrKey::from_sptr::<Sha256>(delegation.sptr);
            state.insert_delegation(sptr_key, delegation.space);
        }

        // Insert new commitments
        for commitment_info in changeset.commitments {
            let commitment_key = CommitmentKey::new::<Sha256>(&commitment_info.space, commitment_info.commitment.state_root);
            let registry_key = RegistryKey::from_slabel::<Sha256>(&commitment_info.space);

            // Points space -> commitments tip
            state.insert_registry(registry_key, commitment_info.commitment.state_root);
            // commitment key = HASH(HASH(space) || state root) -> commitment
            state.insert_commitment(commitment_key, commitment_info.commitment);

        }

        // Create ptrs
        for create in changeset.creates.into_iter() {
            let outpoint = OutPoint {
                txid: changeset.txid,
                vout: create.n as u32,
            };

            // Ptr => Outpoint
            if let Some(ptr) = create.sptr.as_ref() {
                state.insert_ptr(ptr.id, outpoint.into());
            }

            // Outpoint => PtrOut
            let outpoint_key = PtrOutpointKey::from_outpoint::<Sha256>(outpoint);
            state.insert_ptrout(outpoint_key, create);
        }
    }

    fn apply_space_tx(&self, state: &mut Chain, tx: &Transaction, changeset: TxChangeSet) {
        // Remove spends
        for spend in changeset.spends.into_iter() {
            let previous = tx.input[spend.n].previous_output;
            state.remove_space_utxo(previous);
        }

        // Apply outputs
        for create in changeset.creates.into_iter() {
            if let Some(space) = create.space.as_ref() {
                assert!(
                    !matches!(space.covenant, Covenant::Bid { .. }),
                    "bid unexpected"
                );
            }
            let outpoint = OutPoint {
                txid: changeset.txid,
                vout: create.n as u32,
            };

            // Space => Outpoint
            if let Some(space) = create.space.as_ref() {
                let space_key = SpaceKey::from(Sha256::hash(space.name.as_ref()));
                state.insert_space(space_key, outpoint.into());
            }
            // Outpoint => SpaceOut
            let outpoint_key = OutpointKey::from_outpoint::<Sha256>(outpoint);
            state.insert_spaceout(outpoint_key, create);
        }

        // Apply meta outputs
        for update in changeset.updates {
            match update.kind {
                UpdateKind::Revoke(params) => {
                    match params {
                        RevokeReason::BidPsbt(_)
                        | RevokeReason::PrematureClaim
                        | RevokeReason::BadSpend => {
                            // Since these are caused by spends
                            // Outpoint -> Spaceout mapping is already removed,
                            let space = update.output.spaceout.space.unwrap();
                            let base_hash = Sha256::hash(space.name.as_ref());

                            // Remove Space -> Outpoint
                            let space_key = SpaceKey::from(base_hash);
                            state.remove_space(space_key);

                            // Remove any bids from pre-auction pool
                            match space.covenant {
                                Covenant::Bid {
                                    total_burned,
                                    claim_height,
                                    ..
                                } => {
                                    if claim_height.is_none() {
                                        let bid_key = BidKey::from_bid(total_burned, base_hash);
                                        state.remove_bid(bid_key)
                                    }
                                }
                                _ => {}
                            }
                        }
                        RevokeReason::Expired => {
                            // Space => Outpoint mapping will be removed
                            // since this type of revocation only happens when an
                            // expired space is being re-opened for auction.
                            // No bids here so only remove Outpoint -> Spaceout
                            state.remove_space_utxo(update.output.outpoint());
                        }
                    }
                }
                UpdateKind::Rollout(rollout) => {
                    let base_hash = Sha256::hash(
                        update
                            .output
                            .spaceout
                            .space
                            .as_ref()
                            .expect("a space in rollout")
                            .name
                            .as_ref(),
                    );
                    let bid_key = BidKey::from_bid(rollout.priority, base_hash);

                    let outpoint_key =
                        OutpointKey::from_outpoint::<Sha256>(update.output.outpoint());

                    state.remove_bid(bid_key);
                    state.insert_spaceout(outpoint_key, update.output.spaceout);
                }
                UpdateKind::Bid => {
                    // Only bids are expected in meta outputs
                    let base_hash = Sha256::hash(
                        update
                            .output
                            .spaceout
                            .space
                            .as_ref()
                            .expect("space")
                            .name
                            .as_ref(),
                    );

                    let (bid_value, previous_bid) = unwrap_bid_value(&update.output.spaceout);

                    let bid_hash = BidKey::from_bid(bid_value, base_hash);
                    let space_key = SpaceKey::from(base_hash);

                    match update
                        .output
                        .spaceout
                        .space
                        .as_ref()
                        .expect("space")
                        .covenant
                    {
                        Covenant::Bid { claim_height, .. } => {
                            if claim_height.is_none() {
                                let prev_bid_hash = BidKey::from_bid(previous_bid, base_hash);
                                state.update_bid(Some(prev_bid_hash), bid_hash, space_key);
                            }
                        }
                        _ => panic!("expected bid"),
                    }

                    let carried_outpoint = update.output.outpoint();
                    state.insert_space(space_key, carried_outpoint.into());

                    let outpoint_key = OutpointKey::from_outpoint::<Sha256>(carried_outpoint);
                    state.insert_spaceout(outpoint_key, update.output.spaceout);
                }
            }
        }
    }

    fn get_rollout_batch(size: usize, chain: &mut Chain) -> Result<Vec<FullSpaceOut>> {
        let (iter, snapshot) = chain.rollout_iter()?;
        assert_eq!(
            snapshot.metadata(),
            chain.spaces_tip_meatadata()?,
            "rollout snapshots don't match"
        );
        assert!(!chain.is_dirty(), "rollout must begin on clean state");

        let mut spaceouts = Vec::with_capacity(size);

        for element in iter.take(size) {
            let (_, raw_hash) = element?;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(raw_hash.as_slice());

            let space_hash = SpaceKey::from_raw(hash)?;
            let full = chain.get_space_info(&space_hash)?;

            if let Some(full) = full {
                match full.spaceout.space.as_ref().unwrap().covenant {
                    Covenant::Bid { .. } => {}
                    _ => return Err(anyhow!("expected spaceouts with bid covenants")),
                }
                spaceouts.push(full);
            }
        }

        Ok(spaceouts)
    }
}

fn unwrap_bid_value(spaceout: &SpaceOut) -> (Amount, Amount) {
    if let Covenant::Bid {
        total_burned,
        burn_increment: value,
        ..
    } = spaceout
        .space
        .as_ref()
        .expect("space associated with this spaceout")
        .covenant
    {
        return (total_burned, total_burned - value);
    }
    panic!("expected a bid covenant")
}

fn serialize_hex<S>(bytes: &Vec<u8>, s: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(hex::encode(bytes).as_str())
}

fn deserialize_hex<'de, D>(d: D) -> std::result::Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = <String as Deserialize>::deserialize(d)?;
    hex::decode(s).map_err(D::Error::custom)
}
