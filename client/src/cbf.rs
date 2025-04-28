use std::collections::{BTreeMap, HashSet, VecDeque};
use std::time::Duration;
use anyhow::anyhow;
use log::info;
use tokio::time::Instant;
use spaces_protocol::bitcoin::BlockHash;
use spaces_protocol::constants::ChainAnchor;
use spaces_wallet::bdk_wallet::chain::{local_chain, BlockId, ConfirmationBlockTime, IndexedTxGraph, TxUpdate};
use spaces_wallet::bdk_wallet::chain::keychain_txout::KeychainTxOutIndex;
use spaces_wallet::bdk_wallet::{KeychainKind, Update};
use spaces_wallet::bitcoin::bip158::BlockFilter;
use spaces_wallet::bitcoin::ScriptBuf;
use spaces_wallet::SpacesWallet;
use crate::client::{BlockSource, BlockchainInfo};
use crate::source::BitcoinBlockSource;

pub struct CompactFilterSync {
    graph: IndexedTxGraph<ConfirmationBlockTime, KeychainTxOutIndex<KeychainKind>>,
    chain: local_chain::LocalChain,
    chain_changeset: BTreeMap<u32, Option<BlockHash>>,
    scripts: HashSet<ScriptBuf>,
    last_peek_index: u32,
    initial_tip: ChainAnchor,
    queued_blocks: BTreeMap<u32, BlockHash>,
    queued_filters: VecDeque<u32>,
    filters_tip: u32,
    wait: Option<Instant>,
    state: SyncState,
}

enum SyncState {
    SyncChecks,
    LoadFilterRange(BlockchainInfo),
    ProcessFilters,
    QueueBlocks,
    WaitForBlocks,
    ProcessBlocks,
    ApplyUpdate,
    Synced
}

impl CompactFilterSync {
    pub fn new(wallet: &SpacesWallet) -> Self {
        let initial_tip = {
            let tip = wallet.local_chain().tip();
            ChainAnchor { height: tip.height(), hash: tip.hash() }
        };

        let mut cbf = Self {
            graph: IndexedTxGraph::new(wallet.spk_index().clone()),
            chain: wallet.local_chain().clone(),
            chain_changeset: BTreeMap::new(),
            scripts: HashSet::new(),
            last_peek_index: 0,
            initial_tip,
            queued_blocks: BTreeMap::new(),
            queued_filters: Default::default(),
            filters_tip: 0,
            wait: None,
            state: SyncState::SyncChecks,
        };
        cbf.load_scripts(wallet);
        cbf
    }

    fn load_scripts(&mut self, wallet: &SpacesWallet) {
        let lookahead = wallet.spk_index().lookahead();
        let mut max_idx = 0;
        for keychain in [KeychainKind::External, KeychainKind::Internal] {
            let last_revealed = wallet
                .spk_index()
                .last_revealed_index(keychain)
                .unwrap_or(0);
            let chain_limit = last_revealed + lookahead;
            for idx in 0..=chain_limit {
                let script = wallet.peek_address(keychain, idx).script_pubkey();
                self.scripts.insert(script);
            }
            max_idx = max_idx.max(chain_limit);
        }
        self.last_peek_index = max_idx;
    }

    /// Expand scripts by an additional fixed window beyond the last peek
    fn load_more_scripts(&mut self, wallet: &SpacesWallet) {
        let end = self.last_peek_index + 10;
        for keychain in [KeychainKind::External, KeychainKind::Internal] {
            for idx in self.last_peek_index..=end {
                let script = wallet.peek_address(keychain, idx).script_pubkey();
                self.scripts.insert(script);
            }
        }
        self.last_peek_index = end;
    }

    pub fn synced(&self) -> bool {
        matches!(self.state, SyncState::Synced)
    }

    pub fn sync_next(
        &mut self,
        wallet: &mut SpacesWallet,
        source: &BitcoinBlockSource,
    ) -> anyhow::Result<()> {
        if self.wait.is_some_and(|w| w.elapsed() < Duration::from_secs(10)) {
            return Ok(());
        }
        self.wait = None;

        match &self.state {
            SyncState::SyncChecks => {
                let info = source.get_blockchain_info()?;
                if info.headers != info.blocks {
                    info!("Source still syncing, retrying...");
                    self.wait = Some(Instant::now());
                    return Ok(());
                }
                if info.filters != info.filter_headers {
                    info!("Filters syncing, retrying...");
                    self.wait = Some(Instant::now());
                    return Ok(());
                }
                // if wallet already past filter headers, we're done
                if let Some(filter_headers) = info.filter_headers {
                    if self.initial_tip.height >= filter_headers {
                        info!("wallet({}): tip {} >= filters {}, cbf done", wallet.name(), self.initial_tip.height, filter_headers);
                        self.state = SyncState::Synced;
                        return Ok(());
                    }
                }
                self.state = SyncState::LoadFilterRange(info);
            }
            SyncState::LoadFilterRange(info) => {
                let checkpoint = info
                    .checkpoint
                    .ok_or_else(|| anyhow!("filter sync: checkpoint missing"))?;
                if self.initial_tip.height < checkpoint.height {
                    return Err(anyhow!(
                        "Wallet birthday {} < checkpoint {}", self.initial_tip.height, checkpoint.height
                    ));
                }

                let start = self.initial_tip.height;
                let end = info
                    .prune_height
                    .ok_or(anyhow!("Prune height missing"))?;
                let available_filters = info.filters.ok_or(anyhow!("Filters missing"))?;
                if end > available_filters {
                    return Err(anyhow!("Prune height {} > {} available filters", end, available_filters));
                }

                if start >= end {
                    return Ok(());
                }
                for height in start..=end {
                    self.queued_filters.push_back(height);
                }
                self.filters_tip = end;
                self.state = SyncState::ProcessFilters;
            }
            SyncState::ProcessFilters => {
                let height = match self.queued_filters.pop_front() {
                    None => {
                        self.state = SyncState::QueueBlocks;
                        return Ok(())
                    },
                    Some(f) => f,
                };
                let idx_filter = source.get_block_filter_by_height(height)?;
                let idx_filter = idx_filter
                    .ok_or_else(|| anyhow!("filter sync: block filter missing {}", height))?;
                let filter = BlockFilter::new(&idx_filter.content);
                if filter.match_any(&idx_filter.hash, self.scripts.iter().map(|s| s.as_bytes()))? {
                    self.queued_blocks.insert(height, idx_filter.hash);
                    self.load_more_scripts(wallet);
                    info!("wallet({}) processed block filter {} - match found", wallet.name(), height);
                } else {
                    info!("wallet({}) processed block filter {} - no match", wallet.name(), height);
                }
            }
            SyncState::QueueBlocks => {
                if !self.queued_blocks.is_empty() {
                    let heights: Vec<u32> = self.queued_blocks.keys().copied().collect();
                    info!("wallet({}): queueing {} blocks", wallet.name(), heights.len());
                    source.queue_blocks(heights)?;
                }
                self.state = SyncState::WaitForBlocks;
            }
            SyncState::WaitForBlocks => {
                let info = source.get_blockchain_info()?;
                let status = info
                    .block_queue
                    .as_ref()
                    .ok_or_else(|| anyhow!("filter sync: block queue missing"))?;

                if status.pending > 0 {
                    info!("wallet({}): waiting for {} pending blocks", wallet.name(), status.pending);
                    self.wait = Some(Instant::now());
                    return Ok(());
                }

                if status.completed < self.queued_blocks.len() as u32 {
                    return Err(anyhow!(
                        "incomplete downloads: {} of {}", status.completed, self.queued_blocks.len()
                    ));
                }
                self.state = SyncState::ProcessBlocks;
            }
            SyncState::ProcessBlocks => {
                let (height, hash) = match self.queued_blocks.pop_first() {
                    None => {
                        self.state = SyncState::Synced;
                        return Ok(());
                    }
                    Some(f) => f,
                };
                info!("wallet({}): processing block {} {}", wallet.name(), height, hash);
                let block = source.get_block(&hash)?
                    .ok_or(anyhow!("block {} {} not found", height, hash))?;
                self.chain_changeset.insert(height, Some(hash));
                let _ = self.graph.apply_block_relevant(&block, height);
                self.state = SyncState::ApplyUpdate;
            }
            SyncState::ApplyUpdate => {
                info!("wallet({}): updating wallet tip to {}", wallet.name(), self.filters_tip);
                let filters_anchor = BlockId {
                    height: self.filters_tip,
                    hash: source.get_block_hash(self.filters_tip)?,
                };

                let update = self.get_scan_response();
                wallet.apply_update(update)?;
                wallet.insert_checkpoint(filters_anchor)?;
                info!("wallet({}): compact filter sync portion complete at {}", wallet.name(), self.filters_tip);
                self.state = SyncState::Synced;
            }
            SyncState::Synced => {}
        }
        Ok(())
    }

    // based on https://github.com/bitcoindevkit/bdk-kyoto/blob/master/src/lib.rs#L137
    fn get_scan_response(&mut self) -> Update {
        let changes = std::mem::take(&mut self.chain_changeset);
        self.chain
            .apply_changeset(&local_chain::ChangeSet::from(changes))
            .expect("initialized from genesis");
        let tx_update = TxUpdate::from(self.graph.graph().clone());
        let graph = std::mem::take(&mut self.graph);
        let last_indices = graph.index.last_used_indices();
        self.graph = IndexedTxGraph::new(graph.index);
        Update {
            tx_update,
            last_active_indices: last_indices,
            chain: Some(self.chain.tip()),
        }
    }
}
