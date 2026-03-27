use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{anyhow, Context};
use log::{info, warn};
use spaces_protocol::{
    bitcoin::{Block, BlockHash},
    constants::ChainAnchor,
    hasher::BaseHash,
};
use tokio::sync::broadcast;

pub const ROOT_ANCHORS_COUNT: u32 = 120;

use crate::{
    client::{BlockMeta, BlockSource, Client},
    config::ExtendedNetwork,
    source::{
        BitcoinBlockSource, BitcoinRpc, BitcoinRpcError, BlockEvent, BlockFetchError, BlockFetcher,
    },
    std_wait,
    store::LiveStore,
};

// https://internals.rust-lang.org/t/nicer-static-assertions/15986
macro_rules! const_assert {
    ($($tt:tt)*) => {
        const _: () = assert!($($tt)*);
    }
}

pub const COMMIT_BLOCK_INTERVAL: u32 = 36;
const_assert!(
    spaces_protocol::constants::ROLLOUT_BLOCK_INTERVAL % COMMIT_BLOCK_INTERVAL == 0,
    "commit and rollout intervals must be aligned"
);

pub struct Spaced {
    pub network: ExtendedNetwork,
    pub chain: LiveStore,
    pub block_index: Option<LiveStore>,
    pub block_index_full: bool,
    pub rpc: BitcoinRpc,
    pub data_dir: PathBuf,
    pub bind: Vec<SocketAddr>,
    pub auth_token: String,
    pub num_workers: usize,
    pub anchors_path: Option<PathBuf>,
    pub synced: bool,
    pub cbf: bool,
}

impl Spaced {
    // Restores state to a valid checkpoint
    pub fn restore(&self, source: &BitcoinBlockSource) -> anyhow::Result<()> {
        let chain_iter = self.chain.store.iter();
        for (snapshot_index, snapshot) in chain_iter.enumerate() {
            let chain_snapshot = snapshot?;
            let chain_checkpoint: ChainAnchor = chain_snapshot.metadata().try_into()?;
            let required_hash = source.get_block_hash(chain_checkpoint.height)?;

            if required_hash != chain_checkpoint.hash {
                info!(
                    "Could not restore to block={} height={}",
                    chain_checkpoint.hash, chain_checkpoint.height
                );
                continue;
            }

            info!(
                "Restoring block={} height={}",
                chain_checkpoint.hash, chain_checkpoint.height
            );

            if let Some(block_index) = self.block_index.as_ref() {
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

            self.chain.state.restore(chain_checkpoint.clone());

            if let Some(block_index) = self.block_index.as_ref() {
                block_index.state.restore(chain_checkpoint)
            }
            return Ok(());
        }

        Err(anyhow!("Unable to restore to a valid state"))
    }

    pub fn save_block(
        store: LiveStore,
        block_hash: BlockHash,
        block: BlockMeta,
    ) -> anyhow::Result<()> {
        store
            .state
            .insert(BaseHash::from_slice(block_hash.as_ref()), block);
        Ok(())
    }

    pub fn update_anchors(&self) -> anyhow::Result<()> {
        if !self.synced {
            return Ok(());
        }
        info!("Updating root anchors ...");
        let anchors_path = match self.anchors_path.as_ref() {
            None => return Ok(()),
            Some(path) => path,
        };

        let result = self
            .chain
            .store
            .update_anchors(anchors_path, ROOT_ANCHORS_COUNT)
            .or_else(|e| Err(anyhow!("Could not update trust anchors: {}", e)))?;

        if let Some(result) = result.first() {
            info!(
                "Latest root anchor {} (height: {})",
                hex::encode(result.root),
                result.block.height
            )
        }
        Ok(())
    }

    pub fn handle_block(
        &mut self,
        node: &mut Client,
        id: ChainAnchor,
        block: Block,
    ) -> anyhow::Result<()> {
        let index_blocks = self.block_index.is_some();
        let block_result =
            node.apply_block(&mut self.chain, id.height, id.hash, block, index_blocks)?;

        if let Some(index) = self.block_index.as_mut() {
            if let Some(block) = block_result {
                Self::save_block(index.clone(), id.hash, block)?;
            }
        }

        if id.height % COMMIT_BLOCK_INTERVAL == 0 {
            let block_index_writer = self.block_index.clone();

            let tx = self.chain.store.write().expect("write handle");
            let state_meta = ChainAnchor {
                height: id.height,
                hash: id.hash,
            };

            self.chain.state.commit(state_meta.clone(), tx)?;
            if let Some(index) = block_index_writer {
                let tx = index.store.write().expect("write handle");
                index.state.commit(state_meta, tx)?;
            }
            self.update_anchors()?;
        }

        Ok(())
    }

    pub fn protocol_sync(
        &mut self,
        source: BitcoinBlockSource,
        shutdown: broadcast::Sender<()>,
    ) -> anyhow::Result<()> {
        let start_block: ChainAnchor = { self.chain.state.tip.read().expect("read").clone() };
        let mut node = Client::new(self.block_index_full);

        info!(
            "Start block={} height={}",
            start_block.hash, start_block.height
        );

        let (fetcher, receiver) = BlockFetcher::new(
            self.network.fallback_network(),
            source.clone(),
            self.num_workers,
        );
        fetcher.start(start_block);

        let mut shutdown_signal = shutdown.subscribe();
        loop {
            if shutdown_signal.try_recv().is_ok() {
                break;
            }
            match receiver.try_recv() {
                Ok(event) => match event {
                    BlockEvent::Tip(_) => {
                        self.synced = true;
                        if self
                            .anchors_path
                            .as_ref()
                            .is_some_and(|file| !file.exists())
                        {
                            self.update_anchors()?;
                        }
                    }
                    BlockEvent::Block(id, block) => {
                        self.handle_block(&mut node, id, block)?;
                        info!("block={} height={}", id.hash, id.height);
                    }
                    BlockEvent::Error(e) if matches!(e, BlockFetchError::BlockMismatch) => {
                        if let Err(e) = self.restore(&source) {
                            if e.downcast_ref::<BitcoinRpcError>().is_none() {
                                return Err(e);
                            }
                            warn!("Restore: {} - retrying in 1s", e);
                            let mut wait_recv = shutdown.subscribe();
                            std_wait(|| wait_recv.try_recv().is_ok(), Duration::from_secs(1));
                        }
                        // Even if we couldn't restore just attempt to re-sync
                        let new_tip = self.chain.state.tip.read().expect("read").clone();
                        fetcher.restart(new_tip, &receiver);
                    }
                    BlockEvent::Error(e) => {
                        warn!("Fetcher: {} - retrying in 1s", e);
                        let mut wait_recv = shutdown.subscribe();
                        std_wait(|| wait_recv.try_recv().is_ok(), Duration::from_secs(1));
                        // Even if we couldn't restore just attempt to re-sync
                        let new_tip = self.chain.state.tip.read().expect("read").clone();
                        fetcher.restart(new_tip, &receiver);
                    }
                },
                Err(e) if matches!(e, std::sync::mpsc::TryRecvError::Empty) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => {
                    break;
                }
            }
        }

        info!("Shutting down protocol sync");
        fetcher.stop();

        Ok(())
    }

    pub fn genesis(network: ExtendedNetwork) -> ChainAnchor {
        network.genesis()
    }
}
