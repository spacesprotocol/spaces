use std::{net::SocketAddr, path::PathBuf, time::Duration};

use log::{info, warn};
use spaces_protocol::{
    bitcoin::{Block},
    constants::ChainAnchor,
};
use tokio::sync::broadcast;

use crate::{
    callbacks::CallbackRegistry,
    client::{BlockSource, Client},
    config::ExtendedNetwork,
    source::{
        BitcoinBlockSource, BitcoinRpc, BitcoinRpcError, BlockEvent, BlockFetchError, BlockFetcher,
    },
    std_wait,
};
use crate::store::chain::{Chain};

/// Number of blocks to keep from tip when pruning
const PRUNING_BUFFER: u32 = 120;

pub struct Spaced {
    pub network: ExtendedNetwork,
    pub chain: Chain,
    pub block_index_full: bool,
    pub rpc: BitcoinRpc,
    pub data_dir: PathBuf,
    pub bind: Vec<SocketAddr>,
    pub auth_token: String,
    pub num_workers: usize,
    pub anchors_path: Option<PathBuf>,
    pub synced: bool,
    pub cbf: bool,
    pub num_anchors: u32,
    pub enable_pruning: bool,
}

impl Spaced {
    pub fn restore(&self, source: &BitcoinBlockSource) -> anyhow::Result<()> {
        self.chain.restore(|h| {
           let h = source.get_block_hash(h)?;
            Ok(h)
        })?;
        Ok(())
    }

    pub fn update_anchors(&self) -> anyhow::Result<()> {
        if !self.synced {
            return Ok(());
        }

        let anchors_path = match self.anchors_path.as_ref() {
            None => return Ok(()),
            Some(path) => path,
        };

        info!("Updating root anchors ...");
        self.chain.update_anchors(anchors_path, self.num_anchors)?;
        Ok(())
    }

    fn prune(&self, source: &BitcoinBlockSource, height: u32) {
        let prune_height = height.saturating_sub(PRUNING_BUFFER);
        if prune_height == 0 {
            return;
        }
        match source.prune_blockchain(prune_height) {
            Ok(pruned_up_to) => {
                info!("Pruned blocks up to height {}", pruned_up_to);
            }
            Err(e) => {
                warn!("Failed to prune: {} (is Bitcoin Core started with -prune=1?)", e);
            }
        }
    }

    pub fn handle_block(
        &mut self,
        node: &mut Client,
        id: ChainAnchor,
        block: Block,
        callback_registry: &CallbackRegistry,
        tokio_runtime: &tokio::runtime::Handle,
    ) -> anyhow::Result<()> {
        let sp_idx = self.chain.has_spaces_index();
        let pt_idx = self.chain.has_nums_index();

        let (block_result,ptr_block_result) = node
            .scan_block(&mut self.chain, id.height, id.hash, &block, sp_idx, pt_idx)?;

        if let Some(result) = block_result {
            self.chain.apply_block_to_spaces_index(id.hash, result)?;
        }
        if let Some(result) = ptr_block_result {
            self.chain.apply_block_to_ptrs_index(id.hash, result)?;
        }

        let new_tip = ChainAnchor {
            height: id.height,
            hash: id.hash,
        };
        if self.chain.maybe_commit(new_tip)? {
            self.update_anchors()?;
        }

        let block_txids: Vec<_> = block.txdata.iter().map(|tx| tx.compute_txid()).collect();
        let chain_tip = self.chain.tip();
        let block_hash_str = id.hash.to_string();
        let registry = callback_registry.clone();
        tokio_runtime.spawn(async move {
            registry
                .check_and_notify(
                    id.height,
                    &block_hash_str,
                    &block_txids,
                    chain_tip.height,
                )
                .await;
        });

        Ok(())
    }

    pub fn protocol_sync(
        &mut self,
        source: BitcoinBlockSource,
        shutdown: broadcast::Sender<()>,
        callback_registry: CallbackRegistry,
        tokio_runtime: tokio::runtime::Handle,
    ) -> anyhow::Result<()> {
        let start_block = self.chain.tip();
        let mut node = Client::new(self.block_index_full);
        let mut last_idle_prune = std::time::Instant::now();

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
                    BlockEvent::Waiting(bitcoind_height) => {
                        if self.enable_pruning && last_idle_prune.elapsed() >= Duration::from_secs(60) {
                            self.prune(&source, bitcoind_height);
                            last_idle_prune = std::time::Instant::now();
                        }
                    }
                    BlockEvent::Block(id, block) => {
                        self.handle_block(
                            &mut node,
                            id,
                            block,
                            &callback_registry,
                            &tokio_runtime,
                        )?;
                        info!("block={} height={}", id.hash, id.height);
                        if self.enable_pruning && id.height % PRUNING_BUFFER == 0 {
                            self.prune(&source, id.height);
                        }
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
                        let new_tip = self.chain.tip();
                        fetcher.restart(new_tip, &receiver);
                    }
                    BlockEvent::Error(e) => {
                        warn!("Fetcher: {} - retrying in 1s", e);
                        let mut wait_recv = shutdown.subscribe();
                        std_wait(|| wait_recv.try_recv().is_ok(), Duration::from_secs(1));
                        // Even if we couldn't restore just attempt to re-sync
                        let new_tip = self.chain.tip();
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

    pub fn nums_genesis(network: ExtendedNetwork) -> ChainAnchor {
        match network {
            ExtendedNetwork::Mainnet => spaces_nums::constants::NUMS_MAINNET(),
            ExtendedNetwork::Testnet4 => spaces_nums::constants::NUMS_TESTNET4(),
            ExtendedNetwork::Regtest => ChainAnchor::NUMS_REGTEST(),
            _ => panic!("unsupported network"),
        }
    }
}
