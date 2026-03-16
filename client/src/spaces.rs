use std::{net::SocketAddr, path::PathBuf, time::Duration};

use log::{info, warn};
use spaces_protocol::{
    bitcoin::{Block},
    constants::ChainAnchor,
};
use tokio::sync::broadcast;

use crate::{
    client::{BlockSource, Client},
    config::ExtendedNetwork,
    source::{
        BitcoinBlockSource, BitcoinRpc, BitcoinRpcError, BlockEvent, BlockFetchError, BlockFetcher,
    },
    std_wait,
};
use crate::store::chain::{Chain};

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

    pub fn handle_block(
        &mut self,
        node: &mut Client,
        id: ChainAnchor,
        block: Block,
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
        Ok(())
    }

    pub fn protocol_sync(
        &mut self,
        source: BitcoinBlockSource,
        shutdown: broadcast::Sender<()>,
    ) -> anyhow::Result<()> {
        let start_block = self.chain.tip();
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
        match network {
            ExtendedNetwork::Testnet => ChainAnchor::TESTNET(),
            ExtendedNetwork::Testnet4 => ChainAnchor::TESTNET4(),
            ExtendedNetwork::Regtest => ChainAnchor::REGTEST(),
            ExtendedNetwork::Mainnet => ChainAnchor::MAINNET(),
            _ => panic!("unsupported network"),
        }
    }

    pub fn ptr_genesis(network: ExtendedNetwork) -> ChainAnchor {
        match network {
            ExtendedNetwork::Testnet4 => ChainAnchor::PTR_TESTNET4(),
            ExtendedNetwork::Regtest => ChainAnchor::PTR_REGTEST(),
            _ => panic!("unsupported network"),
        }
    }
}
