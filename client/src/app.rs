use std::path::PathBuf;
use std::sync::Arc;
use anyhow::anyhow;
use tokio::sync::{broadcast, mpsc};
use tokio::task::{JoinHandle, JoinSet};
use crate::config::Args;
use crate::rpc::{AsyncChainState, RpcServerImpl, WalletLoadRequest, WalletManager};
use crate::source::{BitcoinBlockSource, BitcoinRpc};
use crate::spaces::Spaced;
use crate::store::LiveSnapshot;
use crate::wallets::RpcWallet;

pub struct App {
    shutdown: broadcast::Sender<()>,
    services: JoinSet<anyhow::Result<()>>,
}

impl App {
    pub fn new(shutdown: broadcast::Sender<()>) -> Self {
        Self {
            shutdown,
            services: JoinSet::new(),
        }
    }

    async fn setup_rpc_wallet(&mut self, spaced: &Spaced, rx: mpsc::Receiver<WalletLoadRequest>, cbf: bool) {
        let wallet_service = RpcWallet::service(
            spaced.network,
            spaced.rpc.clone(),
            spaced.chain.state.clone(),
            rx,
            self.shutdown.clone(),
            spaced.num_workers,
            cbf
        );

        self.services.spawn(async move {
            wallet_service
                .await
                .map_err(|e| anyhow!("Wallet service error: {}", e))
        });
    }

    async fn setup_rpc_services(&mut self, spaced: &Spaced) {
        let (wallet_loader_tx, wallet_loader_rx) = mpsc::channel(1);

        let wallet_manager = WalletManager {
            data_dir: spaced.data_dir.join("wallets"),
            network: spaced.network,
            rpc: spaced.rpc.clone(),
            wallet_loader: wallet_loader_tx,
            wallets: Arc::new(Default::default()),
        };

        let (async_chain_state, async_chain_state_handle) = create_async_store(
            spaced.rpc.clone(),
            spaced.anchors_path.clone(),
            spaced.chain.state.clone(),
            spaced.block_index.as_ref().map(|index| index.state.clone()),
            self.shutdown.subscribe(),
        )
            .await;

        self.services.spawn(async {
            async_chain_state_handle
                .await
                .map_err(|e| anyhow!("Chain state error: {}", e))
        });
        let rpc_server = RpcServerImpl::new(async_chain_state.clone(), wallet_manager);

        let bind = spaced.bind.clone();
        let auth_token = spaced.auth_token.clone();
        let shutdown = self.shutdown.clone();

        self.services.spawn(async move {
            rpc_server
                .listen(bind, auth_token, shutdown)
                .await
                .map_err(|e| anyhow!("RPC Server error: {}", e))
        });

        self.setup_rpc_wallet(spaced, wallet_loader_rx, spaced.cbf).await;
    }

    async fn setup_sync_service(&mut self, mut spaced: Spaced) {
        let (spaced_sender, spaced_receiver) = tokio::sync::oneshot::channel();

        let shutdown = self.shutdown.clone();
        let rpc = spaced.rpc.clone();

        std::thread::spawn(move || {
            let source = BitcoinBlockSource::new(rpc);
            _ = spaced_sender.send(spaced.protocol_sync(source, shutdown));
        });

        self.services.spawn(async move {
            spaced_receiver
                .await?
                .map_err(|e| anyhow!("Protocol sync error: {}", e))
        });
    }

    pub async fn run(&mut self, args: Vec<String>) -> anyhow::Result<()> {
        let spaced = Args::configure(args).await?;
        self.setup_rpc_services(&spaced).await;
        self.setup_sync_service(spaced).await;

        while let Some(res) = self.services.join_next().await {
            res??
        }

        Ok(())
    }
}

async fn create_async_store(
    rpc: BitcoinRpc,
    anchors: Option<PathBuf>,
    chain_state: LiveSnapshot,
    block_index: Option<LiveSnapshot>,
    shutdown: broadcast::Receiver<()>,
) -> (AsyncChainState, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(32);
    let async_store = AsyncChainState::new(tx);
    let client = reqwest::Client::new();
    let handle = tokio::spawn(async move {
        AsyncChainState::handler(
            &client,
            rpc,
            anchors,
            chain_state,
            block_index,
            rx,
            shutdown,
        )
            .await
    });
    (async_store, handle)
}
