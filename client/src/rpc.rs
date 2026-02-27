use std::{
    collections::BTreeMap, fs, fs::File, io::Write, net::SocketAddr, path::PathBuf, str::FromStr,
    sync::Arc,
};

use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::{Amount, BlockHash, FeeRate, Network, Txid},
    chain::BlockId,
    keys::{
        bip39::{Language, Mnemonic, WordCount},
        DerivableKey, ExtendedKey, GeneratableKey, GeneratedKey,
    },
    miniscript::Tap,
    KeychainKind,
};
use jsonrpsee::{
    core::async_trait,
    proc_macros::rpc,
    server::{middleware::http::ProxyGetRequestLayer, Server},
    types::ErrorObjectOwned,
};
use log::info;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use spacedb::{encode::SubTreeEncoder, tx::ProofType};
use spaces_protocol::{
    bitcoin,
    bitcoin::{
        bip32::Xpriv,
        Network::{Regtest, Testnet},
        OutPoint,
    },
    constants::ChainAnchor,
    hasher::{BaseHash, KeyHasher, OutpointKey, SpaceKey},
    prepare::DataSource,
    slabel::SLabel,
    validate::TxChangeSet,
    Bytes, Covenant, FullSpaceOut, SpaceOut,
};
use spaces_wallet::{
    bdk_wallet as bdk, bdk_wallet::template::Bip86, bitcoin::hashes::Hash as BitcoinHash,
    export::WalletExport, nostr::NostrEvent, Balance, DoubleUtxo, Listing, SpacesWallet,
    WalletConfig, WalletDescriptors, WalletOutput,
};
use tokio::{
    select,
    sync::{broadcast, mpsc, oneshot, RwLock},
    task::JoinSet,
};

use crate::auth::BasicAuthLayer;
use crate::wallets::WalletInfoWithProgress;
use crate::{
    calc_progress,
    checker::TxChecker,
    client::{BlockMeta, TxEntry, BlockchainInfo},
    config::ExtendedNetwork,
    deserialize_base64, serialize_base64,
    source::BitcoinRpc,
    spaces::{COMMIT_BLOCK_INTERVAL, ROOT_ANCHORS_COUNT},
    store::{ChainState, LiveSnapshot, RolloutEntry, Sha256},
    wallets::{
        AddressKind, ListSpacesResponse, RpcWallet, TxInfo, TxResponse, WalletCommand,
        WalletResponse,
    },
};

pub(crate) type Responder<T> = oneshot::Sender<T>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub network: ExtendedNetwork,
    pub tip: ChainAnchor,
    pub chain: ChainInfo,
    pub ready: bool,
    pub progress: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainInfo {
    pub blocks: u32,
    pub headers: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootAnchor {
    #[serde(
        serialize_with = "serialize_hash",
        deserialize_with = "deserialize_hash"
    )]
    pub root: spaces_protocol::hasher::Hash,
    pub block: ChainAnchor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HeightOrHash {
    Hash(BlockHash),
    Height(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockMetaWithHash {
    pub hash: BlockHash,
    #[serde(flatten)]
    pub block_meta: BlockMeta,
}

pub enum ChainStateCommand {
    CheckPackage {
        txs: Vec<String>,
        resp: Responder<anyhow::Result<Vec<Option<TxChangeSet>>>>,
    },
    GetServerInfo {
        resp: Responder<anyhow::Result<ServerInfo>>,
    },
    GetSpace {
        hash: SpaceKey,
        resp: Responder<anyhow::Result<Option<FullSpaceOut>>>,
    },
    GetSpaceout {
        outpoint: OutPoint,
        resp: Responder<anyhow::Result<Option<SpaceOut>>>,
    },
    GetSpaceOutpoint {
        hash: SpaceKey,
        resp: Responder<anyhow::Result<Option<OutPoint>>>,
    },
    GetTxMeta {
        txid: Txid,
        resp: Responder<anyhow::Result<Option<TxEntry>>>,
    },
    GetBlockMeta {
        height_or_hash: HeightOrHash,
        resp: Responder<anyhow::Result<BlockMetaWithHash>>,
    },
    EstimateBid {
        target: usize,
        resp: Responder<anyhow::Result<u64>>,
    },
    GetRollout {
        target: usize,
        resp: Responder<anyhow::Result<Vec<RolloutEntry>>>,
    },
    VerifyListing {
        listing: Listing,
        resp: Responder<anyhow::Result<()>>,
    },
    VerifyEvent {
        space: String,
        event: NostrEvent,
        resp: Responder<anyhow::Result<NostrEvent>>,
    },
    ProveSpaceout {
        outpoint: OutPoint,
        prefer_recent: bool,
        resp: Responder<anyhow::Result<ProofResult>>,
    },
    ProveSpaceOutpoint {
        space_or_hash: String,
        resp: Responder<anyhow::Result<ProofResult>>,
    },
    GetRootAnchors {
        resp: Responder<anyhow::Result<Vec<RootAnchor>>>,
    },
}

#[derive(Clone)]
pub struct AsyncChainState {
    sender: mpsc::Sender<ChainStateCommand>,
}

#[rpc(server, client)]
pub trait Rpc {
    #[method(name = "getserverinfo")]
    async fn get_server_info(&self) -> Result<ServerInfo, ErrorObjectOwned>;

    #[method(name = "getspace")]
    async fn get_space(
        &self,
        space_or_hash: &str,
    ) -> Result<Option<FullSpaceOut>, ErrorObjectOwned>;

    #[method(name = "getspaceowner")]
    async fn get_space_owner(
        &self,
        space_or_hash: &str,
    ) -> Result<Option<OutPoint>, ErrorObjectOwned>;

    #[method(name = "getspaceout")]
    async fn get_spaceout(&self, outpoint: OutPoint) -> Result<Option<SpaceOut>, ErrorObjectOwned>;

    #[method(name = "checkpackage")]
    async fn check_package(
        &self,
        txs: Vec<String>,
    ) -> Result<Vec<Option<TxChangeSet>>, ErrorObjectOwned>;

    #[method(name = "estimatebid")]
    async fn estimate_bid(&self, target: usize) -> Result<u64, ErrorObjectOwned>;

    #[method(name = "getrollout")]
    async fn get_rollout(&self, target: usize) -> Result<Vec<RolloutEntry>, ErrorObjectOwned>;

    #[method(name = "getblockmeta")]
    async fn get_block_meta(
        &self,
        height_or_hash: HeightOrHash,
    ) -> Result<BlockMetaWithHash, ErrorObjectOwned>;

    #[method(name = "gettxmeta")]
    async fn get_tx_meta(&self, txid: Txid) -> Result<Option<TxEntry>, ErrorObjectOwned>;

    #[method(name = "listwallets")]
    async fn list_wallets(&self) -> Result<Vec<String>, ErrorObjectOwned>;

    #[method(name = "walletload")]
    async fn wallet_load(&self, name: &str) -> Result<(), ErrorObjectOwned>;

    #[method(name = "walletimport")]
    async fn wallet_import(&self, wallet: WalletExport) -> Result<(), ErrorObjectOwned>;

    #[method(name = "verifyevent")]
    async fn verify_event(
        &self,
        space: &str,
        event: NostrEvent,
    ) -> Result<NostrEvent, ErrorObjectOwned>;

    #[method(name = "walletsignevent")]
    async fn wallet_sign_event(
        &self,
        wallet: &str,
        space: &str,
        event: NostrEvent,
    ) -> Result<NostrEvent, ErrorObjectOwned>;

    #[method(name = "walletgetinfo")]
    async fn wallet_get_info(&self, name: &str)
        -> Result<WalletInfoWithProgress, ErrorObjectOwned>;

    #[method(name = "walletexport")]
    async fn wallet_export(&self, name: &str) -> Result<WalletExport, ErrorObjectOwned>;

    #[method(name = "walletcreate")]
    async fn wallet_create(&self, name: &str) -> Result<String, ErrorObjectOwned>;

    #[method(name = "walletrecover")]
    async fn wallet_recover(&self, name: &str, mnemonic: String) -> Result<(), ErrorObjectOwned>;

    #[method(name = "walletsendrequest")]
    async fn wallet_send_request(
        &self,
        wallet: &str,
        request: RpcWalletTxBuilder,
    ) -> Result<WalletResponse, ErrorObjectOwned>;

    #[method(name = "walletgetnewaddress")]
    async fn wallet_get_new_address(
        &self,
        wallet: &str,
        kind: AddressKind,
    ) -> Result<String, ErrorObjectOwned>;

    #[method(name = "walletbumpfee")]
    async fn wallet_bump_fee(
        &self,
        wallet: &str,
        txid: Txid,
        fee_rate: FeeRate,
        skip_tx_check: bool,
    ) -> Result<Vec<TxResponse>, ErrorObjectOwned>;

    #[method(name = "walletbuy")]
    async fn wallet_buy(
        &self,
        wallet: &str,
        listing: Listing,
        fee_rate: Option<FeeRate>,
        skip_tx_check: bool,
    ) -> Result<TxResponse, ErrorObjectOwned>;

    #[method(name = "walletsell")]
    async fn wallet_sell(
        &self,
        wallet: &str,
        space: String,
        amount: u64,
    ) -> Result<Listing, ErrorObjectOwned>;

    #[method(name = "verifylisting")]
    async fn verify_listing(&self, listing: Listing) -> Result<(), ErrorObjectOwned>;

    #[method(name = "provespaceout")]
    async fn prove_spaceout(
        &self,
        outpoint: OutPoint,
        prefer_recent: Option<bool>,
    ) -> Result<ProofResult, ErrorObjectOwned>;

    #[method(name = "provespaceoutpoint")]
    async fn prove_space_outpoint(
        &self,
        space_or_hash: &str,
    ) -> Result<ProofResult, ErrorObjectOwned>;

    #[method(name = "getrootanchors")]
    async fn get_root_anchors(&self) -> Result<Vec<RootAnchor>, ErrorObjectOwned>;

    #[method(name = "walletlisttransactions")]
    async fn wallet_list_transactions(
        &self,
        wallet: &str,
        count: usize,
        skip: usize,
    ) -> Result<Vec<TxInfo>, ErrorObjectOwned>;

    #[method(name = "walletforcespend")]
    async fn wallet_force_spend(
        &self,
        wallet: &str,
        outpoint: OutPoint,
        fee_rate: FeeRate,
    ) -> Result<TxResponse, ErrorObjectOwned>;

    #[method(name = "walletlistspaces")]
    async fn wallet_list_spaces(
        &self,
        wallet: &str,
    ) -> Result<ListSpacesResponse, ErrorObjectOwned>;

    #[method(name = "walletlistunspent")]
    async fn wallet_list_unspent(
        &self,
        wallet: &str,
    ) -> Result<Vec<WalletOutput>, ErrorObjectOwned>;

    #[method(name = "walletlistbidouts")]
    async fn wallet_list_bidouts(&self, wallet: &str) -> Result<Vec<DoubleUtxo>, ErrorObjectOwned>;

    #[method(name = "walletgetbalance")]
    async fn wallet_get_balance(&self, wallet: &str) -> Result<Balance, ErrorObjectOwned>;

    #[method(name = "estimatefee")]
    async fn estimate_fee(
        &self,
        conf_target: u32,
        estimate_mode: Option<String>,
    ) -> Result<FeeEstimateResponse, ErrorObjectOwned>;
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RpcWalletTxBuilder {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bidouts: Option<u8>,
    pub requests: Vec<RpcWalletRequest>,
    pub fee_rate: Option<FeeRate>,
    pub dust: Option<Amount>,
    pub force: bool,
    pub confirmed_only: bool,
    pub skip_tx_check: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "request")]
pub enum RpcWalletRequest {
    #[serde(rename = "open")]
    Open(OpenParams),
    #[serde(rename = "bid")]
    Bid(BidParams),
    #[serde(rename = "register")]
    Register(RegisterParams),
    #[serde(rename = "execute")]
    Execute(ExecuteParams),
    #[serde(rename = "transfer")]
    Transfer(TransferSpacesParams),
    #[serde(rename = "send")]
    SendCoins(SendCoinsParams),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TransferSpacesParams {
    pub spaces: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SendCoinsParams {
    pub amount: Amount,
    pub to: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ExecuteParams {
    pub context: Vec<String>,
    pub space_script: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OpenParams {
    pub name: String,
    pub amount: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BidParams {
    pub name: String,
    pub amount: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TransferParams {
    pub name: String,
    pub to: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RegisterParams {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}

#[derive(Clone)]
pub struct RpcServerImpl {
    wallet_manager: WalletManager,
    store: AsyncChainState,
    client: reqwest::Client,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProofResult {
    pub root: Bytes,
    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub proof: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FeeEstimateResponse {
    pub feerate_sat_vb: u64,
    pub blocks: u64,
}

fn serialize_hash<S>(
    bytes: &spaces_protocol::hasher::Hash,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if serializer.is_human_readable() {
        serializer.serialize_str(&hex::encode(bytes))
    } else {
        serializer.serialize_bytes(bytes)
    }
}

fn deserialize_hash<'de, D>(deserializer: D) -> Result<spaces_protocol::hasher::Hash, D::Error>
where
    D: Deserializer<'de>,
{
    let mut bytes = [0u8; 32];
    if deserializer.is_human_readable() {
        let s = String::deserialize(deserializer)?;
        hex::decode_to_slice(s, &mut bytes).map_err(serde::de::Error::custom)?;
    } else {
        spaces_protocol::hasher::Hash::deserialize(deserializer)?;
    }
    Ok(bytes)
}

#[derive(Clone)]
pub struct WalletManager {
    pub data_dir: PathBuf,
    pub network: ExtendedNetwork,
    pub rpc: BitcoinRpc,
    pub wallet_loader: mpsc::Sender<WalletLoadRequest>,
    pub wallets: Arc<RwLock<BTreeMap<String, RpcWallet>>>,
}

pub struct WalletLoadRequest {
    pub(crate) rx: mpsc::Receiver<WalletCommand>,
    pub(crate) config: WalletConfig,
    pub(crate) export: WalletExport,
}

const RPC_WALLET_NOT_LOADED: i32 = -18;

impl WalletManager {
    pub async fn import_wallet(&self, wallet: WalletExport) -> anyhow::Result<()> {
        let wallet_path = self.data_dir.join(&wallet.label);
        if wallet_path.exists() {
            return Err(anyhow!(format!(
                "Wallet with label `{}` already exists",
                wallet.label
            )));
        }

        fs::create_dir_all(&wallet_path)?;
        let wallet_export_path = wallet_path.join("wallet.json");
        let mut file = fs::File::create(wallet_export_path)?;
        file.write_all(wallet.to_string().as_bytes())?;

        self.load_wallet(&wallet.label).await?;
        Ok(())
    }

    pub async fn export_wallet(&self, name: &str) -> anyhow::Result<WalletExport> {
        let wallet_dir = self.data_dir.join(name);
        if !wallet_dir.exists() {
            return Err(anyhow!("Wallet does not exist"));
        }
        let wallet = fs::read_to_string(wallet_dir.join("wallet.json"))?;
        let export: WalletExport = serde_json::from_str(&wallet)?;
        Ok(export)
    }

    pub async fn create_wallet(&self, client: &reqwest::Client, name: &str) -> anyhow::Result<String> {
        let mnemonic: GeneratedKey<_, Tap> =
            Mnemonic::generate((WordCount::Words12, Language::English))
                .map_err(|_| anyhow!("Mnemonic generation error"))?;

        let start_block = self.get_wallet_start_block(client).await?;
        self.setup_new_wallet(name.to_string(), mnemonic.to_string(), Some(start_block.height))?;
        self.load_wallet(name).await?;
        Ok(mnemonic.to_string())
    }

    pub async fn recover_wallet(&self, name: &str, mnemonic: &str) -> anyhow::Result<()> {
        self.setup_new_wallet(name.to_string(), mnemonic.to_string(), None)?;
        self.load_wallet(name).await?;
        Ok(())
    }

    fn setup_new_wallet(
        &self,
        name: String,
        mnemonic: String,
        start_block_height: Option<u32>,
    ) -> anyhow::Result<()> {
        let wallet_path = self.data_dir.join(&name);
        if wallet_path.exists() {
            return Err(anyhow!(format!("Wallet `{}` already exists", name)));
        }

        let export = self.wallet_from_mnemonic(name.clone(), mnemonic, start_block_height)?;
        fs::create_dir_all(&wallet_path)?;
        let wallet_export_path = wallet_path.join("wallet.json");
        let mut file = fs::File::create(wallet_export_path)?;
        file.write_all(export.to_string().as_bytes())?;
        Ok(())
    }

    fn wallet_from_mnemonic(
        &self,
        name: String,
        mnemonic: String,
        start_block_height: Option<u32>,
    ) -> anyhow::Result<WalletExport> {
        let (network, _) = self.fallback_network();
        let xpriv = Self::descriptor_from_mnemonic(network, &mnemonic)?;

        let (external, internal) = Self::default_descriptors(xpriv);
        let tmp = bdk::Wallet::create(external, internal)
            .network(network)
            .create_wallet_no_persist()?;

        let start_block_height = match start_block_height {
            Some(height) => height,
            None => self.network.genesis().height,
        };

        let export =
            WalletExport::export_wallet(&tmp, &name, start_block_height).map_err(|e| anyhow!(e))?;

        Ok(export)
    }

    fn fallback_network(&self) -> (Network, Option<BlockHash>) {
        let mut genesis_hash = None;

        let network = match self.network {
            ExtendedNetwork::Testnet => Network::Testnet,
            ExtendedNetwork::Testnet4 => {
                genesis_hash = Some(BlockHash::from_byte_array([
                    67, 240, 139, 218, 176, 80, 227, 91, 86, 124, 134, 75, 145, 244, 127, 80, 174,
                    114, 90, 226, 222, 83, 188, 251, 186, 242, 132, 218, 0, 0, 0, 0,
                ]));
                Network::Testnet
            }

            // Use testnet in the wallet if regtest is specified to work around
            // a bug in bdk comparing regtest descriptors
            // TODO: might have been fixed already?
            ExtendedNetwork::Regtest => {
                genesis_hash = Some(
                    bdk::bitcoin::constants::genesis_block(Regtest)
                        .header
                        .block_hash(),
                );
                Network::Regtest
            }
            ExtendedNetwork::Signet => {
                genesis_hash = Some(
                    bitcoin::constants::genesis_block(Network::Signet)
                        .header
                        .block_hash(),
                );
                Testnet
            }
            _ => self.network.fallback_network(),
        };

        (network, genesis_hash)
    }

    pub async fn list_wallets(&self) -> anyhow::Result<Vec<String>> {
        if !self.data_dir.exists() {
            return Ok(vec![]);
        }
        let wallets = std::fs::read_dir(&self.data_dir)?
            .filter_map(Result::ok)
            .filter(|entry| entry.path().is_dir())
            .filter_map(|entry| {
                entry
                    .path()
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(String::from)
            })
            .collect();

        Ok(wallets)
    }

    pub async fn load_wallet(&self, name: &str) -> anyhow::Result<()> {
        if self.wallets.read().await.contains_key(name) {
            return Ok(());
        }
        let wallet_dir = self.data_dir.join(name);
        if !wallet_dir.exists() {
            return Err(anyhow!("Wallet does not exist"));
        }

        let file = fs::File::open(wallet_dir.join("wallet.json"))?;

        let (network, genesis_hash) = self.fallback_network();
        let export: WalletExport = serde_json::from_reader(file)?;

        let wallet_config = WalletConfig {
            start_block: export.blockheight,
            data_dir: wallet_dir,
            name: name.to_string(),
            network,
            genesis_hash,
            space_descriptors: WalletDescriptors {
                external: export.descriptor(),
                internal: export
                    .change_descriptor()
                    .expect("expected a change descriptor"),
            },
        };

        let (rpc_wallet, rpc_wallet_rx) = RpcWallet::new();
        let request = WalletLoadRequest {
            rx: rpc_wallet_rx,
            config: wallet_config,
            export,
        };

        self.wallet_loader.send(request).await?;
        let mut wallets = self.wallets.write().await;
        wallets.insert(name.to_string(), rpc_wallet);
        Ok(())
    }

    async fn get_wallet_start_block(&self, client: &reqwest::Client) -> anyhow::Result<BlockId> {
        let count: i32 = self
            .rpc
            .send_json(&client, &self.rpc.get_block_count())
            .await?;
        let height = std::cmp::max(count - 1, 0) as u32;

        let hash = self
            .rpc
            .send_json(&client, &self.rpc.get_block_hash(height))
            .await?;

        Ok(BlockId { height, hash })
    }

    fn descriptor_from_mnemonic(network: Network, m: &str) -> anyhow::Result<Xpriv> {
        let mnemonic = Mnemonic::parse(m)?;
        let xkey: ExtendedKey = mnemonic.clone().into_extended_key()?;
        Ok(xkey.into_xprv(network).expect("xpriv"))
    }

    fn default_descriptors(x: Xpriv) -> (Bip86<Xpriv>, Bip86<Xpriv>) {
        (
            Bip86(x, KeychainKind::External),
            Bip86(x, KeychainKind::Internal),
        )
    }
}

impl RpcServerImpl {
    pub fn new(store: AsyncChainState, wallet_manager: WalletManager) -> Self {
        RpcServerImpl {
            wallet_manager,
            store,
            client: reqwest::Client::new(),
        }
    }

    async fn wallet(&self, wallet: &str) -> Result<RpcWallet, ErrorObjectOwned> {
        let wallets = self.wallet_manager.wallets.read().await;
        wallets.get(wallet).cloned().ok_or_else(|| {
            ErrorObjectOwned::owned(
                RPC_WALLET_NOT_LOADED,
                format!("Wallet '{}' not loaded", wallet),
                None::<String>,
            )
        })
    }

    pub async fn listen(
        self,
        addrs: Vec<SocketAddr>,
        auth_token: String,
        signal: broadcast::Sender<()>,
    ) -> anyhow::Result<()> {
        let mut listeners: Vec<_> = Vec::with_capacity(addrs.len());

        for addr in addrs.iter() {
            let service_builder = tower::ServiceBuilder::new()
                .layer(BasicAuthLayer::new(auth_token.clone()))
                .layer(ProxyGetRequestLayer::new(
                    "/root-anchors.json",
                    "getrootanchors",
                )?)
                .layer(ProxyGetRequestLayer::new("/", "getserverinfo")?);

            let server = Server::builder()
                .set_http_middleware(service_builder)
                .build(addr)
                .await?;
            listeners.push(server);
        }

        let mut set = JoinSet::new();
        for listener in listeners {
            let addr = listener.local_addr()?;
            info!("Listening at {addr}");

            let handle = listener.start(self.clone().into_rpc());

            let mut signal = signal.subscribe();
            set.spawn(async move {
                tokio::select! {
                    _ = handle.clone().stopped() => {
                        // Server stopped normally
                    },
                    _ = signal.recv() => {
                        // Shutdown signal received
                        info!("Shutting down listener {addr}...");
                        _ = handle.stop();
                    }
                }
            });
        }

        while let Some(task_result) = set.join_next().await {
            if let Err(e) = task_result {
                _ = signal.send(());
                return Err(anyhow!("A server listener failed: {:?}", e));
            }
        }

        Ok(())
    }
}

#[async_trait]
impl RpcServer for RpcServerImpl {
    async fn get_server_info(&self) -> Result<ServerInfo, ErrorObjectOwned> {
        let info = self
            .store
            .get_server_info()
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(info)
    }

    async fn get_space(
        &self,
        space_or_hash: &str,
    ) -> Result<Option<FullSpaceOut>, ErrorObjectOwned> {
        let space_hash = get_space_key(space_or_hash)?;

        let info = self
            .store
            .get_space(space_hash)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(info)
    }

    async fn get_space_owner(
        &self,
        space_or_hash: &str,
    ) -> Result<Option<OutPoint>, ErrorObjectOwned> {
        let space_hash = get_space_key(space_or_hash)?;
        let info = self
            .store
            .get_space_outpoint(space_hash)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;

        Ok(info)
    }

    async fn get_spaceout(&self, outpoint: OutPoint) -> Result<Option<SpaceOut>, ErrorObjectOwned> {
        let spaceout = self
            .store
            .get_spaceout(outpoint)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(spaceout)
    }

    async fn check_package(
        &self,
        txs: Vec<String>,
    ) -> Result<Vec<Option<TxChangeSet>>, ErrorObjectOwned> {
        let spaceout = self
            .store
            .check_package(txs)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(spaceout)
    }

    async fn estimate_bid(&self, target: usize) -> Result<u64, ErrorObjectOwned> {
        let info = self
            .store
            .estimate_bid(target)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(info)
    }

    async fn get_rollout(&self, target: usize) -> Result<Vec<RolloutEntry>, ErrorObjectOwned> {
        let rollouts = self
            .store
            .get_rollout(target)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(rollouts)
    }

    async fn get_block_meta(
        &self,
        height_or_hash: HeightOrHash,
    ) -> Result<BlockMetaWithHash, ErrorObjectOwned> {
        let data = self
            .store
            .get_block_meta(height_or_hash)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;

        Ok(data)
    }

    async fn get_tx_meta(&self, txid: Txid) -> Result<Option<TxEntry>, ErrorObjectOwned> {
        let data = self
            .store
            .get_tx_meta(txid)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(data)
    }

    async fn list_wallets(&self) -> Result<Vec<String>, ErrorObjectOwned> {
        self.wallet_manager
            .list_wallets()
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_load(&self, name: &str) -> Result<(), ErrorObjectOwned> {
        self.wallet_manager
            .load_wallet(name)
            .await
            .map_err(|error| {
                ErrorObjectOwned::owned(RPC_WALLET_NOT_LOADED, error.to_string(), None::<String>)
            })
    }

    async fn wallet_import(&self, content: WalletExport) -> Result<(), ErrorObjectOwned> {
        self.wallet_manager
            .import_wallet(content)
            .await
            .map_err(|error| {
                ErrorObjectOwned::owned(RPC_WALLET_NOT_LOADED, error.to_string(), None::<String>)
            })
    }

    async fn verify_event(
        &self,
        space: &str,
        event: NostrEvent,
    ) -> Result<NostrEvent, ErrorObjectOwned> {
        self.store
            .verify_event(space, event)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_sign_event(
        &self,
        wallet: &str,
        space: &str,
        event: NostrEvent,
    ) -> Result<NostrEvent, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_sign_event(space, event)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_get_info(
        &self,
        wallet: &str,
    ) -> Result<WalletInfoWithProgress, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_get_info()
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }
    async fn wallet_export(&self, name: &str) -> Result<WalletExport, ErrorObjectOwned> {
        self.wallet_manager
            .export_wallet(name)
            .await
            .map_err(|error| {
                ErrorObjectOwned::owned(RPC_WALLET_NOT_LOADED, error.to_string(), None::<String>)
            })
    }

    async fn wallet_create(&self, name: &str) -> Result<String, ErrorObjectOwned> {
        self.wallet_manager
            .create_wallet(&self.client, name)
            .await
            .map_err(|error| {
                ErrorObjectOwned::owned(RPC_WALLET_NOT_LOADED, error.to_string(), None::<String>)
            })
    }

    async fn wallet_recover(&self, name: &str, mnemonic: String) -> Result<(), ErrorObjectOwned> {
        self.wallet_manager
            .recover_wallet(name, &mnemonic)
            .await
            .map_err(|error| {
                ErrorObjectOwned::owned(RPC_WALLET_NOT_LOADED, error.to_string(), None::<String>)
            })
    }

    async fn wallet_send_request(
        &self,
        wallet: &str,
        request: RpcWalletTxBuilder,
    ) -> Result<WalletResponse, ErrorObjectOwned> {
        let result = self
            .wallet(&wallet)
            .await?
            .send_batch_tx(request)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(result)
    }

    async fn wallet_get_new_address(
        &self,
        wallet: &str,
        kind: AddressKind,
    ) -> Result<String, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_get_new_address(kind)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_bump_fee(
        &self,
        wallet: &str,
        txid: Txid,
        fee_rate: FeeRate,
        skip_tx_check: bool,
    ) -> Result<Vec<TxResponse>, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_fee_bump(txid, fee_rate, skip_tx_check)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_buy(
        &self,
        wallet: &str,
        listing: Listing,
        fee_rate: Option<FeeRate>,
        skip_tx_check: bool,
    ) -> Result<TxResponse, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_buy(listing, fee_rate, skip_tx_check)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_sell(
        &self,
        wallet: &str,
        space: String,
        amount: u64,
    ) -> Result<Listing, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_sell(space, amount)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn verify_listing(&self, listing: Listing) -> Result<(), ErrorObjectOwned> {
        self.store
            .verify_listing(listing)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn prove_spaceout(
        &self,
        outpoint: OutPoint,
        prefer_recent: Option<bool>,
    ) -> Result<ProofResult, ErrorObjectOwned> {
        self.store
            .prove_spaceout(outpoint, prefer_recent.unwrap_or(false))
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn prove_space_outpoint(
        &self,
        space_or_hash: &str,
    ) -> Result<ProofResult, ErrorObjectOwned> {
        self.store
            .prove_space_outpoint(space_or_hash)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn get_root_anchors(&self) -> Result<Vec<RootAnchor>, ErrorObjectOwned> {
        self.store
            .get_root_anchors()
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_list_transactions(
        &self,
        wallet: &str,
        count: usize,
        skip: usize,
    ) -> Result<Vec<TxInfo>, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_list_transactions(count, skip)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_force_spend(
        &self,
        wallet: &str,
        outpoint: OutPoint,
        fee_rate: FeeRate,
    ) -> Result<TxResponse, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_force_spend(outpoint, fee_rate)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_list_spaces(
        &self,
        wallet: &str,
    ) -> Result<ListSpacesResponse, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_list_spaces()
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_list_unspent(
        &self,
        wallet: &str,
    ) -> Result<Vec<WalletOutput>, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_list_unspent()
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_list_bidouts(&self, wallet: &str) -> Result<Vec<DoubleUtxo>, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_list_bidouts()
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_get_balance(&self, wallet: &str) -> Result<Balance, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_get_balance()
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn estimate_fee(
        &self,
        conf_target: u32,
        estimate_mode: Option<String>,
    ) -> Result<FeeEstimateResponse, ErrorObjectOwned> {
        let mode = estimate_mode.unwrap_or_else(|| "unset".to_string());
        let params = serde_json::json!([conf_target, mode]);
        let rpc = self.wallet_manager.rpc.clone();
        
        let estimate_req = rpc.make_request("estimatesmartfee", params);
        
        // Use spawn_blocking to handle the blocking RPC call in async context
        let result = tokio::task::spawn_blocking(move || {
            let blocking_client = reqwest::blocking::Client::new();
            rpc.send_json_blocking::<serde_json::Value>(&blocking_client, &estimate_req)
        })
        .await
        .map_err(|e| ErrorObjectOwned::owned(-1, format!("Task join error: {}", e), None::<String>))?;
        
        match result {
            Ok(res) => {
                if let Some(fee_rate) = res["feerate"].as_f64() {
                    // Convert BTC/kB to sat/vB
                    let fee_rate_sat_vb = (fee_rate * 100_000.0).ceil() as u64;
                    let blocks = res["blocks"].as_u64().unwrap_or(conf_target as u64);
                    
                    Ok(FeeEstimateResponse {
                        feerate_sat_vb: fee_rate_sat_vb,
                        blocks,
                    })
                } else {
                    Err(ErrorObjectOwned::owned(
                        -1,
                        "Fee estimation unavailable: no feerate in response".to_string(),
                        None::<String>,
                    ))
                }
            }
            Err(e) => Err(ErrorObjectOwned::owned(
                -1,
                format!("RPC error: {}", e),
                None::<String>,
            )),
        }
    }
}

impl AsyncChainState {
    pub fn new(sender: mpsc::Sender<ChainStateCommand>) -> Self {
        Self { sender }
    }

    async fn get_indexed_tx(
        index: &mut Option<LiveSnapshot>,
        txid: &Txid,
        client: &reqwest::Client,
        rpc: &BitcoinRpc,
        chain_state: &mut LiveSnapshot,
    ) -> Result<Option<TxEntry>, anyhow::Error> {
        let info: serde_json::Value = rpc
            .send_json(client, &rpc.get_raw_transaction(&txid, true))
            .await
            .map_err(|e| anyhow!("Could not retrieve tx ({})", e))?;

        let block_hash =
            BlockHash::from_str(info.get("blockhash").and_then(|t| t.as_str()).ok_or_else(
                || anyhow!("Could not retrieve block hash for tx (is it in the mempool?)"),
            )?)?;
        let block = Self::get_indexed_block(
            index,
            HeightOrHash::Hash(block_hash),
            client,
            rpc,
            chain_state,
        )
        .await?;

        Ok(block
            .block_meta
            .tx_meta
            .into_iter()
            .find(|tx| &tx.changeset.txid == txid))
    }

    async fn get_indexed_block(
        index: &mut Option<LiveSnapshot>,
        height_or_hash: HeightOrHash,
        client: &reqwest::Client,
        rpc: &BitcoinRpc,
        chain_state: &mut LiveSnapshot,
    ) -> Result<BlockMetaWithHash, anyhow::Error> {
        let index = index
            .as_mut()
            .ok_or_else(|| anyhow!("block index must be enabled"))?;
        let hash = match height_or_hash {
            HeightOrHash::Hash(hash) => hash,
            HeightOrHash::Height(height) => rpc
                .send_json(client, &rpc.get_block_hash(height))
                .await
                .map_err(|e| anyhow!("Could not retrieve block hash ({})", e))?,
        };

        if let Some(block_meta) = index
            .get(BaseHash::from_slice(hash.as_ref()))
            .context("Could not fetch block from index")?
        {
            return Ok(BlockMetaWithHash { hash, block_meta });
        }

        let info: serde_json::Value = rpc
            .send_json(client, &rpc.get_block_header(&hash))
            .await
            .map_err(|e| anyhow!("Could not retrieve block ({})", e))?;

        let height = info
            .get("height")
            .and_then(|t| t.as_u64())
            .and_then(|h| u32::try_from(h).ok())
            .ok_or_else(|| anyhow!("Could not retrieve block height"))?;

        let tip = chain_state.tip.read().expect("read meta").clone();
        if height > tip.height {
            return Err(anyhow!(
                "Spaces is syncing at height {}, requested block height {}",
                tip.height,
                height
            ));
        }
        Ok(BlockMetaWithHash {
            hash,
            block_meta: BlockMeta {
                height,
                tx_meta: Vec::new(),
            },
        })
    }

    pub async fn handle_command(
        client: &reqwest::Client,
        rpc: &BitcoinRpc,
        anchors_path: &Option<PathBuf>,
        chain_state: &mut LiveSnapshot,
        block_index: &mut Option<LiveSnapshot>,
        cmd: ChainStateCommand,
    ) {
        match cmd {
            ChainStateCommand::CheckPackage { txs: raw_txs, resp } => {
                let mut txs = Vec::with_capacity(raw_txs.len());
                for raw_tx in raw_txs {
                    let tx = bitcoin::consensus::encode::deserialize_hex(&raw_tx);
                    if tx.is_err() {
                        let _ = resp.send(Err(anyhow!("could not decode hex transaction")));
                        return;
                    }
                    txs.push(tx.unwrap());
                }

                let tip = chain_state.tip.read().expect("read meta").clone();
                let mut emulator = TxChecker::new(chain_state);
                let result = emulator.apply_package(tip.height + 1, txs);
                let _ = resp.send(result);
            }
            ChainStateCommand::GetServerInfo { resp } => {
                let tip = chain_state.tip.read().expect("read meta").clone();
                _ = resp.send(get_server_info(client, rpc, tip).await)
            }
            ChainStateCommand::GetSpace { hash, resp } => {
                let result = chain_state.get_space_info(&hash);
                let _ = resp.send(result);
            }
            ChainStateCommand::GetSpaceout { outpoint, resp } => {
                let result = chain_state
                    .get_spaceout(&outpoint)
                    .context("could not fetch spaceout");
                let _ = resp.send(result);
            }
            ChainStateCommand::GetSpaceOutpoint { hash, resp } => {
                let result = chain_state
                    .get_space_outpoint(&hash)
                    .context("could not fetch spaceout");
                let _ = resp.send(result);
            }
            ChainStateCommand::GetBlockMeta {
                height_or_hash,
                resp,
            } => {
                let res =
                    Self::get_indexed_block(block_index, height_or_hash, client, rpc, chain_state)
                        .await;
                let _ = resp.send(res);
            }
            ChainStateCommand::GetTxMeta { txid, resp } => {
                let res = Self::get_indexed_tx(block_index, &txid, client, rpc, chain_state).await;
                let _ = resp.send(res);
            }
            ChainStateCommand::EstimateBid { target, resp } => {
                let estimate = chain_state.estimate_bid(target);
                _ = resp.send(estimate);
            }
            ChainStateCommand::GetRollout { target, resp } => {
                let rollouts = chain_state.get_rollout(target);
                _ = resp.send(rollouts);
            }
            ChainStateCommand::VerifyListing { listing, resp } => {
                _ = resp.send(
                    SpacesWallet::verify_listing::<Sha256>(chain_state, &listing).map(|_| ()),
                );
            }
            ChainStateCommand::VerifyEvent { space, event, resp } => {
                _ = resp.send(SpacesWallet::verify_event::<Sha256>(
                    chain_state,
                    &space,
                    event,
                ));
            }
            ChainStateCommand::ProveSpaceout {
                prefer_recent,
                outpoint,
                resp,
            } => {
                _ = resp.send(Self::handle_prove_spaceout(
                    chain_state,
                    outpoint,
                    prefer_recent,
                ));
            }
            ChainStateCommand::ProveSpaceOutpoint {
                space_or_hash,
                resp,
            } => {
                _ = resp.send(Self::handle_prove_space_outpoint(
                    chain_state,
                    &space_or_hash,
                ));
            }
            ChainStateCommand::GetRootAnchors { resp } => {
                _ = resp.send(Self::handle_get_anchor(anchors_path, chain_state));
            }
        }
    }

    fn handle_get_anchor(
        anchors_path: &Option<PathBuf>,
        state: &mut LiveSnapshot,
    ) -> anyhow::Result<Vec<RootAnchor>> {
        if let Some(anchors_path) = anchors_path {
            let anchors: Vec<RootAnchor> = serde_json::from_reader(
                File::open(anchors_path)
                    .or_else(|e| Err(anyhow!("Could not open anchors file: {}", e)))?,
            )
            .or_else(|e| Err(anyhow!("Could not read anchors file: {}", e)))?;
            return Ok(anchors);
        }

        let snapshot = state.inner()?;
        let root = snapshot.compute_root()?;
        let meta: ChainAnchor = snapshot.metadata().try_into()?;
        Ok(vec![RootAnchor {
            root,
            block: ChainAnchor {
                hash: meta.hash,
                height: meta.height,
            },
        }])
    }

    fn handle_prove_space_outpoint(
        state: &mut LiveSnapshot,
        space_or_hash: &str,
    ) -> anyhow::Result<ProofResult> {
        let key = get_space_key(space_or_hash)?;
        let snapshot = state.inner()?;

        // warm up hash cache
        let root = snapshot.compute_root()?;
        let proof = snapshot.prove(&[key.into()], ProofType::Standard)?;

        let mut buf = vec![0u8; 4096];
        let offset = proof.write_to_slice(&mut buf)?;
        buf.truncate(offset);

        Ok(ProofResult {
            proof: buf,
            root: Bytes::new(root.to_vec()),
        })
    }

    /// Determines the optimal snapshot block height for creating a Merkle proof.
    ///
    /// This function finds a suitable historical snapshot that:
    /// 1. Is not older than when the space was last updated.
    /// 2. Falls within [ROOT_ANCHORS_COUNT] range
    /// 3. Skips the oldest trust anchors to prevent the proof from becoming stale too quickly.
    ///
    /// Parameters:
    /// - last_update: Block height when the space was last updated
    /// - tip: Current blockchain tip height
    ///
    /// Returns: Target block height aligned to [COMMIT_BLOCK_INTERVAL]
    fn compute_target_snapshot(last_update: u32, tip: u32) -> u32 {
        const SAFETY_MARGIN: u32 = 8; // Skip oldest trust anchors to prevent proof staleness
        const USABLE_ANCHORS: u32 = ROOT_ANCHORS_COUNT - SAFETY_MARGIN;

        // Align block heights to commit intervals
        let last_update_aligned =
            last_update.div_ceil(COMMIT_BLOCK_INTERVAL) * COMMIT_BLOCK_INTERVAL;
        let current_tip_aligned = (tip / COMMIT_BLOCK_INTERVAL) * COMMIT_BLOCK_INTERVAL;

        // Calculate the oldest allowed snapshot while maintaining safety margin
        let lookback_window = (USABLE_ANCHORS - 1) * COMMIT_BLOCK_INTERVAL;
        let oldest_allowed_snapshot = current_tip_aligned.saturating_sub(lookback_window);

        // Choose the most recent of last update or oldest allowed snapshot
        // to ensure both data freshness and proof verifiability
        std::cmp::max(last_update_aligned, oldest_allowed_snapshot)
    }

    fn handle_prove_spaceout(
        state: &mut LiveSnapshot,
        outpoint: OutPoint,
        prefer_recent: bool,
    ) -> anyhow::Result<ProofResult> {
        let key = OutpointKey::from_outpoint::<Sha256>(outpoint);

        let proof = if !prefer_recent {
            let spaceout = match state.get_spaceout(&outpoint)? {
                Some(spaceot) => spaceot,
                None => {
                    return Err(anyhow!(
                        "Cannot find older proofs for a non-existent utxo (try with oldest: false)"
                    ))
                }
            };
            let target_snapshot = match spaceout.space.as_ref() {
                None => return Ok(ProofResult { proof: vec![], root: Bytes::new(vec![]) }),
                Some(space) => match space.covenant {
                    Covenant::Transfer { expire_height, .. } => {
                        let tip = state.tip.read().expect("read lock").height;
                        let last_update = expire_height.saturating_sub(spaces_protocol::constants::RENEWAL_INTERVAL);
                        Self::compute_target_snapshot(last_update, tip)
                    }
                    _ => return Err(anyhow!("Cannot find older proofs for a non-registered space (try with oldest: false)")),
                }
            };
            state.prove_with_snapshot(&[key.into()], target_snapshot)?
        } else {
            let snapshot = state.inner()?;
            snapshot.prove(&[key.into()], ProofType::Standard)?
        };

        let root = proof.compute_root()?.to_vec();
        info!("Proving with root anchor {}", hex::encode(root.as_slice()));
        let mut buf = vec![0u8; 4096];
        let offset = proof.write_to_slice(&mut buf)?;
        buf.truncate(offset);

        Ok(ProofResult {
            proof: buf,
            root: Bytes::new(root),
        })
    }

    pub async fn handler(
        client: &reqwest::Client,
        rpc: BitcoinRpc,
        anchors_path: Option<PathBuf>,
        mut chain_state: LiveSnapshot,
        mut block_index: Option<LiveSnapshot>,
        mut rx: mpsc::Receiver<ChainStateCommand>,
        mut shutdown: broadcast::Receiver<()>,
    ) {
        loop {
            select! {
                _ = shutdown.recv() => {
                     break;
                }
                Some(cmd) = rx.recv() => {
                    Self::handle_command(client, &rpc, &anchors_path, &mut chain_state, &mut block_index, cmd).await;
                }
            }
        }

        info!("Shutting down chain state...");
    }

    pub async fn estimate_bid(&self, target: usize) -> anyhow::Result<u64> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::EstimateBid { target, resp })
            .await?;
        resp_rx.await?
    }

    pub async fn verify_listing(&self, listing: Listing) -> anyhow::Result<()> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::VerifyListing { listing, resp })
            .await?;
        resp_rx.await?
    }

    pub async fn verify_event(&self, space: &str, event: NostrEvent) -> anyhow::Result<NostrEvent> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::VerifyEvent {
                space: space.to_string(),
                event,
                resp,
            })
            .await?;
        resp_rx.await?
    }

    pub async fn prove_spaceout(
        &self,
        outpoint: OutPoint,
        prefer_recent: bool,
    ) -> anyhow::Result<ProofResult> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::ProveSpaceout {
                outpoint,
                prefer_recent: prefer_recent,
                resp,
            })
            .await?;
        resp_rx.await?
    }

    pub async fn prove_space_outpoint(&self, space_or_hash: &str) -> anyhow::Result<ProofResult> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::ProveSpaceOutpoint {
                space_or_hash: space_or_hash.to_string(),
                resp,
            })
            .await?;
        resp_rx.await?
    }

    pub async fn get_root_anchors(&self) -> anyhow::Result<Vec<RootAnchor>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::GetRootAnchors { resp })
            .await?;
        resp_rx.await?
    }

    pub async fn get_rollout(&self, target: usize) -> anyhow::Result<Vec<RolloutEntry>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::GetRollout { target, resp })
            .await?;
        resp_rx.await?
    }

    pub async fn get_space(&self, hash: SpaceKey) -> anyhow::Result<Option<FullSpaceOut>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::GetSpace { hash, resp })
            .await?;
        resp_rx.await?
    }

    pub async fn get_space_outpoint(&self, hash: SpaceKey) -> anyhow::Result<Option<OutPoint>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::GetSpaceOutpoint { hash, resp })
            .await?;
        resp_rx.await?
    }

    pub async fn check_package(
        &self,
        txs: Vec<String>,
    ) -> anyhow::Result<Vec<Option<TxChangeSet>>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::CheckPackage { txs, resp })
            .await?;
        resp_rx.await?
    }

    pub async fn get_server_info(&self) -> anyhow::Result<ServerInfo> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::GetServerInfo { resp })
            .await?;
        resp_rx.await?
    }

    pub async fn get_spaceout(&self, outpoint: OutPoint) -> anyhow::Result<Option<SpaceOut>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::GetSpaceout { outpoint, resp })
            .await?;
        resp_rx.await?
    }

    pub async fn get_block_meta(
        &self,
        height_or_hash: HeightOrHash,
    ) -> anyhow::Result<BlockMetaWithHash> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::GetBlockMeta {
                height_or_hash,
                resp,
            })
            .await?;
        resp_rx.await?
    }

    pub async fn get_tx_meta(&self, txid: Txid) -> anyhow::Result<Option<TxEntry>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::GetTxMeta { txid, resp })
            .await?;
        resp_rx.await?
    }
}

fn get_space_key(space_or_hash: &str) -> Result<SpaceKey, ErrorObjectOwned> {
    if space_or_hash.len() != 64 {
        return Ok(SpaceKey::from(Sha256::hash(
            SLabel::try_from(space_or_hash)
                .map_err(|_| {
                    ErrorObjectOwned::owned(
                        -1,
                        "expected a space name prefixed with @ or a hex encoded space hash",
                        None::<String>,
                    )
                })?
                .as_ref(),
        )));
    }

    let mut hash = [0u8; 32];
    hex::decode_to_slice(space_or_hash, &mut hash).map_err(|_| {
        ErrorObjectOwned::owned(
            -1,
            "expected a space name prefixed with @ or a hex encoded space hash",
            None::<String>,
        )
    })?;

    Ok(SpaceKey::from(hash))
}

async fn get_server_info(
    client: &reqwest::Client,
    rpc: &BitcoinRpc,
    tip: ChainAnchor,
) -> anyhow::Result<ServerInfo> {
    let info: BlockchainInfo = rpc
        .send_json(client, &rpc.get_blockchain_info())
        .await
        .map_err(|e| anyhow!("Could not retrieve blockchain info ({})", e))?;

    let network = info.chain;
    let network = ExtendedNetwork::from_core_arg(&network)
        .map_err(|_| anyhow!("Unknown network ({})", &network))?;

    let start_block = match network {
        ExtendedNetwork::Mainnet => 871_222,
        ExtendedNetwork::Testnet | ExtendedNetwork::Testnet4 => 50_000,
        _ => 0,
    };

    Ok(ServerInfo {
        network,
        tip,
        chain: ChainInfo {
            blocks: info.blocks,
            headers: info.headers,
        },
        ready: info.headers_synced.unwrap_or(true),
        progress: calc_progress(start_block, tip.height, info.headers),
    })
}
