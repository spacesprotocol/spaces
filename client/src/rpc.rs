use std::{
    collections::BTreeMap, fs, fs::File, io::Write, net::SocketAddr, path::PathBuf, str::FromStr,
    sync::Arc,
};
use std::collections::HashSet;
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
use serde::{Deserialize, Serialize};
use spacedb::tx::ProofType;
use spaces_protocol::{
    bitcoin,
    bitcoin::{
        bip32::Xpriv,
        Network::{Regtest, Testnet},
        OutPoint,
    },
    constants::ChainAnchor,
    hasher::{KeyHasher, OutpointKey, SpaceKey},
    prepare::SpacesSource,
    slabel::SLabel,
    validate::TxChangeSet,
    Bytes, Covenant, FullSpaceOut, SpaceOut,
};
use spaces_wallet::{
    bdk_wallet as bdk, bdk_wallet::template::Bip86, bitcoin::hashes::Hash as BitcoinHash,
    bitcoin::secp256k1::schnorr,
    export::WalletExport, Balance, DoubleUtxo, Listing, SpacesWallet,
    WalletConfig, WalletDescriptors, WalletOutput,
};
pub use spaces_wallet::Subject;
use tokio::{
    select,
    sync::{broadcast, mpsc, oneshot, RwLock},
    task::JoinSet,
};
use spaces_protocol::bitcoin::ScriptBuf;
use spaces_protocol::hasher::Hash;
use spaces_nums::{NumSource, FullNumOut, NumOut, Commitment, CommitmentTipKey, CommitmentKey, DelegatorKey, NumOutpointKey, RootAnchor, ChainProofRequest, NumKeyKind};
use spaces_nums::snumeric::SNumeric;
use spaces_nums::num_id::NumId;
use spaces_wallet::bitcoin::hashes::sha256;
use crate::auth::BasicAuthLayer;
use crate::wallets::WalletInfoWithProgress;
use crate::{
    calc_progress,
    checker::TxChecker,
    client::{BlockMeta, NumBlockMeta, TxEntry, BlockchainInfo},
    config::ExtendedNetwork,
    deserialize_base64, serialize_base64,
    source::BitcoinRpc,
    wallets::{
        AddressKind, ListNumsResponse, ListSpacesResponse, RpcWallet, TxInfo, TxResponse,
        WalletCommand, WalletResponse,
    },
};
use crate::store::chain::{Chain, COMMIT_BLOCK_INTERVAL, CACHED_SNAPSHOT_LOOKBACK};
use crate::store::Sha256;
use crate::store::spaces::RolloutEntry;

pub(crate) type Responder<T> = oneshot::Sender<T>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ServerInfo {
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub network: ExtendedNetwork,
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub tip: ChainAnchor,
    pub chain: ChainInfo,
    pub ready: bool,
    pub progress: f32,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ChainInfo {
    pub blocks: u32,
    pub headers: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(untagged)]
pub enum HeightOrHash {
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    Hash(BlockHash),
    Height(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct BlockMetaWithHash {
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub hash: BlockHash,
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    #[serde(flatten)]
    pub block_meta: BlockMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct NumBlockMetaWithHash {
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub hash: BlockHash,
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    #[serde(flatten)]
    pub block_meta: NumBlockMeta,
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
    GetCommitment {
        subject: Subject,
        root: Option<Hash>,
        resp: Responder<anyhow::Result<Option<Commitment>>>,
    },
    GetDelegation {
        subject: Subject,
        resp: Responder<anyhow::Result<Option<NumId>>>,
    },
    GetDelegator {
        subject: Subject,
        resp: Responder<anyhow::Result<Option<SLabel>>>,
    },
    GetNum {
        subject: Subject,
        resp: Responder<anyhow::Result<Option<FullNumOut>>>,
    },
    GetNumOutpoint {
        subject: Subject,
        resp: Responder<anyhow::Result<Option<OutPoint>>>,
    },
    GetNumOut {
        outpoint: OutPoint,
        resp: Responder<anyhow::Result<Option<NumOut>>>,
    },
    GetTxMeta {
        txid: Txid,
        resp: Responder<anyhow::Result<Option<TxEntry>>>,
    },
    GetBlockMeta {
        height_or_hash: HeightOrHash,
        resp: Responder<anyhow::Result<BlockMetaWithHash>>,
    },
    GetNumBlockMeta {
        height_or_hash: HeightOrHash,
        resp: Responder<anyhow::Result<NumBlockMetaWithHash>>,
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
    VerifySchnorr {
        subject: Subject,
        message: Vec<u8>,
        signature: Vec<u8>,
        resp: Responder<anyhow::Result<()>>,
    },
    BuildChainProof {
        request: ChainProofRequest,
        prefer_recent: bool,
        resp: Responder<anyhow::Result<ChainProofResult>>,
    },
    GetRootAnchors {
        resp: Responder<anyhow::Result<Vec<RootAnchor>>>,
    },
    DebugSetExpireHeight {
        space: SLabel,
        expire_height: u32,
        resp: Responder<anyhow::Result<()>>,
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

    #[method(name = "getnum")]
    async fn get_num(
        &self,
        subject: Subject,
    ) -> Result<Option<FullNumOut>, ErrorObjectOwned>;

    #[method(name = "getnumowner")]
    async fn get_num_owner(
        &self,
        subject: Subject,
    ) -> Result<Option<OutPoint>, ErrorObjectOwned>;

    #[method(name = "getnumout")]
    async fn get_numout(&self, outpoint: OutPoint) -> Result<Option<NumOut>, ErrorObjectOwned>;

    #[method(name = "getcommitment")]
    async fn get_commitment(&self, subject: Subject, root: Option<sha256::Hash>) -> Result<Option<Commitment>, ErrorObjectOwned>;

    #[method(name = "getdelegation")]
    async fn get_delegation(&self, subject: Subject) -> Result<Option<NumId>, ErrorObjectOwned>;


    #[method(name = "getdelegator")]
    async fn get_delegator(&self, subject: Subject) -> Result<Option<SLabel>, ErrorObjectOwned>;

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

    #[method(name = "getnumblockmeta")]
    async fn get_num_block_meta(
        &self,
        height_or_hash: HeightOrHash,
    ) -> Result<NumBlockMetaWithHash, ErrorObjectOwned>;

    #[method(name = "gettxmeta")]
    async fn get_tx_meta(&self, txid: Txid) -> Result<Option<TxEntry>, ErrorObjectOwned>;

    #[method(name = "listwallets")]
    async fn list_wallets(&self) -> Result<Vec<String>, ErrorObjectOwned>;

    #[method(name = "walletload")]
    async fn wallet_load(&self, name: &str) -> Result<(), ErrorObjectOwned>;

    #[method(name = "walletimport")]
    async fn wallet_import(&self, wallet: WalletExport) -> Result<(), ErrorObjectOwned>;


    #[method(name = "walletcanoperate")]
    async fn wallet_can_operate(
        &self,
        wallet: &str,
        subject: Subject,
    ) -> Result<bool, ErrorObjectOwned>;

    #[method(name = "walletsignschnorr")]
    async fn wallet_sign_schnorr(
        &self,
        wallet: &str,
        subject: Subject,
        message: Bytes,
    ) -> Result<Bytes, ErrorObjectOwned>;

    #[method(name = "verifyschnorr")]
    async fn verify_schnorr(
        &self,
        subject: Subject,
        message: Bytes,
        signature: Bytes,
    ) -> Result<bool, ErrorObjectOwned>;

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

    #[method(name = "walletincrementaddress")]
    async fn wallet_increment_address(
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

    #[method(name = "buildchainproof")]
    async fn build_chain_proof(
        &self,
        request: ChainProofRequest,
        prefer_recent: Option<bool>,
    ) -> Result<ChainProofResult, ErrorObjectOwned>;

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

    #[method(name = "walletlistnums")]
    async fn wallet_list_nums(
        &self,
        wallet: &str,
        kind: Option<String>,
    ) -> Result<ListNumsResponse, ErrorObjectOwned>;

    #[method(name = "walletlistunspent")]
    async fn wallet_list_unspent(
        &self,
        wallet: &str,
    ) -> Result<Vec<WalletOutput>, ErrorObjectOwned>;

    #[method(name = "walletlistbidouts")]
    async fn wallet_list_bidouts(&self, wallet: &str) -> Result<Vec<DoubleUtxo>, ErrorObjectOwned>;

    #[method(name = "walletgetbalance")]
    async fn wallet_get_balance(&self, wallet: &str) -> Result<Balance, ErrorObjectOwned>;

    #[method(name = "getfallback")]
    async fn get_fallback(
        &self,
        subject: Subject,
    ) -> Result<Option<FallbackResponse>, ErrorObjectOwned>;

    /// Debug method to set a space's expire height (regtest only)
    #[method(name = "debugsetexpireheight")]
    async fn debug_set_expire_height(&self, space: &str, expire_height: u32) -> Result<(), ErrorObjectOwned>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct FallbackResponse {
    /// Raw data encoded as base64
    pub data: String,
    /// Parsed SIP-7 records, if data is valid
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub records: Option<sip7::RecordSet>,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct RpcWalletTxBuilder {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bidouts: Option<u8>,
    pub requests: Vec<RpcWalletRequest>,
    #[cfg_attr(feature = "schema", schemars(with = "Option<f64>"))]
    pub fee_rate: Option<FeeRate>,
    #[cfg_attr(feature = "schema", schemars(with = "Option<u64>"))]
    pub dust: Option<Amount>,
    pub force: bool,
    pub confirmed_only: bool,
    pub skip_tx_check: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "request")]
pub enum RpcWalletRequest {
    #[serde(rename = "open")]
    Open(OpenParams),
    #[serde(rename = "bid")]
    Bid(BidParams),
    #[serde(rename = "register")]
    Register(RegisterParams),
    #[serde(rename = "transfer")]
    Transfer(TransferSpacesParams),
    #[serde(rename = "createnum")]
    CreateNum(CreateNumParams),
    #[serde(rename = "operate")]
    Operate(OperateParams),
    #[serde(rename = "commit")]
    Commit(CommitParams),
    #[serde(rename = "delegate")]
    Delegate(DelegateParams),
    #[serde(rename = "setfallback")]
    SetFallback(SetFallbackParams),
    #[serde(rename = "send")]
    SendCoins(SendCoinsParams),
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct TransferSpacesParams {
    /// List of spaces and/or PTRs to transfer
    #[cfg_attr(feature = "schema", schemars(with = "Vec<String>"))]
    pub spaces: Vec<Subject>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,

    /// Hex-encoded 32-byte secret key for transferring nums not owned by the wallet
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CreateNumParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub bind_spk: Option<ScriptBuf>,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct OperateParams {
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub subject: Subject,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct DelegateParams {
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub subject: Subject,
    pub to: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CommitParams {
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub subject: Subject,
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub root: Option<sha256::Hash>,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SetFallbackParams {
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub subject: Subject,
    pub data: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SendCoinsParams {
    #[cfg_attr(feature = "schema", schemars(with = "u64"))]
    pub amount: Amount,
    pub to: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct OpenParams {
    pub name: String,
    pub amount: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct BidParams {
    pub name: String,
    pub amount: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct TransferParams {
    pub name: String,
    pub to: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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


/// Combined proof result for a chain proof request containing subtrees from both
/// spaces and ptrs trees at the same snapshot height.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ChainProofResult {
    /// The block anchor these proofs are generated against
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub block: ChainAnchor,
    /// Spaces tree root
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub spaces_root: Bytes,
    /// Subtree proof for the spaces tree (base64)
    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub spaces_proof: Vec<u8>,
    /// PTRs tree root
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub ptrs_root: Bytes,
    /// Subtree proof for the ptrs tree (base64)
    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub ptrs_proof: Vec<u8>,
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
        self.setup_new_wallet(name.to_string(), mnemonic.to_string(), start_block)?;
        self.load_wallet(name).await?;
        Ok(mnemonic.to_string())
    }

    pub async fn recover_wallet(&self, client: &reqwest::Client, name: &str, mnemonic: &str) -> anyhow::Result<()> {
        let start_block = self.get_wallet_start_block(client).await?;
        self.setup_new_wallet(name.to_string(), mnemonic.to_string(), start_block)?;
        self.load_wallet(name).await?;
        Ok(())
    }

    fn setup_new_wallet(
        &self,
        name: String,
        mnemonic: String,
        start_block: BlockId,
    ) -> anyhow::Result<()> {
        let wallet_path = self.data_dir.join(&name);
        if wallet_path.exists() {
            return Err(anyhow!(format!("Wallet `{}` already exists", name)));
        }

        let export = self.wallet_from_mnemonic(name.clone(), mnemonic, start_block)?;
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
        start_block: BlockId,
    ) -> anyhow::Result<WalletExport> {
        let (network, _) = self.fallback_network();
        let xpriv = Self::descriptor_from_mnemonic(network, &mnemonic)?;

        let (external, internal) = Self::default_descriptors(xpriv);
        let tmp = bdk::Wallet::create(external, internal)
            .network(network)
            .create_wallet_no_persist()?;
        let export =
            WalletExport::export_wallet(&tmp, &name, start_block.height).map_err(|e| anyhow!(e))?;

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

            let mut module = self.clone().into_rpc();
            let methods: Vec<String> = module.method_names().map(|s| s.to_string()).collect();
            module.register_method("rpc.discover", move |_, _| {
                serde_json::json!({ "methods": methods })
            }).expect("register rpc.discover");

            #[cfg(feature = "schema")]
            {
                let spec = crate::rpc_schema::full_spec();
                module.register_method("rpc.schema", move |_, _| {
                    spec.clone()
                }).expect("register rpc.schema");
            }

            let handle = listener.start(module);

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

    async fn get_num(&self, subject: Subject) -> Result<Option<FullNumOut>, ErrorObjectOwned> {
        let info = self
            .store
            .get_ptr(subject)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(info)
    }

    async fn get_num_owner(&self, subject: Subject) -> Result<Option<OutPoint>, ErrorObjectOwned> {
        let info = self
            .store
            .get_ptr_outpoint(subject)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(info)
    }

    async fn get_numout(&self, outpoint: OutPoint) -> Result<Option<NumOut>, ErrorObjectOwned> {
        let spaceout = self
            .store
            .get_numout(outpoint)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(spaceout)
    }

    async fn get_commitment(&self, subject: Subject, root: Option<sha256::Hash>) -> Result<Option<Commitment>, ErrorObjectOwned> {
        let c = self
            .store
            .get_commitment(subject, root.map(|r| *r.as_ref()))
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(c)
    }

    async fn get_delegation(&self, subject: Subject) -> Result<Option<NumId>, ErrorObjectOwned> {
        let delegation = self
            .store
            .get_delegation(subject)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(delegation)
    }

    async fn get_delegator(&self, subject: Subject) -> Result<Option<SLabel>, ErrorObjectOwned> {
        let delegator = self
            .store
            .get_delegator(subject)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(delegator)
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

    async fn get_num_block_meta(
        &self,
        height_or_hash: HeightOrHash,
    ) -> Result<NumBlockMetaWithHash, ErrorObjectOwned> {
        let data = self
            .store
            .get_num_block_meta(height_or_hash)
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

    async fn wallet_sign_schnorr(
        &self,
        wallet: &str,
        subject: Subject,
        message: Bytes,
    ) -> Result<Bytes, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_sign_schnorr(subject, message.to_vec())
            .await
            .map(|sig| Bytes::new(sig.as_ref().to_vec()))
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_can_operate(
        &self,
        wallet: &str,
        subject: Subject,
    ) -> Result<bool, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_can_operate(subject)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn verify_schnorr(
        &self,
        subject: Subject,
        message: Bytes,
        signature: Bytes,
    ) -> Result<bool, ErrorObjectOwned> {
        self.store
            .verify_schnorr(subject, message.to_vec(), signature.to_vec())
            .await
            .map(|_| true)
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
            .recover_wallet(&self.client, name, &mnemonic)
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

    async fn wallet_increment_address(
        &self,
        wallet: &str,
        kind: AddressKind,
    ) -> Result<String, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_increment_address(kind)
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

    async fn build_chain_proof(
        &self,
        request: ChainProofRequest,
        prefer_recent: Option<bool>,
    ) -> Result<ChainProofResult, ErrorObjectOwned> {
        self.store
            .build_chain_proof(request, prefer_recent.unwrap_or(false))
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

    async fn wallet_list_nums(
        &self,
        wallet: &str,
        kind: Option<String>,
    ) -> Result<ListNumsResponse, ErrorObjectOwned> {
        let external = kind.as_deref() == Some("external");
        self.wallet(&wallet)
            .await?
            .send_list_nums(external)
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

    async fn get_fallback(&self, subject: Subject) -> Result<Option<FallbackResponse>, ErrorObjectOwned> {
        let data = match &subject {
            Subject::Label(label) if !label.is_numeric() => {
                let space_hash = SpaceKey::from(Sha256::hash(label.as_ref()));
                let fso = self.store.get_space(space_hash).await
                    .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<String>))?;
                fso.and_then(|fso| {
                    if let Some(space) = &fso.spaceout.space {
                        if let Covenant::Transfer { data, .. } = &space.covenant {
                            return data.as_ref().map(|b| b.clone().to_vec());
                        }
                    }
                    None
                })
            }
            _ => {
                let fpt = self.store.get_ptr(subject).await
                    .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<String>))?;
                fpt.and_then(|fpt| fpt.numout.num.data.map(|b| b.to_vec()))
            }
        };

        match data {
            None => Ok(None),
            Some(raw) => {
                use base64::Engine;
                let encoded = base64::engine::general_purpose::STANDARD.encode(&raw);
                let rs = sip7::RecordSet::new(raw);
                let records = if rs.unpack().is_ok() { Some(rs) } else { None };
                Ok(Some(FallbackResponse {
                    data: encoded,
                    records,
                }))
            }
        }
    }

    async fn debug_set_expire_height(&self, space: &str, expire_height: u32) -> Result<(), ErrorObjectOwned> {
        // Only allow on regtest
        let info = self.store.get_server_info().await
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<String>))?;
        if info.network != ExtendedNetwork::Regtest {
            return Err(ErrorObjectOwned::owned(-1, "debug_set_expire_height is only available on regtest", None::<String>));
        }

        let space_label = SLabel::from_str(space)
            .map_err(|e| ErrorObjectOwned::owned(-1, format!("Invalid space name: {}", e), None::<String>))?;

        self.store
            .debug_set_expire_height(space_label, expire_height)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }
}

impl AsyncChainState {
    pub fn new(sender: mpsc::Sender<ChainStateCommand>) -> Self {
        Self { sender }
    }

    async fn get_indexed_tx(
        state: &mut Chain,
        txid: &Txid,
        client: &reqwest::Client,
        rpc: &BitcoinRpc,
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
            state,
            HeightOrHash::Hash(block_hash),
            client,
            rpc,
        )
            .await?;

        Ok(block
            .block_meta
            .tx_meta
            .into_iter()
            .find(|tx| &tx.changeset.txid == txid))
    }

    async fn get_indexed_block(
        state: &mut Chain,
        height_or_hash: HeightOrHash,
        client: &reqwest::Client,
        rpc: &BitcoinRpc,
    ) -> Result<BlockMetaWithHash, anyhow::Error> {
        // let index = state
        //     .as_mut()
        //     .ok_or_else(|| anyhow!("block index must be enabled"))?;
        let hash = match height_or_hash {
            HeightOrHash::Hash(hash) => hash,
            HeightOrHash::Height(height) => rpc
                .send_json(client, &rpc.get_block_hash(height))
                .await
                .map_err(|e| anyhow!("Could not retrieve block hash ({})", e))?,
        };

        if let Some(block_meta) = state.get_spaces_block(hash)? {
            return Ok(block_meta);
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

        let tip = state.tip();
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

    async fn get_indexed_ptr_block(
        state: &mut Chain,
        height_or_hash: HeightOrHash,
        client: &reqwest::Client,
        rpc: &BitcoinRpc,
    ) -> Result<NumBlockMetaWithHash, anyhow::Error> {
        let hash = match height_or_hash {
            HeightOrHash::Hash(hash) => hash,
            HeightOrHash::Height(height) => rpc
                .send_json(client, &rpc.get_block_hash(height))
                .await
                .map_err(|e| anyhow!("Could not retrieve block hash ({})", e))?,
        };

        if let Some(block_meta) = state.get_nums_block(hash)? {
            return Ok(block_meta);
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

        let ptrs_tip = state.nums_tip();
        if height > ptrs_tip.height {
            return Err(anyhow!(
                "Nums index is syncing at height {}, requested block height {}",
                ptrs_tip.height,
                height
            ));
        }
        Ok(NumBlockMetaWithHash {
            hash,
            block_meta: NumBlockMeta {
                height,
                tx_meta: Vec::new(),
            },
        })
    }

    pub async fn handle_command(
        client: &reqwest::Client,
        rpc: &BitcoinRpc,
        anchors_path: &Option<PathBuf>,
        state: &mut Chain,
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

                let tip = state.tip();
                let mut emulator = TxChecker::new(state);
                let result = emulator.apply_package(tip.height + 1, txs);
                let _ = resp.send(result);
            }
            ChainStateCommand::GetServerInfo { resp } => {
                let tip = state.tip();
                _ = resp.send(get_server_info(client, rpc, tip).await)
            }
            ChainStateCommand::GetSpace { hash, resp } => {
                let result = state.get_space_info(&hash);
                let _ = resp.send(result);
            }
            ChainStateCommand::GetSpaceout { outpoint, resp } => {
                let result = state
                    .get_spaceout(&outpoint)
                    .context("could not fetch spaceout");
                let _ = resp.send(result);
            }
            ChainStateCommand::GetSpaceOutpoint { hash, resp } => {
                let result = state
                    .get_space_outpoint(&hash)
                    .context("could not fetch spaceout");
                let _ = resp.send(result);
            }
            ChainStateCommand::GetNum { subject, resp } => {
                let result = resolve_num_id(state, &subject)
                    .and_then(|id| state.get_num_info(&id));
                let _ = resp.send(result);
            }
            ChainStateCommand::GetNumOutpoint { subject, resp } => {
                let result = resolve_num_id(state, &subject)
                    .and_then(|id| state.get_num_outpoint_by_id(&id).context("could not fetch numout"));
                let _ = resp.send(result);
            }
            ChainStateCommand::GetCommitment { subject, root, resp } => {
                let result = get_commitment(state, &subject, root);
                let _ = resp.send(result);
            }
            ChainStateCommand::GetDelegation { subject, resp } => {
                let result = get_delegation(state, &subject);
                let _ = resp.send(result);
            }
            ChainStateCommand::GetDelegator { subject, resp } => {
                let result = resolve_num_id(state, &subject)
                    .and_then(|id| state.get_delegator(&DelegatorKey::from_id::<Sha256>(id))
                        .map_err(|e| anyhow!("could not get delegator: {}", e)));
                let _ = resp.send(result);
            }
            ChainStateCommand::GetNumOut { outpoint, resp } => {
                let result = state
                    .get_numout(&outpoint)
                    .context("could not fetch numouts");
                let _ = resp.send(result);
            }
            ChainStateCommand::GetBlockMeta {
                height_or_hash,
                resp,
            } => {
                let res =
                    Self::get_indexed_block(state, height_or_hash, client, rpc)
                        .await;
                let _ = resp.send(res);
            }
            ChainStateCommand::GetNumBlockMeta {
                height_or_hash,
                resp,
            } => {
                let res =
                    Self::get_indexed_ptr_block(state, height_or_hash, client, rpc)
                        .await;
                let _ = resp.send(res);
            }
            ChainStateCommand::GetTxMeta { txid, resp } => {
                let res = Self::get_indexed_tx(state, &txid, client, rpc).await;
                let _ = resp.send(res);
            }
            ChainStateCommand::EstimateBid { target, resp } => {
                let estimate = state.estimate_bid(target);
                _ = resp.send(estimate);
            }
            ChainStateCommand::GetRollout { target, resp } => {
                let rollouts = state.get_rollout(target);
                _ = resp.send(rollouts);
            }
            ChainStateCommand::VerifyListing { listing, resp } => {
                _ = resp.send(
                    SpacesWallet::verify_listing::<Sha256>(state, &listing).map(|_| ()),
                );
            }
            ChainStateCommand::VerifySchnorr { subject, message, signature, resp } => {
                let result = (|| {
                    let sig = schnorr::Signature::from_slice(&signature)
                        .map_err(|_| anyhow!("Invalid signature format"))?;
                    SpacesWallet::verify_schnorr::<Sha256, _>(state, subject, &message, &sig)
                })();
                _ = resp.send(result);
            }
            ChainStateCommand::BuildChainProof {
                request,
                prefer_recent,
                resp,
            } => {
                _ = resp.send(Self::handle_build_chain_proof(
                    state,
                    request,
                    prefer_recent,
                ));
            }
            ChainStateCommand::GetRootAnchors { resp } => {
                _ = resp.send(Self::handle_get_anchor(anchors_path, state));
            }
            ChainStateCommand::DebugSetExpireHeight { space, expire_height, resp } => {
                _ = resp.send(Self::handle_debug_set_expire_height(state, space, expire_height));
            }
        }
    }

    fn handle_debug_set_expire_height(
        state: &mut Chain,
        space: SLabel,
        expire_height: u32,
    ) -> anyhow::Result<()> {
        let space_key = SpaceKey::from(Sha256::hash(space.as_ref()));
        let outpoint = state.get_space_outpoint(&space_key)?
            .ok_or_else(|| anyhow::anyhow!("Space not found: {}", space))?;
        let mut spaceout = state.get_spaceout(&outpoint)?
            .ok_or_else(|| anyhow::anyhow!("Spaceout not found for outpoint"))?;

        // Update expire_height in the covenant
        if let Some(ref mut space_data) = spaceout.space {
            match &mut space_data.covenant {
                Covenant::Transfer { expire_height: ref mut eh, .. } => {
                    *eh = expire_height;
                }
                _ => return Err(anyhow::anyhow!("Space is not in Transfer covenant (not owned)")),
            }
        } else {
            return Err(anyhow::anyhow!("SpaceOut has no space data"));
        }

        // Write back to database
        let outpoint_key = OutpointKey::from_outpoint::<Sha256>(outpoint);
        state.insert_spaceout(outpoint_key, spaceout);
        Ok(())
    }

    fn handle_get_anchor(
        anchors_path: &Option<PathBuf>,
        state: &mut Chain,
    ) -> anyhow::Result<Vec<RootAnchor>> {
        if let Some(anchors_path) = anchors_path {
            let anchors: Vec<RootAnchor> = serde_json::from_reader(
                File::open(anchors_path)
                    .or_else(|e| Err(anyhow!("Could not open anchors file: {}", e)))?,
            )
                .or_else(|e| Err(anyhow!("Could not read anchors file: {}", e)))?;
            return Ok(anchors);
        }

        let snapshot = state.spaces_inner()?;
        let spaces_root = snapshot.compute_root()?;
        let meta: ChainAnchor = snapshot.metadata().try_into()?;

        // Try to compute PTR root if we're past PTR genesis
        let ptrs_root = if state.can_scan_nums(meta.height) {
            state.nums_mut().state.inner()
                .ok()
                .and_then(|s| s.compute_root().ok())
        } else {
            None
        };

        Ok(vec![RootAnchor {
            spaces_root,
            nums_root: ptrs_root,
            block: ChainAnchor {
                hash: meta.hash,
                height: meta.height,
            },
        }])
    }

    /// Returns the height for a fixed cached snapshot (~1 week behind tip),
    /// aligned to COMMIT_BLOCK_INTERVAL. Returns None if the chain is too young.
    fn cached_snapshot_height(tip_height: u32) -> Option<u32> {
        let tip_aligned = tip_height - (tip_height % COMMIT_BLOCK_INTERVAL);
        tip_aligned.checked_sub(CACHED_SNAPSHOT_LOOKBACK)
    }

    fn handle_build_chain_proof(
        state: &mut Chain,
        mut request: ChainProofRequest,
        prefer_recent: bool,
    ) -> anyhow::Result<ChainProofResult> {
        let mut most_recent_update = 0u32;
        let mut space_tree_keys: HashSet<Hash> = HashSet::new();
        let mut num_tree_keys: HashSet<Hash> = HashSet::new();

        for space in request.spaces {
            if space.is_numeric() {
                request.nums.push(NumKeyKind::Num(space.try_into()?));
                continue;
            }

            let space_key = SpaceKey::from(Sha256::hash(space.as_ref()));
            let Some(fso) = state.get_space_info(&space_key)? else {
                // non-existence proof
                space_tree_keys.insert(space_key.into());
                continue;
            };

            let outpoint_key = OutpointKey::from_outpoint::<Sha256>(fso.outpoint());
            space_tree_keys.insert(outpoint_key.into());
            if let Some(space) = &fso.spaceout.space {
                if let Covenant::Transfer { expire_height, .. } = &space.covenant {
                    let last_update = expire_height
                        .saturating_sub(spaces_protocol::constants::RENEWAL_INTERVAL);
                    most_recent_update = std::cmp::max(most_recent_update, last_update);
                }
            }

            let id = NumId::from_spk::<Sha256>(fso.spaceout.script_pubkey);
            request.nums.push(NumKeyKind::Id(id));
        }

        for key in request.nums {
            match key {
                NumKeyKind::Num(numeric) => {
                    let id = state.get_num_id(&numeric)?;
                    if let Some(id) = id {
                        let fpt = state.get_num_info(&id)?
                            .expect("num id must exist if numeric exists");
                        num_tree_keys.insert(
                            NumOutpointKey::from_outpoint::<Sha256>(fpt.outpoint()).into()
                        );
                        most_recent_update = std::cmp::max(most_recent_update, fpt.numout.num.last_update);

                        // insert delegate information
                        let operator_id = NumId::from_spk::<Sha256>(fpt.numout.script_pubkey);
                        let operator = state.get_num_info(&operator_id)?;
                        if let Some(operator) = operator {
                            num_tree_keys.insert(
                                NumOutpointKey::from_outpoint::<Sha256>(operator.outpoint()).into()
                            );

                            most_recent_update = std::cmp::max(most_recent_update, operator.numout.num.last_update);

                        } else {
                            num_tree_keys.insert(operator_id.into());
                        }

                    }
                }
                NumKeyKind::Id(id) => {
                    if let Some(fpt) = state.get_num_info(&id)? {
                        num_tree_keys.insert(
                            NumOutpointKey::from_outpoint::<Sha256>(fpt.outpoint()).into()
                        );
                        most_recent_update = std::cmp::max(most_recent_update, fpt.numout.num.last_update);

                        // insert delegate information
                        let operator_id = NumId::from_spk::<Sha256>(fpt.numout.script_pubkey);
                        let operator = state.get_num_info(&operator_id)?;
                        if let Some(operator) = operator {
                            num_tree_keys.insert(
                                NumOutpointKey::from_outpoint::<Sha256>(operator.outpoint()).into()
                            );
                            most_recent_update = std::cmp::max(most_recent_update, operator.numout.num.last_update);
                        } else {
                            num_tree_keys.insert(operator_id.into());
                        }
                    } else {
                        // non-existence proof
                        num_tree_keys.insert(id.into());
                    }
                }
                NumKeyKind::Commitment(k) => {
                    num_tree_keys.insert(k.into());
                },
                NumKeyKind::CommitmentTip(k) => {
                    num_tree_keys.insert(k.into());
                },
            }
        }

        let tip = state.tip();
        let last_committed = tip.height - (tip.height % COMMIT_BLOCK_INTERVAL);
        if most_recent_update > last_committed {
            let next_commit = last_committed + COMMIT_BLOCK_INTERVAL;
            let blocks_remaining = next_commit - tip.height;
            return Err(anyhow!(
                "Cannot prove: data updated at block {} is not yet committed. Try again in {} block(s)",
                most_recent_update, blocks_remaining
            ));
        }

        let num_tree_keys : Vec<_> = num_tree_keys.into_iter().collect();
        let space_tree_keys : Vec<_> = space_tree_keys.into_iter().collect();

        let cached_height = Self::cached_snapshot_height(tip.height);
        let use_cached = !prefer_recent
            && cached_height.is_some_and(|h| most_recent_update <= h);

        let (spaces_proof, spaces_root, block_anchor, ptrs_proof, ptrs_root) = if use_cached {
            let height = cached_height.unwrap();
            let snapshot = state.snapshot_at(height)?;

            let spaces_anchor: ChainAnchor = snapshot.spaces.metadata().try_into()?;
            let spaces_proof = snapshot.spaces.prove(&space_tree_keys, ProofType::Standard)?;
            let spaces_root = spaces_proof.compute_root()?;

            let ptrs_anchor: ChainAnchor = snapshot.nums.metadata().try_into()?;
            if spaces_anchor != ptrs_anchor {
                return Err(anyhow!(
                    "Spaces and PTRs snapshots at height {} have mismatched anchors",
                    height
                ));
            }
            let ptrs_proof = snapshot.nums.prove(&num_tree_keys, ProofType::Standard)?;
            let ptrs_root = ptrs_proof.compute_root()?;

            (spaces_proof, spaces_root, spaces_anchor, ptrs_proof, ptrs_root)
        } else {
            let spaces_snapshot = state.spaces_inner()?;
            let spaces_root = spaces_snapshot.compute_root()?;
            let spaces_anchor: ChainAnchor = spaces_snapshot.metadata().try_into()?;
            let spaces_proof = spaces_snapshot.prove(&space_tree_keys, ProofType::Standard)?;

            let ptrs_snapshot = state.nums_mut().state.inner()?;
            let ptrs_anchor: ChainAnchor = ptrs_snapshot.metadata().try_into()?;
            if spaces_anchor != ptrs_anchor {
                return Err(anyhow!(
                    "Spaces and PTRs snapshots have mismatched anchors (spaces: {}, ptrs: {})",
                    spaces_anchor.height,
                    ptrs_anchor.height
                ));
            }
            let ptrs_proof = ptrs_snapshot.prove(&num_tree_keys, ProofType::Standard)?;
            let ptrs_root = ptrs_proof.compute_root()?;

            (spaces_proof, spaces_root, spaces_anchor, ptrs_proof, ptrs_root)
        };

        let spaces_buf = spaces_proof.to_vec()?;

        let ptrs_buf = ptrs_proof.to_vec()?;

        Ok(ChainProofResult {
            block: block_anchor,
            spaces_root: Bytes::new(spaces_root.to_vec()),
            spaces_proof: spaces_buf,
            ptrs_root: Bytes::new(ptrs_root.to_vec()),
            ptrs_proof: ptrs_buf,
        })
    }

    pub async fn handler(
        client: &reqwest::Client,
        rpc: BitcoinRpc,
        anchors_path: Option<PathBuf>,
        mut state: Chain,
        mut rx: mpsc::Receiver<ChainStateCommand>,
        mut shutdown: broadcast::Receiver<()>,
    ) {
        loop {
            select! {
                _ = shutdown.recv() => {
                     break;
                }
                Some(cmd) = rx.recv() => {
                    Self::handle_command(client, &rpc, &anchors_path, &mut state, cmd).await;
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

    pub async fn verify_schnorr(
        &self,
        subject: Subject,
        message: Vec<u8>,
        signature: Vec<u8>,
    ) -> anyhow::Result<()> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::VerifySchnorr {
                subject,
                message,
                signature,
                resp,
            })
            .await?;
        resp_rx.await?
    }

    pub async fn build_chain_proof(
        &self,
        request: ChainProofRequest,
        prefer_recent: bool,
    ) -> anyhow::Result<ChainProofResult> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::BuildChainProof {
                request,
                prefer_recent,
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

    pub async fn debug_set_expire_height(&self, space: SLabel, expire_height: u32) -> anyhow::Result<()> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::DebugSetExpireHeight { space, expire_height, resp })
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

    pub async fn get_ptr(&self, subject: Subject) -> anyhow::Result<Option<FullNumOut>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::GetNum { subject, resp })
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

    pub async fn get_ptr_outpoint(&self, subject: Subject) -> anyhow::Result<Option<OutPoint>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::GetNumOutpoint { subject, resp })
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

    pub async fn get_numout(&self, outpoint: OutPoint) -> anyhow::Result<Option<NumOut>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::GetNumOut { outpoint, resp })
            .await?;
        resp_rx.await?
    }

    pub async fn get_commitment(&self, subject: Subject, root: Option<Hash>) -> anyhow::Result<Option<Commitment>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::GetCommitment { subject, root, resp })
            .await?;
        resp_rx.await?
    }

    pub async fn get_delegation(&self, subject: Subject) -> anyhow::Result<Option<NumId>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::GetDelegation { subject, resp })
            .await?;
        resp_rx.await?
    }

    pub async fn get_delegator(&self, subject: Subject) -> anyhow::Result<Option<SLabel>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::GetDelegator { subject, resp })
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

    pub async fn get_num_block_meta(
        &self,
        height_or_hash: HeightOrHash,
    ) -> anyhow::Result<NumBlockMetaWithHash> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::GetNumBlockMeta {
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

fn resolve_num_id(state: &mut Chain, subject: &Subject) -> anyhow::Result<NumId> {
    match subject {
        Subject::NumId(id) => Ok(*id),
        Subject::Label(label) if label.is_numeric() => {
            let numeric: SNumeric = label.clone().try_into().unwrap();
            state.get_num_id(&numeric)?
                .ok_or_else(|| anyhow!("numeric '{}' not found", numeric))
        }
        Subject::Label(_) => Err(anyhow!("expected a num id or numeric, not a space")),
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


fn resolve_label(state: &mut Chain, subject: &Subject) -> anyhow::Result<SLabel> {
    match subject {
        Subject::Label(label) => Ok(label.clone()),
        Subject::NumId(id) => {
            let info = state.get_num_info(id)?
                .ok_or_else(|| anyhow!("num id '{}' not found", id))?;
            Ok(info.numout.num.name.to_slabel())
        }
    }
}

fn get_delegation(state: &mut Chain, subject: &Subject) -> anyhow::Result<Option<NumId>> {
    let (id, label) = match subject {
        Subject::Label(num) if num.is_numeric() => {
            let numeric: SNumeric = num.clone().try_into().expect("is_numeric");
            let Some(num_id) = state.get_num_id(&numeric)? else {
                return Ok(None);
            };
            let Some(num_info) = state.get_num_info(&num_id)? else {
                return Ok(None);
            };
            (NumId::from_spk::<Sha256>(num_info.numout.script_pubkey), num.clone())
        },
        Subject::Label(space) => {
            let info = match state.get_space_info(
                &SpaceKey::from(Sha256::hash(space.as_ref()))
            )? {
                None => return Ok(None),
                Some(info) => info
            };
            (NumId::from_spk::<Sha256>(info.spaceout.script_pubkey), space.clone())
        }
        Subject::NumId(id) => return Ok(Some(id.clone()))
    };

    let delegate = state.get_delegator(&DelegatorKey::from_id::<Sha256>(id))?;

    // Only return the num id if the reverse mapping points back to this label
    match delegate {
        Some(delegator) if delegator == label => Ok(Some(id)),
        _ => Ok(None),
    }
}

fn get_commitment(state: &mut Chain, subject: &Subject, root: Option<Hash>) -> anyhow::Result<Option<Commitment>> {
    let label = resolve_label(state, subject)?;
    let root = match root {
        None => {
            let rk = CommitmentTipKey::from_slabel::<Sha256>(&label);
            let k = state.get_commitments_tip(&rk)
                    .map_err(|e| anyhow!("could not fetch state root: {}", e))?;
            if let Some(k) = k {
                k
            } else {
                return Ok(None);
            }
        }
        Some(r) => r,
    };

    let ck = CommitmentKey::new::<Sha256>(&label, root);
    state.get_commitment(&ck)
        .map_err(|e|
            anyhow!("could not fetch commitment with root: {}: {}", hex::encode(root), e)
        )
}