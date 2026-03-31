use anyhow::anyhow;
use clap::ValueEnum;
use futures::{stream::FuturesUnordered, StreamExt};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use serde_json::json;
use spaces_protocol::{
    bitcoin::Txid,
    constants::ChainAnchor,
    hasher::{KeyHasher, SpaceKey},
    slabel::SLabel,
    FullSpaceOut, SpaceOut,
};
use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::{collections::BTreeMap, fmt, str::FromStr, time::Duration};

use spaces_wallet::{
    address::SpaceAddress,
    bdk_wallet::{
        chain::{local_chain::CheckPoint, BlockId, ChainPosition},
        KeychainKind,
    },
    bitcoin,
    bitcoin::{secp256k1::schnorr, Address, Amount, FeeRate, OutPoint},
    builder::{CoinTransfer, SpaceTransfer, SpacesAwareCoinSelection},
    tx_event::{TxEvent, TxEventKind, TxRecord},
    nostr::NostrEvent,
    Balance, DoubleUtxo, Listing, SpacesWallet, Subject, WalletInfo, WalletOutput,
};

use crate::cbf::CompactFilterSync;
use crate::rpc::{CommitParams};
use crate::spaces::Spaced;
use crate::store::chain::Chain;
use crate::store::Sha256;
use crate::{
    calc_progress,
    checker::TxChecker,
    client::BlockSource,
    config::ExtendedNetwork,
    rpc::{RpcWalletRequest, RpcWalletTxBuilder, WalletLoadRequest},
    source::{
        BestChain, BitcoinBlockSource, BitcoinRpc, BitcoinRpcError, BlockEvent, BlockFetchError, BlockFetcher,
    },
    std_wait,
};
use spaces_nums::num_id::{NumId, NumIdParseError, NUM_HRP};
use spaces_nums::snumeric::SNumeric;
use spaces_nums::FullNumOut;
use spaces_nums::{DelegatorKey, NumOut, NumSource};
use spaces_protocol::bitcoin::address::ParseError;
use spaces_protocol::bitcoin::{Network, ScriptBuf};
use spaces_wallet::builder::{CommitmentRequest, NumDelegate, NumRequest, NumTransfer};
use tabled::Tabled;
use tokio::{
    select,
    sync::{broadcast, mpsc, mpsc::Receiver, oneshot},
    time::Instant,
};

const MEMPOOL_CHECK_INTERVAL: Duration =
    Duration::from_secs(if cfg!(debug_assertions) { 1 } else { 5 * 60 });

#[derive(Debug, Clone)]
pub enum ResolvableTarget {
    Space(SLabel),
    SpaceAddress(SpaceAddress),
    Address(Address),
    Snum(NumId),
    Numeric(SNumeric),
}

#[derive(Debug)]
pub enum ResolvableTargetParseError {
    SpaceLabelParseError(spaces_protocol::errors::Error),
    AddressParseError(ParseError),
    NumParseError(NumIdParseError),
    NumericParseError(spaces_nums::snumeric::SNumericParseError),
}

impl Display for ResolvableTargetParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ResolvableTargetParseError::SpaceLabelParseError(e) => write!(f, "{}", e),
            ResolvableTargetParseError::AddressParseError(e) => write!(f, "{}", e),
            ResolvableTargetParseError::NumParseError(e) => write!(f, "{}", e),
            ResolvableTargetParseError::NumericParseError(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for ResolvableTargetParseError {}

impl FromStr for ResolvableTarget {
    type Err = ResolvableTargetParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix('@') {
            return SLabel::from_str(rest)
                .map(ResolvableTarget::Space)
                .map_err(ResolvableTargetParseError::SpaceLabelParseError);
        }
        if s.starts_with(NUM_HRP) {
            return NumId::from_str(s)
                .map(ResolvableTarget::Snum)
                .map_err(ResolvableTargetParseError::NumParseError);
        }
        if s.starts_with('#') {
            return SNumeric::from_str(s)
                .map(ResolvableTarget::Numeric)
                .map_err(ResolvableTargetParseError::NumericParseError);
        }

        match SpaceAddress::from_str(s) {
            Ok(addr) => Ok(ResolvableTarget::SpaceAddress(addr)),
            Err(_) => Address::from_str(s)
                .map(|addr| ResolvableTarget::Address(addr.assume_checked()))
                .map_err(ResolvableTargetParseError::AddressParseError),
        }
    }
}

impl fmt::Display for ResolvableTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolvableTarget::Space(label) => write!(f, "{}", label),
            ResolvableTarget::Snum(snum) => write!(f, "{}", snum),
            ResolvableTarget::Numeric(num) => write!(f, "{}", num),
            ResolvableTarget::SpaceAddress(addr) => write!(f, "{}", addr),
            ResolvableTarget::Address(addr) => write!(f, "{}", addr),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct TxResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<BTreeMap<String, String>>,
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub txid: Txid,
    #[cfg_attr(feature = "schema", schemars(with = "Vec<String>"))]
    pub events: Vec<TxEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum WalletStatus {
    #[serde(rename = "header_sync")]
    HeadersSync,
    #[serde(rename = "chain_sync")]
    ChainSync,
    #[serde(rename = "spaces_sync")]
    SpacesSync,
    #[serde(rename = "cbf_filter_sync")]
    CbfFilterSync,
    #[serde(rename = "cbf_process_filters")]
    CbfProcessFilters,
    #[serde(rename = "cbf_download_matching_blocks")]
    CbfDownloadMatchingBlocks,
    #[serde(rename = "cbf_process_matching_blocks")]
    CbfProcessMatchingBlocks,
    #[serde(rename = "cbf_apply_update")]
    CbfApplyUpdate,
    #[serde(rename = "syncing")]
    Syncing,
    #[serde(rename = "complete")]
    Complete,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct WalletProgressUpdate {
    pub status: WalletStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<f32>,
}

impl WalletProgressUpdate {
    pub fn new(status: WalletStatus, progress: Option<f32>) -> Self {
        Self { status, progress }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct WalletInfoWithProgress {
    #[serde(flatten)]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub info: WalletInfo,
    pub sync: WalletProgressUpdate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ListSpacesResponse {
    #[cfg_attr(feature = "schema", schemars(with = "Vec<String>"))]
    pub pending: Vec<SLabel>,
    #[cfg_attr(feature = "schema", schemars(with = "Vec<String>"))]
    pub winning: Vec<FullSpaceOut>,
    #[cfg_attr(feature = "schema", schemars(with = "Vec<String>"))]
    pub outbid: Vec<FullSpaceOut>,
    #[cfg_attr(feature = "schema", schemars(with = "Vec<String>"))]
    pub owned: Vec<FullSpaceOut>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct NumEntry {
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub txid: Txid,
    #[serde(flatten)]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub numout: NumOut,
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub delegating_for: Option<SLabel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ListNumsResponse {
    pub nums: Vec<NumEntry>,
}

#[derive(Tabled, Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[tabled(rename_all = "UPPERCASE")]
pub struct TxInfo {
    #[tabled(display_with = "display_block_height")]
    pub block_height: Option<u32>,
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub txid: Txid,
    #[cfg_attr(feature = "schema", schemars(with = "u64"))]
    pub sent: Amount,
    #[cfg_attr(feature = "schema", schemars(with = "u64"))]
    pub received: Amount,
    #[tabled(display_with = "display_fee")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<u64>"))]
    pub fee: Option<Amount>,
    #[tabled(rename = "DETAILS", display_with = "display_events")]
    #[cfg_attr(feature = "schema", schemars(with = "Vec<String>"))]
    pub events: Vec<TxEvent>,
}

fn display_block_height(block_height: &Option<u32>) -> String {
    match block_height {
        None => "Unconfirmed".to_string(),
        Some(block_height) => block_height.to_string(),
    }
}

fn display_fee(fee: &Option<Amount>) -> String {
    match fee {
        None => "--".to_string(),
        Some(fee) => fee.to_string(),
    }
}

fn display_events(events: &Vec<TxEvent>) -> String {
    events
        .iter()
        .map(|e| {
            format!(
                "{} {}",
                e.kind,
                e.space
                    .as_ref()
                    .map(|s| s.clone())
                    .unwrap_or("".to_string())
            )
        })
        .collect::<Vec<String>>()
        .join("\n")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct WalletResponse {
    pub result: Vec<TxResponse>,
}

pub enum WalletCommand {
    GetInfo {
        resp: crate::rpc::Responder<anyhow::Result<WalletInfoWithProgress>>,
    },
    BatchTx {
        request: RpcWalletTxBuilder,
        resp: crate::rpc::Responder<anyhow::Result<WalletResponse>>,
    },
    GetNewAddress {
        kind: AddressKind,
        resp: crate::rpc::Responder<anyhow::Result<String>>,
    },
    IncrementAddress {
        kind: AddressKind,
        resp: crate::rpc::Responder<anyhow::Result<String>>,
    },
    BumpFee {
        txid: Txid,
        fee_rate: FeeRate,
        skip_tx_check: bool,
        resp: crate::rpc::Responder<anyhow::Result<Vec<TxResponse>>>,
    },
    ListTransactions {
        count: usize,
        skip: usize,
        resp: crate::rpc::Responder<anyhow::Result<Vec<TxInfo>>>,
    },
    ListSpaces {
        resp: crate::rpc::Responder<anyhow::Result<ListSpacesResponse>>,
    },
    ListPtrs {
        resp: crate::rpc::Responder<anyhow::Result<ListNumsResponse>>,
    },
    Buy {
        listing: Listing,
        skip_tx_check: bool,
        fee_rate: Option<FeeRate>,
        resp: crate::rpc::Responder<anyhow::Result<TxResponse>>,
    },
    Sell {
        space: String,
        price: u64,
        resp: crate::rpc::Responder<anyhow::Result<Listing>>,
    },
    ListBidouts {
        resp: crate::rpc::Responder<anyhow::Result<Vec<DoubleUtxo>>>,
    },
    ListUnspent {
        resp: crate::rpc::Responder<anyhow::Result<Vec<WalletOutput>>>,
    },
    ForceSpendOutput {
        outpoint: OutPoint,
        fee_rate: FeeRate,
        resp: crate::rpc::Responder<anyhow::Result<TxResponse>>,
    },
    GetBalance {
        resp: crate::rpc::Responder<anyhow::Result<Balance>>,
    },
    UnloadWallet,
    SignSchnorr {
        subject: Subject,
        message: Vec<u8>,
        resp: crate::rpc::Responder<anyhow::Result<schnorr::Signature>>,
    },
    CanOperate {
        subject: Subject,
        resp: crate::rpc::Responder<anyhow::Result<bool>>,
    },
    SignEvent {
        subject: Subject,
        event: NostrEvent,
        resp: crate::rpc::Responder<anyhow::Result<NostrEvent>>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ValueEnum)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum AddressKind {
    Coin,
    Space,
}

#[derive(Clone)]
pub struct RpcWallet {
    pub sender: mpsc::Sender<WalletCommand>,
}

pub struct MempoolChecker<'a>(&'a BitcoinBlockSource);

impl spaces_wallet::Mempool for MempoolChecker<'_> {
    fn in_mempool(&self, txid: &Txid, height: u32) -> anyhow::Result<bool> {
        Ok(self.0.in_mempool(txid, height)?)
    }
}

fn resolve_subject_to_num_id<H: KeyHasher>(
    chain: &mut Chain,
    subject: &Subject,
) -> anyhow::Result<NumId> {
    match subject {
        Subject::NumId(id) => Ok(*id),
        Subject::Label(label) if label.is_numeric() => {
            let numeric: SNumeric = label.clone().try_into().unwrap();
            chain
                .get_num_id(&numeric)?
                .ok_or_else(|| anyhow!("numeric '{}' not found", numeric))
        }
        Subject::Label(label) => Err(anyhow!(
            "expected a num id or numeric, not a space: '{}'",
            label
        )),
    }
}

fn commit_params_to_req(
    chain: &mut Chain,
    wallet: &SpacesWallet,
    p: CommitParams,
) -> anyhow::Result<CommitmentRequest> {
    // Resolve to the spk-derived NumId (the operator num that holds the delegation)
    let spk_id = match &p.subject {
        Subject::Label(label) if label.is_numeric() => {
            let numeric: SNumeric = label.clone().try_into().unwrap();
            let num_id = chain
                .get_num_id(&numeric)?
                .ok_or_else(|| anyhow!("commit: numeric '{}' not found", label))?;
            let num_info = chain
                .get_num_info(&num_id)?
                .ok_or_else(|| anyhow!("commit: num '{}' not found", label))?;
            NumId::from_spk::<Sha256>(num_info.numout.script_pubkey)
        }
        Subject::Label(label) => {
            let info = chain
                .get_space_info(&SpaceKey::from(Sha256::hash(label.as_ref())))?
                .ok_or_else(|| anyhow!("commit: space '{}' not found", label))?;

            if info.spaceout.space.is_none() || !info.spaceout.space.as_ref().unwrap().is_owned() {
                return Err(anyhow!("commit: space '{}' is not owned", label));
            }
            NumId::from_spk::<Sha256>(info.spaceout.script_pubkey)
        }
        Subject::NumId(id) => *id,
    };

    let num_info = chain
        .get_num_info(&spk_id)?
        .ok_or_else(|| anyhow!("commit: num '{}' not found - use operate first", spk_id))?;

    if !wallet.is_mine(num_info.numout.script_pubkey.clone()) {
        return Err(anyhow!("commit: you don't control '{}'", spk_id));
    }

    Ok(CommitmentRequest {
        numout: num_info,
        root: p.root.map(|p| *p.as_ref()),
        subject: Some(p.subject.to_string()),
    })
}

impl RpcWallet {
    pub fn new() -> (Self, Receiver<WalletCommand>) {
        let (sender, receiver) = mpsc::channel(10);
        (Self { sender }, receiver)
    }

    fn estimate_fee_rate(source: &BitcoinBlockSource) -> Option<FeeRate> {
        let params = json!([/* conf_target= */ 2, "unset"]);

        let estimate_req = source.rpc.make_request("estimatesmartfee", params);
        if let Ok(res) = source
            .rpc
            .send_json_blocking::<serde_json::Value>(&source.client, &estimate_req)
        {
            if let Some(fee_rate) = res["feerate"].as_f64() {
                // Convert BTC/kB to sat/vB
                let fee_rate_sat_vb = (fee_rate * 100_000.0).ceil() as u64;
                return FeeRate::from_sat_per_vb(fee_rate_sat_vb);
            }
        }

        None
    }

    fn handle_buy(
        source: &BitcoinBlockSource,
        chain: &mut Chain,
        wallet: &mut SpacesWallet,
        listing: Listing,
        skip_tx_check: bool,
        fee_rate: Option<FeeRate>,
    ) -> anyhow::Result<TxResponse> {
        let fee_rate = match fee_rate.as_ref() {
            None => match Self::estimate_fee_rate(source) {
                None => return Err(anyhow!("could not estimate fee rate")),
                Some(r) => r,
            },
            Some(r) => r.clone(),
        };
        info!("Using fee rate: {} sat/vB", fee_rate.to_sat_per_vb_ceil());

        let (_, fullspaceout) = SpacesWallet::verify_listing::<Sha256>(chain, &listing)?;

        let space = fullspaceout
            .spaceout
            .space
            .as_ref()
            .expect("space")
            .name
            .to_string();
        let previous_spaceout = fullspaceout.outpoint();
        let tx = wallet.buy::<Sha256>(chain, &listing, fee_rate)?;

        if !skip_tx_check {
            let tip = wallet.local_chain().tip().height();
            let mut checker = TxChecker::new(chain);
            checker.check_apply_tx(tip + 1, &tx)?;
        }

        let new_txid = tx.compute_txid();
        let last_seen = source.rpc.broadcast_tx(&source.client, &tx)?;

        let tx_record = TxRecord::new_with_events(
            tx,
            vec![TxEvent {
                kind: TxEventKind::Buy,
                space: Some(space),
                previous_spaceout: Some(previous_spaceout),
                details: None,
            }],
        );

        let events = tx_record.events.clone();

        // Incrementing last_seen by 1 ensures eviction of older tx
        // in cases with same-second/last seen replacement.
        wallet.apply_unconfirmed_tx_record(tx_record, last_seen + 1)?;
        wallet.commit()?;

        Ok(TxResponse {
            txid: new_txid,
            events,
            error: None,
            raw: None,
        })
    }

    fn handle_fee_bump(
        source: &BitcoinBlockSource,
        chain: &mut Chain,
        wallet: &mut SpacesWallet,
        txid: Txid,
        skip_tx_check: bool,
        fee_rate: FeeRate,
    ) -> anyhow::Result<Vec<TxResponse>> {
        let unspendables = wallet.list_spaces_outpoints(chain)?;
        let tx_events = wallet.get_tx_events(txid)?;
        let builder = wallet.build_fee_bump(unspendables, txid, fee_rate)?;

        let psbt = builder.finish()?;
        let replacement = wallet.sign(psbt, None)?;

        if !skip_tx_check {
            let tip = wallet.local_chain().tip().height();
            let mut checker = TxChecker::new(chain);
            checker.check_apply_tx(tip + 1, &replacement)?;
        }

        let new_txid = replacement.compute_txid();
        let last_seen = source.rpc.broadcast_tx(&source.client, &replacement)?;

        let mut tx_record = TxRecord::new_with_events(replacement, tx_events);
        tx_record.add_fee_bump();

        let new_events = tx_record.events.clone();

        // Incrementing last_seen by 1 ensures eviction of older tx
        // in cases with same-second/last seen replacement.
        wallet.apply_unconfirmed_tx_record(tx_record, last_seen + 1)?;
        wallet.commit()?;

        Ok(vec![TxResponse {
            txid: new_txid,
            events: new_events,
            error: None,
            raw: None,
        }])
    }

    fn handle_force_spend_output(
        _source: &BitcoinBlockSource,
        _chain: &mut Chain,
        _wallet: &mut SpacesWallet,
        _output: OutPoint,
        _fee_rate: FeeRate,
    ) -> anyhow::Result<TxResponse> {
        todo!("")
    }

    fn wallet_handle_commands(
        network: ExtendedNetwork,
        source: &BitcoinBlockSource,
        mut chain: &mut Chain,
        wallet: &mut SpacesWallet,
        command: WalletCommand,
        progress_update: WalletProgressUpdate,
    ) -> anyhow::Result<()> {
        let synced = matches!(progress_update.status, WalletStatus::Complete);
        match command {
            WalletCommand::GetInfo { resp } => {
                let mut wallet_info = WalletInfoWithProgress {
                    info: wallet.get_info(),
                    sync: progress_update,
                };

                let best_chain =
                    source.get_best_chain(Some(wallet_info.info.tip), wallet.config.network);
                if let Ok(BestChain::Tip(best_chain)) = best_chain {
                    wallet_info.info.progress = calc_progress(
                        wallet.config.start_block,
                        wallet_info.info.tip,
                        best_chain.height,
                    );
                }

                _ = resp.send(Ok(wallet_info))
            }
            WalletCommand::BatchTx { request, resp } => {
                if !synced && !request.force {
                    _ = resp.send(Err(anyhow::anyhow!("Wallet is syncing")));
                    return Ok(());
                }
                let batch_result = Self::batch_tx(network, &source, wallet, chain, request);
                _ = resp.send(batch_result);
            }
            WalletCommand::BumpFee {
                txid,
                fee_rate,
                skip_tx_check,
                resp,
            } => {
                if !synced {
                    _ = resp.send(Err(anyhow::anyhow!("Wallet is syncing")));
                    return Ok(());
                }
                let result = Self::handle_fee_bump(
                    source,
                    &mut chain,
                    wallet,
                    txid,
                    skip_tx_check,
                    fee_rate,
                );
                _ = resp.send(result);
            }
            WalletCommand::ForceSpendOutput {
                outpoint,
                fee_rate,
                resp,
            } => {
                let result =
                    Self::handle_force_spend_output(source, chain, wallet, outpoint, fee_rate);
                _ = resp.send(result);
            }
            WalletCommand::GetNewAddress { kind, resp } => {
                let address = match kind {
                    AddressKind::Coin => wallet
                        .next_unused_address(KeychainKind::External)
                        .address
                        .to_string(),
                    AddressKind::Space => wallet.next_unused_space_address().to_string(),
                };
                _ = resp.send(Ok(address));
            }
            WalletCommand::IncrementAddress { kind, resp } => {
                let address = match kind {
                    AddressKind::Coin => wallet
                        .reveal_next_address(KeychainKind::External)
                        .address
                        .to_string(),
                    AddressKind::Space => wallet.reveal_next_space_address().to_string(),
                };
                _ = resp.send(Ok(address));
            }
            WalletCommand::ListUnspent { resp } => {
                _ = resp.send(wallet.list_unspent_with_details(chain));
            }
            WalletCommand::ListTransactions { count, skip, resp } => {
                let transactions = Self::list_transactions(wallet, count, skip);
                _ = resp.send(transactions);
            }
            WalletCommand::ListSpaces { resp } => {
                let result = Self::list_spaces(wallet, chain);
                _ = resp.send(result);
            }
            WalletCommand::ListPtrs { resp } => {
                let result = Self::list_nums(wallet, chain);
                _ = resp.send(result);
            }
            WalletCommand::ListBidouts { resp } => {
                let result = wallet.list_bidouts(false);
                _ = resp.send(result);
            }
            WalletCommand::GetBalance { resp } => {
                if !synced {
                    _ = resp.send(Err(anyhow::anyhow!("Wallet is syncing")));
                    return Ok(());
                }
                let balance = wallet.balance();
                _ = resp.send(balance);
            }
            WalletCommand::UnloadWallet => {
                info!("Unloading wallet '{}' ...", wallet.name());
            }
            WalletCommand::Buy {
                listing,
                resp,
                skip_tx_check,
                fee_rate,
            } => {
                _ = resp.send(Self::handle_buy(
                    source,
                    chain,
                    wallet,
                    listing,
                    skip_tx_check,
                    fee_rate,
                ));
            }
            WalletCommand::Sell { space, price, resp } => {
                _ = resp.send(wallet.sell::<Sha256>(chain, &space, Amount::from_sat(price)));
            }
            WalletCommand::SignSchnorr {
                subject,
                message,
                resp,
            } => {
                _ = resp.send(wallet.sign_schnorr::<Sha256, _>(chain, subject, &message));
            }
            WalletCommand::CanOperate { subject, resp } => {
                let result = Self::can_operate(wallet, chain, &subject);
                _ = resp.send(result);
            }
            WalletCommand::SignEvent {
                subject,
                event,
                resp,
            } => {
                _ = resp.send(wallet.sign_event::<Sha256, _>(chain, subject, event));
            }
        }
        Ok(())
    }

    /// Check if wallet can operate on a subject by verifying it controls the operator num
    fn can_operate(
        wallet: &SpacesWallet,
        chain: &mut Chain,
        subject: &Subject,
    ) -> anyhow::Result<bool> {
        let label = match subject {
            Subject::Label(label) => label.clone(),
            Subject::NumId(id) => {
                let info = chain
                    .get_num_info(id)?
                    .ok_or_else(|| anyhow::anyhow!("num id '{}' not found", id))?;
                info.numout.num.name.to_slabel()
            }
        };

        let spk_id = if label.is_numeric() {
            // For numerics, resolve the num via the numeric key then
            // derive the spk-based id (delegation is on the address, not the num)
            let numeric: SNumeric = label
                .clone()
                .try_into()
                .map_err(|e| anyhow::anyhow!("invalid numeric label: {}", e))?;
            let num_id = chain
                .get_num_id(&numeric)?
                .ok_or_else(|| anyhow::anyhow!("Numeric not found: {}", label))?;
            let num_info = chain
                .get_num_info(&num_id)?
                .ok_or_else(|| anyhow::anyhow!("Num not found: {}", label))?;
            NumId::from_spk::<Sha256>(num_info.numout.script_pubkey)
        } else {
            // For spaces, derive the num id from the space's spk
            let space_info = chain
                .get_space_info(&SpaceKey::from(Sha256::hash(label.as_ref())))?
                .ok_or_else(|| anyhow::anyhow!("Space not found: {}", label))?;
            NumId::from_spk::<Sha256>(space_info.spaceout.script_pubkey.clone())
        };

        // Check reverse mapping to verify delegation is valid
        let delegator = chain.get_delegator(&DelegatorKey::from_id::<Sha256>(spk_id))?;
        if delegator.as_ref() != Some(&label) {
            return Ok(false);
        }

        // Get num info and check if wallet controls it
        let num_info = chain
            .get_num_info(&spk_id)?
            .ok_or_else(|| anyhow::anyhow!("Num not found for id: {}", spk_id))?;

        Ok(wallet.is_mine(num_info.numout.script_pubkey))
    }

    /// Returns true if Bitcoin, protocol, and wallet tips match.
    fn all_synced(
        bitcoin: &BitcoinBlockSource,
        protocol: &mut Chain,
        wallet: &SpacesWallet,
        progress: Option<&mut WalletProgressUpdate>,
    ) -> Option<ChainAnchor> {
        let wallet_tip = wallet.local_chain().tip();

        let info = match bitcoin.get_blockchain_info() {
            Ok(info) => info,
            Err(e) => {
                warn!("Sync check failed: {}", e);
                return None;
            }
        };
        let protocol_tip = protocol.tip();

        if info.headers_synced.is_some_and(|synced| !synced)
            || info.headers == 0
            || info.prune_height.is_some_and(|p| p > info.headers)
            || protocol_tip.height > info.headers
        {
            if let Some(p) = progress {
                *p = WalletProgressUpdate::new(WalletStatus::HeadersSync, None);
            }
            return None;
        }

        // Bitcoin syncing
        if info.headers != info.blocks {
            if let Some(p) = progress {
                *p = WalletProgressUpdate::new(
                    WalletStatus::ChainSync,
                    Some(calc_progress(
                        info.checkpoint.map(|c| c.height).unwrap_or(0),
                        info.blocks,
                        info.headers,
                    )),
                );
            }
            return None;
        }

        if protocol_tip.height != info.headers {
            if let Some(p) = progress {
                let network = match wallet.config.network {
                    Network::Bitcoin => ExtendedNetwork::Mainnet,
                    Network::Testnet => ExtendedNetwork::Testnet4,
                    Network::Signet => ExtendedNetwork::Signet,
                    _ => ExtendedNetwork::Regtest,
                };
                let start = Spaced::genesis(network);
                *p = WalletProgressUpdate::new(
                    WalletStatus::SpacesSync,
                    Some(calc_progress(
                        start.height,
                        protocol_tip.height,
                        info.headers,
                    )),
                );
            }
            return None;
        }

        if protocol_tip.hash == wallet_tip.hash() && protocol_tip.hash == info.best_block_hash {
            if let Some(p) = progress {
                *p = WalletProgressUpdate::new(WalletStatus::Complete, None);
            }
            Some(protocol_tip)
        } else {
            None
        }
    }

    fn wallet_sync(
        network: ExtendedNetwork,
        source: BitcoinBlockSource,
        mut chain: Chain,
        mut wallet: SpacesWallet,
        mut commands: Receiver<WalletCommand>,
        shutdown: broadcast::Sender<()>,
        num_workers: usize,
        cbf: bool,
    ) -> anyhow::Result<()> {
        let (fetcher, receiver) =
            BlockFetcher::new(network.fallback_network(), source.clone(), num_workers);

        let mut wallet_tip = {
            let tip = wallet.local_chain().tip();
            ChainAnchor {
                height: tip.height(),
                hash: tip.hash(),
            }
        };

        let mut shutdown_recv = shutdown.subscribe();

        let mut cbf_sync = if cbf {
            Some(CompactFilterSync::new(&wallet))
        } else {
            fetcher.start(wallet_tip);
            None
        };

        let mut synced_at_least_once = false;
        let mut last_mempool_check = Instant::now();
        let mut wallet_progress = WalletProgressUpdate::new(WalletStatus::Syncing, None);

        loop {
            if shutdown_recv.try_recv().is_ok() {
                info!("Shutting down wallet sync");
                break;
            }

            // Wallet Commands:
            if let Ok(command) = commands.try_recv() {
                let _ = Self::all_synced(&source, &mut chain, &wallet, Some(&mut wallet_progress))
                    .is_some();

                Self::wallet_handle_commands(
                    network,
                    &source,
                    &mut chain,
                    &mut wallet,
                    command,
                    wallet_progress,
                )?;
            }

            // Compact Filter Sync:
            if let Some(mut cbf) = cbf_sync.take() {
                if let Err(e) = cbf.sync_next(&mut wallet, &source, &mut wallet_progress) {
                    info!("Error syncing cbf: {} - retrying ...", e);
                    let mut wait_recv = shutdown.subscribe();
                    std_wait(|| wait_recv.try_recv().is_ok(), Duration::from_secs(1));
                }
                if !cbf.synced() {
                    cbf_sync = Some(cbf);
                    continue;
                }

                // Once compact filter sync is complete
                // start the block fetcher
                wallet_tip = {
                    let tip = wallet.local_chain().tip();
                    ChainAnchor {
                        height: tip.height(),
                        hash: tip.hash(),
                    }
                };
                fetcher.start(wallet_tip);
                continue;
            }

            // Block fetcher events:
            if let Ok(event) = receiver.try_recv() {
                match event {
                    BlockEvent::Tip(_) => {
                        synced_at_least_once = true;
                    }
                    BlockEvent::Block(id, block) => {
                        wallet.apply_block_connected_to(
                            id.height,
                            &block,
                            BlockId {
                                height: wallet_tip.height,
                                hash: wallet_tip.hash,
                            },
                        )?;

                        wallet_tip.height = id.height;
                        wallet_tip.hash = id.hash;

                        info!(
                            "wallet({}): block={} height={}",
                            wallet.name(),
                            wallet_tip.hash,
                            wallet_tip.height
                        );
                        if id.height % 12 == 0 {
                            wallet.commit()?;
                        }
                    }
                    BlockEvent::Waiting(_) => {}
                    BlockEvent::Error(e) if matches!(e, BlockFetchError::BlockMismatch) => {
                        let mut checkpoint_in_chain = None;
                        let best_chain = match source
                            .get_best_chain(Some(wallet_tip.height), network.fallback_network())
                        {
                            Ok(BestChain::Tip(best)) => best,
                            Ok(BestChain::Waiting(_)) | Ok(BestChain::None) => {
                                warn!("Waiting for source to sync");
                                fetcher.restart(wallet_tip, &receiver);
                                continue;
                            }
                            Err(error) => {
                                warn!("Wallet error: {}", error);
                                fetcher.restart(wallet_tip, &receiver);
                                continue;
                            }
                        };

                        for cp in wallet.local_chain().iter_checkpoints() {
                            if cp.height() > best_chain.height {
                                continue;
                            }
                            let hash = match source.get_block_hash(cp.height()) {
                                Ok(hash) => hash,
                                Err(err) => {
                                    warn!("Wallet error: {}", err);
                                    fetcher.restart(wallet_tip, &receiver);
                                    continue;
                                }
                            };
                            if cp.height() != 0 && hash == cp.hash() {
                                checkpoint_in_chain = Some(cp);
                                break;
                            }
                        }
                        let restore_point = match checkpoint_in_chain {
                            None => {
                                // We couldn't find a restore point
                                warn!("Rebuilding wallet `{}`", wallet.config.name);
                                let birthday = wallet.config.start_block;
                                let hash = match source.get_block_hash(birthday) {
                                    Ok(hash) => hash,
                                    Err(error) => {
                                        warn!("Wallet error: {}", error);
                                        fetcher.restart(wallet_tip, &receiver);
                                        continue;
                                    }
                                };

                                let cp = CheckPoint::new(BlockId {
                                    height: birthday,
                                    hash,
                                });
                                wallet = wallet.rebuild()?;
                                wallet.insert_checkpoint(cp.block_id())?;
                                cp
                            }
                            Some(cp) => cp,
                        };

                        wallet_tip.height = restore_point.block_id().height;
                        wallet_tip.hash = restore_point.block_id().hash;

                        info!(
                            "Restore wallet `{}` to block={} height={}",
                            wallet.name(),
                            wallet_tip.hash,
                            wallet_tip.height
                        );
                        fetcher.restart(wallet_tip, &receiver);
                    }
                    BlockEvent::Error(e) => {
                        warn!("Fetcher: {} - retrying in 1s", e);
                        let mut wait_recv = shutdown.subscribe();
                        std_wait(|| wait_recv.try_recv().is_ok(), Duration::from_secs(1));
                        fetcher.restart(wallet_tip, &receiver);
                    }
                }

                continue;
            }

            if synced_at_least_once && last_mempool_check.elapsed() > MEMPOOL_CHECK_INTERVAL {
                if let Some(common_tip) = Self::all_synced(&source, &mut chain, &wallet, None) {
                    let mem = MempoolChecker(&source);
                    match wallet.update_unconfirmed_bids(mem, common_tip.height, &mut chain) {
                        Ok(txids) => {
                            for txid in txids {
                                info!("Dropped {} - no longer in the mempool", txid);
                            }
                        }
                        Err(err) => {
                            warn!("Could not check for unconfirmed bids in mempool: {}", err)
                        }
                    }
                    last_mempool_check = Instant::now();
                }
            }

            std::thread::sleep(Duration::from_millis(10));
        }

        fetcher.stop();
        Ok(())
    }

    fn list_nums(wallet: &mut SpacesWallet, chain: &mut Chain) -> anyhow::Result<ListNumsResponse> {
        let mut nums: Vec<NumEntry> = Vec::new();
        for unspent in wallet.list_unspent() {
            let snum = NumId::from_spk::<Sha256>(unspent.txout.script_pubkey);
            let Some(fpo) = chain.get_num_info(&snum)? else {
                continue;
            };
            if fpo.outpoint() != unspent.outpoint {
                continue;
            }
            let rsk = DelegatorKey::from_id::<Sha256>(snum);
            let delegating_for = chain.get_delegator(&rsk)?;
            nums.push(NumEntry {
                txid: fpo.txid,
                numout: fpo.numout,
                delegating_for,
            })
        }

        Ok(ListNumsResponse { nums: nums })
    }

    fn list_spaces(
        wallet: &mut SpacesWallet,
        chain: &mut Chain,
    ) -> anyhow::Result<ListSpacesResponse> {
        let unspent = wallet.list_unspent_with_details(chain)?;
        let owned_spaces: HashSet<_> = unspent
            .iter()
            .filter_map(|out| out.space.as_ref().map(|s| s.name.to_string()))
            .collect();
        let mut recent_events: HashMap<Txid, Vec<TxEvent>> = HashMap::new();
        for (txid, event) in wallet.list_recent_events()? {
            if !event
                .space
                .as_ref()
                .is_some_and(|s| owned_spaces.contains(s))
            {
                recent_events.entry(txid).or_default().push(event);
            }
        }

        let mut recent_events_with_txs = Vec::new();
        for tx in wallet.transactions() {
            let Some(events) = recent_events.remove(&tx.tx_node.txid) else {
                continue;
            };
            for event in events {
                recent_events_with_txs.push((Some(tx.clone()), event));
            }
            if recent_events.is_empty() {
                break;
            }
        }
        recent_events_with_txs.extend(recent_events.into_values().flatten().map(|e| (None, e)));

        let mut pending = vec![];
        let mut outbid = vec![];
        for (tx, event) in recent_events_with_txs {
            let name = SLabel::from_str(event.space.as_ref().unwrap()).expect("valid space name");
            if tx
                .as_ref()
                .is_some_and(|tx| !tx.chain_position.is_confirmed())
            {
                pending.push(name);
                continue;
            }
            let spacehash = SpaceKey::from(Sha256::hash(name.as_ref()));
            let space = chain.get_space_info(&spacehash)?;
            if let Some(space) = space {
                if space.spaceout.space.as_ref().unwrap().is_owned() {
                    continue;
                }
                if tx.is_none() {
                    outbid.push(space);
                    continue;
                }
                if event
                    .previous_spaceout
                    .is_some_and(|input| input == space.outpoint())
                {
                    continue;
                }
                outbid.push(space);
            }
        }

        let mut owned = vec![];
        let mut winning = vec![];
        for wallet_output in unspent.into_iter().filter(|output| output.space.is_some()) {
            let entry = FullSpaceOut {
                txid: wallet_output.output.outpoint.txid,
                spaceout: SpaceOut {
                    n: wallet_output.output.outpoint.vout as _,
                    space: wallet_output.space,
                    script_pubkey: wallet_output.output.txout.script_pubkey,
                    value: wallet_output.output.txout.value,
                },
            };

            if entry.spaceout.space.as_ref().expect("space").is_owned() {
                owned.push(entry);
            } else {
                winning.push(entry);
            }
        }

        Ok(ListSpacesResponse {
            pending,
            winning,
            outbid,
            owned,
        })
    }

    fn list_transactions(
        wallet: &mut SpacesWallet,
        count: usize,
        skip: usize,
    ) -> anyhow::Result<Vec<TxInfo>> {
        let mut transactions: Vec<_> = wallet.transactions().collect();
        transactions.sort();

        let mut txs: Vec<_> = transactions
            .iter()
            .rev()
            .skip(skip)
            .take(count)
            .map(|ctx| {
                let block_height = match ctx.chain_position {
                    ChainPosition::Confirmed { anchor, .. } => Some(anchor.block_id.height),
                    ChainPosition::Unconfirmed { .. } => None,
                };
                let tx = ctx.tx_node.tx.clone();
                let txid = ctx.tx_node.txid.clone();
                let (sent, received) = wallet.sent_and_received(&tx);
                let fee = wallet.calculate_fee(&tx).ok();
                TxInfo {
                    block_height,
                    txid,
                    sent,
                    received,
                    fee,
                    events: vec![],
                }
            })
            .collect();

        // TODO: use a single query?
        for tx in txs.iter_mut() {
            tx.events = {
                let conn = wallet.connection.transaction()?;
                let mut events = TxEvent::all(&conn, tx.txid).expect("tx event");
                for event in events.iter_mut() {
                    match event.kind {
                        TxEventKind::Commit => event.details = None,
                        _ => {}
                    }
                }
                events
            };
        }
        Ok(txs)
    }

    fn resolve(
        network: ExtendedNetwork,
        chain: &mut Chain,
        to: &str,
        require_space_address: bool,
    ) -> anyhow::Result<Option<Address>> {
        let target = ResolvableTarget::from_str(to)?;
        let address = match target {
            ResolvableTarget::Address(address) => {
                if require_space_address {
                    return Err(anyhow!("recipient must be a space address"));
                }
                address
            }
            ResolvableTarget::Space(sname) => {
                let spacehash = SpaceKey::from(Sha256::hash(sname.as_ref()));
                let script_pubkey = match chain.get_space_info(&spacehash)? {
                    None => return Ok(None),
                    Some(fullspaceout) => fullspaceout.spaceout.script_pubkey,
                };
                Address::from_script(script_pubkey.as_script(), network.fallback_network())?
            }
            ResolvableTarget::SpaceAddress(address) => address.0,
            ResolvableTarget::Snum(snum) => {
                let script_pubkey = match chain.get_num_info(&snum)? {
                    None => return Ok(None),
                    Some(fullnumout) => fullnumout.numout.script_pubkey,
                };
                Address::from_script(script_pubkey.as_script(), network.fallback_network())?
            }
            ResolvableTarget::Numeric(numeric) => {
                let snum = match chain.get_num_id(&numeric)? {
                    None => return Ok(None),
                    Some(snum) => snum,
                };
                let script_pubkey = match chain.get_num_info(&snum)? {
                    None => return Ok(None),
                    Some(fullnumout) => fullnumout.numout.script_pubkey,
                };
                Address::from_script(script_pubkey.as_script(), network.fallback_network())?
            }
        };
        Ok(Some(address))
    }

    fn replaces_unconfirmed_bid(wallet: &SpacesWallet, bid_spaceout: &FullSpaceOut) -> bool {
        let outpoint = bid_spaceout.outpoint();
        wallet
            .transactions()
            .filter(|tx| !tx.chain_position.is_confirmed())
            .any(|tx| {
                tx.tx_node
                    .input
                    .iter()
                    .any(|input| input.previous_output == outpoint)
            })
    }

    fn batch_tx(
        network: ExtendedNetwork,
        source: &BitcoinBlockSource,
        wallet: &mut SpacesWallet,
        chain: &mut Chain,
        tx: RpcWalletTxBuilder,
    ) -> anyhow::Result<WalletResponse> {
        let tip_height = wallet.local_chain().tip().height();

        if let Some(dust) = tx.dust {
            if dust > SpacesAwareCoinSelection::DUST_THRESHOLD {
                // Allowing higher dust may space outs to be accidentally
                // spent during coin selection
                return Err(anyhow!(
                    "dust cannot be higher than {}",
                    SpacesAwareCoinSelection::DUST_THRESHOLD
                ));
            }
        }

        let fee_rate = match tx.fee_rate.as_ref() {
            None => match Self::estimate_fee_rate(source) {
                None => return Err(anyhow!("could not estimate fee rate")),
                Some(r) => r,
            },
            Some(r) => r.clone(),
        };
        info!("Using fee rate: {} sat/vB", fee_rate.to_sat_per_vb_ceil());

        let mut builder = spaces_wallet::builder::Builder::new();
        builder = builder.fee_rate(fee_rate);

        if tx.bidouts.is_some() {
            builder = builder.bidouts(tx.bidouts.unwrap());
        }

        builder = builder.force(tx.force);
        let mut bid_replacement = tx.confirmed_only;

        for req in tx.requests {
            match req {
                RpcWalletRequest::SendCoins(params) => {
                    let recipient = match Self::resolve(network, chain, &params.to, false)? {
                        None => return Err(anyhow!("send: could not resolve '{}'", params.to)),
                        Some(r) => r,
                    };
                    builder = builder.add_send(CoinTransfer {
                        amount: params.amount,
                        recipient: recipient.clone(),
                    });
                }
                RpcWalletRequest::Transfer(params) => {
                    let recipient = if let Some(to) = params.to {
                        match Self::resolve(network, chain, &to, true)? {
                            None => return Err(anyhow!("transfer: could not resolve '{}'", to)),
                            Some(r) => Some(r),
                        }
                    } else {
                        None
                    };

                    // Process each item - space or num
                    for item in &params.spaces {
                        match item {
                            Subject::NumId(id) => {
                                let num = match chain.get_num_info(id)? {
                                    None => return Err(anyhow!("transfer: num '{}' not found or not owned", id)),
                                    Some(full) if !wallet.is_mine(full.numout.script_pubkey.clone()) => {
                                        return Err(anyhow!("transfer: you don't own num '{}'", id))
                                    }
                                    Some(full) if wallet.get_utxo(OutPoint::new(full.txid, full.numout.n as u32)).is_none() => {
                                        return Err(anyhow!(
                                            "transfer '{}': wallet already has a pending tx for this num",
                                            id
                                        ))
                                    }
                                    Some(full) => full,
                                };

                                let recipient_addr = match recipient.clone() {
                                    None => wallet.reveal_next_space_address(),
                                    Some(addr) => SpaceAddress::from(addr),
                                };

                                builder = builder.add_num_transfer(NumTransfer {
                                    num,
                                    recipient: recipient_addr,
                                    is_delegate: false,
                                });
                            }
                            Subject::Label(label) if label.is_numeric() => {
                                let numeric: SNumeric = label.clone().try_into().unwrap();
                                let id = chain.get_num_id(&numeric)?.ok_or_else(|| {
                                    anyhow!("transfer: numeric '{}' not found", numeric)
                                })?;
                                let num = match chain.get_num_info(&id)? {
                                    None => return Err(anyhow!("transfer: num '{}' not found or not owned", id)),
                                    Some(full) if !wallet.is_mine(full.numout.script_pubkey.clone()) => {
                                        return Err(anyhow!("transfer: you don't own num '{}'", id))
                                    }
                                    Some(full) if wallet.get_utxo(OutPoint::new(full.txid, full.numout.n as u32)).is_none() => {
                                        return Err(anyhow!(
                                            "transfer '{}': wallet already has a pending tx for this num",
                                            id
                                        ))
                                    }
                                    Some(full) => full,
                                };

                                let recipient_addr = match recipient.clone() {
                                    None => wallet.reveal_next_space_address(),
                                    Some(addr) => SpaceAddress::from(addr),
                                };

                                builder = builder.add_num_transfer(NumTransfer {
                                    num,
                                    recipient: recipient_addr,
                                    is_delegate: false,
                                });
                            }
                            Subject::Label(space) => {
                                // Handle space transfer
                                let spacehash = SpaceKey::from(Sha256::hash(space.as_ref()));
                                match chain.get_space_info(&spacehash)? {
                                    None => {
                                        return Err(anyhow!("transfer: you don't own `{}`", space))
                                    }
                                    Some(full)
                                        if full.spaceout.space.is_none()
                                            || !full
                                                .spaceout
                                                .space
                                                .as_ref()
                                                .unwrap()
                                                .is_owned()
                                            || !wallet
                                                .is_mine(full.spaceout.script_pubkey.clone()) =>
                                    {
                                        return Err(anyhow!("transfer: you don't own `{}`", space));
                                    }

                                    Some(full) if wallet.get_utxo(full.outpoint()).is_none() => {
                                        return Err(anyhow!(
                                            "transfer '{}': wallet already has a pending tx for this space",
                                            space
                                        ));
                                    }

                                    Some(full)
                                        if !tx.force
                                            && full
                                                .spaceout
                                                .space
                                                .as_ref()
                                                .is_some_and(|s| s.is_expired(tip_height)) =>
                                    {
                                        return Err(anyhow!(
                                            "transfer/renew '{}': space is expired",
                                            space
                                        ));
                                    }
                                    Some(full) => {
                                        let recipient_addr = match recipient.clone() {
                                            None => SpaceAddress(
                                                Address::from_script(
                                                    full.spaceout.script_pubkey.as_script(),
                                                    wallet.config.network,
                                                )
                                                .expect("valid script"),
                                            ),
                                            Some(addr) => SpaceAddress(addr),
                                        };

                                        builder = builder.add_transfer(SpaceTransfer {
                                            space: full,
                                            recipient: recipient_addr.clone(),
                                            create_num: false,
                                        });
                                    }
                                };
                            }
                        }
                    }

                    // Add data OP_RETURN if present
                    if let Some(data) = params.data {
                        builder = builder.add_data(data);
                    }
                }
                RpcWalletRequest::Open(params) => {
                    let name = SLabel::from_str(&params.name)?;
                    if !tx.force {
                        // Warn if already exists
                        let spacehash = SpaceKey::from(Sha256::hash(name.as_ref()));
                        let full = chain.get_space_info(&spacehash)?;
                        if let Some(full) = full {
                            if !full
                                .spaceout
                                .space
                                .is_some_and(|s| s.is_expired(tip_height))
                            {
                                return Err(anyhow!(
                                    "open '{}': space already exists",
                                    params.name
                                ));
                            }
                        }
                    }

                    builder = builder.add_open(&params.name, Amount::from_sat(params.amount));
                }
                RpcWalletRequest::Bid(params) => {
                    let name = SLabel::from_str(&params.name)?;
                    let spacehash = SpaceKey::from(Sha256::hash(name.as_ref()));
                    let spaceout = chain.get_space_info(&spacehash)?;
                    if spaceout.is_none() {
                        return Err(anyhow!("bid '{}': space does not exist", params.name));
                    }

                    let spaceout = spaceout.unwrap();
                    if Self::replaces_unconfirmed_bid(wallet, &spaceout) {
                        bid_replacement = true;
                    }

                    builder = builder.add_bid(spaceout, Amount::from_sat(params.amount));
                }
                RpcWalletRequest::Register(params) => {
                    let name = SLabel::from_str(&params.name)?;
                    let spacehash = SpaceKey::from(Sha256::hash(name.as_ref()));
                    let spaceout = chain.get_space_info(&spacehash)?;
                    if spaceout.is_none() {
                        return Err(anyhow!("register '{}': space does not exist", params.name));
                    }
                    let utxo = spaceout.unwrap();
                    if !wallet.is_mine(utxo.spaceout.script_pubkey.clone()) {
                        return Err(anyhow!(
                            "register '{}': you don't own this space",
                            params.name
                        ));
                    }

                    if wallet.get_utxo(utxo.outpoint()).is_none() {
                        return Err(anyhow!(
                            "register '{}': wallet already has a pending tx for this space",
                            params.name
                        ));
                    }

                    if !tx.force {
                        let claim_height = utxo.spaceout.space.as_ref().unwrap().claim_height();
                        let tip_height = wallet.local_chain().tip().height();

                        if claim_height.is_none() {
                            return Err(anyhow!(
                                "register '{}': space may be in pre-auctions or already registered",
                                params.name
                            ));
                        }

                        let claim_height = claim_height.unwrap();
                        if claim_height > tip_height {
                            return Err(anyhow!(
                                "register '{}': cannot register until claim height {}",
                                params.name,
                                claim_height
                            ));
                        }
                    }

                    let address = match params.to {
                        None => wallet.next_unused_space_address(),
                        Some(address) => match SpaceAddress::from_str(&address) {
                            Ok(addr) => addr,
                            Err(_) => {
                                return Err(anyhow!(
                                    "transfer '{}': recipient must be a valid space address",
                                    params.name
                                ));
                            }
                        },
                    };

                    builder = builder.add_register(utxo, Some(address));
                }
                RpcWalletRequest::CreateNum(params) => {
                    let spk = match params.bind_spk {
                        Some(spk) => spk,
                        None => advance_address_to_unique_num_spk(chain, wallet)?,
                    };
                    let snum = NumId::from_spk::<Sha256>(spk.clone());

                    let snum = chain.get_num_info(&snum)?;
                    if snum.is_some() && !tx.force {
                        return Err(anyhow!("snum already exists"));
                    }

                    builder = builder.add_num(NumRequest { bind_spk: spk })
                }
                RpcWalletRequest::Commit(params) => {
                    let reqs = commit_params_to_req(chain, wallet, params)?;
                    builder = builder.add_commitment(reqs)
                }
                RpcWalletRequest::Operate(params) => {
                    let unique_num_spk = advance_address_to_unique_num_spk(chain, wallet)?;

                    match &params.subject {
                        Subject::Label(label) if label.is_numeric() => {
                            let numeric: SNumeric = label.clone().try_into().unwrap();
                            let id = chain.get_num_id(&numeric)?.ok_or_else(|| {
                                anyhow!("operate: numeric '{}' not found", label)
                            })?;
                            let num = match chain.get_num_info(&id)? {
                                None => return Err(anyhow!("operate: num '{}' not found", id)),
                                Some(full)
                                    if !wallet.is_mine(full.numout.script_pubkey.clone()) =>
                                {
                                    return Err(anyhow!("operate: you don't own '{}'", label))
                                }
                                Some(full)
                                    if wallet
                                        .get_utxo(OutPoint::new(full.txid, full.numout.n as u32))
                                        .is_none() =>
                                {
                                    return Err(anyhow!(
                                        "operate '{}': wallet already has a pending tx",
                                        label
                                    ))
                                }
                                Some(full) => full,
                            };
                            builder = builder.add_num_delegate(NumDelegate {
                                num,
                                unique_num_spk: unique_num_spk.clone(),
                            });
                        }
                        Subject::NumId(id) => {
                            let num = match chain.get_num_info(id)? {
                                None => return Err(anyhow!("operate: num '{}' not found", id)),
                                Some(full)
                                    if !wallet.is_mine(full.numout.script_pubkey.clone()) =>
                                {
                                    return Err(anyhow!("operate: you don't own '{}'", id))
                                }
                                Some(full)
                                    if wallet
                                        .get_utxo(OutPoint::new(full.txid, full.numout.n as u32))
                                        .is_none() =>
                                {
                                    return Err(anyhow!(
                                        "operate '{}': wallet already has a pending tx",
                                        id
                                    ))
                                }
                                Some(full) => full,
                            };
                            builder = builder.add_num_delegate(NumDelegate {
                                num,
                                unique_num_spk: unique_num_spk.clone(),
                            });
                        }
                        Subject::Label(label) => {
                            let spacehash = SpaceKey::from(Sha256::hash(label.as_ref()));

                            let full = match chain.get_space_info(&spacehash)? {
                                None => {
                                    return Err(anyhow!("operate: space '{}' not found", label))
                                }
                                Some(full)
                                    if full.spaceout.space.is_none()
                                        || !full.spaceout.space.as_ref().unwrap().is_owned()
                                        || !wallet.is_mine(full.spaceout.script_pubkey.clone()) =>
                                {
                                    return Err(anyhow!("operate: you don't own '{}'", label))
                                }
                                Some(full) if wallet.get_utxo(full.outpoint()).is_none() => {
                                    return Err(anyhow!(
                                        "operate '{}': wallet already has a pending tx",
                                        label
                                    ))
                                }
                                Some(full) => full,
                            };

                            let recipient = SpaceAddress(
                                Address::from_script(&unique_num_spk, wallet.config.network)
                                    .expect("valid address"),
                            );
                            builder = builder.add_transfer(SpaceTransfer {
                                space: full,
                                recipient,
                                create_num: true,
                            });
                        }
                    }
                }
                RpcWalletRequest::Delegate(params) => {
                    let delegate_utxo = find_delegate_utxo(chain, &params.subject)?;
                    if !wallet.is_mine(delegate_utxo.numout.script_pubkey.clone()) {
                        return Err(anyhow!("delegate: you don't own '{}'", params.subject));
                    }
                    let Some(r) = Self::resolve(network, chain, &params.to, true)? else {
                        return Err(anyhow!("delegate: recipient '{}' not found", params.to));
                    };
                    builder = builder.add_num_transfer(NumTransfer {
                        num: delegate_utxo,
                        recipient: SpaceAddress::from(r),
                        is_delegate: true,
                    })
                }
                RpcWalletRequest::SetFallback(params) => match params.subject {
                    Subject::Label(ref label) if !label.is_numeric() => {
                        let spacehash = SpaceKey::from(Sha256::hash(label.as_ref()));
                        let full = chain
                            .get_space_info(&spacehash)?
                            .ok_or_else(|| anyhow!("setfallback: space '{}' not found", label))?;
                        if !wallet.is_mine(full.spaceout.script_pubkey.clone()) {
                            return Err(anyhow!("setfallback: you don't own '{}'", label));
                        }
                        let recipient = SpaceAddress(
                            Address::from_script(
                                full.spaceout.script_pubkey.as_script(),
                                wallet.config.network,
                            )
                            .expect("valid script"),
                        );
                        builder = builder
                            .add_transfer(SpaceTransfer {
                                space: full,
                                recipient,
                                create_num: false,
                            })
                            .add_data(params.data);
                    }
                    _ => {
                        let id = resolve_subject_to_num_id::<Sha256>(chain, &params.subject)?;
                        let num_info = match chain.get_num_info(&id)? {
                                None => return Err(anyhow!("setfallback: num '{}' not found", id)),
                                Some(num) if !wallet.is_mine(num.numout.script_pubkey.clone()) => {
                                    return Err(anyhow!("setfallback: you don't own '{}'", id))
                                }
                                Some(num)
                                    if wallet
                                        .get_utxo(OutPoint::new(num.txid, num.numout.n as u32))
                                        .is_none() =>
                                {
                                    return Err(anyhow!(
                                        "setfallback '{}': wallet already has a pending tx for this num",
                                        id
                                    ))
                                }
                                Some(num) => num,
                            };
                        let recipient = SpaceAddress(
                            Address::from_script(
                                num_info.numout.script_pubkey.as_script(),
                                wallet.config.network,
                            )
                            .expect("valid script"),
                        );
                        builder = builder
                            .add_num_transfer(NumTransfer {
                                num: num_info,
                                recipient,
                                is_delegate: false,
                            })
                            .add_data(params.data);
                    }
                },
            }
        }

        let unspendables = wallet.list_spaces_outpoints(chain)?;
        let median_time = source.get_median_time()?;
        let mut checker = TxChecker::new(chain);

        if !tx.skip_tx_check {
            let mut unconfirmed: Vec<_> = wallet
                .transactions()
                .filter(|x| !x.chain_position.is_confirmed())
                .collect();
            unconfirmed.sort();
            // no tx checks for unconfirmed as they're already broadcasted,
            // but we need to build on their state still
            for un in unconfirmed {
                checker.apply_tx(tip_height + 1, &un.tx_node.tx)?;
            }
        }

        let mut tx_iter =
            builder.build_iter(tx.dust, median_time, wallet, unspendables, bid_replacement)?;
        let mut result_set = Vec::new();

        while let Some(tx_result) = tx_iter.next() {
            let tx_record = tx_result?;

            let is_bid = tx_record
                .events
                .iter()
                .any(|tag| tag.kind == TxEventKind::Bid);
            result_set.push(TxResponse {
                txid: tx_record.tx.compute_txid(),
                events: tx_record.events.clone(),
                error: None,
                raw: None,
            });

            if !tx.skip_tx_check {
                checker.check_apply_tx(tip_height + 1, &tx_record.tx)?;
            }

            let raw = bitcoin::consensus::encode::serialize_hex(&tx_record.tx);
            let result = source.rpc.broadcast_tx(&source.client, &tx_record.tx);
            match result {
                Ok(last_seen) => {
                    tx_iter
                        .wallet
                        .apply_unconfirmed_tx_record(tx_record, last_seen)?;
                    tx_iter.wallet.commit()?;
                }
                Err(e) => {
                    result_set.last_mut().unwrap().raw = Some(raw);

                    let mut error_data = BTreeMap::new();
                    if let BitcoinRpcError::Rpc(rpc) = e {
                        if is_bid {
                            if rpc.message.contains("replacement-adds-unconfirmed") {
                                error_data.insert(
                                    "hint".to_string(),
                                    "a competing bid in mempool but wallet must use confirmed bidouts and funding \
                                    outputs to replace it. Try --confirmed-only"
                                        .to_string(),
                                );
                            }

                            if let Some(fee_rate) = fee_rate_from_message(&rpc.message) {
                                error_data.insert(
                                    "hint".to_string(),
                                    format!(
                                        "a competing bid in the mempool; replace \
                                                  with a feerate > {} sat/vB.",
                                        fee_rate.to_sat_per_vb_ceil()
                                    ),
                                );
                            }
                        }

                        error_data.insert("rpc_code".to_string(), rpc.code.to_string());
                        error_data.insert("message".to_string(), rpc.message);
                        result_set.last_mut().unwrap().error = Some(error_data);
                    } else {
                        error_data.insert("message".to_string(), format!("{:?}", e));
                        result_set.last_mut().unwrap().error = Some(error_data);
                    }
                    break;
                }
            }
        }

        Ok(WalletResponse { result: result_set })
    }

    pub fn load_wallet(
        src: &BitcoinBlockSource,
        request: &WalletLoadRequest,
    ) -> anyhow::Result<SpacesWallet> {
        let mut wallet = SpacesWallet::new(request.config.clone())?;
        let wallet_tip = wallet.local_chain().tip().height();

        if wallet_tip < request.export.blockheight {
            let hash = src.get_block_hash(request.export.blockheight)?;
            wallet.insert_checkpoint(BlockId {
                height: request.export.blockheight,
                hash,
            })?;
            wallet.commit()?;
        }

        Ok(wallet)
    }

    pub async fn service(
        network: ExtendedNetwork,
        rpc: BitcoinRpc,
        chain: Chain,
        mut channel: Receiver<WalletLoadRequest>,
        shutdown: broadcast::Sender<()>,
        num_workers: usize,
        cbf: bool,
    ) -> anyhow::Result<()> {
        let mut shutdown_signal = shutdown.subscribe();
        let mut wallet_results = FuturesUnordered::new();

        loop {
            select! {
                _ = shutdown_signal.recv() => {
                    info!("Shutting down wallet service...");
                    break;
                }
                wallet = channel.recv() => {
                    if let Some( loaded ) = wallet {
                        let wallet_name = loaded.export.label.clone();
                        let wallet_chain = chain.clone();
                        let rpc = rpc.clone();
                        let wallet_shutdown = shutdown.clone();
                        let (tx, rx) = oneshot::channel();

                        std::thread::spawn(move || {
                            let source = BitcoinBlockSource::new(rpc);
                            let wallet = Self::load_wallet(&source, &loaded);
                            match wallet {
                                Ok(wallet) => {
                                  _ = tx.send(Self::wallet_sync(
                                  network,
                                  source,
                                  wallet_chain,
                                  wallet,
                                  loaded.rx,
                                  wallet_shutdown,
                                  num_workers,
                                  cbf
                                ));
                              }
                              Err(err) => {
                                _ = tx.send(Err(err));
                              }
                            }
                        });
                        wallet_results.push(named_future(wallet_name, rx));
                    }
                }
                Some((name, res)) = wallet_results.next() => {
                    if let Ok(res) = res {
                        match res {
                        Ok(_) => info!("Wallet `{}` shutdown normally", name),
                            Err(e) => {
                                return Err(anyhow!("An error occurred with wallet `{}`: {}", name, e))
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn send_get_info(&self) -> anyhow::Result<WalletInfoWithProgress> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender.send(WalletCommand::GetInfo { resp }).await?;
        resp_rx.await?
    }

    pub async fn send_batch_tx(
        &self,
        request: RpcWalletTxBuilder,
    ) -> anyhow::Result<WalletResponse> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(WalletCommand::BatchTx { request, resp })
            .await?;
        resp_rx.await?
    }

    pub async fn send_get_new_address(&self, kind: AddressKind) -> anyhow::Result<String> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(WalletCommand::GetNewAddress { kind, resp })
            .await?;
        resp_rx.await?
    }

    pub async fn send_increment_address(&self, kind: AddressKind) -> anyhow::Result<String> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(WalletCommand::IncrementAddress { kind, resp })
            .await?;
        resp_rx.await?
    }

    pub async fn send_fee_bump(
        &self,
        txid: Txid,
        fee_rate: FeeRate,
        skip_tx_check: bool,
    ) -> anyhow::Result<Vec<TxResponse>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(WalletCommand::BumpFee {
                txid,
                fee_rate,
                skip_tx_check,
                resp,
            })
            .await?;
        resp_rx.await?
    }

    pub async fn send_buy(
        &self,
        listing: Listing,
        fee_rate: Option<FeeRate>,
        skip_tx_check: bool,
    ) -> anyhow::Result<TxResponse> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(WalletCommand::Buy {
                listing,
                fee_rate,
                skip_tx_check,
                resp,
            })
            .await?;
        resp_rx.await?
    }

    pub async fn send_sell(&self, space: String, price: u64) -> anyhow::Result<Listing> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(WalletCommand::Sell { space, resp, price })
            .await?;
        resp_rx.await?
    }

    pub async fn send_list_transactions(
        &self,
        count: usize,
        skip: usize,
    ) -> anyhow::Result<Vec<TxInfo>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(WalletCommand::ListTransactions { count, skip, resp })
            .await?;
        resp_rx.await?
    }

    pub async fn send_force_spend(
        &self,
        outpoint: OutPoint,
        fee_rate: FeeRate,
    ) -> anyhow::Result<TxResponse> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(WalletCommand::ForceSpendOutput {
                outpoint,
                fee_rate,
                resp,
            })
            .await?;
        resp_rx.await?
    }

    pub async fn send_list_spaces(&self) -> anyhow::Result<ListSpacesResponse> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender.send(WalletCommand::ListSpaces { resp }).await?;
        resp_rx.await?
    }

    pub async fn send_list_nums(&self) -> anyhow::Result<ListNumsResponse> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender.send(WalletCommand::ListPtrs { resp }).await?;
        resp_rx.await?
    }

    pub async fn send_list_bidouts(&self) -> anyhow::Result<Vec<DoubleUtxo>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(WalletCommand::ListBidouts { resp })
            .await?;
        resp_rx.await?
    }

    pub async fn send_list_unspent(&self) -> anyhow::Result<Vec<WalletOutput>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(WalletCommand::ListUnspent { resp })
            .await?;
        resp_rx.await?
    }

    pub async fn send_get_balance(&self) -> anyhow::Result<Balance> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender.send(WalletCommand::GetBalance { resp }).await?;
        resp_rx.await?
    }

    pub async fn unload_wallet(&self) {
        _ = self.sender.send(WalletCommand::UnloadWallet);
    }

    pub async fn send_sign_schnorr(
        &self,
        subject: Subject,
        message: Vec<u8>,
    ) -> anyhow::Result<schnorr::Signature> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(WalletCommand::SignSchnorr {
                subject,
                message,
                resp,
            })
            .await?;
        resp_rx.await?
    }

    pub async fn send_can_operate(&self, subject: Subject) -> anyhow::Result<bool> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(WalletCommand::CanOperate { subject, resp })
            .await?;
        resp_rx.await?
    }

    pub async fn send_sign_event(
        &self,
        subject: Subject,
        event: NostrEvent,
    ) -> anyhow::Result<NostrEvent> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(WalletCommand::SignEvent {
                subject,
                event,
                resp,
            })
            .await?;
        resp_rx.await?
    }
}

// Extracts fee rate from example rpc message: "insufficient fee, rejecting replacement
// 96bb0d5fa00a35e888ff8afb5b41903955b8f34b5b2de01d874ae579a4d1eba0;
// new feerate 0.01000000 BTC/kvB <= old feerate 0.01000000 BTC/kvB"
fn fee_rate_from_message(message: &str) -> Option<FeeRate> {
    // Check if the message contains the expected error
    if !message.contains("insufficient fee, rejecting replacement") {
        return None;
    }

    let parts: Vec<&str> = message.split(';').collect();
    let fee_part = parts.get(1)?;

    let fee_rates: Vec<&str> = fee_part.trim().split("<=").collect();
    let old_fee_str = fee_rates.get(1)?;

    let fee_value = old_fee_str.split_whitespace().nth(2)?.parse::<f64>().ok()?;

    let fee_rate_sat_vb = (fee_value * 100_000.0) as u64;
    FeeRate::from_sat_per_vb(fee_rate_sat_vb)
}

async fn named_future<T>(
    name: String,
    rx: oneshot::Receiver<T>,
) -> (String, Result<T, oneshot::error::RecvError>) {
    (name, rx.await)
}

fn advance_address_to_unique_num_spk(
    chain: &mut Chain,
    w: &mut SpacesWallet,
) -> anyhow::Result<ScriptBuf> {
    loop {
        let addr = w.reveal_next_space_address();
        let spk = addr.script_pubkey();
        let id = NumId::from_spk::<Sha256>(spk);
        if chain.get_num_outpoint_by_id(&id)?.is_some() {
            continue;
        }
        // the num utxo may not be present, but its id can still be delegated
        let dk = DelegatorKey::from_id::<Sha256>(id);
        match chain.get_delegator(&dk)? {
            None => return Ok(addr.script_pubkey()),
            Some(_) => continue,
        }
    }
}


fn find_delegate_utxo(chain: &mut Chain, subject: &Subject) -> anyhow::Result<FullNumOut> {
    let num_id = match &subject {
        Subject::NumId(id) => Some(id.clone()),
        Subject::Label(label) if label.is_numeric() => {
            let numeric: SNumeric = label
                .clone()
                .try_into()
                .expect("valid numeric");
            let id = chain.get_num_id(&numeric)?.ok_or_else(|| {
                anyhow!("delegate: numeric '{}' not found", label)
            })?;
            Some(id)
        }
        Subject::Label(_) => None,
    };

    let target = if let Some(num_id) = num_id {
        let Some(num_utxo) = chain.get_num_info(&num_id)? else {
            return Err(anyhow!("delegate: num {} not found", subject));
        };

        let target = NumId::from_spk::<Sha256>(num_utxo.numout.script_pubkey);
        if target == num_id {
            return Err(anyhow!("delegate: num has no separate operator - call operate first"))
        }

        let dk = DelegatorKey::from_id::<Sha256>(target);
        let Some(delegator) = chain.get_delegator(&dk)? else {
            return Err(anyhow!("delegate: num {} is not operated - call operate first", subject));
        };
        if !delegator.is_numeric() {
            return Err(anyhow!("delegate: num {} is delegated to {} - call operate to switch",
                subject, delegator));
        }
        let numeric : SNumeric = delegator.clone().try_into().expect("valid numeric");

        if numeric != num_utxo.numout.num.name {
            return Err(anyhow!("delegate: num {} is delegated to {} - call operate to switch",
                subject, delegator));
        }

        target
    } else {
        let Subject::Label(label) = subject else {
            return Err(anyhow!("delegate: expected a space, got {}", subject))
        };

        let space_utxo = chain
            .get_space_info(&SpaceKey::from(Sha256::hash(label.as_ref())))?
            .ok_or_else(|| anyhow!("delegate: space '{}' not found", label))?;
        let Some(space) = space_utxo.spaceout.space else {
            return Err(anyhow!("delegate: space {} not found", subject));
        };

        let target = NumId::from_spk::<Sha256>(space_utxo.spaceout.script_pubkey);
        let dk = DelegatorKey::from_id::<Sha256>(target);
        let Some(delegator) = chain.get_delegator(&dk)? else {
            return Err(anyhow!("delegate: space {} is not operated - call operate first", subject));
        };

        if delegator != space.name {
            return Err(anyhow!("delegate: num {} is delegated to {} - call operate to switch",
            target, delegator)
            );
        }

        target
    };

    let Some(num_utxo) = chain.get_num_info(&target)? else {
        return Err(anyhow!("delegate: target '{}' not found - call operate first", target));
    };

    Ok(num_utxo)
}
