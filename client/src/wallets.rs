use std::{collections::BTreeMap, str::FromStr, time::Duration};

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
    script::SpaceScript,
    slabel::SLabel,
    FullSpaceOut, SpaceOut,
};
use spaces_wallet::{
    address::SpaceAddress,
    bdk_wallet::{
        chain::{local_chain::CheckPoint, BlockId},
        KeychainKind,
    },
    bitcoin,
    bitcoin::{Address, Amount, FeeRate, OutPoint},
    builder::{CoinTransfer, SpaceTransfer, SpacesAwareCoinSelection},
    tx_event::{TxEvent, TxEventKind, TxRecord},
    Balance, DoubleUtxo, Listing, SpacesWallet, WalletInfo, WalletOutput,
};
use tabled::Tabled;
use tokio::{
    select,
    sync::{broadcast, mpsc, mpsc::Receiver, oneshot},
    time::Instant,
};

use crate::{
    checker::TxChecker,
    client::BlockSource,
    config::ExtendedNetwork,
    rpc::{RpcWalletRequest, RpcWalletTxBuilder, SignedMessage, WalletLoadRequest},
    source::{
        BitcoinBlockSource, BitcoinRpc, BitcoinRpcError, BlockEvent, BlockFetchError, BlockFetcher,
    },
    std_wait,
    store::{ChainState, LiveSnapshot, Sha256},
};

const MEMPOOL_CHECK_INTERVAL: Duration =
    Duration::from_secs(if cfg!(debug_assertions) { 1 } else { 5 * 60 });

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<BTreeMap<String, String>>,
    pub txid: Txid,
    pub events: Vec<TxEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSpacesResponse {
    pub winning: Vec<FullSpaceOut>,
    pub outbid: Vec<FullSpaceOut>,
    pub owned: Vec<FullSpaceOut>,
}

#[derive(Tabled, Debug, Clone, Serialize, Deserialize)]
#[tabled(rename_all = "UPPERCASE")]
pub struct TxInfo {
    pub txid: Txid,
    pub confirmed: bool,
    pub sent: Amount,
    pub received: Amount,
    #[tabled(display_with = "display_fee")]
    pub fee: Option<Amount>,
    #[tabled(rename = "DETAILS", display_with = "display_events")]
    pub events: Vec<TxEvent>,
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
pub struct WalletResponse {
    pub result: Vec<TxResponse>,
}

pub enum WalletCommand {
    GetInfo {
        resp: crate::rpc::Responder<anyhow::Result<WalletInfo>>,
    },
    BatchTx {
        request: RpcWalletTxBuilder,
        resp: crate::rpc::Responder<anyhow::Result<WalletResponse>>,
    },
    GetNewAddress {
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
    SignMessage {
        space: String,
        msg: spaces_protocol::Bytes,
        resp: crate::rpc::Responder<anyhow::Result<SignedMessage>>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ValueEnum)]
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
        state: &mut LiveSnapshot,
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

        let (_, fullspaceout) = SpacesWallet::verify_listing::<Sha256>(state, &listing)?;

        let space = fullspaceout
            .spaceout
            .space
            .as_ref()
            .expect("space")
            .name
            .to_string();
        let previous_spaceout = fullspaceout.outpoint();
        let tx = wallet.buy::<Sha256>(state, &listing, fee_rate)?;

        if !skip_tx_check {
            let tip = wallet.local_chain().tip().height();
            let mut checker = TxChecker::new(state);
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
        state: &mut LiveSnapshot,
        wallet: &mut SpacesWallet,
        txid: Txid,
        skip_tx_check: bool,
        fee_rate: FeeRate,
    ) -> anyhow::Result<Vec<TxResponse>> {
        let unspendables = wallet.list_spaces_outpoints(state)?;
        let tx_events = wallet.get_tx_events(txid)?;
        let builder = wallet.build_fee_bump(unspendables, txid, fee_rate)?;

        let psbt = builder.finish()?;
        let replacement = wallet.sign(psbt, None)?;

        if !skip_tx_check {
            let tip = wallet.local_chain().tip().height();
            let mut checker = TxChecker::new(state);
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
        _state: &mut LiveSnapshot,
        _wallet: &mut SpacesWallet,
        _output: OutPoint,
        _fee_rate: FeeRate,
    ) -> anyhow::Result<TxResponse> {
        todo!("")
        // let coin_selection = Self::get_spaces_coin_selection(wallet, state, true)?;
        // let addre = wallet.spaces.next_unused_address(KeychainKind::External);
        // let mut builder = wallet.spaces.build_tx().coin_selection(coin_selection);
        //
        // builder.ordering(TxOrdering::Untouched);
        // builder.fee_rate(fee_rate);
        // builder.add_utxo(output)?;
        // builder.add_recipient(addre.script_pubkey(), Amount::from_sat(5000));
        //
        // let psbt = builder.finish()?;
        // let tx = wallet.sign(psbt, None)?;
        //
        // let txid = tx.compute_txid();
        // let last_seen = source.rpc.broadcast_tx(&source.client, &tx)?;
        // wallet.apply_unconfirmed_tx(tx, last_seen);
        // wallet.commit()?;
        //
        // Ok(TxResponse {
        //     txid,
        //     events: vec![],
        //     error: None,
        //     raw: None,
        // })
    }

    fn wallet_handle_commands(
        network: ExtendedNetwork,
        source: &BitcoinBlockSource,
        mut state: &mut LiveSnapshot,
        wallet: &mut SpacesWallet,
        command: WalletCommand,
        synced: bool,
    ) -> anyhow::Result<()> {
        match command {
            WalletCommand::GetInfo { resp } => _ = resp.send(Ok(wallet.get_info())),
            WalletCommand::BatchTx { request, resp } => {
                if !synced && !request.force {
                    _ = resp.send(Err(anyhow::anyhow!("Wallet is syncing")));
                    return Ok(());
                }
                let batch_result = Self::batch_tx(network, &source, wallet, &mut state, request);
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
                    &mut state,
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
                    Self::handle_force_spend_output(source, &mut state, wallet, outpoint, fee_rate);
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
            WalletCommand::ListUnspent { resp } => {
                _ = resp.send(wallet.list_unspent_with_details(state));
            }
            WalletCommand::ListTransactions { count, skip, resp } => {
                let transactions = Self::list_transactions(wallet, count, skip);
                _ = resp.send(transactions);
            }
            WalletCommand::ListSpaces { resp } => {
                let result = Self::list_spaces(wallet, state);
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
                    state,
                    wallet,
                    listing,
                    skip_tx_check,
                    fee_rate,
                ));
            }
            WalletCommand::Sell { space, price, resp } => {
                _ = resp.send(wallet.sell::<Sha256>(state, &space, Amount::from_sat(price)));
            }
            WalletCommand::SignMessage { space, msg, resp } => {
                match wallet.sign_message::<Sha256>(state, &space, msg.as_slice()) {
                    Ok(signature) => {
                        _ = resp.send(Ok(SignedMessage {
                            space,
                            message: msg,
                            signature,
                        }));
                    }
                    Err(err) => {
                        _ = resp.send(Err(err));
                    }
                }
            }
        }
        Ok(())
    }

    /// Returns true if Bitcoin, protocol, and wallet tips match.
    fn all_synced(
        bitcoin: &BitcoinBlockSource,
        protocol: &mut LiveSnapshot,
        wallet: &SpacesWallet,
    ) -> Option<ChainAnchor> {
        let bitcoin_tip = match bitcoin.get_best_chain() {
            Ok(tip) => tip,
            Err(e) => {
                warn!("Sync check failed: {}", e);
                return None;
            }
        };
        let wallet_tip = wallet.local_chain().tip();
        let protocol_tip = match protocol.tip.read() {
            Ok(tip) => tip.clone(),
            Err(e) => {
                warn!("Failed to read protocol tip: {}", e);
                return None;
            }
        };
        if protocol_tip.hash == wallet_tip.hash() && protocol_tip.hash == bitcoin_tip.hash {
            Some(bitcoin_tip)
        } else {
            None
        }
    }

    fn wallet_sync(
        network: ExtendedNetwork,
        source: BitcoinBlockSource,
        mut state: LiveSnapshot,
        mut wallet: SpacesWallet,
        mut commands: Receiver<WalletCommand>,
        shutdown: broadcast::Sender<()>,
        num_workers: usize,
    ) -> anyhow::Result<()> {
        let (fetcher, receiver) = BlockFetcher::new(source.clone(), num_workers);

        let mut wallet_tip = {
            let tip = wallet.local_chain().tip();
            ChainAnchor {
                height: tip.height(),
                hash: tip.hash(),
            }
        };

        let mut shutdown_recv = shutdown.subscribe();
        fetcher.start(wallet_tip);
        let mut synced_at_least_once = false;
        let mut last_mempool_check = Instant::now();
        loop {
            if shutdown_recv.try_recv().is_ok() {
                info!("Shutting down wallet sync");
                break;
            }
            if let Ok(command) = commands.try_recv() {
                let synced = Self::all_synced(&source, &mut state, &wallet).is_some();
                Self::wallet_handle_commands(
                    network,
                    &source,
                    &mut state,
                    &mut wallet,
                    command,
                    synced,
                )?;
            }
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

                        if id.height % 12 == 0 {
                            wallet.commit()?;
                        }
                    }
                    BlockEvent::Error(e) if matches!(e, BlockFetchError::BlockMismatch) => {
                        let mut checkpoint_in_chain = None;
                        let best_chain = match source.get_best_chain() {
                            Ok(best) => best,
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
                if let Some(common_tip) = Self::all_synced(&source, &mut state, &wallet) {
                    let mem = MempoolChecker(&source);
                    match wallet.update_unconfirmed_bids(mem, common_tip.height, &mut state) {
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

    fn list_spaces(
        wallet: &mut SpacesWallet,
        state: &mut LiveSnapshot,
    ) -> anyhow::Result<ListSpacesResponse> {
        let unspent = wallet.list_unspent_with_details(state)?;
        let recent_events = wallet.list_recent_events()?;

        let mut res = ListSpacesResponse {
            winning: vec![],
            outbid: vec![],
            owned: vec![],
        };
        for (txid, event) in recent_events {
            if unspent.iter().any(|out| {
                out.space
                    .as_ref()
                    .is_some_and(|s| &s.name.to_string() == event.space.as_ref().unwrap())
            }) {
                continue;
            }
            let name = SLabel::from_str(event.space.as_ref().unwrap()).expect("valid space name");
            let spacehash = SpaceKey::from(Sha256::hash(name.as_ref()));
            let space = state.get_space_info(&spacehash)?;
            if let Some(space) = space {
                let tx = wallet.get_tx(txid);
                if tx.is_none() {
                    res.outbid.push(space);
                    continue;
                }

                if event
                    .previous_spaceout
                    .is_some_and(|input| input == space.outpoint())
                {
                    continue;
                }
                res.outbid.push(space);
            }
        }

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

            let space = entry.spaceout.space.as_ref().expect("space");
            if matches!(space.covenant, spaces_protocol::Covenant::Bid { .. }) {
                res.winning.push(entry);
            } else if matches!(space.covenant, spaces_protocol::Covenant::Transfer { .. }) {
                res.owned.push(entry);
            }
        }

        Ok(res)
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
                let tx = ctx.tx_node.tx.clone();
                let txid = ctx.tx_node.txid.clone();
                let confirmed = ctx.chain_position.is_confirmed();
                let (sent, received) = wallet.sent_and_received(&tx);
                let fee = wallet.calculate_fee(&tx).ok();
                TxInfo {
                    txid,
                    confirmed,
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
        store: &mut LiveSnapshot,
        to: &str,
        require_space_address: bool,
    ) -> anyhow::Result<Option<Address>> {
        if let Ok(address) = Address::from_str(to) {
            if require_space_address {
                return Err(anyhow!("recipient must be a space address"));
            }
            return Ok(Some(address.require_network(network.fallback_network())?));
        }
        if let Ok(space_address) = SpaceAddress::from_str(to) {
            return Ok(Some(space_address.0));
        }

        let sname = match SLabel::from_str(to) {
            Ok(sname) => sname,
            Err(_) => {
                return Err(anyhow!(
                    "recipient must be a valid space name prefixed with @ or an address"
                ));
            }
        };

        let spacehash = SpaceKey::from(Sha256::hash(sname.as_ref()));
        let script_pubkey = match store.get_space_info(&spacehash)? {
            None => return Ok(None),
            Some(fullspaceout) => fullspaceout.spaceout.script_pubkey,
        };

        Ok(Some(Address::from_script(
            script_pubkey.as_script(),
            network.fallback_network(),
        )?))
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
        store: &mut LiveSnapshot,
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
                    let recipient = match Self::resolve(network, store, &params.to, false)? {
                        None => return Err(anyhow!("send: could not resolve '{}'", params.to)),
                        Some(r) => r,
                    };
                    builder = builder.add_send(CoinTransfer {
                        amount: params.amount,
                        recipient: recipient.clone(),
                    });
                }
                RpcWalletRequest::Transfer(params) => {
                    let spaces: Vec<_> = params
                        .spaces
                        .iter()
                        .filter_map(|space| SLabel::from_str(space).ok())
                        .collect();
                    if spaces.len() != params.spaces.len() {
                        return Err(anyhow!("transfer: some names were malformed"));
                    }

                    let recipient = if let Some(to) = params.to {
                        match Self::resolve(network, store, &to, true)? {
                            None => return Err(anyhow!("transfer: could not resolve '{}'", to)),
                            Some(r) => Some(r),
                        }
                    } else {
                        None
                    };

                    for space in spaces {
                        let spacehash = SpaceKey::from(Sha256::hash(space.as_ref()));
                        match store.get_space_info(&spacehash)? {
                            None => return Err(anyhow!("transfer: you don't own `{}`", space)),
                            Some(full)
                                if full.spaceout.space.is_none()
                                    || !full.spaceout.space.as_ref().unwrap().is_owned()
                                    || !wallet.is_mine(full.spaceout.script_pubkey.clone()) =>
                            {
                                return Err(anyhow!("transfer: you don't own `{}`", space));
                            }

                            Some(full) if wallet.get_utxo(full.outpoint()).is_none() => {
                                return Err(anyhow!(
                                    "transfer '{}': wallet already has a pending tx for this space",
                                    space
                                ));
                            }

                            Some(full) => {
                                let recipient = match recipient.clone() {
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
                                    recipient: recipient.clone(),
                                });
                            }
                        };
                    }
                }
                RpcWalletRequest::Open(params) => {
                    let name = SLabel::from_str(&params.name)?;
                    if !tx.force {
                        // Warn if already exists
                        let spacehash = SpaceKey::from(Sha256::hash(name.as_ref()));
                        let spaceout = store.get_space_info(&spacehash)?;
                        if spaceout.is_some() {
                            return Err(anyhow!("open '{}': space already exists", params.name));
                        }
                    }

                    builder = builder.add_open(&params.name, Amount::from_sat(params.amount));
                }
                RpcWalletRequest::Bid(params) => {
                    let name = SLabel::from_str(&params.name)?;
                    let spacehash = SpaceKey::from(Sha256::hash(name.as_ref()));
                    let spaceout = store.get_space_info(&spacehash)?;
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
                    let spaceout = store.get_space_info(&spacehash)?;
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
                RpcWalletRequest::Execute(params) => {
                    let mut spaces = Vec::new();
                    for space in params.context.iter() {
                        let name = SLabel::from_str(&space)?;
                        let spacehash = SpaceKey::from(Sha256::hash(name.as_ref()));
                        let spaceout = store.get_space_info(&spacehash)?;
                        if spaceout.is_none() {
                            return Err(anyhow!("script '{}': space does not exist", space));
                        }
                        let spaceout = spaceout.unwrap();
                        if !wallet.is_mine(spaceout.spaceout.script_pubkey.clone()) {
                            return Err(anyhow!("script '{}': you don't own this space", space));
                        }

                        if wallet.get_utxo(spaceout.outpoint()).is_none() {
                            return Err(anyhow!(
                                "script '{}': wallet already has a pending tx for this space",
                                space
                            ));
                        }

                        let address = wallet.next_unused_space_address();
                        spaces.push(SpaceTransfer {
                            space: spaceout,
                            recipient: address,
                        });
                    }

                    let script = SpaceScript::nop_script(params.space_script);
                    builder = builder.add_execute(spaces, script);
                }
            }
        }

        let unspendables = wallet.list_spaces_outpoints(store)?;
        let median_time = source.get_median_time()?;
        let mut checker = TxChecker::new(store);

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
        store: LiveSnapshot,
        mut channel: Receiver<WalletLoadRequest>,
        shutdown: broadcast::Sender<()>,
        num_workers: usize,
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
                        let wallet_chain = store.clone();
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
                                  num_workers
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

    pub async fn send_get_info(&self) -> anyhow::Result<WalletInfo> {
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

    pub async fn send_sign_message(
        &self,
        space: &str,
        msg: spaces_protocol::Bytes,
    ) -> anyhow::Result<SignedMessage> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(WalletCommand::SignMessage {
                space: space.to_string(),
                msg,
                resp,
            })
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
