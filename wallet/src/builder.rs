use crate::{
    address::SpaceAddress, tx_event::TxRecord, DoubleUtxo, FullTxOut, SpaceScriptSigningInfo,
    SpacesWallet,
};
use anyhow::{anyhow, Context};

use bdk_wallet::{
    coin_selection::{
        CoinSelectionAlgorithm, CoinSelectionResult, DefaultCoinSelectionAlgorithm,
        InsufficientFunds,
    },
    error::CreateTxError,
    tx_builder::TxOrdering,
    KeychainKind, TxBuilder, Utxo, WeightedUtxo,
};
use bitcoin::{
    absolute::LockTime, key::rand::RngCore, psbt::Input, script, script::PushBytesBuf, Address,
    Amount, FeeRate, Network, OutPoint, Psbt, Script, ScriptBuf, Sequence, Transaction, TxOut,
    Txid, Weight, Witness,
};

use spaces_nums::{create_commitment_script, CommitmentOp, FullNumOut};
use spaces_protocol::hasher::Hash;
use spaces_protocol::script::{create_data_script, create_open_data, nop_script};
use spaces_protocol::{
    bitcoin::absolute::Height,
    constants::{BID_PSBT_INPUT_SEQUENCE, BID_PSBT_TX_VERSION},
    Covenant, FullSpaceOut, Space,
};
use std::{
    cmp::min,
    collections::BTreeMap,
    default::Default,
    ops::{Add, Mul},
    str::FromStr,
};

#[derive(Debug, Clone)]
pub struct Builder {
    /// The requests to bundle into transactions
    requests: Vec<StackRequest>,

    /// The fee rate
    fee_rate: Option<FeeRate>,

    /// Outputs that can be auctioned off during the bidding process
    /// If not specified it will create the minimum number of auction
    /// outputs needed to fulfill the given requests
    bidouts: Option<u8>,

    /// Whether to allow invalid transactions
    /// e.g. opens for name that already exist ... etc.
    /// enable only for testing purposes!
    force: bool,

    /// Optional data to attach to PTR transfers via OP_RETURN
    data: Option<Vec<u8>>,
}

pub struct BuilderIterator<'a> {
    stack: Vec<StackOp>,
    fee_rate: FeeRate,
    dust: Option<Amount>,
    pub wallet: &'a mut SpacesWallet,
    force: bool,
    median_time: u64,
    confirmed_only: bool,
    unspendables: Vec<OutPoint>,
}

pub enum BuilderStack {
    Request(StackRequest),
    CommitInfo((SpaceScriptSigningInfo, TxOut)),
}

#[derive(Debug, Clone)]
pub struct DoubleOutput {
    pub txid: Txid,
    pub connecting_vout: (u32, TxOut),
    pub auctioned_vout: (u32, TxOut),
}

#[derive(Debug, Clone)]
pub enum StackRequest {
    Open(OpenRequest),
    Bid(BidRequest),
    Register(RegisterRequest),
    Transfer(SpaceTransfer),
    Send(CoinTransfer),
    Execute(ExecuteRequest),
    Num(NumRequest),
    NumTransfer(NumTransfer),
    NumDelegate(NumDelegate),
    Commitment(CommitmentRequest),
}

pub enum StackOp {
    Prepare(CreateParams),
    Open(OpenRevealParams),
    Bid(BidRequest),
    Num(NumParams),
    NumDelegate(NumDelegate),
    Commitment(Vec<CommitmentRequest>),
}

#[derive(Clone)]
pub struct SpaceScriptRevealParams {
    signing: SpaceScriptSigningInfo,
    commitment: FullTxOut,
}

#[derive(Clone)]
pub struct OpenRevealParams {
    space: String,
    initial_bid: Amount,
    script: SpaceScriptRevealParams,
}

#[derive(Debug, Clone)]
pub struct RegisterRequest {
    pub space: FullSpaceOut,
    pub to: Option<SpaceAddress>,
}

#[derive(Debug, Clone)]
pub struct NumRequest {
    pub bind_spk: ScriptBuf,
}

#[derive(Debug, Clone)]
pub struct CommitmentRequest {
    pub numout: FullNumOut,
    pub root: Option<Hash>,
    /// The subject (space or num) being committed for
    pub subject: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SpaceTransfer {
    pub space: FullSpaceOut,
    pub recipient: SpaceAddress,
    pub create_num: bool,
}

#[derive(Debug, Clone)]
pub struct NumTransfer {
    pub num: FullNumOut,
    pub recipient: SpaceAddress,
    /// Whether this transfer is a delegation (authorize) rather than a regular transfer
    pub is_delegate: bool,
}

#[derive(Debug, Clone)]
pub struct NumDelegate {
    pub num: FullNumOut,
    // A new spk not used or delegated to by any num
    // owned by the wallet
    pub unique_num_spk: ScriptBuf,
}

#[derive(Debug, Clone)]
pub struct CoinTransfer {
    pub amount: Amount,
    pub recipient: Address,
}

#[derive(Debug, Clone)]
pub struct ExecuteRequest {
    pub context: Vec<SpaceTransfer>,
    pub script: script::Builder,
}

pub struct CreateParams {
    opens: Vec<OpenRequest>,
    executes: Vec<ExecuteRequest>,
    transfers: Vec<SpaceTransfer>,
    sends: Vec<CoinTransfer>,
    bidouts: Option<u8>,
    data: Option<Vec<u8>>,
}

pub struct NumParams {
    transfers: Vec<NumTransfer>,
    binds: Vec<NumRequest>,
    data: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct OpenRequest {
    name: String,
    initial_amount: Amount,
}

#[derive(Clone, Debug)]
pub struct BidRequest {
    space: FullSpaceOut,
    amount: Amount,
}

trait TxBuilderSpacesUtils<'a, Cs: CoinSelectionAlgorithm> {
    fn add_refund(&mut self, info: &FullSpaceOut) -> anyhow::Result<&mut Self>;
    fn add_bid(
        &mut self,
        prev_space: Option<&Space>,
        offer: Psbt,
        placeholder: DoubleUtxo,
        amount: Amount,
        allow_unsafe: bool,
    ) -> anyhow::Result<&mut Self>;

    fn add_reveal(
        &mut self,
        commitment: FullTxOut,
        signing: SpaceScriptSigningInfo,
    ) -> anyhow::Result<&mut Self>;

    fn add_transfer(&mut self, request: SpaceTransfer) -> anyhow::Result<&mut Self>;

    fn add_send(&mut self, request: CoinTransfer) -> anyhow::Result<&mut Self>;
}

pub fn tap_key_spend_weight() -> Weight {
    let tap_key_spend_weight: u64 = 66;
    Weight::from_vb(tap_key_spend_weight).expect("valid weight")
}

impl<'a, Cs: CoinSelectionAlgorithm> TxBuilderSpacesUtils<'a, Cs> for TxBuilder<'a, Cs> {
    fn add_refund(&mut self, info: &FullSpaceOut) -> anyhow::Result<&mut Self> {
        let (input, txout) = match info.refund_psbt_data() {
            None => return Err(anyhow!("expected a space in the bidding process")),
            Some(out) => out,
        };

        self.version(BID_PSBT_TX_VERSION.0);
        self.add_foreign_utxo_with_sequence(
            info.outpoint(),
            input,
            tap_key_spend_weight(),
            BID_PSBT_INPUT_SEQUENCE,
        )?;
        self.add_recipient(txout.script_pubkey, txout.value);

        Ok(self)
    }

    fn add_bid(
        &mut self,
        prev_space: Option<&Space>,
        offer: Psbt,
        placeholder: DoubleUtxo,
        amount: Amount,
        force: bool,
    ) -> anyhow::Result<&mut Self> {
        let burn_amount = match prev_space {
            None => amount,
            Some(space) => match &space.covenant {
                Covenant::Bid { total_burned, .. } => {
                    let min_bid = if force {
                        *total_burned
                    } else {
                        total_burned.add(Amount::from_sat(1))
                    };
                    if amount < min_bid {
                        return Err(anyhow!("Minimum bid is {} sats", min_bid.to_sat()));
                    }
                    amount - *total_burned
                }
                _ => return Err(anyhow!("Space not in auction")),
            },
        };

        let mut spend_input = Input {
            witness_utxo: Some(placeholder.spend.txout.clone()),
            final_script_witness: Some(Witness::default()),
            final_script_sig: Some(ScriptBuf::new()),
            proprietary: BTreeMap::new(),
            ..Default::default()
        };
        spend_input
            .proprietary
            .insert(SpacesWallet::spaces_signer("tbs"), Vec::new());

        let compressed_psbt = PushBytesBuf::try_from(SpacesWallet::compress_bid_psbt(
            placeholder.auction.outpoint.vout as u8,
            &offer,
        )?)
        .expect("compressed psbt script bytes");

        let carrier = ScriptBuf::new_op_return(&compressed_psbt);

        self.add_foreign_utxo_with_sequence(
            placeholder.spend.outpoint,
            spend_input,
            tap_key_spend_weight(),
            Sequence::ENABLE_RBF_NO_LOCKTIME,
        )?;
        self.add_recipient(carrier, burn_amount);

        Ok(self)
    }

    fn add_reveal(
        &mut self,
        commitment: FullTxOut,
        signing_info: SpaceScriptSigningInfo,
    ) -> anyhow::Result<&mut Self> {
        let mut psbt_input = Input {
            witness_utxo: Some(commitment.txout.clone()),
            // to be signed later
            final_script_witness: Some(Witness::default()),
            final_script_sig: Some(ScriptBuf::new()),
            proprietary: BTreeMap::new(),
            ..Default::default()
        };

        // Used by the internal signer after the psbt is built
        psbt_input.proprietary.insert(
            SpacesWallet::spaces_signer("reveal_signing_info"),
            signing_info.to_vec(),
        );

        self.add_foreign_utxo_with_sequence(
            commitment.outpoint,
            psbt_input,
            signing_info.satisfaction_weight(),
            Sequence::ENABLE_RBF_NO_LOCKTIME,
        )?;
        Ok(self)
    }

    fn add_transfer(&mut self, request: SpaceTransfer) -> anyhow::Result<&mut Self> {
        let output_value = space_dust(
            request
                .space
                .spaceout
                .script_pubkey
                .minimal_non_dust()
                .mul(2),
        );

        self.add_utxo(OutPoint {
            txid: request.space.txid,
            vout: request.space.spaceout.n as u32,
        })?;

        self.add_recipient(
            request.recipient.script_pubkey(),
            // TODO: another reason we need to keep more metadata
            // we use a special dust value here so that list auction
            // outputs won't accidentally auction off this output
            output_value,
        );

        Ok(self)
    }

    fn add_send(&mut self, request: CoinTransfer) -> anyhow::Result<&mut Self> {
        self.add_recipient(request.recipient.script_pubkey(), request.amount);
        Ok(self)
    }
}

impl Builder {
    #[allow(unused_assignments)]
    fn prepare_all(
        median_time: u64,
        w: &mut SpacesWallet,
        auction_outputs: Option<u8>,
        reveals: Option<&Vec<SpaceScriptSigningInfo>>,
        space_transfers: Vec<SpaceTransfer>,
        coin_transfers: Vec<CoinTransfer>,
        unspendables: Vec<OutPoint>,
        fee_rate: FeeRate,
        dust: Option<Amount>,
        confirmed_only: bool,
        data: Option<Vec<u8>>,
    ) -> anyhow::Result<(Transaction, Vec<FullTxOut>)> {
        let mut vout: u32 = 0;
        let mut tap_outputs = Vec::new();
        let change_address = w
            .internal
            .next_unused_address(KeychainKind::Internal)
            .script_pubkey();

        let mut placeholder_outputs = Vec::new();
        if let Some(placeholders) = auction_outputs {
            for _ in 0..placeholders {
                // Each placeholder is 2 UTXOs: Keeping outputs adjacent to detect if
                // one is spent in an auction.
                // pointer/spend output
                let addr1 = w
                    .internal
                    .next_unused_address(KeychainKind::Internal)
                    .script_pubkey();
                let dust = match dust {
                    None => addr1.minimal_non_dust().mul(2),
                    Some(dust) => dust,
                };
                let connector_dust = connector_dust(dust);
                let magic_dust = space_utxo_dust(dust);

                placeholder_outputs.push((addr1, connector_dust));
                let addr2 = w.internal.next_unused_address(KeychainKind::External);
                placeholder_outputs.push((addr2.script_pubkey(), magic_dust));
            }
        }

        let commit_psbt = {
            let mut builder = w.build_tx(unspendables, confirmed_only)?;
            builder.nlocktime(signal_space_utxo_tracking_lock_time(median_time));

            // handle transfers and collect PTR addresses
            let mut num_addresses = Vec::new();
            if !space_transfers.is_empty() {
                // Must be an odd number of outputs so that
                // transfers align correctly
                // TODO: use the actual change output instead of creating this
                if vout % 2 == 0 {
                    let dust = match dust {
                        None => change_address.minimal_non_dust().mul(2),
                        Some(dust) => dust,
                    };
                    builder.add_recipient(change_address.clone(), dust);
                    vout += 1;
                }
                for transfer in space_transfers {
                    if transfer.create_num {
                        num_addresses.push(transfer.recipient.script_pubkey());
                    }
                    builder.add_transfer(transfer)?;
                    vout += 1;
                }
            }

            for (addr, amount) in placeholder_outputs {
                builder.add_recipient(addr, amount);
                vout += 1;
            }

            if let Some(tap_data) = reveals {
                for tap_item in tap_data {
                    let dust = match dust {
                        None => tap_item.tweaked_address.minimal_non_dust().mul(2),
                        Some(dust) => dust,
                    };
                    let magic_dust = space_utxo_dust(dust);

                    builder.add_recipient(tap_item.tweaked_address.clone(), magic_dust);
                    tap_outputs.push(vout);
                    vout += 1;
                }
            }

            if !coin_transfers.is_empty() {
                for coin in coin_transfers {
                    builder.add_send(coin)?;
                    vout += 1;
                }
            }

            // Add PTR outputs for delegations
            if !num_addresses.is_empty() {
                if let Some(data) = data {
                    let data_script = create_data_script(&data);
                    builder.add_recipient(data_script, Amount::from_sat(0));
                } else {
                    // Add dummy output to absorb conflicts from PTR inputs using n+1 rule
                    // This is a temporary workaround until we have better change output control
                    let dummy_dust = Amount::from_sat(546);
                    builder.add_recipient(change_address.clone(), dummy_dust);
                }
                vout += 1;

                for spk in num_addresses {
                    builder.add_recipient(spk, num_utxo_dust(Amount::from_sat(1000)));
                    vout += 1;
                }
            } else if let Some(data) = data {
                let data_script = create_data_script(&data);
                builder.add_recipient(data_script, Amount::from_sat(0));
            }

            builder.fee_rate(fee_rate);
            let r = builder.finish().map_err(|e| match e {
                CreateTxError::CoinSelection(e) if confirmed_only => {
                    anyhow!("{} (replacements use confirmed balance only)", e)
                }
                _ => {
                    anyhow!("{}", e)
                }
            })?;
            r
        };

        let tx = w.sign(commit_psbt, None)?;
        let txid = tx.compute_txid();
        let commitments = tap_outputs
            .into_iter()
            .map(|vout| FullTxOut {
                outpoint: OutPoint { txid, vout },
                txout: tx.output[vout as usize].clone(),
            })
            .collect();

        Ok((tx, commitments))
    }
}

impl Iterator for BuilderIterator<'_> {
    type Item = anyhow::Result<TxRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        let op = match self.stack.pop() {
            None => return None,
            Some(req) => req,
        };

        match op {
            // A Prepare tx could bundle all P2TR commitments for open and other scripts
            // it can also bundle all transfers, and it can create bid outputs
            StackOp::Prepare(params) => {
                let mut reveals = Vec::with_capacity(params.opens.len() + params.executes.len());

                // Push all open script commitments
                for req in params.opens.iter() {
                    let tap = Builder::create_open_tap_data(self.wallet.config.network, &req.name)
                        .context("could not initialize tap data for name");
                    if tap.is_err() {
                        return Some(Err(tap.unwrap_err()));
                    }
                    reveals.push(tap.unwrap());
                }

                let (tx, commitments) = match Builder::prepare_all(
                    self.median_time,
                    self.wallet,
                    params.bidouts.clone(),
                    Some(&reveals),
                    params.transfers.clone(),
                    params.sends.clone(),
                    self.unspendables.clone(),
                    self.fee_rate,
                    self.dust,
                    self.confirmed_only,
                    params.data,
                ) {
                    Ok(prep) => prep,
                    Err(err) => return Some(Err(err)),
                };

                let mut detailed_tx = TxRecord::new(tx);
                if let Some(count) = params.bidouts {
                    detailed_tx.add_bidout(count as _);
                }

                let mut reveals_iter = reveals.into_iter();
                let mut commitments_iter = commitments.into_iter();

                let open_reveals = reveals_iter
                    .by_ref()
                    .take(params.opens.len())
                    .collect::<Vec<SpaceScriptSigningInfo>>()
                    .into_iter();
                let open_commitments = commitments_iter
                    .by_ref()
                    .take(params.opens.len())
                    .collect::<Vec<FullTxOut>>()
                    .into_iter();

                for ((signing, commitment), open) in
                    open_reveals.zip(open_commitments).zip(params.opens)
                {
                    detailed_tx.add_commitment(
                        open.name.clone(),
                        commitment.txout.script_pubkey.clone(),
                        signing.to_vec(),
                    );
                    self.stack.push(StackOp::Open(OpenRevealParams {
                        space: open.name,
                        initial_bid: open.initial_amount,
                        script: SpaceScriptRevealParams {
                            signing: signing.clone(),
                            commitment,
                        },
                    }));
                }

                if !params.transfers.is_empty() {
                    // TODO: resolved address recipient
                    for transfer in &params.transfers {
                        if self.wallet.is_mine(transfer.recipient.script_pubkey()) {
                            detailed_tx.add_renew(
                                transfer
                                    .space
                                    .spaceout
                                    .space
                                    .as_ref()
                                    .expect("space")
                                    .name
                                    .to_string(),
                                transfer.recipient.script_pubkey(),
                            );
                        } else {
                            detailed_tx.add_transfer(
                                transfer
                                    .space
                                    .spaceout
                                    .space
                                    .as_ref()
                                    .expect("space")
                                    .name
                                    .to_string(),
                                transfer.recipient.script_pubkey(),
                            );
                        }
                    }
                }
                if !params.sends.is_empty() {
                    // TODO: resolved address recipient
                    for send in &params.sends {
                        detailed_tx.add_send(send.amount, None, send.recipient.script_pubkey());
                    }
                }
                Some(Ok(detailed_tx))
            }
            StackOp::Open(params) => {
                let tx = Builder::open_tx(
                    self.wallet,
                    params.clone(),
                    self.fee_rate,
                    self.unspendables.clone(),
                    self.confirmed_only,
                    self.force,
                );
                Some(tx.map(|tx| {
                    let mut detailed = TxRecord::new(tx);
                    detailed.add_open(params.space, params.initial_bid);
                    detailed
                }))
            }
            StackOp::Bid(bid) => {
                let tx = Builder::bid_tx(
                    self.wallet,
                    bid.space.clone(),
                    bid.amount,
                    self.fee_rate,
                    self.unspendables.clone(),
                    self.confirmed_only,
                    self.force,
                );
                Some(tx.map(|tx| {
                    let mut detailed = TxRecord::new(tx);
                    detailed.add_bid(self.wallet, &bid.space, bid.amount);
                    detailed
                }))
            }
            StackOp::Num(params) => {
                let transfers: Vec<_> = params.transfers.iter().map(|t| {
                    (t.num.numout.num.name.to_string(), t.recipient.script_pubkey(), t.is_delegate)
                }).collect();
                let binds: Vec<_> = params.binds.iter().map(|b| {
                    b.bind_spk.clone()
                }).collect();
                let tx = create_num_tx(
                    self.wallet,
                    self.median_time,
                    self.fee_rate,
                    self.unspendables.clone(),
                    self.confirmed_only,
                    self.force,
                    params,
                );
                Some(tx.map(|tx| {
                    let mut detailed = TxRecord::new(tx);
                    for (name, spk, is_delegate) in transfers {
                        if is_delegate {
                            detailed.add_delegate(name, spk);
                        } else {
                            detailed.add_transfer_num(name, spk);
                        }
                    }
                    for spk in binds {
                        detailed.add_create_num(spk);
                    }
                    detailed
                }))
            }
            StackOp::NumDelegate(d) => {
                let num_name = d.num.numout.num.name.to_string();
                let delegate_spk = d.unique_num_spk.clone();
                let tx = create_num_delegate_tx(
                    self.wallet,
                    self.median_time,
                    self.fee_rate,
                    self.unspendables.clone(),
                    self.confirmed_only,
                    self.force,
                    d,
                );
                Some(tx.map(|tx| {
                    let mut detailed = TxRecord::new(tx);
                    detailed.add_delegate(num_name, delegate_spk);
                    detailed
                }))
            }
            StackOp::Commitment(commitments) => {
                let is_rollback = commitments.iter().all(|c| c.root.is_none());
                let event_info: Vec<_> = commitments.iter().map(|c| {
                    let root_hex = c.root.map(|r|
                        r.iter().map(|b| format!("{:02x}", b)).collect::<String>()
                    );
                    let name = c.subject.clone()
                        .unwrap_or_else(|| c.numout.numout.num.name.to_string());
                    (name, root_hex)
                }).collect();
                let tx = create_commitment_tx(
                    self.wallet,
                    self.median_time,
                    self.fee_rate,
                    self.unspendables.clone(),
                    self.confirmed_only,
                    self.force,
                    commitments,
                );
                Some(tx.map(|tx| {
                    let mut detailed = TxRecord::new(tx);
                    for (name, root) in event_info {
                        if is_rollback {
                            detailed.add_rollback_root(name);
                        } else if let Some(root) = root {
                            detailed.add_commit_root(name, root);
                        }
                    }
                    detailed
                }))
            }
        }
    }
}

impl Builder {
    pub fn new() -> Self {
        Builder {
            requests: Vec::new(),
            fee_rate: None,
            bidouts: None,
            force: false,
            data: None,
        }
    }

    pub fn fee_rate(mut self, fee_rate: FeeRate) -> Self {
        self.fee_rate = Some(fee_rate);
        self
    }

    pub fn force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    pub fn bidouts(mut self, num: u8) -> Self {
        self.bidouts = Some(num);
        self
    }

    pub fn add_bid(mut self, space: FullSpaceOut, amount: Amount) -> Self {
        self.requests
            .push(StackRequest::Bid(BidRequest { space, amount }));
        self
    }

    pub fn add_commitment(mut self, req: CommitmentRequest) -> Self {
        self.requests.push(StackRequest::Commitment(req));
        self
    }

    pub fn add_open(mut self, name: &str, initial_amount: Amount) -> Self {
        self.requests.push(StackRequest::Open(OpenRequest {
            name: name.to_string(),
            initial_amount,
        }));
        self
    }

    pub fn add_register(mut self, space: FullSpaceOut, to: Option<SpaceAddress>) -> Self {
        self.requests
            .push(StackRequest::Register(RegisterRequest { space, to }));
        self
    }

    pub fn add_transfer(mut self, request: SpaceTransfer) -> Self {
        self.requests.push(StackRequest::Transfer(request));
        self
    }

    pub fn add_num_transfer(mut self, request: NumTransfer) -> Self {
        self.requests.push(StackRequest::NumTransfer(request));
        self
    }

    pub fn add_num_delegate(mut self, request: NumDelegate) -> Self {
        self.requests.push(StackRequest::NumDelegate(request));
        self
    }

    pub fn add_data(mut self, data: Vec<u8>) -> Self {
        self.data = Some(data);
        self
    }

    pub fn add_num(mut self, request: NumRequest) -> Self {
        self.requests.push(StackRequest::Num(request));
        self
    }

    pub fn add_send(mut self, request: CoinTransfer) -> Self {
        self.requests.push(StackRequest::Send(request));
        self
    }

    pub fn add_execute(
        mut self,
        spaces: Vec<SpaceTransfer>,
        space_script: script::Builder,
    ) -> Self {
        self.requests.push(StackRequest::Execute(ExecuteRequest {
            context: spaces,
            script: space_script,
        }));
        self
    }

    pub fn build_iter(
        self,
        dust: Option<Amount>,
        median_time: u64,
        wallet: &mut SpacesWallet,
        unspendables: Vec<OutPoint>,
        confirmed_only: bool,
    ) -> anyhow::Result<BuilderIterator<'_>> {
        let fee_rate = self
            .fee_rate
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("fee_rate is required"))?
            .clone();

        let (open_count, bid_count) =
            self.requests
                .iter()
                .fold((0, 0), |mut counts, req| match req {
                    StackRequest::Open(_) => {
                        counts.0 += 1;
                        counts
                    }
                    StackRequest::Bid(_) => {
                        counts.1 += 1;
                        counts
                    }
                    _ => counts,
                });

        let required_bidouts = open_count + bid_count as u8;
        let available = if required_bidouts > 0 {
            wallet.list_bidouts(false)?
        } else {
            Vec::new()
        };

        // Always create a few more bidouts for future transactions
        const EXTRA_BIDOUTS: u8 = 2;
        // check how many bid outputs we need to create
        let auction_outputs = match self.bidouts {
            None => {
                if required_bidouts > available.len() as u8 {
                    Some((required_bidouts - available.len() as u8) + EXTRA_BIDOUTS)
                } else {
                    None
                }
            }
            Some(count) => {
                if required_bidouts > available.len() as u8 + count {
                    return Err(anyhow!(
                        "number of required bidouts {} \
                    exceeds currently available {} + requested {}",
                        required_bidouts,
                        available.len(),
                        count
                    ));
                }
                Some(count)
            }
        };

        let mut stack = Vec::new();

        let mut opens = Vec::new();
        let mut bids = Vec::new();
        let mut transfers = Vec::new();
        let mut sends = Vec::new();
        let mut executes = Vec::new();
        let mut nums = Vec::new();
        let mut num_transfers = Vec::new();
        let mut num_delegates = Vec::new();
        let mut commitments = Vec::new();
        for req in self.requests {
            match req {
                StackRequest::Open(params) => opens.push(params),
                StackRequest::Bid(params) => bids.push(params),
                StackRequest::Register(params) => {
                    let to = match params.to {
                        None => wallet.next_unused_space_address(),
                        Some(address) => address,
                    };
                    transfers.push(SpaceTransfer {
                        space: params.space,
                        recipient: to,
                        create_num: false,
                    })
                }
                StackRequest::Send(send) => sends.push(send),
                StackRequest::Transfer(params) => transfers.push(params),
                StackRequest::Execute(params) => executes.push(params),
                StackRequest::Num(params) => nums.push(params),
                StackRequest::NumTransfer(params) => num_transfers.push(params),
                StackRequest::NumDelegate(params) => num_delegates.push(params),
                StackRequest::Commitment(req) => commitments.push(req),
            }
        }

        if !bids.is_empty() {
            for bid in bids {
                stack.push(StackOp::Bid(bid))
            }
        }
        if !opens.is_empty()
            || !transfers.is_empty()
            || !sends.is_empty()
            || !executes.is_empty()
            || auction_outputs.is_some()
        {
            stack.push(StackOp::Prepare(CreateParams {
                opens,
                executes,
                transfers,
                sends,
                bidouts: auction_outputs,
                data: self.data.clone(),
            }));
        }

        if !nums.is_empty() || !num_transfers.is_empty() {
            let params = NumParams {
                transfers: num_transfers,
                binds: nums,
                data: self.data.clone(),
            };
            stack.push(StackOp::Num(params))
        }

        for d in num_delegates {
            stack.push(StackOp::NumDelegate(d));
        }

        if !commitments.is_empty() {
            stack.push(StackOp::Commitment(commitments));
        }

        Ok(BuilderIterator {
            stack,
            dust,
            fee_rate,
            wallet,
            force: self.force,
            unspendables,
            confirmed_only,
            median_time,
        })
    }

    fn bid_tx(
        w: &mut SpacesWallet,
        prev: FullSpaceOut,
        bid: Amount,
        fee_rate: FeeRate,
        unspendables: Vec<OutPoint>,
        confirmed_only: bool,
        force: bool,
    ) -> anyhow::Result<Transaction> {
        let (offer, placeholder) = w.new_bid_psbt(bid, confirmed_only)?;
        let bid_psbt = {
            let mut builder = w.build_tx(unspendables, confirmed_only)?;
            builder
                .nlocktime(LockTime::Blocks(Height::ZERO))
                .set_exact_sequence(BID_PSBT_INPUT_SEQUENCE)
                .add_bid(
                    Some(prev.spaceout.space.as_ref().unwrap()),
                    offer,
                    placeholder,
                    bid,
                    force,
                )?
                .add_refund(&prev)?
                .fee_rate(fee_rate);
            builder.finish()?
        };

        let signed = w.sign(bid_psbt, None)?;
        Ok(signed)
    }

    fn open_tx(
        w: &mut SpacesWallet,
        params: OpenRevealParams,
        fee_rate: FeeRate,
        unspendables: Vec<OutPoint>,
        confirmed_only: bool,
        force: bool,
    ) -> anyhow::Result<Transaction> {
        let (offer, placeholder) = w.new_bid_psbt(params.initial_bid, confirmed_only)?;
        let mut extra_prevouts = BTreeMap::new();
        let open_psbt = {
            let mut builder = w.build_tx(unspendables, confirmed_only)?;
            builder.ordering(TxOrdering::Untouched).add_bid(
                None,
                offer,
                placeholder,
                params.initial_bid,
                force,
            )?;

            builder.add_reveal(params.script.commitment.clone(), params.script.signing)?;
            extra_prevouts.insert(
                params.script.commitment.outpoint,
                params.script.commitment.txout,
            );

            builder.fee_rate(fee_rate);
            builder.finish()?
        };

        let signed = w.sign(open_psbt, Some(extra_prevouts))?;
        Ok(signed)
    }

    fn create_open_tap_data(
        network: Network,
        name: &str,
    ) -> anyhow::Result<SpaceScriptSigningInfo> {
        let sname = spaces_protocol::slabel::SLabel::from_str(name).expect("valid space name");
        let nop = nop_script(create_open_data(sname));
        SpaceScriptSigningInfo::new(network, nop)
    }
}

#[derive(Debug, Clone)]
pub struct SelectionOutput {
    pub outpoint: OutPoint,
    pub is_space: bool,
    pub is_spaceout: bool,
}

/// A coin selection algorithm that :
/// 1. Guarantees required utxos are ordered first appending
/// any funding/change outputs to the end of the selected utxos.
/// 2. Excludes all dust outputs to avoid accidentally spending space utxos
/// 3. Enables adding additional output exclusions
#[derive(Debug, Clone)]
pub struct SpacesAwareCoinSelection {
    pub default_algorithm: DefaultCoinSelectionAlgorithm,
    // Exclude outputs
    pub exclude_outputs: Vec<OutPoint>,
    // Whether to use confirmed only outputs
    // to fund the transaction
    pub confirmed_only: bool,
}

impl SpacesAwareCoinSelection {
    // Will skip any outputs with value less than the dust threshold
    // to avoid accidentally spending space outputs
    pub const DUST_THRESHOLD: Amount = Amount::from_sat(1200);
    pub fn new(excluded: Vec<OutPoint>, confirmed_only: bool) -> Self {
        Self {
            default_algorithm: DefaultCoinSelectionAlgorithm::default(),
            exclude_outputs: excluded,
            confirmed_only,
        }
    }
}

impl CoinSelectionAlgorithm for SpacesAwareCoinSelection {
    fn coin_select<R: RngCore>(
        &self,
        required_utxos: Vec<WeightedUtxo>,
        mut optional_utxos: Vec<WeightedUtxo>,
        fee_rate: FeeRate,
        target_amount: Amount,
        drain_script: &Script,
        rand: &mut R,
    ) -> Result<CoinSelectionResult, InsufficientFunds> {
        let required = required_utxos
            .iter()
            .map(|w| w.utxo.clone())
            .collect::<Vec<_>>();

        // Filter out UTXOs that are either explicitly excluded or below the dust threshold
        optional_utxos.retain(|weighted_utxo| {
            if self.confirmed_only {
                match &weighted_utxo.utxo {
                    Utxo::Local(local) => {
                        if !local.chain_position.is_confirmed() {
                            return false;
                        }
                    }
                    _ => {}
                }
            }

            weighted_utxo.utxo.txout().value > SpacesAwareCoinSelection::DUST_THRESHOLD
                && !self
                    .exclude_outputs
                    .iter()
                    .any(|o| o == &weighted_utxo.utxo.outpoint())
        });

        let mut result = self.default_algorithm.coin_select(
            required_utxos,
            optional_utxos,
            fee_rate,
            target_amount,
            drain_script,
            rand,
        )?;

        let mut optional = Vec::with_capacity(result.selected.len() - required.len());
        for utxo in result.selected.drain(..) {
            if !required.iter().any(|u| u == &utxo) {
                optional.push(utxo);
            }
        }

        let mut selected = Vec::with_capacity(required.len() + optional.len());
        selected.extend(required);
        selected.extend(optional);

        Ok(CoinSelectionResult {
            selected,
            fee_amount: result.fee_amount,
            excess: result.excess,
        })
    }
}

pub fn signal_num_tracking_lock_time(median_time: u64) -> LockTime {
    let median_time = min(median_time, u32::MAX as u64) as u32;
    let magic_time = median_time - (median_time % 1000) - (1000 - 777);
    LockTime::from_time(magic_time).expect("valid time")
}

pub fn num_utxo_dust(amount: Amount) -> Amount {
    let amount = amount.to_sat();
    Amount::from_sat(amount - (amount % 10) + 7)
}

pub fn num_utxo_delegate_dust(amount: Amount) -> Amount {
    let amount = amount.to_sat();
    Amount::from_sat(amount - (amount % 10) + 8)
}

pub fn is_num_utxo_delegate_dust(amount: Amount) -> bool {
    amount.to_sat() % 10 == 8
}

pub fn signal_space_utxo_tracking_lock_time(median_time: u64) -> LockTime {
    let median_time = min(median_time, u32::MAX as u64) as u32;
    let magic_time = median_time - (median_time % 1000) - (1000 - 222);
    LockTime::from_time(magic_time).expect("valid time")
}

pub fn space_utxo_dust(amount: Amount) -> Amount {
    let amount = amount.to_sat();
    Amount::from_sat(amount - (amount % 10) + 2)
}

pub fn connector_dust(amount: Amount) -> Amount {
    let amount = amount.to_sat();
    Amount::from_sat(amount - (amount % 10) + 4)
}

pub fn is_connector_dust(amount: Amount) -> bool {
    amount.to_sat() % 10 == 4
}

// Special dust value to indicate this output is a space
// could be removed once we track output metadata in some db
pub fn space_dust(amount: Amount) -> Amount {
    let amount = amount.to_sat();
    Amount::from_sat(amount - (amount % 10) + 6)
}

pub fn is_space_dust(amount: Amount) -> bool {
    amount.to_sat() % 10 == 6
}

fn create_num_delegate_tx(
    w: &mut SpacesWallet,
    median_time: u64,
    fee_rate: FeeRate,
    unspendables: Vec<OutPoint>,
    confirmed_only: bool,
    _force: bool,
    d: NumDelegate,
) -> anyhow::Result<Transaction> {
    let mut builder = w.build_tx(unspendables, confirmed_only)?;
    builder
        .nlocktime(signal_num_tracking_lock_time(median_time))
        .fee_rate(fee_rate);

    // Spend the num we want to delegate at input N
    builder
        .add_utxo(d.num.outpoint())
        .map_err(|e| anyhow!("could not transfer num at {}:{}", d.num.outpoint(), e))?;

    // if num utxo is already delegate dust signaling,
    // we can do a normal transfer: input n -> output n (keep same value)
    let (a, b) = if is_num_utxo_delegate_dust(d.num.numout.value) {
        (d.num.numout.value, num_utxo_dust(Amount::from_sat(1000)))
    } else {
        // Swap the value order so we use N+1 rule:
        // output N gets a new mint with a DIFFERENT value to trigger the fall,
        // output N+1 gets the original num rebound with delegate dust.
        let new_mint = if d.num.numout.value == num_utxo_dust(Amount::from_sat(1000)) {
            num_utxo_dust(Amount::from_sat(800))
        } else {
            num_utxo_dust(Amount::from_sat(1000))
        };
        (
            new_mint,
            num_utxo_delegate_dust(d.num.numout.value),
        )
    };
    builder.add_recipient(d.unique_num_spk.clone(), a);
    builder.add_recipient(d.unique_num_spk, b);

    let psbt = builder.finish()?;
    let signed = w.sign(psbt, None)?;
    Ok(signed)
}

fn create_commitment_tx(
    w: &mut SpacesWallet,
    median_time: u64,
    fee_rate: FeeRate,
    unspendables: Vec<OutPoint>,
    confirmed_only: bool,
    _force: bool,
    commitments: Vec<CommitmentRequest>,
) -> anyhow::Result<Transaction> {
    let mut builder = w.build_tx(unspendables, confirmed_only)?;
    builder
        .nlocktime(signal_num_tracking_lock_time(median_time))
        .fee_rate(fee_rate);

    let script = if commitments.iter().all(|c| c.root.is_none()) {
        // rollback
        create_commitment_script(&CommitmentOp::Rollback)
    } else if commitments.iter().all(|c| c.root.is_some()) {
        let roots = commitments
            .iter()
            .map(|c| c.root.unwrap())
            .collect::<Vec<_>>();
        create_commitment_script(&CommitmentOp::Commit(roots))
    } else {
        return Err(anyhow!(
            "cannot combine rollbacks and new commitments in the same tx"
        ));
    };

    // Transfer nums we're committing
    for c in commitments {
        let outpoint = OutPoint {
            txid: c.numout.txid,
            vout: c.numout.numout.n as _,
        };
        // spend num
        builder
            .add_utxo(outpoint)
            .map_err(|e| anyhow!("could not spend snum at {}:{}", outpoint, e))?;
        // add replacement at the same index
        builder.add_recipient(c.numout.numout.script_pubkey.clone(), c.numout.numout.value);
    }

    // Add OP_RETURN commitment last
    builder.add_recipient(script, Amount::from_sat(0));

    let psbt = builder.finish()?;
    let signed = w.sign(psbt, None)?;
    Ok(signed)
}

fn create_num_tx(
    w: &mut SpacesWallet,
    median_time: u64,
    fee_rate: FeeRate,
    unspendables: Vec<OutPoint>,
    confirmed_only: bool,
    _force: bool,
    params: NumParams,
) -> anyhow::Result<Transaction> {
    let mut builder = w.build_tx(unspendables, confirmed_only)?;
    builder
        .nlocktime(signal_num_tracking_lock_time(median_time))
        .fee_rate(fee_rate);

    let has_transfers = !params.transfers.is_empty();

    // Handle transfers:
    for transfer in params.transfers {
        let outpoint = OutPoint {
            txid: transfer.num.txid,
            vout: transfer.num.numout.n as _,
        };

        // spend num
        builder
            .add_utxo(outpoint)
            .map_err(|e| anyhow!("could not transfer num at {}:{}", outpoint, e))?;
        // add replacement output at the same index
        builder.add_recipient(
            transfer.recipient.script_pubkey(),
            transfer.num.numout.value,
        );
    }

    // Handle binds: add any binds last to not mess with input/output order for transfers
    for num in params.binds {
        builder.add_recipient(num.bind_spk, num_utxo_dust(Amount::from_sat(1000)));
    }

    // Add data OP_RETURN if present (only makes sense with transfers)
    if let Some(data) = params.data {
        if has_transfers {
            let script = create_data_script(&data);
            builder.add_recipient(script, Amount::from_sat(0));
        }
    }

    let psbt = builder.finish()?;
    let signed = w.sign(psbt, None)?;
    Ok(signed)
}
