use std::{collections::BTreeMap, fmt::Debug, fs, ops::Mul, path::PathBuf, str::FromStr};

use anyhow::{anyhow, Context};
use bdk_wallet::{
    chain,
    chain::{
        local_chain::{CannotConnectError, LocalChain},
        tx_graph::CalculateFeeError,
        BlockId, ChainPosition, Indexer,
    },
    coin_selection::{CoinSelectionAlgorithm, CoinSelectionResult, Excess, InsufficientFunds},
    keys::DescriptorSecretKey,
    rusqlite::Connection,
    tx_builder::TxOrdering,
    AddressInfo, KeychainKind, LocalOutput, PersistedWallet, SignOptions, TxBuilder, Update,
    Wallet, WalletTx, WeightedUtxo,
};
use bincode::config;
use bitcoin::{
    absolute::{Height, LockTime},
    bip32::ChildNumber,
    consensus::Encodable,
    hashes::{sha256d, Hash, HashEngine},
    key::{rand::RngCore, TapTweak, TweakedKeypair},
    psbt,
    psbt::raw::ProprietaryKey,
    script,
    sighash::{Prevouts, SighashCache},
    taproot,
    taproot::LeafVersion,
    transaction::Version,
    Amount, Block, BlockHash, FeeRate, Network, OutPoint, Psbt, Sequence, TapLeafHash,
    TapSighashType, Transaction, TxIn, TxOut, Txid, VarInt, Weight, Witness,
};
use secp256k1::{schnorr, schnorr::Signature, Message};
use serde::{ser::SerializeSeq, Deserialize, Deserializer, Serialize, Serializer};
use spaces_protocol::{
    bitcoin::{
        constants::genesis_block,
        key::{rand, UntweakedKeypair},
        opcodes,
        taproot::{ControlBlock, TaprootBuilder},
        Address, ScriptBuf, XOnlyPublicKey,
    },
    constants::{BID_PSBT_INPUT_SEQUENCE, BID_PSBT_TX_LOCK_TIME},
    hasher::{KeyHasher, SpaceKey},
    prepare::{is_magic_lock_time, DataSource, TrackableOutput},
    slabel::SLabel,
    Covenant, FullSpaceOut, Space,
};

use crate::{
    address::SpaceAddress,
    builder::{
        is_connector_dust, is_space_dust, space_dust, tap_key_spend_weight,
        SpacesAwareCoinSelection,
    },
    tx_event::{TxEvent, TxEventKind, TxRecord},
};

pub extern crate bdk_wallet;
pub extern crate bitcoin;
extern crate core;

pub mod address;
pub mod builder;
pub mod export;
mod rusqlite_impl;
pub mod tx_event;

pub const SPACES_SIGNED_MSG_PREFIX: &[u8] = b"\x17Spaces Signed Message:\n";

pub struct SpacesWallet {
    pub config: WalletConfig,
    internal: PersistedWallet<Connection>,
    pub connection: Connection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Balance {
    pub balance: Amount,
    pub details: BalanceDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Listing {
    pub space: String,
    pub price: u64,
    pub seller: String,
    pub signature: schnorr::Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceDetails {
    #[serde(flatten)]
    pub balance: bdk_wallet::Balance,
    pub dust: Amount,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInfo {
    pub label: String,
    /// Earliest block to rescan when looking for the wallet's transactions
    pub start_block: u32,
    pub tip: u32,
    pub descriptors: Vec<DescriptorInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorInfo {
    pub descriptor: String,
    pub internal: bool,
    pub spaces: bool,
}

#[derive(Debug, Clone)]
pub struct SpaceScriptSigningInfo {
    pub(crate) ctx: secp256k1::Secp256k1<secp256k1::All>,
    pub(crate) script: ScriptBuf,
    pub(crate) control_block: ControlBlock,
    pub(crate) temp_key_pair: UntweakedKeypair,
    pub(crate) tweaked_address: ScriptBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DoubleUtxo {
    pub spend: FullTxOut,
    pub auction: FullTxOut,
    pub confirmed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletOutput {
    #[serde(flatten)]
    pub output: LocalOutput,
    pub space: Option<Space>,
    pub is_spaceout: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FullTxOut {
    pub outpoint: OutPoint,
    pub(crate) txout: TxOut,
}

#[derive(Clone, Debug)]
pub struct WalletConfig {
    pub name: String,
    pub data_dir: PathBuf,
    pub start_block: u32,
    pub network: Network,
    pub genesis_hash: Option<BlockHash>,
    pub space_descriptors: WalletDescriptors,
}

#[derive(Clone, Debug)]
pub struct WalletDescriptors {
    pub external: String,
    pub internal: String,
}

pub trait Mempool {
    fn in_mempool(&self, txid: &Txid, height: u32) -> anyhow::Result<bool>;
}

impl SpacesWallet {
    pub fn name(&self) -> &str {
        &self.config.name
    }

    pub fn init_sqlite_tables(db_tx: &chain::rusqlite::Transaction) -> chain::rusqlite::Result<()> {
        TxEvent::init_sqlite_tables(db_tx)?;
        Ok(())
    }

    pub fn new(config: WalletConfig) -> anyhow::Result<Self> {
        if !config.data_dir.exists() {
            fs::create_dir_all(config.data_dir.clone())?;
        }

        let wallet_path = config.data_dir.join("wallet.db");
        use bdk_wallet::rusqlite::Connection;

        let mut conn = Connection::open(wallet_path)?;

        let genesis_hash = match config.genesis_hash {
            None => genesis_block(config.network).block_hash(),
            Some(hash) => hash,
        };

        let spaces_wallet = if let Some(wallet) = Wallet::load()
            .check_network(config.network)
            .descriptor(
                KeychainKind::External,
                Some(config.space_descriptors.external.clone()),
            )
            .descriptor(
                KeychainKind::Internal,
                Some(config.space_descriptors.internal.clone()),
            )
            .lookahead(50)
            .extract_keys()
            .load_wallet(&mut conn)
            .context("could not load wallet")?
        {
            wallet
        } else {
            Wallet::create(
                config.space_descriptors.external.clone(),
                config.space_descriptors.internal.clone(),
            )
            .lookahead(50)
            .network(config.network)
            .genesis_hash(genesis_hash)
            .create_wallet(&mut conn)
            .context("could not create wallet")?
        };

        let tx = conn
            .transaction()
            .context("could not create wallet db transaction")?;
        Self::init_sqlite_tables(&tx).context("could not initialize wallet db tables")?;
        tx.commit()
            .context("could not commit wallet db transaction")?;

        let wallet = Self {
            config,
            internal: spaces_wallet,
            connection: conn,
        };
        Ok(wallet)
    }

    pub fn balance(&mut self) -> anyhow::Result<Balance> {
        let unspent = self.list_unspent();
        let balance = self.internal.balance();
        let details = BalanceDetails {
            balance,
            dust: unspent
                .filter(|output|
                    // confirmed or trusted pending only
                    (output.chain_position.is_confirmed() || output.keychain == KeychainKind::Internal) &&
                        (output.txout.value <= SpacesAwareCoinSelection::DUST_THRESHOLD)
                )
                .map(|output| output.txout.value)
                .sum(),
        };
        Ok(Balance {
            balance: (details.balance.confirmed + details.balance.trusted_pending) - details.dust,
            details,
        })
    }

    pub fn get_tx(&mut self, txid: Txid) -> Option<WalletTx> {
        self.internal.get_tx(txid)
    }

    pub fn get_utxo(&mut self, outpoint: OutPoint) -> Option<LocalOutput> {
        self.internal.get_utxo(outpoint)
    }

    pub fn next_unused_address(&mut self, keychain_kind: KeychainKind) -> AddressInfo {
        self.internal.next_unused_address(keychain_kind)
    }

    pub fn local_chain(&self) -> &LocalChain {
        self.internal.local_chain()
    }

    pub fn insert_checkpoint(&mut self, checkpoint: BlockId) -> Result<(), CannotConnectError> {
        let mut cp = self.internal.latest_checkpoint();
        cp = cp.insert(checkpoint);
        self.internal.apply_update(Update {
            chain: Some(cp),
            ..Default::default()
        })
    }

    pub fn transactions(&self) -> impl Iterator<Item = WalletTx> + '_ {
        self.internal
            .transactions()
            .filter(|tx| !is_revert_tx(tx) && self.internal.spk_index().is_tx_relevant(&tx.tx_node))
    }

    pub fn sent_and_received(&self, tx: &Transaction) -> (Amount, Amount) {
        self.internal.sent_and_received(tx)
    }

    pub fn calculate_fee(&self, tx: &Transaction) -> Result<Amount, CalculateFeeError> {
        self.internal.calculate_fee(tx)
    }

    pub fn build_tx(
        &mut self,
        unspendables: Vec<OutPoint>,
        confirmed_only: bool,
    ) -> anyhow::Result<TxBuilder<SpacesAwareCoinSelection>> {
        self.create_builder(unspendables, None, confirmed_only)
    }

    pub fn list_spaces_outpoints(
        &self,
        src: &mut impl DataSource,
    ) -> anyhow::Result<Vec<OutPoint>> {
        let mut outs = Vec::new();
        for unspent in self.list_unspent() {
            if src
                .get_spaceout(&unspent.outpoint)?
                .and_then(|out| out.space)
                .is_some()
            {
                outs.push(unspent.outpoint);
            }
        }
        Ok(outs)
    }

    pub fn build_fee_bump(
        &mut self,
        unspendables: Vec<OutPoint>,
        txid: Txid,
        fee_rate: FeeRate,
    ) -> anyhow::Result<TxBuilder<'_, SpacesAwareCoinSelection>> {
        let events = self.get_tx_events(txid)?;
        for event in events {
            match event.kind {
                TxEventKind::Bid => match self.get_tx(txid) {
                    Some(tx) => {
                        if !tx.chain_position.is_confirmed() {
                            return Err(anyhow!(
                                "Bid with a higher fee on `{}` to replace this tx",
                                event.space.expect("space")
                            ));
                        }
                    }
                    _ => continue,
                },
                _ => {}
            }
        }

        self.create_builder(unspendables, Some((txid, fee_rate)), false)
    }

    fn create_builder(
        &mut self,
        unspendables: Vec<OutPoint>,
        replace: Option<(Txid, FeeRate)>,
        confirmed_only: bool,
    ) -> anyhow::Result<TxBuilder<'_, SpacesAwareCoinSelection>> {
        let selection = SpacesAwareCoinSelection::new(unspendables, confirmed_only);

        let mut builder = match replace {
            None => self.internal.build_tx().coin_selection(selection),
            Some((txid, fee_rate)) => {
                let previous_tx_lock_time = match self.get_tx(txid) {
                    None => return Err(anyhow::anyhow!("No wallet tx {} found", txid)),
                    Some(tx) => tx.tx_node.lock_time,
                };
                let mut builder = self
                    .internal
                    .build_fee_bump(txid)?
                    .coin_selection(selection);
                builder.nlocktime(previous_tx_lock_time).fee_rate(fee_rate);
                builder
            }
        };

        builder.ordering(TxOrdering::Untouched);
        Ok(builder)
    }

    pub fn is_mine(&self, script: ScriptBuf) -> bool {
        self.internal.is_mine(script)
    }

    pub fn list_unspent(&self) -> impl Iterator<Item = LocalOutput> + '_ {
        self.internal.list_unspent()
    }

    pub fn list_output(&self) -> impl Iterator<Item = LocalOutput> + '_ {
        self.internal.list_output()
    }

    pub fn list_recent_events(&mut self) -> anyhow::Result<Vec<(Txid, TxEvent)>> {
        let db_tx = self.connection.transaction().context("no db transaction")?;
        TxEvent::get_latest_events(&db_tx).context("could not read latest events")
    }

    pub fn sign_message<H: KeyHasher>(
        &mut self,
        src: &mut impl DataSource,
        space: &str,
        msg: impl AsRef<[u8]>,
    ) -> anyhow::Result<Signature> {
        let label = SLabel::from_str(space)?;
        let space_key = SpaceKey::from(H::hash(label.as_ref()));
        let outpoint = match src.get_space_outpoint(&space_key)? {
            None => return Err(anyhow::anyhow!("Space not found")),
            Some(outpoint) => outpoint,
        };
        let utxo = match self.get_utxo(outpoint) {
            None => return Err(anyhow::anyhow!("Space not owned by wallet")),
            Some(utxo) => utxo,
        };

        let keypair = self
            .get_taproot_keypair(utxo.keychain, utxo.derivation_index)
            .context("Could not derive taproot keypair to sign message")?;

        let msg_hash = signed_msg_hash(msg);
        let msg_to_sign = secp256k1::Message::from_digest(msg_hash.to_byte_array());
        let ctx = secp256k1::Secp256k1::new();
        Ok(ctx.sign_schnorr(&msg_to_sign, &keypair.to_inner()))
    }

    pub fn verify_message<H: KeyHasher>(
        src: &mut impl DataSource,
        space: &str,
        msg: impl AsRef<[u8]>,
        signature: &Signature,
    ) -> anyhow::Result<()> {
        let label = SLabel::from_str(space)?;
        let space_key = SpaceKey::from(H::hash(label.as_ref()));
        let outpoint = match src.get_space_outpoint(&space_key)? {
            None => return Err(anyhow::anyhow!("Space not found")),
            Some(outpoint) => outpoint,
        };
        let spaceout = match src.get_spaceout(&outpoint)? {
            None => return Err(anyhow::anyhow!("Space not found")),
            Some(spaceout) => spaceout,
        };
        if !spaceout.script_pubkey.is_witness_program() {
            return Err(anyhow::anyhow!("Cannot verify non-taproot spaces"));
        }

        let script_bytes = spaceout.script_pubkey.as_bytes();
        if script_bytes.len() != secp256k1::constants::SCHNORR_PUBLIC_KEY_SIZE + 2 {
            return Err(anyhow::anyhow!("Expected a schnorr public key"));
        }

        let pubkey = XOnlyPublicKey::from_slice(&script_bytes[2..])?;
        let ctx = secp256k1::Secp256k1::new();
        let msg_hash = signed_msg_hash(msg);
        let msg_to_sign = Message::from_digest(msg_hash.to_byte_array());

        ctx.verify_schnorr(signature, &msg_to_sign, &pubkey)?;
        Ok(())
    }

    pub fn list_unspent_with_details(
        &mut self,
        store: &mut impl DataSource,
    ) -> anyhow::Result<Vec<WalletOutput>> {
        let mut wallet_outputs = Vec::new();
        for output in self.internal.list_unspent() {
            let mut details = WalletOutput {
                output,
                space: None,
                is_spaceout: false,
            };
            let result = store.get_spaceout(&details.output.outpoint)?;
            if let Some(spaceout) = result {
                details.is_spaceout = true;
                details.space = spaceout.space;
            }
            wallet_outputs.push(details)
        }
        Ok(wallet_outputs)
    }

    /// Checks the mempool for dropped bid transactions and reverts them in the wallet’s Tx graph,
    /// reclaiming any "stuck" funds. This is necessary because continuously scanning the entire
    /// mainnet mempool would be resource-intensive to fetch from Bitcoin Core RPC.
    pub fn update_unconfirmed_bids(
        &mut self,
        mem: impl Mempool,
        height: u32,
        data_source: &mut impl DataSource,
    ) -> anyhow::Result<Vec<Txid>> {
        let unconfirmed_bids = self.unconfirmed_bids()?;
        let mut revert_txs = Vec::new();
        for (bid, outpoint) in unconfirmed_bids {
            let in_mempool = mem.in_mempool(&bid.tx_node.txid, height)?;
            if in_mempool {
                continue;
            }
            // bid dropped from mempool perhaps it was confirmed spending outpoint?
            if data_source
                .get_spaceout(&outpoint)
                .context("could not fetch spaceout from db")?
                .is_none()
            {
                continue;
            }
            if let Some((revert, seen)) = revert_unconfirmed_bid_tx(&bid, outpoint) {
                revert_txs.push((bid.tx_node.txid, revert, seen));
            }
        }

        let mut txids = Vec::with_capacity(revert_txs.len());
        for (original, revert_tx, last_seen) in revert_txs {
            txids.push(original);
            self.apply_unconfirmed_tx(revert_tx, last_seen);
        }
        Ok(txids)
    }

    /// Returns all unconfirmed bid transactions in the wallet
    /// and any foreign outputs they're spending.
    ///
    /// This is used to monitor bid txs in the mempool
    /// to check if they have been replaced.
    pub fn unconfirmed_bids(&mut self) -> anyhow::Result<Vec<(WalletTx, OutPoint)>> {
        let txids: Vec<_> = {
            let unconfirmed: Vec<_> = self
                .transactions()
                .filter(|x| !x.chain_position.is_confirmed())
                .collect();
            unconfirmed.iter().map(|x| x.tx_node.txid).collect()
        };
        let bid_txids = {
            let db_tx = self.connection.transaction()?;
            TxEvent::filter_bids(&db_tx, txids)?
        };
        let bid_txs: Vec<_> = self
            .transactions()
            .filter(|tx| !tx.chain_position.is_confirmed())
            .filter_map(|tx| {
                bid_txids
                    .iter()
                    .find(|(bid_txid, _)| *bid_txid == tx.tx_node.txid)
                    .map(|(_, bid_outpoint)| (tx, *bid_outpoint))
            })
            .collect();
        Ok(bid_txs)
    }

    pub fn get_tx_events(&mut self, txid: Txid) -> anyhow::Result<Vec<TxEvent>> {
        let db_tx = self
            .connection
            .transaction()
            .context("could not get wallet db transaction")?;
        let result = TxEvent::all(&db_tx, txid).context("could not get wallet db tx events")?;
        Ok(result)
    }

    pub fn rebuild(self) -> anyhow::Result<Self> {
        let config = self.config;
        fs::remove_file(config.data_dir.join("wallet.db"))?;
        Ok(SpacesWallet::new(config)?)
    }

    pub fn get_info(&self) -> WalletInfo {
        let mut descriptors = Vec::with_capacity(2);

        descriptors.push(DescriptorInfo {
            descriptor: self
                .internal
                .public_descriptor(KeychainKind::External)
                .to_string(),
            internal: false,
            spaces: true,
        });
        descriptors.push(DescriptorInfo {
            descriptor: self
                .internal
                .public_descriptor(KeychainKind::Internal)
                .to_string(),
            internal: true,
            spaces: true,
        });

        WalletInfo {
            label: self.config.name.clone(),
            start_block: self.config.start_block,
            tip: self.internal.local_chain().tip().height(),
            descriptors,
        }
    }

    pub fn next_unused_space_address(&mut self) -> SpaceAddress {
        let info = self.internal.next_unused_address(KeychainKind::External);
        SpaceAddress(info.address)
    }

    pub fn apply_block_connected_to(
        &mut self,
        height: u32,
        block: &Block,
        block_id: BlockId,
    ) -> anyhow::Result<()> {
        self.internal
            .apply_block_connected_to(&block, height, block_id)?;
        Ok(())
    }

    pub fn apply_unconfirmed_tx(&mut self, tx: Transaction, seen: u64) {
        self.internal.apply_unconfirmed_txs(vec![(tx, seen)]);
    }

    pub fn apply_unconfirmed_tx_record(
        &mut self,
        tx_record: TxRecord,
        seen: u64,
    ) -> anyhow::Result<()> {
        let txid = tx_record.tx.compute_txid();
        self.apply_unconfirmed_tx(tx_record.tx, seen);

        // Insert txouts for foreign inputs to be able to calculate fees
        for (outpoint, txout) in tx_record.txouts {
            self.internal.insert_txout(outpoint, txout);
        }

        let db_tx = self
            .connection
            .transaction()
            .context("could not create wallet db transaction")?;
        for event in tx_record.events {
            TxEvent::insert(
                &db_tx,
                txid,
                event.kind,
                event.space,
                event.previous_spaceout,
                event.details,
            )
            .context("could not insert tx event into wallet db")?;
        }
        db_tx
            .commit()
            .context("could not commit tx events to wallet db")?;
        Ok(())
    }

    pub fn commit(&mut self) -> anyhow::Result<()> {
        self.internal.persist(&mut self.connection)?;
        Ok(())
    }

    /// List outputs that can be safely auctioned off
    pub fn list_bidouts(&mut self, confirmed_only: bool) -> anyhow::Result<Vec<DoubleUtxo>> {
        let mut unspent: Vec<LocalOutput> = self.list_unspent().collect();
        let mut not_auctioned = vec![];

        if unspent.is_empty() {
            return Ok(not_auctioned);
        }

        // Sort UTXOs by transaction ID and then by output index (vout)
        // to group UTXOs from the same transaction together and in sequential order
        unspent.sort_by(|a, b| {
            a.outpoint
                .txid
                .cmp(&b.outpoint.txid)
                .then_with(|| a.outpoint.vout.cmp(&b.outpoint.vout))
        });

        // Iterate over a sliding window of 2 UTXOs at a time
        for window in unspent.windows(2) {
            let (utxo1, utxo2) = (&window[0], &window[1]);
            // Check if the UTXOs form a valid double utxo pair:
            // - Both UTXOs must be from the same transaction (matching txid)
            // - The first UTXO's vout must be even
            // - The second UTXO's vout must be the first UTXO's vout + 1
            if utxo1.outpoint.txid == utxo2.outpoint.txid
                && utxo1.outpoint.vout % 2 == 0
                && utxo1.keychain == KeychainKind::Internal
                && utxo2.outpoint.vout == utxo1.outpoint.vout + 1
                && utxo2.keychain == KeychainKind::External

                // Adding these as additional safety checks since:
                // 1. outputs less than dust threshold
                //    are protected from being spent to fund txs.
                // 2. outputs representing spaces use "space dust" values.
                //
                // All these checks are needed because we don't actaully know
                // if an unconfirmed output is a spaceout representing a space ...
                // TODO: store metadata to simplify things and make it safer to use
                && utxo1.txout.value < SpacesAwareCoinSelection::DUST_THRESHOLD
                && utxo2.txout.value < SpacesAwareCoinSelection::DUST_THRESHOLD
                && is_connector_dust(utxo1.txout.value)
                && !is_space_dust(utxo2.txout.value)
                && utxo2.txout.is_magic_output()
                // Check if confirmed only are required
                && (!confirmed_only || utxo1.chain_position.is_confirmed())
            {
                // While it's possible to create outputs within space transactions
                // that don't use a special locktime, for now it's safer to require
                // explicitly trackable outputs.
                let locktime = match self.internal.get_tx(utxo2.outpoint.txid) {
                    None => continue,
                    Some(tx) => tx.tx_node.lock_time,
                };
                if !is_magic_lock_time(&locktime) {
                    continue;
                }

                not_auctioned.push(DoubleUtxo {
                    spend: FullTxOut {
                        outpoint: utxo1.outpoint,
                        txout: utxo1.txout.clone(),
                    },
                    auction: FullTxOut {
                        outpoint: utxo2.outpoint,
                        txout: utxo2.txout.clone(),
                    },
                    confirmed: utxo1.chain_position.is_confirmed(),
                });
            }
        }

        Ok(not_auctioned)
    }

    pub fn buy<H: KeyHasher>(
        &mut self,
        src: &mut impl DataSource,
        listing: &Listing,
        fee_rate: FeeRate,
    ) -> anyhow::Result<Transaction> {
        let (seller, spaceout) = Self::verify_listing::<H>(src, &listing)?;

        let mut witness = Witness::new();
        witness.push(
            taproot::Signature {
                signature: listing.signature,
                sighash_type: TapSighashType::SinglePlusAnyoneCanPay,
            }
            .to_vec(),
        );

        let funded_psbt = {
            let unspendables = self.list_spaces_outpoints(src)?;
            let space_address = self.next_unused_space_address();
            let dust_amount = space_dust(space_address.script_pubkey().minimal_non_dust().mul(2));

            let mut builder = self.build_tx(unspendables, false)?;
            builder
                .version(2)
                .ordering(TxOrdering::Untouched)
                .fee_rate(fee_rate)
                .nlocktime(LockTime::Blocks(Height::ZERO))
                .set_exact_sequence(Sequence::ENABLE_RBF_NO_LOCKTIME)
                .add_foreign_utxo_with_sequence(
                    spaceout.outpoint(),
                    psbt::Input {
                        witness_utxo: Some(TxOut {
                            value: spaceout.spaceout.value,
                            script_pubkey: spaceout.spaceout.script_pubkey.clone(),
                        }),
                        final_script_witness: Some(witness),
                        ..Default::default()
                    },
                    tap_key_spend_weight(),
                    BID_PSBT_INPUT_SEQUENCE,
                )?
                .add_recipient(
                    seller.script_pubkey(),
                    spaceout.spaceout.value + Amount::from_sat(listing.price),
                )
                .add_recipient(space_address.script_pubkey(), dust_amount);
            builder.finish()?
        };

        let tx = self.sign(funded_psbt, None)?;
        Ok(tx)
    }

    pub fn verify_listing<H: KeyHasher>(
        src: &mut impl DataSource,
        listing: &Listing,
    ) -> anyhow::Result<(SpaceAddress, FullSpaceOut)> {
        let label = SLabel::from_str(&listing.space)?;
        let space_key = SpaceKey::from(H::hash(label.as_ref()));
        let outpoint = match src.get_space_outpoint(&space_key)? {
            None => {
                return Err(anyhow::anyhow!(
                    "Unknown space {} - no outpoint found",
                    listing.space
                ))
            }
            Some(outpoint) => outpoint,
        };

        let spaceout = match src.get_spaceout(&outpoint)? {
            None => return Err(anyhow!("Unknown or spent spaces utxo: {}", outpoint)),
            Some(outpoint) => outpoint,
        };

        if spaceout.space.is_none() {
            return Err(anyhow!("No associated space"));
        }
        if !matches!(
            spaceout.space.as_ref().unwrap().covenant,
            Covenant::Transfer { .. }
        ) {
            return Err(anyhow::anyhow!("Space not registered"));
        }

        let recipient = Self::verify_listing_signature(
            &listing,
            outpoint,
            TxOut {
                value: spaceout.value,
                script_pubkey: spaceout.script_pubkey.clone(),
            },
        )?;

        Ok((
            recipient,
            FullSpaceOut {
                txid: outpoint.txid,
                spaceout,
            },
        ))
    }

    fn verify_listing_signature(
        listing: &Listing,
        outpoint: OutPoint,
        txout: TxOut,
    ) -> anyhow::Result<SpaceAddress> {
        let prevouts = Prevouts::One(0, txout.clone());
        let addr = SpaceAddress::from_str(&listing.seller)?;

        let total = Amount::from_sat(listing.price) + txout.value;
        let mut tx = bitcoin::blockdata::transaction::Transaction {
            version: Version(2),
            lock_time: BID_PSBT_TX_LOCK_TIME,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: BID_PSBT_INPUT_SEQUENCE,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: total,
                script_pubkey: addr.script_pubkey(),
            }],
        };

        let mut sighash_cache = SighashCache::new(&mut tx);
        let sighash = sighash_cache.taproot_key_spend_signature_hash(
            0,
            &prevouts,
            TapSighashType::SinglePlusAnyoneCanPay,
        )?;

        let msg = Message::from_digest_slice(sighash.as_ref())?;
        let ctx = bitcoin::secp256k1::Secp256k1::verification_only();
        let script_bytes = txout.script_pubkey.as_bytes();

        let pubkey = XOnlyPublicKey::from_slice(&script_bytes[2..])?;

        ctx.verify_schnorr(&listing.signature, &msg, &pubkey)?;
        Ok(addr)
    }

    pub fn sell<H: KeyHasher>(
        &mut self,
        src: &mut impl DataSource,
        space: &str,
        asking_price: Amount,
    ) -> anyhow::Result<Listing> {
        let label = SLabel::from_str(&space)?;
        let spacehash = SpaceKey::from(H::hash(label.as_ref()));
        let space_outpoint = match src.get_space_outpoint(&spacehash)? {
            None => return Err(anyhow::anyhow!("Space not found")),
            Some(outpoint) => outpoint,
        };
        let spaceout = match src.get_spaceout(&space_outpoint)? {
            None => return Err(anyhow::anyhow!("Space not found")),
            Some(spaceout) => spaceout,
        };
        if !matches!(
            spaceout.space.as_ref().unwrap().covenant,
            Covenant::Transfer { .. }
        ) {
            return Err(anyhow::anyhow!("Space not registered"));
        }

        let utxo = match self.internal.get_utxo(space_outpoint) {
            None => {
                return Err(anyhow::anyhow!(
                    "Wallet does not own a space with outpoint {}",
                    space_outpoint
                ))
            }
            Some(utxo) => utxo,
        };

        let recipient = self.next_unused_space_address();

        let mut sell_psbt = {
            let mut builder = self
                .internal
                .build_tx()
                .coin_selection(RequiredUtxosOnlyCoinSelectionAlgorithm);

            let total = utxo.txout.value + asking_price;
            builder
                .version(2)
                .allow_dust(true)
                .ordering(TxOrdering::Untouched)
                .nlocktime(LockTime::Blocks(Height::ZERO))
                .set_exact_sequence(Sequence::ENABLE_RBF_NO_LOCKTIME)
                .manually_selected_only()
                .sighash(TapSighashType::SinglePlusAnyoneCanPay.into())
                .add_utxo(utxo.outpoint)?
                .add_recipient(recipient.script_pubkey(), total);
            builder.finish()?
        };

        let finalized = self.internal.sign(
            &mut sell_psbt,
            SignOptions {
                allow_all_sighashes: true,
                ..Default::default()
            },
        )?;
        if !finalized {
            return Err(anyhow::anyhow!("signing listing psbt failed"));
        }

        let witness = sell_psbt.inputs[0]
            .clone()
            .final_script_witness
            .expect("signed listing psbt has a witness");

        let signature = witness
            .iter()
            .next()
            .expect("signed listing must have a single witness item");

        Ok(Listing {
            space: space.to_string(),
            price: asking_price.to_sat(),
            seller: recipient.to_string(),
            signature: Signature::from_slice(&signature[..64])
                .expect("signed listing has a valid signature"),
        })
    }

    pub fn new_bid_psbt(
        &mut self,
        total_burned: Amount,
        confirmed_only: bool,
    ) -> anyhow::Result<(Psbt, DoubleUtxo)> {
        let all: Vec<_> = self.list_bidouts(confirmed_only)?;

        let msg = if confirmed_only {
            "The wallet already has an unconfirmed bid for this space in the mempool, but no \
            confirmed bid utxos are available to replace it with a different amount."
        } else {
            "No bid outputs found"
        };

        let placeholder = all
            // always prefer confirmed ones since
            // we don't monitor mempool for other competing bids
            // this makes replacements smoother
            .iter()
            .find(|x| x.confirmed)
            .or_else(|| all.first())
            .ok_or_else(|| anyhow::anyhow!("{}", msg))?
            .clone();

        let refund_value = total_burned + placeholder.auction.txout.value;

        let mut bid_psbt = {
            let mut builder = self
                .internal
                .build_tx()
                .coin_selection(RequiredUtxosOnlyCoinSelectionAlgorithm);

            builder
                .version(2)
                .allow_dust(true)
                .ordering(TxOrdering::Untouched)
                .nlocktime(LockTime::Blocks(Height::ZERO))
                .set_exact_sequence(Sequence::ENABLE_RBF_NO_LOCKTIME)
                .manually_selected_only()
                .sighash(TapSighashType::SinglePlusAnyoneCanPay.into())
                .add_utxo(placeholder.auction.outpoint)?
                .add_recipient(
                    placeholder.auction.txout.script_pubkey.clone(),
                    refund_value,
                );
            builder.finish()?
        };

        let finalized = self.internal.sign(
            &mut bid_psbt,
            SignOptions {
                allow_all_sighashes: true,
                ..Default::default()
            },
        )?;
        if !finalized {
            return Err(anyhow::anyhow!("signing bid psbt failed"));
        }

        Ok((bid_psbt, placeholder))
    }

    pub fn compress_bid_psbt(op_return_vout: u8, psbt: &Psbt) -> anyhow::Result<[u8; 65]> {
        if psbt.inputs.len() != 1 || psbt.inputs[0].final_script_witness.is_none() {
            return Err(anyhow::anyhow!(
                "bid psbt witness stack must have exactly one input"
            ));
        }
        let witness = &psbt.inputs[0].final_script_witness.as_ref().unwrap()[0];
        if witness.len() != 65 || witness[64] != TapSighashType::SinglePlusAnyoneCanPay as u8 {
            return Err(anyhow::anyhow!(
                "bid psbt witness must be a taproot key spend with \
            sighash type SingleAnyoneCanPay"
            ));
        }

        let mut compressed = [0u8; 65];
        compressed[0] = op_return_vout;
        compressed[1..].copy_from_slice(&witness[..64]);
        Ok(compressed)
    }

    pub fn spaces_signer(key: &str) -> ProprietaryKey {
        ProprietaryKey {
            prefix: b"spaces".to_vec(),
            subtype: 0u8,
            key: key.as_bytes().to_vec(),
        }
    }

    pub fn get_taproot_keypair(
        &self,
        keychain: KeychainKind,
        derivation_index: u32,
    ) -> anyhow::Result<TweakedKeypair> {
        let secret = match self
            .internal
            .get_signers(keychain)
            .signers()
            .iter()
            .filter_map(|s| s.descriptor_secret_key())
            .next()
        {
            None => return Err(anyhow::anyhow!("No secret key found in signer")),
            Some(secret) => secret,
        };
        let descriptor_x_key = match secret {
            DescriptorSecretKey::XPrv(xprv) => xprv,
            _ => return Err(anyhow::anyhow!("No xprv found")),
        };
        let full_path = descriptor_x_key.derivation_path.child(ChildNumber::Normal {
            index: derivation_index,
        });
        let ctx = secp256k1::Secp256k1::new();
        let xprv = descriptor_x_key.xkey.derive_priv(&ctx, &full_path)?;
        let keypair = UntweakedKeypair::from_secret_key(&ctx, &xprv.private_key);
        Ok(keypair.tap_tweak(&ctx, None))
    }

    pub fn sign(
        &mut self,
        mut psbt: Psbt,
        mut extra_prevouts: Option<BTreeMap<OutPoint, TxOut>>,
    ) -> anyhow::Result<Transaction> {
        // mark any spends needing the spaces signer to be signed later
        for (input_index, input) in psbt.inputs.iter_mut().enumerate() {
            if extra_prevouts.is_none() {
                extra_prevouts = Some(BTreeMap::new());
            }
            if input.witness_utxo.is_some() {
                extra_prevouts.as_mut().unwrap().insert(
                    psbt.unsigned_tx.input[input_index].previous_output,
                    input.witness_utxo.clone().unwrap(),
                );
            }

            if input.final_script_witness.is_none() && input.witness_utxo.is_some() {
                if self
                    .internal
                    .is_mine(input.witness_utxo.as_ref().unwrap().script_pubkey.clone())
                {
                    input
                        .proprietary
                        .insert(Self::spaces_signer("tbs"), Vec::new());
                    input.final_script_witness = Some(Witness::default());
                    continue;
                }

                let previous_output = psbt.unsigned_tx.input[input_index].previous_output;
                let signing_info = self
                    .get_signing_info(
                        previous_output,
                        &input.witness_utxo.as_ref().unwrap().script_pubkey,
                    )
                    .context("could not retrieve signing info for script")?;
                if let Some(info) = signing_info {
                    input
                        .proprietary
                        .insert(Self::spaces_signer("reveal_signing_info"), info.to_vec());
                    input.final_script_witness = Some(Witness::default());
                }
            }
        }

        for input in psbt.inputs.iter_mut() {
            if input.proprietary.contains_key(&Self::spaces_signer("tbs")) {
                // To be signed by the default spaces signer
                input.final_script_witness = None;
                input.final_script_sig = None;
            }
        }
        if !self.internal.sign(&mut psbt, SignOptions::default())? {
            return Err(anyhow!("could not finalize psbt using spaces signer"));
        }

        let mut reveals: BTreeMap<u32, SpaceScriptSigningInfo> = BTreeMap::new();

        for (idx, input) in psbt.inputs.iter_mut().enumerate() {
            let reveal_key = Self::spaces_signer("reveal_signing_info");
            if input.proprietary.contains_key(&reveal_key) {
                let raw = input.proprietary.get(&reveal_key).expect("signing info");
                let signing_info = SpaceScriptSigningInfo::from_slice(raw.as_slice())
                    .context("expected reveal signing info")?;
                reveals.insert(idx as u32, signing_info);
            }
        }

        let mut tx = psbt.extract_tx()?;
        if reveals.len() == 0 {
            return Ok(tx);
        }

        let mut prevouts = Vec::new();
        let extras = extra_prevouts.unwrap_or_else(|| BTreeMap::new());

        for input in tx.input.iter() {
            if let Some(prevout) = extras.get(&input.previous_output) {
                prevouts.push(prevout.clone());
                continue;
            }

            let space_utxo = self.internal.get_utxo(input.previous_output);
            if let Some(space_utxo) = space_utxo {
                prevouts.push(space_utxo.txout);
                continue;
            }

            return Err(anyhow!("couldn't find txout for {}", input.previous_output));
        }

        let prevouts = Prevouts::All(&prevouts);
        let mut sighash_cache = SighashCache::new(&mut tx);

        for (reveal_idx, signing_info) in reveals {
            let sighash = sighash_cache.taproot_script_spend_signature_hash(
                reveal_idx as usize,
                &prevouts,
                TapLeafHash::from_script(&signing_info.script, LeafVersion::TapScript),
                TapSighashType::Default,
            )?;

            let msg = bitcoin::secp256k1::Message::from_digest_slice(sighash.as_ref())?;
            let signature = signing_info
                .ctx
                .sign_schnorr(&msg, &signing_info.temp_key_pair);
            let sighash_type = TapSighashType::Default;

            let witness = sighash_cache
                .witness_mut(reveal_idx as usize)
                .expect("witness should exist");
            witness.push(
                taproot::Signature {
                    signature,
                    sighash_type,
                }
                .to_vec(),
            );
            witness.push(&signing_info.script);
            witness.push(&signing_info.control_block.serialize());
        }

        Ok(tx)
    }

    fn get_signing_info(
        &mut self,
        previous_output: OutPoint,
        script: &ScriptBuf,
    ) -> anyhow::Result<Option<SpaceScriptSigningInfo>> {
        let db_tx = self
            .connection
            .transaction()
            .context("couldn't create db transaction")?;
        let info = TxEvent::get_signing_info(&db_tx, previous_output.txid, script)?;
        Ok(info)
    }
}

#[derive(Debug)]
pub struct RequiredUtxosOnlyCoinSelectionAlgorithm;

impl CoinSelectionAlgorithm for RequiredUtxosOnlyCoinSelectionAlgorithm {
    fn coin_select<R: RngCore>(
        &self,
        required_utxos: Vec<WeightedUtxo>,
        _optional_utxos: Vec<WeightedUtxo>,
        _fee_rate: FeeRate,
        _target_amount: Amount,
        _drain_script: &bitcoin::Script,
        _rand: &mut R,
    ) -> Result<CoinSelectionResult, InsufficientFunds> {
        let utxos = required_utxos.iter().map(|w| w.utxo.clone()).collect();
        Ok(CoinSelectionResult {
            selected: utxos,
            fee_amount: Amount::from_sat(0),
            excess: Excess::NoChange {
                dust_threshold: Amount::from_sat(0),
                remaining_amount: Amount::from_sat(0),
                change_fee: Amount::from_sat(0),
            },
        })
    }
}

/// Creates a dummy revert transaction double spending the foreign input
/// to be applied to the wallet's tx graph
fn revert_unconfirmed_bid_tx(
    bid: &WalletTx,
    foreign_outpoint: OutPoint,
) -> Option<(Transaction, u64)> {
    let foreign_input = bid
        .tx_node
        .input
        .iter()
        .find(|input| input.previous_output == foreign_outpoint)?
        .clone();

    let op_return_output = bid.tx_node.output.first()?.clone();
    if !op_return_output.script_pubkey.is_op_return() {
        return None;
    }
    let revert_tx = Transaction {
        version: bid.tx_node.version,
        lock_time: bid.tx_node.lock_time,
        input: vec![foreign_input],
        output: vec![op_return_output],
    };
    let revert_tx_last_seen = match bid.chain_position {
        ChainPosition::Confirmed { .. } => panic!("must be unconfirmed"),
        ChainPosition::Unconfirmed { last_seen } => last_seen.map(|last_seen| last_seen + 1),
    };
    Some((revert_tx, revert_tx_last_seen.unwrap_or(1)))
}

fn is_revert_tx(tx: &WalletTx) -> bool {
    !tx.chain_position.is_confirmed()
        && tx.tx_node.input.len() == 1
        && tx.tx_node.output.len() == 1
        && tx.tx_node.output[0].script_pubkey.is_op_return()
}

impl SpaceScriptSigningInfo {
    fn new(network: Network, nop_script: script::Builder) -> anyhow::Result<Self> {
        let secp256k1 = bitcoin::secp256k1::Secp256k1::new();
        let key_pair = UntweakedKeypair::new(&secp256k1, &mut rand::thread_rng());
        let (public_key, _) = XOnlyPublicKey::from_keypair(&key_pair);
        let script = nop_script
            .push_slice(&public_key.serialize())
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script();

        let taproot_spend_info = TaprootBuilder::new()
            .add_leaf(0, script.clone())
            .expect("failed adding leaf to taproot builder")
            .finalize(&secp256k1, public_key)
            .expect("failed finalizing taproot builder");
        let control_block = taproot_spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("failed computing control block");
        let tweaked_address = Address::p2tr_tweaked(taproot_spend_info.output_key(), network);

        Ok(SpaceScriptSigningInfo {
            ctx: secp256k1,
            script,
            tweaked_address: tweaked_address.script_pubkey(),
            control_block,
            temp_key_pair: key_pair,
        })
    }

    pub fn satisfaction_weight(&self) -> Weight {
        Weight::from_vb(
            (
                // 1-byte varint(control_block)
                1 + self.control_block.size() +
                    // 1-byte varint(script)
                    1 + self.script.len() +
                    // 1-byte varint(sig+sighash) + <sig(64)+sigHash(1)>
                    1 + 65
            ) as _,
        )
        .expect("valid weight")
    }

    pub(crate) fn to_vec(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, config::standard()).expect("signing info")
    }

    pub fn from_slice(data: &[u8]) -> anyhow::Result<Self> {
        let (de, _) = bincode::serde::decode_from_slice(data, config::standard())?;
        Ok(de)
    }
}

impl Serialize for SpaceScriptSigningInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(4))?;
        seq.serialize_element(&self.script.to_bytes())?;
        seq.serialize_element(&self.tweaked_address.to_bytes())?;
        seq.serialize_element(&self.control_block.serialize())?;
        seq.serialize_element(&self.temp_key_pair.secret_bytes().to_vec())?;

        seq.end()
    }
}

impl<'de> Deserialize<'de> for SpaceScriptSigningInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OpenSigningInfoVisitor;

        impl<'de> serde::de::Visitor<'de> for OpenSigningInfoVisitor {
            type Value = SpaceScriptSigningInfo;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("OpenSigningInfo")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let script_bytes: Vec<u8> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let address_bytes: Vec<u8> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let control_block_bytes: Vec<u8> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                let temp_key_pair_bytes: Vec<u8> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;

                let ctx = bitcoin::secp256k1::Secp256k1::new();
                let script = ScriptBuf::from_bytes(script_bytes).clone();
                let tweaked_address = ScriptBuf::from_bytes(address_bytes).clone();

                let control_block = ControlBlock::decode(control_block_bytes.as_slice())
                    .map_err(serde::de::Error::custom)?;
                let temp_key_pair =
                    UntweakedKeypair::from_seckey_slice(&ctx, temp_key_pair_bytes.as_slice())
                        .map_err(serde::de::Error::custom)?;

                Ok(SpaceScriptSigningInfo {
                    ctx,
                    script,
                    tweaked_address,
                    control_block,
                    temp_key_pair,
                })
            }
        }

        deserializer.deserialize_seq(OpenSigningInfoVisitor)
    }
}

pub fn signed_msg_hash(msg: impl AsRef<[u8]>) -> sha256d::Hash {
    let msg_bytes = msg.as_ref();
    let mut engine = sha256d::Hash::engine();
    engine.input(SPACES_SIGNED_MSG_PREFIX);
    VarInt::from(msg_bytes.len())
        .consensus_encode(&mut engine)
        .expect("varint serialization");
    engine.input(msg_bytes);
    sha256d::Hash::from_engine(engine)
}
