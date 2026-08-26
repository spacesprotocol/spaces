use anyhow::{Context, anyhow};
use bdk_wallet::chain::keychain_txout::KeychainTxOutIndex;
use bdk_wallet::{
    AddressInfo, KeychainKind, LocalOutput, PersistedWallet, SignOptions, TxBuilder, Update,
    Wallet, WalletTx, WeightedUtxo, chain,
    chain::{
        BlockId, ChainPosition, Indexer,
        local_chain::{CannotConnectError, LocalChain},
        tx_graph::CalculateFeeError,
    },
    coin_selection::{CoinSelectionAlgorithm, CoinSelectionResult, Excess, InsufficientFunds},
    keys::DescriptorSecretKey,
    rusqlite::Connection,
    tx_builder::TxOrdering,
};
use bitcoin::{
    Amount, Block, BlockHash, FeeRate, Network, OutPoint, Psbt, Sequence, TapLeafHash,
    TapSighashType, Transaction, TxIn, TxOut, Txid, Weight, Witness,
    absolute::{Height, LockTime},
    bip32::ChildNumber,
    key::{TapTweak, TweakedKeypair, rand::RngCore},
    psbt,
    psbt::raw::ProprietaryKey,
    script,
    sighash::{Prevouts, SighashCache},
    taproot,
    taproot::LeafVersion,
    transaction::Version,
};
use borsh::{BorshDeserialize, BorshSerialize, io};
use secp256k1::{Message, schnorr, schnorr::Signature};
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeSeq};
use spaces_nums::snumeric::SNumeric;
use spaces_nums::{
    NumSource,
    num_id::{NUM_HRP, NumId},
};
use spaces_protocol::{
    Covenant, Space,
    bitcoin::{
        Address, ScriptBuf, XOnlyPublicKey,
        constants::genesis_block,
        key::{UntweakedKeypair, rand},
        opcodes,
        taproot::{ControlBlock, TaprootBuilder},
    },
    constants::{BID_PSBT_INPUT_SEQUENCE, BID_PSBT_TX_LOCK_TIME},
    hasher::{KeyHasher, SpaceKey},
    prepare::{SpacesSource, TrackableOutput, is_magic_lock_time},
    slabel::SLabel,
};
use std::{collections::BTreeMap, fmt, fmt::Debug, fs, ops::Mul, path::PathBuf, str::FromStr};

use crate::{
    address::SpaceAddress,
    builder::{
        SpacesAwareCoinSelection, is_connector_dust, is_space_dust, space_dust,
        tap_key_spend_weight,
    },
    nostr::NostrEvent,
    tx_event::{TxEvent, TxEventKind, TxRecord},
};

pub extern crate bdk_wallet;
pub extern crate bitcoin;
extern crate core;

pub mod address;
pub mod builder;
pub mod export;
pub mod nostr;
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

/// A space name (@bitcoin), numeric (#800000-3), or num id (num1...)
#[derive(Debug, Clone)]
pub enum Subject {
    Label(SLabel),
    NumId(NumId),
}

impl From<SLabel> for Subject {
    fn from(label: SLabel) -> Self {
        Subject::Label(label)
    }
}

impl From<NumId> for Subject {
    fn from(id: NumId) -> Self {
        Subject::NumId(id)
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Subject::Label(label) => write!(f, "{}", label),
            Subject::NumId(id) => write!(f, "{}", id),
        }
    }
}

impl FromStr for Subject {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with(&format!("{}1", NUM_HRP)) {
            NumId::from_str(s)
                .map(Subject::NumId)
                .map_err(|e| format!("invalid num id: {}", e))
        } else {
            let normalized = if s.starts_with('#') || s.starts_with('@') {
                s.to_ascii_lowercase()
            } else {
                format!("@{}", s.to_ascii_lowercase())
            };
            SLabel::from_str(&normalized)
                .map(Subject::Label)
                .map_err(|e| format!("invalid space or numeric: {}", e))
        }
    }
}

impl Serialize for Subject {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Subject::Label(label) => serializer.serialize_str(&label.to_string()),
            Subject::NumId(id) => serializer.serialize_str(&id.to_string()),
        }
    }
}

impl<'de> Deserialize<'de> for Subject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <String as Deserialize>::deserialize(deserializer)?;
        Subject::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Listing {
    /// The space (@bitcoin), numeric (#800000-3-1), or num id (num1...) for
    /// sale. `space` is a deprecated alias accepted on input for older clients.
    #[serde(alias = "space")]
    pub subject: String,
    pub price: u64,
    pub seller: String,
    pub signature: schnorr::Signature,
}

/// What a [`Listing`] refers to, resolved on-chain.
#[derive(Debug, Clone)]
pub enum ListingKind {
    Space(SLabel),
    Num(NumId),
}

/// A verified listing: the seller's committed input/output and what it sells.
#[derive(Debug, Clone)]
pub struct VerifiedListing {
    /// The seller's proceeds address (output 0 of the signed pair).
    pub recipient: SpaceAddress,
    /// The utxo being sold.
    pub outpoint: OutPoint,
    /// Its value + script pubkey (committed by the seller's signature).
    pub prevout: TxOut,
    pub kind: ListingKind,
}

/// A validated single-input/single-output transfer pair extracted from a PSBT.
#[derive(Debug)]
struct TransferPair {
    outpoint: OutPoint,
    prevout: TxOut,
    sequence: Sequence,
    output: TxOut,
    witness: Witness,
}

/// Parse and validate one externally-signed transfer PSBT: exactly one input
/// and one output, tx version 2 / locktime 0, a present witness_utxo, a
/// `SIGHASH_SINGLE|ANYONECANPAY` key-path signature, and input value == output
/// value. Returns the finalized foreign-input material for funding.
fn parse_transfer_pair(psbt: &Psbt) -> anyhow::Result<TransferPair> {
    let tx = &psbt.unsigned_tx;
    if tx.input.len() != 1 || tx.output.len() != 1 {
        return Err(anyhow!("expected exactly 1 input and 1 output"));
    }
    // The taproot sighash commits to version and locktime, so every maker must
    // agree with the tx we build (and each other).
    if tx.version != Version::TWO {
        return Err(anyhow!("expected tx version 2"));
    }
    if tx.lock_time != LockTime::ZERO {
        return Err(anyhow!("expected locktime 0"));
    }

    let prevout = psbt.inputs[0]
        .witness_utxo
        .clone()
        .ok_or_else(|| anyhow!("missing witness_utxo"))?;
    let output = tx.output[0].clone();

    // Safety invariant: value in == value out.
    if prevout.value != output.value {
        return Err(anyhow!(
            "input value {} does not match output value {}",
            prevout.value,
            output.value
        ));
    }

    let single_acp = TapSighashType::SinglePlusAnyoneCanPay as u8;
    let witness = if let Some(w) = psbt.inputs[0].final_script_witness.as_ref() {
        let sig = w
            .iter()
            .next()
            .filter(|_| w.len() == 1)
            .ok_or_else(|| anyhow!("expected single key-path witness"))?;
        if sig.len() != 65 || sig[64] != single_acp {
            return Err(anyhow!("sighash must be SINGLE|ANYONECANPAY"));
        }
        w.clone()
    } else if let Some(sig) = psbt.inputs[0].tap_key_sig.as_ref() {
        if sig.sighash_type != TapSighashType::SinglePlusAnyoneCanPay {
            return Err(anyhow!("sighash must be SINGLE|ANYONECANPAY"));
        }
        let mut w = Witness::new();
        w.push(sig.to_vec());
        w
    } else {
        return Err(anyhow!("input is not signed (no tap key signature)"));
    };

    Ok(TransferPair {
        outpoint: tx.input[0].previous_output,
        prevout,
        sequence: tx.input[0].sequence,
        output,
        witness,
    })
}

/// Protocol-reserved output values that get special consensus treatment: a num
/// is minted at `value % 100 == 77`, a delegation opts in at 78, a revival is
/// signalled at 88, and spaces track `value % 10 == 2`. A wallet change output
/// that coincidentally lands on one of these in a spaces / num-minting tx would
/// be captured by the protocol, so change must avoid them.
fn is_reserved_value(value: Amount) -> bool {
    let sats = value.to_sat();
    matches!(sats % 100, 77 | 78 | 88) || sats % 10 == 2
}

/// Nearest non-reserved value, preferring to move DOWN (which raises the fee by
/// the delta — always safe against the relay floor). The only adjacent reserved
/// pair is 77/78, so a downward move resolves within 2 sats and stays well
/// above dust for any realistic change amount.
fn nearest_unreserved_value(value: Amount) -> Amount {
    let sats = value.to_sat();
    for delta in 1..=2 {
        if sats > delta {
            let candidate = Amount::from_sat(sats - delta);
            if !is_reserved_value(candidate) {
                return candidate;
            }
        }
    }
    // Fallback upward (fee decreases); unreachable for values above dust.
    let mut candidate = sats + 1;
    while is_reserved_value(Amount::from_sat(candidate)) {
        candidate += 1;
    }
    Amount::from_sat(candidate)
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
    pub progress: f32,
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

    pub fn spk_index(&self) -> &KeychainTxOutIndex<KeychainKind> {
        self.internal.spk_index()
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

    pub fn get_tx(&mut self, txid: Txid) -> Option<WalletTx<'_>> {
        self.internal.get_tx(txid)
    }

    pub fn get_utxo(&mut self, outpoint: OutPoint) -> Option<LocalOutput> {
        self.internal.get_utxo(outpoint)
    }

    pub fn next_unused_address(&mut self, keychain_kind: KeychainKind) -> AddressInfo {
        self.internal.next_unused_address(keychain_kind)
    }

    pub fn reveal_next_address(&mut self, keychain_kind: KeychainKind) -> AddressInfo {
        self.internal.reveal_next_address(keychain_kind)
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

    pub fn transactions(&self) -> impl Iterator<Item = WalletTx<'_>> + '_ {
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
    ) -> anyhow::Result<TxBuilder<'_, SpacesAwareCoinSelection>> {
        self.create_builder(unspendables, None, confirmed_only)
    }

    pub fn list_spaces_outpoints(
        &self,
        src: &mut impl SpacesSource,
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
            if event.kind == TxEventKind::Bid {
                match self.get_tx(txid) {
                    Some(tx) => {
                        if !tx.chain_position.is_confirmed() {
                            return Err(anyhow!(
                                "Bid with a higher fee on `{}` to replace this tx",
                                event.space.expect("space")
                            ));
                        }
                    }
                    _ => continue,
                }
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

    pub fn list_create_num_events(&mut self) -> anyhow::Result<Vec<TxEvent>> {
        let db_tx = self.connection.transaction().context("no db transaction")?;
        TxEvent::get_create_num_events(&db_tx).context("could not read create num events")
    }

    pub fn sign_event<H: KeyHasher, S: SpacesSource + NumSource>(
        &mut self,
        src: &mut S,
        subject: Subject,
        mut event: NostrEvent,
    ) -> anyhow::Result<NostrEvent> {
        let outpoint = match &subject {
            Subject::Label(label) if label.is_numeric() => {
                let numeric: SNumeric = label.clone().try_into().unwrap();
                let id = src
                    .get_num_id(&numeric)?
                    .ok_or_else(|| anyhow::anyhow!("Numeric '{}' not found", numeric))?;
                src.get_num_outpoint_by_id(&id)?
                    .ok_or_else(|| anyhow::anyhow!("Num id not found"))?
            }
            Subject::Label(label) => {
                if event.space().is_some_and(|s| s != label.to_string()) {
                    return Err(anyhow::anyhow!("Space tag does not match specified space"));
                }
                let space_key = SpaceKey::from(H::hash(label.as_ref()));
                src.get_space_outpoint(&space_key)?
                    .ok_or_else(|| anyhow::anyhow!("Space not found"))?
            }
            Subject::NumId(id) => src
                .get_num_outpoint_by_id(id)?
                .ok_or_else(|| anyhow::anyhow!("Num id not found"))?,
        };

        // We use list_output instead of get_utxo because the output might
        // be spent in a pending tx, so signatures are still valid until confirmed.
        let utxo = self
            .internal
            .list_output()
            .find(|o| o.outpoint == outpoint)
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Not owned by wallet"))?;

        let keypair = self
            .get_taproot_keypair(utxo.keychain, utxo.derivation_index)
            .context("Could not derive taproot keypair to sign message")?;

        event.sign(secp256k1::Secp256k1::new(), &keypair.to_keypair())?;
        Ok(event)
    }

    pub fn verify_event<H: KeyHasher, S: SpacesSource + NumSource>(
        src: &mut S,
        subject: Subject,
        mut event: NostrEvent,
    ) -> anyhow::Result<NostrEvent> {
        let script_pubkey = match &subject {
            Subject::Label(label) if label.is_numeric() => {
                let numeric: SNumeric = label.clone().try_into().unwrap();
                let id = src
                    .get_num_id(&numeric)?
                    .ok_or_else(|| anyhow::anyhow!("Numeric '{}' not found", numeric))?;
                let outpoint = src
                    .get_num_outpoint_by_id(&id)?
                    .ok_or_else(|| anyhow::anyhow!("Num id not found"))?;
                let numout = src
                    .get_numout(&outpoint)?
                    .ok_or_else(|| anyhow::anyhow!("Num output not found"))?;
                numout.script_pubkey
            }
            Subject::Label(label) => {
                if event.space().is_some_and(|s| s != label.to_string()) {
                    return Err(anyhow::anyhow!("Space tag does not match specified space"));
                }
                let space_key = SpaceKey::from(H::hash(label.as_ref()));
                let outpoint = src
                    .get_space_outpoint(&space_key)?
                    .ok_or_else(|| anyhow::anyhow!("Space not found"))?;
                let spaceout = src
                    .get_spaceout(&outpoint)?
                    .ok_or_else(|| anyhow::anyhow!("Space not found"))?;
                spaceout.script_pubkey
            }
            Subject::NumId(id) => {
                let outpoint = src
                    .get_num_outpoint_by_id(id)?
                    .ok_or_else(|| anyhow::anyhow!("Num id not found"))?;
                let numout = src
                    .get_numout(&outpoint)?
                    .ok_or_else(|| anyhow::anyhow!("Num output not found"))?;
                numout.script_pubkey
            }
        };

        if !script_pubkey.is_witness_program() {
            return Err(anyhow::anyhow!("Cannot verify non-taproot script"));
        }

        let script_bytes = script_pubkey.as_bytes();
        if script_bytes.len() != secp256k1::constants::SCHNORR_PUBLIC_KEY_SIZE + 2 {
            return Err(anyhow::anyhow!("Expected a schnorr public key"));
        }
        let pubkey = XOnlyPublicKey::from_slice(&script_bytes[2..])?;

        match event.pubkey {
            None => {
                event.pubkey = Some(pubkey);
            }
            Some(actual) => {
                if actual != pubkey {
                    return Err(anyhow::anyhow!("Event pubkey doesn't match pubkey"));
                }
            }
        }

        if !event.verify(secp256k1::Secp256k1::new()) {
            return Err(anyhow::anyhow!("Could not verify signature"));
        }
        Ok(event)
    }

    /// Sign a message with the key controlling a space or num id
    pub fn sign_schnorr<H: KeyHasher, S: SpacesSource + NumSource>(
        &mut self,
        src: &mut S,
        subject: Subject,
        message: &[u8],
    ) -> anyhow::Result<schnorr::Signature> {
        use bitcoin::hashes::{Hash, HashEngine, sha256};

        let outpoint = match &subject {
            Subject::Label(label) if label.is_numeric() => {
                let numeric: SNumeric = label.clone().try_into().unwrap();
                let id = src
                    .get_num_id(&numeric)?
                    .ok_or_else(|| anyhow::anyhow!("Numeric '{}' not found", numeric))?;
                src.get_num_outpoint_by_id(&id)?
                    .ok_or_else(|| anyhow::anyhow!("Num id not found"))?
            }
            Subject::Label(label) => {
                let space_key = SpaceKey::from(H::hash(label.as_ref()));
                src.get_space_outpoint(&space_key)?
                    .ok_or_else(|| anyhow::anyhow!("Space not found"))?
            }
            Subject::NumId(id) => src
                .get_num_outpoint_by_id(id)?
                .ok_or_else(|| anyhow::anyhow!("Num id not found"))?,
        };

        // We use list_output instead of get_utxo because the output might
        // be spent in a pending tx, so signatures are still valid until confirmed.
        let utxo = self
            .internal
            .list_output()
            .find(|o| o.outpoint == outpoint)
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Not owned by wallet"))?;

        let keypair = self
            .get_taproot_keypair(utxo.keychain, utxo.derivation_index)
            .context("Could not derive taproot keypair to sign message")?;

        // Hash the message with the prefix
        let mut engine = sha256::Hash::engine();
        engine.input(SPACES_SIGNED_MSG_PREFIX);
        engine.input(message);
        let digest = sha256::Hash::from_engine(engine);

        let msg = secp256k1::Message::from_digest(digest.to_byte_array());
        let sig = secp256k1::Secp256k1::new().sign_schnorr(&msg, &keypair.to_keypair());
        Ok(sig)
    }

    /// Verify a schnorr signature against a space or num id's public key
    pub fn verify_schnorr<H: KeyHasher, S: SpacesSource + NumSource>(
        src: &mut S,
        subject: Subject,
        message: &[u8],
        signature: &schnorr::Signature,
    ) -> anyhow::Result<()> {
        use bitcoin::hashes::{Hash, HashEngine, sha256};

        let script_pubkey = match &subject {
            Subject::Label(label) if label.is_numeric() => {
                let numeric: SNumeric = label.clone().try_into().unwrap();
                let id = src
                    .get_num_id(&numeric)?
                    .ok_or_else(|| anyhow::anyhow!("Numeric '{}' not found", numeric))?;
                let outpoint = src
                    .get_num_outpoint_by_id(&id)?
                    .ok_or_else(|| anyhow::anyhow!("Num id not found"))?;
                let numout = src
                    .get_numout(&outpoint)?
                    .ok_or_else(|| anyhow::anyhow!("Num output not found"))?;
                numout.script_pubkey
            }
            Subject::Label(label) => {
                let space_key = SpaceKey::from(H::hash(label.as_ref()));
                let outpoint = src
                    .get_space_outpoint(&space_key)?
                    .ok_or_else(|| anyhow::anyhow!("Space not found"))?;
                let spaceout = src
                    .get_spaceout(&outpoint)?
                    .ok_or_else(|| anyhow::anyhow!("Space not found"))?;
                spaceout.script_pubkey
            }
            Subject::NumId(id) => {
                let outpoint = src
                    .get_num_outpoint_by_id(id)?
                    .ok_or_else(|| anyhow::anyhow!("Num id not found"))?;
                let numout = src
                    .get_numout(&outpoint)?
                    .ok_or_else(|| anyhow::anyhow!("Num output not found"))?;
                numout.script_pubkey
            }
        };

        if !script_pubkey.is_witness_program() {
            return Err(anyhow::anyhow!("Cannot verify non-taproot script"));
        }

        let script_bytes = script_pubkey.as_bytes();
        if script_bytes.len() != secp256k1::constants::SCHNORR_PUBLIC_KEY_SIZE + 2 {
            return Err(anyhow::anyhow!("Expected a schnorr public key"));
        }
        let pubkey = XOnlyPublicKey::from_slice(&script_bytes[2..])?;

        // Hash the message with the prefix
        let mut engine = sha256::Hash::engine();
        engine.input(SPACES_SIGNED_MSG_PREFIX);
        engine.input(message);
        let digest = sha256::Hash::from_engine(engine);

        let msg = secp256k1::Message::from_digest(digest.to_byte_array());
        secp256k1::Secp256k1::new()
            .verify_schnorr(signature, &msg, &pubkey)
            .map_err(|_| anyhow::anyhow!("Invalid signature"))
    }

    pub fn list_unspent_with_details(
        &mut self,
        store: &mut impl SpacesSource,
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
        data_source: &mut impl SpacesSource,
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
    pub fn unconfirmed_bids(&mut self) -> anyhow::Result<Vec<(WalletTx<'_>, OutPoint)>> {
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
        SpacesWallet::new(config)
    }

    pub fn get_info(&self) -> WalletInfo {
        let descriptors = vec![
            DescriptorInfo {
                descriptor: self
                    .internal
                    .public_descriptor(KeychainKind::External)
                    .to_string(),
                internal: false,
                spaces: true,
            },
            DescriptorInfo {
                descriptor: self
                    .internal
                    .public_descriptor(KeychainKind::Internal)
                    .to_string(),
                internal: true,
                spaces: true,
            },
        ];

        WalletInfo {
            label: self.config.name.clone(),
            start_block: self.config.start_block,
            tip: self.internal.local_chain().tip().height(),
            descriptors,
            progress: 0.0,
        }
    }

    pub fn next_unused_space_address(&mut self) -> SpaceAddress {
        let info = self.internal.next_unused_address(KeychainKind::External);
        SpaceAddress(info.address)
    }

    pub fn reveal_next_space_address(&mut self) -> SpaceAddress {
        let info = self.reveal_next_address(KeychainKind::External);
        SpaceAddress(info.address)
    }

    pub fn apply_block_connected_to(
        &mut self,
        height: u32,
        block: &Block,
        block_id: BlockId,
    ) -> anyhow::Result<()> {
        self.internal
            .apply_block_connected_to(block, height, block_id)?;
        Ok(())
    }

    pub fn apply_update(&mut self, update: impl Into<Update>) -> Result<(), CannotConnectError> {
        self.internal.apply_update(update)
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

    /// Buy a listed space or num. The subject is delivered to `recipient` if
    /// given (e.g. an external keystore's script pubkey), otherwise to a fresh
    /// address of this wallet. The funding wallet always pays the price + fee.
    pub fn buy<H: KeyHasher>(
        &mut self,
        src: &mut (impl SpacesSource + NumSource),
        listing: &Listing,
        fee_rate: FeeRate,
        recipient: Option<ScriptBuf>,
    ) -> anyhow::Result<Transaction> {
        let verified = Self::verify_listing::<H>(src, listing)?;

        // The seller signed input 0 -> output 0 (their proceeds). The subject
        // (space or num) rotates to the *N+1* output the buyer adds, which the
        // seller's SINGLE signature does not commit to. For that N+1 routing to
        // happen the seller's output 0 must not value-match the input, so a num
        // sale requires a non-zero price (a zero-price num sale would rotate the
        // num straight to the seller — use a transfer instead).
        if matches!(verified.kind, ListingKind::Num(_)) && listing.price == 0 {
            return Err(anyhow!("a num sale requires a non-zero price"));
        }

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
            let recipient_spk = match recipient {
                Some(spk) => spk,
                None => self.next_unused_space_address().script_pubkey(),
            };
            let dust_amount = space_dust(recipient_spk.minimal_non_dust().mul(2));

            let mut builder = self.build_tx(unspendables, false)?;
            builder
                .version(2)
                .ordering(TxOrdering::Untouched)
                .fee_rate(fee_rate)
                .nlocktime(LockTime::Blocks(Height::ZERO))
                .set_exact_sequence(Sequence::ENABLE_RBF_NO_LOCKTIME)
                .add_foreign_utxo_with_sequence(
                    verified.outpoint,
                    psbt::Input {
                        witness_utxo: Some(verified.prevout.clone()),
                        final_script_witness: Some(witness),
                        ..Default::default()
                    },
                    tap_key_spend_weight(),
                    BID_PSBT_INPUT_SEQUENCE,
                )?
                .add_recipient(
                    verified.recipient.script_pubkey(),
                    verified.prevout.value + Amount::from_sat(listing.price),
                )
                .add_recipient(recipient_spk, dust_amount);
            builder.finish()?
        };

        let tx = self.sign(funded_psbt, None)?;
        Ok(tx)
    }

    /// Fund and finalize one or more externally-signed transfer PSBTs into a
    /// single transaction. Each PSBT must be a single-input/single-output pair
    /// signed with `SIGHASH_SINGLE | ANYONECANPAY` whose input value equals its
    /// output value. Those two properties make funding *blind and safe*: the
    /// maker's output is fully covered by the maker's own input, so the funder
    /// only ever contributes the fee — it can neither be tricked into covering
    /// the recipient's amount nor redirect the maker's output.
    ///
    /// Layout is index-aligned: transfer `k`'s input sits at `vin[k]` and its
    /// output at `vout[k]` (funder inputs and change are appended after).
    /// Because the taproot SINGLE message commits to the *content* of the
    /// output at the input's position (not the position number), each maker
    /// signature stays valid at any index as long as its paired output keeps
    /// the same content — which the alignment guarantees. The same alignment
    /// satisfies the num successor rule (input `k` value-matches output `k`, so
    /// the num rotates to its recipient).
    ///
    /// `unspendables` must include the funder's own space/num utxos so coin
    /// selection never spends one to pay the fee.
    pub fn fund_transfers(
        &mut self,
        unspendables: Vec<OutPoint>,
        psbts: Vec<Psbt>,
        fee_rate: FeeRate,
    ) -> anyhow::Result<Transaction> {
        if psbts.is_empty() {
            return Err(anyhow!("no transfer psbts provided"));
        }

        let mut pairs: Vec<TransferPair> = Vec::with_capacity(psbts.len());
        let mut seen = std::collections::HashSet::new();
        for (i, psbt) in psbts.iter().enumerate() {
            let pair = parse_transfer_pair(psbt).map_err(|e| anyhow!("transfer {i}: {e}"))?;
            if !seen.insert(pair.outpoint) {
                return Err(anyhow!("transfer {i}: duplicate input {}", pair.outpoint));
            }
            pairs.push(pair);
        }

        let funded_psbt = {
            let mut builder = self.build_tx(unspendables, false)?;
            builder
                .version(2)
                .ordering(TxOrdering::Untouched)
                .nlocktime(LockTime::ZERO)
                .fee_rate(fee_rate);

            // Foreign inputs first, in order -> vin[0..N]. Preserve each
            // maker's own sequence (committed by its sighash).
            for pair in &pairs {
                builder.add_foreign_utxo_with_sequence(
                    pair.outpoint,
                    psbt::Input {
                        witness_utxo: Some(pair.prevout.clone()),
                        final_script_witness: Some(pair.witness.clone()),
                        ..Default::default()
                    },
                    tap_key_spend_weight(),
                    pair.sequence,
                )?;
            }
            // Recipient outputs in the same order -> vout[0..N], aligning
            // input k with output k. Funder fee inputs + change are appended
            // after by coin selection (TxOrdering::Untouched).
            for pair in &pairs {
                builder.add_recipient(pair.output.script_pubkey.clone(), pair.output.value);
            }
            builder.finish()?
        };

        let tx = self.sign(funded_psbt, None)?;
        Ok(tx)
    }

    /// Resolve a listing subject (@space, #numeric, or num1...) to the on-chain
    /// utxo it sells, validating that the utxo is transferable.
    fn resolve_listing_subject<H: KeyHasher>(
        src: &mut (impl SpacesSource + NumSource),
        subject: &str,
    ) -> anyhow::Result<(OutPoint, TxOut, ListingKind)> {
        let parsed = Subject::from_str(subject).map_err(|e| anyhow!(e))?;
        match parsed {
            Subject::Label(label) if !label.is_numeric() => {
                let space_key = SpaceKey::from(H::hash(label.as_ref()));
                let outpoint = src
                    .get_space_outpoint(&space_key)?
                    .ok_or_else(|| anyhow!("Unknown space {} - no outpoint found", subject))?;
                let spaceout = src
                    .get_spaceout(&outpoint)?
                    .ok_or_else(|| anyhow!("Unknown or spent spaces utxo: {}", outpoint))?;
                let space = spaceout
                    .space
                    .as_ref()
                    .ok_or_else(|| anyhow!("No associated space"))?;
                if !matches!(space.covenant, Covenant::Transfer { .. }) {
                    return Err(anyhow!("Space not registered"));
                }
                let name = space.name.clone();
                let prevout = TxOut {
                    value: spaceout.value,
                    script_pubkey: spaceout.script_pubkey,
                };
                Ok((outpoint, prevout, ListingKind::Space(name)))
            }
            parsed => {
                let id = match parsed {
                    Subject::NumId(id) => id,
                    Subject::Label(numeric_label) => {
                        let numeric = SNumeric::try_from(numeric_label)
                            .map_err(|_| anyhow!("invalid numeric: {}", subject))?;
                        src.get_num_id(&numeric)?
                            .ok_or_else(|| anyhow!("Unknown numeric {}", subject))?
                    }
                };
                let outpoint = src
                    .get_num_outpoint_by_id(&id)?
                    .ok_or_else(|| anyhow!("Unknown num {}", subject))?;
                let numout = src
                    .get_numout(&outpoint)?
                    .ok_or_else(|| anyhow!("Unknown or spent num utxo: {}", outpoint))?;
                if numout.spent {
                    return Err(anyhow!("Num {} is dormant", subject));
                }
                let prevout = TxOut {
                    value: numout.value,
                    script_pubkey: numout.script_pubkey,
                };
                Ok((outpoint, prevout, ListingKind::Num(id)))
            }
        }
    }

    pub fn verify_listing<H: KeyHasher>(
        src: &mut (impl SpacesSource + NumSource),
        listing: &Listing,
    ) -> anyhow::Result<VerifiedListing> {
        let (outpoint, prevout, kind) = Self::resolve_listing_subject::<H>(src, &listing.subject)?;
        let recipient = Self::verify_listing_signature(listing, outpoint, prevout.clone())?;
        Ok(VerifiedListing {
            recipient,
            outpoint,
            prevout,
            kind,
        })
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
        src: &mut (impl SpacesSource + NumSource),
        subject: &str,
        asking_price: Amount,
    ) -> anyhow::Result<Listing> {
        let (outpoint, _prevout, _kind) = Self::resolve_listing_subject::<H>(src, subject)?;

        let utxo = match self.internal.get_utxo(outpoint) {
            None => {
                return Err(anyhow::anyhow!(
                    "Wallet does not own {} (outpoint {})",
                    subject,
                    outpoint
                ));
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
            subject: subject.to_string(),
            price: asking_price.to_sat(),
            seller: recipient.to_string(),
            signature: Signature::from_slice(&signature[..64])
                .expect("signed listing has a valid signature"),
        })
    }

    /// Produce a value-preserving transfer PSBT for one of the wallet's own
    /// nums: a single input (the num utxo) -> single output (`recipient`, same
    /// value) signed with `SIGHASH_SINGLE|ANYONECANPAY`. The result can be
    /// funded and broadcast by any wallet via [`Self::fund_transfers`].
    pub fn sign_transfer<H: KeyHasher>(
        &mut self,
        src: &mut (impl SpacesSource + NumSource),
        subject: &str,
        recipient: ScriptBuf,
    ) -> anyhow::Result<Psbt> {
        let (outpoint, prevout, _kind) = Self::resolve_listing_subject::<H>(src, subject)?;
        let utxo = self
            .internal
            .get_utxo(outpoint)
            .ok_or_else(|| anyhow!("Wallet does not own {} (outpoint {})", subject, outpoint))?;

        let mut psbt = {
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
                .add_utxo(utxo.outpoint)?
                // Value-preserving: output value == input value.
                .add_recipient(recipient, prevout.value);
            builder.finish()?
        };

        let finalized = self.internal.sign(
            &mut psbt,
            SignOptions {
                allow_all_sighashes: true,
                ..Default::default()
            },
        )?;
        if !finalized {
            return Err(anyhow!("signing transfer psbt failed"));
        }
        Ok(psbt)
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

    /// Move the wallet's drain/change output off a protocol-reserved value so
    /// it cannot be silently captured (e.g. minted into a num) when the tx is a
    /// spaces or num-minting transaction.
    ///
    /// `build_tx` pins `TxOrdering::Untouched` for every wallet-built tx and bdk
    /// appends the drain output last, so the change (when present) is always the
    /// final output — we only ever inspect that one. It's touched only when it
    /// is unambiguously ordinary change:
    ///
    /// - the tx has more than one output (a single-output tx is a drain such as
    ///   an unbind sink or a listing maker psbt, never ordinary change);
    /// - the last output is an is-mine output on the internal (change) keychain
    ///   — received nums/spaces and funded-transfer maker outputs use the
    ///   external keychain, so they're never considered;
    /// - above the dust floor, so the intentional space/num dust outputs (always
    ///   well below it) can never match.
    ///
    /// The resulting `<=2`-sat adjustment is absorbed by the fee.
    fn sanitize_change(&self, psbt: &mut Psbt) {
        let outputs = &mut psbt.unsigned_tx.output;
        if outputs.len() < 2 {
            return;
        }
        let last = outputs.last_mut().expect("checked len >= 2");
        let is_internal_change = self
            .internal
            .derivation_of_spk(last.script_pubkey.clone())
            .is_some_and(|(keychain, _)| keychain == KeychainKind::Internal);
        if is_internal_change
            && last.value > SpacesAwareCoinSelection::DUST_THRESHOLD
            && is_reserved_value(last.value)
        {
            last.value = nearest_unreserved_value(last.value);
        }
    }

    pub fn sign(
        &mut self,
        mut psbt: Psbt,
        mut extra_prevouts: Option<BTreeMap<OutPoint, TxOut>>,
    ) -> anyhow::Result<Transaction> {
        // Keep the wallet's change off protocol-reserved values BEFORE signing,
        // so it can't be silently captured (e.g. minted into a num) in a spaces
        // or num-minting transaction.
        self.sanitize_change(&mut psbt);

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

            if input.final_script_witness.is_none()
                && let Some(witness_utxo) = input.witness_utxo.as_ref()
            {
                if self.internal.is_mine(witness_utxo.script_pubkey.clone()) {
                    input
                        .proprietary
                        .insert(Self::spaces_signer("tbs"), Vec::new());
                    input.final_script_witness = Some(Witness::default());
                    continue;
                }

                let previous_output = psbt.unsigned_tx.input[input_index].previous_output;
                let signing_info = self
                    .get_signing_info(previous_output, &witness_utxo.script_pubkey)
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
        let mut custom_secrets: BTreeMap<u32, [u8; 32]> = BTreeMap::new();

        for (idx, input) in psbt.inputs.iter_mut().enumerate() {
            let reveal_key = Self::spaces_signer("reveal_signing_info");
            if input.proprietary.contains_key(&reveal_key) {
                let raw = input.proprietary.get(&reveal_key).expect("signing info");
                let signing_info = SpaceScriptSigningInfo::from_slice(raw.as_slice())
                    .context("expected reveal signing info")?;
                reveals.insert(idx as u32, signing_info);
            }
            let secret_key = Self::spaces_signer("sign_with_custom_secret");
            if let Some(raw) = input.proprietary.get(&secret_key) {
                let mut secret = [0u8; 32];
                secret.copy_from_slice(raw.as_slice());
                custom_secrets.insert(idx as u32, secret);
            }
        }

        let mut tx = psbt.extract_tx()?;
        if reveals.is_empty() && custom_secrets.is_empty() {
            return Ok(tx);
        }

        let mut prevouts = Vec::new();
        let extras = extra_prevouts.unwrap_or_default();

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
            witness.push(signing_info.control_block.serialize());
        }

        // Sign inputs with externally-provided secret keys (taproot key-spend)
        for (input_idx, secret) in custom_secrets {
            let ctx = secp256k1::Secp256k1::new();
            let keypair = secp256k1::Keypair::from_seckey_slice(&ctx, &secret)
                .context("invalid secret key")?;

            let sighash = sighash_cache.taproot_key_spend_signature_hash(
                input_idx as usize,
                &prevouts,
                TapSighashType::Default,
            )?;

            let msg = secp256k1::Message::from_digest_slice(sighash.as_ref())?;
            let signature = ctx.sign_schnorr(&msg, &keypair);

            let witness = sighash_cache
                .witness_mut(input_idx as usize)
                .expect("witness should exist");
            witness.push(
                taproot::Signature {
                    signature,
                    sighash_type: TapSighashType::Default,
                }
                .to_vec(),
            );
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

    pub fn peek_address(&self, keychain_kind: KeychainKind, index: u32) -> AddressInfo {
        self.internal.peek_address(keychain_kind, index)
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
            .push_slice(public_key.serialize())
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
        borsh::to_vec(self).expect("signing info")
    }

    pub fn from_slice(data: &[u8]) -> anyhow::Result<Self> {
        let de = borsh::from_slice(data)?;
        Ok(de)
    }
}

impl BorshSerialize for SpaceScriptSigningInfo {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        // Serialize script as bytes
        let script_bytes = self.script.to_bytes();
        BorshSerialize::serialize(&(script_bytes.len() as u32), writer)?;
        writer.write_all(&script_bytes)?;

        // Serialize tweaked_address as bytes
        let address_bytes = self.tweaked_address.to_bytes();
        BorshSerialize::serialize(&(address_bytes.len() as u32), writer)?;
        writer.write_all(&address_bytes)?;

        // Serialize control_block as bytes
        let control_block_bytes = self.control_block.serialize();
        BorshSerialize::serialize(&(control_block_bytes.len() as u32), writer)?;
        writer.write_all(&control_block_bytes)?;

        // Serialize temp_key_pair secret bytes
        let key_bytes = self.temp_key_pair.secret_bytes();
        writer.write_all(&key_bytes)?;

        Ok(())
    }
}

impl BorshDeserialize for SpaceScriptSigningInfo {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        // Deserialize script
        let script_len = u32::deserialize_reader(reader)? as usize;
        let mut script_bytes = vec![0u8; script_len];
        reader.read_exact(&mut script_bytes)?;
        let script = ScriptBuf::from_bytes(script_bytes);

        // Deserialize tweaked_address
        let address_len = u32::deserialize_reader(reader)? as usize;
        let mut address_bytes = vec![0u8; address_len];
        reader.read_exact(&mut address_bytes)?;
        let tweaked_address = ScriptBuf::from_bytes(address_bytes);

        // Deserialize control_block
        let control_block_len = u32::deserialize_reader(reader)? as usize;
        let mut control_block_bytes = vec![0u8; control_block_len];
        reader.read_exact(&mut control_block_bytes)?;
        let control_block = ControlBlock::decode(&control_block_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // Deserialize temp_key_pair (32 bytes for secret key)
        let mut key_bytes = [0u8; 32];
        reader.read_exact(&mut key_bytes)?;
        let ctx = bitcoin::secp256k1::Secp256k1::new();
        let temp_key_pair = UntweakedKeypair::from_seckey_slice(&ctx, &key_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        Ok(SpaceScriptSigningInfo {
            ctx,
            script,
            tweaked_address,
            control_block,
            temp_key_pair,
        })
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

#[cfg(test)]
mod transfer_tests {
    use super::*;

    // A real single-input/single-output num transfer PSBT produced by the
    // nacho app: P2TR num input (2000 sats) -> P2PKH recipient (2000 sats),
    // signed SIGHASH_SINGLE|ANYONECANPAY (0x83).
    const NACHO_PSBT: &str = "cHNidP8BAFUCAAAAAUmIZzfEOyHTqdRTVljO3sK4Vp4C2rKsXzG+Nvjw1RVaAgAAAAD/////AdAHAAAAAAAAGXapFMbmtRt9wz0wsaJKPjjcUkQyOgmfiKwAAAAAAAEBK9AHAAAAAAAAIlEgt9mEd9UzAwXAZNpkSMxuU1SM42Y7BCqgRRvaZHj9nawBAwSDAAAAARNB4BASbMDLf7MkxOjEGPgttqQPynbrKa+GtyLuN7sQkOzaP5HP8mVtfKXsxYugKVePWea5rS5vKyrtj3ii4tK87YMAAA==";

    fn nacho() -> Psbt {
        Psbt::from_str(NACHO_PSBT).expect("valid base64 psbt")
    }

    #[test]
    fn accepts_value_preserving_single_acp() {
        let pair = parse_transfer_pair(&nacho()).expect("valid transfer");
        assert_eq!(pair.prevout.value, pair.output.value);
        assert_eq!(pair.prevout.value, Amount::from_sat(2000));
        assert_eq!(pair.sequence, Sequence::MAX);
        assert_eq!(pair.witness.len(), 1, "single key-path witness element");
        let sig = pair.witness.iter().next().unwrap();
        assert_eq!(sig.len(), 65);
        assert_eq!(sig[64], TapSighashType::SinglePlusAnyoneCanPay as u8);
    }

    #[test]
    fn rejects_value_mismatch() {
        let mut psbt = nacho();
        psbt.unsigned_tx.output[0].value = Amount::from_sat(1999);
        let err = parse_transfer_pair(&psbt).unwrap_err().to_string();
        assert!(err.contains("does not match"), "got: {err}");
    }

    #[test]
    fn rejects_multi_output() {
        let mut psbt = nacho();
        let extra = psbt.unsigned_tx.output[0].clone();
        psbt.unsigned_tx.output.push(extra);
        let err = parse_transfer_pair(&psbt).unwrap_err().to_string();
        assert!(err.contains("1 input and 1 output"), "got: {err}");
    }

    #[test]
    fn rejects_wrong_sighash() {
        let mut psbt = nacho();
        let sig = psbt.inputs[0].tap_key_sig.unwrap();
        psbt.inputs[0].tap_key_sig = Some(taproot::Signature {
            signature: sig.signature,
            sighash_type: TapSighashType::All,
        });
        let err = parse_transfer_pair(&psbt).unwrap_err().to_string();
        assert!(err.contains("SINGLE|ANYONECANPAY"), "got: {err}");
    }

    #[test]
    fn rejects_missing_witness_utxo() {
        let mut psbt = nacho();
        psbt.inputs[0].witness_utxo = None;
        let err = parse_transfer_pair(&psbt).unwrap_err().to_string();
        assert!(err.contains("witness_utxo"), "got: {err}");
    }

    #[test]
    fn rejects_unsigned() {
        let mut psbt = nacho();
        psbt.inputs[0].tap_key_sig = None;
        psbt.inputs[0].final_script_witness = None;
        let err = parse_transfer_pair(&psbt).unwrap_err().to_string();
        assert!(err.contains("not signed"), "got: {err}");
    }
}

#[cfg(test)]
mod change_hygiene_tests {
    use super::*;

    #[test]
    fn identifies_reserved_values() {
        // 77 mint, 78 delegate, 88 revive (mod 100); 2 spaces (mod 10).
        for s in [
            77u64, 78, 88, 177, 288, 2, 12, 72, 1202, 662, 1077, 99_263_102,
        ] {
            assert!(
                is_reserved_value(Amount::from_sat(s)),
                "{s} should be reserved"
            );
        }
        for s in [76u64, 79, 87, 89, 100, 1201, 1203, 1000, 99_263_109] {
            assert!(
                !is_reserved_value(Amount::from_sat(s)),
                "{s} should NOT be reserved"
            );
        }
    }

    #[test]
    fn nearest_is_never_reserved_moves_down_by_at_most_two() {
        // Exhaustive across a wide range straddling many hundreds boundaries.
        for s in 1000u64..=300_000 {
            let v = Amount::from_sat(s);
            if !is_reserved_value(v) {
                continue;
            }
            let adj = nearest_unreserved_value(v);
            assert!(
                !is_reserved_value(adj),
                "adjusted {} still reserved (from {s})",
                adj.to_sat()
            );
            assert!(
                adj.to_sat() < s,
                "should move down: {s} -> {}",
                adj.to_sat()
            );
            assert!(
                s - adj.to_sat() <= 2,
                "moved {s} by more than 2 to {}",
                adj.to_sat()
            );
        }
    }

    #[test]
    fn worst_case_77_78_pair() {
        // 78 -> 76 (77 is also reserved), the only 2-sat move.
        assert_eq!(
            nearest_unreserved_value(Amount::from_sat(1278)),
            Amount::from_sat(1276)
        );
        assert_eq!(
            nearest_unreserved_value(Amount::from_sat(1277)),
            Amount::from_sat(1276)
        );
        assert_eq!(
            nearest_unreserved_value(Amount::from_sat(1288)),
            Amount::from_sat(1287)
        );
        assert_eq!(
            nearest_unreserved_value(Amount::from_sat(1202)),
            Amount::from_sat(1201)
        );
    }
}
