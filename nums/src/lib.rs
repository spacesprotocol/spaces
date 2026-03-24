pub mod constants;
#[cfg(feature = "std")]
pub mod num_id;
pub mod snumeric;

#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::constants::COMMITMENT_FINALITY_INTERVAL;
use crate::num_id::NumId;
use crate::snumeric::SNumeric;
use bitcoin::absolute::LockTime;
use bitcoin::opcodes::all::{OP_PUSHNUM_2, OP_RETURN};
use bitcoin::script::{Instruction, PushBytesBuf};
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use spaces_protocol::constants::ChainAnchor;
use spaces_protocol::hasher::{Hash, KeyHash, KeyHasher};
use spaces_protocol::script::find_op_set_data;
use spaces_protocol::slabel::SLabel;
use spaces_protocol::{Bytes, SpaceOut};

pub trait NumSource {
    fn get_num_outpoint_by_id(
        &mut self,
        id: &NumId,
    ) -> spaces_protocol::errors::Result<Option<OutPoint>>;

    fn get_commitment(
        &mut self,
        key: &CommitmentKey,
    ) -> spaces_protocol::errors::Result<Option<Commitment>>;

    fn get_commitments_tip(
        &mut self,
        key: &CommitmentTipKey,
    ) -> spaces_protocol::errors::Result<Option<Hash>>;

    fn get_delegator(
        &mut self,
        key: &DelegatorKey,
    ) -> spaces_protocol::errors::Result<Option<SLabel>>;

    fn get_numout(
        &mut self,
        outpoint: &OutPoint,
    ) -> spaces_protocol::errors::Result<Option<NumOut>>;

    fn get_num_id(&mut self, _snum: &SNumeric) -> spaces_protocol::errors::Result<Option<NumId>>;
}

#[derive(Debug, Clone)]
pub struct Validator {}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
/// A `TxChangeSet` captures all resulting state changes.
pub struct TxChangeSet {
    #[cfg_attr(
        feature = "borsh",
        borsh(
            serialize_with = "borsh_utils::serialize_txid",
            deserialize_with = "borsh_utils::deserialize_txid"
        )
    )]
    pub txid: Txid,
    /// List of transaction input indexes spending nums.
    pub spends: Vec<usize>,
    /// List of transaction outputs creating numouts.
    pub creates: Vec<NumOut>,
    /// New commitments made
    pub commitments: Vec<CommitmentInfo>,
    pub revoked_commitments: Vec<CommitmentInfo>,
    pub revoked_delegations: Vec<DelegationInfo>,
    pub new_delegations: Vec<DelegationInfo>,
}

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct CommitmentInfo {
    pub space: SLabel,
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub commitment: Commitment,
}

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct DelegationInfo {
    pub id: NumId,
    pub subject: SLabel,
}

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct FullNumOut {
    #[cfg_attr(
        feature = "borsh",
        borsh(
            serialize_with = "borsh_utils::serialize_txid",
            deserialize_with = "borsh_utils::deserialize_txid"
        )
    )]
    pub txid: Txid,

    #[cfg_attr(feature = "serde", serde(flatten))]
    pub numout: NumOut,
}

/// PTR TxOut
/// This structure is a superset of [bitcoin::TxOut]
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct NumOut {
    pub n: usize,
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub num: Num,
    /// The value of the output, in satoshis.
    #[cfg_attr(
        feature = "borsh",
        borsh(
            serialize_with = "borsh_utils::serialize_amount",
            deserialize_with = "borsh_utils::deserialize_amount"
        )
    )]
    pub value: Amount,
    /// The script which must be satisfied for the output to be spent.
    #[cfg_attr(
        feature = "borsh",
        borsh(
            serialize_with = "borsh_utils::serialize_script",
            deserialize_with = "borsh_utils::deserialize_script"
        )
    )]
    pub script_pubkey: ScriptBuf,
}

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct Num {
    pub id: NumId,
    pub name: SNumeric,
    pub data: Option<Bytes>,
    pub last_update: u32,
}

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct Commitment {
    /// Merkle/Trie commitment to the current state.
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "serialize_hash_serde",
            deserialize_with = "deserialize_hash_serde"
        )
    )]
    pub state_root: [u8; 32],

    /// Previous state root (None for genesis).
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "serialize_optional_hash_serde",
            deserialize_with = "deserialize_optional_hash_serde"
        )
    )]
    pub prev_root: Option<[u8; 32]>,

    /// Rolling hash for all previous commitments
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "serialize_hash_serde",
            deserialize_with = "deserialize_hash_serde"
        )
    )]
    pub rolling_hash: [u8; 32],

    /// Block height at which the commitment was made
    pub block_height: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Commitment = 0x01,
    NumId = 0x02,
    Registry = 0x03,
    Delegator = 0x04,
    NumOutpoint = 0x05,
    SNumeric = 0x06,
}

impl KeyKind {
    #[inline]
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

pub fn ns_hash<H: KeyHasher>(kind: KeyKind, data: [u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 1 + 32];
    buf[0] = kind.as_byte();
    buf[1..].copy_from_slice(&data);
    H::hash(&buf)
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct CommitmentTipKey([u8; 32]);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct DelegatorKey([u8; 32]);

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct CommitmentKey([u8; 32]);

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct NumOutpointKey([u8; 32]);

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct NumericKey([u8; 32]);

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RootAnchor {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "serialize_hash_serde",
            deserialize_with = "deserialize_hash_serde"
        )
    )]
    pub spaces_root: Hash,
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Option::is_none",
            serialize_with = "serialize_optional_hash_serde",
            deserialize_with = "deserialize_optional_hash_serde"
        )
    )]
    pub nums_root: Option<Hash>,
    pub block: ChainAnchor,
}

/// Keys needed to fetch chain proofs for certificate verification.
///
/// Built from certificates, this tells a spaced client which merkle
/// proof paths to include in the spaces and ptrs trees.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone)]
pub struct ChainProofRequest {
    /// Spaces to prove (server resolves to outpoint keys).
    pub spaces: Vec<SLabel>,
    /// Typed keys to prove in the ptrs tree.
    pub nums: Vec<NumKeyKind>,
}

/// A typed key for the nums tree.
///
/// Server resolves these to the appropriate merkle proof paths.
/// For a num id, the server must look up the outpoint to prove existence.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "key", content = "value", rename_all = "lowercase")
)]
#[derive(Clone, Copy)]
pub enum NumKeyKind {
    Id(NumId),
    Num(SNumeric),
    Commitment(CommitmentKey),
    CommitmentTip(CommitmentTipKey),
}

impl KeyHash for CommitmentTipKey {}
impl KeyHash for DelegatorKey {}
impl KeyHash for CommitmentKey {}
impl KeyHash for NumOutpointKey {}
impl KeyHash for NumericKey {}

impl Commitment {
    pub fn is_finalized(&self, height: u32) -> bool {
        let finality_height = self.block_height + COMMITMENT_FINALITY_INTERVAL;
        height > finality_height
    }
}

impl FullNumOut {
    pub fn outpoint(&self) -> OutPoint {
        OutPoint {
            txid: self.txid,
            vout: self.numout.n as _,
        }
    }
}

impl From<CommitmentTipKey> for Hash {
    fn from(value: CommitmentTipKey) -> Self {
        value.0
    }
}

impl From<DelegatorKey> for Hash {
    fn from(value: DelegatorKey) -> Self {
        value.0
    }
}

impl From<CommitmentKey> for Hash {
    fn from(value: CommitmentKey) -> Self {
        value.0
    }
}

impl From<NumOutpointKey> for Hash {
    fn from(value: NumOutpointKey) -> Self {
        value.0
    }
}

impl From<NumericKey> for Hash {
    fn from(value: NumericKey) -> Self {
        value.0
    }
}

impl NumOutpointKey {
    pub fn from_outpoint<H: KeyHasher>(outpoint: OutPoint) -> Self {
        let mut buffer = [0u8; 36];
        buffer[0..32].copy_from_slice(outpoint.txid.as_ref());
        buffer[32..36].copy_from_slice(&outpoint.vout.to_le_bytes());
        Self(ns_hash::<H>(KeyKind::NumOutpoint, H::hash(&buffer)))
    }
}

impl CommitmentKey {
    pub fn new<H: KeyHasher>(space: &SLabel, root: [u8; 32]) -> Self {
        let mut data = [0u8; 64];
        data[0..32].copy_from_slice(&H::hash(space.as_ref()));
        data[32..64].copy_from_slice(&root);
        Self(ns_hash::<H>(KeyKind::Registry, H::hash(&data)))
    }
}

impl CommitmentTipKey {
    pub fn from_slabel<H: KeyHasher>(subject: &SLabel) -> Self {
        Self(ns_hash::<H>(KeyKind::Registry, H::hash(subject.as_ref())))
    }
}

impl DelegatorKey {
    pub fn from_id<H: KeyHasher>(id: NumId) -> Self {
        DelegatorKey(ns_hash::<H>(KeyKind::Delegator, id.to_bytes()))
    }
}

impl NumericKey {
    pub fn from_numeric<H: KeyHasher>(numeric: &SNumeric) -> Self {
        let mut buf = [0u8; 8];
        buf[..4].copy_from_slice(&numeric.block().to_le_bytes());
        buf[4..6].copy_from_slice(&numeric.tx_pos().to_le_bytes());
        buf[6..8].copy_from_slice(&numeric.vout().to_le_bytes());
        Self(ns_hash::<H>(KeyKind::SNumeric, H::hash(&buf)))
    }
}

#[derive(Clone)]
pub struct Stxo {
    pub n: usize,
    pub numout: NumOut,
    pub delegate: Option<DelegateContext>,
}

#[derive(Clone)]
pub struct DelegateContext {
    subject: SLabel,
    pending_tip: Option<Commitment>,
    finalized_tip: Option<Commitment>,
}

pub struct TxContext {
    pub inputs: Vec<Stxo>,
    pub existing_num_spks: Vec<ScriptBuf>,
    // nums with existing delegations cannot be used multiple times
    pub nums_with_delegations: Vec<DelegatorKey>,
}

impl TxContext {
    pub fn spending_nums<T: NumSource>(
        src: &mut T,
        tx: &Transaction,
    ) -> spaces_protocol::errors::Result<bool> {
        for input in tx.input.iter() {
            if src.get_numout(&input.previous_output)?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Creates a [TxContext] from a Bitcoin [Transaction], loading all necessary data
    /// for validation from the provided data source `src`.
    ///
    /// Returns `Some(TxContext)` if the transaction is ptrs tx.
    /// Returns `None` if the transaction is not relevant.
    pub fn from_tx<T: NumSource, H: KeyHasher>(
        src: &mut T,
        tx: &Transaction,
        spends_spaces: bool,
        space_outputs: Vec<SpaceOut>,
        height: u32,
    ) -> spaces_protocol::errors::Result<Option<TxContext>> {
        let has_num_outputs = is_num_minting_locktime(&tx.lock_time)
            && tx.output.iter().any(|out| out.is_ptr_output());
        let has_spaces = spends_spaces || space_outputs.len() > 0;

        let relevant = has_spaces || has_num_outputs || Self::spending_nums(src, tx)?;
        if !relevant {
            return Ok(None);
        }

        let mut inputs = Vec::with_capacity(tx.input.len());

        for (n, input) in tx.input.iter().enumerate() {
            let Some(numout) = src.get_numout(&input.previous_output)? else {
                continue;
            };

            let delegate = {
                let dk = DelegatorKey::from_id::<H>(numout.num.id);
                match src.get_delegator(&dk)? {
                    Some(slabel) => {
                        let ctip = CommitmentTipKey::from_slabel::<H>(&slabel);
                        let tip_root = src.get_commitments_tip(&ctip)?;
                        let tip = match tip_root {
                            Some(root) => {
                                let ck = CommitmentKey::new::<H>(&slabel, root);
                                src.get_commitment(&ck)?
                            }
                            None => None,
                        };

                        // Determine pending and finalized tips
                        let (pending_tip, finalized_tip) = match tip {
                            Some(t) if t.is_finalized(height) => (None, Some(t)),
                            Some(t) => {
                                // Tip is pending, check for previous finalized commitment
                                let finalized = match t.prev_root {
                                    Some(prev_root) => {
                                        let ck = CommitmentKey::new::<H>(&slabel, prev_root);
                                        src.get_commitment(&ck)?
                                    }
                                    None => None,
                                };
                                (Some(t), finalized)
                            }
                            None => (None, None),
                        };

                        Some(DelegateContext {
                            subject: slabel,
                            pending_tip,
                            finalized_tip,
                        })
                    }
                    None => None,
                }
            };

            inputs.push(Stxo {
                n,
                numout,
                delegate,
            });
        }

        let mut nums_with_delegations = Vec::with_capacity(space_outputs.len());
        for spaceout in space_outputs {
            let rsk = DelegatorKey::from_id::<H>(NumId::from_spk::<H>(spaceout.script_pubkey));
            if src.get_delegator(&rsk)?.is_some() {
                nums_with_delegations.push(rsk);
            }
        }
        for input in &inputs {
            let dk = DelegatorKey::from_id::<H>(
                NumId::from_spk::<H>(input.numout.script_pubkey.clone()),
            );
            if !nums_with_delegations.contains(&dk) {
                if src.get_delegator(&dk)?.is_some() {
                    nums_with_delegations.push(dk);
                }
            }
        }

        // Output script pubkeys that already have a num (skip minting duplicates)
        let existing_num_spks = tx
            .output
            .iter()
            .filter(|out| out.is_ptr_output())
            .filter_map(|out| {
                let id = NumId::from_spk::<H>(out.script_pubkey.clone());
                src.get_num_outpoint_by_id(&id)
                    .ok()?
                    .map(|_| out.script_pubkey.clone())
            })
            .collect();

        Ok(Some(TxContext {
            inputs,
            existing_num_spks,
            nums_with_delegations,
        }))
    }
}

pub fn rolling_hash<H: KeyHasher>(old: [u8; 32], new_root: [u8; 32]) -> [u8; 32] {
    let mut data = [0u8; 64];
    data[0..32].copy_from_slice(&old);
    data[32..64].copy_from_slice(&new_root);
    H::hash(&data)
}

impl Validator {
    pub fn new() -> Self {
        Self {}
    }

    pub fn process<H: KeyHasher>(
        &self,
        height: u32,
        tx: &Transaction,
        tx_pos: u16,
        mut ctx: TxContext,
        spent_space_utxos: Vec<SpaceOut>,
        new_space_utxos: Vec<SpaceOut>,
    ) -> TxChangeSet {
        let mut changeset = TxChangeSet {
            txid: tx.compute_txid(),
            spends: vec![],
            creates: vec![],
            commitments: vec![],
            revoked_commitments: vec![],
            revoked_delegations: vec![],
            new_delegations: vec![],
        };

        let commitment_op = find_op_commit(&tx.output);
        let data_op = find_op_set_data(&tx.output);
        let has_spaces = !spent_space_utxos.is_empty() || !new_space_utxos.is_empty();

        // Revoke num id -> space delegations for spent space UTXOs
        changeset.revoked_delegations = spent_space_utxos
            .into_iter()
            .filter_map(|spent| {
                spent.space.as_ref().map(|space| {
                    let id = NumId::from_spk::<H>(spent.script_pubkey);
                    DelegationInfo {
                        subject: space.name.clone(),
                        id,
                    }
                })
            })
            .collect();

        // Revoke num to num delegations only when the source num is spent
        // and a delegation actually exists at that address.
        changeset.revoked_delegations.extend(
            ctx.inputs
                .iter()
                .filter_map(|input| {
                    let operator_id = NumId::from_spk::<H>(input.numout.script_pubkey.clone());
                    if operator_id == input.numout.num.id {
                        return None;
                    }
                    let dk = DelegatorKey::from_id::<H>(operator_id);
                    if !ctx.nums_with_delegations.contains(&dk) {
                        return None;
                    }
                    Some(DelegationInfo {
                        subject: input.numout.num.name.to_slabel(),
                        id: operator_id,
                    })
                }),
        );

        // Clear revoked num ids so they can be redelegated in the same tx
        let revoked_keys: Vec<DelegatorKey> = changeset
            .revoked_delegations
            .iter()
            .map(|rd| DelegatorKey::from_id::<H>(rd.id))
            .collect();
        ctx.nums_with_delegations
            .retain(|rsk| !revoked_keys.contains(rsk));

        // Create delegations for owned spaces (Transfer covenant only).
        // Spaces still in auction (Bid covenant) are not delegatable.
        changeset.new_delegations = new_space_utxos
            .iter()
            .filter_map(|created| {
                if !created.space.as_ref().is_some_and(|s| s.is_owned()) {
                    return None;
                }

                let id = NumId::from_spk::<H>(created.script_pubkey.clone());
                let dk = DelegatorKey::from_id::<H>(id);
                if ctx.nums_with_delegations.contains(&dk) {
                    return None;
                }
                created.space.as_ref().map(|space| DelegationInfo {
                    subject: space.name.clone(),
                    id,
                })
            })
            .collect();

        let mut commitment_roots = match &commitment_op {
            Some(CommitmentOp::Commit(roots)) => roots.iter(),
            _ => [].iter(), // Empty iterator for rollback or no-op
        };

        for input_ctx in ctx.inputs.into_iter() {
            // Handle delegate commitments (only first delegate gets commitment_root)
            if let Some(delegate) = input_ctx.delegate {
                match &commitment_op {
                    Some(CommitmentOp::Rollback) => {
                        // Rollback applies to ALL delegates with pending commitments
                        if let Some(pending) = delegate.pending_tip {
                            if !pending.is_finalized(height) {
                                changeset.revoked_commitments.push(CommitmentInfo {
                                    space: delegate.subject.clone(),
                                    commitment: pending,
                                });
                            }
                        }
                    }
                    Some(CommitmentOp::Commit(_)) => {
                        if let Some(root) = commitment_roots.next() {
                            let commitment = match delegate.finalized_tip {
                                None => Commitment {
                                    state_root: *root,
                                    rolling_hash: *root,
                                    prev_root: None,
                                    block_height: height,
                                },
                                Some(prev) => {
                                    assert!(prev.is_finalized(height), "expected a finalized tip");
                                    Commitment {
                                        state_root: *root,
                                        rolling_hash: rolling_hash::<H>(prev.rolling_hash, *root),
                                        prev_root: Some(prev.state_root),
                                        block_height: height,
                                    }
                                }
                            };
                            // Revoke pending commitment
                            if let Some(pending) = delegate.pending_tip {
                                changeset.revoked_commitments.push(CommitmentInfo {
                                    space: delegate.subject.clone(),
                                    commitment: pending,
                                });
                            }
                            changeset.commitments.push(CommitmentInfo {
                                space: delegate.subject,
                                commitment,
                            });
                        }
                    }
                    None => {}
                }
            }
            // Process spend
            changeset.spends.push(input_ctx.n);
            self.process_spend(
                tx,
                input_ctx.n,
                input_ctx.numout,
                &new_space_utxos,
                &mut changeset,
                height,
                &data_op,
            );
        }

        // Process new nums
        for (n, output) in tx.output.iter().enumerate() {
            // Skip if not a PTR output or already processed
            if !output.is_ptr_output()
                || changeset.creates.iter().any(|x| x.n == n)
                || new_space_utxos.iter().any(|x| x.n == n)
            {
                continue;
            }

            // Skip if num id already exists
            if ctx
                .existing_num_spks
                .iter()
                .any(|spk| output.script_pubkey.as_bytes() == spk.as_bytes())
            {
                continue;
            }

            changeset.creates.push(NumOut {
                n,
                num: Num {
                    id: NumId::from_spk::<H>(output.script_pubkey.clone()),
                    name: SNumeric::new(height, tx_pos, n as u16),
                    data: data_op.clone(),
                    last_update: height,
                },
                value: output.value,
                script_pubkey: output.script_pubkey.clone(),
            });
        }

        // Create delegations for nums that opt in via output
        // value ending in 8. Most numerics don't need commitments, so this
        // avoids creating a delegation entry for every PTR.
        // Skipped for txs involving spaces to prevent a nums delegation
        // from overwriting a space delegation sharing the same num id.
        if !has_spaces {
            for created in &changeset.creates {
                // Here we are only concerned with the main num that wants to delegate....
                if created.value.to_sat() % 10 != 8 {
                    continue;
                }

                // The current spk of the num points to the operator
                let operator_id = NumId::from_spk::<H>(created.script_pubkey.clone());
                let operator_key = DelegatorKey::from_id::<H>(operator_id);
                if !ctx.nums_with_delegations.contains(&operator_key) {
                    changeset.new_delegations.push(DelegationInfo {
                        subject: created.num.name.to_slabel(),
                        id: operator_id,
                    });
                }
            }
        }

        changeset
    }

    fn process_spend(
        &self,
        tx: &Transaction,
        input_index: usize,
        mut numout: NumOut,
        new_space_utxos: &Vec<SpaceOut>,
        changeset: &mut TxChangeSet,
        height: u32,
        data: &Option<Bytes>,
    ) {
        let mut ptr = numout.num;
        // if a corresponding output at the same index has the same value,
        // that output becomes the num
        let mut output_index = input_index;
        let mut output = match tx.output.get(input_index) {
            None => return, // cannot be rebound, if N doesn't exist, then we can skip n+1 rule check
            Some(output) => output,
        };

        // if the values don't match, then we assume it's a trading tx - ptr should be at n+1
        if output.value != numout.value {
            output_index = input_index + 1;
            output = match tx.output.get(output_index) {
                None => return, // no rebounds
                Some(output) => output,
            };
        }

        // if the output is already a space, then it can't be rebound
        if new_space_utxos.iter().any(|s| s.n == output_index) {
            return;
        }

        ptr.last_update = height;
        // Only update data if:
        // 1. A data OP_RETURN is present
        // 2. PTR is P2TR and input uses SIGHASH_ALL (prevents malicious data injection)
        if let Some(new_data) = data {
            if numout.script_pubkey.is_p2tr() && is_p2tr_sighash_all(tx, input_index) {
                ptr.data = Some(new_data.clone());
            }
        }
        numout.n = output_index;
        numout.value = output.value;
        numout.script_pubkey = output.script_pubkey.clone();
        numout.num = ptr;
        changeset.creates.push(numout);
    }
}

pub enum CommitmentOp {
    /// Add one or more new commitments
    Commit(Vec<[u8; 32]>),
    /// Rollback the last finalized commitment
    Rollback,
}

pub enum NumOp {
    Commitment(CommitmentOp),
    Data(Vec<u8>),
}

/// To make a commitment, we use:
/// Commit: OP_RETURN OP_PUSHNUM_2 OP_PUSHBYTES_x <data>
/// Rollback: OP_RETURN OP_PUSHNUM_2 OP_PUSHBYTES_0
pub fn find_op_commit(tx_outputs: &[TxOut]) -> Option<CommitmentOp> {
    tx_outputs.iter().find_map(|s| {
        let mut instructions = s.script_pubkey.instructions().skip(1);
        match (instructions.next()?.ok()?, instructions.next()?.ok()?) {
            (Instruction::Op(OP_PUSHNUM_2), Instruction::PushBytes(payload)) => {
                if payload.is_empty() {
                    Some(CommitmentOp::Rollback)
                } else if payload.len() % 32 != 0 {
                    None
                } else {
                    let mut commitments = Vec::with_capacity(payload.len() / 32);
                    for chunk in payload.as_bytes().chunks_exact(32) {
                        let mut commitment = [0u8; 32];
                        commitment.copy_from_slice(chunk);
                        commitments.push(commitment);
                    }
                    Some(CommitmentOp::Commit(commitments))
                }
            }
            _ => None,
        }
    })
}

// Create commitment scripts
// Format: OP_RETURN OP_PUSHNUM_2 <commitments>
pub fn create_commitment_script(op: &CommitmentOp) -> ScriptBuf {
    let mut builder = ScriptBuf::builder()
        .push_opcode(OP_RETURN)
        .push_opcode(OP_PUSHNUM_2);

    match op {
        CommitmentOp::Rollback => {
            // OP_RETURN OP_PUSHNUM_2 OP_PUSHBYTES_0
            builder = builder.push_slice(&[]);
        }
        CommitmentOp::Commit(commitments) => {
            // OP_RETURN OP_PUSHNUM_2 OP_PUSHBYTES_N <commitments>
            let mut buf = PushBytesBuf::new();
            for commitment in commitments {
                buf.extend_from_slice(commitment).expect("valid");
            }
            builder = builder.push_slice(buf);
        }
    };

    builder.into_script()
}

/// Check if an input uses SIGHASH_ALL for a P2TR key path spend
/// Per BIP 341:
/// - 64 bytes = SIGHASH_DEFAULT (0x00), equivalent to SIGHASH_ALL
/// - 65 bytes with last byte 0x01 = SIGHASH_ALL
/// Note: 0x00 is never appended (always 64 bytes for default)
fn is_p2tr_sighash_all(tx: &Transaction, input_index: usize) -> bool {
    let input = match tx.input.get(input_index) {
        Some(input) => input,
        None => return false,
    };

    let witness = &input.witness;
    if witness.is_empty() {
        return false;
    }

    // First witness element is the schnorr signature for P2TR key path
    let sig = &witness[0];

    match sig.len() {
        64 => true,            // SIGHASH_DEFAULT (0x00) - equivalent to SIGHASH_ALL
        65 => sig[64] == 0x01, // SIGHASH_ALL (0x01)
        _ => false,
    }
}

pub fn is_num_minting_locktime(lock_time: &LockTime) -> bool {
    if let LockTime::Seconds(s) = lock_time {
        return s.to_consensus_u32() % 1000 == 777;
    }
    false
}

pub trait PtrTrackableOutput {
    fn is_ptr_output(&self) -> bool;
}

impl PtrTrackableOutput for TxOut {
    fn is_ptr_output(&self) -> bool {
        self.value.to_sat() % 10 == 7
    }
}

#[cfg(feature = "serde")]
mod serde_helpers {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize_hash_serde<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(bytes))
        } else {
            serializer.serialize_bytes(bytes)
        }
    }

    pub fn deserialize_hash_serde<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let mut bytes = [0u8; 32];
            hex::decode_to_slice(s, &mut bytes).map_err(serde::de::Error::custom)?;
            Ok(bytes)
        } else {
            <[u8; 32]>::deserialize(deserializer)
        }
    }

    pub fn serialize_optional_hash_serde<S>(
        bytes: &Option<[u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(b) => serialize_hash_serde(b, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize_optional_hash_serde<'de, D>(
        deserializer: D,
    ) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|s| {
                let mut bytes = [0u8; 32];
                hex::decode_to_slice(s, &mut bytes).map_err(serde::de::Error::custom)?;
                Ok(bytes)
            })
            .transpose()
    }
}

#[cfg(feature = "serde")]
use serde_helpers::*;

#[cfg(feature = "serde")]
mod hash_key_serde {
    use super::serde_helpers::*;
    use serde::{Deserializer, Serializer};

    macro_rules! impl_hash_key_serde {
        ($ty:ident) => {
            impl serde::Serialize for super::$ty {
                fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    serialize_hash_serde(&self.0, serializer)
                }
            }

            impl<'de> serde::Deserialize<'de> for super::$ty {
                fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                    deserialize_hash_serde(deserializer).map(Self)
                }
            }
        };
    }

    impl_hash_key_serde!(CommitmentTipKey);
    impl_hash_key_serde!(CommitmentKey);
}
