#[cfg(feature = "std")]
pub mod sptr;
pub mod constants;

#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use bitcoin::absolute::LockTime;
use bitcoin::opcodes::all::{OP_PUSHNUM_2, OP_RETURN};
use bitcoin::script::{Instruction, PushBytesBuf};
use spaces_protocol::hasher::{KeyHasher, KeyHash, Hash};
use spaces_protocol::slabel::SLabel;
use spaces_protocol::{Bytes, SpaceOut};
use crate::constants::COMMITMENT_FINALITY_INTERVAL;
use crate::sptr::{Sptr};


pub trait PtrSource {
    fn get_ptr_outpoint(&mut self, sptr: &Sptr) -> spaces_protocol::errors::Result<Option<OutPoint>>;

    fn get_commitment(&mut self, key: &CommitmentKey) -> spaces_protocol::errors::Result<Option<Commitment>>;

    fn get_commitments_tip(&mut self, key: &RegistryKey) -> spaces_protocol::errors::Result<Option<Hash>>;

    fn get_delegator(&mut self, sptr: &RegistrySptrKey) -> spaces_protocol::errors::Result<Option<SLabel>>;

    fn get_ptrout(&mut self, outpoint: &OutPoint) -> spaces_protocol::errors::Result<Option<PtrOut>>;
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
    /// List of transaction input indexes spending a ptrout.
    pub spends: Vec<usize>,
    /// List of transaction outputs creating a ptrout.
    pub creates: Vec<PtrOut>,
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
    pub space: SLabel,
    pub sptr: Sptr,
}

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct FullPtrOut {
    #[cfg_attr(
        feature = "borsh",
        borsh(
            serialize_with = "borsh_utils::serialize_txid",
            deserialize_with = "borsh_utils::deserialize_txid"
        )
    )]
    pub txid: Txid,

    #[cfg_attr(feature = "serde", serde(flatten))]
    pub ptrout: PtrOut,
}

/// PTR TxOut
/// This structure is a superset of [bitcoin::TxOut]
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct PtrOut {
    pub n: usize,
    /// Any handle associated with this output
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub sptr: Option<Ptr>,
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
pub struct Ptr {
    pub id: Sptr,
    pub data: Option<Bytes>,
    pub last_update: u32,
}

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct Commitment {
    /// Merkle/Trie commitment to the current state.
    #[cfg_attr(feature = "serde", serde(
        serialize_with = "serialize_hash_serde",
        deserialize_with = "deserialize_hash_serde"
    ))]
    pub state_root: [u8; 32],

    /// Previous state root (None for genesis).
    #[cfg_attr(feature = "serde", serde(
        serialize_with = "serialize_optional_hash_serde",
        deserialize_with = "deserialize_optional_hash_serde"
    ))]
    pub prev_root: Option<[u8; 32]>,

    /// Running history hash
    #[cfg_attr(feature = "serde", serde(
        serialize_with = "serialize_hash_serde",
        deserialize_with = "deserialize_hash_serde"
    ))]
    pub history_hash: [u8; 32],

    /// Block height at which the commitment was made
    pub block_height: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Commitment = 0x01,
    Sptr = 0x02,
    Registry = 0x03,
    RegistrySptr = 0x04,
    PtrOutpoint = 0x05,
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct RegistryKey([u8; 32]);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct RegistrySptrKey([u8; 32]);

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct CommitmentKey([u8; 32]);

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct PtrOutpointKey([u8; 32]);

impl KeyHash for RegistryKey {}
impl KeyHash for RegistrySptrKey {}
impl KeyHash for CommitmentKey {}
impl KeyHash for PtrOutpointKey {}

impl Commitment {
    pub fn is_finalized(&self, height: u32) -> bool {
        let finality_height = self.block_height + COMMITMENT_FINALITY_INTERVAL;
        height > finality_height
    }
}


impl From<RegistryKey> for Hash {
    fn from(value: RegistryKey) -> Self {
        value.0
    }
}

impl From<RegistrySptrKey> for Hash {
    fn from(value: RegistrySptrKey) -> Self {
        value.0
    }
}

impl From<CommitmentKey> for Hash {
    fn from(value: CommitmentKey) -> Self {
        value.0
    }
}

impl From<PtrOutpointKey> for Hash {
    fn from(value: PtrOutpointKey) -> Self {
        value.0
    }
}

impl PtrOutpointKey {
    pub fn from_outpoint<H: KeyHasher>(outpoint: OutPoint) -> Self {
        let mut buffer = [0u8; 36];
        buffer[0..32].copy_from_slice(outpoint.txid.as_ref());
        buffer[32..36].copy_from_slice(&outpoint.vout.to_le_bytes());
        Self(ns_hash::<H>(KeyKind::PtrOutpoint, H::hash(&buffer)))
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


impl RegistryKey {
    pub fn from_slabel<H: KeyHasher>(space: &SLabel) -> Self {
        Self(ns_hash::<H>(KeyKind::Registry, H::hash(space.as_ref())))
    }
}

impl RegistrySptrKey {
    pub fn from_sptr<H: KeyHasher>(sptr: Sptr) -> Self {
        RegistrySptrKey(ns_hash::<H>(KeyKind::RegistrySptr, sptr.to_bytes()))
    }
}

#[derive(Clone)]
pub struct Stxo {
    pub n: usize,
    pub ptrout: PtrOut,
    pub delegate: Option<DelegateContext>,
}

#[derive(Clone)]
pub struct DelegateContext {
    space: SLabel,
    pending_tip: Option<Commitment>,
    finalized_tip: Option<Commitment>,
}

pub struct TxContext {
    pub inputs: Vec<Stxo>,
    pub relevant_sptr_spks: Vec<ScriptBuf>,
    // sptrs with existing delegations cannot be used multiple times
    pub sptrs_with_delegations: Vec<RegistrySptrKey>,
}

impl TxContext {
    pub fn spending_ptrs<T: PtrSource>(src: &mut T, tx: &Transaction) -> spaces_protocol::errors::Result<bool> {
        for input in tx.input.iter() {
            if src.get_ptrout(&input.previous_output)?.is_some() {
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
    pub fn from_tx<T: PtrSource, H: KeyHasher>(
        src: &mut T,
        tx: &Transaction,
        spends_spaces: bool,
        space_outputs: Vec<SpaceOut>,
        height: u32,
    ) -> spaces_protocol::errors::Result<Option<TxContext>> {
        let has_ptr_outputs = is_ptr_minting_locktime(&tx.lock_time) &&
            tx.output.iter().any(|out| out.is_ptr_output());
        let has_spaces = spends_spaces || space_outputs.len() > 0;

        let relevant = has_spaces || has_ptr_outputs || Self::spending_ptrs(src, tx)?;

        if !relevant {
            return Ok(None);
        }

        let mut inputs = Vec::with_capacity(tx.input.len());

        for (n, input) in tx.input.iter().enumerate() {
            let ptrout = src.get_ptrout(&input.previous_output)?;

            if let Some(ptrout) = ptrout {
                let delegate = match &ptrout.sptr {
                    Some(sptr) => {
                        let rsk = RegistrySptrKey::from_sptr::<H>(sptr.id);

                        match src.get_delegator(&rsk)? {
                            Some(slabel) => {
                                let registry_key = RegistryKey::from_slabel::<H>(&slabel);
                                let tip_root = src.get_commitments_tip(&registry_key)?;
                                let tip = match tip_root {
                                    Some(root) => {
                                        let ck = CommitmentKey::new::<H>(&slabel, root);
                                        src.get_commitment(&ck)?
                                    }
                                    None => None,
                                };

                                // Determine pending and finalized tips
                                let (pending_tip, finalized_tip) = match tip {
                                    Some(t) if t.is_finalized(height) => {
                                        (None, Some(t))
                                    }
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
                                    space: slabel,
                                    pending_tip,
                                    finalized_tip,
                                })
                            }
                            None => None,
                        }
                    }
                    None => None,
                };

                inputs.push(Stxo {
                    n,
                    ptrout,
                    delegate,
                });
            }
        }

        let mut sptrs_with_delegations = Vec::with_capacity(space_outputs.len());
        for spaceout in space_outputs {
            let rsk = RegistrySptrKey::from_sptr::<H>(Sptr::from_spk::<H>(spaceout.script_pubkey));
            if src.get_delegator(&rsk)?.is_some() {
                sptrs_with_delegations.push(rsk);
            }
        }

        // Build relevant SPTR script pubkeys for existence checks
        let relevant_sptr_spks = tx.output
            .iter()
            .filter(|out| out.is_ptr_output())
            .filter_map(|out| {
                let sptr = Sptr::from_spk::<H>(out.script_pubkey.clone());
                src.get_ptr_outpoint(&sptr)
                    .ok()?
                    .map(|_| out.script_pubkey.clone())
            })
            .collect();

        Ok(Some(TxContext {
            inputs,
            relevant_sptr_spks,
            sptrs_with_delegations
        }))
    }
}

pub fn transcript_hash<H: KeyHasher>(old: [u8; 32], new_root: [u8; 32]) -> [u8; 32] {
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
        &self, height: u32,
        tx: &Transaction,
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

        // Remove sptr -> space mappings if a space is spent
        changeset.revoked_delegations = spent_space_utxos
            .into_iter()
            .filter_map(|spent| {
                spent.space.as_ref().map(|space| {
                    let sptr = Sptr::from_spk::<H>(spent.script_pubkey);
                    DelegationInfo {
                        space: space.name.clone(),
                        sptr,
                    }
                })
            })
            .collect();

        // Allow sptrs to be redelegated
        let revoked_keys: Vec<RegistrySptrKey> = changeset.revoked_delegations
            .iter()
            .map(|rd| RegistrySptrKey::from_sptr::<H>(rd.sptr))
            .collect();
        ctx.sptrs_with_delegations.retain(|rsk| !revoked_keys.contains(rsk));

        // Process new delegations from created space UTXOs
        changeset.new_delegations = new_space_utxos
            .iter()
            .filter_map(|created| {
                let sptr = Sptr::from_spk::<H>(created.script_pubkey.clone());
                let rsk = RegistrySptrKey::from_sptr::<H>(sptr);
                if ctx.sptrs_with_delegations.contains(&rsk) {
                    return None;
                }
                created.space.as_ref().map(|space| {
                    DelegationInfo {
                        space: space.name.clone(),
                        sptr,
                    }
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
                                changeset.revoked_commitments.push(
                                    CommitmentInfo {
                                        space: delegate.space.clone(),
                                        commitment: pending,
                                    }
                                );
                            }
                        }
                    }
                    Some(CommitmentOp::Commit(_)) => {
                        if let Some(root) = commitment_roots.next() {
                            let commitment = match delegate.finalized_tip {
                                None => Commitment {
                                    state_root: *root,
                                    history_hash: *root,
                                    prev_root: None,
                                    block_height: height,
                                },
                                Some(prev) => {
                                    assert!(prev.is_finalized(height), "expected a finalized tip");
                                    Commitment {
                                        state_root: *root,
                                        history_hash: transcript_hash::<H>(prev.history_hash, *root),
                                        prev_root: Some(prev.state_root),
                                        block_height: height,
                                    }
                                }
                            };
                            // Revoke pending commitment
                            if let Some(pending) = delegate.pending_tip {
                                changeset.revoked_commitments.push(
                                    CommitmentInfo {
                                        space: delegate.space.clone(),
                                        commitment: pending,
                                    }
                                );
                            }
                            changeset.commitments.push(CommitmentInfo {
                                space: delegate.space,
                                commitment,
                            });
                        }
                    }
                    None => {}
                }
            }
            // Process spend
            changeset.spends.push(input_ctx.n);
            self.process_spend(tx, input_ctx.n, input_ctx.ptrout, &new_space_utxos, &mut changeset, height, &data_op);
        }

        // Process new PTR outputs
        for (n, output) in tx.output.iter().enumerate() {
            // Skip if not a PTR output or already processed
            if !output.is_ptr_output()
                || changeset.creates.iter().any(|x| x.n == n)
                || new_space_utxos.iter().any(|x| x.n == n) {
                continue;
            }

            // Skip if SPTR already exists
            if ctx.relevant_sptr_spks
                .iter()
                .any(|spk| output.script_pubkey.as_bytes() == spk.as_bytes()) {
                continue;
            }

            changeset.creates.push(PtrOut {
                n,
                sptr: Some(Ptr {
                    id: Sptr::from_spk::<H>(output.script_pubkey.clone()),
                    data: data_op.clone(),
                    last_update: height,
                }),
                value: output.value,
                script_pubkey: output.script_pubkey.clone(),
            });
        }

        changeset
    }

    fn process_spend(
        &self,
        tx: &Transaction,
        input_index: usize,
        mut ptrout: PtrOut,
        new_space_utxos: &Vec<SpaceOut>,
        changeset: &mut TxChangeSet,
        height: u32,
        data: &Option<Bytes>,
    ) {
        let mut ptr = match ptrout.sptr {
            None => return,
            Some(ptr) => ptr,
        };
        // if a corresponding output at the same index has the same value,
        // that output becomes the PTR
        let mut output_index = input_index;
        let mut output = match tx.output.get(input_index) {
            None => return, // cannot be rebound, if N doesn't exist, then we can skip n+1 rule check
            Some(output) => output,
        };

        // if the values don't match, then we assume it's a trading tx - ptr should be at n+1
        if output.value != ptrout.value {
            output_index = input_index + 1;
            output = match tx.output.get(output_index) {
                None => return, // no rebounds
                Some(output) => output
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
            if ptrout.script_pubkey.is_p2tr() && is_p2tr_sighash_all(tx, input_index) {
                ptr.data = Some(new_data.clone());
            }
        }
        ptrout.n = output_index;
        ptrout.value = output.value;
        ptrout.script_pubkey = output.script_pubkey.clone();
        ptrout.sptr = Some(ptr);
        changeset.creates.push(ptrout);
    }
}


pub enum CommitmentOp {
    /// Add one or more new commitments
    Commit(Vec<[u8; 32]>),
    /// Rollback the last finalized commitment
    Rollback,
}

pub enum PtrOp {
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
            (Instruction::Op(OP_PUSHNUM_2), Instruction::PushBytes(payload)) =>
                {
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

                },
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
        64 => true, // SIGHASH_DEFAULT (0x00) - equivalent to SIGHASH_ALL
        65 => sig[64] == 0x01, // SIGHASH_ALL (0x01)
        _ => false,
    }
}

pub fn is_ptr_minting_locktime(lock_time: &LockTime) -> bool {
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
    use serde::{Deserializer, Serializer, Deserialize};

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
use spaces_protocol::script::find_op_set_data;

