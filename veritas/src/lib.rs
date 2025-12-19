#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

mod wasm;

extern crate alloc;

use alloc::{collections::BTreeSet, vec::Vec};

use bincode::config;
use spacedb::{
    encode::SubTreeEncoder,
    subtree::{SubTree, SubtreeIter},
    Hash, Sha256Hasher, VerifyError,
};
use spaces_protocol::{
    bitcoin::{key::Secp256k1, secp256k1, secp256k1::VerifyOnly, OutPoint, XOnlyPublicKey},
    hasher,
    hasher::{OutpointKey, SpaceKey},
    slabel::SLabel,
    SpaceOut,
};
use spaces_ptr::{PtrOut, Commitment, sptr::Sptr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofType {
    Spaces,
    Ptrs,
}

pub struct Veritas {
    anchors: BTreeSet<hasher::Hash>,
    proof_type: ProofType,
    ctx: Secp256k1<VerifyOnly>,
}

pub struct Proof {
    root: Hash,
    proof_type: ProofType,
    inner: SubTree<Sha256Hasher>,
}

pub struct ProofIter<'a> {
    proof_type: ProofType,
    inner: SubtreeIter<'a>,
}

pub enum Value {
    Outpoint(OutPoint),
    UTXO(SpaceOut),
    PtrUTXO(PtrOut),
    Commitment(Commitment),
    Space(SLabel),
    Root(hasher::Hash),
    Unknown(Vec<u8>),
}

pub trait UtxoExt {
    fn public_key(&self) -> Option<XOnlyPublicKey>;
}

#[derive(Debug)]
pub enum Error {
    MalformedSubtree,
    MalformedValue,
    KeyExists,
    IncompleteProof,
    KeyNotFound,
    NoMatchingAnchor,
    UnsupportedScriptPubKey,
    InvalidSignature,
    SignatureVerificationFailed,
}

impl Veritas {
    pub fn new(proof_type: ProofType) -> Self {
        Self {
            anchors: BTreeSet::new(),
            proof_type,
            ctx: Secp256k1::verification_only(),
        }
    }

    pub fn add_anchor(&mut self, anchor: hasher::Hash) {
        self.anchors.insert(anchor);
    }

    pub fn verify_proof(&self, proof: impl AsRef<[u8]>) -> Result<Proof, Error> {
        let inner = SubTree::from_slice(proof.as_ref()).map_err(|_| Error::MalformedSubtree)?;
        let root = inner.compute_root()?;

        if !self.anchors.contains(&root) {
            return Err(Error::NoMatchingAnchor);
        }
        Ok(Proof {
            root,
            proof_type: self.proof_type.clone(),
            inner
        })
    }

    pub fn verify_schnorr(&self, pubkey: &[u8], digest: &[u8], sig: &[u8]) -> bool {
        if digest.len() != 32 {
            return false;
        }
        let sig = match secp256k1::schnorr::Signature::from_slice(sig) {
            Err(_) => return false,
            Ok(sig) => sig,
        };
        let pubkey = match XOnlyPublicKey::from_slice(pubkey) {
            Err(_) => return false,
            Ok(pubkey) => pubkey,
        };

        let mut msg_digest = [0u8; 32];
        msg_digest.copy_from_slice(digest.as_ref());
        let msg_digest = secp256k1::Message::from_digest(msg_digest);
        self.ctx
            .verify_schnorr(&sig, &msg_digest, &pubkey)
            .map(|_| true)
            .unwrap_or(false)
    }
}

impl Proof {
    pub fn iter(&self) -> ProofIter<'_> {
        ProofIter {
            proof_type: self.proof_type,
            inner: self.inner.iter(),
        }
    }

    pub fn root(&self) -> &Hash {
        &self.root
    }

    pub fn contains(&self, key: &Hash) -> Result<bool, Error> {
        self.inner.contains(key).map_err(|e| e.into())
    }

    /// Retrieves a UTXO leaf within the subtree specified the outpoint hash
    pub fn get_utxo(&self, utxo_key: &Hash) -> Result<Option<SpaceOut>, Error> {
        let (_, value) = match self.inner.iter().find(|(k, _)| *k == utxo_key) {
            None => return Ok(None),
            Some(kv) => kv,
        };
        let (utxo, _): (SpaceOut, _) = bincode::decode_from_slice(value, config::standard())
            .map_err(|_| Error::MalformedValue)?;
        Ok(Some(utxo))
    }

    /// Retrieves a UTXO leaf containing the specified space
    pub fn find_space(&self, space: &SLabel) -> Result<Option<SpaceOut>, Error> {
        for (_, v) in self.iter() {
            match v {
                Value::UTXO(utxo) => {
                    if utxo
                        .space
                        .as_ref()
                        .is_some_and(|s| s.name.as_ref() == space.as_ref())
                    {
                        return Ok(Some(utxo));
                    }
                }
                _ => continue,
            }
        }
        Ok(None)
    }

    /// Retrieves a PTR UTXO leaf within the subtree specified by the outpoint hash
    pub fn get_ptrout(&self, utxo_key: &Hash) -> Result<Option<PtrOut>, Error> {
        let (_, value) = match self.inner.iter().find(|(k, _)| *k == utxo_key) {
            None => return Ok(None),
            Some(kv) => kv,
        };
        let (ptrout, _): (PtrOut, _) = bincode::decode_from_slice(value, config::standard())
            .map_err(|_| Error::MalformedValue)?;
        Ok(Some(ptrout))
    }

    /// Retrieves a PTR UTXO leaf containing the specified sptr
    pub fn find_ptr(&self, sptr: &Sptr) -> Result<Option<PtrOut>, Error> {
        for (_, v) in self.iter() {
            match v {
                Value::PtrUTXO(ptrout) => {
                    if ptrout
                        .sptr
                        .as_ref()
                        .is_some_and(|ptr| &ptr.id == sptr)
                    {
                        return Ok(Some(ptrout));
                    }
                }
                _ => continue,
            }
        }
        Ok(None)
    }

    /// Retrieves a commitment by its key
    pub fn get_commitment(&self, commitment_key: &Hash) -> Result<Option<Commitment>, Error> {
        let (_, value) = match self.inner.iter().find(|(k, _)| *k == commitment_key) {
            None => return Ok(None),
            Some(kv) => kv,
        };
        let (commitment, _): (Commitment, _) = bincode::decode_from_slice(value, config::standard())
            .map_err(|_| Error::MalformedValue)?;
        Ok(Some(commitment))
    }

    /// Retrieves the delegated space for an SPTR
    pub fn get_delegation(&self, sptr_key: &Hash) -> Result<Option<SLabel>, Error> {
        let (_, value) = match self.inner.iter().find(|(k, _)| *k == sptr_key) {
            None => return Ok(None),
            Some(kv) => kv,
        };
        let (space, _): (SLabel, _) = bincode::decode_from_slice(value, config::standard())
            .map_err(|_| Error::MalformedValue)?;
        Ok(Some(space))
    }

    /// Retrieves the latest commitment root for a space
    pub fn get_registry_tip(&self, registry_key: &Hash) -> Result<Option<hasher::Hash>, Error> {
        let (_, value) = match self.inner.iter().find(|(k, _)| *k == registry_key) {
            None => return Ok(None),
            Some(kv) => kv,
        };
        let (root, _): (hasher::Hash, _) = bincode::decode_from_slice(value, config::standard())
            .map_err(|_| Error::MalformedValue)?;
        Ok(Some(root))
    }
}

impl From<spacedb::Error> for Error {
    fn from(e: spacedb::Error) -> Self {
        match e {
            spacedb::Error::Verify(e) => match e {
                VerifyError::KeyExists => Error::KeyExists,
                VerifyError::IncompleteProof => Error::IncompleteProof,
                VerifyError::KeyNotFound => Error::KeyNotFound,
            },
            _ => Error::MalformedSubtree,
        }
    }
}

impl UtxoExt for SpaceOut {
    fn public_key(&self) -> Option<XOnlyPublicKey> {
        match self.script_pubkey.is_p2tr() {
            true => XOnlyPublicKey::from_slice(&self.script_pubkey.as_bytes()[2..]).ok(),
            false => None,
        }
    }
}

impl UtxoExt for PtrOut {
    fn public_key(&self) -> Option<XOnlyPublicKey> {
        match self.script_pubkey.is_p2tr() {
            true => XOnlyPublicKey::from_slice(&self.script_pubkey.as_bytes()[2..]).ok(),
            false => None,
        }
    }
}

impl Iterator for ProofIter<'_> {
    type Item = (Hash, Value);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(k, v)| {
            match self.proof_type {
                ProofType::Spaces => {
                    // Spaces proof: OutpointKey → SpaceOut, SpaceKey → OutPoint
                    if OutpointKey::is_valid(k) {
                        let result = bincode::decode_from_slice(v.as_slice(), config::standard())
                            .ok()
                            .map(|(raw, _)| Value::UTXO(raw));
                        return (*k, result.unwrap_or(Value::Unknown(v.clone())));
                    }
                    if SpaceKey::is_valid(k) {
                        let result: Option<OutPoint> =
                            bincode::serde::decode_from_slice(v.as_slice(), config::standard())
                                .ok()
                                .map(|(raw, _)| raw);
                        return result
                            .map(|r| (*k, Value::Outpoint(r)))
                            .unwrap_or_else(|| (*k, Value::Unknown(v.clone())));
                    }
                    (*k, Value::Unknown(v.clone()))
                }
                ProofType::Ptrs => {
                    // PTR proof: Try to decode value as different PTR types

                    // Try PtrOutpointKey → PtrOut
                    let ptrout_result: Result<(PtrOut, _), _> = bincode::decode_from_slice(v.as_slice(), config::standard());
                    if let Ok((ptrout, _)) = ptrout_result {
                        return (*k, Value::PtrUTXO(ptrout));
                    }

                    // Try Sptr → OutPoint
                    let outpoint_result: Result<(OutPoint, _), _> = bincode::serde::decode_from_slice(v.as_slice(), config::standard());
                    if let Ok((outpoint, _)) = outpoint_result {
                        return (*k, Value::Outpoint(outpoint));
                    }

                    // Try CommitmentKey → Commitment
                    let commitment_result: Result<(Commitment, _), _> = bincode::decode_from_slice(v.as_slice(), config::standard());
                    if let Ok((commitment, _)) = commitment_result {
                        return (*k, Value::Commitment(commitment));
                    }

                    // Try RegistrySptrKey → SLabel
                    let space_result: Result<(SLabel, _), _> = bincode::decode_from_slice(v.as_slice(), config::standard());
                    if let Ok((space, _)) = space_result {
                        return (*k, Value::Space(space));
                    }

                    // Try RegistryKey → Hash (root)
                    if v.len() == 32 {
                        let root_result: Result<(hasher::Hash, _), _> = bincode::decode_from_slice(v.as_slice(), config::standard());
                        if let Ok((root, _)) = root_result {
                            return (*k, Value::Root(root));
                        }
                    }

                    (*k, Value::Unknown(v.clone()))
                }
            }
        })
    }
}
