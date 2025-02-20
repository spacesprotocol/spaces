#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

mod wasm;

extern crate alloc;

use alloc::vec::Vec;
use alloc::collections::BTreeSet;
use bincode::{config};
use spacedb::{encode::SubTreeEncoder, subtree::{SubTree, SubtreeIter}, Hash, NodeHasher, Sha256Hasher, VerifyError};
use spaces_protocol::{hasher, hasher::{OutpointKey, SpaceKey}, SpaceOut};
use spaces_protocol::bitcoin::hashes::{sha256d, Hash as BitcoinHash, HashEngine};
use spaces_protocol::bitcoin::key::Secp256k1;
use spaces_protocol::bitcoin::{secp256k1, OutPoint, VarInt, XOnlyPublicKey};
use spaces_protocol::bitcoin::consensus::Encodable;
use spaces_protocol::bitcoin::secp256k1::{VerifyOnly};


pub struct Veritas {
    anchors: BTreeSet<hasher::Hash>,
    ctx: Secp256k1<VerifyOnly>,
}

pub struct Proof {
    root: Hash,
    inner: SubTree<Sha256Hasher>,
}

pub struct ProofIter<'a> {
    inner: SubtreeIter<'a>,
}

pub enum Value {
    Outpoint(OutPoint),
    UTXO(SpaceOut),
    Unknown(Vec<u8>),
}

pub trait SpaceoutExt {
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
    pub fn new() -> Self {
        Self {
            anchors: BTreeSet::new(),
            ctx: Secp256k1::verification_only(),
        }
    }

    pub fn add_anchor(&mut self, anchor: hasher::Hash) {
        self.anchors.insert(anchor);
    }

    pub fn verify_proof(&self, proof: impl AsRef<[u8]>) -> Result<Proof, Error> {
        let inner = SubTree::from_slice(proof.as_ref()).map_err(|_| Error::MalformedSubtree)?;
        let root = inner.compute_root()?;

        if !self
            .anchors
            .contains(&root) {
            return Err(Error::NoMatchingAnchor);
        }
        Ok(Proof {
            root,
            inner,
        })
    }

    pub fn verify_message(&self, utxo: &SpaceOut, msg: impl AsRef<[u8]>, sig: &[u8]) -> Result<(), Error> {
        let sig = secp256k1::schnorr::Signature::from_slice(sig).map_err(|_| Error::InvalidSignature)?;
        let pubkey = utxo.public_key().ok_or(Error::UnsupportedScriptPubKey)?;
        let msg_hash = signed_msg_hash(msg.as_ref());
        let msg = secp256k1::Message::from_digest(msg_hash.to_byte_array());
        self.ctx.verify_schnorr(&sig, &msg, &pubkey).map_err(|_| Error::SignatureVerificationFailed)?;
        Ok(())
    }
}

impl Proof {
    pub fn iter(&self) -> ProofIter {
        ProofIter {
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
            Some(kv) => kv
        };
        let (utxo, _): (SpaceOut, _) = bincode::decode_from_slice(value, config::standard())
            .map_err(|_| Error::MalformedValue)?;
        Ok(Some(utxo))
    }

    /// Retrieves a UTXO leaf containing a space that matches the given key
    /// within the subtree
    ///
    /// Subtree stores Outpoint -> UTXO
    /// so this is an O(n) lookup
    pub fn find_space(&self, space_key: &Hash) -> Result<Option<SpaceOut>, Error> {
        for (_, v) in self.iter() {
            match v {
                Value::UTXO(utxo) => {
                    match space_key_from_utxo(&utxo) {
                        Some(key) if &key == space_key => {
                            return Ok(Some(utxo))
                        }
                        _ => {}
                    }
                }
                _ => continue,
            }
        }
        Ok(None)
    }
}

fn space_key_from_utxo(utxo: &SpaceOut) -> Option<Hash> {
    let space = utxo.space.as_ref()?;
    let hash = Sha256Hasher::hash(space.name.as_ref());
    Some(SpaceKey::from(hash).into())
}

fn signed_msg_hash(msg: impl AsRef<[u8]>) -> sha256d::Hash {
    let msg_bytes = msg.as_ref();
    let mut engine = sha256d::Hash::engine();
    engine.input(spaces_protocol::constants::SPACES_SIGNED_MSG_PREFIX);
    VarInt::from(msg_bytes.len())
        .consensus_encode(&mut engine)
        .expect("varint serialization");
    engine.input(msg_bytes);
    sha256d::Hash::from_engine(engine)
}

impl From<spacedb::Error> for Error {
    fn from(e: spacedb::Error) -> Self {
        match e {
            spacedb::Error::Verify(e) => match e {
                VerifyError::KeyExists => Error::KeyExists,
                VerifyError::IncompleteProof => Error::IncompleteProof,
                VerifyError::KeyNotFound => Error::KeyNotFound,
            }
            _ => Error::MalformedSubtree,
        }
    }
}

impl SpaceoutExt for SpaceOut {
    fn public_key(&self) -> Option<XOnlyPublicKey> {
        match self.script_pubkey.is_p2tr() {
            true => XOnlyPublicKey::from_slice(&self.script_pubkey.as_bytes()[2..]).ok(),
            false => None
        }
    }
}

impl Iterator for ProofIter<'_> {
    type Item = (Hash, Value);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(k, v)| {
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
        })
    }
}
