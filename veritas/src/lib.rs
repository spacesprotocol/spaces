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

        if !self.anchors.contains(&root) {
            return Err(Error::NoMatchingAnchor);
        }
        Ok(Proof { root, inner })
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

impl SpaceoutExt for SpaceOut {
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
