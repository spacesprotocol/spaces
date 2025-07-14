use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use secp256k1::{schnorr::Signature, Keypair, Secp256k1, Signing, Verification, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NostrTag(pub Vec<String>);

impl NostrTag {
    pub fn is_space_tag(&self) -> bool {
        self.0.len() >= 3 && self.0[0] == "s"
    }

    pub fn get_space_data(&self) -> Option<(&String, &String)> {
        if self.is_space_tag() {
            Some((&self.0[1], &self.0[2]))
        } else {
            None
        }
    }

    pub fn new_space_tag(space: &str, proof: &str) -> Self {
        NostrTag(vec!["s".to_string(), space.to_string(), proof.to_string()])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrEvent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<sha256::Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<XOnlyPublicKey>,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<NostrTag>,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<Signature>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
}

impl NostrEvent {
    pub fn new(kind: u32, content: &str, tags: Vec<NostrTag>) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        Self {
            id: None,
            pubkey: None,
            created_at,
            kind,
            tags,
            content: content.to_string(),
            sig: None,
            proof: None,
        }
    }

    pub fn get_space_tag(&self) -> Option<(&String, &String)> {
        let space_tags: Vec<&NostrTag> =
            self.tags.iter().filter(|tag| tag.is_space_tag()).collect();
        if space_tags.len() == 1 {
            space_tags[0].get_space_data()
        } else {
            None
        }
    }

    pub fn set_space_tag(&mut self, space: &str, proof: &str) {
        self.tags.retain(|tag| !tag.is_space_tag());
        self.tags.push(NostrTag::new_space_tag(space, proof));
    }

    pub fn serialize_for_signing(&self) -> Option<String> {
        let pubkey = match &self.pubkey {
            None => return None,
            Some(pubkey) => pubkey,
        };
        // Nostr requires a specific serialization format for signing:
        // [0, <pubkey>, <created_at>, <kind>, <tags>, <content>]
        let serialized = json!([
            0,
            pubkey,
            self.created_at,
            self.kind,
            self.tags,
            self.content
        ]);
        Some(serialized.to_string())
    }

    pub fn compute_id(&self) -> Option<sha256::Hash> {
        let serialized = self.serialize_for_signing()?;

        let mut engine = sha256::Hash::engine();
        engine.input(serialized.as_bytes());

        Some(sha256::Hash::from_engine(engine))
    }

    pub fn verify<C: Verification>(&self, ctx: Secp256k1<C>) -> bool {
        let pubkey = match &self.pubkey {
            None => return false,
            Some(pubkey) => pubkey,
        };
        let digest = match self.compute_id() {
            None => return false,
            Some(id) => id,
        };
        if self.id.is_some_and(|id| id != digest) {
            return false;
        }
        let sig = match self.sig {
            None => return false,
            Some(sig) => sig,
        };
        let msg = secp256k1::Message::from_digest(digest.to_byte_array());
        match ctx.verify_schnorr(&sig, &msg, pubkey) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    pub fn sign<C: Signing>(&mut self, ctx: Secp256k1<C>, keypair: &Keypair) -> Result<()> {
        let (pubkey, _) = keypair.x_only_public_key();
        self.pubkey = match self.pubkey {
            None => Some(pubkey),
            Some(key) => {
                if key != pubkey {
                    return Err(anyhow!("wrong pubkey"));
                } else {
                    Some(pubkey)
                }
            }
        };

        let digest = self.compute_id().expect("digest");
        if self.id.is_some_and(|id| id != digest) {
            return Err(anyhow!("wrong event id"));
        }

        self.id = Some(digest.clone());
        let msg_to_sign = secp256k1::Message::from_digest(digest.to_byte_array());
        self.sig = Some(ctx.sign_schnorr(&msg_to_sign, keypair));
        Ok(())
    }
}
