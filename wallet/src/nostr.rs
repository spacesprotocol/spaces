use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow, Context};
use bech32::{Bech32, Hrp};
use bitcoin::hashes::{Hash, HashEngine, sha256};
use secp256k1::{Keypair, Secp256k1, Signing, Verification, XOnlyPublicKey, schnorr::Signature};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NostrTag(pub Vec<String>);

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

    pub fn space(&self) -> Option<String> {
        self.tags
            .iter()
            .find(|tag| {
                if !tag.0.is_empty() {
                    tag.0[0] == "space"
                } else {
                    false
                }
            })
            .map(|tag| tag.0[1].clone())
    }

    pub fn serialize_for_signing(&self) -> Option<String> {
        let pubkey = self.pubkey.as_ref()?;
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
        ctx.verify_schnorr(&sig, &msg, pubkey).is_ok()
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

        self.id = Some(digest);
        let msg_to_sign = secp256k1::Message::from_digest(digest.to_byte_array());
        self.sig = Some(ctx.sign_schnorr(&msg_to_sign, keypair));
        Ok(())
    }
}

/// NIP-19 `nsec` and the raw 32-byte secret key it encodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NsecExport {
    pub nsec: String,
    /// Lowercase hex of the 32-byte secp256k1 secret.
    pub hex: String,
}

/// Bech32-encode a 32-byte secp256k1 secret key as a NIP-19 `nsec`.
pub fn encode_nsec(secret_key: &[u8; 32]) -> Result<String> {
    let hrp = Hrp::parse("nsec").context("invalid nsec hrp")?;
    bech32::encode::<Bech32>(hrp, secret_key).context("nsec bech32 encode failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_nsec_roundtrip() {
        let secret = [0xab; 32];
        let nsec = encode_nsec(&secret).unwrap();
        assert!(nsec.starts_with("nsec1"));
        let (hrp, data) = bech32::decode(&nsec).unwrap();
        assert_eq!(hrp.as_str(), "nsec");
        assert_eq!(data, secret);
    }
}
