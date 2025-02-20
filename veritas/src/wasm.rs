#[cfg(feature = "wasm")]
mod wasm_api {
    use alloc::format;
    use alloc::string::{String, ToString};
    use wasm_bindgen::prelude::*;
    use alloc::vec::Vec;
    use core::str::FromStr;
    use spacedb::{self, NodeHasher, Sha256Hasher};

    use crate::{Veritas as VeritasNative, Proof as ProofNative, Value as ValueNative, Error};
    use spaces_protocol::{
        Covenant as NativeCovenant, slabel::SLabel as NativeSLabel, Space as NativeSpace,
        SpaceOut as NativeSpaceOut,
    };
    use spaces_protocol::hasher::SpaceKey;

    #[wasm_bindgen]
    pub struct Veritas {
        inner: VeritasNative,
    }

    #[wasm_bindgen]
    pub struct Proof {
        inner: ProofNative,
    }

    #[wasm_bindgen]
    pub struct SpaceOut {
        inner: NativeSpaceOut,
    }

    #[wasm_bindgen]
    pub struct Space {
        inner: NativeSpace,
    }

    #[wasm_bindgen]
    pub struct SLabel {
        inner: NativeSLabel,
    }

    #[wasm_bindgen]
    pub struct Covenant {
        inner: NativeCovenant,
    }

    #[wasm_bindgen]
    pub struct TransferCovenant {
        expire_height: u32,
        data: Option<Vec<u8>>,
    }

    #[wasm_bindgen]
    pub struct BidCovenant {
        burn_increment: u64,
        signature: Vec<u8>,
        total_burned: u64,
        claim_height: Option<u32>,
    }

    #[wasm_bindgen]
    impl SLabel {
        #[wasm_bindgen(constructor)]
        pub fn new(space: &str) -> Result<Self, JsValue> {
            Ok(Self {
                inner: NativeSLabel::from_str(space)
                    .map_err(|err| JsValue::from_str(&format!("{:?}", err)))?
            })
        }

        #[wasm_bindgen(js_name = "toString")]
        pub fn to_string(&self) -> String {
            self.inner.to_string()
        }

        #[wasm_bindgen(js_name = "toBytes")]
        pub fn to_bytes(&self) -> Vec<u8> {
           self.inner.as_ref().to_vec()
        }

        #[wasm_bindgen(js_name = "computeHash")]
        pub fn compute_hash(&self) -> Vec<u8> {
            let hash = Sha256Hasher::hash(self.inner.as_ref());
            SpaceKey::from(hash).as_slice().to_vec()
        }
    }

    #[wasm_bindgen]
    impl SpaceOut {
        /// Constructs a SpaceOut from raw bytes.
        #[wasm_bindgen(js_name = "fromBytes")]
        pub fn from_bytes(data: &[u8]) -> Result<SpaceOut, JsValue> {
            let (native, _): (NativeSpaceOut, _) =
                bincode::decode_from_slice(data, bincode::config::standard())
                    .map_err(|e| JsValue::from_str(&format!("Deserialization error: {:?}", e)))?;
            Ok(SpaceOut { inner: native })
        }

        #[wasm_bindgen(js_name = "getScriptPubkey")]
        pub fn get_script_pubkey(&self) -> Vec<u8> {
            self.inner.script_pubkey.to_bytes()
        }

        #[wasm_bindgen(js_name = "getPublicKey")]
        pub fn get_public_key(&self) -> Option<Vec<u8>> {
            match self.inner.script_pubkey.is_p2tr() {
                true => Some(self.inner.script_pubkey.as_bytes()[2..].to_vec()),
                false => None
            }
        }

        #[wasm_bindgen(js_name = "getValue")]
        pub fn get_value(&self) -> u64 {
            self.inner.value.to_sat()
        }

        #[wasm_bindgen(js_name = "getSpace")]
        pub fn get_space(&self) -> Option<Space> {
            self.inner.space.clone().map(|s| Space { inner: s })
        }
    }

    #[wasm_bindgen]
    impl Space {
        #[wasm_bindgen(js_name = "getName")]
        pub fn get_name(&self) -> SLabel {
            SLabel {
                inner: self.inner.name.clone(),
            }
        }

        #[wasm_bindgen(js_name = "getCovenant")]
        pub fn get_covenant(&self) -> Covenant {
            Covenant {
                inner: self.inner.covenant.clone(),
            }
        }
    }

    #[wasm_bindgen]
    impl Covenant {
        /// Returns "bid", "transfer", or "reserved" to indicate the variant.
        #[wasm_bindgen(js_name = "getKind")]
        pub fn get_kind(&self) -> String {
            match self.inner {
                NativeCovenant::Bid { .. } => "bid".into(),
                NativeCovenant::Transfer { .. } => "transfer".into(),
                NativeCovenant::Reserved => "reserved".into(),
            }
        }

        /// If this covenant is a Bid, returns the bid details.
        #[wasm_bindgen(js_name = "asBid")]
        pub fn as_bid(&self) -> Option<BidCovenant> {
            if let NativeCovenant::Bid {
                ref burn_increment,
                ref signature,
                ref total_burned,
                claim_height,
            } = self.inner
            {
                Some(BidCovenant {
                    burn_increment: burn_increment.to_sat(),
                    signature: signature.as_ref().to_vec(),
                    total_burned: total_burned.to_sat(),
                    claim_height,
                })
            } else {
                None
            }
        }

        /// If this covenant is a Transfer, returns the transfer details.
        #[wasm_bindgen(js_name = "asTransfer")]
        pub fn as_transfer(&self) -> Option<TransferCovenant> {
            if let NativeCovenant::Transfer {
                expire_height,
                ref data,
            } = self.inner
            {
                Some(TransferCovenant {
                    expire_height,
                    data: data.clone().map(|d| d.to_vec()),
                })
            } else {
                None
            }
        }
    }

    #[wasm_bindgen]
    impl BidCovenant {
        #[wasm_bindgen(js_name = "getBurnIncrement")]
        pub fn get_burn_increment(&self) -> u64 {
            self.burn_increment
        }

        #[wasm_bindgen(js_name = "getSignature")]
        pub fn get_signature(&self) -> Vec<u8> {
            self.signature.clone()
        }

        #[wasm_bindgen(js_name = "getTotalBurned")]
        pub fn total_burned(&self) -> u64 {
            self.total_burned
        }

        #[wasm_bindgen(js_name = "getClaimHeight")]
        pub fn claim_height(&self) -> Option<u32> {
            self.claim_height
        }
    }

    #[wasm_bindgen]
    impl TransferCovenant {
        #[wasm_bindgen(js_name = "getExpireHeight")]
        pub fn get_expire_height(&self) -> u32 {
            self.expire_height
        }

        #[wasm_bindgen(js_name = "getData")]
        pub fn get_data(&self) -> Option<Vec<u8>> {
            self.data.clone()
        }
    }

    #[wasm_bindgen]
    impl Veritas {
        /// Creates a new Veritas instance.
        #[wasm_bindgen(constructor)]
        pub fn new() -> Veritas {
            Veritas {
                inner: VeritasNative::new(),
            }
        }

        /// Adds an anchor.
        ///
        /// The provided `anchor` must be a 32‑byte array (passed as a Uint8Array).
        #[wasm_bindgen(js_name = "addAnchor")]
        pub fn add_anchor(&mut self, anchor: &[u8]) -> Result<(), JsValue> {
            let hash = read_hash(anchor)?;
            self.inner.add_anchor(hash);
            Ok(())
        }

        /// Verifies a proof.
        #[wasm_bindgen(js_name = "verifyProof")]
        pub fn verify_proof(&self, proof: &[u8]) -> Result<Proof, JsValue> {
            self.inner
                .verify_proof(proof)
                .map(|p| Proof { inner: p })
                .map_err(|e| error_to_jsvalue(e))
        }

        /// Verifies a message.
        #[wasm_bindgen(js_name = "verifyMessage")]
        pub fn verify_message(&self, utxo: &SpaceOut, msg: &[u8], signature: &[u8]) -> Result<(), JsValue> {
            self.inner
                .verify_message(&utxo.inner, msg, signature)
                .map_err(|e| error_to_jsvalue(e))
        }
    }

    #[wasm_bindgen]
    impl Proof {
        /// Returns the proof’s root hash.
        #[wasm_bindgen(js_name = "getRoot")]
        pub fn get_root(&self) -> Vec<u8> {
            self.inner.root.to_vec()
        }

        /// Checks whether a given key (a 32‑byte array) provably exists or not exists
        #[wasm_bindgen]
        pub fn contains(&self, key: &[u8]) -> Result<bool, JsValue> {
            let hash = read_hash(key)?;
            self.inner
                .contains(&hash)
                .map_err(|e| error_to_jsvalue(e))
        }

        #[wasm_bindgen(js_name = "findSpace")]
        pub fn find_space(&self, space_key: &[u8]) -> Result<Option<SpaceOut>, JsValue> {
            let hash = read_hash(space_key)?;
            Ok(
                self.inner.
                    find_space(&hash)
                    .map_err(|e| error_to_jsvalue(e))?
                    .map(|out| SpaceOut { inner: out})
            )
        }

        /// Returns all proof entries as an array of objects.
        #[wasm_bindgen]
        pub fn entries(&self) -> Result<JsValue, JsValue> {
            let entries = js_sys::Array::new();
            for (k, v) in self.inner.iter() {
                let entry = js_sys::Object::new();

                let key_array = js_sys::Uint8Array::from(k.as_ref());
                js_sys::Reflect::set(&entry, &JsValue::from_str("key"), &key_array.into())?;

                // Convert the value.
                let value_js = match v {
                    ValueNative::Outpoint(ref op) => {
                        JsValue::from_str(&op.to_string())
                    }
                    ValueNative::UTXO(ref utxo) => {
                        JsValue::from(SpaceOut {
                            inner: utxo.clone(),
                        })
                    }
                    ValueNative::Unknown(ref bytes) => {
                        JsValue::from(js_sys::Uint8Array::from(&bytes[..]))
                    }
                };
                js_sys::Reflect::set(&entry, &JsValue::from_str("value"), &value_js)?;
                entries.push(&entry);
            }
            Ok(entries.into())
        }
    }

    fn read_hash(hash: &[u8]) -> Result<[u8;32], JsValue> {
        if hash.len() != 32 {
            return Err(JsValue::from_str("hash must be 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hash);
        Ok(arr)
    }

    fn error_to_jsvalue(e: Error) -> JsValue {
        JsValue::from_str(&format!("{:?}", e))
    }
}
