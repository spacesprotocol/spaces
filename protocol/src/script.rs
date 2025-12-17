use alloc::vec::Vec;

#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};
use bitcoin::{opcodes::all::OP_DROP, script, script::{Instruction, PushBytesBuf}, Script, ScriptBuf, TxOut};
use bitcoin::opcodes::all::{OP_PUSHNUM_1, OP_RETURN};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{hasher::{KeyHasher, SpaceKey}, prepare::SpacesSource, slabel::{SLabel, SLabelRef}, validate::RejectParams, Bytes, FullSpaceOut};

/// Ways that a script might fail. Not everything is split up as
/// much as it could be; patches welcome if more detailed errors
/// would help you.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(tag = "type", rename_all = "snake_case")
)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[non_exhaustive]
pub enum OpenError {
    MalformedName,
    ReservedName,
    Reject(RejectParams),
}

pub type OpenResult<T> = Result<T, OpenError>;

pub const OPEN_MAGIC: &[u8] = &[0xde, 0xde, 0xde, 0xde, 0x01];

#[derive(Clone, Debug)]
pub enum OpenContext {
    /// If OP_OPEN is attempting to initiate an auction for an existing Space,
    /// a reference for the previous space is included
    ExistingSpace(FullSpaceOut),

    /// A new Space we haven't seen before
    NewSpace(SLabel),
}

/// To set data associated with a space, we use:
/// OP_RETURN OP_PUSHNUM_1 <op push bytes> <data>
pub fn find_op_set_data(tx_outputs: &[TxOut]) -> Option<Bytes> {
    tx_outputs.iter().find_map(|s| {
        let mut instructions = s.script_pubkey.instructions().skip(1);
        match (instructions.next()?.ok()?, instructions.next()?.ok()?) {
            (Instruction::Op(OP_PUSHNUM_1), Instruction::PushBytes(bytes)) =>
                Some(Bytes::new(bytes.as_bytes().to_vec())),
            _ => None,
        }
    })
}

/// Create data OP_RETURN script for spaces/PTRs
/// Format: OP_RETURN OP_PUSHNUM_1 <data>
pub fn create_data_script(data: &[u8]) -> ScriptBuf {
    let mut buf = PushBytesBuf::new();
    buf.extend_from_slice(data).expect("valid");

    ScriptBuf::builder()
        .push_opcode(OP_RETURN)
        .push_opcode(OP_PUSHNUM_1)
        .push_slice(buf)
        .into_script()
}

pub fn create_open_data(name: SLabel) -> Vec<u8> {
    let name = name.as_ref();
    let mut data = Vec::with_capacity(OPEN_MAGIC.len() + name.len());
    data.extend(OPEN_MAGIC);
    data.extend(name);
    data
}

pub fn nop_script(space_script: Vec<u8>) -> script::Builder {
    script::Builder::new()
        .push_slice(
            PushBytesBuf::try_from(space_script)
                .expect("push bytes")
                .as_push_bytes(),
        )
        .push_opcode(OP_DROP)
}

pub fn load_open_context<T: SpacesSource, H: KeyHasher>(
    src: &mut T,
    script: &Script
) -> crate::errors::Result<Option<OpenResult<OpenContext>>> {
    let name = match find_open(script) {
        Some(Ok(name)) => name,
        Some(Err(e)) => return Ok(Some(Err(e))),
        None => return Ok(None),
    };
    if name.is_reserved() {
        return Ok(Some(Err(OpenError::ReservedName)));
    }

    let ctx = {
        let spacehash = SpaceKey::from(H::hash(name.as_ref()));
        let existing = src.get_space_outpoint(&spacehash)?;
        match existing {
            None => OpenContext::NewSpace(name.to_owned()),
            Some(outpoint) => OpenContext::ExistingSpace(FullSpaceOut {
                txid: outpoint.txid,
                spaceout: src.get_spaceout(&outpoint)?.expect("spaceout exists"),
            }),
        }
    };
    Ok(Some(Ok(ctx)))
}


fn find_open(script: &Script) -> Option<OpenResult<SLabelRef<'_>>> {
    // Find the first OP_PUSH bytes in a bitcoin script prefixed with our magic
    let mut open_bytes = None;
    for op in script.instructions() {
        if op.is_err() {
            return None;
        }
        match op.unwrap() {
            Instruction::Op(_) => continue,
            Instruction::PushBytes(push_bytes) => {
                let mut bytes = push_bytes.as_bytes();
                // Starts with our prefix + at least 1 additional op code byte
                if bytes.len() < OPEN_MAGIC.len() || !bytes.starts_with(OPEN_MAGIC) {
                    continue;
                }
                bytes = &bytes[OPEN_MAGIC.len()..];
                let name = SLabelRef::try_from(bytes)
                    .map_err(|_| OpenError::MalformedName);
                open_bytes = Some(name);
                break;
            }
        }
    }

    open_bytes
}


impl core::fmt::Display for OpenError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use OpenError::*;

        match *self {
            MalformedName => f.write_str("malformed name"),
            ReservedName => f.write_str("reserved name"),
            Reject(_) => f.write_str("rejected"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{collections::BTreeMap, format, string::ToString, vec::Vec};
    use core::str::FromStr;

    use bitcoin::{
        hashes::Hash as OtherHash, opcodes, script::PushBytesBuf, OutPoint, ScriptBuf, Txid,
    };

    use crate::{
        hasher::{Hash, KeyHasher, SpaceKey},
        prepare::SpacesSource,
        script::{create_open_data, load_open_context, OpenContext, OpenError, OPEN_MAGIC},
        slabel::SLabel,
        Covenant, FullSpaceOut, Space, SpaceOut,
    };

    pub struct DummySource {
        spaces: BTreeMap<SpaceKey, OutPoint>,
        spaceouts: BTreeMap<OutPoint, SpaceOut>,
    }
    impl DummySource {
        fn new() -> Self {
            let mut ds = Self {
                spaces: Default::default(),
                spaceouts: Default::default(),
            };

            for i in 0..20 {
                let name = format!("@test{}", i);
                ds.insert(FullSpaceOut {
                    txid: Txid::all_zeros(),
                    spaceout: SpaceOut {
                        n: i,
                        space: Some(Space {
                            name: SLabel::from_str(&name).unwrap(),
                            covenant: Covenant::Reserved,
                        }),
                        value: Default::default(),
                        script_pubkey: Default::default(),
                    },
                });
            }

            ds
        }

        fn insert(&mut self, space: FullSpaceOut) {
            let key = DummyHasher::hash(space.spaceout.space.as_ref().unwrap().name.as_ref());
            assert!(
                self.spaces
                    .insert(SpaceKey::from(key), space.outpoint())
                    .is_none(),
                "space already exists"
            );
            assert!(
                self.spaceouts
                    .insert(space.outpoint(), space.spaceout)
                    .is_none(),
                "outpoint already exists"
            );
        }
    }
    impl SpacesSource for DummySource {
        fn get_space_outpoint(
            &mut self,
            space_hash: &SpaceKey,
        ) -> crate::errors::Result<Option<OutPoint>> {
            Ok(self.spaces.get(space_hash).cloned())
        }
        fn get_spaceout(&mut self, outpoint: &OutPoint) -> crate::errors::Result<Option<SpaceOut>> {
            Ok(self.spaceouts.get(outpoint).cloned())
        }
    }

    pub struct DummyHasher;

    impl KeyHasher for DummyHasher {
        fn hash(data: &[u8]) -> Hash {
            let mut hash = [*data.last().unwrap(); 32];
            let len = data.len().min(32);
            hash[..len].copy_from_slice(&data[..len]);
            hash
        }
    }

    #[test]
    pub fn test_open_scripts() {
        let mut src = DummySource::new();

        let mut builder = ScriptBuf::new();

        // Doesn't matter just throwing some dummy script
        builder.push_slice(&[0u8; 32]);
        builder.push_opcode(opcodes::all::OP_CHECKSIG);

        // Should ignore magic without an opcode
        builder.push_slice(
            PushBytesBuf::try_from(OPEN_MAGIC.to_vec())
                .expect("push bytes")
                .as_push_bytes(),
        );

        // Valid script with correct magic
        let pancake_space = create_open_data(SLabel::from_str("@pancakes").unwrap());
        builder.push_slice(
            PushBytesBuf::try_from(pancake_space)
                .expect("push bytes")
                .as_push_bytes(),
        );
        builder.push_opcode(opcodes::all::OP_DROP);

        // Another script, ignored since it picks the first one it sees
        let example_space = create_open_data(SLabel::from_str("@example").unwrap());
        builder.push_slice(
            PushBytesBuf::try_from(example_space)
                .expect("push bytes")
                .as_push_bytes(),
        );
        builder.push_opcode(opcodes::all::OP_DROP);

        let ctx = load_open_context::<_, DummyHasher>(&mut src, &builder)
            .expect("no error")
            .expect("found open")
            .expect("valid open");

        match ctx {
            OpenContext::NewSpace(space) => assert_eq!(space.to_string(), "@pancakes"),
            _ => panic!("unexpected space type"),
        }

        // Test with existing space
        let mut builder2 = ScriptBuf::new();
        let test_space = create_open_data(SLabel::from_str("@test12").unwrap());
        builder2.push_slice(
            PushBytesBuf::try_from(test_space)
                .expect("push bytes")
                .as_push_bytes(),
        );
        builder2.push_opcode(opcodes::all::OP_DROP);

        let ctx = load_open_context::<_, DummyHasher>(&mut src, &builder2)
            .expect("no error")
            .expect("found open")
            .expect("valid open");

        match ctx {
            OpenContext::ExistingSpace(e) => {
                assert_eq!(
                    e.spaceout.space.as_ref().unwrap().name.to_string(),
                    "@test12"
                )
            }
            _ => panic!("unexpected space type"),
        }
    }

    #[test]
    fn test_open_malformed_name() {
        let mut src = DummySource::new();

        // Create an OPEN script with malformed name
        let bad_name = [200u8; 60];
        let mut space_script = Vec::with_capacity(OPEN_MAGIC.len() + bad_name.len());
        space_script.extend(OPEN_MAGIC);
        space_script.extend(bad_name);

        let mut builder3 = ScriptBuf::new();
        builder3.push_slice(
            PushBytesBuf::try_from(space_script)
                .expect("push bytes")
                .as_push_bytes(),
        );

        let res = load_open_context::<_, DummyHasher>(&mut src, &builder3)
            .expect("no error")
            .expect("found open");

        assert_eq!(res.err(), Some(OpenError::MalformedName));
    }

    // test_reserve removed - reserve functionality has been removed
}
