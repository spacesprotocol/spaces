//! Borsh serialization utilities for bitcoin types.
//!
//! This crate provides helper functions for serializing and deserializing
//! bitcoin types using the borsh serialization format.

#![no_std]

extern crate alloc;

use alloc::vec;
use bitcoin::hashes::Hash;
use bitcoin::{secp256k1::schnorr, Amount, BlockHash, OutPoint, ScriptBuf, Txid};
use borsh::{io, BorshDeserialize, BorshSerialize};

/// Serialize a Txid
pub fn serialize_txid<W: io::Write>(txid: &Txid, writer: &mut W) -> io::Result<()> {
    writer.write_all(txid.as_ref())
}

/// Deserialize a Txid
pub fn deserialize_txid<R: io::Read>(reader: &mut R) -> io::Result<Txid> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Ok(Txid::from_byte_array(bytes))
}

/// Serialize an Amount (as satoshis)
pub fn serialize_amount<W: io::Write>(amount: &Amount, writer: &mut W) -> io::Result<()> {
    writer.write_all(&amount.to_sat().to_le_bytes())
}

/// Deserialize an Amount (from satoshis)
pub fn deserialize_amount<R: io::Read>(reader: &mut R) -> io::Result<Amount> {
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes)?;
    Ok(Amount::from_sat(u64::from_le_bytes(bytes)))
}

/// Serialize a ScriptBuf
pub fn serialize_script<W: io::Write>(script: &ScriptBuf, writer: &mut W) -> io::Result<()> {
    let bytes = script.as_bytes();
    (bytes.len() as u32).serialize(writer)?;
    writer.write_all(bytes)
}

/// Deserialize a ScriptBuf
pub fn deserialize_script<R: io::Read>(reader: &mut R) -> io::Result<ScriptBuf> {
    let len: u32 = BorshDeserialize::deserialize_reader(reader)?;
    let mut bytes = vec![0u8; len as usize];
    reader.read_exact(&mut bytes)?;
    Ok(ScriptBuf::from_bytes(bytes))
}

/// Serialize a Schnorr signature
pub fn serialize_signature<W: io::Write>(
    sig: &schnorr::Signature,
    writer: &mut W,
) -> io::Result<()> {
    writer.write_all(sig.as_ref())
}

/// Deserialize a Schnorr signature
pub fn deserialize_signature<R: io::Read>(reader: &mut R) -> io::Result<schnorr::Signature> {
    let mut bytes = [0u8; 64];
    reader.read_exact(&mut bytes)?;
    schnorr::Signature::from_slice(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid schnorr signature"))
}

/// Serialize an OutPoint
pub fn serialize_outpoint<W: io::Write>(outpoint: &OutPoint, writer: &mut W) -> io::Result<()> {
    serialize_txid(&outpoint.txid, writer)?;
    writer.write_all(&outpoint.vout.to_le_bytes())
}

/// Deserialize an OutPoint
pub fn deserialize_outpoint<R: io::Read>(reader: &mut R) -> io::Result<OutPoint> {
    let txid = deserialize_txid(reader)?;
    let mut vout_bytes = [0u8; 4];
    reader.read_exact(&mut vout_bytes)?;
    Ok(OutPoint {
        txid,
        vout: u32::from_le_bytes(vout_bytes),
    })
}

/// Serialize a BlockHash
pub fn serialize_block_hash<W: io::Write>(hash: &BlockHash, writer: &mut W) -> io::Result<()> {
    writer.write_all(&hash.to_byte_array())
}

/// Deserialize a BlockHash
pub fn deserialize_block_hash<R: io::Read>(reader: &mut R) -> io::Result<BlockHash> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Ok(BlockHash::from_byte_array(bytes))
}
