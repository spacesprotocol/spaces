use std::collections::BTreeMap;
use borsh::{BorshDeserialize, BorshSerialize};
use spacedb::db::Database;
use spacedb::{Hash, NodeHasher, Sha256Hasher};
use spacedb::tx::{ReadTransaction, WriteTransaction};
use spaces_protocol::bitcoin::OutPoint;

pub mod spaces;
pub mod ptrs;
pub mod chain;

type SpaceDb = Database<Sha256Hasher>;
type ReadTx = ReadTransaction<Sha256Hasher>;
pub type WriteTx<'db> = WriteTransaction<'db, Sha256Hasher>;
type WriteMemory = BTreeMap<Hash, Option<Vec<u8>>>;

pub struct Sha256;


#[derive(BorshSerialize, BorshDeserialize)]
pub struct EncodableOutpoint(
    #[borsh(
        serialize_with = "borsh_utils::serialize_outpoint",
        deserialize_with = "borsh_utils::deserialize_outpoint"
    )]
    pub OutPoint
);

impl From<OutPoint> for EncodableOutpoint {
    fn from(value: OutPoint) -> Self {
        Self(value)
    }
}

impl From<EncodableOutpoint> for OutPoint {
    fn from(value: EncodableOutpoint) -> Self {
        value.0
    }
}

impl spaces_protocol::hasher::KeyHasher for Sha256 {
    fn hash(data: &[u8]) -> spaces_protocol::hasher::Hash {
        Sha256Hasher::hash(data)
    }
}
