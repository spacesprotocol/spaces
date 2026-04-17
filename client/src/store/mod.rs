use crate::store::chain::ROOT_ANCHORS_COUNT;
use borsh::{BorshDeserialize, BorshSerialize};
use spacedb::db::Database;
use spacedb::tx::{ReadTransaction, WriteTransaction};
use spacedb::{Configuration, Hash, NodeHasher, Sha256Hasher};
use spaces_protocol::bitcoin::OutPoint;
use std::collections::BTreeMap;
use std::path::PathBuf;

const DEFAULT_CACHE_SIZE: usize = 50 * 1024 * 1024; /* 50MB */

pub mod chain;
pub mod index;
pub mod ptrs;
pub mod spaces;

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
    pub OutPoint,
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

fn open_db(
    path_buf: PathBuf,
    auto_hash_index: bool,
    cache_size: Option<usize>,
) -> anyhow::Result<Database<Sha256Hasher>> {
    let config = Configuration::standard()
        .with_auto_hash_index(auto_hash_index)
        .with_hash_index_pruning(Some(ROOT_ANCHORS_COUNT as _))
        .with_cache_size(cache_size.unwrap_or(DEFAULT_CACHE_SIZE));

    Ok(Database::open_with_config(
        path_buf.to_str().unwrap(),
        config,
    )?)
}
