use anyhow::{Result, anyhow};
use borsh::BorshDeserialize;
use rusqlite::{Connection, params};
use spaces_nums::num_id::NumId;
use spaces_nums::snumeric::SNumeric;
use spaces_protocol::bitcoin::BlockHash;
use std::path::Path;
use std::sync::{Mutex, RwLock};

use crate::client::{BlockMeta, NumBlockMeta};

pub struct SqliteIndex {
    conn: Mutex<Connection>,
    staged: RwLock<Staged>,
}

#[derive(Default)]
struct Staged {
    spaces_blocks: Vec<(BlockHash, u32, BlockMeta)>,
    nums_blocks: Vec<(BlockHash, u32, NumBlockMeta)>,
    snumeric: Vec<(u32, u16, u16, NumId)>,
}

impl Staged {
    fn clear(&mut self) {
        self.spaces_blocks.clear();
        self.nums_blocks.clear();
        self.snumeric.clear();
    }
}

impl SqliteIndex {
    pub fn open(dir: &Path) -> Result<Self> {
        let path = dir.join("index.sqlite");
        let conn = Connection::open(path)?;

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;

             CREATE TABLE IF NOT EXISTS spaces_blocks (
                 block_height INTEGER NOT NULL,
                 block_hash BLOB NOT NULL UNIQUE,
                 data BLOB NOT NULL
             );

             CREATE TABLE IF NOT EXISTS nums_blocks (
                 block_height INTEGER NOT NULL,
                 block_hash BLOB NOT NULL UNIQUE,
                 data BLOB NOT NULL
             );

             CREATE TABLE IF NOT EXISTS snumeric (
                 block_height INTEGER NOT NULL,
                 tx_pos INTEGER NOT NULL,
                 vout INTEGER NOT NULL,
                 num_id BLOB NOT NULL,
                 PRIMARY KEY (block_height, tx_pos, vout)
             ) WITHOUT ROWID;",
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
            staged: RwLock::new(Staged::default()),
        })
    }

    // --- Spaces block index ---

    pub fn insert_spaces_block(&self, hash: BlockHash, height: u32, meta: BlockMeta) {
        self.staged
            .write()
            .unwrap()
            .spaces_blocks
            .push((hash, height, meta));
    }

    pub fn get_spaces_block(&self, hash: &BlockHash) -> Result<Option<BlockMeta>> {
        // Check staged first
        {
            let staged = self.staged.read().unwrap();
            for (h, _, meta) in staged.spaces_blocks.iter().rev() {
                if h == hash {
                    return Ok(Some(meta.clone()));
                }
            }
        }
        // Fall back to sqlite
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare_cached("SELECT data FROM spaces_blocks WHERE block_hash = ?1")?;
        let result = stmt.query_row(params![<BlockHash as AsRef<[u8]>>::as_ref(hash)], |row| {
            let data: Vec<u8> = row.get(0)?;
            Ok(data)
        });
        match result {
            Ok(data) => Ok(Some(
                BlockMeta::try_from_slice(&data)
                    .map_err(|e| anyhow!("deserialize BlockMeta: {}", e))?,
            )),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    // --- Nums block index ---

    pub fn insert_nums_block(&self, hash: BlockHash, height: u32, meta: NumBlockMeta) {
        self.staged
            .write()
            .unwrap()
            .nums_blocks
            .push((hash, height, meta));
    }

    pub fn get_nums_block(&self, hash: &BlockHash) -> Result<Option<NumBlockMeta>> {
        // Check staged first
        {
            let staged = self.staged.read().unwrap();
            for (h, _, meta) in staged.nums_blocks.iter().rev() {
                if h == hash {
                    return Ok(Some(meta.clone()));
                }
            }
        }
        // Fall back to sqlite
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached("SELECT data FROM nums_blocks WHERE block_hash = ?1")?;
        let result = stmt.query_row(params![<BlockHash as AsRef<[u8]>>::as_ref(hash)], |row| {
            let data: Vec<u8> = row.get(0)?;
            Ok(data)
        });
        match result {
            Ok(data) => Ok(Some(
                NumBlockMeta::try_from_slice(&data)
                    .map_err(|e| anyhow!("deserialize NumBlockMeta: {}", e))?,
            )),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    // --- SNumeric index ---

    pub fn insert_snumeric(&self, snum: &SNumeric, id: NumId) {
        self.staged
            .write()
            .unwrap()
            .snumeric
            .push((snum.block(), snum.tx_pos(), snum.vout(), id));
    }

    pub fn get_snumeric(&self, snum: &SNumeric) -> Result<Option<NumId>> {
        let block = snum.block();
        let tx_pos = snum.tx_pos();
        let vout = snum.vout();

        // Check staged first
        {
            let staged = self.staged.read().unwrap();
            for &(b, t, v, ref id) in staged.snumeric.iter().rev() {
                if b == block && t == tx_pos && v == vout {
                    return Ok(Some(*id));
                }
            }
        }
        // Fall back to sqlite
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached(
            "SELECT num_id FROM snumeric WHERE block_height = ?1 AND tx_pos = ?2 AND vout = ?3",
        )?;
        let result = stmt.query_row(params![block, tx_pos as u32, vout as u32], |row| {
            let data: Vec<u8> = row.get(0)?;
            Ok(data)
        });
        match result {
            Ok(data) => {
                if data.len() != 32 {
                    return Err(anyhow!("invalid NumId length: {}", data.len()));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&data);
                Ok(Some(NumId::from_bytes(arr)))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    // --- Commit / Restore ---

    pub fn commit(&self) -> Result<()> {
        let mut staged = self.staged.write().unwrap();
        let conn = self.conn.lock().unwrap();

        conn.execute_batch("BEGIN")?;

        {
            let mut stmt = conn.prepare_cached(
                "INSERT OR REPLACE INTO spaces_blocks (block_height, block_hash, data) VALUES (?1, ?2, ?3)",
            )?;
            for (hash, height, meta) in staged.spaces_blocks.drain(..) {
                let data = borsh::to_vec(&meta)?;
                stmt.execute(params![
                    height,
                    <BlockHash as AsRef<[u8]>>::as_ref(&hash),
                    data
                ])?;
            }
        }

        {
            let mut stmt = conn.prepare_cached(
                "INSERT OR REPLACE INTO nums_blocks (block_height, block_hash, data) VALUES (?1, ?2, ?3)",
            )?;
            for (hash, height, meta) in staged.nums_blocks.drain(..) {
                let data = borsh::to_vec(&meta)?;
                stmt.execute(params![
                    height,
                    <BlockHash as AsRef<[u8]>>::as_ref(&hash),
                    data
                ])?;
            }
        }

        {
            let mut stmt = conn.prepare_cached(
                "INSERT OR REPLACE INTO snumeric (block_height, tx_pos, vout, num_id) VALUES (?1, ?2, ?3, ?4)",
            )?;
            for (block_height, tx_pos, vout, id) in staged.snumeric.drain(..) {
                stmt.execute(params![
                    block_height,
                    tx_pos as u32,
                    vout as u32,
                    id.as_slice()
                ])?;
            }
        }

        conn.execute_batch("COMMIT")?;
        Ok(())
    }

    pub fn restore(&self, to_height: u32) -> Result<()> {
        self.staged.write().unwrap().clear();

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM spaces_blocks WHERE block_height > ?1",
            params![to_height],
        )?;
        conn.execute(
            "DELETE FROM nums_blocks WHERE block_height > ?1",
            params![to_height],
        )?;
        conn.execute(
            "DELETE FROM snumeric WHERE block_height > ?1",
            params![to_height],
        )?;
        Ok(())
    }
}
