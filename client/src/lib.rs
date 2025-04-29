extern crate core;

// needed for testutil
pub extern crate jsonrpsee;
pub extern crate log;

use std::time::{Duration, Instant};

use base64::Engine;
use serde::{Deserialize, Deserializer, Serializer};

mod checker;
pub mod client;
pub mod config;
pub mod format;
pub mod rpc;
pub mod source;
pub mod store;
pub mod spaces;
pub mod wallets;
mod cbf;

fn std_wait<F>(mut predicate: F, wait: Duration)
where
    F: FnMut() -> bool,
{
    let start = Instant::now();
    loop {
        if predicate() {
            break;
        }
        if start.elapsed() >= wait {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub fn serialize_base64<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if serializer.is_human_readable() {
        serializer.serialize_str(&base64::prelude::BASE64_STANDARD.encode(bytes))
    } else {
        serializer.serialize_bytes(bytes)
    }
}

pub fn deserialize_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        let s = String::deserialize(deserializer)?;
        base64::prelude::BASE64_STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)
    } else {
        Vec::<u8>::deserialize(deserializer)
    }
}

pub fn calc_progress(start_block: u32, tip: u32, chain_tip: u32) -> f32 {
    if chain_tip <= start_block || tip < start_block {
        0.0
    } else if tip >= chain_tip {
        1.0
    } else {
        let blocks_synced = tip - start_block;
        let blocks_to_sync = chain_tip - start_block;
        blocks_synced as f32 / blocks_to_sync as f32
    }
}
