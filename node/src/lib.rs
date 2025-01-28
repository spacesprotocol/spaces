extern crate core;

// needed for testutil
pub extern crate jsonrpsee;
pub extern crate log;

use std::time::{Duration, Instant};

mod checker;
pub mod config;
pub mod node;
pub mod rpc;
pub mod source;
pub mod store;
pub mod sync;
pub mod wallets;
pub mod format;

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
