use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc::Receiver,
        Arc,
    },
    time::Duration,
};

use base64::Engine;
use bitcoin::{Block, BlockHash, Txid};
use hex::FromHexError;
use log::{error};
use protocol::constants::ChainAnchor;
use reqwest::StatusCode;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use threadpool::ThreadPool;
use tokio::time::Instant;
use wallet::{bitcoin, bitcoin::Transaction};

use crate::node::BlockSource;
use crate::std_wait;

const BITCOIN_RPC_IN_WARMUP: i32 = -28; // Client still warming up
const BITCOIN_RPC_CLIENT_NOT_CONNECTED: i32 = -9; // Bitcoin is not connected
const BITCOIN_RPC_CLIENT_IN_INITIAL_DOWNLOAD: i32 = -10; // Still downloading initial blocks

const RPC_PARSE_ERROR: i32 = -32700;

#[derive(Clone)]
pub struct BitcoinRpc {
    id: Arc<AtomicU64>,
    auth_token: Option<String>,
    url: String,
}

pub struct BlockFetcher {
    src: BitcoinBlockSource,
    job_id: Arc<AtomicUsize>,
    sender: std::sync::mpsc::SyncSender<BlockEvent>,
    num_workers: usize,
}

pub enum BlockEvent {
    Tip(ChainAnchor),
    Block(ChainAnchor, Block),
    Error(BlockFetchError),
}

pub enum BitcoinRpcAuth {
    UserPass(String, String),
    Cookie(String),
    None,
}

#[derive(Debug)]
pub enum BitcoinRpcError {
    Rpc(JsonRpcError),
    Transport(reqwest::Error),
    Other(String),
}

#[derive(Debug)]
pub enum BlockFetchError {
    RpcError(BitcoinRpcError),
    BlockMismatch,
    ChannelClosed,
}

impl fmt::Display for BlockFetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockFetchError::RpcError(e) => write!(f, "RPC error: {}", e),
            BlockFetchError::BlockMismatch => write!(f, "Block mismatch detected"),
            BlockFetchError::ChannelClosed => write!(f, "Channel closed"),
        }
    }
}

impl std::error::Error for BlockFetchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BlockFetchError::RpcError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<BitcoinRpcError> for BlockFetchError {
    fn from(err: BitcoinRpcError) -> Self {
        BlockFetchError::RpcError(err)
    }
}

#[derive(Serialize, Deserialize)]
pub struct JsonRpcResponse<T> {
    pub result: Option<T>,
    pub error: Option<JsonRpcError>,
    pub id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

pub struct BitcoinRpcRequest {
    id: u64,
    body: serde_json::Value,
}

trait ErrorForRpc {
    async fn error_for_rpc<T: DeserializeOwned>(self) -> Result<T, BitcoinRpcError>;
}

trait ErrorForRpcBlocking {
    fn error_for_rpc<T: DeserializeOwned>(self) -> Result<T, BitcoinRpcError>;
}

impl BitcoinRpc {
    pub fn new(url: &str, auth: BitcoinRpcAuth) -> Self {
        Self {
            id: Default::default(),
            auth_token: auth.to_token(),
            url: url.to_string(),
        }
    }

    pub fn make_request(&self, method: &str, params: serde_json::Value) -> BitcoinRpcRequest {
        let id = self.id.fetch_add(1, Ordering::Relaxed);
        let body = serde_json::json!({
            "jsonrpc": "1.0",
            "id": id.to_string(),
            "method": method,
            "params": params,
        });
        return BitcoinRpcRequest { id, body };
    }

    pub fn get_block_count(&self) -> BitcoinRpcRequest {
        let params = serde_json::json!([]);

        self.make_request("getblockcount", params)
    }

    pub fn get_block_header(&self, hash: &BlockHash) -> BitcoinRpcRequest {
        let params = serde_json::json!([hash]);
        self.make_request("getblockheader", params)
    }

    pub fn get_raw_transaction(&self, hash: &Txid, verbose: bool) -> BitcoinRpcRequest {
        let params = serde_json::json!([hash, verbose]);
        self.make_request("getrawtransaction", params)
    }

    pub fn get_block_hash(&self, height: u32) -> BitcoinRpcRequest {
        let params = serde_json::json!([height]);

        self.make_request("getblockhash", params)
    }

    pub fn get_block(&self, hash: &BlockHash) -> BitcoinRpcRequest {
        let params = serde_json::json!([hash, /* verbosity */ 0]);

        self.make_request("getblock", params)
    }

    pub fn get_blockchain_info(&self) -> BitcoinRpcRequest {
        let params = serde_json::json!([]);
        self.make_request("getblockchaininfo", params)
    }
    pub fn get_mempool_entry(&self, txid: &Txid) -> BitcoinRpcRequest {
        let params = serde_json::json!([txid]);

        self.make_request("getmempoolentry", params)
    }

    pub fn send_raw_transaction(&self, tx: &Transaction) -> BitcoinRpcRequest {
        let raw_hex = bitcoin::consensus::encode::serialize_hex(&tx);
        let params =
            serde_json::json!([raw_hex, /* max fee rate */ 0, /* max burn amount */ 21_000_000]);

        self.make_request("sendrawtransaction", params)
    }

    pub async fn send_json<T: DeserializeOwned>(
        &self,
        client: &reqwest::Client,
        request: &BitcoinRpcRequest,
    ) -> Result<T, BitcoinRpcError> {
        self.send_request(client, request)
            .await?
            .error_for_rpc()
            .await
    }

    pub fn send_json_blocking<T: DeserializeOwned>(
        &self,
        client: &reqwest::blocking::Client,
        request: &BitcoinRpcRequest,
    ) -> Result<T, BitcoinRpcError> {
        self.send_request_blocking(client, request)
            .and_then(|res| res.error_for_rpc())
    }

    pub fn broadcast_tx(
        &self,
        client: &reqwest::blocking::Client,
        tx: &Transaction,
    ) -> Result<u64, BitcoinRpcError> {
        let txid: String = self.send_json_blocking(client, &self.send_raw_transaction(tx))?;

        const MAX_RETRIES: usize = 10;
        let mut retry_count = 0;
        let mut last_error = None;
        while retry_count < MAX_RETRIES {
            let params = serde_json::json!([txid]);
            let res: Result<serde_json::Value, _> =
                self.send_json_blocking(client, &self.make_request("getmempoolentry", params));
            match res {
                Ok(mem) => {
                    if let Some(time) = mem.get("time").and_then(|t| t.as_u64()) {
                        return Ok(time);
                    }
                }
                Err(e) => last_error = Some(e),
            }
            std::thread::sleep(Duration::from_millis(100));
            retry_count += 1;
        }

        Err(last_error.expect("an error"))
    }

    async fn send_request(
        &self,
        client: &reqwest::Client,
        request: &BitcoinRpcRequest,
    ) -> Result<reqwest::Response, BitcoinRpcError> {
        let mut delay = Duration::from_millis(100);
        let max_retries = 5;
        let mut last_error = None;

        for attempt in 0..max_retries {
            let mut builder = client.post(&self.url);
            if let Some(auth) = self.auth_token.as_ref() {
                builder = builder.header("Authorization", format!("Basic {}", auth));
            }

            match builder
                .json(&request.body)
                .send()
                .await
                .map_err(BitcoinRpcError::from)
            {
                Ok(res) => return Self::clean_rpc_response(res).await,
                Err(e) if e.is_temporary() && attempt < max_retries - 1 => {
                    error!("Rpc: {} - retrying in {:?}...", e, delay);
                    last_error = Some(e.into());
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                }
                Err(e) => return Err(e),
            }
        }

        Err(last_error.expect("an error"))
    }

    fn send_request_blocking(
        &self,
        client: &reqwest::blocking::Client,
        request: &BitcoinRpcRequest,
    ) -> Result<reqwest::blocking::Response, BitcoinRpcError> {
        let mut delay = Duration::from_millis(100);
        let max_retries = 5;
        let mut last_error = None;

        for attempt in 0..max_retries {
            let mut builder = client.post(&self.url);
            if let Some(auth) = self.auth_token.as_ref() {
                builder = builder.header("Authorization", format!("Basic {}", auth));
            }

            match builder
                .json(&request.body)
                .send()
                .map_err(BitcoinRpcError::from)
            {
                Ok(res) => return Self::clean_rpc_response_blocking(res),
                Err(e) if e.is_temporary() && attempt < max_retries - 1 => {
                    error!("Rpc: {} - retrying in {:?}...", e, delay);
                    last_error = Some(e.into());
                    std::thread::sleep(delay);
                    delay *= 2;
                }
                Err(e) => return Err(e),
            }
        }

        Err(last_error.expect("an error"))
    }

    pub async fn clean_rpc_response(
        res: reqwest::Response,
    ) -> Result<reqwest::Response, BitcoinRpcError> {
        let status = res.status();
        if status.is_success() {
            return Ok(res);
        }
        let response_bytes = res.bytes().await.map_err(|e| {
            BitcoinRpcError::Rpc(JsonRpcError {
                code: RPC_PARSE_ERROR,
                message: format!("Failed to read response bytes: {}", e),
            })
        })?;
        Err(Self::parse_error_bytes(status, response_bytes.as_ref()))
    }

    pub fn clean_rpc_response_blocking(
        res: reqwest::blocking::Response,
    ) -> Result<reqwest::blocking::Response, BitcoinRpcError> {
        let status = res.status();
        if status.is_success() {
            return Ok(res);
        }
        let binding = res.bytes().map_err(|e| {
            BitcoinRpcError::Rpc(JsonRpcError {
                code: RPC_PARSE_ERROR,
                message: format!("Failed to read response bytes: {}", e),
            })
        })?;
        let response_bytes = binding.as_ref();
        Err(Self::parse_error_bytes(status, response_bytes))
    }

    fn parse_error_bytes(status: StatusCode, res_bytes: &[u8]) -> BitcoinRpcError {
        let parsed_response: Result<JsonRpcResponse<String>, serde_json::Error> =
            serde_json::from_slice(&res_bytes);

        match parsed_response {
            Ok(json) => {
                if let Some(rpc_error) = json.error {
                    BitcoinRpcError::Rpc(rpc_error)
                } else {
                    BitcoinRpcError::Rpc(JsonRpcError {
                        code: RPC_PARSE_ERROR,
                        message: format!(
                            "Unexpected JSON structure (HTTP code: {}): {:?}",
                            status, json.result
                        ),
                    })
                }
            }
            Err(_) => BitcoinRpcError::Rpc(JsonRpcError {
                code: RPC_PARSE_ERROR,
                message: format!(
                    "Received non-JSON response (HTTP code: {}): {}",
                    status,
                    String::from_utf8_lossy(res_bytes)
                ),
            }),
        }
    }
}

impl BitcoinRpcAuth {
    fn to_token(&self) -> Option<String> {
        match self {
            BitcoinRpcAuth::UserPass(user, pass) => {
                Some(base64::prelude::BASE64_STANDARD.encode(format!("{user}:{pass}")))
            }
            BitcoinRpcAuth::Cookie(cookie) => Some(cookie.clone()),
            BitcoinRpcAuth::None => None,
        }
    }
}

impl BlockFetcher {
    pub fn new(
        src: BitcoinBlockSource,
        num_workers: usize,
    ) -> (Self, std::sync::mpsc::Receiver<BlockEvent>) {
        let (tx, rx) = std::sync::mpsc::sync_channel(12);
        (
            Self {
                src,
                job_id: Arc::new(AtomicUsize::new(0)),
                sender: tx,
                num_workers,
            },
            rx,
        )
    }

    pub fn stop(&self) {
        self.job_id.fetch_add(1, Ordering::SeqCst);
    }

    fn should_sync(
        source: &BitcoinBlockSource,
        start: ChainAnchor,
    ) -> Result<Option<ChainAnchor>, BlockFetchError> {
        let tip = source.get_best_chain()?;
        if start.height > tip.height {
            return Err(BlockFetchError::BlockMismatch);
        }

        // Ensure start block is still in the best chain
        let start_hash: BlockHash = source.get_block_hash(start.height)?;
        if start.hash != start_hash {
            return Err(BlockFetchError::BlockMismatch);
        }

        // If the chain didn't advance and the hashes match, no rescan is needed
        if tip.height == start.height && tip.hash == start.hash {
            return Ok(None);
        }

        Ok(Some(tip))
    }

    pub fn restart(&self, checkpoint: ChainAnchor, drain_receiver: &Receiver<BlockEvent>) {
        self.stop();
        while drain_receiver.try_recv().is_ok() {}
        self.start(checkpoint)
    }

    pub fn start(&self, mut checkpoint: ChainAnchor) {
        self.stop();

        let job_id = self.job_id.load(Ordering::SeqCst);
        let task_src = self.src.clone();
        let current_task = self.job_id.clone();
        let task_sender = self.sender.clone();
        let num_workers = self.num_workers;

        _ = std::thread::spawn(move || {
            let mut last_check = Instant::now() - Duration::from_secs(2);

            loop {
                if current_task.load(Ordering::SeqCst) != job_id {
                    return;
                }
                if last_check.elapsed() < Duration::from_secs(1) {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                last_check = Instant::now();

                let tip = match BlockFetcher::should_sync(&task_src, checkpoint) {
                    Ok(t) => t,
                    Err(e) => {
                        _ = task_sender.send(BlockEvent::Error(e));
                        std_wait(|| current_task.load(Ordering::SeqCst) != job_id,
                                 Duration::from_secs(1));
                        continue;
                    }
                };

                if let Some(tip) = tip {
                    let res = Self::run_workers(
                        job_id,
                        current_task.clone(),
                        task_src.clone(),
                        task_sender.clone(),
                        checkpoint,
                        tip.height,
                        num_workers,
                    );

                    match res {
                        Ok(new_tip) => {
                            checkpoint = new_tip;
                        }
                        Err(e) if matches!(e, BlockFetchError::RpcError(_)) => {
                            _ = task_sender.send(BlockEvent::Error(e));
                            std_wait(|| current_task.load(Ordering::SeqCst) != job_id,
                                     Duration::from_secs(1));
                            continue;
                        }
                        Err(e) => {
                            _ = task_sender.send(BlockEvent::Error(e));
                            current_task.fetch_add(1, Ordering::SeqCst);
                            return;
                        }
                    }
                } else {
                    _ = task_sender.send(BlockEvent::Tip(checkpoint));
                }
            }
        });
    }

    fn run_workers(
        job_id: usize,
        current_job: Arc<AtomicUsize>,
        src: BitcoinBlockSource,
        sender: std::sync::mpsc::SyncSender<BlockEvent>,
        start_block: ChainAnchor,
        end_height: u32,
        num_workers: usize,
    ) -> Result<ChainAnchor, BlockFetchError> {
        let mut workers = Workers {
            current_job,
            job_id,
            out_of_order: Default::default(),
            last_emitted: start_block,
            queued_height: start_block.height + 1,
            end_height,
            ordered_sender: sender,
            src,
            num_workers,
            pool: ThreadPool::new(num_workers),
        };

        workers.run()
    }

    pub fn fetch_block(
        source: &BitcoinBlockSource,
        hash: &BlockHash,
    ) -> Result<Block, BitcoinRpcError> {
        let block_req = source.rpc.get_block(&hash);
        let id = block_req.id;
        let response = source
            .rpc
            .send_request_blocking(&source.client, &block_req)?;

        let mut raw = response.bytes()?.to_vec();

        let start_needle = "{\"result\":\"";
        let end_needle = format!("\",\"error\":null,\"id\":\"{}\"}}\n", id.to_string());

        // Check if we can quickly extract block
        let hex_block =
            if raw.starts_with(start_needle.as_bytes()) && raw.ends_with(end_needle.as_bytes()) {
                raw.drain(0..start_needle.len());
                raw.truncate(raw.len() - end_needle.len());
                raw
            } else {
                // fallback to decoding json
                let hex_block: JsonRpcResponse<String> = serde_json::from_slice(raw.as_slice())
                    .map_err(|e| BitcoinRpcError::Other(e.to_string()))?;
                if let Some(e) = hex_block.error {
                    return Err(BitcoinRpcError::Rpc(e));
                }
                hex_block.result.unwrap().into_bytes()
            };

        if hex_block.len() % 2 != 0 {
            return Err(BitcoinRpcError::Other(
                "Parse error: could not hex decode block".to_string(),
            ));
        }

        let raw_block = hex_to_bytes(hex_block).map_err(|e| {
            BitcoinRpcError::Other(format!("Hex deserialize error: {}", e.to_string()))
        })?;

        let block: Block =
            bitcoin::consensus::encode::deserialize(raw_block.as_slice()).map_err(|e| {
                BitcoinRpcError::Other(format!("Block Deserialize error: {}", e.to_string()))
            })?;
        Ok(block)
    }
}

struct Workers {
    current_job: Arc<AtomicUsize>,
    job_id: usize,
    out_of_order: BTreeMap<u32, (ChainAnchor, Block)>,
    last_emitted: ChainAnchor,
    queued_height: u32,
    end_height: u32,
    ordered_sender: std::sync::mpsc::SyncSender<BlockEvent>,
    src: BitcoinBlockSource,
    num_workers: usize,
    pool: ThreadPool,
}

type RpcBlockReceiver = Receiver<Result<(ChainAnchor, Block), BitcoinRpcError>>;

impl Workers {
    fn try_emit_next_block(
        &mut self,
        unordered: &RpcBlockReceiver,
    ) -> Result<bool, BlockFetchError> {
        while let Ok(unordered_block) = unordered.try_recv() {
            if self.should_stop() {
                return Err(BlockFetchError::ChannelClosed);
            }
            let (id, block) = unordered_block?;
            self.out_of_order.insert(id.height, (id, block));
        }

        let next = self.last_emitted.height + 1;
        if next > self.end_height {
            return Ok(false);
        }

        if let Some((id, block)) = self.out_of_order.remove(&next) {
            if self.should_stop() {
                return Err(BlockFetchError::ChannelClosed);
            }

            if block.header.prev_blockhash != self.last_emitted.hash {
                return Err(BlockFetchError::BlockMismatch);
            }

            self.last_emitted = id;
            self.ordered_sender
                .send(BlockEvent::Block(id.clone(), block))
                .map_err(|_| BlockFetchError::ChannelClosed)?;
            return Ok(true);
        }
        Ok(false)
    }

    #[inline(always)]
    fn can_add_workers(&self) -> bool {
        self.out_of_order.len() < self.num_workers
            && self.pool.queued_count() < self.num_workers
            && !self.queued_all()
    }

    #[inline(always)]
    fn queued_all(&self) -> bool {
        self.queued_height > self.end_height
    }

    fn run(&mut self) -> Result<ChainAnchor, BlockFetchError> {
        let (tx, rx) = std::sync::mpsc::sync_channel(self.num_workers);

        'queue_blocks: while !self.queued_all() {
            if self.should_stop() {
                return Err(BlockFetchError::ChannelClosed);
            }

            while self.can_add_workers() {
                if self.should_stop() {
                    return Err(BlockFetchError::ChannelClosed);
                }
                let tx = tx.clone();
                let rpc = self.src.clone();
                let task_sigterm = self.current_job.clone();
                let height = self.queued_height;
                let job_id = self.job_id;

                self.pool.execute(move || {
                    if task_sigterm.load(Ordering::SeqCst) != job_id {
                        return;
                    }
                    let result: Result<_, BitcoinRpcError> = (move || {
                        let hash: BlockHash = rpc.get_block_hash(height)?;
                        let block = BlockFetcher::fetch_block(&rpc, &hash)?;
                        Ok((ChainAnchor { height, hash }, block))
                    })();
                    _ = tx.send(result);
                });
                self.queued_height += 1;
            }

            // Emits any completed blocks while workers are processing
            while self.try_emit_next_block(&rx)? {
                // If pool has availability queue up more instead
                if self.can_add_workers() {
                    continue 'queue_blocks;
                }
            }

            std::thread::sleep(Duration::from_millis(1));
        }

        // Wait for all blocks to be processed
        while self.pool.active_count() > 0 || self.last_emitted.height != self.end_height {
            while self.try_emit_next_block(&rx)? {
                // do nothing
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(self.last_emitted)
    }

    #[inline(always)]
    fn should_stop(&self) -> bool {
        self.current_job.load(Ordering::SeqCst) != self.job_id
    }
}

// From hex crate
pub(crate) fn hex_to_bytes(mut hex_data: Vec<u8>) -> Result<Vec<u8>, FromHexError> {
    let len = hex_data.len() / 2;
    for i in 0..len {
        let byte = val(hex_data[2 * i], 2 * i)? << 4 | val(hex_data[2 * i + 1], 2 * i + 1)?;
        hex_data[i] = byte;
    }
    hex_data.truncate(len);
    Ok(hex_data)
}

// From hex crate
fn val(c: u8, idx: usize) -> Result<u8, FromHexError> {
    match c {
        b'A'..=b'F' => Ok(c - b'A' + 10),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'0'..=b'9' => Ok(c - b'0'),
        _ => Err(hex::FromHexError::InvalidHexCharacter {
            c: c as char,
            index: idx,
        }),
    }
}

impl BitcoinRpcError {
    fn is_temporary(&self) -> bool {
        match self {
            BitcoinRpcError::Transport(e) => {
                if e.is_timeout() || e.is_connect() {
                    return true;
                }
                if let Some(status) = e.status() {
                    match status {
                        StatusCode::REQUEST_TIMEOUT
                        | StatusCode::TOO_MANY_REQUESTS
                        | StatusCode::INTERNAL_SERVER_ERROR
                        | StatusCode::BAD_GATEWAY
                        | StatusCode::SERVICE_UNAVAILABLE
                        | StatusCode::GATEWAY_TIMEOUT => return true,
                        _ => {}
                    }
                }
                false
            }
            BitcoinRpcError::Rpc(e) => {
                matches!(
                    e.code,
                    BITCOIN_RPC_IN_WARMUP
                        | BITCOIN_RPC_CLIENT_IN_INITIAL_DOWNLOAD
                        | BITCOIN_RPC_CLIENT_NOT_CONNECTED
                )
            }
            _ => false,
        }
    }
}

impl From<reqwest::Error> for BitcoinRpcError {
    fn from(value: reqwest::Error) -> Self {
        Self::Transport(value)
    }
}

impl fmt::Display for BitcoinRpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BitcoinRpcError::Rpc(rpc_error) => {
                write!(f, "RPC: {}:{}", rpc_error.code, rpc_error.message)
            }
            BitcoinRpcError::Transport(transport_error) => {
                write!(f, "Transport: {}", transport_error)
            }
            BitcoinRpcError::Other(message) => write!(f, "{}", message),
        }
    }
}

impl std::error::Error for BitcoinRpcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BitcoinRpcError::Transport(e) => Some(e),
            _ => None,
        }
    }
}

impl ErrorForRpc for reqwest::Response {
    async fn error_for_rpc<T: DeserializeOwned>(self) -> Result<T, BitcoinRpcError> {
        let rpc_res: JsonRpcResponse<T> = self.json().await?;
        if let Some(e) = rpc_res.error {
            return Err(BitcoinRpcError::Rpc(e));
        }

        Ok(rpc_res.result.unwrap())
    }
}

impl ErrorForRpcBlocking for reqwest::blocking::Response {
    fn error_for_rpc<T: DeserializeOwned>(self) -> Result<T, BitcoinRpcError> {
        let rpc_res: JsonRpcResponse<T> = self.json()?;
        if let Some(e) = rpc_res.error {
            return Err(BitcoinRpcError::Rpc(e));
        }

        Ok(rpc_res.result.unwrap())
    }
}

#[derive(Clone)]
pub struct BitcoinBlockSource {
    pub client: reqwest::blocking::Client,
    pub rpc: BitcoinRpc,
}

impl BitcoinBlockSource {
    pub fn new(rpc: BitcoinRpc) -> Self {
        let client = reqwest::blocking::Client::new();
        Self { client, rpc }
    }
}

impl BlockSource for BitcoinBlockSource {
    fn get_block_hash(&self, height: u32) -> Result<BlockHash, BitcoinRpcError> {
        Ok(self
            .rpc
            .send_json_blocking(&self.client, &self.rpc.get_block_hash(height))?)
    }

    fn get_block(&self, hash: &BlockHash) -> Result<Block, BitcoinRpcError> {
        Ok(self
            .rpc
            .send_json_blocking(&self.client, &self.rpc.get_block(hash))?)
    }

    fn get_median_time(&self) -> Result<u64, BitcoinRpcError> {
        let info: serde_json::Value = self
            .rpc
            .send_json_blocking(&self.client, &self.rpc.get_blockchain_info())?;
        if let Some(time) = info.get("mediantime").and_then(|t| t.as_u64()) {
            return Ok(time);
        }
        Err(BitcoinRpcError::Other(
            "Could not fetch median time".to_string(),
        ))
    }

    fn in_mempool(&self, txid: &Txid, height: u32) -> Result<bool, BitcoinRpcError> {
        let result: Result<Value, _> = self
            .rpc
            .send_json_blocking(&self.client, &self.rpc.get_mempool_entry(txid));

        match result {
            Ok(_) => Ok(true),
            Err(error) => match error {
                BitcoinRpcError::Rpc(rpc) => {
                    let current_count = self.get_block_count()?;
                    if current_count != height as u64 {
                        // Report it as still in mempool since height changed during the check
                        return Ok(true);
                    }

                    if rpc.code == -5 && rpc.message.contains("not in mempool") {
                        return Ok(false);
                    }
                    Err(BitcoinRpcError::Rpc(rpc))
                }
                _ => Err(error),
            },
        }
    }

    fn get_block_count(&self) -> Result<u64, BitcoinRpcError> {
        Ok(self
            .rpc
            .send_json_blocking(&self.client, &self.rpc.get_block_count())?)
    }

    fn get_best_chain(&self) -> Result<ChainAnchor, BitcoinRpcError> {
        #[derive(Deserialize)]
        struct Info {
            #[serde(rename = "blocks")]
            height: u64,
            #[serde(rename = "bestblockhash")]
            hash: BlockHash,
        }
        let info: Info = self
            .rpc
            .send_json_blocking(&self.client, &self.rpc.get_blockchain_info())?;

        Ok(ChainAnchor {
            hash: info.hash,
            height: info.height as _,
        })
    }
}
