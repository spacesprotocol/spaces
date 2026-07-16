use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use anyhow::Result;
use spaces_protocol::bitcoin::Txid;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use reqwest::Client as HttpClient;

const CALLBACK_PERSISTENCE_VERSION: u32 = 1;

/// On-disk format for [`CallbackRegistry`] (reverse index is rebuilt on load).
#[derive(Debug, Serialize, Deserialize)]
struct CallbackPersistence {
    version: u32,
    clients: Vec<CallbackClient>,
}

/// Represents a registered callback client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackClient {
    /// Unique identifier for this client
    pub client_id: String,
    /// URL endpoint to call when a watched transaction is found
    pub callback_url: String,
    /// Set of transaction IDs this client is watching for
    pub watched_txids: HashSet<Txid>,
    /// Timestamp when this client was registered
    pub registered_at: u64,
}

/// Notification payload sent to callback URLs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionNotification {
    /// The transaction ID that was found
    pub txid: Txid,
    /// Block height where the transaction was included
    pub block_height: u32,
    /// Block hash where the transaction was included
    pub block_hash: String,
    /// Number of confirmations (1 for the block it was included in)
    pub confirmations: u32,
    /// Current chain tip height
    pub chain_tip_height: u32,
    /// Timestamp when the notification was sent
    pub notified_at: u64,
}

/// Registry for managing transaction callbacks
#[derive(Clone)]
pub struct CallbackRegistry {
    /// Map from client_id to CallbackClient
    clients: Arc<RwLock<HashMap<String, CallbackClient>>>,
    /// Reverse map from txid to set of client_ids watching it
    txid_to_clients: Arc<RwLock<HashMap<Txid, HashSet<String>>>>,
    /// HTTP client for making callback requests
    http_client: Arc<HttpClient>,
    /// When set, registry state is saved here after each mutation (atomic replace).
    persist_path: Option<PathBuf>,
}

impl CallbackRegistry {
    pub fn new() -> Self {
        Self {
            clients: Arc::new(RwLock::new(HashMap::new())),
            txid_to_clients: Arc::new(RwLock::new(HashMap::new())),
            http_client: Arc::new(HttpClient::new()),
            persist_path: None,
        }
    }

    /// Load saved registrations from `path` if it exists, otherwise start empty. State is re-saved after each change.
    pub async fn load_or_new(path: PathBuf) -> Result<Self> {
        let registry = Self {
            clients: Arc::new(RwLock::new(HashMap::new())),
            txid_to_clients: Arc::new(RwLock::new(HashMap::new())),
            http_client: Arc::new(HttpClient::new()),
            persist_path: Some(path.clone()),
        };

        if path.exists() {
            let bytes = tokio::fs::read(&path).await?;
            let file: CallbackPersistence = serde_json::from_slice(&bytes)?;
            if file.version != CALLBACK_PERSISTENCE_VERSION {
                anyhow::bail!(
                    "unsupported tx callback persistence version {} (expected {})",
                    file.version,
                    CALLBACK_PERSISTENCE_VERSION
                );
            }
            let mut clients: HashMap<String, CallbackClient> = HashMap::new();
            for client in file.clients {
                let cid = client.client_id.clone();
                clients.insert(cid, client);
            }
            let n = clients.len();
            let txid_map = Self::rebuild_txid_index(&clients);
            *registry.clients.write().await = clients;
            *registry.txid_to_clients.write().await = txid_map;
            info!(
                "txcallback: restored {} registered client(s) from {}",
                n,
                path.display()
            );
        }

        Ok(registry)
    }

    fn rebuild_txid_index(
        clients: &HashMap<String, CallbackClient>,
    ) -> HashMap<Txid, HashSet<String>> {
        let mut txid_map: HashMap<Txid, HashSet<String>> = HashMap::new();
        for (cid, client) in clients {
            for txid in &client.watched_txids {
                txid_map
                    .entry(*txid)
                    .or_insert_with(HashSet::new)
                    .insert(cid.clone());
            }
        }
        txid_map
    }

    async fn persist_to_disk(&self) {
        let Some(path) = self.persist_path.as_ref() else {
            return;
        };

        let clients_vec: Vec<CallbackClient> = {
            let guard = self.clients.read().await;
            guard.values().cloned().collect()
        };

        let payload = CallbackPersistence {
            version: CALLBACK_PERSISTENCE_VERSION,
            clients: clients_vec,
        };

        let data = match serde_json::to_vec_pretty(&payload) {
            Ok(d) => d,
            Err(e) => {
                error!("txcallback: failed to serialize persistence: {}", e);
                return;
            }
        };

        if let Some(parent) = path.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                error!(
                    "txcallback: create_dir_all {}: {}",
                    parent.display(),
                    e
                );
                return;
            }
        }

        let tmp_path = path.with_extension("tmp");
        if let Err(e) = tokio::fs::write(&tmp_path, &data).await {
            error!(
                "txcallback: write {}: {}",
                tmp_path.display(),
                e
            );
            return;
        }

        if let Err(e) = tokio::fs::rename(&tmp_path, path).await {
            error!("txcallback: rename {} -> {}: {}", tmp_path.display(), path.display(), e);
            let _ = tokio::fs::remove_file(&tmp_path).await;
        }
    }

    /// Register a new callback client
    pub async fn register_client(
        &self,
        client_id: String,
        callback_url: String,
    ) -> Result<()> {
        let mut clients = self.clients.write().await;
        let mut txid_map = self.txid_to_clients.write().await;

        // If client already exists, remove old watched txids from reverse map
        if let Some(old_client) = clients.get(&client_id) {
            info!(
                "txcallback: re-registering client '{}' (url: {} -> {}), clearing {} watched txid(s)",
                client_id,
                old_client.callback_url,
                callback_url,
                old_client.watched_txids.len()
            );
            for txid in &old_client.watched_txids {
                if let Some(client_set) = txid_map.get_mut(txid) {
                    client_set.remove(&client_id);
                    if client_set.is_empty() {
                        txid_map.remove(txid);
                    }
                }
            }
        } else {
            info!(
                "txcallback: registering new client '{}' with callback url '{}'",
                client_id, callback_url
            );
        }

        let client = CallbackClient {
            client_id: client_id.clone(),
            callback_url,
            watched_txids: HashSet::new(),
            registered_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        clients.insert(client_id, client);
        drop(clients);
        drop(txid_map);
        self.persist_to_disk().await;
        Ok(())
    }

    /// Unregister a callback client
    pub async fn unregister_client(&self, client_id: &str) -> Result<bool> {
        let mut clients = self.clients.write().await;
        let mut txid_map = self.txid_to_clients.write().await;

        if let Some(client) = clients.remove(client_id) {
            info!(
                "txcallback: unregistered client '{}' (url: '{}', had {} watched txid(s))",
                client_id,
                client.callback_url,
                client.watched_txids.len()
            );
            // Remove all watched txids from reverse map
            for txid in &client.watched_txids {
                if let Some(client_set) = txid_map.get_mut(txid) {
                    client_set.remove(client_id);
                    if client_set.is_empty() {
                        txid_map.remove(txid);
                    }
                }
            }
            drop(clients);
            drop(txid_map);
            self.persist_to_disk().await;
            Ok(true)
        } else {
            info!("txcallback: unregister requested for unknown client '{}'", client_id);
            Ok(false)
        }
    }

    /// Update the list of watched transaction IDs for a client
    pub async fn update_watched_txids(
        &self,
        client_id: &str,
        txids: Vec<Txid>,
    ) -> Result<bool> {
        let mut clients = self.clients.write().await;
        let mut txid_map = self.txid_to_clients.write().await;

        if let Some(client) = clients.get_mut(client_id) {
            let prev_count = client.watched_txids.len();

            // Remove old txids from reverse map
            for txid in &client.watched_txids {
                if let Some(client_set) = txid_map.get_mut(txid) {
                    client_set.remove(client_id);
                    if client_set.is_empty() {
                        txid_map.remove(txid);
                    }
                }
            }

            // Update client's watched txids
            let new_txids: HashSet<Txid> = txids.into_iter().collect();
            let new_count = new_txids.len();
            client.watched_txids = new_txids.clone();

            // Add new txids to reverse map
            for txid in &new_txids {
                txid_map
                    .entry(*txid)
                    .or_insert_with(HashSet::new)
                    .insert(client_id.to_string());
            }

            let tx_list = new_txids
                .iter()
                .map(|t| t.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            if tx_list.is_empty() {
                info!(
                    "txcallback: updated watches for client '{}': {} -> {} txid(s) (none)",
                    client_id, prev_count, new_count
                );
            } else {
                info!(
                    "txcallback: updated watches for client '{}': {} -> {} txid(s): {}",
                    client_id, prev_count, new_count, tx_list
                );
            }
            drop(clients);
            drop(txid_map);
            self.persist_to_disk().await;
            Ok(true)
        } else {
            info!(
                "txcallback: updatetxwatches for unknown client '{}'",
                client_id
            );
            Ok(false)
        }
    }

    /// Get information about a registered client
    pub async fn get_client(&self, client_id: &str) -> Option<CallbackClient> {
        let clients = self.clients.read().await;
        clients.get(client_id).cloned()
    }

    /// List all registered clients
    pub async fn list_clients(&self) -> Vec<CallbackClient> {
        let clients = self.clients.read().await;
        clients.values().cloned().collect()
    }

    /// Check if any watched transactions are in a block and notify clients
    pub async fn check_and_notify(
        &self,
        block_height: u32,
        block_hash: &str,
        block_txids: &[Txid],
        chain_tip_height: u32,
    ) {
        let txid_map = self.txid_to_clients.read().await;
        let clients = self.clients.read().await;

        if !txid_map.is_empty() {
            info!(
                "txcallback: scanning block {} ({} txs) against {} watched txid(s) across {} client(s)",
                block_height,
                block_txids.len(),
                txid_map.len(),
                clients.len()
            );
        }

        let mut notifications = Vec::new();

        // Find which clients need to be notified
        for txid in block_txids {
            if let Some(client_ids) = txid_map.get(txid) {
                for client_id in client_ids {
                    if let Some(client) = clients.get(client_id) {
                        info!(
                            "txcallback: watched txid {} found in block {} — queuing notification for client '{}'",
                            txid, block_height, client_id
                        );
                        let confirmations = chain_tip_height.saturating_sub(block_height) + 1;
                        notifications.push((
                            client.clone(),
                            TransactionNotification {
                                txid: *txid,
                                block_height,
                                block_hash: block_hash.to_string(),
                                confirmations,
                                chain_tip_height,
                                notified_at: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                            },
                        ));
                    }
                }
            }
        }

        // Send notifications asynchronously
        for (client, notification) in notifications {
            let http_client = self.http_client.clone();
            let callback_url = client.callback_url.clone();
            let client_id = client.client_id.clone();

            tokio::spawn(async move {
                match http_client
                    .post(&callback_url)
                    .json(&notification)
                    .send()
                    .await
                {
                    Ok(response) => {
                        if response.status().is_success() {
                            info!(
                                "Successfully notified client {} about txid {} at block {}",
                                client_id, notification.txid, block_height
                            );
                        } else {
                            warn!(
                                "Callback to {} returned status {} for txid {}",
                                callback_url,
                                response.status(),
                                notification.txid
                            );
                        }
                    }
                    Err(e) => {
                        error!(
                            "Failed to send callback to {} for txid {}: {}",
                            callback_url, notification.txid, e
                        );
                    }
                }
            });
        }
    }
}

impl Default for CallbackRegistry {
    fn default() -> Self {
        Self::new()
    }
}
