use std::{
    fmt::Display,
    fs,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use anyhow::anyhow;
use clap::{ArgGroup, Parser, ValueEnum};
use directories::ProjectDirs;
use jsonrpsee::core::Serialize;
use log::error;
use rand::{
    distributions::Alphanumeric,
    {thread_rng, Rng},
};
use serde::Deserialize;
use spaces_protocol::{bitcoin::Network, constants::ChainAnchor};

use crate::{
    auth::{auth_token_from_cookie, auth_token_from_creds},
    source::{BitcoinRpc, BitcoinRpcAuth},
    spaces::Spaced,
    store::{LiveStore, Store},
};

const RPC_OPTIONS: &str = "RPC Server Options";

/// Spaces protocol Bitcoin Daemon
#[derive(Parser, Debug, Serialize, Deserialize)]
#[clap(group(
    ArgGroup::new("bitcoin_rpc_auth")
    .required(false)
    .multiple(false)
    .args(&["bitcoin_rpc_cookie","bitcoin_rpc_user"])
))]
#[command(args_override_self = true, author, version, about, long_about = None)]
pub struct Args {
    #[arg(long, env = "SPACED_BLOCK_INDEX", default_value = "false")]
    block_index: bool,
    #[arg(long, env = "SPACED_DATA_DIR")]
    data_dir: Option<PathBuf>,
    /// Network to use
    #[arg(long, env = "SPACED_CHAIN", default_value = "mainnet")]
    chain: ExtendedNetwork,
    /// Number of concurrent workers allowed during syncing
    #[arg(short, long, env = "SPACED_JOBS", default_value = "8")]
    jobs: u8,
    /// Bitcoin RPC URL
    #[arg(long, env = "SPACED_BITCOIN_RPC_URL")]
    bitcoin_rpc_url: Option<String>,
    /// Bitcoin RPC cookie file path
    #[arg(long, env = "SPACED_BITCOIN_RPC_COOKIE")]
    bitcoin_rpc_cookie: Option<PathBuf>,
    /// Bitcoin RPC user
    #[arg(
        long,
        requires = "bitcoin_rpc_password",
        env = "SPACED_BITCOIN_RPC_USER"
    )]
    bitcoin_rpc_user: Option<String>,
    /// Bitcoin RPC password
    #[arg(long, env = "SPACED_BITCOIN_RPC_PASSWORD")]
    bitcoin_rpc_password: Option<String>,
    /// Spaced RPC user
    #[arg(long, requires = "rpc_password", env = "SPACED_RPC_USER")]
    rpc_user: Option<String>,
    /// Spaced RPC password
    #[arg(long, env = "SPACED_RPC_PASSWORD")]
    rpc_password: Option<String>,
    /// Bind to given address to listen for JSON-RPC connections.
    /// This option can be specified multiple times (default: 127.0.0.1 and ::1 i.e., localhost)
    #[arg(long, help_heading = Some(RPC_OPTIONS), default_values = ["127.0.0.1", "::1"], env = "SPACED_RPC_BIND")]
    rpc_bind: Vec<String>,
    /// Listen for JSON-RPC connections on <port>
    #[arg(long, help_heading = Some(RPC_OPTIONS), env = "SPACED_RPC_PORT")]
    rpc_port: Option<u16>,
    /// Index blocks including the full transaction data
    #[arg(long, env = "SPACED_BLOCK_INDEX_FULL", default_value = "false")]
    block_index_full: bool,
    /// Skip maintaining historical root anchors
    #[arg(long, env = "SPACED_SKIP_ANCHORS", default_value = "false")]
    skip_anchors: bool,
    /// The specified Bitcoin RPC is a light client
    #[arg(long, env = "SPACED_BITCOIN_RPC_LIGHT", default_value = "false")]
    bitcoin_rpc_light: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtendedNetwork {
    Mainnet,
    Testnet,
    Testnet4,
    Signet,
    Regtest,
}

impl ExtendedNetwork {
    pub fn fallback_network(&self) -> Network {
        match self {
            ExtendedNetwork::Mainnet => Network::Bitcoin,
            ExtendedNetwork::Testnet => Network::Testnet,
            ExtendedNetwork::Signet => Network::Signet,
            ExtendedNetwork::Regtest => Network::Regtest,
            ExtendedNetwork::Testnet4 => Network::Testnet,
        }
    }

    pub fn from_core_arg(arg: &str) -> Result<Self, ()> {
        match arg.to_lowercase().as_str() {
            "main" => Ok(ExtendedNetwork::Mainnet),
            "test" => Ok(ExtendedNetwork::Testnet),
            "testnet4" => Ok(ExtendedNetwork::Testnet4),
            "signet" => Ok(ExtendedNetwork::Signet),
            "regtest" => Ok(ExtendedNetwork::Regtest),
            _ => Err(()),
        }
    }

    pub fn genesis(&self) -> ChainAnchor {
        match self {
            ExtendedNetwork::Testnet => ChainAnchor::TESTNET(),
            ExtendedNetwork::Testnet4 => ChainAnchor::TESTNET4(),
            ExtendedNetwork::Regtest => ChainAnchor::REGTEST(),
            ExtendedNetwork::Mainnet => ChainAnchor::MAINNET(),
            _ => panic!("unsupported network"),
        }
    }
}

impl Args {
    /// Configures spaced node by processing command line arguments
    /// and configuration files
    pub async fn configure(args: Vec<String>) -> anyhow::Result<Spaced> {
        let mut args = Args::try_parse_from(args)?;
        let default_dirs = get_default_node_dirs();

        if args.bitcoin_rpc_url.is_none() {
            args.bitcoin_rpc_url = Some(default_bitcoin_rpc_url(&args.chain).to_string())
        }
        if args.rpc_port.is_none() {
            args.rpc_port = Some(default_spaces_rpc_port(&args.chain));
        }

        let data_dir = match args.data_dir {
            None => default_dirs.data_dir().to_path_buf(),
            Some(data_dir) => data_dir,
        }
        .join(args.chain.to_string());
        fs::create_dir_all(data_dir.clone())?;

        let default_port = args.rpc_port.unwrap();
        let rpc_bind_addresses: Vec<SocketAddr> = args
            .rpc_bind
            .iter()
            .filter_map(|s| {
                s.parse::<SocketAddr>()
                    .or_else(|_| {
                        s.parse::<IpAddr>()
                            .map(|ip| SocketAddr::new(ip, default_port))
                    })
                    .ok()
            })
            .collect();

        let auth_token = if args.rpc_user.is_some() {
            auth_token_from_creds(
                args.rpc_user.as_ref().unwrap(),
                args.rpc_password.as_ref().unwrap(),
            )
        } else {
            let cookie = format!(
                "__cookie__:{}",
                thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(64)
                    .map(char::from)
                    .collect::<String>()
            );
            let cookie_path = data_dir.join(".cookie");
            fs::write(&cookie_path, &cookie).map_err(|e| {
                anyhow!(
                    "Failed to write cookie file '{}': {}",
                    cookie_path.display(),
                    e
                )
            })?;
            auth_token_from_cookie(&cookie)
        };

        let bitcoin_rpc_auth = if let Some(cookie) = args.bitcoin_rpc_cookie {
            let cookie = std::fs::read_to_string(cookie)?;
            BitcoinRpcAuth::Cookie(cookie)
        } else if let Some(user) = args.bitcoin_rpc_user {
            BitcoinRpcAuth::UserPass(user, args.bitcoin_rpc_password.expect("password"))
        } else {
            BitcoinRpcAuth::None
        };

        let rpc = BitcoinRpc::new(
            &args.bitcoin_rpc_url.expect("bitcoin rpc url"),
            bitcoin_rpc_auth,
            !args.bitcoin_rpc_light,
        );

        let genesis = Spaced::genesis(args.chain);

        let proto_db_path = data_dir.join("protocol.sdb");
        let initial_sync = !proto_db_path.exists();

        let chain_store = Store::open(proto_db_path)?;
        let chain = LiveStore {
            state: chain_store.begin(&genesis)?,
            store: chain_store,
        };

        let anchors_path = match args.skip_anchors {
            true => None,
            false => Some(data_dir.join("root_anchors.json")),
        };
        let block_index_enabled = args.block_index || args.block_index_full;
        let block_index = if block_index_enabled {
            let block_db_path = data_dir.join("block_index.sdb");
            if !initial_sync && !block_db_path.exists() {
                return Err(anyhow::anyhow!(
                    "Block index must be enabled from the initial sync."
                ));
            }
            let block_store = Store::open(block_db_path)?;
            let index = LiveStore {
                state: block_store.begin(&genesis).expect("begin block index"),
                store: block_store,
            };
            {
                let tip_1 = index.state.tip.read().expect("index");
                let tip_2 = chain.state.tip.read().expect("tip");
                if tip_1.height != tip_2.height || tip_1.hash != tip_2.hash {
                    return Err(anyhow::anyhow!(
                        "Protocol and block index states don't match."
                    ));
                }
            }
            Some(index)
        } else {
            None
        };

        Ok(Spaced {
            network: args.chain,
            rpc,
            data_dir,
            bind: rpc_bind_addresses,
            auth_token,
            chain,
            block_index,
            block_index_full: args.block_index_full,
            num_workers: args.jobs as usize,
            anchors_path,
            synced: false,
            cbf: args.bitcoin_rpc_light,
        })
    }
}

fn get_default_node_dirs() -> ProjectDirs {
    ProjectDirs::from("", "", "spaced").unwrap_or_else(|| {
        error!("error: could not retrieve default project directories from os");
        safe_exit(1);
    })
}

pub fn default_cookie_path(network: &ExtendedNetwork) -> PathBuf {
    get_default_node_dirs()
        .data_dir()
        .join(network.to_string())
        .join(".cookie")
}

// from clap utilities
pub fn safe_exit(code: i32) -> ! {
    use std::io::Write;

    let _ = std::io::stdout().lock().flush();
    let _ = std::io::stderr().lock().flush();

    std::process::exit(code)
}

pub fn default_bitcoin_rpc_url(network: &ExtendedNetwork) -> &'static str {
    match network {
        ExtendedNetwork::Mainnet => "http://127.0.0.1:8332",
        ExtendedNetwork::Testnet4 => "http://127.0.0.1:48332",
        ExtendedNetwork::Signet => "http://127.0.0.1:38332",
        ExtendedNetwork::Testnet => "http://127.0.0.1:18332",
        ExtendedNetwork::Regtest => "http://127.0.0.1:18443",
    }
}

impl Display for ExtendedNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            ExtendedNetwork::Mainnet => "mainnet".to_string(),
            ExtendedNetwork::Testnet => "testnet".to_string(),
            ExtendedNetwork::Testnet4 => "testnet4".to_string(),
            ExtendedNetwork::Signet => "signet".to_string(),
            ExtendedNetwork::Regtest => "regtest".to_string(),
        };
        write!(f, "{}", str)
    }
}

pub fn default_spaces_rpc_port(chain: &ExtendedNetwork) -> u16 {
    match chain {
        ExtendedNetwork::Mainnet => 7225,
        ExtendedNetwork::Testnet4 => 7224,
        ExtendedNetwork::Testnet => 7223,
        ExtendedNetwork::Signet => 7221,
        ExtendedNetwork::Regtest => 7218,
    }
}
