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
    {Rng, thread_rng},
};
use serde::Deserialize;
use spaces_protocol::bitcoin::Network;

use crate::store::chain::{Chain, ROOT_ANCHORS_COUNT};
use crate::{
    auth::{auth_token_from_cookie, auth_token_from_creds},
    source::{BitcoinRpc, BitcoinRpcAuth},
    spaces::Spaced,
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
    /// Listen for JSON-RPC connections on `<port>`
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

    /// Specify the number of anchors spaced will calculate for /root-anchors endpoint
    #[arg(long, env = "SPACED_NUM_ANCHORS")]
    num_anchors: Option<u32>,

    /// Index internal node hashes for spaces & nums tree for
    /// faster merkle proof generation (with build_chain_proof rpc)
    #[arg(long, env = "SPACED_INDEX_NODE_HASHES", default_value = "false")]
    index_node_hashes: bool,

    /// Enable manual pruning of Bitcoin Core blocks after they have been
    /// processed by spaced. Calls `pruneblockchain` RPC periodically,
    /// keeping a buffer of blocks from tip to handle reorgs.
    #[arg(long, env = "SPACED_ENABLE_PRUNING", default_value = "false")]
    enable_pruning: bool,

    /// Cache size in bytes for the spacedb database
    #[arg(long, env = "SPACED_CACHE_SIZE")]
    cache_size: Option<usize>,
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

    #[allow(clippy::result_unit_err)]
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

        let auth_token = if let Some(user) = args.rpc_user.as_ref() {
            auth_token_from_creds(user, args.rpc_password.as_ref().unwrap())
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
            let cookie = std::fs::read_to_string(&cookie).map_err(|e| {
                anyhow!(
                    "Failed to read Bitcoin RPC cookie '{}': {}",
                    cookie.display(),
                    e
                )
            })?;
            BitcoinRpcAuth::Cookie(cookie)
        } else if let Some(user) = args.bitcoin_rpc_user {
            BitcoinRpcAuth::UserPass(user, args.bitcoin_rpc_password.expect("password"))
        } else if let Some(cookie) =
            default_bitcoin_cookie_path(&args.chain).and_then(|p| std::fs::read_to_string(&p).ok())
        {
            log::info!("Using Bitcoin Core cookie authentication");
            BitcoinRpcAuth::Cookie(cookie)
        } else {
            BitcoinRpcAuth::None
        };

        let rpc = BitcoinRpc::new(
            &args.bitcoin_rpc_url.expect("bitcoin rpc url"),
            bitcoin_rpc_auth,
            !args.bitcoin_rpc_light,
        );

        let genesis = Spaced::genesis(args.chain);
        let ptr_genesis = Spaced::nums_genesis(args.chain);

        let chain = Chain::load(
            args.chain.fallback_network(),
            genesis,
            ptr_genesis,
            &data_dir,
            args.block_index || args.block_index_full,
            args.index_node_hashes,
            args.cache_size,
        )?;

        let anchors_path = match args.skip_anchors {
            true => None,
            false => Some(data_dir.join("root_anchors.json")),
        };

        Ok(Spaced {
            network: args.chain,
            rpc,
            data_dir,
            bind: rpc_bind_addresses,
            auth_token,
            chain,
            block_index_full: args.block_index_full,
            num_workers: args.jobs as usize,
            anchors_path,
            synced: false,
            cbf: args.bitcoin_rpc_light,
            num_anchors: args.num_anchors.unwrap_or(ROOT_ANCHORS_COUNT),
            enable_pruning: args.enable_pruning,
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

/// Returns the default Bitcoin Core cookie file path for the given network.
pub fn default_bitcoin_cookie_path(network: &ExtendedNetwork) -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let base = if cfg!(target_os = "linux") {
        home?.join(".bitcoin")
    } else if cfg!(target_os = "macos") {
        home?.join("Library/Application Support/Bitcoin")
    } else if cfg!(target_os = "windows") {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)?
            .join("Bitcoin")
    } else {
        return None;
    };

    let path = match network {
        ExtendedNetwork::Mainnet => base.join(".cookie"),
        ExtendedNetwork::Testnet => base.join("testnet3").join(".cookie"),
        ExtendedNetwork::Testnet4 => base.join("testnet4").join(".cookie"),
        ExtendedNetwork::Signet => base.join("signet").join(".cookie"),
        ExtendedNetwork::Regtest => base.join("regtest").join(".cookie"),
    };

    Some(path)
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
