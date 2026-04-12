extern crate core;

use std::{
    fs, io,
    io::Write,
    path::PathBuf,
};
use std::str::FromStr;
use anyhow::anyhow;
use clap::{Parser, Subcommand};
use colored::{Color, Colorize};
use jsonrpsee::{
    core::{client::Error, ClientError},
    http_client::HttpClient,
};
use spaces_client::{
    auth::{auth_token_from_cookie, auth_token_from_creds, http_client_with_auth},
    config::{default_cookie_path, default_spaces_rpc_port, ExtendedNetwork},
    format::{
        print_error_rpc_response, print_list_bidouts, print_list_nums_response,
        print_list_spaces_response, print_list_transactions, print_list_unspent,
        print_list_wallets, print_server_info, print_wallet_balance_response,
        print_wallet_info, print_wallet_response, Format,
    },
    rpc::{
        BidParams, OpenParams, RegisterParams, RpcClient, RpcWalletRequest,
        RpcWalletTxBuilder, SendCoinsParams, Subject, TransferSpacesParams,
    },
    wallets::{AddressKind, WalletResponse},
};
use spaces_client::rpc::{CommitParams, CreateNumParams, DelegateParams, OperateParams, SetFallbackParams};
use spaces_client::store::Sha256;
use spaces_protocol::bitcoin::{Amount, FeeRate, OutPoint, Txid};
use spaces_protocol::slabel::SLabel;
use spaces_nums::num_id::NumId;
use spaces_wallet::{bitcoin::secp256k1::schnorr::Signature, export::WalletExport, Listing};
use spaces_wallet::bitcoin::hashes::sha256;
use spaces_wallet::bitcoin::ScriptBuf;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Bitcoin network to use
    #[arg(long, env = "SPACED_CHAIN", default_value = "mainnet")]
    chain: ExtendedNetwork,
    #[arg(long, default_value = "text")]
    output_format: Format,
    /// Spaced RPC URL [default: based on specified chain]
    #[arg(long)]
    rpc_url: Option<String>,
    /// Spaced RPC cookie file path
    #[arg(long, env = "SPACED_RPC_COOKIE")]
    rpc_cookie: Option<PathBuf>,
    /// Spaced RPC user
    #[arg(long, requires = "rpc_password", env = "SPACED_RPC_USER")]
    rpc_user: Option<String>,
    /// Spaced RPC password
    #[arg(long, env = "SPACED_RPC_PASSWORD")]
    rpc_password: Option<String>,
    /// Specify wallet to use
    #[arg(long, short, global = true, default_value = "default")]
    wallet: String,
    /// Custom dust amount in sat for bid outputs
    #[arg(long, short, global = true)]
    dust: Option<u64>,
    /// Force invalid transaction (for testing only)
    #[arg(long, global = true, default_value = "false")]
    force: bool,
    /// Skip tx checker (not recommended)
    #[arg(long, global = true, default_value = "false")]
    skip_tx_check: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// List existing wallets
    #[command(name = "listwallets")]
    ListWallets,
    /// Generate a new wallet
    #[command(name = "createwallet")]
    CreateWallet,
    /// Recover wallet from mnemonic phrase
    #[command(name = "recoverwallet")]
    RecoverWallet,
    /// Load a wallet
    #[command(name = "loadwallet")]
    LoadWallet,
    /// Export a wallet
    #[command(name = "exportwallet")]
    ExportWallet {
        // Destination path to export json file
        path: PathBuf,
    },
    /// Import a wallet
    #[command(name = "importwallet")]
    ImportWallet {
        // Wallet json file to import
        path: PathBuf,
    },
    /// Export a wallet
    #[command(name = "getwalletinfo")]
    GetWalletInfo,
    /// Export a wallet
    #[command(name = "getserverinfo")]
    GetServerInfo,
    /// Open an auction
    Open {
        /// Space name
        space: String,
        /// Amount in sats
        #[arg(default_value = "1000")]
        initial_bid: u64,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: Option<u64>,
    },
    /// Place a bid
    Bid {
        /// Space name
        space: String,
        /// Amount in satoshi
        amount: u64,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: Option<u64>,
        #[arg(long, short, default_value = "false")]
        confirmed_only: bool,
    },
    /// Register a won auction
    Register {
        /// Space name
        space: String,
        /// Recipient address
        address: Option<String>,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: Option<u64>,
    },
    /// Get space info
    #[command(name = "getspace")]
    GetSpace {
        /// The space name
        space: String,
    },
    /// Generate a random p2tr keypair and print the secret key, script pubkey, and num id
    #[command(name = "generatekey")]
    GenerateKey,
    /// Create a new num
    #[command(name = "createnum")]
    CreateNum {
        /// Optional script public key as hex string.
        /// If omitted, a unique address is generated automatically.
        #[arg(long)]
        bind_spk: Option<String>,

        #[arg(long, short)]
        fee_rate: Option<u64>,
    },
    /// Get num info
    #[command(name = "getnum")]
    GetNum {
        /// Space name, numeric, or num id
        subject: Subject,
    },
    /// Transfer ownership of spaces and/or nums to the given name or address
    #[command(
        name = "transfer",
        override_usage = "space-cli transfer [SPACES-OR-NUMS]... --to <SPACE-OR-ADDRESS>"
    )]
    Transfer {
        /// Spaces (e.g., @bitcoin) and/or nums (e.g., num1... or #800000-3) to send
        #[arg(display_order = 0)]
        spaces: Vec<Subject>,
        /// Recipient space name or address
        #[arg(long, display_order = 1)]
        to: String,
        /// Read hex-encoded secret key from stdin for transferring nums not owned by wallet
        #[arg(long)]
        secret_stdin: bool,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: Option<u64>,
    },
    /// Renew ownership of a space
    #[command(name = "renew")]
    Renew {
        /// Spaces to renew
        #[arg(display_order = 0)]
        spaces: Vec<String>,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: Option<u64>,
    },
    /// Initialize a space or numeric for operation of off-chain subspaces
    #[command(name = "operate")]
    Operate {
        /// Space name, numeric, or num id
        subject: Subject,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: Option<u64>,
    },
    /// Commit a new root
    #[command(name = "commit")]
    Commit {
        /// Space name, numeric, or num id
        subject: Subject,
        /// The new state root
        root: sha256::Hash,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: Option<u64>,
    },
    /// Rollback the last pending commitment
    #[command(name = "rollback")]
    Rollback {
        /// Space name, numeric, or num id
        subject: Subject,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: Option<u64>,
    },
    /// Delegate operation of a space or numeric to someone else
    #[command(name = "delegate")]
    Delegate {
        /// Space name, numeric, or num id
        #[arg(display_order = 0)]
        subject: Subject,
        /// Recipient space name or address (must be a space address)
        #[arg(long, display_order = 1)]
        to: String,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: Option<u64>,
    },
    /// Get the current space a num id is responsible for
    #[command(name = "getdelegator")]
    GetDelegator {
        /// A num id (e.g., num1...) or numeric (e.g., #800000-3)
        subject: Subject,
    },
    /// Get the current num id responsible for a space or numeric
    #[command(name = "getdelegation")]
    GetDelegation {
        /// Space name, numeric, or num id
        subject: Subject,
    },
    /// Get a commitment for a space or numeric
    #[command(name = "getcommitment")]
    GetCommitment {
        /// Space name, numeric, or num id
        subject: Subject,
        // If no specific root, the most recent commitment will be fetched
        root: Option<sha256::Hash>,
    },
    /// Estimates the minimum bid needed for a rollout within the given target blocks
    #[command(name = "estimatebid")]
    EstimateBid {
        /// Rollout within target blocks
        #[arg(default_value = "0")]
        target: usize,
    },
    /// Send the specified amount of BTC to the given name or address
    #[command(
        name = "send",
        override_usage = "space-cli send <AMOUNT> --to <SPACE-OR-ADDRESS>"
    )]
    SendCoins {
        /// Amount to send in satoshi
        #[arg(display_order = 0)]
        amount: u64,
        /// Recipient space name or address
        #[arg(long, display_order = 1)]
        to: String,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: Option<u64>,
    },
    /// Get wallet balance
    #[command(name = "balance")]
    Balance,
    /// Pre-create outputs that can be auctioned off during the bidding process
    #[command(name = "createbidouts")]
    CreateBidOuts {
        /// Number of output pairs to create
        /// Each pair can be used to make a bid
        pairs: u8,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: Option<u64>,
    },
    /// Bump the fee for a transaction created by this wallet
    #[command(name = "bumpfee")]
    BumpFee {
        txid: Txid,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: u64,
    },
    /// List a space you own for sale
    #[command(name = "sell")]
    Sell {
        /// The space to sell
        space: String,
        /// Amount in satoshis
        price: u64,
    },
    /// Buy a space from the specified listing
    #[command(name = "buy")]
    Buy {
        /// The space to buy
        space: String,
        /// The listing price
        price: u64,
        /// The seller's signature
        #[arg(long)]
        signature: String,
        /// The seller's address
        #[arg(long)]
        seller: String,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: Option<u64>,
    },
    /// Verify a listing
    #[command(name = "verifylisting")]
    VerifyListing {
        /// The space to buy
        space: String,
        /// The listing price
        price: u64,
        /// The seller's signature
        #[arg(long)]
        signature: String,
        /// The seller's address
        #[arg(long)]
        seller: String,
    },
    /// Get a spaceout - a Bitcoin output relevant to the Spaces protocol.
    #[command(name = "getspaceout")]
    GetSpaceOut {
        /// The OutPoint
        outpoint: OutPoint,
    },
    /// Get a num output
    #[command(name = "getnumout")]
    GetNumOut {
        /// The OutPoint
        outpoint: OutPoint,
    },
    /// Get the estimated rollout batch for the specified interval
    #[command(name = "getrollout")]
    GetRollout {
        // Get the estimated rollout for the target interval. Every ~144 blocks (a rollout interval),
        // 10 spaces are released for auction. Specify 0 [default] for the coming interval, 1
        // for the interval after and so on.
        #[arg(default_value = "0")]
        target_interval: usize,
    },
    /// Set on-chain fallback record data for a space or num.
    ///
    /// Records can be specified as key=value flags, raw base64, or JSON from stdin.
    ///
    /// Examples:
    ///   space-cli setfallback @alice --txt btc=bc1q... --txt nostr=npub1...
    ///   space-cli setfallback @alice --raw SGVsbG8=
    ///   echo '[{"type":"txt","key":"btc","value":["bc1q..."]}]' | space-cli setfallback @alice --stdin
    #[command(name = "setfallback")]
    SetFallback {
        /// Space name, numeric, or num id
        subject: Subject,
        /// Add a TXT record (key=value, can be repeated)
        #[arg(long = "txt", value_name = "KEY=VALUE")]
        txt_records: Vec<String>,
        /// Add a BLOB record (key=base64, can be repeated)
        #[arg(long = "blob", value_name = "KEY=BASE64")]
        blob_records: Vec<String>,
        /// Set raw wire-format data as base64
        #[arg(long, conflicts_with_all = ["txt_records", "blob_records", "stdin"])]
        raw: Option<String>,
        /// Read JSON records from stdin
        #[arg(long, conflicts_with_all = ["txt_records", "blob_records", "raw"])]
        stdin: bool,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: Option<u64>,
    },
    /// Get on-chain fallback record data for a space or num.
    #[command(name = "getfallback")]
    GetFallback {
        /// Space name, numeric, or num id
        subject: Subject,
    },
    /// List last transactions
    #[command(name = "listtransactions")]
    ListTransactions {
        #[arg(default_value = "10")]
        count: usize,
        #[arg(default_value = "0")]
        skip: usize,
    },
    /// List won spaces including ones
    /// still in auction with a winning bid
    #[command(name = "listspaces")]
    ListSpaces,
    /// List nums. Defaults to owned, use --kind external for nums created but not owned.
    #[command(name = "listnums")]
    ListNums {
        #[arg(long, default_value = "owned")]
        kind: String,
    },
    /// List unspent auction outputs i.e. outputs that can be
    /// auctioned off in the bidding process
    #[command(name = "listbidouts")]
    ListBidOuts,
    /// List unspent coins owned by wallet
    #[command(name = "listunspent")]
    ListUnspent,
    /// Get a new Bitcoin address suitable for receiving spaces and coins
    /// (Spaces compatible bitcoin wallets only)
    #[command(name = "getnewspaceaddress")]
    GetSpaceAddress,
    /// Get a new Bitcoin address suitable for receiving coins
    /// compatible with most bitcoin wallets
    #[command(name = "getnewaddress")]
    GetCoinAddress,
    /// Increment the address index and return the next address.
    /// Useful when you need a guaranteed fresh address
    #[command(name = "walletincrementaddress")]
    IncrementAddress {
        /// The kind of address to increment (coin or space)
        #[arg(value_enum, default_value = "coin")]
        kind: AddressKind,
    },
}

struct SpaceCli {
    wallet: String,
    format: Format,
    dust: Option<Amount>,
    force: bool,
    skip_tx_check: bool,
    network: ExtendedNetwork,
    rpc_url: String,
    client: HttpClient,
}

impl SpaceCli {
    async fn configure() -> anyhow::Result<(Self, Args)> {
        let mut args = Args::parse();
        if args.rpc_url.is_none() {
            args.rpc_url = Some(default_rpc_url(&args.chain));
        }

        let auth_token = if args.rpc_user.is_some() {
            auth_token_from_creds(
                args.rpc_user.as_ref().unwrap(),
                args.rpc_password.as_ref().unwrap(),
            )
        } else {
            let cookie_path = match &args.rpc_cookie {
                Some(path) => path,
                None => &default_cookie_path(&args.chain),
            };
            let cookie = fs::read_to_string(cookie_path).map_err(|e| {
                anyhow!(
                    "Failed to read cookie file '{}': {}",
                    cookie_path.display(),
                    e
                )
            })?;
            auth_token_from_cookie(&cookie)
        };
        let client = http_client_with_auth(args.rpc_url.as_ref().unwrap(), &auth_token)?;

        Ok((
            Self {
                wallet: args.wallet.clone(),
                format: args.output_format,
                dust: args.dust.map(|d| Amount::from_sat(d)),
                force: args.force,
                skip_tx_check: args.skip_tx_check,
                network: args.chain,
                rpc_url: args.rpc_url.clone().unwrap(),
                client,
            },
            args,
        ))
    }

    async fn send_request(
        &self,
        req: Option<RpcWalletRequest>,
        bidouts: Option<u8>,
        fee_rate: Option<u64>,
        confirmed_only: bool,
    ) -> Result<(), ClientError> {
        let fee_rate = fee_rate.map(|fee| FeeRate::from_sat_per_vb(fee).unwrap());
        let result = self
            .client
            .wallet_send_request(
                &self.wallet,
                RpcWalletTxBuilder {
                    bidouts,
                    requests: match req {
                        None => vec![],
                        Some(req) => vec![req],
                    },
                    fee_rate,
                    dust: self.dust,
                    force: self.force,
                    confirmed_only,
                    skip_tx_check: self.skip_tx_check,
                },
            )
            .await?;

        print_wallet_response(self.network.fallback_network(), result, self.format);
        Ok(())
    }
}

fn normalize_space(space: &str) -> String {
    let lowercase = space.to_ascii_lowercase();
    if lowercase.starts_with('@') {
        lowercase
    } else {
        format!("@{}", lowercase)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (cli, args) = SpaceCli::configure().await?;
    let result = handle_commands(&cli, args.command).await;

    match result {
        Ok(_) => {}
        Err(error) => match ClientError::from(error) {
            Error::Call(rpc) => {
                print_error_rpc_response(rpc.code(), rpc.message().to_string(), cli.format);
            }
            Error::Transport(err) => {
                println!(
                    "Transport error: {}: Rpc url: {} (network: {})",
                    err, cli.rpc_url, cli.network
                );
            }
            Error::RestartNeeded(err) => {
                println!("Restart needed: {}", err);
            }
            Error::ParseError(err) => {
                println!("Parse error: {}", err);
            }
            Error::InvalidSubscriptionId => {
                println!("Invalid subscription ID");
            }
            Error::InvalidRequestId(err) => {
                println!("Invalid request ID: {}", err);
            }
            Error::RequestTimeout => {
                println!("Request timeout");
            }
            Error::MaxSlotsExceeded => {
                println!("Max concurrent requests exceeded");
            }
            Error::Custom(msg) => {
                println!("Custom error: {}", msg);
            }
            Error::HttpNotImplemented => {
                println!("HTTP not implemented");
            }
            Error::EmptyBatchRequest(err) => {
                println!("Empty batch request: {}", err);
            }
            Error::RegisterMethod(err) => {
                println!("Register method error: {}", err);
            }
        },
    }
    Ok(())
}

async fn handle_commands(cli: &SpaceCli, command: Commands) -> Result<(), ClientError> {
    match command {
        Commands::GetRollout {
            target_interval: target,
        } => {
            let data = cli.client.get_rollout(target).await?;
            println!("{}", serde_json::to_string_pretty(&data)?);
        }
        Commands::EstimateBid { target } => {
            let response = cli.client.estimate_bid(target).await?;
            println!("{} sat", Amount::from_sat(response).to_sat());
        }
        Commands::GetSpace { space } => {
            let space = normalize_space(&space);
            let response = cli.client.get_space(&space).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Commands::GetSpaceOut { outpoint } => {
            let response = cli.client.get_spaceout(outpoint).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Commands::ListWallets => {
            let result = cli.client.list_wallets().await?;
            print_list_wallets(result, cli.format);
        }
        Commands::CreateWallet => {
            let response = cli.client.wallet_create(&cli.wallet).await?;
            println!("⚠️ Write down your recovery phrase NOW!");
            println!("This is the ONLY time it will be shown:");
            println!("{}", &response);
        }
        Commands::RecoverWallet => {
            print!("Enter mnemonic phrase: ");
            io::stdout().flush().unwrap();
            let mut mnemonic = String::new();
            io::stdin().read_line(&mut mnemonic).unwrap();
            cli.client.wallet_recover(&cli.wallet, mnemonic).await?;
        }
        Commands::LoadWallet => {
            cli.client.wallet_load(&cli.wallet).await?;
        }
        Commands::ImportWallet { path } => {
            let content =
                fs::read_to_string(path).map_err(|e| ClientError::Custom(e.to_string()))?;
            let wallet: WalletExport = serde_json::from_str(&content)?;
            cli.client.wallet_import(wallet).await?;
        }
        Commands::ExportWallet { path } => {
            let result = cli.client.wallet_export(&cli.wallet).await?;
            let content = serde_json::to_string_pretty(&result).expect("result");
            fs::write(path, content).map_err(|e| {
                ClientError::Custom(format!("Could not save to path: {}", e.to_string()))
            })?;
        }
        Commands::GetWalletInfo => {
            let result = cli.client.wallet_get_info(&cli.wallet).await?;
            print_wallet_info(result, cli.format);
        }
        Commands::GetServerInfo => {
            let result = cli.client.get_server_info().await?;
            print_server_info(result, cli.format);
        }
        Commands::Open {
            ref space,
            initial_bid,
            fee_rate,
        } => {
            cli.send_request(
                Some(RpcWalletRequest::Open(OpenParams {
                    name: normalize_space(space),
                    amount: initial_bid,
                })),
                None,
                fee_rate,
                false,
            )
            .await?
        }
        Commands::Bid {
            space,
            amount,
            fee_rate,
            confirmed_only,
        } => {
            cli.send_request(
                Some(RpcWalletRequest::Bid(BidParams {
                    name: normalize_space(&space),
                    amount,
                })),
                None,
                fee_rate,
                confirmed_only,
            )
            .await?
        }
        Commands::CreateBidOuts { pairs, fee_rate } => {
            cli.send_request(None, Some(pairs), fee_rate, false).await?
        }
        Commands::Register {
            space,
            address,
            fee_rate,
        } => {
            cli.send_request(
                Some(RpcWalletRequest::Register(RegisterParams {
                    name: normalize_space(&space),
                    to: address,
                })),
                None,
                fee_rate,
                false,
            )
            .await?
        }
        Commands::Renew { spaces, fee_rate } => {
            let spaces: Vec<_> = spaces.into_iter().map(|s| {
                let normalized = normalize_space(&s);
                Subject::Label(SLabel::from_str(&normalized).expect("valid space"))
            }).collect();
            cli.send_request(
                Some(RpcWalletRequest::Transfer(TransferSpacesParams { secret: None,
                    spaces,
                    to: None,
                    data: None,
                })),
                None,
                fee_rate,
                false,
            )
            .await?
        }
        Commands::Transfer {
            spaces,
            to,
            secret_stdin,
            fee_rate,
        } => {
            let secret = if secret_stdin {
                let mut input = String::new();
                io::stdin().read_line(&mut input)
                    .map_err(|e| ClientError::Custom(format!("failed to read secret from stdin: {}", e)))?;
                Some(input.trim().to_string())
            } else {
                None
            };
            cli.send_request(
                Some(RpcWalletRequest::Transfer(TransferSpacesParams {
                    secret,
                    spaces,
                    to: Some(to),
                    data: None,
                })),
                None,
                fee_rate,
                false,
            )
            .await?
        }
        Commands::SendCoins {
            amount,
            to,
            fee_rate,
        } => {
            cli.send_request(
                Some(RpcWalletRequest::SendCoins(SendCoinsParams {
                    amount: Amount::from_sat(amount),
                    to,
                })),
                None,
                fee_rate,
                false,
            )
            .await?
        }
        Commands::SetFallback {
            subject,
            txt_records,
            blob_records,
            raw,
            stdin,
            fee_rate,
        } => {
            use base64::Engine;
            let data = if let Some(raw_b64) = raw {
                // Raw base64-encoded wire-format bytes
                base64::engine::general_purpose::STANDARD.decode(&raw_b64)
                    .map_err(|e| ClientError::Custom(format!("Could not base64 decode data: {}", e)))?
            } else if stdin {
                // Read JSON records from stdin
                let mut input = String::new();
                io::stdin().read_line(&mut input).map_err(|e|
                    ClientError::Custom(format!("Failed to read stdin: {}", e)))?;
                let record_set: sip7::RecordSet = serde_json::from_str(input.trim())
                    .map_err(|e| ClientError::Custom(format!("Invalid SIP-7 JSON: {}", e)))?;
                record_set.to_bytes()
            } else if !txt_records.is_empty() || !blob_records.is_empty() {
                // Build from --txt and --blob flags
                let mut records = Vec::new();
                for txt in &txt_records {
                    let (key, value) = txt.split_once('=').ok_or_else(||
                        ClientError::Custom(format!("Invalid --txt format '{}': expected key=value", txt)))?;
                    records.push(sip7::Record::txt(key, &[value]));
                }
                for blob in &blob_records {
                    let (key, b64_value) = blob.split_once('=').ok_or_else(||
                        ClientError::Custom(format!("Invalid --blob format '{}': expected key=base64", blob)))?;
                    let value = base64::engine::general_purpose::STANDARD.decode(b64_value)
                        .map_err(|e| ClientError::Custom(format!("Invalid base64 in --blob '{}': {}", key, e)))?;
                    records.push(sip7::Record::blob(key, value));
                }
                sip7::RecordSet::pack(records)
                    .map_err(|e| ClientError::Custom(format!("Invalid record: {}", e)))?
                    .to_bytes()
            } else {
                return Err(ClientError::Custom(
                    "No data specified. Use --txt, --blob, --raw, or --stdin".to_string()
                ));
            };

            cli.send_request(
                Some(RpcWalletRequest::SetFallback(SetFallbackParams { subject, data })),
                None,
                fee_rate,
                false,
            )
            .await?;
        }
        Commands::GetFallback {
            subject,
        } => {
            let response = cli.client.get_fallback(subject).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Commands::ListUnspent => {
            let utxos = cli.client.wallet_list_unspent(&cli.wallet).await?;
            print_list_unspent(utxos, cli.format);
        }
        Commands::ListBidOuts => {
            let bidouts = cli.client.wallet_list_bidouts(&cli.wallet).await?;
            print_list_bidouts(bidouts, cli.format);
        }
        Commands::ListTransactions { count, skip } => {
            let txs = cli
                .client
                .wallet_list_transactions(&cli.wallet, count, skip)
                .await?;
            print_list_transactions(txs, cli.format);
        }
        Commands::ListSpaces => {
            let tip = cli.client.get_server_info().await?;
            let spaces = cli.client.wallet_list_spaces(&cli.wallet).await?;
            print_list_spaces_response(tip.tip.height, spaces, cli.format);
        }
        Commands::ListNums { kind } => {
            let kind = if kind == "owned" { None } else { Some(kind) };
            let nums = cli.client.wallet_list_nums(&cli.wallet, kind).await?;
            print_list_nums_response(nums, cli.format);
        }
        Commands::Balance => {
            let balance = cli.client.wallet_get_balance(&cli.wallet).await?;
            print_wallet_balance_response(balance, cli.format);
        }
        Commands::GetCoinAddress => {
            let response = cli
                .client
                .wallet_get_new_address(&cli.wallet, AddressKind::Coin)
                .await?;
            println!("{}", response);
        }
        Commands::GetSpaceAddress => {
            let response = cli
                .client
                .wallet_get_new_address(&cli.wallet, AddressKind::Space)
                .await?;
            println!("{}", response);
        }
        Commands::IncrementAddress { kind } => {
            let response = cli
                .client
                .wallet_increment_address(&cli.wallet, kind)
                .await?;
            println!("{}", response);
        }
        Commands::BumpFee { txid, fee_rate } => {
            let fee_rate = FeeRate::from_sat_per_vb(fee_rate).expect("valid fee rate");
            let response = cli
                .client
                .wallet_bump_fee(&cli.wallet, txid, fee_rate, cli.skip_tx_check)
                .await?;
            print_wallet_response(
                cli.network.fallback_network(),
                WalletResponse { result: response },
                cli.format,
            );
        }
        Commands::Buy {
            space,
            price,
            signature,
            seller,
            fee_rate,
        } => {
            let listing = Listing {
                space: normalize_space(&space),
                price,
                seller,
                signature: Signature::from_slice(
                    hex::decode(signature)
                        .map_err(|_| {
                            ClientError::Custom("Signature must be in hex format".to_string())
                        })?
                        .as_slice(),
                )
                .map_err(|_| ClientError::Custom("Invalid signature".to_string()))?,
            };
            let result = cli
                .client
                .wallet_buy(
                    &cli.wallet,
                    listing,
                    fee_rate.map(|rate| FeeRate::from_sat_per_vb(rate).expect("valid fee rate")),
                    cli.skip_tx_check,
                )
                .await?;
            print_wallet_response(
                cli.network.fallback_network(),
                WalletResponse {
                    result: vec![result],
                },
                cli.format,
            );
        }
        Commands::Sell { mut space, price } => {
            space = normalize_space(&space);
            let result = cli.client.wallet_sell(&cli.wallet, space, price).await?;
            println!("{}", serde_json::to_string_pretty(&result).expect("result"));
        }
        Commands::VerifyListing {
            space,
            price,
            signature,
            seller,
        } => {
            let listing = Listing {
                space: normalize_space(&space),
                price,
                seller,
                signature: Signature::from_slice(
                    hex::decode(signature)
                        .map_err(|_| {
                            ClientError::Custom("Signature must be in hex format".to_string())
                        })?
                        .as_slice(),
                )
                .map_err(|_| ClientError::Custom("Invalid signature".to_string()))?,
            };

            cli.client.verify_listing(listing).await?;
            println!("{} Listing verified", "✓".color(Color::Green));
        }
        Commands::GenerateKey => {
            use spaces_wallet::bitcoin::secp256k1::{Secp256k1, Keypair};
            use spaces_wallet::bitcoin::key::TapTweak;
            use spaces_wallet::bitcoin::script::Builder;
            use spaces_wallet::bitcoin::opcodes::all::OP_PUSHNUM_1;

            let secp = Secp256k1::new();
            let (secret_key, _) = secp.generate_keypair(&mut rand::thread_rng());
            let keypair = Keypair::from_secret_key(&secp, &secret_key);
            let tweaked = keypair.tap_tweak(&secp, None);
            let (xonly, _) = tweaked.to_keypair().x_only_public_key();

            let spk = Builder::new()
                .push_opcode(OP_PUSHNUM_1)
                .push_slice(xonly.serialize())
                .into_script();

            let num_id = NumId::from_spk::<Sha256>(spk.clone());
            let tweaked_secret = tweaked.to_keypair().secret_key().secret_bytes();

            println!("secret: {}", hex::encode(tweaked_secret));
            println!("spk: {}", hex::encode(spk.as_bytes()));
            println!("num_id: {}", num_id);
        }
        Commands::CreateNum { bind_spk, fee_rate } => {
            let spk = match bind_spk {
                Some(hex) => {
                    let spk = ScriptBuf::from(hex::decode(hex)
                        .map_err(|_| ClientError::Custom("Invalid spk hex".to_string()))?);
                    let num_id = NumId::from_spk::<Sha256>(spk.clone());
                    println!("Creating num id: {}", num_id);
                    Some(spk)
                }
                None => {
                    println!("Creating num with auto-generated address");
                    None
                }
            };
            cli.send_request(
                Some(RpcWalletRequest::CreateNum(CreateNumParams {
                    bind_spk: spk,
                })),
                None,
                fee_rate,
                false,
            )
                .await?
        }
        Commands::GetNum { subject } => {
            let num = cli
                .client
                .get_num(subject)
                .await
                .map_err(|e| ClientError::Custom(e.to_string()))?;
            println!("{}", serde_json::to_string(&num).expect("result"));
        }

        Commands::GetNumOut { outpoint } => {
            let numout = cli
                .client
                .get_numout(outpoint)
                .await
                .map_err(|e| ClientError::Custom(e.to_string()))?;
            println!("{}", serde_json::to_string(&numout).expect("result"));
        }
        Commands::Operate { subject, fee_rate } => {
            cli.send_request(
                Some(RpcWalletRequest::Operate(OperateParams {
                    subject,
                })),
                None,
                fee_rate,
                false,
            )
                .await?;
            println!("Operate setup should be complete once tx is confirmed");
        }
        Commands::Commit { subject, root, fee_rate } => {
            cli.send_request(
                Some(RpcWalletRequest::Commit(CommitParams {
                    subject,
                    root: Some(root),
                })),
                None,
                fee_rate,
                false,
            )
                .await?;
        }
        Commands::Rollback { subject, fee_rate } => {
            cli.send_request(
                Some(RpcWalletRequest::Commit(CommitParams {
                    subject,
                    root: None,
                })),
                None,
                fee_rate,
                false,
            )
                .await?;
            println!("Rollback transaction sent");
        }
        Commands::Delegate { subject, to, fee_rate } => {
            cli.send_request(
                Some(RpcWalletRequest::Delegate(DelegateParams {
                    subject,
                    to,
                })),
                None,
                fee_rate,
                false,
            )
                .await?;
        }
        Commands::GetDelegator { subject } => {
            let delegator = cli
                .client
                .get_delegator(subject)
                .await
                .map_err(|e| ClientError::Custom(e.to_string()))?;
            println!("{}", serde_json::to_string(&delegator).expect("result"));
        }
        Commands::GetDelegation { subject } => {
            let delegation = cli
                .client
                .get_delegation(subject)
                .await
                .map_err(|e| ClientError::Custom(e.to_string()))?;
            println!("{}", serde_json::to_string(&delegation).expect("result"));
        }
        Commands::GetCommitment { subject, root } => {
            let c = cli
                .client
                .get_commitment(subject, root)
                .await
                .map_err(|e| ClientError::Custom(e.to_string()))?;
            println!("{}", serde_json::to_string(&c).expect("result"));
        }
    }

    Ok(())
}

fn default_rpc_url(chain: &ExtendedNetwork) -> String {
    format!("http://127.0.0.1:{}", default_spaces_rpc_port(chain))
}
