extern crate core;

use std::{
    fs, io,
    io::{Cursor, IsTerminal, Write},
    path::PathBuf,
};

use anyhow::anyhow;
use base64::Engine;
use clap::{Parser, Subcommand};
use colored::{Color, Colorize};
use domain::{
    base::{iana::Opcode, MessageBuilder, TreeCompressor},
    zonefile::inplace::{Entry, Zonefile},
};
use jsonrpsee::{
    core::{client::Error, ClientError},
    http_client::HttpClient,
};
use spaces_client::{
    auth::{auth_token_from_cookie, auth_token_from_creds, http_client_with_auth},
    config::{default_cookie_path, default_spaces_rpc_port, ExtendedNetwork},
    format::{
        print_error_rpc_response, print_list_bidouts, print_list_spaces_response,
        print_list_transactions, print_list_unspent, print_list_wallets, print_server_info,
        print_wallet_balance_response, print_wallet_info, print_wallet_response, Format,
    },
    rpc::{
        BidParams, ExecuteParams, OpenParams, RegisterParams, RpcClient, RpcWalletRequest,
        RpcWalletTxBuilder, SendCoinsParams, TransferSpacesParams,
    },
    wallets::{AddressKind, WalletResponse},
};
use spaces_protocol::bitcoin::{Amount, FeeRate, OutPoint, Txid};
use spaces_wallet::{
    bitcoin::secp256k1::schnorr::Signature,
    export::WalletExport,
    nostr::{NostrEvent, NostrTag},
    Listing,
};

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
    /// Transfer ownership of a set of spaces to the given name or address
    #[command(
        name = "transfer",
        override_usage = "space-cli transfer [SPACES]... --to <SPACE-OR-ADDRESS>"
    )]
    Transfer {
        /// Spaces to send
        #[arg(display_order = 0)]
        spaces: Vec<String>,
        /// Recipient space name or address (must be a space address)
        #[arg(long, display_order = 1)]
        to: String,
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
    /// Estimates the minimum bid needed for a rollout within the given target blocks
    #[command(name = "estimatebid")]
    EstimateBid {
        /// Rollout within target blocks
        #[arg(default_value = "0")]
        target: usize,
    },
    /// Estimate fee rate for a given confirmation target
    #[command(name = "estimatefee")]
    EstimateFee {
        /// Target number of blocks for confirmation (1-1008)
        #[arg(default_value = "6")]
        conf_target: u32,
        /// Fee estimation mode: unset, conservative, or economical
        #[arg(long, short)]
        mode: Option<String>,
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
    /// Sign any Nostr event using the space's private key
    #[command(name = "signevent")]
    SignEvent {
        /// Space name (e.g., @example)
        space: String,

        /// Path to a Nostr event json file (omit for stdin)
        #[arg(short, long)]
        input: Option<PathBuf>,

        /// Include a space-tag and trust path data
        #[arg(short, long)]
        anchor: bool,
    },
    /// Verify a signed Nostr event against the space's public key
    #[command(name = "verifyevent")]
    VerifyEvent {
        /// Space name (e.g., @example)
        space: String,

        /// Path to a signed Nostr event json file (omit for stdin)
        #[arg(short, long)]
        input: Option<PathBuf>,
    },
    /// Sign a zone file turning it into a space-anchored Nostr event
    #[command(name = "signzone")]
    SignZone {
        /// The space to use for signing the DNS file
        space: String,
        /// The DNS zone file path (omit for stdin)
        input: Option<PathBuf>,
        /// Skip including bundled Merkle proof in the event.
        #[arg(long)]
        skip_anchor: bool,
    },
    /// Updates the Merkle trust path for space-anchored Nostr events
    #[command(name = "refreshanchor")]
    RefreshAnchor {
        /// Path to a Nostr event file (omit for stdin)
        input: Option<PathBuf>,
        /// Prefer the most recent trust path (not recommended)
        #[arg(long)]
        prefer_recent: bool,
    },
    /// Get a spaceout - a Bitcoin output relevant to the Spaces protocol.
    #[command(name = "getspaceout")]
    GetSpaceOut {
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
    /// Associate on-chain record data with a space as a fallback to P2P options like Fabric.
    #[command(name = "setrawfallback")]
    SetRawFallback {
        /// Space name
        space: String,
        /// Hex encoded data
        data: String,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: Option<u64>,
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

    async fn sign_event(
        &self,
        space: String,
        event: NostrEvent,
        anchor: bool,
        most_recent: bool,
    ) -> Result<NostrEvent, ClientError> {
        let mut result = self
            .client
            .wallet_sign_event(&self.wallet, &space, event)
            .await?;

        if anchor {
            result = self.add_anchor(result, most_recent).await?
        }

        Ok(result)
    }
    async fn add_anchor(
        &self,
        mut event: NostrEvent,
        most_recent: bool,
    ) -> Result<NostrEvent, ClientError> {
        let space = match event.space() {
            None => {
                return Err(ClientError::Custom(
                    "A space tag is required to add an anchor".to_string(),
                ))
            }
            Some(space) => space,
        };

        let spaceout = self
            .client
            .get_space(&space)
            .await
            .map_err(|e| ClientError::Custom(e.to_string()))?
            .ok_or(ClientError::Custom(format!(
                "Space not found \"{}\"",
                space
            )))?;

        event.proof = Some(
            base64::prelude::BASE64_STANDARD.encode(
                self.client
                    .prove_spaceout(
                        OutPoint {
                            txid: spaceout.txid,
                            vout: spaceout.spaceout.n as _,
                        },
                        Some(most_recent),
                    )
                    .await
                    .map_err(|e| ClientError::Custom(e.to_string()))?
                    .proof,
            ),
        );

        Ok(event)
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
        Commands::EstimateFee { conf_target, mode } => {
            let response = cli.client.estimate_fee(conf_target, mode.clone()).await?;
            match cli.format {
                Format::Text => {
                    println!("Fee rate: {} sat/vB", response.feerate_sat_vb);
                    println!("Blocks: {}", response.blocks);
                }
                Format::Json => {
                    println!("{}", serde_json::to_string_pretty(&response)?);
                }
            }
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
            let spaces: Vec<_> = spaces.into_iter().map(|s| normalize_space(&s)).collect();
            cli.send_request(
                Some(RpcWalletRequest::Transfer(TransferSpacesParams {
                    spaces,
                    to: None,
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
            fee_rate,
        } => {
            let spaces: Vec<_> = spaces.into_iter().map(|s| normalize_space(&s)).collect();
            cli.send_request(
                Some(RpcWalletRequest::Transfer(TransferSpacesParams {
                    spaces,
                    to: Some(to),
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
        Commands::SetRawFallback {
            mut space,
            data,
            fee_rate,
        } => {
            space = normalize_space(&space);
            let data = match hex::decode(data) {
                Ok(data) => data,
                Err(e) => {
                    return Err(ClientError::Custom(format!(
                        "Could not hex decode data: {}",
                        e
                    )))
                }
            };

            let space_script =
                spaces_protocol::script::SpaceScript::create_set_fallback(data.as_slice());

            cli.send_request(
                Some(RpcWalletRequest::Execute(ExecuteParams {
                    context: vec![space],
                    space_script,
                })),
                None,
                fee_rate,
                false,
            )
            .await?;
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
        Commands::SignEvent {
            mut space,
            input,
            anchor,
        } => {
            let mut event = read_event(input)
                .map_err(|e| ClientError::Custom(format!("input error: {}", e.to_string())))?;

            space = normalize_space(&space);
            match event.space() {
                None if anchor => event
                    .tags
                    .insert(0, NostrTag(vec!["space".to_string(), space.clone()])),
                Some(tag) => {
                    if tag != space {
                        return Err(ClientError::Custom(format!(
                            "Expected a space tag with value '{}', got '{}'",
                            space, tag
                        )));
                    }
                }
                _ => {}
            };

            let result = cli.sign_event(space, event, anchor, false).await?;
            println!("{}", serde_json::to_string(&result).expect("result"));
        }
        Commands::SignZone {
            space,
            input,
            skip_anchor,
        } => {
            let update = encode_dns_update(&space, input)
                .map_err(|e| ClientError::Custom(format!("Parse error: {}", e)))?;
            let result = cli.sign_event(space, update, !skip_anchor, false).await?;

            println!("{}", serde_json::to_string(&result).expect("result"));
        }
        Commands::RefreshAnchor {
            input,
            prefer_recent,
        } => {
            let event = read_event(input)
                .map_err(|e| ClientError::Custom(format!("input error: {}", e.to_string())))?;
            let space = match event.space() {
                None => {
                    return Err(ClientError::Custom(
                        "Not a space-anchored event (no space tag)".to_string(),
                    ))
                }
                Some(space) => space,
            };

            let mut event = cli
                .client
                .verify_event(&space, event)
                .await
                .map_err(|e| ClientError::Custom(e.to_string()))?;
            event.proof = None;
            event = cli.add_anchor(event, prefer_recent).await?;

            println!("{}", serde_json::to_string(&event).expect("result"));
        }
        Commands::VerifyEvent { space, input } => {
            let event = read_event(input)
                .map_err(|e| ClientError::Custom(format!("input error: {}", e.to_string())))?;
            let event = cli
                .client
                .verify_event(&space, event)
                .await
                .map_err(|e| ClientError::Custom(e.to_string()))?;

            println!("{}", serde_json::to_string(&event).expect("result"));
        }
    }

    Ok(())
}

fn default_rpc_url(chain: &ExtendedNetwork) -> String {
    format!("http://127.0.0.1:{}", default_spaces_rpc_port(chain))
}

fn encode_dns_update(space: &str, zone_file: Option<PathBuf>) -> anyhow::Result<NostrEvent> {
    // domain crate panics if zone doesn't end in a new line
    let zone = get_input(zone_file)? + "\n";

    let mut builder = MessageBuilder::from_target(TreeCompressor::new(Vec::new()))?.authority();

    builder.header_mut().set_opcode(Opcode::UPDATE);

    let mut cursor = Cursor::new(zone);
    let mut reader = Zonefile::load(&mut cursor)?;

    while let Some(entry) = reader
        .next_entry()
        .or_else(|e| Err(anyhow!("Error reading zone entry: {}", e)))?
    {
        if let Entry::Record(record) = &entry {
            builder.push(record)?;
        }
    }

    let msg = builder.finish();
    Ok(NostrEvent::new(
        871_222,
        &base64::prelude::BASE64_STANDARD.encode(msg.as_slice()),
        vec![NostrTag(vec!["space".to_string(), space.to_string()])],
    ))
}

fn read_event(file: Option<PathBuf>) -> anyhow::Result<NostrEvent> {
    let content = get_input(file)?;
    let event: NostrEvent = serde_json::from_str(&content)?;
    Ok(event)
}

// Helper to handle file or stdin input
fn get_input(input: Option<PathBuf>) -> anyhow::Result<String> {
    Ok(match input {
        Some(file) => fs::read_to_string(file)?,
        None => {
            let input = io::stdin();
            match input.is_terminal() {
                true => return Err(anyhow!("no input provided: specify file path or stdin")),
                false => input.lines().collect::<Result<String, _>>()?,
            }
        }
    })
}
