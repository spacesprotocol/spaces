extern crate core;

use std::{fs, path::PathBuf};
use std::fs::File;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::anyhow;
use clap::{Parser, Subcommand};
use colored::{Color, Colorize};
use domain::base::{MessageBuilder, Name, ParsedName, Record, Serial, ToName, TreeCompressor};
use domain::base::iana::Opcode;
use domain::dep::octseq::OctetsBuilder;
use domain::rdata::{Soa, ZoneRecordData};
use domain::zonefile::inplace::{Entry, ScannedRecordData, Zonefile};
use jsonrpsee::{
    core::{client::Error, ClientError},
    http_client::{HttpClient, HttpClientBuilder},
};
use serde::{Deserialize, Serialize};
use spaces_client::{config::{default_spaces_rpc_port, ExtendedNetwork}, serialize_base64, deserialize_base64, format::{
    print_error_rpc_response, print_list_bidouts, print_list_spaces_response,
    print_list_transactions, print_list_unspent, print_server_info,
    print_wallet_balance_response, print_wallet_info, print_wallet_response, Format,
}, rpc::{
    BidParams, ExecuteParams, OpenParams, RegisterParams, RpcClient, RpcWalletRequest,
    RpcWalletTxBuilder, SendCoinsParams, SignedMessage, TransferSpacesParams,
}, wallets::{AddressKind, WalletResponse}};
use spaces_protocol::{bitcoin::{Amount, FeeRate, OutPoint, Txid}};
use spaces_protocol::bitcoin::consensus::Encodable;
use spaces_protocol::bitcoin::VarInt;
use spaces_wallet::{bitcoin::secp256k1::schnorr::Signature, export::WalletExport, Listing};


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
    spaced_rpc_url: Option<String>,
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
    /// Generate a new wallet
    #[command(name = "createwallet")]
    CreateWallet,
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
    /// Sign a message using the owner address of the specified space
    #[command(name = "signmessage")]
    SignMessage {
        /// The space to use
        space: String,
        /// The message to sign
        message: String,
    },
    /// Verify a message using the owner address of the specified space
    #[command(name = "verifymessage")]
    VerifyMessage {
        /// The space to verify
        space: String,

        /// The message to verify
        message: String,

        /// The signature to verify
        #[arg(long)]
        signature: String,
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
    /// Sign a zone file turning it into a signed DNS UPDATE packet
    #[command(name = "signzone")]
    SignZone {
        /// The DNS zone file path
        zone: PathBuf,
        /// When set, preserves the zone serial (default is false, meaning the serial is updated automatically)
        #[arg(long)]
        preserve_serial: bool,
        /// Skip including bundled Merkle proof information in the packet.
        #[arg(long)]
        skip_proof: bool,
    },
    // Verifies the DNS packet and updates authentication data
    #[command(name = "refreshpacket")]
    RefreshPacket {
        /// Path to the signed .packet.json file
        packet: PathBuf,
        /// Prefer the most recent proof (not recommended)
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

#[derive(Serialize, Deserialize)]
struct SignedDnsUpdate {
    serial: u32,
    space: String,
    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    packet: Vec<u8>,
    signature: Signature,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<Base64Bytes>,
}

#[derive(Serialize, Deserialize)]
struct Base64Bytes(
    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    Vec<u8>
);

struct DnsUpdate {
    space: String,
    serial: u32,
    packet: Vec<u8>,
}

impl SpaceCli {
    async fn configure() -> anyhow::Result<(Self, Args)> {
        let mut args = Args::parse();
        if args.spaced_rpc_url.is_none() {
            args.spaced_rpc_url = Some(default_spaced_rpc_url(&args.chain));
        }

        let client = HttpClientBuilder::default().build(args.spaced_rpc_url.clone().unwrap())?;
        Ok((
            Self {
                wallet: args.wallet.clone(),
                format: args.output_format,
                dust: args.dust.map(|d| Amount::from_sat(d)),
                force: args.force,
                skip_tx_check: args.skip_tx_check,
                network: args.chain,
                rpc_url: args.spaced_rpc_url.clone().unwrap(),
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

async fn handle_commands(
    cli: &SpaceCli,
    command: Commands,
) -> std::result::Result<(), ClientError> {
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
        Commands::CreateWallet => {
            cli.client.wallet_create(&cli.wallet).await?;
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
        Commands::SignMessage { mut space, message } => {
            space = normalize_space(&space);
            let result = cli
                .client
                .wallet_sign_message(
                    &cli.wallet,
                    &space,
                    spaces_protocol::Bytes::new(message.as_bytes().to_vec()),
                )
                .await?;
            println!("{}", result.signature);
        }
        Commands::VerifyMessage {
            mut space,
            message,
            signature,
        } => {
            space = normalize_space(&space);
            let raw = hex::decode(signature)
                .map_err(|_| ClientError::Custom("Invalid signature".to_string()))?;
            let signature = Signature::from_slice(raw.as_slice())
                .map_err(|_| ClientError::Custom("Invalid signature".to_string()))?;
            cli.client
                .verify_message(SignedMessage {
                    space,
                    message: spaces_protocol::Bytes::new(message.as_bytes().to_vec()),
                    signature,
                })
                .await?;
            println!("{} Message verified", "✓".color(Color::Green));
        }
        Commands::SignZone { zone, preserve_serial, skip_proof } => {
            let update = encode_dns_update(&zone, preserve_serial)
                .map_err(|e| ClientError::Custom(format!("Parse error: {}", e)))?;

            let signable = dns_update_signable(update.serial, &update.packet);
            let spaceout = cli.client.get_space(&update.space).await
                .map_err(|e| ClientError::Custom(e.to_string()))?
                .ok_or(ClientError::Custom(format!("Space not found \"{}\"", update.space)))?;

            let result = cli
                .client
                .wallet_sign_message(
                    &cli.wallet,
                    &update.space,
                    spaces_protocol::Bytes::new(signable),
                )
                .await?;

            let proof = match skip_proof {
                true => None,
                false => Some(
                    cli.client.prove_spaceout(OutPoint {
                        txid: spaceout.txid,
                        vout: spaceout.spaceout.n as _,
                    }, Some(false)).await.map_err(|e| ClientError::Custom(e.to_string()))?.proof
                ),
            };

            let signed = SignedDnsUpdate {
                serial: update.serial,
                space: update.space,
                packet: update.packet,
                signature: result.signature,
                proof: proof.map(|p| Base64Bytes(p)),
            };

            let out = serde_json::to_vec_pretty(&signed).unwrap();
            let path = zone.with_extension("packet.json");
            fs::write(&path, out).map_err(|e| ClientError::Custom(e.to_string()))?;
            println!("{} DNS Packet signed: {} (serial: {})", "✓".color(Color::Green), path.as_path().display(), signed.serial);
        }
        Commands::RefreshPacket { packet: packet_path, prefer_recent } => {
            let (soa_owner, mut signed) =
                parse_packet_and_soa_owner(&packet_path)
                    .map_err(|e| ClientError::Custom(e.to_string()))?;

            if soa_owner != signed.space {
                return Err(
                    ClientError::Custom(
                        format!("Invalid packet space name \"{}\" != \"{}\" SOA owner", signed.space, soa_owner)
                    )
                );
            }

            let signable = dns_update_signable(signed.serial, &signed.packet);
            cli.client
                .verify_message(SignedMessage {
                    space: soa_owner.clone(),
                    message: spaces_protocol::Bytes::new(signable),
                    signature: signed.signature,
                })
                .await?;

            let spaceout = cli.client.get_space(&soa_owner).await
                .map_err(|e| ClientError::Custom(e.to_string()))?
                .ok_or(ClientError::Custom(format!("Space not found \"{}\"", soa_owner)))?;

            let raw_subtree = cli.client.prove_spaceout(OutPoint {
                txid: spaceout.txid,
                vout: spaceout.spaceout.n as _,
            }, Some(prefer_recent)).await.map_err(|e| ClientError::Custom(e.to_string()))?.proof;
            signed.proof = Some(Base64Bytes(raw_subtree));

            let out = serde_json::to_vec_pretty(&signed).unwrap();
            fs::write(&packet_path, out).map_err(|e| ClientError::Custom(e.to_string()))?;
            println!("{} Refreshed packet: {}", "✓".color(Color::Green), packet_path.as_path().display());
        }
    }

    Ok(())
}

fn default_spaced_rpc_url(chain: &ExtendedNetwork) -> String {
    format!("http://127.0.0.1:{}", default_spaces_rpc_port(chain))
}

fn generate_dns_zone_serial() -> u32 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Clock may have gone backwards")
        .as_secs();

    now as u32
}

fn dns_update_signable(serial: u32, packet: &Vec<u8>) -> Vec<u8> {
    let mut signable = Vec::new();

    // Write sequence as compact int
    VarInt::from(serial)
        .consensus_encode(&mut signable)
        .expect("encoded varint");

    // Write the packet length
    VarInt::from(packet.as_slice().len())
        .consensus_encode(&mut signable)
        .expect("encoded varint");
    // Write the DNS update packet
    signable.append_slice(packet.as_slice()).expect("buffer");
    signable
}
fn parse_packet_and_soa_owner(packet_file: &Path) -> anyhow::Result<(String, SignedDnsUpdate)> {
    let file = fs::read_to_string(packet_file)?;
    let packet: SignedDnsUpdate = serde_json::from_str(&file)?;
    let message = domain::base::Message::from_octets(&packet.packet)?;

    let mut space = None;
    for record in message.authority()? {
        let record = record?;
        if let Ok(Some(record)) = record
            .into_record::<ZoneRecordData<_, ParsedName<_>>>()
        {
            match record.data() {
                ZoneRecordData::Soa(_) => space = Some(record.owner().to_string()),
                _ => continue,
            }
        }
    }

    let space = space.ok_or(anyhow!("Space name not found in packet"))?;
    Ok((space, packet))
}

fn encode_dns_update(zone_file: &Path, preserve_serial: bool) -> anyhow::Result<DnsUpdate> {
    let mut builder = MessageBuilder::from_target(
        TreeCompressor::new(
            Vec::new()
        )
    )?.authority();

    let mut space = None;
    builder.header_mut().set_opcode(Opcode::UPDATE);

    let mut reader =
        Zonefile::load(&mut File::open(&zone_file)?)?;

    let mut serial = 0;
    while let Some(entry) = reader.next_entry()
        .or_else(|e| Err(anyhow!("Error reading zone entry: {}", e)))? {
        if let Entry::Record(record) = &entry {
            match record.data() {
                ScannedRecordData::Soa(data) => {
                    if space.is_some() {
                        return Err(anyhow!("Multiple SOA records"));
                    }

                    space = Some(record.owner().clone().to_string());
                    serial = match preserve_serial {
                        true => data.serial().into_int(),
                        false => generate_dns_zone_serial(),
                    };

                    let record_serial = Serial::from(serial);
                    let record =
                        Record::new(
                            record.owner().try_to_name::<Vec<u8>>()?,
                            record.class(),
                            record.ttl(),
                            ZoneRecordData::<Vec<u8>, Name<Vec<u8>>>::Soa(
                                Soa::new(
                                    data.mname().try_to_name()?,
                                    data.rname().try_to_name()?,
                                    record_serial,
                                    data.refresh(),
                                    data.retry(),
                                    data.expire(),
                                    data.minimum(),
                                )),
                        );

                    builder.push(record)?;
                }
                _ => {
                    builder.push(record)?;
                }
            };
        }
    }

    if space.is_none() {
        return Err(anyhow!("SOA record is required"));
    }

    let msg = builder.finish();
    Ok(DnsUpdate {
        space: space.unwrap(),
        serial,
        packet: msg.into_target(),
    })
}
