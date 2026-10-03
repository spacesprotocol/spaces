extern crate core;

use std::{
    cmp::Ordering,
    fs, io,
    io::{BufRead, IsTerminal, Write},
    path::PathBuf,
};
use std::str::FromStr;
use anyhow::anyhow;
use clap::{Parser, Subcommand, ValueEnum};
use colored::{Color, Colorize};
use jsonrpsee::{
    core::{client::Error, ClientError},
    http_client::HttpClient,
};
use spaces_client::rpc::{
    CommitParams, CreateNumParams, DelegateParams, OperateParams, SetFallbackParams, UnbindParams,
};
use spaces_client::{
    auth::{auth_token_from_cookie, auth_token_from_creds, http_client_with_auth},
    config::{default_cookie_path, default_spaces_rpc_port, ExtendedNetwork},
    fallback_payload::FallbackDataFlags,
    format::{
        print_create_num_bindings_from_events, print_error_rpc_response, print_list_bidouts,
        print_list_nums_response, print_list_spaces_response, print_list_transactions,
        print_list_unspent, print_list_wallets, print_server_info,
        print_wallet_balance_response, print_wallet_info, print_wallet_response, Format,
    },
    rpc::{
        BidParams, OpenParams, RegisterParams, RpcClient, RpcWalletRequest,
        RpcWalletTxBuilder, SendCoinsParams, Subject, TransferSpacesParams,
    },
    store::Sha256,
    wallets::{AddressKind, ListNumsResponse, ListSpacesResponse, TxtRecordFilter, WalletResponse},
};
use spaces_protocol::bitcoin::{Amount, FeeRate, OutPoint, Txid};
use spaces_protocol::{Covenant, FullSpaceOut};
use spaces_protocol::slabel::SLabel;
use spaces_nums::num_id::NumId;
use spaces_wallet::{bitcoin::secp256k1::schnorr::Signature, export::WalletExport, nostr::NostrEvent, Listing};
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
    /// Get all defined spaces
    #[command(name = "getallspaces")]
    GetAllSpaces {
        /// Only return spaces that have reached expiration
        #[arg(long)]
        expired: bool,
    },
    /// Get all known nums on the indexed chain (no wallet).
    ///
    /// Optional `--filter KEY=VALUE` keeps nums with a SIP-7 TXT record for KEY.
    /// Use `*` to match any value, or a substring such as `nsite-gateway`.
    ///
    /// Examples:
    ///   space-cli getallnums --filter type=*
    ///   space-cli getallnums --filter type=nsite-gateway
    #[command(name = "getallnums")]
    GetAllNums {
        /// Filter by SIP-7 TXT record: `type=*` (any value) or `type=nsite-gateway`
        /// (value contains that string).
        #[arg(long, value_name = "KEY=VALUE")]
        filter: Option<TxtRecordFilter>,
    },
    /// Create a new num.
    ///
    /// Optional SIP-7 fallback data can be attached in the same transaction using
    /// `--txt`, `--addr`, `--blob`, `--raw`, or `--stdin` (same format as `setfallback`).
    ///
    /// Examples:
    ///   space-cli createnum --txt btc=bc1q... --dry-run
    #[command(name = "createnum")]
    CreateNum {
        /// Optional script public key as hex string.
        /// If omitted, a unique address is generated automatically.
        #[arg(long)]
        bind_spk: Option<String>,

        #[command(flatten)]
        fallback: FallbackDataFlags,

        #[arg(long, short)]
        fee_rate: Option<u64>,
        /// Print hex of the OP_RETURN data payload (SIP-7 bytes) and the raw
        /// transaction that would be broadcast, then exit without broadcasting.
        #[arg(long)]
        dry_run: bool,
    },
    /// Get num info, including parsed SIP-7 records when on-chain data is valid
    #[command(name = "getnum")]
    GetNum {
        /// Space name, numeric, or num id
        subject: Subject,
    },
    /// Unbind nums: spend them with no successor so they go dormant.
    /// A dormant num can be revived at its death spk with `createnum`.
    #[command(name = "unbind")]
    Unbind {
        /// Nums to unbind (e.g., num1... or #800000-3-1)
        subjects: Vec<Subject>,
        /// Read hex-encoded secret key from stdin for unbinding nums not owned by wallet
        #[arg(long)]
        secret_stdin: bool,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: Option<u64>,
    },
    /// Get the rebind parked at a script pubkey (a num that died there,
    /// revivable with `createnum --bind-spk <hex>`), if any
    #[command(name = "getrebind")]
    GetRebind {
        /// Script public key as hex string
        script_pubkey: String,
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
        /// The space (@bitcoin), numeric (#800000-3-1), or num id (num1...) to sell
        subject: String,
        /// Amount in satoshis
        price: u64,
    },
    /// Buy a space or num from the specified listing
    #[command(name = "buy")]
    Buy {
        /// The space (@bitcoin), numeric (#800000-3-1), or num id (num1...) to buy
        subject: String,
        /// The listing price
        price: u64,
        /// The seller's signature
        #[arg(long)]
        signature: String,
        /// The seller's address
        #[arg(long)]
        seller: String,
        /// Deliver the space/num to this address instead of the wallet's own
        /// (e.g. an external keystore)
        #[arg(long)]
        to: Option<String>,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: Option<u64>,
    },
    /// Fund and broadcast one or more externally-signed transfer PSBTs.
    /// Each PSBT must be a single input/output pair signed with
    /// SIGHASH_SINGLE|ANYONECANPAY whose input value equals its output value;
    /// the wallet adds fee inputs and change and broadcasts one transaction.
    #[command(name = "fundtransfer")]
    FundTransfer {
        /// Base64-encoded PSBT(s), one per transfer to batch into the tx
        #[arg(required = true)]
        psbts: Vec<String>,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: Option<u64>,
    },
    /// Verify a listing
    #[command(name = "verifylisting")]
    VerifyListing {
        /// The space (@bitcoin), numeric (#800000-3-1), or num id (num1...)
        subject: String,
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
    /// Show the node's trust id (as an ASCII QR code) for clients to pin.
    ///
    /// The trust id commits to the most recent window of root anchors. By
    /// default the latest id is shown with a QR; use --all to list every id
    /// or --json for the raw list.
    Trust {
        /// List all trust ids (newest first) instead of just the latest.
        #[arg(long)]
        all: bool,
        /// Print the raw JSON list of trust ids.
        #[arg(long)]
        json: bool,
        /// Print only the hex id(s), without the QR code.
        #[arg(long)]
        no_qr: bool,
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
    ///   space-cli setfallback @alice --addr btc=bc1q...,bc1qother
    ///   space-cli setfallback @alice --raw SGVsbG8=
    ///   echo '[{"type":"txt","key":"btc","value":["bc1q..."]}]' | space-cli setfallback @alice --stdin
    ///   space-cli setfallback @alice --txt btc=bc1q... --dry-run
    #[command(name = "setfallback")]
    SetFallback {
        /// Space name, numeric, or num id
        subject: Subject,

        #[command(flatten)]
        fallback: FallbackDataFlags,

        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: Option<u64>,
        /// Print hex of the OP_RETURN data payload (SIP-7 bytes) and the raw
        /// transaction that would be broadcast, then exit without broadcasting.
        #[arg(long)]
        dry_run: bool,
    },
    /// Get on-chain fallback record data for a space or num.
    #[command(name = "getfallback")]
    GetFallback {
        /// Space name, numeric, or num id
        subject: Subject,
    },
    /// Sign a Nostr event using the space's private key
    #[command(name = "signevent")]
    SignEvent {
        /// Space name (e.g., @example)
        space: String,
        /// Path to a Nostr event JSON file (omit for stdin)
        #[arg(short, long)]
        input: Option<PathBuf>,
    },
    /// Export the Nostr nsec and raw private key for a space or num
    /// (same key used by signevent)
    #[command(name = "getnsec")]
    GetNsec {
        /// Space (@example), numeric (#800000-3), or num id (num1...)
        #[arg(value_name = "SPACE|NUM")]
        subject: Subject,
    },
    /// Export the taproot-tweaked private key (hex) for a space or num
    #[command(name = "getprivtweak")]
    GetPrivTweak {
        /// Space (@example), numeric (#800000-3), or num id (num1...)
        #[arg(value_name = "SPACE|NUM")]
        subject: Subject,
    },
    /// Verify a signed Nostr event against the space's or numeric's public key
    #[command(name = "verifyevent")]
    VerifyEvent {
        /// Space or numeric subject (e.g., @example)
        space: String,
        /// Path to a signed Nostr event JSON file (omit for stdin)
        #[arg(short, long)]
        input: Option<PathBuf>,
    },
    /// List last transactions
    #[command(name = "listtransactions")]
    ListTransactions {
        #[arg(default_value = "10")]
        count: usize,
        #[arg(default_value = "0")]
        skip: usize,
    },
    /// List won spaces including ones still in auction with a winning bid.
    ///
    /// `--not-operated` keeps owned spaces with no live operator num.
    /// `--operated` keeps owned spaces whose operator num still sits on the
    /// space output. `--delegated` keeps owned spaces whose operator num has
    /// been moved to another script. Any combination returns the union. With
    /// none of them, the full list is returned.
    ///
    /// `--sortby` orders every section that is still present. `space_name`
    /// sorts A–Z. `days_left` sorts soonest expiry or claim first. `--reverse`
    /// flips that order.
    #[command(name = "listspaces")]
    ListSpaces {
        /// Owned spaces that have not been operated
        #[arg(long)]
        not_operated: bool,
        /// Owned spaces that have been operated and not delegated
        #[arg(long)]
        operated: bool,
        /// Owned spaces that have been operated and then delegated
        #[arg(long)]
        delegated: bool,
        /// Sort each section by space name or days left
        #[arg(long, value_enum)]
        sortby: Option<ListSpacesSort>,
        /// Reverse the --sortby order
        #[arg(long, requires = "sortby")]
        reverse: bool,
    },
    /// List nums in the wallet.
    ///
    /// With `--spk`, lists matching nums from both owned and external (`--kind` is ignored).
    #[command(
        name = "listnums",
        override_usage = "space-cli listnums [--kind owned|external] [--spk <HEX>]"
    )]
    ListNums {
        /// Nums to list: `owned` (wallet-held outputs) or `external` (created but not owned)
        #[arg(long, value_enum, default_value_t = ListNumsKind::Owned)]
        kind: ListNumsKind,
        /// Hex-encoded script_pubkey; only nums whose output script matches (owned and external)
        #[arg(long, value_name = "HEX")]
        spk: Option<String>,
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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ListSpacesSort {
    /// Alphabetical by space name
    #[value(name = "space_name")]
    SpaceName,
    /// Soonest claim or expiry first
    #[value(name = "days_left")]
    DaysLeft,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ListNumsKind {
    /// Nums the wallet currently owns
    Owned,
    /// Nums created by the wallet but not currently owned
    External,
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
                    dry_run: false,
                },
            )
            .await?;

        print_wallet_response(self.network.fallback_network(), result, self.format);
        Ok(())
    }

    /// Build and sign `req` without broadcasting. Prints each result's raw tx hex.
    async fn send_dry_run(
        &self,
        req: RpcWalletRequest,
        fee_rate: Option<u64>,
    ) -> Result<(), ClientError> {
        let fee_rate = fee_rate.map(|fee| FeeRate::from_sat_per_vb(fee).unwrap());
        let result = self
            .client
            .wallet_send_request(
                &self.wallet,
                RpcWalletTxBuilder {
                    bidouts: None,
                    requests: vec![req],
                    fee_rate,
                    dust: self.dust,
                    force: self.force,
                    confirmed_only: false,
                    skip_tx_check: self.skip_tx_check,
                    dry_run: true,
                },
            )
            .await?;
        let mut printed_raw = false;
        for tx in result.result {
            if let Some(errors) = tx.error {
                return Err(ClientError::Custom(format!(
                    "dry-run tx error: {:?}",
                    errors
                )));
            }
            print_create_num_bindings_from_events(
                self.network.fallback_network(),
                &tx.events,
                "",
            );
            if let Some(raw) = tx.raw {
                println!("{}", raw);
                printed_raw = true;
            }
        }
        if !printed_raw {
            return Err(ClientError::Custom(
                "dry-run: wallet did not return a raw transaction".into(),
            ));
        }
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

/// Normalize a listing subject: @space, #numeric, or num1... — validated and
/// canonicalized via [`Subject`].
fn normalize_subject(subject: &str) -> Result<String, ClientError> {
    spaces_wallet::Subject::from_str(subject)
        .map(|s| s.to_string())
        .map_err(ClientError::Custom)
}

/// Render `data` as an ASCII QR code to stdout. Colors are inverted so the code
/// scans on a typical dark terminal; failure is non-fatal (the caller still
/// prints the hex).
fn print_qr(data: &str) {
    use qrcode::{QrCode, render::unicode};
    match QrCode::new(data.as_bytes()) {
        Ok(code) => {
            let qr = code
                .render::<unicode::Dense1x2>()
                .dark_color(unicode::Dense1x2::Light)
                .light_color(unicode::Dense1x2::Dark)
                .quiet_zone(true)
                .build();
            println!("{qr}");
        }
        Err(err) => eprintln!("could not render QR code: {err}"),
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
        Commands::Trust { all, json, no_qr } => {
            let ids = cli.client.get_trust_ids().await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&ids)?);
            } else if ids.is_empty() {
                println!("No trust ids yet (node still syncing root anchors)");
            } else if all {
                for (i, t) in ids.iter().enumerate() {
                    let tag = if i == 0 { " (latest)" } else { "" };
                    println!("{}  height {}{}", hex::encode(t.id), t.block.height, tag);
                }
            } else {
                let latest = &ids[0];
                let id_hex = hex::encode(latest.id);
                if !no_qr {
                    // Encode the scannable veritas URI, not the bare hex, so a
                    // veritas client recognizes it as a trust id to pin.
                    print_qr(&format!("veritas://scan?id={id_hex}"));
                }
                println!("{}  height {}", id_hex, latest.block.height);
            }
        }
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
            let response = cli.client.estimate_fee(conf_target, mode).await?;
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
        Commands::GetAllSpaces { expired } => {
            let mut spaces = cli.client.get_all_spaces().await?;
            if expired {
                let info = cli.client.get_server_info().await?;
                let current_height = info.tip.height;
                spaces.retain(|fso| {
                    fso.spaceout.space.as_ref()
                        .map_or(false, |s| s.is_expired(current_height))
                });
            }
            println!("{}", serde_json::to_string_pretty(&spaces)?);
        }
        Commands::GetAllNums { filter } => {
            let mut nums = cli.client.get_all_nums().await?;
            if let Some(filter) = filter {
                nums.nums.retain(|entry| entry.matches_txt_filter(&filter));
            }
            println!("{}", serde_json::to_string_pretty(&nums)?);
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
            println!("{}", response);
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
            fallback,
            fee_rate,
            dry_run,
        } => {
            let data = fallback.required_payload().map_err(|e| ClientError::Custom(e.to_string()))?;

            if dry_run {
                println!("{}", hex::encode(&data));
                cli.send_dry_run(
                    RpcWalletRequest::SetFallback(SetFallbackParams { subject, data }),
                    fee_rate,
                )
                .await?;
            } else {
                cli.send_request(
                    Some(RpcWalletRequest::SetFallback(SetFallbackParams { subject, data })),
                    None,
                    fee_rate,
                    false,
                )
                .await?;
            }
        }
        Commands::GetFallback {
            subject,
        } => {
            let response = cli.client.get_fallback(subject).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Commands::SignEvent { mut space, input } => {
            let event = read_event(input)
                .map_err(|e| ClientError::Custom(format!("input error: {}", e)))?;
            space = normalize_space(&space);
            let subject = Subject::from_str(&space)
                .map_err(|e| ClientError::Custom(e.to_string()))?;
            let result = cli
                .client
                .wallet_sign_event(&cli.wallet, subject, event)
                .await?;
            println!("{}", serde_json::to_string(&result).expect("result"));
        }
        Commands::GetNsec { subject } => {
            let key = cli
                .client
                .wallet_get_nsec(&cli.wallet, subject)
                .await?;
            match cli.format {
                Format::Json => println!("{}", serde_json::to_string_pretty(&key)?),
                Format::Text => {
                    println!("nsec: {}", key.nsec);
                    println!("hex: {}", key.hex);
                }
            }
        }
        Commands::GetPrivTweak { subject } => {
            let key = cli
                .client
                .wallet_get_priv_tweak(&cli.wallet, subject)
                .await?;
            println!("{key}");
        }
        Commands::VerifyEvent { mut space, input } => {
            let event = read_event(input)
                .map_err(|e| ClientError::Custom(format!("input error: {}", e)))?;
            space = normalize_space(&space);
            let subject = Subject::from_str(&space)
                .map_err(|e| ClientError::Custom(e.to_string()))?;
            let event = cli
                .client
                .verify_event(subject, event)
                .await
                .map_err(|e| ClientError::Custom(e.to_string()))?;
            println!("{}", serde_json::to_string(&event).expect("result"));
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
        Commands::ListSpaces {
            not_operated,
            operated,
            delegated,
            sortby,
            reverse,
        } => {
            let tip = cli.client.get_server_info().await?;
            let spaces = cli.client.wallet_list_spaces(&cli.wallet).await?;
            let mut spaces =
                filter_list_spaces(&cli.client, spaces, not_operated, operated, delegated).await?;
            sort_list_spaces(&mut spaces, tip.tip.height, sortby, reverse);
            print_list_spaces_response(tip.tip.height, spaces, cli.format);
        }
        Commands::ListNums { kind, spk } => {
            if let Some(hex) = spk {
                let spk_script = ScriptBuf::from(
                    hex::decode(hex.trim()).map_err(|_| {
                        ClientError::Custom("Invalid --spk hex (expected script_pubkey bytes)".to_string())
                    })?,
                );
                let owned = cli.client.wallet_list_nums(&cli.wallet, None).await?;
                let external = cli
                    .client
                    .wallet_list_nums(&cli.wallet, Some("external".to_string()))
                    .await?;
                let mut nums: Vec<_> = owned
                    .nums
                    .into_iter()
                    .chain(external.nums)
                    .filter(|e| e.numout.script_pubkey == spk_script)
                    .collect();
                nums.sort_by_key(|e| (e.txid, e.numout.n));
                nums.dedup_by_key(|e| (e.txid, e.numout.n));
                print_list_nums_response(ListNumsResponse { nums }, cli.format);
            } else {
                let kind = match kind {
                    ListNumsKind::Owned => None,
                    ListNumsKind::External => Some("external".to_string()),
                };
                let nums = cli.client.wallet_list_nums(&cli.wallet, kind).await?;
                print_list_nums_response(nums, cli.format);
            }
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
            subject,
            price,
            signature,
            seller,
            to,
            fee_rate,
        } => {
            let listing = Listing {
                subject: normalize_subject(&subject)?,
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
                    to,
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
        Commands::FundTransfer { psbts, fee_rate } => {
            let result = cli
                .client
                .wallet_fund_transfer(
                    &cli.wallet,
                    psbts,
                    fee_rate.map(|rate| FeeRate::from_sat_per_vb(rate).expect("valid fee rate")),
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
        Commands::Sell { subject, price } => {
            let subject = normalize_subject(&subject)?;
            let result = cli.client.wallet_sell(&cli.wallet, subject, price).await?;
            println!("{}", serde_json::to_string_pretty(&result).expect("result"));
        }
        Commands::VerifyListing {
            subject,
            price,
            signature,
            seller,
        } => {
            let listing = Listing {
                subject: normalize_subject(&subject)?,
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
        Commands::CreateNum {
            bind_spk,
            fallback,
            fee_rate,
            dry_run,
        } => {
            if dry_run {
                let data = fallback.required_payload().map_err(|e| ClientError::Custom(e.to_string()))?;
                println!("{}", hex::encode(&data));

                let spk = match bind_spk {
                    Some(hex) => {
                        let spk = ScriptBuf::from(hex::decode(hex)
                            .map_err(|_| ClientError::Custom("Invalid spk hex".to_string()))?);
                        Some(spk)
                    }
                    None => None,
                };
                cli.send_dry_run(
                    RpcWalletRequest::CreateNum(CreateNumParams {
                        bind_spk: spk,
                        data: Some(data),
                    }),
                    fee_rate,
                )
                .await?;
            } else {
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
                let data = fallback
                    .optional_payload()
                    .map_err(|e| ClientError::Custom(e.to_string()))?;
                cli.send_request(
                    Some(RpcWalletRequest::CreateNum(CreateNumParams { bind_spk: spk, data })),
                    None,
                    fee_rate,
                    false,
                )
                .await?
            }
        }
        Commands::GetNum { subject } => {
            let num = cli
                .client
                .get_num(subject)
                .await
                .map_err(|e| ClientError::Custom(e.to_string()))?;
            println!("{}", serde_json::to_string_pretty(&num).expect("result"));
        }
        Commands::Unbind {
            subjects,
            secret_stdin,
            fee_rate,
        } => {
            let secret = if secret_stdin {
                let mut input = String::new();
                io::stdin().read_line(&mut input).map_err(|e| {
                    ClientError::Custom(format!("failed to read secret from stdin: {}", e))
                })?;
                Some(input.trim().to_string())
            } else {
                None
            };
            cli.send_request(
                Some(RpcWalletRequest::Unbind(UnbindParams { subjects, secret })),
                None,
                fee_rate,
                false,
            )
            .await?;
            println!(
                "Num(s) go dormant once the tx confirms; revive with `createnum --bind-spk <death spk>`"
            );
        }
        Commands::GetRebind { script_pubkey } => {
            let spk = ScriptBuf::from(
                hex::decode(script_pubkey)
                    .map_err(|_| ClientError::Custom("Invalid spk hex".to_string()))?,
            );
            let rebind = cli
                .client
                .get_rebind(spk)
                .await
                .map_err(|e| ClientError::Custom(e.to_string()))?;
            println!("{}", serde_json::to_string(&rebind).expect("result"));
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum OperatorState {
    /// Owned, but no live operator num.
    NotOperated,
    /// Operator num still sits on the space output.
    Operated,
    /// Operator num has been moved to another script.
    Delegated,
}

/// Keep owned spaces by operator state.
///
/// A space is not operated when it has no live operator num. It is operated
/// when `get_delegation` names a live num whose script is still the space
/// output. It is delegated when that num has been moved. Auction rows are
/// dropped whenever any flag is set. Multiple flags return the union.
async fn filter_list_spaces(
    client: &HttpClient,
    mut response: ListSpacesResponse,
    not_operated: bool,
    operated: bool,
    delegated: bool,
) -> Result<ListSpacesResponse, ClientError> {
    if !not_operated && !operated && !delegated {
        return Ok(response);
    }

    response.pending.clear();
    response.winning.clear();
    response.outbid.clear();

    let mut owned = Vec::with_capacity(response.owned.len());
    for space in response.owned {
        let state = operator_state(&client, &space).await?;
        let keep = (not_operated && state == OperatorState::NotOperated)
            || (operated && state == OperatorState::Operated)
            || (delegated && state == OperatorState::Delegated);
        if keep {
            owned.push(space);
        }
    }
    response.owned = owned;
    Ok(response)
}

async fn operator_state(
    client: &HttpClient,
    space: &FullSpaceOut,
) -> Result<OperatorState, ClientError> {
    let Some(name) = space.spaceout.space.as_ref().map(|s| s.name.clone()) else {
        return Ok(OperatorState::NotOperated);
    };
    let Some(id) = client
        .get_delegation(Subject::Label(name))
        .await
        .map_err(|e| ClientError::Custom(e.to_string()))?
    else {
        return Ok(OperatorState::NotOperated);
    };
    let Some(num) = client
        .get_num(Subject::NumId(id))
        .await
        .map_err(|e| ClientError::Custom(e.to_string()))?
    else {
        return Ok(OperatorState::NotOperated);
    };
    if num.numout.script_pubkey != space.spaceout.script_pubkey {
        Ok(OperatorState::Delegated)
    } else {
        Ok(OperatorState::Operated)
    }
}

/// Sort every section that is still present. `days_left` uses claim height
/// for auctions and `expire_height` for owned spaces. Pending rows have no
/// height, so `days_left` orders them by name. Equal keys stay A–Z by name.
fn sort_list_spaces(
    response: &mut ListSpacesResponse,
    current_block: u32,
    sortby: Option<ListSpacesSort>,
    reverse: bool,
) {
    let Some(sortby) = sortby else {
        return;
    };
    match sortby {
        ListSpacesSort::SpaceName => {
            response.pending.sort_by(|a, b| {
                directed(a.to_string().cmp(&b.to_string()), reverse)
            });
            sort_full_spaces(&mut response.outbid, |a, b| {
                directed(space_name(a).cmp(&space_name(b)), reverse)
            });
            sort_full_spaces(&mut response.winning, |a, b| {
                directed(space_name(a).cmp(&space_name(b)), reverse)
            });
            sort_full_spaces(&mut response.owned, |a, b| {
                directed(space_name(a).cmp(&space_name(b)), reverse)
            });
        }
        ListSpacesSort::DaysLeft => {
            response.pending.sort_by(|a, b| {
                directed(a.to_string().cmp(&b.to_string()), reverse)
            });
            let by_days = |a: &FullSpaceOut, b: &FullSpaceOut| {
                let primary = match (blocks_remaining(a, current_block), blocks_remaining(b, current_block)) {
                    (Some(left), Some(right)) => left.cmp(&right),
                    (Some(_), None) => Ordering::Less,
                    (None, Some(_)) => Ordering::Greater,
                    (None, None) => Ordering::Equal,
                };
                directed(primary, reverse).then_with(|| space_name(a).cmp(&space_name(b)))
            };
            sort_full_spaces(&mut response.outbid, by_days);
            sort_full_spaces(&mut response.winning, by_days);
            sort_full_spaces(&mut response.owned, by_days);
        }
    }
}

fn sort_full_spaces(spaces: &mut [FullSpaceOut], cmp: impl Fn(&FullSpaceOut, &FullSpaceOut) -> Ordering) {
    spaces.sort_by(cmp);
}

fn directed(order: Ordering, reverse: bool) -> Ordering {
    if reverse { order.reverse() } else { order }
}

fn space_name(space: &FullSpaceOut) -> String {
    space
        .spaceout
        .space
        .as_ref()
        .map(|s| s.name.to_string())
        .unwrap_or_default()
}

/// Blocks until claim (auction) or expiry (owned). `None` when the covenant
/// has no target height.
fn blocks_remaining(space: &FullSpaceOut, current_block: u32) -> Option<i64> {
    let height = match space.spaceout.space.as_ref()?.covenant {
        Covenant::Transfer { expire_height, .. } => Some(expire_height),
        Covenant::Bid { claim_height, .. } => claim_height,
        Covenant::Reserved => None,
    }?;
    Some(height as i64 - current_block as i64)
}

fn default_rpc_url(chain: &ExtendedNetwork) -> String {
    format!("http://127.0.0.1:{}", default_spaces_rpc_port(chain))
}

fn read_event(file: Option<PathBuf>) -> anyhow::Result<NostrEvent> {
    let content = get_input(file)?;
    let event: NostrEvent = serde_json::from_str(&content)?;
    Ok(event)
}

fn get_input(input: Option<PathBuf>) -> anyhow::Result<String> {
    Ok(match input {
        Some(file) => fs::read_to_string(file)?,
        None => {
            let stdin = io::stdin();
            if stdin.is_terminal() {
                return Err(anyhow!("no input provided: specify a file path or pipe via stdin"));
            }
            stdin.lock().lines().collect::<Result<String, _>>()?
        }
    })
}
