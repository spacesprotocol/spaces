use schemars::schema_for;
use serde::Serialize;
use serde_json::{json, Value};

use crate::rpc::*;
use crate::wallets::*;

#[derive(Serialize, Clone)]
pub struct ParamInfo {
    pub name: &'static str,
    pub description: &'static str,
    pub r#type: &'static str,
    pub required: bool,
    pub example: Value,
}

#[derive(Serialize, Clone)]
pub struct MethodSchema {
    pub name: &'static str,
    pub description: &'static str,
    pub params: Vec<ParamInfo>,
    pub result_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_schema: Option<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub extra_examples: Vec<(&'static str, Value)>,
}

fn param(name: &'static str, r#type: &'static str, description: &'static str, example: Value) -> ParamInfo {
    ParamInfo { name, description, r#type, required: true, example }
}

fn opt_param(name: &'static str, r#type: &'static str, description: &'static str, example: Value) -> ParamInfo {
    ParamInfo { name, description, r#type, required: false, example }
}

fn rpc_request(method: &str, params: &[&ParamInfo]) -> Value {
    let params_array: Vec<Value> = params.iter().map(|p| p.example.clone()).collect();
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params_array,
    })
}

pub fn build_schema() -> Vec<MethodSchema> {
    vec![
        // Server info
        MethodSchema {
            name: "getserverinfo",
            description: "Get server status including network, sync progress, and chain tip",
            params: vec![],
            result_type: "ServerInfo",
            result_schema: Some(serde_json::to_value(schema_for!(ServerInfo)).unwrap()),
            extra_examples: vec![],
        },
        // Space queries
        MethodSchema {
            name: "getspace",
            description: "Get full space output by space name or hash",
            params: vec![param("space_or_hash", "string", "Space name (e.g. \"@example\") or hex hash", json!("@example"))],
            result_type: "Option<FullSpaceOut>",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "getspaceowner",
            description: "Get the outpoint that owns a space",
            params: vec![param("space_or_hash", "string", "Space name (e.g. \"@example\") or hex hash", json!("@example"))],
            result_type: "Option<OutPoint>",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "getspaceout",
            description: "Get a space output by outpoint",
            params: vec![param("outpoint", "OutPoint", "Transaction outpoint (txid:vout)", json!("a]1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d:0"))],
            result_type: "Option<SpaceOut>",
            result_schema: None,
            extra_examples: vec![],
        },
        // Num queries
        MethodSchema {
            name: "getnum",
            description: "Get full num output by numeric id or num id",
            params: vec![param("subject", "Subject", "#numeric or num1... id", json!("#1-2-3"))],
            result_type: "Option<FullNumOut>",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "getnumowner",
            description: "Get the outpoint that owns a num",
            params: vec![param("subject", "Subject", "#numeric or num1... id", json!("#1-2-3"))],
            result_type: "Option<OutPoint>",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "getnumout",
            description: "Get a num output by outpoint",
            params: vec![param("outpoint", "OutPoint", "Transaction outpoint (txid:vout)", json!("a]1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d:0"))],
            result_type: "Option<NumOut>",
            result_schema: None,
            extra_examples: vec![],
        },
        // Commitment/delegation queries
        MethodSchema {
            name: "getcommitment",
            description: "Get commitment for a subject, optionally at a specific root",
            params: vec![
                param("subject", "Subject", "@space, #numeric, or num1... id", json!("@example")),
                opt_param("root", "string", "Specific commitment root hash", json!(null)),
            ],
            result_type: "Option<Commitment>",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "getdelegation",
            description: "Get the operator num id delegated for a subject",
            params: vec![param("subject", "Subject", "@space, #numeric, or num1... id", json!("@example"))],
            result_type: "Option<NumId>",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "getdelegator",
            description: "Get the subject that a num is operating for",
            params: vec![param("subject", "Subject", "#numeric or num1... id of the operator", json!("num1qp..."))],
            result_type: "Option<SLabel>",
            result_schema: None,
            extra_examples: vec![],
        },
        // Transaction/block queries
        MethodSchema {
            name: "checkpackage",
            description: "Simulate a package of transactions and return their changesets",
            params: vec![param("txs", "string[]", "Array of raw transaction hex strings", json!(["0200000001..."]))],
            result_type: "Vec<Option<TxChangeSet>>",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "estimatebid",
            description: "Estimate the minimum bid amount to enter a rollout at the given target",
            params: vec![param("target", "integer", "Target number of blocks ahead", json!(10))],
            result_type: "u64",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "getrollout",
            description: "Get the rollout entries for a given target",
            params: vec![param("target", "integer", "Target number of blocks ahead", json!(10))],
            result_type: "Vec<RolloutEntry>",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "getblockmeta",
            description: "Get spaces block metadata by height or hash",
            params: vec![param("height_or_hash", "integer|string", "Block height or block hash", json!(100))],
            result_type: "BlockMetaWithHash",
            result_schema: Some(serde_json::to_value(schema_for!(BlockMetaWithHash)).unwrap()),
            extra_examples: vec![],
        },
        MethodSchema {
            name: "getnumblockmeta",
            description: "Get nums block metadata by height or hash",
            params: vec![param("height_or_hash", "integer|string", "Block height or block hash", json!(100))],
            result_type: "NumBlockMetaWithHash",
            result_schema: Some(serde_json::to_value(schema_for!(NumBlockMetaWithHash)).unwrap()),
            extra_examples: vec![],
        },
        MethodSchema {
            name: "gettxmeta",
            description: "Get transaction metadata by txid",
            params: vec![param("txid", "string", "Transaction id", json!("a]1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"))],
            result_type: "Option<TxEntry>",
            result_schema: None,
            extra_examples: vec![],
        },
        // Wallet management
        MethodSchema {
            name: "listwallets",
            description: "List all loaded wallet names",
            params: vec![],
            result_type: "string[]",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "walletload",
            description: "Load a wallet by name",
            params: vec![param("name", "string", "Wallet name", json!("default"))],
            result_type: "()",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "walletimport",
            description: "Import a wallet from an export object",
            params: vec![param("wallet", "WalletExport", "Wallet export data", json!({"descriptor": "...", "blockheight": 0, "label": "default"}))],
            result_type: "()",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "walletcanoperate",
            description: "Check if a wallet controls the operator num for a subject",
            params: vec![
                param("wallet", "string", "Wallet name", json!("default")),
                param("subject", "Subject", "@space, #numeric, or num1... id", json!("@example")),
            ],
            result_type: "bool",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "walletsignschnorr",
            description: "Sign a message with a subject's schnorr key",
            params: vec![
                param("wallet", "string", "Wallet name", json!("default")),
                param("subject", "Subject", "@space, #numeric, or num1... id", json!("@example")),
                param("message", "string", "Message bytes (hex)", json!("48656c6c6f")),
            ],
            result_type: "string",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "verifyschnorr",
            description: "Verify a schnorr signature for a subject",
            params: vec![
                param("subject", "Subject", "@space, #numeric, or num1... id", json!("@example")),
                param("message", "string", "Message bytes (hex)", json!("48656c6c6f")),
                param("signature", "string", "Signature bytes (hex)", json!("aabbccdd...")),
            ],
            result_type: "bool",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "walletgetinfo",
            description: "Get wallet info including sync status",
            params: vec![param("name", "string", "Wallet name", json!("default"))],
            result_type: "WalletInfoWithProgress",
            result_schema: Some(serde_json::to_value(schema_for!(WalletInfoWithProgress)).unwrap()),
            extra_examples: vec![],
        },
        MethodSchema {
            name: "walletexport",
            description: "Export a wallet",
            params: vec![param("name", "string", "Wallet name", json!("default"))],
            result_type: "WalletExport",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "walletcreate",
            description: "Create a new wallet, returns the mnemonic phrase",
            params: vec![param("name", "string", "Wallet name", json!("default"))],
            result_type: "string",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "walletrecover",
            description: "Recover a wallet from a mnemonic phrase",
            params: vec![
                param("name", "string", "Wallet name", json!("default")),
                param("mnemonic", "string", "BIP-39 mnemonic phrase", json!("abandon abandon abandon ... about")),
            ],
            result_type: "()",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "walletsendrequest",
            description: "Send a batch of wallet requests (open, bid, register, transfer, etc.)",
            params: vec![
                param("wallet", "string", "Wallet name", json!("default")),
                param("request", "RpcWalletTxBuilder", "Transaction builder with requests", json!({
                    "requests": [{"request": "open", "name": "@example", "amount": 1000}],
                    "fee_rate": 1.0,
                    "force": false,
                    "confirmed_only": false,
                    "skip_tx_check": false,
                })),
            ],
            result_type: "WalletResponse",
            result_schema: Some(serde_json::to_value(schema_for!(RpcWalletTxBuilder)).unwrap()),
            extra_examples: vec![
                ("Bid on a space", json!({
                    "jsonrpc": "2.0", "id": 1,
                    "method": "walletsendrequest",
                    "params": ["default", {
                        "requests": [{"request": "bid", "name": "@example", "amount": 2000}],
                        "fee_rate": 1.0,
                        "force": false,
                        "confirmed_only": false,
                        "skip_tx_check": false,
                    }]
                })),
                ("Register a space", json!({
                    "jsonrpc": "2.0", "id": 1,
                    "method": "walletsendrequest",
                    "params": ["default", {
                        "requests": [{"request": "register", "name": "@example"}],
                        "fee_rate": 1.0,
                        "force": false,
                        "confirmed_only": false,
                        "skip_tx_check": false,
                    }]
                })),
                ("Transfer spaces", json!({
                    "jsonrpc": "2.0", "id": 1,
                    "method": "walletsendrequest",
                    "params": ["default", {
                        "requests": [{"request": "transfer", "spaces": ["@example"], "to": "bc1q..."}],
                        "fee_rate": 1.0,
                        "force": false,
                        "confirmed_only": false,
                        "skip_tx_check": false,
                    }]
                })),
                ("Create a num", json!({
                    "jsonrpc": "2.0", "id": 1,
                    "method": "walletsendrequest",
                    "params": ["default", {
                        "requests": [{"request": "createnum"}],
                        "fee_rate": 1.0,
                        "force": false,
                        "confirmed_only": false,
                        "skip_tx_check": false,
                    }]
                })),
                ("Set up an operator for a space", json!({
                    "jsonrpc": "2.0", "id": 1,
                    "method": "walletsendrequest",
                    "params": ["default", {
                        "requests": [{"request": "operate", "subject": "@example"}],
                        "fee_rate": 1.0,
                        "force": false,
                        "confirmed_only": false,
                        "skip_tx_check": false,
                    }]
                })),
                ("Commit a root hash", json!({
                    "jsonrpc": "2.0", "id": 1,
                    "method": "walletsendrequest",
                    "params": ["default", {
                        "requests": [{"request": "commit", "subject": "@example", "root": "a]1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"}],
                        "fee_rate": 1.0,
                        "force": false,
                        "confirmed_only": false,
                        "skip_tx_check": false,
                    }]
                })),
                ("Delegate operator to another wallet", json!({
                    "jsonrpc": "2.0", "id": 1,
                    "method": "walletsendrequest",
                    "params": ["default", {
                        "requests": [{"request": "delegate", "subject": "@example", "to": "bc1q..."}],
                        "fee_rate": 1.0,
                        "force": false,
                        "confirmed_only": false,
                        "skip_tx_check": false,
                    }]
                })),
                ("Set fallback data", json!({
                    "jsonrpc": "2.0", "id": 1,
                    "method": "walletsendrequest",
                    "params": ["default", {
                        "requests": [{"request": "setfallback", "subject": "@example", "data": [0, 1, 2]}],
                        "fee_rate": 1.0,
                        "force": false,
                        "confirmed_only": false,
                        "skip_tx_check": false,
                    }]
                })),
                ("Send coins", json!({
                    "jsonrpc": "2.0", "id": 1,
                    "method": "walletsendrequest",
                    "params": ["default", {
                        "requests": [{"request": "send", "amount": 50000, "to": "bc1q..."}],
                        "fee_rate": 1.0,
                        "force": false,
                        "confirmed_only": false,
                        "skip_tx_check": false,
                    }]
                })),
            ],
        },
        MethodSchema {
            name: "walletgetnewaddress",
            description: "Get a new address from the wallet",
            params: vec![
                param("wallet", "string", "Wallet name", json!("default")),
                param("kind", "AddressKind", "\"Coin\" or \"Space\"", json!("Coin")),
            ],
            result_type: "string",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "walletincrementaddress",
            description: "Increment and return the next address from the wallet",
            params: vec![
                param("wallet", "string", "Wallet name", json!("default")),
                param("kind", "AddressKind", "\"Coin\" or \"Space\"", json!("Coin")),
            ],
            result_type: "string",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "walletbumpfee",
            description: "Bump the fee of an existing transaction",
            params: vec![
                param("wallet", "string", "Wallet name", json!("default")),
                param("txid", "string", "Transaction id to bump", json!("a]1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d")),
                param("fee_rate", "number", "New fee rate in sat/vB", json!(2.0)),
                param("skip_tx_check", "bool", "Skip transaction validation", json!(false)),
            ],
            result_type: "Vec<TxResponse>",
            result_schema: Some(serde_json::to_value(schema_for!(TxResponse)).unwrap()),
            extra_examples: vec![],
        },
        MethodSchema {
            name: "walletbuy",
            description: "Buy a space from a listing",
            params: vec![
                param("wallet", "string", "Wallet name", json!("default")),
                param("listing", "Listing", "The listing to buy", json!({"space": "@example", "price": 100000, "seller_psbt": "..."})),
                opt_param("fee_rate", "number", "Fee rate in sat/vB", json!(1.0)),
                param("skip_tx_check", "bool", "Skip transaction validation", json!(false)),
            ],
            result_type: "TxResponse",
            result_schema: Some(serde_json::to_value(schema_for!(TxResponse)).unwrap()),
            extra_examples: vec![],
        },
        MethodSchema {
            name: "walletsell",
            description: "Create a listing to sell a space",
            params: vec![
                param("wallet", "string", "Wallet name", json!("default")),
                param("space", "string", "Space name", json!("@example")),
                param("amount", "integer", "Asking price in satoshis", json!(100000)),
            ],
            result_type: "Listing",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "verifylisting",
            description: "Verify that a listing is valid",
            params: vec![param("listing", "Listing", "The listing to verify", json!({"space": "@example", "price": 100000, "seller_psbt": "..."}))],
            result_type: "()",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "buildchainproof",
            description: "Build a chain proof for verifying spaces/nums state",
            params: vec![
                param("request", "ChainProofRequest", "The proof request specifying keys to prove", json!({"keys": [{"space": "@example"}]})),
                opt_param("prefer_recent", "bool", "Prefer the most recent snapshot", json!(true)),
            ],
            result_type: "ChainProofResult",
            result_schema: Some(serde_json::to_value(schema_for!(ChainProofResult)).unwrap()),
            extra_examples: vec![],
        },
        MethodSchema {
            name: "getrootanchors",
            description: "Get all root anchors for chain proof verification",
            params: vec![],
            result_type: "Vec<RootAnchor>",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "walletlisttransactions",
            description: "List wallet transactions with pagination",
            params: vec![
                param("wallet", "string", "Wallet name", json!("default")),
                param("count", "integer", "Number of transactions to return", json!(10)),
                param("skip", "integer", "Number of transactions to skip", json!(0)),
            ],
            result_type: "Vec<TxInfo>",
            result_schema: Some(serde_json::to_value(schema_for!(TxInfo)).unwrap()),
            extra_examples: vec![],
        },
        MethodSchema {
            name: "walletforcespend",
            description: "Force spend a specific outpoint",
            params: vec![
                param("wallet", "string", "Wallet name", json!("default")),
                param("outpoint", "OutPoint", "Transaction outpoint (txid:vout)", json!("a]1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d:0")),
                param("fee_rate", "number", "Fee rate in sat/vB", json!(1.0)),
            ],
            result_type: "TxResponse",
            result_schema: Some(serde_json::to_value(schema_for!(TxResponse)).unwrap()),
            extra_examples: vec![],
        },
        MethodSchema {
            name: "walletlistspaces",
            description: "List all spaces in a wallet grouped by status",
            params: vec![param("wallet", "string", "Wallet name", json!("default"))],
            result_type: "ListSpacesResponse",
            result_schema: Some(serde_json::to_value(schema_for!(ListSpacesResponse)).unwrap()),
            extra_examples: vec![],
        },
        MethodSchema {
            name: "walletlistnums",
            description: "List all nums in a wallet",
            params: vec![param("wallet", "string", "Wallet name", json!("default"))],
            result_type: "ListNumsResponse",
            result_schema: Some(serde_json::to_value(schema_for!(ListNumsResponse)).unwrap()),
            extra_examples: vec![],
        },
        MethodSchema {
            name: "walletlistunspent",
            description: "List all unspent outputs in a wallet",
            params: vec![param("wallet", "string", "Wallet name", json!("default"))],
            result_type: "Vec<WalletOutput>",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "walletlistbidouts",
            description: "List all bid outputs in a wallet",
            params: vec![param("wallet", "string", "Wallet name", json!("default"))],
            result_type: "Vec<DoubleUtxo>",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "walletgetbalance",
            description: "Get the wallet balance",
            params: vec![param("wallet", "string", "Wallet name", json!("default"))],
            result_type: "Balance",
            result_schema: None,
            extra_examples: vec![],
        },
        MethodSchema {
            name: "getfallback",
            description: "Get fallback data and parsed SIP-7 records for a subject. Supports * and ? wildcards for pattern matching (e.g. *@mad, @*).",
            params: vec![param(
                "subject",
                "Subject",
                "@space, #numeric, num1... id, handle (sub@space) for indexed lookup, or wildcard pattern (*@mad, @*)",
                json!("dictionary@mad"),
            )],
            result_type: "Value",
            result_schema: Some(serde_json::to_value(schema_for!(FallbackResponse)).unwrap()),
            extra_examples: vec![],
        },
        MethodSchema {
            name: "debugsetexpireheight",
            description: "Debug method to set a space's expire height (regtest only)",
            params: vec![
                param("space", "string", "Space name", json!("@example")),
                param("expire_height", "integer", "New expiration height", json!(1000)),
            ],
            result_type: "()",
            result_schema: None,
            extra_examples: vec![],
        },
    ]
}

pub fn full_spec() -> Value {
    let methods = build_schema();
    serde_json::to_value(&methods).unwrap()
}

pub fn to_markdown() -> String {
    let methods = build_schema();
    let mut md = String::new();

    md.push_str("# Spaces RPC API\n\n");

    for method in &methods {
        md.push_str(&format!("## `{}`\n\n", method.name));
        md.push_str(&format!("{}\n\n", method.description));

        if !method.params.is_empty() {
            md.push_str("| Parameter | Type | Required | Description |\n");
            md.push_str("|-----------|------|----------|-------------|\n");
            for p in &method.params {
                md.push_str(&format!(
                    "| `{}` | `{}` | {} | {} |\n",
                    p.name,
                    p.r#type,
                    if p.required { "yes" } else { "no" },
                    p.description
                ));
            }
            md.push_str("\n");
        }

        md.push_str(&format!("**Returns:** `{}`\n\n", method.result_type));

        // Build the default example request
        let example = rpc_request(method.name, &method.params.iter().collect::<Vec<_>>());
        md.push_str("**Example:**\n\n```json\n");
        md.push_str(&serde_json::to_string_pretty(&example).unwrap());
        md.push_str("\n```\n\n");

        // Extra examples for methods with multiple variants
        for (label, ex) in &method.extra_examples {
            md.push_str(&format!("**{}:**\n\n```json\n", label));
            md.push_str(&serde_json::to_string_pretty(ex).unwrap());
            md.push_str("\n```\n\n");
        }

        md.push_str("---\n\n");
    }

    md
}
