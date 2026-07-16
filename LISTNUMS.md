# List nums with `--spk` (CLI and JSON-RPC)

This document describes how to list **nums** filtered by **script public key** (`--spk`), matching `spaces listnums --spk <hex>` (the `spaces` alias from [setup-spaced-prod-env.sh](setup-spaced-prod-env.sh)).

## CLI

```bash
spaces listnums --spk <spk-hex>
```

Equivalent without the alias:

```bash
space-cli -w main --chain=mainnet \
  --rpc-url=http://127.0.0.1:7225 \
  --rpc-user=testuser --rpc-password=SomeRisk84 \
  listnums --spk <spk-hex>
```

### `--spk`

- **`<spk-hex>`** — hex-encoded **script pubkey bytes** (even-length hex string), e.g. a P2TR output script from `createnum --bind-spk` or `getnewspaceaddress`.
- Matches nums whose live output `script_pubkey` equals those bytes **exactly**.
- Searches **both** wallet-held nums (`owned`) and nums the wallet created but no longer holds (`external`).
- **`--kind` is ignored** when `--spk` is set.

### `--kind` (without `--spk`)

| Value | Meaning |
|-------|---------|
| `owned` (default) | Nums the wallet currently owns |
| `external` | Nums created by the wallet but not currently owned |

```bash
spaces listnums                    # all owned nums
spaces listnums --kind external    # external nums only
spaces listnums --spk 5120…        # filter owned + external by spk
```

### Example

```bash
source setup-spaced-prod-env.sh

spaces listnums --spk 5120cfeec34216dfaaf5eb91cabe45acf6da7c35187af8e8b5364d53fe29d4439e8a
```

Output is JSON (`ListNumsResponse`): an object with a `nums` array. Each entry includes `txid`, `numout` (with `script_pubkey`, `num`, etc.), optional `delegating_for`, and optional parsed SIP-7 `records`.

## JSON-RPC

Transport, default ports, and `Authorization: Basic` are the same as in [ESTIMATE_FEE.md](ESTIMATE_FEE.md) (POST JSON-RPC 2.0 to the base HTTP URL, Basic auth from cookie or user/password).

There is **no single RPC method** named for `--spk`. The CLI implements `--spk` by calling **`walletlistnums` twice** (owned, then external) and filtering client-side by script pubkey.

### Option 1: `walletlistnums` (CLI parity, wallet-scoped)

Parameters: `["<wallet_name>", <kind>]`

- **`kind: null`** — owned nums (same as `--kind owned`)
- **`kind: "external"`** — external nums

Fetch owned nums:

```bash
curl -sS -X POST http://127.0.0.1:7225 \
  -u testuser:SomeRisk84 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "walletlistnums",
    "params": ["main", null]
  }'
```

Fetch external nums:

```bash
curl -sS -X POST http://127.0.0.1:7225 \
  -u testuser:SomeRisk84 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "walletlistnums",
    "params": ["main", "external"]
  }'
```

Filter both responses for a given spk (requires [jq](https://jqlang.org/)):

```bash
SPK="5120cfeec34216dfaaf5eb91cabe45acf6da7c35187af8e8b5364d53fe29d4439e8a"
RPC="http://127.0.0.1:7225"
AUTH="testuser:SomeRisk84"

rpc() {
  curl -sS -u "$AUTH" -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"walletlistnums\",\"params\":[\"main\",$1]}" \
    "$RPC"
}

jq -s --arg spk "$SPK" '
  [.[] | .result.nums[]]
  | map(select(.numout.script_pubkey == $spk))
  | unique_by(.txid + ":" + (.numout.n | tostring))
  | { nums: . }
' <(rpc null) <(rpc "\"external\"")
```

Replace `"main"` with your wallet name if different.

### Option 2: `listnumsbyspk` (chain index, no wallet)

Method **`listnumsbyspk`** takes one positional parameter: **`spk_hex`** (hex-encoded script pubkey). It returns live num outputs on the **indexed chain** whose script matches, with the same `ListNumsResponse` shape as `walletlistnums`.

This does **not** require a wallet and is **not** limited to nums the wallet created. Use it when you want chain-wide lookup by spk; use Option 1 when you need the same wallet-scoped behavior as `spaces listnums --spk`.

```bash
curl -sS -X POST http://127.0.0.1:7225 \
  -u testuser:SomeRisk84 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "listnumsbyspk",
    "params": [
      "5120cfeec34216dfaaf5eb91cabe45acf6da7c35187af8e8b5364d53fe29d4439e8a"
    ]
  }'
```

## See also

- Rust types: `client/src/wallets.rs` — `ListNumsResponse`, `NumEntry`
- RPC definitions: `client/src/rpc.rs` — `wallet_list_nums`, `list_nums_by_spk`
- Schema examples: `client/src/rpc_schema.rs` — `walletlistnums`, `listnumsbyspk`
- [CREATENUM.md](CREATENUM.md) — create a num bound to a script pubkey
- [ESTIMATE_FEE.md](ESTIMATE_FEE.md) — HTTP, ports, and Basic authentication for JSON-RPC
