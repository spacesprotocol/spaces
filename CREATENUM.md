# Create a num with `--bind-spk` (CLI, JSON-RPC, Node.js)

This document describes how to create a new **num** with a **bound script public key** (`--bind-spk`), matching `space-cli createnum --bind-spk <hex> [--fee-rate <sat/vB>]` and the equivalent JSON-RPC calls.

## CLI

```bash
space-cli createnum --bind-spk <spk-hex> [--fee-rate <sat/vB>]
```

- **`--bind-spk`** — script pubkey as hex (even-length hex string). Same bytes you would pass over JSON-RPC as `bind_spk`.
- **`--fee-rate`** — optional; fee in **sat/vB**. If omitted, the wallet **estimates** a fee (via Bitcoin Core `estimatesmartfee`, same as other wallet operations without an explicit rate).

Omitting `--bind-spk` is a different code path (auto-generated address). This document only covers the explicit `--bind-spk` case.

## JSON-RPC (same node as `space-cli`)

Transport, default ports, and `Authorization: Basic` are the same as in [ESTIMATE_FEE.md](ESTIMATE_FEE.md) (POST JSON-RPC 2.0 to the base HTTP URL, Basic auth from cookie or user/password).

### Option 1: `walletsendrequest` (full CLI parity)

The CLI uses this method. Parameters are a **positional array**: `["<wallet_name>", <RpcWalletTxBuilder>]`.

The builder should contain a **single** request of type `createnum` with `bind_spk` set to the same hex string as the CLI. Optional fee behavior matches the CLI:

- **`fee_rate: null`** — no explicit fee in the request; the node estimates (like omitting `--fee-rate`).
- **`fee_rate: <u64>`** — wire format for [rust-bitcoin `FeeRate`](https://docs.rs/bitcoin/): the value is the internal **sat/kwu** integer, not sat/vB. Conversion: **sat/kwu = sat/vB × 250** (because 1 vB = 4 WU, and the newtype stores sat per 1000 WU). Example: 2 sat/vB → `500`.

Minimal example (no explicit fee, wallet name `default`):

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "walletsendrequest",
  "params": [
    "default",
    {
      "requests": [
        {
          "request": "createnum",
          "bind_spk": "5120aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
      ],
      "fee_rate": null,
      "force": false,
      "confirmed_only": false,
      "skip_tx_check": false
    }
  ]
}
```

To set an explicit fee in sat/vB (e.g. 2), set `"fee_rate": 500` in the object above (2 × 250). The [Node.js helper](#nodejs-helper-spaced-createnum-apimjs) below accepts **sat/vB** and applies this conversion for you.

**Result** — same shape as other wallet batch operations (`WalletResponse` JSON from the node).

### Option 2: `walletcreatenum` (convenience)

Method **`walletcreatenum`** takes three positional parameters:

1. **Wallet** (string)  
2. **`fee_rate_sat_vb`** (integer) — fee in **sat/vB** (the server maps this to an internal `FeeRate`; you do not send sat/kwu yourself).  
3. **`spk_hex`** (string) — hex-encoded script pubkey.  

This path **always** requires an explicit `fee_rate_sat_vb`. It does **not** support the “no `--fee-rate` / estimate” behavior. For that, use **`walletsendrequest`** with `fee_rate: null` (Option 1) or the Node helper with `feeRateSatPerVB: null`.

Example (from the built-in schema examples):

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "walletcreatenum",
  "params": [
    "default",
    2,
    "5120aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  ]
}
```

## Node.js helper: `spaced-createnum-api.mjs`

The repo includes **`spaced-createnum-api.mjs`**, which calls **`walletsendrequest`** with a `createnum` request so behavior matches the CLI (optional estimated fee or explicit **sat/vB**).

- **`createNumWithBindSpk({ ... })`** — main entry point.  
- **`createSpacedAuthHeader(...)`** — builds `Authorization: Basic` from `SPACED_RPC_USER` / `SPACED_RPC_PASSWORD`, **`SPACED_COOKIE`**, or an options object.  
- **`feeRateSatPerVbToWire(satPerVb)`** — **sat/vB →** JSON `fee_rate` value (× 250) when you build requests by hand.  
- **`spacedJsonRpc({ rpcUrl, authorization, method, params })`** — low-level POST wrapper.

**Environment** (optional): `SPACED_RPC_URL` (default `http://127.0.0.1:7225` if unset in code), and the same auth env vars as above.

**Import (ESM):**

```javascript
import { createNumWithBindSpk } from "./spaced-createnum-api.mjs";

const result = await createNumWithBindSpk({
  bindSpkHex: "5120…",
  feeRateSatPerVB: null, // estimate fee (like omitting --fee-rate)
  auth: { cookiePath: process.env.HOME + "/.local/share/spaced/mainnet/.cookie" },
});
```

**Explicit fee (e.g. 2 sat/vB, like `--fee-rate 2`):**

```javascript
await createNumWithBindSpk({
  bindSpkHex: "5120…",
  feeRateSatPerVB: 2,
  auth: { cookiePath: "…" },
});
```

**One-shot CLI** (same module, no `import`):

```bash
node spaced-createnum-api.mjs <spk-hex> [fee-sat/vB]
```

If the fee argument is omitted, the helper uses **`null`** (estimate).

## Example script: `test-createnum.js`

**`test-createnum.js`** loads the ESM module and demonstrates **with** and **without** an explicit `feeRateSatPerVB`. Requires **Node 18+** for `fetch`.

**Usage:**

```text
node test-createnum.js <spk-hex> [with-fee|no-fee|both]
```

| Mode       | Effect |
|------------|--------|
| `no-fee`   | (default) `feeRateSatPerVB: null` — estimated fee. |
| `with-fee` | `feeRateSatPerVB: 2` — same idea as `--fee-rate 2`. |
| `both`     | Runs **no-fee** first, then **with-fee** — **two separate transactions**; use on regtest/signet or when you intend to broadcast twice. |

Set `SPACED_RPC_URL` and cookie or credentials the same way as for `space-cli`.

## More examples in the tree

- **`client/src/rpc_schema.rs`** — under method `walletsendrequest`, look for the **“Create a num”** example; under **`walletcreatenum`**, a full JSON-RPC example with binding script.  
- With the `schema` feature, **`cargo run -p spaces_client --bin rpc-docs`** prints markdown or `rpc-docs --json` for the full spec.

## See also

- Rust types: `client/src/rpc.rs` — `RpcWalletTxBuilder`, `RpcWalletRequest` (`createnum` / `CreateNumParams` with `bind_spk`), `FeeRate`.  
- [ESTIMATE_FEE.md](ESTIMATE_FEE.md) — HTTP, ports, and Basic authentication for JSON-RPC.  
