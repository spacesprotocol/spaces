# `estimatefee` — JSON-RPC from Node.js

`estimatefee` is a **spaced** JSON-RPC method. It does not talk to Bitcoin Core directly; the node forwards the request to `estimatesmartfee` and returns a fee rate in **sat/vB** plus an estimated **blocks** value.

## Method

| Field | Value |
|--------|--------|
| **JSON-RPC method** | `estimatefee` |
| **Parameters** | Positional array (see below) |
| **Result** | `{ "feerate_sat_vb": number, "blocks": number }` |

**Parameters (array, in order):**

1. **`conf_target`** (number) — desired confirmation target in blocks (1–1008, same range as Bitcoin Core `estimatesmartfee`).
2. **`estimate_mode`** (string, optional) — second element of the **same** `params` array. If you need Core’s default behavior, pass `"unset"`. Other values: `"conservative"`, `"economical"` (Bitcoin Core 0.16+).

Omitting the second value is not covered here; the CLI always sends a mode (default `"unset"`). To mirror the CLI’s default target of **6** blocks: `[6, "unset"]`.

**Example** (equivalent to `space-cli estimatefee 1 -m conservative`):

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "estimatefee",
  "params": [1, "conservative"]
}
```

**Example success `result`:**

```json
{
  "feerate_sat_vb": 12,
  "blocks": 2
}
```

On failure, the response is a normal JSON-RPC error object (`error.code`, `error.message`).

## Transport and URL

- **Protocol:** JSON-RPC 2.0 over **HTTP POST**.
- **Path:** The node serves JSON-RPC on the **root** of the listen URL (e.g. `http://127.0.0.1:7225/`), with `Content-Type: application/json`.
- **Default listen ports** (if you did not override `--rpc-bind` / `SPACED_RPC_PORT`):

| Network  | Port |
|----------|------|
| Mainnet  | 7225 |
| Testnet4 | 7224 |
| Testnet  | 7223 |
| Signet   | 7221 |
| Regtest  | 7218 |

## Authentication

The RPC HTTP server requires a **`Authorization: Basic ...`** header. The value after `Basic` is a **base64 string** (not double-encoded) built in one of two ways, matching the spaced node and `space-cli`.

### Option A — RPC user and password (when spaced was started with them)

`Authorization` = ``Basic `` + `Buffer.from(\`${user}:${password}\`, "utf8").toString("base64")` (Node.js).

### Option B — Cookie file (default when no RPC user is configured)

1. The node writes a one-line file `__cookie__:<64 random chars>` under its data directory for the chain, e.g. on Linux: `~/.local/share/spaced/<mainnet|testnet|…>/.cookie` (see your platform’s “data directory” for the `spaced` project).
2. Read that file as UTF-8, trim.
3. `Authorization` = ``Basic `` + `Buffer.from(trimmed, "utf8").toString("base64")`.

## Node.js example (Node 18+ `fetch`)

```javascript
import { readFile } from "node:fs/promises";

const RPC_URL = process.env.SPACED_RPC_URL ?? "http://127.0.0.1:7225";
const COOKIE_PATH = process.env.SPACED_COOKIE; // e.g. path to .cookie
const SPACED_RPC_USER = process.env.SPACED_RPC_USER;
const SPACED_RPC_PASSWORD = process.env.SPACED_RPC_PASSWORD;

/**
 * @param {string} [cookiePath] - Path to spaced .cookie (if not using user/password)
 */
async function basicAuthHeader(cookiePath) {
  if (SPACED_RPC_USER != null && SPACED_RPC_PASSWORD != null) {
    const t = Buffer.from(
      `${SPACED_RPC_USER}:${SPACED_RPC_PASSWORD}`,
      "utf8"
    ).toString("base64");
    return `Basic ${t}`;
  }
  if (!cookiePath) {
    throw new Error(
      "Set SPACED_RPC_USER/SPACED_RPC_PASSWORD or SPACED_COOKIE path (spaced .cookie file)"
    );
  }
  const raw = (await readFile(cookiePath, "utf8")).trim();
  return `Basic ${Buffer.from(raw, "utf8").toString("base64")}`;
}

/**
 * @param {number} confTarget - confirmation target in blocks
 * @param {string} [mode='unset'] - 'unset' | 'conservative' | 'economical' (as in space-cli)
 */
export async function estimateFee(
  confTarget,
  mode = "unset",
  { cookiePath = COOKIE_PATH } = {}
) {
  const res = await fetch(RPC_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: await basicAuthHeader(cookiePath),
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "estimatefee",
      params: [confTarget, mode],
    }),
  });

  if (!res.ok) {
    throw new Error(`HTTP ${res.status} ${res.statusText}`);
  }

  const j = await res.json();
  if (j.error) {
    const msg =
      j.error.data != null
        ? `${j.error.message}: ${JSON.stringify(j.error.data)}`
        : j.error.message;
    throw new Error(msg);
  }

  return j.result; // { feerate_sat_vb, blocks }
}

// Example: same as: space-cli estimatefee 1 -m conservative
const r = await estimateFee(1, "conservative", {
  cookiePath: "/path/to/.cookie",
});
console.log(r);
```

**Environment alignment with `space-cli`:**

- `SPACED_RPC_URL` (or construct default URL from your chain’s port, as in the table above).
- Either `SPACED_RPC_USER` + `SPACED_RPC_PASSWORD`, or the path to the same cookie file the CLI would use (often in the spaced data directory for that network).

## Discovery

The node also exposes **`rpc.discover`**, which returns a list of method names (for tooling). That does not replace this document for parameter shapes, but is useful to confirm the method name `estimatefee` on your build.

## See also

- Implementation: `client/src/rpc.rs` — method `estimatefee`, struct `FeeEstimateResponse`.
- CLI: `space-cli estimatefee` — same RPC call under the hood.
