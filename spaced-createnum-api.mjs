#!/usr/bin/env node
/**
 * Spaced JSON-RPC — create a num with a bound script-pubkey (mirrors
 *   space-cli createnum --bind-spk <hex> [--fee-rate <sat/vB>]
 *
 * Uses `walletsendrequest` with a `createnum` request so behavior matches the CLI
 * (including optional fee: omit or pass null to let the node estimate a fee).
 *
 * Environment (optional): SPACED_RPC_URL, SPACED_RPC_USER, SPACED_RPC_PASSWORD,
 *   or SPACED_COOKIE (path to the spaced .cookie file).
 *
 * @example
 *   import { createNumWithBindSpk } from "./spaced-createnum-api.mjs";
 *   const result = await createNumWithBindSpk({
 *     bindSpkHex: "5120aa…",
 *     auth: { cookiePath: process.env.HOME + "/.local/share/spaced/mainnet/.cookie" },
 *   });
 */

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

let reqId = 1;

/** rust-bitcoin `FeeRate` JSON is the raw sat/kwu u64: sat/vB × (1000/4) === sat/vB × 250. */
export function feeRateSatPerVbToWire(satPerVb) {
  if (!Number.isInteger(satPerVb) || satPerVb < 0) {
    throw new TypeError("fee rate (sat/vB) must be a non-negative integer");
  }
  return satPerVb * 250;
}

/**
 * @param {string} spkHex - Script pubkey as hex (same as CLI `--bind-spk`)
 * @returns {string} Normalized lowercase hex
 */
export function normalizeBindSpkHex(spkHex) {
  const s = String(spkHex).trim().replace(/^0x/i, "");
  if (s.length === 0) throw new Error("bindSpk is empty");
  if (s.length % 2 !== 0) {
    throw new Error("bindSpk must be an even number of hex digits");
  }
  if (!/^[0-9a-fA-F]+$/.test(s)) {
    throw new Error("bindSpk must be hexadecimal");
  }
  return s;
}

/**
 * @param {object} [opts]
 * @param {string} [opts.user]
 * @param {string} [opts.password]
 * @param {string} [opts.cookiePath]
 * @param {string} [opts.basicToken] - Value only (or full `Basic …` header)
 * @returns {Promise<string>} `Authorization` header value
 */
export async function createSpacedAuthHeader(opts = {}) {
  const user = opts.user ?? process.env.SPACED_RPC_USER;
  const password = opts.password ?? process.env.SPACED_RPC_PASSWORD;
  const cookiePath = opts.cookiePath ?? process.env.SPACED_COOKIE;
  if (user != null && password != null) {
    const t = Buffer.from(`${user}:${password}`, "utf8").toString("base64");
    return `Basic ${t}`;
  }
  if (cookiePath) {
    const raw = (await readFile(cookiePath, "utf8")).trim();
    return `Basic ${Buffer.from(raw, "utf8").toString("base64")}`;
  }
  if (opts.basicToken) {
    const raw = String(opts.basicToken).trim();
    return /^Basic\s+/i.test(raw) ? raw : `Basic ${raw}`;
  }
  throw new Error(
    "Set auth: { user, password } or { cookiePath } or { basicToken }, or SPACED_RPC_USER/SPACED_RPC_PASSWORD or SPACED_COOKIE"
  );
}

/**
 * @param {object} c
 * @param {string} c.rpcUrl
 * @param {string} c.authorization
 * @param {string} c.method
 * @param {unknown[]} c.params
 */
export async function spacedJsonRpc({ rpcUrl, authorization, method, params }) {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: reqId++,
    method,
    params,
  });
  const res = await fetch(rpcUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: authorization,
    },
    body,
  });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} ${res.statusText}`);
  }
  const json = await res.json();
  if (json.error) {
    const err = new Error(json.error.message ?? "JSON-RPC error");
    err.code = json.error.code;
    err.data = json.error.data;
    throw err;
  }
  return json.result;
}

/**
 * Submits `walletsendrequest` to create a num bound to `bindSpkHex`, matching
 * `space-cli createnum --bind-spk <spk>` (and optional `--fee-rate`).
 *
 * @param {object} options
 * @param {string} options.bindSpkHex - Hex script pubkey
 * @param {string} [options.rpcUrl] - Default: SPACED_RPC_URL or http://127.0.0.1:7225
 * @param {string} [options.wallet] - Wallet name (default: `default`)
 * @param {number | null} [options.feeRateSatPerVB] - Sat/vB; omit or `null` to estimate (same as no `--fee-rate`)
 * @param {object} [options.auth] - Forwarded to {@link createSpacedAuthHeader}
 * @param {boolean} [options.force]
 * @param {boolean} [options.confirmedOnly]
 * @param {boolean} [options.skipTxCheck]
 * @returns {Promise<unknown>} `WalletResponse` from the node
 */
export async function createNumWithBindSpk({
  bindSpkHex,
  rpcUrl = process.env.SPACED_RPC_URL ?? "http://127.0.0.1:7225",
  wallet = "default",
  feeRateSatPerVB = null,
  auth = {},
  force = false,
  confirmedOnly = false,
  skipTxCheck = false,
} = {}) {
  const bind_spk = normalizeBindSpkHex(bindSpkHex);
  const authorization = await createSpacedAuthHeader(auth);

  /** @type {Record<string, unknown>} */
  const builder = {
    requests: [
      {
        request: "createnum",
        bind_spk,
      },
    ],
    force,
    confirmed_only: confirmedOnly,
    skip_tx_check: skipTxCheck,
  };

  if (feeRateSatPerVB != null) {
    builder.fee_rate = feeRateSatPerVbToWire(feeRateSatPerVB);
  } else {
    builder.fee_rate = null;
  }

  return spacedJsonRpc({
    rpcUrl,
    authorization,
    method: "walletsendrequest",
    params: [wallet, builder],
  });
}

// CLI:  node spaced-createnum-api.mjs <spk-hex> [fee-sat/vb]
const isMain =
  process.argv[1] &&
  path.normalize(fileURLToPath(import.meta.url)) ===
    path.normalize(path.resolve(process.argv[1]));
if (isMain) {
  const [spk, fee] = process.argv.slice(2);
  if (!spk) {
    console.error("Usage: node spaced-createnum-api.mjs <spk-hex> [fee-sat/vB]");
    process.exit(1);
  }
  const feeN = fee != null && fee !== "" ? Number(fee) : null;
  try {
    const out = await createNumWithBindSpk({
      bindSpkHex: spk,
      feeRateSatPerVB: feeN != null && !Number.isNaN(feeN) ? feeN : null,
    });
    console.log(JSON.stringify(out, null, 2));
  } catch (e) {
    console.error(e.message ?? e);
    process.exit(1);
  }
}
