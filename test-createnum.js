#!/usr/bin/env node
// Example: spaced-createnum-api.mjs — create a num with --bind-spk, with and without --fee-rate
//
// Requires Node 18+ (fetch). Auth via env, same as space-cli:
//   SPACED_RPC_URL     default http://127.0.0.1:7225 (or set in code via env)
//   SPACED_RPC_USER + SPACED_RPC_PASSWORD
//   or SPACED_COOKIE  path to spaced .cookie
//
// Usage:
//   node test-createnum.js <spk-hex> [mode]
//     mode:  with-fee   — explicit sat/vB (example uses 2)
//            no-fee     — let the node estimate (default)
//            both       — run without fee then with fee (two transactions)
//
// Examples:
//   node test-createnum.js 5120aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
//   node test-createnum.js 5120aa…  with-fee
//   node test-createnum.js 5120aa…  both

const path = require("node:path");
const { pathToFileURL } = require("node:url");

const RPC_URL = process.env.SPACED_RPC_URL;

async function main() {
  const { createNumWithBindSpk } = await import(
    pathToFileURL(path.join(__dirname, "spaced-createnum-api.mjs")).href
  );

  const spkHex = process.argv[2];
  const mode = (process.argv[3] || "no-fee").toLowerCase();

  if (!spkHex) {
    console.error("Usage: node test-createnum.js <spk-hex> [with-fee|no-fee|both]");
    process.exit(1);
  }

  if (!["with-fee", "no-fee", "both"].includes(mode)) {
    console.error(
      `Invalid mode: ${process.argv[3]}. Use with-fee, no-fee, or both.`
    );
    process.exit(1);
  }

  const base = {
    bindSpkHex: spkHex,
    rpcUrl: RPC_URL,
    auth: {},
  };

  if (mode === "no-fee" || mode === "both") {
    console.log(
      "\n── Example: no explicit fee (node estimates; same as omitting --fee-rate)\n"
    );
    const noFee = await createNumWithBindSpk({
      ...base,
      feeRateSatPerVB: null,
    });
    console.log(JSON.stringify(noFee, null, 2));
  }

  if (mode === "with-fee" || mode === "both") {
    console.log(
      "\n── Example: with explicit fee rate (like --fee-rate 2 sat/vB)\n"
    );
    const withFee = await createNumWithBindSpk({
      ...base,
      feeRateSatPerVB: 2,
    });
    console.log(JSON.stringify(withFee, null, 2));
  }
}

main().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
