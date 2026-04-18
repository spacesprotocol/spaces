#!/usr/bin/env node
// Test program for the Transaction Callback API (TX_CALLBACK_API.md)
// Usage: node test-txcallback.js [rpc-url]
//   e.g. node test-txcallback.js http://127.0.0.1:7224   (testnet4)
//        node test-txcallback.js                          (mainnet default: 7225)

const RPC_URL = process.argv[2] || "http://127.0.0.1:7225";

const CLIENT_ID = `test-client-${Date.now()}`;
const CALLBACK_URL = "http://127.0.0.1:9999/callback";

// Plausible-looking fake txids for watch list tests
const TXID_1 = "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d";
const TXID_2 = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16";
const TXID_3 = "6f7cf9580f1c2dfb3c4d8d43b5d9f8c6e4a7b2e1d0f9c8b7a6e5d4c3b2a1908";

let reqId = 1;

// ─── RPC helper ────────────────────────────────────────────────────────────────

async function rpc(method, params = {}) {
  const body = JSON.stringify({ jsonrpc: "2.0", id: reqId++, method, params });
  const res = await fetch(RPC_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
  const json = await res.json();
  if (json.error) throw Object.assign(new Error(json.error.message), { code: json.error.code });
  return json.result;
}

// ─── Test helpers ───────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;

function assert(label, condition, detail = "") {
  if (condition) {
    console.log(`  ✓  ${label}`);
    passed++;
  } else {
    console.error(`  ✗  ${label}${detail ? ` — ${detail}` : ""}`);
    failed++;
  }
}

async function test(name, fn) {
  console.log(`\n── ${name}`);
  try {
    await fn();
  } catch (err) {
    console.error(`  ✗  threw: ${err.message}`);
    failed++;
  }
}

// ─── Tests ──────────────────────────────────────────────────────────────────────

async function main() {
  console.log(`RPC endpoint : ${RPC_URL}`);
  console.log(`Client ID   : ${CLIENT_ID}`);

  // 1. Register
  await test("registertxcallback — register new client", async () => {
    const result = await rpc("registertxcallback", {
      client_id: CLIENT_ID,
      callback_url: CALLBACK_URL,
    });
    assert("result is null", result === null, JSON.stringify(result));
  });

  // 2. Get — verify registration
  await test("gettxcallback — client exists after registration", async () => {
    const result = await rpc("gettxcallback", { client_id: CLIENT_ID });
    assert("result is not null", result !== null);
    assert("client_id matches", result?.client_id === CLIENT_ID, result?.client_id);
    assert("callback_url matches", result?.callback_url === CALLBACK_URL, result?.callback_url);
    assert("watched_txids is empty array", Array.isArray(result?.watched_txids) && result.watched_txids.length === 0);
    assert("registered_at is a number", typeof result?.registered_at === "number");
    console.log(`     registered_at: ${new Date(result.registered_at * 1000).toISOString()}`);
  });

  // 3. Get — unknown client returns null
  await test("gettxcallback — unknown client returns null", async () => {
    const result = await rpc("gettxcallback", { client_id: "nonexistent-client-xyz" });
    assert("result is null for unknown client", result === null, JSON.stringify(result));
  });

  // 4. List — newly registered client appears
  await test("listtxcallbacks — registered client appears in list", async () => {
    const result = await rpc("listtxcallbacks", {});
    assert("result is an array", Array.isArray(result));
    const found = result?.find((c) => c.client_id === CLIENT_ID);
    assert("our client is in the list", !!found);
    assert("found entry has callback_url", found?.callback_url === CALLBACK_URL);
  });

  // 5. Update watches — set two txids
  await test("updatetxwatches — set watch list", async () => {
    const result = await rpc("updatetxwatches", {
      client_id: CLIENT_ID,
      txids: [TXID_1, TXID_2],
    });
    assert("result is true", result === true, JSON.stringify(result));
  });

  // 6. Get — verify watch list
  await test("gettxcallback — watched_txids reflect update", async () => {
    const result = await rpc("gettxcallback", { client_id: CLIENT_ID });
    assert("watched_txids has 2 entries", result?.watched_txids?.length === 2, JSON.stringify(result?.watched_txids));
    assert("TXID_1 is watched", result?.watched_txids?.includes(TXID_1));
    assert("TXID_2 is watched", result?.watched_txids?.includes(TXID_2));
  });

  // 7. Update watches — replace with different set
  await test("updatetxwatches — replace watch list with 3 txids", async () => {
    const result = await rpc("updatetxwatches", {
      client_id: CLIENT_ID,
      txids: [TXID_1, TXID_2, TXID_3],
    });
    assert("result is true", result === true, JSON.stringify(result));

    const info = await rpc("gettxcallback", { client_id: CLIENT_ID });
    assert("watched_txids now has 3 entries", info?.watched_txids?.length === 3, JSON.stringify(info?.watched_txids));
  });

  // 8. Update watches — clear list
  await test("updatetxwatches — clear watch list", async () => {
    const result = await rpc("updatetxwatches", {
      client_id: CLIENT_ID,
      txids: [],
    });
    assert("result is true", result === true);

    const info = await rpc("gettxcallback", { client_id: CLIENT_ID });
    assert("watched_txids is now empty", info?.watched_txids?.length === 0, JSON.stringify(info?.watched_txids));
  });

  // 9. Update watches — unknown client returns false
  await test("updatetxwatches — unknown client returns false", async () => {
    const result = await rpc("updatetxwatches", {
      client_id: "nonexistent-client-xyz",
      txids: [TXID_1],
    });
    assert("result is false for unknown client", result === false, JSON.stringify(result));
  });

  // 10. Unregister
  await test("unregistertxcallback — unregister client", async () => {
    const result = await rpc("unregistertxcallback", { client_id: CLIENT_ID });
    assert("result is true", result === true, JSON.stringify(result));
  });

  // 11. Get — gone after unregister
  await test("gettxcallback — null after unregister", async () => {
    const result = await rpc("gettxcallback", { client_id: CLIENT_ID });
    assert("result is null after unregistering", result === null, JSON.stringify(result));
  });

  // 12. Unregister — already gone returns false
  await test("unregistertxcallback — second unregister returns false", async () => {
    const result = await rpc("unregistertxcallback", { client_id: CLIENT_ID });
    assert("result is false for already-removed client", result === false, JSON.stringify(result));
  });

  // 13. List — client no longer appears
  await test("listtxcallbacks — unregistered client absent from list", async () => {
    const result = await rpc("listtxcallbacks", {});
    assert("result is an array", Array.isArray(result));
    const found = result?.find((c) => c.client_id === CLIENT_ID);
    assert("our client is gone from the list", !found);
  });

  // ─── Summary ──────────────────────────────────────────────────────────────────
  console.log(`\n${"─".repeat(50)}`);
  console.log(`  Passed: ${passed}   Failed: ${failed}`);
  if (failed > 0) process.exit(1);
}

main().catch((err) => {
  console.error("Fatal:", err.message);
  process.exit(1);
});
