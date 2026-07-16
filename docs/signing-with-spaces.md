# Signing with Spaces Keys

## Overview

There are two signing methods in the wallet:

| Method                | Scheme                                                                  | Available via RPC? |
|-----------------------|-------------------------------------------------------------------------|--------------------|
| `walletsignschnorr`   | `SHA256("\x17Spaces Signed Message:\n" \|\| message)` → BIP340 Schnorr | Yes                |
| `sign_event` (Nostr)  | `SHA256([0, pubkey, created_at, kind, tags, content])` → BIP340 Schnorr | No (library only)  |

Both use the **Taproot-tweaked keypair** (BIP86, tweaked with no script tree) of the
UTXO that holds the space.

## Using `walletsignschnorr` via curl

This is the only signing method currently exposed over RPC. It signs an arbitrary
byte payload using the private key that controls a given space.

### RPC Method

```text
walletsignschnorr(wallet, subject, message)
```

- **wallet**: wallet name (e.g. `"main"`)
- **subject**: space name, numeric, or num ID (e.g. `"@rad"`)
- **message**: hex-encoded bytes to sign

### Example: Sign the event in `data/sign_this.json`

The file `data/sign_this.json` contains:

```json
{
    "created_at": 1774906587,
    "kind": 10002,
    "tags": [["d", "rad"], ["r", "wss://relay.primal.net"], ["r", "wss://relay.damus.io"]],
    "content": "I am RAD",
    "space_name": "@rad",
    "sig": null
}
```

The `space_name` field indicates which space's key to sign with — it is not part of
the signed payload.

#### Step 1: Hex-encode the message

Convert the event content (or the whole serialized event) to hex. For example, to
sign the raw `content` string:

```bash
MESSAGE_HEX=$(echo -n "I am RAD" | xxd -p | tr -d '\n')
# Result: 4920616d20524144
```

Or to sign the entire JSON payload (excluding `space_name` and `sig`):

```bash
MESSAGE_HEX=$(jq -c '{created_at, kind, tags, content}' data/sign_this.json \
  | xxd -p | tr -d '\n')
```

#### Step 2: Call the RPC

```bash
curl -s -X POST http://127.0.0.1:7224 \
  -u testuser:SomeRisk84 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "walletsignschnorr",
    "params": ["main", "@rad", "'"$MESSAGE_HEX"'"]
  }'
```

Expected response:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": "<64-byte hex-encoded BIP340 Schnorr signature>"
}
```

#### Step 3: Verify the signature

```bash
SIGNATURE="<signature hex from above>"

curl -s -X POST http://127.0.0.1:7224 \
  -u testuser:SomeRisk84 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "verifyschnorr",
    "params": ["@rad", "'"$MESSAGE_HEX"'", "'"$SIGNATURE"'"]
  }'
```

### All-in-one script: sign and verify

```bash
#!/bin/bash
# Sign the content of data/sign_this.json with @rad's key and verify it.
# Uses the walletsignschnorr RPC (Spaces-prefixed digest, not Nostr-compatible).
# Requires: jq, xxd, curl
# Source setup-spaced-prod-env.sh first for env vars, or set them here:

RPC_URL="http://127.0.0.1:7224"
RPC_USER="testuser"
RPC_PASS="SomeRisk84"
WALLET="main"
SPACE="@rad"

CONTENT=$(jq -r '.content' data/sign_this.json)
MESSAGE_HEX=$(echo -n "$CONTENT" | xxd -p | tr -d '\n')

echo "Signing '$CONTENT' as $SPACE..."
echo "Message hex: $MESSAGE_HEX"

SIGN_RESPONSE=$(curl -s -X POST "$RPC_URL" \
  -u "$RPC_USER:$RPC_PASS" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "walletsignschnorr",
    "params": ["'"$WALLET"'", "'"$SPACE"'", "'"$MESSAGE_HEX"'"]
  }')

echo "Sign response: $SIGN_RESPONSE"
SIGNATURE=$(echo "$SIGN_RESPONSE" | jq -r '.result')

if [ "$SIGNATURE" = "null" ] || [ -z "$SIGNATURE" ]; then
  echo "ERROR: Signing failed"
  echo "$SIGN_RESPONSE" | jq .
  exit 1
fi

echo "Signature: $SIGNATURE"

echo ""
echo "Verifying..."
VERIFY_RESPONSE=$(curl -s -X POST "$RPC_URL" \
  -u "$RPC_USER:$RPC_PASS" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "verifyschnorr",
    "params": ["'"$SPACE"'", "'"$MESSAGE_HEX"'", "'"$SIGNATURE"'"]
  }')

echo "Verify response: $VERIFY_RESPONSE"
```

## Building a complete signed Nostr event

A valid Nostr event ready for relay broadcast requires these fields
([NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md)):

```json
{
  "id": "<32-byte lowercase hex SHA256 of the serialized event>",
  "pubkey": "<32-byte lowercase hex x-only public key>",
  "created_at": 1774906587,
  "kind": 10002,
  "tags": [["d","rad"], ["r","wss://relay.primal.net"], ["r","wss://relay.damus.io"]],
  "content": "I am RAD",
  "sig": "<64-byte lowercase hex BIP340 Schnorr signature of the id>"
}
```

The `id` is computed as:

```text
SHA256(json_serialize([0, <pubkey>, <created_at>, <kind>, <tags>, <content>]))
```

And `sig` is a BIP340 Schnorr signature over those raw `id` bytes (no prefix, no
extra hashing).

> **Important:** `walletsignschnorr` prepends `"\x17Spaces Signed Message:\n"`
> before hashing, so it **cannot** produce a Nostr-compatible signature. The
> complete script below uses `getspace` to obtain the pubkey and constructs the
> event ID locally, then calls `walletsignschnorr` to sign the event ID. The
> resulting signature uses the Spaces digest scheme. For a fully
> Nostr-standard signature, `sign_event` would need to be exposed as an RPC
> endpoint (see [Nostr-compatible signing](#nostr-compatible-signing-with-sign_event)
> below).

### Complete script: assemble a signed Nostr event from `data/sign_this.json`

```bash
#!/bin/bash
# Build a complete signed Nostr JSON event from data/sign_this.json.
# Requires: jq, xxd, curl, openssl (or shasum)
set -euo pipefail

RPC_URL="http://127.0.0.1:7224"
RPC_USER="testuser"
RPC_PASS="SomeRisk84"
WALLET="main"
INPUT="data/sign_this.json"

# --- Helper: JSON-RPC call ---
rpc_call() {
  curl -s -X POST "$RPC_URL" \
    -u "$RPC_USER:$RPC_PASS" \
    -H "Content-Type: application/json" \
    -d "$1"
}

# --- Step 1: Read input event and extract the space name ---
SPACE=$(jq -r '.space_name' "$INPUT")
CREATED_AT=$(jq '.created_at' "$INPUT")
KIND=$(jq '.kind' "$INPUT")
TAGS=$(jq -c '.tags' "$INPUT")
CONTENT=$(jq -r '.content' "$INPUT")

echo "=== Input ==="
echo "Space:      $SPACE"
echo "Kind:       $KIND"
echo "Content:    $CONTENT"

# --- Step 2: Get the space's pubkey from the chain ---
GETSPACE_RESPONSE=$(rpc_call '{
  "jsonrpc": "2.0", "id": 1,
  "method": "getspace",
  "params": ["'"${SPACE#@}"'"]
}')

SCRIPT_PUBKEY=$(echo "$GETSPACE_RESPONSE" | jq -r '.result.script_pubkey')

if [ "$SCRIPT_PUBKEY" = "null" ] || [ -z "$SCRIPT_PUBKEY" ]; then
  echo "ERROR: Could not get space info for $SPACE"
  echo "$GETSPACE_RESPONSE" | jq .
  exit 1
fi

# script_pubkey is "5120<32-byte-x-only-pubkey-hex>"
# Strip the SegWit v1 witness prefix (0x5120)
PUBKEY="${SCRIPT_PUBKEY:4}"
echo "Pubkey:     $PUBKEY"

# --- Step 3: Compute the Nostr event ID ---
# Serialization per NIP-01: [0, <pubkey>, <created_at>, <kind>, <tags>, <content>]
SERIALIZED=$(jq -c -n \
  --arg pubkey "$PUBKEY" \
  --argjson created_at "$CREATED_AT" \
  --argjson kind "$KIND" \
  --argjson tags "$TAGS" \
  --arg content "$CONTENT" \
  '[0, $pubkey, $created_at, $kind, $tags, $content]')

echo ""
echo "=== Nostr serialization for signing ==="
echo "$SERIALIZED"

EVENT_ID=$(echo -n "$SERIALIZED" | openssl dgst -sha256 -hex | awk '{print $NF}')
echo "Event ID:   $EVENT_ID"

# --- Step 4: Sign the event ID with the space's key ---
# Convert the event ID (hex string) to raw bytes, then hex-encode those bytes.
# walletsignschnorr expects the message as hex-encoded bytes.
MESSAGE_HEX="$EVENT_ID"

SIGN_RESPONSE=$(rpc_call '{
  "jsonrpc": "2.0", "id": 2,
  "method": "walletsignschnorr",
  "params": ["'"$WALLET"'", "'"$SPACE"'", "'"$MESSAGE_HEX"'"]
}')

SIGNATURE=$(echo "$SIGN_RESPONSE" | jq -r '.result')

if [ "$SIGNATURE" = "null" ] || [ -z "$SIGNATURE" ]; then
  echo "ERROR: Signing failed"
  echo "$SIGN_RESPONSE" | jq .
  exit 1
fi

echo "Signature:  $SIGNATURE"

# --- Step 5: Assemble the complete signed Nostr event ---
SIGNED_EVENT=$(jq -n \
  --arg id "$EVENT_ID" \
  --arg pubkey "$PUBKEY" \
  --argjson created_at "$CREATED_AT" \
  --argjson kind "$KIND" \
  --argjson tags "$TAGS" \
  --arg content "$CONTENT" \
  --arg sig "$SIGNATURE" \
  '{
    id: $id,
    pubkey: $pubkey,
    created_at: $created_at,
    kind: $kind,
    tags: $tags,
    content: $content,
    sig: $sig
  }')

echo ""
echo "=== Signed Nostr Event ==="
echo "$SIGNED_EVENT" | jq .

# --- Step 6 (optional): Write to file ---
OUTPUT="data/signed_event.json"
echo "$SIGNED_EVENT" | jq . > "$OUTPUT"
echo ""
echo "Written to $OUTPUT"

# --- Step 7 (optional): Broadcast to relay ---
# To send to a Nostr relay, wrap in a ["EVENT", <event>] message:
#
#   RELAY="wss://relay.primal.net"
#   echo '["EVENT", '"$SIGNED_EVENT"']' | websocat "$RELAY"
#
# Or using wscat:
#   echo '["EVENT", '"$SIGNED_EVENT"']' | wscat -c "$RELAY"
```

### Expected output

Running the script produces a complete Nostr event JSON:

```json
{
  "id": "a1b2c3...64-char-hex-sha256...",
  "pubkey": "016313c8c189588492b9268e3a7d9e426e9e3d7a0340328f8d68b8f623dd8604",
  "created_at": 1774906587,
  "kind": 10002,
  "tags": [
    ["d", "rad"],
    ["r", "wss://relay.primal.net"],
    ["r", "wss://relay.damus.io"]
  ],
  "content": "I am RAD",
  "sig": "deadbeef...128-char-hex-schnorr-signature..."
}
```

This can then be broadcast to relays using the Nostr `EVENT` message format:

```json
["EVENT", { "id": "...", "pubkey": "...", ... }]
```

### Input vs output field mapping

| Input (`sign_this.json`)    | Output (signed event)        | Source                                          |
|-----------------------------|------------------------------|-------------------------------------------------|
| —                           | `id`                         | SHA256 of NIP-01 serialization                  |
| —                           | `pubkey`                     | From `getspace` → `script_pubkey` (strip 5120)  |
| `created_at`                | `created_at`                 | Passed through                                  |
| `kind`                      | `kind`                       | Passed through                                  |
| `tags`                      | `tags`                       | Passed through                                  |
| `content`                   | `content`                    | Passed through                                  |
| `space_name`                | —                            | Consumed (selects signing key, not in output)    |
| `sig` (null)                | `sig`                        | BIP340 Schnorr signature of `id`                |

## Signing scheme details

### `walletsignschnorr` digest construction

The message is **not** signed directly. It is prefixed and hashed:

```text
digest = SHA256(b"\x17Spaces Signed Message:\n" || raw_bytes)
signature = BIP340_schnorr_sign(tweaked_privkey, digest)
```

The `\x17` byte (decimal 23) is the length of `"Spaces Signed Message:\n"`.

This means `walletsignschnorr` signatures are **not** Nostr-compatible. The signed
digest includes the Spaces prefix, so Nostr relays that verify signatures using
the standard NIP-01 scheme will reject them.

### Nostr-compatible signing with `sign_event`

The `sign_event` function in `wallet/src/lib.rs` follows the standard Nostr
convention — it signs the event ID directly with no prefix:

```text
serialized = JSON([0, pubkey, created_at, kind, tags, content])
event_id   = SHA256(serialized)
signature  = BIP340_schnorr_sign(tweaked_privkey, event_id)
```

This function is **not currently exposed as an RPC endpoint**. To produce
relay-compatible signatures, either:

1. **Expose `sign_event` over RPC** — add a `walletsignevent` method to the
   JSON-RPC trait in `client/src/rpc.rs` that accepts a `NostrEvent` and returns
   the signed event with `id`, `pubkey`, and `sig` populated.

2. **Sign externally** — derive the Taproot-tweaked private key from the wallet's
   BIP86 descriptor at the correct derivation index (`m/86'/coin'/0'/0/{index}`)
   and sign the event ID directly with BIP340 Schnorr (no prefix). See the
   [key derivation details](#using-walletsignschnorr-via-curl) earlier in this
   document.
