#!/bin/bash
# Sign a Nostr event JSON file using the space's key via the spaced RPC.
#
# Usage: ./sign_space_event.sh <input.json> [wallet_name]
#
# Input JSON must contain: created_at, kind, tags, content, space_name
# Output: <space_name>_signed.json in the same directory as the input file
#
# Reads RPC config from environment (set by setup-spaced-prod-env.sh):
#   SPACED_RPC_URL, SPACED_RPC_USER, SPACED_RPC_PASSWORD
set -euo pipefail

INPUT="${1:?Usage: $0 <input.json> [wallet_name]}"
WALLET="${2:-main}"

RPC_URL="${SPACED_RPC_URL:-http://127.0.0.1:7224}"
RPC_USER="${SPACED_RPC_USER:-testuser}"
RPC_PASS="${SPACED_RPC_PASSWORD:-SomeRisk84}"

if [ ! -f "$INPUT" ]; then
  echo "ERROR: File not found: $INPUT" >&2
  exit 1
fi

rpc_call() {
  curl -s -X POST "$RPC_URL" \
    -u "$RPC_USER:$RPC_PASS" \
    -H "Content-Type: application/json" \
    -d "$1"
}

SPACE=$(jq -r '.space_name' "$INPUT")
CREATED_AT=$(jq '.created_at' "$INPUT")
KIND=$(jq '.kind' "$INPUT")
TAGS=$(jq -c '.tags' "$INPUT")
CONTENT=$(jq -r '.content' "$INPUT")

if [ "$SPACE" = "null" ] || [ -z "$SPACE" ]; then
  echo "ERROR: No space_name field in $INPUT" >&2
  exit 1
fi

# Strip leading @ for the output filename; keep it for RPC calls
SPACE_BARE="${SPACE#@}"
OUTPUT_DIR=$(dirname "$INPUT")
OUTPUT="${OUTPUT_DIR}/${SPACE_BARE}_signed.json"

echo "Input:   $INPUT"
echo "Space:   $SPACE"
echo "Wallet:  $WALLET"
echo "Output:  $OUTPUT"
echo ""

# Get the space's pubkey from the chain
GETSPACE_RESPONSE=$(rpc_call '{
  "jsonrpc":"2.0","id":1,
  "method":"getspace",
  "params":["'"$SPACE"'"]
}')

SCRIPT_PUBKEY=$(echo "$GETSPACE_RESPONSE" | jq -r '.result.script_pubkey')

if [ "$SCRIPT_PUBKEY" = "null" ] || [ -z "$SCRIPT_PUBKEY" ]; then
  echo "ERROR: Could not get space info for $SPACE" >&2
  echo "$GETSPACE_RESPONSE" | jq . >&2
  exit 1
fi

# script_pubkey is "5120<32-byte-x-only-pubkey-hex>" — strip the witness prefix
PUBKEY="${SCRIPT_PUBKEY:4}"
echo "Pubkey:  $PUBKEY"

# Compute the Nostr event ID per NIP-01
SERIALIZED=$(jq -c -n \
  --arg pubkey "$PUBKEY" \
  --argjson created_at "$CREATED_AT" \
  --argjson kind "$KIND" \
  --argjson tags "$TAGS" \
  --arg content "$CONTENT" \
  '[0, $pubkey, $created_at, $kind, $tags, $content]')

EVENT_ID=$(echo -n "$SERIALIZED" | openssl dgst -sha256 -hex | awk '{print $NF}')
echo "EventID: $EVENT_ID"

# Sign the event ID
MESSAGE_HEX="$EVENT_ID"

SIGN_RESPONSE=$(rpc_call '{
  "jsonrpc":"2.0","id":2,
  "method":"walletsignschnorr",
  "params":["'"$WALLET"'","'"$SPACE"'","'"$MESSAGE_HEX"'"]
}')

SIGNATURE=$(echo "$SIGN_RESPONSE" | jq -r '.result')

if [ "$SIGNATURE" = "null" ] || [ -z "$SIGNATURE" ]; then
  echo "ERROR: Signing failed" >&2
  echo "$SIGN_RESPONSE" | jq . >&2
  exit 1
fi

echo "Sig:     $SIGNATURE"

# Assemble the complete signed Nostr event
jq -n \
  --arg id "$EVENT_ID" \
  --arg pubkey "$PUBKEY" \
  --argjson created_at "$CREATED_AT" \
  --argjson kind "$KIND" \
  --argjson tags "$TAGS" \
  --arg content "$CONTENT" \
  --arg space_name "$SPACE" \
  --arg sig "$SIGNATURE" \
  '{
    id: $id,
    pubkey: $pubkey,
    created_at: $created_at,
    kind: $kind,
    tags: $tags,
    content: $content,
    space_name: $space_name,
    sig: $sig
  }' > "$OUTPUT"

echo ""
echo "Wrote signed event to $OUTPUT"
echo ""
jq . "$OUTPUT"
