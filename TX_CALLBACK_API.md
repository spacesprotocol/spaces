# Transaction Callback API Documentation

## Overview

The Transaction Callback API provides a mechanism for clients to register callback endpoints that will be notified when specific Bitcoin transactions are included in blocks. This enables real-time monitoring of transaction confirmations without requiring continuous polling.

## Architecture

The callback system consists of:
- **Callback Registry**: Manages registered clients and their watched transaction IDs
- **Block Processing Integration**: Automatically checks each new block for watched transactions
- **HTTP Notifications**: Sends POST requests to registered callback URLs when transactions are found

## RPC Endpoints

### 1. `registertxcallback`

Register a new client with a callback URL.

**Parameters:**
- `client_id` (string): Unique identifier for this client
- `callback_url` (string): HTTP/HTTPS URL endpoint to receive notifications

**Returns:**
- Success: `null` (no error)
- Error: Error object with code and message

**Example:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "registertxcallback",
  "params": {
    "client_id": "my-service-001",
    "callback_url": "https://example.com/api/tx-notifications"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": null
}
```

### 2. `unregistertxcallback`

Unregister a client and remove all its watched transactions.

**Parameters:**
- `client_id` (string): The client ID to unregister

**Returns:**
- `true` if client was found and unregistered
- `false` if client was not found

**Example:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "unregistertxcallback",
  "params": {
    "client_id": "my-service-001"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": true
}
```

### 3. `updatetxwatches`

Update the list of transaction IDs that a client is watching for.

**Parameters:**
- `client_id` (string): The client ID
- `txids` (array of strings): Array of transaction IDs (hex-encoded) to watch for

**Returns:**
- `true` if client was found and updated
- `false` if client was not found

**Example:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "updatetxwatches",
  "params": {
    "client_id": "my-service-001",
    "txids": [
      "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
      "b2086ec66e527e4db2aa0g66c7195f3226c0456f27d6dg413gd91f0e6gcg6e59e"
    ]
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": true
}
```

### 4. `gettxcallback`

Get information about a registered callback client.

**Parameters:**
- `client_id` (string): The client ID to query

**Returns:**
- `null` if client not found
- Client object with:
  - `client_id` (string)
  - `callback_url` (string)
  - `watched_txids` (array of strings)
  - `registered_at` (number): Unix timestamp

**Example:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "gettxcallback",
  "params": {
    "client_id": "my-service-001"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "client_id": "my-service-001",
    "callback_url": "https://example.com/api/tx-notifications",
    "watched_txids": [
      "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"
    ],
    "registered_at": 1704067200
  }
}
```

### 5. `listtxcallbacks`

List all registered callback clients.

**Parameters:** None

**Returns:**
- Array of client objects (same structure as `gettxcallback`)

**Example:**
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "listtxcallbacks",
  "params": {}
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "result": [
    {
      "client_id": "my-service-001",
      "callback_url": "https://example.com/api/tx-notifications",
      "watched_txids": ["a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"],
      "registered_at": 1704067200
    },
    {
      "client_id": "another-service",
      "callback_url": "https://another.example.com/webhook",
      "watched_txids": [],
      "registered_at": 1704067300
    }
  ]
}
```

## Callback Notification Format

When a watched transaction is found in a block, a POST request is sent to the registered callback URL with the following JSON payload:

```json
{
  "txid": "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
  "block_height": 850000,
  "block_hash": "0000000000000000000123456789abcdef0123456789abcdef0123456789abcdef",
  "confirmations": 1,
  "chain_tip_height": 850000,
  "notified_at": 1704067500
}
```

**Fields:**
- `txid`: The transaction ID that was found (hex string)
- `block_height`: Block height where the transaction was included
- `block_hash`: Block hash (hex string)
- `confirmations`: Number of confirmations (1 for the block it was included in)
- `chain_tip_height`: Current chain tip height at notification time
- `notified_at`: Unix timestamp when the notification was sent

## Complete Usage Example

This example demonstrates the full lifecycle of watching for a transaction:

### Step 1: Register a Client

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic <token>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "registertxcallback",
    "params": {
      "client_id": "payment-processor",
      "callback_url": "https://myapp.com/api/payment-confirmed"
    }
  }'
```

### Step 2: Set Up Watched Transactions

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic <token>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "updatetxwatches",
    "params": {
      "client_id": "payment-processor",
      "txids": [
        "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"
      ]
    }
  }'
```

### Step 3: Update Watched Transactions (Adding More)

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic <token>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "updatetxwatches",
    "params": {
      "client_id": "payment-processor",
      "txids": [
        "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
        "b2086ec66e527e4db2aa0g66c7195f3226c0456f27d6dg413gd91f0e6gcg6e59e",
        "c3097fd77f638f5ec3bb1h77d82a0g4337d1568g38eh524he02g1f7hdhd7f6af"
      ]
    }
  }'
```

### Step 4: Check Client Status

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic <token>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "gettxcallback",
    "params": {
      "client_id": "payment-processor"
    }
  }'
```

### Step 5: Receive Notification

When one of the watched transactions is included in a block, your callback endpoint will receive:

```http
POST https://myapp.com/api/payment-confirmed HTTP/1.1
Content-Type: application/json

{
  "txid": "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
  "block_height": 850000,
  "block_hash": "0000000000000000000123456789abcdef0123456789abcdef0123456789abcdef",
  "confirmations": 1,
  "chain_tip_height": 850000,
  "notified_at": 1704067500
}
```

### Step 6: Update Watched Transactions (Remove Completed)

After processing a notification, you may want to remove that transaction from the watch list:

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic <token>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 5,
    "method": "updatetxwatches",
    "params": {
      "client_id": "payment-processor",
      "txids": [
        "b2086ec66e527e4db2aa0g66c7195f3226c0456f27d6dg413gd91f0e6gcg6e59e",
        "c3097fd77f638f5ec3bb1h77d82a0g4337d1568g38eh524he02g1f7hdhd7f6af"
      ]
    }
  }'
```

### Step 7: Unregister When Done

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic <token>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 6,
    "method": "unregistertxcallback",
    "params": {
      "client_id": "payment-processor"
    }
  }'
```

## Implementation Notes

### Callback Endpoint Requirements

Your callback endpoint should:
1. Accept POST requests with JSON content
2. Return a 2xx HTTP status code on success
3. Respond quickly (notifications are sent asynchronously, but slow responses may cause issues)
4. Be idempotent (same notification may be sent multiple times in case of retries)

### Error Handling

- If a callback URL returns a non-2xx status code, an error is logged but the system continues
- Network errors are logged but don't affect block processing
- Failed callbacks do not prevent other callbacks from being sent

### Performance Considerations

- Notifications are sent asynchronously and don't block block processing
- Multiple transactions in the same block trigger separate notifications
- The same transaction ID can be watched by multiple clients
- Callback registry operations are thread-safe and use async locks

### Security Considerations

- Use HTTPS for callback URLs in production
- Implement authentication/authorization on your callback endpoints
- Validate the notification payload on your callback endpoint
- Consider rate limiting on your callback endpoint

## Example Callback Endpoint Implementation

Here's a simple example of a callback endpoint handler:

```python
from flask import Flask, request, jsonify
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

@app.route('/api/payment-confirmed', methods=['POST'])
def payment_confirmed():
    notification = request.json
    
    txid = notification['txid']
    block_height = notification['block_height']
    confirmations = notification['confirmations']
    
    logging.info(f"Transaction {txid} confirmed in block {block_height} with {confirmations} confirmations")
    
    # Process the payment confirmation
    # ... your business logic here ...
    
    return jsonify({'status': 'received'}), 200
```

## Troubleshooting

### Notifications Not Received

1. Verify the client is registered: `gettxcallback`
2. Check that transaction IDs are correctly set: `gettxcallback` shows `watched_txids`
3. Verify the callback URL is accessible from the spaced server
4. Check server logs for callback errors

### Transaction Already Confirmed

If a transaction was already confirmed before you registered the callback, you won't receive a notification. You should:
1. Check the transaction status using `gettxmeta`
2. Register the callback before the transaction is broadcast
3. Monitor the mempool separately if needed

### Multiple Notifications

You may receive multiple notifications for the same transaction if:
- The callback endpoint was slow to respond
- Network issues caused retries
- The transaction appears in multiple blocks (shouldn't happen, but handle gracefully)

Always make your callback handler idempotent.

