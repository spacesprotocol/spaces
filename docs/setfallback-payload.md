# Forming the `setfallback` OP_RETURN payload

This document describes **exactly** how to build the byte string that `space-cli setfallback` places inside the Taproot/Spaces transaction’s **data output**: the bytes pushed after `OP_RETURN` and `OP_PUSHNUM_1`. The same bytes are what `--dry-run` prints (hex-encoded).

Implementation references:

- SIP-7 packing: `sip7/src/lib.rs` (`Record`, `RecordSet`, `write_compact_size`)
- OP_RETURN script: `protocol/src/script.rs` (`create_data_script`)
- CLI assembly: `client/src/bin/space-cli.rs` (`SetFallback`)

---

## 1. Terms

| Term | Meaning |
|------|--------|
| **Payload** | Raw SIP-7 **record set** bytes: zero or more records concatenated. This is the `data` field sent to the wallet / passed to `create_data_script`. |
| **Script** | Full `scriptPubKey` of the 0-sat output: `OP_RETURN` · `OP_PUSHNUM_1` · Bitcoin push opcode · **payload**. Built by `create_data_script(&payload)`. |

The indexer reads the payload with `find_op_set_data`: it expects `OP_RETURN`, then `OP_PUSHNUM_1`, then the pushed bytes (the payload).

---

## 2. Record set layout

A **record set** is a **concatenation** of one or more **records**, in order. Each record has this outer shape:

1. **`rtype`** — 1 byte: record type (see §3).
2. **`rlen`** — **compact size** (Bitcoin-style, see §4): length of **`rdata`** in bytes.
3. **`rdata`** — type-specific body, exactly `rlen` bytes.

There is **no** record count field; parsing is sequential until the buffer ends.

---

## 3. Record type bytes

Defined in `sip7` as:

| `rtype` | Constant | Semantics |
|---------|-----------|-----------|
| `0x00` | `TYPE_SEQ` | Sequence / version record |
| `0x01` | `TYPE_TXT` | Key/value text record (used by `--txt`) |
| `0x02` | `TYPE_BLOB` | Key + binary blob (used by `--blob`) |
| other | — | **Unknown** record: `rdata` is opaque |

---

## 4. Compact size (`write_compact_size`)

Used for `rlen` on every record and for string lengths inside TXT values.

Let `n` be a non-negative integer:

- If `n ≤ 0xFC`: emit **one** byte `n`.
- If `0xFD ≤ n ≤ 0xFFFF`: emit `0xFD` then `n` as **little-endian u16** (2 bytes).
- If `0x10000 ≤ n ≤ 0xFFFFFFFF`: emit `0xFE` then `n` as **little-endian u32** (4 bytes).
- Else: emit `0xFF` then `n` as **little-endian u64** (8 bytes).

For typical `setfallback` usage, all sizes fit in the single-byte form.

---

## 5. TXT record (`rtype = 0x01`)

Used when you pass `--txt key=value` or JSON `{ "type": "txt", "key": "…", "value": ["…"] }`.

### 5.1 Key rules

Keys must pass `validate_key` in `sip7`:

- Non-empty, at most **255** bytes.
- Every byte must be **lowercase ASCII letter** (`a`–`z`), **digit** (`0`–`9`), or **hyphen** (`-`).

So keys like `space`, `nostr`, `btc` are valid; `@` in the key is **not** allowed (the `@` belongs in the **value**, e.g. `space=@rad`).

### 5.2 `rdata` layout (inside the TXT record)

After `rtype` and `rlen`, **`rdata`** is:

| Field | Size | Description |
|-------|------|-------------|
| `kl` | 1 byte | Key length; must equal `key.as_bytes().len()` and be ≤ 255 |
| `key` | `kl` bytes | UTF-8 key (ASCII in practice) |
| `values` | rest | Concatenation of one or more **value chunks** |

Each **value chunk** is:

1. **`write_compact_size(len)`** where `len` is the byte length of the next string.
2. **`len` bytes** — UTF-8 string.

`Record::txt(key, value)` produces **one** value string. `Record::txts(key, values)` produces **multiple** chunks in order.

### 5.3 Computing `rlen` for a TXT record

`rlen` must equal the length of `rdata`:

```text
rlen = 1 + key.len() + sum_over_values ( compact_size(utf8_len(s)) + utf8_len(s) )
```

Equivalently, the code builds `val_buf` from all value strings, then:

```text
rlen = 1 + key.len() + val_buf.len()
```

---

## 6. BLOB record (`rtype = 0x02`)

Used for `--blob key=BASE64`. **`rdata`** is:

| Field | Size | Description |
|-------|------|-------------|
| `kl` | 1 byte | Key length |
| `key` | `kl` bytes | Same key rules as TXT |
| `value` | rest | Raw bytes (decoded from base64 on the CLI) |

`rlen = 1 + key.len() + value.len()`.

---

## 7. SEQ record (`rtype = 0x00`)

**`rdata`** is a single compact-encoded integer (the version). Packing uses a small inner buffer, then `rlen` is the length of that buffer.

**Rules when mixing with other records:**

- At most **one** SEQ record.
- If present, SEQ must be the **first** record in the set.

`setfallback` via `--txt` / `--blob` / `--raw` / `--stdin` does **not** insert a SEQ unless you include it in JSON or raw bytes yourself.

---

## 8. Unknown record (`rtype` not in 0x00–0x02)

**`rdata`** is arbitrary; `rlen` is its length. For round-tripping opaque types.

---

## 9. Order of records (CLI)

For `space-cli setfallback`:

- **`--txt` / `--blob`**: records are appended in the **order flags appear** on the command line.
- **`--stdin` JSON**: order is the order of elements in the JSON array.
- **`--raw`**: the payload is **exactly** your decoded bytes; you must already encode valid SIP-7.

The `<SUBJECT>` argument (`@rad`, etc.) selects **which space/num** is updated; it does **not** appear inside the SIP-7 payload unless you put it in a `--txt` or JSON field (e.g. `space=@rad`).

---

## 10. From payload to full `scriptPubKey`

After you have the payload bytes `P`:

1. Build a Bitcoin script:

   - `OP_RETURN` (`0x6a`)
   - `OP_PUSHNUM_1` (`0x51`)
   - **Push** `P` using standard Bitcoin script push rules (for `len(P) ≤ 75`, this is `OP_PUSHBYTES_len` = `0x01`…`0x4b` with `len = |P|`, followed by `P`).

2. The 0-sat output uses that script as `scriptPubKey`.

In Rust, `spaces_protocol::script::create_data_script(&P)` does this via `bitcoin::ScriptBuf`’s builder (`push_slice`).

---

## 11. Full worked example

Command (conceptually):

```bash
space-cli setfallback @rad --txt space=@rad --txt nostr=npub1mutuum
```

**Record 1 — TXT `space` → `@rad`**

- `rtype` = `0x01`
- `key` = `space` → `kl = 5`, key bytes `73 70 61 63 65`
- Value `@"rad"` UTF-8 = 4 bytes `40 72 61 64` → compact size `0x04`, then those 4 bytes  
- `val_buf` = `04 40 72 61 64` (5 bytes)
- `rlen` = `1 + 5 + 5` = **11** → compact size `0x0b`
- Full record: `01 0b 05 73 70 61 63 65 04 40 72 61 64`

**Record 2 — TXT `nostr` → `npub1mutuum`**

- `key` = `nostr` (5 bytes)
- Value length 11 → compact `0x0b`, then ASCII `npub1mutuum`
- `rlen` = `1 + 5 + (1 + 11)` = **18** → compact `0x12`
- Full record: `01 12 05 6e 6f 73 74 72 0b 6e 70 75 62 31 6d 75 74 75 75 6d`

**Payload `P`** (33 bytes, hex):

```text
010b05737061636504407261640112056e6f7374720b6e707562316d757475756d
```

**Script** (prefix only; actual push opcode follows Bitcoin rules for length 33, typically `0x21` + 33 bytes):

```text
6a 51 <push P> P
```

---

## 12. Verification

- **Rust**: `sip7::RecordSet::pack(vec![...])?.to_bytes()` must equal your hand-built `P`.
- **CLI**: `space-cli setfallback <any-subject> ... --dry-run` prints `hex_encode(P)` (subject ignored for encoding).

---

## 13. Related reading

- SIP-7 JSON shape for `--stdin`: `sip7` serde types in `sip7/src/lib.rs` (`RecordJson`, etc.).
- How the wallet attaches `P` to the tx: `client/src/wallets.rs` (`RpcWalletRequest::SetFallback` → `add_data` → `create_data_script` in `wallet/src/builder.rs`).
