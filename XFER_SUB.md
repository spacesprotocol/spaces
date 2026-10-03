# Transferring a Top-Level Space to a New Operator

How to hand off operation of a space (example: `@bitcoinand`) to a different operator, with and
without transferring ownership of the name itself.

There is **no transfer feature in subs**. A clean handoff is a manual runbook combining an on-chain
delegation change (via `space-cli`) with a file-level copy of irreplaceable local state.

---

## Three separable layers

A space handoff touches three things that can each move independently. Confusing them is the main
source of mistakes.

| Layer | What it is | Where it lives | How it moves |
|-------|-----------|----------------|--------------|
| **Sovereignty** | Ownership of the name itself | Space UTXO in a `spaced` wallet | `space-cli transfer` |
| **Operation rights** | Permission to commit subspace roots | Operator num UTXO | `space-cli delegate`, or owner re-runs `space-cli operate` |
| **Operator state** | The handle tree and commitment history | Files under `$SUBS_DATA_DIR` | Manual file copy |

**subs holds no private keys.** Every signature comes from the `spaced` wallet named by
`SUBS_WALLET`, over RPC — Schnorr signatures for temp certs via `wallet_sign_schnorr`, commitment
transactions via `wallet_send_request`. The incoming operator therefore needs their own `spaced`
node and wallet; no key material transfers between operators.

### The delegation key

The delegation for a space is keyed by the hash of the space's **current** script pubkey:

```rust
// nums/src/num_id.rs
NumId::from_spk::<H>(spk)
```

subs calls this value `sptr` and derives it on every live-space lookup, in `get_live_space`
(`core/src/app.rs`):

```rust
let sptr = NumId::from_spk::<Sha256>(fso.script_pubkey().clone());
```

**Anything that moves the space UTXO changes `sptr`**, which revokes the old delegation. The indexer
does this explicitly when a space UTXO is spent (`nums/src/lib.rs:688-700`), then creates a fresh
delegation entry for the new script pubkey (`nums/src/lib.rs:730-749`).

### What survives regardless

Commitments are keyed by **space label + root**, never by owner or script pubkey:

`CommitmentKey::new` in `spaced-spacesops/nums/src/lib.rs`:

```rust
pub fn new<H: KeyHasher>(space: &SLabel, root: [u8; 32]) -> Self {
    let mut data = [0u8; 64];
    data[0..32].copy_from_slice(&H::hash(space.as_ref()));
    data[32..64].copy_from_slice(&root);
    Self(ns_hash::<H>(KeyKind::Registry, H::hash(&data)))
}
```

So the on-chain commitment chain and its tip survive both re-delegation and ownership transfer. The
new operator continues the existing chain rather than starting a new one — which is exactly why they
need the local state described below.

---

## The part that can go permanently wrong

subs compares the on-chain `state_root` against its local commitment history at load time. If it
does not recognise the on-chain root, it disables every operation on the space:

From `check_commitment_health` in `core/src/app.rs`:

```rust
Ok(Some(HealthWarning {
    message: "This space has an on-chain commitment that is not tracked locally. \
              All actions are disabled until recovery is supported. \
              To recover in the future, you will need the .sdb file \
              (name database) and the certificate that was used to prove it.".to_string(),
```

"Until recovery is supported" is literal. `require_healthy` bails out of every action and **no
rebuild path exists** — nothing reconstructs the SpaceDB tree from the SQLite tables. If the new
operator starts with an empty data directory against a space that already has an on-chain
commitment, the space can never be committed to again.

Already-published handles keep resolving throughout, because certificates live on fabric relays
rather than on the operator's disk. The damage is to future operation, not to existing resolution.

### State that must move

Everything under `$SUBS_DATA_DIR/@<space>/`:

| File | Status | Why |
|------|--------|-----|
| `@<space>.sdb` | **Irreplaceable** | The SpaceDB Merkle tree. Treated as source of truth over SQLite. |
| `subs.db` | **Irreplaceable** | Handles, the `prev_root`→`root` chain, `zk_batch` and `exclusion_merkle_proof` guest inputs, and STARK/fold/groth16 receipt blobs. |
| `*.hidx.sqlite` | Regenerable | Hash-index sidecars, rebuilt automatically on open. |

Plus `config.db` at the data-dir root — prover and registry endpoints and tokens. Convenient to
carry, but the new operator can re-enter these.

Prover state is fully disposable: calibration and job queues are in-memory only, so the incoming
operator just needs a reachable prover.

`backup_space.sh` and `backup_subs.sh` in this repo already capture exactly the right set. They
require subs to be stopped, which matters — copying SQLite and the append-only `.sdb` from a live
process risks a torn snapshot. There is no matching restore script; restoring means unpacking so
paths land back at `$SUBS_DATA_DIR/@<space>/`.

---

## Preflight: quiesce the pipeline

Do this before any handoff variant. It matters more than the on-chain mechanics.

Drive the space to a state where nothing is in flight:

1. **No staged handles** — anything staged but uncommitted exists only in the outgoing operator's
   database.
2. **No local commit that has not been broadcast** — it lives in A's `.sdb` and is invisible to the
   chain.
3. **Last broadcast commitment confirmed** — `space-cli getcommitment @<space>` matches the local tip.
4. **All committed handles published** — otherwise handles exist in the tree but resolve nowhere.
5. **No temp certificates outstanding** — see the caveat below; publish everything to final.

The `can_commit_local` gate gives a natural window: after a commit lands on-chain, the next local
commit is blocked until 150 confirmations anyway, so the tail of a cycle is the safest handoff point.

```bash
BASE=http://127.0.0.1:7777
SPACE=%40bitcoinand   # URL-encoded @bitcoinand

# If basic auth is enabled, add: -u "$SUBS_BASIC_AUTH_USER:$SUBS_BASIC_AUTH_PASSWORD"
curl -s "$BASE/spaces/$SPACE/pipeline"
curl -s "$BASE/spaces/$SPACE/commit/status"
```

Confirm the dashboard shows **no health warning** for the space before you begin.

---

## Scenario A — Re-delegation only (name stays with the same owner)

The space keeps its current sovereign owner; only the operating party changes. This is the lower-risk
path and should be preferred whenever ownership does not need to move.

### A1 — Outgoing operator cooperates (recommended)

The current operator can hand off operation **entirely on their own**. `delegate` only requires that
the caller hold the operator num UTXO:

From the `Delegate` handler in `spaced-spacesops/client/src/wallets.rs`:

```rust
RpcWalletRequest::Delegate(params) => {
    let delegate_utxo = find_delegate_utxo(chain, &params.subject)?;
    if !wallet.is_mine(delegate_utxo.numout.script_pubkey.clone()) {
        return Err(anyhow!("delegate: you don't own '{}'", params.subject));
    }
```

The sovereign owner is **not** required to sign, and does not need to be involved.

Critically, `delegate` transfers the operator num without moving the space UTXO, so **`sptr` does not
change**. This is the only handoff variant that leaves the signing identity intact.

**Steps:**

1. **Quiesce** (see preflight above).

2. **Operator B generates a receiving space address.** `--to` must be a space address
   (`bcs1…` mainnet, `tbs1…` testnet, `bcrts1…` regtest); plain Bitcoin addresses are rejected.

   ```bash
   # On B's spaced wallet
   space-cli -w "$B_WALLET" getnewspaceaddress
   ```

   subs also surfaces this on its `/ui/operate` page as the Operator Address.

3. **Stop subs on A**, then back up:

   ```bash
   ./backup_space.sh @bitcoinand
   ```

4. **Restore onto B** so files land at `$SUBS_DATA_DIR/@bitcoinand/`, and start subs pointed at it.
   Verify **no health warning** appears and that handle counts and pipeline state match what A
   reported. Do this *before* moving the delegation — while the delegation still sits with A, this
   step is fully reversible.

5. **Operator A transfers the operator num to B:**

   ```bash
   space-cli -w "$A_WALLET" delegate @bitcoinand --to "$B_SPACE_ADDRESS"
   ```

6. **Wait for confirmation**, then verify from B (see Verification below).

7. **Decommission A** only after B has completed a full commit cycle.

### A2 — Outgoing operator is unavailable or uncooperative

There is **no `revoke` or `undelegate` command**. The owner revokes an operator by re-running
`operate`, which spends the space UTXO — revoking the delegation keyed to the old script pubkey — and
mints a fresh operator num in the owner's own wallet:

From the `Operate` handler in `spaced-spacesops/client/src/wallets.rs`:

```rust
builder = builder.add_transfer(SpaceTransfer {
    space: full,
    recipient,
    create_num: true,
});
```

Because this moves the space UTXO, **`sptr` changes** — carrying the same temp-certificate caveat as
a full ownership transfer.

```bash
# Sovereign owner, in the wallet holding @bitcoinand
space-cli -w "$OWNER_WALLET" operate @bitcoinand
# wait for confirmation, then:
space-cli -w "$OWNER_WALLET" delegate @bitcoinand --to "$B_SPACE_ADDRESS"
```

The local state copy (steps 3–4 above) is still required, and is still the part that can fail
permanently. If A is unreachable and their `.sdb` was never copied, the space is unrecoverable for
future commits.

---

## Scenario B — Full transfer (name and operation)

Ownership of `@bitcoinand` moves to a new party, who then operates it (or delegates onward).

A plain `transfer` revokes the delegation and does **not** mint a replacement operator num, so
operation is broken until the new owner runs `operate`. Expect two sovereignty-moving transactions.

**Steps:**

1. **Quiesce**, and specifically **flush all temp certificates to final** — see the caveat below.

2. **Copy local state** to the new operator and verify it loads without a health warning, exactly as
   in A1 steps 3–4. Do this first; it is the only irreversible part.

3. **Current owner transfers the space:**

   ```bash
   space-cli -w "$OWNER_WALLET" transfer @bitcoinand --to "$NEW_OWNER_SPACE_ADDRESS"
   ```

   `--to` accepts a space name (`@newowner`), a numeric, a num id, or a space address.

4. **Wait for confirmation.** At this point the old delegation is revoked and no operator num exists
   at the new script pubkey, so nobody can commit. This is expected.

5. **New owner initialises operation:**

   ```bash
   space-cli -w "$NEW_OWNER_WALLET" operate @bitcoinand
   ```

   This moves the space again — to a fresh unique address inside the new owner's wallet — and mints
   the operator num there.

6. **If the operator is a different party from the new owner**, delegate onward:

   ```bash
   space-cli -w "$NEW_OWNER_WALLET" delegate @bitcoinand --to "$OPERATOR_SPACE_ADDRESS"
   ```

   Skip this if the new owner operates the space themselves.

7. **Verify and run a full commit cycle** before decommissioning the old operator.

---

## The temp-certificate caveat

Any operation that moves the space UTXO — `transfer`, or `operate` re-run by the owner — changes
`sptr`. Two consequences:

**Delegation must be re-established.** `get_live_space` requires a num to exist at the new `sptr`
and errors with `no delegate {} found for space {}` otherwise (`core/src/app.rs:1602-1604`).

**Outstanding temp certificates are expected to stop verifying.** Temp certs are the staged,
uncommitted ones, signed via `wallet_sign_schnorr` against `Subject::NumId(sptr)`. Final certificates
use Merkle inclusion proofs with `signature: None` (`core/src/core.rs:754-762`) and are unaffected.

> The temp-cert half of this is **inference** from how the certificates are constructed, not
> something traced through `libveritas` verification. Treat it as a reason to publish everything to
> final before an `sptr`-changing operation, rather than as a confirmed failure mode.

Scenario A1 avoids this entirely, which is the main argument for preferring it.

---

## Verification

Run these from the new operator after the delegation has confirmed.

**On-chain:**

```bash
# Delegation points at a num the new operator holds
space-cli getdelegation @bitcoinand
space-cli -w "$B_WALLET" listnums --kind owned

# Space ownership and commitment tip
space-cli getspace @bitcoinand
space-cli getcommitment @bitcoinand
```

There is no `space-cli` wrapper for `walletcanoperate`; use the subs dashboard, which calls it during
the operate flow, or infer it from `getdelegation` plus `listnums`.

**In subs:**

| Check | Expectation |
|-------|-------------|
| Dashboard health | No warning on the space |
| `GET /spaces/:space/pipeline` | Local tip matches `getcommitment` |
| Handle counts | Match what the outgoing operator reported |
| `POST /query` for a known handle | Resolves and verifies via fabric relays |

The `POST /query` check is the strongest signal — it goes out to relays and verifies against your own
spaced root anchors, exercising the full chain.

**Final gate:** run one complete cycle — stage, commit, prove, broadcast, confirm, publish — before
destroying the outgoing operator's copy. Keep an offline archive of A's final backup permanently; it
is the only recovery material that exists.

---

## Common mistakes

| Wrong | Right |
|-------|-------|
| Move the delegation, then copy the files | Copy and verify the files first; the delegation change is the easy part to redo |
| Copy the data directory with subs running | Stop subs first — the `.sdb` is append-only and SQLite may tear |
| Start the new operator with an empty data dir | Unrecoverable: on-chain root unknown locally disables all actions |
| Hand off mid-cycle | Quiesce first; unbroadcast commits and unpublished handles do not survive the move |
| Assume the owner must authorise re-delegation | In A1 the current operator acts alone; the owner is not involved |
| Look for a `revoke` command | Does not exist; the owner re-runs `operate` |
| `delegate --to` a regular `bc1…` address | Must be a space address (`bcs1…` / `tbs1…` / `bcrts1…`) |
| Expect `transfer` alone to hand over operation | `transfer` revokes delegation; the new owner must then run `operate` |
| Delete the old operator's backup after cutover | Keep it offline and permanently |

---

## Command reference

Verified against `spaced-spacesops` (`client/src/bin/space-cli.rs`). Subcommands are lowercase with
no hyphens.

| Command | Who signs | Effect |
|---------|-----------|--------|
| `space-cli operate <SUBJECT>` | Sovereign owner | Moves space to a fresh address in own wallet, mints operator num. Also the revoke mechanism. |
| `space-cli delegate <SUBJECT> --to <SPACE-ADDR>` | Current operator | Transfers the operator num. Does not move the space. |
| `space-cli transfer <SUBJECT>... --to <SPACE-OR-ADDR>` | Sovereign owner | Moves sovereignty; revokes delegation. |
| `space-cli commit <SUBJECT> <ROOT>` | Current operator | Commits a state root (subs does this for you). |
| `space-cli rollback <SUBJECT>` | Current operator | Rolls back the last pending commitment. |
| `space-cli getdelegation <SUBJECT>` | — | Num id currently responsible for the space. |
| `space-cli getdelegator <SUBJECT>` | — | Space a given num id is responsible for. |
| `space-cli getcommitment <SUBJECT> [ROOT]` | — | On-chain commitment / tip. |
| `space-cli getspace <SUBJECT>` | — | Space UTXO and owner script pubkey. |
| `space-cli getnewspaceaddress` | — | Space address for receiving spaces and nums. |
| `space-cli listnums --kind owned` | — | Operator nums held by the wallet. |

Connection flags are global: `--chain` (`SPACED_CHAIN`), `--rpc-url`, `--rpc-cookie`
(`SPACED_RPC_COOKIE`), `--rpc-user` / `--rpc-password` (`SPACED_RPC_USER` / `SPACED_RPC_PASSWORD`),
and `-w` / `--wallet` (default `default`). Default mainnet RPC port is 7225.

---

## Related docs

| Topic | File |
|-------|------|
| New space setup and the commit cycle | `SETUP_NEW_SPACE.md` |
| Publish walkthrough | `SUBS_PUBLISH.md` |
| Resolution and trust model | `VERITAS_RESOLUTION.md` |
| Publish/resolve failures | `FIX_SIGNATURE_INVALID.md` |
| Delegation from the indexer side | `spaced-spacesops/OPERATOR.md`, `spaced-spacesops/SUBSPACES.md` |
| Health check implementation | `core/src/app.rs` (`check_commitment_health`, `require_healthy`) |
| Delegation lifecycle | `spaced-spacesops/nums/src/lib.rs` (revoked/new delegations) |
