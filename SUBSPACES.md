# Guide to Subspaces

## Operating a Space

### 1. Initialize the Space

Delegate your space to a UTXO that can be used to submit commitments:

```bash
$ space-cli delegate @bitcoin
```

### 2. Issue Subspaces

Use [subs](https://github.com/spacesprotocol/subs) to issue subspaces off-chain and create commitments.


An **end-user** can generate a key pair like this:

```
$ subs request alice@bitcoin
✔ Created handle request
   → alice@bitcoin.req.json
   → Private key saved: alice@bitcoin.priv
```

An **operator** such as @bitcoin, can accept requests into their tree:

```
$ subs add alice@bitcoin.req.json
```


For this example, we will commit just one handle, but it's more efficient to add a large batch of handles before making a commitment.

```
$ subs commit
✔ Committed batch
   → Tree root: 79d39952ac5a8d6daedd48e59c0a58d12d10644c09f2fa3c70e9fe76e72f866a
```


### 3. Submit Commitments

After your tree is updated, commit it's root hash. Each commitment is cryptographically bound to all previous commitments you made on-chain.

**Example:** To submit a commitment for `@bitcoin` with root hash `79d39952ac5a8d6daedd48e59c0a58d12d10644c09f2fa3c70e9fe76e72f866a`:

```bash
$ space-cli commit @bitcoin 79d39952ac5a8d6daedd48e59c0a58d12d10644c09f2fa3c70e9fe76e72f866a
```

**Retrieve commitments** for a space:

```bash
$ space-cli getcommitment @bitcoin
```


### Authorizing Operational Control

You can authorize another party to make commitments on your behalf by transferring the space pointer:

```bash
$ space-cli authorize @bitcoin --to <operator-address>
```

## Binding Handles On-Chain

Handles like `alice@bitcoin` are bound to unique script pubkeys off-chain and are designed to remain off-chain by default. However, when on-chain interactivity is required, handles can be bound to UTXOs with minimal on-chain footprint.

### Creating a Space Pointer

Given a handle with its associated script pubkey:

```json
{
  "handle": "alice@bitcoin",
  "script_pubkey": "5120d3c3196cb3ed7fa79c882ed62f8e5942e546130d5ae5983da67dbb6c9bdd2e79"
}
```

You can create an on-chain identifier that only the controller of the script pubkey can use, without requiring additional metadata on-chain:

```bash
$ space-cli createptr 5120d3c3196cb3ed7fa79c882ed62f8e5942e546130d5ae5983da67dbb6c9bdd2e79
```

This command creates a UTXO with the same script pubkey and "mints" a num id derived from it:

```
sptr13thcluavwywaktvv466wr6hykf7x5avg49hgdh7w8hh8chsqvwcskmtxpd
```

The space pointer serves as a permanent, transferable on-chain reference for the handle that can be sold and transferred like any other space UTXO.