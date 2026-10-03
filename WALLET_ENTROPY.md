# Wallet Creation: Libraries and Entropy

This document traces what happens when a wallet is created — which libraries are involved, where the randomness comes from, and how many bits of entropy back the resulting keys.

**Summary:** wallet creation generates a **12-word BIP-39 mnemonic carrying 128 bits of entropy**, drawn from `thread_rng()` and expanded into a BIP-86 taproot wallet. This repository implements no key generation primitives of its own; it is a thin wrapper over BDK.

## The creation path

Everything starts in `create_wallet` in `client/src/rpc.rs`, which backs both the `walletcreate` JSON-RPC method and the `space-cli createwallet` command:

```rust
pub async fn create_wallet(&self, client: &reqwest::Client, name: &str) -> anyhow::Result<String> {
    let mnemonic: GeneratedKey<_, Tap> =
        Mnemonic::generate((WordCount::Words12, Language::English))
            .map_err(|_| anyhow!("Mnemonic generation error"))?;

    let start_block = self.get_wallet_start_block(client).await?;
    self.setup_new_wallet(name.to_string(), mnemonic.to_string(), Some(start_block.height))?;
    self.load_wallet(name).await?;
    Ok(mnemonic.to_string())
}
```

The mnemonic is then turned into a master extended private key and split into external/internal BIP-86 descriptors:

```rust
fn descriptor_from_mnemonic(network: Network, m: &str) -> anyhow::Result<Xpriv> {
    let mnemonic = Mnemonic::parse(m)?;
    let xkey: ExtendedKey = mnemonic.clone().into_extended_key()?;
    Ok(xkey.into_xprv(network).expect("xpriv"))
}

fn default_descriptors(x: Xpriv) -> (Bip86<Xpriv>, Bip86<Xpriv>) {
    (
        Bip86(x, KeychainKind::External),
        Bip86(x, KeychainKind::Internal),
    )
}
```

## Libraries involved

| Crate | Locked version | Role in wallet creation |
|---|---|---|
| `bdk_wallet` (aliased to `bdk_wallet_backport`) | 1.0.0-beta.6 | Key generation traits, descriptor building, wallet construction |
| `bip39` | 2.2.2 | Mnemonic encoding/parsing and seed derivation (re-exported through BDK's `keys-bip39` feature) |
| `bitcoin` (rust-bitcoin) | 0.32.8 | BIP-32 `Xpriv`, and the re-exported `rand` used as the entropy source |
| `rand` / `rand_core` / `getrandom` | 0.8.5 / 0.6.4 / 0.2.17 | The actual CSPRNG and OS entropy syscall |
| `miniscript` | 12.3.5 | The `Tap` script context parameterizing `GeneratedKey<_, Tap>` |
| `secp256k1` | 0.29.1 | Underlying EC key math for the derived keys |

Note that `bdk_wallet` here is not upstream BDK — the workspace pins a fork, with a comment in the root `Cargo.toml` explaining it is "a temporary backport of bdk for the double-spend issue until we migrate to bdk v3.0".

## Entropy in detail

There is a subtlety worth knowing. BDK declares the entropy buffer as `type Entropy = [u8; 32]`, so `generate_with_aux_rand` fills **32 bytes (256 bits)** from the RNG, and `generate_with_entropy` then truncates it to `word_count / 8` bytes:

```rust
let entropy = &entropy[..(word_count as usize / 8)];
let mnemonic = Mnemonic::from_entropy_in(language, entropy)?;
```

With `WordCount::Words12 = 128`, that slices down to 16 bytes, so the **effective entropy is 128 bits** — the upper 16 bytes are discarded. That is standard and gives roughly 128-bit security, matching secp256k1's own security level, but it means the code requests twice as much randomness as it keeps.

The RNG is `bitcoin::key::rand::thread_rng()`, i.e. `rand` 0.8's thread-local `ThreadRng`: a ChaCha12-based CSPRNG seeded from the OS via `getrandom` and periodically reseeded. This is a cryptographically appropriate source, not a `SmallRng`-style PRNG.

From the mnemonic, `into_extended_key()` derives a 512-bit seed via the standard BIP-39 PBKDF2-HMAC-SHA512 with 2048 iterations, then calls `Xpriv::new_master`. One thing to flag: BDK's `DerivableKey for Mnemonic` impl hardcodes `(self, None)`, meaning an **empty BIP-39 passphrase**. This codebase exposes no way to set a passphrase (no "25th word"), so wallets are recoverable from the 12 words alone.

For reference, the word count to entropy mapping BDK exposes is:

| `WordCount` variant | Entropy |
|---|---|
| `Words12` | 128 bits |
| `Words15` | 160 bits |
| `Words18` | 192 bits |
| `Words21` | 224 bits |
| `Words24` | 256 bits |

Only `Words12` is used by this codebase, and it is not configurable at runtime.

## Recovery is more permissive than creation

`recover_wallet` funnels through the same `descriptor_from_mnemonic`, which uses `Mnemonic::parse` rather than `parse_in`. That accepts any BIP-39-valid length (12/15/18/21/24 words) and auto-detects the language, so a 24-word phrase from elsewhere can be restored even though this client only ever *generates* 12-word English phrases.

## Security notes

The entropy generation itself is sound. The parts worth scrutinizing instead:

- `create_wallet` returns the plaintext mnemonic over JSON-RPC.
- `setup_new_wallet` writes a `wallet.json` export containing the xpriv-bearing descriptors to disk without any explicit file permission hardening.
- No BIP-39 passphrase support, so the mnemonic is the sole secret.
