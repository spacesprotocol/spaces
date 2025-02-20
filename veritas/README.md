
# 🔑 Veritas 

Veritas is a <strong>stateless way</strong> to verify <strong><a href="https://spacesprotocol.org">Spaces on Bitcoin</a></strong> using a permissionless <strong>trust anchor</strong> (a 32-byte hash), without needing a full Bitcoin node on your phone!


## 🚀 What Can Your App Do?

- **Scan or fetch a trust anchor** from a **trusted node** to sync instantly.
- **Use it to verify any `space -> pubkey` mapping** with a Merkle inclusion proof.
- **Messages & DNS packets are signed with the space's pubkey**—records can be resolved and updated off-chain without modifying the trust anchor itself.
- **Display the trust anchor for transparency**—users can compare it against public explorers or services they trust.
    - Think of it like a [Signal safety number](https://support.signal.org/hc/en-us/articles/360007060632-What-is-a-safety-number-and-why-do-I-see-that-it-changed), except better! A **single** identifier for all contacts.
- **Re-scan or fetch** periodically to include recent changes, such as new space registrations or transfers.

> **Note:** Trust anchors are **32-byte Merkle tree roots** that represent a **summary of the entire protocol state** at a specific Bitcoin block height.

---

## Javascript Example

### Verifying proofs

```javascript
const veritas = new Veritas();

// Set up a trust anchor
const root = Buffer.from(
    "a44ad8bca3184798d75f69b9c50bfbc67dd1bcf550a9ce3a943ff6501ab60693",
    "hex"
);
veritas.addAnchor(root);

const rawProof = Buffer.from(
    "AQEAAouXDhe+rJKxqcvRzRIthc2QkNuPDt34M2NmW8nLoqk0AQACD5+x6CJLkmxgKPTyS0Nq9Ci03Lev9Fm20W+kyCzvewMBAAEAAvNWZU+az0t38K0pMm5Ny5fWGFZskajtKZ+On2Z4PkGqAQACXb+CBVIEjx7wDHZbG/FWKuczR8WgyHSelZBwXIzjflIBAAJo/bDo+osV3y5G7AGeMv6i/LMbCozs2tk3jUg0+0L8nwEAAQABAAEAAiMCqoVnipJoF4xoNhz7owXgN+ozXdgce3MZX/M7WCXOAG4seB00O3x87+y2CM1e1uZhmTkmmkyUwyjxv/IronYzADcBAQdtZW1wb29sAfzA3gEAAPuaAiJRIHj13+6+2Wc7tWB+ZswSvzvEKCzhUjuwUsQyFJX0f8SHAklClIvNFftzNbqMoAe7bdDpm4pnWyU6o+abgq+22xEgAiNAa7W4k9sjy7lYKzZtx1ag2VVcz+XzwDLPZU02XiIDAqh+BDASBJSQYgMZPd/BAgbND21I/8FFfcpHsJqqsb4lAnHXQmQvzKYfAhWXtBD687lb4qqZudMBPZY0UQsqNWBC",
    "base64"
);

// Verify a proof with veritas
const proof = veritas.verifyProof(rawProof);

// Iterate over the proof entries
for (const {key, value: utxo} of proof.entries()) {
    const space = utxo.getSpace();
    console.log('✅ Space: ', space.getName().toString());
    console.log('🔑 Public key: ', Buffer.from(utxo.getPublicKey()).toString('hex'));
}
```

### Verifying messages

```javascript
const veritas = new Veritas();

// Set up a trust anchor
const anchor = Buffer.from(
    "a44ad8bca3184798d75f69b9c50bfbc67dd1bcf550a9ce3a943ff6501ab60693",
    "hex"
);
veritas.addAnchor(anchor);

const rawProof = Buffer.from(
    "AQEAAouXDhe+rJKxqcvRzRIthc2QkNuPDt34M2NmW8nLoqk0AQACD5+x6CJLkmxgKPTyS0Nq9Ci03Lev9Fm20W+kyCzvewMBAAEAAvNWZU+az0t38K0pMm5Ny5fWGFZskajtKZ+On2Z4PkGqAQACXb+CBVIEjx7wDHZbG/FWKuczR8WgyHSelZBwXIzjflIBAAJo/bDo+osV3y5G7AGeMv6i/LMbCozs2tk3jUg0+0L8nwEAAQABAAEAAiMCqoVnipJoF4xoNhz7owXgN+ozXdgce3MZX/M7WCXOAG4seB00O3x87+y2CM1e1uZhmTkmmkyUwyjxv/IronYzADcBAQdtZW1wb29sAfzA3gEAAPuaAiJRIHj13+6+2Wc7tWB+ZswSvzvEKCzhUjuwUsQyFJX0f8SHAklClIvNFftzNbqMoAe7bdDpm4pnWyU6o+abgq+22xEgAiNAa7W4k9sjy7lYKzZtx1ag2VVcz+XzwDLPZU02XiIDAqh+BDASBJSQYgMZPd/BAgbND21I/8FFfcpHsJqqsb4lAnHXQmQvzKYfAhWXtBD687lb4qqZudMBPZY0UQsqNWBC",
    "base64"
);

// Verify proof with veritas
const proof = veritas.verifyProof(rawProof);

// Prepare space, message, and signature.
const space = new SLabel("@mempool");
const msg = Buffer.from("hello world", "utf-8");
const sig = Buffer.from(
    "c13064e2bc671c5444f610110d7bf9cebe7a003cb09279fd0b04ab34415913c2cacd22e7795a49fe7310e3bcde4df58055d89ccc7cfbd002f612d2fe74271b4a",
    "hex"
);

// Find a UTXO associated with the space withtin the proof 
// to verify a message signed with it
const utxo = proof.findSpace(space.computeHash());
veritas.verifyMessage(utxo, msg, sig);

console.log("✅ Verified message:", msg.toString("utf-8"));
console.log("- Signed by: ", space.toString());
console.log("- Public Key:", Buffer.from(utxo.getPublicKey()).toString("hex"));
console.log("- Signature: ", sig.toString('hex'));
```



## Multiple anchors

Since the Spaces client generates a new trust anchor every 6 hours to include recent updates, it’s recommended to retain older anchors to verify against older proofs while prioritizing the most recent one when available. Depending on your use case and the availability of older proofs, your app could need to re-scan/sync a new anchor once a day, week, month or even longer!


## Compiling from Source

To compile from source, use `wasm-pack` you need to have clang installed.

```bash
./wasm.sh
```


## License

Licensed under the MIT license.