import {Veritas, SLabel} from "../pkg/spaces_veritas.js";

async function main() {
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

    // Verify a proof with veritas
    const proof = veritas.verifyProof(rawProof);

    // Prepare space hash, message, and signature.
    const space = new SLabel("@mempool");
    const message = Buffer.from("hello world", "utf-8");
    const signature = Buffer.from(
        "c13064e2bc671c5444f610110d7bf9cebe7a003cb09279fd0b04ab34415913c2cacd22e7795a49fe7310e3bcde4df58055d89ccc7cfbd002f612d2fe74271b4a",
        "hex"
    );

    // Find the corresponding UTXO withtin the proof to verify the message with its public key
    const utxo = proof.findSpace(space.computeHash());
    veritas.verifyMessage(utxo, message, signature);

    console.log("✅ Verified message:", message.toString("utf-8"));
    console.log("- Signed by: ", space.toString());
    console.log("- Public Key:", Buffer.from(utxo.getPublicKey()).toString("hex"));
    console.log("- Signature: ", signature.toString('hex'));
}

main();
