# PVCE: Pedersen Vector Commitment Witness Encryption

**Educational / research prototype — not for production use.**

## What is this?

PVCE is a two-party protocol that locks Bitcoin funds to a Pedersen vector commitment, such that only the party who knows the commitment opening (the witness vector and blinding factor) can recover the private key and spend the funds.

The core idea: the Verifier encrypts a Bitcoin private key to a Pedersen commitment using an ECDH-like construction over the commitment's generators. A DLEQ (Discrete Log Equality) proof guarantees the encryption is well-formed. The Prover, knowing the witness that opens the commitment, can reconstruct the shared secret, derive the same private key, and spend from the resulting Pay-to-Taproot address.

This is a form of *witness encryption* — the ability to encrypt to an NP statement such that only a party holding a valid witness can decrypt. Here the NP statement is "I know an opening of this Pedersen vector commitment," which is a natural building block for more complex constructions (range proofs, set membership, credential systems, etc.).

### Why is this interesting?

- **Conditional payments without scripts**: the spending condition is enforced by the algebraic structure of the commitment, not by on-chain script logic. The output itself is a plain P2TR key-path spend — indistinguishable from any other taproot payment.
- **Composability**: Pedersen vector commitments underpin Bulletproofs, confidential transactions, and many zero-knowledge constructions. Being able to lock funds to a commitment opening means you can build payment conditions around any statement those systems can express.
- **Simplicity**: the protocol uses only standard secp256k1 operations (scalar multiplication, point addition) plus HKDF and SHA256. No pairings, no trusted setup, no exotic assumptions beyond DDH on secp256k1.

### Security properties (brief)

- **Correctness**: a prover with a valid opening always recovers the correct key.
- **Soundness**: without a valid opening, recovering the key requires breaking the ECDH problem on secp256k1.
- **Hiding**: the ciphertext reveals nothing about the witness (under DDH).
- **DLEQ soundness**: a malicious verifier using inconsistent encryption is detected and rejected.

See `pvce_protocol.txt` for the full specification and security discussion.

## Usage

### Build

```bash
cargo build --release
```

### Phase 1 — Setup

```bash
cargo run --release -- setup -n <dimension> [-o state.json]
```

This simulates both parties locally:
- Generates a random witness vector of dimension `n` and a blinding factor (Prover).
- Computes the Pedersen vector commitment.
- Encrypts to the commitment and produces a DLEQ validity proof (Verifier).
- Derives the Bitcoin private key and corresponding P2TR address.

The signet address is printed to stdout. All protocol state (witness, ciphertext, proof, keys) is saved to the JSON file (default: `pvce_state.json`).

**Pay to the printed address on Bitcoin signet.** You can use a signet faucet or any signet wallet.

### Phase 2 — Recover and spend

```bash
cargo run --release -- recover -s state.json --txid <funding_txid> --vout <output_index> --amount <satoshis> [--fee <sats>]
```

This runs the Prover side:
- Verifies the DLEQ proof (ciphertext is well-formed).
- Recovers the shared secret using the witness opening.
- Derives the Bitcoin private key and verifies it matches the funded address.
- Builds and signs a spending transaction (P2TR key-path, BIP 340/341).
- Outputs the raw transaction hex to stdout.

The spending transaction pays to a freshly generated destination key. The destination's WIF private key is printed to stderr.

Broadcast the transaction hex to signet (e.g. via `bitcoin-cli -signet sendrawtransaction <hex>`).

Fee defaults to 200 satoshis.

### Example

```bash
# Generate address (n=4 witness vector)
$ cargo run --release -- setup -n 4
tb1pav7az0wtmrsr3r44r8shaf5tmhl4amq4mw2947tyazmetszuny7qqayl7x

# ... pay to that address on signet, note the txid ...

# Recover and spend
$ cargo run --release -- recover -s pvce_state.json \
    --txid <your_txid> --vout 0 --amount 10000
```

## Project structure

```
src/
  main.rs       CLI (setup / recover), Bitcoin transaction construction
  protocol.rs   Protocol cryptography: generators, commitments, DLEQ, encryption, KDF
```

## Dependencies

- **k256** — secp256k1 elliptic curve arithmetic (RustCrypto)
- **bitcoin** — transaction construction, P2TR addressing, BIP 340 signing
- **sha2** / **hkdf** — SHA-256 and HKDF-SHA256
- **clap** — CLI parsing
- **serde** / **serde_json** — state serialization

## Disclaimer

This is an **educational prototype** built to demonstrate the PVCE construction. It is not audited, not reviewed for side-channel resistance, and not suitable for use with real funds. The protocol specification and implementation are provided for learning and research purposes only.

## Author

Built by Claude (Anthropic), based on the PVCE protocol specification by waxwing.

