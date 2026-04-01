# PVCE: Pedersen Vector Commitment Witness Encryption

## Protocol Specification — Bitcoin Signet Settlement

---

## Overview

A two-party protocol. The **Prover** holds a secret witness vector and its commitment blinding. The **Verifier** holds only the commitment. The Verifier encrypts a Bitcoin private key to the commitment such that only the Prover — by virtue of knowing the commitment opening — can recover it and spend the associated on-chain output.

## Participants

| Party | Knows | Wants |
|-------|-------|-------|
| **P** (Prover) | Witness $(c_1, \ldots, c_n)$ and blinding scalar $r$ | To recover the Bitcoin private key and spend the output |
| **V** (Verifier) | Commitment $C$ | To lock funds such that only a valid opener can spend |

## Cryptographic Setting

- **Curve:** secp256k1, order $p$, standard generator $G$ (the Bitcoin generator)

**Generators for Pedersen commitment** — independent of $G$, generated once via deterministic hash-to-curve from fixed public strings:

$$G_i = \textrm{HashToCurve}(\texttt{"PVCE\\_G\\_"} \Vert i) \quad \text{for } i = 1, \ldots, n$$

$$H = \textrm{HashToCurve}(\texttt{"PVCE\\_H"})$$

**Independence assumption:** no party knows any discrete-log relation among $G, G_1, \ldots, G_n, H$. This holds by the random oracle model applied to the hash-to-curve function.

All group elements are serialized in **compressed form** (33 bytes on secp256k1).

---

## Phase 0 — Generator Setup (one-time, public)

Both parties compute and verify the generators independently using the same hash-to-curve specification. No interaction required. The dimension $n$ is agreed in advance as part of the protocol context string.

$$G_i = \textrm{HashToCurve}\bigl(\textrm{SHA256}(\texttt{"PVCE\\_G\\_"} \Vert \textrm{LE32}(i))\bigr)$$

$$H = \textrm{HashToCurve}\bigl(\textrm{SHA256}(\texttt{"PVCE\\_H"})\bigr)$$

These values are fixed for all subsequent protocol executions with the same $n$.

---

## Phase 1 — Commitment (Prover &rarr; Verifier)

$P$ holds witness $(c_1, \ldots, c_n)$ where each $c_i \in \mathbb{Z}_p$, and chooses a uniform blinding scalar $r \in \mathbb{Z}_p$.

$P$ computes the **Pedersen vector commitment**:

$$C = c_1 \cdot G_1 + c_2 \cdot G_2 + \cdots + c_n \cdot G_n + r \cdot H$$

$P$ sends $C$ to $V$.

### Optional — Proof of Knowledge of Opening

$P$ may accompany $C$ with a Schnorr-style proof that it knows a valid opening, without revealing $(c_i, r)$. This is not required for the encryption to work but may be required by $V$ before proceeding.

1. $P$ samples nonces $a_1, \ldots, a_n, b$ uniformly from $\mathbb{Z}_p$.
2. $P$ computes $A = \sum_i a_i \cdot G_i + b \cdot H$
3. **Challenge:** $e = \textrm{SHA256}(\texttt{"PVCE\\_POK"} \Vert C \Vert A)$, interpreted as a scalar.
4. **Responses:** $s_i = a_i + e \cdot c_i \bmod p$ for each $i$, and $t = b + e \cdot r \bmod p$.
5. $P$ sends $(A,\; e,\; s_1, \ldots, s_n,\; t)$.

**Verification by V:**

$$\sum_i s_i \cdot G_i + t \cdot H \stackrel{?}{=} A + e \cdot C$$

---

## Phase 2 — Encryption and Bitcoin Payment (Verifier)

### Step 2.1 — Ephemeral Key and Shared Secret

$V$ samples a uniform ephemeral scalar $q \in \mathbb{Z}_p$.

$V$ computes the **shared secret** as the scalar multiple of the commitment:

$$S = q \cdot C$$

$S$ is a curve point. $V$ will use $S$ to derive the Bitcoin private key.

### Step 2.2 — Bitcoin Private Key Derivation

From $S$, $V$ derives the Bitcoin private key scalar $m$ using a KDF:

$$m = \textrm{HKDF-SHA256}(\ \textrm{ikm} = S_x \Vert S_y\,,\ \textrm{salt} = \texttt{"PVCE\\_salt"}\,,\ \textrm{info} = \texttt{"PVCE\\_privkey"}\ ) \bmod p$$

where $S_x, S_y$ are the 32-byte big-endian affine coordinates of $S$ (64 bytes total).

If $m = 0$, $V$ must resample $q$ (negligible probability).

$V$ computes the corresponding Bitcoin public key:

$$M = m \cdot G$$

### Step 2.3 — Bitcoin Payment on Signet

$V$ constructs a Bitcoin transaction output paying amount $A$ (in satoshis) to a **Pay-to-Taproot** (P2TR) output with internal key $M$ and no script path (key-path-only spend, per BIP 341):

```
scriptPubKey = OP_1 <32-byte x-only pubkey of M>
```

$V$ broadcasts this transaction to the Bitcoin signet network and records:

| Field | Description |
|-------|-------------|
| `txid` | Transaction ID of the funding transaction |
| `vout` | Output index within that transaction |
| `amount` | Amount in satoshis |

$V$ waits for the transaction to be confirmed before publishing the ciphertext (to prevent a race where the prover spends before confirmation, or $V$ reverts).

### Step 2.4 — Ciphertext Components

$V$ computes the ECDH ciphertext: one scalar multiple of $q$ for each generator.

$$Q_i = q \cdot G_i \quad \text{for } i = 1, \ldots, n$$

$$Q_H = q \cdot H$$

The ciphertext is $\mathrm{CT} = (Q_1, Q_2, \ldots, Q_n, Q_H)$.

These are $(n+1)$ curve points, each 33 bytes compressed.

### Step 2.5 — DLEQ Validity Proof

$V$ must prove that all components of CT share the same scalar $q$, i.e., that $Q_i = q \cdot G_i$ for all $i$, and $Q_H = q \cdot H$ — without revealing $q$.

This is a **multi-base discrete log equality proof** (batched Schnorr):

1. $V$ samples a uniform nonce $k \in \mathbb{Z}_p$.
2. $V$ computes commitment points:

$$R_i = k \cdot G_i \quad \text{for } i = 1, \ldots, n \qquad R_H = k \cdot H$$

3. **Challenge** (Fiat-Shamir over all components):

$$e = \textrm{SHA256}\bigl(\texttt{"PVCE\\_DLEQ"} \Vert G_1 \Vert \cdots \Vert G_n \Vert H \Vert Q_1 \Vert \cdots \Vert Q_n \Vert Q_H \Vert R_1 \Vert \cdots \Vert R_n \Vert R_H\bigr) \bmod p$$

4. **Response:**

$$s = k - e \cdot q \bmod p$$

$V$ publishes the DLEQ proof: $\pi = (e,\; s)$

**Verification by P (or any party):**

For each $i = 1, \ldots, n$ recompute $R_i$ and $R_H$:

$$s \cdot G_i + e \cdot Q_i \stackrel{?}{=} R_i$$

$$s \cdot H + e \cdot Q_H \stackrel{?}{=} R_H$$

If all $(n+1)$ checks pass, the ciphertext is well-formed with respect to a single consistent $q$.

### Step 2.6 — Publication

$V$ publishes the following bundle (may be posted publicly or sent to $P$):

| Component | Description |
|-----------|-------------|
| $C$ | The commitment (may already be public) |
| $\mathrm{CT} = (Q_1, \ldots, Q_n, Q_H)$ | Ciphertext components |
| $\pi = (e, s)$ | DLEQ validity proof |
| `txid`, `vout`, `amount` | Locating the on-chain output |

---

## Phase 3 — Decryption and Spending (Prover)

### Step 3.1 — Verify Ciphertext Validity

$P$ verifies $\pi$ against CT using the verification equations from Step 2.5. If verification fails, $P$ aborts: the ciphertext is malformed or dishonest.

### Step 3.2 — Recover the Shared Secret

$P$ uses the commitment opening $(c_1, \ldots, c_n, r)$ to reconstruct $S = q \cdot C$:

$$S = c_1 \cdot Q_1 + c_2 \cdot Q_2 + \cdots + c_n \cdot Q_n + r \cdot Q_H$$

**Correctness:**

$$\sum_i c_i \cdot Q_i + r \cdot Q_H = \sum_i c_i \cdot q \cdot G_i + r \cdot q \cdot H = q \cdot \left(\sum_i c_i \cdot G_i + r \cdot H\right) = q \cdot C = S \quad \checkmark$$

### Step 3.3 — Derive Private Key

$P$ applies the same KDF as $V$:

$$m = \textrm{HKDF-SHA256}(\ \textrm{ikm} = S_x \Vert S_y\,,\ \textrm{salt} = \texttt{"PVCE\\_salt"}\,,\ \textrm{info} = \texttt{"PVCE\\_privkey"}\ ) \bmod p$$

$P$ computes $M = m \cdot G$ and verifies that $M$ matches the internal key of the P2TR output at (`txid`, `vout`). If it does not match, either $V$ acted dishonestly (paid to a different key than the one derived from CT) or $P$ has the wrong opening. $P$ should abort.

### Step 3.4 — Construct and Broadcast Spending Transaction

$P$ constructs a Bitcoin transaction spending the output (`txid`, `vout`):

**Input:**
- `prevout:` txid:vout
- `sequence:` 0xFFFFFFFF (or as appropriate)
- `witness:` \[schnorr\_signature\] — key-path P2TR spend per BIP 341

**Output(s):**
- $P$'s chosen destination(s), up to the input amount minus fees.

**Signing (BIP 341 key-path):**

1. Compute the tweaked private key per BIP 341 taproot key tweaking:

$$t = \textrm{SHA256}(\texttt{"TapTweak"} \Vert M_x) \quad \text{(as scalar)}$$

$$m_{\mathrm{tweaked}} = m + t \bmod p$$

2. Compute the sighash per BIP 341 (`SIGHASH_DEFAULT` or explicit type).

3. Produce a BIP 340 Schnorr signature:

$$\sigma = \textrm{SchnorrSign}(m_{\mathrm{tweaked}},\; \textrm{sighash})$$

4. Set `witness =` $[\sigma]$ (64 or 65 bytes depending on sighash type).

$P$ broadcasts the spending transaction to the Bitcoin signet network.

---

## Security Properties

### Correctness

If $P$ holds a valid opening of $C$, the shared secret $S$ computed in Step 3.2 equals $q \cdot C$, and so $m$ derived in Step 3.3 equals $m$ derived in Step 2.2. Hence $M = m \cdot G$ matches the P2TR key, and $P$ can always spend.

### Soundness (Binding)

The Pedersen vector commitment $C$ is computationally binding under the discrete logarithm assumption on secp256k1. A party without a valid opening of $C$ cannot compute $q \cdot C$ from CT without solving the ECDH problem (i.e., computing $q \cdot C$ from $\lbrace q \cdot G_i \rbrace$ and $C$). This is hard under DDH.

### Hiding of Witness (from V and third parties)

$\mathrm{CT} = \lbrace q \cdot G_i,\; q \cdot H \rbrace$ reveals nothing about the $c_i$ or $r$ to a party not knowing $q$. This follows from the DDH assumption: $q \cdot G_i$ is computationally indistinguishable from a random point.

### DLEQ Proof Soundness

A malicious $V$ who uses different $q$ values for different components would fail the DLEQ verification, and $P$ aborts before attempting decryption. Specifically: if $Q_i = q_i \cdot G_i$ with distinct $q_i$, no single $(e, s)$ pair can satisfy all $(n+1)$ verification equations simultaneously (except with negligible probability).

### Known Limitation — V's Payment Honesty

The DLEQ proof establishes that CT encodes a consistent $q$. It does **not** prove that $V$ paid to the key $M$ derived from that $q$. A dishonest $V$ could publish a valid CT but pay to a different address. The prover detects this in Step 3.3 (the derived $M$ will not match the on-chain output) but only after $V$'s transaction is already confirmed. If the protocol requires $V$'s payment honesty to be publicly verifiable before $P$ invests effort, additional measures are needed (e.g., a commitment from $V$ to $M$ alongside the on-chain output, verifiable by $P$ before decryption begins).

---

## Parameter Summary

| Parameter | Value |
|-----------|-------|
| Curve | secp256k1 |
| $n$ | Dimension of witness vector (agreed at setup) |
| Ciphertext size | $(n+1)$ curve points = $33(n+1)$ bytes |
| DLEQ proof size | 2 scalars = 64 bytes |
| PoK proof size | $(n+2)$ scalars + 1 point = $32(n+2) + 33$ bytes |
| KDF | HKDF-SHA256 with fixed salt and info strings |
| Bitcoin output | P2TR key-path-only (BIP 341 / BIP 340) |
| Network | Bitcoin signet (for testing) |
