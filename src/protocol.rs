use anyhow::{bail, ensure, Result};
use hkdf::Hkdf;
use k256::{
    elliptic_curve::{
        ops::Reduce,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field, PrimeField,
    },
    AffinePoint, EncodedPoint, ProjectivePoint, Scalar, U256,
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};


// ---- Serialization helpers ----

pub fn point_to_hex(p: &ProjectivePoint) -> String {
    let affine = p.to_affine();
    let encoded = affine.to_encoded_point(true); // compressed
    hex::encode(encoded.as_bytes())
}

pub fn hex_to_point(s: &str) -> Result<ProjectivePoint> {
    let bytes = hex::decode(s)?;
    let ep =
        EncodedPoint::from_bytes(&bytes).map_err(|e| anyhow::anyhow!("invalid point: {}", e))?;
    let affine = AffinePoint::from_encoded_point(&ep);
    if bool::from(affine.is_some()) {
        Ok(ProjectivePoint::from(affine.unwrap()))
    } else {
        bail!("point not on curve")
    }
}

pub fn scalar_to_hex(s: &Scalar) -> String {
    hex::encode(s.to_bytes())
}

pub fn hex_to_scalar(s: &str) -> Result<Scalar> {
    let bytes = hex::decode(s)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("scalar must be 32 bytes"))?;
    let opt = Scalar::from_repr(arr.into());
    if bool::from(opt.is_some()) {
        Ok(opt.unwrap())
    } else {
        bail!("invalid scalar (>= group order)")
    }
}

// ---- Generators ----

/// Try-and-increment hash-to-curve: hash seed||counter, use as x-coordinate
/// with even y (0x02 prefix). Increment counter until valid point found.
fn hash_to_curve(seed: &[u8; 32]) -> ProjectivePoint {
    for counter in 0u32.. {
        let mut h = Sha256::new();
        h.update(seed);
        h.update(counter.to_le_bytes());
        let hash = h.finalize();

        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(&hash);

        if let Ok(ep) = EncodedPoint::from_bytes(&compressed[..]) {
            let opt = AffinePoint::from_encoded_point(&ep);
            if bool::from(opt.is_some()) {
                return ProjectivePoint::from(opt.unwrap());
            }
        }
    }
    unreachable!()
}

/// Compute generators G_1..G_n and H per the spec.
pub fn compute_generators(n: usize) -> (Vec<ProjectivePoint>, ProjectivePoint) {
    let gs: Vec<_> = (1..=n as u32)
        .map(|i| {
            let seed: [u8; 32] = Sha256::new()
                .chain_update(b"PVCE_G_")
                .chain_update(i.to_le_bytes())
                .finalize()
                .into();
            hash_to_curve(&seed)
        })
        .collect();

    let h_seed: [u8; 32] = Sha256::new()
        .chain_update(b"PVCE_H")
        .finalize()
        .into();
    let h = hash_to_curve(&h_seed);

    (gs, h)
}

// ---- Pedersen vector commitment ----

/// C = sum(c_i * G_i) + r * H
pub fn pedersen_commit(
    witness: &[Scalar],
    blinding: &Scalar,
    gs: &[ProjectivePoint],
    h: &ProjectivePoint,
) -> ProjectivePoint {
    let mut c = ProjectivePoint::IDENTITY;
    for (ci, gi) in witness.iter().zip(gs.iter()) {
        c = c + *gi * ci;
    }
    c + *h * blinding
}

// ---- Scalar helpers ----

/// Interpret 32-byte hash as scalar mod p.
fn scalar_from_hash(hash: &[u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(&(*hash).into())
}

pub fn random_scalar() -> Scalar {
    Scalar::random(&mut OsRng)
}

// ---- DLEQ Proof ----

pub struct DleqProof {
    pub e: Scalar,
    pub s: Scalar,
}

fn point_to_compressed(p: &ProjectivePoint) -> Vec<u8> {
    let affine = p.to_affine();
    affine.to_encoded_point(true).as_bytes().to_vec()
}

fn dleq_challenge(
    gs: &[ProjectivePoint],
    h: &ProjectivePoint,
    qs: &[ProjectivePoint],
    q_h: &ProjectivePoint,
    rs: &[ProjectivePoint],
    r_h: &ProjectivePoint,
) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(b"PVCE_DLEQ");
    for gi in gs {
        hasher.update(point_to_compressed(gi));
    }
    hasher.update(point_to_compressed(h));
    for qi in qs {
        hasher.update(point_to_compressed(qi));
    }
    hasher.update(point_to_compressed(q_h));
    for ri in rs {
        hasher.update(point_to_compressed(ri));
    }
    hasher.update(point_to_compressed(r_h));

    let hash: [u8; 32] = hasher.finalize().into();
    scalar_from_hash(&hash)
}

/// Prove that Q_i = q*G_i for all i, and Q_H = q*H, using a single scalar q.
pub fn dleq_prove(
    q: &Scalar,
    gs: &[ProjectivePoint],
    h: &ProjectivePoint,
    qs: &[ProjectivePoint],
    q_h: &ProjectivePoint,
) -> DleqProof {
    let k = Scalar::random(&mut OsRng);

    let rs: Vec<_> = gs.iter().map(|gi| *gi * &k).collect();
    let r_h = *h * &k;

    let e = dleq_challenge(gs, h, qs, q_h, &rs, &r_h);
    let s = k - e * q;

    DleqProof { e, s }
}

/// Verify the DLEQ proof.
pub fn dleq_verify(
    proof: &DleqProof,
    gs: &[ProjectivePoint],
    h: &ProjectivePoint,
    qs: &[ProjectivePoint],
    q_h: &ProjectivePoint,
) -> Result<()> {
    // Recompute R_i = s*G_i + e*Q_i
    let rs: Vec<_> = gs
        .iter()
        .zip(qs.iter())
        .map(|(gi, qi)| *gi * &proof.s + *qi * &proof.e)
        .collect();
    let r_h = *h * &proof.s + *q_h * &proof.e;

    let e = dleq_challenge(gs, h, qs, q_h, &rs, &r_h);
    ensure!(e == proof.e, "DLEQ proof verification failed");
    Ok(())
}

// ---- Encryption (Verifier side) ----

pub struct EncryptionResult {
    /// Ciphertext: Q_1..Q_n, Q_H  (n+1 points)
    pub ciphertext: Vec<ProjectivePoint>,
    /// Shared secret S = q*C
    pub shared_secret: ProjectivePoint,
    /// DLEQ proof of consistent q
    pub dleq_proof: DleqProof,
}

/// Verifier encrypts: samples q, computes CT and DLEQ proof.
pub fn encrypt(
    commitment: &ProjectivePoint,
    gs: &[ProjectivePoint],
    h: &ProjectivePoint,
) -> EncryptionResult {
    let q = Scalar::random(&mut OsRng);
    let shared_secret = *commitment * &q;

    let mut ciphertext: Vec<_> = gs.iter().map(|gi| *gi * &q).collect();
    let q_h = *h * &q;
    ciphertext.push(q_h);

    let qs = &ciphertext[..gs.len()];
    let dleq_proof = dleq_prove(&q, gs, h, qs, &q_h);

    EncryptionResult {
        ciphertext,
        shared_secret,
        dleq_proof,
    }
}

// ---- Decryption (Prover side) ----

/// Prover recovers S = q*C from the ciphertext using the witness opening.
/// S = sum(c_i * Q_i) + r * Q_H
pub fn decrypt(
    witness: &[Scalar],
    blinding: &Scalar,
    ciphertext: &[ProjectivePoint],
) -> ProjectivePoint {
    let n = witness.len();
    let mut s = ProjectivePoint::IDENTITY;
    for (ci, qi) in witness.iter().zip(ciphertext[..n].iter()) {
        s = s + *qi * ci;
    }
    s + ciphertext[n] * blinding
}

// ---- Key derivation ----

/// Derive the Bitcoin private key scalar from shared secret S via HKDF-SHA256.
pub fn derive_privkey(shared_secret: &ProjectivePoint) -> Result<Scalar> {
    let affine = shared_secret.to_affine();
    let encoded = affine.to_encoded_point(false); // uncompressed: 04 || x || y
    let x = encoded
        .x()
        .ok_or_else(|| anyhow::anyhow!("point at infinity"))?;
    let y = encoded
        .y()
        .ok_or_else(|| anyhow::anyhow!("point at infinity"))?;

    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(x);
    ikm.extend_from_slice(y);

    let hk = Hkdf::<Sha256>::new(Some(b"PVCE_salt"), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"PVCE_privkey", &mut okm)
        .map_err(|e| anyhow::anyhow!("HKDF expand error: {}", e))?;

    let m = scalar_from_hash(&okm);
    ensure!(
        bool::from(!m.is_zero()),
        "derived key is zero — resample needed"
    );
    Ok(m)
}
