mod protocol;

use anyhow::{ensure, Result};
use bitcoin::{
    consensus::encode::serialize_hex,
    hashes::Hash,
    key::TapTweak,
    locktime::absolute::LockTime,
    secp256k1::{Keypair, Message, Secp256k1, SecretKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    transaction::Version,
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use clap::{Parser, Subcommand};
use protocol::{
    compute_generators, decrypt, derive_privkey, dleq_verify, encrypt, hex_to_point,
    hex_to_scalar, pedersen_commit, point_to_hex, random_scalar, scalar_to_hex, DleqProof,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Parser)]
#[command(name = "pvce", about = "Pedersen Vector Commitment Witness Encryption")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Phase 1: generate commitment, encrypt, output P2TR address
    Setup {
        /// Dimension of the witness vector
        #[arg(short)]
        n: usize,
        /// Output state file path
        #[arg(short, default_value = "pvce_state.json")]
        o: String,
    },
    /// Phase 2: verify ciphertext, recover key, build spending tx
    Recover {
        /// Path to state file from setup phase
        #[arg(short)]
        s: String,
        /// Funding transaction ID (hex)
        #[arg(long)]
        txid: String,
        /// Funding output index
        #[arg(long)]
        vout: u32,
        /// Funding output amount in satoshis
        #[arg(long)]
        amount: u64,
        /// Fee in satoshis (default 200)
        #[arg(long, default_value = "200")]
        fee: u64,
    },
}

/// Serializable state passed between setup and recover phases.
#[derive(Serialize, Deserialize)]
struct State {
    n: usize,
    witness: Vec<String>,
    blinding: String,
    commitment: String,
    ciphertext: Vec<String>,
    dleq_e: String,
    dleq_s: String,
    internal_pubkey_hex: String,
    address: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Setup { n, o } => cmd_setup(n, &o),
        Commands::Recover {
            s,
            txid,
            vout,
            amount,
            fee,
        } => cmd_recover(&s, &txid, vout, amount, fee),
    }
}

fn cmd_setup(n: usize, output_path: &str) -> Result<()> {
    ensure!(n >= 1, "n must be at least 1");

    eprintln!("Computing generators for n={n}...");
    let (gs, h) = compute_generators(n);

    // -- Prover: random witness and blinding --
    let witness: Vec<_> = (0..n).map(|_| random_scalar()).collect();
    let blinding = random_scalar();
    let commitment = pedersen_commit(&witness, &blinding, &gs, &h);
    eprintln!("Commitment: {}", point_to_hex(&commitment));

    // -- Verifier: encrypt to commitment --
    let enc = encrypt(&commitment, &gs, &h);

    // -- Derive Bitcoin private key from shared secret --
    let m = derive_privkey(&enc.shared_secret)?;
    let m_bytes: [u8; 32] = m.to_bytes().into();

    // -- Compute P2TR address (key-path only, no script tree) --
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&m_bytes)?;
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _parity) = kp.x_only_public_key();
    let address = Address::p2tr(&secp, xonly, None, Network::Signet);

    eprintln!("Internal pubkey (x-only): {}", xonly);
    println!("{address}");
    eprintln!("Pay to this address on signet, then run `recover`.");

    // -- Save state --
    let state = State {
        n,
        witness: witness.iter().map(scalar_to_hex).collect(),
        blinding: scalar_to_hex(&blinding),
        commitment: point_to_hex(&commitment),
        ciphertext: enc.ciphertext.iter().map(point_to_hex).collect(),
        dleq_e: scalar_to_hex(&enc.dleq_proof.e),
        dleq_s: scalar_to_hex(&enc.dleq_proof.s),
        internal_pubkey_hex: hex::encode(xonly.serialize()),
        address: address.to_string(),
    };

    let json = serde_json::to_string_pretty(&state)?;
    std::fs::write(output_path, &json)?;
    eprintln!("State saved to {output_path}");

    Ok(())
}

fn cmd_recover(state_path: &str, txid_hex: &str, vout: u32, amount: u64, fee: u64) -> Result<()> {
    ensure!(amount > fee, "fee must be less than amount");

    let json = std::fs::read_to_string(state_path)?;
    let state: State = serde_json::from_str(&json)?;

    eprintln!("Computing generators for n={}...", state.n);
    let (gs, h) = compute_generators(state.n);

    // -- Deserialize state --
    let witness: Vec<_> = state
        .witness
        .iter()
        .map(|s| hex_to_scalar(s))
        .collect::<Result<_>>()?;
    let blinding = hex_to_scalar(&state.blinding)?;
    let ciphertext: Vec<_> = state
        .ciphertext
        .iter()
        .map(|s| hex_to_point(s))
        .collect::<Result<_>>()?;
    let dleq_proof = DleqProof {
        e: hex_to_scalar(&state.dleq_e)?,
        s: hex_to_scalar(&state.dleq_s)?,
    };

    // -- Step 3.1: Verify DLEQ proof --
    eprintln!("Verifying DLEQ proof...");
    let n = state.n;
    ensure!(ciphertext.len() == n + 1, "ciphertext length mismatch");
    let qs = &ciphertext[..n];
    let q_h = &ciphertext[n];
    dleq_verify(&dleq_proof, &gs, &h, qs, q_h)?;
    eprintln!("DLEQ proof valid.");

    // -- Step 3.2: Recover shared secret --
    let shared_secret = decrypt(&witness, &blinding, &ciphertext);

    // -- Step 3.3: Derive private key --
    let m = derive_privkey(&shared_secret)?;
    let m_bytes: [u8; 32] = m.to_bytes().into();

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&m_bytes)?;
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _parity) = kp.x_only_public_key();

    // Verify derived key matches the one from setup
    let derived_hex = hex::encode(xonly.serialize());
    ensure!(
        derived_hex == state.internal_pubkey_hex,
        "Derived pubkey {} does not match saved {}. Protocol failure.",
        derived_hex,
        state.internal_pubkey_hex
    );
    eprintln!("Derived key matches on-chain internal pubkey.");

    // -- Generate destination keypair --
    let dest_sk = SecretKey::new(&mut rand::thread_rng());
    let dest_kp = Keypair::from_secret_key(&secp, &dest_sk);
    let (dest_xonly, _) = dest_kp.x_only_public_key();
    let dest_address = Address::p2tr(&secp, dest_xonly, None, Network::Signet);

    // -- Build spending transaction --
    let txid = Txid::from_str(txid_hex)?;
    let outpoint = OutPoint::new(txid, vout);

    // Reconstruct the funding scriptPubKey
    let funding_address = Address::p2tr(&secp, xonly, None, Network::Signet);
    let funding_script = funding_address.script_pubkey();

    let send_amount = amount
        .checked_sub(fee)
        .ok_or_else(|| anyhow::anyhow!("fee exceeds amount"))?;

    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(send_amount),
            script_pubkey: dest_address.script_pubkey(),
        }],
    };

    // -- Sign (BIP 341 key-path spend) --
    let prevouts = [TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: funding_script,
    }];

    let sighash = SighashCache::new(&tx).taproot_key_spend_signature_hash(
        0,
        &Prevouts::All(&prevouts),
        TapSighashType::Default,
    )?;

    let msg = Message::from_digest(sighash.to_byte_array());
    let tweaked_kp = kp.tap_tweak(&secp, None);
    let sig = secp.sign_schnorr(&msg, &tweaked_kp.to_keypair());

    // SIGHASH_DEFAULT: 64-byte signature, no sighash byte appended
    tx.input[0].witness.push(sig.serialize());

    // -- Output --
    let tx_hex = serialize_hex(&tx);
    eprintln!("\nSpending transaction hex:");
    println!("{tx_hex}");

    let dest_privkey = bitcoin::PrivateKey::new(dest_sk, Network::Signet);
    eprintln!("\nDestination address: {dest_address}");
    eprintln!("Destination private key (WIF): {dest_privkey}");

    Ok(())
}
