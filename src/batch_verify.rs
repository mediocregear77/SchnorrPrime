// batch_verify.rs – CPU-side Batch Verification for Schnorr Signatures

use crate::utils::{hash_message, PublicKey, SchnorrSignature};
use rayon::prelude::*;

/// Verifies a batch of Schnorr signatures using CPU logic only.
/// Uses multithreading (via rayon) to improve performance on multicore systems.
pub fn verify_batch_cpu(
    signatures: &[SchnorrSignature],
    public_keys: &[PublicKey],
    messages: &[Vec<u8>],
) -> Result<bool, String> {
    if signatures.len() != public_keys.len() || signatures.len() != messages.len() {
        return Err("Mismatched input lengths.".to_string());
    }

    // Parallel iteration using rayon
    let all_valid = (0..signatures.len())
        .into_par_iter()
        .map(|i| verify_individual(&signatures[i], &public_keys[i], &messages[i]))
        .all(|res| res.unwrap_or(false)); // Treat errors as invalid sigs

    Ok(all_valid)
}

/// Verifies a single Schnorr signature (internal function)
fn verify_individual(
    sig: &SchnorrSignature,
    pubkey: &PublicKey,
    message: &[u8],
) -> Result<bool, String> {
    // H(R || P || m)
    let challenge = hash_message(&sig.r_compressed, pubkey, message)?;

    // s*G = R + e*P
    let s_g = sig.s * crate::utils::G;
    let r_plus_ep = sig.r + (challenge * pubkey.point);

    Ok(s_g == r_plus_ep)
}
