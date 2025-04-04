// single_verify.rs – Schnorr Single Signature Verifier

use crate::utils::{hash_message, PublicKey, SchnorrSignature};

/// Verifies a single Schnorr signature against a message and public key.
/// Returns `true` if the signature is valid.
pub fn verify_single(
    signature: &SchnorrSignature,
    pubkey: &PublicKey,
    message: &[u8],
) -> Result<bool, String> {
    // 1. Calculate the challenge scalar: e = H(R || P || m)
    let challenge = hash_message(&signature.r_compressed, pubkey, message)?;

    // 2. Compute s * G
    let s_g = signature.s * crate::utils::G;

    // 3. Compute R + e * P
    let r_plus_ep = signature.r + (challenge * pubkey.point);

    // 4. Check if s * G == R + e * P
    Ok(s_g == r_plus_ep)
}
