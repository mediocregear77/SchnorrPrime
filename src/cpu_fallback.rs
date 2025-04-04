// cpu_fallback.rs – CPU Fallback for Schnorr Verification (Single & Batch)

use crate::batch_verify::verify_batch;
use crate::single_verify::verify_single;
use crate::utils::{PublicKey, SchnorrSignature};

/// Verifies a single Schnorr signature using CPU fallback.
pub fn verify_single_cpu(
    signature: &SchnorrSignature,
    pubkey: &PublicKey,
    message: &[u8],
) -> Result<bool, String> {
    verify_single(signature, pubkey, message)
}

/// Verifies a batch of Schnorr signatures using CPU fallback.
/// Returns `true` if all signatures in the batch are valid.
pub fn verify_batch_cpu(
    signatures: &[SchnorrSignature],
    pubkeys: &[PublicKey],
    messages: &[Vec<u8>],
) -> Result<bool, String> {
    if signatures.len() != pubkeys.len() || signatures.len() != messages.len() {
        return Err("Input vectors must be the same length.".into());
    }

    verify_batch(signatures, pubkeys, messages)
}
