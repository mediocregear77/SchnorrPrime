// lib.rs – Schnorr Engine Entry Point

pub mod batch_verify;
pub mod single_verify;
pub mod cpu_fallback;
pub mod gpu_bridge;
pub mod zk_prepare;
pub mod utils;

use batch_verify::verify_batch_cpu;
use gpu_bridge::verify_batch_gpu;
use single_verify::verify_single_signature_internal;
use zk_prepare::prepare_batch_for_zk;
use utils::{is_gpu_available, SchnorrSignature, PublicKey};

/// Public function: Verifies a batch of Schnorr signatures
/// Automatically uses GPU if available, falls back to CPU otherwise
pub fn verify_batch_schnorr_signatures(
    signatures: &[SchnorrSignature],
    public_keys: &[PublicKey],
    messages: &[Vec<u8>],
) -> Result<bool, String> {
    if is_gpu_available() {
        match verify_batch_gpu(signatures, public_keys, messages) {
            Ok(result) => return Ok(result),
            Err(e) => {
                eprintln!("[WARN] GPU verification failed: {}. Falling back to CPU.", e);
            }
        }
    }
    verify_batch_cpu(signatures, public_keys, messages)
}

/// Public function: Verifies a single Schnorr signature using CPU
pub fn verify_single_signature(
    signature: &SchnorrSignature,
    public_key: &PublicKey,
    message: &[u8],
) -> Result<bool, String> {
    verify_single_signature_internal(signature, public_key, message)
}

/// Public function: Prepares verified batch for export to ZK-SNARK proof
pub fn export_for_zk_proof(
    signatures: &[SchnorrSignature],
    public_keys: &[PublicKey],
    messages: &[Vec<u8>],
) -> Result<Vec<u8>, String> {
    prepare_batch_for_zk(signatures, public_keys, messages)
}
