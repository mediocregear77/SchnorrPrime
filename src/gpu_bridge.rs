// gpu_bridge.rs – GPU-Accelerated Schnorr Signature Verification (via cuECC)

use crate::cpu_fallback::{verify_batch_cpu, verify_single_cpu};
use crate::utils::{PublicKey, SchnorrSignature};
use std::env;

// Conditional compilation for GPU acceleration
#[cfg(feature = "cuda")]
mod cuda_accel {
    extern crate libc;
    use super::*;
    use cuda_sys::runtime::*;
    use std::ffi::c_void;

    extern "C" {
        fn schnorr_batch_verify_cuda(
            signatures: *const c_void,
            pubkeys: *const c_void,
            messages: *const c_void,
            count: usize,
        ) -> i32;
    }

    pub fn verify_batch_gpu(
        signatures: &[SchnorrSignature],
        pubkeys: &[PublicKey],
        messages: &[Vec<u8>],
    ) -> Result<bool, String> {
        let count = signatures.len();
        if count != pubkeys.len() || count != messages.len() {
            return Err("Input arrays must be the same length.".into());
        }

        // Call the cuECC CUDA kernel
        unsafe {
            let sig_ptr = signatures.as_ptr() as *const c_void;
            let pk_ptr = pubkeys.as_ptr() as *const c_void;
            let msg_ptr = messages.as_ptr() as *const c_void;

            let result = schnorr_batch_verify_cuda(sig_ptr, pk_ptr, msg_ptr, count);
            Ok(result == 1)
        }
    }
}

/// GPU-aware wrapper that attempts GPU acceleration first.
/// Falls back to CPU verification if CUDA is disabled or fails.
pub fn verify_batch(
    signatures: &[SchnorrSignature],
    pubkeys: &[PublicKey],
    messages: &[Vec<u8>],
) -> Result<bool, String> {
    let gpu_enabled = env::var("USE_GPU").unwrap_or_else(|_| "true".to_string()) == "true";

    #[cfg(feature = "cuda")]
    {
        if gpu_enabled {
            match cuda_accel::verify_batch_gpu(signatures, pubkeys, messages) {
                Ok(valid) => return Ok(valid),
                Err(e) => {
                    eprintln!("GPU verification failed: {}. Falling back to CPU.", e);
                }
            }
        }
    }

    verify_batch_cpu(signatures, pubkeys, messages)
}
