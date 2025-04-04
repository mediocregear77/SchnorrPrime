// utils.rs – Cryptographic primitives, secp256k1 helpers, modular ops

use k256::{
    elliptic_curve::{
        sec1::{ToEncodedPoint, FromEncodedPoint},
        FieldBytes,
    },
    ProjectivePoint, PublicKey as K256PubKey, Scalar, SecretKey,
};
use sha2::{Digest, Sha256};
use hex;
use std::fmt;

// Schnorr Signature Struct
#[derive(Clone)]
pub struct SchnorrSignature {
    pub r_x: ProjectivePoint, // Only x is used
    pub s: Scalar,
}

impl fmt::Debug for SchnorrSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SchnorrSignature {{ r_x: {}, s: {} }}",
               hex::encode(self.r_x.to_encoded_point(false).x().unwrap()),
               hex::encode(self.s.to_bytes()))
    }
}

// Public Key Struct
#[derive(Clone)]
pub struct PublicKey {
    pub x: FieldBytes,
    pub y: FieldBytes,
}

impl PublicKey {
    pub fn from_k256(pk: &K256PubKey) -> Self {
        let encoded = pk.to_encoded_point(false);
        PublicKey {
            x: encoded.x().unwrap().clone(),
            y: encoded.y().unwrap().clone(),
        }
    }

    pub fn to_projective(&self) -> Result<ProjectivePoint, String> {
        let mut bytes = vec![0x04]; // Uncompressed prefix
        bytes.extend_from_slice(&self.x);
        bytes.extend_from_slice(&self.y);

        let ep = k256::EncodedPoint::from_bytes(&bytes).map_err(|e| e.to_string())?;
        let affine = k256::AffinePoint::from_encoded_point(&ep)
            .ok_or("Invalid affine point")?;

        Ok(ProjectivePoint::from(affine))
    }
}

// Hash message with public key and R.x
pub fn challenge_hash(r_x: &FieldBytes, pk: &PublicKey, msg: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(r_x);
    hasher.update(&pk.x);
    hasher.update(&pk.y);
    hasher.update(msg);
    let hash = hasher.finalize();
    Scalar::from_bytes_reduced(FieldBytes::from_slice(&hash))
}

// Safe scalar creation from bytes
pub fn scalar_from_bytes(bytes: &[u8]) -> Result<Scalar, String> {
    let fb = FieldBytes::from_slice(bytes);
    Ok(Scalar::from_bytes_reduced(fb))
}
