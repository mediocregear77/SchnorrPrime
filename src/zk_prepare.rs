// zk_prepare.rs – Export Schnorr batch verification data for ZK proof generation

use crate::utils::{PublicKey, SchnorrSignature};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ZKBatchExport {
    pub signatures: Vec<ZKSignature>,
    pub pubkeys: Vec<ZKPublicKey>,
    pub messages: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ZKSignature {
    pub r_x: String,
    pub s: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ZKPublicKey {
    pub x: String,
    pub y: String,
}

pub fn export_batch_for_zk(
    signatures: &[SchnorrSignature],
    pubkeys: &[PublicKey],
    messages: &[Vec<u8>],
) -> Result<ZKBatchExport, String> {
    if signatures.len() != pubkeys.len() || signatures.len() != messages.len() {
        return Err("Input batch lengths must match".to_string());
    }

    let zk_sigs: Vec<ZKSignature> = signatures.iter().map(|sig| ZKSignature {
        r_x: hex::encode(sig.r_x.as_bytes()),
        s: hex::encode(sig.s.to_bytes()),
    }).collect();

    let zk_keys: Vec<ZKPublicKey> = pubkeys.iter().map(|pk| ZKPublicKey {
        x: hex::encode(pk.x.as_bytes()),
        y: hex::encode(pk.y.as_bytes()),
    }).collect();

    Ok(ZKBatchExport {
        signatures: zk_sigs,
        pubkeys: zk_keys,
        messages: messages.to_vec(),
    })
}

pub fn export_json(batch: &ZKBatchExport) -> Result<String, String> {
    serde_json::to_string(batch).map_err(|e| e.to_string())
}
