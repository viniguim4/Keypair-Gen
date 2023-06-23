use tiny_keccak::keccak256;
use secp256k1::{SecretKey};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug,)]
pub struct ETHWallet {
    private_key: String,
    address: String,
}

impl ETHWallet{
    pub fn new(l: &[u8; 32]) -> Self {
        ETHWallet { private_key: Self::eth_priv_key(l), address: Self::eth_addrss(l) }
    }

    pub fn eth_priv_key(l: &[u8; 32]) -> String {
        hex::encode(l).to_string()
    }

    pub fn eth_addrss(l: &[u8; 32]) -> String {
        let secp = secp256k1::Secp256k1::new();
        let p_uncompreesed = secp256k1::PublicKey::from_secret_key(&secp, &SecretKey::from_slice(l).unwrap()).serialize_uncompressed().to_vec();

        let keccak_encdd = keccak256(&p_uncompreesed[1..]);
        let address =hex::encode(&keccak_encdd[12..32]).to_string();
        format!("0x{}", address)
    }
}