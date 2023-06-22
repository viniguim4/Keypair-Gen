use ring::hmac;
use bs58;
use secp256k1::{SecretKey};
use num_bigint::BigUint;
use crypto::{digest::Digest,
    sha2::Sha256,
    ripemd160::Ripemd160};
use crate::wallet::derivation_path::ChildType;

const HMAC_KEY : &[u8; 12] = b"Bitcoin seed";                             // Hmac key 12 Bytes for HD wallet porpuses
const VERSION_BYTES_MAINNET_PRIVATE: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];  // mainnet_private prefix 4 Bytes (xprv)

#[derive(Debug, Clone, Copy)]
pub struct KeyPair {
    private_key: [u8; 32],
    chain_code: [u8; 32],
}


impl KeyPair {
    pub fn new(seed : &Vec<u8>) -> Self {
        let (private_key, chain_code) = generate_hmac_sha512(seed);
        KeyPair { private_key, chain_code }
    }

    pub fn new_ack(private_key : [u8; 32], chain_code : [u8; 32]) -> Self {
        KeyPair { private_key, chain_code }
    }

    //getters
    pub fn get_pk(&self) -> &[u8; 32] {
        &self.private_key
    }

    pub fn get_cc(&self) -> &[u8; 32] {
        &self.chain_code
    }

    //Private root key.
    pub fn gen_prk(&self) -> String {
        let depth_byte: [u8; 1] = [0x00];                      //  1 Byte
        let parent_fingerprint: [u8; 4] = [0x00; 4];           //  4 Bytes
        let child_number_bytes: [u8; 4] = [0x00; 4];           //  4 Bytes
        let mut key_bytes = Vec::new();
            key_bytes.push(0x00);
            key_bytes.extend_from_slice(self.get_pk());

        let all_parts: Vec<&[u8]> = vec![
            &VERSION_BYTES_MAINNET_PRIVATE, 
            &depth_byte,
            &parent_fingerprint,
            &child_number_bytes,
            self.get_cc(),
            &key_bytes,
        ];

        let all_bytes: Vec<u8> = all_parts.concat();
        let root_key = bs58::encode(all_bytes)
                            .with_check()
                            .into_string();
        root_key.into()
    }

    //secp256k1 calculation for child private key
    pub fn childpk_from_secp256k1(&self, priv_k: &[u8; 32]) -> [u8; 32]{
        let calc_priv_k = &((BigUint::from_bytes_be(priv_k) + BigUint::from_bytes_be(&self.private_key)) % BigUint::from_bytes_be(&secp256k1::constants::CURVE_ORDER));
        let result = BigUint::to_bytes_be(calc_priv_k);
        let mut byte_calc_priv_k = [0u8; 32];
        byte_calc_priv_k[32-result.len()..].copy_from_slice(&result);
        byte_calc_priv_k
    }

    //
    pub fn parent_fingerprint(&self) -> ChildType {
        let secp = secp256k1::Secp256k1::new();
        let k_compreesed = secp256k1::PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&self.private_key).unwrap())
                                                                                                        .serialize()
                                                                                                        .to_vec();
        let mut bytes: Vec<u8> = [0; 32].to_vec();
        let mut hasher = Sha256::new();
        hasher.input(&k_compreesed);
        hasher.result(&mut bytes);
        let mut indentifier = Ripemd160::new();
        indentifier.input(&bytes);
        let _ripemded = indentifier.result(&mut bytes);
        //println!("indentifier: {:?}", bytes[0..4].to_vec());
        let value: u32 = u32::from_le_bytes(<[u8; 4]>::try_from(&bytes[..4]).unwrap());
        if value < 1 << 31 {
            ChildType::normal(value)
        } else {
            ChildType::hardened(value - (1 << 31))
        }
    }
}



pub fn generate_hmac_sha512(seed : &Vec<u8>) -> ([u8; 32], [u8; 32]) {       
    // Create HMAC-SHA512 instance
    let hmac = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA512, HMAC_KEY), seed);

    //get the result of the hmac
    let hmac_result = hmac.as_ref();
    let (l, r) = hmac_result.split_at(32);
    (l.try_into().expect("Failed to unwrap"), r.try_into().expect("Failed to unwrap"))
}