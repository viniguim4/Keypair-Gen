use rand::{RngCore};
use bip39::{Mnemonic, Language, Seed};
use ring::hmac;
use bs58;
use secp256k1::{SecretKey};
use num_bigint::BigUint;
use crypto::{digest::Digest,
            sha2::Sha256,
            ripemd160::Ripemd160};
use tiny_keccak::keccak256;

/*
BIT VECTOR FOR VALIDATION IN https://iancoleman.io/bip39/
fn vec_u8_to_bit_array(vec: &Vec<u8>) -> Vec<u8> {
    let mut bits = Vec::new();
    for byte in vec {
        for i in (0..8).rev() {
            let bit = (byte >> i) & 1;
            bits.push(bit);
        }
    }
    bits
}*/

const VERSION_BYTES_MAINNET_PRIVATE: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4]; // mainnet_private prefix 4 Bytes

pub fn generate_entropy(length: usize) -> Vec<u8> {    
    let mut entropy = vec![0u8; length];
    let mut rng = rand::thread_rng();

    rng.fill_bytes(&mut entropy);
    println!("Entropy is: {:?}", entropy);

    entropy
}

pub fn generate_mnemonic(byte_array: Vec<u8>) -> Mnemonic {
    let mnemonic = Mnemonic::from_entropy(&byte_array, Language::English).expect("Failed to generate mnemonic");

    println!("Mnemonic is: {:?}", mnemonic);

    mnemonic
}

pub fn generate_bip39_seed(mnemonic: &Mnemonic, passw: &str) -> Vec<u8> {
    let seed = Seed::new(mnemonic, passw);
    
    println!("BIP39 Seed:{:?}", seed);
    println!("BIP39 Seed:{:?}", (*seed.as_bytes()).to_vec());

    (*seed.as_bytes()).to_vec()
}

pub fn generate_hmac_sha512(seed : &Vec<u8>) -> (Vec<u8>, Vec<u8>) {        
        // Define HMAC key
        let hmac_key = b"Bitcoin seed";
    
        // Create HMAC-SHA512 instance
        let hmac = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA512, hmac_key), seed);

        //get the result of the hmac
        let hmac_result = hmac.as_ref();
        let (l, r) = hmac_result.split_at(32);  //split result into two 32 byte arrays

        // Print L and R as vector u8
        //println!("L: {:?}", l); //left is private key
        //println!("R: {:?}", r); //right is chain code
        (l.to_vec(), r.to_vec())
}

pub fn generate_priv_root_key(l: &Vec<u8>, r:&Vec<u8>) -> Vec<u8> {
    //let version_bytes: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];  mainnet_private prefix 4 Bytes
    let depth_byte: [u8; 1] = [0x00];                      //  1 Byte
    let parent_fingerprint: [u8; 4] = [0x00; 4];           //  4 Bytes
    let child_number_bytes: [u8; 4] = [0x00; 4];           //  4 Bytes
    let mut key_bytes = Vec::new();
        key_bytes.push(0x00);
        key_bytes.extend_from_slice(l);

    let all_parts: Vec<&[u8]> = vec![
        &VERSION_BYTES_MAINNET_PRIVATE,
        &depth_byte,
        &parent_fingerprint,
        &child_number_bytes,
        &r,
        &key_bytes,
    ];

    let all_bytes: Vec<u8> = all_parts.concat();
    let root_key = bs58::encode(all_bytes)
                        .with_check()
                        .into_string();

    println!("Root key: {:?}", root_key);

    root_key.into()
}

pub fn derivate_child(l: &Vec<u8>, r: &Vec<u8>, n: u32) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    //default path is m/44'/60'/0'/0/0 for eth
    // Break each depth into integers (m/44'/60'/0'/0/0)
    //    e.g. (44, 60, 0, 0, 0)
    // If hardened, add 2*31 to the number:
    //  e.g. (2**31 + 44, 2**31 + 60, 2**31 + 0, 0, 0) 
    let mut data = Vec::new();
    if n >= 2_147_483_648 {
       //generate_hardened_child
       data.push(0x00);
       data.extend_from_slice(l);
    }
    else {
        let secp = secp256k1::Secp256k1::new();
        data.extend_from_slice(&secp256k1::PublicKey::from_secret_key(&secp, &SecretKey::from_slice(l).unwrap()).serialize().to_vec());
    }

    data.extend_from_slice(&n.to_be_bytes().to_vec());

    // Create HMAC-SHA512 instance
    let hmac = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA512, &r), &data.to_vec());

    //get the result of the hmac
    let hmac_result = hmac.as_ref();
    let (priv_k, chain_c) = hmac_result.split_at(32);  //split result into two 32 byte arrays
    let calc_priv_k = &((BigUint::from_bytes_be(priv_k) + BigUint::from_bytes_be(l)) % BigUint::from_bytes_be(&secp256k1::constants::CURVE_ORDER));
    let result = BigUint::to_bytes_be(calc_priv_k);
    let mut byte_calc_priv_k = [0u8; 32];
    byte_calc_priv_k[32-result.len()..].copy_from_slice(&result);
    // Print L and R as vector u8
    let fp_parent = parent_fingerprint(&l);

    //println!("priv_k: {:?}", byte_calc_priv_k);
    //println!("chain_c: {:?}", chain_c);
    
    (byte_calc_priv_k.to_vec(), chain_c.to_vec(), fp_parent)

}

pub fn parent_fingerprint(l: &Vec<u8>) -> Vec<u8> {
    let secp = secp256k1::Secp256k1::new();
    let k_compreesed = secp256k1::PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&l).unwrap())
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
    bytes[0..4].to_vec()
}

pub fn derive_extnd_priv_key(l: &Vec<u8>, r: &Vec<u8>, depth: u8, fp_parent: [u8; 4], chld_nmbr: [u8; 4]) -> Vec<u8> {
    let depth_byte: [u8; 1] = [depth];                      //  1 Byte
    let parent_fingerprint: [u8; 4] = fp_parent;           //  4 Bytes
    let child_number_bytes: [u8; 4] = chld_nmbr;           //  4 Bytes
    let mut key_bytes = Vec::new();
        key_bytes.push(0x00);
        key_bytes.extend_from_slice(l);

    let all_parts: Vec<&[u8]> = vec![
        &VERSION_BYTES_MAINNET_PRIVATE,
        &depth_byte,
        &parent_fingerprint,
        &child_number_bytes,
        &r,
        &key_bytes,
    ];

    let all_bytes: Vec<u8> = all_parts.concat();
    let root_key = bs58::encode(all_bytes)
                        .with_check()
                        .into_string();

    println!("Derived key: {:?}", root_key);

    root_key.into()
}
pub fn eth_priv_key(l: &Vec<u8>) -> String {
    hex::encode(l).to_string()
}

pub fn eth_addrss(l: &Vec<u8>) -> String {
    let secp = secp256k1::Secp256k1::new();
    let p_uncompreesed = secp256k1::PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&l).unwrap()).serialize_uncompressed().to_vec();

    let keccak_encdd = keccak256(&p_uncompreesed[1..]);
    hex::encode(&keccak_encdd[12..32]).to_string()

}

fn main() {
    let entropy = generate_entropy(16); // Generate 16, 20, 24, 28 or 32 bytes of entropy
    //let bit_array = vec_u8_to_bit_array(&entropy);
    //println!("{:?}", bit_array);
    let mnemonic = generate_mnemonic(entropy);
    let passwrd = "";
    //let bip39_test = [93, 18, 109, 120, 235, 185, 46, 161, 165, 119, 32, 127, 13, 245, 186, 254, 9, 189, 51, 171, 64, 38, 23, 174, 89, 25, 126, 33, 173, 147, 156, 246, 188, 174, 8, 53, 148, 240, 160, 128, 64, 4, 137, 42, 45, 84, 157, 171, 222, 150, 164, 22, 245, 13, 16, 186, 54, 103, 30, 56, 61, 254, 5, 38];
    let bip39_seed = generate_bip39_seed(&mnemonic, &passwrd);
    let (mut l, mut r) = generate_hmac_sha512(&bip39_seed);
    let mut fp_parent = Vec::new();
    let _priv_root_key = generate_priv_root_key(&l, &r);
    (l, r, fp_parent) = derivate_child(&l, &r, 2147483692); // m/44'
    (l, r, fp_parent) = derivate_child(&l, &r, 2147483708); // 60'
    (l, r, fp_parent) = derivate_child(&l, &r, 2147483648); // 0'
    (l, r, fp_parent) = derivate_child(&l, &r, 0);          // 0
    let (l_2derive, r_2derive, _fp_parent_2derive) = (l.clone(), r.clone(), fp_parent.clone());
    
    (l, r, fp_parent) = derivate_child(&l, &r, 0);          // 0 - master wallet (1 means next wallet in root)
    println!("eth priv key MASTER: {:?}", eth_priv_key(&l));       // PRIV KEY 
    println!("eth address MASTER : {:?}", eth_addrss(&l));     // PUBLIC ADDR

    derive_extnd_priv_key(&l, &r, 5, fp_parent.try_into().unwrap(), [0x00, 0x00, 0x00, 0x00]);

    for i in 1..522 { //generate 3 wallets after master
        (l, r, fp_parent) = derivate_child(&l_2derive, &r_2derive, i);
        println!("eth priv key {:?} : {:?}", i, eth_priv_key(&l));               
        println!("eth address {:?} : {:?}", i, eth_addrss(&l));             
    }
}