use rand::RngCore;
use bip39::{Mnemonic, Language, Seed};

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

fn generate_entropy(length: usize) -> Vec<u8> {
    let mut entropy = vec![0u8; length];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut entropy);
    entropy
}

fn generate_mnemonic(byte_array: Vec<u8>) -> Mnemonic{
    let mnemonic = Mnemonic::from_entropy(&byte_array, Language::English).expect("Failed to generate mnemonic");
    println!("{:?}", mnemonic);
    mnemonic
}

fn generate_seed(mnemonic: &Mnemonic, passw: &str) -> Seed {
    let seed = Seed::new(mnemonic, passw);
    println!("{:?}", seed);
    seed
}

fn main() {
    let entropy = generate_entropy(32); // Generate 16, 20, 24, 28 or 32 bytes of entropy
    println!("{:?}", entropy);
    //let bit_array = vec_u8_to_bit_array(&entropy);
    //println!("{:?}", bit_array);
    let mnemonic = generate_mnemonic(entropy);
    let passwrd = "";
    generate_seed(&mnemonic, &passwrd);
}