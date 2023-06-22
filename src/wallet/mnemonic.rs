use bip39::{Mnemonic, Language, Seed, MnemonicType};

#[derive(Debug)]
pub struct MnemonicStruct {
    pub mnemonic_words: Mnemonic,
    pub mnemonic_size: usize, // 12, 15, 18, 21, 24
    pub bip39_seed: Vec<u8>,
}


impl MnemonicStruct {
    
    pub fn new(byte_array: &Vec<u8>, passw: &str) -> Self {
        let mnemonic_words = Mnemonic::from_entropy(&byte_array, Language::English).expect("Failed to generate mnemonic");
        let mnemonic_size = mnemonic_size(&mnemonic_words) ;
        let bip39_seed = gen_bip39_seed(&mnemonic_words, &passw);
        MnemonicStruct { mnemonic_words, mnemonic_size, bip39_seed }
    }

    pub fn get_mnemonic(&self) -> &Mnemonic {
        &self.mnemonic_words
    }

    pub fn mnemonic_len(&self) -> usize {
        self.mnemonic_size
    }

    pub fn get_seed(&self) -> &Vec<u8> {
        &self.bip39_seed
    }
}

pub fn mnemonic_size(mnemonic_words: &Mnemonic) -> usize {
    let mnemonic_type = MnemonicType::for_phrase(&mnemonic_words.to_string()).expect("Failed to calculate mnemonic size");
    let total_bytes = mnemonic_type.total_bits();
    let mnemonic_size = total_bytes / 11;
    mnemonic_size
}

pub fn gen_bip39_seed(mnemonic_words: &Mnemonic, passw: &str) -> Vec<u8> {
    let seed = Seed::new(&mnemonic_words, &passw);
    let bip39_seed = (*seed.as_bytes()).to_vec();
    bip39_seed
}