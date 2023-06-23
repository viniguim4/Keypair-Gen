mod wallet {pub mod entropy;
            pub mod mnemonic;
            pub mod hmac_sha512;
            pub mod derivation_path;
               pub mod ethereum{
                    pub mod eth_wallet;
                }
            }
use wallet::{mnemonic::{MnemonicStruct},
            entropy::{WordsSize, Entropy},
            hmac_sha512::{KeyPair},
            derivation_path::{DerivationPath, DeriveChild},
            ethereum::eth_wallet::{ETHWallet},
            };

use std::{thread, fs::OpenOptions, io::{BufReader,
    BufWriter,}};
use serde::{Deserialize, Serialize};
use anyhow::{Result};

#[derive(Debug, Serialize, Deserialize)]
pub struct Child{
    pub index: u32,
    pub wallet: ETHWallet,
}

impl Child {
    pub fn new(index: u32, wallet: ETHWallet) -> Self {
        Child { index, wallet }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonWallet {
    mnemonic: String,
    size: usize,
    master_wallet: ETHWallet,
    childs_wallet: Vec<Child>,
}

impl JsonWallet {
    pub fn new(mnemonic: String, size: usize, master_wallet: ETHWallet, childs_wallet: Vec<Child>) -> Self {
        JsonWallet { mnemonic, size, master_wallet, childs_wallet }
    }

    pub fn save(&self, file_path: &str) -> Result<()> {
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(file_path)?;
        let buf_writer = BufWriter::new(file);
        serde_json::to_writer_pretty(buf_writer, self)?;
        Ok(())
    }
}

fn eth_wallet() -> (DeriveChild, String, usize, ETHWallet) {
        // Generate entropy.
        let generator = Entropy::new(WordsSize::W12);
        let entropy = generator.gen_entropy();
    
        // Generate mnemonic and bip39 mnemonic/seed.
        let passwrd = "";
        let mnemonic = MnemonicStruct::new(&entropy, &passwrd);
    
        // Stores in keypair the generated private key and chain code from hmac-sha512 function.
        let keypair = KeyPair::new(&mnemonic.get_seed());
    
        //Derive to path m/44'/60'/0'/0 for aplly to wallet generator.
        let path = DerivationPath::new(DerivationPath::Ethereum).expect("Failed to create derivation path");
        let mut derivation = DeriveChild::new(keypair);
        let derivation2path = derivation.path_derivation(&path);    
    
        //Generate master wallet Keypair.
        let master_wallet = DeriveChild::wllt_derivation(&derivation2path, 0);
    
        //Parse the master wallet.
        let master_wallet = ETHWallet::new(&master_wallet.get_keypair().get_pk());
        (derivation2path.clone(), mnemonic.get_mnemonic().to_string(), mnemonic.mnemonic_len(), master_wallet)
}

fn eth_new_childs_thread(derivation2path: &DeriveChild, n: u32) -> Vec<Child> {
    let handles: Vec<_> = (1..=n)
        .map(|index| {
            let derivation2path = derivation2path.clone();
            thread::spawn(move || {
                let wallet = DeriveChild::wllt_derivation(&derivation2path, index);
                let wallet = ETHWallet::new(&wallet.get_keypair().get_pk());
                Child {index, wallet}
            })
        })
        .collect();
    
    handles.into_iter().map(|handle| handle.join().unwrap()).collect()
}

fn main() {
    for i in 0..=10 {
        let (master2derive, mnemonic, msize, masterwllt) = eth_wallet();
        let child_wallets = eth_new_childs_thread(&master2derive, 50);
        let json_wallet = JsonWallet::new(mnemonic, msize, masterwllt, child_wallets);
        let wallet_file_path = format!("genwallets/wallets{}.json", i);
        json_wallet.save(&wallet_file_path).expect("Failed to save json wallet");
    }
}