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

fn eth_wallet() -> DeriveChild {
        // Generate entropy.
        let generator = Entropy::new(WordsSize::W12);
        let entropy = generator.gen_entropy();
    
        // Generate mnemonic and bip39 mnemonic/seed.
        let passwrd = "";
        let mnemonic = MnemonicStruct::new(&entropy, &passwrd);
        println!("Mnemonic: {:?}", mnemonic);
    
        // Stores in keypair the generated private key and chain code from hmac-sha512 function.
        let keypair = KeyPair::new(&mnemonic.get_seed());
        println!("keypair: {:?}", keypair);
    
        //Derive to path m/44'/60'/0'/0 for aplly to wallet generator.
        let path = DerivationPath::new(DerivationPath::Ethereum).expect("Failed to create derivation path");
        println!("Path: {:?}", path);
        let mut derivation = DeriveChild::new(keypair);
        let derivation2path = derivation.path_derivation(&path);    
    
        //Generate master wallet Keypair.
        let master_wallet = DeriveChild::wllt_derivation(&derivation2path, 0);
    
        //Parse the master wallet.
        let master_wallet = ETHWallet::new(&master_wallet.get_keypair().get_pk());
        println!("Master wallet: {:#?}", master_wallet);
        derivation2path.clone()
}

fn eth_new_childs(derivation2path : &DeriveChild, n : u32) {
    for i in 1..=n {
        let child_wallet = DeriveChild::wllt_derivation(&derivation2path, i);
        let child_wallet = ETHWallet::new(&child_wallet.get_keypair().get_pk());
        println!("Child wallet {:?}: {:#?}", i ,child_wallet);
    }
}

fn main() {
    let master = eth_wallet();
    eth_new_childs(&master, 100);
}