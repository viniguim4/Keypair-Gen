use secp256k1::{SecretKey};
use ring::hmac;
use crate::wallet::hmac_sha512::{KeyPair};

#[derive(Clone, Debug)]
pub enum ChildType {
    Normal(u32),
    Hardened(u32),
}

impl ChildType {
    pub fn hardened(num: u32) -> Self {
        Self::Hardened(Self::check_size(num))
    }

    pub fn normal(num: u32) -> Self {
        Self::Normal(Self::check_size(num))
    }

    fn check_size(num: u32) -> u32 {
        if num & (1 << 31) == 0 {
            num
        } else {
            panic!("Child index must be less than 2^31")
        }
    }

    pub fn get_value(&self) -> u32 {
        match self {
            ChildType::Normal(value) => *value,
            ChildType::Hardened(value) => value + (1 << 31),
        }
    }
}
  

pub enum DerivationPath{
    Ethereum, // Derivation path for nets like ETH, Bsc, Arb is m/44'/60'/0'/0/0.
    None,
}


#[derive(Clone, Debug)]
pub struct DerivationPathStruct {
    purpose: ChildType,
    coin:    ChildType,
    account: ChildType,
    change:  ChildType,
    address: ChildType,    
}

impl DerivationPath {
    pub fn new(self) -> Option<DerivationPathStruct> {
        match self {
            DerivationPath::Ethereum => Some(DerivationPathStruct {
                purpose: ChildType::hardened(44),
                coin:    ChildType::hardened(60),
                account: ChildType::hardened(0),
                change:  ChildType::normal(0),
                address: ChildType::normal(0),
            }),
            DerivationPath::None => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeriveChild {
    keypair: KeyPair,
    parent_fp : ChildType
}

impl DeriveChild {
    pub fn new(keypair : KeyPair) -> Self {
        let parent_fp = ChildType::normal(0);
        DeriveChild { keypair, parent_fp }
    }

    pub fn get_keypair(&self) -> &KeyPair {
        &self.keypair
    }

    pub fn change_kp(&mut self, keypair : KeyPair) {
        self.keypair = keypair;
    }

    pub fn change_path(&mut self, path : &ChildType) {
        self.parent_fp = path.clone();
    }

    pub fn derivate_child(&mut self) {
        let mut data = Vec::new();
        // Verify if the child to be generated is or isn't a hardened.
        match &self.parent_fp {
            ChildType::Normal(_value) => {
                                            let secp = secp256k1::Secp256k1::new();
                                            data.extend_from_slice(&secp256k1::PublicKey::from_secret_key(&secp, &SecretKey::from_slice(self.get_keypair().get_pk()).unwrap()).serialize().to_vec());
                                        },
            ChildType::Hardened(_value) => {
                                            data.push(0x00);
                                            data.extend_from_slice(self.get_keypair().get_pk());
                                        }
        }
        // Concatenate the parent fingerprint to the data.
        data.extend_from_slice(&self.parent_fp.get_value().to_be_bytes());	
        // Create HMAC-SHA512 instance.
        let hmac = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA512, self.get_keypair().get_cc()), &data.to_vec());
        //get the result of the hmac
        let hmac_result = hmac.as_ref();
        let (aux_private_key, child_chain_code) = hmac_result.split_at(32);
        // Calculate child private key from secp256k1 curve.
        let child_calc_pk = self.get_keypair().childpk_from_secp256k1(aux_private_key.try_into().expect("slice with incorrect length"));
        // Calculate the parent fingerprint to be written in the child.
        
        let parent_fp = self.get_keypair().parent_fingerprint();

        let keypair = KeyPair::new_ack(child_calc_pk, child_chain_code.try_into().expect("slice with incorrect length"));
        self.change_kp(keypair);
        self.change_path(&parent_fp);
    }

    pub fn path_derivation(&mut self, paths : &DerivationPathStruct) -> &DeriveChild {
        let mut paths_in = Vec::new();
        paths_in.push(&paths.purpose);
        paths_in.push(&paths.coin);
        paths_in.push(&paths.account);
        paths_in.push(&paths.change);
        paths_in.push(&paths.address);

        for path in paths_in.iter().take(paths_in.len() - 1) {
            self.change_path(path);
            self.derivate_child();
        }
        self
    }

    pub fn wllt_derivation(frompath : &DeriveChild, n : u32) -> DeriveChild{
        let mut copy : DeriveChild = DeriveChild::new(frompath.get_keypair().clone());
        copy.change_path(&ChildType::Normal(n));
        copy.derivate_child();
        copy
    }
}