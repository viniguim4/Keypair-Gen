use rand::{RngCore};

pub enum WordsSize {
    W12,    // 12 words means 128 bits of entropy/16 bytes
    W15,    // 15 words means 160 bits of entropy/20 bytes
    W18,    // 18 words means 192 bits of entropy/24 bytes
    W21,    // 21 words means 224 bits of entropy/28 bytes
    W24,    // 24 words means 256 bits of entropy/32 bytes
}

pub struct Entropy {
    entropy_bytes: WordsSize,
}

impl Entropy {
    pub fn new(entropy_bytes: WordsSize) -> Self {
        Entropy { entropy_bytes }
    }

    pub fn gen_entropy(&self) -> Vec<u8> {
        let length = self.len();
        let mut entropy = vec![0u8; length];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut entropy);
        entropy
    }

    // vector size in bytes to construct the N-word entropy
    pub fn len(&self) -> usize {
        match self.entropy_bytes {
            WordsSize::W12 => 16,
            WordsSize::W15 => 20,
            WordsSize::W18 => 24,
            WordsSize::W21 => 28,
            WordsSize::W24 => 32,
        }
    }
}
