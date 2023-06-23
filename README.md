# Keypair-Gen [DEPRECATED MD]
This Rust program generates keypairs for Ethereum wallets using the BIP39 mnemonic seed phrase and the secp256k1 elliptic curve algorithm. It utilizes several libraries such as `rand`, `bip39`, `ring`, `bs58`, `secp256k1`, `num_bigint`, `crypto`, and `tiny_keccak`.

## Prerequisites

- Rust programming language (https://www.rust-lang.org/tools/install)

## Installation

1. Clone the repository:
   ```git clone https://github.com/viniguim4/keypair-generator.git```
2. Add the necessary dependencies to your Cargo.toml file:
    ```
    [dependencies]
    rand = "0.8"
    bip39 = "0.10"
    ring = "0.16"
    bs58 = "0.6"
    secp256k1 = "0.13"
    num-bigint = "0.5"
    crypto = "0.2"
    tiny-keccak = "2.0"
    hex = "0.4"
3. Navigate to the project directory:
   ```cd keypair-gen```
4. Build the project:
    ```cargo build --release```
   
## Usage

1. Run the program:
    ```cargo run --release```
2. The program can generate a 16, 20, 24, 28 or 32-byte entropy, derive the BIP39 mnemonic seed phrase, generate the root private key, and derive child keys for Ethereum wallets.
3. The generated Ethereum mnemonic, private keys and addresses will be displayed in the console.

## Functionality

  The program provides the following functions:

  - ```generate_entropy(length: usize) -> Vec<u8>:``` Generates random entropy of the specified length.
  - ```generate_mnemonic(byte_array: Vec<u8>) -> Mnemonic:``` Generates a mnemonic phrase from the given byte array.
  - ```generate_bip39_seed(mnemonic: &Mnemonic, passw: &str) -> Vec<u8>:``` Generates a BIP39 seed from the mnemonic and password.
  - ```generate_hmac_sha512(seed: &Vec<u8>) -> (Vec<u8>, Vec<u8>):``` Generates an HMAC-SHA512 hash from the seed and returns the private-key and chain-code.
  - ```generate_priv_root_key(l: &Vec<u8>, r: &Vec<u8>) -> Vec<u8>:``` Generates the root key from the private-key and chain-code.
  - ```derivate_child(l: &Vec<u8>, r: &Vec<u8>, n: u32) -> (Vec<u8>, Vec<u8>, Vec<u8>):``` Derives a child key from the given parent key and chain-code.
  - ```parent_fingerprint(l: &Vec<u8>) -> Vec<u8>:``` Calculates the parent fingerprint from the private-key.
  - ```derive_extnd_priv_key(l: &Vec<u8>, r: &Vec<u8>, depth: u8, fp_parent: [u8; 4], chld_nmbr: [u8; 4]) -> Vec<u8>:``` Derives an extended-private-key from the given parameters.
  - ```eth_priv_key(l: &Vec<u8>) -> String:``` Converts the private-key to its hexadecimal representation.
  - ```eth_addrss(l: &Vec<u8>) -> String:``` Generates the Ethereum address from the private-key.
   
## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).
