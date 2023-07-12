#![forbid(unsafe_code)]

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key,
};
use anyhow::{Error, Result};

use rand::prelude::*;

use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::str;

const BLOCKSIZE: usize = 16;
const NONCESIZE: usize = 12; // Defined as 96 bits. 96/8.

mod pbp_subkey;
use pbp_subkey::SubKey;

// Uses the new Subkey algorithm to decrypt ciphertext with AES-256-GCM
fn pbp_decrypt(
    subkey: &mut SubKey,
    ciphertext: &[u8],
    nonce: &[u8; NONCESIZE],
) -> Result<Vec<u8>, anyhow::Error> {
    let key = subkey.get_keys();
    let key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(&key);
    let payload = Payload {
        msg: ciphertext,
        aad: &subkey.commit,
    };

    let cipher = Aes256Gcm::new(key);
    Ok(cipher.decrypt(nonce.into(), payload).map_err(Error::msg)?)
}

// Uses the new Subkey algorithm to decrypt ciphertext with AES-256-GCM
// Return Vec is nonce || cipher
fn pbp_encrypt(
    subkey: &mut SubKey,
    plaintext: &[u8],
    nonce: &[u8; NONCESIZE],
) -> Result<Vec<u8>, anyhow::Error> {
    // The actual key requires joining the subkeys
    let key = subkey.get_keys();
    let key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(&key);
    let payload = Payload {
        msg: plaintext,
        aad: &subkey.commit,
    };

    let cipher = Aes256Gcm::new(key);
    Ok([
        nonce.to_vec(),
        cipher.encrypt(nonce.into(), payload).map_err(Error::msg)?,
    ]
    .concat())
}

fn pbp_decrypt_file(filename: &str, key: &[u8; 32]) -> Result<Vec<u8>, anyhow::Error> {
    let mut extension = [0u8; BLOCKSIZE];
    let mut readnonce: [u8; NONCESIZE] = [0u8; NONCESIZE];
    let mut contents = vec![];
    let mut readback = File::open(filename).unwrap();

    // Valid file format is three chunks: extension, nonce, ciphertext.
    readback.read_exact(&mut extension)?;
    readback.read_exact(&mut readnonce)?;
    readback.read_to_end(&mut contents)?;
    let mut sk: SubKey = SubKey::new(&extension, key.try_into().unwrap());
    Ok(pbp_decrypt(&mut sk, &contents, &readnonce)?)
}

fn pbp_encrypt_file(filename: &str, key: &[u8; 32]) -> Result<(), anyhow::Error> {
    let mut extension = [0u8; BLOCKSIZE];
    rand::thread_rng().fill_bytes(&mut extension);
    let mut sk: SubKey = SubKey::new(&extension, key.try_into().unwrap());
    let plaintext = fs::read(filename)?;
    let mut nonce: [u8; NONCESIZE] = [0; NONCESIZE];
    rand::thread_rng().fill_bytes(&mut nonce);

    let ciphertext = pbp_encrypt(&mut sk, &plaintext, &nonce).map_err(Error::msg)?;
    let mut outfile = File::create("tests/testoutput.pbp")?;
    outfile.write_all(&extension)?;
    outfile.write_all(&ciphertext)?;
    Ok(())
}

fn main() {
    println!("Welcome to PBP!");

    let key: &[u8; 32] = b"YELLOW SUBMARINEYELLOW SUBMARINE";
    pbp_encrypt_file("tests/testinput.txt", key).unwrap();
    let recovered = pbp_decrypt_file("tests/testoutput.pbp", key);

    println!("{}", str::from_utf8(&recovered.unwrap()).unwrap());
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn decrypts_file_correctly() {
        let recovered =
            pbp_decrypt_file("tests/testoutput.pbp", b"YELLOW SUBMARINEYELLOW SUBMARINE").unwrap();
        let plaintext = str::from_utf8(&recovered).unwrap();
        let correct = include_str!("../tests/testinput.txt");
        assert_eq!(plaintext, correct);
    }

    #[test]
    fn decrypt_fail_key() {
        let recovered =
            pbp_decrypt_file("tests/testoutput.pbp", b"YELLOW SUBMARINEYEBLOW SUBMARINE")
                .unwrap_err();
        assert_eq!(recovered.to_string(), "aead::Error");
    }

    #[test]
    fn decrypt_missing_file() {
        let recovered =
            pbp_encrypt_file("tests/Idontexist.dat", b"YELLOW SUBMARINEYELLOW SUBMARINE").unwrap_err();
        let recovered_err = recovered.downcast_ref::<std::io::Error>().expect("Failed to produce an error");
        assert_eq!(
            recovered_err.kind(),
            std::io::ErrorKind::NotFound
        );
    }
}
