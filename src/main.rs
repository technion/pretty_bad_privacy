#![forbid(unsafe_code)]

// stdlib stuff
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::str;

// crates
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key,
};
use anyhow::{Error, Result};
use clap::Parser;
use rand::prelude::*;
use secrecy::{ExposeSecret, Secret, Zeroize};
use sha2::{Sha256, Digest};


const BLOCKSIZE: usize = 16;
const NONCESIZE: usize = 12; // Defined as 96 bits. 96/8.

mod pbp_subkey;
use pbp_subkey::SubKey;

// Custom key handling structure
struct AESKey([u8; 32]);
impl Zeroize for AESKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl From<String> for AESKey {
    fn from(passphrase: String) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&passphrase);
        let result = hasher.finalize(); // Due to 256 bit hash, result is guaranteed to be 32 bytes
        AESKey(result.into())
    }
}
impl AESKey {
    fn as_bytes(&self) -> [u8; 32] {
        self.0
    }
}
type SecretAESKey = Secret<AESKey>;

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
    cipher.decrypt(nonce.into(), payload).map_err(Error::msg)
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

fn pbp_decrypt_file(filename: &str, key: &SecretAESKey) -> Result<Vec<u8>, anyhow::Error> {
    let mut extension = [0u8; BLOCKSIZE];
    let mut readnonce: [u8; NONCESIZE] = [0u8; NONCESIZE];
    let mut contents = vec![];
    let mut readback = File::open(filename)?;

    // Valid file format is three chunks: extension, nonce, ciphertext.
    readback.read_exact(&mut extension)?;
    readback.read_exact(&mut readnonce)?;
    readback.read_to_end(&mut contents)?;
    let mut sk: SubKey = SubKey::new(&extension, &key.expose_secret().as_bytes());
    pbp_decrypt(&mut sk, &contents, &readnonce)
}

fn pbp_encrypt_file(filename: &str, outfile: &str, key: &SecretAESKey) -> Result<(), anyhow::Error> {
    let mut extension = [0u8; BLOCKSIZE];
    rand::thread_rng().fill_bytes(&mut extension);
    let mut sk: SubKey = SubKey::new(&extension, &key.expose_secret().as_bytes());
    let plaintext = fs::read(filename)?;
    let mut nonce: [u8; NONCESIZE] = [0; NONCESIZE];
    rand::thread_rng().fill_bytes(&mut nonce);

    let ciphertext = pbp_encrypt(&mut sk, &plaintext, &nonce).map_err(Error::msg)?;
    let mut outfile = File::create(outfile)?;
    outfile.write_all(&extension)?;
    outfile.write_all(&ciphertext)?;
    Ok(())
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct CmdArgs {
    /// Encrypt this file. Encrypted data will be saved with a .pbp extension on the same file.
    #[arg(long)]
    encrypt: Option<String>,
    /// Alternatively, decrypt this file and output to stdout.
    #[arg(long)]
    decrypt: Option<String>,
    /// Key
    #[arg(short, long)]
    key: String,
}

fn main() {
    println!("Welcome to PBP!");
    let cli = CmdArgs::parse();
    let userkey = cli.key;
    let myaeskey: SecretAESKey = AESKey::from(userkey).into() ;

    if let Some(encryptfile) = cli.encrypt {
        let mut outfile = encryptfile.clone();
        outfile.push_str(".pbp");
        pbp_encrypt_file(&encryptfile, &outfile, &myaeskey).unwrap();
    }
    if let Some(decryptfile) = cli.decrypt {
        match pbp_decrypt_file(&decryptfile, &myaeskey) {
            Err(recovered_err) => {
                if let Some(recovered_err_io) = recovered_err.downcast_ref::<std::io::Error>() {
                    eprintln!("Error reading encryption input file: {recovered_err_io}");
                } else if let Some(_recovered_err_aead) = recovered_err.downcast_ref::<aes_gcm::aead::Error>()
                {
                    // This error is opaque and will not contain a message string.
                    eprintln!("File was unable to be decrypted. This could be an incorrect key, or a tampered file");
                } else {
                    panic!("Unknown error handling decryption");
                }
            }
            Ok(recovered) => {
                println!("{}", str::from_utf8(&recovered).unwrap());
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn decrypts_file_correctly() {
        let key: SecretAESKey = AESKey::from(String::from("YELLOW SUBMARINEYELLOW SUBMARINE")).into() ;
        let recovered =
            pbp_decrypt_file("tests/testoutput.pbp", &key).unwrap();
        let plaintext = str::from_utf8(&recovered).unwrap();
        let correct = include_str!("../tests/testinput.txt");
        assert_eq!(plaintext, correct);
    }

    #[test]
    fn decrypt_fail_key() {
        let key: SecretAESKey = AESKey::from(String::from("YELLOW SUBMARINEBELLOW SUBMARINE")).into() ;
        let recovered =
            pbp_decrypt_file("tests/testoutput.pbp", &key)
                .unwrap_err();
        assert_eq!(recovered.to_string(), "aead::Error");
    }

    #[test]
    fn decrypt_missing_file() {
        let key: SecretAESKey = AESKey::from(String::from("YELLOW SUBMARINEYELLOW SUBMARINE")).into() ;
        let recovered = pbp_encrypt_file(
            "tests/Idontexist.dat",
            "tests/Idontexist.dat.pbp",
            &key,
        )
        .unwrap_err();
        let recovered_err = recovered
            .downcast_ref::<std::io::Error>()
            .expect("Failed to produce an error");
        assert_eq!(recovered_err.kind(), std::io::ErrorKind::NotFound);
    }
}
