#![forbid(unsafe_code)]

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit},
    aes::Aes256,
    Aes256Gcm, Key,
};
use rand::prelude::*;

use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::str;

type Aes256CbcEnc = cbc::Encryptor<Aes256>;

const BLOCKSIZE: usize = 16;
const NONCESIZE: usize = 12; // Defined as 96 bits. 96/8.

struct SubKey {
    b0: [u8; BLOCKSIZE],
    b1: [u8; BLOCKSIZE],
    commit: [u8; BLOCKSIZE],
}

impl SubKey {
    fn new(extension: &[u8; BLOCKSIZE], key: &[u8; 32]) -> SubKey {
        let niliv = [0; BLOCKSIZE];
        let mut b0 = [0; BLOCKSIZE];
        let mut b1 = [0; BLOCKSIZE];
        let mut commit = [0; BLOCKSIZE];
        let info1 = [extension, String::from("doing b0\x01").as_bytes()].concat();
        let b0all =
            Aes256CbcEnc::new(key.into(), &niliv.into()).encrypt_padded_vec_mut::<Pkcs7>(&info1);

        // As BLOCKSIZE is hardcoded, the Option for next() finding a chunk should be impossible to fail
        let b0chunk = b0all.rchunks(BLOCKSIZE).next().unwrap();
        b0.copy_from_slice(b0chunk);

        let info2 = [b0all, String::from("doing b1\x02").into()].concat();
        let b1all =
            Aes256CbcEnc::new(key.into(), &niliv.into()).encrypt_padded_vec_mut::<Pkcs7>(&info2);

        let b1chunk = b1all.rchunks(BLOCKSIZE).next().unwrap();
        b1.copy_from_slice(b1chunk);

        let info3 = [b1all, String::from("doing commitment\x03").into()].concat();
        let commitall =
            Aes256CbcEnc::new(key.into(), &niliv.into()).encrypt_padded_vec_mut::<Pkcs7>(&info3);

        let commitchunk = commitall.rchunks(BLOCKSIZE).next().unwrap();
        commit.copy_from_slice(commitchunk);

        SubKey { b0, b1, commit }
    }
}

// A custom debugger allows us to get output in hex
// This should never exist. However, it has been repeatedly re-introduced for debugging.
// To faciliate this, we place it under a non existent feature.
#[cfg(feature = "never")]
impl fmt::Debug for SubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "b0, b1 are {:02x?}, {:02x?} and commit tag is {:02x?}",
            self.b0, self.b1, self.commit
        )
    }
}

// Uses the new Subkey algorithm to decrypt ciphertext with AES-256-GCM
fn pbp_decrypt(subkey: &SubKey, ciphertext: &[u8], nonce: &[u8; NONCESIZE]) -> Vec<u8> {
    let key: &mut [u8; 32] = &mut [0; 32];
    key[..BLOCKSIZE].copy_from_slice(&subkey.b0);
    key[BLOCKSIZE..].copy_from_slice(&subkey.b1);
    let key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(key);
    let payload = Payload {
        msg: ciphertext,
        aad: &subkey.commit,
    };

    let cipher = Aes256Gcm::new(key);
    cipher.decrypt(nonce.into(), payload).unwrap()
}

// Uses the new Subkey algorithm to decrypt ciphertext with AES-256-GCM
// Return Vec is nonce || cipher
fn pbp_encrypt(subkey: &SubKey, plaintext: &[u8], nonce: &[u8; NONCESIZE]) -> Vec<u8> {
    // The actual key requires joining the subkeys
    let key: &mut [u8; 32] = &mut [0; 32];
    key[..BLOCKSIZE].copy_from_slice(&subkey.b0);
    key[BLOCKSIZE..].copy_from_slice(&subkey.b1);
    let key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(key);
    let payload = Payload {
        msg: plaintext,
        aad: &subkey.commit,
    };

    let cipher = Aes256Gcm::new(key);
    [
        nonce.to_vec(),
        cipher.encrypt(nonce.into(), payload).unwrap(),
    ]
    .concat()
}

fn pbp_decrypt_file(filename: &str, key: &[u8]) -> Vec<u8> {
    let mut extension = [0u8; BLOCKSIZE];
    let mut readnonce: [u8; NONCESIZE] = [0u8; NONCESIZE];
    let mut contents = vec![];
    let mut readback = File::open(filename).unwrap();

    // Valid file format is three chunks: extension, nonce, ciphertext.
    readback.read_exact(&mut extension).unwrap();
    readback.read_exact(&mut readnonce).unwrap();
    readback.read_to_end(&mut contents).unwrap();
    let sk: SubKey = SubKey::new(&extension, key.try_into().unwrap());
    pbp_decrypt(&sk, &contents, &readnonce)
}

fn pbp_encrypt_file(filename: &str, key: &[u8]) {
    let mut extension = [0u8; BLOCKSIZE];
    rand::thread_rng().fill_bytes(&mut extension);
    let sk: SubKey = SubKey::new(&extension, key.try_into().unwrap());

    let plaintext = fs::read(filename).unwrap();
    let mut nonce: [u8; NONCESIZE] = [0; NONCESIZE];
    rand::thread_rng().fill_bytes(&mut nonce);

    let ciphertext = pbp_encrypt(&sk, &plaintext, &nonce);
    let mut outfile = File::create("tests/testoutput.pbp").unwrap();
    outfile.write_all(&extension).unwrap();
    outfile.write_all(&ciphertext).unwrap();
}

fn main() {
    println!("Welcome to PBP!");

    pbp_encrypt_file("tests/testinput.txt", b"YELLOW SUBMARINEYELLOW SUBMARINE");
    let recovered = pbp_decrypt_file("tests/testoutput.pbp", b"YELLOW SUBMARINEYELLOW SUBMARINE");
    println!("{}", str::from_utf8(&recovered).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn key_derive_matches_prototype() {
        // This is the exact output from the Ruby prototype as a verifier
        let sk: SubKey = SubKey::new(b"EEEEEEEEEEEEEEEE", b"YELLOW SUBMARINEYELLOW SUBMARINE");
        assert_eq!(
            &sk.b0,
            b"\x50\x17\x8d\x3f\x59\x81\xb0\xed\xf7\x82\x1f\xff\x45\x46\x56\xbd"
        );
        assert_eq!(
            &sk.b1,
            b"\xdb\x9c\x68\x94\xf9\x96\xaf\x49\xc8\x74\x67\x41\x91\x72\xc4\x3e"
        );
        assert_eq!(
            &sk.commit,
            b"\x02\x43\x3d\x99\x12\x93\x8d\xde\xb9\x57\x4e\xd3\x5d\xf0\x0d\x9f"
        );
    }
    #[test]
    fn key_modified_doesnt_match() {
        // A single byte changed in the key should invalidate all output
        let sk: SubKey = SubKey::new(b"EEEEEEEEEEEEEEEE", b"YEBLOW SUBMARINEYELLOW SUBMARINE");
        assert_ne!(
            &sk.b0,
            b"\x50\x17\x8d\x3f\x59\x81\xb0\xed\xf7\x82\x1f\xff\x45\x46\x56\xbd"
        );
        assert_ne!(
            &sk.b1,
            b"\xdb\x9c\x68\x94\xf9\x96\xaf\x49\xc8\x74\x67\x41\x91\x72\xc4\x3e"
        );
        assert_ne!(
            &sk.commit,
            b"\x02\x43\x3d\x99\x12\x93\x8d\xde\xb9\x57\x4e\xd3\x5d\xf0\x0d\x9f"
        );
    }

    #[test]
    fn nonce_modified_doesnt_match() {
        // A single byte changed in the nonce should invalidate all output
        let sk: SubKey = SubKey::new(b"REEEEEEEEEEEEEEE", b"YELLOW SUBMARINEYELLOW SUBMARINE");
        assert_ne!(
            &sk.b0,
            b"\x50\x17\x8d\x3f\x59\x81\xb0\xed\xf7\x82\x1f\xff\x45\x46\x56\xbd"
        );
        assert_ne!(
            &sk.b1,
            b"\xdb\x9c\x68\x94\xf9\x96\xaf\x49\xc8\x74\x67\x41\x91\x72\xc4\x3e"
        );
        assert_ne!(
            &sk.commit,
            b"\x02\x43\x3d\x99\x12\x93\x8d\xde\xb9\x57\x4e\xd3\x5d\xf0\x0d\x9f"
        );
    }

    #[test]
    fn decrypts_file_correctly() {
        let recovered =
            pbp_decrypt_file("tests/testoutput.pbp", b"YELLOW SUBMARINEYELLOW SUBMARINE");
        let plaintext = str::from_utf8(&recovered).unwrap();
        let correct = include_str!("../tests/testinput.txt");
        assert_eq!(plaintext, correct);
    }

    #[test]
    #[should_panic]
    fn decrypt_fail_key() {
        let _recovered =
            pbp_decrypt_file("tests/testoutput.pbp", b"YELLOW SUBMARINEYEBLOW SUBMARINE");
    }
}
