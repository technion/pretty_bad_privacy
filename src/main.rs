use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, KeyInit, Payload},
    aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit},
    aes::Aes256,
    Aes256Gcm, Key,
};

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
use std::fmt;

const BLOCKSIZE: usize = 16;

struct SubKey {
    b0: [u8; BLOCKSIZE],
    b1: [u8; BLOCKSIZE],
    commit: [u8; BLOCKSIZE],
}

impl SubKey {
    fn new(extension: &[u8; 16], key: &[u8; 32]) -> SubKey {
        let niliv = [0; 16];
        let mut b0 = [0; 16];
        let mut b1 = [0; 16];
        let mut commit = [0; 16];
        let info1 = [extension, String::from("doing b0\x01").as_bytes()].concat();
        let b0all =
            Aes256CbcEnc::new(key.into(), &niliv.into()).encrypt_padded_vec_mut::<Pkcs7>(&info1);

        if let Some(b0chunk) = b0all.rchunks(BLOCKSIZE).nth(0) {
            b0.copy_from_slice(b0chunk);
        } else {
            panic!("Subkey derivation coding bug");
        }

        let info2 = [b0all, String::from("doing b1\x02").into()].concat();
        let b1all =
            Aes256CbcEnc::new(key.into(), &niliv.into()).encrypt_padded_vec_mut::<Pkcs7>(&info2);

        if let Some(b1chunk) = b1all.rchunks(BLOCKSIZE).nth(0) {
            b1.copy_from_slice(b1chunk);
        } else {
            panic!("Subkey derivation coding bug");
        }

        let info3 = [b1all, String::from("doing commitment\x01").into()].concat();
        let commitall =
            Aes256CbcEnc::new(key.into(), &niliv.into()).encrypt_padded_vec_mut::<Pkcs7>(&info3);

        if let Some(commitchunk) = commitall.rchunks(BLOCKSIZE).nth(0) {
            commit.copy_from_slice(commitchunk);
        } else {
            panic!("Subkey derivation coding bug");
        }
        SubKey { b0, b1, commit }
    }
}

impl fmt::Debug for SubKey {
    // A custom debugger allows us to get output in hex
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "b0, b1 are {:02x?}, {:02x?} and commit tag is {:02x?}",
            self.b0, self.b1, self.commit
        )
    }
}

fn pbp_encrypt(subkey: SubKey, plaintext: &[u8], nonce: &[u8; 12]) {
    let key: &mut [u8; 32] = &mut [0; 32];
    key[..BLOCKSIZE].copy_from_slice(&subkey.b0);
    key[BLOCKSIZE..].copy_from_slice(&subkey.b1);
    let key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(key);
    let payload = Payload {
        msg: plaintext,
        aad: &subkey.commit,
    };

    let cipher = Aes256Gcm::new(key);
    let nonce = GenericArray::from_slice(nonce);
    let _ciphertext = cipher.encrypt(nonce, payload).unwrap();
}

fn main() {
    println!("Hello, world!");

    let sk: SubKey = SubKey::new(b"EEEEEEEEEEEEEEEE", b"YELLOW SUBMARINEYELLOW SUBMARINE");
    println! {"{:?}", sk};
    pbp_encrypt(sk, b"this is my plaintext", b"123456789012");
}
