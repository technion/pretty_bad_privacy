
use aes_gcm::{
    aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit},
    aes::Aes256,
};
type Aes256CbcEnc = cbc::Encryptor<Aes256>;
use secrecy::{ExposeSecret, Secret, Zeroize};
const BLOCKSIZE: usize = 16;

#[derive(Debug)]
struct SubKeyBlock([u8; BLOCKSIZE]);
impl Zeroize for SubKeyBlock {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl SubKeyBlock {
    fn as_bytes(&self) -> [u8; BLOCKSIZE] {
        self.0
    }
}

pub struct SubKey {
    b0: Secret<SubKeyBlock>,
    b1: Secret<SubKeyBlock>,
    burnt: bool,
    pub commit: [u8; BLOCKSIZE],
}

impl SubKey {
    pub fn new(extension: &[u8; BLOCKSIZE], key: &[u8; 32]) -> SubKey {
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

        SubKey {
            b0: SubKeyBlock(b0).into(),
            b1: SubKeyBlock(b1).into(),
            burnt: false,
            commit,
        }
    }

    pub fn get_keys(&mut self) -> [u8; 32] {
        // The only way to get keys out of this SubKey structure is to use this function
        // This sets a burnt flag and guarantees they (and by association, the nonce extension) is single use
        assert!(self.burnt == false);
        let key: &mut [u8; 32] = &mut [0; 32];
        key[..BLOCKSIZE].copy_from_slice(&self.b0.expose_secret().as_bytes());
        key[BLOCKSIZE..].copy_from_slice(&self.b1.expose_secret().as_bytes());
        self.burnt = true;

        *key
    }
}


#[test]
fn key_derive_matches_prototype() {
    // This is the exact output from the Ruby prototype as a verifier
    let sk: SubKey = SubKey::new(b"EEEEEEEEEEEEEEEE", b"YELLOW SUBMARINEYELLOW SUBMARINE");

    assert_eq!(
        &sk.b0.expose_secret().as_bytes(),
        b"\x50\x17\x8d\x3f\x59\x81\xb0\xed\xf7\x82\x1f\xff\x45\x46\x56\xbd"
    );
    assert_eq!(
        &sk.b1.expose_secret().as_bytes(),
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
        &sk.b0.expose_secret().as_bytes(),
        b"\x50\x17\x8d\x3f\x59\x81\xb0\xed\xf7\x82\x1f\xff\x45\x46\x56\xbd"
    );
    assert_ne!(
        &sk.b1.expose_secret().as_bytes(),
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
        &sk.b0.expose_secret().as_bytes(),
        b"\x50\x17\x8d\x3f\x59\x81\xb0\xed\xf7\x82\x1f\xff\x45\x46\x56\xbd"
    );
    assert_ne!(
        &sk.b1.expose_secret().as_bytes(),
        b"\xdb\x9c\x68\x94\xf9\x96\xaf\x49\xc8\x74\x67\x41\x91\x72\xc4\x3e"
    );
    assert_ne!(
        &sk.commit,
        b"\x02\x43\x3d\x99\x12\x93\x8d\xde\xb9\x57\x4e\xd3\x5d\xf0\x0d\x9f"
    );
}
