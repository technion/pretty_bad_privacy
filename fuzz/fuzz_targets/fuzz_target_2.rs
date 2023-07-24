#![no_main]
#![allow(unused_variables)]
#![allow(dead_code)]
include!("../../src/main.rs");

use libfuzzer_sys::fuzz_target;
use tempfile::NamedTempFile;

fuzz_target!(|data: &[u8]| {
    
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(&data).unwrap();
    let key: SecretAESKey = AESKey::from(String::from("YELLOW SUBMARINEYELLOW SUBMARINE")).into() ;
    let res = pbp_decrypt_file(file.path().to_str().unwrap(), &key);
    file.close().unwrap();

});