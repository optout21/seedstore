use crate::{ChildSpecifier, SeedStore, SeedStoreCreator};
use hex_conservative::{DisplayHex, FromHex};
use rand::Rng;
use std::env::temp_dir;
use std::fs;
use zeroize::Zeroize;

const PASSWORD1: &str = "password";
const PASSWORD2: &str = "This is a different password, ain't it?";
const ENTROPY_OIL12: &str = "99d33a674ce99d33a674ce99d33a674c";
const PAYLOAD_V1_EV3_CHACHA: &str =
    "53530102000e030d15f1608af5fd9885600a614d3c5da8c42e06e3c9dd872ac2959234d2a31412f81ca7171ffb33f27120007d735a87f4691fb5fb2ae657030412f310ee748ecbe49a5266beb6fb61f02da09d464546";
const PAYLOAD_V1_EV2_SCRYPT: &str =
    "53530102000e020e612e9f5b26e546eb1c184df10479bf871000830a2ea9fcbb9ecc25b9d671e5a969d951190574";
const PAYLOAD_V1_EV1_XOR: &str =
    "53530102000e01fe2f895dbc4d8f75c87b47aa4051549e10001770917c0ea37427b716a4a5df5770f12d1b575e";
const XPUB1: &str = "xpub6CDDB17Xj7pDDWedpLsED1JbPPQmyuapHmAzQEEs2P57hciCjwQ3ov7TfGsTZftAM2gVdPzE55L6gUvHguwWjY82518zw1Z3VbDeWgx3Jqs";
const XPUB2: &str = "tpubDCRo9GmRAvEWANJ5iSfMEqPoq3uYvjBPAAjrDj5iQMxAq7DCs5orw7m9xJes8hWYAwKuH3T63WrKfzzw7g9ucbjq4LUu5cgCLUPMN7gUkrL";
const ADDR1: &str = "bc1q98wufxmtfh5qlk7fe5dzy2z8cflvqjysrh4fx2";

#[test]
fn create_from_data() {
    let network = 0u8;
    let entropy = Vec::from_hex(ENTROPY_OIL12).unwrap();
    let mut store = SeedStoreCreator::new_from_data(&entropy, network).unwrap();

    assert_eq!(store.network(), 0);
    assert_eq!(store.get_xpub().unwrap().to_string(), XPUB1);
    assert_eq!(
        store
            .get_child_address(&ChildSpecifier::Indices3and4(0, 0))
            .unwrap(),
        ADDR1
    );
    assert_eq!(
        store
            .get_child_address(&ChildSpecifier::Indices3and4(0, 1))
            .unwrap(),
        "bc1q2acf8wdcjkskt5ug24szudejaqv6wgu3jzuw02"
    );
    assert_eq!(
        store
            .get_child_address(&ChildSpecifier::Indices3and4(1, 0))
            .unwrap(),
        "bc1q0rent4vu9eyqw3g0me4h0lgcply7j23yelnx6k"
    );
    assert_eq!(
        store
            .get_child_public_key(&ChildSpecifier::Indices3and4(0, 0))
            .unwrap()
            .to_string(),
        "032814221178177cb5ac81ae0ffa3be2e3c936503d6927050af739a41311f3821e"
    );

    // uncomment for obtaining actual output
    // let payload = store.secretstore.assemble_encrypted_payload(&PASSWORD1).unwrap();
    // assert_eq!(payload.to_lower_hex_string(), "_placeholder_");

    store.zeroize();
}

#[test]
fn create_from_data_net_3() {
    let network = 3u8;
    let entropy = Vec::from_hex(ENTROPY_OIL12).unwrap();
    let store = SeedStoreCreator::new_from_data(&entropy, network).unwrap();

    assert_eq!(store.network(), 3);
    assert_eq!(store.get_xpub().unwrap().to_string(), XPUB2);
    assert_eq!(
        store
            .get_child_address(&ChildSpecifier::Indices3and4(0, 0))
            .unwrap(),
        "tb1q6p8uqhn8rp5wrclfhh7a5q350zravflrd79rwg"
    );
}

#[test]
fn create_from_payload_const_scrypt() {
    let payload = Vec::from_hex(PAYLOAD_V1_EV2_SCRYPT).unwrap();
    let password = PASSWORD1.to_owned();

    let mut store = SeedStore::new_from_payload(&payload, &password).unwrap();

    assert_eq!(store.network(), 0);
    assert_eq!(store.get_xpub().unwrap().to_string(), XPUB1);
    assert_eq!(
        store
            .get_child_address(&ChildSpecifier::Indices3and4(0, 0))
            .unwrap(),
        ADDR1
    );

    store.zeroize();
}

#[test]
fn create_from_payload_const_chacha() {
    let payload = Vec::from_hex(PAYLOAD_V1_EV3_CHACHA).unwrap();
    let password = PASSWORD1.to_owned();

    let mut store = SeedStore::new_from_payload(&payload, &password).unwrap();

    assert_eq!(store.network(), 0);
    assert_eq!(store.get_xpub().unwrap().to_string(), XPUB1);
    assert_eq!(
        store
            .get_child_address(&ChildSpecifier::Indices3and4(0, 0))
            .unwrap(),
        ADDR1
    );

    store.zeroize();
}

#[test]
fn create_from_payload_const_xor() {
    let payload = Vec::from_hex(PAYLOAD_V1_EV1_XOR).unwrap();
    let password = PASSWORD1.to_owned();

    let mut store = SeedStore::new_from_payload(&payload, &password).unwrap();

    assert_eq!(store.network(), 0);
    assert_eq!(store.get_xpub().unwrap().to_string(), XPUB1);
    assert_eq!(
        store
            .get_child_address(&ChildSpecifier::Indices3and4(0, 0))
            .unwrap(),
        ADDR1,
    );

    store.zeroize();
}

fn get_temp_file_name() -> String {
    format!(
        "{}/_seedstore_tempfile_{}_.tmp",
        temp_dir().to_str().unwrap(),
        rand::rng().random::<u32>()
    )
}

#[test]
fn write_to_file() {
    let network = 0u8;
    let entropy = Vec::from_hex(ENTROPY_OIL12).unwrap();
    let store = SeedStoreCreator::new_from_data(&entropy, network).unwrap();

    let temp_file = get_temp_file_name();
    let password = PASSWORD1.to_owned();
    let _res = store.write_to_file(&temp_file, &password).unwrap();

    // check the file
    let contents = fs::read(&temp_file).unwrap();
    // Note: cannot assert full contents, it contains dynamic fields
    assert_eq!(contents.len(), 46);
    assert_eq!(contents[0..8].to_lower_hex_string(), "53530102000e020e");

    let _res = fs::remove_file(&temp_file);
}

#[test]
fn read_from_file() {
    let temp_file = get_temp_file_name();

    // write constant payload to file
    let payload = Vec::from_hex(PAYLOAD_V1_EV2_SCRYPT).unwrap();
    let _res = fs::write(&temp_file, &payload).unwrap();

    let password = PASSWORD1.to_owned();
    let store = SeedStore::new_from_encrypted_file(&temp_file, &password).unwrap();

    assert_eq!(store.network(), 0);
    assert_eq!(store.get_xpub().unwrap().to_string(), XPUB1);

    let _res = fs::remove_file(&temp_file);
}

#[test]
fn neg_read_from_file_scrypt_wrong_pw_invalid_checksum() {
    let temp_file = get_temp_file_name();

    // write constant payload to file
    let payload = Vec::from_hex(PAYLOAD_V1_EV2_SCRYPT).unwrap();
    let _res = fs::write(&temp_file, &payload).unwrap();

    let password = PASSWORD2.to_owned();
    let res = SeedStore::new_from_encrypted_file(&temp_file, &password);
    debug_assert_eq!(
        res.err().unwrap(),
        "Checksum mismatch (14 vs 6), check the password and the secret file!"
    );

    let _res = fs::remove_file(&temp_file);
}

#[test]
fn neg_read_from_file_chacha_wrong_pw_decrypt_error() {
    let temp_file = get_temp_file_name();

    // write constant payload to file
    let payload = Vec::from_hex(PAYLOAD_V1_EV3_CHACHA).unwrap();
    let _res = fs::write(&temp_file, &payload).unwrap();

    let password = PASSWORD2.to_owned();
    let res = SeedStore::new_from_encrypted_file(&temp_file, &password);
    debug_assert_eq!(res.err().unwrap(), "Decryption error aead::Error");

    let _res = fs::remove_file(&temp_file);
}

#[test]
fn neg_read_from_file_xor_wrong_pw_invalid_checksum() {
    let temp_file = get_temp_file_name();

    // write constant payload to file
    let payload = Vec::from_hex(PAYLOAD_V1_EV1_XOR).unwrap();
    let _res = fs::write(&temp_file, &payload).unwrap();

    let password = PASSWORD2.to_owned();
    let res = SeedStore::new_from_encrypted_file(&temp_file, &password);
    debug_assert_eq!(
        res.err().unwrap(),
        "Checksum mismatch (14 vs 4), check the password and the secret file!"
    );

    let _res = fs::remove_file(&temp_file);
}
