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
    "53530104002a2b2c030d6a14b96b3dc98ad33c2dc35966f1d019ae236ce28b8f003388bd0c6f6d6fa18c1ff12521a46bd2e52000e8b03820e69c000daddc7dbcf76a6a0137097893246d83033a6249cd89a21e3a3f8e8626";
const PAYLOAD_V1_EV2_SCRYPT: &str =
    "53530104002a2b2c020ee3d3970706fbe9f680eb68763af3c849100010907fc4f2740c7613422df300488137c1e6af59";
const PAYLOAD_V1_EV1_XOR: &str =
    "53530104002a2b2c01134a7bef7fd0b5704d7b44122dd634d210001662e6ef23b24a283f236315d8572c057fb8254d";
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
    assert_eq!(contents.len(), 48);
    assert_eq!(
        contents[0..10].to_lower_hex_string(),
        "53530104002a2b2c020e"
    );

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
fn neg_read_from_file_scrypt_wrong_pw_wrong_result() {
    let temp_file = get_temp_file_name();

    // write constant payload to file
    let payload = Vec::from_hex(PAYLOAD_V1_EV2_SCRYPT).unwrap();
    let _res = fs::write(&temp_file, &payload).unwrap();

    let password = PASSWORD2.to_owned();
    let store = SeedStore::new_from_encrypted_file(&temp_file, &password).unwrap();
    assert_eq!(
        store.get_xpub().unwrap().to_string(),
        "xpub6C9bhdVGdXxNebC2e2JWUxQVvuES2hyCSCVceFs8CttjxbLcZY4BwibjSjt9wYYMre2dwsHsEsonMZ9K7s28f2KdUARC1hLvmY2cBiufbJ4"
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
    assert_eq!(res.err().unwrap(), "Decryption error aead::Error");

    let _res = fs::remove_file(&temp_file);
}

#[test]
fn neg_read_from_file_xor_wrong_pw_wrong_result() {
    let temp_file = get_temp_file_name();

    // write constant payload to file
    let payload = Vec::from_hex(PAYLOAD_V1_EV1_XOR).unwrap();
    let _res = fs::write(&temp_file, &payload).unwrap();

    let password = PASSWORD2.to_owned();
    let store = SeedStore::new_from_encrypted_file(&temp_file, &password).unwrap();
    assert_eq!(
        store.get_xpub().unwrap().to_string(),
        "xpub6DDKxdpioLFXu3Gmg99GKf5Rrkpk5VoLU555MQPbhu8wT1zLWbp37wXtCUSwTnBcRwk4fhD8vtiTuwoSThBsXT4H8p3bNc6UduF44c9cTMe"
    );

    let _res = fs::remove_file(&temp_file);
}

#[test]
fn neg_create_from_data_invalid_entropy_len() {
    let network = 0u8;
    // 18-byte entropy is not valid
    let entropy = [42u8; 18].to_vec();
    let store_res = SeedStoreCreator::new_from_data(&entropy, network);
    assert_eq!(store_res.err().unwrap(), "Invalid entropy length 18");
}
