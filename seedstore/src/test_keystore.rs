use crate::{KeyStore, KeyStoreCreator};
use hex_conservative::{DisplayHex, FromHex};
use rand::Rng;
use std::env::temp_dir;
use std::fs;
use zeroize::Zeroize;

const PASSWORD1: &str = "password";
const PASSWORD2: &str = "This is a different password, ain't it?";
const PAYLOAD_V1_EV2_SCRYPT: &str = "535301042a2b2c2d020ef2b6285346559b45dd51fa64ecb5d4e82000adb162a64389dee81bbf1a788b0626961153c6e6edefe6aa03b07e44d2d3d727bb318d87";
const SECRETKEY1: &str = "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";
const PUBKEY1: &str = "03e93e38d9069fea998726eb25a5e9bdaadae9161ef8e63508dba807334dced88b";

#[test]
fn create_from_data() {
    let secret_key = <[u8; 32]>::from_hex(SECRETKEY1).unwrap();
    let mut store = KeyStoreCreator::new_from_data(&secret_key).unwrap();

    assert_eq!(store.get_public_key().unwrap().to_string(), PUBKEY1);

    // uncomment for obtaining actual output
    // let payload = store.secretstore.assemble_encrypted_payload(&PASSWORD1).unwrap();
    // assert_eq!(payload.to_lower_hex_string(), "_placeholder_");

    store.zeroize();
}

#[cfg(feature = "accesssecret")]
#[test]
fn create_get_secret() {
    let secret_key = <[u8; 32]>::from_hex(SECRETKEY1).unwrap();
    let mut store = KeyStoreCreator::new_from_data(&secret_key).unwrap();

    assert_eq!(
        store
            .get_secret_private_key()
            .unwrap()
            .as_ref()
            .to_lower_hex_string(),
        SECRETKEY1
    );

    store.zeroize();
}

#[test]
fn create_from_payload_const() {
    let payload = Vec::from_hex(PAYLOAD_V1_EV2_SCRYPT).unwrap();
    let password = PASSWORD1.to_owned();

    let mut store = KeyStore::new_from_payload(&payload, &password).unwrap();

    assert_eq!(store.get_public_key().unwrap().to_string(), PUBKEY1);

    store.zeroize();
}

#[test]
fn neg_create_from_payload_wrong_pw_wrong_result() {
    let payload = Vec::from_hex(PAYLOAD_V1_EV2_SCRYPT).unwrap();
    let password = PASSWORD2.to_owned();

    let mut store = KeyStore::new_from_payload(&payload, &password).unwrap();

    assert_eq!(
        store.get_public_key().unwrap().to_string(),
        "0220f48152da86d1c482078eefaf71121ca61295cdfbcd630bf9b07b63566c39d2"
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
    let secret_key = <[u8; 32]>::from_hex(SECRETKEY1).unwrap();
    let store = KeyStoreCreator::new_from_data(&secret_key).unwrap();

    let temp_file = get_temp_file_name();
    let password = PASSWORD1.to_owned();
    let _res = store.write_to_file(&temp_file, &password).unwrap();

    // check the file
    let contents = fs::read(&temp_file).unwrap();
    // Note: cannot assert full contents, it contains dynamic fields
    assert_eq!(contents.len(), 64);
    assert_eq!(
        contents[0..10].to_lower_hex_string(),
        "535301042a2b2c2d020e"
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
    let store = KeyStore::new_from_encrypted_file(&temp_file, &password).unwrap();

    assert_eq!(store.get_public_key().unwrap().to_string(), PUBKEY1);

    let _res = fs::remove_file(&temp_file);
}

#[test]
fn test_signature() {
    let secret_key = <[u8; 32]>::from_hex(SECRETKEY1).unwrap();
    let store = KeyStoreCreator::new_from_data(&secret_key).unwrap();

    assert_eq!(store.get_public_key().unwrap().to_string(), PUBKEY1);

    let pubkey = store.get_public_key().unwrap();

    let hash_to_be_signed = [42; 32];

    let signature = store
        .sign_hash_with_private_key_ecdsa(&hash_to_be_signed, &pubkey)
        .unwrap();

    // Signature can change, do not assert,
    // but verify the signature
    {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let msg = bitcoin::secp256k1::Message::from_digest_slice(&hash_to_be_signed).unwrap();
        let verify_result = secp.verify_ecdsa(&msg, &signature, &pubkey);
        assert!(verify_result.is_ok());
    }
}
