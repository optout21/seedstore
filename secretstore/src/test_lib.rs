use crate::{SecretStore, SecretStoreCreator};
use hex_conservative::{DisplayHex, FromHex};
use rand::Rng;
use std::env::temp_dir;
use std::fs;

const PASSWORD1: &str = "password";
const PASSWORD2: &str = "This is a different password, ain't it?";
const NONSECRET_DATA1: &str = "010203";
const SECRET_DATA1: &str = "0102030405060708";
const PAYLOAD1: &str =
    "5353010301020301f6ecb1e25f4945ae0605638d75c6a34208006e59b27ff2c90dd87c320627";

fn create_store_from_data(nonsecret_data: Vec<u8>, secret_data: &Vec<u8>) -> SecretStore {
    SecretStoreCreator::new_from_data(nonsecret_data, secret_data).unwrap()
}

fn create_store_from_payload(payload: &Vec<u8>, encryption_password: &str) -> SecretStore {
    SecretStore::new_from_payload(payload, encryption_password).unwrap()
}

fn create_payload_from_data(
    nonsecret_data: Vec<u8>,
    secret_data: &Vec<u8>,
    encryption_password: &str,
) -> Vec<u8> {
    let store = create_store_from_data(nonsecret_data, secret_data);
    let payload = store
        .assemble_encrypted_payload(encryption_password)
        .unwrap();
    payload
}

#[test]
fn create_from_data() {
    let nonsecret_data = Vec::from_hex(NONSECRET_DATA1).unwrap();
    let secret_data = Vec::from_hex(SECRET_DATA1).unwrap();
    let store = create_store_from_data(nonsecret_data.clone(), &secret_data);

    assert_eq!(store.nonsecret_data().clone(), nonsecret_data);
    assert_eq!(store.secret_data().unwrap().clone(), secret_data);

    // uncomment for obtaining actual output
    // let payload = store.assemble_encrypted_payload(&PASSWORD1).unwrap();
    // assert_eq!(payload.to_lower_hex_string(), "123");
}

#[test]
fn create_from_payload_const() {
    let payload = Vec::from_hex(PAYLOAD1).unwrap();
    let password = PASSWORD1.to_owned();

    let store = create_store_from_payload(&payload, &password);

    assert_eq!(
        store.nonsecret_data().to_lower_hex_string(),
        NONSECRET_DATA1
    );
    assert_eq!(
        store.secret_data().unwrap().to_lower_hex_string(),
        SECRET_DATA1
    );

    assert_eq!(
        store
            .assemble_encrypted_payload(&password)
            .unwrap()
            .to_lower_hex_string(),
        PAYLOAD1
    );
}

#[test]
fn create_from_payload_generated() {
    let nonsecret_data = Vec::from_hex(NONSECRET_DATA1).unwrap();
    let secret_data = Vec::from_hex(SECRET_DATA1).unwrap();
    let password = PASSWORD1.to_owned();
    let payload = create_payload_from_data(nonsecret_data.clone(), &secret_data, &password);

    let store = create_store_from_payload(&payload, &password);

    assert_eq!(store.nonsecret_data().clone(), nonsecret_data);
    assert_eq!(store.secret_data().unwrap().clone(), secret_data);

    // Note: cannot assert full payload, contains dynamic fields
    let payload = store.assemble_encrypted_payload(&password).unwrap();
    assert_eq!(payload.len(), 38);
    assert_eq!(payload[0..8].to_lower_hex_string(), "5353010301020301");
}

#[test]
fn create_from_payload_different_pw() {
    let nonsecret_data = Vec::from_hex(NONSECRET_DATA1).unwrap();
    let secret_data = Vec::from_hex(SECRET_DATA1).unwrap();
    let password = PASSWORD2.to_owned();
    let payload = create_payload_from_data(nonsecret_data.clone(), &secret_data, &password);

    let store = create_store_from_payload(&payload, &password);

    assert_eq!(store.nonsecret_data().clone(), nonsecret_data);
    assert_eq!(store.secret_data().unwrap().clone(), secret_data);

    // Note: cannot assert full payload, contains dynamic fields
    let payload = store.assemble_encrypted_payload(&password).unwrap();
    assert_eq!(payload.len(), 38);
    assert_eq!(payload[0..8].to_lower_hex_string(), "5353010301020301");
}

#[test]
fn create_from_data_very_long() {
    let nonsecret_data = [7; 255].to_vec();
    let secret_data = [8; 256].to_vec();
    let store = create_store_from_data(nonsecret_data.clone(), &secret_data);

    assert_eq!(store.nonsecret_data().clone(), nonsecret_data);
    assert_eq!(store.secret_data().unwrap().clone(), secret_data);
}

#[test]
fn create_from_data_very_short() {
    let nonsecret_data = Vec::new();
    let secret_data = vec![0];
    let store = create_store_from_data(nonsecret_data.clone(), &secret_data);

    assert_eq!(store.nonsecret_data().clone(), nonsecret_data);
    assert_eq!(store.secret_data().unwrap().clone(), secret_data);
}

#[test]
fn neg_create_from_data_secret_too_long() {
    let nonsecret_data = Vec::from_hex(NONSECRET_DATA1).unwrap();
    let secret_data = [7; 65536].to_vec();
    let res = SecretStoreCreator::new_from_data(nonsecret_data, &secret_data);
    assert_eq!(res.err().unwrap(), "Secret data too long, 65536 vs 65535");
}

#[test]
fn neg_create_from_data_nonsecret_too_long() {
    let nonsecret_data = [7; 256].to_vec();
    let secret_data = Vec::from_hex(SECRET_DATA1).unwrap();
    let res = SecretStoreCreator::new_from_data(nonsecret_data, &secret_data);
    assert_eq!(res.err().unwrap(), "Non-secret data too long, 256 vs 255");
}

#[test]
fn neg_create_from_payload_with_wrong_checksum() {
    let nonsecret_data = Vec::from_hex(NONSECRET_DATA1).unwrap();
    let secret_data = Vec::from_hex(SECRET_DATA1).unwrap();
    let password = PASSWORD1.to_owned();
    let mut payload = create_payload_from_data(nonsecret_data.clone(), &secret_data, &password);
    let payload_len = payload.len();
    assert!(payload_len > 0);
    payload[payload_len - 1] -= 1;

    let res = SecretStore::new_from_payload(&payload, &password);
    assert_eq!(
        res.err().unwrap(),
        "Checksum mismatch, check the secret file!"
    );
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
    let nonsecret_data = Vec::from_hex(NONSECRET_DATA1).unwrap();
    let secret_data = Vec::from_hex(SECRET_DATA1).unwrap();
    let store = create_store_from_data(nonsecret_data.clone(), &secret_data);

    let temp_file = get_temp_file_name();
    let password = PASSWORD1.to_owned();
    let _res = store.write_to_file(&temp_file, &password).unwrap();

    // check the file
    let contents = fs::read(&temp_file).unwrap();
    // Note: cannot assert full contents, it contains dynamic fields
    assert_eq!(contents.len(), 38);
    assert_eq!(contents[0..8].to_lower_hex_string(), "5353010301020301");

    let _res = fs::remove_file(&temp_file);
}

#[test]
fn read_from_file() {
    let temp_file = get_temp_file_name();

    // write constant payload to file
    let payload = Vec::from_hex(PAYLOAD1).unwrap();
    let _res = fs::write(&temp_file, &payload).unwrap();

    let password = PASSWORD1.to_owned();
    let store = SecretStore::new_from_encrypted_file(&temp_file, &password).unwrap();

    assert_eq!(
        store.nonsecret_data().to_lower_hex_string(),
        NONSECRET_DATA1
    );
    assert_eq!(
        store.secret_data().unwrap().to_lower_hex_string(),
        SECRET_DATA1
    );

    let _res = fs::remove_file(&temp_file);
}

#[test]
fn read_from_file_diff_pw() {
    let temp_file = get_temp_file_name();

    // write constant payload to file
    let payload = Vec::from_hex(PAYLOAD1).unwrap();
    let _res = fs::write(&temp_file, &payload).unwrap();

    let password = PASSWORD2.to_owned();
    let store = SecretStore::new_from_encrypted_file(&temp_file, &password).unwrap();

    assert_eq!(store.nonsecret_data().to_lower_hex_string(), "010203");
    assert_eq!(
        store.secret_data().unwrap().to_lower_hex_string(),
        "14bfe3f1c46b3d3c"
    );

    let _res = fs::remove_file(&temp_file);
}

#[test]
fn neg_create_password_too_short() {
    let nonsecret_data = Vec::from_hex(NONSECRET_DATA1).unwrap();
    let secret_data = Vec::from_hex(SECRET_DATA1).unwrap();
    let store = create_store_from_data(nonsecret_data.clone(), &secret_data);

    let short_password = "no";
    let res = SecretStoreCreator::write_to_file(&store, "dummy_filename", short_password);
    assert_eq!(res.err().unwrap(), "Password is too short! (2 vs 7)");
}
