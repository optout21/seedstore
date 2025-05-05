use crate::{ChildSpecifier, SeedStore, SeedStoreCreator};
use bitcoin::Network;
use hex_conservative::{DisplayHex, FromHex};
use rand::Rng;
use std::env::temp_dir;
use std::fs;
use zeroize::Zeroize;

const PASSWORD1: &str = "password";
const PASSWORD2: &str = "This is a different password, ain't it?";
const PASSWORD3: &str = "aA1+bB2+cC3";
const ENTROPY_OIL12: &str = "99d33a674ce99d33a674ce99d33a674c";
const PAYLOAD_V1_EV3_CHACHA: &str =
    "53530104002a2b2c030d6a14b96b3dc98ad33c2dc35966f1d019ae236ce28b8f003388bd0c6f6d6fa18c1ff12521a46bd2e52000e8b03820e69c000daddc7dbcf76a6a0137097893246d83033a6249cd89a21e3a3f8e8626";
const PAYLOAD_V1_EV2_SCRYPT: &str =
    "53530104002a2b2c020ee3d3970706fbe9f680eb68763af3c849100010907fc4f2740c7613422df300488137c1e6af59";
const PAYLOAD_V1_EV1_XOR: &str =
    "53530104002a2b2c01134a7bef7fd0b5704d7b44122dd634d210001662e6ef23b24a283f236315d8572c057fb8254d";
const XPUB1: &str = "xpub6CDDB17Xj7pDDWedpLsED1JbPPQmyuapHmAzQEEs2P57hciCjwQ3ov7TfGsTZftAM2gVdPzE55L6gUvHguwWjY82518zw1Z3VbDeWgx3Jqs";
const XPUB2: &str = "tpubDCRo9GmRAvEWANJ5iSfMEqPoq3uYvjBPAAjrDj5iQMxAq7DCs5orw7m9xJes8hWYAwKuH3T63WrKfzzw7g9ucbjq4LUu5cgCLUPMN7gUkrL";
const XPUB3: &str = "xpub6CVT9PXjALUVjoa3t1kgq3fAiUoGYeothP8sZSstrJ6d2nJXy4ajmtCPgE59Xyw9LkHtf9TznxA8BhPu5d33JycXxRwToufe6zWoU6icLbJ";
const ADDR1: &str = "bc1q98wufxmtfh5qlk7fe5dzy2z8cflvqjysrh4fx2";
const PASSPHRASE1: &str = "this_is_a_secret_passphrase";

#[test]
fn create_from_data() {
    let entropy = Vec::from_hex(ENTROPY_OIL12).unwrap();
    let mut store = SeedStoreCreator::new_from_data(&entropy, None, None).unwrap();

    assert_eq!(store.network(), Network::Bitcoin);
    assert_eq!(store.get_xpub().unwrap().to_string(), XPUB1);
    assert_eq!(
        store
            .get_child_address(&ChildSpecifier::ChangeAndIndex34(0, 0))
            .unwrap(),
        ADDR1
    );
    assert_eq!(
        store
            .get_child_address(&ChildSpecifier::ChangeAndIndex34(0, 1))
            .unwrap(),
        "bc1q2acf8wdcjkskt5ug24szudejaqv6wgu3jzuw02"
    );
    assert_eq!(
        store
            .get_child_address(&ChildSpecifier::ChangeAndIndex34(1, 0))
            .unwrap(),
        "bc1q0rent4vu9eyqw3g0me4h0lgcply7j23yelnx6k"
    );
    assert_eq!(
        store
            .get_child_public_key(&ChildSpecifier::ChangeAndIndex34(0, 0))
            .unwrap()
            .to_string(),
        "032814221178177cb5ac81ae0ffa3be2e3c936503d6927050af739a41311f3821e"
    );

    // uncomment for obtaining actual output
    // let payload = store.secretstore.assemble_encrypted_payload(&PASSWORD1).unwrap();
    // assert_eq!(payload.to_lower_hex_string(), "_placeholder_");

    store.zeroize();
}

#[cfg(feature = "accesssecret")]
#[test]
fn create_get_secret() {
    let entropy = Vec::from_hex(ENTROPY_OIL12).unwrap();
    let mut store = SeedStoreCreator::new_from_data(&entropy, None, None).unwrap();

    assert_eq!(
        store
            .get_secret_child_private_key(&ChildSpecifier::ChangeAndIndex34(0, 0))
            .unwrap()
            .as_ref()
            .to_lower_hex_string(),
        "4a325ea0f3928321a2856b1d26d89c98a634b257d58a6e3ca434e4f0593ce3df"
    );
    assert_eq!(
        store.get_secret_mnemonic().unwrap(),
        "oil oil oil oil oil oil oil oil oil oil oil oil"
    );

    store.zeroize();
}

#[test]
fn create_from_data_net_signet() {
    let network = Network::Signet;
    let entropy = Vec::from_hex(ENTROPY_OIL12).unwrap();
    let store = SeedStoreCreator::new_from_data(&entropy, Some(network), None).unwrap();

    assert_eq!(store.network(), network);
    assert_eq!(store.get_xpub().unwrap().to_string(), XPUB2);
    assert_eq!(
        store
            .get_child_address(&ChildSpecifier::ChangeAndIndex34(0, 0))
            .unwrap(),
        "tb1q6p8uqhn8rp5wrclfhh7a5q350zravflrd79rwg"
    );
}

#[test]
fn create_from_payload_const_scrypt() {
    let payload = Vec::from_hex(PAYLOAD_V1_EV2_SCRYPT).unwrap();
    let password = PASSWORD1.to_owned();

    let mut store = SeedStore::new_from_payload(&payload, &password, None).unwrap();

    assert_eq!(store.network(), Network::Bitcoin);
    assert_eq!(store.get_xpub().unwrap().to_string(), XPUB1);
    assert_eq!(
        store
            .get_child_address(&ChildSpecifier::ChangeAndIndex34(0, 0))
            .unwrap(),
        ADDR1
    );

    store.zeroize();
}

#[test]
fn create_from_payload_const_chacha() {
    let payload = Vec::from_hex(PAYLOAD_V1_EV3_CHACHA).unwrap();
    let password = PASSWORD1.to_owned();

    let mut store = SeedStore::new_from_payload(&payload, &password, None).unwrap();

    assert_eq!(store.network(), Network::Bitcoin);
    assert_eq!(store.get_xpub().unwrap().to_string(), XPUB1);
    assert_eq!(
        store
            .get_child_address(&ChildSpecifier::ChangeAndIndex34(0, 0))
            .unwrap(),
        ADDR1
    );

    store.zeroize();
}

#[test]
fn create_from_payload_const_xor() {
    let payload = Vec::from_hex(PAYLOAD_V1_EV1_XOR).unwrap();
    let password = PASSWORD1.to_owned();

    let mut store = SeedStore::new_from_payload(&payload, &password, None).unwrap();

    assert_eq!(store.network(), Network::Bitcoin);
    assert_eq!(store.get_xpub().unwrap().to_string(), XPUB1);
    assert_eq!(
        store
            .get_child_address(&ChildSpecifier::ChangeAndIndex34(0, 0))
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
    let entropy = Vec::from_hex(ENTROPY_OIL12).unwrap();
    let store = SeedStoreCreator::new_from_data(&entropy, None, None).unwrap();

    let temp_file = get_temp_file_name();
    let password = PASSWORD3.to_owned();
    let _res = store.write_to_file(&temp_file, &password, None).unwrap();

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
    let store = SeedStore::new_from_encrypted_file(&temp_file, &password, None).unwrap();

    assert_eq!(store.network(), Network::Bitcoin);
    assert_eq!(store.get_xpub().unwrap().to_string(), XPUB1);

    let _res = fs::remove_file(&temp_file);
}

#[test]
fn neg_create_from_payload_scrypt_wrong_pw_wrong_result() {
    let payload = Vec::from_hex(PAYLOAD_V1_EV2_SCRYPT).unwrap();
    let password = PASSWORD2.to_owned();
    let store = SeedStore::new_from_payload(&payload, &password, None).unwrap();
    assert_eq!(
        store.get_xpub().unwrap().to_string(),
        "xpub6C9bhdVGdXxNebC2e2JWUxQVvuES2hyCSCVceFs8CttjxbLcZY4BwibjSjt9wYYMre2dwsHsEsonMZ9K7s28f2KdUARC1hLvmY2cBiufbJ4"
    );
}

#[test]
fn neg_create_from_payload_chacha_wrong_pw_decrypt_error() {
    let payload = Vec::from_hex(PAYLOAD_V1_EV3_CHACHA).unwrap();
    let password = PASSWORD2.to_owned();
    let res = SeedStore::new_from_payload(&payload, &password, None);
    assert_eq!(res.err().unwrap(), "Decryption error aead::Error");
}

#[test]
fn neg_rcreate_from_payload_xor_wrong_pw_wrong_result() {
    let payload = Vec::from_hex(PAYLOAD_V1_EV1_XOR).unwrap();
    let password = PASSWORD2.to_owned();
    let store = SeedStore::new_from_payload(&payload, &password, None).unwrap();
    assert_eq!(
        store.get_xpub().unwrap().to_string(),
        "xpub6DDKxdpioLFXu3Gmg99GKf5Rrkpk5VoLU555MQPbhu8wT1zLWbp37wXtCUSwTnBcRwk4fhD8vtiTuwoSThBsXT4H8p3bNc6UduF44c9cTMe"
    );
}

#[test]
fn neg_create_from_data_invalid_entropy_len() {
    // 18-byte entropy is not valid
    let entropy = [42u8; 18].to_vec();
    let store_res = SeedStoreCreator::new_from_data(&entropy, None, None);
    assert_eq!(store_res.err().unwrap(), "Invalid entropy length 18");
}

#[test]
fn test_signature() {
    let entropy = Vec::from_hex(ENTROPY_OIL12).unwrap();
    let store = SeedStoreCreator::new_from_data(&entropy, None, None).unwrap();

    assert_eq!(store.network(), Network::Bitcoin);
    assert_eq!(store.get_xpub().unwrap().to_string(), XPUB1);

    let child_specifier = ChildSpecifier::Index4(7);
    let pubkey = store.get_child_public_key(&child_specifier).unwrap();

    let hash_to_be_signed = [42; 32];

    let signature = store
        .sign_hash_with_child_private_key_ecdsa(&child_specifier, &hash_to_be_signed, &pubkey)
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

#[test]
fn neg_test_signature_wrong_signer_key() {
    let entropy = Vec::from_hex(ENTROPY_OIL12).unwrap();
    let store = SeedStoreCreator::new_from_data(&entropy, None, None).unwrap();

    assert_eq!(store.network(), Network::Bitcoin);
    assert_eq!(store.get_xpub().unwrap().to_string(), XPUB1);

    let hash_to_be_signed = [42; 32];

    let signature_res = store.sign_hash_with_child_private_key_ecdsa(
        &ChildSpecifier::Index4(7),
        &hash_to_be_signed,
        &store
            .get_child_public_key(&ChildSpecifier::Index4(88))
            .unwrap(),
    );
    assert_eq!(
        signature_res.err().unwrap().get(0..23).unwrap(),
        "Public key mismatch, 03"
    );
}

#[test]
fn passphrase_create_from_payload() {
    let payload = Vec::from_hex(PAYLOAD_V1_EV2_SCRYPT).unwrap();
    let password = PASSWORD1.to_owned();

    {
        // with no passphrase
        let passphrase = None;
        let store = SeedStore::new_from_payload(&payload, &password, passphrase).unwrap();
        assert_eq!(store.get_xpub().unwrap().to_string(), XPUB1);
    }
    {
        // with a passphrase
        let passphrase = Some(PASSPHRASE1);
        let store = SeedStore::new_from_payload(&payload, &password, passphrase).unwrap();
        assert_eq!(store.get_xpub().unwrap().to_string(), XPUB3);
    }
    {
        // with another passphrase
        let passphrase = Some("passphrase2");
        let store = SeedStore::new_from_payload(&payload, &password, passphrase).unwrap();
        assert_eq!(store.get_xpub().unwrap().to_string(), "xpub6D9q41qHBV9sjixixeA79ueUspGs5tiyfjkQhVtEhMUXLLXNT2d7LUUy8UbHB588GAUXSYwCi7ETXurtCFpvYNTtUGGyHUnch8DfgjetBUg");
    }
    {
        // with empty passphase is the same as without
        let passphrase = Some("");
        let store = SeedStore::new_from_payload(&payload, &password, passphrase).unwrap();
        assert_eq!(store.get_xpub().unwrap().to_string(), XPUB1);
    }
}

#[test]
fn passphrase_create_from_data() {
    let entropy = Vec::from_hex(ENTROPY_OIL12).unwrap();

    {
        // with no passphrase
        let passphrase = None;
        let store = SeedStoreCreator::new_from_data(&entropy, None, passphrase).unwrap();
        assert_eq!(store.get_xpub().unwrap().to_string(), XPUB1);
    }
    {
        // with a passphrase
        let passphrase = Some(PASSPHRASE1);
        let store = SeedStoreCreator::new_from_data(&entropy, None, passphrase).unwrap();
        assert_eq!(store.get_xpub().unwrap().to_string(), XPUB3);
    }
}
