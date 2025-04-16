use crate::{SeedStore, SeedStoreCreator};
use hex_conservative::prelude::*;
use rand::Rng;
use std::env::temp_dir;
use std::fs;

const PASSWORD1: &str = "password";
const PASSWORD2: &str = "This is a different password, ain't it?";
const ENTROPY_OIL12: &str = "99d33a674ce99d33a674ce99d33a674c";
const PAYLOAD1: &str = "02000e10438398863fda0aa2abd08a8d02b18b1d20a38850";
const XPUB1: &str = "xpub6CDDB17Xj7pDDWedpLsED1JbPPQmyuapHmAzQEEs2P57hciCjwQ3ov7TfGsTZftAM2gVdPzE55L6gUvHguwWjY82518zw1Z3VbDeWgx3Jqs";
const XPUB2: &str = "tpubDCRo9GmRAvEWANJ5iSfMEqPoq3uYvjBPAAjrDj5iQMxAq7DCs5orw7m9xJes8hWYAwKuH3T63WrKfzzw7g9ucbjq4LUu5cgCLUPMN7gUkrL";

#[test]
fn create_from_data() {
    let network = 0u8;
    let entropy = Vec::from_hex(ENTROPY_OIL12).unwrap();
    let store = SeedStoreCreator::new_from_data(network, &entropy).unwrap();

    assert_eq!(store.network(), 0);
    assert_eq!(store.get_xpub().unwrap().to_string(), XPUB1);
    assert_eq!(
        store.get_child_public_key(&entropy, 0).unwrap().to_string(),
        "032814221178177cb5ac81ae0ffa3be2e3c936503d6927050af739a41311f3821e"
    );
    assert_eq!(
        store.get_child_public_key(&entropy, 1).unwrap().to_string(),
        "033107250a6f0a7acf9c33436c43310467d69c858f1cf8c7a5ddc5283ae53d44c8"
    );
}

#[test]
fn create_from_data_net3() {
    let network = 3u8;
    let entropy = Vec::from_hex(ENTROPY_OIL12).unwrap();
    let store = SeedStoreCreator::new_from_data(network, &entropy).unwrap();

    assert_eq!(store.network(), 3);
    assert_eq!(store.get_xpub().unwrap().to_string(), XPUB2);
}

#[test]
fn create_from_payload_const() {
    let payload = Vec::from_hex(PAYLOAD1).unwrap();
    let password = PASSWORD1.to_owned();

    let store = SeedStore::new_from_payload(&payload, &password).unwrap();

    assert_eq!(store.network(), 0);
    assert_eq!(store.get_xpub().unwrap().to_string(), XPUB1);
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
    let store = SeedStoreCreator::new_from_data(network, &entropy).unwrap();

    let temp_file = get_temp_file_name();
    let password = PASSWORD1.to_owned();
    let _res = store.write_to_file(&temp_file, &password).unwrap();

    // check the file
    let contents = fs::read(temp_file).unwrap();
    assert_eq!(contents.to_lower_hex_string(), PAYLOAD1);
}

#[test]
fn read_from_file() {
    let temp_file = get_temp_file_name();

    // write constant payload to file
    let payload = Vec::from_hex(PAYLOAD1).unwrap();
    let _res = fs::write(&temp_file, &payload).unwrap();

    let password = PASSWORD1.to_owned();
    let store = SeedStore::new_from_encrypted_file(&temp_file, &password).unwrap();

    assert_eq!(store.network(), 0);
    assert_eq!(store.get_xpub().unwrap().to_string(), XPUB1);
}

#[test]
fn neg_read_from_file_diff_pw_invalid_checksum() {
    let temp_file = get_temp_file_name();

    // write constant payload to file
    let payload = Vec::from_hex(PAYLOAD1).unwrap();
    let _res = fs::write(&temp_file, &payload).unwrap();

    let password = PASSWORD2.to_owned();
    let res = SeedStore::new_from_encrypted_file(&temp_file, &password);
    debug_assert_eq!(res.err().unwrap(), "Invalid checksum, 14 vs 12");
}
