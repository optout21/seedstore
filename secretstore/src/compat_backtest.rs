// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the  MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// You may not use this file except in accordance with the license.

//! Data format Backward-Compatibility tests.
//! Ensure that supported data stays supported in later versions,
//! even though it may not be created exactly the same way by later versions
//! (e.g. due to different defaults),
//! or may not be created at all, but it can be read.
//! The reading of secret files created by older versions should be supported.

use crate::SecretStore;
use hex_conservative::{DisplayHex, FromHex};

const PASSWORD1: &str = "password";
const NONSECRET_DATA1: &str = "010203";
const SECRET_DATA1: &str = "0102030405060708";

#[test]
fn backward_compatibility_tests() {
    // Test data for multiple tests
    let test_data = [
        (
            1,
            1,
            "5353010301020301f6ecb1e25f4945ae0605638d75c6a34208006e59b27ff2c90dd87c320627",
            PASSWORD1,
            SECRET_DATA1,
            NONSECRET_DATA1,
        ),
        (
            1,
            2,
            "53530103010203020e24799f2ebaf27d4cd517136dd57ad71b0800b44fe9ca543c2f4dd8349e1b",
            PASSWORD1,
            SECRET_DATA1,
            NONSECRET_DATA1,
        ),
        (
            1,
            3,
            "53530103010203030db42435f1ff810be24030aee961eb14528c7bb8303431d947b0f5a7e5a0b5648b9c481fd4e1cfad7918007525accb0b6e1b4a66683e6d1264dac8ecda5ba82cdbcbadccd5cd05",
            PASSWORD1,
            SECRET_DATA1,
            NONSECRET_DATA1,
        ),
    ];

    for test_data1 in test_data.iter() {
        let (
            format_version,
            encryption_version,
            payload_hex,
            password,
            expected_unencrypted_secret_hex,
            expected_nonsecret_hex,
        ) = &test_data1;
        println!("Test: fv{} ev{}", format_version, encryption_version);
        test_create_from_data_parse_verify(
            &payload_hex,
            &password,
            &expected_unencrypted_secret_hex,
            &expected_nonsecret_hex,
        );
    }
}

fn test_create_from_data_parse_verify(
    payload_hex: &str,
    password: &str,
    expected_unencrypted_secret_hex: &str,
    expected_nonsecret_hex: &str,
) {
    let payload = <Vec<u8>>::from_hex(payload_hex).unwrap();
    let store = SecretStore::new_from_payload(&payload, password).unwrap();
    let actual_unencrypted_hex = store.secret_data().unwrap().to_lower_hex_string();
    assert_eq!(
        actual_unencrypted_hex, expected_unencrypted_secret_hex,
        "Mismatch in secret data!"
    );
    let actual_nonsecret_hex = store.nonsecret_data().to_lower_hex_string();
    assert_eq!(
        actual_nonsecret_hex, expected_nonsecret_hex,
        "Mismatch in nonsecret data!"
    );
}
