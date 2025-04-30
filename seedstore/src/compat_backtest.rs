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

use crate::SeedStore;
use hex_conservative::FromHex;

const PASSWORD1: &str = "password";
const PASSPHRASE1: &str = "this_is_a_secret_passphrase";
const XPUB1: &str = "xpub6CDDB17Xj7pDDWedpLsED1JbPPQmyuapHmAzQEEs2P57hciCjwQ3ov7TfGsTZftAM2gVdPzE55L6gUvHguwWjY82518zw1Z3VbDeWgx3Jqs";
const XPUB2: &str = "xpub6CVT9PXjALUVjoa3t1kgq3fAiUoGYeothP8sZSstrJ6d2nJXy4ajmtCPgE59Xyw9LkHtf9TznxA8BhPu5d33JycXxRwToufe6zWoU6icLbJ";

#[test]
fn backward_compatibility_tests() {
    // Test data for multiple tests
    let test_data = [
        (
            1,
            1,
            "53530104002a2b2c01134a7bef7fd0b5704d7b44122dd634d210001662e6ef23b24a283f236315d8572c057fb8254d",
            PASSWORD1,
            "",
            XPUB1
        ),
        (
            1,
            2,
            "53530104002a2b2c020ee3d3970706fbe9f680eb68763af3c849100010907fc4f2740c7613422df300488137c1e6af59",
            PASSWORD1,
            "",
            XPUB1
        ),
        (
            1,
            2,
            "53530104002a2b2c020ee3d3970706fbe9f680eb68763af3c849100010907fc4f2740c7613422df300488137c1e6af59",
            PASSWORD1,
            PASSPHRASE1,
            XPUB2
        ),
        (
            1,
            2,
            "53530104002a2b2c020e650e2a5f62dc8902054924c371095cce10005bc1e8c728cc0dde549b01f75d1630e3a63721b2",
            PASSWORD1,
            "",
            XPUB1
        ),
        (
            1,
            3,
            "53530104002a2b2c030d6a14b96b3dc98ad33c2dc35966f1d019ae236ce28b8f003388bd0c6f6d6fa18c1ff12521a46bd2e52000e8b03820e69c000daddc7dbcf76a6a0137097893246d83033a6249cd89a21e3a3f8e8626",
            PASSWORD1,
            "",
            XPUB1
        ),
    ];

    for test_data1 in test_data.iter() {
        let (
            format_version,
            encryption_version,
            payload_hex,
            encryption_password,
            optional_seed_password,
            expected_xpub_hex,
        ) = &test_data1;
        println!("Test: fv{} ev{}", format_version, encryption_version);
        test_create_from_data_parse_verify(
            &payload_hex,
            &encryption_password,
            &optional_seed_password,
            &expected_xpub_hex,
        );
    }
}

fn test_create_from_data_parse_verify(
    payload_hex: &str,
    encryption_password: &str,
    optional_seed_password: &str,
    expected_xpub_hex: &str,
) {
    let payload = <Vec<u8>>::from_hex(payload_hex).unwrap();
    let store =
        SeedStore::new_from_payload(&payload, encryption_password, Some(optional_seed_password))
            .unwrap();
    let actual_xpub_hex = store.get_xpub().unwrap().to_string();
    assert_eq!(
        actual_xpub_hex, expected_xpub_hex,
        "Mismatch in retrieved XPub!"
    );
}
