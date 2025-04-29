// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the  MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// You may not use this file except in accordance with the license.

use crate::encrypt_common::{EncryptionAuxData, Encryptor};
use rand_core::{OsRng, RngCore};

const ENCRYPTION_KEY_LEN: usize = 32;
type EncryptionKey = [u8; ENCRYPTION_KEY_LEN];
pub(crate) const SALT_LEN: usize = 16;
pub(crate) type EncryptionSalt = [u8; SALT_LEN];

/// Encryptor/decryptor using XChaCha20-Poly1305
/// See https://en.wikipedia.org/wiki/ChaCha20-Poly1305
pub(crate) struct ScryptEncryptor {}

/// Encrypt data using the password, and the provided rounds, and salt, in-place.
/// It is recommend to zeroize() the password after use.
/// Return: encrypted data
fn encrypt_data(
    data: &mut Vec<u8>,
    password: &str,
    log2_rounds: u8,
    salt: &EncryptionSalt,
) -> Result<(), String> {
    let encryption_key = password_to_key(password, &salt, log2_rounds)?;

    perform_xor(data, &encryption_key)
}

#[inline]
fn perform_xor(data: &mut Vec<u8>, key: &EncryptionKey) -> Result<(), String> {
    for i in 0..data.len() {
        data[i] = data[i] ^ key[i % ENCRYPTION_KEY_LEN];
    }
    Ok(())
}

#[cfg(test)]
fn encrypt_data_generated(
    data: &mut Vec<u8>,
    password: &str,
) -> Result<(u8, EncryptionSalt), String> {
    let rounds = default_log2_rounds();
    let salt = generate_salt();
    let _res = encrypt_data(data, password, rounds, &salt)?;
    Ok((rounds, salt))
}

fn default_log2_rounds() -> u8 {
    14
}

/// Generate a random 16-byte salt
fn generate_salt() -> EncryptionSalt {
    let mut salt = EncryptionSalt::default();
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Decrypt a key encrypted using [`encrypt_data`], in-place.
/// It is recommend to zeroize() the password after use.
fn decrypt_data(
    log2_rounds: u8,
    salt: &EncryptionSalt,
    encrypted_data: &mut Vec<u8>,
    password: &str,
) -> Result<(), String> {
    let key = password_to_key(password, &salt, log2_rounds)?;

    perform_xor(encrypted_data, &key)
}

// Hash/Stretch password with scrypt into a 32-byte (256-bit) key
fn password_to_key(
    password: &str,
    salt: &EncryptionSalt,
    log_n: u8,
) -> Result<EncryptionKey, String> {
    let params = scrypt::Params::new(log_n, 8, 1, ENCRYPTION_KEY_LEN)
        .map_err(|e| format!("Password key error, {}", e))?;
    let mut key = EncryptionKey::default();
    if scrypt::scrypt(password.as_bytes(), salt, &params, &mut key).is_err() {
        return Err(format!("Password key error"));
    }
    Ok(key)
}

impl Encryptor for ScryptEncryptor {
    fn encrypt(
        unencrypted_data: &mut Vec<u8>,
        password: &str,
        aux_data: &EncryptionAuxData,
    ) -> Result<(), String> {
        if let EncryptionAuxData::V2Scrypt((rounds, salt)) = aux_data {
            let _res = encrypt_data(unencrypted_data, password, *rounds, salt)?;
            Ok(())
        } else {
            Err("Invalid aux data type".to_owned())
        }
    }

    fn decrypt(
        encrypted_data: &mut Vec<u8>,
        password: &str,
        aux_data: &EncryptionAuxData,
    ) -> Result<(), String> {
        if let EncryptionAuxData::V2Scrypt((rounds, salt)) = aux_data {
            let _res = decrypt_data(*rounds, salt, encrypted_data, password)?;
            Ok(())
        } else {
            Err("Invalid aux data type".to_owned())
        }
    }

    fn generate_aux_data() -> EncryptionAuxData {
        let rounds = default_log2_rounds();
        let salt = generate_salt();
        EncryptionAuxData::V2Scrypt((rounds, salt))
    }
}

#[cfg(test)]
mod test {
    use super::{decrypt_data, encrypt_data_generated, EncryptionSalt};
    use hex_conservative::{DisplayHex, FromHex};

    const PASSWORD1: &str = "password";
    const SALT1: &str = "be856097a4f91e9a1951764973613172";
    const DATA1: &str = "0102030405060708";
    const DATA1_ENC: &str = "6120c087a74e51f3";

    #[test]
    fn test_encrypt_and_decrypt() {
        let mut data = Vec::from_hex(DATA1).unwrap();
        let password = PASSWORD1.to_owned();

        let (rounds, salt) = encrypt_data_generated(&mut data, &password).unwrap();

        let _res = decrypt_data(rounds, &salt, &mut data, &password).unwrap();

        assert_eq!(data.to_lower_hex_string(), DATA1);
    }

    #[test]
    fn test_encrypt() {
        let mut data = Vec::from_hex(DATA1).unwrap();
        let password = PASSWORD1.to_owned();

        let (rounds, _salt) = encrypt_data_generated(&mut data, &password).unwrap();

        // println!("encrypted {}", data.to_lower_hex_string());
        // println!("salt {}", salt.to_lower_hex_string());

        assert_eq!(rounds, 14);
        // Encrypted data is variable, cannot assert
        assert_eq!(data.len(), 8);
    }

    #[test]
    fn test_decrypt() {
        let mut data = Vec::from_hex(DATA1_ENC).unwrap();
        let salt = EncryptionSalt::from_hex(SALT1).unwrap();
        let password = PASSWORD1.to_owned();

        let _res = decrypt_data(14, &salt, &mut data, &password).unwrap();
        assert_eq!(data.to_lower_hex_string(), DATA1);
    }
}
