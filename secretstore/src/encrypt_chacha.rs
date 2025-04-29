use crate::encrypt_common::{EncryptionAuxData, Encryptor};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, Payload},
    XChaCha20Poly1305,
};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

const ENCRYPTION_KEY_LEN: usize = 32;
type EncryptionKey = [u8; ENCRYPTION_KEY_LEN];
pub(crate) const SALT_LEN: usize = 16;
pub(crate) type EncryptionSalt = [u8; SALT_LEN];
pub(crate) const NONCE_LEN: usize = 24;
pub(crate) type EncryptionNonce = [u8; NONCE_LEN];
const ASSOCIATED_DATA_1: u8 = 83;

/// Encryptor/decryptor using XChaCha20-Poly1305
/// See https://en.wikipedia.org/wiki/ChaCha20-Poly1305
pub(crate) struct ChaChaEncryptor {}

/// Encrypt data using the password, and the provided rounds, salt and nonce.
/// It is recommend to zeroize() the password after use.
/// Return: rounds, salt, nonce, encrypted data
fn encrypt_data(
    data: &Vec<u8>,
    password: &str,
    log2_rounds: u8,
    salt: &EncryptionSalt,
    nonce: &EncryptionNonce,
) -> Result<Vec<u8>, String> {
    let associated_data: Vec<u8> = vec![ASSOCIATED_DATA_1];

    let ciphertext = {
        let cipher = {
            let symmetric_key = password_to_key(password, &salt, log2_rounds)?;
            XChaCha20Poly1305::new((&symmetric_key).into())
        };

        // The inner secret. We don't have to drop this because we are encrypting-in-place
        let mut inner_secret: Vec<u8> = data.clone();

        let payload = Payload {
            msg: &inner_secret,
            aad: &associated_data,
        };

        let ciphertext = cipher
            .encrypt(nonce.into(), payload)
            .map_err(|e| format!("Encryption error {}", e.to_string()))?;

        inner_secret.zeroize();

        ciphertext
    };

    Ok(ciphertext)
}

#[cfg(test)]
fn encrypt_data_generated(
    data: &Vec<u8>,
    password: &str,
) -> Result<(u8, EncryptionSalt, EncryptionNonce, Vec<u8>), String> {
    let rounds = default_log2_rounds();
    let salt = generate_salt();
    let nonce = generate_nonce();
    let encrypted = encrypt_data(data, password, rounds, &salt, &nonce)?;
    Ok((rounds, salt, nonce, encrypted))
}

fn default_log2_rounds() -> u8 {
    13
}

/// Generate a random 16-byte salt
fn generate_salt() -> EncryptionSalt {
    let mut salt = EncryptionSalt::default();
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generate a random 24-byte nonce
fn generate_nonce() -> EncryptionNonce {
    XChaCha20Poly1305::generate_nonce(&mut OsRng).into()
}

/// Decrypt a key encrypted using [`encrypt_data`]
/// It is recommend to zeroize() the password after use.
fn decrypt_data(
    log2_rounds: u8,
    salt: &EncryptionSalt,
    nonce: &EncryptionNonce,
    encrypted_data: &Vec<u8>,
    password: &str,
) -> Result<Vec<u8>, String> {
    let cipher = {
        let symmetric_key = password_to_key(password, &salt, log2_rounds)?;
        XChaCha20Poly1305::new((&symmetric_key).into())
    };

    let associated_data: Vec<u8> = vec![ASSOCIATED_DATA_1];

    let payload = Payload {
        msg: &encrypted_data,
        aad: &associated_data,
    };

    let inner_secret = cipher
        .decrypt(nonce.into(), payload)
        .map_err(|e| format!("Decryption error {}", e))?;

    Ok(inner_secret)
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

impl Encryptor for ChaChaEncryptor {
    fn encrypt(
        unencrypted_data: &mut Vec<u8>,
        password: &str,
        aux_data: &EncryptionAuxData,
    ) -> Result<(), String> {
        if let EncryptionAuxData::V3ChaCha((rounds, salt, nonce)) = aux_data {
            let encrypted = encrypt_data(&unencrypted_data, password, *rounds, salt, nonce)?;
            *unencrypted_data = encrypted;
            Ok(())
        } else {
            Err("Invalid aux data type".to_owned())
        }
    }

    /// Decrypt some encrypted data using an encryption password and salt
    fn decrypt(
        encrypted_data: &mut Vec<u8>,
        password: &str,
        aux_data: &EncryptionAuxData,
    ) -> Result<(), String> {
        if let EncryptionAuxData::V3ChaCha((rounds, salt, nonce)) = aux_data {
            let decrypted = decrypt_data(*rounds, salt, nonce, &encrypted_data, password)?;
            *encrypted_data = decrypted;
            Ok(())
        } else {
            Err("Invalid aux data type".to_owned())
        }
    }

    fn generate_aux_data() -> EncryptionAuxData {
        let rounds = default_log2_rounds();
        let salt = generate_salt();
        let nonce = generate_nonce();
        EncryptionAuxData::V3ChaCha((rounds, salt, nonce))
    }
}

#[cfg(test)]
mod test {
    use crate::encrypt_chacha::{
        decrypt_data, encrypt_data_generated, EncryptionNonce, EncryptionSalt,
    };
    use hex_conservative::{DisplayHex, FromHex};

    const PASSWORD1: &str = "password";
    const SALT1: &str = "4275b539ae966e24c14085897e9253fa";
    const NONCE1: &str = "09c51efd6c8f0cf1c555bdc0ea33895624bd15e790f1df88";
    const DATA1: &str = "0102030405060708";
    const DATA1_ENC: &str = "e1f87aa217d7947c63da82686deb5e4f151e6e8d1180d78e";

    #[test]
    fn test_encrypt_and_decrypt() {
        let data = Vec::from_hex(DATA1).unwrap();
        let password = PASSWORD1.to_owned();

        let (rounds, salt, nonce, encrypted) = encrypt_data_generated(&data, &password).unwrap();

        let decrypted = decrypt_data(rounds, &salt, &nonce, &encrypted, &password).unwrap();

        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_encrypt() {
        let data = Vec::from_hex(DATA1).unwrap();
        let password = PASSWORD1.to_owned();

        let (rounds, _salt, _nonce, encrypted) = encrypt_data_generated(&data, &password).unwrap();

        // println!("encrypted {}", encrypted.to_lower_hex_string());
        // println!("salt {}", salt.to_lower_hex_string());
        // println!("nonce {}", nonce.to_lower_hex_string());

        assert_eq!(rounds, 13);
        // Encrypted data is variable, cannot assert
        assert_eq!(encrypted.len(), 24);
    }

    #[test]
    fn test_decrypt() {
        let data = Vec::from_hex(DATA1_ENC).unwrap();
        let salt = EncryptionSalt::from_hex(SALT1).unwrap();
        let nonce = EncryptionNonce::from_hex(NONCE1).unwrap();
        let password = PASSWORD1.to_owned();

        let decrypted = decrypt_data(13, &salt, &nonce, &data, &password).unwrap();
        assert_eq!(decrypted.to_lower_hex_string(), DATA1);
    }
}
