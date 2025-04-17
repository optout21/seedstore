use hex_conservative::prelude::*;

const ENCRYPTION_KEY_LEN: usize = 32;
const ENCRYPT_KEY_HASH_MESSAGE: &str = "Secret Storage Key Prefix - could be anything";

pub(crate) type EncryptionKey = [u8; ENCRYPTION_KEY_LEN];

/// Trait for an actor that can encrypt and decrypt using a password.
pub(crate) trait Encryptor {
    /// Encrypt some data using an encryption password and salt, in-place.
    fn encrypt(
        unencrypted_data: &mut Vec<u8>,
        password: &str,
        salt: &Vec<u8>,
    ) -> Result<(), String>;

    /// Decrypt some encrypted data using an encryption password and salt, in-place.
    /// Caution: encrypted version is returned in copy
    fn decrypt(encrypted_data: &mut Vec<u8>, password: &str, salt: &Vec<u8>) -> Result<(), String>;
}

/// Encryptor/decryptor using bitwise XOR.
pub(crate) struct XorEncryptor {}

impl XorEncryptor {
    #[inline]
    pub(crate) fn encrypt_with_key(
        unencrypted_data: &mut Vec<u8>,
        encryption_key: &EncryptionKey,
    ) -> Result<(), String> {
        perform_xor(unencrypted_data, &encryption_key)
    }

    #[inline]
    pub(crate) fn decrypt_with_key(
        encrypted_data: &mut Vec<u8>,
        encryption_key: &EncryptionKey,
    ) -> Result<(), String> {
        perform_xor(encrypted_data, &encryption_key)
    }
}

impl Encryptor for XorEncryptor {
    fn encrypt(
        unencrypted_data: &mut Vec<u8>,
        password: &str,
        _salt: &Vec<u8>,
    ) -> Result<(), String> {
        let encryption_key = encryption_key_from_password(password)?;
        Self::encrypt_with_key(unencrypted_data, &encryption_key)
    }

    /// Decrypt some encrypted data using an encryption password and salt
    fn decrypt(
        encrypted_data: &mut Vec<u8>,
        password: &str,
        _salt: &Vec<u8>,
    ) -> Result<(), String> {
        let encryption_key = encryption_key_from_password(password)?;
        Self::decrypt_with_key(encrypted_data, &encryption_key)
    }
}

fn encryption_key_from_password(encryption_password: &str) -> Result<EncryptionKey, String> {
    let message = ENCRYPT_KEY_HASH_MESSAGE.to_string() + encryption_password;
    let encryption_key_str = sha256::digest(message);
    let encryption_key = EncryptionKey::from_hex(&encryption_key_str).map_err(|e| {
        format!(
            "Internal error: Could not parse hex hash digest string, {}",
            e
        )
    })?;
    Ok(encryption_key)
}

#[inline]
fn perform_xor(data: &mut Vec<u8>, key: &EncryptionKey) -> Result<(), String> {
    for i in 0..data.len() {
        data[i] = data[i] ^ key[i % ENCRYPTION_KEY_LEN];
    }
    Ok(())
}
