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

#[cfg(test)]
mod test {
    use super::{encryption_key_from_password, Encryptor, XorEncryptor};
    use hex_conservative::{DisplayHex, FromHex};

    const PASSWORD1: &str = "password";
    const DATA1: &str = "0102030405060708";
    const DATA1_ENC: &str = "db52a1e576359099";

    #[test]
    fn encrypt() {
        let mut data = Vec::from_hex(DATA1).unwrap();

        let _res = XorEncryptor::encrypt(&mut data, PASSWORD1, &Vec::new()).unwrap();
        assert_eq!(data.to_lower_hex_string(), DATA1_ENC);
    }

    #[test]
    fn decrypt() {
        let mut data = Vec::from_hex(DATA1_ENC).unwrap();

        let _res = XorEncryptor::decrypt(&mut data, PASSWORD1, &Vec::new()).unwrap();
        assert_eq!(data.to_lower_hex_string(), DATA1);
    }

    #[test]
    fn encrypt_key() {
        let encryption_key = encryption_key_from_password(PASSWORD1).unwrap();
        assert_eq!(
            encryption_key.to_lower_hex_string(),
            "da50a2e1733397910da44414d18bec51d7d0997a300085830ab8a6cfd1b13b50"
        );

        let mut data = Vec::from_hex(DATA1).unwrap();

        let _res = XorEncryptor::encrypt_with_key(&mut data, &encryption_key).unwrap();
        assert_eq!(data.to_lower_hex_string(), DATA1_ENC);
    }
}
