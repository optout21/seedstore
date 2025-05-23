use crate::encrypt_common::{EncryptionAuxData, Encryptor};
use bitcoin_hashes::Sha256d;
use rand_core::{OsRng, RngCore};

const ENCRYPTION_KEY_LEN: usize = 32;
pub(crate) const SALT_LEN: usize = 16;
const ENCRYPT_KEY_HASH_MESSAGE: &str = "Secret Storage Key Prefix || Fix the Money ||";

pub(crate) type EncryptionKey = [u8; ENCRYPTION_KEY_LEN];
pub(crate) type EncryptionSalt = [u8; SALT_LEN];

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
        aux_data: &EncryptionAuxData,
    ) -> Result<(), String> {
        if let EncryptionAuxData::V1Xor(salt) = aux_data {
            let encryption_key = encryption_key_from_password(password, salt)?;
            Self::encrypt_with_key(unencrypted_data, &encryption_key)
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
        if let EncryptionAuxData::V1Xor(salt) = aux_data {
            let encryption_key = encryption_key_from_password(password, salt)?;
            Self::decrypt_with_key(encrypted_data, &encryption_key)
        } else {
            Err("Invalid aux data type".to_owned())
        }
    }

    fn generate_aux_data() -> EncryptionAuxData {
        EncryptionAuxData::V1Xor(generate_salt())
    }
}

fn encryption_key_from_password(
    encryption_password: &str,
    salt: &[u8],
) -> Result<EncryptionKey, String> {
    if salt.len() != SALT_LEN {
        return Err(format!("Invalid salt len {}", salt.len()));
    }

    let mut to_hash: Vec<u8> = Vec::with_capacity(256);
    to_hash.extend(ENCRYPT_KEY_HASH_MESSAGE.to_string().as_bytes());
    to_hash.extend(encryption_password.as_bytes());
    to_hash.extend(salt);

    let encryption_key = Sha256d::hash(&to_hash).to_byte_array().into();

    Ok(encryption_key)
}

#[inline]
fn perform_xor(data: &mut Vec<u8>, key: &EncryptionKey) -> Result<(), String> {
    for i in 0..data.len() {
        data[i] = data[i] ^ key[i % ENCRYPTION_KEY_LEN];
    }
    Ok(())
}

/// Generate a random 16-byte salt
fn generate_salt() -> EncryptionSalt {
    let mut salt = EncryptionSalt::default();
    let _res = OsRng.fill_bytes(&mut salt);
    salt
}

pub(crate) fn generate_key() -> EncryptionKey {
    let mut key = EncryptionKey::default();
    let _res = OsRng.fill_bytes(&mut key);
    key
}

#[cfg(test)]
mod test {
    use super::{encryption_key_from_password, Encryptor, XorEncryptor};
    use crate::{encrypt_chacha::EncryptionSalt, encrypt_common::EncryptionAuxData};
    use hex_conservative::{DisplayHex, FromHex};

    const PASSWORD1: &str = "password";
    const SALT1: &str = "deadbeef000000000000000000000000";
    const DATA1: &str = "0102030405060708";
    const DATA1_ENC: &str = "2d5c3c536f813ea9";

    #[test]
    fn encrypt() {
        let salt = EncryptionSalt::from_hex(SALT1).unwrap();
        let mut data = Vec::from_hex(DATA1).unwrap();
        let aux_data = EncryptionAuxData::V1Xor(salt);

        let _res = XorEncryptor::encrypt(&mut data, PASSWORD1, &aux_data).unwrap();
        assert_eq!(data.to_lower_hex_string(), DATA1_ENC);
    }

    #[test]
    fn decrypt() {
        let salt = EncryptionSalt::from_hex(SALT1).unwrap();
        let mut data = Vec::from_hex(DATA1_ENC).unwrap();
        let aux_data = EncryptionAuxData::V1Xor(salt);

        let _res = XorEncryptor::decrypt(&mut data, PASSWORD1, &aux_data).unwrap();
        assert_eq!(data.to_lower_hex_string(), DATA1);
    }

    #[test]
    fn encrypt_key() {
        let salt = Vec::from_hex(SALT1).unwrap();
        let encryption_key = encryption_key_from_password(PASSWORD1, &salt).unwrap();
        assert_eq!(
            encryption_key.to_lower_hex_string(),
            "2c5e3f576a8739a1d6bf1a370dc74d67430bc137a7526adedba63007d9c4bb50"
        );

        let mut data = Vec::from_hex(DATA1).unwrap();

        let _res = XorEncryptor::encrypt_with_key(&mut data, &encryption_key).unwrap();
        assert_eq!(data.to_lower_hex_string(), DATA1_ENC);
    }
}
