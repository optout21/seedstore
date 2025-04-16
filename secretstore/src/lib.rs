#[cfg(test)]
mod test_lib;

use hex_conservative::prelude::*;
use rand::Rng;
use std::fs;

const MAGIC_BYTE: u8 = 'S' as u8; // dec 83 hex 53
const SECRET_DATA_MAXLEN: usize = 256;
const SECRET_DATA_MINLEN: usize = 1;
const NONSECRET_DATA_MAXLEN: usize = 255;
const ENCRYPTION_KEY_LEN: usize = 32;
const CHECKSUM_LEN: usize = 4;
const ENCRYPT_KEY_HASH_MESSAGE: &str = "Secret Storage Key Prefix - could be anything";

type SecretData = [u8; SECRET_DATA_MAXLEN];
pub type EncryptionPassword = String;
type EncryptionKey = [u8; ENCRYPTION_KEY_LEN];

/// Store a secret data in an encrypred file.
/// Also store some nonsecret data.
/// Read them, store the secret encrypted with an ephemeral key.
/// Secret data length can be between 1 and 256 bytes.
/// Secret data is stored in a fixed byte array, to avoid allocations.
/// A checksum is also stored, for the whole data.
/// The encrypted part has no checksum, because if it had, it would be possible
/// to check if a password decrypts it or not, which helps brute forcing.
pub struct SecretStore {
    /// Secret data, encrypted with the ephemeral key, stored on fixed len
    encrypted_secret_data: SecretData,
    /// The length of the encrypted secret data minus 1
    encrypted_secret_data_len_m1: u8,
    nonsecret_data: Vec<u8>,
    ephemeral_encryption_key: EncryptionKey,
}

/// Helper class for creating the store from given data.
/// Should be used only by the utility that creates the encrypted file.
pub struct SecretStoreCreator {}

impl SecretStore {
    pub fn new_from_encrypted_file(
        path_for_secret_file: &str,
        encryption_password: &String,
    ) -> Result<Self, String> {
        let secret_payload = read_payload_from_file(path_for_secret_file)?;
        Self::new_from_payload(&secret_payload, encryption_password)
    }

    pub fn new_from_payload(
        secret_payload: &Vec<u8>,
        encryption_password: &String,
    ) -> Result<Self, String> {
        let (nonsecret_data, encrypted_secret_data) = parse_payload(&secret_payload)?;
        let ephemeral_encryption_key = Self::generate_ephemeral_key();
        let (encrypted_secret_data, encrypted_secret_data_len_m1) = recrypt_secret_data_with_key(
            &encrypted_secret_data,
            encryption_password,
            &ephemeral_encryption_key,
        )?;
        Ok(Self {
            encrypted_secret_data,
            encrypted_secret_data_len_m1,
            nonsecret_data,
            ephemeral_encryption_key,
        })
    }

    pub fn nonsecret_data(&self) -> &Vec<u8> {
        &self.nonsecret_data
    }

    #[cfg(test)]
    fn secret_data(&self) -> Result<Vec<u8>, String> {
        let decrypted = decrypt_secret(
            &self.encrypted_secret_data,
            self.encrypted_secret_data_len_m1,
            &self.ephemeral_encryption_key,
        )?;
        Ok(decrypted)
    }

    pub fn processed_secret_data<F, R>(&self, f: F) -> Result<R, String>
    where
        F: Fn(&Vec<u8>) -> Result<R, String>,
    {
        let decrypted = decrypt_secret(
            &self.encrypted_secret_data,
            self.encrypted_secret_data_len_m1,
            &self.ephemeral_encryption_key,
        )?;
        let res = f(&decrypted)?;
        Ok(res)
    }

    pub fn write_to_file(
        &self,
        path_for_secret_file: &str,
        encryption_password: &EncryptionPassword,
    ) -> Result<(), String> {
        let payload = self.assemble_payload(encryption_password)?;
        let _res = fs::write(path_for_secret_file, payload).map_err(|e| {
            format!(
                "Error writing to file {}, {}",
                path_for_secret_file,
                e.to_string()
            )
        })?;
        Ok(())
    }

    pub fn assemble_payload(
        &self,
        encryption_password: &EncryptionPassword,
    ) -> Result<Vec<u8>, String> {
        let reencrypted = recrypt_secret_data_with_pw(
            &self.encrypted_secret_data,
            self.encrypted_secret_data_len_m1,
            &self.ephemeral_encryption_key,
            encryption_password,
        )?;
        let len = (self.encrypted_secret_data_len_m1 as usize) + 1;
        assemble_payload(&self.nonsecret_data, &reencrypted[0..len].to_vec())
    }

    fn generate_ephemeral_key() -> EncryptionKey {
        let mut rng = rand::rng();
        let key: EncryptionKey = rng.random();
        key
    }
}

impl SecretStoreCreator {
    pub fn new_from_data(
        nonsecret_data: Vec<u8>,
        secret_data: &Vec<u8>,
    ) -> Result<SecretStore, String> {
        if nonsecret_data.len() > NONSECRET_DATA_MAXLEN {
            return Err(format!(
                "Non-secret data too long, {} vs {}",
                nonsecret_data.len(),
                NONSECRET_DATA_MAXLEN
            ));
        }
        if secret_data.len() > SECRET_DATA_MAXLEN {
            return Err(format!(
                "Secret data too long, {} vs {}",
                secret_data.len(),
                SECRET_DATA_MAXLEN
            ));
        }
        if secret_data.len() < SECRET_DATA_MINLEN {
            return Err(format!(
                "Secret data too short, {} vs {}",
                secret_data.len(),
                SECRET_DATA_MINLEN
            ));
        }
        let ephemeral_encryption_key = SecretStore::generate_ephemeral_key();
        let (encrypted_secret_data, encrypted_secret_data_len_m1) =
            encrypt_secret(secret_data, &ephemeral_encryption_key)?;
        Ok(SecretStore {
            encrypted_secret_data,
            encrypted_secret_data_len_m1,
            nonsecret_data,
            ephemeral_encryption_key,
        })
    }
}

fn read_payload_from_file(path_for_secret_file: &str) -> Result<Vec<u8>, String> {
    let contents = fs::read(path_for_secret_file).map_err(|e| {
        format!(
            "Could not read file '{}', {}",
            path_for_secret_file,
            e.to_string()
        )
    })?;
    Ok(contents)
}

fn parse_payload(payload: &Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut pos: usize = 0;
    let magic_byte = *payload
        .get(pos)
        .ok_or(format!("File content is too short, {}", pos))?;
    if magic_byte != MAGIC_BYTE {
        return Err(format!(
            "Wrong magic byte ({}), check the secret file!",
            magic_byte
        ));
    }
    pos += 1;
    let unencrypted_len = *payload
        .get(pos)
        .ok_or(format!("File content is too short, {}", pos))? as usize;
    pos += 1;
    if payload.len() < pos + unencrypted_len {
        return Err(format!(
            "File content is too short, {} vs {}",
            payload.len(),
            pos + unencrypted_len
        ));
    }
    let nonsecret_data = payload[pos..pos + unencrypted_len].to_vec();
    pos += unencrypted_len;
    let encrypted_len = *payload
        .get(pos)
        .ok_or(format!("File content is too short, {}", pos))? as usize;
    pos += 1;
    if payload.len() < pos + encrypted_len {
        return Err(format!(
            "File content is too short, {} vs {}",
            payload.len(),
            pos + encrypted_len
        ));
    }
    let encrypted_secret_data = payload[pos..pos + encrypted_len].to_vec();
    pos += encrypted_len;
    if payload.len() < pos + CHECKSUM_LEN {
        return Err(format!(
            "File content is too short, {} vs {}",
            payload.len(),
            pos + CHECKSUM_LEN
        ));
    }
    let checksum_parsed = payload[pos..pos + CHECKSUM_LEN].to_vec();
    // Compute and check checksum
    let checksum_computed = checksum_of_payload(&payload[0..pos]);
    if checksum_parsed != checksum_computed {
        return Err(format!("Checksum mismatch, check the secret file!"));
    }
    pos += CHECKSUM_LEN;

    // Final check, for too long
    if payload.len() != pos {
        return Err(format!(
            "File content is too long, {} vs {}",
            payload.len(),
            pos
        ));
    }

    Ok((nonsecret_data, encrypted_secret_data))
}

fn assemble_payload(
    nonsecret_data: &Vec<u8>,
    encrypted_secre_data: &Vec<u8>,
) -> Result<Vec<u8>, String> {
    let mut o = Vec::new();
    o.push(MAGIC_BYTE);
    o.push(nonsecret_data.len() as u8); // TODO check
    o.extend(nonsecret_data);
    o.push(encrypted_secre_data.len() as u8); // TODO check
    o.extend(encrypted_secre_data);
    // compute and add checksum
    let checksum = checksum_of_payload(&o);
    o.extend(&checksum);
    Ok(o)
}

fn decrypt_xor(data: &mut SecretData, data_len_m1: u8, key: &EncryptionKey) -> Result<(), String> {
    for i in 0..(data_len_m1 as usize + 1) {
        data[i] = data[i] ^ key[i % ENCRYPTION_KEY_LEN];
    }
    Ok(())
}

fn encryption_key_from_password(
    encryption_password: &EncryptionPassword,
) -> Result<EncryptionKey, String> {
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

/// Use with caution!
fn decrypt_secret(
    encrypted: &SecretData,
    encrypted_len_m1: u8,
    encryption_key: &EncryptionKey,
) -> Result<Vec<u8>, String> {
    let mut buffer = encrypted.clone();
    let _res = decrypt_xor(&mut buffer, encrypted_len_m1, &encryption_key)?;
    let mut res = Vec::new();
    let len = (encrypted_len_m1 as usize) + 1;
    for i in 0..len {
        res.push(buffer[i]);
    }
    Ok(res)
}

fn encrypt_secret(
    unencrypted: &Vec<u8>,
    encryption_key: &EncryptionKey,
) -> Result<(SecretData, u8), String> {
    let len = unencrypted.len();
    if len > SECRET_DATA_MAXLEN {
        return Err(format!(
            "Data too long, {} vs {}",
            unencrypted.len(),
            SECRET_DATA_MAXLEN
        ));
    }
    debug_assert!(len <= SECRET_DATA_MAXLEN);
    let mut buffer = [0; SECRET_DATA_MAXLEN];
    for i in 0..len {
        buffer[i] = unencrypted[i];
    }
    // Encrypt using the encryption password
    let len_m1 = (len - 1) as u8;
    let _res = decrypt_xor(&mut buffer, len_m1, &encryption_key)?;
    Ok((buffer, len_m1))
}

fn recrypt_secret_data_key_key(
    unencrypted: &mut SecretData,
    unencrypted_len_m1: u8,
    decryption_key: &EncryptionKey,
    encryption_key: &EncryptionKey,
) -> Result<(), String> {
    let _res = decrypt_xor(unencrypted, unencrypted_len_m1, decryption_key)?;
    let _res = decrypt_xor(unencrypted, unencrypted_len_m1, encryption_key)?;
    Ok(())
}

fn recrypt_secret_data_with_key(
    unencrypted: &Vec<u8>,
    decryption_password: &EncryptionPassword,
    encryption_key: &EncryptionKey,
) -> Result<(SecretData, u8), String> {
    let mut buffer: SecretData = [0; SECRET_DATA_MAXLEN];
    if unencrypted.len() > SECRET_DATA_MAXLEN {
        return Err(format!(
            "Data too long, {} vs {}",
            unencrypted.len(),
            SECRET_DATA_MAXLEN
        ));
    }
    debug_assert!(unencrypted.len() <= SECRET_DATA_MAXLEN);
    let len_m1 = std::cmp::min(
        (unencrypted.len() - 1) as u8,
        (SECRET_DATA_MAXLEN - 1) as u8,
    );
    for i in 0..(len_m1 as usize + 1) {
        buffer[i] = unencrypted[i];
    }
    let decryption_key = encryption_key_from_password(decryption_password)?;
    let _res = recrypt_secret_data_key_key(&mut buffer, len_m1, &decryption_key, encryption_key)?;
    Ok((buffer, len_m1))
}

fn recrypt_secret_data_with_pw(
    unencrypted: &SecretData,
    unencrypted_len_m1: u8,
    decryption_key: &EncryptionKey,
    encryption_password: &EncryptionPassword,
) -> Result<SecretData, String> {
    let encryption_key = encryption_key_from_password(encryption_password)?;
    let mut buffer = unencrypted.clone();
    let _res = recrypt_secret_data_key_key(
        &mut buffer,
        unencrypted_len_m1,
        &decryption_key,
        &encryption_key,
    )?;
    Ok(buffer)
}

fn checksum_of_payload(payload: &[u8]) -> Vec<u8> {
    let checksum_full = sha256::digest(payload);
    let checksum_truncated = &checksum_full[0..(2 * CHECKSUM_LEN)];
    let checksum_bin = Vec::from_hex(&checksum_truncated).unwrap();
    debug_assert_eq!(checksum_bin.len(), CHECKSUM_LEN);
    checksum_bin
}
