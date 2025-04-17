use crate::encrypt_xor::{EncryptionKey, EncryptionSalt, Encryptor, XorEncryptor, SALT_LEN};
use hex_conservative::{DisplayHex, FromHex};
use rand_core::{OsRng, RngCore};
use std::fs;

const MAGIC_BYTES_LEN: usize = 2;
const MAGIC_BYTES_STR: &str = "5353"; // "SS" from SeedStore; dec 83, 83
const SECRET_DATA_MAXLEN: usize = 65535;
const SECRET_DATA_MINLEN: usize = 1;
const NONSECRET_DATA_MAXLEN: usize = 255;
const BYTE_MAX: u8 = 255;
// const ENCRYPTION_KEY_LEN: usize = 32;
const CHECKSUM_LEN: usize = 4;

/// Store a secret data in an encrypred file.
/// Also store some nonsecret data.
/// Read them, store the secret encrypted with an ephemeral key.
/// Secret data length can be between 1 and 256 bytes.
/// Secret data is stored in a fixed byte array, to avoid allocations.
/// A checksum is also stored, for the whole data.
/// The encrypted part has no checksum, because if it had, it would be possible
/// to check if a password decrypts it or not, which helps brute forcing.
pub struct SecretStore {
    format_version: FormatVersion,
    /// Secret data, encrypted with the ephemeral key, stored on fixed len
    scrambled_secret_data: Vec<u8>,
    nonsecret_data: Vec<u8>,
    encryption_salt: EncryptionSalt,
    ephemeral_scrambling_key: EncryptionKey,
}

/// Helper class for creating the store from given data.
/// Should be used only by the utility that creates the encrypted file.
pub struct SecretStoreCreator {}

#[derive(Clone, Copy)]
enum FormatVersion {
    One = 1,
}

const FORMAT_VERSION_LATEST: FormatVersion = FormatVersion::One;
const FORMAT_VERSION_OLDEST: FormatVersion = FormatVersion::One;

impl SecretStore {
    pub fn new_from_encrypted_file(
        path_for_secret_file: &str,
        encryption_password: &str,
    ) -> Result<Self, String> {
        let secret_payload = read_payload_from_file(path_for_secret_file)?;
        Self::new_from_payload(&secret_payload, encryption_password)
    }

    pub fn new_from_payload(
        secret_payload: &Vec<u8>,
        encryption_password: &str,
    ) -> Result<Self, String> {
        let (format_version, nonsecret_data, mut encrypted_secret_data, encryption_salt) =
            parse_payload(&secret_payload)?;
        let ephemeral_scrambling_key = Self::generate_scrambling_key();
        let _res = scramble_encrypted_secret_data(
            &mut encrypted_secret_data,
            encryption_password,
            &encryption_salt,
            &ephemeral_scrambling_key,
        )?;
        Ok(Self {
            format_version,
            scrambled_secret_data: encrypted_secret_data,
            nonsecret_data,
            encryption_salt,
            ephemeral_scrambling_key,
        })
    }

    pub fn nonsecret_data(&self) -> &Vec<u8> {
        &self.nonsecret_data
    }

    /// Caution: decrypted secret is returned on copy.
    #[cfg(test)]
    pub(crate) fn secret_data(&self) -> Result<Vec<u8>, String> {
        // Caution: decrypted secret
        let mut decrypted = self.scrambled_secret_data.clone();
        let _res = descramble_secret(&mut decrypted, &self.ephemeral_scrambling_key)?;
        Ok(decrypted)
    }

    pub fn processed_secret_data<F, R>(&self, f: F) -> Result<R, String>
    where
        F: Fn(&Vec<u8>) -> Result<R, String>,
    {
        // Caution: decrypted secret
        let mut decrypted = self.scrambled_secret_data.clone();
        let _res = descramble_secret(&mut decrypted, &self.ephemeral_scrambling_key)?;
        let res = f(&decrypted)?;
        Ok(res)
    }

    /// Write out secret content to a file.
    /// Use it through [`SecretStoreCreator`]
    pub(crate) fn write_to_file(
        &self,
        path_for_secret_file: &str,
        encryption_password: &str,
    ) -> Result<(), String> {
        let file_exists = fs::exists(path_for_secret_file).map_err(|e| {
            format!(
                "Could not check existence of secret file ({} {})",
                path_for_secret_file,
                e.to_string()
            )
        })?;
        if file_exists {
            return Err(format!(
                "A secret file already exisits, refusing to overwrite ({})",
                path_for_secret_file
            ));
        }
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

    pub fn assemble_payload(&self, encryption_password: &str) -> Result<Vec<u8>, String> {
        let mut encrypted = self.scrambled_secret_data.clone();
        let _res = encrypt_scrambled_secret_data(
            &mut encrypted,
            &self.ephemeral_scrambling_key,
            encryption_password,
            &self.encryption_salt,
        )?;
        assemble_payload(
            self.format_version,
            &self.nonsecret_data,
            &encrypted,
            &self.encryption_salt,
        )
    }

    fn generate_encryption_salt() -> EncryptionSalt {
        let mut salt = EncryptionSalt::default();
        let _res = OsRng.fill_bytes(&mut salt);
        salt
    }

    fn generate_scrambling_key() -> EncryptionKey {
        let mut key = EncryptionKey::default();
        let _res = OsRng.fill_bytes(&mut key);
        key
    }
}

impl SecretStoreCreator {
    pub fn new_from_data(
        nonsecret_data: Vec<u8>,
        secret_data: &Vec<u8>,
    ) -> Result<SecretStore, String> {
        let format_version = FORMAT_VERSION_LATEST;
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
        let encryption_salt = SecretStore::generate_encryption_salt();
        let ephemeral_scrambling_key = SecretStore::generate_scrambling_key();
        let mut scrambled_secret_data = secret_data.clone();
        let _res = scramble_secret(&mut scrambled_secret_data, &ephemeral_scrambling_key)?;
        Ok(SecretStore {
            format_version,
            scrambled_secret_data,
            nonsecret_data,
            ephemeral_scrambling_key,
            encryption_salt,
        })
    }

    /// Write out secret content to a file.
    pub fn write_to_file(
        secretstore: &SecretStore,
        path_for_secret_file: &str,
        encryption_password: &str,
    ) -> Result<(), String> {
        secretstore.write_to_file(path_for_secret_file, encryption_password)
    }
}

impl FormatVersion {
    fn from_u8(byte: u8) -> Result<FormatVersion, String> {
        match byte {
            1 => Ok(FormatVersion::One),
            _ => Err(format!("Invalid format {}", byte)),
        }
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

fn verify_payload_len(payload_len: usize, min_len: usize) -> Result<(), String> {
    if payload_len < min_len {
        return Err(format!(
            "File content is too short, {} vs {}",
            payload_len, min_len,
        ));
    }
    Ok(())
}

fn get_next_payload_byte(payload: &Vec<u8>, pos: &mut usize) -> Result<u8, String> {
    let next_byte = *payload
        .get(*pos)
        .ok_or(format!("File content is too short, {}", pos))?;
    *(pos) += 1;
    Ok(next_byte)
}

fn u16_from_two_bytes(b1: u8, b2: u8) -> u16 {
    ((b2 as u16) << 8) + (b1 as u16)
}

fn two_bytes_from_u16(s: u16) -> (u8, u8) {
    ((s & 0x00ffu16) as u8, (s >> 8) as u8)
}

fn parse_payload(
    payload: &Vec<u8>,
) -> Result<(FormatVersion, Vec<u8>, Vec<u8>, EncryptionSalt), String> {
    let mut pos: usize = 0;

    let _res = verify_payload_len(payload.len(), pos + MAGIC_BYTES_LEN)?;
    let magic_bytes = &payload[pos..pos + MAGIC_BYTES_LEN];
    if magic_bytes.to_lower_hex_string() != MAGIC_BYTES_STR {
        return Err(format!(
            "Wrong magic byte ({}), check the secret file!",
            magic_bytes.to_lower_hex_string()
        ));
    }
    pos += MAGIC_BYTES_LEN;

    let format_version_byte = get_next_payload_byte(payload, &mut pos)?;
    if format_version_byte < FORMAT_VERSION_OLDEST as u8
        || format_version_byte > FORMAT_VERSION_LATEST as u8
    {
        return Err(format!("Invalid format version {}", format_version_byte));
    }
    let format_version = FormatVersion::from_u8(format_version_byte)?;

    let nonsecret_len = get_next_payload_byte(payload, &mut pos)? as usize;

    let _res = verify_payload_len(payload.len(), pos + nonsecret_len)?;

    let nonsecret_data = payload[pos..pos + nonsecret_len].to_vec();
    pos += nonsecret_len;

    let encryption_version_byte = get_next_payload_byte(payload, &mut pos)?;
    if encryption_version_byte != 1 {
        return Err(format!(
            "Invalid encryption version {}",
            encryption_version_byte
        ));
    }

    let _res = verify_payload_len(payload.len(), pos + SALT_LEN)?;
    let encryption_salt_temp = &payload[pos..pos + SALT_LEN];
    pos += SALT_LEN;
    debug_assert_eq!(encryption_salt_temp.len(), SALT_LEN);
    let encryption_salt = <EncryptionSalt>::try_from(encryption_salt_temp)
        .map_err(|e| format!("Internal salt conversion error {}", e))?;

    let el_b1 = get_next_payload_byte(payload, &mut pos)?;
    let el_b2 = get_next_payload_byte(payload, &mut pos)?;
    let encrypted_len = u16_from_two_bytes(el_b1, el_b2) as usize;

    let _res = verify_payload_len(payload.len(), pos + encrypted_len)?;
    let encrypted_secret_data = payload[pos..pos + encrypted_len].to_vec();
    pos += encrypted_len;

    let _res = verify_payload_len(payload.len(), pos + CHECKSUM_LEN)?;
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

    Ok((
        format_version,
        nonsecret_data,
        encrypted_secret_data,
        encryption_salt,
    ))
}

fn assemble_payload(
    format_version: FormatVersion,
    nonsecret_data: &Vec<u8>,
    encrypted_secret_data: &Vec<u8>,
    encryption_salt: &EncryptionSalt,
) -> Result<Vec<u8>, String> {
    let mut o: Vec<u8> = Vec::with_capacity(256);
    o.extend(Vec::from_hex(MAGIC_BYTES_STR).unwrap());
    let nonsecret_len = nonsecret_data.len();
    if nonsecret_len > NONSECRET_DATA_MAXLEN {
        return Err(format!(
            "Nonsecret data too long ({} vs {})",
            nonsecret_len, NONSECRET_DATA_MAXLEN
        ));
    }

    o.push(format_version as u8);

    debug_assert!(nonsecret_len <= BYTE_MAX as usize);
    o.push(nonsecret_len as u8);

    o.extend(nonsecret_data);

    let encryption_version = 1u8;
    o.push(encryption_version);

    o.extend(encryption_salt);

    let encrypted_secret_data_len = encrypted_secret_data.len();
    if encrypted_secret_data_len < SECRET_DATA_MINLEN {
        return Err(format!(
            "Secret data too short ({} vs {})",
            encrypted_secret_data_len, SECRET_DATA_MINLEN
        ));
    }
    if encrypted_secret_data_len > SECRET_DATA_MAXLEN {
        return Err(format!(
            "Secret data too long ({} vs {})",
            encrypted_secret_data_len, SECRET_DATA_MAXLEN
        ));
    }
    debug_assert!(
        encrypted_secret_data_len >= SECRET_DATA_MINLEN
            && encrypted_secret_data_len <= SECRET_DATA_MAXLEN
    );
    let (el_b1, el_b2) = two_bytes_from_u16(encrypted_secret_data_len as u16);
    o.push(el_b1);
    o.push(el_b2);

    o.extend(encrypted_secret_data);

    // compute and add checksum
    let checksum = checksum_of_payload(&o);
    o.extend(&checksum);

    Ok(o)
}

/// Descramble scrambled secret, in-place.
/// Caution: decrypted secret is made available
fn descramble_secret(
    encrypted: &mut Vec<u8>,
    scrambling_key: &EncryptionKey,
) -> Result<(), String> {
    let _res = XorEncryptor::decrypt_with_key(encrypted, &scrambling_key)?;
    Ok(())
}

/// Scramble secret, in-place.
fn scramble_secret(
    unencrypted: &mut Vec<u8>,
    scrambling_key: &EncryptionKey,
) -> Result<(), String> {
    debug_assert!(unencrypted.len() <= SECRET_DATA_MAXLEN);
    let _res = XorEncryptor::encrypt_with_key(unencrypted, &scrambling_key)?;
    Ok(())
}

/// Take encrypted secret, and scramble it.
/// Caution: Secret is available unencrypted internally for a short time.
fn scramble_encrypted_secret_data(
    encrypted: &mut Vec<u8>,
    decryption_password: &str,
    encryption_salt: &EncryptionSalt,
    scrambling_key: &EncryptionKey,
) -> Result<(), String> {
    debug_assert!(encrypted.len() <= SECRET_DATA_MAXLEN);
    let _res = XorEncryptor::decrypt(encrypted, decryption_password, encryption_salt)?;
    let _res = scramble_secret(encrypted, scrambling_key)?;
    Ok(())
}

/// Take scrambled secret, and encrypt it.
/// Caution: Secret is available unencrypted internally for a short time.
fn encrypt_scrambled_secret_data(
    scrambled: &mut Vec<u8>,
    scrambling_key: &EncryptionKey,
    encryption_password: &str,
    salt: &EncryptionSalt,
) -> Result<(), String> {
    let _res = descramble_secret(scrambled, scrambling_key)?;
    let _res = XorEncryptor::encrypt(scrambled, encryption_password, salt);
    Ok(())
}

fn checksum_of_payload(payload: &[u8]) -> Vec<u8> {
    let checksum_full = sha256::digest(payload);
    let checksum_truncated = &checksum_full[0..(2 * CHECKSUM_LEN)];
    let checksum_bin = Vec::from_hex(&checksum_truncated).unwrap();
    debug_assert_eq!(checksum_bin.len(), CHECKSUM_LEN);
    checksum_bin
}

#[cfg(test)]
mod tests {
    use super::{two_bytes_from_u16, u16_from_two_bytes};

    #[test]
    fn parse_u16() {
        assert_eq!(u16_from_two_bytes(0x07, 0x03), 0x0307);

        assert_eq!(two_bytes_from_u16(0x0307), (0x07, 0x03));

        assert_eq!(two_bytes_from_u16(u16_from_two_bytes(201, 202)), (201, 202));

        let (b1, b2) = two_bytes_from_u16(0x7348);
        assert_eq!(u16_from_two_bytes(b1, b2), 0x7348)
    }
}
