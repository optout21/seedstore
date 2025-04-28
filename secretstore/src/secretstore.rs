use crate::encrypt_xor::{EncryptionKey, EncryptionSalt, Encryptor, XorEncryptor, SALT_LEN};
use bitcoin_hashes::Sha256d;
use hex_conservative::{DisplayHex, FromHex};
use rand_core::{OsRng, RngCore};
use std::fs;
use zeroize::Zeroize;

/// Minimum accepted password length
pub const PASSWORD_MIN_LEN: usize = 7;
pub const SECRET_DATA_MIN_LEN: usize = 1;
pub const SECRET_DATA_MAX_LEN: usize = 65535;
pub const NONSECRET_DATA_MAX_LEN: usize = 255;

const MAGIC_BYTES_LEN: usize = 2;
const MAGIC_BYTES_STR: &str = "5353"; // "SS" from SeedStore; dec 83, 83
const CHECKSUM_LEN: usize = 4;
const BYTE_MAX: u8 = 255;

/// Store a secret data in an encrypred file.
/// Also store some nonsecret data.
/// Can be loaded from an encrypted file.
/// The secret is stored in memory scrabmled (using an ephemeral scrambling key).
/// Secret data length can be between 1 and 65535 bytes.
pub struct SecretStore {
    /// The format version used.
    format_version: FormatVersion,
    /// The encryption version used.
    encryption_version: EncryptionVersion,
    /// Secret data, scrabmled with the ephemeral key.
    scrambled_secret_data: Vec<u8>,
    /// The non-secret part of the data
    nonsecret_data: Vec<u8>,
    /// Auxiliary encryption data, such as salt using for encryption.
    encryption_aux_data: EncryptionAuxData,
    /// Scrambling key used to scramble the secret data in memory.
    ephemeral_scrambling_key: EncryptionKey,
}

/// Helper class for creating the store from given data.
/// Should be used only by the utility that creates the encrypted file.
pub struct SecretStoreCreator {}

#[derive(Clone, Copy)]
enum FormatVersion {
    One = 1,
}

/// Encryption versions
#[derive(Clone, Copy, Debug, PartialEq)]
enum EncryptionVersion {
    /// V1: XOR encryption
    V1Xor = 1,
}

/// Version-dependent auxiliary encryption data
enum EncryptionAuxData {
    /// V1 XOR encryption: encrypted data plus encryption salt
    V1Xor(EncryptionSalt),
}

const FORMAT_VERSION_LATEST: FormatVersion = FormatVersion::One;
const FORMAT_VERSION_OLDEST: FormatVersion = FormatVersion::One;

impl SecretStore {
    /// Load the secret from a password-protected secret file.
    pub fn new_from_encrypted_file(
        path_for_secret_file: &str,
        encryption_password: &str,
    ) -> Result<Self, String> {
        let secret_payload = read_payload_from_file(path_for_secret_file)?;
        Self::new_from_payload(&secret_payload, encryption_password)
    }

    /// Load the secret store from encrypted data.
    /// Typically the data is stored in a file, but this method takes the contents directly.
    pub fn new_from_payload(
        secret_payload: &Vec<u8>,
        encryption_password: &str,
    ) -> Result<Self, String> {
        let (
            format_version,
            nonsecret_data,
            encryption_version,
            mut encrypted_secret_data,
            encryption_aux_data,
        ) = parse_payload(&secret_payload)?;
        let ephemeral_scrambling_key = Self::generate_scrambling_key();
        let _res = scramble_encrypted_secret_data(
            encryption_version,
            &mut encrypted_secret_data,
            encryption_password,
            &encryption_aux_data,
            &ephemeral_scrambling_key,
        )?;
        Ok(Self {
            format_version,
            encryption_version,
            scrambled_secret_data: encrypted_secret_data,
            nonsecret_data,
            encryption_aux_data,
            ephemeral_scrambling_key,
        })
    }

    pub fn nonsecret_data(&self) -> &Vec<u8> {
        &self.nonsecret_data
    }

    /// Caution: unencrypted secret is returned in copy.
    #[cfg(test)]
    pub(crate) fn secret_data(&self) -> Result<Vec<u8>, String> {
        // Caution: unencrypted secret
        let mut decrypted = self.scrambled_secret_data.clone();
        let _res = descramble_secret(&mut decrypted, &self.ephemeral_scrambling_key)?;
        Ok(decrypted)
    }

    /// Invokes a processor function on the unencrypted secret data.
    /// Caution: unencrypted secret is made available in a user processor method.
    pub fn processed_secret_data<F, R>(&self, f: F) -> Result<R, String>
    where
        F: Fn(&Vec<u8>) -> Result<R, String>,
    {
        // Caution: unencrypted secret
        let mut decrypted = self.scrambled_secret_data.clone();
        let _res = descramble_secret(&mut decrypted, &self.ephemeral_scrambling_key)?;
        let res = f(&decrypted)?;
        decrypted.zeroize();
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
        let encrypted_payload = self.assemble_encrypted_payload(encryption_password)?;
        let _res = fs::write(path_for_secret_file, encrypted_payload).map_err(|e| {
            format!(
                "Error writing to file {}, {}",
                path_for_secret_file,
                e.to_string()
            )
        })?;
        Ok(())
    }

    pub(crate) fn assemble_encrypted_payload(
        &self,
        encryption_password: &str,
    ) -> Result<Vec<u8>, String> {
        let mut encrypted = self.scrambled_secret_data.clone();
        let _res = encrypt_scrambled_secret_data(
            &mut encrypted,
            &self.ephemeral_scrambling_key,
            self.encryption_version,
            encryption_password,
            &self.encryption_aux_data,
        )?;
        assemble_payload(
            self.format_version,
            &self.nonsecret_data,
            self.encryption_version,
            &encrypted,
            &self.encryption_aux_data,
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

impl Zeroize for SecretStore {
    fn zeroize(&mut self) {
        self.scrambled_secret_data.zeroize();
        self.encryption_aux_data.zeroize();
        self.ephemeral_scrambling_key.zeroize();
        self.nonsecret_data.zeroize();
        self.format_version = FORMAT_VERSION_OLDEST;
    }
}

impl SecretStoreCreator {
    /// Create a new store instance from given contained data.
    /// The store can be written out to file using [`write_to_file`]
    pub fn new_from_data(
        nonsecret_data: Vec<u8>,
        secret_data: &Vec<u8>,
    ) -> Result<SecretStore, String> {
        let format_version = FORMAT_VERSION_LATEST;
        if nonsecret_data.len() > NONSECRET_DATA_MAX_LEN {
            return Err(format!(
                "Non-secret data too long, {} vs {}",
                nonsecret_data.len(),
                NONSECRET_DATA_MAX_LEN
            ));
        }
        if secret_data.len() > SECRET_DATA_MAX_LEN {
            return Err(format!(
                "Secret data too long, {} vs {}",
                secret_data.len(),
                SECRET_DATA_MAX_LEN
            ));
        }
        if secret_data.len() < SECRET_DATA_MIN_LEN {
            return Err(format!(
                "Secret data too short, {} vs {}",
                secret_data.len(),
                SECRET_DATA_MIN_LEN
            ));
        }
        let encryption_salt = SecretStore::generate_encryption_salt();
        let ephemeral_scrambling_key = SecretStore::generate_scrambling_key();
        let mut scrambled_secret_data = secret_data.clone();
        let _res = scramble_secret(&mut scrambled_secret_data, &ephemeral_scrambling_key)?;
        Ok(SecretStore {
            format_version,
            encryption_version: EncryptionVersion::V1Xor,
            scrambled_secret_data,
            nonsecret_data,
            ephemeral_scrambling_key,
            encryption_aux_data: EncryptionAuxData::V1Xor(encryption_salt),
        })
    }

    /// Write out the encrypted contents to a file.
    /// ['encryption_password']: The passowrd to be used for encryption, should be strong.
    /// Minimal length of password is checked.
    pub fn write_to_file(
        secretstore: &SecretStore,
        path_for_secret_file: &str,
        encryption_password: &str,
    ) -> Result<(), String> {
        secretstore.write_to_file(path_for_secret_file, encryption_password)
    }
}

impl FormatVersion {
    fn from_u8(byte: u8) -> Result<Self, String> {
        match byte {
            1 => Ok(Self::One),
            _ => Err(format!("Invalid format version {}", byte)),
        }
    }
}

impl EncryptionVersion {
    fn from_u8(byte: u8) -> Result<Self, String> {
        match byte {
            1 => Ok(Self::V1Xor),
            _ => Err(format!("Invalid encryption version {}", byte)),
        }
    }
}

impl Zeroize for EncryptionAuxData {
    fn zeroize(&mut self) {
        match self {
            Self::V1Xor(ref mut salt) => {
                salt.zeroize();
            }
        }
    }
}

impl EncryptionAuxData {
    /// Return the `EncryptionVersion` matching this aux data.
    fn version(&self) -> Result<EncryptionVersion, String> {
        match &self {
            Self::V1Xor(_) => Ok(EncryptionVersion::V1Xor),
        }
    }

    /// Verify that the given encryption version matches this aux data.
    fn check_version(&self, encryption_version: EncryptionVersion) -> Result<(), String> {
        let expected_version = self.version()?;
        if encryption_version != expected_version {
            return Err(format!(
                "Invalid encryption version, {:?} vs {:?}",
                encryption_version, expected_version
            ));
        }
        Ok(())
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

/// Method to parse an encrypted payload.
fn parse_payload(
    payload: &Vec<u8>,
) -> Result<
    (
        FormatVersion,
        Vec<u8>,
        EncryptionVersion,
        Vec<u8>,
        EncryptionAuxData,
    ),
    String,
> {
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
    let format_version = FormatVersion::from_u8(format_version_byte)?;

    let nonsecret_len = get_next_payload_byte(payload, &mut pos)? as usize;

    let _res = verify_payload_len(payload.len(), pos + nonsecret_len)?;

    let nonsecret_data = payload[pos..pos + nonsecret_len].to_vec();
    pos += nonsecret_len;

    let encryption_version_byte = get_next_payload_byte(payload, &mut pos)?;
    let encryption_version = EncryptionVersion::from_u8(encryption_version_byte)?;

    let (encryption_aux_data, encrypted_secret_data) = match encryption_version {
        EncryptionVersion::V1Xor => {
            let (encryption_aux_data, encrypted_secret_data) =
                parse_encrypted_data_v1_xor(payload, &mut pos)?;
            (encryption_aux_data, encrypted_secret_data)
        }
    };

    let _res = verify_payload_len(payload.len(), pos + CHECKSUM_LEN)?;
    let checksum_parsed = payload[pos..pos + CHECKSUM_LEN].to_vec();
    // Compute and check checksum
    let checksum_computed = checksum_of_payload(&payload[0..pos])?;
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
        encryption_version,
        encrypted_secret_data,
        encryption_aux_data,
    ))
}

fn parse_encrypted_data_v1_xor(
    payload: &Vec<u8>,
    pos: &mut usize,
) -> Result<(EncryptionAuxData, Vec<u8>), String> {
    let _res = verify_payload_len(payload.len(), *pos + SALT_LEN)?;
    let encryption_salt_temp = &payload[(*pos)..(*pos + SALT_LEN)];
    *pos += SALT_LEN;
    debug_assert_eq!(encryption_salt_temp.len(), SALT_LEN);
    let encryption_salt = <EncryptionSalt>::try_from(encryption_salt_temp)
        .map_err(|e| format!("Internal salt conversion error {}", e))?;
    let encryption_aux_data = EncryptionAuxData::V1Xor(encryption_salt);

    let encrypted_secret_data = parse_encrypted_data(payload, pos)?;

    Ok((encryption_aux_data, encrypted_secret_data))
}

fn parse_encrypted_data(payload: &Vec<u8>, pos: &mut usize) -> Result<Vec<u8>, String> {
    let el_b1 = get_next_payload_byte(payload, pos)?;
    let el_b2 = get_next_payload_byte(payload, pos)?;
    let encrypted_len = u16_from_two_bytes(el_b1, el_b2) as usize;

    let _res = verify_payload_len(payload.len(), *pos + encrypted_len)?;
    let encrypted_secret_data = payload[(*pos)..(*pos + encrypted_len)].to_vec();
    *pos += encrypted_len;
    Ok(encrypted_secret_data)
}

/// Method to assemble the encrypted payload.
fn assemble_payload(
    format_version: FormatVersion,
    nonsecret_data: &Vec<u8>,
    encryption_version: EncryptionVersion,
    encrypted_secret_data: &Vec<u8>,
    encryption_aux_data: &EncryptionAuxData,
) -> Result<Vec<u8>, String> {
    let _res = encryption_aux_data.check_version(encryption_version)?;

    let mut o: Vec<u8> = Vec::with_capacity(256);
    o.extend(Vec::from_hex(MAGIC_BYTES_STR).unwrap());
    let nonsecret_len = nonsecret_data.len();
    if nonsecret_len > NONSECRET_DATA_MAX_LEN {
        return Err(format!(
            "Nonsecret data too long ({} vs {})",
            nonsecret_len, NONSECRET_DATA_MAX_LEN
        ));
    }

    o.push(format_version as u8);

    debug_assert!(nonsecret_len <= BYTE_MAX as usize);
    o.push(nonsecret_len as u8);

    o.extend(nonsecret_data);

    o.push(encryption_version as u8);

    match encryption_aux_data {
        EncryptionAuxData::V1Xor(salt) => {
            let _res = assemble_encrypted_data_v1_xor(&mut o, salt, encrypted_secret_data)?;
        }
    }

    // compute and add checksum
    let checksum = checksum_of_payload(&o)?;
    o.extend(&checksum);

    Ok(o)
}

fn assemble_encrypted_data_v1_xor(
    o: &mut Vec<u8>,
    salt: &EncryptionSalt,
    encrypted_secret_data: &Vec<u8>,
) -> Result<(), String> {
    o.extend(salt);
    assemble_encrypted_data(o, encrypted_secret_data)
}

fn assemble_encrypted_data(o: &mut Vec<u8>, encrypted_secret_data: &Vec<u8>) -> Result<(), String> {
    let encrypted_data_len = encrypted_secret_data.len();
    if encrypted_data_len < SECRET_DATA_MIN_LEN {
        return Err(format!(
            "Secret data too short ({} vs {})",
            encrypted_data_len, SECRET_DATA_MIN_LEN
        ));
    }
    if encrypted_data_len > SECRET_DATA_MAX_LEN {
        return Err(format!(
            "Secret data too long ({} vs {})",
            encrypted_data_len, SECRET_DATA_MAX_LEN
        ));
    }
    debug_assert!(
        encrypted_data_len >= SECRET_DATA_MIN_LEN && encrypted_data_len <= SECRET_DATA_MAX_LEN
    );
    let (el_b1, el_b2) = two_bytes_from_u16(encrypted_data_len as u16);
    o.push(el_b1);
    o.push(el_b2);

    o.extend(encrypted_secret_data);

    Ok(())
}

/// Descramble scrambled secret, in-place.
/// Caution: unencrypted secret is made available
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
    debug_assert!(unencrypted.len() <= SECRET_DATA_MAX_LEN);
    let _res = XorEncryptor::encrypt_with_key(unencrypted, &scrambling_key)?;
    Ok(())
}

/// Take encrypted secret, and scramble it.
/// Caution: unencrypted secret is available internally for a short time.
fn scramble_encrypted_secret_data(
    encryption_version: EncryptionVersion,
    encrypted: &mut Vec<u8>,
    decryption_password: &str,
    aux_data: &EncryptionAuxData,
    scrambling_key: &EncryptionKey,
) -> Result<(), String> {
    debug_assert!(encrypted.len() <= SECRET_DATA_MAX_LEN);
    let _res = aux_data.check_version(encryption_version)?;
    match aux_data {
        EncryptionAuxData::V1Xor(salt) => {
            let _res = XorEncryptor::decrypt(encrypted, decryption_password, salt)?;
            let _res = scramble_secret(encrypted, scrambling_key)?;
            Ok(())
        }
    }
}

fn validate_password(encryption_password: &str) -> Result<(), String> {
    if encryption_password.len() < PASSWORD_MIN_LEN {
        return Err(format!(
            "Password is too short! ({} vs {})",
            encryption_password.len(),
            PASSWORD_MIN_LEN
        ));
    }
    Ok(())
}

/// Take scrambled secret, and encrypt it.
/// Caution: unencrypted secret is available internally for a short time.
fn encrypt_scrambled_secret_data(
    scrambled: &mut Vec<u8>,
    scrambling_key: &EncryptionKey,
    encryption_version: EncryptionVersion,
    encryption_password: &str,
    aux_data: &EncryptionAuxData,
) -> Result<(), String> {
    let _res = validate_password(encryption_password)?;
    let _res = descramble_secret(scrambled, scrambling_key)?;
    let _res = aux_data.check_version(encryption_version)?;
    match aux_data {
        EncryptionAuxData::V1Xor(salt) => {
            let _res = XorEncryptor::encrypt(scrambled, encryption_password, salt);
            Ok(())
        }
    }
}

fn checksum_of_payload(payload: &[u8]) -> Result<Vec<u8>, String> {
    let checksum_truncated = Sha256d::hash(payload).as_byte_array()[0..CHECKSUM_LEN].to_vec();
    debug_assert_eq!(checksum_truncated.len(), CHECKSUM_LEN);
    Ok(checksum_truncated)
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
