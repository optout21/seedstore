use zeroize::Zeroize;

/// Encryption versions
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum EncryptionVersion {
    /// V3: ChaCha -- XChaCha20-Poly1305 encryption with Scrypt key
    V3ChaCha = 3,
    /// V1: DEPRECATED -- XOR encryption with hashed key
    V1Xor = 1,
}

/// Version-dependent auxiliary encryption data
pub(crate) enum EncryptionAuxData {
    /// V3 ChaCha encryption: rounds, salt, nonce
    V3ChaCha(
        (
            u8,
            crate::encrypt_chacha::EncryptionSalt,
            crate::encrypt_chacha::EncryptionNonce,
        ),
    ),
    /// V1 DEPRECATED XOR encryption: encryption salt
    V1Xor(crate::encrypt_xor::EncryptionSalt),
}

/// Trait for an actor that can encrypt and decrypt using a password.
pub(crate) trait Encryptor {
    /// Encrypt some data using an encryption password and aux data, in-place.
    fn encrypt(
        unencrypted_data: &mut Vec<u8>,
        password: &str,
        aux_data: &EncryptionAuxData,
    ) -> Result<(), String>;

    /// Decrypt some encrypted data using an encryption password and aux data, in-place.
    /// Caution: unencrypted data is returned in copy
    fn decrypt(
        encrypted_data: &mut Vec<u8>,
        password: &str,
        aux_data: &EncryptionAuxData,
    ) -> Result<(), String>;

    /// Generate new random auxiliary data.
    fn generate_aux_data() -> EncryptionAuxData;
}

impl EncryptionVersion {
    pub(crate) fn from_u8(byte: u8) -> Result<Self, String> {
        match byte {
            3 => Ok(Self::V3ChaCha),
            1 => Ok(Self::V1Xor),
            _ => Err(format!("Invalid encryption version {}", byte)),
        }
    }
}

impl Zeroize for EncryptionAuxData {
    fn zeroize(&mut self) {
        match self {
            Self::V3ChaCha((_rounds, ref mut salt, ref mut nonce)) => {
                salt.zeroize();
                nonce.zeroize();
            }
            Self::V1Xor(ref mut salt) => {
                salt.zeroize();
            }
        }
    }
}

impl EncryptionAuxData {
    /// Return the `EncryptionVersion` matching this aux data.
    pub(crate) fn version(&self) -> Result<EncryptionVersion, String> {
        match &self {
            Self::V3ChaCha(_) => Ok(EncryptionVersion::V3ChaCha),
            Self::V1Xor(_) => Ok(EncryptionVersion::V1Xor),
        }
    }

    /// Verify that the given encryption version matches this aux data.
    pub(crate) fn check_version(
        &self,
        encryption_version: EncryptionVersion,
    ) -> Result<(), String> {
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
