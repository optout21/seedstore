// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the  MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// You may not use this file except in accordance with the license.

//! KeyStore is a solution for storing a single bitcoin-style ECDSA private key (32 bytes)
//! in a password-protected encrypted file.
//! SeedStore is built on [`SecretStore`].
//! A typical example is a wallet storing the secret seed.
//! See also [`SeedStore`] for storing a master key (as opposed to a single key)

use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{All, Message, PublicKey, SecretKey, Signing};
use secretstore::{SecretStore, SecretStoreCreator};
use zeroize::{Zeroize, ZeroizeOnDrop};

const NONSECRET_DATA_LEN: usize = 4;

/// Store a single bitcoin-style ECDSA 32-byte private key in an encrypted file.
/// The secret can be loaded from an encrypted file.
/// Additionally store 4 bytes of non-secret data, reserved for later use.
///
/// The secret is stored in memory scrambled (using an ephemeral scrambling key).
/// See also [`KeyStoreCreator`], [`super::SeedStore`].
pub struct KeyStore {
    secretstore: SecretStore,
    public_key: PublicKey,
    secp: Secp256k1<All>,
}

/// Helper class for creating the store from given data.
/// Should be used only by the utility that creates the encrypted file.
/// See also [`KeyStore`].
pub struct KeyStoreCreator {}

impl KeyStore {
    /// Load the secret from a password-protected secret file.
    pub fn new_from_encrypted_file(
        path_for_secret_file: &str,
        encryption_password: &str,
    ) -> Result<Self, String> {
        let secretstore =
            SecretStore::new_from_encrypted_file(path_for_secret_file, encryption_password)?;
        Self::new_from_secretstore(secretstore)
    }

    /// Load the secret store from encrypted data.
    /// Typically the data is stored in a file, but this method takes the contents directly.
    pub fn new_from_payload(
        secret_payload: &Vec<u8>,
        encryption_password: &str,
    ) -> Result<Self, String> {
        let secretstore = SecretStore::new_from_payload(secret_payload, encryption_password)?;
        Self::new_from_secretstore(secretstore)
    }

    fn new_from_secretstore(secretstore: SecretStore) -> Result<Self, String> {
        let nonsecret_data = secretstore.nonsecret_data();
        if nonsecret_data.len() != NONSECRET_DATA_LEN {
            return Err(format!(
                "Nonsecret data len should be {} (was {})",
                NONSECRET_DATA_LEN,
                nonsecret_data.len()
            ));
        }
        debug_assert_eq!(nonsecret_data.len(), NONSECRET_DATA_LEN);
        let secp = Secp256k1::new();
        let public_key = Self::get_public_key_intern(&secretstore, &secp)?;

        Ok(KeyStore {
            secretstore,
            public_key,
            secp,
        })
    }

    fn get_public_key_intern<C: Signing>(
        secret_store: &SecretStore,
        secp: &Secp256k1<C>,
    ) -> Result<PublicKey, String> {
        let public_key = secret_store.processed_secret_data(|secret| {
            Self::get_public_key_from_secret_intern(secret, &secp)
        })?;
        Ok(public_key)
    }

    /// Caution: secret data is processed internally.
    fn get_public_key_from_secret_intern<C: Signing>(
        secret: &Vec<u8>,
        secp: &Secp256k1<C>,
    ) -> Result<PublicKey, String> {
        let private_key = SecretKey::from_slice(secret)
            .map_err(|e| format!("Secret key conversion error {}", e))?;
        let public_key = private_key.public_key(&secp);

        let _ = private_key;

        Ok(public_key)
    }

    /// Caution: secret data is returned in copy
    fn get_secret_private_key_from_secret_intern(secret: &Vec<u8>) -> Result<SecretKey, String> {
        let private_key = SecretKey::from_slice(secret)
            .map_err(|e| format!("Secret key conversion error {}", e))?;
        Ok(private_key)
    }

    /// Write out secret content to a file.
    /// Use it through [`SeedStoreCreator`]
    pub(crate) fn write_to_file(
        &self,
        path_for_secret_file: &str,
        encryption_password: &str,
    ) -> Result<(), String> {
        SecretStoreCreator::write_to_file(
            &self.secretstore,
            path_for_secret_file,
            encryption_password,
        )
    }

    /// Return the corresponding public key, generated from the secret private key.
    pub fn get_public_key(&self) -> Result<PublicKey, String> {
        Ok(self.public_key)
    }

    /// Return the PRIVATE key.
    /// CAUTION: unencrypted secret is returned in copy!
    #[cfg(feature = "accesssecret")]
    pub fn get_secret_private_key(&self) -> Result<SecretKey, String> {
        self.get_secret_private_key_nonpub()
    }

    /// Return the PRIVATE key.
    /// CAUTION: unencrypted secret is returned in copy!
    fn get_secret_private_key_nonpub(&self) -> Result<SecretKey, String> {
        let private_key = self.secretstore.processed_secret_data(|secret| {
            Self::get_secret_private_key_from_secret_intern(secret)
        })?;
        Ok(private_key)
    }

    /// Sign using the private key. Use ECDSA signature as it is used in bitcoin.
    /// A 32-byte digest (hash) is signed.
    /// The signer public key has to be provided as well, to be able to check the signer key.
    /// Caution: secret material is processed internally
    pub fn sign_hash_with_private_key_ecdsa(
        &self,
        hash: &[u8; 32],
        signer_public_key: &PublicKey,
    ) -> Result<Signature, String> {
        let private_key = self.get_secret_private_key_nonpub()?;
        let public_key = private_key.public_key(&self.secp);
        // verify public key
        if *signer_public_key != public_key {
            return Err(format!(
                "Public key mismatch, {} vs {}",
                signer_public_key.to_string(),
                public_key.to_string()
            ));
        }
        let msg = Message::from_digest_slice(hash)
            .map_err(|e| format!("Hash digest processing error {}", e.to_string()))?;
        let signature = self.secp.sign_ecdsa(&msg, &private_key);

        let _ = private_key;

        Ok(signature)
    }
}

impl Zeroize for KeyStore {
    fn zeroize(&mut self) {
        self.secretstore.zeroize();
        let _ = self.public_key;
        self.secp = Secp256k1::new();
    }
}

impl ZeroizeOnDrop for KeyStore {}

impl KeyStoreCreator {
    /// Create a new store instance from given secret private key bytes.
    /// The store can be written out to file using [`write_to_file`]
    /// Caution: unencrypted secret data is taken.
    pub fn new_from_data(secret_private_key_bytes: &[u8; 32]) -> Result<KeyStore, String> {
        // Non-secret data: network byte, and 3 reserved bytes (reserved for later use)
        let nonsecret_data = vec![42, 43, 44, 45];
        debug_assert_eq!(nonsecret_data.len(), NONSECRET_DATA_LEN);

        let secretstore =
            SecretStoreCreator::new_from_data(nonsecret_data, &secret_private_key_bytes.to_vec())?;
        KeyStore::new_from_secretstore(secretstore)
    }

    /// Write out the encrypted contents to a file.
    /// ['encryption_password']: The passowrd to be used for encryption, should be strong.
    /// Minimal length of password is checked.
    pub fn write_to_file(
        seedstore: &KeyStore,
        path_for_secret_file: &str,
        encryption_password: &str,
    ) -> Result<(), String> {
        seedstore.write_to_file(path_for_secret_file, encryption_password)
    }
}
