// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the  MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// You may not use this file except in accordance with the license.

//! NsecStore is a solution for storing a single Nostr private key (nsec, 32 bytes)
//! in a password-protected encrypted file.
//! NsecStore is built on [`SecretStore`].

use bech32::{encode, ToBase32};
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{All, Message, PublicKey, SecretKey, Signing};
use secretstore::{Options, SecretStore, SecretStoreCreator};
use zeroize::{Zeroize, ZeroizeOnDrop};

const NPUB_BECH_HRP: &str = "npub";

/// Store a single Nostr nsec 32-byte private key in an encrypted file.
/// The secret can be loaded from an encrypted file.
///
/// The secret is stored in memory scrambled (using an ephemeral scrambling key).
/// See also [`NsecStoreCreator`], [`super::SeedStore`].
pub struct NsecStore {
    secretstore: SecretStore,
    npub: String,
    secp: Secp256k1<All>,
}

/// Helper class for creating the store from given data.
/// Should be used only by the utility that creates the encrypted file.
/// See also [`NsecStore`].
pub struct NsecStoreCreator {}

impl NsecStore {
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
        let secp = Secp256k1::new();
        let npub = Self::get_npub_intern(&secretstore, &secp)?;

        Ok(NsecStore {
            secretstore,
            npub,
            secp,
        })
    }

    fn get_npub_intern<C: Signing>(
        secret_store: &SecretStore,
        secp: &Secp256k1<C>,
    ) -> Result<String, String> {
        let npub = secret_store
            .processed_secret_data(|secret| Self::get_npub_from_secret_intern(secret, &secp))?;
        Ok(npub)
    }

    /// Caution: secret data is processed internally.
    fn get_npub_from_secret_intern<C: Signing>(
        secret: &Vec<u8>,
        secp: &Secp256k1<C>,
    ) -> Result<String, String> {
        let private_key = SecretKey::from_slice(secret)
            .map_err(|e| format!("Secret key conversion error {}", e))?;
        let public_key = private_key.x_only_public_key(&secp).0.serialize();

        let npub = encode(
            NPUB_BECH_HRP,
            public_key.to_base32(),
            bech32::Variant::Bech32,
        )
        .map_err(|e| e.to_string())?;

        Ok(npub)
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
        options: Option<Options>,
    ) -> Result<(), String> {
        SecretStoreCreator::write_to_file(
            &self.secretstore,
            path_for_secret_file,
            encryption_password,
            options,
        )
    }

    /// Return the corresponding npub, generated from the secret nsec.
    pub fn get_npub(&self) -> Result<&str, String> {
        Ok(&self.npub)
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

    // TODO Change to schnorr!

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

        Ok(signature)
    }
}

impl Zeroize for NsecStore {
    fn zeroize(&mut self) {
        self.secretstore.zeroize();
        let _ = self.npub;
        self.secp = Secp256k1::new();
    }
}

impl ZeroizeOnDrop for NsecStore {}

impl NsecStoreCreator {
    /// Create a new store instance from given secret private key bytes.
    /// The store can be written out to file using [`write_to_file`]
    /// Caution: unencrypted secret data is taken.
    pub fn new_from_data(secret_private_key_bytes: &[u8; 32]) -> Result<NsecStore, String> {
        let nonsecret_data = Vec::new();

        let secretstore =
            SecretStoreCreator::new_from_data(nonsecret_data, &secret_private_key_bytes.to_vec())?;
        NsecStore::new_from_secretstore(secretstore)
    }

    /// Write out the encrypted contents to a file.
    /// ['encryption_password']: The passowrd to be used for encryption, should be strong.
    /// Minimal length of password is checked.
    pub fn write_to_file(
        nsecstore: &NsecStore,
        path_for_secret_file: &str,
        encryption_password: &str,
        options: Option<Options>,
    ) -> Result<(), String> {
        nsecstore.write_to_file(path_for_secret_file, encryption_password, options)
    }
}
