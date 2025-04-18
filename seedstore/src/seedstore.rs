use bip39::Mnemonic;
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::secp256k1::{All, PublicKey, SecretKey};
use bitcoin::{Network, NetworkKind};
use secretstore::{SecretStore, SecretStoreCreator};
use std::str::FromStr;

/// Store a secret data in an encrypred file.
/// Also store some nonsecret data.
/// Read them, store the secret encrypted with an ephemeral key.
/// Secret data length can be between 1 and 256 bytes.
/// Secret data is stored in a fixed byte array, to avoid allocations.
/// A checksum is also stored, for the whole data.
/// The encrypted part has no checksum, because if it had, it would be possible
/// to check if a password decrypts it or not, which helps brute forcing.
pub struct SeedStore {
    pub(crate) secretstore: SecretStore,
    secp: Secp256k1<All>,
}

/// Helper class for creating the store from given data.
/// Should be used only by the utility that creates the encrypted file.
pub struct SeedStoreCreator {}

impl SeedStore {
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
        if nonsecret_data.len() != 2 {
            return Err(format!(
                "Nonsecret data len should be 2 (was {})",
                nonsecret_data.len()
            ));
        }
        debug_assert_eq!(nonsecret_data.len(), 2);

        let entropy_checksum_computed =
            secretstore.processed_secret_data(process_compute_checksum)?;
        let entropy_checksum_provided = nonsecret_data[1];
        if entropy_checksum_computed != entropy_checksum_provided {
            return Err(format!(
                "Checksum mismatch ({} vs {}), check the password and the secret file!",
                entropy_checksum_provided, entropy_checksum_computed
            ));
        }

        Ok(SeedStore {
            secretstore,
            secp: Secp256k1::new(),
        })
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

    /// Accessor for network byte.
    pub fn network(&self) -> u8 {
        let nonsecret_data = self.secretstore.nonsecret_data();
        debug_assert_eq!(nonsecret_data.len(), 2);
        nonsecret_data[0]
    }

    /// Convert network byte to [`bitcoin::network::Netork`]
    pub fn network_as_enum(&self) -> Network {
        match self.network() {
            0 => Network::Bitcoin,
            1 => Network::Testnet,
            2 => Network::Testnet4,
            3 => Network::Signet,
            4 => Network::Regtest,
            _ => Network::Bitcoin,
        }
    }

    /// Accessor for the XPUB, generated from the secret entropy (and network).
    pub fn get_xpub(&self) -> Result<Xpub, String> {
        let xpub = self
            .secretstore
            .processed_secret_data(|entropy| self.xpub_from_entropy(entropy))?;
        Ok(xpub)
    }

    /// Return a child public key, generated from the secret entropy (and network).
    /// Standard BIP84 derivation path is used, with the last index provided.
    /// [`index`] The last index (account) of the derivation path.
    pub fn get_child_public_key(&self, index: u32) -> Result<PublicKey, String> {
        let pubkey = self
            .secretstore
            .processed_secret_data(|entropy| self.get_child_public_key_intern(entropy, index))?;
        Ok(pubkey)
    }

    /// Return a child PRIVATE key, generated from the secret entropy (and network).
    /// Caution: partial unencrypted secret is returned in copy!
    /// Standard BIP84 derivation path is used, with the last index provided.
    /// [`index`] The last index (account) of the derivation path.
    pub fn get_child_private_key(&self, index: u32) -> Result<SecretKey, String> {
        let privkey = self
            .secretstore
            .processed_secret_data(|entropy| self.get_child_private_key_intern(entropy, index))?;
        Ok(privkey)
    }

    fn default_account_derivation_path(&self) -> String {
        match self.network() {
            0 => "m/84'/0'/0'".to_string(),
            _ => "m/84'/1'/0'".to_string(),
        }
    }

    fn xpriv_from_entropy(&self, entropy: &Vec<u8>) -> Result<Xpriv, String> {
        let mnemo = Mnemonic::from_entropy(entropy)
            .map_err(|e| format!("Could not process entropy {}", e.to_string()))?;
        let seed = mnemo.to_seed_normalized("");
        let xpriv = Xpriv::new_master(
            <Network as Into<NetworkKind>>::into(self.network_as_enum()),
            &seed,
        )
        .expect("Creating XPriv");
        let derivation = self.default_account_derivation_path();
        let derivation_path_3 =
            DerivationPath::from_str(&derivation).expect("Creating DerivationPath");
        let xpriv_level_3 = xpriv
            .derive_priv(&self.secp, &derivation_path_3)
            .expect("Derive level3 xpriv");
        Ok(xpriv_level_3)
    }

    fn xpub_from_entropy(&self, entropy: &Vec<u8>) -> Result<Xpub, String> {
        let xpriv_level_3 = self.xpriv_from_entropy(entropy)?;
        let xpub_level_3 = Xpub::from_priv(&self.secp, &xpriv_level_3);
        Ok(xpub_level_3)
    }

    fn get_child_keypair_intern(&self, entropy: &Vec<u8>, index: u32) -> Result<Keypair, String> {
        let xpriv = self.xpriv_from_entropy(entropy)?;
        // derive
        let index_4 = ChildNumber::from_normal_idx(0).unwrap();
        let index_5 = ChildNumber::from_normal_idx(index).unwrap();
        let xpriv_5 = xpriv
            .derive_priv(&self.secp, &vec![index_4, index_5])
            .map_err(|e| format!("Derivation error {}", e))?;
        let keypair = xpriv_5.to_keypair(&self.secp);
        Ok(keypair)
    }

    fn get_child_public_key_intern(
        &self,
        entropy: &Vec<u8>,
        index: u32,
    ) -> Result<PublicKey, String> {
        let keypair = self.get_child_keypair_intern(entropy, index)?;
        Ok(keypair.public_key())
    }

    fn get_child_private_key_intern(
        &self,
        entropy: &Vec<u8>,
        index: u32,
    ) -> Result<SecretKey, String> {
        let keypair = self.get_child_keypair_intern(entropy, index)?;
        Ok(keypair.secret_key())
    }
}

impl SeedStoreCreator {
    /// Create a new store instance from given secret entropy bytes and network byte.
    /// The store can be written out to file using [`write_to_file`]
    pub fn new_from_data(entropy: &Vec<u8>, network: u8) -> Result<SeedStore, String> {
        let entropy_checksum = checksum_of_entropy(entropy)?;
        let nonsecret_data = vec![network, entropy_checksum];
        let secretstore = SecretStoreCreator::new_from_data(nonsecret_data, entropy)?;
        SeedStore::new_from_secretstore(secretstore)
    }

    /// Write out the encrypted contents to a file.
    /// ['encryption_password']: The passowrd to be used for encryption, should be strong.
    /// Minimal length of password is checked.
    pub fn write_to_file(
        seedstore: &SeedStore,
        path_for_secret_file: &str,
        encryption_password: &str,
    ) -> Result<(), String> {
        seedstore.write_to_file(path_for_secret_file, encryption_password)
    }
}

fn process_compute_checksum(entropy: &Vec<u8>) -> Result<u8, String> {
    let entropy_checksum_computed = checksum_of_entropy(&entropy)?;
    Ok(entropy_checksum_computed)
}

fn checksum_of_entropy(entropy: &Vec<u8>) -> Result<u8, String> {
    let mnemo = Mnemonic::from_entropy(entropy)
        .map_err(|e| format!("Could not process entropy {}", e.to_string()))?;
    let checksum = mnemo.checksum();
    Ok(checksum)
}
