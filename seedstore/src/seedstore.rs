use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::secp256k1::{All, PublicKey, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network, NetworkKind};
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
    /// Standard level-3 XPub is returned, using standaard BIP84 derivation path (ie. "m/84'/x'/0'").
    pub fn get_xpub(&self) -> Result<Xpub, String> {
        let xpub = self
            .secretstore
            .processed_secret_data(|entropy| self.xpub3_from_entropy(entropy))?;
        Ok(xpub)
    }

    /// Return a child address, generated from the secret entropy (and network).
    /// Standard P2WPKH address type is used.
    /// Standard BIP84 derivation path is used, with the last two indices provided.
    /// [`index4`] The but-last index (4th, change) of the derivation path, usually 0.
    /// [`index5`] The last index (5th, account) of the derivation path.
    pub fn get_child_address(&self, index4: u32, index5: u32) -> Result<String, String> {
        let derivation = format!(
            "{}/{}/{}",
            self.default_account_derivation_path(),
            index4,
            index5
        );
        self.get_child_address_derivation(&derivation)
    }

    /// Return a child address with arbitrary derivation,
    /// generated from the secret entropy (and network).
    /// Standard P2WPKH address type is used.
    /// [`derivation`] The derivation path to use, eg. "m/84'/0'/0'/0/11"
    pub fn get_child_address_derivation(&self, derivation: &str) -> Result<String, String> {
        let pubkey = self
            .secretstore
            .processed_secret_data(|entropy| self.get_child_address_intern(entropy, derivation))?;
        Ok(pubkey)
    }

    /// Return a child public key, generated from the secret entropy (and network).
    /// Standard BIP84 derivation path is used, with the last two indices provided.
    /// [`index4`] The but-last index (4th, change) of the derivation path, usually 0.
    /// [`index5`] The last index (5th, account) of the derivation path.
    pub fn get_child_public_key(&self, index4: u32, index5: u32) -> Result<PublicKey, String> {
        let derivation = format!(
            "{}/{}/{}",
            self.default_account_derivation_path(),
            index4,
            index5
        );
        self.get_child_public_key_derivation(&derivation)
    }

    /// Return a child public key with arbitrary derivation, generated from the secret entropy (and network).
    /// [`derivation`] The derivation path to use, eg. "m/84'/0'/0'/0/11"
    pub fn get_child_public_key_derivation(&self, derivation: &str) -> Result<PublicKey, String> {
        let pubkey = self.secretstore.processed_secret_data(|entropy| {
            self.get_child_public_key_intern(entropy, derivation)
        })?;
        Ok(pubkey)
    }

    /// Return a child PRIVATE key, generated from the secret entropy (and network).
    /// Caution: partial unencrypted secret is returned in copy!
    /// [`derivation`] The derivation path to use, eg. "m/84'/0'/0'/0/11"
    pub fn get_child_private_key_derivation(&self, derivation: &str) -> Result<SecretKey, String> {
        let privkey = self.secretstore.processed_secret_data(|entropy| {
            self.get_child_private_key_intern(entropy, derivation)
        })?;
        Ok(privkey)
    }

    fn default_account_derivation_path(&self) -> String {
        match self.network() {
            0 => "m/84'/0'/0'".to_string(),
            _ => "m/84'/1'/0'".to_string(),
        }
    }

    fn seed_from_entropy(&self, entropy: &Vec<u8>) -> Result<[u8; 64], String> {
        let mnemo = Mnemonic::from_entropy(entropy)
            .map_err(|e| format!("Could not process entropy {}", e.to_string()))?;
        let seed = mnemo.to_seed_normalized("");
        Ok(seed)
    }

    fn xpriv3_from_entropy(&self, entropy: &Vec<u8>) -> Result<Xpriv, String> {
        let seed = self.seed_from_entropy(entropy)?;
        let xpriv = Xpriv::new_master(
            <Network as Into<NetworkKind>>::into(self.network_as_enum()),
            &seed,
        )
        .map_err(|e| format!("Internal XPriv derivation error {}", e))?;
        let derivation = self.default_account_derivation_path();
        let derivation_path_3 = DerivationPath::from_str(&derivation)
            .map_err(|e| format!("Internal derivation conversion error {}", e))?;
        let xpriv_level_3 = xpriv
            .derive_priv(&self.secp, &derivation_path_3)
            .map_err(|e| format!("Internal XPriv derivation error {}", e))?;
        Ok(xpriv_level_3)
    }

    fn xpub3_from_entropy(&self, entropy: &Vec<u8>) -> Result<Xpub, String> {
        let xpriv_level_3 = self.xpriv3_from_entropy(entropy)?;
        let xpub_level_3 = Xpub::from_priv(&self.secp, &xpriv_level_3);
        Ok(xpub_level_3)
    }

    fn get_child_keypair_intern(
        &self,
        entropy: &Vec<u8>,
        derivation_path: &str,
    ) -> Result<Keypair, String> {
        let seed = self.seed_from_entropy(entropy)?;
        let xpriv = Xpriv::new_master(
            <Network as Into<NetworkKind>>::into(self.network_as_enum()),
            &seed,
        )
        .map_err(|e| format!("Internal XPriv derivation error {}", e))?;
        let derivation = DerivationPath::from_str(&derivation_path)
            .map_err(|e| format!("Internal derivation conversion error {}", e))?;
        let child_xpriv = xpriv
            .derive_priv(&self.secp, &derivation)
            .map_err(|e| format!("Internal XPriv derivation error {}", e))?;
        let keypair = child_xpriv.to_keypair(&self.secp);
        Ok(keypair)
    }

    fn get_child_address_intern(
        &self,
        entropy: &Vec<u8>,
        derivation: &str,
    ) -> Result<String, String> {
        let public_key = self
            .get_child_keypair_intern(entropy, &derivation)?
            .public_key();
        let address = Address::p2wpkh(&CompressedPublicKey(public_key), self.network_as_enum());
        Ok(address.to_string())
    }

    fn get_child_public_key_intern(
        &self,
        entropy: &Vec<u8>,
        derivation: &str,
    ) -> Result<PublicKey, String> {
        let public_key = self
            .get_child_keypair_intern(entropy, &derivation)?
            .public_key();
        Ok(public_key)
    }

    fn get_child_private_key_intern(
        &self,
        entropy: &Vec<u8>,
        derivation: &str,
    ) -> Result<SecretKey, String> {
        let secret_key = self
            .get_child_keypair_intern(entropy, &derivation)?
            .secret_key();
        Ok(secret_key)
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
