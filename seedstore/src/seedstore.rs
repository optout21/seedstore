use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::secp256k1::{All, PublicKey, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network, NetworkKind};
use secretstore::{SecretStore, SecretStoreCreator};
use std::str::FromStr;
use zeroize::Zeroize;

const NONSECRET_DATA_LEN: usize = 4;

/// Store a secret BIP32-style entropy in an encrypted file
/// Can be loaded from an encrypted file.
/// Additionally store a network type byte, and 3 bytes reserved for later use.
/// and an entropy checksum (to be able to avoid using wrong entropy due to wrong password).
/// The secret is stored in memory scrabmled (using an ephemeral scrambling key).
pub struct SeedStore {
    pub(crate) secretstore: SecretStore,
    secp: Secp256k1<All>,
}

/// Helper class for creating the store from given data.
/// Should be used only by the utility that creates the encrypted file.
pub struct SeedStoreCreator {}

/// Various ways to specify a child, e.g. by index or derivation path.
pub enum ChildSpecifier {
    /// Specify by the 4th (last, 'account') index (non-hardened) of the BIP84 derivation path;
    /// corresponds to "m/84'/<net>'/0'/0/<idx>"
    IndexAccount(u32),
    /// Specify by index, specifying the 3rd ('change') and 4th ('account') indices
    /// (non-hardened) of the BIP84 derivation path;
    /// corresponds to "m/84'/<net>'/0'/<idx3>/<idx4>"
    Indices3and4(u32, u32),
    /// Specify by full derivation path (as string), such as "m/84'/0'/0'/1/19"
    Derivation(String),
}

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
        if nonsecret_data.len() != NONSECRET_DATA_LEN {
            return Err(format!(
                "Nonsecret data len should be {} (was {})",
                NONSECRET_DATA_LEN,
                nonsecret_data.len()
            ));
        }
        debug_assert_eq!(nonsecret_data.len(), NONSECRET_DATA_LEN);

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
        debug_assert_eq!(nonsecret_data.len(), NONSECRET_DATA_LEN);
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
    /// Standard level-3 XPub is returned, using standaard BIP84 derivation path (ie. "m/84'/<net>'/0'").
    pub fn get_xpub(&self) -> Result<Xpub, String> {
        let xpub = self
            .secretstore
            .processed_secret_data(|entropy| self.xpub3_from_entropy(entropy))?;
        Ok(xpub)
    }

    /// Return a child address, generated from the secret entropy (and network).
    /// Standard P2WPKH address type is used.
    /// The child can be specified by index or derivation, see [`ChildSpecifier`]
    pub fn get_child_address(&self, child_specifier: &ChildSpecifier) -> Result<String, String> {
        let derivation = child_specifier.derivation_path(self.network())?;
        let pubkey = self
            .secretstore
            .processed_secret_data(|entropy| self.get_child_address_intern(entropy, &derivation))?;
        Ok(pubkey)
    }

    /// Return a child public key, generated from the secret entropy (and network).
    /// The child can be specified by index or derivation, see [`ChildSpecifier`]
    pub fn get_child_public_key(
        &self,
        child_specifier: &ChildSpecifier,
    ) -> Result<PublicKey, String> {
        let derivation = child_specifier.derivation_path(self.network())?;
        let pubkey = self.secretstore.processed_secret_data(|entropy| {
            self.get_child_public_key_intern(entropy, &derivation)
        })?;
        Ok(pubkey)
    }

    /// Return a child PRIVATE key, generated from the secret entropy (and network).
    /// Caution: partial unencrypted secret is returned in copy!
    /// The child can be specified by index or derivation, see [`ChildSpecifier`]
    pub fn get_child_private_key_derivation(
        &self,
        child_specifier: &ChildSpecifier,
    ) -> Result<SecretKey, String> {
        let derivation = child_specifier.derivation_path(self.network())?;
        let privkey = self.secretstore.processed_secret_data(|entropy| {
            self.get_child_private_key_intern(entropy, &derivation)
        })?;
        Ok(privkey)
    }

    /// Caution: secret material is taken, processed and returned
    fn seed_from_entropy(&self, entropy: &Vec<u8>) -> Result<[u8; 64], String> {
        let mut mnemo = Mnemonic::from_entropy(entropy)
            .map_err(|e| format!("Invalid entropy, {} {}", entropy.len(), e.to_string()))?;
        let seed = mnemo.to_seed_normalized("");
        mnemo.zeroize();
        Ok(seed)
    }

    /// Caution: secret material is taken, processed and returned
    fn xpriv3_from_entropy(&self, entropy: &Vec<u8>) -> Result<Xpriv, String> {
        let mut seed = self.seed_from_entropy(entropy)?;
        let xpriv = Xpriv::new_master(
            <Network as Into<NetworkKind>>::into(self.network_as_enum()),
            &seed,
        )
        .map_err(|e| format!("Internal XPriv derivation error {}", e))?;
        let derivation = ChildSpecifier::default_account_derivation_path3(self.network());
        let derivation_path_3 = DerivationPath::from_str(&derivation)
            .map_err(|e| format!("Internal derivation conversion error {}", e))?;
        let xpriv_level_3 = xpriv
            .derive_priv(&self.secp, &derivation_path_3)
            .map_err(|e| format!("Internal XPriv derivation error {}", e))?;
        seed.zeroize();
        Ok(xpriv_level_3)
    }

    /// Caution: secret material is taken and processed
    fn xpub3_from_entropy(&self, entropy: &Vec<u8>) -> Result<Xpub, String> {
        let xpriv_level_3 = self.xpriv3_from_entropy(entropy)?;
        let xpub_level_3 = Xpub::from_priv(&self.secp, &xpriv_level_3);
        Ok(xpub_level_3)
    }

    /// Caution: secret material is taken, processed and returned
    fn get_child_keypair_intern(
        &self,
        entropy: &Vec<u8>,
        derivation: &DerivationPath,
    ) -> Result<Keypair, String> {
        let mut seed = self.seed_from_entropy(entropy)?;
        let xpriv = Xpriv::new_master(
            <Network as Into<NetworkKind>>::into(self.network_as_enum()),
            &seed,
        )
        .map_err(|e| format!("Internal XPriv derivation error {}", e))?;
        let child_xpriv = xpriv
            .derive_priv(&self.secp, &derivation)
            .map_err(|e| format!("Internal XPriv derivation error {}", e))?;
        let keypair = child_xpriv.to_keypair(&self.secp);
        seed.zeroize();
        Ok(keypair)
    }

    /// Caution: secret material is taken and processed
    fn get_child_address_intern(
        &self,
        entropy: &Vec<u8>,
        derivation: &DerivationPath,
    ) -> Result<String, String> {
        let public_key = self
            .get_child_keypair_intern(entropy, &derivation)?
            .public_key();
        let address = Address::p2wpkh(&CompressedPublicKey(public_key), self.network_as_enum());
        Ok(address.to_string())
    }

    /// Caution: secret material is taken and processed
    fn get_child_public_key_intern(
        &self,
        entropy: &Vec<u8>,
        derivation: &DerivationPath,
    ) -> Result<PublicKey, String> {
        let public_key = self
            .get_child_keypair_intern(entropy, derivation)?
            .public_key();
        Ok(public_key)
    }

    /// Caution: secret material is taken, processed and returned
    fn get_child_private_key_intern(
        &self,
        entropy: &Vec<u8>,
        derivation: &DerivationPath,
    ) -> Result<SecretKey, String> {
        let secret_key = self
            .get_child_keypair_intern(entropy, derivation)?
            .secret_key();
        Ok(secret_key)
    }
}

impl Zeroize for SeedStore {
    fn zeroize(&mut self) {
        self.secretstore.zeroize();
        self.secp = Secp256k1::new();
    }
}

impl SeedStoreCreator {
    /// Create a new store instance from given secret entropy bytes and network byte.
    /// The store can be written out to file using [`write_to_file`]
    /// Caution: unencrypted secret data is taken.
    /// `entropy`: the BIP39-style entropy bytes, with one of these lengths:
    ///  16 (12 BIP39 mnemonic words), 20 (15 words), 24 (18 words), 28 bytes (21 words), or 32 bytes (24 words).
    pub fn new_from_data(entropy: &Vec<u8>, network: u8) -> Result<SeedStore, String> {
        // verify entropy length
        let _res = Self::verify_entropy_length(entropy)?;

        // Non-secret data: network byte, and 3 reserved bytes (reserved for later use)
        let nonsecret_data = vec![network, 42, 43, 44];
        debug_assert_eq!(nonsecret_data.len(), NONSECRET_DATA_LEN);

        let secretstore = SecretStoreCreator::new_from_data(nonsecret_data, entropy)?;
        SeedStore::new_from_secretstore(secretstore)
    }

    /// Verify that the entropy is of valid size. Valid sizes:
    ///  16 (12 BIP39 mnemonic words), 20 (15 words), 24 (18 words), 28 bytes (21 words), or 32 bytes (24 words).
    fn verify_entropy_length(entropy: &Vec<u8>) -> Result<(), String> {
        let len = entropy.len();
        if len == 16 || len == 20 || len == 24 || len == 28 || len == 32 {
            Ok(())
        } else {
            Err(format!("Invalid entropy length {}", len))
        }
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

impl ChildSpecifier {
    fn derivation_path(&self, network: u8) -> Result<DerivationPath, String> {
        let derivation_str = match &self {
            Self::Derivation(derivation_str) => derivation_str.clone(),
            Self::Indices3and4(i3, i4) => format!(
                "{}/{}/{}",
                Self::default_account_derivation_path3(network),
                i3,
                i4
            ),
            Self::IndexAccount(i4) => format!(
                "{}/0/{}",
                Self::default_account_derivation_path3(network),
                i4
            ),
        };
        let derivation = DerivationPath::from_str(&derivation_str).map_err(|e| {
            format!(
                "Derivation parsing error {} {}",
                derivation_str,
                e.to_string()
            )
        })?;
        Ok(derivation)
    }

    fn default_account_derivation_path3(network: u8) -> String {
        match network {
            0 => "m/84'/0'/0'".to_string(),
            _ => "m/84'/1'/0'".to_string(),
        }
    }
}

#[allow(unused)]
fn process_compute_checksum(entropy: &Vec<u8>) -> Result<u8, String> {
    let entropy_checksum_computed = checksum_of_entropy(&entropy)?;
    Ok(entropy_checksum_computed)
}

#[allow(unused)]
fn checksum_of_entropy(entropy: &Vec<u8>) -> Result<u8, String> {
    let mnemo = Mnemonic::from_entropy(entropy)
        .map_err(|e| format!("Could not process entropy {}", e.to_string()))?;
    let checksum = mnemo.checksum();
    Ok(checksum)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::bip32::DerivationPath;

    use super::ChildSpecifier;

    #[test]
    fn test_default_path() {
        assert_eq!(
            ChildSpecifier::default_account_derivation_path3(0),
            "m/84'/0'/0'"
        );
        assert_eq!(
            ChildSpecifier::default_account_derivation_path3(1),
            "m/84'/1'/0'"
        );
        assert_eq!(
            ChildSpecifier::default_account_derivation_path3(2),
            "m/84'/1'/0'"
        );
    }

    #[test]
    fn test_derivation() {
        assert_eq!(
            ChildSpecifier::Derivation("m/49'/1'/2'/3/4".to_owned())
                .derivation_path(0)
                .unwrap(),
            DerivationPath::from_str("m/49'/1'/2'/3/4").unwrap()
        );
        assert_eq!(
            ChildSpecifier::Indices3and4(1, 4)
                .derivation_path(0)
                .unwrap(),
            DerivationPath::from_str("m/84'/0'/0'/1/4").unwrap()
        );
        assert_eq!(
            ChildSpecifier::Indices3and4(1, 4)
                .derivation_path(1)
                .unwrap(),
            DerivationPath::from_str("m/84'/1'/0'/1/4").unwrap()
        );
        assert_eq!(
            ChildSpecifier::IndexAccount(66).derivation_path(0).unwrap(),
            DerivationPath::from_str("m/84'/0'/0'/0/66").unwrap()
        );
    }

    #[test]
    fn neg_test_invalid_derivation() {
        assert_eq!(
            ChildSpecifier::Derivation("what//deriv/j9".to_owned())
                .derivation_path(0)
                .err()
                .unwrap(),
            "Derivation parsing error what//deriv/j9 invalid child number format"
        );
    }
}
