// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the  MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// You may not use this file except in accordance with the license.

use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{All, Message, PublicKey, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network, NetworkKind};
use secretstore::{Options, SecretStore, SecretStoreCreator};
use std::str::FromStr;
use zeroize::{Zeroize, ZeroizeOnDrop};

const NONSECRET_DATA_LEN: usize = 4;

/// Store a secret BIP32-style entropy in an encrypted file.
/// Can be loaded from an encrypted file.
/// Additionally store a network type byte, and 3 bytes reserved for later use.
///
/// The secret is stored in memory scrambled (using an ephemeral scrambling key).
/// A seed passphrase can be used optionally, but it is not stored in the encrypted file,
/// it has to be provided when the file is read. Internally it is stored scrambled.
///
/// See also [`SeedStoreCreator`], [`super::KeyStore`].
pub struct SeedStore {
    secretstore: SecretStore,
    /// Optional seed passphrase, stored as scrambled bytes (normalized UTF).
    scrambled_optional_passphrase: Vec<u8>,
    secp: Secp256k1<All>,
}

/// Helper class for creating the store from given data.
/// Should be used only by the utility that creates the encrypted file.
/// See also [`SeedStore`].
pub struct SeedStoreCreator {}

/// Various ways to specify a child key, e.g. by index or derivation path.
pub enum ChildSpecifier {
    /// Specify by the 4th (last, 'address_index') index (non-hardened) of the BIP84 derivation path;
    /// corresponds to "m/84'/<net>'/0'/0/<idx>"
    Index4(u32),
    /// Specify by index, specifying the 3rd ('change') and 4th ('address_index') indices
    /// (non-hardened) of the BIP84 derivation path;
    /// corresponds to "m/84'/<net>'/0'/<idx3>/<idx4>"
    ChangeAndIndex34(u32, u32),
    /// Specify by full derivation path (as string), such as "m/84'/0'/0'/1/19"
    Derivation(String),
}

impl SeedStore {
    /// Load the secret from a password-protected secret file.
    /// `seed_passphrase`: Optional seed passphrase, needed to get the correct seed from the entropy (if it was used).
    pub fn new_from_encrypted_file(
        path_for_secret_file: &str,
        encryption_password: &str,
        seed_passphrase: Option<&str>,
    ) -> Result<Self, String> {
        let secretstore =
            SecretStore::new_from_encrypted_file(path_for_secret_file, encryption_password)?;
        Self::new_from_secretstore(secretstore, seed_passphrase)
    }

    /// Load the secret store from encrypted data.
    /// Typically the data is stored in a file, but this method takes the contents directly.
    /// `seed_passphrase`: Optional seed passphrase, needed to get the correct seed from the entropy (if it was used).
    pub fn new_from_payload(
        secret_payload: &Vec<u8>,
        encryption_password: &str,
        seed_passphrase: Option<&str>,
    ) -> Result<Self, String> {
        let secretstore = SecretStore::new_from_payload(secret_payload, encryption_password)?;
        Self::new_from_secretstore(secretstore, seed_passphrase)
    }

    /// Create new instance from secret store, and passphrase.
    /// `seed_passphrase`: Optional seed passphrase, needed to get the correct seed from the entropy (if it was used).
    fn new_from_secretstore(
        secretstore: SecretStore,
        seed_passphrase: Option<&str>,
    ) -> Result<Self, String> {
        let nonsecret_data = secretstore.nonsecret_data();
        if nonsecret_data.len() != NONSECRET_DATA_LEN {
            return Err(format!(
                "Nonsecret data len should be {} (was {})",
                NONSECRET_DATA_LEN,
                nonsecret_data.len()
            ));
        }
        debug_assert_eq!(nonsecret_data.len(), NONSECRET_DATA_LEN);

        let scrambled_optional_passphrase = match seed_passphrase {
            None => Vec::new(),
            Some(passphrase) => {
                let mut bytes = passphrase.as_bytes().to_vec();
                let _res = secretstore.scramble_data(&mut bytes)?;
                bytes
            }
        };

        Ok(SeedStore {
            secretstore,
            scrambled_optional_passphrase,
            secp: Secp256k1::new(),
        })
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

    /// Accessor for network.
    pub fn network(&self) -> Network {
        Self::network_byte_to_enum(self.network_as_u8())
    }

    /// Accessor for network, as byte.
    pub fn network_as_u8(&self) -> u8 {
        let nonsecret_data = self.secretstore.nonsecret_data();
        debug_assert_eq!(nonsecret_data.len(), NONSECRET_DATA_LEN);
        nonsecret_data[0]
    }

    /// Convert network byte to [`bitcoin::network::Network`].
    pub fn network_byte_to_enum(network: u8) -> Network {
        match network {
            0 => Network::Bitcoin,
            1 => Network::Testnet,
            2 => Network::Testnet4,
            3 => Network::Signet,
            4 => Network::Regtest,
            _ => Network::Bitcoin,
        }
    }

    /// Convert [`bitcoin::network::Network`] to network byte.
    pub fn network_enum_as_byte(network_enum: Network) -> u8 {
        match network_enum {
            Network::Bitcoin => 0,
            Network::Testnet => 1,
            Network::Testnet4 => 2,
            Network::Signet => 3,
            Network::Regtest => 4,
            _ => 0,
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
    /// CAUTION: partial unencrypted secret is returned in copy!
    /// The child can be specified by index or derivation, see [`ChildSpecifier`]
    #[cfg(feature = "accesssecret")]
    pub fn get_secret_child_private_key(
        &self,
        child_specifier: &ChildSpecifier,
    ) -> Result<SecretKey, String> {
        self.get_secret_child_private_key_nonpub(child_specifier)
    }

    /// Return a child PRIVATE key, generated from the secret entropy (and network).
    /// CAUTION: partial unencrypted secret is returned in copy!
    fn get_secret_child_private_key_nonpub(
        &self,
        child_specifier: &ChildSpecifier,
    ) -> Result<SecretKey, String> {
        let derivation = child_specifier.derivation_path(self.network())?;
        let privkey = self.secretstore.processed_secret_data(|entropy| {
            self.get_secret_child_private_key_intern(entropy, &derivation)
        })?;
        Ok(privkey)
    }

    /// Return the full BIP39 secret mnemonic (corresponding to the entropy and network).
    /// CAUTION: unencrypted secret is returned in copy!
    #[cfg(feature = "accesssecret")]
    pub fn get_secret_mnemonic(&self) -> Result<String, String> {
        let mnemonic = self
            .secretstore
            .processed_secret_data(|entropy| self.get_secret_mnemonic_intern(entropy))?;
        Ok(mnemonic)
    }

    fn seed_from_entropy(&self, entropy: &Vec<u8>) -> Result<[u8; 64], String> {
        let mut mnemo = Mnemonic::from_entropy(entropy)
            .map_err(|e| format!("Invalid entropy, {} {}", entropy.len(), e.to_string()))?;
        let mut passphrase = self.unscambled_passphrase()?;
        let seed = mnemo.to_seed_normalized(&passphrase);
        mnemo.zeroize();
        drop(mnemo);
        passphrase.zeroize();
        drop(passphrase);
        Ok(seed)
    }

    /// Return the unscrambled passphrase as string, or empty string if none is used.
    /// Caution: unencrypted partial data is returned.
    fn unscambled_passphrase(&self) -> Result<String, String> {
        if self.scrambled_optional_passphrase.is_empty() {
            return Ok(String::new());
        }
        // there is a passphrase
        let mut bytes = self.scrambled_optional_passphrase.clone();
        let _res = self.secretstore.descramble_data(&mut bytes)?;
        let passphrase = String::from_utf8(bytes)
            .map_err(|e| format!("Passphrase processing error {}", e.to_string()))?;
        Ok(passphrase)
    }

    /// Caution: secret material is taken, processed and returned
    fn xpriv3_from_entropy(&self, entropy: &Vec<u8>) -> Result<Xpriv, String> {
        let mut seed = self.seed_from_entropy(entropy)?;
        let xpriv = Xpriv::new_master(<Network as Into<NetworkKind>>::into(self.network()), &seed)
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
    fn get_secret_child_keypair_intern(
        &self,
        entropy: &Vec<u8>,
        derivation: &DerivationPath,
    ) -> Result<Keypair, String> {
        let mut seed = self.seed_from_entropy(entropy)?;
        let xpriv = Xpriv::new_master(<Network as Into<NetworkKind>>::into(self.network()), &seed)
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
        let public_key = self.get_child_public_key_intern(entropy, derivation)?;
        let address = Address::p2wpkh(&CompressedPublicKey(public_key), self.network());
        Ok(address.to_string())
    }

    /// Caution: secret material is taken and processed
    fn get_child_public_key_intern(
        &self,
        entropy: &Vec<u8>,
        derivation: &DerivationPath,
    ) -> Result<PublicKey, String> {
        let public_key = self
            .get_secret_child_keypair_intern(entropy, derivation)?
            .public_key();
        Ok(public_key)
    }

    /// Caution: secret material is taken, processed and returned
    fn get_secret_child_private_key_intern(
        &self,
        entropy: &Vec<u8>,
        derivation: &DerivationPath,
    ) -> Result<SecretKey, String> {
        let secret_key = self
            .get_secret_child_keypair_intern(entropy, derivation)?
            .secret_key();
        Ok(secret_key)
    }

    /// Caution: secret material is taken, processed and returned
    #[cfg(feature = "accesssecret")]
    fn get_secret_mnemonic_intern(&self, entropy: &Vec<u8>) -> Result<String, String> {
        let mnemonic = Mnemonic::from_entropy(entropy).map_err(|e| e.to_string())?;
        Ok(mnemonic.to_string())
    }

    /// Sign using a child private key. Use ECDSA signature as it is used in bitcoin.
    /// The child can be specified by index or derivation, see [`ChildSpecifier`].
    /// A 32-byte digest (hash) is signed.
    /// The signer public key has to be provided as well, to be able to check the signer key
    /// (can be obtained using [`get_child_public_key`]).
    /// Caution: secret material is processed internally
    pub fn sign_hash_with_child_private_key_ecdsa(
        &self,
        child_specifier: &ChildSpecifier,
        hash: &[u8; 32],
        signer_public_key: &PublicKey,
    ) -> Result<Signature, String> {
        let private_key = self.get_secret_child_private_key_nonpub(child_specifier)?;
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

    /// Validate if an encryption password is acceptable (strong enough)
    pub fn validate_password(encryption_password: &str) -> Result<(), String> {
        SecretStore::validate_password(encryption_password)
    }
}

impl Zeroize for SeedStore {
    fn zeroize(&mut self) {
        self.secretstore.zeroize();
        self.scrambled_optional_passphrase.zeroize();
        self.secp = Secp256k1::new();
    }
}

impl ZeroizeOnDrop for SeedStore {}

impl SeedStoreCreator {
    /// Create a new store instance from given secret entropy bytes and network byte.
    /// The store can be written out to file using [`write_to_file`]
    /// Caution: unencrypted secret data is taken.
    /// `entropy`: the BIP39-style entropy bytes, with one of these lengths:
    ///  16 (12 BIP39 mnemonic words), 20 (15 words), 24 (18 words), 28 bytes (21 words), or 32 bytes (24 words).
    /// - network: Optionally a different bitcoin network can be specified, default is Mainnet/0 (also for None).
    /// `seed_passphrase`: Optional seed passphrase, needed to get the correct seed from the entropy (if it was used).
    pub fn new_from_data(
        entropy: &Vec<u8>,
        network: Option<Network>,
        seed_passphrase: Option<&str>,
    ) -> Result<SeedStore, String> {
        // verify entropy length
        let _res = Self::verify_entropy_length(entropy)?;

        // Non-secret data: network byte, and 3 reserved bytes (reserved for later use)
        let network_byte = SeedStore::network_enum_as_byte(network.unwrap_or(Network::Bitcoin));
        let nonsecret_data = vec![network_byte, 42, 43, 44];
        debug_assert_eq!(nonsecret_data.len(), NONSECRET_DATA_LEN);

        let secretstore = SecretStoreCreator::new_from_data(nonsecret_data, entropy)?;
        SeedStore::new_from_secretstore(secretstore, seed_passphrase)
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
        options: Option<Options>,
    ) -> Result<(), String> {
        seedstore.write_to_file(path_for_secret_file, encryption_password, options)
    }
}

impl ChildSpecifier {
    pub fn derivation_path(&self, network: Network) -> Result<DerivationPath, String> {
        let derivation_str = match &self {
            Self::Derivation(derivation_str) => derivation_str.clone(),
            Self::ChangeAndIndex34(i3, i4) => format!(
                "{}/{}/{}",
                Self::default_account_derivation_path3(network),
                i3,
                i4
            ),
            Self::Index4(i4) => format!(
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

    fn default_account_derivation_path3(network: Network) -> String {
        match network {
            Network::Bitcoin => "m/84'/0'/0'".to_string(),
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
    use bitcoin::Network;

    use super::ChildSpecifier;

    #[test]
    fn test_default_path() {
        assert_eq!(
            ChildSpecifier::default_account_derivation_path3(Network::Bitcoin),
            "m/84'/0'/0'"
        );
        assert_eq!(
            ChildSpecifier::default_account_derivation_path3(Network::Signet),
            "m/84'/1'/0'"
        );
        assert_eq!(
            ChildSpecifier::default_account_derivation_path3(Network::Testnet4),
            "m/84'/1'/0'"
        );
    }

    #[test]
    fn test_derivation() {
        assert_eq!(
            ChildSpecifier::Derivation("m/49'/1'/2'/3/4".to_owned())
                .derivation_path(Network::Bitcoin)
                .unwrap(),
            DerivationPath::from_str("m/49'/1'/2'/3/4").unwrap()
        );
        assert_eq!(
            ChildSpecifier::ChangeAndIndex34(1, 4)
                .derivation_path(Network::Bitcoin)
                .unwrap(),
            DerivationPath::from_str("m/84'/0'/0'/1/4").unwrap()
        );
        assert_eq!(
            ChildSpecifier::ChangeAndIndex34(1, 4)
                .derivation_path(Network::Testnet)
                .unwrap(),
            DerivationPath::from_str("m/84'/1'/0'/1/4").unwrap()
        );
        assert_eq!(
            ChildSpecifier::Index4(66)
                .derivation_path(Network::Bitcoin)
                .unwrap(),
            DerivationPath::from_str("m/84'/0'/0'/0/66").unwrap()
        );
    }

    #[test]
    fn neg_test_invalid_derivation() {
        assert_eq!(
            ChildSpecifier::Derivation("what//deriv/j9".to_owned())
                .derivation_path(Network::Bitcoin)
                .err()
                .unwrap(),
            "Derivation parsing error what//deriv/j9 invalid child number format"
        );
    }
}
