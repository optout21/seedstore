use seedstore::SeedStoreCreator;
use std::env::temp_dir;
use zeroize::Zeroize;

fn main() -> Result<(), String> {
    // Create a new secret file with provided secret data

    let network = 0;
    // Entropy corresponding to a 12-word BIP39 mnemonic, dummy data
    let dummy_entropy = [42; 16].to_vec();

    let user_password = "SecretStrongPasswordVDSVEWFVFDHHEBNJS36DFH";
    let path_for_secret_file = format!("{}/sample.secret", temp_dir().to_str().unwrap());

    let mut seedstore = SeedStoreCreator::new_from_data(&dummy_entropy, network, None)?;
    let _res = SeedStoreCreator::write_to_file(&seedstore, &path_for_secret_file, user_password)?;
    println!("Secret entropy written to file {}", path_for_secret_file);

    seedstore.zeroize();

    Ok(())
}
