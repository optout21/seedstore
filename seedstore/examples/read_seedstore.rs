use seedstore::SeedStore;
use std::env::temp_dir;
use zeroize::Zeroize;

fn main() -> Result<(), String> {
    // Read secret from secret file. It assumes the file exists, see [`create_seedstore`]

    let user_password = "SecretStrongPasswordVDSVEWFVFDHHEBNJS36DFH";
    let path_for_secret_file = format!("{}/sample.secret", temp_dir().to_str().unwrap());

    match SeedStore::new_from_encrypted_file(&path_for_secret_file, user_password, None) {
        Err(e) => {
            eprintln!("Could not read from secret file, {}", e);
        }
        Ok(ref mut seedstore) => {
            println!("Secret loaded from file ({})", path_for_secret_file);

            let xpub = seedstore.get_xpub().unwrap();
            let network = seedstore.network();

            println!("XPUB:     {}", xpub);
            println!("Network:  {}", network);

            seedstore.zeroize();
        }
    };
    Ok(())
}
