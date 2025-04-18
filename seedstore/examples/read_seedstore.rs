use seedstore::SeedStore;
use std::env::temp_dir;

fn main() -> Result<(), String> {
    // Read secret from secret file. It assumes the file exists, see [`create_seedstore`]

    let user_password = "SecretPassword";
    let path_for_secret_file = format!("{}/sample.secret", temp_dir().to_str().unwrap());

    match SeedStore::new_from_encrypted_file(&path_for_secret_file, user_password) {
        Ok(seedstore) => {
            println!("Secret loaded from file ({})", path_for_secret_file);

            let network = seedstore.network();
            let xpub = seedstore.get_xpub().unwrap();

            println!("Network:  {}", network);
            println!("XPUB:     {}", xpub);
        }
        Err(e) => {
            eprintln!("Could not read from secret file, {}", e);
        }
    };
    Ok(())
}
