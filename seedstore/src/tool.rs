///! Utility tool implementation: tool to create or check an encrypted secret seed file.
use crate::{SeedStore, SeedStoreCreator};
use bip39::Mnemonic;
use std::io::{self, stdout, BufRead, Write};
use std::{fs, str::FromStr};

const DEFAULT_FILE_NAME: &str = "secret.sec";
const DEFAULT_NETWORK: u8 = 0;

#[derive(PartialEq)]
enum Mode {
    /// Create new file
    Set,
    /// Check existing file
    Check,
    /// Help only
    Help,
}

struct Config {
    mode: Mode,
    filename: String,
    network: Option<u8>,
    program_name: String,
    test_canned_input: Vec<String>,
}

/// Utility tool implementation: tool to create or check an encrypted secret seed file.
pub struct SeedStoreTool {
    config: Config,
}

impl Config {
    fn default() -> Self {
        Self {
            mode: Mode::Check,
            filename: DEFAULT_FILE_NAME.to_owned(),
            network: None,
            program_name: "tool".to_owned(),
            test_canned_input: Vec::new(),
        }
    }
}

impl ToString for Config {
    fn to_string(&self) -> std::string::String {
        let mut s = String::with_capacity(200);
        s += &format!("[{}]:  ", self.program_name);
        s += "Mode: ";
        s += match self.mode {
            Mode::Check => "Check only",
            Mode::Set => "Set",
            Mode::Help => "Help only",
        };
        s += &format!("   File: {}", self.filename);
        if let Some(n) = self.network {
            s += &format!("   Network: {}", n);
        }
        s
    }
}

impl SeedStoreTool {
    pub fn new(args: &Vec<String>) -> Result<Self, String> {
        // Process cmd line arguments
        let config = Self::process_args(args)?;

        Ok(Self::new_from_config(config))
    }

    fn new_from_config(config: Config) -> Self {
        Self { config }
    }

    pub fn print_usage(progname: &Option<&String>) {
        let default_progname = "tool".to_owned();
        let progname = progname.unwrap_or(&default_progname);
        println!("{}:  Set or check secret seed file", progname);
        println!("");
        println!(
            "{}  [--help] [--set] [--file <file>] [--signet] [--net <N>]",
            progname
        );
        println!("  --set:         If specified, mnemominc is prompted for, and secret is saved. Secret file must not exist.");
        println!("                 Default is to only check secret file, and print the xpub");
        println!(
            "  --file <file>  Secret file to use, default is {}",
            DEFAULT_FILE_NAME
        );
        println!(
            "  --signet       If specified, assume Signet network. Default is mainnet ({})",
            DEFAULT_NETWORK
        );
        println!(
            "  --net <N>      Network byte. Default is mainnet ({})",
            DEFAULT_NETWORK
        );
        println!("  --help         Print usage (this)");
        println!("");
    }

    fn process_args(args: &Vec<String>) -> Result<Config, String> {
        let mut config = Config::default();
        let len = args.len();
        if len < 1 {
            return Err("Internal arg error, progname missing".to_owned());
        }
        debug_assert!(len >= 1);
        config.program_name = args[0].clone();
        let mut i = 1;
        while i < len {
            let a = &args[i];
            if *a == "--set" {
                config.mode = Mode::Set;
            } else if *a == "--file" {
                if i + 1 < len {
                    config.filename = args[i + 1].clone();
                    i += 1;
                } else {
                    return Err("--file requires a <file> argument".to_owned());
                }
            } else if *a == "--signet" {
                config.network = Some(3);
            } else if *a == "--net" {
                if i + 1 < len {
                    match args[i + 1].parse::<u8>() {
                        Err(e) => {
                            return Err(format!("--net requires a numerical <N> argument, {}", e)
                                .to_string())
                        }
                        Ok(n) => config.network = Some(n),
                    }
                    i += 1;
                } else {
                    return Err("--net requires an argument".to_owned());
                }
            } else if *a == "--help" {
                config.mode = Mode::Help;
            } else {
                return Err(format!("Unknown argument {}", a));
            }
            i += 1;
        }

        if config.network.is_some() && config.mode != Mode::Set {
            return Err("Network should be specified only in Set mode".to_owned());
        }

        Ok(config)
    }

    pub fn run(args: &Vec<String>) {
        match Self::new(&args) {
            Err(err) => {
                println!("Error processing arguments! {}", err);
                Self::print_usage(&args.get(0));
            }
            Ok(mut tool) => match tool.execute() {
                Err(err) => println!("ERROR: {}", err),
                Ok(_) => {
                    println!("Done.");
                }
            },
        }
    }

    /// Return XPub (for testing)
    pub fn execute(&mut self) -> Result<String, String> {
        println!("{}", self.config.to_string());

        match self.config.mode {
            Mode::Set => self.do_set(),
            Mode::Check => self.do_check(),
            Mode::Help => {
                Self::print_usage(&Some(&self.config.program_name));
                Ok("".to_owned())
            }
        }
    }

    /// Perform Set file operation
    /// Return XPub (for testing)
    fn do_set(&mut self) -> Result<String, String> {
        let exists = fs::exists(&self.config.filename).unwrap_or(true);
        if exists {
            return Err(format!(
                "File already exists, won't overwrite, aborting {}",
                self.config.filename
            ));
        }

        let mnemonic_str = self.read_mnemonic()?;
        let mnemonic = Mnemonic::from_str(&mnemonic_str)
            .map_err(|e| format!("Invalid mnemonic {}", e.to_string()))?;
        let entropy = mnemonic.to_entropy();
        println!("Seedphrase entered, seems OK");

        let password = self.read_password()?;

        let passphrase = self.read_passphrase_if_needed(&password)?;

        let seedstore = SeedStoreCreator::new_from_data(
            &entropy,
            self.config.network.unwrap_or_default(),
            Some(&passphrase),
        )
        .map_err(|e| format!("Could not encrypt secret, {}", e))?;

        let xpub = self.print_info(&seedstore)?;

        let _res = SeedStoreCreator::write_to_file(&seedstore, &self.config.filename, &password)
            .map_err(|e| format!("Could not write secret file, {}", e))?;

        println!("Seed written to encrypted file: {}", self.config.filename);

        Ok(xpub)
    }

    fn next_canned_input(&mut self) -> Option<String> {
        if self.config.test_canned_input.is_empty() {
            return None;
        }
        debug_assert!(self.config.test_canned_input.len() >= 1);
        let next = self.config.test_canned_input.remove(0);
        println!("Using canned input '{}'", next);
        Some(next)
    }

    fn read_no_echo(&mut self, item_name: &str, prompt: &str) -> Result<String, String> {
        if let Some(canned_input) = self.next_canned_input() {
            return Ok(canned_input);
        }
        let result = rpassword::prompt_password(prompt)
            .map_err(|e| format!("Error reading {}, {}", item_name, e.to_string()))?;
        Ok(result)
    }

    fn read_password(&mut self) -> Result<String, String> {
        let password1 = self.read_no_echo("password", "Enter the encryption password: ")?;
        let password2 = self.read_no_echo("password", "Repeat the encryption password: ")?;
        if password1 != password2 {
            return Err("The two passwords don't match".to_owned());
        }
        println!("Passwords entered, match OK");
        debug_assert_eq!(password1, password2);
        Ok(password1)
    }

    fn read_mnemonic(&mut self) -> Result<String, String> {
        let mnemonic = self.read_no_echo(
            "mnemonic",
            "Enter the seedphrase (mnemonic) words (input is hidden): ",
        )?;
        Ok(mnemonic)
    }

    fn read_line(&mut self) -> String {
        if let Some(canned_input) = self.next_canned_input() {
            return canned_input;
        }
        let stdin = io::stdin();
        let mut iterator = stdin.lock().lines();
        let line1 = iterator.next().unwrap().unwrap_or_default();
        line1
    }

    fn read_passphrase(&mut self) -> Result<String, String> {
        let passphrase1 = self.read_no_echo("passphrase", "Enter the seed passphrase: ")?;
        let passphrase2 = self.read_no_echo("passphrase", "Repeat the seed passphrase: ")?;
        if passphrase1 != passphrase2 {
            return Err("The two passphrase don't match".to_owned());
        }
        println!("Passphrases entered, match OK");
        debug_assert_eq!(passphrase1, passphrase2);
        Ok(passphrase1)
    }

    fn read_passphrase_if_needed(
        &mut self,
        encryption_password: &String,
    ) -> Result<String, String> {
        println!("Optionally, a seed passphrase can be used. Please choose:");
        println!("  Enter or 0 : no passphrase");
        println!("  1          : enter a passphrase");
        println!("  2          : use the encryption password as passphrase too");
        loop {
            print!("Enter your choice: ");
            let _res = stdout().flush();
            let resp = self.read_line();
            match resp.as_str() {
                "" | "0" => return Ok("".to_string()),
                "1" => {
                    let passphrase = self.read_passphrase()?;
                    return Ok(passphrase);
                }
                "2" => return Ok(encryption_password.clone()),
                _ => {}
            }
        }
    }

    /// Print out info from the seedstore
    /// Return XPub (for testing)
    fn print_info(&self, seedstore: &SeedStore) -> Result<String, String> {
        let xpub = seedstore.get_xpub()?.to_string();
        let child_spec0 = crate::ChildSpecifier::Index4(0);
        let address0 = seedstore.get_child_address(&child_spec0)?;
        let pubkey0 = seedstore.get_child_public_key(&child_spec0)?.to_string();

        let network = seedstore.network();
        let derivation = child_spec0.derivation_path(network)?.to_string();
        println!(
            "XPUB, first address, and public key (network {}, derivation {}):",
            network, derivation
        );
        println!("  {}", xpub);
        println!("  {}", address0);
        println!("  {}", pubkey0);
        println!("");

        Ok(xpub)
    }

    /// Return XPub (for testing)
    fn do_check(&mut self) -> Result<String, String> {
        let exists = fs::exists(&self.config.filename).unwrap_or(false);
        if !exists {
            return Err(format!(
                "Could not find secret file {}",
                self.config.filename
            ));
        }

        let password = self.read_password()?;

        let passphrase = self.read_passphrase_if_needed(&password)?;

        let seedstore =
            SeedStore::new_from_encrypted_file(&self.config.filename, &password, Some(&passphrase))
                .map_err(|e| format!("Could not read secret file, {}", e))?;

        println!("");
        println!(
            "Seed has been read from secret file {}",
            self.config.filename
        );

        let xpub = self.print_info(&seedstore)?;

        Ok(xpub)
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, Mode, SeedStore, SeedStoreTool};
    use hex_conservative::FromHex;
    use rand::Rng;
    use std::env::temp_dir;
    use std::fs;

    const PAYLOAD_V1_EV2_SCRYPT: &str = "53530104002a2b2c020ee3d3970706fbe9f680eb68763af3c849100010907fc4f2740c7613422df300488137c1e6af59";
    const PASSWORD1: &str = "password";
    const XPUB1: &str = "xpub6CDDB17Xj7pDDWedpLsED1JbPPQmyuapHmAzQEEs2P57hciCjwQ3ov7TfGsTZftAM2gVdPzE55L6gUvHguwWjY82518zw1Z3VbDeWgx3Jqs";
    const MNEMO1: &str = "oil oil oil oil oil oil oil oil oil oil oil oil";

    fn get_temp_file_name() -> String {
        format!(
            "{}/_seedstore_tempfile_{}_.tmp",
            temp_dir().to_str().unwrap(),
            rand::rng().random::<u32>()
        )
    }

    #[test]
    fn check() {
        let temp_file = get_temp_file_name();
        let payload = Vec::from_hex(PAYLOAD_V1_EV2_SCRYPT).unwrap();
        let _res = fs::write(&temp_file, &payload).unwrap();

        let config = Config {
            mode: Mode::Check,
            filename: temp_file.clone(),
            network: None,
            program_name: "tool".to_owned(),
            test_canned_input: vec![
                PASSWORD1.to_owned(), // encryption password
                PASSWORD1.to_owned(), // repeat encryption password
                "".to_owned(),        // passphrase
            ],
        };
        let mut tool = SeedStoreTool::new_from_config(config);

        let xpub = tool.execute().unwrap();

        assert_eq!(xpub.to_string(), XPUB1);

        let _res = fs::remove_file(&temp_file);
    }

    #[test]
    fn set() {
        let temp_file = get_temp_file_name();

        let network = 3;
        let config = Config {
            mode: Mode::Set,
            filename: temp_file.clone(),
            network: Some(network),
            program_name: "tool".to_owned(),
            test_canned_input: vec![
                MNEMO1.to_owned(),    // mnemonic
                PASSWORD1.to_owned(), // encryption password
                PASSWORD1.to_owned(), // repeat encryption password
                "".to_owned(),        // passphrase
            ],
        };
        let mut tool = SeedStoreTool::new_from_config(config);

        let xpub = tool.execute().unwrap();

        assert_eq!(xpub.to_string(), "tpubDCRo9GmRAvEWANJ5iSfMEqPoq3uYvjBPAAjrDj5iQMxAq7DCs5orw7m9xJes8hWYAwKuH3T63WrKfzzw7g9ucbjq4LUu5cgCLUPMN7gUkrL");

        // Read back the file
        {
            let store = SeedStore::new_from_encrypted_file(&temp_file, PASSWORD1, None).unwrap();

            assert_eq!(store.network(), network);
            assert_eq!(store.get_xpub().unwrap().to_string(), "tpubDCRo9GmRAvEWANJ5iSfMEqPoq3uYvjBPAAjrDj5iQMxAq7DCs5orw7m9xJes8hWYAwKuH3T63WrKfzzw7g9ucbjq4LUu5cgCLUPMN7gUkrL");
            drop(store);
        }

        let _res = fs::remove_file(&temp_file);
    }

    #[test]
    fn neg_set_pw_dont_match() {
        let temp_file = get_temp_file_name();

        let config = Config {
            mode: Mode::Set,
            filename: temp_file,
            network: Some(0),
            program_name: "tool".to_owned(),
            test_canned_input: vec![
                MNEMO1.to_owned(),      // mnemonic
                "password".to_owned(),  // encryption password
                "passsword".to_owned(), // repeat encryption password
            ],
        };
        let mut tool = SeedStoreTool::new_from_config(config);

        let res = tool.execute();
        assert_eq!(res.err().unwrap(), "The two passwords don't match");
    }
}
