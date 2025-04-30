///! Utility tool implementation: tool to create or check an encrypted secret seed file.
use crate::{SeedStore, SeedStoreCreator};
use bip39::Mnemonic;
use std::{fs, str::FromStr};

const DEFAULT_FILE_NAME: &str = "secret.sec";
const DEFAULT_NETWORK: u8 = 0;

#[derive(PartialEq)]
enum Mode {
    /// Create new file
    Set,
    /// Check existing file
    Check,
}

struct Config {
    mode: Mode,
    filename: String,
    network: Option<u8>,
    program_name: String,
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

        Ok(Self { config })
    }

    pub fn print_usage(progname: &Option<&String>) {
        let default_progname = "tool".to_owned();
        let progname = progname.unwrap_or(&default_progname);
        println!("{}:  Set or check secret seed file", progname);
        println!("");
        println!(
            "{}  [--set] [--file <file>] [--signet] [--net <N>]",
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
            } else {
                return Err(format!("Unknown argument {}", a));
            }
            i += 1;
        }

        if config.mode == Mode::Check && config.network.is_some() {
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

    pub fn execute(&mut self) -> Result<(), String> {
        println!("{}", self.config.to_string());

        match self.config.mode {
            Mode::Set => self.do_set(),
            Mode::Check => self.do_check(),
        }
    }

    fn do_set(&self) -> Result<(), String> {
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

        let password = self.read_password()?;

        let seedstore =
            SeedStoreCreator::new_from_data(&entropy, self.config.network.unwrap_or_default())
                .map_err(|e| format!("Could not encrypt secret, {}", e))?;

        let _res = SeedStoreCreator::write_to_file(&seedstore, &self.config.filename, &password)
            .map_err(|e| format!("Could not write secret file, {}", e))?;

        println!("Seed written to encrypted file: {}", self.config.filename);

        Ok(())
    }

    fn read_password(&self) -> Result<String, String> {
        let password = "password".to_owned(); // TODO read
        Ok(password)
    }

    fn read_mnemonic(&self) -> Result<String, String> {
        let mnemonic = "oil oil oil oil oil oil oil oil oil oil oil oil".to_owned(); // TODO read
        Ok(mnemonic)
    }

    fn do_check(&self) -> Result<(), String> {
        let exists = fs::exists(&self.config.filename).unwrap_or(false);
        if !exists {
            return Err(format!("Could not secret file {}", self.config.filename));
        }

        let password = self.read_password()?;

        let seedstore = SeedStore::new_from_encrypted_file(&self.config.filename, &password)
            .map_err(|e| format!("Could not read secret file, {}", e))?;

        let xpub = seedstore.get_xpub()?.to_string();
        let child_spec0 = crate::ChildSpecifier::Index4(0);
        let address0 = seedstore.get_child_address(&child_spec0)?;
        let pubkey0 = seedstore.get_child_public_key(&child_spec0)?.to_string();

        let network = seedstore.network();
        let derivation = child_spec0.derivation_path(network)?.to_string();
        println!("");
        println!(
            "Seed has been read from secret file {}",
            self.config.filename
        );
        println!(
            "XPUB, first address, and public key (network {}, derivation {}):",
            network, derivation
        );
        println!("  {}", xpub);
        println!("  {}", address0);
        println!("  {}", pubkey0);
        println!("");

        Ok(())
    }
}
