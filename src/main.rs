mod hash_algo;
use clap::{Parser, Subcommand};
use std::{
    io::{self, BufRead},
    path::PathBuf,
    process,
};
use hash_algo::bcrypt::BcryptHash;
use hash_algo::scrypt::ScryptHash;
use hash_algo::{
    HashAlgorithm,
    md2::Md2Hash,
    md4::Md4Hash,
    md5::Md5Hash,
    md6::Md6Hash,
    sha1::Sha1Hash,
    sha2::Sha2Hash,
    sha3::Sha3Hash,
};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short = 'f', long, value_name = "FILE", required = true)]
    file: PathBuf,
    
    #[arg(long, value_name = "HASH", required = true)]
    hash: String,
    
    #[arg(short, long, value_name = "MODE", required = true)]
    mode: HashMode,
    
    #[command(subcommand)]
    scrypt: Option<ScryptCommand>,
}

#[derive(Subcommand, Debug)]
enum ScryptCommand {
    Scrypt {
        #[arg(long, default_value = "16384")]
        n: u32,
        #[arg(long, default_value = "8")]
        r: u32,
        #[arg(long, default_value = "1")]
        p: u32,
        #[arg(long, default_value = "salty_salty")]
        salt: String,
        #[arg(long, default_value = "32")]
        key_length: usize,
    }
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum HashMode {
    Md2,
    Md4,
    Md5,
    Md6,
    Sha1,
    Sha2,
    Sha3,
    Bcrypt,
    Scrypt,
}

fn word_comp(cli: &Cli, hasher: Option<Box<dyn HashAlgorithm>>) {
    let file = match std::fs::File::open(&cli.file) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error reading file {}: {}", cli.file.display(), e);
            return;
        }
    };

    let reader = io::BufReader::new(file);
    let target_hash = cli.hash.trim(); // Trim any whitespace from input hash

    for (i, line) in reader.lines().enumerate() {
        if let Ok(word) = line {
            let word = word.trim(); // Trim whitespace from word
            println!("Trying: {}", word);

            let matched = match cli.mode {
                HashMode::Scrypt => {
                    // For scrypt, check if it's encoded format or hex format
                    if target_hash.starts_with("$scrypt$") {
                        // Industry-standard encoded format
                        match ScryptHash::verify_encoded(target_hash, word.as_bytes()) {
                            Ok(result) => result,
                            Err(e) => {
                                eprintln!("Error verifying scrypt hash: {}", e);
                                false
                            }
                        }
                    } else {
                        // Hex format - use the hasher instance
                        if let Some(ref h) = hasher {
                            let computed_hash = h.hash_hex(word.as_bytes());
                            computed_hash.eq_ignore_ascii_case(target_hash)
                        } else {
                            eprintln!("No hasher available for hex scrypt comparison");
                            false
                        }
                    }
                }
                HashMode::Bcrypt => {
                    // BCrypt typically uses encoded format like $2b$...
                    if target_hash.starts_with("$2") {
                        // Use bcrypt's verify method if available
                        // For now, fall back to hasher
                        if let Some(ref h) = hasher {
                            let computed_hash = h.hash_hex(word.as_bytes());
                            computed_hash.eq_ignore_ascii_case(target_hash)
                        } else {
                            false
                        }
                    } else {
                        if let Some(ref h) = hasher {
                            let computed_hash = h.hash_hex(word.as_bytes());
                            computed_hash.eq_ignore_ascii_case(target_hash)
                        } else {
                            false
                        }
                    }
                }
                _ => {
                    // For other hashes, just compare raw hex
                    if let Some(ref h) = hasher {
                        let computed_hash = h.hash_hex(word.as_bytes());
                        computed_hash.eq_ignore_ascii_case(target_hash)
                    } else {
                        eprintln!("No hasher available");
                        false
                    }
                }
            };

            if matched {
                println!("✅ Match found at line {}: {}", i + 1, word);
                println!("Hash: {}", target_hash);
                return;
            }
        }
    }

    println!("❌ No match found.");
}

fn create_hasher(cli: &Cli) -> Result<Option<Box<dyn HashAlgorithm>>, String> {
    match cli.mode {
        HashMode::Md2 => Ok(Some(Box::new(Md2Hash))),
        HashMode::Md4 => Ok(Some(Box::new(Md4Hash))),
        HashMode::Md5 => Ok(Some(Box::new(Md5Hash))),
        HashMode::Md6 => Ok(Some(Box::new(Md6Hash))),
        HashMode::Sha1 => Ok(Some(Box::new(Sha1Hash))),
        HashMode::Sha2 => Ok(Some(Box::new(Sha2Hash))),
        HashMode::Sha3 => Ok(Some(Box::new(Sha3Hash))),
        HashMode::Bcrypt => Ok(Some(Box::new(BcryptHash::new(cli.hash.clone())))),
        HashMode::Scrypt => {
            // Only create hasher if we're using hex format
            if cli.hash.starts_with("$scrypt$") {
                // For encoded format, we don't need a hasher instance
                Ok(None)
            } else {
                // For hex format, we need a hasher with parameters
                match &cli.scrypt {
                    Some(ScryptCommand::Scrypt { n, r, p, salt, key_length }) => {
                        // ScryptHash::new doesn't return Result, adjust if needed
                        let hasher = ScryptHash::new(*n, *r, *p, salt.clone(), *key_length);
                        Ok(Some(Box::new(hasher)))
                    }
                    None => {
                        // If no parameters provided, we can't create a hasher for hex format
                        Err("Scrypt parameters required for hex format verification".into())
                    }
                }
            }
        }
    }
}

fn main() {
    let cli = Cli::parse();
    
    // Validate input
    if cli.hash.is_empty() {
        eprintln!("Error: Hash cannot be empty");
        process::exit(1);
    }
    
    // Create hasher (may be None for encoded scrypt)
    let hasher = match create_hasher(&cli) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };
    
    // Print mode information
    println!("Mode: {:?}", cli.mode);
    println!("Hash format: {}", 
        if cli.hash.starts_with("$") { "encoded" } else { "hex" }
    );
    println!("Hash length: {} chars", cli.hash.len());
    println!("---");
    
    word_comp(&cli, hasher);
}