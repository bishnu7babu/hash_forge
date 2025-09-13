mod hash_algo;
use clap::{Parser, Subcommand};
use std::{
    io::{self, BufRead},
    path::PathBuf,
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

fn word_comp(cli: &Cli, hasher: &dyn HashAlgorithm) {
    let file = match std::fs::File::open(&cli.file) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error reading file {}: {}", cli.file.display(), e);
            return;
        }
    };
    
    let reader = io::BufReader::new(file);
    for (i, line) in reader.lines().enumerate() {
        match line {
            Ok(word) => {
                println!("Trying: {}", word);
                let computed_hash = hasher.hash_hex(word.as_bytes());
                
                // Special handling for scrypt
                if matches!(cli.mode, HashMode::Scrypt) {
                    if computed_hash == cli.hash {
                        println!("✅ Match found at line {}: {}", i + 1, word);
                        println!("Hash: {}", computed_hash);
                        return;
                    }
                } 
                // For other algorithms
                else if computed_hash == cli.hash {
                    println!("✅ Match found at line {}: {}", i + 1, word);
                    println!("Hash: {}", computed_hash);
                    return;
                }
            }
            Err(e) => eprintln!("Error reading line {}: {}", i + 1, e),
        }
    }
    println!("❌ No match found.");
}


fn main() {
    let cli = Cli::parse();
    
    let hasher: Box<dyn HashAlgorithm> = match cli.mode {
        HashMode::Md2 => Box::new(Md2Hash),
        HashMode::Md4 => Box::new(Md4Hash),
        HashMode::Md5 => Box::new(Md5Hash),
        HashMode::Md6 => Box::new(Md6Hash),
        HashMode::Sha1 => Box::new(Sha1Hash),
        HashMode::Sha2 => Box::new(Sha2Hash),
        HashMode::Sha3 => Box::new(Sha3Hash),
        HashMode::Bcrypt => Box::new(BcryptHash::new(cli.hash.clone())),
        HashMode::Scrypt => {
            match &cli.scrypt {
                Some(ScryptCommand::Scrypt { n, r, p, salt, key_length }) => {
                    Box::new(ScryptHash::new(*n, *r, *p, salt.clone(), *key_length))
                }
                None => {
                    eprintln!("Scrypt parameters required when using Scrypt mode");
                    return;
                }
            }
        }
    };
    
    word_comp(&cli, hasher.as_ref());
}