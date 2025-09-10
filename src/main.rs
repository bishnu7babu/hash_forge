mod hash_algo;

use clap::Parser;
use std::{
    io::{self, BufRead},
    path::PathBuf,
};
use md5;
use sha1::{Digest, Sha1};

use hash_algo::{HashAlgorithm,md5::Md5Hash, sha1::Sha1Hash};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short = 'f', long, value_name = "FILE", required = true)]
    file: PathBuf,

    #[arg(long, value_name = "HASH", required = true)]
    hash: String,

    #[arg(short, long, value_name = "MODE", required = true, help = "md5, sha1")]
    mode: String,
}

fn main() {
    let cli = Cli::parse();

    // choose hasher based on mode
    let hasher: Box<dyn HashAlgorithm> = match cli.mode.as_str() {
        "md5" => Box::new(Md5Hash),
        "sha1" => Box::new(Sha1Hash),
        _ => {
            eprintln!("Unsupported mode: {}", cli.mode);
            return;
        }
    };

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
                let computed_hash = hasher.hash_hex(word.as_bytes());
                if computed_hash == cli.hash {
                    println!("✅ Match found at line {}: {}", i + 1, word);
                    return;
                }
            }
            Err(e) => eprintln!("Error reading line {}: {}", i + 1, e),
        }
    }

    println!("❌ No match found.");
}