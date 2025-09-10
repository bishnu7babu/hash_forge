use md5;
use clap::Parser;
use std::{io::{self, BufRead}, path::PathBuf};
use sha1;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short = 'f', long, value_name = "FILE", required = true)]
    path: PathBuf,

    #[arg(long, value_name = "HASH", required = true)]
    hash: String,
}

trait HashAlgorithm {
    fn hash(&self, input: &[u8]) -> Vec<u8>;
    fn hash_hex(&self, input: &[u8]) -> String {
        self.hash(input).iter().map(|b| format!("{:02x}", b)).collect()
    }
}

struct Md5Hash;

impl HashAlgorithm for Md5Hash {
    fn hash(&self, input: &[u8]) -> Vec<u8> {
        let hash = md5::compute(input);
        hash.0.to_vec()
    }
}

fn main() {

    let cli = Cli::parse();
    let hash = cli.hash;
    let hasher = Md5Hash;

    let file = match std::fs::File::open(&cli.path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error reading file {}: {}", cli.path.display(), e);
            return;
        }
    };

    let reader = io::BufReader::new(&file);

    for (i,line) in reader.lines().enumerate() {
        match line {
            Ok(word) => {
                let computed_hash = hasher.hash_hex(word.as_bytes());
                if computed_hash == hash {
                    println!("✅ Match found at line {}: {}", i + 1, word);
                    return;
                }
            },
            Err(e) => eprintln!("Error reading line {}",e)
        }
    }

    let input: &[u8] = b"hello";
    let hash = hasher.hash(input);
}