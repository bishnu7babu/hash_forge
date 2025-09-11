use sha2::{Digest, Sha256};
use super::HashAlgorithm;

pub struct Sha2Hash;

impl HashAlgorithm for Sha2Hash {
    fn name(&self) -> &str {
        "SHA2HASH"
    }
    fn hash(&self, input: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(input);
        hasher.finalize().to_vec()
    }
}