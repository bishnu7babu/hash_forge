use sha3::{Digest, Sha3_256};
use super::HashAlgorithm;

pub struct Sha3Hash;

impl HashAlgorithm for Sha3Hash {
    fn name(&self) -> &str {
        "SHA3HASH"
    }

    fn hash(&self, input: &[u8]) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(input);
        hasher.finalize().to_vec()
    }
}