use md4::{Digest, Md4};
use super::HashAlgorithm;

pub struct Md4Hash;

impl HashAlgorithm for Md4Hash {
    fn name(&self) -> &str {
        "MD4HASH"
    }

    fn hash(&self, input: &[u8]) -> Vec<u8> {
        let mut hasher = Md4::new();
        hasher.update(input);
        hasher.finalize().to_vec()
    }
}