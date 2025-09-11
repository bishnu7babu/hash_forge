use md2::{Digest, Md2};
use super::HashAlgorithm;

pub struct Md2Hash;

impl HashAlgorithm for Md2Hash {
    fn name(&self) -> &str {
        "MD2HASH"
    }

    fn hash(&self, input: &[u8]) -> Vec<u8> {
        let mut hasher = Md2::new();
        hasher.update(input);
        hasher.finalize().to_vec()
    }
}