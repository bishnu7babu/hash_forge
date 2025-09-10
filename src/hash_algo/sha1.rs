use sha1::{Sha1, Digest};
use super::HashAlgorithm;

pub struct Sha1Hash;
impl HashAlgorithm for Sha1Hash {
    fn name(&self) -> &str {
        "SHA1"
    }
    fn hash(&self, input: &[u8]) -> Vec<u8> {
        let mut hasher = Sha1::new();
        hasher.update(input);
        hasher.finalize().to_vec()
    }
}