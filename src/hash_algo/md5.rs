use md5;
use super::HashAlgorithm;

pub struct Md5Hash;
impl HashAlgorithm for Md5Hash {
    fn name(&self) -> &str {
        "MD5"
    }
    fn hash(&self, input: &[u8]) -> Vec<u8> {
        let hash = md5::compute(input);
        hash.0.to_vec()
    }
}


