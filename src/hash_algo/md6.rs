use md6::Md6;
use super::HashAlgorithm;

pub struct Md6Hash;

impl HashAlgorithm for Md6Hash {
    fn name(&self) -> &str {
        "MD6HASH"
    }

    fn hash(&self, input: &[u8]) -> Vec<u8> {
        let mut result = [0; 32];
        let mut hasher = Md6::new(256).unwrap();
        hasher.update(input);
        hasher.finalise(&mut result);
        result.to_vec()
    }
}