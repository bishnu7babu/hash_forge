pub mod md2;
pub mod md4;
pub mod md5;
pub mod md6;
pub mod sha1;
pub mod sha2;
pub mod sha3;
pub trait HashAlgorithm {
     fn name(&self) -> &str;
     fn hash(&self, input: &[u8]) -> Vec<u8>;
     fn hash_hex(&self, input: &[u8]) -> String {
        self.hash(input).iter().map(|b| format!("{:02x}", b)).collect()
    }
}