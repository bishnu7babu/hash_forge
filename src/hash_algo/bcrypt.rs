use bcrypt::verify;
use super::HashAlgorithm;

pub struct BcryptHash {
    target_hash: String,
}

impl BcryptHash {
    pub fn new(target_hash: String) -> Self {
        Self { target_hash }
    }
}


impl HashAlgorithm for BcryptHash {
    fn name(&self) -> &str {
        "BCRYPT"
    }

    fn hash(&self, input: &[u8]) -> Vec<u8> {
        self.hash_hex(input).into_bytes()
    }

    fn hash_hex(&self, input: &[u8]) -> String {
        let password = std::str::from_utf8(input).unwrap();
        if verify(password, &self.target_hash).unwrap_or(false) {
            self.target_hash.clone()  
        } else {
            String::new()
        }
    }
}