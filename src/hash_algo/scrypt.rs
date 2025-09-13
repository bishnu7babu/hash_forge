use scrypt::{scrypt, Params};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hex;
use std::convert::TryInto;
use super::HashAlgorithm;

pub struct ScryptHash {
    n: u32,
    r: u32,
    p: u32,
    salt: Vec<u8>,
    key_length: usize,
}

impl ScryptHash {
    pub fn new(n: u32, r: u32, p: u32, salt: String, key_length: usize) -> Self {
        assert!(key_length > 0 && key_length <= 1024, "invalid key_length");
        assert!(n >= 2 && (n & (n - 1)) == 0, "n must be a power of two (e.g. 16384)");
        assert!(r > 0 && p > 0, "r and p must be > 0");
    
        Self {
            n,
            r,
            p,
            salt: salt.into_bytes(),
            key_length,
        }
    }
    

    fn log2_n(&self) -> u8 {
        self.n.trailing_zeros() as u8
    }

    fn derive_raw(&self, password: &[u8]) -> Result<Vec<u8>, String> {
        let params = Params::new(self.log2_n(), self.r, self.p, self.key_length)
            .map_err(|e| format!("invalid scrypt params: {:?}", e))?;
        let mut output = vec![0u8; self.key_length];
        scrypt(password, &self.salt, &params, &mut output)
            .map_err(|e| format!("scrypt failed: {:?}", e))?;
        Ok(output)
    }

    /// ✅ Industry-style encoded string: `$scrypt$ln=14,r=8,p=1$<salt_b64>$<dk_b64>`
    pub fn encode_password_hash(&self, password: &[u8]) -> Result<String, String> {
        let dk = self.derive_raw(password)?;
        let salt_b64 = B64.encode(&self.salt);
        let dk_b64 = B64.encode(&dk);

        Ok(format!(
            "$scrypt$ln={},r={},p={}${}${}",
            self.log2_n(),
            self.r,
            self.p,
            salt_b64,
            dk_b64
        ))
    }

    /// ✅ Verification: re-derive and compare encoded hash
    pub fn verify_encoded(encoded: &str, candidate: &[u8]) -> Result<bool, String> {
        let parts: Vec<&str> = encoded.split('$').collect();
        if parts.len() != 5 || parts[1] != "scrypt" {
            return Err("invalid scrypt encoded format".into());
        }

        // parse ln, r, p
        let params_str = parts[2];
        let mut ln = None;
        let mut r = None;
        let mut p = None;

        for kv in params_str.split(',') {
            let mut split = kv.split('=');
            match (split.next(), split.next()) {
                (Some("ln"), Some(v)) => ln = v.parse::<u8>().ok(),
                (Some("r"), Some(v)) => r = v.parse::<u32>().ok(),
                (Some("p"), Some(v)) => p = v.parse::<u32>().ok(),
                _ => {}
            }
        }

        let ln = ln.ok_or("missing ln")?;
        let r = r.ok_or("missing r")?;
        let p = p.ok_or("missing p")?;
        let n = 1u32 << ln;

        let salt = B64.decode(parts[3].as_bytes()).map_err(|_| "invalid base64 salt")?;
        let dk_expected = B64.decode(parts[4].as_bytes()).map_err(|_| "invalid base64 dk")?;
        let key_length = dk_expected.len();

        let hasher = Self {
            n,
            r,
            p,
            salt,
            key_length,
        };

        let dk_actual = hasher.derive_raw(candidate)?;
        Ok(dk_actual == dk_expected)
    }
}

impl HashAlgorithm for ScryptHash {
    fn name(&self) -> &str {
        "SCRYPT"
    }

    fn hash(&self, input: &[u8]) -> Vec<u8> {
        self.derive_raw(input).unwrap_or_default()
    }

    fn hash_hex(&self, input: &[u8]) -> String {
        match self.derive_raw(input) {
            Ok(out) => hex::encode(out),
            Err(_) => String::new(),
        }
    }
}
