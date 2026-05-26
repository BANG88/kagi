use std::env;
use std::fs;
use std::path::PathBuf;
use crate::domain::error::DomainError;
use zeroize::Zeroizing;

pub struct KeyManager {
    base_path: PathBuf,
}

impl KeyManager {
    pub fn new(base_path: PathBuf) -> Self {
        Self { base_path }
    }

    pub fn load(&self) -> Result<Zeroizing<Vec<u8>>, DomainError> {
        if let Ok(key_hex) = env::var("KAGI_MASTER_KEY") {
            return decode_hex(&key_hex);
        }
        let key_path = self.base_path.join("key/master.key");
        let key_hex = fs::read_to_string(key_path)?;
        decode_hex(key_hex.trim())
    }

    pub fn generate_and_save(&self) -> Result<Zeroizing<Vec<u8>>, DomainError> {
        let key: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let key_path = self.base_path.join("key/master.key");
        fs::create_dir_all(key_path.parent().unwrap())?;
        fs::write(&key_path, hex::encode(&key))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(Zeroizing::new(key))
    }
}

fn decode_hex(s: &str) -> Result<Zeroizing<Vec<u8>>, DomainError> {
    if s.len() != 64 {
        return Err(DomainError::InvalidMasterKey);
    }
    let mut result = Vec::with_capacity(32);
    for i in 0..32 {
        let byte = u8::from_str_radix(&s[i*2..i*2+2], 16)
            .map_err(|_| DomainError::InvalidMasterKey)?;
        result.push(byte);
    }
    Ok(Zeroizing::new(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_generate_and_load() {
        let dir = TempDir::new().unwrap();
        let km = KeyManager::new(dir.path().to_path_buf());
        let key = km.generate_and_save().unwrap();
        assert_eq!(key.len(), 32);
        let loaded = km.load().unwrap();
        assert_eq!(key.to_vec(), loaded.to_vec());
    }

    #[test]
    fn test_decode_hex_invalid_length() {
        let result = decode_hex("tooshort");
        assert!(matches!(result, Err(DomainError::InvalidMasterKey)));
    }

    #[test]
    fn test_decode_hex_invalid_chars() {
        let result = decode_hex("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
        assert!(matches!(result, Err(DomainError::InvalidMasterKey)));
    }
}
