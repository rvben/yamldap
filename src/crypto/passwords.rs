use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use sha1::Sha1;
use sha2::{Digest, Sha256};

pub fn verify_password(password: &str, stored: &str) -> crate::Result<bool> {
    // Check for password hash prefix
    if stored.starts_with("{SSHA}") {
        verify_ssha(password, &stored[6..])
    } else if stored.starts_with("{SHA}") {
        verify_sha(password, &stored[5..])
    } else if stored.starts_with("{SHA256}") {
        verify_sha256(password, &stored[8..])
    } else if stored.starts_with("{BCRYPT}") || stored.starts_with("$2") {
        verify_bcrypt(password, stored.trim_start_matches("{BCRYPT}"))
    } else {
        // Plain text comparison
        Ok(password == stored)
    }
}

fn verify_ssha(password: &str, encoded: &str) -> crate::Result<bool> {
    let decoded = BASE64
        .decode(encoded)
        .map_err(|e| crate::YamlLdapError::Auth(format!("Invalid SSHA encoding: {}", e)))?;
    
    if decoded.len() < 20 {
        return Err(crate::YamlLdapError::Auth(
            "Invalid SSHA hash length".to_string(),
        ));
    }
    
    let (hash, salt) = decoded.split_at(20);
    
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    let computed_hash = hasher.finalize();
    
    Ok(computed_hash.as_slice() == hash)
}

fn verify_sha(password: &str, encoded: &str) -> crate::Result<bool> {
    let decoded = BASE64
        .decode(encoded)
        .map_err(|e| crate::YamlLdapError::Auth(format!("Invalid SHA encoding: {}", e)))?;
    
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let computed_hash = hasher.finalize();
    
    Ok(computed_hash.as_slice() == decoded)
}

fn verify_sha256(password: &str, encoded: &str) -> crate::Result<bool> {
    let decoded = BASE64
        .decode(encoded)
        .map_err(|e| crate::YamlLdapError::Auth(format!("Invalid SHA256 encoding: {}", e)))?;
    
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let computed_hash = hasher.finalize();
    
    Ok(computed_hash.as_slice() == decoded)
}

fn verify_bcrypt(password: &str, hash: &str) -> crate::Result<bool> {
    bcrypt::verify(password, hash)
        .map_err(|e| crate::YamlLdapError::Auth(format!("Bcrypt verification failed: {}", e)))
}

pub fn hash_password(password: &str, method: &str) -> crate::Result<String> {
    match method {
        "plain" => Ok(password.to_string()),
        "sha" => {
            let mut hasher = Sha1::new();
            hasher.update(password.as_bytes());
            let hash = hasher.finalize();
            Ok(format!("{{SHA}}{}", BASE64.encode(hash)))
        }
        "ssha" => {
            use rand::Rng;
            let salt: [u8; 8] = rand::thread_rng().gen();
            
            let mut hasher = Sha1::new();
            hasher.update(password.as_bytes());
            hasher.update(&salt);
            let hash = hasher.finalize();
            
            let mut result = hash.to_vec();
            result.extend_from_slice(&salt);
            
            Ok(format!("{{SSHA}}{}", BASE64.encode(result)))
        }
        "bcrypt" => {
            let hash = bcrypt::hash(password, bcrypt::DEFAULT_COST)
                .map_err(|e| crate::YamlLdapError::Auth(format!("Bcrypt hashing failed: {}", e)))?;
            Ok(format!("{{BCRYPT}}{}", hash))
        }
        _ => Err(crate::YamlLdapError::Auth(format!(
            "Unknown password hash method: {}",
            method
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plain_password() {
        assert!(verify_password("test123", "test123").unwrap());
        assert!(!verify_password("test123", "wrong").unwrap());
    }
    
    #[test]
    fn test_sha_password() {
        let hashed = hash_password("test123", "sha").unwrap();
        assert!(verify_password("test123", &hashed).unwrap());
        assert!(!verify_password("wrong", &hashed).unwrap());
    }
    
    #[test]
    fn test_bcrypt_password() {
        let hashed = hash_password("test123", "bcrypt").unwrap();
        assert!(verify_password("test123", &hashed).unwrap());
        assert!(!verify_password("wrong", &hashed).unwrap());
    }
}