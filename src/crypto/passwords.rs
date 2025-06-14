use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use sha1::Sha1;
use sha2::{Digest, Sha256};

pub fn verify_password(password: &str, stored: &str) -> crate::Result<bool> {
    // Check for password hash prefix
    if let Some(stripped) = stored.strip_prefix("{SSHA}") {
        verify_ssha(password, stripped)
    } else if let Some(stripped) = stored.strip_prefix("{SHA}") {
        verify_sha(password, stripped)
    } else if let Some(stripped) = stored.strip_prefix("{SHA256}") {
        verify_sha256(password, stripped)
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
        "sha256" => {
            let mut hasher = Sha256::new();
            hasher.update(password.as_bytes());
            let hash = hasher.finalize();
            Ok(format!("{{SHA256}}{}", BASE64.encode(hash)))
        }
        "ssha" => {
            use rand::Rng;
            let salt: [u8; 8] = rand::thread_rng().gen();

            let mut hasher = Sha1::new();
            hasher.update(password.as_bytes());
            hasher.update(salt);
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

    #[test]
    fn test_sha256_password() {
        // Test with generated hash
        let hashed = hash_password("test123", "sha256").unwrap();
        assert!(verify_password("test123", &hashed).unwrap());
        assert!(!verify_password("wrong", &hashed).unwrap());

        // Test with known hash
        // "test123" in SHA256 = ecd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc703527c30265534f75ae
        let known_hash = "{SHA256}7NcYcNGWMxapfjrDQIyYNa2M8PPBvHA1J8MCZVNPda4=";
        assert!(verify_password("test123", known_hash).unwrap());
        assert!(!verify_password("test456", known_hash).unwrap());
    }

    #[test]
    fn test_ssha_password() {
        // Test with generated hash (includes random salt)
        let hashed = hash_password("test123", "ssha").unwrap();
        assert!(hashed.starts_with("{SSHA}"));
        assert!(verify_password("test123", &hashed).unwrap());
        assert!(!verify_password("wrong", &hashed).unwrap());

        // Test with empty password
        let empty_hash = hash_password("", "ssha").unwrap();
        assert!(verify_password("", &empty_hash).unwrap());
        assert!(!verify_password("test", &empty_hash).unwrap());
    }

    #[test]
    fn test_verify_sha256_directly() {
        // Test verify_sha256 function directly
        let valid_base64 = "7NcYcNGWMxapfjrDQIyYNa2M8PPBvHA1J8MCZVNPda4=";
        assert!(verify_sha256("test123", valid_base64).unwrap());
        assert!(!verify_sha256("wrong", valid_base64).unwrap());

        // Test with invalid base64
        let result = verify_sha256("test", "invalid@base64!");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid SHA256 encoding"));
    }

    #[test]
    fn test_verify_ssha_edge_cases() {
        // Test with invalid base64
        let result = verify_password("test", "{SSHA}invalid@base64!");
        assert!(result.is_err());

        // Test with hash too short for salt
        let result = verify_password("test", "{SSHA}YWI="); // "ab" in base64, too short
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid SSHA hash"));
    }

    #[test]
    fn test_hash_password_unknown_method() {
        let result = hash_password("test", "unknown");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unknown password hash method"));
    }

    #[test]
    fn test_empty_passwords() {
        // Plain empty password
        assert!(verify_password("", "").unwrap());
        assert!(!verify_password("test", "").unwrap());

        // SHA empty password
        let sha_empty = hash_password("", "sha").unwrap();
        assert!(verify_password("", &sha_empty).unwrap());

        // SHA256 empty password
        let sha256_empty = hash_password("", "sha256").unwrap();
        assert!(verify_password("", &sha256_empty).unwrap());
    }

    #[test]
    fn test_special_characters_in_password() {
        let special_pass = "test!@#$%^&*()_+-=[]{}|;':\",./<>?";

        // Test with different hash methods
        for method in &["plain", "sha", "sha256", "ssha", "bcrypt"] {
            let hashed = hash_password(special_pass, method).unwrap();
            assert!(verify_password(special_pass, &hashed).unwrap());
            assert!(!verify_password("wrong", &hashed).unwrap());
        }
    }

    #[test]
    fn test_unicode_passwords() {
        let unicode_pass = "测试密码🔐";

        // Test with different hash methods
        for method in &["plain", "sha", "sha256", "ssha"] {
            let hashed = hash_password(unicode_pass, method).unwrap();
            assert!(verify_password(unicode_pass, &hashed).unwrap());
            assert!(!verify_password("wrong", &hashed).unwrap());
        }
    }

    #[test]
    fn test_bcrypt_with_prefix() {
        // Test that bcrypt hashes work with and without {BCRYPT} prefix
        let password = "test123";
        let hashed = hash_password(password, "bcrypt").unwrap();

        // Should have {BCRYPT} prefix
        assert!(hashed.starts_with("{BCRYPT}"));

        // Should verify with prefix
        assert!(verify_password(password, &hashed).unwrap());

        // Should also verify without prefix (raw bcrypt hash)
        let raw_hash = hashed.trim_start_matches("{BCRYPT}");
        assert!(verify_password(password, raw_hash).unwrap());
    }

    #[test]
    fn test_invalid_hash_format() {
        // Test invalid base64 in SHA
        assert!(verify_password("test", "{SHA}invalid!!!").is_err());

        // Test invalid base64 in SHA256
        assert!(verify_password("test", "{SHA256}invalid!!!").is_err());

        // Test invalid base64 in SSHA
        assert!(verify_password("test", "{SSHA}invalid!!!").is_err());

        // Test SSHA with too short decoded value
        assert!(verify_password("test", "{SSHA}dGVzdA==").is_err()); // "test" in base64, too short
    }

    #[test]
    fn test_bcrypt_error_handling() {
        // Test that bcrypt works with and without {BCRYPT} prefix
        let hash_without_prefix = bcrypt::hash("test123", bcrypt::DEFAULT_COST).unwrap();
        let hash_with_prefix = format!("{{BCRYPT}}{}", hash_without_prefix);

        assert!(verify_password("test123", &hash_without_prefix).unwrap());
        assert!(verify_password("test123", &hash_with_prefix).unwrap());
    }

    #[test]
    fn test_unknown_hash_method() {
        assert!(hash_password("test", "md5").is_err());
        assert!(hash_password("test", "unknown").is_err());
    }

    #[test]
    fn test_empty_password() {
        // Test empty passwords with various hash methods
        assert!(verify_password("", "").unwrap());
        assert!(!verify_password("something", "").unwrap());

        let sha_empty = hash_password("", "sha").unwrap();
        assert!(verify_password("", &sha_empty).unwrap());

        let sha256_empty = hash_password("", "sha256").unwrap();
        assert!(verify_password("", &sha256_empty).unwrap());
    }
}
