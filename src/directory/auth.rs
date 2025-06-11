use super::entry::{AttributeValue, LdapEntry};
use crate::crypto::passwords::verify_password;
use crate::YamlLdapError;

#[derive(Debug, Clone)]
pub struct AuthHandler {
    allow_anonymous: bool,
}

impl AuthHandler {
    pub fn new(allow_anonymous: bool) -> Self {
        Self { allow_anonymous }
    }

    pub fn authenticate(&self, entry: Option<&LdapEntry>, password: &str) -> crate::Result<bool> {
        // Anonymous bind
        if password.is_empty() {
            if self.allow_anonymous {
                return Ok(true);
            } else {
                return Err(YamlLdapError::Auth(
                    "Anonymous bind not allowed".to_string(),
                ));
            }
        }

        // Must have entry for non-anonymous bind
        let entry = entry.ok_or_else(|| YamlLdapError::Auth("Invalid credentials".to_string()))?;

        // Get userPassword attribute
        let password_attr = entry
            .get_attribute("userpassword")
            .or_else(|| entry.get_attribute("userPassword"))
            .ok_or_else(|| YamlLdapError::Auth("No password attribute found".to_string()))?;

        // Check password against all values
        for value in &password_attr.values {
            if let AttributeValue::String(stored_password) = value {
                if verify_password(password, stored_password)? {
                    return Ok(true);
                }
            }
        }

        Err(YamlLdapError::Auth("Invalid credentials".to_string()))
    }

    pub fn is_anonymous_allowed(&self) -> bool {
        self.allow_anonymous
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::entry::AttributeSyntax;

    fn create_test_entry_with_password(dn: &str, password: &str) -> LdapEntry {
        let mut entry = LdapEntry::new(dn.to_string());
        entry.add_attribute(
            "userPassword".to_string(),
            vec![AttributeValue::String(password.to_string())],
            AttributeSyntax::String,
        );
        entry
    }

    #[test]
    fn test_auth_handler_new() {
        let handler = AuthHandler::new(true);
        assert!(handler.is_anonymous_allowed());

        let handler = AuthHandler::new(false);
        assert!(!handler.is_anonymous_allowed());
    }

    #[test]
    fn test_anonymous_bind_allowed() {
        let handler = AuthHandler::new(true);
        let result = handler.authenticate(None, "");
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_anonymous_bind_not_allowed() {
        let handler = AuthHandler::new(false);
        let result = handler.authenticate(None, "");
        assert!(result.is_err());
        match result.unwrap_err() {
            YamlLdapError::Auth(msg) => assert_eq!(msg, "Anonymous bind not allowed"),
            _ => panic!("Expected Auth error"),
        }
    }

    #[test]
    fn test_authenticate_with_no_entry() {
        let handler = AuthHandler::new(false);
        let result = handler.authenticate(None, "password");
        assert!(result.is_err());
        match result.unwrap_err() {
            YamlLdapError::Auth(msg) => assert_eq!(msg, "Invalid credentials"),
            _ => panic!("Expected Auth error"),
        }
    }

    #[test]
    fn test_authenticate_with_no_password_attribute() {
        let handler = AuthHandler::new(false);
        let entry = LdapEntry::new("cn=test,dc=example,dc=com".to_string());
        let result = handler.authenticate(Some(&entry), "password");
        assert!(result.is_err());
        match result.unwrap_err() {
            YamlLdapError::Auth(msg) => assert_eq!(msg, "No password attribute found"),
            _ => panic!("Expected Auth error"),
        }
    }

    #[test]
    fn test_authenticate_with_plain_password() {
        let handler = AuthHandler::new(false);
        let entry = create_test_entry_with_password("cn=test,dc=example,dc=com", "plainpassword");
        
        // Correct password
        let result = handler.authenticate(Some(&entry), "plainpassword");
        assert!(result.is_ok());
        assert!(result.unwrap());
        
        // Wrong password
        let result = handler.authenticate(Some(&entry), "wrongpassword");
        assert!(result.is_err());
        match result.unwrap_err() {
            YamlLdapError::Auth(msg) => assert_eq!(msg, "Invalid credentials"),
            _ => panic!("Expected Auth error"),
        }
    }

    #[test]
    fn test_authenticate_with_hashed_password() {
        let handler = AuthHandler::new(false);
        // SSHA hash for "password" (this is a test hash)
        let entry = create_test_entry_with_password(
            "cn=test,dc=example,dc=com", 
            "{SSHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
        );
        
        // Correct password
        let result = handler.authenticate(Some(&entry), "password");
        assert!(result.is_ok());
        assert!(result.unwrap());
        
        // Wrong password
        let result = handler.authenticate(Some(&entry), "wrongpassword");
        assert!(result.is_err());
    }

    #[test]
    fn test_authenticate_with_bcrypt_password() {
        let handler = AuthHandler::new(false);
        // Bcrypt hash for "password"
        let entry = create_test_entry_with_password(
            "cn=test,dc=example,dc=com",
            "{BCRYPT}$2b$12$GhvMmNVjRW29ulnudl.LbuAnUtN/LRfe1JsBm1Xu6LE3059z5Tr8m"
        );
        
        // Correct password
        let result = handler.authenticate(Some(&entry), "password");
        assert!(result.is_ok());
        assert!(result.unwrap());
        
        // Wrong password
        let result = handler.authenticate(Some(&entry), "wrongpassword");
        assert!(result.is_err());
    }

    #[test]
    fn test_authenticate_with_multiple_passwords() {
        let handler = AuthHandler::new(false);
        let mut entry = LdapEntry::new("cn=test,dc=example,dc=com".to_string());
        entry.add_attribute(
            "userPassword".to_string(),
            vec![
                AttributeValue::String("password1".to_string()),
                AttributeValue::String("password2".to_string()),
            ],
            AttributeSyntax::String,
        );
        
        // First password
        let result = handler.authenticate(Some(&entry), "password1");
        assert!(result.is_ok());
        assert!(result.unwrap());
        
        // Second password
        let result = handler.authenticate(Some(&entry), "password2");
        assert!(result.is_ok());
        assert!(result.unwrap());
        
        // Wrong password
        let result = handler.authenticate(Some(&entry), "wrongpassword");
        assert!(result.is_err());
    }

    #[test]
    fn test_authenticate_case_insensitive_attribute() {
        let handler = AuthHandler::new(false);
        let mut entry = LdapEntry::new("cn=test,dc=example,dc=com".to_string());
        // Use "userpassword" (lowercase)
        entry.add_attribute(
            "userpassword".to_string(),
            vec![AttributeValue::String("password".to_string())],
            AttributeSyntax::String,
        );
        
        let result = handler.authenticate(Some(&entry), "password");
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_authenticate_with_non_string_attribute_value() {
        let handler = AuthHandler::new(false);
        let mut entry = LdapEntry::new("cn=test,dc=example,dc=com".to_string());
        entry.add_attribute(
            "userPassword".to_string(),
            vec![AttributeValue::Integer(12345)], // Non-string value
            AttributeSyntax::Integer,
        );
        
        let result = handler.authenticate(Some(&entry), "12345");
        assert!(result.is_err());
        match result.unwrap_err() {
            YamlLdapError::Auth(msg) => assert_eq!(msg, "Invalid credentials"),
            _ => panic!("Expected Auth error"),
        }
    }
}
