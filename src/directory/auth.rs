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
