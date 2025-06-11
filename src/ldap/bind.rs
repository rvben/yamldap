use super::protocol::{
    BindAuthentication, LdapMessage, LdapMessageId, LdapProtocolOp, LdapResult, LdapResultCode,
};
use crate::directory::{AuthHandler, Directory};

pub fn handle_bind_request(
    message_id: LdapMessageId,
    dn: String,
    auth: BindAuthentication,
    directory: &Directory,
    auth_handler: &AuthHandler,
) -> LdapMessage {
    let result = match auth {
        BindAuthentication::Anonymous => {
            if auth_handler.is_anonymous_allowed() {
                LdapResult::success()
            } else {
                LdapResult::error(
                    LdapResultCode::StrongerAuthRequired,
                    "Anonymous bind not allowed".to_string(),
                )
            }
        }
        BindAuthentication::Simple(password) => {
            // Get the entry if DN is provided
            let entry = if dn.is_empty() {
                None
            } else {
                directory.get_entry(&dn)
            };

            match auth_handler.authenticate(entry.as_ref(), &password) {
                Ok(true) => LdapResult::success(),
                Ok(false) => LdapResult::error(
                    LdapResultCode::InvalidDNSyntax,
                    "Invalid credentials".to_string(),
                ),
                Err(e) => LdapResult::error(LdapResultCode::InvalidDNSyntax, e.to_string()),
            }
        }
    };

    LdapMessage {
        message_id,
        protocol_op: LdapProtocolOp::BindResponse { result },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::entry::{AttributeSyntax, AttributeValue, LdapEntry};

    fn create_test_directory() -> Directory {
        let schema = crate::yaml::YamlSchema::default();
        let directory = Directory::new("dc=example,dc=com".to_string(), schema);
        
        // Add a test user
        let mut entry = LdapEntry::new("cn=test,dc=example,dc=com".to_string());
        entry.add_attribute(
            "userPassword".to_string(),
            vec![AttributeValue::String("password".to_string())],
            AttributeSyntax::String,
        );
        directory.add_entry(entry);
        
        directory
    }

    #[test]
    fn test_handle_bind_anonymous_allowed() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(true);
        
        let response = handle_bind_request(
            1,
            String::new(),
            BindAuthentication::Anonymous,
            &directory,
            &auth_handler,
        );
        
        match response.protocol_op {
            LdapProtocolOp::BindResponse { result } => {
                assert_eq!(result.result_code, LdapResultCode::Success);
                assert_eq!(result.diagnostic_message, "");
            }
            _ => panic!("Expected BindResponse"),
        }
    }

    #[test]
    fn test_handle_bind_anonymous_not_allowed() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);
        
        let response = handle_bind_request(
            1,
            String::new(),
            BindAuthentication::Anonymous,
            &directory,
            &auth_handler,
        );
        
        match response.protocol_op {
            LdapProtocolOp::BindResponse { result } => {
                assert_eq!(result.result_code, LdapResultCode::StrongerAuthRequired);
                assert_eq!(result.diagnostic_message, "Anonymous bind not allowed");
            }
            _ => panic!("Expected BindResponse"),
        }
    }

    #[test]
    fn test_handle_bind_simple_success() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);
        
        let response = handle_bind_request(
            1,
            "cn=test,dc=example,dc=com".to_string(),
            BindAuthentication::Simple("password".to_string()),
            &directory,
            &auth_handler,
        );
        
        match response.protocol_op {
            LdapProtocolOp::BindResponse { result } => {
                assert_eq!(result.result_code, LdapResultCode::Success);
                assert_eq!(result.diagnostic_message, "");
            }
            _ => panic!("Expected BindResponse"),
        }
    }

    #[test]
    fn test_handle_bind_simple_wrong_password() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);
        
        let response = handle_bind_request(
            1,
            "cn=test,dc=example,dc=com".to_string(),
            BindAuthentication::Simple("wrongpassword".to_string()),
            &directory,
            &auth_handler,
        );
        
        match response.protocol_op {
            LdapProtocolOp::BindResponse { result } => {
                assert_eq!(result.result_code, LdapResultCode::InvalidDNSyntax);
                assert!(result.diagnostic_message.contains("Invalid credentials"));
            }
            _ => panic!("Expected BindResponse"),
        }
    }

    #[test]
    fn test_handle_bind_simple_nonexistent_user() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);
        
        let response = handle_bind_request(
            1,
            "cn=nonexistent,dc=example,dc=com".to_string(),
            BindAuthentication::Simple("password".to_string()),
            &directory,
            &auth_handler,
        );
        
        match response.protocol_op {
            LdapProtocolOp::BindResponse { result } => {
                assert_eq!(result.result_code, LdapResultCode::InvalidDNSyntax);
                assert!(result.diagnostic_message.contains("Invalid credentials"));
            }
            _ => panic!("Expected BindResponse"),
        }
    }

    #[test]
    fn test_handle_bind_empty_dn_with_password() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);
        
        let response = handle_bind_request(
            1,
            String::new(),
            BindAuthentication::Simple("password".to_string()),
            &directory,
            &auth_handler,
        );
        
        match response.protocol_op {
            LdapProtocolOp::BindResponse { result } => {
                assert_eq!(result.result_code, LdapResultCode::InvalidDNSyntax);
                assert!(result.diagnostic_message.contains("Invalid credentials"));
            }
            _ => panic!("Expected BindResponse"),
        }
    }

    #[test]
    fn test_handle_bind_message_id_preserved() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(true);
        
        let message_id = 42;
        let response = handle_bind_request(
            message_id,
            String::new(),
            BindAuthentication::Anonymous,
            &directory,
            &auth_handler,
        );
        
        assert_eq!(response.message_id, message_id);
    }

    #[test]
    fn test_handle_bind_with_hashed_password() {
        let schema = crate::yaml::YamlSchema::default();
        let directory = Directory::new("dc=example,dc=com".to_string(), schema);
        
        // Add a test user with hashed password
        let mut entry = LdapEntry::new("cn=hashed,dc=example,dc=com".to_string());
        entry.add_attribute(
            "userPassword".to_string(),
            vec![AttributeValue::String("{SSHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=".to_string())],
            AttributeSyntax::String,
        );
        directory.add_entry(entry);
        
        let auth_handler = AuthHandler::new(false);
        
        let response = handle_bind_request(
            1,
            "cn=hashed,dc=example,dc=com".to_string(),
            BindAuthentication::Simple("password".to_string()),
            &directory,
            &auth_handler,
        );
        
        match response.protocol_op {
            LdapProtocolOp::BindResponse { result } => {
                assert_eq!(result.result_code, LdapResultCode::Success);
                assert_eq!(result.diagnostic_message, "");
            }
            _ => panic!("Expected BindResponse"),
        }
    }

    #[test]
    fn test_handle_bind_anonymous_with_empty_password() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(true);
        
        // Empty password is treated as anonymous bind
        let response = handle_bind_request(
            1,
            "cn=test,dc=example,dc=com".to_string(),
            BindAuthentication::Simple(String::new()),
            &directory,
            &auth_handler,
        );
        
        match response.protocol_op {
            LdapProtocolOp::BindResponse { result } => {
                assert_eq!(result.result_code, LdapResultCode::Success);
                assert_eq!(result.diagnostic_message, "");
            }
            _ => panic!("Expected BindResponse"),
        }
    }
}
