use super::protocol::{BindAuthentication, LdapMessage, LdapMessageId, LdapProtocolOp, LdapResult, LdapResultCode};
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
                Err(e) => LdapResult::error(
                    LdapResultCode::InvalidDNSyntax,
                    e.to_string(),
                ),
            }
        }
    };
    
    LdapMessage {
        message_id,
        protocol_op: LdapProtocolOp::BindResponse { result },
    }
}