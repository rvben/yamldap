use crate::directory::{AuthHandler, Directory};
use crate::ldap::protocol::{LdapMessage, LdapProtocolOp};
use crate::ldap::{handle_operation, LdapOperation, SimpleLdapCodec};
use crate::server::session::LdapSession;
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use tracing::{debug, error, info};

pub async fn handle_connection(
    socket: TcpStream,
    directory: Arc<Directory>,
    auth_handler: Arc<AuthHandler>,
) -> crate::Result<()> {
    let peer_addr = socket.peer_addr()?;
    info!("Handling connection from {}", peer_addr);
    
    // Create framed connection with our simple LDAP codec
    let mut framed = Framed::new(socket, SimpleLdapCodec);
    
    // Session state
    let mut session = LdapSession::new();
    
    // Message handling loop
    while let Some(result) = framed.next().await {
        match result {
            Ok(message) => {
                debug!("Received LDAP message: {:?}", message);
                
                // Convert protocol message to operation
                let operation = match protocol_to_operation(&message) {
                    Some(op) => op,
                    None => {
                        error!("Could not convert protocol message to operation");
                        continue;
                    }
                };
                
                // Handle the operation
                let responses = handle_operation(
                    message.message_id,
                    operation,
                    &directory,
                    &auth_handler,
                    session.is_bound(),
                );
                
                // Update session state for bind operations
                if let LdapProtocolOp::BindRequest { ref dn, .. } = message.protocol_op {
                    // Check if bind was successful
                    if let Some(response) = responses.first() {
                        if let LdapProtocolOp::BindResponse { ref result } = response.protocol_op {
                            if result.result_code == crate::ldap::protocol::LdapResultCode::Success {
                                session.bind(dn.clone());
                                info!("Successful bind for DN: {}", dn);
                            }
                        }
                    }
                } else if matches!(message.protocol_op, LdapProtocolOp::UnbindRequest) {
                    session.unbind();
                    info!("Client unbind, closing connection");
                    break;
                }
                
                // Send responses
                for response in responses {
                    debug!("Sending LDAP response: {:?}", response);
                    if let Err(e) = framed.send(response).await {
                        error!("Failed to send response: {}", e);
                        break;
                    }
                }
            }
            Err(e) => {
                error!("Error reading from socket: {}", e);
                break;
            }
        }
    }
    
    info!("Connection closed for {}", peer_addr);
    Ok(())
}

// Convert protocol messages to operations
fn protocol_to_operation(msg: &LdapMessage) -> Option<LdapOperation> {
    match &msg.protocol_op {
        LdapProtocolOp::BindRequest { version, dn, authentication } => {
            Some(LdapOperation::Bind {
                version: *version,
                dn: dn.clone(),
                auth: authentication.clone(),
            })
        }
        LdapProtocolOp::UnbindRequest => Some(LdapOperation::Unbind),
        LdapProtocolOp::SearchRequest {
            base_dn,
            scope,
            filter,
            attributes,
            ..
        } => Some(LdapOperation::Search {
            base_dn: base_dn.clone(),
            scope: *scope,
            filter: filter.clone(),
            attributes: attributes.clone(),
        }),
        _ => None,
    }
}