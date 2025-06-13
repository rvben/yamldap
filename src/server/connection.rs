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
                            if result.result_code == crate::ldap::protocol::LdapResultCode::Success
                            {
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
        LdapProtocolOp::BindRequest {
            version,
            dn,
            authentication,
        } => Some(LdapOperation::Bind {
            version: *version,
            dn: dn.clone(),
            auth: authentication.clone(),
        }),
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
        LdapProtocolOp::CompareRequest {
            dn,
            attribute,
            value,
        } => Some(LdapOperation::Compare {
            dn: dn.clone(),
            attribute: attribute.clone(),
            value: value.clone(),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::entry::{AttributeSyntax, AttributeValue, LdapEntry};
    use crate::ldap::protocol::{BindAuthentication, DerefAliases, SearchScope};
    use crate::yaml::YamlSchema;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn create_test_directory() -> Arc<Directory> {
        let schema = YamlSchema::default();
        let directory = Directory::new("dc=test,dc=com".to_string(), schema);

        // Add a test user
        let mut entry = LdapEntry::new("cn=admin,dc=test,dc=com".to_string());
        entry.add_attribute(
            "userPassword".to_string(),
            vec![AttributeValue::String("password".to_string())],
            AttributeSyntax::String,
        );
        entry.add_attribute(
            "objectClass".to_string(),
            vec![AttributeValue::String("person".to_string())],
            AttributeSyntax::String,
        );
        directory.add_entry(entry);

        Arc::new(directory)
    }

    #[test]
    fn test_protocol_to_operation_bind() {
        let msg = LdapMessage {
            message_id: 1,
            protocol_op: LdapProtocolOp::BindRequest {
                version: 3,
                dn: "cn=admin,dc=test,dc=com".to_string(),
                authentication: BindAuthentication::Simple("password".to_string()),
            },
        };

        let operation = protocol_to_operation(&msg).unwrap();
        match operation {
            LdapOperation::Bind { version, dn, auth } => {
                assert_eq!(version, 3);
                assert_eq!(dn, "cn=admin,dc=test,dc=com");
                match auth {
                    BindAuthentication::Simple(pwd) => assert_eq!(pwd, "password"),
                    _ => panic!("Expected Simple authentication"),
                }
            }
            _ => panic!("Expected Bind operation"),
        }
    }

    #[test]
    fn test_protocol_to_operation_unbind() {
        let msg = LdapMessage {
            message_id: 2,
            protocol_op: LdapProtocolOp::UnbindRequest,
        };

        let operation = protocol_to_operation(&msg).unwrap();
        match operation {
            LdapOperation::Unbind => {}
            _ => panic!("Expected Unbind operation"),
        }
    }

    #[test]
    fn test_protocol_to_operation_search() {
        let msg = LdapMessage {
            message_id: 3,
            protocol_op: LdapProtocolOp::SearchRequest {
                base_dn: "dc=test,dc=com".to_string(),
                scope: SearchScope::WholeSubtree,
                deref_aliases: DerefAliases::NeverDerefAliases,
                size_limit: 0,
                time_limit: 0,
                types_only: false,
                filter: "(objectClass=*)".to_string(),
                attributes: vec!["cn".to_string(), "mail".to_string()],
            },
        };

        let operation = protocol_to_operation(&msg).unwrap();
        match operation {
            LdapOperation::Search {
                base_dn,
                scope,
                filter,
                attributes,
            } => {
                assert_eq!(base_dn, "dc=test,dc=com");
                assert_eq!(scope, SearchScope::WholeSubtree);
                assert_eq!(filter, "(objectClass=*)");
                assert_eq!(attributes, vec!["cn", "mail"]);
            }
            _ => panic!("Expected Search operation"),
        }
    }

    #[test]
    fn test_protocol_to_operation_compare() {
        let msg = LdapMessage {
            message_id: 4,
            protocol_op: LdapProtocolOp::CompareRequest {
                dn: "cn=admin,ou=Engineering,dc=example,dc=com".to_string(),
                attribute: "cn".to_string(),
                value: "admin".to_string(),
            },
        };

        let operation = protocol_to_operation(&msg).unwrap();
        match operation {
            LdapOperation::Compare {
                dn,
                attribute,
                value,
            } => {
                assert_eq!(dn, "cn=admin,ou=Engineering,dc=example,dc=com");
                assert_eq!(attribute, "cn");
                assert_eq!(value, "admin");
            }
            _ => panic!("Expected Compare operation"),
        }
    }

    #[test]
    fn test_protocol_to_operation_unsupported() {
        let msg = LdapMessage {
            message_id: 4,
            protocol_op: LdapProtocolOp::BindResponse {
                result: crate::ldap::protocol::LdapResult::success(),
            },
        };

        let operation = protocol_to_operation(&msg);
        assert!(operation.is_none());
    }

    #[tokio::test]
    async fn test_handle_connection_unbind() {
        // Start a test server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let directory = create_test_directory();
        let auth_handler = Arc::new(AuthHandler::new(false));

        // Handle connections in background
        let dir = directory.clone();
        let auth = auth_handler.clone();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let _ = handle_connection(socket, dir, auth).await;
        });

        // Connect as client
        let mut client = TcpStream::connect(addr).await.unwrap();

        // Send an unbind request (simplified)
        // In real implementation, this would be properly encoded
        client
            .write_all(b"\x30\x05\x02\x01\x01\x42\x00")
            .await
            .unwrap();

        // Connection should close
        let mut buf = [0u8; 10];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(n, 0); // EOF
    }

    #[tokio::test]
    async fn test_handle_connection_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let directory = create_test_directory();
        let auth_handler = Arc::new(AuthHandler::new(false));

        let dir = directory.clone();
        let auth = auth_handler.clone();
        let handle = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let _ = handle_connection(socket, dir, auth).await;
        });

        // Connect and immediately close
        let client = TcpStream::connect(addr).await.unwrap();
        drop(client);

        // Connection handler should complete without panic
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;
    }
}
