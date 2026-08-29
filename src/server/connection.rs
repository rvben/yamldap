use crate::directory::AuthHandler;
use crate::ldap::operations::OperationLimits;
use crate::ldap::protocol::{BindAuthentication, LdapRequest, LdapResponse};
use crate::ldap::SimpleLdapCodec;
use crate::server::session::{ConnectionDisposition, LdapSession, SessionContext};
use crate::server::{DirectoryStore, ResourceLimits};
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_util::codec::Framed;
use tracing::{debug, info};

pub(crate) async fn handle_connection(
    socket: TcpStream,
    directory: DirectoryStore,
    auth_handler: Arc<AuthHandler>,
    ad_compat: bool,
    limits: ResourceLimits,
    blocking_operations: Arc<Semaphore>,
    password_operations: Arc<Semaphore>,
) -> crate::Result<()> {
    let peer_addr = socket.peer_addr()?;
    info!(%peer_addr, "handling LDAP connection");

    let codec = SimpleLdapCodec::new(limits.max_message_bytes);
    let mut framed = Framed::new(socket, codec);
    let mut session = LdapSession::new();

    loop {
        let next = timeout(limits.idle_timeout, framed.next())
            .await
            .map_err(|_| timed_out("LDAP connection idle timeout"))?;
        let Some(message) = next else {
            break;
        };
        let message = message?;
        let operation_name = request_name(&message.protocol_op);
        debug!(
            message_id = message.message_id,
            operation = operation_name,
            "received LDAP request"
        );

        let password_permit = if matches!(
            &message.protocol_op,
            LdapRequest::BindRequest {
                authentication: BindAuthentication::Simple(_),
                ..
            }
        ) {
            Some(
                Arc::clone(&password_operations)
                    .acquire_owned()
                    .await
                    .map_err(|_| unavailable("password-operation limiter closed"))?,
            )
        } else {
            None
        };
        let blocking_permit = Arc::clone(&blocking_operations)
            .acquire_owned()
            .await
            .map_err(|_| unavailable("blocking-operation limiter closed"))?;

        let snapshot = directory.snapshot()?;
        let auth_handler = Arc::clone(&auth_handler);
        let operation_limits = OperationLimits {
            max_search_entries: limits.max_search_entries,
            max_search_duration: limits.search_timeout,
            max_search_response_bytes: limits.max_search_response_bytes,
        };

        let processed = tokio::task::spawn_blocking(move || {
            let _blocking_permit = blocking_permit;
            let _password_permit = password_permit;
            let mut session = session;
            let outcome = session.process(
                message,
                SessionContext {
                    directory: &snapshot,
                    auth_handler: &auth_handler,
                    ad_compat,
                    limits: operation_limits,
                },
            );
            (session, outcome)
        })
        .await
        .map_err(|error| {
            crate::YamlLdapError::Directory(format!("LDAP operation task failed: {error}"))
        })?;
        session = processed.0;
        let outcome = processed.1;

        for response in outcome.responses {
            debug!(
                message_id = response.message_id,
                operation = response_name(&response.protocol_op),
                "sending LDAP response"
            );
            timeout(limits.write_timeout, framed.send(response))
                .await
                .map_err(|_| timed_out("LDAP response write timeout"))??;
        }

        if outcome.disposition == ConnectionDisposition::Close {
            break;
        }
    }

    info!(%peer_addr, "LDAP connection closed");
    Ok(())
}

fn request_name(request: &LdapRequest) -> &'static str {
    match request {
        LdapRequest::BindRequest { .. } => "bind",
        LdapRequest::UnbindRequest => "unbind",
        LdapRequest::SearchRequest { .. } => "search",
        LdapRequest::CompareRequest { .. } => "compare",
        LdapRequest::AbandonRequest { .. } => "abandon",
        LdapRequest::ExtendedRequest { .. } => "extended",
    }
}

fn response_name(response: &LdapResponse) -> &'static str {
    match response {
        LdapResponse::BindResponse { .. } => "bind",
        LdapResponse::SearchResultEntry { .. } => "search-entry",
        LdapResponse::SearchResultDone { .. } => "search-done",
        LdapResponse::CompareResponse { .. } => "compare",
        LdapResponse::ExtendedResponse { .. } => "extended",
    }
}

fn timed_out(message: &'static str) -> crate::YamlLdapError {
    std::io::Error::new(std::io::ErrorKind::TimedOut, message).into()
}

fn unavailable(message: &'static str) -> crate::YamlLdapError {
    crate::YamlLdapError::Directory(message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::Directory;
    use crate::yaml::YamlSchema;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn unbind_closes_the_connection_without_a_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let directory = DirectoryStore::new(Directory::new(
            "dc=test,dc=com".to_string(),
            YamlSchema::default(),
        ));
        let limits = ResourceLimits::default();
        let blocking = Arc::new(Semaphore::new(limits.max_blocking_operations));
        let passwords = Arc::new(Semaphore::new(limits.max_password_operations));

        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            handle_connection(
                socket,
                directory,
                Arc::new(AuthHandler::new(true)),
                false,
                limits,
                blocking,
                passwords,
            )
            .await
            .unwrap();
        });

        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(&[0x30, 0x05, 0x02, 0x01, 0x01, 0x42, 0x00])
            .await
            .unwrap();
        let mut byte = [0_u8; 1];
        let count = timeout(std::time::Duration::from_secs(1), client.read(&mut byte))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(count, 0);
        server.await.unwrap();
    }
}
