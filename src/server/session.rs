use crate::directory::{AuthHandler, Directory, DistinguishedName, DnKey};
use crate::ldap::bind::evaluate_bind;
use crate::ldap::operations::{handle_operation, OperationLimits};
use crate::ldap::protocol::{
    LdapRequest, LdapRequestMessage, LdapResponse, LdapResponseMessage, LdapResult, LdapResultCode,
    SearchScope,
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum SessionIdentity {
    Unbound,
    Anonymous,
    Bound { dn: DnKey },
}

#[derive(Debug)]
pub(crate) struct LdapSession {
    identity: SessionIdentity,
}

pub(crate) struct SessionContext<'a> {
    pub directory: &'a Directory,
    pub auth_handler: &'a AuthHandler,
    pub ad_compat: bool,
    pub limits: OperationLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionDisposition {
    Continue,
    Close,
}

#[derive(Debug)]
pub(crate) struct SessionOutcome {
    pub responses: Vec<LdapResponseMessage>,
    pub disposition: ConnectionDisposition,
}

impl Default for LdapSession {
    fn default() -> Self {
        Self {
            identity: SessionIdentity::Unbound,
        }
    }
}

impl LdapSession {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn process(
        &mut self,
        message: LdapRequestMessage,
        context: SessionContext<'_>,
    ) -> SessionOutcome {
        let LdapRequestMessage {
            message_id,
            protocol_op,
        } = message;

        match protocol_op {
            LdapRequest::BindRequest {
                version: _,
                dn,
                authentication,
            } => {
                // RFC 4511: a bind request discards the previous authentication
                // state even when the replacement bind fails.
                self.identity = SessionIdentity::Unbound;
                let mut result =
                    evaluate_bind(&dn, authentication, context.directory, context.auth_handler);
                if result.result_code == LdapResultCode::Success {
                    self.identity = if dn.is_empty() {
                        SessionIdentity::Anonymous
                    } else {
                        match DistinguishedName::parse(&dn) {
                            Ok(dn) => SessionIdentity::Bound { dn: dn.key() },
                            Err(error) => {
                                result = LdapResult::error(
                                    LdapResultCode::InvalidDNSyntax,
                                    error.to_string(),
                                );
                                SessionIdentity::Unbound
                            }
                        }
                    };
                }

                SessionOutcome::continue_with(vec![LdapResponseMessage {
                    message_id,
                    protocol_op: LdapResponse::BindResponse { result },
                }])
            }
            LdapRequest::UnbindRequest => {
                self.identity = SessionIdentity::Unbound;
                SessionOutcome {
                    responses: Vec::new(),
                    disposition: ConnectionDisposition::Close,
                }
            }
            request if !self.is_authorized(&request, &context) => {
                SessionOutcome::continue_with(vec![access_denied_response(message_id, &request)])
            }
            request => SessionOutcome::continue_with(handle_operation(
                message_id,
                request,
                context.directory,
                context.auth_handler,
                context.ad_compat,
                context.limits,
            )),
        }
    }

    fn is_authorized(&self, request: &LdapRequest, context: &SessionContext<'_>) -> bool {
        let requires_authentication = match request {
            LdapRequest::SearchRequest { base_dn, scope, .. } => {
                !(base_dn.trim().is_empty() && matches!(scope, SearchScope::BaseObject))
            }
            LdapRequest::CompareRequest { .. } => true,
            _ => false,
        };

        !requires_authentication
            || self.bound_dn().is_some()
            || context.auth_handler.is_anonymous_allowed()
    }

    fn bound_dn(&self) -> Option<&DnKey> {
        match &self.identity {
            SessionIdentity::Bound { dn } => Some(dn),
            SessionIdentity::Unbound | SessionIdentity::Anonymous => None,
        }
    }
}

impl SessionOutcome {
    fn continue_with(responses: Vec<LdapResponseMessage>) -> Self {
        Self {
            responses,
            disposition: ConnectionDisposition::Continue,
        }
    }
}

fn access_denied_response(message_id: u32, request: &LdapRequest) -> LdapResponseMessage {
    let result = LdapResult::error(
        LdapResultCode::InsufficientAccessRights,
        "Authentication is required".to_string(),
    );
    let protocol_op = match request {
        LdapRequest::SearchRequest { .. } => LdapResponse::SearchResultDone { result },
        LdapRequest::CompareRequest { .. } => LdapResponse::CompareResponse { result },
        _ => unreachable!("only search and compare require authentication"),
    };

    LdapResponseMessage {
        message_id,
        protocol_op,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::entry::{AttributeSyntax, AttributeValue, LdapEntry};
    use crate::ldap::filters::parse_ldap_filter;
    use crate::ldap::protocol::{BindAuthentication, DerefAliases};
    use crate::yaml::YamlSchema;

    const USER_DN: &str = "cn=admin,dc=test,dc=com";

    fn directory() -> Directory {
        let mut directory = Directory::new("dc=test,dc=com".to_string(), YamlSchema::default());
        let mut entry = LdapEntry::new(USER_DN.to_string());
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
        directory
    }

    fn context<'a>(directory: &'a Directory, auth_handler: &'a AuthHandler) -> SessionContext<'a> {
        SessionContext {
            directory,
            auth_handler,
            ad_compat: false,
            limits: OperationLimits::default(),
        }
    }

    fn bind(message_id: u32, password: &str) -> LdapRequestMessage {
        LdapRequestMessage {
            message_id,
            protocol_op: LdapRequest::BindRequest {
                version: 3,
                dn: USER_DN.to_string(),
                authentication: BindAuthentication::Simple(password.to_string()),
            },
        }
    }

    fn search(message_id: u32, base_dn: &str, scope: SearchScope) -> LdapRequestMessage {
        LdapRequestMessage {
            message_id,
            protocol_op: LdapRequest::SearchRequest {
                base_dn: base_dn.to_string(),
                scope,
                deref_aliases: DerefAliases::NeverDerefAliases,
                size_limit: 0,
                time_limit: 0,
                types_only: false,
                filter: parse_ldap_filter("(objectClass=*)").unwrap(),
                attributes: vec!["cn".to_string()],
            },
        }
    }

    fn result_code(outcome: &SessionOutcome) -> LdapResultCode {
        match &outcome.responses.last().unwrap().protocol_op {
            LdapResponse::BindResponse { result }
            | LdapResponse::SearchResultDone { result }
            | LdapResponse::CompareResponse { result } => result.result_code,
            other => panic!("expected a result response, got {other:?}"),
        }
    }

    #[test]
    fn successful_bind_authorizes_a_search_and_preserves_message_ids() {
        let directory = directory();
        let auth_handler = AuthHandler::new(false);
        let mut session = LdapSession::new();

        let bind_outcome = session.process(bind(7, "password"), context(&directory, &auth_handler));
        assert_eq!(result_code(&bind_outcome), LdapResultCode::Success);
        assert_eq!(bind_outcome.responses[0].message_id, 7);

        let search_outcome = session.process(
            search(8, USER_DN, SearchScope::BaseObject),
            context(&directory, &auth_handler),
        );
        assert_eq!(result_code(&search_outcome), LdapResultCode::Success);
        assert!(search_outcome
            .responses
            .iter()
            .all(|response| response.message_id == 8));
    }

    #[test]
    fn failed_rebind_discards_the_previous_identity() {
        let directory = directory();
        let auth_handler = AuthHandler::new(false);
        let mut session = LdapSession::new();

        assert_eq!(
            result_code(&session.process(bind(1, "password"), context(&directory, &auth_handler))),
            LdapResultCode::Success
        );
        assert_eq!(
            result_code(&session.process(
                bind(2, "wrong-password"),
                context(&directory, &auth_handler)
            )),
            LdapResultCode::InvalidCredentials
        );
        assert_eq!(
            result_code(&session.process(
                search(3, USER_DN, SearchScope::BaseObject),
                context(&directory, &auth_handler)
            )),
            LdapResultCode::InsufficientAccessRights
        );
    }

    #[test]
    fn unsupported_bind_discards_identity_but_keeps_connection_open() {
        let directory = directory();
        let auth_handler = AuthHandler::new(false);
        let mut session = LdapSession::new();
        session.process(bind(1, "password"), context(&directory, &auth_handler));

        let outcome = session.process(
            LdapRequestMessage {
                message_id: 2,
                protocol_op: LdapRequest::BindRequest {
                    version: 3,
                    dn: String::new(),
                    authentication: BindAuthentication::Sasl {
                        mechanism: "GSS-SPNEGO".to_string(),
                        credentials: None,
                    },
                },
            },
            context(&directory, &auth_handler),
        );
        assert_eq!(
            result_code(&outcome),
            LdapResultCode::AuthMethodNotSupported
        );
        assert_eq!(outcome.disposition, ConnectionDisposition::Continue);

        let search_outcome = session.process(
            search(3, USER_DN, SearchScope::BaseObject),
            context(&directory, &auth_handler),
        );
        assert_eq!(
            result_code(&search_outcome),
            LdapResultCode::InsufficientAccessRights
        );
    }

    #[test]
    fn rootdse_is_available_before_bind() {
        let directory = directory();
        let auth_handler = AuthHandler::new(false);
        let mut session = LdapSession::new();

        let outcome = session.process(
            search(4, "", SearchScope::BaseObject),
            context(&directory, &auth_handler),
        );
        assert_eq!(result_code(&outcome), LdapResultCode::Success);
        assert!(matches!(
            outcome.responses.first().unwrap().protocol_op,
            LdapResponse::SearchResultEntry { .. }
        ));
    }

    #[test]
    fn unbind_closes_without_a_response() {
        let directory = directory();
        let auth_handler = AuthHandler::new(false);
        let mut session = LdapSession::new();

        let outcome = session.process(
            LdapRequestMessage {
                message_id: 5,
                protocol_op: LdapRequest::UnbindRequest,
            },
            context(&directory, &auth_handler),
        );
        assert!(outcome.responses.is_empty());
        assert_eq!(outcome.disposition, ConnectionDisposition::Close);
    }
}
